"""Trusted offline coordinator for one W09-B2 resolver attempt.

This module is intentionally not an HTTP implementation yet.  It is the sole
entry point that composes the already-frozen credential, attempt, helper, and
address-policy contracts in their security-sensitive order.  The production
helper remains fail-closed, so importing or constructing these objects cannot
perform process, credential, DNS, socket, TLS, or HTTP I/O.
"""
from __future__ import annotations

from threading import RLock
from uuid import UUID, uuid4

from snapquiz.domain._validation import require_uuid, runtime_final
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.runtime.attempt import (
    AttemptGate,
    AttemptPermit,
    CredentialResolutionPermit,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.transport.address_policy import (
    INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
    INTERNET_PUBLIC_ADDRESS_POLICY_REF,
    ResolutionSet,
    _frozen_attempt_network_binding,
    build_resolution_set,
)
from snapquiz.transport.credentials import (
    CredentialHandle,
    CredentialResolver,
)
from snapquiz.transport.resolver import (
    AttemptTerminalGuard,
    LifecycleObserver,
    PreAttemptResolverGuard,
    ResolverHelperLauncher,
    ResolverResultReceipt,
)


RESOLVER_COORDINATOR_POLICY_VERSION = "snapquiz.resolver-coordinator.v1"

_PREPARED_RESOLVER_ATTEMPT_AUTHORITY = object()


def _coordinator_error(message: str) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_coordinator",
        retryable=False,
        safe_message=message,
    )


def _observe_attempt_terminal(
    gate: AttemptGate,
    attempt: AttemptPermit,
) -> bool:
    try:
        return gate._attempt_is_terminal(
            attempt,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
    except BaseException:
        return False


def _finish_owned_attempt(
    gate: AttemptGate,
    attempt: AttemptPermit,
    *,
    claim_id: UUID,
    guard: AttemptTerminalGuard | None,
) -> tuple[bool, BaseException | None]:
    try:
        changed = gate.finish_attempt(
            attempt,
            claim_id=claim_id,
            guard_id=None if guard is None else guard.terminal_guard_id,
            guard_digest=None if guard is None else guard.terminal_guard_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
    except BaseException as error:
        return _observe_attempt_terminal(gate, attempt), error
    return changed or _observe_attempt_terminal(gate, attempt), None


def _abandon_unclaimed_attempt(
    gate: AttemptGate,
    attempt: AttemptPermit,
) -> tuple[bool, BaseException | None]:
    try:
        changed = gate.abandon_attempt(
            attempt,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
    except BaseException as error:
        return _observe_attempt_terminal(gate, attempt), error
    return changed or _observe_attempt_terminal(gate, attempt), None


def _cleanup_failed_coordination(
    *,
    gate: AttemptGate,
    credential_permit: CredentialResolutionPermit,
    credential_resolver: CredentialResolver,
    pre_guard: PreAttemptResolverGuard | None,
    terminal_guard: AttemptTerminalGuard | None,
    credential_handle: CredentialHandle | None,
    attempt: AttemptPermit | None,
    claim_id: UUID,
) -> None:
    """Best-effort cleanup without ever changing the selected primary error.

    Rejected owner/proof candidates are side-effect free.  This allows an
    uncertain observer path to try the exact terminal-guard proof, then the
    no-guard proof, and finally active-attempt abandonment without stealing a
    different owner's state.
    """

    helper_owner: object | None = terminal_guard or pre_guard
    helper_terminal = helper_owner is None
    if helper_owner is not None:
        try:
            helper_owner.cleanup()  # type: ignore[union-attr]
        except BaseException:
            pass
        try:
            helper_terminal = (
                helper_owner.safe_metadata()["state"] == "terminal"  # type: ignore[union-attr]
            )
        except BaseException:
            helper_terminal = False

    # The helper owner is the outermost resource.  If kill/reap/pipe cleanup
    # is not proven, retaining the claimed Gate and handle is safer than
    # terminalizing their only recovery anchor while a child may still live.
    if not helper_terminal:
        return

    attempt_terminal = False
    if attempt is not None:
        guard_candidates: tuple[AttemptTerminalGuard | None, ...]
        if terminal_guard is not None:
            guard_candidates = (terminal_guard, None)
        else:
            guard_candidates = (None,)

        # Each candidate is owner/proof exact and a rejection is side-effect
        # free.  Trying both shapes is therefore safer than trusting an
        # observer after a commit-then-raise fault: a bound Gate accepts only
        # the exact guard, while a pre-bind Gate accepts only the no-guard
        # shape.  If the claim itself never committed, both reject and exact
        # active-attempt abandonment remains available.
        for selected_guard in guard_candidates:
            attempt_terminal, _ = _finish_owned_attempt(
                gate,
                attempt,
                claim_id=claim_id,
                guard=selected_guard,
            )
            if attempt_terminal:
                break
        if not attempt_terminal:
            attempt_terminal, _ = _abandon_unclaimed_attempt(gate, attempt)

    if credential_handle is not None and (
        attempt is None or attempt_terminal
    ):
        # A consumed handle becomes closable only after its AttemptGate state
        # is terminal.  Retain it as the recovery anchor when owner-bound Gate
        # completion is not proven.
        try:
            credential_resolver.close(credential_handle)
        except BaseException:
            pass
    elif attempt is None:
        # Covers launch-before-read failures.  CredentialResolver owns any
        # permit it successfully claimed, so this public transition can only
        # abandon the still-authorized pre-read state.
        try:
            gate.abandon_credential_resolution(credential_permit)
        except BaseException:
            pass


def _build_started_resolution(
    attempt: AttemptPermit,
    result_receipt: ResolverResultReceipt,
) -> ResolutionSet:
    """Keep the proof-bound RESULT factory call in one upgrade seam."""

    return build_resolution_set(attempt, result_receipt)


@runtime_final
class PreparedResolverAttempt:
    """Factory-only owner of one resolved, not-yet-wired attempt.

    B2b can consume the exact attempt, credential handle, and ResolutionSet.
    If it does not, the caller must explicitly call :meth:`close` to reap the
    helper, terminalize the owner-bound attempt, and close the secret handle.
    """

    __slots__ = (
        "policy_version",
        "attempt_permit",
        "credential_handle",
        "result_receipt",
        "resolution_set",
        "transport_claim_id",
        "terminal_guard_id",
        "terminal_guard_digest",
        "dns_start_id",
        "_gate",
        "_credential_resolver",
        "_terminal_guard",
        "_status",
        "_lock",
    )

    def __init__(
        self,
        *,
        gate: AttemptGate,
        credential_resolver: CredentialResolver,
        terminal_guard: AttemptTerminalGuard,
        credential_handle: CredentialHandle,
        attempt_permit: AttemptPermit,
        result_receipt: ResolverResultReceipt,
        resolution_set: ResolutionSet,
        transport_claim_id: UUID,
        dns_start_id: UUID,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PREPARED_RESOLVER_ATTEMPT_AUTHORITY:
            raise TypeError("prepared resolver attempts require the coordinator")
        if type(gate) is not AttemptGate:
            raise TypeError("gate must be AttemptGate")
        if type(credential_resolver) is not CredentialResolver:
            raise TypeError("credential_resolver must be CredentialResolver")
        if type(terminal_guard) is not AttemptTerminalGuard:
            raise TypeError("terminal_guard must be AttemptTerminalGuard")
        if type(credential_handle) is not CredentialHandle:
            raise TypeError("credential_handle must be CredentialHandle")
        if type(attempt_permit) is not AttemptPermit:
            raise TypeError("attempt_permit must be AttemptPermit")
        if type(result_receipt) is not ResolverResultReceipt:
            raise TypeError("result_receipt must be ResolverResultReceipt")
        if type(resolution_set) is not ResolutionSet:
            raise TypeError("resolution_set must be ResolutionSet")
        require_uuid(transport_claim_id, "transport_claim_id")
        require_uuid(dns_start_id, "dns_start_id")

        attempt_permit.validate_integrity()
        credential_handle.validate_integrity()
        resolution_set.validate_binding(attempt_permit, result_receipt)
        exact = (
            attempt_permit._attempt_gate is gate,
            attempt_permit.credential_handle_id == credential_handle.handle_id,
            attempt_permit.credential_handle_digest
            == credential_handle.handle_digest,
            terminal_guard.attempt_permit_id
            == attempt_permit.attempt_permit_id,
            terminal_guard.attempt_permit_digest
            == attempt_permit.attempt_permit_digest,
            terminal_guard.transport_claim_id == transport_claim_id,
            result_receipt.lifecycle_id == terminal_guard.lifecycle_id,
            result_receipt.attempt_permit_id
            == attempt_permit.attempt_permit_id,
            result_receipt.attempt_permit_digest
            == attempt_permit.attempt_permit_digest,
            result_receipt.transport_claim_id == transport_claim_id,
            result_receipt.terminal_guard_id
            == terminal_guard.terminal_guard_id,
            result_receipt.terminal_guard_digest
            == terminal_guard.terminal_guard_digest,
            result_receipt.dns_start_id == dns_start_id,
            resolution_set.receipt_digest == result_receipt.receipt_digest,
        )
        if not all(exact):
            raise _coordinator_error("resolver attempt 的 owner proof 不匹配。")
        if not gate._dns_start_is_committed(
            attempt_permit,
            claim_id=transport_claim_id,
            guard_id=terminal_guard.terminal_guard_id,
            guard_digest=terminal_guard.terminal_guard_digest,
            start_id=dns_start_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("resolver attempt 的 DNS START 未提交。")

        values = (
            ("policy_version", RESOLVER_COORDINATOR_POLICY_VERSION),
            ("attempt_permit", attempt_permit),
            ("credential_handle", credential_handle),
            ("result_receipt", result_receipt),
            ("resolution_set", resolution_set),
            ("transport_claim_id", transport_claim_id),
            ("terminal_guard_id", terminal_guard.terminal_guard_id),
            ("terminal_guard_digest", terminal_guard.terminal_guard_digest),
            ("dns_start_id", dns_start_id),
            ("_gate", gate),
            ("_credential_resolver", credential_resolver),
            ("_terminal_guard", terminal_guard),
            ("_status", "active"),
            ("_lock", RLock()),
        )
        for name, value in values:
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("PreparedResolverAttempt is immutable")

    def __copy__(self) -> "PreparedResolverAttempt":
        raise TypeError("PreparedResolverAttempt cannot be copied")

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "PreparedResolverAttempt":
        del memo
        raise TypeError("PreparedResolverAttempt cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("PreparedResolverAttempt cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("PreparedResolverAttempt cannot be serialized")

    def __repr__(self) -> str:
        return (
            "PreparedResolverAttempt("
            f"attempt_permit_id={self.attempt_permit.attempt_permit_id!r}, "
            f"resolution_id={self.resolution_set.resolution_id!r}, "
            f"closed={self.is_closed!r})"
        )

    @property
    def is_closed(self) -> bool:
        with self._lock:
            return self._status == "closed"

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "policy_version": self.policy_version,
                "attempt_permit_id": str(
                    self.attempt_permit.attempt_permit_id
                ),
                "resolution_id": str(self.resolution_set.resolution_id),
                "transport_claim_id": str(self.transport_claim_id),
                "terminal_guard_id": str(self.terminal_guard_id),
                "dns_start_id": str(self.dns_start_id),
                "result_receipt_digest_prefix": str(
                    self.result_receipt.receipt_digest
                )[:12],
                "state": self._status,
            }

    def close(self) -> bool:
        """Close every owner-held resource; consumed budget is not refunded."""

        with self._lock:
            if self._status == "closed":
                return False
            if self._status == "closing":
                raise _coordinator_error("resolver attempt 正在终结。")
            object.__setattr__(self, "_status", "closing")

            errors: list[BaseException] = []
            try:
                self._terminal_guard.cleanup()
            except BaseException as error:
                errors.append(error)

            helper_terminal = False
            try:
                helper_terminal = (
                    self._terminal_guard.safe_metadata()["state"] == "terminal"
                )
            except BaseException:
                pass

            attempt_terminal = False
            if helper_terminal:
                attempt_terminal, finish_error = _finish_owned_attempt(
                    self._gate,
                    self.attempt_permit,
                    claim_id=self.transport_claim_id,
                    guard=self._terminal_guard,
                )
                if finish_error is not None:
                    errors.append(finish_error)

            if attempt_terminal:
                try:
                    self._credential_resolver.close(self.credential_handle)
                except BaseException as error:
                    errors.append(error)

            all_terminal = (
                helper_terminal
                and attempt_terminal
                and self.credential_handle.is_closed
            )
            object.__setattr__(
                self,
                "_status",
                "closed" if all_terminal else "active",
            )

            if errors:
                raise errors[0]
            if not all_terminal:
                raise _coordinator_error("resolver attempt 未能证明完整终结。")
            return True


def coordinate_resolver_attempt(
    *,
    launcher: ResolverHelperLauncher,
    credential_resolver: CredentialResolver,
    gate: AttemptGate,
    credential_permit: CredentialResolutionPermit,
    lifecycle_id: UUID,
    transport_claim_id: UUID,
    dns_start_id: UUID,
    observer: LifecycleObserver | None = None,
) -> PreparedResolverAttempt:
    """Resolve exactly once through READY -> secret -> claim -> DNS START.

    ``transport_claim_id`` and ``dns_start_id`` are caller-generated owner
    proofs.  No target-bearing START is written unless every Gate transition
    returns normally *and* the exact committed proof can be observed.
    """

    if type(launcher) is not ResolverHelperLauncher:
        raise TypeError("launcher must be ResolverHelperLauncher")
    if type(credential_resolver) is not CredentialResolver:
        raise TypeError("credential_resolver must be CredentialResolver")
    if type(gate) is not AttemptGate:
        raise TypeError("gate must be AttemptGate")
    if type(credential_permit) is not CredentialResolutionPermit:
        raise TypeError("credential_permit must be CredentialResolutionPermit")
    require_uuid(lifecycle_id, "lifecycle_id")
    require_uuid(transport_claim_id, "transport_claim_id")
    require_uuid(dns_start_id, "dns_start_id")
    if credential_permit._attempt_gate is not gate:
        raise _coordinator_error("credential permit 不属于当前 AttemptGate。")

    pre_guard: PreAttemptResolverGuard | None = None
    terminal_guard: AttemptTerminalGuard | None = None
    credential_handle: CredentialHandle | None = None
    attempt: AttemptPermit | None = None
    ready_publication_id = uuid4()
    ready_reservation_owner = object()
    try:
        ready_publication_ticket = launcher._reserve_ready_publication(
            publication_id=ready_publication_id,
            lifecycle_id=lifecycle_id,
            reservation_owner=ready_reservation_owner,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
    except BaseException:
        # Reservation itself can return through an outer wrapper that raises
        # before assignment.  The pre-created owner identity removes only
        # this exact still-reserved entry and cannot steal a colliding caller.
        try:
            launcher._recover_ready_reservation(
                publication_id=ready_publication_id,
                lifecycle_id=lifecycle_id,
                reservation_owner=ready_reservation_owner,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            pass
        _cleanup_failed_coordination(
            gate=gate,
            credential_permit=credential_permit,
            credential_resolver=credential_resolver,
            pre_guard=None,
            terminal_guard=None,
            credential_handle=None,
            attempt=None,
            claim_id=transport_claim_id,
        )
        raise
    try:
        # This is deliberately the first operation that can cross an injected
        # external boundary.  Its spawn request contains neither target nor
        # secret data, and READY must complete before credential resolution.
        try:
            pre_guard = launcher.launch_ready(
                lifecycle_id=lifecycle_id,
                observer=observer,
                publication_ticket=ready_publication_ticket,
            )
            if not launcher._consume_ready_publication(
                ready_publication_ticket,
                pre_guard,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            ):
                raise _coordinator_error(
                    "resolver READY publication 未能精确消费。"
                )
        except BaseException:
            # An outer wrapper can raise after launch_ready() returned but
            # before assignment.  Only this pre-spawn-reserved ticket can
            # recover the exact published guard; an unused reservation is
            # consumed without manufacturing an owner.
            try:
                recovered_pre_guard = (
                    launcher._recover_ready_publication(
                        ready_publication_ticket,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )
            except BaseException:
                recovered_pre_guard = None
            if recovered_pre_guard is not None:
                pre_guard = recovered_pre_guard
            raise

        credential_publication_id = uuid4()
        try:
            credential_handle = credential_resolver.resolve(
                credential_permit,
                publication_id=credential_publication_id,
            )
        except BaseException:
            # A wrapper can raise after resolve() published and returned its
            # handle but before this assignment completed.  Recover only the
            # unique exact proof for cleanup; the original exception still
            # forbids every later transition, including START.
            try:
                recovered_handle = (
                    credential_resolver._recover_published_handle(
                        credential_permit,
                        publication_id=credential_publication_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )
            except BaseException:
                recovered_handle = None
            if recovered_handle is not None:
                credential_handle = recovered_handle
            raise

        try:
            attempt = gate.reserve_attempt(
                credential_permit=credential_permit,
                credential_handle_id=credential_handle.handle_id,
                credential_handle_digest=credential_handle.handle_digest,
            )
        except BaseException:
            # Same return/assignment window for AttemptPermit publication.
            # Recovery requires the exact input handle proof and accepts only
            # one active, unclaimed attempt; it is used solely for cleanup.
            try:
                recovered_attempt = gate._recover_published_attempt(
                    credential_permit=credential_permit,
                    credential_handle_id=credential_handle.handle_id,
                    credential_handle_digest=credential_handle.handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                recovered_attempt = None
            if recovered_attempt is not None:
                attempt = recovered_attempt
            raise

        try:
            gate._claim_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            raise
        if not gate._attempt_claim_is_owned(
            attempt,
            claim_id=transport_claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("transport claim 未能精确提交。")

        try:
            terminal_guard = pre_guard.transfer(
                attempt_permit_id=attempt.attempt_permit_id,
                attempt_permit_digest=attempt.attempt_permit_digest,
                transport_claim_id=transport_claim_id,
                observer=observer,
            )
        except BaseException:
            # transfer() can also return normally into an outer wrapper that
            # raises before assignment.  The ledger retains the exact former
            # pre-owner so only its matching terminal guard can be recovered.
            try:
                recovered_guard = pre_guard._recover_transferred_guard(
                    attempt_permit_id=attempt.attempt_permit_id,
                    attempt_permit_digest=attempt.attempt_permit_digest,
                    transport_claim_id=transport_claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                recovered_guard = None
            if recovered_guard is not None:
                terminal_guard = recovered_guard
                pre_guard = None
            raise
        pre_guard = None
        try:
            gate._bind_terminal_guard(
                attempt,
                claim_id=transport_claim_id,
                guard_id=terminal_guard.terminal_guard_id,
                guard_digest=terminal_guard.terminal_guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            raise
        if not gate._terminal_guard_is_bound(
            attempt,
            claim_id=transport_claim_id,
            guard_id=terminal_guard.terminal_guard_id,
            guard_digest=terminal_guard.terminal_guard_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("terminal guard 未能精确绑定。")

        hostname, port, _ = _frozen_attempt_network_binding(attempt)
        try:
            gate._commit_dns_start(
                attempt,
                claim_id=transport_claim_id,
                guard_id=terminal_guard.terminal_guard_id,
                guard_digest=terminal_guard.terminal_guard_digest,
                start_id=dns_start_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            # Observe a possible commit-then-raise for exact cleanup only.  An
            # exception never causes START, even when the commit is visible.
            try:
                gate._dns_start_is_committed(
                    attempt,
                    claim_id=transport_claim_id,
                    guard_id=terminal_guard.terminal_guard_id,
                    guard_digest=terminal_guard.terminal_guard_digest,
                    start_id=dns_start_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                pass
            raise
        if not gate._dns_start_is_committed(
            attempt,
            claim_id=transport_claim_id,
            guard_id=terminal_guard.terminal_guard_id,
            guard_digest=terminal_guard.terminal_guard_digest,
            start_id=dns_start_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("DNS START 提交证明不确定。")

        terminal_guard.start(
            hostname=hostname,
            port=port,
            network_policy_ref=INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            network_policy_digest=INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
            dns_start_id=dns_start_id,
            observer=observer,
        )
        result_receipt = terminal_guard.read_result_receipt(observer=observer)
        if not gate._dns_start_is_committed(
            attempt,
            claim_id=transport_claim_id,
            guard_id=terminal_guard.terminal_guard_id,
            guard_digest=terminal_guard.terminal_guard_digest,
            start_id=dns_start_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("resolver RESULT 的 START proof 已变化。")
        resolution = _build_started_resolution(
            attempt,
            result_receipt,
        )
        return PreparedResolverAttempt(
            gate=gate,
            credential_resolver=credential_resolver,
            terminal_guard=terminal_guard,
            credential_handle=credential_handle,
            attempt_permit=attempt,
            result_receipt=result_receipt,
            resolution_set=resolution,
            transport_claim_id=transport_claim_id,
            dns_start_id=dns_start_id,
            _authority=_PREPARED_RESOLVER_ATTEMPT_AUTHORITY,
        )
    except BaseException:
        _cleanup_failed_coordination(
            gate=gate,
            credential_permit=credential_permit,
            credential_resolver=credential_resolver,
            pre_guard=pre_guard,
            terminal_guard=terminal_guard,
            credential_handle=credential_handle,
            attempt=attempt,
            claim_id=transport_claim_id,
        )
        raise


__all__ = [
    "RESOLVER_COORDINATOR_POLICY_VERSION",
    "PreparedResolverAttempt",
    "coordinate_resolver_attempt",
]
