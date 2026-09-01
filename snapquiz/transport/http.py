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
from snapquiz.domain.digest import Digest256
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
    _ResolverLifecycleLedger,
    _RESOLVER_LIFECYCLE_AUTHORITY,
    _cleanup_guard,
)


RESOLVER_COORDINATOR_POLICY_VERSION = "snapquiz.resolver-coordinator.v1"

_PREPARED_RESOLVER_ATTEMPT_AUTHORITY = object()


def _coordinator_error(message: str) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_coordinator",
        retryable=False,
        safe_message=message,
    )


def _cleanup_failed_coordination(
    *,
    gate: AttemptGate,
    credential_permit: CredentialResolutionPermit,
    credential_resolver: CredentialResolver,
    pre_guard: PreAttemptResolverGuard | None,
    terminal_guard: AttemptTerminalGuard | None,
    credential_handle: CredentialHandle | None,
    credential_publication_id: UUID | None = None,
    credential_handle_id: UUID | None = None,
    credential_handle_digest: Digest256 | None = None,
    attempt: AttemptPermit | None,
    claim_id: UUID | None,
    terminal_guard_id: UUID | None = None,
    terminal_guard_digest: Digest256 | None = None,
    helper_terminal_hint: bool = False,
) -> None:
    """Best-effort cleanup without ever changing the selected primary error.

    Rejected owner/proof candidates are side-effect free.  This allows an
    uncertain observer path to try the exact terminal-guard proof, then the
    no-guard proof, and finally active-attempt abandonment without stealing a
    different owner's state.
    """

    helper_owner: object | None = terminal_guard or pre_guard
    helper_terminal = helper_terminal_hint or helper_owner is None
    if helper_owner is not None and not helper_terminal:
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
    if attempt is not None and type(claim_id) is UUID:
        try:
            attempt_terminal = gate._recover_attempt_for_cleanup(
                attempt,
                credential_permit=credential_permit,
                credential_handle_id=credential_handle_id,
                credential_handle_digest=credential_handle_digest,
                claim_id=claim_id,
                guard_id=terminal_guard_id,
                guard_digest=terminal_guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            attempt_terminal = False

    # A wrapper may publish the real AttemptPermit, then return a different
    # object normally.  The assigned object cannot identify that live ledger
    # entry, so fall back to the frozen credential proof used for reservation.
    if (
        not attempt_terminal
        and type(credential_handle_id) is UUID
        and type(credential_handle_digest) is Digest256
    ):
        try:
            attempt_terminal = gate._recover_published_attempt_for_cleanup(
                credential_permit=credential_permit,
                credential_handle_id=credential_handle_id,
                credential_handle_digest=credential_handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            attempt_terminal = False

    handle_terminal = False
    if type(credential_publication_id) is UUID:
        try:
            credential_resolver._recover_published_handle_for_cleanup(
                credential_permit,
                publication_id=credential_publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            pass
        try:
            handle_terminal = (
                credential_resolver._published_handle_is_closed_for_cleanup(
                    credential_permit,
                    publication_id=credential_publication_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
        except BaseException:
            handle_terminal = False
        if not handle_terminal:
            try:
                credential_resolver._recover_published_handle_state_for_cleanup(
                    credential_permit,
                    publication_id=credential_publication_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                pass
            try:
                handle_terminal = (
                    credential_resolver._published_handle_is_closed_for_cleanup(
                        credential_permit,
                        publication_id=credential_publication_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )
            except BaseException:
                handle_terminal = False

    if credential_handle is not None and not handle_terminal:
        try:
            handle_terminal = (
                credential_resolver._handle_is_closed_for_cleanup(
                    credential_handle,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
        except BaseException:
            handle_terminal = False

    if credential_handle is None and attempt is None:
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
    The RESULT path has already reaped the helper and closed its pipes.  If B2b
    does not consume this object, the caller must explicitly call :meth:`close`
    to terminalize the helper ledger, owner-bound attempt, and secret handle.
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
        "_terminal_guard_ledger_snapshot",
        "_attempt_permit_snapshot",
        "_credential_permit_snapshot",
        "_credential_handle_snapshot",
        "_credential_handle_id_snapshot",
        "_credential_handle_digest_snapshot",
        "_status",
        "_lock",
    )

    def __init__(
        self,
        *,
        gate: AttemptGate,
        credential_resolver: CredentialResolver,
        terminal_guard: AttemptTerminalGuard,
        terminal_guard_ledger: _ResolverLifecycleLedger,
        credential_handle: CredentialHandle,
        attempt_permit: AttemptPermit,
        result_receipt: ResolverResultReceipt,
        resolution_set: ResolutionSet,
        transport_claim_id: UUID,
        terminal_guard_id: UUID,
        terminal_guard_digest: Digest256,
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
        if type(terminal_guard_ledger) is not _ResolverLifecycleLedger:
            raise TypeError(
                "terminal_guard_ledger must be _ResolverLifecycleLedger"
            )
        if type(credential_handle) is not CredentialHandle:
            raise TypeError("credential_handle must be CredentialHandle")
        if type(attempt_permit) is not AttemptPermit:
            raise TypeError("attempt_permit must be AttemptPermit")
        if type(result_receipt) is not ResolverResultReceipt:
            raise TypeError("result_receipt must be ResolverResultReceipt")
        if type(resolution_set) is not ResolutionSet:
            raise TypeError("resolution_set must be ResolutionSet")
        require_uuid(transport_claim_id, "transport_claim_id")
        require_uuid(terminal_guard_id, "terminal_guard_id")
        require_uuid(dns_start_id, "dns_start_id")
        _, terminal_snapshot = terminal_guard_ledger.require_exact_terminal_guard(
            terminal_guard,
            terminal_guard._capability,
        )
        if (
            terminal_guard_id != terminal_snapshot.terminal_guard_id
            or terminal_guard_digest != terminal_snapshot.terminal_guard_digest
        ):
            raise _coordinator_error("resolver terminal guard snapshot 不匹配。")

        attempt_permit.validate_integrity()
        credential_handle.validate_integrity()
        resolution_set.validate_binding(attempt_permit, result_receipt)
        credential_permit_snapshot = attempt_permit._credential_permit
        if type(credential_permit_snapshot) is not CredentialResolutionPermit:
            raise _coordinator_error("resolver credential owner proof 无效。")
        exact = (
            attempt_permit._attempt_gate is gate,
            attempt_permit.credential_handle_id == credential_handle.handle_id,
            attempt_permit.credential_handle_digest
            == credential_handle.handle_digest,
            terminal_snapshot.attempt_permit_id
            == attempt_permit.attempt_permit_id,
            terminal_snapshot.attempt_permit_digest
            == attempt_permit.attempt_permit_digest,
            terminal_snapshot.transport_claim_id == transport_claim_id,
            result_receipt.lifecycle_id == terminal_guard.lifecycle_id,
            result_receipt.attempt_permit_id
            == attempt_permit.attempt_permit_id,
            result_receipt.attempt_permit_digest
            == attempt_permit.attempt_permit_digest,
            result_receipt.transport_claim_id == transport_claim_id,
            result_receipt.terminal_guard_id == terminal_guard_id,
            result_receipt.terminal_guard_digest == terminal_guard_digest,
            result_receipt.dns_start_id == dns_start_id,
            resolution_set.receipt_digest == result_receipt.receipt_digest,
        )
        if not all(exact):
            raise _coordinator_error("resolver attempt 的 owner proof 不匹配。")
        if not gate._dns_start_is_committed(
            attempt_permit,
            claim_id=transport_claim_id,
            guard_id=terminal_guard_id,
            guard_digest=terminal_guard_digest,
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
            ("terminal_guard_id", terminal_guard_id),
            ("terminal_guard_digest", terminal_guard_digest),
            ("dns_start_id", dns_start_id),
            ("_gate", gate),
            ("_credential_resolver", credential_resolver),
            ("_terminal_guard", terminal_guard),
            ("_terminal_guard_ledger_snapshot", terminal_guard_ledger),
            ("_attempt_permit_snapshot", attempt_permit),
            ("_credential_permit_snapshot", credential_permit_snapshot),
            ("_credential_handle_snapshot", credential_handle),
            ("_credential_handle_id_snapshot", credential_handle.handle_id),
            (
                "_credential_handle_digest_snapshot",
                credential_handle.handle_digest,
            ),
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
                _cleanup_guard(
                    self._terminal_guard,
                    self._terminal_guard_ledger_snapshot,
                    observer=None,
                    suppress_errors=False,
                )
            except BaseException as error:
                errors.append(error)

            helper_terminal = False
            try:
                helper_terminal = (
                    self._terminal_guard_ledger_snapshot.is_terminal()
                )
            except BaseException:
                pass

            attempt_terminal = False
            if helper_terminal:
                try:
                    attempt_terminal = (
                        self._gate._recover_attempt_for_cleanup(
                            self._attempt_permit_snapshot,
                            credential_permit=self._credential_permit_snapshot,
                            credential_handle_id=(
                                self._credential_handle_id_snapshot
                            ),
                            credential_handle_digest=(
                                self._credential_handle_digest_snapshot
                            ),
                            claim_id=self.transport_claim_id,
                            guard_id=self.terminal_guard_id,
                            guard_digest=self.terminal_guard_digest,
                            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                        )
                    )
                except BaseException:
                    attempt_terminal = False

            if attempt_terminal:
                try:
                    self._credential_resolver.close(
                        self._credential_handle_snapshot
                    )
                except BaseException as error:
                    errors.append(error)

            handle_terminal = False
            try:
                handle_terminal = (
                    self._credential_resolver._handle_is_closed_for_cleanup(
                        self._credential_handle_snapshot,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )
            except BaseException:
                pass
            all_terminal = (
                helper_terminal and attempt_terminal and handle_terminal
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
    observer: LifecycleObserver | None = None,
) -> PreparedResolverAttempt:
    """Resolve exactly once through READY -> secret -> claim -> DNS START.

    The launcher generates the lifecycle, claim, and DNS-start role IDs as one
    exact capability before spawn.  No target-bearing START is written unless
    every Gate transition returns normally and the committed capability proofs
    remain exact.
    """

    if type(launcher) is not ResolverHelperLauncher:
        raise TypeError("launcher must be ResolverHelperLauncher")
    if type(credential_resolver) is not CredentialResolver:
        raise TypeError("credential_resolver must be CredentialResolver")
    if type(gate) is not AttemptGate:
        raise TypeError("gate must be AttemptGate")
    if type(credential_permit) is not CredentialResolutionPermit:
        raise TypeError("credential_permit must be CredentialResolutionPermit")
    if credential_permit._attempt_gate is not gate:
        raise _coordinator_error("credential permit 不属于当前 AttemptGate。")

    pre_guard: PreAttemptResolverGuard | None = None
    terminal_guard: AttemptTerminalGuard | None = None
    credential_handle: CredentialHandle | None = None
    credential_handle_id: UUID | None = None
    credential_handle_digest: Digest256 | None = None
    attempt: AttemptPermit | None = None
    terminal_guard_id: UUID | None = None
    terminal_guard_digest: Digest256 | None = None
    helper_cleanup_terminal = False
    credential_publication_id: UUID | None = None
    ready_ledger_snapshot: _ResolverLifecycleLedger | None = None
    attempt_permit_id: UUID | None = None
    attempt_permit_digest: Digest256 | None = None
    ready_reservation_owner = object()
    ready_launch_owner = object()
    try:
        ready_publication_ticket = launcher._reserve_lifecycle_capability(
            reservation_owner=ready_reservation_owner,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        # Keep even normal-return aliases inside the reservation recovery
        # window.  A wrong object must not strand the real reserved ticket.
        ready_capability_snapshot = (
            launcher._reserved_lifecycle_snapshot_for_owner(
                ready_publication_ticket,
                reservation_owner=ready_reservation_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        transport_claim_id = ready_capability_snapshot.transport_claim_id
        dns_start_id = ready_capability_snapshot.dns_start_id
    except BaseException:
        # Reservation itself can return through an outer wrapper that raises
        # before assignment.  The pre-created owner identity removes only
        # this exact still-reserved entry and cannot steal a colliding caller.
        try:
            launcher._recover_lifecycle_reservation(
                reservation_owner=ready_reservation_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
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
            credential_publication_id=None,
            attempt=None,
            claim_id=None,
        )
        raise
    try:
        # This is deliberately the first operation that can cross an injected
        # external boundary.  Its spawn request contains neither target nor
        # secret data, and READY must complete before credential resolution.
        try:
            candidate_pre_guard = launcher._launch_ready(
                capability=ready_publication_ticket,
                launch_owner=ready_launch_owner,
                observer=observer,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            if not launcher._consume_ready_publication(
                ready_publication_ticket,
                candidate_pre_guard,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            ):
                raise _coordinator_error(
                    "resolver READY publication 未能精确消费。"
                )
            ready_ledger_snapshot = launcher._accepted_ready_guard_ledger(
                ready_publication_ticket,
                candidate_pre_guard,
                launch_owner=ready_launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            pre_guard = candidate_pre_guard
        except BaseException:
            # Cleanup is performed inside the launcher against the exact
            # pre-created launch owner.  No live guard is returned to this
            # exception path, and a concurrent loser cannot steal a winner.
            try:
                helper_cleanup_terminal = (
                    launcher._recover_ready_publication_for_cleanup(
                        ready_publication_ticket,
                        launch_owner=ready_launch_owner,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )
                    or helper_cleanup_terminal
                )
            except BaseException:
                pass
            try:
                launcher._recover_lifecycle_reservation(
                    reservation_owner=ready_reservation_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            except BaseException:
                pass
            raise

        credential_publication_id = uuid4()
        try:
            candidate_credential_handle = credential_resolver.resolve(
                credential_permit,
                publication_id=credential_publication_id,
            )
        except BaseException:
            # A wrapper can raise after resolve() published and returned its
            # handle but before this assignment completed.  Recover only the
            # unique exact proof for cleanup; the original exception still
            # forbids every later transition, including START.
            try:
                credential_resolver._recover_published_handle_for_cleanup(
                    credential_permit,
                    publication_id=credential_publication_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                pass
            raise

        candidate_credential_handle.validate_integrity()
        if not credential_resolver._published_handle_is_exact_for_transport(
            candidate_credential_handle,
            permit=credential_permit,
            publication_id=credential_publication_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error(
                "credential handle publication 未能精确证明。"
            )
        credential_handle = candidate_credential_handle
        credential_handle_id = candidate_credential_handle.handle_id
        credential_handle_digest = candidate_credential_handle.handle_digest

        try:
            attempt = gate.reserve_attempt(
                credential_permit=credential_permit,
                credential_handle_id=credential_handle_id,
                credential_handle_digest=credential_handle_digest,
            )
        except BaseException:
            # Same return/assignment window for AttemptPermit publication.
            # Recovery requires the exact input handle proof and accepts only
            # one active, unclaimed attempt; it is used solely for cleanup.
            try:
                gate._recover_published_attempt_for_cleanup(
                    credential_permit=credential_permit,
                    credential_handle_id=credential_handle_id,
                    credential_handle_digest=credential_handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                pass
            raise

        try:
            gate._claim_attempt(
                attempt,
                claim_id=transport_claim_id,
                expected_credential_permit=credential_permit,
                expected_credential_handle_id=credential_handle_id,
                expected_credential_handle_digest=credential_handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            raise
        attempt_permit_id, attempt_permit_digest = (
            gate._claimed_attempt_snapshot_for_transport(
                attempt,
                credential_permit=credential_permit,
                credential_handle_id=credential_handle_id,
                credential_handle_digest=credential_handle_digest,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        if not gate._attempt_claim_is_owned(
            attempt,
            claim_id=transport_claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("transport claim 未能精确提交。")

        try:
            candidate_terminal_guard = pre_guard._transfer(
                attempt_permit_id=attempt_permit_id,
                attempt_permit_digest=attempt_permit_digest,
                observer=observer,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            if ready_ledger_snapshot is None:
                raise _coordinator_error(
                    "resolver READY ledger snapshot 缺失。"
                )
            _, transferred_snapshot = (
                ready_ledger_snapshot.require_exact_terminal_guard(
                    candidate_terminal_guard,
                    ready_publication_ticket,
                )
            )
            if (
                transferred_snapshot.attempt_permit_id != attempt_permit_id
                or transferred_snapshot.attempt_permit_digest
                != attempt_permit_digest
                or transferred_snapshot.transport_claim_id
                != transport_claim_id
            ):
                raise _coordinator_error(
                    "resolver terminal guard owner proof 不匹配。"
                )
            terminal_guard = candidate_terminal_guard
        except BaseException:
            # _transfer() can also return normally into an outer wrapper that
            # raises before assignment.  The ledger retains the exact former
            # pre-owner so only its matching terminal guard can be recovered.
            try:
                if ready_ledger_snapshot is not None:
                    helper_cleanup_terminal = (
                        ready_ledger_snapshot.recover_transferred_guard_for_cleanup(
                            pre_guard,
                            attempt_permit_id=attempt_permit_id,
                            attempt_permit_digest=attempt_permit_digest,
                        )
                        or helper_cleanup_terminal
                    )
                else:
                    helper_cleanup_terminal = (
                        pre_guard._recover_transferred_guard_for_cleanup(
                            attempt_permit_id=attempt_permit_id,
                            attempt_permit_digest=attempt_permit_digest,
                            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                        )
                        or helper_cleanup_terminal
                    )
            except BaseException:
                pass
            raise
        pre_guard = None
        terminal_snapshot = terminal_guard._proof_snapshot(
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        terminal_guard_id = terminal_snapshot.terminal_guard_id
        terminal_guard_digest = terminal_snapshot.terminal_guard_digest
        try:
            gate._bind_terminal_guard(
                attempt,
                claim_id=transport_claim_id,
                guard_id=terminal_guard_id,
                guard_digest=terminal_guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            raise
        if not gate._terminal_guard_is_bound(
            attempt,
            claim_id=transport_claim_id,
            guard_id=terminal_guard_id,
            guard_digest=terminal_guard_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("terminal guard 未能精确绑定。")

        hostname, port, _ = _frozen_attempt_network_binding(attempt)
        try:
            gate._commit_dns_start(
                attempt,
                claim_id=transport_claim_id,
                guard_id=terminal_guard_id,
                guard_digest=terminal_guard_digest,
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
                    guard_id=terminal_guard_id,
                    guard_digest=terminal_guard_digest,
                    start_id=dns_start_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                pass
            raise
        if not gate._dns_start_is_committed(
            attempt,
            claim_id=transport_claim_id,
            guard_id=terminal_guard_id,
            guard_digest=terminal_guard_digest,
            start_id=dns_start_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _coordinator_error("DNS START 提交证明不确定。")

        terminal_guard._start(
            hostname=hostname,
            port=port,
            network_policy_ref=INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            network_policy_digest=INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
            observer=observer,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        result_receipt = terminal_guard._read_result_receipt(
            observer=observer,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        if not gate._dns_start_is_committed(
            attempt,
            claim_id=transport_claim_id,
            guard_id=terminal_guard_id,
            guard_digest=terminal_guard_digest,
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
            terminal_guard_ledger=ready_ledger_snapshot,
            credential_handle=credential_handle,
            attempt_permit=attempt,
            result_receipt=result_receipt,
            resolution_set=resolution,
            transport_claim_id=transport_claim_id,
            terminal_guard_id=terminal_guard_id,
            terminal_guard_digest=terminal_guard_digest,
            dns_start_id=dns_start_id,
            _authority=_PREPARED_RESOLVER_ATTEMPT_AUTHORITY,
        )
    except BaseException:
        try:
            helper_cleanup_terminal = (
                launcher._recover_ready_publication_for_cleanup(
                    ready_publication_ticket,
                    launch_owner=ready_launch_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
                or helper_cleanup_terminal
            )
        except BaseException:
            pass
        _cleanup_failed_coordination(
            gate=gate,
            credential_permit=credential_permit,
            credential_resolver=credential_resolver,
            pre_guard=pre_guard,
            terminal_guard=terminal_guard,
            credential_handle=credential_handle,
            credential_publication_id=credential_publication_id,
            credential_handle_id=credential_handle_id,
            credential_handle_digest=credential_handle_digest,
            attempt=attempt,
            claim_id=transport_claim_id,
            terminal_guard_id=terminal_guard_id,
            terminal_guard_digest=terminal_guard_digest,
            helper_terminal_hint=helper_cleanup_terminal,
        )
        raise


__all__ = [
    "RESOLVER_COORDINATOR_POLICY_VERSION",
    "PreparedResolverAttempt",
    "coordinate_resolver_attempt",
]
