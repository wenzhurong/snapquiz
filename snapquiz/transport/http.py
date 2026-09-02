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
    _CREDENTIAL_RESOLVER_AUTHORITY,
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
)


RESOLVER_COORDINATOR_POLICY_VERSION = "snapquiz.resolver-coordinator.v1"

_PREPARED_RESOLVER_ATTEMPT_AUTHORITY = object()
_RESOLVER_CLEANUP_TICKET_AUTHORITY = object()


def _coordinator_error(message: str) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_coordinator",
        retryable=False,
        safe_message=message,
    )


class _ResolverCoordinationRecoveryLedger:
    """Strong, cleanup-only ownership for one coordinator invocation.

    The public ticket never receives transport capabilities.  This ledger
    freezes each owner before the operation that can publish it, then retains
    those exact identities until independent observers prove all three layers
    terminal in helper -> attempt -> credential order.
    """

    __slots__ = (
        "_lock",
        "_state",
        "_ticket",
        "_coordination_owner",
        "_launcher",
        "_credential_resolver",
        "_gate",
        "_credential_permit",
        "_ready_reservation_owner",
        "_ready_launch_owner",
        "_ready_ticket",
        "_ready_capability_snapshot",
        "_ready_ledger",
        "_credential_publication_id",
        "_credential_handle",
        "_credential_handle_id",
        "_credential_handle_digest",
        "_attempt_started",
        "_attempt",
        "_claim_id",
        "_terminal_guard_id",
        "_terminal_guard_digest",
        "_prepared_published",
        "_resources_terminal_proven",
    )

    def __init__(self) -> None:
        self._lock = RLock()
        self._state = "issued"
        self._ticket: ResolverCleanupTicket | None = None
        self._coordination_owner: object | None = None
        self._launcher: ResolverHelperLauncher | None = None
        self._credential_resolver: CredentialResolver | None = None
        self._gate: AttemptGate | None = None
        self._credential_permit: CredentialResolutionPermit | None = None
        self._ready_reservation_owner = object()
        self._ready_launch_owner = object()
        self._ready_ticket: object | None = None
        self._ready_capability_snapshot: object | None = None
        self._ready_ledger: _ResolverLifecycleLedger | None = None
        self._credential_publication_id: UUID | None = None
        self._credential_handle: CredentialHandle | None = None
        self._credential_handle_id: UUID | None = None
        self._credential_handle_digest: Digest256 | None = None
        self._attempt_started = False
        self._attempt: AttemptPermit | None = None
        self._claim_id: UUID | None = None
        self._terminal_guard_id: UUID | None = None
        self._terminal_guard_digest: Digest256 | None = None
        self._prepared_published = False
        self._resources_terminal_proven = False

    def attach_ticket(
        self,
        ticket: "ResolverCleanupTicket",
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RESOLVER_CLEANUP_TICKET_AUTHORITY:
            raise TypeError("resolver cleanup ticket requires its factory")
        with self._lock:
            if self._ticket is not None or self._state != "issued":
                raise _coordinator_error("resolver cleanup ticket 已绑定。")
            self._ticket = ticket

    def ticket_is_attached(self, ticket: "ResolverCleanupTicket") -> bool:
        with self._lock:
            return (
                self._ticket is ticket
                and ticket._ledger_snapshot is self
                and self._state == "issued"
                and self._coordination_owner is None
            )

    def bind_coordination(
        self,
        ticket: "ResolverCleanupTicket",
        *,
        coordination_owner: object,
        launcher: ResolverHelperLauncher,
        credential_resolver: CredentialResolver,
        gate: AttemptGate,
        credential_permit: CredentialResolutionPermit,
    ) -> tuple[object, object]:
        """Bind once before reservation, spawn, secret read, or budget use."""

        if coordination_owner is None:
            raise TypeError("coordination_owner must be an identity object")
        with self._lock:
            if (
                self._ticket is not ticket
                or ticket._ledger_snapshot is not self
                or self._state != "issued"
                or self._coordination_owner is not None
            ):
                raise _coordinator_error(
                    "resolver cleanup ticket 已使用或不属于当前协调。"
                )
            self._coordination_owner = coordination_owner
            self._launcher = launcher
            self._credential_resolver = credential_resolver
            self._gate = gate
            self._credential_permit = credential_permit
            self._state = "coordinating"
            return (
                self._ready_reservation_owner,
                self._ready_launch_owner,
            )

    def _require_coordinating_locked(self, owner: object) -> None:
        if (
            self._coordination_owner is not owner
            or self._state != "coordinating"
        ):
            raise _coordinator_error("resolver cleanup owner 或状态已经变化。")

    def coordination_is_exact(
        self,
        ticket: "ResolverCleanupTicket",
        owner: object,
        *,
        launcher: ResolverHelperLauncher,
        credential_resolver: CredentialResolver,
        gate: AttemptGate,
        credential_permit: CredentialResolutionPermit,
        reservation_owner: object,
        launch_owner: object,
    ) -> bool:
        with self._lock:
            return (
                self._ticket is ticket
                and self._coordination_owner is owner
                and self._state == "coordinating"
                and self._launcher is launcher
                and self._credential_resolver is credential_resolver
                and self._gate is gate
                and self._credential_permit is credential_permit
                and self._ready_reservation_owner is reservation_owner
                and self._ready_launch_owner is launch_owner
            )

    def record_ready_ticket(
        self,
        owner: object,
        ticket: object,
        capability_snapshot: object,
    ) -> None:
        with self._lock:
            self._require_coordinating_locked(owner)
            if self._ready_ticket is not None:
                raise _coordinator_error("resolver READY ticket 已记录。")
            if (
                getattr(capability_snapshot, "launcher", None)
                is not self._launcher
                or getattr(capability_snapshot, "reservation_owner", None)
                is not self._ready_reservation_owner
                or getattr(capability_snapshot, "transport_claim_id", None)
                is None
            ):
                raise _coordinator_error("resolver READY ticket snapshot 无效。")
            self._ready_ticket = ticket
            self._ready_capability_snapshot = capability_snapshot
            self._claim_id = getattr(
                capability_snapshot,
                "transport_claim_id",
            )

    def ready_ticket_is_exact(
        self,
        owner: object,
        ticket: object,
        capability_snapshot: object,
    ) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._ready_ticket is ticket
                and self._ready_capability_snapshot is capability_snapshot
                and self._claim_id
                == getattr(capability_snapshot, "transport_claim_id", None)
            )

    def record_ready_ledger(
        self,
        owner: object,
        ledger: _ResolverLifecycleLedger,
    ) -> None:
        with self._lock:
            self._require_coordinating_locked(owner)
            if (
                type(ledger) is not _ResolverLifecycleLedger
                or self._ready_ticket is None
                or ledger._capability is not self._ready_ticket
            ):
                raise _coordinator_error("resolver READY ledger snapshot 无效。")
            self._ready_ledger = ledger

    def ready_ledger_is_exact(
        self,
        owner: object,
        ledger: _ResolverLifecycleLedger,
    ) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._ready_ledger is ledger
                and ledger._capability is self._ready_ticket
            )

    def begin_credential_publication(
        self,
        owner: object,
        publication_id: UUID,
    ) -> None:
        require_uuid(publication_id, "credential_publication_id")
        with self._lock:
            self._require_coordinating_locked(owner)
            if self._credential_publication_id is not None:
                raise _coordinator_error("credential publication 已开始。")
            self._credential_publication_id = publication_id

    def credential_publication_is_exact(
        self,
        owner: object,
        publication_id: UUID,
    ) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._credential_publication_id == publication_id
            )

    def record_credential_handle(
        self,
        owner: object,
        handle: CredentialHandle,
        *,
        handle_id: UUID,
        handle_digest: Digest256,
    ) -> None:
        require_uuid(handle_id, "credential_handle_id")
        if type(handle_digest) is not Digest256:
            raise TypeError("handle_digest must be Digest256")
        with self._lock:
            self._require_coordinating_locked(owner)
            if (
                type(handle) is not CredentialHandle
                or self._credential_publication_id is None
                or self._credential_handle is not None
            ):
                raise _coordinator_error("credential handle snapshot 无效。")
            self._credential_handle = handle
            self._credential_handle_id = handle_id
            self._credential_handle_digest = handle_digest

    def credential_handle_is_exact(
        self,
        owner: object,
        handle: CredentialHandle,
        *,
        handle_id: UUID,
        handle_digest: Digest256,
    ) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._credential_handle is handle
                and self._credential_handle_id == handle_id
                and self._credential_handle_digest == handle_digest
            )

    def begin_attempt_publication(self, owner: object) -> None:
        with self._lock:
            self._require_coordinating_locked(owner)
            if (
                self._attempt_started
                or type(self._credential_handle_id) is not UUID
                or type(self._credential_handle_digest) is not Digest256
            ):
                raise _coordinator_error("attempt publication snapshot 无效。")
            self._attempt_started = True

    def attempt_publication_is_started(self, owner: object) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._attempt_started
            )

    def record_attempt(
        self,
        owner: object,
        attempt: AttemptPermit,
    ) -> bool:
        with self._lock:
            self._require_coordinating_locked(owner)
            if type(attempt) is not AttemptPermit:
                return False
            if not self._attempt_started or self._attempt is not None:
                raise _coordinator_error("attempt owner snapshot 无效。")
            permit = self._credential_permit
            if (
                attempt._attempt_gate is not self._gate
                or type(permit) is not CredentialResolutionPermit
                or attempt.credential_permit_id != permit.permit_id
                or attempt.credential_permit_digest != permit.permit_digest
                or attempt.credential_handle_id != self._credential_handle_id
                or attempt.credential_handle_digest
                != self._credential_handle_digest
            ):
                return False
            self._attempt = attempt
            return True

    def attempt_is_exact(
        self,
        owner: object,
        attempt: AttemptPermit,
    ) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._attempt is attempt
            )

    def record_terminal_guard(
        self,
        owner: object,
        *,
        guard_id: UUID,
        guard_digest: Digest256,
    ) -> None:
        require_uuid(guard_id, "terminal_guard_id")
        if type(guard_digest) is not Digest256:
            raise TypeError("guard_digest must be Digest256")
        with self._lock:
            self._require_coordinating_locked(owner)
            if self._attempt is None:
                raise _coordinator_error("terminal guard 缺少 attempt owner。")
            self._terminal_guard_id = guard_id
            self._terminal_guard_digest = guard_digest

    def terminal_guard_is_exact(
        self,
        owner: object,
        *,
        guard_id: UUID,
        guard_digest: Digest256,
    ) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._terminal_guard_id == guard_id
                and self._terminal_guard_digest == guard_digest
            )

    def prepared_inputs_are_exact(
        self,
        owner: object,
        *,
        gate: AttemptGate,
        credential_resolver: CredentialResolver,
        terminal_guard_ledger: _ResolverLifecycleLedger,
        credential_handle: CredentialHandle,
        attempt_permit: AttemptPermit,
        transport_claim_id: UUID,
        terminal_guard_id: UUID,
        terminal_guard_digest: Digest256,
    ) -> bool:
        with self._lock:
            return (
                self._coordination_owner is owner
                and self._state == "coordinating"
                and self._gate is gate
                and self._credential_resolver is credential_resolver
                and self._ready_ledger is terminal_guard_ledger
                and self._credential_handle is credential_handle
                and self._attempt is attempt_permit
                and self._claim_id == transport_claim_id
                and self._terminal_guard_id == terminal_guard_id
                and self._terminal_guard_digest == terminal_guard_digest
            )

    def publish_recoverable(self, owner: object) -> None:
        with self._lock:
            self._require_coordinating_locked(owner)
            self._prepared_published = True
            self._state = "recoverable"

    def prepared_publication_is_committed(self, owner: object) -> bool:
        with self._lock:
            return (
                self._prepared_published
                and self._state in ("recoverable", "terminal")
                and (
                    self._coordination_owner is owner
                    or self._state == "terminal"
                )
            )

    def _helper_terminal_locked(self, errors: list[BaseException]) -> bool:
        launcher = self._launcher
        if type(launcher) is not ResolverHelperLauncher:
            return False
        ticket = self._ready_ticket
        if ticket is None:
            try:
                launcher._recover_lifecycle_reservation(
                    reservation_owner=self._ready_reservation_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            except BaseException as error:
                errors.append(error)
            try:
                return launcher._lifecycle_reservation_is_absent_for_cleanup(
                    reservation_owner=self._ready_reservation_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            except BaseException as error:
                errors.append(error)
                return False

        try:
            launcher._recover_ready_publication_for_cleanup(
                ticket,
                launch_owner=self._ready_launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        except BaseException as error:
            errors.append(error)
        try:
            launcher._recover_lifecycle_reservation(
                reservation_owner=self._ready_reservation_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        except BaseException as error:
            errors.append(error)
        try:
            return launcher._ready_publication_is_terminal_for_cleanup(
                ticket,
                reservation_owner=self._ready_reservation_owner,
                launch_owner=self._ready_launch_owner,
                ledger=self._ready_ledger,
                capability_snapshot=self._ready_capability_snapshot,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        except BaseException as error:
            errors.append(error)
            return False

    def _attempt_terminal_locked(self, errors: list[BaseException]) -> bool:
        if not self._attempt_started:
            return True
        gate = self._gate
        permit = self._credential_permit
        handle_id = self._credential_handle_id
        handle_digest = self._credential_handle_digest
        if (
            type(gate) is not AttemptGate
            or type(permit) is not CredentialResolutionPermit
            or type(handle_id) is not UUID
            or type(handle_digest) is not Digest256
        ):
            return False
        if self._attempt is not None and type(self._claim_id) is UUID:
            try:
                gate._recover_attempt_for_cleanup(
                    self._attempt,
                    credential_permit=permit,
                    credential_handle_id=handle_id,
                    credential_handle_digest=handle_digest,
                    claim_id=self._claim_id,
                    guard_id=self._terminal_guard_id,
                    guard_digest=self._terminal_guard_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException as error:
                errors.append(error)
        try:
            gate._recover_published_attempt_for_cleanup(
                credential_permit=permit,
                credential_handle_id=handle_id,
                credential_handle_digest=handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException as error:
            errors.append(error)
        try:
            state = gate._attempt_terminal_state_for_cleanup(
                credential_permit=permit,
                credential_handle_id=handle_id,
                credential_handle_digest=handle_digest,
                attempt=self._attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException as error:
            errors.append(error)
            return False
        return state in ("absent", "terminal")

    def _credential_terminal_locked(
        self,
        errors: list[BaseException],
        *,
        raise_errors: bool,
    ) -> bool:
        resolver = self._credential_resolver
        gate = self._gate
        permit = self._credential_permit
        if (
            type(resolver) is not CredentialResolver
            or type(gate) is not AttemptGate
            or type(permit) is not CredentialResolutionPermit
        ):
            return False

        publication_id = self._credential_publication_id
        publication_state = "absent"
        close_failed = False
        if type(publication_id) is UUID:
            if self._credential_handle is not None:
                try:
                    resolver.close(self._credential_handle)
                except BaseException as error:
                    errors.append(error)
                    close_failed = True
            if not close_failed or not raise_errors:
                try:
                    resolver._recover_published_handle_for_cleanup(
                        permit,
                        publication_id=publication_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                except BaseException as error:
                    errors.append(error)
                try:
                    resolver._recover_published_handle_state_for_cleanup(
                        permit,
                        publication_id=publication_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                except BaseException as error:
                    errors.append(error)
            try:
                publication_state = (
                    resolver._published_handle_terminal_state_for_cleanup(
                        permit,
                        publication_id=publication_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )
            except BaseException as error:
                errors.append(error)
                publication_state = "ambiguous"

        if publication_state == "absent":
            try:
                gate.abandon_credential_resolution(permit)
            except BaseException as error:
                errors.append(error)
        try:
            gate_terminal = gate._credential_resolution_is_terminal_for_cleanup(
                permit,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        except BaseException as error:
            errors.append(error)
            gate_terminal = False
        return publication_state in ("absent", "closed") and gate_terminal

    def _release_resource_refs_locked(self) -> None:
        self._coordination_owner = None
        self._launcher = None
        self._credential_resolver = None
        self._gate = None
        self._credential_permit = None
        self._ready_reservation_owner = None
        self._ready_launch_owner = None
        self._ready_ticket = None
        self._ready_capability_snapshot = None
        self._ready_ledger = None
        self._credential_publication_id = None
        self._credential_handle = None
        self._credential_handle_id = None
        self._credential_handle_digest = None
        self._attempt = None
        self._claim_id = None
        self._terminal_guard_id = None
        self._terminal_guard_digest = None

    def _resource_refs_are_released_locked(self) -> bool:
        return self._resources_terminal_proven and all(
            value is None
            for value in (
                self._coordination_owner,
                self._launcher,
                self._credential_resolver,
                self._gate,
                self._credential_permit,
                self._ready_reservation_owner,
                self._ready_launch_owner,
                self._ready_ticket,
                self._ready_capability_snapshot,
                self._ready_ledger,
                self._credential_publication_id,
                self._credential_handle,
                self._credential_handle_id,
                self._credential_handle_digest,
                self._attempt,
                self._claim_id,
                self._terminal_guard_id,
                self._terminal_guard_digest,
            )
        )

    def _retry_locked(self, *, raise_errors: bool) -> bool:
        errors: list[BaseException] = []
        self._state = "retrying"
        try:
            all_terminal = self._resources_terminal_proven
            if not all_terminal:
                helper_terminal = self._helper_terminal_locked(errors)
                attempt_terminal = False
                credential_terminal = False
                if helper_terminal:
                    attempt_terminal = self._attempt_terminal_locked(errors)
                if helper_terminal and attempt_terminal:
                    credential_terminal = self._credential_terminal_locked(
                        errors,
                        raise_errors=raise_errors,
                    )
                all_terminal = (
                    helper_terminal
                    and attempt_terminal
                    and credential_terminal
                )
                if all_terminal:
                    self._resources_terminal_proven = True
            if all_terminal:
                try:
                    self._release_resource_refs_locked()
                except BaseException as error:
                    errors.append(error)
                all_terminal = self._resource_refs_are_released_locked()
                if not all_terminal:
                    errors.append(
                        _coordinator_error(
                            "resolver cleanup resource release 未提交。"
                        )
                    )
            self._state = "terminal" if all_terminal else "recoverable"
            if raise_errors and errors:
                raise errors[0]
            return all_terminal
        finally:
            if self._state == "retrying":
                self._state = "recoverable"

    def fail_and_retry(self, owner: object) -> bool:
        """Internal failure path; never retain or replace the primary error."""

        with self._lock:
            if self._coordination_owner is not owner:
                return False
            if self._state == "terminal":
                return True
            if self._state == "coordinating":
                self._state = "recoverable"
            if self._state != "recoverable":
                return False
            return self._retry_locked(raise_errors=False)

    def retry_cleanup(self, ticket: "ResolverCleanupTicket") -> bool:
        with self._lock:
            if self._ticket is not ticket:
                return False
            if self._state == "terminal":
                return True
            if self._state in ("issued", "coordinating", "retrying"):
                return False
            if self._state != "recoverable":
                return False
            try:
                return self._retry_locked(raise_errors=False)
            except BaseException:
                return False

    def retry_for_prepared(self, *, _authority: object | None = None) -> bool:
        if _authority is not _PREPARED_RESOLVER_ATTEMPT_AUTHORITY:
            raise TypeError("prepared cleanup requires coordinator authority")
        with self._lock:
            if self._state == "terminal":
                return True
            if self._state != "recoverable":
                return False
            return self._retry_locked(raise_errors=True)

    def is_terminal(self) -> bool:
        with self._lock:
            return self._state == "terminal"

    def safe_metadata(self, ticket: "ResolverCleanupTicket") -> dict[str, object]:
        with self._lock:
            if self._ticket is not ticket:
                return {
                    "policy_version": RESOLVER_COORDINATOR_POLICY_VERSION,
                    "state": "invalid",
                    "terminal": False,
                    "retryable": False,
                }
            return {
                "policy_version": RESOLVER_COORDINATOR_POLICY_VERSION,
                "state": self._state,
                "terminal": self._state == "terminal",
                "retryable": self._state == "recoverable",
            }


@runtime_final
class ResolverCleanupTicket:
    """Caller-owned, cleanup-only recovery handle issued before coordination."""

    __slots__ = ("policy_version", "_ledger", "_ledger_snapshot")

    def __init__(
        self,
        ledger: _ResolverCoordinationRecoveryLedger,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RESOLVER_CLEANUP_TICKET_AUTHORITY:
            raise TypeError("ResolverCleanupTicket requires its factory")
        if type(ledger) is not _ResolverCoordinationRecoveryLedger:
            raise TypeError("ledger must be resolver recovery ledger")
        object.__setattr__(
            self,
            "policy_version",
            RESOLVER_COORDINATOR_POLICY_VERSION,
        )
        object.__setattr__(self, "_ledger", ledger)
        object.__setattr__(self, "_ledger_snapshot", ledger)
        ledger.attach_ticket(
            self,
            _authority=_RESOLVER_CLEANUP_TICKET_AUTHORITY,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverCleanupTicket is immutable")

    def __copy__(self) -> "ResolverCleanupTicket":
        raise TypeError("ResolverCleanupTicket cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> "ResolverCleanupTicket":
        del memo
        raise TypeError("ResolverCleanupTicket cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("ResolverCleanupTicket cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("ResolverCleanupTicket cannot be serialized")

    def __repr__(self) -> str:
        metadata = self.safe_metadata()
        return f"ResolverCleanupTicket(state={metadata['state']!r})"

    @property
    def is_terminal(self) -> bool:
        return bool(self.safe_metadata()["terminal"])

    def safe_metadata(self) -> dict[str, object]:
        return self._ledger_snapshot.safe_metadata(self)

    def retry_cleanup(self) -> bool:
        return self._ledger_snapshot.retry_cleanup(self)


def issue_resolver_cleanup_ticket() -> ResolverCleanupTicket:
    """Issue an inert recovery owner before any resolver-side operation."""

    ledger = _ResolverCoordinationRecoveryLedger()
    ticket = ResolverCleanupTicket(
        ledger,
        _authority=_RESOLVER_CLEANUP_TICKET_AUTHORITY,
    )
    if not ledger.ticket_is_attached(ticket):
        raise _coordinator_error("resolver cleanup ticket issuance 未提交。")
    return ticket


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
        "_recovery_ledger_snapshot",
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
        recovery_ledger: _ResolverCoordinationRecoveryLedger,
        coordination_owner: object,
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
        if type(recovery_ledger) is not _ResolverCoordinationRecoveryLedger:
            raise TypeError("recovery_ledger must be resolver recovery ledger")
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
        if not recovery_ledger.prepared_inputs_are_exact(
            coordination_owner,
            gate=gate,
            credential_resolver=credential_resolver,
            terminal_guard_ledger=terminal_guard_ledger,
            credential_handle=credential_handle,
            attempt_permit=attempt_permit,
            transport_claim_id=transport_claim_id,
            terminal_guard_id=terminal_guard_id,
            terminal_guard_digest=terminal_guard_digest,
        ):
            raise _coordinator_error("resolver cleanup ledger owner proof 不匹配。")
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
            ("_recovery_ledger_snapshot", recovery_ledger),
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

    def _sync_terminal_state_locked(self) -> None:
        if (
            self._status != "closed"
            and self._recovery_ledger_snapshot.is_terminal()
        ):
            object.__setattr__(self, "_status", "closed")

    def _sync_terminal_state(
        self,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PREPARED_RESOLVER_ATTEMPT_AUTHORITY:
            raise TypeError("prepared state sync requires coordinator authority")
        with self._lock:
            self._sync_terminal_state_locked()

    @property
    def is_closed(self) -> bool:
        with self._lock:
            self._sync_terminal_state_locked()
            return self._status == "closed"

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            self._sync_terminal_state_locked()
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
            self._sync_terminal_state_locked()
            if self._status == "closed":
                return False
            if self._status == "closing":
                raise _coordinator_error("resolver attempt 正在终结。")
            object.__setattr__(self, "_status", "closing")
            try:
                all_terminal = (
                    self._recovery_ledger_snapshot.retry_for_prepared(
                        _authority=_PREPARED_RESOLVER_ATTEMPT_AUTHORITY,
                    )
                )
            except BaseException:
                object.__setattr__(
                    self,
                    "_status",
                    (
                        "closed"
                        if self._recovery_ledger_snapshot.is_terminal()
                        else "active"
                    ),
                )
                raise
            object.__setattr__(
                self,
                "_status",
                "closed" if all_terminal else "active",
            )
            if not all_terminal:
                raise _coordinator_error("resolver attempt 未能证明完整终结。")
            return True


def coordinate_resolver_attempt(
    *,
    launcher: ResolverHelperLauncher,
    credential_resolver: CredentialResolver,
    gate: AttemptGate,
    credential_permit: CredentialResolutionPermit,
    cleanup_ticket: ResolverCleanupTicket,
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
    if type(cleanup_ticket) is not ResolverCleanupTicket:
        raise TypeError("cleanup_ticket must be ResolverCleanupTicket")
    if credential_permit._attempt_gate is not gate:
        raise _coordinator_error("credential permit 不属于当前 AttemptGate。")
    recovery_ledger = cleanup_ticket._ledger_snapshot
    if type(recovery_ledger) is not _ResolverCoordinationRecoveryLedger:
        raise _coordinator_error("resolver cleanup ticket ledger 无效。")
    coordination_owner = object()
    try:
        (
            ready_reservation_owner,
            ready_launch_owner,
        ) = recovery_ledger.bind_coordination(
            cleanup_ticket,
            coordination_owner=coordination_owner,
            launcher=launcher,
            credential_resolver=credential_resolver,
            gate=gate,
            credential_permit=credential_permit,
        )
        if not recovery_ledger.coordination_is_exact(
            cleanup_ticket,
            coordination_owner,
            launcher=launcher,
            credential_resolver=credential_resolver,
            gate=gate,
            credential_permit=credential_permit,
            reservation_owner=ready_reservation_owner,
            launch_owner=ready_launch_owner,
        ):
            raise _coordinator_error("resolver cleanup ticket bind 未提交。")
    except BaseException:
        try:
            recovery_ledger.fail_and_retry(coordination_owner)
        except BaseException:
            pass
        raise

    pre_guard: PreAttemptResolverGuard | None = None
    terminal_guard: AttemptTerminalGuard | None = None
    credential_handle: CredentialHandle | None = None
    credential_handle_id: UUID | None = None
    credential_handle_digest: Digest256 | None = None
    attempt: AttemptPermit | None = None
    terminal_guard_id: UUID | None = None
    terminal_guard_digest: Digest256 | None = None
    credential_publication_id: UUID | None = None
    ready_ledger_snapshot: _ResolverLifecycleLedger | None = None
    attempt_permit_id: UUID | None = None
    attempt_permit_digest: Digest256 | None = None
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
        recovery_ledger.record_ready_ticket(
            coordination_owner,
            ready_publication_ticket,
            ready_capability_snapshot,
        )
        if not recovery_ledger.ready_ticket_is_exact(
            coordination_owner,
            ready_publication_ticket,
            ready_capability_snapshot,
        ):
            raise _coordinator_error("resolver READY ticket recovery 未提交。")
        transport_claim_id = ready_capability_snapshot.transport_claim_id
        dns_start_id = ready_capability_snapshot.dns_start_id
    except BaseException:
        try:
            recovery_ledger.fail_and_retry(coordination_owner)
        except BaseException:
            pass
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
            recovery_ledger.record_ready_ledger(
                coordination_owner,
                ready_ledger_snapshot,
            )
            if not recovery_ledger.ready_ledger_is_exact(
                coordination_owner,
                ready_ledger_snapshot,
            ):
                raise _coordinator_error("resolver READY ledger recovery 未提交。")
            pre_guard = candidate_pre_guard
        except BaseException:
            # Cleanup is performed inside the launcher against the exact
            # pre-created launch owner.  No live guard is returned to this
            # exception path, and a concurrent loser cannot steal a winner.
            try:
                launcher._recover_ready_publication_for_cleanup(
                    ready_publication_ticket,
                    launch_owner=ready_launch_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
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
        recovery_ledger.begin_credential_publication(
            coordination_owner,
            credential_publication_id,
        )
        if not recovery_ledger.credential_publication_is_exact(
            coordination_owner,
            credential_publication_id,
        ):
            raise _coordinator_error("credential publication recovery 未提交。")
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
        recovery_ledger.record_credential_handle(
            coordination_owner,
            candidate_credential_handle,
            handle_id=credential_handle_id,
            handle_digest=credential_handle_digest,
        )
        if not recovery_ledger.credential_handle_is_exact(
            coordination_owner,
            candidate_credential_handle,
            handle_id=credential_handle_id,
            handle_digest=credential_handle_digest,
        ):
            raise _coordinator_error("credential handle recovery 未提交。")

        recovery_ledger.begin_attempt_publication(coordination_owner)
        if not recovery_ledger.attempt_publication_is_started(
            coordination_owner
        ):
            raise _coordinator_error("attempt publication recovery 未提交。")
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
        candidate_attempt_is_expected = (
            type(attempt) is AttemptPermit
            and attempt._attempt_gate is gate
            and attempt.credential_permit_id == credential_permit.permit_id
            and attempt.credential_permit_digest == credential_permit.permit_digest
            and attempt.credential_handle_id == credential_handle_id
            and attempt.credential_handle_digest == credential_handle_digest
        )
        recovery_ledger.record_attempt(coordination_owner, attempt)
        if (
            candidate_attempt_is_expected
            and not recovery_ledger.attempt_is_exact(
                coordination_owner,
                attempt,
            )
        ):
            raise _coordinator_error("attempt owner recovery 未提交。")

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
                    ready_ledger_snapshot.recover_transferred_guard_for_cleanup(
                        pre_guard,
                        attempt_permit_id=attempt_permit_id,
                        attempt_permit_digest=attempt_permit_digest,
                    )
                else:
                    pre_guard._recover_transferred_guard_for_cleanup(
                        attempt_permit_id=attempt_permit_id,
                        attempt_permit_digest=attempt_permit_digest,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
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
        recovery_ledger.record_terminal_guard(
            coordination_owner,
            guard_id=terminal_guard_id,
            guard_digest=terminal_guard_digest,
        )
        if not recovery_ledger.terminal_guard_is_exact(
            coordination_owner,
            guard_id=terminal_guard_id,
            guard_digest=terminal_guard_digest,
        ):
            raise _coordinator_error("terminal guard recovery 未提交。")
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
        prepared = PreparedResolverAttempt(
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
            recovery_ledger=recovery_ledger,
            coordination_owner=coordination_owner,
            _authority=_PREPARED_RESOLVER_ATTEMPT_AUTHORITY,
        )
        recovery_ledger.publish_recoverable(coordination_owner)
        if not recovery_ledger.prepared_publication_is_committed(
            coordination_owner
        ):
            raise _coordinator_error("resolver cleanup ticket publication 未提交。")
        prepared._sync_terminal_state(
            _authority=_PREPARED_RESOLVER_ATTEMPT_AUTHORITY,
        )
        return prepared
    except BaseException:
        try:
            recovery_ledger.fail_and_retry(coordination_owner)
        except BaseException:
            pass
        raise


__all__ = [
    "RESOLVER_COORDINATOR_POLICY_VERSION",
    "PreparedResolverAttempt",
    "ResolverCleanupTicket",
    "coordinate_resolver_attempt",
    "issue_resolver_cleanup_ticket",
]
