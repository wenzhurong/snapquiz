"""Two-stage, zero-I/O attempt authority for W09-A.

This module authorizes credential resolution and, only after a trusted resolver
confirms the exact non-secret binding, reserves one network attempt.  It never
reads a credential, environment variable, file, socket or network response.

The nested live-authority order is fixed and uniform for both stages::

    ConsentLedger -> EgressApprovalLedger -> SendSessionLedger
    -> RegistryPolicyAuthorityLedger -> CallContextLedger

The final CallContext transition either performs a pure credential preflight or
atomically consumes all applicable attempt budgets.
"""
from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Callable, TypeVar
from uuid import UUID, uuid4, uuid5

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.domain.plan import (
    ExecutionPlanNetworkOperation,
    ExecutionPlanStage,
)
from snapquiz.domain.policy import ContractMarker
from snapquiz.pipelines.contracts import StageInvocation
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentLedger,
    _CONSENT_ATTEMPT_AUTHORITY,
)
from snapquiz.privacy.egress import (
    EgressApprovalLedger,
    _EGRESS_ATTEMPT_AUTHORITY,
    _validate_exact_egress_binding_for_session,
)
from snapquiz.routing.planner import PlannedExecution
from snapquiz.runtime.authority import (
    RegistryPolicyAuthorityLedger,
    _ATTEMPT_AUTHORITY,
)
from snapquiz.runtime.clock import ClockSample, MonotonicDeadline
from snapquiz.runtime.context import (
    AttemptBudgetReservation,
    CallContext,
    CallContextLedger,
    CancellationToken,
    _ATTEMPT_BUDGET_AUTHORITY,
)
from snapquiz.transport.session import (
    AuthorizedSendSession,
    SendSessionLedger,
    _SESSION_ATTEMPT_AUTHORITY,
)


CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION = (
    "snapquiz.credential-resolution-permit.v1"
)
ATTEMPT_PERMIT_SCHEMA_VERSION = "snapquiz.attempt-permit.v2"
HELPER_STOP_AUTHORITY_SCHEMA_VERSION = "snapquiz.helper-stop-authority.v1"
HELPER_WAIT_SLICE_SCHEMA_VERSION = "snapquiz.helper-wait-slice.v1"
HELPER_WAIT_QUANTUM_NS = 50_000_000

_PERMIT_FACTORY_AUTHORITY = object()
_PERMIT_RELEASE_AUTHORITY = object()
_CREDENTIAL_RESOLVER_AUTHORITY = object()
_TRANSPORT_ATTEMPT_AUTHORITY = object()
_HELPER_STOP_FACTORY_AUTHORITY = object()
_HELPER_WAIT_SLICE_FACTORY_AUTHORITY = object()
_CREDENTIAL_PERMIT_UUID_NAMESPACE = UUID(
    "f1112d3e-51ad-53f4-b70f-c05a8a3cd5c6"
)
_ATTEMPT_PERMIT_UUID_NAMESPACE = UUID(
    "fc6dc07a-2dcb-509f-8ca4-52fcbd77d07b"
)
_HELPER_STOP_UUID_NAMESPACE = UUID(
    "2c12c850-3e72-52b3-b5fa-83efacebfb63"
)
_HELPER_WAIT_SLICE_UUID_NAMESPACE = UUID(
    "4ee0cb29-f86b-58cf-bf84-fd8c8d1b69e7"
)
_T = TypeVar("_T")


def _attempt_error(message: str) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="attempt_gate",
        retryable=False,
        safe_message=message,
    )


def _binding_payload(value: Digest256 | ContractMarker) -> object:
    return value.value if isinstance(value, ContractMarker) else value


def _require_credential_binding(
    value: Digest256 | ContractMarker,
) -> None:
    if value is ContractMarker.NOT_APPLICABLE:
        return
    if isinstance(value, ContractMarker):
        raise ValueError("credential binding cannot be unknown")
    require_digest(value, "credential_binding_digest")


def _credential_permit_payload(
    permit: "CredentialResolutionPermit",
) -> dict[str, object]:
    return {
        "permit_id": permit.permit_id,
        "gate_id": permit.gate_id,
        "sequence": permit.sequence,
        "context_id": permit.context_id,
        "context_digest": permit.context_digest,
        "session_id": permit.session_id,
        "session_terms_digest": permit.session_terms_digest,
        "request_envelope_digest": permit.request_envelope_digest,
        "credential_binding_digest": _binding_payload(
            permit.credential_binding_digest
        ),
        "registry_policy_lease_id": permit.registry_policy_lease_id,
        "registry_policy_lease_digest": permit.registry_policy_lease_digest,
        "authorized_at": permit.authorized_at,
        "authorized_monotonic_ns": permit.authorized_monotonic_ns,
    }


def _credential_permit_identifier_payload(
    permit: "CredentialResolutionPermit",
) -> dict[str, object]:
    return {
        "gate_id": permit.gate_id,
        "sequence": permit.sequence,
        "context_id": permit.context_id,
        "session_id": permit.session_id,
        "request_envelope_digest": permit.request_envelope_digest,
        "credential_binding_digest": _binding_payload(
            permit.credential_binding_digest
        ),
        "authorized_at": permit.authorized_at,
        "authorized_monotonic_ns": permit.authorized_monotonic_ns,
    }


def _credential_permit_id_for(
    permit: "CredentialResolutionPermit",
) -> UUID:
    return uuid5(
        _CREDENTIAL_PERMIT_UUID_NAMESPACE,
        str(
            digest256(
                "CredentialResolutionPermitIdentifier",
                CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION,
                _credential_permit_identifier_payload(permit),
            )
        ),
    )


@runtime_final
class CredentialResolutionPermit:
    """Factory-only authority to resolve one exact session binding once."""

    __slots__ = (
        "permit_id",
        "gate_id",
        "sequence",
        "context_id",
        "context_digest",
        "session_id",
        "session_terms_digest",
        "request_envelope_digest",
        "credential_binding_digest",
        "registry_policy_lease_id",
        "registry_policy_lease_digest",
        "authorized_at",
        "authorized_monotonic_ns",
        "permit_digest",
        "_issued_sequence",
        "_source_sample",
        "_issued_digest",
        "_attempt_gate",
        "_planned",
        "_invocation",
        "_prepared",
        "_authorization",
        "_consent_ledger",
        "_session",
        "_approval_ledger",
        "_session_ledger",
        "_authority_ledger",
        "_context",
        "_context_ledger",
        "_released",
    )

    def __init__(
        self,
        *,
        gate_id: UUID,
        sequence: int,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        session: AuthorizedSendSession,
        approval_ledger: EgressApprovalLedger,
        session_ledger: SendSessionLedger,
        authority_ledger: RegistryPolicyAuthorityLedger,
        context: CallContext,
        context_ledger: CallContextLedger,
        sample: ClockSample,
        attempt_gate: "AttemptGate",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMIT_FACTORY_AUTHORITY:
            raise TypeError("credential permits require AttemptGate")
        require_uuid(gate_id, "gate_id")
        require_plain_int(sequence, "sequence", minimum=1)
        sample.validate_integrity()
        identifier = {
            "gate_id": gate_id,
            "sequence": sequence,
            "context_id": context.context_id,
            "session_id": session.session_id,
            "request_envelope_digest": prepared.request_envelope_digest,
            "credential_binding_digest": _binding_payload(
                prepared.credential_binding_digest
            ),
            "authorized_at": sample.wall_time,
            "authorized_monotonic_ns": sample.monotonic_after_ns,
        }
        permit_id = uuid5(
            _CREDENTIAL_PERMIT_UUID_NAMESPACE,
            str(
                digest256(
                    "CredentialResolutionPermitIdentifier",
                    CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION,
                    identifier,
                )
            ),
        )
        values = (
            ("permit_id", permit_id),
            ("gate_id", gate_id),
            ("sequence", sequence),
            ("context_id", context.context_id),
            ("context_digest", context.context_digest),
            ("session_id", session.session_id),
            ("session_terms_digest", session.session_terms_digest),
            ("request_envelope_digest", prepared.request_envelope_digest),
            ("credential_binding_digest", prepared.credential_binding_digest),
            (
                "registry_policy_lease_id",
                context.registry_policy_lease.lease_id,
            ),
            (
                "registry_policy_lease_digest",
                context.registry_policy_lease.lease_digest,
            ),
            ("authorized_at", sample.wall_time),
            ("authorized_monotonic_ns", sample.monotonic_after_ns),
            ("_issued_sequence", sequence),
            ("_source_sample", sample),
            ("_attempt_gate", attempt_gate),
            ("_planned", planned),
            ("_invocation", invocation),
            ("_prepared", prepared),
            ("_authorization", authorization),
            ("_consent_ledger", consent_ledger),
            ("_session", session),
            ("_approval_ledger", approval_ledger),
            ("_session_ledger", session_ledger),
            ("_authority_ledger", authority_ledger),
            ("_context", context),
            ("_context_ledger", context_ledger),
            ("_released", False),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "permit_digest",
            digest256(
                "CredentialResolutionPermit",
                CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION,
                _credential_permit_payload(self),
            ),
        )
        object.__setattr__(self, "_issued_digest", self.permit_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CredentialResolutionPermit is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "CredentialResolutionPermit":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "CredentialResolutionPermit("
            f"permit_id={self.permit_id!r}, context_id={self.context_id!r}, "
            f"session_id={self.session_id!r})"
        )

    def validate_integrity(self) -> None:
        for name in (
            "permit_id",
            "gate_id",
            "context_id",
            "session_id",
            "registry_policy_lease_id",
        ):
            require_uuid(getattr(self, name), name)
        require_plain_int(self.sequence, "sequence", minimum=1)
        require_plain_int(self._issued_sequence, "issued_sequence", minimum=1)
        for name in (
            "context_digest",
            "session_terms_digest",
            "request_envelope_digest",
            "registry_policy_lease_digest",
            "permit_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        _require_credential_binding(self.credential_binding_digest)
        require_aware_datetime(self.authorized_at, "authorized_at")
        require_plain_int(
            self.authorized_monotonic_ns,
            "authorized_monotonic_ns",
        )
        if type(self._attempt_gate) is not AttemptGate:
            raise ValueError("attempt gate authority changed")
        if (
            self.gate_id != self._attempt_gate._gate_id
            or self.permit_id != _credential_permit_id_for(self)
            or self.sequence != self._issued_sequence
            or type(self._source_sample) is not ClockSample
            or self.authorized_at != self._source_sample.wall_time
            or self.authorized_monotonic_ns
            != self._source_sample.monotonic_after_ns
        ):
            raise ValueError("credential permit identifier changed")
        self._source_sample.validate_integrity()
        if type(self._released) is not bool:
            raise ValueError("credential permit release state changed")
        sensitive = (
            self._planned,
            self._invocation,
            self._prepared,
            self._authorization,
            self._consent_ledger,
            self._session,
            self._approval_ledger,
            self._session_ledger,
            self._authority_ledger,
            self._context,
            self._context_ledger,
        )
        if self._released:
            if any(value is not None for value in sensitive):
                raise ValueError("released credential permit retains authority")
        else:
            if type(self._context_ledger) is not CallContextLedger:
                raise ValueError("context ledger authority changed")
            if (
                type(self._planned) is not PlannedExecution
                or type(self._invocation) is not StageInvocation
                or type(self._prepared) is not PreparedOutbound
                or type(self._authorization) is not AuthorizationContext
                or type(self._consent_ledger) is not ConsentLedger
                or type(self._session) is not AuthorizedSendSession
                or type(self._approval_ledger) is not EgressApprovalLedger
                or type(self._session_ledger) is not SendSessionLedger
                or type(self._authority_ledger)
                is not RegistryPolicyAuthorityLedger
                or type(self._context) is not CallContext
                or type(self._context_ledger) is not CallContextLedger
            ):
                raise ValueError("credential permit authority type changed")
            self._planned.validate_integrity()
            self._invocation.validate_integrity()
            self._prepared.validate_integrity()
            self._authorization.validate_integrity()
            self._session.validate_integrity()
            self._context.validate_integrity()
            if (
                self._context._context_ledger is not self._context_ledger
                or self._session._approval_ledger is not self._approval_ledger
                or self._session._session_ledger is not self._session_ledger
                or self._context.registry_policy_lease._authority_ledger
                is not self._authority_ledger
                or self.context_id != self._context.context_id
                or self.context_digest != self._context.context_digest
                or self.session_id != self._session.session_id
                or self.session_terms_digest != self._session.session_terms_digest
                or self.request_envelope_digest
                != self._prepared.request_envelope_digest
                or self.credential_binding_digest
                != self._prepared.credential_binding_digest
                or self.registry_policy_lease_id
                != self._context.registry_policy_lease.lease_id
                or self.registry_policy_lease_digest
                != self._context.registry_policy_lease.lease_digest
                or self._planned
                is not self._context.registry_policy_lease._planned_execution
                or self._authorization._consent_ledger
                is not self._consent_ledger
                or self._context.request_id != self._planned.plan.request_id
                or self._context.plan_id != self._planned.plan.plan_id
                or self._context.plan_digest != self._planned.plan.plan_digest
                or self._context.planned_execution_digest
                != self._planned.planned_execution_digest
                or self._session.invocation_id != self._invocation.invocation_id
                or self._session.invocation_digest
                != self._invocation.invocation_digest
                or self._session.privacy_authorization_id
                != self._authorization.authorization_id
                or self._session.privacy_authorization_digest
                != self._authorization.authorization_digest
            ):
                raise ValueError("credential permit exact binding changed")
        if (
            self.permit_digest != self._issued_digest
            or self.permit_digest
            != digest256(
                "CredentialResolutionPermit",
                CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION,
                _credential_permit_payload(self),
            )
        ):
            raise ValueError("credential permit integrity mismatch")

    def _release_authority_refs(
        self,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMIT_RELEASE_AUTHORITY:
            raise TypeError("permit cleanup requires AttemptGate")
        if self._released:
            return
        for name in (
            "_planned",
            "_invocation",
            "_prepared",
            "_authorization",
            "_consent_ledger",
            "_session",
            "_approval_ledger",
            "_session_ledger",
            "_authority_ledger",
            "_context",
            "_context_ledger",
        ):
            object.__setattr__(self, name, None)
        object.__setattr__(self, "_released", True)

    def safe_metadata(self) -> dict[str, object]:
        return {
            "permit_id": str(self.permit_id),
            "context_id": str(self.context_id),
            "session_id": str(self.session_id),
            "credential_required": (
                self.credential_binding_digest
                is not ContractMarker.NOT_APPLICABLE
            ),
            "authorized_at": self.authorized_at,
        }


def _attempt_permit_payload(permit: "AttemptPermit") -> dict[str, object]:
    return {
        "attempt_permit_id": permit.attempt_permit_id,
        "credential_permit_id": permit.credential_permit_id,
        "credential_permit_digest": permit.credential_permit_digest,
        "context_id": permit.context_id,
        "context_digest": permit.context_digest,
        "session_id": permit.session_id,
        "session_terms_digest": permit.session_terms_digest,
        "operation_id": permit.operation_id,
        "request_envelope_digest": permit.request_envelope_digest,
        "credential_binding_digest": _binding_payload(
            permit.credential_binding_digest
        ),
        "credential_handle_id": permit.credential_handle_id,
        "credential_handle_digest": permit.credential_handle_digest,
        "reservation_id": permit.reservation_id,
        "reservation_digest": permit.reservation_digest,
        "operation_attempt": permit.operation_attempt,
        "global_attempt": permit.global_attempt,
        "billable_attempt": permit.billable_attempt,
        "reserved_at": permit.reserved_at,
        "reserved_monotonic_ns": permit.reserved_monotonic_ns,
    }


def _attempt_permit_id_for(permit: "AttemptPermit") -> UUID:
    return uuid5(
        _ATTEMPT_PERMIT_UUID_NAMESPACE,
        str(
            digest256(
                "AttemptPermitIdentifier",
                ATTEMPT_PERMIT_SCHEMA_VERSION,
                {
                    "credential_permit_id": permit.credential_permit_id,
                    "credential_handle_id": permit.credential_handle_id,
                    "credential_handle_digest": permit.credential_handle_digest,
                    "reservation_id": permit.reservation_id,
                    "reservation_digest": permit.reservation_digest,
                },
            )
        ),
    )


@runtime_final
class AttemptPermit:
    """Factory-only proof that one exact attempt owns all required budgets."""

    __slots__ = (
        "attempt_permit_id",
        "credential_permit_id",
        "credential_permit_digest",
        "context_id",
        "context_digest",
        "session_id",
        "session_terms_digest",
        "operation_id",
        "request_envelope_digest",
        "credential_binding_digest",
        "credential_handle_id",
        "credential_handle_digest",
        "reservation_id",
        "reservation_digest",
        "operation_attempt",
        "global_attempt",
        "billable_attempt",
        "reserved_at",
        "reserved_monotonic_ns",
        "attempt_permit_digest",
        "_issued_digest",
        "_attempt_gate",
        "_credential_permit",
        "_reservation",
        "_context_ledger",
        "_released",
    )

    def __init__(
        self,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
        reservation: AttemptBudgetReservation,
        attempt_gate: "AttemptGate",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMIT_FACTORY_AUTHORITY:
            raise TypeError("attempt permits require AttemptGate")
        require_uuid(credential_handle_id, "credential_handle_id")
        require_digest(credential_handle_digest, "credential_handle_digest")
        identifier = {
            "credential_permit_id": credential_permit.permit_id,
            "credential_handle_id": credential_handle_id,
            "credential_handle_digest": credential_handle_digest,
            "reservation_id": reservation.reservation_id,
            "reservation_digest": reservation.reservation_digest,
        }
        attempt_permit_id = uuid5(
            _ATTEMPT_PERMIT_UUID_NAMESPACE,
            str(
                digest256(
                    "AttemptPermitIdentifier",
                    ATTEMPT_PERMIT_SCHEMA_VERSION,
                    identifier,
                )
            ),
        )
        values = (
            ("attempt_permit_id", attempt_permit_id),
            ("credential_permit_id", credential_permit.permit_id),
            ("credential_permit_digest", credential_permit.permit_digest),
            ("context_id", reservation.context_id),
            ("context_digest", credential_permit.context_digest),
            ("session_id", reservation.session_id),
            (
                "session_terms_digest",
                credential_permit.session_terms_digest,
            ),
            ("operation_id", reservation.operation_id),
            (
                "request_envelope_digest",
                reservation.request_envelope_digest,
            ),
            (
                "credential_binding_digest",
                credential_permit.credential_binding_digest,
            ),
            ("credential_handle_id", credential_handle_id),
            ("credential_handle_digest", credential_handle_digest),
            ("reservation_id", reservation.reservation_id),
            ("reservation_digest", reservation.reservation_digest),
            ("operation_attempt", reservation.operation_attempt),
            ("global_attempt", reservation.global_attempt),
            ("billable_attempt", reservation.billable_attempt),
            ("reserved_at", reservation.reserved_wall_at),
            (
                "reserved_monotonic_ns",
                reservation.reserved_monotonic_ns,
            ),
            ("_attempt_gate", attempt_gate),
            ("_credential_permit", credential_permit),
            ("_reservation", reservation),
            ("_context_ledger", reservation._context_ledger),
            ("_released", False),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "attempt_permit_digest",
            digest256(
                "AttemptPermit",
                ATTEMPT_PERMIT_SCHEMA_VERSION,
                _attempt_permit_payload(self),
            ),
        )
        object.__setattr__(
            self,
            "_issued_digest",
            self.attempt_permit_digest,
        )
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AttemptPermit is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "AttemptPermit":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "AttemptPermit("
            f"attempt_permit_id={self.attempt_permit_id!r}, "
            f"session_id={self.session_id!r}, "
            f"operation_attempt={self.operation_attempt!r})"
        )

    def validate_integrity(self) -> None:
        for name in (
            "attempt_permit_id",
            "credential_permit_id",
            "context_id",
            "session_id",
            "operation_id",
            "credential_handle_id",
            "reservation_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "credential_permit_digest",
            "context_digest",
            "session_terms_digest",
            "request_envelope_digest",
            "credential_handle_digest",
            "reservation_digest",
            "attempt_permit_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        _require_credential_binding(self.credential_binding_digest)
        require_plain_int(self.operation_attempt, "operation_attempt", minimum=1)
        require_plain_int(self.global_attempt, "global_attempt", minimum=1)
        if self.billable_attempt is not None:
            require_plain_int(self.billable_attempt, "billable_attempt", minimum=1)
        require_aware_datetime(self.reserved_at, "reserved_at")
        require_plain_int(self.reserved_monotonic_ns, "reserved_monotonic_ns")
        if type(self._attempt_gate) is not AttemptGate:
            raise ValueError("attempt permit authority changed")
        if self.attempt_permit_id != _attempt_permit_id_for(self):
            raise ValueError("attempt permit identifier changed")
        if type(self._released) is not bool:
            raise ValueError("attempt permit release state changed")
        if self._released:
            if any(
                value is not None
                for value in (
                    self._credential_permit,
                    self._reservation,
                    self._context_ledger,
                )
            ):
                raise ValueError("released attempt permit retains authority")
        else:
            if (
                type(self._credential_permit) is not CredentialResolutionPermit
                or type(self._reservation) is not AttemptBudgetReservation
                or type(self._context_ledger) is not CallContextLedger
            ):
                raise ValueError("attempt permit authority changed")
            self._credential_permit.validate_integrity()
            self._reservation.validate_integrity()
            if (
                self._credential_permit._attempt_gate is not self._attempt_gate
                or self._reservation._context_ledger is not self._context_ledger
                or self.credential_permit_id != self._credential_permit.permit_id
                or self.credential_permit_digest
                != self._credential_permit.permit_digest
                or self.context_id != self._reservation.context_id
                or self.context_id != self._credential_permit.context_id
                or self.context_digest
                != self._credential_permit.context_digest
                or self.session_id != self._reservation.session_id
                or self.session_id != self._credential_permit.session_id
                or self.session_terms_digest
                != self._credential_permit.session_terms_digest
                or self.operation_id != self._reservation.operation_id
                or self.request_envelope_digest
                != self._reservation.request_envelope_digest
                or self.request_envelope_digest
                != self._credential_permit.request_envelope_digest
                or self.credential_binding_digest
                != self._credential_permit.credential_binding_digest
                or self.reservation_id != self._reservation.reservation_id
                or self.reservation_digest
                != self._reservation.reservation_digest
                or self.operation_attempt
                != self._reservation.operation_attempt
                or self.global_attempt != self._reservation.global_attempt
                or self.billable_attempt
                != self._reservation.billable_attempt
                or self.reserved_at != self._reservation.reserved_wall_at
                or self.reserved_monotonic_ns
                != self._reservation.reserved_monotonic_ns
            ):
                raise ValueError("attempt permit exact binding changed")
        if (
            self.attempt_permit_digest != self._issued_digest
            or self.attempt_permit_digest
            != digest256(
                "AttemptPermit",
                ATTEMPT_PERMIT_SCHEMA_VERSION,
                _attempt_permit_payload(self),
            )
        ):
            raise ValueError("attempt permit integrity mismatch")

    def _release_authority_refs(
        self,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMIT_RELEASE_AUTHORITY:
            raise TypeError("permit cleanup requires AttemptGate")
        if self._released:
            return
        for name in (
            "_credential_permit",
            "_reservation",
            "_context_ledger",
        ):
            object.__setattr__(self, name, None)
        object.__setattr__(self, "_released", True)

    def safe_metadata(self) -> dict[str, object]:
        return {
            "attempt_permit_id": str(self.attempt_permit_id),
            "context_id": str(self.context_id),
            "session_id": str(self.session_id),
            "credential_handle_id": str(self.credential_handle_id),
            "operation_attempt": self.operation_attempt,
            "global_attempt": self.global_attempt,
            "billable_attempt": self.billable_attempt,
        }


def _helper_stop_authority_payload(
    value: "HelperStopAuthority",
) -> dict[str, object]:
    return {
        "authority_id": value.authority_id,
        "gate_id": value.gate_id,
        "credential_permit_id": value.credential_permit_id,
        "credential_permit_digest": value.credential_permit_digest,
        "context_id": value.context_id,
        "context_digest": value.context_digest,
        "session_id": value.session_id,
        "session_terms_digest": value.session_terms_digest,
        "runtime_deadline_digest": value.runtime_deadline_digest,
        "cancellation_token_id": value.cancellation_token_id,
        "cancellation_token_digest": value.cancellation_token_digest,
        "effective_deadline_ns": value.effective_deadline_ns,
    }


@runtime_final
class HelperStopAuthority:
    """Exact live cancellation/deadline authority for one helper lifecycle."""

    __slots__ = (
        "authority_id",
        "authority_digest",
        "gate_id",
        "credential_permit_id",
        "credential_permit_digest",
        "context_id",
        "context_digest",
        "session_id",
        "session_terms_digest",
        "runtime_deadline_digest",
        "cancellation_token_id",
        "cancellation_token_digest",
        "effective_deadline_ns",
        "_issued_digest",
        "_attempt_gate",
        "_credential_permit",
        "_context",
        "_context_ledger",
        "_session",
        "_runtime_deadline",
        "_cancellation_token",
        "_released",
    )

    def __init__(
        self,
        *,
        credential_permit: CredentialResolutionPermit,
        context: CallContext,
        context_ledger: CallContextLedger,
        session: AuthorizedSendSession,
        effective_deadline_ns: int,
        attempt_gate: "AttemptGate",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _HELPER_STOP_FACTORY_AUTHORITY:
            raise TypeError("helper stop authority requires AttemptGate")
        if type(credential_permit) is not CredentialResolutionPermit:
            raise TypeError("credential_permit must be CredentialResolutionPermit")
        if type(context) is not CallContext:
            raise TypeError("context must be CallContext")
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        if type(session) is not AuthorizedSendSession:
            raise TypeError("session must be AuthorizedSendSession")
        if type(attempt_gate) is not AttemptGate:
            raise TypeError("attempt_gate must be AttemptGate")
        checked_deadline_ns = require_plain_int(
            effective_deadline_ns,
            "effective_deadline_ns",
            minimum=1,
        )
        runtime_deadline = context.runtime_deadline
        cancellation_token = context.cancellation_token
        if (
            credential_permit._attempt_gate is not attempt_gate
            or credential_permit._context is not context
            or credential_permit._context_ledger is not context_ledger
            or credential_permit._session is not session
            or context._context_ledger is not context_ledger
            or type(runtime_deadline) is not MonotonicDeadline
            or type(cancellation_token) is not CancellationToken
            or cancellation_token._context_ledger is not context_ledger
            or checked_deadline_ns
            > runtime_deadline.deadline_monotonic_ns
        ):
            raise _attempt_error("helper stop authority exact binding 无效。")
        identifier = {
            "gate_id": attempt_gate._gate_id,
            "credential_permit_id": credential_permit.permit_id,
            "credential_permit_digest": credential_permit.permit_digest,
            "context_id": context.context_id,
            "context_digest": context.context_digest,
            "session_id": session.session_id,
            "session_terms_digest": session.session_terms_digest,
            "runtime_deadline_digest": runtime_deadline.deadline_digest,
            "cancellation_token_id": cancellation_token.token_id,
            "cancellation_token_digest": cancellation_token.token_digest,
            "effective_deadline_ns": checked_deadline_ns,
        }
        authority_id = uuid5(
            _HELPER_STOP_UUID_NAMESPACE,
            str(
                digest256(
                    "HelperStopAuthorityIdentifier",
                    HELPER_STOP_AUTHORITY_SCHEMA_VERSION,
                    identifier,
                )
            ),
        )
        values = (
            ("authority_id", authority_id),
            ("gate_id", attempt_gate._gate_id),
            ("credential_permit_id", credential_permit.permit_id),
            ("credential_permit_digest", credential_permit.permit_digest),
            ("context_id", context.context_id),
            ("context_digest", context.context_digest),
            ("session_id", session.session_id),
            ("session_terms_digest", session.session_terms_digest),
            ("runtime_deadline_digest", runtime_deadline.deadline_digest),
            ("cancellation_token_id", cancellation_token.token_id),
            ("cancellation_token_digest", cancellation_token.token_digest),
            ("effective_deadline_ns", checked_deadline_ns),
            ("_attempt_gate", attempt_gate),
            ("_credential_permit", credential_permit),
            ("_context", context),
            ("_context_ledger", context_ledger),
            ("_session", session),
            ("_runtime_deadline", runtime_deadline),
            ("_cancellation_token", cancellation_token),
            ("_released", False),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        authority_digest = digest256(
            "HelperStopAuthority",
            HELPER_STOP_AUTHORITY_SCHEMA_VERSION,
            _helper_stop_authority_payload(self),
        )
        object.__setattr__(self, "authority_digest", authority_digest)
        object.__setattr__(self, "_issued_digest", authority_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("HelperStopAuthority is immutable")

    def __copy__(self) -> "HelperStopAuthority":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "HelperStopAuthority":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("HelperStopAuthority cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("HelperStopAuthority cannot be serialized")

    def __repr__(self) -> str:
        return (
            "HelperStopAuthority("
            f"authority_id={self.authority_id!r}, "
            f"context_id={self.context_id!r}, session_id={self.session_id!r})"
        )

    def validate_integrity(self) -> None:
        for name in (
            "authority_id",
            "gate_id",
            "credential_permit_id",
            "context_id",
            "session_id",
            "cancellation_token_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "authority_digest",
            "credential_permit_digest",
            "context_digest",
            "session_terms_digest",
            "runtime_deadline_digest",
            "cancellation_token_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        require_plain_int(
            self.effective_deadline_ns,
            "effective_deadline_ns",
            minimum=1,
        )
        if type(self._released) is not bool:
            raise ValueError("helper stop release state changed")
        references = (
            self._attempt_gate,
            self._credential_permit,
            self._context,
            self._context_ledger,
            self._session,
            self._runtime_deadline,
            self._cancellation_token,
        )
        if self._released:
            if any(value is not None for value in references):
                raise ValueError("released helper stop authority retains authority")
        else:
            if (
                type(self._attempt_gate) is not AttemptGate
                or type(self._credential_permit)
                is not CredentialResolutionPermit
                or type(self._context) is not CallContext
                or type(self._context_ledger) is not CallContextLedger
                or type(self._session) is not AuthorizedSendSession
                or type(self._runtime_deadline) is not MonotonicDeadline
                or type(self._cancellation_token) is not CancellationToken
            ):
                raise ValueError("helper stop authority reference changed")
            self._credential_permit.validate_integrity()
            self._context.validate_integrity()
            self._session.validate_integrity()
            self._runtime_deadline.validate_integrity()
            self._cancellation_token.validate_integrity()
            if (
                self.gate_id != self._attempt_gate._gate_id
                or self._credential_permit._attempt_gate is not self._attempt_gate
                or self.credential_permit_id
                != self._credential_permit.permit_id
                or self.credential_permit_digest
                != self._credential_permit.permit_digest
                or self._credential_permit._context is not self._context
                or self._credential_permit._context_ledger
                is not self._context_ledger
                or self._credential_permit._session is not self._session
                or self._context._context_ledger is not self._context_ledger
                or self.context_id != self._context.context_id
                or self.context_digest != self._context.context_digest
                or self.session_id != self._session.session_id
                or self.session_terms_digest
                != self._session.session_terms_digest
                or self._context.runtime_deadline is not self._runtime_deadline
                or self.runtime_deadline_digest
                != self._runtime_deadline.deadline_digest
                or self._context.cancellation_token
                is not self._cancellation_token
                or self._cancellation_token._context_ledger
                is not self._context_ledger
                or self.cancellation_token_id
                != self._cancellation_token.token_id
                or self.cancellation_token_digest
                != self._cancellation_token.token_digest
                or self.effective_deadline_ns
                > self._runtime_deadline.deadline_monotonic_ns
            ):
                raise ValueError("helper stop authority exact binding changed")
        expected_id = uuid5(
            _HELPER_STOP_UUID_NAMESPACE,
            str(
                digest256(
                    "HelperStopAuthorityIdentifier",
                    HELPER_STOP_AUTHORITY_SCHEMA_VERSION,
                    {
                        key: value
                        for key, value in _helper_stop_authority_payload(
                            self
                        ).items()
                        if key != "authority_id"
                    },
                )
            ),
        )
        if (
            self.authority_id != expected_id
            or self.authority_digest != self._issued_digest
            or self.authority_digest
            != digest256(
                "HelperStopAuthority",
                HELPER_STOP_AUTHORITY_SCHEMA_VERSION,
                _helper_stop_authority_payload(self),
            )
        ):
            raise ValueError("helper stop authority integrity mismatch")

    def _checkpoint(
        self,
        phase: str,
        *,
        _authority: object | None = None,
    ) -> "HelperWaitSlice":
        """Issue one bounded wait slice through the exact five-ledger path."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("helper checkpoint requires trusted transport")
        gate = self._attempt_gate
        if type(gate) is not AttemptGate:
            raise _attempt_error("helper stop authority 已终结。")
        return gate._checkpoint_helper_stop_authority(
            self,
            phase=phase,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )

    def _release_authority_refs(
        self,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMIT_RELEASE_AUTHORITY:
            raise TypeError("helper stop cleanup requires AttemptGate")
        if self._released:
            return
        for name in (
            "_attempt_gate",
            "_credential_permit",
            "_context",
            "_context_ledger",
            "_session",
            "_runtime_deadline",
            "_cancellation_token",
        ):
            object.__setattr__(self, name, None)
        object.__setattr__(self, "_released", True)

    def safe_metadata(self) -> dict[str, object]:
        return {
            "authority_id": str(self.authority_id),
            "context_id": str(self.context_id),
            "session_id": str(self.session_id),
            "effective_deadline_ns": self.effective_deadline_ns,
        }


def _helper_wait_slice_payload(value: "HelperWaitSlice") -> dict[str, object]:
    return {
        "slice_id": value.slice_id,
        "authority_id": value.authority_id,
        "authority_digest": value.authority_digest,
        "sequence": value.sequence,
        "phase": value.phase,
        "context_id": value.context_id,
        "session_id": value.session_id,
        "runtime_deadline_digest": value.runtime_deadline_digest,
        "cancellation_token_id": value.cancellation_token_id,
        "cancellation_token_digest": value.cancellation_token_digest,
        "effective_deadline_ns": value.effective_deadline_ns,
        "observed_monotonic_ns": value.observed_monotonic_ns,
        "remaining_ns": value.remaining_ns,
        "max_wait_ns": value.max_wait_ns,
    }


@runtime_final
class HelperWaitSlice:
    """Factory-only, single-checkpoint bound for one helper poll."""

    __slots__ = (
        "slice_id",
        "authority_id",
        "authority_digest",
        "sequence",
        "phase",
        "context_id",
        "session_id",
        "runtime_deadline_digest",
        "cancellation_token_id",
        "cancellation_token_digest",
        "effective_deadline_ns",
        "observed_monotonic_ns",
        "remaining_ns",
        "max_wait_ns",
        "slice_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        stop_authority: HelperStopAuthority,
        sequence: int,
        phase: str,
        effective_deadline_ns: int,
        observed_monotonic_ns: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _HELPER_WAIT_SLICE_FACTORY_AUTHORITY:
            raise TypeError("helper wait slices require AttemptGate")
        if type(stop_authority) is not HelperStopAuthority:
            raise TypeError("stop_authority must be HelperStopAuthority")
        stop_authority.validate_integrity()
        checked_sequence = require_plain_int(sequence, "sequence", minimum=1)
        checked_phase = require_text(phase, "phase", max_length=64)
        checked_deadline = require_plain_int(
            effective_deadline_ns,
            "effective_deadline_ns",
            minimum=1,
        )
        checked_observed = require_plain_int(
            observed_monotonic_ns,
            "observed_monotonic_ns",
        )
        if (
            checked_deadline != stop_authority.effective_deadline_ns
            or checked_observed >= checked_deadline
        ):
            raise _attempt_error("helper wait slice deadline 无效。")
        remaining_ns = checked_deadline - checked_observed
        max_wait_ns = min(remaining_ns, HELPER_WAIT_QUANTUM_NS)
        slice_id = uuid5(
            _HELPER_WAIT_SLICE_UUID_NAMESPACE,
            str(
                digest256(
                    "HelperWaitSliceIdentifier",
                    HELPER_WAIT_SLICE_SCHEMA_VERSION,
                    {
                        "authority_id": stop_authority.authority_id,
                        "authority_digest": stop_authority.authority_digest,
                        "sequence": checked_sequence,
                        "phase": checked_phase,
                        "observed_monotonic_ns": checked_observed,
                    },
                )
            ),
        )
        values = (
            ("slice_id", slice_id),
            ("authority_id", stop_authority.authority_id),
            ("authority_digest", stop_authority.authority_digest),
            ("sequence", checked_sequence),
            ("phase", checked_phase),
            ("context_id", stop_authority.context_id),
            ("session_id", stop_authority.session_id),
            (
                "runtime_deadline_digest",
                stop_authority.runtime_deadline_digest,
            ),
            ("cancellation_token_id", stop_authority.cancellation_token_id),
            (
                "cancellation_token_digest",
                stop_authority.cancellation_token_digest,
            ),
            ("effective_deadline_ns", checked_deadline),
            ("observed_monotonic_ns", checked_observed),
            ("remaining_ns", remaining_ns),
            ("max_wait_ns", max_wait_ns),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        slice_digest = digest256(
            "HelperWaitSlice",
            HELPER_WAIT_SLICE_SCHEMA_VERSION,
            _helper_wait_slice_payload(self),
        )
        object.__setattr__(self, "slice_digest", slice_digest)
        object.__setattr__(self, "_issued_digest", slice_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("HelperWaitSlice is immutable")

    def __copy__(self) -> "HelperWaitSlice":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "HelperWaitSlice":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("HelperWaitSlice cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("HelperWaitSlice cannot be serialized")

    def validate_integrity(self) -> None:
        for name in (
            "slice_id",
            "authority_id",
            "context_id",
            "session_id",
            "cancellation_token_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "authority_digest",
            "runtime_deadline_digest",
            "cancellation_token_digest",
            "slice_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        require_plain_int(self.sequence, "sequence", minimum=1)
        require_text(self.phase, "phase", max_length=64)
        require_plain_int(
            self.effective_deadline_ns,
            "effective_deadline_ns",
            minimum=1,
        )
        require_plain_int(
            self.observed_monotonic_ns,
            "observed_monotonic_ns",
        )
        require_plain_int(self.remaining_ns, "remaining_ns", minimum=1)
        require_plain_int(self.max_wait_ns, "max_wait_ns", minimum=1)
        if (
            self.observed_monotonic_ns >= self.effective_deadline_ns
            or self.remaining_ns
            != self.effective_deadline_ns - self.observed_monotonic_ns
            or self.max_wait_ns
            != min(self.remaining_ns, HELPER_WAIT_QUANTUM_NS)
            or self.max_wait_ns > HELPER_WAIT_QUANTUM_NS
        ):
            raise ValueError("helper wait slice bound changed")
        expected_id = uuid5(
            _HELPER_WAIT_SLICE_UUID_NAMESPACE,
            str(
                digest256(
                    "HelperWaitSliceIdentifier",
                    HELPER_WAIT_SLICE_SCHEMA_VERSION,
                    {
                        "authority_id": self.authority_id,
                        "authority_digest": self.authority_digest,
                        "sequence": self.sequence,
                        "phase": self.phase,
                        "observed_monotonic_ns": self.observed_monotonic_ns,
                    },
                )
            ),
        )
        if (
            self.slice_id != expected_id
            or self.slice_digest != self._issued_digest
            or self.slice_digest
            != digest256(
                "HelperWaitSlice",
                HELPER_WAIT_SLICE_SCHEMA_VERSION,
                _helper_wait_slice_payload(self),
            )
        ):
            raise ValueError("helper wait slice integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "slice_id": str(self.slice_id),
            "authority_id": str(self.authority_id),
            "phase": self.phase,
            "max_wait_ns": self.max_wait_ns,
        }


class _HelperStopAuthorityState:
    """Gate-owned exact snapshot independent from caller-held authority fields."""

    __slots__ = (
        "authority",
        "authority_id",
        "authority_digest",
        "gate_id",
        "credential_permit_id",
        "credential_permit_digest",
        "context_id",
        "context_digest",
        "session_id",
        "session_terms_digest",
        "runtime_deadline_digest",
        "cancellation_token_id",
        "cancellation_token_digest",
        "effective_deadline_ns",
        "attempt_gate",
        "credential_permit",
        "context",
        "context_ledger",
        "session",
        "runtime_deadline",
        "cancellation_token",
        "status",
        "sequence",
        "issued_wait_slice",
        "issued_wait_slice_digest",
        "completion_attempt_id",
        "completion_receipt_digest",
    )

    def __init__(self, authority: HelperStopAuthority) -> None:
        authority.validate_integrity()
        self.authority = authority
        self.authority_id = authority.authority_id
        self.authority_digest = authority.authority_digest
        self.gate_id = authority.gate_id
        self.credential_permit_id = authority.credential_permit_id
        self.credential_permit_digest = authority.credential_permit_digest
        self.context_id = authority.context_id
        self.context_digest = authority.context_digest
        self.session_id = authority.session_id
        self.session_terms_digest = authority.session_terms_digest
        self.runtime_deadline_digest = authority.runtime_deadline_digest
        self.cancellation_token_id = authority.cancellation_token_id
        self.cancellation_token_digest = authority.cancellation_token_digest
        self.effective_deadline_ns = authority.effective_deadline_ns
        self.attempt_gate = authority._attempt_gate
        self.credential_permit = authority._credential_permit
        self.context = authority._context
        self.context_ledger = authority._context_ledger
        self.session = authority._session
        self.runtime_deadline = authority._runtime_deadline
        self.cancellation_token = authority._cancellation_token
        self.status = "active"
        self.sequence = 0
        self.issued_wait_slice: HelperWaitSlice | None = None
        self.issued_wait_slice_digest: Digest256 | None = None
        self.completion_attempt_id: UUID | None = None
        self.completion_receipt_digest: Digest256 | None = None

    def authority_refs(self) -> tuple[object, ...]:
        return (
            self.attempt_gate,
            self.credential_permit,
            self.context,
            self.context_ledger,
            self.session,
            self.runtime_deadline,
            self.cancellation_token,
        )

    def clear_authority_refs(self) -> None:
        self.attempt_gate = None
        self.credential_permit = None
        self.context = None
        self.context_ledger = None
        self.session = None
        self.runtime_deadline = None
        self.cancellation_token = None

    def restore_authority_refs(self, refs: tuple[object, ...]) -> None:
        (
            self.attempt_gate,
            self.credential_permit,
            self.context,
            self.context_ledger,
            self.session,
            self.runtime_deadline,
            self.cancellation_token,
        ) = refs


class _CredentialPermitState:
    __slots__ = (
        "permit",
        "permit_id",
        "session_id",
        "credential_binding_digest",
        "context",
        "context_ledger",
        "status",
        "resolved_binding",
        "credential_handle_id",
        "credential_handle_digest",
        "resolved_publication_id",
        "resolver_claim_id",
    )

    def __init__(self, permit: CredentialResolutionPermit) -> None:
        self.permit = permit
        self.permit_id = permit.permit_id
        self.session_id = permit.session_id
        self.credential_binding_digest = permit.credential_binding_digest
        self.context = permit._context
        self.context_ledger = permit._context_ledger
        self.status = "authorized"
        self.resolved_binding: Digest256 | ContractMarker | None = None
        self.credential_handle_id: UUID | None = None
        self.credential_handle_digest: Digest256 | None = None
        self.resolved_publication_id: UUID | None = None
        self.resolver_claim_id: UUID | None = None

    def recovery_refs(self) -> tuple[object, object]:
        return self.context, self.context_ledger

    def restore_recovery_refs(self, refs: tuple[object, object]) -> None:
        self.context, self.context_ledger = refs

    def clear_recovery_refs(self) -> None:
        self.context = None
        self.context_ledger = None


class _AttemptPermitState:
    __slots__ = (
        "permit",
        "attempt_permit_id",
        "attempt_permit_digest",
        "credential_permit",
        "credential_permit_id",
        "credential_handle_id",
        "credential_handle_digest",
        "session_id",
        "context",
        "context_ledger",
        "reservation",
        "status",
        "transport_claim_id",
        "terminal_guard_id",
        "terminal_guard_digest",
        "dns_start_id",
        "credential_borrow_id",
        "wire_commit_id",
        "wire_evidence_digest",
        "wire_borrow_id",
        "resolver_completion_status",
        "resolver_completion_authority_id",
        "resolver_completion_claim_id",
        "resolver_completion_guard_id",
        "resolver_completion_guard_digest",
        "resolver_completion_start_id",
        "resolver_completion_receipt_digest",
    )

    def __init__(self, permit: AttemptPermit) -> None:
        self.permit = permit
        self.attempt_permit_id = permit.attempt_permit_id
        self.attempt_permit_digest = permit.attempt_permit_digest
        self.credential_permit = permit._credential_permit
        self.credential_permit_id = permit.credential_permit_id
        self.credential_handle_id = permit.credential_handle_id
        self.credential_handle_digest = permit.credential_handle_digest
        self.session_id = permit.session_id
        self.context = permit._credential_permit._context
        self.context_ledger = permit._context_ledger
        self.reservation = permit._reservation
        self.status = "active"
        self.transport_claim_id: UUID | None = None
        self.terminal_guard_id: UUID | None = None
        self.terminal_guard_digest: Digest256 | None = None
        self.dns_start_id: UUID | None = None
        self.credential_borrow_id: UUID | None = None
        self.wire_commit_id: UUID | None = None
        self.wire_evidence_digest: Digest256 | None = None
        self.wire_borrow_id: UUID | None = None
        self.resolver_completion_status = "uncommitted"
        self.resolver_completion_authority_id: UUID | None = None
        self.resolver_completion_claim_id: UUID | None = None
        self.resolver_completion_guard_id: UUID | None = None
        self.resolver_completion_guard_digest: Digest256 | None = None
        self.resolver_completion_start_id: UUID | None = None
        self.resolver_completion_receipt_digest: Digest256 | None = None

    def clear_recovery_refs(self) -> None:
        """Drop strong recovery anchors after irreversible terminal commit."""

        self.credential_permit = None
        self.context = None
        self.context_ledger = None
        self.reservation = None

    def recovery_refs(self) -> tuple[object, object, object, object]:
        return (
            self.credential_permit,
            self.context,
            self.context_ledger,
            self.reservation,
        )

    def restore_recovery_refs(
        self,
        refs: tuple[object, object, object, object],
    ) -> None:
        (
            self.credential_permit,
            self.context,
            self.context_ledger,
            self.reservation,
        ) = refs


def _validate_session_binding(
    *,
    planned: PlannedExecution,
    invocation: StageInvocation,
    prepared: PreparedOutbound,
    authorization: AuthorizationContext,
    session: AuthorizedSendSession,
    approval_ledger: EgressApprovalLedger,
    session_ledger: SendSessionLedger,
    stage: ExecutionPlanStage,
    operation: ExecutionPlanNetworkOperation,
) -> None:
    valid = type(session) is AuthorizedSendSession
    if valid:
        try:
            session.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            valid = False
    expected = (
        session._approval_ledger is approval_ledger,
        session._session_ledger is session_ledger,
        session.request_id == planned.plan.request_id,
        session.plan_id == planned.plan.plan_id,
        session.plan_digest == planned.plan.plan_digest,
        session.planned_execution_digest == planned.planned_execution_digest,
        session.registry_revision
        == planned.resolved_pipeline.registry_revision,
        session.registry_digest == planned.resolved_pipeline.registry_digest,
        session.privacy_authorization_id == authorization.authorization_id,
        session.privacy_authorization_digest
        == authorization.authorization_digest,
        session.stage_id == invocation.stage_id == stage.stage_id,
        session.operation_id == prepared.operation_id == operation.operation_id,
        session.invocation_id == invocation.invocation_id,
        session.invocation_digest == invocation.invocation_digest,
        session.source_ids == prepared.source_ids,
        session.source_digests == prepared.source_digests,
        session.capture_scope_fingerprint
        == prepared.capture_scope_fingerprint,
        session.http_method == prepared.http_method,
        session.canonical_url == prepared.canonical_url,
        session.content_type == prepared.content_type,
        session.non_secret_headers_digest
        == prepared.non_secret_headers_digest,
        session.credential_binding_digest
        == prepared.credential_binding_digest,
        session.outbound_data == prepared.outbound_data,
        session.body_digest == prepared.body_digest,
        session.payload_byte_size == prepared.payload_byte_size,
        session.request_envelope_digest == prepared.request_envelope_digest,
        session.max_network_attempts == stage.max_attempts_per_operation,
        session.billable == operation.billable,
        session.issued_at is not None,
        session.valid_until is not None,
    ) if valid else (False,)
    if not valid or not all(expected):
        raise _attempt_error("发送会话未精确绑定当前请求封装。")


@runtime_final
class AttemptGate:
    """Own one-shot permit state; every authority decision remains zero-I/O."""

    __slots__ = (
        "_gate_id",
        "_credential_permits",
        "_attempt_permits",
        "_helper_stop_authorities",
        "_helper_stop_by_credential",
        "_active_by_session",
        "_sequence",
        "_lock",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "_gate_id", uuid4())
        object.__setattr__(self, "_credential_permits", {})
        object.__setattr__(self, "_attempt_permits", {})
        object.__setattr__(self, "_helper_stop_authorities", {})
        object.__setattr__(self, "_helper_stop_by_credential", {})
        object.__setattr__(self, "_active_by_session", {})
        object.__setattr__(self, "_sequence", 0)
        object.__setattr__(self, "_lock", RLock())

    @staticmethod
    def _validate_inputs(
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        session: AuthorizedSendSession,
        approval_ledger: EgressApprovalLedger,
        session_ledger: SendSessionLedger,
        authority_ledger: RegistryPolicyAuthorityLedger,
        context: CallContext,
        context_ledger: CallContextLedger,
    ) -> None:
        expected_types = (
            (planned, PlannedExecution, "planned"),
            (invocation, StageInvocation, "invocation"),
            (prepared, PreparedOutbound, "prepared"),
            (authorization, AuthorizationContext, "authorization"),
            (consent_ledger, ConsentLedger, "consent_ledger"),
            (session, AuthorizedSendSession, "session"),
            (approval_ledger, EgressApprovalLedger, "approval_ledger"),
            (session_ledger, SendSessionLedger, "session_ledger"),
            (
                authority_ledger,
                RegistryPolicyAuthorityLedger,
                "authority_ledger",
            ),
            (context, CallContext, "context"),
            (context_ledger, CallContextLedger, "context_ledger"),
        )
        for value, expected_type, name in expected_types:
            if type(value) is not expected_type:
                raise TypeError(f"{name} must be {expected_type.__name__}")
        if (
            context._context_ledger is not context_ledger
            or context_ledger._authority_ledger is not authority_ledger
            or context.registry_policy_lease._authority_ledger
            is not authority_ledger
            or session._approval_ledger is not approval_ledger
            or session._session_ledger is not session_ledger
        ):
            raise _attempt_error("本次 attempt 的账本 authority 不匹配。")

    def _run_authority_path(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        session: AuthorizedSendSession,
        approval_ledger: EgressApprovalLedger,
        session_ledger: SendSessionLedger,
        authority_ledger: RegistryPolicyAuthorityLedger,
        context: CallContext,
        context_ledger: CallContextLedger,
        final_action: Callable[..., _T],
        include_effective_deadline: bool = False,
    ) -> _T:
        self._validate_inputs(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            session=session,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            authority_ledger=authority_ledger,
            context=context,
            context_ledger=context_ledger,
        )
        if not callable(final_action):
            raise TypeError("final_action must be callable")
        if type(include_effective_deadline) is not bool:
            raise TypeError("include_effective_deadline must be bool")

        # Obtain caller-independent time before taking the ordered authority
        # locks.  The final context action samples again while all locks remain
        # held, so cancellation/deadline transitions cannot slip through.
        initial_sample = context_ledger._sample_for_attempt(
            context=context,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        initial_now = initial_sample.wall_time

        def under_consent() -> _T:
            stage, operation = _validate_exact_egress_binding_for_session(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                now=initial_now,
                _authority=_EGRESS_ATTEMPT_AUTHORITY,
            )
            if (
                type(stage) is not ExecutionPlanStage
                or type(operation) is not ExecutionPlanNetworkOperation
            ):
                raise _attempt_error("冻结计划中的网络操作无效。")
            _validate_session_binding(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                stage=stage,
                operation=operation,
            )

            def under_approval() -> _T:
                def under_session() -> _T:
                    def under_registry() -> _T:
                        if include_effective_deadline:
                            return context_ledger._run_active_helper_action(
                                context=context,
                                attempt_gate=self,
                                session_id=session.session_id,
                                session_valid_until=session.valid_until,
                                action=lambda sample, effective_deadline_ns: (
                                    final_action(
                                        stage,
                                        operation,
                                        sample,
                                        effective_deadline_ns,
                                    )
                                ),
                                _authority=_ATTEMPT_BUDGET_AUTHORITY,
                            )
                        return context_ledger._run_active_action(
                            context=context,
                            attempt_gate=self,
                            session_id=session.session_id,
                            session_valid_until=session.valid_until,
                            action=lambda sample: final_action(
                                stage,
                                operation,
                                sample,
                            ),
                            _authority=_ATTEMPT_BUDGET_AUTHORITY,
                        )

                    return authority_ledger._run_active_action(
                        lease=context.registry_policy_lease,
                        planned=planned,
                        action=under_registry,
                        _authority=_ATTEMPT_AUTHORITY,
                    )

                return session_ledger._run_active_action(
                    session=session,
                    now=initial_now,
                    action=under_session,
                    _authority=_SESSION_ATTEMPT_AUTHORITY,
                )

            return approval_ledger._run_consumed_action(
                approval_id=session.approval_id,
                approval_terms_digest=session.approval_terms_digest,
                consumed_approval_digest=session.consumed_approval_digest,
                consumed_at=session.issued_at,
                now=initial_now,
                action=under_approval,
                _authority=_EGRESS_ATTEMPT_AUTHORITY,
            )

        return consent_ledger._run_session_authorized_action(
            planned=planned,
            authorization=authorization,
            session=session,
            now=initial_now,
            action=under_consent,
            _authority=_CONSENT_ATTEMPT_AUTHORITY,
        )

    def authorize_credential_resolution(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        session: AuthorizedSendSession,
        approval_ledger: EgressApprovalLedger,
        session_ledger: SendSessionLedger,
        authority_ledger: RegistryPolicyAuthorityLedger,
        context: CallContext,
        context_ledger: CallContextLedger,
    ) -> CredentialResolutionPermit:
        def issue(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
        ) -> CredentialResolutionPermit:
            del stage, operation
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            with self._lock:
                if session.session_id in self._active_by_session:
                    raise _attempt_error("当前发送会话已有凭据解析授权。")
                sequence = self._sequence + 1
                object.__setattr__(self, "_sequence", sequence)
            permit = CredentialResolutionPermit(
                gate_id=self._gate_id,
                sequence=sequence,
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                authority_ledger=authority_ledger,
                context=context,
                context_ledger=context_ledger,
                sample=sample,
                attempt_gate=self,
                _authority=_PERMIT_FACTORY_AUTHORITY,
            )
            context_ledger._register_gate_activity(
                context=context,
                attempt_gate=self,
                activity_id=permit.permit_id,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
            try:
                with self._lock:
                    if session.session_id in self._active_by_session:
                        raise _attempt_error("当前发送会话已有凭据解析授权。")
                    self._credential_permits[permit.permit_id] = (
                        _CredentialPermitState(permit)
                    )
                    self._active_by_session[session.session_id] = permit.permit_id
                    return permit
            except BaseException:
                context_ledger._discard_gate_activity(
                    context=context,
                    attempt_gate=self,
                    activity_id=permit.permit_id,
                    _authority=_ATTEMPT_BUDGET_AUTHORITY,
                )
                permit._release_authority_refs(
                    _authority=_PERMIT_RELEASE_AUTHORITY,
                )
                raise

        return self._run_authority_path(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            session=session,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            authority_ledger=authority_ledger,
            context=context,
            context_ledger=context_ledger,
            final_action=issue,
        )

    def _require_helper_stop_state_locked(
        self,
        authority: HelperStopAuthority,
        *,
        require_active: bool = True,
    ) -> _HelperStopAuthorityState:
        if type(authority) is not HelperStopAuthority:
            raise TypeError("authority must be HelperStopAuthority")
        try:
            authority.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _attempt_error("helper stop authority 完整性校验失败。") from None
        state = self._helper_stop_authorities.get(authority.authority_id)
        primitive_matches = state is not None and (
            state.authority is authority
            and state.authority_id == authority.authority_id
            and state.authority_digest == authority.authority_digest
            and state.gate_id == authority.gate_id == self._gate_id
            and state.credential_permit_id
            == authority.credential_permit_id
            and state.credential_permit_digest
            == authority.credential_permit_digest
            and state.context_id == authority.context_id
            and state.context_digest == authority.context_digest
            and state.session_id == authority.session_id
            and state.session_terms_digest == authority.session_terms_digest
            and state.runtime_deadline_digest
            == authority.runtime_deadline_digest
            and state.cancellation_token_id
            == authority.cancellation_token_id
            and state.cancellation_token_digest
            == authority.cancellation_token_digest
            and state.effective_deadline_ns
            == authority.effective_deadline_ns
            and self._helper_stop_by_credential.get(
                state.credential_permit_id
            )
            == state.authority_id
        )
        if not primitive_matches:
            raise _attempt_error("helper stop authority 不属于当前 AttemptGate。")
        if not require_active:
            return state
        credential_state = self._credential_permits.get(
            state.credential_permit_id
        )
        if (
            state.status != "active"
            or authority._released
            or state.attempt_gate is not self
            or state.credential_permit is not authority._credential_permit
            or state.context is not authority._context
            or state.context_ledger is not authority._context_ledger
            or state.session is not authority._session
            or state.runtime_deadline is not authority._runtime_deadline
            or state.cancellation_token is not authority._cancellation_token
            or credential_state is None
            or credential_state.permit is not state.credential_permit
            or credential_state.status in ("abandoned", "finished")
            or self._active_by_session.get(state.session_id)
            != state.credential_permit_id
        ):
            raise _attempt_error("helper stop authority 已终结或 owner 已变化。")
        return state

    def _issue_helper_stop_authority(
        self,
        credential_permit: CredentialResolutionPermit,
        *,
        _authority: object | None = None,
    ) -> HelperStopAuthority:
        """Issue the sole exact helper stop authority for one credential permit."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("helper stop issuance requires trusted transport")
        if type(credential_permit) is not CredentialResolutionPermit:
            raise TypeError(
                "credential_permit must be CredentialResolutionPermit"
            )
        if credential_permit._attempt_gate is not self:
            raise _attempt_error("凭据解析授权不属于当前 AttemptGate。")
        with self._lock:
            credential_state = self._require_credential_state_locked(
                credential_permit
            )
            bindings = (
                credential_permit._planned,
                credential_permit._invocation,
                credential_permit._prepared,
                credential_permit._authorization,
                credential_permit._consent_ledger,
                credential_permit._session,
                credential_permit._approval_ledger,
                credential_permit._session_ledger,
                credential_permit._authority_ledger,
                credential_permit._context,
                credential_permit._context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings

        def issue_stop(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
            effective_deadline_ns: int,
        ) -> HelperStopAuthority:
            del stage, operation
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            with self._lock:
                current = self._require_credential_state_locked(
                    credential_permit
                )
                existing_id = self._helper_stop_by_credential.get(
                    credential_permit.permit_id
                )
                if existing_id is not None:
                    existing = self._helper_stop_authorities.get(existing_id)
                    if existing is None:
                        raise _attempt_error(
                            "helper stop authority publication 无效。"
                        )
                    candidate = existing.authority
                    validated = self._require_helper_stop_state_locked(candidate)
                    if (
                        validated is not existing
                        or existing.effective_deadline_ns
                        != effective_deadline_ns
                    ):
                        raise _attempt_error(
                            "helper stop authority deadline 已变化。"
                        )
                    return candidate
                if current is not credential_state or current.status != "authorized":
                    raise _attempt_error(
                        "helper stop authority 只能在 helper 启动前签发。"
                    )
                candidate = HelperStopAuthority(
                    credential_permit=credential_permit,
                    context=context,
                    context_ledger=context_ledger,
                    session=session,
                    effective_deadline_ns=effective_deadline_ns,
                    attempt_gate=self,
                    _authority=_HELPER_STOP_FACTORY_AUTHORITY,
                )
                stop_state = _HelperStopAuthorityState(candidate)
                try:
                    if candidate.authority_id in self._helper_stop_authorities:
                        raise _attempt_error(
                            "helper stop authority id 已使用。"
                        )
                    self._helper_stop_authorities[candidate.authority_id] = (
                        stop_state
                    )
                    self._helper_stop_by_credential[
                        credential_permit.permit_id
                    ] = candidate.authority_id
                    return candidate
                except BaseException:
                    if (
                        self._helper_stop_authorities.get(candidate.authority_id)
                        is stop_state
                    ):
                        del self._helper_stop_authorities[candidate.authority_id]
                    if (
                        self._helper_stop_by_credential.get(
                            credential_permit.permit_id
                        )
                        == candidate.authority_id
                    ):
                        del self._helper_stop_by_credential[
                            credential_permit.permit_id
                        ]
                    candidate._release_authority_refs(
                        _authority=_PERMIT_RELEASE_AUTHORITY,
                    )
                    raise

        candidate = self._run_authority_path(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            session=session,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            authority_ledger=authority_ledger,
            context=context,
            context_ledger=context_ledger,
            final_action=issue_stop,
            include_effective_deadline=True,
        )
        with self._lock:
            state = self._require_helper_stop_state_locked(candidate)
            if state.credential_permit is not credential_permit:
                raise _attempt_error("helper stop authority publication 未提交。")
        return candidate

    def _checkpoint_helper_stop_authority(
        self,
        authority: HelperStopAuthority,
        *,
        phase: str,
        _authority: object | None = None,
    ) -> HelperWaitSlice:
        """Recheck all live ledgers and issue one caller-independent wait bound."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("helper checkpoint requires trusted transport")
        checked_phase = require_text(phase, "phase", max_length=64)
        with self._lock:
            stop_state = self._require_helper_stop_state_locked(authority)
            previous_sequence = stop_state.sequence
            expected_sequence = previous_sequence + 1
            previous_wait_slice = stop_state.issued_wait_slice
            previous_wait_slice_digest = stop_state.issued_wait_slice_digest
            bindings = (
                stop_state.credential_permit._planned,
                stop_state.credential_permit._invocation,
                stop_state.credential_permit._prepared,
                stop_state.credential_permit._authorization,
                stop_state.credential_permit._consent_ledger,
                stop_state.session,
                stop_state.credential_permit._approval_ledger,
                stop_state.credential_permit._session_ledger,
                stop_state.credential_permit._authority_ledger,
                stop_state.context,
                stop_state.context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings

        def checkpoint(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
            effective_deadline_ns: int,
        ) -> HelperWaitSlice:
            del stage, operation
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            with self._lock:
                current = self._require_helper_stop_state_locked(authority)
                if (
                    current is not stop_state
                    or current.sequence != previous_sequence
                    or current.issued_wait_slice is not previous_wait_slice
                    or current.issued_wait_slice_digest
                    != previous_wait_slice_digest
                    or effective_deadline_ns
                    != current.effective_deadline_ns
                    or sample.monotonic_after_ns >= effective_deadline_ns
                ):
                    raise _attempt_error(
                        "helper stop authority deadline 已变化。"
                    )
                wait_slice = HelperWaitSlice(
                    stop_authority=authority,
                    sequence=expected_sequence,
                    phase=checked_phase,
                    effective_deadline_ns=effective_deadline_ns,
                    observed_monotonic_ns=sample.monotonic_after_ns,
                    _authority=_HELPER_WAIT_SLICE_FACTORY_AUTHORITY,
                )
                current.sequence = expected_sequence
                current.issued_wait_slice = wait_slice
                current.issued_wait_slice_digest = wait_slice.slice_digest
                return wait_slice

        candidate = self._run_authority_path(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            session=session,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            authority_ledger=authority_ledger,
            context=context,
            context_ledger=context_ledger,
            final_action=checkpoint,
            include_effective_deadline=True,
        )
        candidate_is_valid = type(candidate) is HelperWaitSlice
        if candidate_is_valid:
            try:
                candidate.validate_integrity()
            except (TypeError, ValueError, AttributeError):
                candidate_is_valid = False
        with self._lock:
            current = self._require_helper_stop_state_locked(authority)
            publication_is_exact = (
                candidate_is_valid
                and current is stop_state
                and current.sequence == expected_sequence
                and current.issued_wait_slice is candidate
                and current.issued_wait_slice_digest
                == candidate.slice_digest
                and candidate.sequence == expected_sequence
                and candidate.authority_id == authority.authority_id
                and candidate.authority_digest == authority.authority_digest
                and candidate.phase == checked_phase
                and candidate.effective_deadline_ns
                == current.effective_deadline_ns
            )
        if not publication_is_exact:
            raise _attempt_error("helper wait slice publication 未提交。")
        return candidate

    def _confirm_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
        *,
        claim_id: UUID,
        publication_id: UUID | None = None,
        resolved_binding_digest: Digest256 | ContractMarker,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Revalidate after one backend read, then bind primitive handle proof."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential confirmation requires trusted resolver")
        if type(claim_id) is not UUID:
            raise _attempt_error("resolver claim owner 无效。")
        effective_publication_id = (
            claim_id if publication_id is None else publication_id
        )
        binding_is_valid = True
        try:
            _require_credential_binding(resolved_binding_digest)
        except (TypeError, ValueError, AttributeError):
            binding_is_valid = False
        proof_is_valid = (
            type(effective_publication_id) is UUID
            and type(handle_id) is UUID
            and type(handle_digest) is Digest256
        )
        confirmation_is_valid = (
            binding_is_valid
            and proof_is_valid
            and resolved_binding_digest == permit.credential_binding_digest
        )
        preconfirm_snapshot: tuple[object, object, object, object] | None = None
        bindings: tuple[object, ...] | None = None
        with self._lock:
            state = self._require_credential_state_locked(permit)
            if (
                state.status != "resolving"
                or state.resolver_claim_id != claim_id
            ):
                raise _attempt_error("凭据解析授权未被 resolver 独占。")
            if confirmation_is_valid:
                bindings = (
                    permit._planned,
                    permit._invocation,
                    permit._prepared,
                    permit._authorization,
                    permit._consent_ledger,
                    permit._session,
                    permit._approval_ledger,
                    permit._session_ledger,
                    permit._authority_ledger,
                    permit._context,
                    permit._context_ledger,
                )
                preconfirm_snapshot = (
                    state.resolved_binding,
                    state.credential_handle_id,
                    state.credential_handle_digest,
                    state.resolved_publication_id,
                )

        transition_started = False
        try:
            # Cover the first visible transition.  The exact resolver owner is
            # revalidated under the lock so an asynchronous BaseException can
            # restore only this transaction's partial state.
            with self._lock:
                current = self._require_credential_state_locked(permit)
                if (
                    current is not state
                    or current.status != "resolving"
                    or current.resolver_claim_id != claim_id
                ):
                    raise _attempt_error(
                        "凭据解析确认状态已经变化。"
                    )
                transition_started = True
                current.status = (
                    "confirming" if confirmation_is_valid else "failing"
                )

            if not confirmation_is_valid:
                self._finish_credential_activity(
                    permit,
                    required_status="failing",
                    terminal_status="abandoned",
                )
                raise _attempt_error(
                    "凭据解析结果或句柄证明与批准内容不匹配。"
                )

            assert bindings is not None
            (
                planned,
                invocation,
                prepared,
                authorization,
                consent_ledger,
                session,
                approval_ledger,
                session_ledger,
                authority_ledger,
                context,
                context_ledger,
            ) = bindings

            def confirm(
                stage: ExecutionPlanStage,
                operation: ExecutionPlanNetworkOperation,
                sample: ClockSample,
            ) -> None:
                del stage, operation
                if (
                    sample.wall_time < session.issued_at
                    or sample.wall_time >= session.valid_until
                ):
                    raise _attempt_error("发送会话已经过期或尚未生效。")
                with self._lock:
                    current = self._require_credential_state_locked(permit)
                    if (
                        current.status != "confirming"
                        or current.resolver_claim_id != claim_id
                    ):
                        raise _attempt_error("凭据解析确认状态已经变化。")
                    current.resolved_binding = resolved_binding_digest
                    current.credential_handle_id = handle_id
                    current.credential_handle_digest = handle_digest
                    current.resolved_publication_id = effective_publication_id
                    current.resolver_claim_id = None
                    current.status = "resolved"

            self._run_authority_path(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                authority_ledger=authority_ledger,
                context=context,
                context_ledger=context_ledger,
                final_action=confirm,
            )
            with self._lock:
                current = self._require_credential_state_locked(permit)
                committed = (
                    current is state
                    and current.status == "resolved"
                    and current.resolver_claim_id is None
                    and current.resolved_binding
                    == resolved_binding_digest
                    and current.credential_handle_id == handle_id
                    and current.credential_handle_digest == handle_digest
                    and current.resolved_publication_id
                    == effective_publication_id
                    and self._active_by_session.get(current.session_id)
                    == current.permit_id
                )
                if not committed:
                    raise _attempt_error(
                        "credential confirmation transaction 未提交。"
                    )
        except BaseException:
            with self._lock:
                current = self._lookup_credential_state_locked(permit)
                if transition_started and current is state:
                    if (
                        not confirmation_is_valid
                        and current.status == "failing"
                        and current.resolver_claim_id == claim_id
                    ):
                        current.status = "resolving"
                    elif (
                        confirmation_is_valid
                        and preconfirm_snapshot is not None
                        and current.status == "confirming"
                        and current.resolver_claim_id in (claim_id, None)
                        and current.resolved_binding
                        in (preconfirm_snapshot[0], resolved_binding_digest)
                        and current.credential_handle_id
                        in (preconfirm_snapshot[1], handle_id)
                        and current.credential_handle_digest
                        in (preconfirm_snapshot[2], handle_digest)
                        and current.resolved_publication_id
                        in (
                            preconfirm_snapshot[3],
                            effective_publication_id,
                        )
                        and self._active_by_session.get(current.session_id)
                        == current.permit_id
                    ):
                        (
                            current.resolved_binding,
                            current.credential_handle_id,
                            current.credential_handle_digest,
                            current.resolved_publication_id,
                        ) = preconfirm_snapshot
                        current.resolver_claim_id = claim_id
                        current.status = "resolving"
            raise

    def _finish_credential_activity(
        self,
        permit: CredentialResolutionPermit,
        *,
        required_status: str,
        terminal_status: str,
    ) -> None:
        """Release Context activity before dropping sensitive Gate refs."""

        with self._lock:
            state = self._require_credential_state_locked(permit)
            if state.status != required_status:
                raise _attempt_error("凭据解析状态不允许当前终态操作。")
            context = permit._context
            context_ledger = permit._context_ledger

        def terminal() -> None:
            with self._lock:
                current = self._require_credential_state_locked(permit)
                if current.status != required_status:
                    raise _attempt_error("凭据解析状态已经变化。")
                self._commit_credential_terminal_locked(
                    permit=permit,
                    state=current,
                    terminal_status=terminal_status,
                )

        context_ledger._finish_gate_activity(
            context=context,
            attempt_gate=self,
            activity_id=permit.permit_id,
            action=terminal,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        with self._lock:
            if (
                self._credential_permits.get(state.permit_id) is not state
                or state.status != terminal_status
                or state.resolver_claim_id is not None
                or state.resolved_publication_id is not None
                or state.session_id in self._active_by_session
            ):
                raise _attempt_error(
                    "凭据解析终态 transaction 未提交。"
                )

    def _fail_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
        *,
        claim_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Trusted resolver cleanup after an exclusive backend read fails."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential failure requires trusted resolver")
        if type(claim_id) is not UUID:
            raise _attempt_error("resolver claim owner 无效。")
        with self._lock:
            state = self._lookup_credential_state_locked(permit)
            if state.status in ("abandoned", "finished"):
                return False
            if self._active_by_session.get(permit.session_id) != permit.permit_id:
                raise _attempt_error("凭据解析授权当前不可用。")
            if (
                state.status != "resolving"
                or state.resolver_claim_id != claim_id
            ):
                raise _attempt_error("只能终止 resolver 已独占的凭据授权。")
        transition_started = False
        try:
            with self._lock:
                current = self._lookup_credential_state_locked(permit)
                if (
                    current is not state
                    or current.status != "resolving"
                    or current.resolver_claim_id != claim_id
                    or self._active_by_session.get(current.session_id)
                    != current.permit_id
                ):
                    raise _attempt_error(
                        "凭据解析失败状态已经变化。"
                    )
                transition_started = True
                current.status = "failing"
            self._finish_credential_activity(
                permit,
                required_status="failing",
                terminal_status="abandoned",
            )
        except BaseException:
            with self._lock:
                current = self._lookup_credential_state_locked(permit)
                if (
                    transition_started
                    and current is state
                    and current.status == "failing"
                    and current.resolver_claim_id == claim_id
                ):
                    current.status = "resolving"
            raise
        return True

    def _credential_resolution_is_terminal(
        self,
        permit: CredentialResolutionPermit,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Let the trusted resolver observe cleanup after commit-then-raise."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential state observation requires trusted resolver")
        with self._lock:
            state = self._lookup_credential_state_locked(permit)
            return state.status in ("abandoned", "finished")

    def _credential_resolution_is_terminal_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Observe terminal state without trusting released permit slots."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential cleanup observation requires resolver")
        if type(permit) is not CredentialResolutionPermit:
            return False
        with self._lock:
            matches = [
                state
                for key, state in self._credential_permits.items()
                if state.permit is permit and state.permit_id == key
            ]
            if len(matches) != 1:
                return False
            state = matches[0]
            return (
                state.status in ("abandoned", "finished")
                and state.resolver_claim_id is None
                and state.resolved_publication_id is None
                and state.context is None
                and state.context_ledger is None
                and state.session_id not in self._active_by_session
                and self._helper_stop_is_terminal_for_credential_locked(
                    state.permit_id
                )
            )

    def _credential_claim_is_owned(
        self,
        permit: CredentialResolutionPermit,
        *,
        claim_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Observe a caller-generated resolver owner after claim raises."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential claim observation requires resolver")
        if type(claim_id) is not UUID:
            return False
        with self._lock:
            state = self._lookup_credential_state_locked(permit)
            return (
                state.resolver_claim_id == claim_id
                and state.status in (
                    "claiming",
                    "resolving",
                    "confirming",
                    "failing",
                )
            )

    def _resolved_credential_handle_is_active(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Observe one exact published resolver handle without consuming it.

        This transport-only query exists for the narrow return-publication
        window where ``CredentialResolver.resolve`` completed normally but an
        outer caller lost the returned handle to a ``BaseException``.  A
        pre-confirmation state, a terminal state, or a mismatched proof is
        never recoverable.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential publication recovery requires transport")
        if (
            type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
            or type(handle_id) is not UUID
            or type(handle_digest) is not Digest256
            or permit._attempt_gate is not self
        ):
            return False
        with self._lock:
            try:
                state = self._lookup_credential_state_locked(permit)
            except (TypeError, ValueError, AttributeError, EndpointPolicyError):
                return False
            return (
                state.status == "resolved"
                and state.resolver_claim_id is None
                and state.resolved_binding
                == permit.credential_binding_digest
                and state.credential_handle_id == handle_id
                and state.credential_handle_digest == handle_digest
                and state.resolved_publication_id == publication_id
                and self._active_by_session.get(permit.session_id)
                == permit.permit_id
            )

    def _claim_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
        *,
        claim_id: UUID,
        _authority: object | None = None,
    ) -> CredentialResolutionPermit:
        """Atomically claim before any resolver backend may read a secret."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential claim requires trusted resolver")
        if type(claim_id) is not UUID:
            raise _attempt_error("resolver claim owner 无效。")
        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
        if permit._attempt_gate is not self:
            raise _attempt_error("凭据解析授权不属于当前 AttemptGate。")
        with self._lock:
            initial_state = self._require_credential_state_locked(permit)
            if initial_state.status != "authorized":
                raise _attempt_error("凭据解析授权已被其他 resolver 领取。")
            if initial_state.resolver_claim_id is not None:
                raise _attempt_error("凭据解析授权已有 resolver owner。")
            bindings = (
                permit._planned,
                permit._invocation,
                permit._prepared,
                permit._authorization,
                permit._consent_ledger,
                permit._session,
                permit._approval_ledger,
                permit._session_ledger,
                permit._authority_ledger,
                permit._context,
                permit._context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings

        def claim(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
        ) -> CredentialResolutionPermit:
            del stage, operation
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            with self._lock:
                state = self._require_credential_state_locked(permit)
                if (
                    state.status != "claiming"
                    or state.resolver_claim_id != claim_id
                ):
                    raise _attempt_error("凭据解析授权已被其他 resolver 领取。")
                state.status = "resolving"
                return permit

        transition_started = False
        try:
            with self._lock:
                current = self._require_credential_state_locked(permit)
                if (
                    current is not initial_state
                    or current.status != "authorized"
                    or current.resolver_claim_id is not None
                ):
                    raise _attempt_error(
                        "凭据解析授权已被其他 resolver 领取。"
                    )
                transition_started = True
                current.status = "claiming"
                current.resolver_claim_id = claim_id
            self._run_authority_path(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                authority_ledger=authority_ledger,
                context=context,
                context_ledger=context_ledger,
                final_action=claim,
            )
            with self._lock:
                current = self._require_credential_state_locked(permit)
                if (
                    current is not initial_state
                    or current.status != "resolving"
                    or current.resolver_claim_id != claim_id
                    or self._active_by_session.get(current.session_id)
                    != current.permit_id
                ):
                    raise _attempt_error(
                        "credential claim transaction 未提交。"
                    )
        except BaseException:
            with self._lock:
                if (
                    self._credential_permits.get(initial_state.permit_id)
                    is initial_state
                    and transition_started
                    and (
                        initial_state.status == "claiming"
                        and initial_state.resolver_claim_id in (None, claim_id)
                        or initial_state.status == "authorized"
                        and initial_state.resolver_claim_id == claim_id
                    )
                ):
                    initial_state.status = "authorized"
                    initial_state.resolver_claim_id = None
            raise
        return permit

    def abandon_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
    ) -> bool:
        """Invalidate a permit before any resolver has read credential bytes."""

        with self._lock:
            state = self._lookup_credential_state_locked(permit)
            if state.status in ("abandoned", "finished"):
                return False
            if state.status != "authorized":
                raise _attempt_error(
                    "resolver 已领取的凭据授权必须由 secret owner 终结。"
                )
        self._finish_credential_activity(
            permit,
            required_status="authorized",
            terminal_status="abandoned",
        )
        return True

    def _abandon_resolved_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
        *,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Terminalize exact Gate proof before the owner zeroes its handle."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("resolved cleanup requires trusted resolver")
        if type(handle_id) is not UUID or type(handle_digest) is not Digest256:
            raise _attempt_error("凭据句柄证明无效。")
        with self._lock:
            state = self._lookup_credential_state_locked(permit)
            if state.status in ("abandoned", "finished"):
                return False
            if (
                state.status != "resolved"
                or state.credential_handle_id != handle_id
                or state.credential_handle_digest != handle_digest
            ):
                raise _attempt_error("凭据句柄证明与 resolver 状态不匹配。")
        transition_started = False
        try:
            with self._lock:
                current = self._lookup_credential_state_locked(permit)
                if (
                    current is not state
                    or current.status != "resolved"
                    or current.credential_handle_id != handle_id
                    or current.credential_handle_digest != handle_digest
                ):
                    raise _attempt_error(
                        "凭据句柄证明与 resolver 状态不匹配。"
                    )
                transition_started = True
                current.status = "abandoning"
            self._finish_credential_activity(
                permit,
                required_status="abandoning",
                terminal_status="abandoned",
            )
        except BaseException:
            with self._lock:
                current = self._lookup_credential_state_locked(permit)
                if (
                    transition_started
                    and current is state
                    and current.status == "abandoning"
                    and current.credential_handle_id == handle_id
                    and current.credential_handle_digest == handle_digest
                ):
                    current.status = "resolved"
            raise
        return True

    def _lookup_credential_state_locked(
        self,
        permit: CredentialResolutionPermit,
    ) -> _CredentialPermitState:
        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
        valid = permit._attempt_gate is self
        if valid:
            try:
                permit.validate_integrity()
            except (TypeError, ValueError, AttributeError):
                valid = False
        state = self._credential_permits.get(permit.permit_id) if valid else None
        if (
            state is None
            or state.permit is not permit
        ):
            raise _attempt_error("凭据解析授权不属于当前 AttemptGate。")
        return state

    @staticmethod
    def _snapshot_slots(value: object) -> dict[str, object]:
        return {
            name: getattr(value, name)
            for name in type(value).__slots__
        }

    @staticmethod
    def _restore_slots(
        value: object,
        snapshot: dict[str, object],
    ) -> None:
        for name, original in snapshot.items():
            object.__setattr__(value, name, original)

    @staticmethod
    def _credential_permit_refs_are_released(
        permit: CredentialResolutionPermit,
    ) -> bool:
        return permit._released is True and all(
            getattr(permit, name) is None
            for name in (
                "_planned",
                "_invocation",
                "_prepared",
                "_authorization",
                "_consent_ledger",
                "_session",
                "_approval_ledger",
                "_session_ledger",
                "_authority_ledger",
                "_context",
                "_context_ledger",
            )
        )

    @staticmethod
    def _attempt_permit_refs_are_released(permit: AttemptPermit) -> bool:
        return permit._released is True and all(
            getattr(permit, name) is None
            for name in (
                "_credential_permit",
                "_reservation",
                "_context_ledger",
            )
        )

    def _helper_stop_release_snapshot_locked(
        self,
        credential_permit_id: UUID,
    ) -> tuple[
        _HelperStopAuthorityState,
        dict[str, object],
        tuple[object, ...],
        str,
    ] | None:
        authority_id = self._helper_stop_by_credential.get(
            credential_permit_id
        )
        if authority_id is None:
            return None
        state = self._helper_stop_authorities.get(authority_id)
        if state is None or state.credential_permit_id != credential_permit_id:
            raise _attempt_error("helper stop authority release owner 无效。")
        self._require_helper_stop_state_locked(state.authority)
        return (
            state,
            self._snapshot_slots(state.authority),
            state.authority_refs(),
            state.status,
        )

    def _release_helper_stop_locked(
        self,
        snapshot: tuple[
            _HelperStopAuthorityState,
            dict[str, object],
            tuple[object, ...],
            str,
        ]
        | None,
    ) -> None:
        if snapshot is None:
            return
        state, _, _, _ = snapshot
        authority = state.authority
        authority._release_authority_refs(
            _authority=_PERMIT_RELEASE_AUTHORITY,
        )
        state.clear_authority_refs()
        state.status = "terminal"
        try:
            authority.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _attempt_error(
                "helper stop authority refs 未释放。"
            ) from None
        if state.authority_refs() != (None, None, None, None, None, None, None):
            raise _attempt_error("helper stop recovery refs 未释放。")

    def _restore_helper_stop_locked(
        self,
        snapshot: tuple[
            _HelperStopAuthorityState,
            dict[str, object],
            tuple[object, ...],
            str,
        ]
        | None,
    ) -> None:
        if snapshot is None:
            return
        state, authority_slots, refs, status = snapshot
        self._restore_slots(state.authority, authority_slots)
        state.restore_authority_refs(refs)
        state.status = status

    def _helper_stop_is_terminal_for_credential_locked(
        self,
        credential_permit_id: UUID,
    ) -> bool:
        """Prove the exact helper authority has released every live owner."""

        indexed_authority_id = self._helper_stop_by_credential.get(
            credential_permit_id
        )
        matches = [
            (authority_id, state)
            for authority_id, state in self._helper_stop_authorities.items()
            if authority_id == indexed_authority_id
            or state.credential_permit_id == credential_permit_id
        ]
        if indexed_authority_id is None:
            return not matches
        if len(matches) != 1:
            return False
        authority_id, state = matches[0]
        authority = state.authority
        if type(authority) is not HelperStopAuthority:
            return False
        try:
            current = self._require_helper_stop_state_locked(
                authority,
                require_active=False,
            )
        except (TypeError, ValueError, AttributeError, EndpointPolicyError):
            return False
        return (
            current is state
            and authority_id == indexed_authority_id == state.authority_id
            and state.credential_permit_id == credential_permit_id
            and sum(
                candidate_id == authority_id
                for candidate_id in self._helper_stop_by_credential.values()
            )
            == 1
            and state.status == "terminal"
            and authority._released is True
            and state.authority_refs()
            == (None, None, None, None, None, None, None)
        )

    def _helper_stop_release_is_committed_locked(
        self,
        snapshot: tuple[
            _HelperStopAuthorityState,
            dict[str, object],
            tuple[object, ...],
            str,
        ]
        | None,
        *,
        credential_permit_id: UUID,
    ) -> bool:
        """Independently observe the exact release selected by a transaction."""

        if snapshot is None:
            return self._helper_stop_is_terminal_for_credential_locked(
                credential_permit_id
            )
        state, _, _, _ = snapshot
        return (
            self._helper_stop_authorities.get(state.authority_id) is state
            and state.credential_permit_id == credential_permit_id
            and self._helper_stop_is_terminal_for_credential_locked(
                credential_permit_id
            )
        )

    def _commit_credential_terminal_locked(
        self,
        *,
        permit: CredentialResolutionPermit,
        state: _CredentialPermitState,
        terminal_status: str,
    ) -> None:
        """Release refs and Gate state as one rollback-capable transaction."""

        active_id = self._active_by_session.get(permit.session_id)
        if active_id != permit.permit_id:
            raise _attempt_error("凭据解析授权的 active session 绑定已经变化。")
        permit_snapshot = self._snapshot_slots(permit)
        old_status = state.status
        old_claim_id = state.resolver_claim_id
        old_publication_id = state.resolved_publication_id
        old_recovery_refs = state.recovery_refs()
        helper_stop_snapshot = self._helper_stop_release_snapshot_locked(
            permit.permit_id
        )
        try:
            self._release_helper_stop_locked(helper_stop_snapshot)
            if not self._helper_stop_release_is_committed_locked(
                helper_stop_snapshot,
                credential_permit_id=permit.permit_id,
            ):
                raise _attempt_error(
                    "helper stop authority terminal release 未提交。"
                )
            permit._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            if not self._credential_permit_refs_are_released(permit):
                raise _attempt_error(
                    "credential permit authority refs 未释放。"
                )
            state.status = terminal_status
            state.resolver_claim_id = None
            state.resolved_publication_id = None
            if self._active_by_session.get(permit.session_id) != permit.permit_id:
                raise _attempt_error("凭据解析授权的 active session 绑定已经变化。")
            del self._active_by_session[permit.session_id]
            state.clear_recovery_refs()
            if state.recovery_refs() != (None, None):
                raise _attempt_error(
                    "credential recovery refs 未释放。"
                )
        except BaseException:
            self._restore_slots(permit, permit_snapshot)
            state.status = old_status
            state.resolver_claim_id = old_claim_id
            state.resolved_publication_id = old_publication_id
            state.restore_recovery_refs(old_recovery_refs)
            self._active_by_session[permit.session_id] = active_id
            self._restore_helper_stop_locked(helper_stop_snapshot)
            raise

    def _commit_recovered_credential_terminal_locked(
        self,
        *,
        permit: CredentialResolutionPermit,
        state: _CredentialPermitState,
    ) -> None:
        """Terminalize a resolved credential from independent Gate snapshots."""

        active_id = self._active_by_session.get(state.session_id)
        if (
            state.permit is not permit
            or self._credential_permits.get(state.permit_id) is not state
            or active_id != state.permit_id
        ):
            raise _attempt_error("credential cleanup recovery owner 已变化。")
        permit_snapshot = self._snapshot_slots(permit)
        old_status = state.status
        old_claim_id = state.resolver_claim_id
        old_publication_id = state.resolved_publication_id
        old_recovery_refs = state.recovery_refs()
        helper_stop_snapshot = self._helper_stop_release_snapshot_locked(
            state.permit_id
        )
        try:
            self._release_helper_stop_locked(helper_stop_snapshot)
            if not self._helper_stop_release_is_committed_locked(
                helper_stop_snapshot,
                credential_permit_id=state.permit_id,
            ):
                raise _attempt_error(
                    "helper stop authority terminal release 未提交。"
                )
            permit._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            if not self._credential_permit_refs_are_released(permit):
                raise _attempt_error(
                    "credential permit authority refs 未释放。"
                )
            state.status = "abandoned"
            state.resolver_claim_id = None
            state.resolved_publication_id = None
            if self._active_by_session.get(state.session_id) != state.permit_id:
                raise _attempt_error("credential cleanup recovery session 已变化。")
            del self._active_by_session[state.session_id]
            state.clear_recovery_refs()
            if state.recovery_refs() != (None, None):
                raise _attempt_error(
                    "credential recovery refs 未释放。"
                )
        except BaseException:
            self._restore_slots(permit, permit_snapshot)
            state.status = old_status
            state.resolver_claim_id = old_claim_id
            state.resolved_publication_id = old_publication_id
            state.restore_recovery_refs(old_recovery_refs)
            self._active_by_session[state.session_id] = active_id
            self._restore_helper_stop_locked(helper_stop_snapshot)
            raise

    def _recover_resolved_credential_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Recovery entry point for one exact resolved credential."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential cleanup recovery requires resolver")
        return self._recover_resolved_credential_state_for_cleanup(
            permit,
            publication_id=publication_id,
            handle_id=handle_id,
            handle_digest=handle_digest,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )

    def _recover_resolved_credential_state_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Independent ledger path for retrying resolved cleanup."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential cleanup recovery requires resolver")
        if (
            type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
            or type(handle_id) is not UUID
            or type(handle_digest) is not Digest256
        ):
            return False
        with self._lock:
            matches = [
                state
                for key, state in self._credential_permits.items()
                if state.permit is permit
                and state.permit_id == key
            ]
            if len(matches) != 1:
                return False
            state = matches[0]
            if state.status in ("abandoned", "finished"):
                return True
            if (
                state.status not in ("resolved", "abandoning")
                or state.resolver_claim_id is not None
                or state.credential_handle_id != handle_id
                or state.credential_handle_digest != handle_digest
                or state.resolved_publication_id != publication_id
                or self._active_by_session.get(state.session_id)
                != state.permit_id
                or state.context is None
                or state.context_ledger is None
            ):
                return False
            context = state.context
            context_ledger = state.context_ledger

        def terminal() -> None:
            with self._lock:
                if (
                    self._credential_permits.get(state.permit_id) is not state
                    or state.status != "abandoning"
                    or state.credential_handle_id != handle_id
                    or state.credential_handle_digest != handle_digest
                    or state.resolved_publication_id != publication_id
                ):
                    raise _attempt_error(
                        "credential cleanup recovery 状态已经变化。"
                    )
                self._commit_recovered_credential_terminal_locked(
                    permit=permit,
                    state=state,
                )

        transition_started = False
        try:
            with self._lock:
                if (
                    self._credential_permits.get(state.permit_id) is not state
                    or state.status not in ("resolved", "abandoning")
                    or state.resolver_claim_id is not None
                    or state.credential_handle_id != handle_id
                    or state.credential_handle_digest != handle_digest
                    or state.resolved_publication_id != publication_id
                    or self._active_by_session.get(state.session_id)
                    != state.permit_id
                    or state.context is not context
                    or state.context_ledger is not context_ledger
                ):
                    return False
                transition_started = True
                state.status = "abandoning"
            context_ledger._finish_gate_activity(
                context=context,
                attempt_gate=self,
                activity_id=state.permit_id,
                action=terminal,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
        except BaseException:
            with self._lock:
                if transition_started and state.status == "abandoning":
                    state.status = "resolved"
        else:
            with self._lock:
                if transition_started and state.status == "abandoning":
                    state.status = "resolved"
        with self._lock:
            return (
                state.status in ("abandoned", "finished")
                and state.resolver_claim_id is None
                and state.resolved_publication_id is None
                and state.session_id not in self._active_by_session
            )

    def _recover_claimed_credential_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        claim_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Recovery entry point for one exact resolver-owned claim."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential cleanup recovery requires resolver")
        return self._recover_claimed_credential_state_for_cleanup(
            permit,
            claim_id=claim_id,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )

    def _recover_claimed_credential_state_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        claim_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Independent ledger path for retrying claimed cleanup."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential cleanup recovery requires resolver")
        if (
            type(permit) is not CredentialResolutionPermit
            or type(claim_id) is not UUID
        ):
            return False
        with self._lock:
            matches = [
                state
                for key, state in self._credential_permits.items()
                if state.permit is permit
                and state.permit_id == key
            ]
            if len(matches) != 1:
                return False
            state = matches[0]
            if state.status in ("abandoned", "finished"):
                return True
            if (
                state.status
                not in ("claiming", "resolving", "confirming", "failing")
                or state.resolver_claim_id != claim_id
                or self._active_by_session.get(state.session_id)
                != state.permit_id
                or state.context is None
                or state.context_ledger is None
            ):
                return False
            previous_status = (
                "resolving" if state.status == "failing" else state.status
            )
            context = state.context
            context_ledger = state.context_ledger

        def terminal() -> None:
            with self._lock:
                if (
                    self._credential_permits.get(state.permit_id) is not state
                    or state.status != "failing"
                    or state.resolver_claim_id != claim_id
                ):
                    raise _attempt_error(
                        "credential claim cleanup recovery 状态已经变化。"
                    )
                self._commit_recovered_credential_terminal_locked(
                    permit=permit,
                    state=state,
                )

        transition_started = False
        try:
            with self._lock:
                if (
                    self._credential_permits.get(state.permit_id) is not state
                    or state.status
                    not in (
                        previous_status,
                        "failing",
                    )
                    or state.resolver_claim_id != claim_id
                    or self._active_by_session.get(state.session_id)
                    != state.permit_id
                    or state.context is not context
                    or state.context_ledger is not context_ledger
                ):
                    return False
                transition_started = True
                state.status = "failing"
            context_ledger._finish_gate_activity(
                context=context,
                attempt_gate=self,
                activity_id=state.permit_id,
                action=terminal,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
        except BaseException:
            with self._lock:
                if (
                    transition_started
                    and state.status == "failing"
                    and state.resolver_claim_id == claim_id
                ):
                    state.status = previous_status
        else:
            with self._lock:
                if (
                    transition_started
                    and state.status == "failing"
                    and state.resolver_claim_id == claim_id
                ):
                    state.status = previous_status
        with self._lock:
            return (
                state.status in ("abandoned", "finished")
                and state.resolver_claim_id is None
                and state.resolved_publication_id is None
                and state.session_id not in self._active_by_session
            )

    def _commit_attempt_terminal_locked(
        self,
        *,
        permit: AttemptPermit,
        state: _AttemptPermitState,
        credential: CredentialResolutionPermit,
        credential_state: _CredentialPermitState,
        terminal_status: str,
    ) -> None:
        """Atomically release a credential/attempt pair or restore both."""

        active_id = self._active_by_session.get(permit.session_id)
        if active_id != permit.credential_permit_id:
            raise _attempt_error("attempt 的 active session 绑定已经变化。")
        credential_snapshot = self._snapshot_slots(credential)
        permit_snapshot = self._snapshot_slots(permit)
        old_attempt_status = state.status
        old_transport_claim_id = state.transport_claim_id
        old_terminal_guard_id = state.terminal_guard_id
        old_terminal_guard_digest = state.terminal_guard_digest
        old_dns_start_id = state.dns_start_id
        old_credential_borrow_id = state.credential_borrow_id
        old_wire_commit_id = state.wire_commit_id
        old_wire_evidence_digest = state.wire_evidence_digest
        old_wire_borrow_id = state.wire_borrow_id
        old_credential_status = credential_state.status
        old_credential_publication_id = (
            credential_state.resolved_publication_id
        )
        old_recovery_refs = state.recovery_refs()
        old_credential_recovery_refs = credential_state.recovery_refs()
        helper_stop_snapshot = self._helper_stop_release_snapshot_locked(
            permit.credential_permit_id
        )
        try:
            self._release_helper_stop_locked(helper_stop_snapshot)
            if not self._helper_stop_release_is_committed_locked(
                helper_stop_snapshot,
                credential_permit_id=permit.credential_permit_id,
            ):
                raise _attempt_error(
                    "helper stop authority terminal release 未提交。"
                )
            credential._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            permit._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            if not self._credential_permit_refs_are_released(credential):
                raise _attempt_error(
                    "credential permit authority refs 未释放。"
                )
            if not self._attempt_permit_refs_are_released(permit):
                raise _attempt_error("attempt permit authority refs 未释放。")
            state.status = terminal_status
            state.transport_claim_id = None
            state.terminal_guard_id = None
            state.terminal_guard_digest = None
            state.dns_start_id = None
            state.credential_borrow_id = None
            state.wire_commit_id = None
            state.wire_evidence_digest = None
            state.wire_borrow_id = None
            credential_state.status = "finished"
            credential_state.resolved_publication_id = None
            if (
                self._active_by_session.get(permit.session_id)
                != permit.credential_permit_id
            ):
                raise _attempt_error("attempt 的 active session 绑定已经变化。")
            del self._active_by_session[permit.session_id]
            state.clear_recovery_refs()
            credential_state.clear_recovery_refs()
            if state.recovery_refs() != (None, None, None, None):
                raise _attempt_error("attempt recovery refs 未释放。")
            if credential_state.recovery_refs() != (None, None):
                raise _attempt_error(
                    "credential recovery refs 未释放。"
                )
        except BaseException:
            self._restore_slots(credential, credential_snapshot)
            self._restore_slots(permit, permit_snapshot)
            state.status = old_attempt_status
            state.transport_claim_id = old_transport_claim_id
            state.terminal_guard_id = old_terminal_guard_id
            state.terminal_guard_digest = old_terminal_guard_digest
            state.dns_start_id = old_dns_start_id
            state.credential_borrow_id = old_credential_borrow_id
            state.wire_commit_id = old_wire_commit_id
            state.wire_evidence_digest = old_wire_evidence_digest
            state.wire_borrow_id = old_wire_borrow_id
            credential_state.status = old_credential_status
            credential_state.resolved_publication_id = (
                old_credential_publication_id
            )
            state.restore_recovery_refs(old_recovery_refs)
            credential_state.restore_recovery_refs(
                old_credential_recovery_refs
            )
            self._active_by_session[permit.session_id] = active_id
            self._restore_helper_stop_locked(helper_stop_snapshot)
            raise

    def _require_credential_state_locked(
        self,
        permit: CredentialResolutionPermit,
    ) -> _CredentialPermitState:
        state = self._lookup_credential_state_locked(permit)
        if self._active_by_session.get(permit.session_id) != permit.permit_id:
            raise _attempt_error("凭据解析授权当前不可用。")
        return state

    def reserve_attempt(
        self,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
    ) -> AttemptPermit:
        if type(credential_permit) is not CredentialResolutionPermit:
            raise TypeError(
                "credential_permit must be CredentialResolutionPermit"
            )
        if type(credential_handle_id) is not UUID:
            raise TypeError("credential_handle_id must be UUID")
        if type(credential_handle_digest) is not Digest256:
            raise TypeError("credential_handle_digest must be Digest256")
        if credential_permit._attempt_gate is not self:
            raise _attempt_error("凭据解析授权不属于当前 AttemptGate。")
        with self._lock:
            initial_state = self._require_credential_state_locked(
                credential_permit
            )
            if (
                initial_state.status != "resolved"
                or initial_state.resolved_binding
                != credential_permit.credential_binding_digest
                or initial_state.credential_handle_id != credential_handle_id
                or initial_state.credential_handle_digest
                != credential_handle_digest
            ):
                raise _attempt_error(
                    "凭据尚未按批准 binding 和调用方句柄证明解析。"
                )
            bindings = (
                credential_permit._planned,
                credential_permit._invocation,
                credential_permit._prepared,
                credential_permit._authorization,
                credential_permit._consent_ledger,
                credential_permit._session,
                credential_permit._approval_ledger,
                credential_permit._session_ledger,
                credential_permit._authority_ledger,
                credential_permit._context,
                credential_permit._context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings

        def reserve(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
        ) -> AttemptPermit:
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            transition_started = False
            try:
                with self._lock:
                    state = self._require_credential_state_locked(
                        credential_permit
                    )
                    if (
                        state is not initial_state
                        or state.status != "resolved"
                        or state.resolved_binding
                        != credential_permit.credential_binding_digest
                        or state.credential_handle_id != credential_handle_id
                        or state.credential_handle_digest
                        != credential_handle_digest
                    ):
                        raise _attempt_error(
                            "凭据尚未按批准 binding 和调用方句柄证明解析。"
                        )
                    # Context lock is already held by _run_authority_path.  The
                    # rollback handler begins before this first visible write.
                    transition_started = True
                    state.status = "reserving"

                def build(
                    reservation: AttemptBudgetReservation,
                ) -> AttemptPermit:
                    candidate_permit: AttemptPermit | None = None
                    candidate_state: _AttemptPermitState | None = None
                    try:
                        with self._lock:
                            current = self._require_credential_state_locked(
                                credential_permit
                            )
                            if (
                                current is not initial_state
                                or current.status != "reserving"
                            ):
                                raise _attempt_error(
                                    "凭据解析授权已经消费。"
                                )
                            candidate_permit = AttemptPermit(
                                credential_permit=credential_permit,
                                credential_handle_id=(
                                    current.credential_handle_id
                                ),
                                credential_handle_digest=(
                                    current.credential_handle_digest
                                ),
                                reservation=reservation,
                                attempt_gate=self,
                                _authority=_PERMIT_FACTORY_AUTHORITY,
                            )
                            candidate_state = _AttemptPermitState(
                                candidate_permit
                            )
                            self._attempt_permits[
                                candidate_permit.attempt_permit_id
                            ] = candidate_state
                            # ``consumed`` is the publication marker.  Any
                            # exception before the callback returns removes the
                            # exact candidate and restores ``reserving`` so the
                            # enclosing Context transaction can roll back.
                            current.status = "consumed"
                            return candidate_permit
                    except BaseException:
                        with self._lock:
                            if (
                                candidate_permit is not None
                                and candidate_state is not None
                                and self._attempt_permits.get(
                                    candidate_permit.attempt_permit_id
                                )
                                is candidate_state
                            ):
                                del self._attempt_permits[
                                    candidate_permit.attempt_permit_id
                                ]
                            if (
                                self._credential_permits.get(
                                    initial_state.permit_id
                                )
                                is initial_state
                                and initial_state.status == "consumed"
                            ):
                                initial_state.status = "reserving"
                            if candidate_permit is not None:
                                candidate_permit._release_authority_refs(
                                    _authority=_PERMIT_RELEASE_AUTHORITY,
                                )
                        raise

                candidate = context_ledger._reserve_attempt_budgets(
                    context=context,
                    session_id=credential_permit.session_id,
                    session_valid_until=session.valid_until,
                    attempt_gate=self,
                    operation_id=operation.operation_id,
                    request_envelope_digest=(
                        credential_permit.request_envelope_digest
                    ),
                    billable=operation.billable,
                    action=build,
                    _authority=_ATTEMPT_BUDGET_AUTHORITY,
                )
                with self._lock:
                    current = self._require_credential_state_locked(
                        credential_permit
                    )
                    attempt_state = (
                        self._attempt_permits.get(
                            candidate.attempt_permit_id
                        )
                        if type(candidate) is AttemptPermit
                        else None
                    )
                    if (
                        current is not initial_state
                        or current.status != "consumed"
                        or attempt_state is None
                        or attempt_state.permit is not candidate
                        or attempt_state.status != "active"
                        or attempt_state.credential_permit
                        is not credential_permit
                        or attempt_state.credential_handle_id
                        != credential_handle_id
                        or attempt_state.credential_handle_digest
                        != credential_handle_digest
                    ):
                        raise _attempt_error(
                            "attempt reservation transaction 未提交。"
                        )
                return candidate
            except BaseException:
                with self._lock:
                    if (
                        transition_started
                        and self._credential_permits.get(
                            initial_state.permit_id
                        )
                        is initial_state
                        and initial_state.status == "reserving"
                    ):
                        initial_state.status = "resolved"
                raise

        candidate = self._run_authority_path(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            session=session,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            authority_ledger=authority_ledger,
            context=context,
            context_ledger=context_ledger,
            final_action=reserve,
        )
        with self._lock:
            published = (
                self._attempt_permits.get(candidate.attempt_permit_id)
                if type(candidate) is AttemptPermit
                else None
            )
            if (
                published is None
                or published.permit is not candidate
                or published.status != "active"
                or published.credential_permit is not credential_permit
                or published.credential_handle_id != credential_handle_id
                or published.credential_handle_digest != credential_handle_digest
            ):
                raise _attempt_error(
                    "attempt reservation publication 未提交。"
                )
        return candidate

    def _find_published_attempt_for_cleanup_locked(
        self,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
    ) -> tuple[
        AttemptPermit,
        _AttemptPermitState,
        _CredentialPermitState,
    ] | None:
        """Find one exact active/unclaimed attempt while ``_lock`` is held."""

        credential_matches = [
            state
            for key, state in self._credential_permits.items()
            if state.permit is credential_permit
            and state.permit_id == key
        ]
        if len(credential_matches) != 1:
            return None
        credential_state = credential_matches[0]
        if (
            credential_state.status != "consumed"
            or credential_state.credential_handle_id != credential_handle_id
            or credential_state.credential_handle_digest
            != credential_handle_digest
            or self._active_by_session.get(credential_state.session_id)
            != credential_state.permit_id
        ):
            return None

        matches: list[
            tuple[AttemptPermit, _AttemptPermitState, _CredentialPermitState]
        ] = []
        for candidate_state in self._attempt_permits.values():
            candidate = candidate_state.permit
            if (
                candidate_state.status != "active"
                or candidate_state.transport_claim_id is not None
                or candidate_state.terminal_guard_id is not None
                or candidate_state.terminal_guard_digest is not None
                or candidate_state.dns_start_id is not None
                or candidate_state.credential_borrow_id is not None
                or not self._wire_state_is_well_formed(candidate_state)
                or candidate_state.resolver_completion_status != "uncommitted"
                or not self._resolver_completion_proof_is_well_formed(
                    candidate_state,
                    allow_committing=False,
                )
                or type(candidate) is not AttemptPermit
                or candidate_state.credential_permit is not credential_permit
                or candidate_state.credential_permit_id
                != credential_state.permit_id
                or candidate_state.credential_handle_id != credential_handle_id
                or candidate_state.credential_handle_digest
                != credential_handle_digest
            ):
                continue
            matches.append((candidate, candidate_state, credential_state))
            if len(matches) > 1:
                return None
        return matches[0] if len(matches) == 1 else None

    def _commit_recovered_attempt_terminal_locked(
        self,
        *,
        permit: AttemptPermit,
        state: _AttemptPermitState,
        credential_state: _CredentialPermitState,
        terminal_status: str,
    ) -> None:
        """Terminalize from ledger snapshots, never returned permit fields."""

        credential = state.credential_permit
        active_id = self._active_by_session.get(state.session_id)
        if (
            type(credential) is not CredentialResolutionPermit
            or credential_state.permit is not credential
            or self._attempt_permits.get(state.attempt_permit_id) is not state
            or state.permit is not permit
            or active_id != state.credential_permit_id
        ):
            raise _attempt_error("attempt cleanup recovery owner 已变化。")
        credential_snapshot = self._snapshot_slots(credential)
        permit_snapshot = self._snapshot_slots(permit)
        old_attempt_status = state.status
        old_transport_claim_id = state.transport_claim_id
        old_terminal_guard_id = state.terminal_guard_id
        old_terminal_guard_digest = state.terminal_guard_digest
        old_dns_start_id = state.dns_start_id
        old_credential_borrow_id = state.credential_borrow_id
        old_wire_commit_id = state.wire_commit_id
        old_wire_evidence_digest = state.wire_evidence_digest
        old_wire_borrow_id = state.wire_borrow_id
        old_credential_status = credential_state.status
        old_publication_id = credential_state.resolved_publication_id
        old_recovery_refs = state.recovery_refs()
        old_credential_recovery_refs = credential_state.recovery_refs()
        helper_stop_snapshot = self._helper_stop_release_snapshot_locked(
            state.credential_permit_id
        )
        try:
            self._release_helper_stop_locked(helper_stop_snapshot)
            if not self._helper_stop_release_is_committed_locked(
                helper_stop_snapshot,
                credential_permit_id=state.credential_permit_id,
            ):
                raise _attempt_error(
                    "helper stop authority terminal release 未提交。"
                )
            credential._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            permit._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            if not self._credential_permit_refs_are_released(credential):
                raise _attempt_error(
                    "credential permit authority refs 未释放。"
                )
            if not self._attempt_permit_refs_are_released(permit):
                raise _attempt_error("attempt permit authority refs 未释放。")
            state.status = terminal_status
            state.transport_claim_id = None
            state.terminal_guard_id = None
            state.terminal_guard_digest = None
            state.dns_start_id = None
            state.credential_borrow_id = None
            state.wire_commit_id = None
            state.wire_evidence_digest = None
            state.wire_borrow_id = None
            credential_state.status = "finished"
            credential_state.resolved_publication_id = None
            if (
                self._active_by_session.get(state.session_id)
                != state.credential_permit_id
            ):
                raise _attempt_error("attempt cleanup recovery session 已变化。")
            del self._active_by_session[state.session_id]
            state.clear_recovery_refs()
            credential_state.clear_recovery_refs()
            if state.recovery_refs() != (None, None, None, None):
                raise _attempt_error("attempt recovery refs 未释放。")
            if credential_state.recovery_refs() != (None, None):
                raise _attempt_error(
                    "credential recovery refs 未释放。"
                )
        except BaseException:
            self._restore_slots(credential, credential_snapshot)
            self._restore_slots(permit, permit_snapshot)
            state.status = old_attempt_status
            state.transport_claim_id = old_transport_claim_id
            state.terminal_guard_id = old_terminal_guard_id
            state.terminal_guard_digest = old_terminal_guard_digest
            state.dns_start_id = old_dns_start_id
            state.credential_borrow_id = old_credential_borrow_id
            state.wire_commit_id = old_wire_commit_id
            state.wire_evidence_digest = old_wire_evidence_digest
            state.wire_borrow_id = old_wire_borrow_id
            credential_state.status = old_credential_status
            credential_state.resolved_publication_id = old_publication_id
            state.restore_recovery_refs(old_recovery_refs)
            credential_state.restore_recovery_refs(
                old_credential_recovery_refs
            )
            self._active_by_session[state.session_id] = active_id
            self._restore_helper_stop_locked(helper_stop_snapshot)
            raise

    def _abandon_recovered_attempt_for_cleanup(
        self,
        permit: AttemptPermit,
        state: _AttemptPermitState,
        credential_state: _CredentialPermitState,
    ) -> None:
        """Release one independently snapshotted unclaimed attempt."""

        with self._lock:
            if (
                self._attempt_permits.get(state.attempt_permit_id) is not state
                or state.permit is not permit
                or state.status != "active"
                or state.transport_claim_id is not None
                or state.terminal_guard_id is not None
                or state.terminal_guard_digest is not None
                or state.dns_start_id is not None
                or state.credential_borrow_id is not None
                or not self._wire_state_is_well_formed(state)
                or state.resolver_completion_status != "uncommitted"
                or not self._resolver_completion_proof_is_well_formed(
                    state,
                    allow_committing=False,
                )
            ):
                raise _attempt_error("attempt cleanup recovery 状态无效。")
        transition_started = False
        try:
            with self._lock:
                if (
                    self._attempt_permits.get(state.attempt_permit_id)
                    is not state
                    or state.permit is not permit
                    or state.status != "active"
                    or state.transport_claim_id is not None
                    or state.terminal_guard_id is not None
                    or state.terminal_guard_digest is not None
                    or state.dns_start_id is not None
                    or state.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(state)
                    or state.resolver_completion_status != "uncommitted"
                    or not self._resolver_completion_proof_is_well_formed(
                        state,
                        allow_committing=False,
                    )
                    or self._credential_permits.get(
                        state.credential_permit_id
                    )
                    is not credential_state
                ):
                    raise _attempt_error(
                        "attempt cleanup recovery 状态无效。"
                    )
                transition_started = True
                state.status = "abandoning"

            def terminal() -> None:
                with self._lock:
                    if (
                        self._attempt_permits.get(state.attempt_permit_id)
                        is not state
                        or state.status != "abandoning"
                        or self._credential_permits.get(
                            state.credential_permit_id
                        )
                        is not credential_state
                    ):
                        raise _attempt_error(
                            "attempt cleanup recovery 状态已经变化。"
                        )
                    self._commit_recovered_attempt_terminal_locked(
                        permit=permit,
                        state=state,
                        credential_state=credential_state,
                        terminal_status="abandoned",
                    )

            state.context_ledger._finish_attempt_and_activity(
                context=state.context,
                reservation=state.reservation,
                attempt_gate=self,
                activity_id=state.credential_permit_id,
                action=terminal,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
        except BaseException:
            with self._lock:
                if transition_started and state.status == "abandoning":
                    state.status = "active"
            raise
        with self._lock:
            if transition_started and state.status == "abandoning":
                state.status = "active"
                raise _attempt_error(
                    "attempt cleanup transaction 未提交。"
                )

    def _recover_attempt_for_cleanup(
        self,
        permit: AttemptPermit,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
        claim_id: UUID,
        guard_id: UUID | None,
        guard_digest: Digest256 | None,
        _authority: object | None = None,
    ) -> bool:
        """Terminalize an assigned attempt from ledger-owned owner snapshots."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt cleanup recovery requires transport")
        if (
            type(permit) is not AttemptPermit
            or type(credential_permit) is not CredentialResolutionPermit
            or type(credential_handle_id) is not UUID
            or type(credential_handle_digest) is not Digest256
            or type(claim_id) is not UUID
            or (guard_id is None) != (guard_digest is None)
            or (guard_id is not None and type(guard_id) is not UUID)
            or (
                guard_digest is not None
                and type(guard_digest) is not Digest256
            )
        ):
            return False
        with self._lock:
            matches = [
                state
                for key, state in self._attempt_permits.items()
                if state.permit is permit
                and state.attempt_permit_id == key
            ]
            if len(matches) != 1:
                return False
            state = matches[0]
            credential_state = self._credential_permits.get(
                state.credential_permit_id
            )
            if (
                credential_state is None
                or credential_state.permit is not credential_permit
                or state.credential_handle_id != credential_handle_id
                or state.credential_handle_digest != credential_handle_digest
            ):
                return False
            if state.status in ("finished", "abandoned"):
                return (
                    state.credential_permit is None
                    and state.context is None
                    and state.context_ledger is None
                    and state.reservation is None
                    and credential_state.status == "finished"
                    and credential_state.context is None
                    and credential_state.context_ledger is None
                    and self._wire_state_is_well_formed(state)
                    and state.session_id not in self._active_by_session
                )
            if state.credential_permit is not credential_permit:
                return False
            if state.status == "active":
                if (
                    state.transport_claim_id is not None
                    or state.terminal_guard_id is not None
                    or state.terminal_guard_digest is not None
                    or state.dns_start_id is not None
                    or state.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(state)
                    or state.resolver_completion_status != "uncommitted"
                    or not self._resolver_completion_proof_is_well_formed(
                        state,
                        allow_committing=False,
                    )
                ):
                    return False
                cleanup_kind = "abandon"
            else:
                if (
                    state.status not in ("io_claimed", "wire_committed")
                    or state.transport_claim_id != claim_id
                    or state.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(state)
                    or not self._resolver_completion_proof_is_well_formed(
                        state,
                        allow_committing=False,
                    )
                ):
                    return False
                if state.terminal_guard_id is None:
                    if state.terminal_guard_digest is not None:
                        return False
                elif (
                    state.terminal_guard_id != guard_id
                    or state.terminal_guard_digest != guard_digest
                ):
                    return False
                cleanup_kind = "finish"
            if credential_state.permit is not state.credential_permit:
                return False

        if cleanup_kind == "abandon":
            try:
                self._abandon_recovered_attempt_for_cleanup(
                    permit,
                    state,
                    credential_state,
                )
            except BaseException:
                pass
        else:
            with self._lock:
                if (
                    state.status not in ("io_claimed", "wire_committed")
                    or not self._wire_state_is_well_formed(state)
                    or not self._resolver_completion_proof_is_well_formed(
                        state,
                        allow_committing=False,
                    )
                ):
                    return state.status in ("finished", "abandoned")
                previous_status = state.status
            transition_started = False
            try:
                with self._lock:
                    if (
                        self._attempt_permits.get(state.attempt_permit_id)
                        is not state
                        or state.status != previous_status
                        or state.transport_claim_id != claim_id
                        or state.credential_borrow_id is not None
                        or not self._wire_state_is_well_formed(state)
                        or not self._resolver_completion_proof_is_well_formed(
                            state,
                            allow_committing=False,
                        )
                    ):
                        return state.status in ("finished", "abandoned")
                    transition_started = True
                    state.status = "finishing"

                def terminal() -> None:
                    with self._lock:
                        if (
                            self._attempt_permits.get(state.attempt_permit_id)
                            is not state
                            or state.status != "finishing"
                            or state.transport_claim_id != claim_id
                            or self._credential_permits.get(
                                state.credential_permit_id
                            )
                            is not credential_state
                        ):
                            raise _attempt_error(
                                "attempt cleanup recovery 状态已经变化。"
                            )
                        if state.terminal_guard_id is None:
                            if state.terminal_guard_digest is not None:
                                raise _attempt_error(
                                    "attempt cleanup recovery guard 无效。"
                                )
                        elif (
                            state.terminal_guard_id != guard_id
                            or state.terminal_guard_digest != guard_digest
                        ):
                            raise _attempt_error(
                                "attempt cleanup recovery guard 已变化。"
                            )
                        self._commit_recovered_attempt_terminal_locked(
                            permit=permit,
                            state=state,
                            credential_state=credential_state,
                            terminal_status="finished",
                        )

                state.context_ledger._finish_attempt_and_activity(
                    context=state.context,
                    reservation=state.reservation,
                    attempt_gate=self,
                    activity_id=state.credential_permit_id,
                    action=terminal,
                    _authority=_ATTEMPT_BUDGET_AUTHORITY,
                )
                with self._lock:
                    if (
                        transition_started
                        and state.status == "finishing"
                        and state.transport_claim_id == claim_id
                    ):
                        state.status = previous_status
            except BaseException:
                with self._lock:
                    if (
                        transition_started
                        and state.status == "finishing"
                        and state.transport_claim_id == claim_id
                    ):
                        state.status = previous_status

        with self._lock:
            return (
                state.status in ("finished", "abandoned")
                and state.transport_claim_id is None
                and state.terminal_guard_id is None
                and state.terminal_guard_digest is None
                and state.dns_start_id is None
                and state.credential_borrow_id is None
                and self._wire_state_is_well_formed(state)
                and credential_state.status == "finished"
                and credential_state.resolved_publication_id is None
                and state.session_id not in self._active_by_session
            )

    def _recover_published_attempt_for_cleanup(
        self,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Recover and abandon one published, unclaimed attempt.

        This recovery capability never claims an attempt and never returns a
        permit that could authorize transport.  A terminal ledger observation
        also handles the case where abandonment commits immediately before an
        injected outer exception.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt cleanup recovery requires transport")
        if (
            type(credential_permit) is not CredentialResolutionPermit
            or type(credential_handle_id) is not UUID
            or type(credential_handle_digest) is not Digest256
        ):
            return False
        with self._lock:
            recovered = self._find_published_attempt_for_cleanup_locked(
                credential_permit=credential_permit,
                credential_handle_id=credential_handle_id,
                credential_handle_digest=credential_handle_digest,
            )
            if recovered is None:
                return False
            attempt, state, credential_state = recovered
            credential_permit_id = credential_state.permit_id
            session_id = credential_state.session_id
        try:
            self._abandon_recovered_attempt_for_cleanup(
                attempt,
                state,
                credential_state,
            )
        except BaseException:
            # The context-ledger transaction may have committed before an
            # injected wrapper raised.  Only the exact state captured above
            # can turn that post-commit fault into successful cleanup.
            pass
        with self._lock:
            return (
                state.permit is attempt
                and state.status in ("finished", "abandoned")
                and state.transport_claim_id is None
                and state.terminal_guard_id is None
                and state.terminal_guard_digest is None
                and state.dns_start_id is None
                and state.credential_borrow_id is None
                and self._wire_state_is_well_formed(state)
                and self._credential_permits.get(credential_permit_id)
                is credential_state
                and credential_state.permit is credential_permit
                and credential_state.status == "finished"
                and credential_state.resolved_publication_id is None
                and session_id not in self._active_by_session
            )

    def _attempt_terminal_state_for_cleanup(
        self,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
        attempt: AttemptPermit | None = None,
        _authority: object | None = None,
    ) -> str:
        """Classify exact attempt cleanup without trusting recovery calls.

        ``attempt`` is the candidate returned to the coordinator when that
        assignment completed.  A ``None`` candidate covers the narrower
        reserve publication window: the frozen credential permit and handle
        proof can establish that publication is absent, active, or terminal.
        Multiple matches and malformed or identity-mismatched records are
        always ``"ambiguous"``.

        This method only observes Gate-owned state.  It never attempts cleanup
        and the transport-only authority prevents it becoming a public proof
        oracle or attempt capability.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt cleanup observation requires transport")
        if (
            type(credential_permit) is not CredentialResolutionPermit
            or type(credential_handle_id) is not UUID
            or type(credential_handle_digest) is not Digest256
            or (attempt is not None and type(attempt) is not AttemptPermit)
        ):
            return "ambiguous"

        with self._lock:
            credential_matches = [
                state
                for key, state in self._credential_permits.items()
                if state.permit_id == key
                and state.permit is credential_permit
                and state.credential_handle_id == credential_handle_id
                and state.credential_handle_digest
                == credential_handle_digest
            ]
            if len(credential_matches) != 1:
                return "ambiguous"
            credential_state = credential_matches[0]

            attempt_matches = [
                state
                for key, state in self._attempt_permits.items()
                if state.attempt_permit_id == key
                and state.credential_permit_id
                == credential_state.permit_id
                and state.credential_handle_id == credential_handle_id
                and state.credential_handle_digest
                == credential_handle_digest
            ]
            if not attempt_matches:
                if attempt is not None:
                    return "ambiguous"
                active_absence = (
                    credential_state.status == "resolved"
                    and credential_state.resolver_claim_id is None
                    and type(credential_state.resolved_publication_id) is UUID
                    and credential_state.recovery_refs()
                    == (
                        credential_state.context,
                        credential_state.context_ledger,
                    )
                    and credential_state.context is not None
                    and credential_state.context_ledger is not None
                    and self._active_by_session.get(
                        credential_state.session_id
                    )
                    == credential_state.permit_id
                    and sum(
                        active_id == credential_state.permit_id
                        for active_id in self._active_by_session.values()
                    )
                    == 1
                )
                terminal_absence = (
                    credential_state.status in ("abandoned", "finished")
                    and credential_state.resolver_claim_id is None
                    and credential_state.resolved_publication_id is None
                    and credential_state.recovery_refs() == (None, None)
                    and self._credential_permit_refs_are_released(
                        credential_permit
                    )
                    and credential_state.session_id
                    not in self._active_by_session
                    and credential_state.permit_id
                    not in self._active_by_session.values()
                    and self._helper_stop_is_terminal_for_credential_locked(
                        credential_state.permit_id
                    )
                )
                return (
                    "absent"
                    if active_absence or terminal_absence
                    else "ambiguous"
                )
            if len(attempt_matches) != 1:
                return "ambiguous"
            attempt_state = attempt_matches[0]
            published_attempt = attempt_state.permit
            if (
                type(published_attempt) is not AttemptPermit
                or (
                    attempt is not None
                    and published_attempt is not attempt
                )
            ):
                return "ambiguous"

            exact_binding = (
                (attempt is None or published_attempt is attempt)
                and type(attempt_state.attempt_permit_id) is UUID
                and type(attempt_state.attempt_permit_digest) is Digest256
                and type(credential_state.permit_id) is UUID
                and type(credential_state.session_id) is UUID
                and self._attempt_permits.get(
                    attempt_state.attempt_permit_id
                )
                is attempt_state
                and self._credential_permits.get(
                    attempt_state.credential_permit_id
                )
                is credential_state
                and credential_state.permit is credential_permit
                and attempt_state.permit is published_attempt
                and attempt_state.session_id == credential_state.session_id
            )
            if not exact_binding:
                return "ambiguous"

            terminal = (
                attempt_state.status in ("finished", "abandoned")
                and attempt_state.transport_claim_id is None
                and attempt_state.terminal_guard_id is None
                and attempt_state.terminal_guard_digest is None
                and attempt_state.dns_start_id is None
                and attempt_state.credential_borrow_id is None
                and self._wire_state_is_well_formed(attempt_state)
                and self._resolver_completion_proof_is_well_formed(
                    attempt_state,
                    allow_committing=False,
                )
                and attempt_state.recovery_refs()
                == (None, None, None, None)
                and self._attempt_permit_refs_are_released(
                    published_attempt
                )
                and credential_state.status == "finished"
                and credential_state.resolver_claim_id is None
                and credential_state.resolved_publication_id is None
                and credential_state.recovery_refs() == (None, None)
                and self._credential_permit_refs_are_released(
                    credential_permit
                )
                and credential_state.session_id
                not in self._active_by_session
                and credential_state.permit_id
                not in self._active_by_session.values()
                and self._helper_stop_is_terminal_for_credential_locked(
                    credential_state.permit_id
                )
            )
            if terminal:
                return "terminal"

            active = (
                attempt_state.status
                in (
                    "active",
                    "claiming",
                    "io_claimed",
                    "guard_binding",
                    "dns_starting",
                    "wire_committing",
                    "wire_committed",
                    "abandoning",
                    "finishing",
                )
                and attempt_state.credential_permit is credential_permit
                and attempt_state.context is credential_state.context
                and attempt_state.context_ledger
                is credential_state.context_ledger
                and attempt_state.context is not None
                and attempt_state.context_ledger is not None
                and attempt_state.reservation is not None
                and self._wire_state_is_well_formed(attempt_state)
                and self._resolver_completion_proof_is_well_formed(
                    attempt_state,
                    allow_committing=False,
                )
                and credential_state.status == "consumed"
                and credential_state.resolver_claim_id is None
                and type(credential_state.resolved_publication_id) is UUID
                and credential_state.recovery_refs()
                == (
                    credential_state.context,
                    credential_state.context_ledger,
                )
                and self._active_by_session.get(
                    credential_state.session_id
                )
                == credential_state.permit_id
                and sum(
                    active_id == credential_state.permit_id
                    for active_id in self._active_by_session.values()
                )
                == 1
            )
            return "active" if active else "ambiguous"

    def _attempt_is_terminal_for_cleanup(
        self,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
        attempt: AttemptPermit | None = None,
        _authority: object | None = None,
    ) -> bool:
        """Observe terminal Gate state independently of recovery results."""

        return self._attempt_terminal_state_for_cleanup(
            credential_permit=credential_permit,
            credential_handle_id=credential_handle_id,
            credential_handle_digest=credential_handle_digest,
            attempt=attempt,
            _authority=_authority,
        ) == "terminal"

    @staticmethod
    def _resolver_completion_proof_is_well_formed(
        state: _AttemptPermitState,
        *,
        allow_committing: bool,
    ) -> bool:
        status = state.resolver_completion_status
        proof = (
            state.resolver_completion_authority_id,
            state.resolver_completion_claim_id,
            state.resolver_completion_guard_id,
            state.resolver_completion_guard_digest,
            state.resolver_completion_start_id,
            state.resolver_completion_receipt_digest,
        )
        if status == "uncommitted":
            return all(value is None for value in proof)
        if status == "committing":
            return allow_committing and all(value is None for value in proof)
        if status != "committed":
            return False
        return (
            type(proof[0]) is UUID
            and type(proof[1]) is UUID
            and type(proof[2]) is UUID
            and type(proof[3]) is Digest256
            and type(proof[4]) is UUID
            and type(proof[5]) is Digest256
        )

    def _lookup_attempt_state_locked(
        self,
        permit: AttemptPermit,
    ) -> _AttemptPermitState:
        if type(permit) is not AttemptPermit:
            raise TypeError("permit must be AttemptPermit")
        valid = permit._attempt_gate is self
        if valid:
            try:
                permit.validate_integrity()
            except (TypeError, ValueError, AttributeError):
                valid = False
        state = (
            self._attempt_permits.get(permit.attempt_permit_id)
            if valid
            else None
        )
        if state is None or state.permit is not permit:
            raise _attempt_error("attempt permit 不属于当前 AttemptGate。")
        return state

    def _require_attempt_credential_proof_locked(
        self,
        permit: AttemptPermit,
    ) -> CredentialResolutionPermit:
        credential = permit._credential_permit
        credential_state = self._credential_permits.get(
            permit.credential_permit_id
        )
        if (
            type(credential) is not CredentialResolutionPermit
            or credential_state is None
            or credential_state.permit is not credential
            or credential_state.status != "consumed"
            or credential_state.credential_handle_id
            != permit.credential_handle_id
            or credential_state.credential_handle_digest
            != permit.credential_handle_digest
            or self._active_by_session.get(permit.session_id)
            != permit.credential_permit_id
        ):
            raise _attempt_error("attempt 的凭据句柄证明已经变化。")
        return credential

    @staticmethod
    def _require_transport_owner_locked(
        state: _AttemptPermitState,
        claim_id: UUID,
    ) -> None:
        if state.transport_claim_id != claim_id:
            raise _attempt_error("attempt 不属于当前 transport owner。")

    @staticmethod
    def _require_terminal_guard_proof_locked(
        state: _AttemptPermitState,
        *,
        guard_id: UUID | None,
        guard_digest: Digest256 | None,
    ) -> None:
        if state.terminal_guard_id is None:
            if guard_id is not None or guard_digest is not None:
                raise _attempt_error("attempt 尚未绑定 terminal guard。")
            return
        if (
            state.terminal_guard_id != guard_id
            or state.terminal_guard_digest != guard_digest
        ):
            raise _attempt_error("attempt 的 terminal guard 证明不匹配。")

    @staticmethod
    def _wire_state_is_well_formed(state: _AttemptPermitState) -> bool:
        values = (
            state.wire_commit_id,
            state.wire_evidence_digest,
            state.wire_borrow_id,
        )
        if state.status in ("wire_committing", "wire_committed"):
            return (
                type(values[0]) is UUID
                and type(values[1]) is Digest256
                and type(values[2]) is UUID
            )
        if state.status == "finishing":
            return values == (None, None, None) or (
                type(values[0]) is UUID
                and type(values[1]) is Digest256
                and type(values[2]) is UUID
            )
        return values == (None, None, None)

    def _claim_attempt(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        expected_credential_permit: CredentialResolutionPermit | None = None,
        expected_credential_handle_id: UUID | None = None,
        expected_credential_handle_digest: Digest256 | None = None,
        _authority: object | None = None,
    ) -> AttemptPermit:
        """Revalidate and atomically assign one transport owner before I/O."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt claim requires trusted transport")
        if type(claim_id) is not UUID:
            raise _attempt_error("transport claim owner 无效。")
        if type(permit) is not AttemptPermit:
            raise TypeError("permit must be AttemptPermit")
        expected_binding_supplied = any(
            value is not None
            for value in (
                expected_credential_permit,
                expected_credential_handle_id,
                expected_credential_handle_digest,
            )
        )
        if expected_binding_supplied and (
            type(expected_credential_permit)
            is not CredentialResolutionPermit
            or type(expected_credential_handle_id) is not UUID
            or type(expected_credential_handle_digest) is not Digest256
        ):
            raise _attempt_error("attempt expected credential proof 不完整。")
        with self._lock:
            initial_state = self._lookup_attempt_state_locked(permit)
            if expected_binding_supplied and (
                initial_state.credential_permit
                is not expected_credential_permit
                or initial_state.credential_handle_id
                != expected_credential_handle_id
                or initial_state.credential_handle_digest
                != expected_credential_handle_digest
            ):
                raise _attempt_error("attempt 不属于预期 credential owner。")
            if (
                initial_state.status != "active"
                or initial_state.transport_claim_id is not None
                or initial_state.terminal_guard_id is not None
                or initial_state.terminal_guard_digest is not None
                or initial_state.dns_start_id is not None
                or initial_state.credential_borrow_id is not None
                or not self._wire_state_is_well_formed(initial_state)
            ):
                raise _attempt_error("attempt permit 已被领取或终结。")
            credential = self._require_attempt_credential_proof_locked(permit)
            bindings = (
                credential._planned,
                credential._invocation,
                credential._prepared,
                credential._authorization,
                credential._consent_ledger,
                credential._session,
                credential._approval_ledger,
                credential._session_ledger,
                credential._authority_ledger,
                credential._context,
                credential._context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings

        def claim(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
        ) -> AttemptPermit:
            del stage, operation
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            with self._lock:
                state = self._lookup_attempt_state_locked(permit)
                if (
                    state.status != "claiming"
                    or state.transport_claim_id != claim_id
                    or state.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(state)
                ):
                    raise _attempt_error("attempt permit 已被领取或终结。")
                if expected_binding_supplied and (
                    state.credential_permit is not expected_credential_permit
                    or state.credential_handle_id
                    != expected_credential_handle_id
                    or state.credential_handle_digest
                    != expected_credential_handle_digest
                ):
                    raise _attempt_error(
                        "attempt expected credential proof 已变化。"
                    )
                self._require_attempt_credential_proof_locked(permit)
                state.status = "io_claimed"
                return permit

        transition_started = False
        try:
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not initial_state
                    or current.status != "active"
                    or current.transport_claim_id is not None
                    or current.terminal_guard_id is not None
                    or current.terminal_guard_digest is not None
                    or current.dns_start_id is not None
                    or current.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current)
                ):
                    raise _attempt_error(
                        "attempt permit 已被领取或终结。"
                    )
                if expected_binding_supplied and (
                    current.credential_permit
                    is not expected_credential_permit
                    or current.credential_handle_id
                    != expected_credential_handle_id
                    or current.credential_handle_digest
                    != expected_credential_handle_digest
                ):
                    raise _attempt_error(
                        "attempt expected credential proof 已变化。"
                    )
                self._require_attempt_credential_proof_locked(permit)
                transition_started = True
                current.status = "claiming"
                current.transport_claim_id = claim_id
            self._run_authority_path(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                authority_ledger=authority_ledger,
                context=context,
                context_ledger=context_ledger,
                final_action=claim,
            )
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not initial_state
                    or current.status != "io_claimed"
                    or current.transport_claim_id != claim_id
                    or current.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current)
                ):
                    raise _attempt_error(
                        "attempt claim transaction 未提交。"
                    )
                if expected_binding_supplied and (
                    current.credential_permit
                    is not expected_credential_permit
                    or current.credential_handle_id
                    != expected_credential_handle_id
                    or current.credential_handle_digest
                    != expected_credential_handle_digest
                ):
                    raise _attempt_error(
                        "attempt expected credential proof 已变化。"
                    )
                self._require_attempt_credential_proof_locked(permit)
        except BaseException:
            with self._lock:
                if (
                    self._attempt_permits.get(
                        initial_state.attempt_permit_id
                    )
                    is initial_state
                    and transition_started
                    and (
                        initial_state.status == "claiming"
                        and initial_state.transport_claim_id in (None, claim_id)
                        or initial_state.status == "active"
                        and initial_state.transport_claim_id == claim_id
                    )
                ):
                    initial_state.status = "active"
                    initial_state.transport_claim_id = None
            raise
        return permit

    def _claimed_attempt_snapshot_for_transport(
        self,
        permit: AttemptPermit,
        *,
        credential_permit: CredentialResolutionPermit,
        credential_handle_id: UUID,
        credential_handle_digest: Digest256,
        claim_id: UUID,
        _authority: object | None = None,
    ) -> tuple[UUID, Digest256]:
        """Return immutable ledger proof for one exact claimed attempt."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt claim attestation requires transport")
        if (
            type(permit) is not AttemptPermit
            or type(credential_permit) is not CredentialResolutionPermit
            or type(credential_handle_id) is not UUID
            or type(credential_handle_digest) is not Digest256
            or type(claim_id) is not UUID
        ):
            raise _attempt_error("attempt claim attestation proof 无效。")
        with self._lock:
            matches = [
                state
                for key, state in self._attempt_permits.items()
                if state.permit is permit and state.attempt_permit_id == key
            ]
            if len(matches) != 1:
                raise _attempt_error("attempt claim attestation owner 无效。")
            state = matches[0]
            credential_state = self._credential_permits.get(
                state.credential_permit_id
            )
            if (
                state.status != "io_claimed"
                or state.transport_claim_id != claim_id
                or not self._wire_state_is_well_formed(state)
                or state.credential_permit is not credential_permit
                or state.credential_handle_id != credential_handle_id
                or state.credential_handle_digest != credential_handle_digest
                or credential_state is None
                or credential_state.permit is not credential_permit
                or credential_state.status != "consumed"
                or self._active_by_session.get(state.session_id)
                != state.credential_permit_id
            ):
                raise _attempt_error("attempt claim attestation 未提交。")
            return state.attempt_permit_id, state.attempt_permit_digest

    def _attempt_claim_is_owned(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Observe an exact caller-generated owner after claim raises."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt claim observation requires transport")
        if type(claim_id) is not UUID:
            return False
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            return (
                state.transport_claim_id == claim_id
                and self._wire_state_is_well_formed(state)
                and state.status
                in (
                    "claiming",
                    "io_claimed",
                    "dns_starting",
                    "wire_committing",
                    "wire_committed",
                    "finishing",
                )
            )

    def _bind_terminal_guard(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Bind the proof of an already completed local helper handoff once."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("terminal guard binding requires trusted transport")
        if type(claim_id) is not UUID or type(guard_id) is not UUID:
            raise _attempt_error("transport 或 terminal guard owner 无效。")
        if type(guard_digest) is not Digest256:
            raise _attempt_error("terminal guard digest 无效。")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if (
                state.status != "io_claimed"
                or state.terminal_guard_id is not None
                or state.terminal_guard_digest is not None
                or state.dns_start_id is not None
                or state.credential_borrow_id is not None
                or state.resolver_completion_status != "uncommitted"
                or not self._wire_state_is_well_formed(state)
                or not self._resolver_completion_proof_is_well_formed(
                    state,
                    allow_committing=False,
                )
            ):
                raise _attempt_error("attempt 当前不能绑定 terminal guard。")
            self._require_transport_owner_locked(state, claim_id)
            self._require_attempt_credential_proof_locked(permit)
        transition_started = False
        try:
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not state
                    or current.status != "io_claimed"
                    or current.terminal_guard_id is not None
                    or current.terminal_guard_digest is not None
                    or current.dns_start_id is not None
                    or current.credential_borrow_id is not None
                    or current.resolver_completion_status != "uncommitted"
                    or not self._wire_state_is_well_formed(current)
                    or not self._resolver_completion_proof_is_well_formed(
                        current,
                        allow_committing=False,
                    )
                ):
                    raise _attempt_error(
                        "attempt 当前不能绑定 terminal guard。"
                    )
                self._require_transport_owner_locked(current, claim_id)
                self._require_attempt_credential_proof_locked(permit)
                transition_started = True
                current.status = "guard_binding"
                current.terminal_guard_id = guard_id
                current.terminal_guard_digest = guard_digest
                current.status = "io_claimed"
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not state
                    or current.status != "io_claimed"
                    or current.transport_claim_id != claim_id
                    or current.terminal_guard_id != guard_id
                    or current.terminal_guard_digest != guard_digest
                ):
                    raise _attempt_error(
                        "terminal guard binding transaction 未提交。"
                    )
        except BaseException:
            with self._lock:
                if (
                    transition_started
                    and self._attempt_permits.get(state.attempt_permit_id)
                    is state
                    and state.status == "guard_binding"
                    and state.transport_claim_id == claim_id
                    and state.terminal_guard_id in (None, guard_id)
                    and state.terminal_guard_digest in (None, guard_digest)
                    and state.dns_start_id is None
                    and state.credential_borrow_id is None
                ):
                    state.terminal_guard_id = None
                    state.terminal_guard_digest = None
                    state.status = "io_claimed"
            raise

    def _terminal_guard_is_bound(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Observe exact helper ownership proof after a bind fault."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("terminal guard observation requires transport")
        if (
            type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
        ):
            return False
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            return (
                state.transport_claim_id == claim_id
                and state.terminal_guard_id == guard_id
                and state.terminal_guard_digest == guard_digest
                and self._wire_state_is_well_formed(state)
                and state.status
                in (
                    "io_claimed",
                    "dns_starting",
                    "wire_committing",
                    "wire_committed",
                    "finishing",
                )
            )

    def _commit_dns_start(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        _authority: object | None = None,
    ) -> None:
        """Revalidate all authority immediately before one helper START."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("DNS start commit requires trusted transport")
        if (
            type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(start_id) is not UUID
        ):
            raise _attempt_error("DNS START owner proof 无效。")
        if type(guard_digest) is not Digest256:
            raise _attempt_error("terminal guard digest 无效。")
        with self._lock:
            initial_state = self._lookup_attempt_state_locked(permit)
            if (
                initial_state.status != "io_claimed"
                or initial_state.dns_start_id is not None
                or initial_state.credential_borrow_id is not None
                or not self._wire_state_is_well_formed(initial_state)
            ):
                raise _attempt_error("attempt 当前不能提交 DNS START。")
            self._require_transport_owner_locked(initial_state, claim_id)
            self._require_terminal_guard_proof_locked(
                initial_state,
                guard_id=guard_id,
                guard_digest=guard_digest,
            )
            credential = self._require_attempt_credential_proof_locked(permit)
            bindings = (
                credential._planned,
                credential._invocation,
                credential._prepared,
                credential._authorization,
                credential._consent_ledger,
                credential._session,
                credential._approval_ledger,
                credential._session_ledger,
                credential._authority_ledger,
                credential._context,
                credential._context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings

        def commit(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
        ) -> None:
            del stage, operation
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            with self._lock:
                state = self._lookup_attempt_state_locked(permit)
                if (
                    state.status != "dns_starting"
                    or state.transport_claim_id != claim_id
                    or state.dns_start_id != start_id
                    or state.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(state)
                ):
                    raise _attempt_error("DNS START 提交状态已经变化。")
                self._require_terminal_guard_proof_locked(
                    state,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                )
                self._require_attempt_credential_proof_locked(permit)
                state.status = "io_claimed"

        transition_started = False
        try:
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not initial_state
                    or current.status != "io_claimed"
                    or current.dns_start_id is not None
                    or current.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current)
                ):
                    raise _attempt_error(
                        "attempt 当前不能提交 DNS START。"
                    )
                self._require_transport_owner_locked(current, claim_id)
                self._require_terminal_guard_proof_locked(
                    current,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                )
                self._require_attempt_credential_proof_locked(permit)
                transition_started = True
                current.status = "dns_starting"
                current.dns_start_id = start_id
            self._run_authority_path(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                authority_ledger=authority_ledger,
                context=context,
                context_ledger=context_ledger,
                final_action=commit,
            )
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not initial_state
                    or current.status != "io_claimed"
                    or current.transport_claim_id != claim_id
                    or current.dns_start_id != start_id
                    or current.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current)
                ):
                    raise _attempt_error(
                        "DNS START transaction 未提交。"
                    )
                self._require_terminal_guard_proof_locked(
                    current,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                )
                self._require_attempt_credential_proof_locked(permit)
        except BaseException:
            with self._lock:
                if (
                    self._attempt_permits.get(
                        initial_state.attempt_permit_id
                    )
                    is initial_state
                    and transition_started
                    and initial_state.status == "dns_starting"
                    and initial_state.transport_claim_id == claim_id
                    and initial_state.dns_start_id in (None, start_id)
                ):
                    initial_state.status = "io_claimed"
                    initial_state.dns_start_id = None
            raise

    def _dns_start_is_committed(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Observe only a completed, proof-exact START authorization."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("DNS start observation requires transport")
        if (
            type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
            or type(start_id) is not UUID
        ):
            return False
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            return (
                state.status
                in ("io_claimed", "wire_committing", "wire_committed", "finishing")
                and state.transport_claim_id == claim_id
                and state.terminal_guard_id == guard_id
                and state.terminal_guard_digest == guard_digest
                and state.dns_start_id == start_id
                and self._wire_state_is_well_formed(state)
            )

    def _commit_resolver_completion(
        self,
        authority: HelperStopAuthority,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Linearize one exact resolver result under every live authority.

        Resolver completion is independent from the later provider wire-start
        state.  The attempt therefore remains ``io_claimed`` after this commit.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("resolver completion requires trusted transport")
        if (
            type(authority) is not HelperStopAuthority
            or type(permit) is not AttemptPermit
            or type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
            or type(start_id) is not UUID
            or type(result_receipt_digest) is not Digest256
        ):
            raise _attempt_error("resolver completion proof 无效。")
        with self._lock:
            stop_state = self._require_helper_stop_state_locked(authority)
            attempt_state = self._lookup_attempt_state_locked(permit)
            credential = self._require_attempt_credential_proof_locked(permit)
            if (
                stop_state.credential_permit is not credential
                or stop_state.credential_permit_id
                != permit.credential_permit_id
                or stop_state.context_id != permit.context_id
                or stop_state.session_id != permit.session_id
                or attempt_state.status != "io_claimed"
                or attempt_state.transport_claim_id != claim_id
                or attempt_state.terminal_guard_id != guard_id
                or attempt_state.terminal_guard_digest != guard_digest
                or attempt_state.dns_start_id != start_id
                or attempt_state.credential_borrow_id is not None
                or not self._wire_state_is_well_formed(attempt_state)
                or attempt_state.resolver_completion_status != "uncommitted"
                or attempt_state.resolver_completion_authority_id is not None
                or attempt_state.resolver_completion_claim_id is not None
                or attempt_state.resolver_completion_guard_id is not None
                or attempt_state.resolver_completion_guard_digest is not None
                or attempt_state.resolver_completion_start_id is not None
                or attempt_state.resolver_completion_receipt_digest is not None
                or stop_state.completion_attempt_id is not None
                or stop_state.completion_receipt_digest is not None
            ):
                raise _attempt_error("resolver completion owner 或状态无效。")
            bindings = (
                stop_state.credential_permit._planned,
                stop_state.credential_permit._invocation,
                stop_state.credential_permit._prepared,
                stop_state.credential_permit._authorization,
                stop_state.credential_permit._consent_ledger,
                stop_state.session,
                stop_state.credential_permit._approval_ledger,
                stop_state.credential_permit._session_ledger,
                stop_state.credential_permit._authority_ledger,
                stop_state.context,
                stop_state.context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings

        def commit(
            stage: ExecutionPlanStage,
            operation: ExecutionPlanNetworkOperation,
            sample: ClockSample,
            effective_deadline_ns: int,
        ) -> None:
            del stage, operation
            if (
                sample.wall_time < session.issued_at
                or sample.wall_time >= session.valid_until
            ):
                raise _attempt_error("发送会话已经过期或尚未生效。")
            with self._lock:
                current_stop = self._require_helper_stop_state_locked(
                    authority
                )
                current_attempt = self._lookup_attempt_state_locked(permit)
                if (
                    current_stop is not stop_state
                    or current_attempt is not attempt_state
                    or effective_deadline_ns
                    != current_stop.effective_deadline_ns
                    or current_attempt.status != "io_claimed"
                    or current_attempt.transport_claim_id != claim_id
                    or current_attempt.terminal_guard_id != guard_id
                    or current_attempt.terminal_guard_digest != guard_digest
                    or current_attempt.dns_start_id != start_id
                    or current_attempt.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current_attempt)
                    or current_attempt.resolver_completion_status
                    != "committing"
                    or current_attempt.resolver_completion_authority_id
                    is not None
                    or current_attempt.resolver_completion_claim_id is not None
                    or current_attempt.resolver_completion_guard_id is not None
                    or current_attempt.resolver_completion_guard_digest
                    is not None
                    or current_attempt.resolver_completion_start_id is not None
                    or current_attempt.resolver_completion_receipt_digest
                    is not None
                    or current_stop.completion_attempt_id is not None
                    or current_stop.completion_receipt_digest is not None
                ):
                    raise _attempt_error(
                        "resolver completion transaction 状态已变化。"
                    )
                self._require_attempt_credential_proof_locked(permit)
                current_attempt.resolver_completion_authority_id = (
                    authority.authority_id
                )
                current_attempt.resolver_completion_claim_id = claim_id
                current_attempt.resolver_completion_guard_id = guard_id
                current_attempt.resolver_completion_guard_digest = guard_digest
                current_attempt.resolver_completion_start_id = start_id
                current_attempt.resolver_completion_receipt_digest = (
                    result_receipt_digest
                )
                current_stop.completion_attempt_id = permit.attempt_permit_id
                current_stop.completion_receipt_digest = result_receipt_digest
                current_attempt.resolver_completion_status = "committed"

        transition_started = False
        try:
            with self._lock:
                current_stop = self._require_helper_stop_state_locked(
                    authority
                )
                current_attempt = self._lookup_attempt_state_locked(permit)
                if (
                    current_stop is not stop_state
                    or current_attempt is not attempt_state
                    or current_stop.credential_permit is not credential
                    or current_attempt.status != "io_claimed"
                    or current_attempt.transport_claim_id != claim_id
                    or current_attempt.terminal_guard_id != guard_id
                    or current_attempt.terminal_guard_digest != guard_digest
                    or current_attempt.dns_start_id != start_id
                    or current_attempt.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current_attempt)
                    or current_attempt.resolver_completion_status
                    != "uncommitted"
                    or current_attempt.resolver_completion_authority_id
                    is not None
                    or current_attempt.resolver_completion_claim_id is not None
                    or current_attempt.resolver_completion_guard_id is not None
                    or current_attempt.resolver_completion_guard_digest
                    is not None
                    or current_attempt.resolver_completion_start_id is not None
                    or current_attempt.resolver_completion_receipt_digest
                    is not None
                    or current_stop.completion_attempt_id is not None
                    or current_stop.completion_receipt_digest is not None
                ):
                    raise _attempt_error(
                        "resolver completion owner 或状态无效。"
                    )
                self._require_attempt_credential_proof_locked(permit)
                transition_started = True
                current_attempt.resolver_completion_status = "committing"
            self._run_authority_path(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                authority_ledger=authority_ledger,
                context=context,
                context_ledger=context_ledger,
                final_action=commit,
                include_effective_deadline=True,
            )
            with self._lock:
                if not self._resolver_completion_is_committed_locked(
                    authority,
                    permit,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=start_id,
                    result_receipt_digest=result_receipt_digest,
                ):
                    raise _attempt_error(
                        "resolver completion transaction 未提交。"
                    )
        except BaseException:
            with self._lock:
                if (
                    self._attempt_permits.get(attempt_state.attempt_permit_id)
                    is attempt_state
                    and transition_started
                    and attempt_state.resolver_completion_status == "committing"
                    and attempt_state.resolver_completion_authority_id
                    in (None, authority.authority_id)
                    and attempt_state.resolver_completion_claim_id
                    in (None, claim_id)
                    and attempt_state.resolver_completion_guard_id
                    in (None, guard_id)
                    and attempt_state.resolver_completion_guard_digest
                    in (None, guard_digest)
                    and attempt_state.resolver_completion_start_id
                    in (None, start_id)
                    and attempt_state.resolver_completion_receipt_digest
                    in (None, result_receipt_digest)
                    and stop_state.completion_attempt_id
                    in (None, permit.attempt_permit_id)
                    and stop_state.completion_receipt_digest
                    in (None, result_receipt_digest)
                ):
                    attempt_state.resolver_completion_status = "uncommitted"
                    attempt_state.resolver_completion_authority_id = None
                    attempt_state.resolver_completion_claim_id = None
                    attempt_state.resolver_completion_guard_id = None
                    attempt_state.resolver_completion_guard_digest = None
                    attempt_state.resolver_completion_start_id = None
                    attempt_state.resolver_completion_receipt_digest = None
                    stop_state.completion_attempt_id = None
                    stop_state.completion_receipt_digest = None
            raise

    def _resolver_completion_is_committed_locked(
        self,
        authority: HelperStopAuthority,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
    ) -> bool:
        try:
            stop_state = self._require_helper_stop_state_locked(
                authority,
                require_active=not authority._released,
            )
            attempt_state = self._lookup_attempt_state_locked(permit)
        except (TypeError, ValueError, AttributeError, EndpointPolicyError):
            return False
        return (
            attempt_state.resolver_completion_status == "committed"
            and attempt_state.resolver_completion_authority_id
            == authority.authority_id
            and attempt_state.resolver_completion_claim_id == claim_id
            and attempt_state.resolver_completion_guard_id == guard_id
            and attempt_state.resolver_completion_guard_digest == guard_digest
            and attempt_state.resolver_completion_start_id == start_id
            and attempt_state.resolver_completion_receipt_digest
            == result_receipt_digest
            and stop_state.completion_attempt_id == permit.attempt_permit_id
            and stop_state.completion_receipt_digest == result_receipt_digest
        )

    def _resolver_completion_is_committed(
        self,
        authority: HelperStopAuthority,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Observe an exact completion, including a commit-then-raise outcome."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("resolver completion observation requires transport")
        if (
            type(authority) is not HelperStopAuthority
            or type(permit) is not AttemptPermit
            or type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
            or type(start_id) is not UUID
            or type(result_receipt_digest) is not Digest256
        ):
            return False
        with self._lock:
            return self._resolver_completion_is_committed_locked(
                authority,
                permit,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=result_receipt_digest,
            )

    def _resolver_completion_is_committed_for_publication(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Observe the Gate-owned completion before Resolution publication.

        The address-policy factory does not receive a caller-supplied stop
        authority.  Resolve it only through the exact committed attempt proof
        so a direct ``build_resolution_set`` call cannot bypass the
        cancellation/deadline linearization point.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError(
                "resolver completion publication observation requires transport"
            )
        if (
            type(permit) is not AttemptPermit
            or type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
            or type(start_id) is not UUID
            or type(result_receipt_digest) is not Digest256
        ):
            return False
        with self._lock:
            try:
                attempt_state = self._lookup_attempt_state_locked(permit)
            except (TypeError, ValueError, AttributeError, EndpointPolicyError):
                return False
            authority_id = attempt_state.resolver_completion_authority_id
            if type(authority_id) is not UUID:
                return False
            stop_state = self._helper_stop_authorities.get(authority_id)
            if stop_state is None or type(stop_state.authority) is not HelperStopAuthority:
                return False
            return self._resolver_completion_is_committed_locked(
                stop_state.authority,
                permit,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=result_receipt_digest,
            )

    @staticmethod
    def _resolver_completion_matches_wire_locked(
        state: _AttemptPermitState,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
    ) -> bool:
        return (
            state.resolver_completion_status == "committed"
            and type(state.resolver_completion_authority_id) is UUID
            and state.resolver_completion_claim_id == claim_id
            and state.resolver_completion_guard_id == guard_id
            and state.resolver_completion_guard_digest == guard_digest
            and state.resolver_completion_start_id == start_id
            and state.resolver_completion_receipt_digest
            == result_receipt_digest
        )

    def _commit_wire_start(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        borrow_id: UUID,
        wire_commit_id: UUID,
        wire_evidence_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Linearize the only provider-wire start under all five ledgers.

        The caller must already hold an exact credential borrow and must supply
        a digest of the validated numeric peer/TLS evidence.  This transition
        happens after DNS, numeric connect, and TLS, but before the first HTTP
        request byte.  A committed state is never rolled back after an outer
        wrapper fault; callers must use ``_wire_start_is_committed`` to recover
        that outcome without replaying bytes.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("wire start commit requires trusted transport")
        if (
            type(permit) is not AttemptPermit
            or type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
            or type(start_id) is not UUID
            or type(result_receipt_digest) is not Digest256
            or type(borrow_id) is not UUID
            or type(wire_commit_id) is not UUID
            or type(wire_evidence_digest) is not Digest256
        ):
            raise _attempt_error("wire start proof 无效。")
        with self._lock:
            initial_state = self._lookup_attempt_state_locked(permit)
            if (
                initial_state.status != "io_claimed"
                or initial_state.transport_claim_id != claim_id
                or initial_state.terminal_guard_id != guard_id
                or initial_state.terminal_guard_digest != guard_digest
                or initial_state.dns_start_id != start_id
                or initial_state.credential_borrow_id != borrow_id
                or not self._wire_state_is_well_formed(initial_state)
                or not self._resolver_completion_matches_wire_locked(
                    initial_state,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=start_id,
                    result_receipt_digest=result_receipt_digest,
                )
            ):
                raise _attempt_error("attempt 当前不能提交 provider wire。")
            credential = self._require_attempt_credential_proof_locked(permit)
            bindings = (
                credential._planned,
                credential._invocation,
                credential._prepared,
                credential._authorization,
                credential._consent_ledger,
                credential._session,
                credential._approval_ledger,
                credential._session_ledger,
                credential._authority_ledger,
                credential._context,
                credential._context_ledger,
            )
        (
            planned,
            invocation,
            prepared,
            authorization,
            consent_ledger,
            session,
            approval_ledger,
            session_ledger,
            authority_ledger,
            context,
            context_ledger,
        ) = bindings
        transition_started = False
        try:
            # The rollback handler must cover the first mutable write.  In
            # particular, an asynchronous BaseException between ``status``
            # and the three proof fields must not strand an active credential
            # borrow in an unobservable ``wire_committing`` state.
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not initial_state
                    or current.status != "io_claimed"
                    or current.transport_claim_id != claim_id
                    or current.terminal_guard_id != guard_id
                    or current.terminal_guard_digest != guard_digest
                    or current.dns_start_id != start_id
                    or current.credential_borrow_id != borrow_id
                    or not self._wire_state_is_well_formed(current)
                    or not self._resolver_completion_matches_wire_locked(
                        current,
                        claim_id=claim_id,
                        guard_id=guard_id,
                        guard_digest=guard_digest,
                        start_id=start_id,
                        result_receipt_digest=result_receipt_digest,
                    )
                ):
                    raise _attempt_error(
                        "wire start transaction 状态已变化。"
                    )
                self._require_attempt_credential_proof_locked(permit)
                transition_started = True
                current.status = "wire_committing"
                current.wire_commit_id = wire_commit_id
                current.wire_evidence_digest = wire_evidence_digest
                current.wire_borrow_id = borrow_id

            def commit(
                stage: ExecutionPlanStage,
                operation: ExecutionPlanNetworkOperation,
                sample: ClockSample,
            ) -> None:
                del stage, operation
                if (
                    sample.wall_time < session.issued_at
                    or sample.wall_time >= session.valid_until
                ):
                    raise _attempt_error("发送会话已经过期或尚未生效。")
                with self._lock:
                    current = self._lookup_attempt_state_locked(permit)
                    if (
                        current is not initial_state
                        or current.status != "wire_committing"
                        or current.transport_claim_id != claim_id
                        or current.terminal_guard_id != guard_id
                        or current.terminal_guard_digest != guard_digest
                        or current.dns_start_id != start_id
                        or current.credential_borrow_id != borrow_id
                        or current.wire_commit_id != wire_commit_id
                        or current.wire_evidence_digest
                        != wire_evidence_digest
                        or current.wire_borrow_id != borrow_id
                        or not self._wire_state_is_well_formed(current)
                        or not self._resolver_completion_matches_wire_locked(
                            current,
                            claim_id=claim_id,
                            guard_id=guard_id,
                            guard_digest=guard_digest,
                            start_id=start_id,
                            result_receipt_digest=result_receipt_digest,
                        )
                    ):
                        raise _attempt_error(
                            "wire start transaction 状态已变化。"
                        )
                    self._require_attempt_credential_proof_locked(permit)
                    current.status = "wire_committed"

            self._run_authority_path(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                session=session,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
                authority_ledger=authority_ledger,
                context=context,
                context_ledger=context_ledger,
                final_action=commit,
            )
            with self._lock:
                if not self._wire_start_is_committed_locked(
                    permit,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=start_id,
                    result_receipt_digest=result_receipt_digest,
                    borrow_id=borrow_id,
                    wire_commit_id=wire_commit_id,
                    wire_evidence_digest=wire_evidence_digest,
                ):
                    raise _attempt_error("wire start transaction 未提交。")
        except BaseException:
            with self._lock:
                if (
                    transition_started
                    and
                    self._attempt_permits.get(
                        initial_state.attempt_permit_id
                    )
                    is initial_state
                    and initial_state.status == "wire_committing"
                    and initial_state.wire_commit_id in (None, wire_commit_id)
                    and initial_state.wire_evidence_digest
                    in (None, wire_evidence_digest)
                    and initial_state.wire_borrow_id in (None, borrow_id)
                ):
                    initial_state.wire_commit_id = None
                    initial_state.wire_evidence_digest = None
                    initial_state.wire_borrow_id = None
                    initial_state.status = "io_claimed"
            raise

    def _wire_start_is_committed_locked(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        borrow_id: UUID,
        wire_commit_id: UUID,
        wire_evidence_digest: Digest256,
    ) -> bool:
        try:
            state = self._lookup_attempt_state_locked(permit)
        except (AttributeError, TypeError, ValueError, EndpointPolicyError):
            return False
        return (
            state.status == "wire_committed"
            and state.transport_claim_id == claim_id
            and state.terminal_guard_id == guard_id
            and state.terminal_guard_digest == guard_digest
            and state.dns_start_id == start_id
            and state.wire_commit_id == wire_commit_id
            and state.wire_evidence_digest == wire_evidence_digest
            and state.wire_borrow_id == borrow_id
            and self._wire_state_is_well_formed(state)
            and self._resolver_completion_matches_wire_locked(
                state,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=result_receipt_digest,
            )
        )

    def _wire_start_is_committed(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        borrow_id: UUID,
        wire_commit_id: UUID,
        wire_evidence_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("wire start observation requires trusted transport")
        if (
            type(permit) is not AttemptPermit
            or type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
            or type(start_id) is not UUID
            or type(result_receipt_digest) is not Digest256
            or type(borrow_id) is not UUID
            or type(wire_commit_id) is not UUID
            or type(wire_evidence_digest) is not Digest256
        ):
            return False
        with self._lock:
            return self._wire_start_is_committed_locked(
                permit,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=result_receipt_digest,
                borrow_id=borrow_id,
                wire_commit_id=wire_commit_id,
                wire_evidence_digest=wire_evidence_digest,
            )

    @staticmethod
    def _transport_io_state_matches_locked(
        state: _AttemptPermitState,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        borrow_id: UUID | None,
        wire_commit_id: UUID | None,
        wire_evidence_digest: Digest256 | None,
    ) -> bool:
        if (
            state.transport_claim_id != claim_id
            or state.terminal_guard_id != guard_id
            or state.terminal_guard_digest != guard_digest
            or state.dns_start_id != start_id
            or not AttemptGate._wire_state_is_well_formed(state)
            or not AttemptGate._resolver_completion_matches_wire_locked(
                state,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=result_receipt_digest,
            )
        ):
            return False
        if wire_commit_id is None and wire_evidence_digest is None:
            return (
                state.status == "io_claimed"
                and state.credential_borrow_id == borrow_id
                and state.wire_commit_id is None
                and state.wire_evidence_digest is None
                and state.wire_borrow_id is None
            )
        return (
            type(borrow_id) is UUID
            and type(wire_commit_id) is UUID
            and type(wire_evidence_digest) is Digest256
            and state.status == "wire_committed"
            and state.credential_borrow_id in (None, borrow_id)
            and state.wire_borrow_id == borrow_id
            and state.wire_commit_id == wire_commit_id
            and state.wire_evidence_digest == wire_evidence_digest
        )

    def _checkpoint_transport_io(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID,
        guard_digest: Digest256,
        start_id: UUID,
        result_receipt_digest: Digest256,
        phase: str,
        borrow_id: UUID | None = None,
        wire_commit_id: UUID | None = None,
        wire_evidence_digest: Digest256 | None = None,
        _authority: object | None = None,
    ) -> HelperWaitSlice:
        """Issue one bounded provider-I/O slice from the frozen attempt.

        Pre-wire checkpoints accept either no credential borrow or the exact
        active borrow.  Post-wire checkpoints require the committed wire
        owner/evidence and remain usable after the secret borrow has been
        released.  No caller supplies time, duration, deadline, or token.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("transport checkpoint requires trusted transport")
        checked_phase = require_text(phase, "phase", max_length=48)
        wire_values_absent = (
            wire_commit_id is None and wire_evidence_digest is None
        )
        wire_values_exact = (
            type(wire_commit_id) is UUID
            and type(wire_evidence_digest) is Digest256
            and type(borrow_id) is UUID
        )
        if (
            type(permit) is not AttemptPermit
            or type(claim_id) is not UUID
            or type(guard_id) is not UUID
            or type(guard_digest) is not Digest256
            or type(start_id) is not UUID
            or type(result_receipt_digest) is not Digest256
            or (borrow_id is not None and type(borrow_id) is not UUID)
            or not (wire_values_absent or wire_values_exact)
        ):
            raise _attempt_error("transport checkpoint proof 无效。")
        with self._lock:
            initial_state = self._lookup_attempt_state_locked(permit)
            if not self._transport_io_state_matches_locked(
                initial_state,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=result_receipt_digest,
                borrow_id=borrow_id,
                wire_commit_id=wire_commit_id,
                wire_evidence_digest=wire_evidence_digest,
            ):
                raise _attempt_error("transport checkpoint owner 或状态无效。")
            authority_id = initial_state.resolver_completion_authority_id
            stop_state = self._helper_stop_authorities.get(authority_id)
            if (
                type(authority_id) is not UUID
                or stop_state is None
                or type(stop_state.authority) is not HelperStopAuthority
                or stop_state.completion_attempt_id
                != permit.attempt_permit_id
                or stop_state.completion_receipt_digest
                != result_receipt_digest
            ):
                raise _attempt_error("transport checkpoint deadline owner 无效。")
            stop_authority = stop_state.authority

        candidate = self._checkpoint_helper_stop_authority(
            stop_authority,
            phase=f"transport:{checked_phase}",
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        with self._lock:
            current = self._lookup_attempt_state_locked(permit)
            current_stop = self._helper_stop_authorities.get(authority_id)
            if (
                current is not initial_state
                or current_stop is not stop_state
                or current_stop.issued_wait_slice is not candidate
                or current_stop.issued_wait_slice_digest
                != candidate.slice_digest
                or not self._transport_io_state_matches_locked(
                    current,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=start_id,
                    result_receipt_digest=result_receipt_digest,
                    borrow_id=borrow_id,
                    wire_commit_id=wire_commit_id,
                    wire_evidence_digest=wire_evidence_digest,
                )
            ):
                raise _attempt_error("transport checkpoint publication 已变化。")
        return candidate

    def _helper_stop_authority_is_released(
        self,
        authority: HelperStopAuthority,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Observe exact terminal release without dereferencing live owners."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("helper stop release observation requires transport")
        if type(authority) is not HelperStopAuthority:
            return False
        with self._lock:
            try:
                state = self._require_helper_stop_state_locked(
                    authority,
                    require_active=False,
                )
            except (TypeError, ValueError, AttributeError, EndpointPolicyError):
                return False
            credential_state = self._credential_permits.get(
                state.credential_permit_id
            )
            return (
                state.status == "terminal"
                and authority._released is True
                and state.authority_refs()
                == (None, None, None, None, None, None, None)
                and self._helper_stop_is_terminal_for_credential_locked(
                    state.credential_permit_id
                )
                and credential_state is not None
                and credential_state.status in ("abandoned", "finished")
                and state.session_id not in self._active_by_session
            )

    def _begin_credential_borrow(
        self,
        permit: AttemptPermit,
        *,
        borrow_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Mark an in-flight attempt as borrowing its exact credential."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential borrow requires trusted transport")
        if type(borrow_id) is not UUID:
            raise _attempt_error("凭据借用 owner 无效。")
        if type(handle_id) is not UUID or type(handle_digest) is not Digest256:
            raise _attempt_error("凭据句柄证明无效。")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if (
                state.status != "io_claimed"
                or not self._wire_state_is_well_formed(state)
            ):
                raise _attempt_error("attempt 当前不能借用凭据。")
            if state.credential_borrow_id is not None:
                raise _attempt_error("attempt 已有凭据借用 owner。")
            self._require_attempt_credential_proof_locked(permit)
            if (
                permit.credential_handle_id != handle_id
                or permit.credential_handle_digest != handle_digest
            ):
                raise _attempt_error("attempt 的凭据句柄证明不匹配。")
            state.credential_borrow_id = borrow_id

    def _finish_credential_borrow(
        self,
        permit: AttemptPermit,
        *,
        borrow_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Release the borrow marker only after the secret view is invalid."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential borrow release requires trusted transport")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if (
                state.status not in ("io_claimed", "wire_committed")
                or state.credential_borrow_id != borrow_id
                or permit.credential_handle_id != handle_id
                or permit.credential_handle_digest != handle_digest
            ):
                raise _attempt_error("attempt 的凭据借用状态已经变化。")
            if not self._wire_state_is_well_formed(state):
                raise _attempt_error("attempt 的 wire 状态无效。")
            self._require_attempt_credential_proof_locked(permit)
            state.credential_borrow_id = None

    def _credential_borrow_is_active(
        self,
        permit: AttemptPermit,
        *,
        borrow_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Observe a proof-exact marker after a transition raises."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential borrow observation requires transport")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if (
                permit.credential_handle_id != handle_id
                or permit.credential_handle_digest != handle_digest
            ):
                raise _attempt_error("attempt 的凭据句柄证明不匹配。")
            return (
                state.status in ("io_claimed", "wire_committed")
                and state.credential_borrow_id == borrow_id
                and self._wire_state_is_well_formed(state)
            )

    def _force_finish_credential_borrow(
        self,
        permit: AttemptPermit,
        *,
        borrow_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Fault fallback after the view and ledger secret are already closed."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential borrow recovery requires transport")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if (
                state.status not in ("io_claimed", "wire_committed")
                or state.credential_borrow_id != borrow_id
                or permit.credential_handle_id != handle_id
                or permit.credential_handle_digest != handle_digest
            ):
                raise _attempt_error("attempt 的凭据借用恢复状态不匹配。")
            if not self._wire_state_is_well_formed(state):
                raise _attempt_error("attempt 的 wire 状态无效。")
            self._require_attempt_credential_proof_locked(permit)
            state.credential_borrow_id = None

    def abandon_attempt(
        self,
        permit: AttemptPermit,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Release an unclaimed attempt; budget remains consumed."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt abandonment requires trusted transport")
        if type(permit) is not AttemptPermit:
            raise TypeError("permit must be AttemptPermit")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if state.status in ("abandoned", "finished"):
                return False
            if (
                state.status != "active"
                or state.transport_claim_id is not None
                or state.terminal_guard_id is not None
                or state.terminal_guard_digest is not None
                or state.dns_start_id is not None
                or state.credential_borrow_id is not None
                or not self._wire_state_is_well_formed(state)
            ):
                raise _attempt_error("已领取或正在终结的 attempt 不能废弃。")
            context_ledger = permit._context_ledger
            reservation = permit._reservation
            credential = permit._credential_permit
            context = credential._context
        transition_started = False
        try:
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not state
                    or current.status != "active"
                    or current.transport_claim_id is not None
                    or current.terminal_guard_id is not None
                    or current.terminal_guard_digest is not None
                    or current.dns_start_id is not None
                    or current.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current)
                ):
                    raise _attempt_error(
                        "已领取或正在终结的 attempt 不能废弃。"
                    )
                transition_started = True
                current.status = "abandoning"

            def terminal() -> None:
                with self._lock:
                    current = self._lookup_attempt_state_locked(permit)
                    if current.status != "abandoning":
                        raise _attempt_error("attempt 废弃状态已经变化。")
                    credential_state = self._credential_permits[
                        permit.credential_permit_id
                    ]
                    self._commit_attempt_terminal_locked(
                        permit=permit,
                        state=current,
                        credential=credential,
                        credential_state=credential_state,
                        terminal_status="abandoned",
                    )

            context_ledger._finish_attempt_and_activity(
                context=context,
                reservation=reservation,
                attempt_gate=self,
                activity_id=permit.credential_permit_id,
                action=terminal,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
        except BaseException:
            with self._lock:
                if transition_started and state.status == "abandoning":
                    state.status = "active"
            raise
        with self._lock:
            if transition_started and state.status == "abandoning":
                state.status = "active"
                raise _attempt_error("attempt 废弃 transaction 未提交。")
        return True

    def finish_attempt(
        self,
        permit: AttemptPermit,
        *,
        claim_id: UUID,
        guard_id: UUID | None = None,
        guard_digest: Digest256 | None = None,
        _authority: object | None = None,
    ) -> bool:
        """Release in-flight state; consumed budgets are never refunded."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt completion requires trusted transport")
        if type(claim_id) is not UUID:
            raise _attempt_error("transport claim owner 无效。")
        if (guard_id is None) != (guard_digest is None):
            raise _attempt_error("terminal guard 证明不完整。")
        if guard_id is not None and type(guard_id) is not UUID:
            raise _attempt_error("terminal guard owner 无效。")
        if guard_digest is not None and type(guard_digest) is not Digest256:
            raise _attempt_error("terminal guard digest 无效。")
        if type(permit) is not AttemptPermit:
            raise TypeError("permit must be AttemptPermit")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if state.status in ("finished", "abandoned"):
                return False
            if (
                state.status not in ("io_claimed", "wire_committed")
                or state.credential_borrow_id is not None
                or not self._wire_state_is_well_formed(state)
                or not self._resolver_completion_proof_is_well_formed(
                    state,
                    allow_committing=False,
                )
            ):
                raise _attempt_error("attempt permit 尚未由 transport 领取。")
            self._require_transport_owner_locked(state, claim_id)
            self._require_terminal_guard_proof_locked(
                state,
                guard_id=guard_id,
                guard_digest=guard_digest,
            )
            context_ledger = permit._context_ledger
            reservation = permit._reservation
            credential = permit._credential_permit
            context = credential._context
            previous_status = state.status
        transition_started = False
        try:
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if (
                    current is not state
                    or current.status != previous_status
                    or current.credential_borrow_id is not None
                    or not self._wire_state_is_well_formed(current)
                    or not self._resolver_completion_proof_is_well_formed(
                        current,
                        allow_committing=False,
                    )
                ):
                    raise _attempt_error(
                        "attempt 终结状态已经变化。"
                    )
                self._require_transport_owner_locked(current, claim_id)
                self._require_terminal_guard_proof_locked(
                    current,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                )
                transition_started = True
                current.status = "finishing"

            def terminal() -> None:
                with self._lock:
                    current = self._lookup_attempt_state_locked(permit)
                    if (
                        current.status != "finishing"
                        or current.transport_claim_id != claim_id
                    ):
                        raise _attempt_error("attempt 终结状态已经变化。")
                    self._require_terminal_guard_proof_locked(
                        current,
                        guard_id=guard_id,
                        guard_digest=guard_digest,
                    )
                    credential_state = self._credential_permits[
                        permit.credential_permit_id
                    ]
                    self._commit_attempt_terminal_locked(
                        permit=permit,
                        state=current,
                        credential=credential,
                        credential_state=credential_state,
                        terminal_status="finished",
                    )

            context_ledger._finish_attempt_and_activity(
                context=context,
                reservation=reservation,
                attempt_gate=self,
                activity_id=permit.credential_permit_id,
                action=terminal,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
            with self._lock:
                if (
                    transition_started
                    and state.status == "finishing"
                    and state.transport_claim_id == claim_id
                ):
                    state.status = previous_status
                    raise _attempt_error(
                        "attempt 终结 transaction 未提交。"
                    )
        except BaseException:
            with self._lock:
                if (
                    transition_started
                    and
                    state.status == "finishing"
                    and state.transport_claim_id == claim_id
                ):
                    state.status = previous_status
            raise
        return True

    def _attempt_is_terminal(
        self,
        permit: AttemptPermit,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Observe terminal commit without reopening on an outer fault."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt terminal observation requires transport")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            return state.status in ("finished", "abandoned")

    def safe_metadata(self) -> dict[str, int]:
        with self._lock:
            return {
                "credential_permit_count": len(self._credential_permits),
                "attempt_permit_count": len(self._attempt_permits),
                "helper_stop_authority_count": len(
                    self._helper_stop_authorities
                ),
                "active_session_count": len(self._active_by_session),
            }


__all__ = [
    "ATTEMPT_PERMIT_SCHEMA_VERSION",
    "CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION",
    "HELPER_STOP_AUTHORITY_SCHEMA_VERSION",
    "HELPER_WAIT_QUANTUM_NS",
    "HELPER_WAIT_SLICE_SCHEMA_VERSION",
    "AttemptGate",
    "AttemptPermit",
    "CredentialResolutionPermit",
    "HelperStopAuthority",
    "HelperWaitSlice",
]
