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
from snapquiz.runtime.clock import ClockSample
from snapquiz.runtime.context import (
    AttemptBudgetReservation,
    CallContext,
    CallContextLedger,
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
ATTEMPT_PERMIT_SCHEMA_VERSION = "snapquiz.attempt-permit.v1"

_PERMIT_FACTORY_AUTHORITY = object()
_PERMIT_RELEASE_AUTHORITY = object()
_CREDENTIAL_RESOLVER_AUTHORITY = object()
_TRANSPORT_ATTEMPT_AUTHORITY = object()
_CREDENTIAL_PERMIT_UUID_NAMESPACE = UUID(
    "f1112d3e-51ad-53f4-b70f-c05a8a3cd5c6"
)
_ATTEMPT_PERMIT_UUID_NAMESPACE = UUID(
    "fc6dc07a-2dcb-509f-8ca4-52fcbd77d07b"
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
        reservation: AttemptBudgetReservation,
        attempt_gate: "AttemptGate",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMIT_FACTORY_AUTHORITY:
            raise TypeError("attempt permits require AttemptGate")
        identifier = {
            "credential_permit_id": credential_permit.permit_id,
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
            "reservation_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "credential_permit_digest",
            "context_digest",
            "session_terms_digest",
            "request_envelope_digest",
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
            "operation_attempt": self.operation_attempt,
            "global_attempt": self.global_attempt,
            "billable_attempt": self.billable_attempt,
        }


class _CredentialPermitState:
    __slots__ = ("permit", "status", "resolved_binding")

    def __init__(self, permit: CredentialResolutionPermit) -> None:
        self.permit = permit
        self.status = "authorized"
        self.resolved_binding: Digest256 | ContractMarker | None = None


class _AttemptPermitState:
    __slots__ = ("permit", "status")

    def __init__(self, permit: AttemptPermit) -> None:
        self.permit = permit
        self.status = "active"


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
        "_active_by_session",
        "_sequence",
        "_lock",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "_gate_id", uuid4())
        object.__setattr__(self, "_credential_permits", {})
        object.__setattr__(self, "_attempt_permits", {})
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
        final_action: Callable[
            [ExecutionPlanStage, ExecutionPlanNetworkOperation, ClockSample], _T
        ],
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

    def _confirm_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
        *,
        resolved_binding_digest: Digest256 | ContractMarker,
        _authority: object | None = None,
    ) -> None:
        """Trusted resolver callback; carries no credential bytes."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential confirmation requires trusted resolver")
        _require_credential_binding(resolved_binding_digest)
        mismatch = False
        with self._lock:
            state = self._require_credential_state_locked(permit)
            if state.status != "resolving":
                raise _attempt_error("凭据解析授权未被 resolver 独占。")
            if resolved_binding_digest != permit.credential_binding_digest:
                state.status = "failing"
                mismatch = True
            else:
                state.resolved_binding = resolved_binding_digest
                state.status = "resolved"
        if mismatch:
            try:
                self._finish_credential_activity(
                    permit,
                    required_status="failing",
                    terminal_status="abandoned",
                )
            except BaseException:
                with self._lock:
                    current = self._lookup_credential_state_locked(permit)
                    if current.status == "failing":
                        current.status = "resolving"
                raise
            raise _attempt_error("凭据解析结果与批准的 binding 不匹配。")

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

    def _fail_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
        *,
        _authority: object | None = None,
    ) -> None:
        """Trusted resolver cleanup after an exclusive backend read fails."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential failure requires trusted resolver")
        with self._lock:
            state = self._require_credential_state_locked(permit)
            if state.status != "resolving":
                raise _attempt_error("只能终止 resolver 已独占的凭据授权。")
            state.status = "failing"
        try:
            self._finish_credential_activity(
                permit,
                required_status="failing",
                terminal_status="abandoned",
            )
        except BaseException:
            with self._lock:
                current = self._lookup_credential_state_locked(permit)
                if current.status == "failing":
                    current.status = "resolving"
            raise

    def _claim_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
        *,
        _authority: object | None = None,
    ) -> CredentialResolutionPermit:
        """Atomically claim before any resolver backend may read a secret."""

        if _authority is not _CREDENTIAL_RESOLVER_AUTHORITY:
            raise TypeError("credential claim requires trusted resolver")
        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
        if permit._attempt_gate is not self:
            raise _attempt_error("凭据解析授权不属于当前 AttemptGate。")
        with self._lock:
            initial_state = self._require_credential_state_locked(permit)
            if initial_state.status != "authorized":
                raise _attempt_error("凭据解析授权已被其他 resolver 领取。")
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
            initial_state.status = "claiming"
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
                if state.status != "claiming":
                    raise _attempt_error("凭据解析授权已被其他 resolver 领取。")
                state.status = "resolving"
                return permit

        try:
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
                final_action=claim,
            )
        except BaseException:
            with self._lock:
                current = self._lookup_credential_state_locked(permit)
                if current.status == "claiming":
                    current.status = "authorized"
            raise

    def abandon_credential_resolution(
        self,
        permit: CredentialResolutionPermit,
    ) -> bool:
        """Invalidate an unused permit after resolver failure or cancellation."""

        with self._lock:
            state = self._lookup_credential_state_locked(permit)
            if state.status in ("abandoned", "finished"):
                return False
            if state.status not in ("authorized", "resolved"):
                raise _attempt_error(
                    "resolver 已领取或 attempt 已预留的凭据授权不能公开废弃。"
                )
            required_status = state.status
        self._finish_credential_activity(
            permit,
            required_status=required_status,
            terminal_status="abandoned",
        )
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
        try:
            permit._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            state.status = terminal_status
            if self._active_by_session.get(permit.session_id) != permit.permit_id:
                raise _attempt_error("凭据解析授权的 active session 绑定已经变化。")
            del self._active_by_session[permit.session_id]
        except BaseException:
            self._restore_slots(permit, permit_snapshot)
            state.status = old_status
            self._active_by_session[permit.session_id] = active_id
            raise

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
        old_credential_status = credential_state.status
        try:
            credential._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            permit._release_authority_refs(
                _authority=_PERMIT_RELEASE_AUTHORITY,
            )
            state.status = terminal_status
            credential_state.status = "finished"
            if (
                self._active_by_session.get(permit.session_id)
                != permit.credential_permit_id
            ):
                raise _attempt_error("attempt 的 active session 绑定已经变化。")
            del self._active_by_session[permit.session_id]
        except BaseException:
            self._restore_slots(credential, credential_snapshot)
            self._restore_slots(permit, permit_snapshot)
            state.status = old_attempt_status
            credential_state.status = old_credential_status
            self._active_by_session[permit.session_id] = active_id
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
    ) -> AttemptPermit:
        if type(credential_permit) is not CredentialResolutionPermit:
            raise TypeError(
                "credential_permit must be CredentialResolutionPermit"
            )
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
            ):
                raise _attempt_error("凭据尚未按批准 binding 解析。")
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
            with self._lock:
                state = self._require_credential_state_locked(
                    credential_permit
                )
                if (
                    state.status != "resolved"
                    or state.resolved_binding
                    != credential_permit.credential_binding_digest
                ):
                    raise _attempt_error("凭据尚未按批准 binding 解析。")
                # Context lock is already held by _run_authority_path.  Marking
                # this state before budget reservation makes abandon-vs-reserve
                # linearizable without reversing the Context -> AttemptGate
                # order.
                state.status = "reserving"

            def build(reservation: AttemptBudgetReservation) -> AttemptPermit:
                with self._lock:
                    current = self._require_credential_state_locked(
                        credential_permit
                    )
                    if current.status != "reserving":
                        raise _attempt_error("凭据解析授权已经消费。")
                    permit = AttemptPermit(
                        credential_permit=credential_permit,
                        reservation=reservation,
                        attempt_gate=self,
                        _authority=_PERMIT_FACTORY_AUTHORITY,
                    )
                    current.status = "consumed"
                    self._attempt_permits[permit.attempt_permit_id] = (
                        _AttemptPermitState(permit)
                    )
                    return permit

            try:
                return context_ledger._reserve_attempt_budgets(
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
            except BaseException:
                with self._lock:
                    current = self._lookup_credential_state_locked(
                        credential_permit
                    )
                    if current.status == "reserving":
                        current.status = "resolved"
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
            final_action=reserve,
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

    def _claim_attempt(
        self,
        permit: AttemptPermit,
        *,
        _authority: object | None = None,
    ) -> AttemptPermit:
        """Revalidate and atomically claim immediately before wire work."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt claim requires trusted transport")
        if type(permit) is not AttemptPermit:
            raise TypeError("permit must be AttemptPermit")
        with self._lock:
            initial_state = self._lookup_attempt_state_locked(permit)
            if initial_state.status != "active":
                raise _attempt_error("attempt permit 已被领取或终结。")
            credential = permit._credential_permit
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
            initial_state.status = "claiming"
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
                if state.status != "claiming":
                    raise _attempt_error("attempt permit 已被领取或终结。")
                state.status = "sending"
                return permit

        try:
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
                final_action=claim,
            )
        except BaseException:
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if current.status == "claiming":
                    current.status = "active"
            raise

    def abandon_attempt(self, permit: AttemptPermit) -> bool:
        """Release an unclaimed attempt; budget remains consumed."""

        if type(permit) is not AttemptPermit:
            raise TypeError("permit must be AttemptPermit")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if state.status in ("abandoned", "finished"):
                return False
            if state.status != "active":
                raise _attempt_error("已领取或正在终结的 attempt 不能废弃。")
            context_ledger = permit._context_ledger
            reservation = permit._reservation
            credential = permit._credential_permit
            context = credential._context
            state.status = "abandoning"

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

        try:
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
                state.status = "active"
            raise
        return True

    def finish_attempt(
        self,
        permit: AttemptPermit,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Release in-flight state; consumed budgets are never refunded."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("attempt completion requires trusted transport")
        if type(permit) is not AttemptPermit:
            raise TypeError("permit must be AttemptPermit")
        with self._lock:
            state = self._lookup_attempt_state_locked(permit)
            if state.status in ("finished", "abandoned"):
                return False
            if state.status != "sending":
                raise _attempt_error("attempt permit 尚未由 transport 领取。")
            context_ledger = permit._context_ledger
            reservation = permit._reservation
            credential = permit._credential_permit
            context = credential._context
            state.status = "finishing"

        def terminal() -> None:
            with self._lock:
                current = self._lookup_attempt_state_locked(permit)
                if current.status != "finishing":
                    raise _attempt_error("attempt 终结状态已经变化。")
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

        try:
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
                state.status = "sending"
            raise
        return True

    def safe_metadata(self) -> dict[str, int]:
        with self._lock:
            return {
                "credential_permit_count": len(self._credential_permits),
                "attempt_permit_count": len(self._attempt_permits),
                "active_session_count": len(self._active_by_session),
            }


__all__ = [
    "ATTEMPT_PERMIT_SCHEMA_VERSION",
    "CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION",
    "AttemptGate",
    "AttemptPermit",
    "CredentialResolutionPermit",
]
