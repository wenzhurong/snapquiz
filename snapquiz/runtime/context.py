"""Trusted per-request runtime authority for W09-A.

The runtime context starts immediately after privacy authorization and owns the
single monotonic deadline, cancellation state and all network-call budgets for
that request.  Mutable state lives only in ``CallContextLedger`` so callers
cannot reset a budget by constructing another value object.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from threading import Condition, RLock
from typing import Callable, TypeVar
from uuid import UUID, uuid5

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_plain_int,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CancelledError, EndpointPolicyError, TimeoutError
from snapquiz.domain.policy import ContractMarker
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentLedger,
    PrivacyGate,
    _ATOMIC_PRIVACY_AUTHORITY,
)
from snapquiz.routing.planner import PlannedExecution
from snapquiz.runtime.authority import (
    RegistryPolicyAuthorityLedger,
    RegistryPolicyLease,
    _CONTEXT_AUTHORITY,
)
from snapquiz.runtime.clock import (
    ClockSample,
    MonotonicDeadline,
    RuntimeClock,
    SystemRuntimeClock,
    _DEADLINE_AUTHORITY,
)


CALL_CONTEXT_SCHEMA_VERSION = "snapquiz.call-context.v1"
ATOMIC_BUDGET_SCHEMA_VERSION = "snapquiz.atomic-budget.v1"
ATTEMPT_BUDGET_RESERVATION_SCHEMA_VERSION = (
    "snapquiz.attempt-budget-reservation.v1"
)
CANCELLATION_TOKEN_SCHEMA_VERSION = "snapquiz.cancellation-token.v1"

_CALL_FACTORY_AUTHORITY = object()
_ATTEMPT_BUDGET_AUTHORITY = object()
_TEST_CLOCK_AUTHORITY = object()
_CONTEXT_UUID_NAMESPACE = UUID("9136d674-8356-58fb-a70e-bca2d1b303f2")
_BUDGET_UUID_NAMESPACE = UUID("1740174d-d91a-5a1c-9aeb-02683450d984")
_CANCELLATION_UUID_NAMESPACE = UUID("9c9700c2-c54f-5abc-949b-ebbf9a51393f")
_RESERVATION_UUID_NAMESPACE = UUID("84b78598-b29a-5263-a2d6-686a28d06de6")
_T = TypeVar("_T")


def _runtime_error(message: str) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="call_context",
        retryable=False,
        safe_message=message,
    )


def _timeout_error() -> TimeoutError:
    return TimeoutError(
        stage="call_context",
        retryable=False,
        safe_message="本次请求的执行时限已经结束。",
    )


def _cancelled_error() -> CancelledError:
    return CancelledError(
        stage="call_context",
        retryable=False,
        safe_message="本次请求已取消。",
    )


def _is_billable(value: bool | ContractMarker) -> bool:
    return value is True or value is ContractMarker.UNKNOWN


class BudgetKind(str, Enum):
    OPERATION_NETWORK = "operation_network"
    GLOBAL_NETWORK = "global_network"
    GLOBAL_BILLABLE = "global_billable"


class CancellationReason(str, Enum):
    USER_REQUEST = "user_request"
    APP_SHUTDOWN = "app_shutdown"
    PIPELINE_TERMINAL = "pipeline_terminal"


@runtime_final
class BudgetSnapshot:
    __slots__ = ("limit", "consumed", "remaining")

    def __init__(self, *, limit: int, consumed: int) -> None:
        require_plain_int(limit, "limit")
        require_plain_int(consumed, "consumed")
        if consumed > limit:
            raise ValueError("consumed cannot exceed limit")
        object.__setattr__(self, "limit", limit)
        object.__setattr__(self, "consumed", consumed)
        object.__setattr__(self, "remaining", limit - consumed)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("BudgetSnapshot is immutable")


def _budget_payload(budget: "AtomicBudget") -> dict[str, object]:
    return {
        "budget_id": budget.budget_id,
        "context_id": budget.context_id,
        "kind": budget.kind.value,
        "scope_id": budget.scope_id,
        "limit": budget.limit,
    }


@runtime_final
class AtomicBudget:
    """Immutable handle; the mutable counter is ledger-owned."""

    __slots__ = (
        "budget_id",
        "context_id",
        "kind",
        "scope_id",
        "limit",
        "budget_digest",
        "_context_ledger",
    )

    def __init__(
        self,
        *,
        budget_id: UUID,
        context_id: UUID,
        kind: BudgetKind,
        scope_id: UUID,
        limit: int,
        context_ledger: "CallContextLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CALL_FACTORY_AUTHORITY:
            raise TypeError("AtomicBudget requires RuntimeCallFactory")
        require_uuid(budget_id, "budget_id")
        require_uuid(context_id, "context_id")
        if type(kind) is not BudgetKind:
            raise TypeError("kind must be BudgetKind")
        require_uuid(scope_id, "scope_id")
        require_plain_int(limit, "limit")
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        for name, value in (
            ("budget_id", budget_id),
            ("context_id", context_id),
            ("kind", kind),
            ("scope_id", scope_id),
            ("limit", limit),
            ("_context_ledger", context_ledger),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "budget_digest",
            digest256(
                "AtomicBudget",
                ATOMIC_BUDGET_SCHEMA_VERSION,
                _budget_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AtomicBudget is immutable")

    def __repr__(self) -> str:
        return (
            "AtomicBudget("
            f"kind={self.kind.value!r}, scope_id={self.scope_id!r}, "
            f"limit={self.limit!r})"
        )

    def validate_integrity(self) -> None:
        require_uuid(self.budget_id, "budget_id")
        require_uuid(self.context_id, "context_id")
        if type(self.kind) is not BudgetKind:
            raise ValueError("budget kind changed")
        require_uuid(self.scope_id, "scope_id")
        require_plain_int(self.limit, "limit")
        if type(self._context_ledger) is not CallContextLedger:
            raise ValueError("budget ledger authority changed")
        expected_id = _budget_id_for(
            context_id=self.context_id,
            kind=self.kind,
            scope_id=self.scope_id,
            limit=self.limit,
        )
        if self.budget_id != expected_id or self.budget_digest != digest256(
            "AtomicBudget",
            ATOMIC_BUDGET_SCHEMA_VERSION,
            _budget_payload(self),
        ):
            raise ValueError("budget integrity mismatch")

    def snapshot(self) -> BudgetSnapshot:
        return self._context_ledger.snapshot_budget(self)


def _budget_id_for(
    *, context_id: UUID, kind: BudgetKind, scope_id: UUID, limit: int
) -> UUID:
    seed = digest256(
        "AtomicBudgetIdentifier",
        ATOMIC_BUDGET_SCHEMA_VERSION,
        {
            "context_id": context_id,
            "kind": kind.value,
            "scope_id": scope_id,
            "limit": limit,
        },
    )
    return uuid5(_BUDGET_UUID_NAMESPACE, str(seed))


def _cancellation_payload(token: "CancellationToken") -> dict[str, object]:
    return {
        "token_id": token.token_id,
        "context_id": token.context_id,
    }


@runtime_final
class CancellationToken:
    __slots__ = (
        "token_id",
        "context_id",
        "token_digest",
        "_context_ledger",
    )

    def __init__(
        self,
        *,
        token_id: UUID,
        context_id: UUID,
        context_ledger: "CallContextLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CALL_FACTORY_AUTHORITY:
            raise TypeError("CancellationToken requires RuntimeCallFactory")
        require_uuid(token_id, "token_id")
        require_uuid(context_id, "context_id")
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        object.__setattr__(self, "token_id", token_id)
        object.__setattr__(self, "context_id", context_id)
        object.__setattr__(self, "_context_ledger", context_ledger)
        object.__setattr__(
            self,
            "token_digest",
            digest256(
                "CancellationToken",
                CANCELLATION_TOKEN_SCHEMA_VERSION,
                _cancellation_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CancellationToken is immutable")

    def __repr__(self) -> str:
        return f"CancellationToken(context_id={self.context_id!r})"

    def validate_integrity(self) -> None:
        require_uuid(self.token_id, "token_id")
        require_uuid(self.context_id, "context_id")
        if type(self._context_ledger) is not CallContextLedger:
            raise ValueError("cancellation token ledger changed")
        expected_id = uuid5(
            _CANCELLATION_UUID_NAMESPACE,
            str(
                digest256(
                    "CancellationTokenIdentifier",
                    CANCELLATION_TOKEN_SCHEMA_VERSION,
                    {"context_id": self.context_id},
                )
            ),
        )
        if self.token_id != expected_id or self.token_digest != digest256(
            "CancellationToken",
            CANCELLATION_TOKEN_SCHEMA_VERSION,
            _cancellation_payload(self),
        ):
            raise ValueError("cancellation token integrity mismatch")

    def is_cancelled(self) -> bool:
        return self._context_ledger.is_cancelled(self)

    def wait(self, *, timeout_ms: int) -> bool:
        """Wait interruptibly; return true when cancelled or deadline-expired."""

        require_plain_int(timeout_ms, "timeout_ms", minimum=1)
        return self._context_ledger.wait_for_stop(self, timeout_ms=timeout_ms)


@runtime_final
class CancellationSource:
    __slots__ = ("_token", "_context_ledger")

    def __init__(
        self,
        *,
        token: CancellationToken,
        context_ledger: "CallContextLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CALL_FACTORY_AUTHORITY:
            raise TypeError("CancellationSource requires RuntimeCallFactory")
        if type(token) is not CancellationToken:
            raise TypeError("token must be CancellationToken")
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_context_ledger", context_ledger)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CancellationSource is immutable")

    def __repr__(self) -> str:
        return f"CancellationSource(context_id={self._token.context_id!r})"

    def cancel(self, *, reason: CancellationReason) -> bool:
        if type(reason) is not CancellationReason:
            raise TypeError("reason must be CancellationReason")
        return self._context_ledger.cancel(self._token, reason=reason)


def _context_identifier_payload(
    *,
    planned: PlannedExecution,
    authorization: AuthorizationContext,
    lease: RegistryPolicyLease,
    deadline: MonotonicDeadline,
) -> dict[str, object]:
    return {
        "request_id": planned.plan.request_id,
        "plan_id": planned.plan.plan_id,
        "plan_digest": planned.plan.plan_digest,
        "planned_execution_digest": planned.planned_execution_digest,
        "registry_revision": planned.resolved_pipeline.registry_revision,
        "registry_digest": planned.resolved_pipeline.registry_digest,
        "privacy_authorization_id": authorization.authorization_id,
        "privacy_authorization_digest": authorization.authorization_digest,
        "registry_policy_lease_id": lease.lease_id,
        "registry_policy_lease_digest": lease.lease_digest,
        "runtime_deadline_digest": deadline.deadline_digest,
        "max_network_calls_total": planned.plan.max_network_calls_total,
        "max_billable_calls": planned.plan.max_billable_calls,
    }


def _context_payload(context: "CallContext") -> dict[str, object]:
    return {
        "context_id": context.context_id,
        "request_id": context.request_id,
        "plan_id": context.plan_id,
        "plan_digest": context.plan_digest,
        "planned_execution_digest": context.planned_execution_digest,
        "registry_revision": context.registry_revision,
        "registry_digest": context.registry_digest,
        "privacy_authorization_id": context.privacy_authorization_id,
        "privacy_authorization_digest": context.privacy_authorization_digest,
        "registry_policy_lease_id": context.registry_policy_lease.lease_id,
        "registry_policy_lease_digest": context.registry_policy_lease.lease_digest,
        "runtime_deadline_digest": context.runtime_deadline.deadline_digest,
        "operation_budget_digests": tuple(
            budget.budget_digest for budget in context.operation_budgets
        ),
        "global_network_budget_digest": context.global_network_budget.budget_digest,
        "billable_budget_digest": context.billable_budget.budget_digest,
        "cancellation_token_digest": context.cancellation_token.token_digest,
    }


@runtime_final
class CallContext:
    __slots__ = (
        "context_id",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "registry_revision",
        "registry_digest",
        "privacy_authorization_id",
        "privacy_authorization_digest",
        "runtime_deadline",
        "operation_budgets",
        "global_network_budget",
        "billable_budget",
        "registry_policy_lease",
        "cancellation_token",
        "context_digest",
        "_context_ledger",
    )

    def __init__(
        self,
        *,
        context_id: UUID,
        planned: PlannedExecution,
        authorization: AuthorizationContext,
        runtime_deadline: MonotonicDeadline,
        operation_budgets: tuple[AtomicBudget, ...],
        global_network_budget: AtomicBudget,
        billable_budget: AtomicBudget,
        registry_policy_lease: RegistryPolicyLease,
        cancellation_token: CancellationToken,
        context_ledger: "CallContextLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CALL_FACTORY_AUTHORITY:
            raise TypeError("CallContext requires RuntimeCallFactory")
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(authorization) is not AuthorizationContext:
            raise TypeError("authorization must be AuthorizationContext")
        if type(runtime_deadline) is not MonotonicDeadline:
            raise TypeError("runtime_deadline must be MonotonicDeadline")
        if type(registry_policy_lease) is not RegistryPolicyLease:
            raise TypeError("registry_policy_lease must be RegistryPolicyLease")
        if type(cancellation_token) is not CancellationToken:
            raise TypeError("cancellation_token must be CancellationToken")
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        if type(operation_budgets) is not tuple or not all(
            type(item) is AtomicBudget for item in operation_budgets
        ):
            raise TypeError("operation_budgets must contain AtomicBudget values")
        values = (
            ("context_id", context_id),
            ("request_id", planned.plan.request_id),
            ("plan_id", planned.plan.plan_id),
            ("plan_digest", planned.plan.plan_digest),
            ("planned_execution_digest", planned.planned_execution_digest),
            ("registry_revision", planned.resolved_pipeline.registry_revision),
            ("registry_digest", planned.resolved_pipeline.registry_digest),
            ("privacy_authorization_id", authorization.authorization_id),
            ("privacy_authorization_digest", authorization.authorization_digest),
            ("runtime_deadline", runtime_deadline),
            ("operation_budgets", operation_budgets),
            ("global_network_budget", global_network_budget),
            ("billable_budget", billable_budget),
            ("registry_policy_lease", registry_policy_lease),
            ("cancellation_token", cancellation_token),
            ("_context_ledger", context_ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "context_digest",
            digest256(
                "CallContext", CALL_CONTEXT_SCHEMA_VERSION, _context_payload(self)
            ),
        )
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CallContext is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "CallContext":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "CallContext("
            f"context_id={self.context_id!r}, request_id={self.request_id!r}, "
            f"operation_budget_count={len(self.operation_budgets)!r})"
        )

    def validate_integrity(self) -> None:
        for name in (
            "context_id",
            "request_id",
            "plan_id",
            "privacy_authorization_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "plan_digest",
            "planned_execution_digest",
            "registry_digest",
            "privacy_authorization_digest",
            "context_digest",
        ):
            require_digest(getattr(self, name), name)
        if type(self._context_ledger) is not CallContextLedger:
            raise ValueError("context ledger authority changed")
        self.runtime_deadline.validate_integrity()
        self.registry_policy_lease.validate_integrity()
        self.cancellation_token.validate_integrity()
        if self.cancellation_token._context_ledger is not self._context_ledger:
            raise ValueError("cancellation token ledger changed")
        budgets = (
            *self.operation_budgets,
            self.global_network_budget,
            self.billable_budget,
        )
        if len({item.budget_id for item in budgets}) != len(budgets):
            raise ValueError("budget identifiers must be unique")
        for budget in budgets:
            budget.validate_integrity()
            if (
                budget.context_id != self.context_id
                or budget._context_ledger is not self._context_ledger
            ):
                raise ValueError("budget context binding changed")
        if self.cancellation_token.context_id != self.context_id:
            raise ValueError("cancellation token context changed")
        if self.context_digest != digest256(
            "CallContext", CALL_CONTEXT_SCHEMA_VERSION, _context_payload(self)
        ):
            raise ValueError("call context integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "context_id": str(self.context_id),
            "request_id": str(self.request_id),
            "registry_revision": self.registry_revision,
            "operation_budget_count": len(self.operation_budgets),
            "cancelled": self.cancellation_token.is_cancelled(),
        }


def _reservation_payload(value: "AttemptBudgetReservation") -> dict[str, object]:
    return {
        "reservation_id": value.reservation_id,
        "context_id": value.context_id,
        "session_id": value.session_id,
        "operation_id": value.operation_id,
        "request_envelope_digest": value.request_envelope_digest,
        "operation_attempt": value.operation_attempt,
        "global_attempt": value.global_attempt,
        "billable_attempt": value.billable_attempt,
        "reserved_wall_at": value.reserved_wall_at,
        "reserved_monotonic_ns": value.reserved_monotonic_ns,
    }


@runtime_final
class AttemptBudgetReservation:
    """Ledger-owned proof that all applicable counters advanced atomically."""

    __slots__ = (
        "reservation_id",
        "context_id",
        "session_id",
        "operation_id",
        "request_envelope_digest",
        "operation_attempt",
        "global_attempt",
        "billable_attempt",
        "reserved_wall_at",
        "reserved_monotonic_ns",
        "reservation_digest",
        "_context_ledger",
    )

    def __init__(
        self,
        *,
        reservation_id: UUID,
        context_id: UUID,
        session_id: UUID,
        operation_id: UUID,
        request_envelope_digest: Digest256,
        operation_attempt: int,
        global_attempt: int,
        billable_attempt: int | None,
        reserved_wall_at: datetime,
        reserved_monotonic_ns: int,
        context_ledger: "CallContextLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("reservation requires AttemptGate")
        for name, value in (
            ("reservation_id", reservation_id),
            ("context_id", context_id),
            ("session_id", session_id),
            ("operation_id", operation_id),
        ):
            require_uuid(value, name)
        require_digest(request_envelope_digest, "request_envelope_digest")
        require_plain_int(operation_attempt, "operation_attempt", minimum=1)
        require_plain_int(global_attempt, "global_attempt", minimum=1)
        if billable_attempt is not None:
            require_plain_int(billable_attempt, "billable_attempt", minimum=1)
        require_aware_datetime(reserved_wall_at, "reserved_wall_at")
        require_plain_int(reserved_monotonic_ns, "reserved_monotonic_ns")
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        for name, value in (
            ("reservation_id", reservation_id),
            ("context_id", context_id),
            ("session_id", session_id),
            ("operation_id", operation_id),
            ("request_envelope_digest", request_envelope_digest),
            ("operation_attempt", operation_attempt),
            ("global_attempt", global_attempt),
            ("billable_attempt", billable_attempt),
            ("reserved_wall_at", reserved_wall_at),
            ("reserved_monotonic_ns", reserved_monotonic_ns),
            ("_context_ledger", context_ledger),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "reservation_digest",
            digest256(
                "AttemptBudgetReservation",
                ATTEMPT_BUDGET_RESERVATION_SCHEMA_VERSION,
                _reservation_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AttemptBudgetReservation is immutable")

    def validate_integrity(self) -> None:
        if type(self._context_ledger) is not CallContextLedger:
            raise ValueError("reservation ledger changed")
        if self.reservation_digest != digest256(
            "AttemptBudgetReservation",
            ATTEMPT_BUDGET_RESERVATION_SCHEMA_VERSION,
            _reservation_payload(self),
        ):
            raise ValueError("reservation integrity mismatch")


class _ContextState:
    __slots__ = (
        "context",
        "context_digest",
        "authorization",
        "planned",
        "budget_counts",
        "operation_billable",
        "cancelled_reason",
        "closed",
        "attempt_gate",
        "gate_activities",
        "session_deadlines",
        "in_flight",
        "reservations",
    )

    def __init__(
        self,
        *,
        context: CallContext,
        authorization: AuthorizationContext,
        planned: PlannedExecution,
    ) -> None:
        self.context = context
        self.context_digest = context.context_digest
        self.authorization = authorization
        self.planned = planned
        self.budget_counts = {
            budget.budget_id: 0
            for budget in (
                *context.operation_budgets,
                context.global_network_budget,
                context.billable_budget,
            )
        }
        self.operation_billable = {
            operation.operation_id: operation.billable
            for stage in planned.plan.stages
            for operation in stage.network_operations
        }
        self.cancelled_reason: CancellationReason | None = None
        self.closed = False
        self.attempt_gate: object | None = None
        self.gate_activities: dict[UUID, object] = {}
        self.session_deadlines: dict[UUID, tuple[datetime, int]] = {}
        self.in_flight: dict[UUID, UUID] = {}
        self.reservations: dict[UUID, AttemptBudgetReservation] = {}


@runtime_final
class CallContextLedger:
    """Single-lock owner of request lifecycle, cancellation and all budgets."""

    __slots__ = (
        "_authority_ledger",
        "_clock",
        "_contexts",
        "_pending_starts",
        "_lock",
        "_condition",
        "_last_wall_time",
        "_last_monotonic_after_ns",
        "_revision",
    )

    def __init__(self, authority_ledger: RegistryPolicyAuthorityLedger) -> None:
        self._initialize(
            authority_ledger=authority_ledger,
            clock=SystemRuntimeClock(),
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        authority_ledger: RegistryPolicyAuthorityLedger,
        clock: RuntimeClock,
        _authority: object | None = None,
    ) -> "CallContextLedger":
        if _authority is not _TEST_CLOCK_AUTHORITY:
            raise TypeError("test clocks require trusted test authority")
        if not isinstance(clock, RuntimeClock):
            raise TypeError("clock must be RuntimeClock")
        value = object.__new__(cls)
        value._initialize(authority_ledger=authority_ledger, clock=clock)
        return value

    def _initialize(
        self,
        *,
        authority_ledger: RegistryPolicyAuthorityLedger,
        clock: RuntimeClock,
    ) -> None:
        if type(authority_ledger) is not RegistryPolicyAuthorityLedger:
            raise TypeError(
                "authority_ledger must be RegistryPolicyAuthorityLedger"
            )
        if not isinstance(clock, RuntimeClock):
            raise TypeError("clock must be RuntimeClock")
        lock = RLock()
        object.__setattr__(self, "_authority_ledger", authority_ledger)
        object.__setattr__(self, "_clock", clock)
        object.__setattr__(self, "_contexts", {})
        object.__setattr__(self, "_pending_starts", {})
        object.__setattr__(self, "_lock", lock)
        object.__setattr__(self, "_condition", Condition(lock))
        object.__setattr__(self, "_last_wall_time", None)
        object.__setattr__(self, "_last_monotonic_after_ns", None)
        object.__setattr__(self, "_revision", 0)

    def _sample_locked(self) -> ClockSample:
        try:
            sample = self._clock.sample()
        except Exception:
            raise _runtime_error("可信运行时钟不可用。") from None
        if type(sample) is not ClockSample:
            raise _runtime_error("可信运行时钟返回了无效样本。")
        try:
            sample.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _runtime_error("可信运行时钟返回了无效样本。") from None
        previous_mono = self._last_monotonic_after_ns
        previous_wall = self._last_wall_time
        if (
            previous_mono is not None
            and sample.monotonic_before_ns < previous_mono
        ):
            raise _runtime_error("运行时单调时钟发生回退。")
        if previous_wall is not None and sample.wall_time < previous_wall:
            raise _runtime_error("运行时墙钟发生回退。")
        object.__setattr__(
            self, "_last_monotonic_after_ns", sample.monotonic_after_ns
        )
        object.__setattr__(self, "_last_wall_time", sample.wall_time)
        return sample

    def _begin_start(
        self,
        *,
        planned: PlannedExecution,
        _authority: object | None = None,
    ) -> ClockSample:
        if _authority is not _CALL_FACTORY_AUTHORITY:
            raise TypeError("context start requires RuntimeCallFactory")
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        try:
            planned.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _runtime_error("执行计划完整性校验失败。") from None
        request_id = planned.plan.request_id
        with self._lock:
            if request_id in self._contexts or request_id in self._pending_starts:
                raise _runtime_error("同一请求不能创建第二个 CallContext。")
            sample = self._sample_locked()
            self._pending_starts[request_id] = (
                planned.planned_execution_digest,
                sample,
            )
            return sample

    def _abandon_start(
        self,
        *,
        planned: PlannedExecution,
        sample: ClockSample,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CALL_FACTORY_AUTHORITY:
            raise TypeError("context start cleanup requires RuntimeCallFactory")
        with self._lock:
            pending = self._pending_starts.get(planned.plan.request_id)
            if pending == (planned.planned_execution_digest, sample):
                del self._pending_starts[planned.plan.request_id]

    def _start_with(
        self,
        *,
        planned: PlannedExecution,
        authorization: AuthorizationContext,
        lease: RegistryPolicyLease,
        start_sample: ClockSample,
        _authority: object | None = None,
    ) -> tuple[CallContext, CancellationSource]:
        if _authority is not _CALL_FACTORY_AUTHORITY:
            raise TypeError("context issue requires RuntimeCallFactory")
        if type(authorization) is not AuthorizationContext:
            raise TypeError("authorization must be AuthorizationContext")
        if type(lease) is not RegistryPolicyLease:
            raise TypeError("lease must be RegistryPolicyLease")
        request_id = planned.plan.request_id
        with self._lock:
            pending = self._pending_starts.get(request_id)
            if pending != (planned.planned_execution_digest, start_sample):
                raise _runtime_error("CallContext 启动样本不属于当前账本。")
            if request_id in self._contexts:
                raise _runtime_error("同一请求不能创建第二个 CallContext。")
            current_sample = self._sample_locked()
            try:
                deadline = MonotonicDeadline.from_sample(
                    sample=start_sample,
                    timeout_budget_ms=planned.plan.timeout_budget_ms,
                    wall_valid_until=authorization.valid_until,
                    _authority=_DEADLINE_AUTHORITY,
                )
            except (TypeError, ValueError, AttributeError):
                raise _runtime_error(
                    "无法从当前隐私授权建立运行时 deadline。"
                ) from None
            if deadline.is_expired_at(current_sample.monotonic_after_ns):
                raise _timeout_error()
            identifier = _context_identifier_payload(
                planned=planned,
                authorization=authorization,
                lease=lease,
                deadline=deadline,
            )
            context_id = uuid5(
                _CONTEXT_UUID_NAMESPACE,
                str(
                    digest256(
                        "CallContextIdentifier",
                        CALL_CONTEXT_SCHEMA_VERSION,
                        identifier,
                    )
                ),
            )
            token_id = uuid5(
                _CANCELLATION_UUID_NAMESPACE,
                str(
                    digest256(
                        "CancellationTokenIdentifier",
                        CANCELLATION_TOKEN_SCHEMA_VERSION,
                        {"context_id": context_id},
                    )
                ),
            )
            token = CancellationToken(
                token_id=token_id,
                context_id=context_id,
                context_ledger=self,
                _authority=_CALL_FACTORY_AUTHORITY,
            )
            operation_budgets = tuple(
                AtomicBudget(
                    budget_id=_budget_id_for(
                        context_id=context_id,
                        kind=BudgetKind.OPERATION_NETWORK,
                        scope_id=operation.operation_id,
                        limit=stage.max_attempts_per_operation,
                    ),
                    context_id=context_id,
                    kind=BudgetKind.OPERATION_NETWORK,
                    scope_id=operation.operation_id,
                    limit=stage.max_attempts_per_operation,
                    context_ledger=self,
                    _authority=_CALL_FACTORY_AUTHORITY,
                )
                for stage in planned.plan.stages
                for operation in stage.network_operations
            )
            global_budget = AtomicBudget(
                budget_id=_budget_id_for(
                    context_id=context_id,
                    kind=BudgetKind.GLOBAL_NETWORK,
                    scope_id=planned.plan.plan_id,
                    limit=planned.plan.max_network_calls_total,
                ),
                context_id=context_id,
                kind=BudgetKind.GLOBAL_NETWORK,
                scope_id=planned.plan.plan_id,
                limit=planned.plan.max_network_calls_total,
                context_ledger=self,
                _authority=_CALL_FACTORY_AUTHORITY,
            )
            billable_budget = AtomicBudget(
                budget_id=_budget_id_for(
                    context_id=context_id,
                    kind=BudgetKind.GLOBAL_BILLABLE,
                    scope_id=planned.plan.plan_id,
                    limit=planned.plan.max_billable_calls,
                ),
                context_id=context_id,
                kind=BudgetKind.GLOBAL_BILLABLE,
                scope_id=planned.plan.plan_id,
                limit=planned.plan.max_billable_calls,
                context_ledger=self,
                _authority=_CALL_FACTORY_AUTHORITY,
            )
            context = CallContext(
                context_id=context_id,
                planned=planned,
                authorization=authorization,
                runtime_deadline=deadline,
                operation_budgets=operation_budgets,
                global_network_budget=global_budget,
                billable_budget=billable_budget,
                registry_policy_lease=lease,
                cancellation_token=token,
                context_ledger=self,
                _authority=_CALL_FACTORY_AUTHORITY,
            )
            state = _ContextState(
                context=context,
                authorization=authorization,
                planned=planned,
            )
            source = CancellationSource(
                token=token,
                context_ledger=self,
                _authority=_CALL_FACTORY_AUTHORITY,
            )
            # Publish only after every fallible value construction succeeds.
            # The remaining assignments are the minimal start-once commit.
            self._contexts[request_id] = state
            del self._pending_starts[request_id]
            object.__setattr__(self, "_revision", self._revision + 1)
            return context, source

    def _require_context_locked(self, context: CallContext) -> _ContextState:
        if type(context) is not CallContext:
            raise TypeError("context must be CallContext")
        try:
            context.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _runtime_error("CallContext 完整性校验失败。") from None
        state = self._contexts.get(context.request_id)
        if (
            state is None
            or state.context is not context
            or context._context_ledger is not self
            or state.context_digest != context.context_digest
            or state.planned.planned_execution_digest
            != context.planned_execution_digest
            or state.planned.plan.request_id != context.request_id
            or state.planned.plan.plan_id != context.plan_id
            or state.planned.plan.plan_digest != context.plan_digest
            or state.planned.resolved_pipeline.registry_revision
            != context.registry_revision
            or state.planned.resolved_pipeline.registry_digest
            != context.registry_digest
            or state.authorization.authorization_id
            != context.privacy_authorization_id
            or state.authorization.authorization_digest
            != context.privacy_authorization_digest
            or context.registry_policy_lease._planned_execution
            is not state.planned
            or context.registry_policy_lease._authority_ledger
            is not self._authority_ledger
        ):
            raise _runtime_error("CallContext 不属于当前账本。")
        return state

    @staticmethod
    def _budget_for(
        context: CallContext, *, kind: BudgetKind, scope_id: UUID
    ) -> AtomicBudget:
        budgets = (
            *context.operation_budgets,
            context.global_network_budget,
            context.billable_budget,
        )
        matches = tuple(
            item
            for item in budgets
            if item.kind is kind and item.scope_id == scope_id
        )
        if len(matches) != 1:
            raise _runtime_error("CallContext 预算绑定无效。")
        return matches[0]

    def snapshot(self, request_id: UUID) -> CallContext:
        require_uuid(request_id, "request_id")
        with self._lock:
            state = self._contexts.get(request_id)
            if state is None:
                raise _runtime_error("CallContext 不存在。")
            self._require_context_locked(state.context)
            return state.context

    def snapshot_budget(self, budget: AtomicBudget) -> BudgetSnapshot:
        if type(budget) is not AtomicBudget:
            raise TypeError("budget must be AtomicBudget")
        with self._lock:
            state = self._contexts.get(budget.context_id)
            if state is None:
                state = next(
                    (
                        item
                        for item in self._contexts.values()
                        if item.context.context_id == budget.context_id
                    ),
                    None,
                )
            if (
                state is None
                or budget._context_ledger is not self
                or budget.budget_id not in state.budget_counts
            ):
                raise _runtime_error("预算不属于当前 CallContext。")
            budget.validate_integrity()
            return BudgetSnapshot(
                limit=budget.limit,
                consumed=state.budget_counts[budget.budget_id],
            )

    def is_cancelled(self, token: CancellationToken) -> bool:
        if type(token) is not CancellationToken:
            raise TypeError("token must be CancellationToken")
        with self._lock:
            state = next(
                (
                    item
                    for item in self._contexts.values()
                    if item.context.context_id == token.context_id
                ),
                None,
            )
            if (
                state is None
                or state.context.cancellation_token is not token
                or token._context_ledger is not self
            ):
                raise _runtime_error("取消令牌不属于当前 CallContext。")
            return state.cancelled_reason is not None

    def cancel(
        self,
        token: CancellationToken,
        *,
        reason: CancellationReason,
    ) -> bool:
        if type(reason) is not CancellationReason:
            raise TypeError("reason must be CancellationReason")
        with self._condition:
            state = next(
                (
                    item
                    for item in self._contexts.values()
                    if item.context.cancellation_token is token
                ),
                None,
            )
            if state is None or token._context_ledger is not self:
                raise _runtime_error("取消令牌不属于当前 CallContext。")
            if state.closed:
                return False
            if state.cancelled_reason is not None:
                return False
            self._sample_locked()
            state.cancelled_reason = reason
            object.__setattr__(self, "_revision", self._revision + 1)
            self._condition.notify_all()
            return True

    def wait_for_stop(self, token: CancellationToken, *, timeout_ms: int) -> bool:
        require_plain_int(timeout_ms, "timeout_ms", minimum=1)
        with self._condition:
            state = next(
                (
                    item
                    for item in self._contexts.values()
                    if item.context.cancellation_token is token
                ),
                None,
            )
            if state is None or token._context_ledger is not self:
                raise _runtime_error("取消令牌不属于当前 CallContext。")
            sample = self._sample_locked()
            if (
                state.closed
                or state.cancelled_reason is not None
                or sample.monotonic_after_ns
                >= state.context.runtime_deadline.deadline_monotonic_ns
            ):
                return True
            remaining_ns = (
                state.context.runtime_deadline.deadline_monotonic_ns
                - sample.monotonic_after_ns
            )
            wait_seconds = min(timeout_ms / 1000, remaining_ns / 1_000_000_000)
            self._condition.wait(timeout=wait_seconds)
            sample = self._sample_locked()
            return (
                state.closed
                or state.cancelled_reason is not None
                or sample.monotonic_after_ns
                >= state.context.runtime_deadline.deadline_monotonic_ns
            )

    def _run_active_action(
        self,
        *,
        context: CallContext,
        attempt_gate: object,
        session_id: UUID,
        session_valid_until: datetime,
        action: Callable[[ClockSample], _T],
        _authority: object | None = None,
    ) -> _T:
        """Run a pure AttemptGate preflight under the context lock.

        Credential authorization needs the same exact-object, cancellation and
        deadline checks as an attempt reservation, but must not consume any
        network budget.  Passing the trusted sample to the callback also keeps
        caller-supplied wall-clock values out of the authority path.
        """

        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("context checks require AttemptGate")
        if attempt_gate is None:
            raise TypeError("attempt_gate must be an exact object")
        require_uuid(session_id, "session_id")
        require_aware_datetime(session_valid_until, "session_valid_until")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._lock:
            state = self._require_context_locked(context)
            self._require_attempt_gate_locked(
                state=state,
                attempt_gate=attempt_gate,
            )
            sample = self._sample_locked()
            if state.closed:
                raise _runtime_error("CallContext 已经终结。")
            if state.cancelled_reason is not None:
                raise _cancelled_error()
            if (
                sample.monotonic_after_ns
                >= context.runtime_deadline.deadline_monotonic_ns
            ):
                raise _timeout_error()
            self._require_session_deadline_locked(
                state=state,
                context=context,
                sample=sample,
                session_id=session_id,
                session_valid_until=session_valid_until,
            )
            return action(sample)

    def _sample_for_attempt(
        self,
        *,
        context: CallContext,
        _authority: object | None = None,
    ) -> ClockSample:
        """Take a trusted pre-lock sample without binding an AttemptGate.

        No caller-controlled gate or session identity is committed here.  The
        exact gate/session binding happens only at the end of the full ordered
        authority path, preventing an invalid preflight from poisoning a live
        CallContext.
        """

        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("attempt sampling requires AttemptGate")
        with self._lock:
            state = self._require_context_locked(context)
            sample = self._sample_locked()
            if state.closed:
                raise _runtime_error("CallContext 已经终结。")
            if state.cancelled_reason is not None:
                raise _cancelled_error()
            if (
                sample.monotonic_after_ns
                >= context.runtime_deadline.deadline_monotonic_ns
            ):
                raise _timeout_error()
            return sample

    @staticmethod
    def _require_attempt_gate_locked(
        *,
        state: _ContextState,
        attempt_gate: object,
    ) -> None:
        if state.attempt_gate is None:
            state.attempt_gate = attempt_gate
        elif state.attempt_gate is not attempt_gate:
            raise _runtime_error("CallContext 已绑定另一个 AttemptGate。")

    @staticmethod
    def _require_session_deadline_locked(
        *,
        state: _ContextState,
        context: CallContext,
        sample: ClockSample,
        session_id: UUID,
        session_valid_until: datetime,
    ) -> int:
        """Map one exact wall expiry to a conservative monotonic deadline."""

        cached = state.session_deadlines.get(session_id)
        if cached is None:
            remaining = session_valid_until - sample.wall_time
            remaining_ns = (
                remaining.days * 86_400_000_000_000
                + remaining.seconds * 1_000_000_000
                + remaining.microseconds * 1_000
            )
            if remaining_ns <= 0:
                raise _timeout_error()
            deadline_ns = min(
                context.runtime_deadline.deadline_monotonic_ns,
                sample.monotonic_before_ns + remaining_ns,
            )
            state.session_deadlines[session_id] = (
                session_valid_until,
                deadline_ns,
            )
        else:
            cached_valid_until, deadline_ns = cached
            if cached_valid_until != session_valid_until:
                raise _runtime_error("发送会话的有效期绑定已经变化。")
        if (
            sample.wall_time >= session_valid_until
            or sample.monotonic_after_ns >= deadline_ns
        ):
            raise _timeout_error()
        return deadline_ns

    def _reserve_attempt_budgets(
        self,
        *,
        context: CallContext,
        session_id: UUID,
        session_valid_until: datetime,
        attempt_gate: object,
        operation_id: UUID,
        request_envelope_digest: Digest256,
        billable: bool | ContractMarker,
        action: Callable[[AttemptBudgetReservation], _T],
        _authority: object | None = None,
    ) -> _T:
        """Atomically reserve operation/global/billable budgets, then callback."""

        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("budget reservation requires AttemptGate")
        require_uuid(session_id, "session_id")
        require_aware_datetime(session_valid_until, "session_valid_until")
        if attempt_gate is None:
            raise TypeError("attempt_gate must be an exact object")
        require_uuid(operation_id, "operation_id")
        require_digest(request_envelope_digest, "request_envelope_digest")
        if type(billable) is not bool and billable is not ContractMarker.UNKNOWN:
            raise TypeError("billable must be bool or unknown")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._lock:
            state = self._require_context_locked(context)
            self._require_attempt_gate_locked(
                state=state,
                attempt_gate=attempt_gate,
            )
            sample = self._sample_locked()
            if state.closed:
                raise _runtime_error("CallContext 已经终结。")
            if state.cancelled_reason is not None:
                raise _cancelled_error()
            if (
                sample.monotonic_after_ns
                >= context.runtime_deadline.deadline_monotonic_ns
            ):
                raise _timeout_error()
            self._require_session_deadline_locked(
                state=state,
                context=context,
                sample=sample,
                session_id=session_id,
                session_valid_until=session_valid_until,
            )
            expected_billable = state.operation_billable.get(operation_id)
            if expected_billable is None or expected_billable != billable:
                raise _runtime_error("网络操作与冻结计费策略不匹配。")
            if session_id in state.in_flight:
                raise _runtime_error("同一发送会话已有在途 attempt。")
            operation_budget = self._budget_for(
                context,
                kind=BudgetKind.OPERATION_NETWORK,
                scope_id=operation_id,
            )
            global_budget = context.global_network_budget
            billable_budget = context.billable_budget
            selected = [operation_budget, global_budget]
            if _is_billable(billable):
                selected.append(billable_budget)
            if any(
                state.budget_counts[item.budget_id] >= item.limit
                for item in selected
            ):
                raise _runtime_error("本次请求的网络调用预算已经耗尽。")
            for item in selected:
                state.budget_counts[item.budget_id] += 1
            operation_attempt = state.budget_counts[operation_budget.budget_id]
            global_attempt = state.budget_counts[global_budget.budget_id]
            billable_attempt = (
                state.budget_counts[billable_budget.budget_id]
                if _is_billable(billable)
                else None
            )
            seed_payload = {
                "context_id": context.context_id,
                "session_id": session_id,
                "operation_id": operation_id,
                "request_envelope_digest": request_envelope_digest,
                "operation_attempt": operation_attempt,
                "global_attempt": global_attempt,
                "billable_attempt": billable_attempt,
                "reserved_wall_at": sample.wall_time,
                "reserved_monotonic_ns": sample.monotonic_after_ns,
            }
            reservation_id = uuid5(
                _RESERVATION_UUID_NAMESPACE,
                str(
                    digest256(
                        "AttemptBudgetReservationIdentifier",
                        ATTEMPT_BUDGET_RESERVATION_SCHEMA_VERSION,
                        seed_payload,
                    )
                ),
            )
            reservation = AttemptBudgetReservation(
                reservation_id=reservation_id,
                context_id=context.context_id,
                session_id=session_id,
                operation_id=operation_id,
                request_envelope_digest=request_envelope_digest,
                operation_attempt=operation_attempt,
                global_attempt=global_attempt,
                billable_attempt=billable_attempt,
                reserved_wall_at=sample.wall_time,
                reserved_monotonic_ns=sample.monotonic_after_ns,
                context_ledger=self,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
            state.reservations[reservation_id] = reservation
            state.in_flight[session_id] = reservation_id
            object.__setattr__(self, "_revision", self._revision + 1)
            try:
                return action(reservation)
            except BaseException:
                # Reservation is never refunded, but a failed pure permit
                # construction must not leave a phantom in-flight request.
                del state.in_flight[session_id]
                del state.reservations[reservation_id]
                object.__setattr__(self, "_revision", self._revision + 1)
                self._condition.notify_all()
                raise

    def _register_gate_activity(
        self,
        *,
        context: CallContext,
        attempt_gate: object,
        activity_id: UUID,
        _authority: object | None = None,
    ) -> None:
        """Bind one non-sensitive active permit marker to this context."""

        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("gate activity registration requires AttemptGate")
        require_uuid(activity_id, "activity_id")
        if attempt_gate is None:
            raise TypeError("attempt_gate must be an exact object")
        with self._lock:
            state = self._require_context_locked(context)
            self._require_attempt_gate_locked(
                state=state,
                attempt_gate=attempt_gate,
            )
            if state.closed:
                raise _runtime_error("CallContext 已经终结。")
            if activity_id in state.gate_activities:
                raise _runtime_error("CallContext gate activity 已存在。")
            state.gate_activities[activity_id] = attempt_gate
            object.__setattr__(self, "_revision", self._revision + 1)

    def _discard_gate_activity(
        self,
        *,
        context: CallContext,
        attempt_gate: object,
        activity_id: UUID,
        _authority: object | None = None,
    ) -> None:
        """Rollback a permit construction that failed before publication."""

        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("gate activity rollback requires AttemptGate")
        require_uuid(activity_id, "activity_id")
        with self._condition:
            state = self._require_context_locked(context)
            if state.gate_activities.get(activity_id) is not attempt_gate:
                raise _runtime_error("CallContext gate activity 不匹配。")
            del state.gate_activities[activity_id]
            object.__setattr__(self, "_revision", self._revision + 1)
            self._condition.notify_all()

    def _finish_gate_activity(
        self,
        *,
        context: CallContext,
        attempt_gate: object,
        activity_id: UUID,
        action: Callable[[], _T],
        _authority: object | None = None,
    ) -> _T:
        """Finish a credential-only activity in Context -> Gate order."""

        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("gate activity completion requires AttemptGate")
        require_uuid(activity_id, "activity_id")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._condition:
            state = self._require_context_locked(context)
            if state.gate_activities.get(activity_id) is not attempt_gate:
                raise _runtime_error("CallContext gate activity 不属于当前 Gate。")
            result = action()
            del state.gate_activities[activity_id]
            object.__setattr__(self, "_revision", self._revision + 1)
            self._condition.notify_all()
            return result

    def _finish_attempt_and_activity(
        self,
        *,
        context: CallContext,
        reservation: AttemptBudgetReservation,
        attempt_gate: object,
        activity_id: UUID,
        action: Callable[[], _T],
        _authority: object | None = None,
    ) -> _T:
        """Atomically release in-flight and context-bound Gate activity."""

        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("attempt completion requires AttemptGate")
        if type(reservation) is not AttemptBudgetReservation:
            raise TypeError("reservation must be AttemptBudgetReservation")
        require_uuid(activity_id, "activity_id")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._condition:
            state = self._require_context_locked(context)
            if (
                reservation._context_ledger is not self
                or reservation.context_id != context.context_id
                or state.reservations.get(reservation.reservation_id)
                is not reservation
                or state.in_flight.get(reservation.session_id)
                != reservation.reservation_id
                or state.gate_activities.get(activity_id) is not attempt_gate
            ):
                raise _runtime_error("attempt 或 gate activity 不属于当前账本。")
            try:
                reservation.validate_integrity()
            except (TypeError, ValueError, AttributeError):
                raise _runtime_error("attempt 预算凭证完整性校验失败。") from None
            result = action()
            del state.in_flight[reservation.session_id]
            del state.reservations[reservation.reservation_id]
            del state.gate_activities[activity_id]
            object.__setattr__(self, "_revision", self._revision + 1)
            self._condition.notify_all()
            return result

    def _finish_attempt(
        self,
        reservation: AttemptBudgetReservation,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ATTEMPT_BUDGET_AUTHORITY:
            raise TypeError("attempt completion requires AttemptGate")
        if type(reservation) is not AttemptBudgetReservation:
            raise TypeError("reservation must be AttemptBudgetReservation")
        with self._lock:
            state = next(
                (
                    item
                    for item in self._contexts.values()
                    if item.context.context_id == reservation.context_id
                ),
                None,
            )
            if (
                state is None
                or reservation._context_ledger is not self
                or state.reservations.get(reservation.reservation_id)
                is not reservation
                or state.in_flight.get(reservation.session_id)
                != reservation.reservation_id
            ):
                raise _runtime_error("attempt 预算凭证不属于当前账本。")
            try:
                reservation.validate_integrity()
            except (TypeError, ValueError, AttributeError):
                raise _runtime_error("attempt 预算凭证完整性校验失败。") from None
            del state.in_flight[reservation.session_id]
            del state.reservations[reservation.reservation_id]
            object.__setattr__(self, "_revision", self._revision + 1)
            self._condition.notify_all()

    def close(self, context: CallContext) -> bool:
        with self._condition:
            state = self._require_context_locked(context)
            if state.closed:
                return False
            if state.gate_activities:
                raise _runtime_error(
                    "仍有活跃 credential/attempt authority，不能终结 CallContext。"
                )
            if state.in_flight:
                raise _runtime_error("仍有在途 attempt，不能终结 CallContext。")
            state.closed = True
            if state.cancelled_reason is None:
                state.cancelled_reason = CancellationReason.PIPELINE_TERMINAL
            object.__setattr__(self, "_revision", self._revision + 1)
            self._condition.notify_all()
            return True

    def safe_metadata(self) -> dict[str, int]:
        with self._lock:
            return {
                "revision": self._revision,
                "context_count": len(self._contexts),
                "pending_start_count": len(self._pending_starts),
                "in_flight_attempt_count": sum(
                    len(state.in_flight) for state in self._contexts.values()
                ),
                "active_gate_activity_count": sum(
                    len(state.gate_activities)
                    for state in self._contexts.values()
                ),
            }


@runtime_final
class RuntimeCallFactory:
    """Authorize privacy and immediately start the unique request context."""

    __slots__ = ()

    @staticmethod
    def authorize_and_start(
        *,
        planned: PlannedExecution,
        consent_ledger: ConsentLedger,
        consent_grant_ids: tuple[UUID, ...],
        authority_ledger: RegistryPolicyAuthorityLedger,
        context_ledger: CallContextLedger,
    ) -> tuple[AuthorizationContext, CallContext, CancellationSource]:
        if type(consent_ledger) is not ConsentLedger:
            raise TypeError("consent_ledger must be ConsentLedger")
        if type(authority_ledger) is not RegistryPolicyAuthorityLedger:
            raise TypeError(
                "authority_ledger must be RegistryPolicyAuthorityLedger"
            )
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        if context_ledger._authority_ledger is not authority_ledger:
            raise _runtime_error("CallContext 与 Registry authority 不匹配。")
        start_sample = context_ledger._begin_start(
            planned=planned,
            _authority=_CALL_FACTORY_AUTHORITY,
        )
        try:
            gate = PrivacyGate()
            authorization = gate.authorize(
                planned=planned,
                ledger=consent_ledger,
                consent_grant_ids=consent_grant_ids,
                now=start_sample.wall_time,
            )

            def issue_authority_and_context() -> tuple[
                CallContext, CancellationSource
            ]:
                return authority_ledger._issue_with(
                    planned=planned,
                    issued_at=start_sample.wall_time,
                    action=lambda lease: context_ledger._start_with(
                        planned=planned,
                        authorization=authorization,
                        lease=lease,
                        start_sample=start_sample,
                        _authority=_CALL_FACTORY_AUTHORITY,
                    ),
                    _authority=_CONTEXT_AUTHORITY,
                )

            context, source = gate._run_authorized_action(
                planned=planned,
                authorization=authorization,
                ledger=consent_ledger,
                now=start_sample.wall_time,
                action=issue_authority_and_context,
                _authority=_ATOMIC_PRIVACY_AUTHORITY,
            )
            return authorization, context, source
        finally:
            context_ledger._abandon_start(
                planned=planned,
                sample=start_sample,
                _authority=_CALL_FACTORY_AUTHORITY,
            )


__all__ = [
    "ATOMIC_BUDGET_SCHEMA_VERSION",
    "ATTEMPT_BUDGET_RESERVATION_SCHEMA_VERSION",
    "CALL_CONTEXT_SCHEMA_VERSION",
    "CANCELLATION_TOKEN_SCHEMA_VERSION",
    "AtomicBudget",
    "AttemptBudgetReservation",
    "BudgetKind",
    "BudgetSnapshot",
    "CallContext",
    "CallContextLedger",
    "CancellationReason",
    "CancellationSource",
    "CancellationToken",
    "RuntimeCallFactory",
]
