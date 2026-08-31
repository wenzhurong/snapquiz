from __future__ import annotations

from datetime import timedelta
import inspect
from threading import Barrier, Lock, Thread
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.config.profiles import build_builtin_registry
from snapquiz.domain.errors import (
    CancelledError,
    EndpointPolicyError,
    TimeoutError,
)
from snapquiz.domain.policy import ContractMarker
from snapquiz.runtime.authority import (
    RegistryPolicyAuthorityLedger,
    _ATTEMPT_AUTHORITY,
)
from snapquiz.runtime.context import (
    AttemptBudgetReservation,
    BudgetKind,
    CallContext,
    CallContextLedger,
    CancellationReason,
    RuntimeCallFactory,
    _ATTEMPT_BUDGET_AUTHORITY,
    _TEST_CLOCK_AUTHORITY,
)
from snapquiz.runtime.clock import RuntimeClock

from tests.w06_helpers import NOW
from tests.w07_helpers import make_w07_authorities
from tests.w09_helpers import ManualRuntimeClock, make_w09_runtime


SESSION_IDS = tuple(
    UUID(f"90000000-0000-0000-0000-{value:012d}")
    for value in range(1, 8)
)
_CONTEXT_TEST_ATTEMPT_GATE = object()


def _operation(runtime):
    return runtime.planned.plan.stages[0].network_operations[0]


def _reserve(runtime, *, session_id=SESSION_IDS[0], action=lambda value: value):
    operation = _operation(runtime)
    return runtime.authority_ledger._run_active_action(
        lease=runtime.call_context.registry_policy_lease,
        planned=runtime.planned,
        action=lambda: runtime.context_ledger._reserve_attempt_budgets(
            context=runtime.call_context,
            session_id=session_id,
            session_valid_until=(
                runtime.call_context.runtime_deadline.started_wall_at
                + timedelta(
                    milliseconds=(
                        runtime.call_context.runtime_deadline.timeout_budget_ms
                    )
                )
            ),
            attempt_gate=_CONTEXT_TEST_ATTEMPT_GATE,
            operation_id=operation.operation_id,
            request_envelope_digest=runtime.prepared.request_envelope_digest,
            billable=operation.billable,
            action=action,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        ),
        _authority=_ATTEMPT_AUTHORITY,
    )


class W09CallContextTest(unittest.TestCase):
    def test_factory_starts_unique_context_with_conservative_deadline(self):
        runtime = make_w09_runtime()
        context = runtime.call_context

        self.assertEqual(
            runtime.events,
            (
                "plan",
                "consent_grant",
                "call_context",
                "capture_authorization",
                "capture_consumed",
                "capture_artifact",
                "capture_validated",
                "stage_invocation",
                "prepared_outbound",
            ),
        )

        self.assertIs(type(context), CallContext)
        self.assertIs(
            runtime.context_ledger.snapshot(context.request_id),
            context,
        )
        self.assertIs(
            runtime.authority_ledger.snapshot(
                context.registry_policy_lease.lease_id
            ),
            context.registry_policy_lease,
        )
        self.assertEqual(
            context.runtime_deadline.started_monotonic_ns,
            10_000_000_000,
        )
        self.assertEqual(
            context.runtime_deadline.deadline_monotonic_ns,
            10_000_000_000
            + runtime.planned.plan.timeout_budget_ms * 1_000_000,
        )
        self.assertEqual(
            context.runtime_deadline.wall_valid_until,
            runtime.runtime_authorization.valid_until,
        )
        self.assertEqual(len(context.operation_budgets), 1)
        self.assertEqual(
            context.operation_budgets[0].kind,
            BudgetKind.OPERATION_NETWORK,
        )
        self.assertEqual(
            context.global_network_budget.snapshot().remaining,
            runtime.planned.plan.max_network_calls_total,
        )
        self.assertEqual(
            context.billable_budget.snapshot().remaining,
            runtime.planned.plan.max_billable_calls,
        )
        context.validate_integrity()

        signature = inspect.signature(RuntimeCallFactory.authorize_and_start)
        for forbidden in (
            "now",
            "clock",
            "deadline",
            "timeout_budget_ms",
            "max_network_calls_total",
            "max_billable_calls",
        ):
            self.assertNotIn(forbidden, signature.parameters)

    def test_same_request_cannot_restart_or_reset_budgets(self):
        runtime = make_w09_runtime()
        reservation = _reserve(runtime)
        runtime.context_ledger._finish_attempt(
            reservation,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))
        self.assertFalse(runtime.context_ledger.close(runtime.call_context))

        with self.assertRaises(EndpointPolicyError):
            RuntimeCallFactory.authorize_and_start(
                planned=runtime.planned,
                consent_ledger=runtime.consent_ledger,
                consent_grant_ids=runtime.runtime_authorization.consent_grant_ids,
                authority_ledger=runtime.authority_ledger,
                context_ledger=runtime.context_ledger,
            )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            1,
        )

    def test_concurrent_start_has_exactly_one_winner(self):
        registry = build_builtin_registry()
        base = make_w07_authorities(registry=registry)
        authority = RegistryPolicyAuthorityLedger(registry)
        ledger = CallContextLedger._for_testing(
            authority_ledger=authority,
            clock=ManualRuntimeClock(),
            _authority=_TEST_CLOCK_AUTHORITY,
        )
        barrier = Barrier(3)
        lock = Lock()
        successes = []
        errors = []

        def worker():
            barrier.wait()
            try:
                result = RuntimeCallFactory.authorize_and_start(
                    planned=base.planned,
                    consent_ledger=base.consent_ledger,
                    consent_grant_ids=base.privacy.consent_grant_ids,
                    authority_ledger=authority,
                    context_ledger=ledger,
                )
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    successes.append(result)

        threads = [Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=3)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        self.assertEqual(ledger.safe_metadata()["context_count"], 1)
        self.assertEqual(ledger.safe_metadata()["pending_start_count"], 0)

    def test_start_construction_failure_rolls_back_context_and_lease(self):
        registry = build_builtin_registry()
        base = make_w07_authorities(registry=registry)
        authority = RegistryPolicyAuthorityLedger(registry)
        ledger = CallContextLedger._for_testing(
            authority_ledger=authority,
            clock=ManualRuntimeClock(),
            _authority=_TEST_CLOCK_AUTHORITY,
        )

        with (
            patch(
                "snapquiz.runtime.context.CancellationSource",
                side_effect=RuntimeError("unpublished construction failed"),
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "unpublished construction failed",
            ),
        ):
            RuntimeCallFactory.authorize_and_start(
                planned=base.planned,
                consent_ledger=base.consent_ledger,
                consent_grant_ids=base.privacy.consent_grant_ids,
                authority_ledger=authority,
                context_ledger=ledger,
            )

        self.assertEqual(ledger.safe_metadata()["context_count"], 0)
        self.assertEqual(ledger.safe_metadata()["pending_start_count"], 0)
        self.assertEqual(authority.safe_metadata()["lease_count"], 0)

        _, context, _ = RuntimeCallFactory.authorize_and_start(
            planned=base.planned,
            consent_ledger=base.consent_ledger,
            consent_grant_ids=base.privacy.consent_grant_ids,
            authority_ledger=authority,
            context_ledger=ledger,
        )
        self.assertIs(ledger.snapshot(context.request_id), context)
        self.assertEqual(authority.safe_metadata()["lease_count"], 1)

    def test_clock_backend_failure_is_sanitized_and_does_not_start(self):
        class FailingClock(RuntimeClock):
            def sample(self):
                raise RuntimeError("sensitive clock backend detail")

        registry = build_builtin_registry()
        base = make_w07_authorities(registry=registry)
        authority = RegistryPolicyAuthorityLedger(registry)
        ledger = CallContextLedger._for_testing(
            authority_ledger=authority,
            clock=FailingClock(),
            _authority=_TEST_CLOCK_AUTHORITY,
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            RuntimeCallFactory.authorize_and_start(
                planned=base.planned,
                consent_ledger=base.consent_ledger,
                consent_grant_ids=base.privacy.consent_grant_ids,
                authority_ledger=authority,
                context_ledger=ledger,
            )

        self.assertEqual(str(raised.exception), "可信运行时钟不可用。")
        self.assertNotIn("sensitive", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(ledger.safe_metadata()["context_count"], 0)
        self.assertEqual(ledger.safe_metadata()["pending_start_count"], 0)
        self.assertEqual(authority.safe_metadata()["lease_count"], 0)

    def test_budget_reservation_is_atomic_unknown_is_billable_and_not_refunded(self):
        runtime = make_w09_runtime()
        self.assertIs(_operation(runtime).billable, ContractMarker.UNKNOWN)

        first = _reserve(runtime, session_id=SESSION_IDS[0])
        self.assertIs(type(first), AttemptBudgetReservation)
        self.assertEqual(first.operation_attempt, 1)
        self.assertEqual(first.global_attempt, 1)
        self.assertEqual(first.billable_attempt, 1)
        for budget in (
            runtime.call_context.operation_budgets[0],
            runtime.call_context.global_network_budget,
            runtime.call_context.billable_budget,
        ):
            self.assertEqual(budget.snapshot().consumed, 1)

        with self.assertRaises(EndpointPolicyError):
            _reserve(runtime, session_id=SESSION_IDS[0])
        for budget in (
            runtime.call_context.operation_budgets[0],
            runtime.call_context.global_network_budget,
            runtime.call_context.billable_budget,
        ):
            self.assertEqual(budget.snapshot().consumed, 1)

        runtime.context_ledger._finish_attempt(
            first,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        second = _reserve(runtime, session_id=SESSION_IDS[0])
        runtime.context_ledger._finish_attempt(
            second,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        with self.assertRaises(EndpointPolicyError):
            _reserve(runtime, session_id=SESSION_IDS[1])
        for budget in (
            runtime.call_context.operation_budgets[0],
            runtime.call_context.global_network_budget,
            runtime.call_context.billable_budget,
        ):
            self.assertEqual(budget.snapshot().consumed, 2)
            self.assertEqual(budget.snapshot().remaining, 0)

    def test_concurrent_budget_exhaustion_has_two_winners_without_overdraft(self):
        runtime = make_w09_runtime()
        barrier = Barrier(4)
        lock = Lock()
        reservations = []
        errors = []

        def worker(session_id):
            barrier.wait()
            try:
                result = _reserve(runtime, session_id=session_id)
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    reservations.append(result)

        threads = [
            Thread(target=worker, args=(SESSION_IDS[index],))
            for index in range(3)
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=3)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(reservations), 2)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            2,
        )
        self.assertEqual(
            runtime.call_context.billable_budget.snapshot().consumed,
            2,
        )

    def test_cancel_deadline_and_clock_rollback_fail_before_budget_change(self):
        runtime = make_w09_runtime()
        self.assertTrue(
            runtime.cancellation_source.cancel(
                reason=CancellationReason.USER_REQUEST
            )
        )
        self.assertFalse(
            runtime.cancellation_source.cancel(
                reason=CancellationReason.USER_REQUEST
            )
        )
        self.assertTrue(runtime.call_context.cancellation_token.is_cancelled())
        with self.assertRaises(CancelledError) as cancelled:
            _reserve(runtime)
        self.assertFalse(cancelled.exception.retryable)
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )

        expired = make_w09_runtime()
        expired.clock.advance(milliseconds=30_000)
        with self.assertRaises(TimeoutError) as timeout:
            _reserve(expired)
        self.assertFalse(timeout.exception.retryable)
        self.assertEqual(
            expired.call_context.global_network_budget.snapshot().consumed,
            0,
        )

        rollback = make_w09_runtime()
        rollback.clock.advance(
            milliseconds=1,
            wall_delta=timedelta(seconds=-1),
        )
        with self.assertRaises(EndpointPolicyError):
            _reserve(rollback)
        self.assertEqual(
            rollback.call_context.global_network_budget.snapshot().consumed,
            0,
        )

    def test_close_stops_waiters_and_later_cancel_is_idempotent(self):
        runtime = make_w09_runtime()
        token = runtime.call_context.cancellation_token

        self.assertTrue(runtime.context_ledger.close(runtime.call_context))
        self.assertTrue(token.is_cancelled())
        self.assertTrue(token.wait(timeout_ms=1))
        self.assertFalse(
            runtime.cancellation_source.cancel(
                reason=CancellationReason.USER_REQUEST
            )
        )

    def test_authority_revoke_fails_before_context_budget_lock(self):
        runtime = make_w09_runtime()
        runtime.authority_ledger.revoke()
        with self.assertRaises(EndpointPolicyError) as raised:
            _reserve(runtime)
        self.assertEqual(raised.exception.stage, "attempt_gate")
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )

    def test_failed_permit_callback_burns_budget_but_releases_in_flight(self):
        runtime = make_w09_runtime()

        def fail(_reservation):
            raise RuntimeError("pure permit construction failed")

        with self.assertRaisesRegex(RuntimeError, "pure permit construction"):
            _reserve(runtime, action=fail)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            1,
        )
        second = _reserve(runtime)
        self.assertEqual(second.global_attempt, 2)

    def test_cross_ledger_and_static_tamper_are_rejected(self):
        first = make_w09_runtime()
        second_registry = build_builtin_registry()
        second_authority = RegistryPolicyAuthorityLedger(second_registry)
        second_ledger = CallContextLedger._for_testing(
            authority_ledger=second_authority,
            clock=ManualRuntimeClock(),
            _authority=_TEST_CLOCK_AUTHORITY,
        )
        with self.assertRaises(EndpointPolicyError):
            second_ledger.snapshot_budget(
                first.call_context.global_network_budget
            )

        object.__setattr__(
            first.call_context,
            "registry_revision",
            "caller-controlled-revision",
        )
        with self.assertRaises(EndpointPolicyError) as raised:
            _reserve(first)
        self.assertNotIn("caller-controlled", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
