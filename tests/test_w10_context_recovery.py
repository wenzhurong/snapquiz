"""Focused W10 tests for caller-owned Context recovery postconditions."""
from __future__ import annotations

import unittest
from unittest import mock
from uuid import UUID

from snapquiz.domain.errors import CancelledError, ConfigError, EndpointPolicyError
from snapquiz.runtime.attempt import AttemptGate
from snapquiz.runtime.context import (
    CallContextLedger,
    RuntimeCallFactory,
    _ATTEMPT_BUDGET_AUTHORITY,
)

from tests.w09_helpers import make_w09_runtime
from tests.w10_helpers import execute_fixture, make_w10_fixture


class _InterruptingPendingStarts(dict):
    """Expose the context-published/pending-not-deleted interruption state."""

    def __init__(self, source, *, deletion_failures: int) -> None:
        super().__init__(source)
        self.deletion_failures = deletion_failures

    def __delitem__(self, key) -> None:
        if self.deletion_failures:
            self.deletion_failures -= 1
            raise KeyboardInterrupt
        super().__delitem__(key)


class _NoOpSetDict(dict):
    """Return normally while refusing to publish a context state."""

    def __setitem__(self, key, value) -> None:
        del key, value


class W10ContextRecoveryTest(unittest.TestCase):
    def _foreign_context(self, fixture):
        foreign = make_w10_fixture(
            request_id=UUID("85000000-0000-0000-0000-000000000001"),
            registry=fixture.registry,
        )
        authorization, context, source = RuntimeCallFactory.authorize_and_start(
            planned=foreign.planned,
            consent_ledger=foreign.consent_ledger,
            consent_grant_ids=(foreign.grant.grant_id,),
            authority_ledger=fixture.authority_ledger,
            context_ledger=fixture.context_ledger,
        )
        return foreign, authorization, context, source

    def test_context_map_normal_noop_never_returns_unregistered_context(self):
        fixture = make_w10_fixture()
        object.__setattr__(
            fixture.context_ledger,
            "_contexts",
            _NoOpSetDict(fixture.context_ledger._contexts),
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            execute_fixture(fixture)

        self.assertEqual(raised.exception.stage, "call_context")
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(
            fixture.context_ledger.safe_metadata()["pending_start_count"],
            0,
        )

    def test_foreign_same_request_context_does_not_block_owner_cleanup(self):
        fixture = make_w10_fixture()
        _, foreign_context, _ = RuntimeCallFactory.authorize_and_start(
            planned=fixture.planned,
            consent_ledger=fixture.consent_ledger,
            consent_grant_ids=(fixture.grant.grant_id,),
            authority_ledger=fixture.authority_ledger,
            context_ledger=fixture.context_ledger,
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            execute_fixture(fixture)

        self.assertEqual(raised.exception.stage, "call_context")
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertFalse(fixture.context_ledger.is_closed(foreign_context))
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )
        self.assertTrue(fixture.context_ledger.close(foreign_context))

    def test_unproven_foreign_recovery_context_is_never_adopted_or_closed(self):
        fixture = make_w10_fixture()
        _, _, foreign_context, _ = self._foreign_context(fixture)
        original_start = RuntimeCallFactory.authorize_and_start

        def lose_target_return(**kwargs):
            original_start(**kwargs)
            raise RuntimeError("synthetic target return loss")

        with (
            mock.patch.object(
                RuntimeCallFactory,
                "authorize_and_start",
                new=staticmethod(lose_target_return),
            ),
            mock.patch.object(
                CallContextLedger,
                "_recover_context_for_cleanup",
                new=lambda *args, **kwargs: foreign_context,
            ),
        ):
            with self.assertRaises(EndpointPolicyError):
                execute_fixture(fixture)

        self.assertFalse(fixture.context_ledger.is_closed(foreign_context))
        target_context = fixture.context_ledger.snapshot(
            fixture.planned.plan.request_id
        )
        self.assertFalse(fixture.context_ledger.is_closed(target_context))
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            1,
        )

        with self.assertRaises(ConfigError):
            fixture.executor.retry_cleanup_and_finalize(
                fixture.planned.plan.request_id
            )

        self.assertTrue(fixture.context_ledger.is_closed(target_context))
        self.assertFalse(fixture.context_ledger.is_closed(foreign_context))
        self.assertTrue(fixture.context_ledger.close(foreign_context))

    def test_factory_foreign_source_alias_is_rejected_before_adoption(self):
        fixture = make_w10_fixture()
        _, _, foreign_context, foreign_source = self._foreign_context(fixture)
        original_start = RuntimeCallFactory.authorize_and_start

        def swap_source(**kwargs):
            authorization, context, _ = original_start(**kwargs)
            return authorization, context, foreign_source

        with mock.patch.object(
            RuntimeCallFactory,
            "authorize_and_start",
            new=staticmethod(swap_source),
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        target_context = fixture.context_ledger.snapshot(
            fixture.planned.plan.request_id
        )
        self.assertTrue(fixture.context_ledger.is_closed(target_context))
        self.assertFalse(fixture.context_ledger.is_closed(foreign_context))
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertTrue(fixture.context_ledger.close(foreign_context))

    def test_factory_foreign_context_alias_is_rejected_before_adoption(self):
        fixture = make_w10_fixture()
        _, _, foreign_context, foreign_source = self._foreign_context(fixture)
        original_start = RuntimeCallFactory.authorize_and_start

        def swap_context(**kwargs):
            authorization, _, _ = original_start(**kwargs)
            return authorization, foreign_context, foreign_source

        with mock.patch.object(
            RuntimeCallFactory,
            "authorize_and_start",
            new=staticmethod(swap_context),
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        target_context = fixture.context_ledger.snapshot(
            fixture.planned.plan.request_id
        )
        self.assertTrue(fixture.context_ledger.is_closed(target_context))
        self.assertFalse(fixture.context_ledger.is_closed(foreign_context))
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertTrue(fixture.context_ledger.close(foreign_context))
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )

    def test_capture_claim_normal_noop_prevents_capture(self):
        fixture = make_w10_fixture()

        def claim_noop(*args, **kwargs):
            del args, kwargs
            return None

        with mock.patch.object(
            CallContextLedger,
            "_claim_capture_start",
            new=claim_noop,
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        context = fixture.context_ledger.snapshot(fixture.planned.plan.request_id)
        self.assertTrue(fixture.context_ledger.is_closed(context))

    def test_capture_claim_commit_then_raise_still_captures_exactly_once(self):
        fixture = make_w10_fixture()
        original = CallContextLedger._claim_capture_start

        def commit_then_raise(owner, context, **kwargs):
            original(owner, context, **kwargs)
            raise KeyboardInterrupt

        with mock.patch.object(
            CallContextLedger,
            "_claim_capture_start",
            new=commit_then_raise,
        ):
            result = execute_fixture(fixture)

        self.assertEqual(result.answer, "2")
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.transport.calls, 1)

    def test_result_claim_normal_noop_prevents_result_delivery(self):
        fixture = make_w10_fixture()

        def claim_noop(*args, **kwargs):
            del args, kwargs
            return None

        with mock.patch.object(
            CallContextLedger,
            "_claim_result_publication",
            new=claim_noop,
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.transport.calls, 1)
        context = fixture.context_ledger.snapshot(fixture.planned.plan.request_id)
        self.assertTrue(fixture.context_ledger.is_closed(context))

    def test_result_claim_commit_then_raise_delivers_original_result(self):
        fixture = make_w10_fixture()
        original = CallContextLedger._claim_result_publication

        def commit_then_raise(owner, context, **kwargs):
            original(owner, context, **kwargs)
            raise KeyboardInterrupt

        with mock.patch.object(
            CallContextLedger,
            "_claim_result_publication",
            new=commit_then_raise,
        ):
            result = execute_fixture(fixture)

        self.assertEqual(result.answer, "2")
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.transport.calls, 1)

    def test_recovery_noop_return_is_not_terminal_proof(self):
        fixture = make_w10_fixture()
        original_start = RuntimeCallFactory.authorize_and_start

        def lose_context_return(**kwargs):
            original_start(**kwargs)
            raise RuntimeError("synthetic context return loss")

        def recovery_noop(*args, **kwargs):
            del args, kwargs
            return None

        with (
            mock.patch.object(
                RuntimeCallFactory,
                "authorize_and_start",
                new=staticmethod(lose_context_return),
            ),
            mock.patch.object(
                CallContextLedger,
                "_recover_context_for_cleanup",
                new=recovery_noop,
            ),
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture)

        self.assertEqual(raised.exception.stage, "multimodal_cleanup")
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            1,
        )
        self.assertEqual(fixture.context_ledger.safe_metadata()["context_count"], 1)
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)

        with self.assertRaises(ConfigError):
            fixture.executor.retry_cleanup_and_finalize(
                fixture.planned.plan.request_id
            )
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )
        context = fixture.context_ledger.snapshot(fixture.planned.plan.request_id)
        self.assertTrue(fixture.context_ledger.is_closed(context))

    def test_context_map_commit_with_pending_delete_interruption_is_normalized(self):
        fixture = make_w10_fixture()
        interrupted = _InterruptingPendingStarts(
            fixture.context_ledger._pending_starts,
            deletion_failures=2,
        )
        object.__setattr__(
            fixture.context_ledger,
            "_pending_starts",
            interrupted,
        )

        with self.assertRaises(CancelledError):
            execute_fixture(fixture)

        metadata = fixture.context_ledger.safe_metadata()
        self.assertEqual(metadata["context_count"], 1)
        self.assertEqual(metadata["pending_start_count"], 0)
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )
        context = fixture.context_ledger.snapshot(fixture.planned.plan.request_id)
        self.assertTrue(fixture.context_ledger.is_closed(context))
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)

    def test_context_recovery_observer_rejects_truthy_non_boolean_wrapper(self):
        fixture = make_w10_fixture()
        original_start = RuntimeCallFactory.authorize_and_start

        def lose_context_return(**kwargs):
            original_start(**kwargs)
            raise RuntimeError("synthetic context return loss")

        def recovery_noop(*args, **kwargs):
            del args, kwargs
            return None

        def truthy_observer(*args, **kwargs):
            del args, kwargs
            return 1

        with (
            mock.patch.object(
                RuntimeCallFactory,
                "authorize_and_start",
                new=staticmethod(lose_context_return),
            ),
            mock.patch.object(
                CallContextLedger,
                "_recover_context_for_cleanup",
                new=recovery_noop,
            ),
            mock.patch.object(
                CallContextLedger,
                "_context_recovery_is_exact",
                new=truthy_observer,
            ),
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture)

        self.assertEqual(raised.exception.stage, "multimodal_cleanup")
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            1,
        )
        with self.assertRaises(ConfigError):
            fixture.executor.retry_cleanup_and_finalize(
                fixture.planned.plan.request_id
            )
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )

    def test_gate_activity_observer_requires_exact_context_gate_and_id(self):
        runtime = make_w09_runtime()
        gate = AttemptGate()
        activity_id = UUID("84000000-0000-0000-0000-000000000001")
        other_id = UUID("84000000-0000-0000-0000-000000000002")

        runtime.context_ledger._register_gate_activity(
            context=runtime.call_context,
            attempt_gate=gate,
            activity_id=activity_id,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        observed = runtime.context_ledger._gate_activity_is_exact(
            context=runtime.call_context,
            attempt_gate=gate,
            activity_id=activity_id,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        self.assertIs(type(observed), bool)
        self.assertIs(observed, True)
        self.assertIs(
            runtime.context_ledger._gate_activity_is_exact(
                context=runtime.call_context,
                attempt_gate=gate,
                activity_id=other_id,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            ),
            False,
        )
        self.assertIs(
            runtime.context_ledger._gate_activity_is_exact(
                context=runtime.call_context,
                attempt_gate=object(),
                activity_id=activity_id,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            ),
            False,
        )

        runtime.context_ledger._discard_gate_activity(
            context=runtime.call_context,
            attempt_gate=gate,
            activity_id=activity_id,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        self.assertIs(
            runtime.context_ledger._gate_activity_is_exact(
                context=runtime.call_context,
                attempt_gate=gate,
                activity_id=activity_id,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            ),
            False,
        )
        runtime.validated.release()
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))


if __name__ == "__main__":
    unittest.main()
