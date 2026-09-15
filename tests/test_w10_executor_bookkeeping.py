"""W10 executor-owned recovery for interrupted run bookkeeping."""
from __future__ import annotations

import unittest
from unittest import mock

from snapquiz.domain.errors import CancelledError, ConfigError, EndpointPolicyError
from snapquiz.runtime.context import CallContextLedger

from tests.w10_helpers import execute_fixture, make_w10_fixture


class _CommitThenRaiseSetDict(dict):
    """Commit one mapping write, then emulate an asynchronous interrupt."""

    def __init__(self, source, *, failure: BaseException | None = None) -> None:
        super().__init__(source)
        self.armed = True
        self.failure = failure

    def __setitem__(self, key, value) -> None:
        super().__setitem__(key, value)
        if self.armed:
            self.armed = False
            if self.failure is not None:
                raise self.failure
            raise KeyboardInterrupt


class _CommitThenRaiseDeleteDict(dict):
    """Commit one mapping deletion, then emulate an asynchronous interrupt."""

    def __init__(self, source) -> None:
        super().__init__(source)
        self.armed = True

    def __delitem__(self, key) -> None:
        super().__delitem__(key)
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt


class _RaiseBeforeDeleteDict(dict):
    """Interrupt one deletion before the mapping is mutated."""

    def __init__(self, source) -> None:
        super().__init__(source)
        self.armed = True

    def __delitem__(self, key) -> None:
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt
        super().__delitem__(key)


class _NoOpDeleteDict(dict):
    """Adversarial mapping whose deletion reports success without mutation."""

    def __delitem__(self, key) -> None:
        del key


class _RaiseOnceValuesDict(dict):
    """Lose one postcondition read after terminal deletion has committed."""

    def __init__(self, source) -> None:
        super().__init__(source)
        self.armed = True

    def values(self):
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt
        return super().values()


class W10ExecutorBookkeepingRecoveryTest(unittest.TestCase):
    def _assert_no_effects(self, fixture) -> None:
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)

    def _assert_no_pending_or_active(self, fixture) -> None:
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata(),
            {
                "pending_cleanup_count": 0,
                "pending_request_ids": (),
                "active_request_count": 0,
            },
        )

    def test_recovery_registration_commit_then_raise_is_removed(self):
        fixture = make_w10_fixture()
        fixture.executor._recovery_states = _CommitThenRaiseSetDict(
            fixture.executor._recovery_states
        )

        with self.assertRaises(CancelledError):
            execute_fixture(fixture)

        self._assert_no_effects(fixture)
        self._assert_no_pending_or_active(fixture)

    def test_active_registration_commit_then_raise_is_removed(self):
        fixture = make_w10_fixture()
        fixture.executor._active_request_ids = _CommitThenRaiseSetDict(
            fixture.executor._active_request_ids
        )

        with self.assertRaises(CancelledError):
            execute_fixture(fixture)

        self._assert_no_effects(fixture)
        self._assert_no_pending_or_active(fixture)

    def test_active_deletion_commit_then_raise_still_delivers_result(self):
        fixture = make_w10_fixture()
        fixture.executor._active_request_ids = _CommitThenRaiseDeleteDict(
            fixture.executor._active_request_ids
        )

        result = execute_fixture(fixture)

        self.assertEqual(result.answer, "2")
        self._assert_no_pending_or_active(fixture)

    def test_recovery_deletion_commit_then_raise_still_delivers_result(self):
        fixture = make_w10_fixture()
        fixture.executor._recovery_states = _CommitThenRaiseDeleteDict(
            fixture.executor._recovery_states
        )

        result = execute_fixture(fixture)

        self.assertEqual(result.answer, "2")
        self._assert_no_pending_or_active(fixture)

    def test_active_deletion_precommit_failure_retains_recoverable_result(self):
        fixture = make_w10_fixture()
        fixture.executor._active_request_ids = _RaiseBeforeDeleteDict(
            fixture.executor._active_request_ids
        )

        with self.assertRaises(EndpointPolicyError):
            execute_fixture(fixture)

        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)
        before = (
            fixture.capture_source.capture_calls,
            len(fixture.credential_source.calls),
            fixture.transport.calls,
        )

        result = fixture.executor.retry_cleanup_and_finalize(
            fixture.planned.plan.request_id
        )

        self.assertEqual(result.answer, "2")
        self.assertEqual(
            before,
            (
                fixture.capture_source.capture_calls,
                len(fixture.credential_source.calls),
                fixture.transport.calls,
            ),
        )
        self._assert_no_pending_or_active(fixture)

    def test_active_deletion_noop_never_drops_recovery_state(self):
        fixture = make_w10_fixture()
        fixture.executor._active_request_ids = _NoOpDeleteDict(
            fixture.executor._active_request_ids
        )

        with self.assertRaises(EndpointPolicyError):
            execute_fixture(fixture)

        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)
        with self.assertRaises(ConfigError):
            fixture.executor.retry_cleanup_and_finalize(
                fixture.planned.plan.request_id
            )
        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)

    def test_recovery_deletion_precommit_failure_is_retryable(self):
        fixture = make_w10_fixture()
        fixture.executor._recovery_states = _RaiseBeforeDeleteDict(
            fixture.executor._recovery_states
        )

        with self.assertRaises(EndpointPolicyError):
            execute_fixture(fixture)

        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)

        result = fixture.executor.retry_cleanup_and_finalize(
            fixture.planned.plan.request_id
        )

        self.assertEqual(result.answer, "2")
        self._assert_no_pending_or_active(fixture)

    def test_terminal_observer_loss_republishes_recovery_state(self):
        fixture = make_w10_fixture()
        fixture.executor._recovery_states = _RaiseOnceValuesDict(
            fixture.executor._recovery_states
        )

        with self.assertRaises(EndpointPolicyError):
            execute_fixture(fixture)

        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)

        result = fixture.executor.retry_cleanup_and_finalize(
            fixture.planned.plan.request_id
        )

        self.assertEqual(result.answer, "2")
        self._assert_no_pending_or_active(fixture)

    def test_retry_terminal_observer_loss_republishes_recovery_state(self):
        fixture = make_w10_fixture()
        with mock.patch.object(
            CallContextLedger,
            "close",
            new=lambda owner, context: False,
        ):
            with self.assertRaises(EndpointPolicyError):
                execute_fixture(fixture)

        fixture.executor._recovery_states = _RaiseOnceValuesDict(
            fixture.executor._recovery_states
        )
        request_id = fixture.planned.plan.request_id
        before = (
            fixture.capture_source.capture_calls,
            len(fixture.credential_source.calls),
            fixture.transport.calls,
        )

        with self.assertRaises(EndpointPolicyError):
            fixture.executor.retry_cleanup_and_finalize(request_id)

        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)

        result = fixture.executor.retry_cleanup_and_finalize(request_id)

        self.assertEqual(result.answer, "2")
        self.assertEqual(
            before,
            (
                fixture.capture_source.capture_calls,
                len(fixture.credential_source.calls),
                fixture.transport.calls,
            ),
        )
        self._assert_no_pending_or_active(fixture)

    def test_retry_active_registration_return_loss_does_not_replay(self):
        fixture = make_w10_fixture()
        with mock.patch.object(
            CallContextLedger,
            "close",
            new=lambda owner, context: False,
        ):
            with self.assertRaises(EndpointPolicyError):
                execute_fixture(fixture)

        request_id = fixture.planned.plan.request_id
        before = (
            fixture.capture_source.capture_calls,
            len(fixture.credential_source.calls),
            fixture.transport.calls,
        )
        fixture.executor._active_request_ids = _CommitThenRaiseSetDict(
            fixture.executor._active_request_ids
        )

        with self.assertRaises(ConfigError):
            fixture.executor.retry_cleanup_and_finalize(request_id)

        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)
        self.assertEqual(
            before,
            (
                fixture.capture_source.capture_calls,
                len(fixture.credential_source.calls),
                fixture.transport.calls,
            ),
        )

        result = fixture.executor.retry_cleanup_and_finalize(request_id)

        self.assertEqual(result.answer, "2")
        self.assertEqual(
            before,
            (
                fixture.capture_source.capture_calls,
                len(fixture.credential_source.calls),
                fixture.transport.calls,
            ),
        )
        self._assert_no_pending_or_active(fixture)

    def test_retry_active_registration_operation_error_is_settled(self):
        fixture = make_w10_fixture()
        with mock.patch.object(
            CallContextLedger,
            "close",
            new=lambda owner, context: False,
        ):
            with self.assertRaises(EndpointPolicyError):
                execute_fixture(fixture)

        request_id = fixture.planned.plan.request_id
        fixture.executor._active_request_ids = _CommitThenRaiseSetDict(
            fixture.executor._active_request_ids,
            failure=ConfigError(
                stage="synthetic_mapping",
                retryable=False,
                safe_message="synthetic mapping failure",
            ),
        )

        with self.assertRaises(ConfigError) as raised:
            fixture.executor.retry_cleanup_and_finalize(request_id)

        self.assertEqual(raised.exception.stage, "multimodal_pipeline")
        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        self.assertEqual(metadata["active_request_count"], 0)

        result = fixture.executor.retry_cleanup_and_finalize(request_id)

        self.assertEqual(result.answer, "2")
        self._assert_no_pending_or_active(fixture)


if __name__ == "__main__":
    unittest.main()
