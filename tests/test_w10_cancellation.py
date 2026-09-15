"""W10 cancellation binding, retry, and cross-executor isolation."""
from __future__ import annotations

import threading
import unittest
from unittest import mock

from snapquiz.domain.errors import CancelledError, ConfigError, EndpointPolicyError
from snapquiz.pipelines.multimodal import MultimodalCancellation
from snapquiz.runtime.context import CallContextLedger

from tests.w10_helpers import execute_fixture, make_w10_fixture


class W10CancellationRecoveryTest(unittest.TestCase):
    def _run_blocked(self, fixture, cancellation):
        entered = threading.Event()
        release = threading.Event()
        outcome: list[object] = []

        def block_after_observation() -> None:
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("test barrier timed out")

        fixture.capture_source.after_authorization_observation = (
            block_after_observation
        )

        def run() -> None:
            try:
                outcome.append(
                    execute_fixture(fixture, cancellation=cancellation)
                )
            except BaseException as error:
                outcome.append(error)

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(entered.wait(timeout=5))
        return release, worker, outcome

    def _finish_blocked(self, release, worker, outcome) -> object:
        release.set()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcome), 1)
        return outcome[0]

    def _assert_zero_capture_secret_network(self, fixture) -> None:
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)

    def test_shared_handle_second_executor_cannot_finish_first_binding(self):
        first = make_w10_fixture()
        second = make_w10_fixture()
        cancellation = MultimodalCancellation()
        release, worker, outcome = self._run_blocked(first, cancellation)
        try:
            with self.assertRaises(ConfigError):
                execute_fixture(second, cancellation=cancellation)

            self.assertEqual(
                cancellation.safe_metadata(),
                {
                    "cancel_requested": False,
                    "bound": True,
                    "finished": False,
                },
            )
            self.assertTrue(cancellation.cancel())
        finally:
            result = self._finish_blocked(release, worker, outcome)

        self.assertIsInstance(result, CancelledError)
        self.assertTrue(cancellation.is_finished)
        self._assert_zero_capture_secret_network(first)
        self._assert_zero_capture_secret_network(second)

    def test_bind_normal_noop_is_rejected_before_capture(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()

        with mock.patch.object(
            MultimodalCancellation,
            "_bind",
            new=lambda *args, **kwargs: None,
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture, cancellation=cancellation)

        self._assert_zero_capture_secret_network(fixture)
        self.assertFalse(cancellation.is_finished)
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )

    def test_bind_commit_then_raise_is_observed_and_pipeline_continues(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        original = MultimodalCancellation._bind

        def bind_then_interrupt(handle, *args, **kwargs):
            original(handle, *args, **kwargs)
            raise KeyboardInterrupt

        with mock.patch.object(
            MultimodalCancellation,
            "_bind",
            new=bind_then_interrupt,
        ):
            result = execute_fixture(fixture, cancellation=cancellation)

        self.assertEqual(result.answer, "2")
        self.assertTrue(cancellation.is_finished)

    def test_cancel_precommit_failure_can_be_redriven(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        original = CallContextLedger.cancel
        attempts = 0

        def fail_once(owner, *args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise KeyboardInterrupt
            return original(owner, *args, **kwargs)

        with mock.patch.object(CallContextLedger, "cancel", new=fail_once):
            release, worker, outcome = self._run_blocked(
                fixture,
                cancellation,
            )
            try:
                self.assertFalse(cancellation.cancel())
                self.assertTrue(cancellation.cancel())
            finally:
                result = self._finish_blocked(release, worker, outcome)

        self.assertIsInstance(result, CancelledError)
        self.assertEqual(attempts, 2)
        self._assert_zero_capture_secret_network(fixture)

    def test_single_cancel_survives_persistent_context_cancel_failure(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        attempts = 0

        def always_fail(owner, *args, **kwargs):
            nonlocal attempts
            del owner, args, kwargs
            attempts += 1
            raise KeyboardInterrupt

        with mock.patch.object(
            CallContextLedger,
            "cancel",
            new=always_fail,
        ):
            release, worker, outcome = self._run_blocked(
                fixture,
                cancellation,
            )
            try:
                self.assertFalse(cancellation.cancel())
            finally:
                result = self._finish_blocked(release, worker, outcome)

        self.assertIsInstance(result, CancelledError)
        self.assertGreaterEqual(attempts, 2)
        self._assert_zero_capture_secret_network(fixture)

    def test_cancel_commit_then_raise_is_observed_exactly_once(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        original = CallContextLedger.cancel
        attempts = 0

        def commit_then_interrupt(owner, *args, **kwargs):
            nonlocal attempts
            attempts += 1
            original(owner, *args, **kwargs)
            raise KeyboardInterrupt from None

        with mock.patch.object(
            CallContextLedger,
            "cancel",
            new=commit_then_interrupt,
        ):
            release, worker, outcome = self._run_blocked(
                fixture,
                cancellation,
            )
            try:
                self.assertTrue(cancellation.cancel())
                self.assertFalse(cancellation.cancel())
            finally:
                result = self._finish_blocked(release, worker, outcome)

        self.assertIsInstance(result, CancelledError)
        self.assertEqual(attempts, 1)
        self._assert_zero_capture_secret_network(fixture)

    def test_cancel_normal_noop_can_be_redriven(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        original = CallContextLedger.cancel
        attempts = 0

        def noop_once(owner, *args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return True
            return original(owner, *args, **kwargs)

        with mock.patch.object(CallContextLedger, "cancel", new=noop_once):
            release, worker, outcome = self._run_blocked(
                fixture,
                cancellation,
            )
            try:
                self.assertFalse(cancellation.cancel())
                self.assertTrue(cancellation.cancel())
            finally:
                result = self._finish_blocked(release, worker, outcome)

        self.assertIsInstance(result, CancelledError)
        self.assertEqual(attempts, 2)
        self._assert_zero_capture_secret_network(fixture)

    def test_pending_cancel_action_noop_is_rejected_by_observer(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        self.assertTrue(cancellation.cancel())

        with mock.patch.object(
            MultimodalCancellation,
            "_apply_pending_cancellation",
            new=lambda *args, **kwargs: True,
        ):
            with self.assertRaises(CancelledError):
                execute_fixture(fixture, cancellation=cancellation)

        self._assert_zero_capture_secret_network(fixture)
        self.assertTrue(cancellation.is_finished)

    def test_release_noop_retains_result_for_cleanup_only_retry(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()

        with mock.patch.object(
            MultimodalCancellation,
            "_release_for_run",
            new=lambda *args, **kwargs: None,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture, cancellation=cancellation)

        self.assertEqual(raised.exception.stage, "multimodal_cleanup")
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            1,
        )
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
        self.assertTrue(cancellation.is_finished)


if __name__ == "__main__":
    unittest.main()
