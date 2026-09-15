"""Integrated fail-closed side-effect matrix for the W10 composition."""
from __future__ import annotations

import unittest
from unittest import mock

from snapquiz.core.permissions import ScreenPermissionState
from snapquiz.domain.errors import (
    CaptureError,
    ConfigError,
    EndpointPolicyError,
    InvalidOutputError,
    OperationError,
    PermissionDeniedError,
    TimeoutError,
)
from snapquiz.domain.solve import SolveResult
from snapquiz.pipelines.multimodal import (
    MultimodalCaptureSource,
    MultimodalPipelineExecutor,
    RemoteTransport,
    _TEST_PIPELINE_AUTHORITY,
)
import snapquiz.pipelines.multimodal as multimodal_module
from snapquiz.transport.session import SendSessionFactory

from tests.w10_helpers import (
    RecordingAdapter,
    VALID_SECRET,
    execute_fixture,
    make_w10_fixture,
)
from tests.w06_helpers import permission_observation, topology


class _TimeoutTransport(RemoteTransport):
    __slots__ = ("calls",)

    def __init__(self) -> None:
        self.calls = 0

    def send_once(self, prepared_attempt):
        del prepared_attempt
        self.calls += 1
        raise TimeoutError(stage="exact_transport")


class W10FailureMatrixTest(unittest.TestCase):
    def _replace_executor(self, fixture, *, adapter=None, transport=None) -> None:
        if adapter is not None:
            fixture.adapter = adapter
        if transport is not None:
            fixture.transport = transport
        fixture.executor = MultimodalPipelineExecutor._for_testing(
            adapter=fixture.adapter,
            capture_source=fixture.capture_source,
            preview_controller=fixture.preview_controller,
            launcher=fixture.launcher,
            credential_resolver=fixture.credential_resolver,
            transport=fixture.transport,
            _authority=_TEST_PIPELINE_AUTHORITY,
        )

    def _budgets(self, fixture) -> tuple[int, ...]:
        context = fixture.context_ledger.snapshot(
            fixture.planned.plan.request_id
        )
        return tuple(
            fixture.context_ledger.snapshot_budget(item).consumed
            for item in (
                *context.operation_budgets,
                context.global_network_budget,
                context.billable_budget,
            )
        )

    def _assert_terminal(self, fixture) -> None:
        context = fixture.context_ledger.snapshot(
            fixture.planned.plan.request_id
        )
        with self.assertRaises(OperationError):
            fixture.context_ledger.sample_active(context)
        metadata = fixture.context_ledger.safe_metadata()
        self.assertEqual(metadata["pending_start_count"], 0)
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()[
                "pending_cleanup_count"
            ],
            0,
        )

    def _assert_safe(self, error: OperationError) -> None:
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        rendered = str(error)
        self.assertNotIn(VALID_SECRET.decode("ascii"), rendered)
        self.assertNotIn("8.8.8.8", rendered)
        self.assertNotIn("request-w10-offline", rendered)

    def _assert_no_downstream(self, fixture) -> None:
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.spawner.requests, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))

    def test_first_permission_denied_or_unknown_has_zero_capture_and_io(self):
        for state in (
            ScreenPermissionState.DENIED,
            ScreenPermissionState.UNKNOWN,
        ):
            with self.subTest(state=state.value):
                fixture = make_w10_fixture()
                fixture.capture_source.authorization_state = state

                with self.assertRaises(PermissionDeniedError) as raised:
                    execute_fixture(fixture)

                self._assert_safe(raised.exception)
                self.assertEqual(fixture.capture_source.capture_calls, 0)
                self._assert_no_downstream(fixture)
                self._assert_terminal(fixture)

    def test_capture_exception_is_sanitized_before_preview_secret_or_network(self):
        fixture = make_w10_fixture()

        def fail_capture(owner, *, consumed):
            del consumed
            owner.capture_calls += 1
            raise RuntimeError(VALID_SECRET.decode("ascii"))

        with mock.patch.object(
            type(fixture.capture_source),
            "capture_once",
            new=fail_capture,
        ):
            with self.assertRaises(CaptureError) as raised:
                execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self._assert_no_downstream(fixture)
        self._assert_terminal(fixture)

    def test_invalid_capture_frame_is_rejected_before_propagation(self):
        fixture = make_w10_fixture()

        with mock.patch.object(
            type(fixture.capture_source),
            "capture_once",
            return_value=object(),
        ):
            with self.assertRaises(CaptureError) as raised:
                execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self._assert_no_downstream(fixture)
        self._assert_terminal(fixture)

    def test_post_capture_permission_change_stops_before_adapter_and_preview(self):
        fixture = make_w10_fixture()
        fixture.capture_source.post_capture_state = ScreenPermissionState.DENIED

        with self.assertRaises(PermissionDeniedError) as raised:
            execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.adapter.prepare_calls, 0)
        self._assert_no_downstream(fixture)
        self._assert_terminal(fixture)

    def test_post_capture_topology_change_stops_before_adapter_and_preview(self):
        fixture = make_w10_fixture()

        def changed_topology(owner, *, consumed, frame, now):
            del consumed, frame
            owner.events.append("observe_after_capture")
            return MultimodalCaptureSource.observation(
                permission=permission_observation(
                    ScreenPermissionState.GRANTED,
                    observed_at=now,
                ),
                topology=topology(
                    observed_at=now,
                    primary_pixel_width=2_559,
                ),
            )

        with mock.patch.object(
            type(fixture.capture_source),
            "observe_after_capture",
            new=changed_topology,
        ):
            with self.assertRaises(CaptureError) as raised:
                execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.adapter.prepare_calls, 0)
        self._assert_no_downstream(fixture)
        self._assert_terminal(fixture)

    def test_adapter_exception_and_invalid_envelope_stop_before_preview(self):
        def fail_prepare(owner, **kwargs):
            del kwargs
            owner.prepare_calls += 1
            raise RuntimeError(VALID_SECRET.decode("ascii"))

        cases = ((fail_prepare, ConfigError), (lambda *args, **kwargs: object(), ConfigError))
        for replacement, expected_error in cases:
            with self.subTest(replacement=replacement.__name__):
                fixture = make_w10_fixture()
                with mock.patch.object(
                    RecordingAdapter,
                    "prepare",
                    new=replacement,
                ):
                    with self.assertRaises(expected_error) as raised:
                        execute_fixture(fixture)

                self._assert_safe(raised.exception)
                self.assertEqual(fixture.capture_source.capture_calls, 1)
                self._assert_no_downstream(fixture)
                self._assert_terminal(fixture)

    def test_preview_controller_failure_stops_before_secret_and_network(self):
        fixture = make_w10_fixture()

        def fail_review(owner, preview):
            del owner, preview
            raise RuntimeError(VALID_SECRET.decode("ascii"))

        with mock.patch.object(
            type(fixture.preview_controller),
            "review",
            new=fail_review,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.spawner.requests, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))
        self._assert_terminal(fixture)

    def test_session_failure_stops_before_secret_and_network(self):
        fixture = make_w10_fixture()

        with mock.patch.object(
            SendSessionFactory,
            "create",
            side_effect=RuntimeError(VALID_SECRET.decode("ascii")),
        ):
            with self.assertRaises(ConfigError) as raised:
                execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.preview_controller.reviews, 1)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.spawner.requests, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))
        self._assert_terminal(fixture)

    def test_credential_read_failure_has_no_attempt_or_transport(self):
        fixture = make_w10_fixture()
        fixture.credential_source.value = RuntimeError(
            VALID_SECRET.decode("ascii")
        )

        with self.assertRaises(OperationError) as raised:
            execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.credential_source.calls, ["env:GLM_API_KEY"])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))
        self._assert_terminal(fixture)

    def test_resolver_result_failure_never_reaches_transport(self):
        fixture = make_w10_fixture()
        fixture.kernel.result_address = "127.0.0.1"

        with self.assertRaises(EndpointPolicyError) as raised:
            execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.credential_source.calls, ["env:GLM_API_KEY"])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (1, 1, 1))
        self._assert_terminal(fixture)

    def test_transport_timeout_is_not_retried(self):
        fixture = make_w10_fixture()
        transport = _TimeoutTransport()
        self._replace_executor(fixture, transport=transport)

        with self.assertRaises(TimeoutError) as raised:
            execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(transport.calls, 1)
        self.assertEqual(self._budgets(fixture), (1, 1, 1))
        self._assert_terminal(fixture)

    def test_result_validator_failure_is_not_retried_or_published(self):
        fixture = make_w10_fixture()

        with mock.patch.object(
            multimodal_module,
            "validate_answer_candidate",
            side_effect=InvalidOutputError(stage="result_validator"),
        ):
            with self.assertRaises(InvalidOutputError) as raised:
                execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(fixture.transport.calls, 1)
        self.assertEqual(fixture.adapter.decode_calls, 1)
        self.assertEqual(self._budgets(fixture), (1, 1, 1))
        self._assert_terminal(fixture)

    def test_result_validator_return_alias_is_not_published(self):
        fixture = make_w10_fixture()
        original = multimodal_module.validate_answer_candidate

        def return_alternate_answer(*args, **kwargs):
            trusted = original(*args, **kwargs)
            return SolveResult(
                schema_version=trusted.schema_version,
                status=trusted.status,
                question_summary=trusted.question_summary,
                answer="3",
                rationale=trusted.rationale,
                confidence=trusted.confidence,
                confidence_kind=trusted.confidence_kind,
                confidence_calibration_ref=(
                    trusted.confidence_calibration_ref
                ),
                warnings=trusted.warnings,
                provenance=trusted.provenance,
            )

        with mock.patch.object(
            multimodal_module,
            "validate_answer_candidate",
            new=return_alternate_answer,
        ):
            with self.assertRaises(InvalidOutputError) as raised:
                execute_fixture(fixture)

        self._assert_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "result_validation")
        self.assertEqual(fixture.transport.calls, 1)
        self.assertEqual(fixture.adapter.decode_calls, 1)
        self.assertEqual(self._budgets(fixture), (1, 1, 1))
        self._assert_terminal(fixture)


if __name__ == "__main__":
    unittest.main()
