"""W10 exact-owner tests for InputValidator result publication."""
from __future__ import annotations

import unittest
from unittest import mock
from uuid import UUID

from snapquiz.capture.policy import (
    CaptureAuthorizationLedger,
    CapturePolicy,
)
from snapquiz.capture.validation import (
    InputValidator,
    ValidatedCapture,
    _VALIDATED_CAPTURE_AUTHORITY,
)
from snapquiz.domain.capture import CaptureArtifact
from snapquiz.domain.errors import CaptureError, ConfigError, EndpointPolicyError
from snapquiz.pipelines.contracts import (
    SolveRequestFactory,
    StageInvocationFactory,
)
import snapquiz.pipelines.multimodal as multimodal_module

from tests.test_capture_validation import _png
from tests.w10_helpers import execute_fixture, make_w10_fixture


class _SetThenRaiseMap(dict):
    """Publish one exact entry, then lose the normal return edge."""

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        raise RuntimeError("synthetic validation publication return loss")


class _NoOpSetMap(dict):
    """Return from assignment without publishing the requested entry."""

    def __setitem__(self, key, value):
        del key, value


def _alternate_validated_capture(
    target: ValidatedCapture,
    validation_kwargs,
) -> ValidatedCapture:
    artifact = target.artifact
    alternate_bytes = _png(
        pixels=(b"\xff\xff\xff" * 4) + (b"\x00\x00\x00" * 4)
    )
    alternate_artifact = CaptureArtifact(
        id=artifact.id,
        data=alternate_bytes,
        mime_type=artifact.mime_type,
        width_px=artifact.width_px,
        height_px=artifact.height_px,
        scope=artifact.scope,
        captured_at=artifact.captured_at,
    )
    alternate = ValidatedCapture(
        artifact=alternate_artifact,
        planned=validation_kwargs["planned"],
        authorization=validation_kwargs["consumed"].authorization,
        consumed=validation_kwargs["consumed"],
        post_permission_observation=validation_kwargs[
            "permission_observation"
        ],
        topology=validation_kwargs["topology"],
        validated_at=validation_kwargs["now"],
        _authority=_VALIDATED_CAPTURE_AUTHORITY,
    )
    alternate.validate_integrity()
    return alternate


class W10CapturePublicationTest(unittest.TestCase):
    def _assert_no_propagation(self, fixture) -> None:
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)

    def _assert_no_pending_cleanup(self, fixture) -> None:
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()[
                "pending_cleanup_count"
            ],
            0,
        )

    def test_foreign_authorization_return_stops_before_source_followup(self):
        fixture = make_w10_fixture()
        original = CapturePolicy.authorize
        issued_targets = []
        issued_foreign = []

        def return_foreign(owner, **kwargs):
            issued_targets.append(original(owner, **kwargs))
            foreign_kwargs = dict(kwargs)
            foreign_kwargs["capture_ledger"] = CaptureAuthorizationLedger()
            foreign_kwargs["capture_id"] = UUID(
                "83000000-0000-0000-0000-000000000001"
            )
            issued_foreign.append(original(owner, **foreign_kwargs))
            return issued_foreign[0]

        with mock.patch.object(
            CapturePolicy,
            "authorize",
            new=return_foreign,
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        self.assertEqual(len(issued_targets), 1)
        self.assertEqual(len(issued_foreign), 1)
        self.assertEqual(fixture.events, ["observe_authorization"])
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self._assert_no_propagation(fixture)
        self._assert_no_pending_cleanup(fixture)

    def test_foreign_consumption_return_stops_before_capture_start(self):
        fixture = make_w10_fixture()
        original_authorize = CapturePolicy.authorize
        original_prepare = CapturePolicy.prepare_capture
        consumed_targets = []
        consumed_foreign = []

        def return_foreign(owner, **kwargs):
            consumed_targets.append(original_prepare(owner, **kwargs))
            foreign_ledger = CaptureAuthorizationLedger()
            foreign_authorization = original_authorize(
                owner,
                planned=kwargs["planned"],
                privacy_authorization=kwargs["privacy_authorization"],
                consent_ledger=kwargs["consent_ledger"],
                permission_observation=kwargs["permission_observation"],
                topology=kwargs["topology"],
                selected_scope=kwargs["authorization"].scope,
                capture_id=UUID(
                    "83000000-0000-0000-0000-000000000002"
                ),
                capture_ledger=foreign_ledger,
                now=kwargs["now"],
            )
            foreign_kwargs = dict(kwargs)
            foreign_kwargs["authorization"] = foreign_authorization
            foreign_kwargs["capture_ledger"] = foreign_ledger
            consumed_foreign.append(original_prepare(owner, **foreign_kwargs))
            return consumed_foreign[0]

        with mock.patch.object(
            CapturePolicy,
            "prepare_capture",
            new=return_foreign,
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        self.assertEqual(len(consumed_targets), 1)
        self.assertEqual(len(consumed_foreign), 1)
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self._assert_no_propagation(fixture)
        self._assert_no_pending_cleanup(fixture)

    def test_capture_holding_commit_then_raise_is_observed_as_committed(self):
        fixture = make_w10_fixture()
        state_type = multimodal_module._RunState
        original = state_type.publish_capture_validation_holding

        def commit_then_raise(owner, *args, **kwargs):
            original(owner, *args, **kwargs)
            raise KeyboardInterrupt

        with mock.patch.object(
            state_type,
            "publish_capture_validation_holding",
            new=commit_then_raise,
        ):
            result = execute_fixture(fixture)

        self.assertEqual(result.answer, "2")
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.transport.calls, 1)
        self._assert_no_pending_cleanup(fixture)

    def test_capture_holding_normal_noop_stops_without_pending_cleanup(self):
        fixture = make_w10_fixture()

        with mock.patch.object(
            multimodal_module._RunState,
            "publish_capture_validation_holding",
            return_value=None,
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self._assert_no_propagation(fixture)
        self._assert_no_pending_cleanup(fixture)

    def test_foreign_validated_return_is_rejected_and_target_is_released(self):
        fixture = make_w10_fixture()
        original = InputValidator.validate
        targets: list[ValidatedCapture] = []
        foreign: list[ValidatedCapture] = []

        def return_foreign(**kwargs):
            target = original(**kwargs)
            targets.append(target)
            foreign.append(_alternate_validated_capture(target, kwargs))
            return foreign[0]

        try:
            with mock.patch.object(
                InputValidator,
                "validate",
                new=staticmethod(return_foreign),
            ):
                with self.assertRaises(ConfigError):
                    execute_fixture(fixture)

            self.assertEqual(len(targets), 1)
            self.assertEqual(len(foreign), 1)
            self.assertNotEqual(
                targets[0].artifact_sha256,
                foreign[0].artifact_sha256,
            )
            self.assertTrue(targets[0].is_released)
            self.assertFalse(foreign[0].is_released)
            self._assert_no_propagation(fixture)
            self._assert_no_pending_cleanup(fixture)
        finally:
            for candidate in foreign:
                candidate.release()

    def test_foreign_solve_request_input_is_rejected_before_adapter(self):
        fixture = make_w10_fixture()
        original_validate = InputValidator.validate
        original_create = SolveRequestFactory.create
        foreign: list[ValidatedCapture] = []

        def validate_and_prepare_foreign(**kwargs):
            target = original_validate(**kwargs)
            foreign.append(_alternate_validated_capture(target, kwargs))
            return target

        def return_foreign_request(**kwargs):
            foreign_kwargs = dict(kwargs)
            foreign_kwargs["validated_capture"] = foreign[0]
            return original_create(**foreign_kwargs)

        try:
            with (
                mock.patch.object(
                    InputValidator,
                    "validate",
                    new=staticmethod(validate_and_prepare_foreign),
                ),
                mock.patch.object(
                    SolveRequestFactory,
                    "create",
                    new=staticmethod(return_foreign_request),
                ),
            ):
                with self.assertRaises(ConfigError):
                    execute_fixture(fixture)

            self.assertEqual(len(foreign), 1)
            self.assertFalse(foreign[0].is_released)
            self.assertEqual(fixture.adapter.prepare_calls, 0)
            self._assert_no_propagation(fixture)
            self._assert_no_pending_cleanup(fixture)
        finally:
            for candidate in foreign:
                candidate.release()

    def test_foreign_stage_invocation_input_is_rejected_before_adapter(self):
        fixture = make_w10_fixture()
        original_validate = InputValidator.validate
        original_request = SolveRequestFactory.create
        original_invocation = StageInvocationFactory.create
        foreign: list[ValidatedCapture] = []

        def validate_and_prepare_foreign(**kwargs):
            target = original_validate(**kwargs)
            foreign.append(_alternate_validated_capture(target, kwargs))
            return target

        def return_foreign_invocation(**kwargs):
            foreign_request = original_request(
                planned=kwargs["planned"],
                intent=fixture.intent,
                validated_capture=foreign[0],
            )
            foreign_kwargs = dict(kwargs)
            foreign_kwargs["solve_request"] = foreign_request
            return original_invocation(**foreign_kwargs)

        try:
            with (
                mock.patch.object(
                    InputValidator,
                    "validate",
                    new=staticmethod(validate_and_prepare_foreign),
                ),
                mock.patch.object(
                    StageInvocationFactory,
                    "create",
                    new=staticmethod(return_foreign_invocation),
                ),
            ):
                with self.assertRaises(ConfigError):
                    execute_fixture(fixture)

            self.assertEqual(len(foreign), 1)
            self.assertFalse(foreign[0].is_released)
            self.assertEqual(fixture.adapter.prepare_calls, 0)
            self._assert_no_propagation(fixture)
            self._assert_no_pending_cleanup(fixture)
        finally:
            for candidate in foreign:
                candidate.release()

    def test_validator_return_loss_recovers_and_releases_published_target(self):
        fixture = make_w10_fixture()
        original = InputValidator.validate
        targets: list[ValidatedCapture] = []

        def commit_then_raise(**kwargs):
            targets.append(original(**kwargs))
            raise RuntimeError("synthetic validator return loss")

        with mock.patch.object(
            InputValidator,
            "validate",
            new=staticmethod(commit_then_raise),
        ):
            with self.assertRaises(ConfigError):
                execute_fixture(fixture)

        self.assertEqual(len(targets), 1)
        self.assertTrue(targets[0].is_released)
        self._assert_no_propagation(fixture)
        self._assert_no_pending_cleanup(fixture)

    def test_validation_ledger_commit_then_raise_is_observed_as_success(self):
        fixture = make_w10_fixture()
        original = CaptureAuthorizationLedger._complete_validation

        def commit_then_raise(owner, **kwargs):
            object.__setattr__(
                owner,
                "_validated",
                _SetThenRaiseMap(owner._validated),
            )
            original(owner, **kwargs)

        with mock.patch.object(
            CaptureAuthorizationLedger,
            "_complete_validation",
            new=commit_then_raise,
        ):
            result = execute_fixture(fixture)

        self.assertEqual(result.answer, "2")
        self.assertEqual(fixture.transport.calls, 1)
        self._assert_no_pending_cleanup(fixture)

    def test_validation_ledger_normal_noop_releases_lease_and_stops(self):
        fixture = make_w10_fixture()
        releases: list[ValidatedCapture] = []
        original_release = ValidatedCapture.release
        original_complete = CaptureAuthorizationLedger._complete_validation

        def record_release(owner):
            releases.append(owner)
            return original_release(owner)

        def normal_noop(owner, **kwargs):
            object.__setattr__(
                owner,
                "_validated",
                _NoOpSetMap(owner._validated),
            )
            return original_complete(owner, **kwargs)

        with (
            mock.patch.object(
                CaptureAuthorizationLedger,
                "_complete_validation",
                new=normal_noop,
            ),
            mock.patch.object(
                ValidatedCapture,
                "release",
                new=record_release,
            ),
        ):
            with self.assertRaises(CaptureError):
                execute_fixture(fixture)

        self.assertEqual(len(releases), 1)
        self.assertTrue(releases[0].is_released)
        self._assert_no_propagation(fixture)
        self._assert_no_pending_cleanup(fixture)

    def test_truthy_validation_observer_does_not_authorize_propagation(self):
        fixture = make_w10_fixture()
        original = CaptureAuthorizationLedger._validated_capture_is_exact
        observations = 0

        def truthy_once(owner, **kwargs):
            nonlocal observations
            observations += 1
            if observations == 1:
                return object()
            return original(owner, **kwargs)

        with mock.patch.object(
            CaptureAuthorizationLedger,
            "_validated_capture_is_exact",
            new=truthy_once,
        ):
            with self.assertRaises(CaptureError):
                execute_fixture(fixture)

        self.assertGreaterEqual(observations, 2)
        self._assert_no_propagation(fixture)
        self._assert_no_pending_cleanup(fixture)

    def test_foreign_cleanup_return_is_not_released_or_adopted(self):
        fixture = make_w10_fixture()
        original_validate = InputValidator.validate
        targets: list[ValidatedCapture] = []
        foreign: list[ValidatedCapture] = []

        def publish_then_raise(**kwargs):
            target = original_validate(**kwargs)
            targets.append(target)
            foreign.append(_alternate_validated_capture(target, kwargs))
            raise RuntimeError("synthetic validator return loss")

        try:
            with (
                mock.patch.object(
                    InputValidator,
                    "validate",
                    new=staticmethod(publish_then_raise),
                ),
                mock.patch.object(
                    CaptureAuthorizationLedger,
                    "_validated_capture_for_cleanup",
                    side_effect=lambda **kwargs: foreign[0],
                ),
            ):
                with self.assertRaises(EndpointPolicyError) as raised:
                    execute_fixture(fixture)

            self.assertEqual(raised.exception.stage, "multimodal_cleanup")
            self.assertEqual(len(targets), 1)
            self.assertFalse(targets[0].is_released)
            self.assertFalse(foreign[0].is_released)
            self._assert_no_propagation(fixture)
            self.assertEqual(
                fixture.executor.pending_cleanup_metadata()[
                    "pending_cleanup_count"
                ],
                1,
            )

            with self.assertRaises(ConfigError):
                fixture.executor.retry_cleanup_and_finalize(
                    fixture.planned.plan.request_id
                )

            self.assertTrue(targets[0].is_released)
            self.assertFalse(foreign[0].is_released)
            self._assert_no_pending_cleanup(fixture)
        finally:
            for candidate in foreign:
                candidate.release()


if __name__ == "__main__":
    unittest.main()
