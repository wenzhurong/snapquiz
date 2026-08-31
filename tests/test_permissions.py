import builtins
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

from snapquiz.core.permissions import (
    MacOSScreenPermissionProbe,
    PermissionGate,
    PermissionObservation,
    PermissionObservationReason,
    ScreenPermissionState,
    has_screen_recording,
    request_screen_recording,
)
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import PermissionDeniedError


OBSERVED_AT = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


_DEFAULT_REASON_BY_STATE = {
    ScreenPermissionState.GRANTED: PermissionObservationReason.GRANTED,
    ScreenPermissionState.DENIED: PermissionObservationReason.DENIED,
    ScreenPermissionState.UNKNOWN: PermissionObservationReason.API_ERROR,
}


def _quartz_module(result=None, *, error=None):
    module = types.ModuleType("Quartz")

    def preflight():
        if error is not None:
            raise error
        return result

    module.CGPreflightScreenCaptureAccess = preflight
    return module


def _observe_reason(
    reason: PermissionObservationReason,
    *,
    observed_at: datetime = OBSERVED_AT,
) -> PermissionObservation:
    probe = MacOSScreenPermissionProbe()
    if reason is PermissionObservationReason.UNSUPPORTED_PLATFORM:
        with patch.object(sys, "platform", "linux"):
            return probe.observe(now=observed_at)

    if reason is PermissionObservationReason.API_UNAVAILABLE:
        original_import = builtins.__import__

        def unavailable_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.split(".", 1)[0] == "Quartz":
                raise ImportError("Quartz unavailable")
            return original_import(name, globals, locals, fromlist, level)

        with (
            patch.object(sys, "platform", "darwin"),
            patch("builtins.__import__", unavailable_import),
        ):
            return probe.observe(now=observed_at)

    quartz_result = {
        PermissionObservationReason.GRANTED: True,
        PermissionObservationReason.DENIED: False,
        PermissionObservationReason.INVALID_RESULT: 1,
    }.get(reason)
    quartz_error = (
        RuntimeError("probe failed")
        if reason is PermissionObservationReason.API_ERROR
        else None
    )
    with (
        patch.object(sys, "platform", "darwin"),
        patch.dict(
            sys.modules,
            {"Quartz": _quartz_module(quartz_result, error=quartz_error)},
        ),
    ):
        return probe.observe(now=observed_at)


def _observation(
    state: ScreenPermissionState,
    reason: PermissionObservationReason | None = None,
    *,
    observed_at: datetime = OBSERVED_AT,
) -> PermissionObservation:
    expected_reason = _DEFAULT_REASON_BY_STATE[state] if reason is None else reason
    observation = _observe_reason(expected_reason, observed_at=observed_at)
    if observation.state is not state:
        raise AssertionError("test helper requested an inconsistent state/reason")
    return observation


class PermissionObservationTest(unittest.TestCase):
    def test_all_three_states_are_distinct_and_digest_bound(self):
        observations = tuple(_observation(state) for state in ScreenPermissionState)

        self.assertEqual(
            tuple(observation.state for observation in observations),
            (
                ScreenPermissionState.GRANTED,
                ScreenPermissionState.DENIED,
                ScreenPermissionState.UNKNOWN,
            ),
        )
        self.assertEqual(
            len({observation.observation_digest for observation in observations}),
            3,
        )
        for observation in observations:
            self.assertIsNone(observation.validate_integrity())

    def test_all_reasons_are_distinct_and_digest_bound(self):
        observations = (
            _observation(
                ScreenPermissionState.GRANTED,
                PermissionObservationReason.GRANTED,
            ),
            _observation(
                ScreenPermissionState.DENIED,
                PermissionObservationReason.DENIED,
            ),
            *(
                _observation(ScreenPermissionState.UNKNOWN, reason)
                for reason in (
                    PermissionObservationReason.UNSUPPORTED_PLATFORM,
                    PermissionObservationReason.API_UNAVAILABLE,
                    PermissionObservationReason.API_ERROR,
                    PermissionObservationReason.INVALID_RESULT,
                )
            ),
        )

        self.assertEqual(
            {observation.reason for observation in observations},
            set(PermissionObservationReason),
        )
        self.assertEqual(
            len({observation.observation_digest for observation in observations}),
            len(PermissionObservationReason),
        )
        for observation in observations:
            self.assertIsNone(observation.validate_integrity())

    def test_external_direct_construction_is_type_error(self):
        with self.assertRaises(TypeError):
            PermissionObservation(
                state=ScreenPermissionState.GRANTED,
                reason=PermissionObservationReason.GRANTED,
                observed_at=OBSERVED_AT,
            )

    def test_is_immutable_and_runtime_final(self):
        observation = _observation(ScreenPermissionState.GRANTED)
        with self.assertRaises(AttributeError):
            observation.state = ScreenPermissionState.DENIED
        with self.assertRaises(TypeError):
            type("ForgedObservation", (PermissionObservation,), {})

    def test_tampering_is_detected_by_observation_and_gate(self):
        observation = _observation(ScreenPermissionState.GRANTED)
        object.__setattr__(observation, "state", ScreenPermissionState.DENIED)

        with self.assertRaises(ValueError):
            observation.validate_integrity()
        with self.assertRaises(PermissionDeniedError) as raised:
            PermissionGate.require_granted(observation=observation, now=OBSERVED_AT)
        self.assertEqual(raised.exception.code, "permission_denied")
        self.assertEqual(raised.exception.stage, "permission_gate")

    def test_reason_tampering_is_detected_by_observation_and_gate(self):
        observation = _observation(ScreenPermissionState.GRANTED)
        object.__setattr__(
            observation,
            "reason",
            PermissionObservationReason.API_ERROR,
        )

        with self.assertRaises(ValueError):
            observation.validate_integrity()
        with self.assertRaises(PermissionDeniedError):
            PermissionGate.require_granted(observation=observation, now=OBSERVED_AT)

    def test_source_tampering_is_detected_and_fails_closed(self):
        observation = _observation(ScreenPermissionState.GRANTED)
        object.__setattr__(observation, "source", "forged_permission_source")

        with self.assertRaises(ValueError):
            observation.validate_integrity()
        with self.assertRaises(PermissionDeniedError):
            PermissionGate.require_granted(observation=observation, now=OBSERVED_AT)

    def test_digest_field_tampering_is_detected(self):
        observation = _observation(ScreenPermissionState.GRANTED)
        object.__setattr__(
            observation,
            "observation_digest",
            Digest256("f" * 64),
        )
        with self.assertRaises(ValueError):
            observation.validate_integrity()
        with self.assertRaises(PermissionDeniedError):
            PermissionGate.require_granted(observation=observation, now=OBSERVED_AT)


class MacOSScreenPermissionProbeTest(unittest.TestCase):
    def test_strict_boolean_results_map_to_granted_and_denied(self):
        for raw_state, expected_state, expected_reason in (
            (
                True,
                ScreenPermissionState.GRANTED,
                PermissionObservationReason.GRANTED,
            ),
            (
                False,
                ScreenPermissionState.DENIED,
                PermissionObservationReason.DENIED,
            ),
        ):
            with self.subTest(raw_state=raw_state):
                quartz = _quartz_module(raw_state)
                with (
                    patch.object(sys, "platform", "darwin"),
                    patch.dict(sys.modules, {"Quartz": quartz}),
                ):
                    observation = MacOSScreenPermissionProbe().observe(now=OBSERVED_AT)
                self.assertEqual(observation.state, expected_state)
                self.assertEqual(observation.reason, expected_reason)
                self.assertEqual(observation.observed_at, OBSERVED_AT)
                self.assertIsNone(observation.validate_integrity())

    def test_non_darwin_is_unknown_without_importing_quartz(self):
        original_import = builtins.__import__
        quartz_imports = []

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.split(".", 1)[0] == "Quartz":
                quartz_imports.append(name)
                raise AssertionError("Quartz must not be imported")
            return original_import(name, globals, locals, fromlist, level)

        with (
            patch.object(sys, "platform", "linux"),
            patch("builtins.__import__", guarded_import),
        ):
            observation = MacOSScreenPermissionProbe().observe(now=OBSERVED_AT)

        self.assertEqual(observation.state, ScreenPermissionState.UNKNOWN)
        self.assertEqual(
            observation.reason,
            PermissionObservationReason.UNSUPPORTED_PLATFORM,
        )
        self.assertEqual(quartz_imports, [])

    def test_missing_quartz_is_unknown(self):
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.split(".", 1)[0] == "Quartz":
                raise ImportError("Quartz unavailable")
            return original_import(name, globals, locals, fromlist, level)

        with (
            patch.object(sys, "platform", "darwin"),
            patch("builtins.__import__", guarded_import),
        ):
            observation = MacOSScreenPermissionProbe().observe(now=OBSERVED_AT)
        self.assertEqual(observation.state, ScreenPermissionState.UNKNOWN)
        self.assertEqual(
            observation.reason,
            PermissionObservationReason.API_UNAVAILABLE,
        )

    def test_api_exception_is_unknown(self):
        quartz = _quartz_module(error=RuntimeError("probe failed"))
        with (
            patch.object(sys, "platform", "darwin"),
            patch.dict(sys.modules, {"Quartz": quartz}),
        ):
            observation = MacOSScreenPermissionProbe().observe(now=OBSERVED_AT)
        self.assertEqual(observation.state, ScreenPermissionState.UNKNOWN)
        self.assertEqual(
            observation.reason,
            PermissionObservationReason.API_ERROR,
        )

    def test_non_strict_boolean_results_are_unknown(self):
        for raw_state in (0, 1, None, "granted", object()):
            with self.subTest(raw_state=raw_state):
                quartz = _quartz_module(raw_state)
                with (
                    patch.object(sys, "platform", "darwin"),
                    patch.dict(sys.modules, {"Quartz": quartz}),
                ):
                    observation = MacOSScreenPermissionProbe().observe(now=OBSERVED_AT)
                self.assertEqual(observation.state, ScreenPermissionState.UNKNOWN)
                self.assertEqual(
                    observation.reason,
                    PermissionObservationReason.INVALID_RESULT,
                )

    def test_observe_requires_aware_now(self):
        with self.assertRaises(ValueError):
            MacOSScreenPermissionProbe().observe(
                now=datetime(2026, 8, 29, 12, 0)
            )

    def test_importing_module_does_not_import_quartz(self):
        repository_root = Path(__file__).resolve().parents[1]
        script = """
import builtins
original_import = builtins.__import__
def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.split('.', 1)[0] == 'Quartz':
        raise RuntimeError('forbidden Quartz import')
    return original_import(name, globals, locals, fromlist, level)
builtins.__import__ = guarded_import
import snapquiz.core.permissions
"""
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(repository_root),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repository_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("forbidden Quartz import", completed.stderr)


class PermissionGateTest(unittest.TestCase):
    def test_only_granted_same_snapshot_observation_passes(self):
        self.assertIsNone(
            PermissionGate.require_granted(
                observation=_observation(ScreenPermissionState.GRANTED),
                now=OBSERVED_AT,
            )
        )
        for state in (
            ScreenPermissionState.DENIED,
            ScreenPermissionState.UNKNOWN,
        ):
            with self.subTest(state=state):
                with self.assertRaises(PermissionDeniedError) as raised:
                    PermissionGate.require_granted(
                        observation=_observation(state), now=OBSERVED_AT
                    )
                self.assertEqual(raised.exception.code, "permission_denied")
                self.assertEqual(raised.exception.stage, "permission_gate")
                self.assertFalse(raised.exception.retryable)

    def test_every_unknown_reason_fails_closed(self):
        for reason in (
            PermissionObservationReason.UNSUPPORTED_PLATFORM,
            PermissionObservationReason.API_UNAVAILABLE,
            PermissionObservationReason.API_ERROR,
            PermissionObservationReason.INVALID_RESULT,
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(PermissionDeniedError):
                    PermissionGate.require_granted(
                        observation=_observation(
                            ScreenPermissionState.UNKNOWN,
                            reason,
                        ),
                        now=OBSERVED_AT,
                    )

    def test_snapshot_time_mismatch_is_typed_denial(self):
        with self.assertRaises(PermissionDeniedError):
            PermissionGate.require_granted(
                observation=_observation(ScreenPermissionState.GRANTED),
                now=OBSERVED_AT + timedelta(microseconds=1),
            )

    def test_invalid_now_or_observation_is_typed_denial(self):
        with self.assertRaises(PermissionDeniedError):
            PermissionGate.require_granted(
                observation=object(), now=OBSERVED_AT
            )
        with self.assertRaises(PermissionDeniedError):
            PermissionGate.require_granted(
                observation=_observation(ScreenPermissionState.GRANTED),
                now=datetime(2026, 8, 29, 12, 0),
            )

    def test_legacy_boolean_seams_are_permanently_fail_closed(self):
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.split(".", 1)[0] == "Quartz":
                raise AssertionError("legacy seam must not import Quartz")
            return original_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", guarded_import):
            self.assertIs(has_screen_recording(), False)
            self.assertIs(request_screen_recording(), False)


if __name__ == "__main__":
    unittest.main()
