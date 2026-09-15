import sys
import types
import unittest
from unittest.mock import patch

from snapquiz.core.permissions import (
    PermissionDenied,
    PermissionReason,
    ScreenPermissionState,
    observe_screen_permission,
    require_screen_permission,
)


def _fake_quartz(preflight):
    module = types.ModuleType("Quartz")
    module.CGPreflightScreenCaptureAccess = preflight
    return module


class ScreenPermissionTest(unittest.TestCase):
    """MVP-0 的缺陷是 fail-open:异常时返回「有权限」。这里逐个钉死。"""

    def _observe_with(self, preflight, platform="darwin"):
        with patch.object(sys, "platform", platform), patch.dict(
            sys.modules, {"Quartz": _fake_quartz(preflight)}
        ):
            return observe_screen_permission()

    def test_true_is_granted(self):
        obs = self._observe_with(lambda: True)
        self.assertEqual(obs.state, ScreenPermissionState.GRANTED)
        self.assertTrue(obs.granted)

    def test_false_is_denied(self):
        obs = self._observe_with(lambda: False)
        self.assertEqual(obs.state, ScreenPermissionState.DENIED)
        self.assertFalse(obs.granted)

    def test_api_exception_is_unknown_not_granted(self):
        def boom():
            raise RuntimeError("Quartz exploded")

        obs = self._observe_with(boom)
        self.assertEqual(obs.state, ScreenPermissionState.UNKNOWN)
        self.assertEqual(obs.reason, PermissionReason.API_ERROR)
        self.assertFalse(obs.granted)

    def test_non_bool_result_is_unknown(self):
        """整数、mock、外来标量包装器都不是权限授予。"""

        for value in (1, "yes", object(), None, [True]):
            with self.subTest(value=type(value).__name__):
                obs = self._observe_with(lambda v=value: v)
                self.assertEqual(obs.state, ScreenPermissionState.UNKNOWN)
                self.assertEqual(obs.reason, PermissionReason.INVALID_RESULT)

    def test_missing_quartz_is_unknown(self):
        with patch.object(sys, "platform", "darwin"), patch.dict(
            sys.modules, {"Quartz": None}
        ):
            obs = observe_screen_permission()
        self.assertEqual(obs.state, ScreenPermissionState.UNKNOWN)
        self.assertFalse(obs.granted)

    def test_non_darwin_is_unknown(self):
        obs = self._observe_with(lambda: True, platform="linux")
        self.assertEqual(obs.state, ScreenPermissionState.UNKNOWN)
        self.assertEqual(obs.reason, PermissionReason.UNSUPPORTED_PLATFORM)

    def test_require_blocks_on_anything_but_granted(self):
        for preflight in (lambda: False, lambda: 1, lambda: None):
            with self.subTest(preflight=preflight):
                with patch.object(sys, "platform", "darwin"), patch.dict(
                    sys.modules, {"Quartz": _fake_quartz(preflight)}
                ), self.assertRaises(PermissionDenied):
                    require_screen_permission()

    def test_require_passes_only_on_granted(self):
        with patch.object(sys, "platform", "darwin"), patch.dict(
            sys.modules, {"Quartz": _fake_quartz(lambda: True)}
        ):
            require_screen_permission()  # 不抛错即通过


if __name__ == "__main__":
    unittest.main()
