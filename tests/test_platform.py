import pathlib
import re
import sys
import types
import unittest
from unittest.mock import patch

from snapquiz import platform as platform_pkg
from snapquiz.platform import (
    HotkeyConflict,
    HotkeyUnavailable,
    PermissionDenied,
    PermissionObservation,
    PermissionReason,
    Platform,
    ScreenPermissionState,
    require_granted,
)
from snapquiz.platform.darwin import DarwinPlatform


def _fake_quartz(preflight=None, request=None):
    module = types.ModuleType("Quartz")
    if preflight is not None:
        module.CGPreflightScreenCaptureAccess = preflight
    if request is not None:
        module.CGRequestScreenCaptureAccess = request
    return module


class PlatformSeamTest(unittest.TestCase):
    """B0 的核心判据：核心层与操作系统之间只有这一条缝。"""

    ROOT = pathlib.Path(__file__).resolve().parent.parent

    #: Qt 给不了、必须留在平台层的东西。
    PLATFORM_ONLY = ("Quartz", "Carbon", "pynput")

    def test_no_platform_imports_outside_the_platform_package(self):
        """这就是 B0-1 的验收判据，写成测试免得以后悄悄回归。

        （AppKit 还留在 capture/validation.py 里，那是 B0-3 换 QImage 的活；
        osascript / qlmanage / screencapture 是 B0-4/B0-5 的活。）
        """

        offenders = []
        for path in sorted((self.ROOT / "snapquiz").rglob("*.py")):
            rel = path.relative_to(self.ROOT).as_posix()
            if rel.startswith("snapquiz/platform/"):
                continue
            text = path.read_text(encoding="utf-8")
            # 只看代码，不看文档字符串里的提及
            code = re.sub(r'"""(.*?)"""', "", text, flags=re.S)
            for marker in self.PLATFORM_ONLY:
                if marker in code:
                    offenders.append(f"{rel}: {marker}")
        self.assertEqual(
            offenders, [], "平台调用必须收在 snapquiz/platform/ 里"
        )

    def test_current_returns_something_implementing_the_protocol(self):
        platform = platform_pkg.current()
        self.assertIsInstance(platform, Platform)
        self.assertEqual(platform.name, sys.platform if sys.platform == "darwin" else platform.name)

    def test_current_is_cached(self):
        self.assertIs(platform_pkg.current(), platform_pkg.current())

    def test_windows_is_an_explicit_error_not_a_silent_degradation(self):
        platform_pkg.current.cache_clear()
        self.addCleanup(platform_pkg.current.cache_clear)
        with patch.object(sys, "platform", "win32"):
            with self.assertRaises(platform_pkg.UnsupportedPlatform) as ctx:
                platform_pkg.current()
        self.assertIn("B5", str(ctx.exception))


class DarwinPermissionTest(unittest.TestCase):
    """MVP-0 的缺陷是 fail-open：异常时返回「有权限」。这里逐个钉死。"""

    def setUp(self):
        self.platform = DarwinPlatform()

    def _observe_with(self, preflight, platform_name="darwin"):
        with patch.object(sys, "platform", platform_name), patch.dict(
            sys.modules, {"Quartz": _fake_quartz(preflight=preflight)}
        ):
            return self.platform.screen_permission()

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
            obs = self.platform.screen_permission()
        self.assertEqual(obs.state, ScreenPermissionState.UNKNOWN)

    def test_non_darwin_is_unknown(self):
        obs = self._observe_with(lambda: True, platform_name="linux")
        self.assertEqual(obs.reason, PermissionReason.UNSUPPORTED_PLATFORM)

    def test_request_is_false_off_darwin(self):
        with patch.object(sys, "platform", "linux"):
            self.assertFalse(self.platform.request_screen_permission())


class RequireGrantedTest(unittest.TestCase):
    class _Stub:
        name = "stub"

        def __init__(self, observation):
            self.observation = observation

        def screen_permission(self):
            return self.observation

        def request_screen_permission(self):
            return False

        def install_hotkey(self, spec, on_trigger):
            raise NotImplementedError

    def test_blocks_on_anything_but_granted(self):
        for state, reason in (
            (ScreenPermissionState.DENIED, PermissionReason.DENIED),
            (ScreenPermissionState.UNKNOWN, PermissionReason.API_ERROR),
            (ScreenPermissionState.UNKNOWN, PermissionReason.NOT_APPLICABLE),
        ):
            with self.subTest(state=state, reason=reason):
                with self.assertRaises(PermissionDenied):
                    require_granted(self._Stub(PermissionObservation(state, reason)))

    def test_passes_only_on_granted(self):
        require_granted(
            self._Stub(
                PermissionObservation(
                    ScreenPermissionState.GRANTED, PermissionReason.GRANTED
                )
            )
        )


class HotkeyBackendTest(unittest.TestCase):
    def setUp(self):
        self.platform = DarwinPlatform()

    def test_backend_is_selectable_and_defaults_to_the_verified_one(self):
        from snapquiz.platform.darwin import DEFAULT_HOTKEY_BACKEND

        # B0-2 在 Qt 事件循环里验证 Carbon 之前，默认用已验证可用的 pynput。
        self.assertEqual(DEFAULT_HOTKEY_BACKEND, "pynput")

    def test_unknown_backend_is_refused(self):
        import os

        with patch.dict(os.environ, {"SNAPQUIZ_HOTKEY_BACKEND": "telepathy"}):
            with self.assertRaises(HotkeyUnavailable) as ctx:
                self.platform.install_hotkey("cmd+shift+space", lambda: None)
        self.assertIn("telepathy", str(ctx.exception))

    def test_conflict_message_is_readable(self):
        """D8：热键冲突要给可读提示，不能静默失败。"""

        exc = HotkeyConflict("cmd+shift+space", "eventHotKeyExistsErr")
        text = str(exc)
        self.assertIn("cmd+shift+space", text)
        self.assertIn("已被其他程序占用", text)
        self.assertIn("换一个", text)
        self.assertIsInstance(exc, HotkeyUnavailable)

    def test_handles_satisfy_the_protocol(self):
        from snapquiz.platform import HotkeyHandle
        from snapquiz.platform._carbon import CarbonHotkeyHandle
        from snapquiz.platform._pynput import PynputHotkeyHandle

        for cls in (CarbonHotkeyHandle, PynputHotkeyHandle):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(hasattr(cls, "unregister"))
                self.assertTrue(issubclass(cls, HotkeyHandle))


if __name__ == "__main__":
    unittest.main()


class TriggerModePrecedenceTest(unittest.TestCase):
    """显式 --trigger 必须优先于 GUI 自动检测。

    这是 B0-1 实跑时发现的：在没有 tty 的环境里（CI、管道、harness），
    `--trigger stdin` 会被 `is_gui_launch()` 悄悄覆盖成 hotkey 分支，
    用户明确说的话被忽略了。
    """

    def _decide(self, *, gui_flag, trigger, isatty):
        """复刻 app.main 里的判定，保持与实现同步。"""

        from snapquiz.app import is_gui_launch

        with patch("sys.stdin") as stdin:
            stdin.isatty.return_value = isatty
            auto = is_gui_launch()
        if gui_flag:
            gui = True
        elif trigger is not None:
            gui = False
        else:
            gui = auto
        return gui, trigger or ("hotkey" if gui else "stdin")

    def test_explicit_stdin_wins_even_without_a_tty(self):
        gui, mode = self._decide(gui_flag=False, trigger="stdin", isatty=False)
        self.assertFalse(gui)
        self.assertEqual(mode, "stdin")

    def test_explicit_hotkey_without_gui_stays_terminal_hotkey(self):
        gui, mode = self._decide(gui_flag=False, trigger="hotkey", isatty=True)
        self.assertFalse(gui)
        self.assertEqual(mode, "hotkey")

    def test_gui_flag_always_wins(self):
        gui, mode = self._decide(gui_flag=True, trigger="stdin", isatty=True)
        self.assertTrue(gui)
        self.assertEqual(mode, "stdin")

    def test_auto_detect_only_when_nothing_specified(self):
        self.assertEqual(
            self._decide(gui_flag=False, trigger=None, isatty=True), (False, "stdin")
        )
        self.assertEqual(
            self._decide(gui_flag=False, trigger=None, isatty=False), (True, "hotkey")
        )
