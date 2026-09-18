"""macOS 平台实现。

只做两件 Qt 做不了的事：屏幕录制权限（TCC）与全局热键。

⚠️ **权限归属**：从终端跑时 macOS 把截屏行为归属给**调用它的终端**，
所以权限要勾给终端。打包成 .app 之后才记在 SnapQuiz 自己名下。
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Callable

from snapquiz.platform.base import (
    HotkeyHandle,
    HotkeyUnavailable,
    PermissionObservation,
    PermissionReason,
    ScreenPermissionState,
)

logger = logging.getLogger(__name__)

#: 热键后端。B0-2 用 `--carbon-selftest` 在 Qt 事件循环里验证 Carbon 之后，
#: 二选一删掉另一个（见 SPEC_B0_PLATFORM §3），**不并存**。
#: 在那之前默认用已验证可用的 pynput。
HOTKEY_BACKEND_ENV = "SNAPQUIZ_HOTKEY_BACKEND"
DEFAULT_HOTKEY_BACKEND = "pynput"


class DarwinPlatform:
    name = "darwin"

    # -- 屏幕录制权限 ------------------------------------------------------

    def screen_permission(self) -> PermissionObservation:
        """探测一次。任何不确定都归为 UNKNOWN，绝不当成 granted。

        MVP-0 的缺陷正是 fail-open：Quartz 导入或调用异常时返回「有权限」。
        """

        if sys.platform != "darwin":
            return PermissionObservation(
                ScreenPermissionState.UNKNOWN,
                PermissionReason.UNSUPPORTED_PLATFORM,
            )
        try:
            from Quartz import CGPreflightScreenCaptureAccess
        except ImportError:
            return PermissionObservation(
                ScreenPermissionState.UNKNOWN, PermissionReason.API_UNAVAILABLE
            )
        except Exception as exc:
            logger.debug("导入 Quartz 失败:%s", exc)
            return PermissionObservation(
                ScreenPermissionState.UNKNOWN, PermissionReason.API_ERROR
            )

        try:
            raw = CGPreflightScreenCaptureAccess()
        except Exception as exc:
            logger.debug("屏幕录制权限预检失败:%s", exc)
            return PermissionObservation(
                ScreenPermissionState.UNKNOWN, PermissionReason.API_ERROR
            )

        # 刻意不用 bool(raw)：整数、mock 和外来标量包装器都不是权限授予。
        if type(raw) is not bool:
            return PermissionObservation(
                ScreenPermissionState.UNKNOWN, PermissionReason.INVALID_RESULT
            )
        if raw:
            return PermissionObservation(
                ScreenPermissionState.GRANTED, PermissionReason.GRANTED
            )
        return PermissionObservation(
            ScreenPermissionState.DENIED, PermissionReason.DENIED
        )

    def request_screen_permission(self) -> bool:
        if sys.platform != "darwin":
            return False
        try:
            from Quartz import CGRequestScreenCaptureAccess

            return bool(CGRequestScreenCaptureAccess())
        except Exception as exc:
            logger.debug("请求屏幕录制权限失败:%s", exc)
            return False

    # -- 全局热键 ----------------------------------------------------------

    def install_hotkey(
        self, spec: str, on_trigger: Callable[[], None]
    ) -> HotkeyHandle:
        backend = (os.environ.get(HOTKEY_BACKEND_ENV) or DEFAULT_HOTKEY_BACKEND).strip()
        if backend == "carbon":
            from snapquiz.platform import _carbon

            return _carbon.install(spec, on_trigger)
        if backend == "pynput":
            from snapquiz.platform import _pynput

            return _pynput.install(spec, on_trigger)
        raise HotkeyUnavailable(
            f"未知热键后端 {backend!r};可选:carbon / pynput"
        )


__all__ = ["DarwinPlatform", "HOTKEY_BACKEND_ENV", "DEFAULT_HOTKEY_BACKEND"]
