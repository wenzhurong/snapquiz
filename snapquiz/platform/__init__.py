r"""平台层：核心与操作系统之间唯一的缝。

核心代码**只** import ``snapquiz.platform``，不直接 import 任何平台框架。
验收判据就是这条 grep 干净：

    grep -rn "Quartz\|Carbon\|pynput" snapquiz/ --include="*.py" \
      | grep -v "^snapquiz/platform/"
"""
from __future__ import annotations

import sys
from functools import lru_cache

from snapquiz.platform.base import (
    HotkeyConflict,
    HotkeyHandle,
    HotkeyUnavailable,
    PermissionDenied,
    PermissionObservation,
    PermissionReason,
    Platform,
    ScreenPermissionState,
    require_granted,
)


class UnsupportedPlatform(Exception):
    """这个操作系统还没有实现。"""


@lru_cache(maxsize=1)
def current() -> Platform:
    """返回本机的平台实现。"""

    if sys.platform == "darwin":
        from snapquiz.platform.darwin import DarwinPlatform

        return DarwinPlatform()
    if sys.platform.startswith("win"):
        # B5 才实现。现在明确报错，而不是静默退化。
        raise UnsupportedPlatform(
            "Windows 实现在 B5;见 docs/SPEC_B0_PLATFORM.md"
        )
    raise UnsupportedPlatform(f"未支持的平台:{sys.platform}")


def hotkey_selftest(spec: str | None = None, seconds: float | None = None) -> bool:
    """B0-2：在**真正的 Qt 事件循环**里验证零权限热键。

    需要人亲手按两次（Carbon 一次、pynput 对照组一次）—— macOS 的热键分发层
    忽略 ``CGEventPost`` 合成的按键（实测连系统自己的 Cmd+Shift+3 都不触发），
    所以这件事在原理上无法自动化验证。

    定夺之后**这个函数连同落败的那个后端一起删掉**，不留死代码。
    """

    if sys.platform != "darwin":
        raise UnsupportedPlatform("零权限热键自检目前只有 macOS 实现")
    from snapquiz.platform import _qt_selftest

    kwargs = {}
    if spec is not None:
        kwargs["spec"] = spec
    if seconds is not None:
        kwargs["seconds"] = seconds
    return _qt_selftest.run(**kwargs)


__all__ = [
    "HotkeyConflict",
    "HotkeyHandle",
    "HotkeyUnavailable",
    "PermissionDenied",
    "PermissionObservation",
    "PermissionReason",
    "Platform",
    "ScreenPermissionState",
    "UnsupportedPlatform",
    "current",
    "hotkey_selftest",
    "require_granted",
]
