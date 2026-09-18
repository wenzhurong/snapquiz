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


def hotkey_selftest(spec: str = "cmd+shift+space", seconds: float = 15.0) -> bool:
    """临时诊断：验证**零权限**热键在当前进程形态下是否真的收得到事件。

    需要人亲手按一次 —— macOS 的热键分发层忽略 ``CGEventPost`` 合成的按键
    （实测连系统自己的 Cmd+Shift+3 都不触发），所以这件事无法自动化验证。

    B0-2 用它定夺 Carbon 能否取代 pynput；定完之后**这个函数连同落败的那个
    后端一起删掉**，不留死代码。
    """

    if sys.platform != "darwin":
        raise UnsupportedPlatform("零权限热键自检目前只有 macOS 实现")
    from snapquiz.platform._carbon import selftest

    return selftest(spec=spec, seconds=seconds)


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
