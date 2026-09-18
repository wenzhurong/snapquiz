"""平台接口：核心层与操作系统之间唯一的缝。

**只有三个方法。** 上一轮设想里有八项平台能力，选定 PySide6 之后其中六项变成
跨端的（截屏、显示器拓扑、拖框选区、预览、对话框、通知），详见
`docs/SPEC_B0_PLATFORM.md` §2。剩下的只有 Qt 给不了的两样：

1. **屏幕录制权限** —— macOS 的 TCC 概念，Windows 上根本没有这回事；
2. **全局热键** —— PySide6 没有。``QShortcut`` 只在应用有焦点时才生效。

设计约束：

- 实现**不得自己起事件循环**。宿主（B0-5 之后是 Qt）拥有主循环，平台实现只往
  里挂钩子。所以 ``install_hotkey`` 立即返回一个句柄，而不是阻塞。
- 本模块保持纯标准库，导入它不产生任何 I/O，也不 import 任何平台框架。
"""
from __future__ import annotations

from enum import Enum
from typing import Callable, NamedTuple, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# 屏幕录制权限
# ---------------------------------------------------------------------------


class ScreenPermissionState(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"
    UNKNOWN = "unknown"


class PermissionReason(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"
    #: 这个平台没有屏幕录制权限这个概念（Windows）。
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    API_UNAVAILABLE = "api_unavailable"
    API_ERROR = "api_error"
    INVALID_RESULT = "invalid_result"


class PermissionObservation(NamedTuple):
    state: ScreenPermissionState
    reason: PermissionReason

    @property
    def granted(self) -> bool:
        return self.state is ScreenPermissionState.GRANTED


class PermissionDenied(Exception):
    """权限不是 granted。调用方必须停止，不得截屏。"""


# ---------------------------------------------------------------------------
# 全局热键
# ---------------------------------------------------------------------------


class HotkeyUnavailable(Exception):
    """这个平台 / 这个进程形态下装不了全局热键。"""


class HotkeyConflict(HotkeyUnavailable):
    """组合已被其他程序占用。

    D8：必须给出**可读**提示，不能静默失败 —— 用户在设置页里选了一个被占用的
    组合时，要看得懂发生了什么，而不是"热键没反应"。
    """

    def __init__(self, spec: str, detail: str = "") -> None:
        self.spec = spec
        self.detail = detail
        message = f"热键 {spec} 已被其他程序占用，请换一个组合。"
        if detail:
            message += f"（{detail}）"
        super().__init__(message)


@runtime_checkable
class HotkeyHandle(Protocol):
    """已装上的热键。调用 ``unregister`` 解除。"""

    def unregister(self) -> None: ...


# ---------------------------------------------------------------------------
# 平台
# ---------------------------------------------------------------------------


@runtime_checkable
class Platform(Protocol):
    name: str  # "darwin" | "windows"

    def screen_permission(self) -> PermissionObservation: ...

    def request_screen_permission(self) -> bool:
        """触发系统授权请求。返回是否已授权。"""
        ...

    def install_hotkey(
        self, spec: str, on_trigger: Callable[[], None]
    ) -> HotkeyHandle:
        """装一个全局热键并**立即返回**。

        不阻塞、不起事件循环 —— 事件由宿主的循环分发。
        组合被占用时抛 :class:`HotkeyConflict`。
        """
        ...


def require_granted(platform: Platform) -> None:
    """截屏前的唯一闸门。非 granted 直接抛错。

    这是 fail-closed 的落点：原 MVP-0 的缺陷正是"拿不到权限就当成有权限"。
    """

    observation = platform.screen_permission()
    if not observation.granted:
        raise PermissionDenied(observation.reason.value)


__all__ = [
    "HotkeyConflict",
    "HotkeyHandle",
    "HotkeyUnavailable",
    "PermissionDenied",
    "PermissionObservation",
    "PermissionReason",
    "Platform",
    "ScreenPermissionState",
    "require_granted",
]
