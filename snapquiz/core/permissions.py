"""macOS 屏幕录制权限：三态、fail-closed。

MVP-0 的缺陷是 fail-open —— Quartz 导入或调用异常时返回「有权限」，与文档承诺相反。
这里保留 v3 的三态判定（granted / denied / unknown），非 granted 一律阻断捕获；
去掉了 v3 的 observation digest、构造授权守卫和 ``observed_at == now`` 精确相等要求。

⚠️ 权限归属：snapquiz 目前不是独立 app bundle，macOS 把截屏行为归属给调用它的
终端。所以「屏幕录制」要勾给终端.app，不是勾给 snapquiz。打包成 .app 之后才会变。
"""
from __future__ import annotations

import logging
import sys
from enum import Enum
from typing import NamedTuple

logger = logging.getLogger(__name__)


class ScreenPermissionState(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"
    UNKNOWN = "unknown"


class PermissionReason(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"
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
    """权限不是 granted；调用方必须停止，不得截屏。"""


def observe_screen_permission() -> PermissionObservation:
    """探测一次屏幕录制权限。任何不确定都归为 UNKNOWN，绝不当成 granted。"""

    if sys.platform != "darwin":
        return PermissionObservation(
            ScreenPermissionState.UNKNOWN, PermissionReason.UNSUPPORTED_PLATFORM
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
    return PermissionObservation(ScreenPermissionState.DENIED, PermissionReason.DENIED)


def require_screen_permission() -> None:
    """非 granted 直接抛错。这是捕获前的唯一闸门。"""

    observation = observe_screen_permission()
    if not observation.granted:
        raise PermissionDenied(observation.reason.value)


def request_screen_recording() -> bool:
    """触发系统授权弹窗；返回是否已授权。"""

    if sys.platform != "darwin":
        return False
    try:
        from Quartz import CGRequestScreenCaptureAccess

        return bool(CGRequestScreenCaptureAccess())
    except Exception as exc:
        logger.debug("请求屏幕录制权限失败:%s", exc)
        return False
