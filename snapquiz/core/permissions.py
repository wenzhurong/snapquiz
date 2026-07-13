"""macOS 屏幕录制权限自检(fail-closed 用)。

非 macOS 或拿不到该 API 时返回 True(不拦截),避免在其它平台误伤开发/测试。
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def has_screen_recording() -> bool:
    try:
        from Quartz import CGPreflightScreenCaptureAccess
    except Exception:
        return True  # 非 macOS / 无 API:不拦截
    try:
        return bool(CGPreflightScreenCaptureAccess())
    except Exception as exc:
        logger.debug("屏幕录制权限预检失败:%s", exc)
        return True


def request_screen_recording() -> bool:
    """触发系统授权弹窗;返回是否已授权。"""
    try:
        from Quartz import CGRequestScreenCaptureAccess
    except Exception:
        return False
    try:
        return bool(CGRequestScreenCaptureAccess())
    except Exception as exc:
        logger.debug("请求屏幕录制权限失败:%s", exc)
        return False
