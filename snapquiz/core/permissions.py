"""已隔离的 MVP-0 权限探测器。

该实现保留旧的 fail-open 行为，仅供迁移识别，产品入口不得调用；M3 将以
``granted / denied / unknown`` 三态实现替换。
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
