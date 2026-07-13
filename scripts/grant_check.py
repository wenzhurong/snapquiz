"""屏幕录制权限预检小工具:python scripts/grant_check.py"""
from __future__ import annotations

from snapquiz.core.permissions import has_screen_recording, request_screen_recording


def main() -> int:
    if has_screen_recording():
        print("✅ 已授予屏幕录制权限,可以直接运行 snapquiz。")
        return 0
    print("❌ 未授予屏幕录制权限,正在弹出系统授权请求……")
    request_screen_recording()
    print("请在 系统设置 › 隐私与安全性 › 屏幕录制 勾选 snapquiz(或你的终端)后,重启本工具。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
