"""屏幕录制权限预检:python scripts/grant_check.py

权限归属于**调用它的终端**,不是 snapquiz —— 后者目前不是独立 app bundle。
所以要在「系统设置 › 隐私与安全性 › 屏幕录制」里勾选你的终端。
"""
from __future__ import annotations

from snapquiz.core.permissions import (
    ScreenPermissionState,
    observe_screen_permission,
    request_screen_recording,
)

EXIT_GRANTED = 0
EXIT_NOT_GRANTED = 1


def main() -> int:
    observation = observe_screen_permission()

    if observation.granted:
        print("✅ 已授予屏幕录制权限,可以直接运行 snapquiz。")
        return EXIT_GRANTED

    if observation.state is ScreenPermissionState.DENIED:
        print("❌ 未授予屏幕录制权限,正在弹出系统授权请求……")
        request_screen_recording()
        print(
            "请在 系统设置 › 隐私与安全性 › 屏幕录制 中勾选你的**终端**\n"
            "(不是 snapquiz —— 它还不是独立 app,权限记在终端名下),\n"
            "勾选后需要重启终端才生效。"
        )
        return EXIT_NOT_GRANTED

    # UNKNOWN:非 macOS、Quartz 缺失、API 异常或返回了非布尔值。
    print(
        f"⚠️ 无法确认屏幕录制权限(原因:{observation.reason.value})。\n"
        "snapquiz 对非 granted 一律 fail-closed,不会尝试截屏。"
    )
    return EXIT_NOT_GRANTED


if __name__ == "__main__":
    raise SystemExit(main())
