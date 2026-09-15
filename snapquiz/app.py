"""snapquiz 命令行入口。

流程：加载配置 → 权限自检 → 构造 Adapter + 编排器 → 绑定触发方式。

两种触发方式的执行模型**故意不同**：
- ``stdin``（默认）：串行同步执行。确认提示要读 stdin，不能和触发循环抢同一个输入流，
  所以这一题跑完才读下一次 Enter。
- ``hotkey``：触发来自监听线程，用 busy-guard 挡住连击造成的并发截图与重复计费；
  确认走系统对话框，因为终端多半没有焦点、stdin 也被触发循环占着。

注意：屏幕录制权限归属于**调用 snapquiz 的终端**，不是 snapquiz 本身 ——
它目前不是独立 app bundle。打包成 .app 之后才会变（见 docs/RECOVERY_PLAN.md 阶段 C）。
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from snapquiz.config import ConfigError, load_config

logger = logging.getLogger("snapquiz")

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_PERMISSION_ERROR = 4


def _build_orchestrator(cfg, *, approve):
    # 延迟 import：未装依赖时不影响纯逻辑测试。
    from snapquiz.adapters.openai_chat import OpenAIChatAdapter
    from snapquiz.capture.screen import capture_png_bytes
    from snapquiz.core.orchestrator import Orchestrator
    from snapquiz.core.permissions import require_screen_permission
    from snapquiz.present.notify import notify_error, present
    from snapquiz.transport.client import send_once

    return Orchestrator(
        config=cfg,
        adapter=OpenAIChatAdapter(),
        capture_fn=lambda: capture_png_bytes(cfg.region),
        send_fn=send_once,
        present_fn=present,
        require_permission_fn=require_screen_permission,
        on_error=notify_error,
        approve_fn=approve,
    )


def _describe(prepared) -> str:
    meta = prepared.safe_metadata()
    kinds = "、".join(meta["outbound_data"])
    return (
        f"即将上传 {kinds},{meta['payload_byte_size'] / 1024:.0f} KB"
        f" → {meta['canonical_url']}"
    )


def _confirm_in_terminal(prepared) -> bool:
    """stdin 模式：直接在终端问。此时主线程没有别的东西在读 stdin。"""

    print("\n" + _describe(prepared), flush=True)
    try:
        return input("发送?[y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _confirm_in_dialog(prepared) -> bool:
    """hotkey 模式：终端多半没有焦点,而且 stdin 被触发循环占着,只能弹系统对话框。"""

    import subprocess

    script = (
        'display dialog "{}" with title "snapquiz" '
        'buttons {{"取消", "发送"}} default button "取消"'
    ).format(_describe(prepared).replace("\\", "\\\\").replace('"', '\\"'))
    try:
        done = subprocess.run(
            ["osascript", "-e", script], capture_output=True, timeout=60, check=False
        )
    except Exception:
        return False
    return done.returncode == 0 and b"\xe5\x8f\x91\xe9\x80\x81" in done.stdout


def _startup_permission_hint() -> bool:
    from snapquiz.core.permissions import (
        ScreenPermissionState,
        observe_screen_permission,
        request_screen_recording,
    )

    observation = observe_screen_permission()
    if observation.granted:
        return True
    if observation.state is ScreenPermissionState.DENIED:
        print(
            "⚠️ 尚未授予屏幕录制权限,正在弹出系统授权请求……\n"
            "   请在 系统设置 › 隐私与安全性 › 屏幕录制 中勾选你的**终端**\n"
            "   (snapquiz 目前不是独立 app,权限归属于终端),然后重启终端。",
            flush=True,
        )
        request_screen_recording()
        return False
    print(
        f"⚠️ 无法确认屏幕录制权限({observation.reason.value});"
        "按 fail-closed 处理,不会截屏。",
        flush=True,
    )
    return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="snapquiz", description="个人学习刷题助手"
    )
    parser.add_argument(
        "--trigger",
        choices=["stdin", "hotkey"],
        default="stdin",
        help="触发方式:stdin=终端按 Enter(默认);hotkey=全局热键(需辅助功能权限)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="跳过每次发送前的确认(不推荐:确认是防止误传隐私内容的主要手段)",
    )
    parser.add_argument("--verbose", action="store_true", help="打印调试日志")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    try:
        cfg = load_config(os.environ)
    except ConfigError as exc:
        print(f"❌ 配置错误:{exc}", file=sys.stderr, flush=True)
        return EXIT_CONFIG_ERROR

    if not _startup_permission_hint():
        return EXIT_PERMISSION_ERROR

    from snapquiz.core.orchestrator import always_approve

    left, top, width, height = cfg.region
    banner = (
        f"snapquiz 就绪 | {cfg.provider.provider_id.value}/{cfg.model}"
        f" | 选区 {width}×{height} @ ({left},{top})"
    )

    if args.trigger == "hotkey":
        # 热键来自监听线程,必须用 busy-guard 挡住连击造成的并发截图与重复计费;
        # 确认只能走系统对话框,因为 stdin 被触发循环占着、终端也多半没有焦点。
        from snapquiz.core.busyguard import BusyGuard
        from snapquiz.hotkey.global_hotkey import run_global_hotkey

        approve = always_approve if args.yes else _confirm_in_dialog
        orchestrator = _build_orchestrator(cfg, approve=approve)
        guard = BusyGuard(on_error=lambda exc: logger.error("后台任务失败:%s", exc))

        def trigger() -> None:
            if not guard.try_run(orchestrator.run_once):
                print("上一题还在处理中,已忽略这次触发。", flush=True)

        print(banner, flush=True)
        run_global_hotkey(cfg.hotkey, trigger)
        guard.wait_idle(timeout=cfg.timeout + 5)
    else:
        # stdin 模式本来就是串行的:同步跑完这一题再读下一次 Enter。
        # 不能丢进后台线程 —— 那样确认提示会和触发循环抢同一个 stdin。
        from snapquiz.hotkey.stdin_trigger import run_stdin_trigger

        approve = always_approve if args.yes else _confirm_in_terminal
        orchestrator = _build_orchestrator(cfg, approve=approve)
        print(banner, flush=True)
        run_stdin_trigger(orchestrator.run_once)

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
