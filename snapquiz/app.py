"""snapquiz MVP-0 入口。

流程:加载配置 → 构造 GLM provider + 编排器 → 用 busy-guard 包住 → 绑定触发方式。
触发方式:--trigger stdin(默认,零权限)| hotkey(全局热键,需辅助功能权限)。
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from snapquiz.config import ConfigError, load_config
from snapquiz.core.busyguard import BusyGuard
from snapquiz.core.orchestrator import Orchestrator
from snapquiz.core.permissions import has_screen_recording, request_screen_recording

logger = logging.getLogger("snapquiz")


def _build_orchestrator(cfg) -> Orchestrator:
    # 延迟到此处 import,避免未装依赖时影响纯逻辑测试
    from snapquiz.capture.screen import capture_data_url
    from snapquiz.llm.glm import GLMProvider
    from snapquiz.present.notify import notify_denied, present

    provider = GLMProvider.from_config(cfg)
    return Orchestrator(
        provider=provider,
        capture_fn=lambda: capture_data_url(cfg.region),
        present_fn=present,
        has_permission_fn=has_screen_recording,
        on_denied=notify_denied,
    )


def _startup_permission_hint() -> None:
    if not has_screen_recording():
        print(
            "⚠️ 尚未授予屏幕录制权限,正在弹出系统授权请求……\n"
            "   请在 系统设置 › 隐私与安全性 › 屏幕录制 勾选后重启本工具。",
            flush=True,
        )
        request_screen_recording()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="snapquiz", description="个人学习刷题助手(MVP-0)")
    parser.add_argument(
        "--trigger",
        choices=["stdin", "hotkey"],
        default="stdin",
        help="触发方式:stdin=终端按 Enter(默认,零权限);hotkey=全局热键(需辅助功能权限)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    try:
        from dotenv import load_dotenv

        load_dotenv()
    except Exception:
        pass  # 没装 python-dotenv 也可,只要环境变量里有 GLM_API_KEY

    try:
        cfg = load_config(os.environ)
    except ConfigError as exc:
        print(f"配置错误:{exc}", file=sys.stderr)
        return 2

    _startup_permission_hint()

    try:
        orch = _build_orchestrator(cfg)
    except Exception as exc:
        print(f"初始化失败:{exc}", file=sys.stderr)
        return 1

    guard = BusyGuard(on_error=lambda exc: print(f"查询失败:{exc}", file=sys.stderr, flush=True))

    def on_trigger() -> None:
        if not guard.try_run(orch.run_once):
            print("上一题还在处理中,已忽略这次触发。", flush=True)

    if args.trigger == "hotkey":
        from snapquiz.hotkey.global_hotkey import run_global_hotkey

        run_global_hotkey(cfg.hotkey, on_trigger)
    else:
        from snapquiz.hotkey.stdin_trigger import run_stdin_trigger

        run_stdin_trigger(on_trigger)

    guard.wait_idle(timeout=cfg.timeout + 5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
