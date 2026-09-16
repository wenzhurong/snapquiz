"""snapquiz 命令行入口。

流程：加载配置 → 数据政策同意（仅首次）→ 权限自检 → 绑定触发方式
→ 拖框选区 → 预览实际出站字节 → 逐次确认 → 发送。

两种触发方式的执行模型**故意不同**：
- ``stdin``（默认）：串行同步执行。确认提示要读 stdin，不能和触发循环抢同一个
  输入流，所以这一题跑完才读下一次 Enter。
- ``hotkey``：触发来自监听线程，用 busy-guard 挡住连击造成的并发截图与重复计费；
  确认走系统对话框，因为终端多半没有焦点、stdin 也被触发循环占着。

注意：屏幕录制权限归属于**调用 snapquiz 的终端**，不是 snapquiz 本身 ——
它目前不是独立 app bundle。打包成 .app 之后才会变（见 docs/RECOVERY_PLAN.md 阶段 C）。
"""
from __future__ import annotations

import argparse
import logging
import os
import pathlib
import subprocess
import sys

from snapquiz.config import ConfigError, load_config

logger = logging.getLogger("snapquiz")

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_CONSENT_DECLINED = 3
EXIT_PERMISSION_ERROR = 4


class CaptureModeError(Exception):
    """选区模式的配置自相矛盾。"""


def choose_interactive(cfg, *, select: bool, region: bool) -> bool:
    """决定这次用「拖框」还是「固定选区」。

    规则（显式 > 隐式）：
      --select        → 拖框（即使配了 SNAPQUIZ_REGION）
      --region        → 固定选区（没配就报错，不静默退回拖框）
      都没给          → 配了 SNAPQUIZ_REGION 就固定，否则拖框

    ⚠️ 陷阱：``SNAPQUIZ_REGION`` 一旦写进 ``.env``，shell 里 ``unset`` 是没用的 ——
    ``load_dotenv()`` 会把它重新读回来。所以要临时拖框必须用 ``--select``。
    """

    if select and region:
        raise CaptureModeError("--select 与 --region 不能同时给")
    if select:
        return True
    if region:
        if cfg.region is None:
            raise CaptureModeError(
                "--region 需要先配置 SNAPQUIZ_REGION='left,top,width,height'"
            )
        return False
    return cfg.region is None


def _build_capture_fn(cfg, *, interactive: bool):
    """交互拖框 or 固定选区。两条路都没有「全屏」这个选项。"""

    if interactive:
        from snapquiz.capture.select import select_region_png

        return select_region_png

    from snapquiz.capture.screen import capture_png_bytes

    return lambda: capture_png_bytes(cfg.region)


def _build_orchestrator(cfg, *, approve, interactive: bool, gui: bool = False):
    # 延迟 import：未装依赖时不影响纯逻辑测试。
    from snapquiz.adapters.openai_chat import OpenAIChatAdapter
    from snapquiz.core.orchestrator import Orchestrator
    from snapquiz.core.permissions import require_screen_permission
    from snapquiz.present.notify import (
        notify_error,
        notify_error_in_dialog,
        present,
        present_in_dialog,
    )
    from snapquiz.transport.client import send_once

    # GUI 模式没有终端,print 会消失在虚空里 —— 结果与错误都必须走对话框。
    present_fn = present_in_dialog if gui else present
    error_fn = notify_error_in_dialog if gui else notify_error

    return Orchestrator(
        config=cfg,
        adapter=OpenAIChatAdapter(),
        capture_fn=_build_capture_fn(cfg, interactive=interactive),
        send_fn=send_once,
        present_fn=present_fn,
        require_permission_fn=require_screen_permission,
        on_error=error_fn,
        approve_fn=approve,
    )


# --------------------------------------------------------------------------
# 发送前确认：让人**看到实际要发的那张图**，而不是只看字节数
# --------------------------------------------------------------------------


def _confirm_in_terminal(prepared) -> bool:
    """stdin 模式：Quick Look 弹图 + 终端问 y/N。"""

    from snapquiz.privacy.preview import (
        PreviewUnavailable,
        build_preview,
        discard,
        show_image,
    )

    try:
        preview = build_preview(prepared)
    except PreviewUnavailable as exc:
        # 看不到要发什么就不发。
        print(f"\n⚠️ 无法预览即将发送的内容({exc});已取消。", flush=True)
        return False

    path = show_image(preview)
    try:
        print("\n" + preview.describe(), flush=True)
        if path is None:
            print("  (没能弹出预览窗口,下面的确认是盲发,请谨慎)", flush=True)
        try:
            return input("发送?[y/N] ").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            print()
            return False
    finally:
        discard(path)


def _confirm_in_dialog(prepared) -> bool:
    """hotkey 模式：Quick Look 弹图 + 系统对话框。

    终端多半没有焦点,而且 stdin 被触发循环占着,只能走对话框。
    """

    from snapquiz.privacy.preview import (
        PreviewUnavailable,
        build_preview,
        discard,
        show_image,
    )

    try:
        preview = build_preview(prepared)
    except PreviewUnavailable:
        return False

    path = show_image(preview)
    try:
        text = preview.describe().replace("\\", "\\\\").replace('"', '\\"')
        script = (
            f'display dialog "{text}" with title "snapquiz 发送确认" '
            'buttons {"取消", "发送"} default button "取消"'
        )
        try:
            done = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=180,
                check=False,
            )
        except Exception:
            return False
        return done.returncode == 0 and "发送" in done.stdout.decode(
            "utf-8", errors="replace"
        )
    finally:
        discard(path)


# --------------------------------------------------------------------------
# 一次性的数据政策同意（与逐次发送确认是两层，不能互相替代）
# --------------------------------------------------------------------------


def _ensure_consent(cfg, *, assume_yes: bool, gui: bool = False) -> bool:
    from snapquiz.privacy import consent

    provider_id = cfg.provider.provider_id.value
    if consent.load(provider_id=provider_id, endpoint=cfg.endpoint_url):
        return True
    if assume_yes:
        consent.grant(provider_id=provider_id, endpoint=cfg.endpoint_url)
        return True

    text = consent.disclosure(
        provider_id=provider_id, endpoint=cfg.endpoint_url, model=cfg.model
    )
    if gui:
        if not _ask_in_dialog(text, title="snapquiz 数据政策"):
            return False
        consent.grant(provider_id=provider_id, endpoint=cfg.endpoint_url)
        return True

    print()
    print("=" * 66)
    print(
        consent.disclosure(
            provider_id=provider_id, endpoint=cfg.endpoint_url, model=cfg.model
        )
    )
    print("=" * 66)
    try:
        answer = input("接受并继续?[y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if answer not in ("y", "yes"):
        return False
    consent.grant(provider_id=provider_id, endpoint=cfg.endpoint_url)
    print("已记录(可用 snapquiz --revoke-consent 撤销)。\n", flush=True)
    return True


#: 打包成 .app 之后，工作目录是 `/`，仓库里的 .env 根本不在搜索路径上。
#: 所以必须有一个与启动方式无关的固定位置。
USER_CONFIG_DIR = pathlib.Path(os.path.expanduser("~/.snapquiz"))
USER_ENV_PATH = USER_CONFIG_DIR / ".env"


def load_environment() -> None:
    """按「全局 → 就近」两层加载配置。

    1. ``~/.snapquiz/.env`` —— 与启动方式无关，双击 .app 时唯一能找到的那份；
    2. 当前目录向上搜到的 ``.env`` —— 从仓库里跑时更贴近手头的工作，覆盖前者。
    """

    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:
        return

    if USER_ENV_PATH.exists():
        load_dotenv(USER_ENV_PATH)
    nearby = find_dotenv(usecwd=True)
    if nearby:
        load_dotenv(nearby, override=True)


def missing_key_help(key_env: str, *, gui: bool) -> str:
    where = USER_ENV_PATH if gui else "项目目录下的 .env"
    return (
        f"缺少 {key_env}。\n\n"
        f"请把它写进 {where}:\n"
        f"    {key_env}=你的密钥\n\n"
        + (
            f"(双击启动时工作目录是 /,只会读 {USER_ENV_PATH};"
            "仓库里的 .env 读不到)"
            if gui
            else "格式见 .env.example"
        )
    )


def is_gui_launch() -> bool:
    """双击 .app 启动时没有可交互的终端。

    此时 stdin 触发、终端确认、print 输出全部失效,必须整条切到
    「热键 + 系统对话框 + 通知」。从终端跑则保持终端体验。
    """

    try:
        return not sys.stdin.isatty()
    except (AttributeError, ValueError):
        return True


def _ask_in_dialog(text: str, *, title: str) -> bool:
    """GUI 模式下的是/否询问。默认按钮是「取消」,误触不会变成同意。"""

    import subprocess as sp

    safe = text.replace("\\", "\\\\").replace('"', '\\"')
    script = (
        f'display dialog "{safe}" with title "{title}" '
        'buttons {"取消", "同意"} default button "取消"'
    )
    try:
        done = sp.run(
            ["osascript", "-e", script], capture_output=True, timeout=300, check=False
        )
    except Exception:
        return False
    return done.returncode == 0 and "同意" in done.stdout.decode(
        "utf-8", errors="replace"
    )


def _startup_permission_hint(*, gui: bool = False) -> bool:
    from snapquiz.core.permissions import (
        ScreenPermissionState,
        observe_screen_permission,
        request_screen_recording,
    )

    from snapquiz.present.notify import notify_error_in_dialog

    observation = observe_screen_permission()
    if observation.granted:
        return True

    who = "SnapQuiz" if gui else "你的**终端**(snapquiz 不是独立 app,权限记在终端名下)"
    if observation.state is ScreenPermissionState.DENIED:
        message = (
            "尚未授予屏幕录制权限,正在弹出系统授权请求。\n"
            f"请在 系统设置 › 隐私与安全性 › 屏幕录制 中勾选 {who},然后重新启动。"
        )
        request_screen_recording()
    else:
        message = (
            f"无法确认屏幕录制权限(原因:{observation.reason.value});"
            "按 fail-closed 处理,不会截屏。"
        )
    if gui:
        notify_error_in_dialog(message)
    else:
        print("⚠️ " + message, flush=True)
    return False


def _run_gui(cfg, trigger, guard) -> int:
    """GUI 模式主循环。

    热键监听跑在后台线程，主线程停在一个「运行中」对话框上 —— 这是**退出的唯一
    出口**：一个没有 Dock 图标、没有菜单栏的后台 app，否则只能去活动监视器杀。
    做成菜单栏图标是更体面的方案，属于后续打磨。
    """

    import threading

    from snapquiz.hotkey.global_hotkey import run_global_hotkey
    from snapquiz.present.notify import _osascript_dialog, notify_error_in_dialog

    try:
        listener = threading.Thread(
            target=run_global_hotkey, args=(cfg.hotkey, trigger), daemon=True
        )
        listener.start()
    except Exception as exc:  # pragma: no cover - 取决于系统权限
        notify_error_in_dialog(f"无法注册全局热键:{exc}")
        return EXIT_PERMISSION_ERROR

    _osascript_dialog(
        f"snapquiz 正在后台运行。\n\n"
        f"  解题热键   {cfg.hotkey}\n"
        f"  模型       {cfg.provider.provider_id.value}/{cfg.model}\n\n"
        "按热键 → 拖框选题 → 确认要上传的图 → 出答案。\n"
        "点「退出」结束运行。",
        title="snapquiz",
        buttons='{"退出"}',
        timeout=86_400,
    )
    guard.wait_idle(timeout=cfg.timeout + 5)
    return EXIT_OK


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="snapquiz", description="个人学习刷题助手")
    parser.add_argument(
        "--trigger",
        choices=["stdin", "hotkey"],
        default="stdin",
        help="触发方式:stdin=终端按 Enter(默认);hotkey=全局热键(需辅助功能权限)",
    )
    parser.add_argument(
        "--select",
        action="store_true",
        help="每次弹十字准星拖框选题。未配 SNAPQUIZ_REGION 时是默认行为;"
        "配了也可以用它临时覆盖(shell 里 unset 无效,.env 会被重新读入)",
    )
    parser.add_argument(
        "--region",
        action="store_true",
        help="使用 SNAPQUIZ_REGION 配置的固定选区,不弹准星",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="跳过每次发送前的确认(不推荐:确认是防止误传隐私内容的主要手段)",
    )
    parser.add_argument(
        "--revoke-consent",
        action="store_true",
        help="撤销已记录的数据政策同意并退出",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="强制 GUI 模式(热键 + 系统对话框)。双击 .app 启动时自动开启",
    )
    parser.add_argument("--verbose", action="store_true", help="打印调试日志")
    args = parser.parse_args(argv)

    # 双击 .app 时没有终端:stdin 触发、终端确认、print 全部失效。
    gui = args.gui or is_gui_launch()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.revoke_consent:
        from snapquiz.privacy import consent

        print("已撤销。" if consent.revoke() else "本来就没有已记录的同意。")
        return EXIT_OK

    load_environment()

    try:
        # 选区可以来自环境变量,也可以每次拖框;两者都不是「全屏」。
        cfg = load_config(os.environ, require_region=False)
    except ConfigError as exc:
        message = str(exc)
        if "缺少" in message and "API_KEY" in message:
            key_env = message.split("缺少 ")[1].split("(")[0].strip()
            message = missing_key_help(key_env, gui=gui)
        if gui:
            from snapquiz.present.notify import notify_error_in_dialog

            notify_error_in_dialog(message)
        else:
            print(f"❌ 配置错误:{message}", file=sys.stderr, flush=True)
        return EXIT_CONFIG_ERROR

    try:
        interactive = choose_interactive(
            cfg, select=args.select, region=args.region
        )
    except CaptureModeError as exc:
        print(f"❌ {exc}", file=sys.stderr, flush=True)
        return EXIT_CONFIG_ERROR

    if not _ensure_consent(cfg, assume_yes=args.yes, gui=gui):
        print("未获得数据政策同意,已退出(什么都没有发送)。", flush=True)
        return EXIT_CONSENT_DECLINED

    if not _startup_permission_hint(gui=gui):
        return EXIT_PERMISSION_ERROR

    from snapquiz.core.orchestrator import always_approve

    head = f"snapquiz 就绪 | {cfg.provider.provider_id.value}/{cfg.model}"
    if interactive:
        banner = f"{head} | 选区:每次拖框(Esc 取消)"
    else:
        # 固定选区最容易让人误以为「怎么没弹准星」,所以把来源和切换方式都说清楚。
        left, top, width, height = cfg.region
        banner = (
            f"{head} | 选区:固定 {width}×{height} @ ({left},{top}) —— **不会弹准星**\n"
            f"           想每次拖框:加 --select,或把 SNAPQUIZ_REGION 从 .env 里注释掉\n"
            f"           (shell 里 unset 没用,.env 会被重新读入)"
        )

    # GUI 模式只能走热键 —— 没有终端可以按 Enter。
    if gui or args.trigger == "hotkey":
        from snapquiz.core.busyguard import BusyGuard
        from snapquiz.hotkey.global_hotkey import run_global_hotkey

        approve = always_approve if args.yes else _confirm_in_dialog
        orchestrator = _build_orchestrator(
            cfg, approve=approve, interactive=interactive, gui=gui
        )
        guard = BusyGuard(on_error=lambda exc: logger.error("后台任务失败:%s", exc))

        def trigger() -> None:
            if not guard.try_run(orchestrator.run_once):
                logger.info("上一题还在处理中,已忽略这次触发。")

        print(banner, flush=True)
        if gui:
            return _run_gui(cfg, trigger, guard)
        run_global_hotkey(cfg.hotkey, trigger)
        guard.wait_idle(timeout=cfg.timeout + 5)
    else:
        from snapquiz.hotkey.stdin_trigger import run_stdin_trigger

        approve = always_approve if args.yes else _confirm_in_terminal
        orchestrator = _build_orchestrator(
            cfg, approve=approve, interactive=interactive
        )
        print(banner, flush=True)
        run_stdin_trigger(orchestrator.run_once)

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
