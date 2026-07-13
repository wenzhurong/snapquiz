"""呈现:格式化答案并展示(终端打印 + macOS 通知)。

MVP-0 用终端 + 系统通知;MVP-1 再换成 NSPanel「先自答」浮层。
format_result 是纯函数(可测)。
"""
from __future__ import annotations

import logging
import subprocess

from snapquiz.llm.base import AnswerResult

logger = logging.getLogger(__name__)


def format_result(result: AnswerResult) -> str:
    if not result.parsed_ok:
        body = result.rationale or result.raw
        return "⚠️ 未能结构化解析,以下是模型原文:\n" + body

    conf = f"{round(result.confidence * 100)}%" if result.confidence is not None else "未知"
    return "\n".join(
        [
            f"答案:{result.answer}",
            f"置信度:{conf}",
            "",
            f"解析:{result.rationale}",
        ]
    )


def _summary(result: AnswerResult) -> str:
    if not result.parsed_ok:
        return "未能解析,详见终端"
    conf = f"{round(result.confidence * 100)}%" if result.confidence is not None else "未知"
    return f"答案 {result.answer}(置信度 {conf})"


def _osascript_notify(title: str, message: str) -> None:
    safe_msg = message.replace('\\', '\\\\').replace('"', '\\"')
    safe_title = title.replace('\\', '\\\\').replace('"', '\\"')
    try:
        subprocess.run(
            ["osascript", "-e", f'display notification "{safe_msg}" with title "{safe_title}"'],
            check=False,
            timeout=5,
        )
    except Exception as exc:  # 通知失败不影响主流程(终端已打印)
        logger.debug("osascript 通知失败:%s", exc)


def present(result: AnswerResult) -> None:
    print("\n" + format_result(result) + "\n", flush=True)
    _osascript_notify("snapquiz", _summary(result))


def notify_denied() -> None:
    msg = "缺少屏幕录制权限:请在 系统设置 › 隐私与安全性 › 屏幕录制 中勾选 snapquiz(或你的终端),然后重启。"
    print("⚠️ " + msg, flush=True)
    _osascript_notify("snapquiz 权限", "缺少屏幕录制权限")
