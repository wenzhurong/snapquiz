"""呈现：格式化 SolveResult 并展示（终端 + macOS 通知）。

``format_result`` 是纯函数（可测）。

一条刻意的产品规则（来自 ARCHITECTURE §4.6 与原审计第 6 条）：
**模型自报的 confidence 不以百分比展示。** 把主观自评渲染成 "82%" 会让它看起来
像可靠度，而它没有经过任何校准。这里降级成粗粒度提示，并明说是模型自评。
将来若有本地校准服务，calibrated 分数才可以数值化。
"""
from __future__ import annotations

import logging
import subprocess
from typing import Optional

from snapquiz.domain.solve import ConfidenceKind, SolveResult, SolveStatus

logger = logging.getLogger(__name__)

_STATUS_LABEL = {
    SolveStatus.ANSWERED: "",
    SolveStatus.INSUFFICIENT_INPUT: "⚠️ 信息不足,模型未作答",
    SolveStatus.UNSUPPORTED_INPUT: "⚠️ 该题型无法通过截图可靠作答",
    SolveStatus.REFUSED: "⚠️ 模型拒绝作答",
}


def _confidence_hint(result: SolveResult) -> Optional[str]:
    if result.confidence is None or result.confidence_kind is ConfidenceKind.NONE:
        return None
    if result.confidence_kind is ConfidenceKind.CALIBRATED:
        return f"把握:{round(result.confidence * 100)}%(已校准)"
    # model_self_reported：只给粗粒度，且标明是自评。
    if result.confidence >= 0.8:
        level = "较高"
    elif result.confidence >= 0.5:
        level = "中等"
    else:
        level = "较低"
    return f"模型自评把握:{level}(未校准,仅供参考)"


def format_result(result: SolveResult) -> str:
    lines: list[str] = []
    label = _STATUS_LABEL.get(result.status, "")
    if label:
        lines.append(label)
    if result.question_summary:
        lines.append(f"题面:{result.question_summary}")
    if result.answer:
        lines.append(f"答案:{result.answer}")
    hint = _confidence_hint(result)
    if hint:
        lines.append(hint)
    if result.rationale:
        lines.append("")
        lines.append(f"解析:{result.rationale}")
    for warning in result.warnings:
        lines.append(f"· {warning}")
    return "\n".join(lines)


def _summary(result: SolveResult) -> str:
    if result.status is not SolveStatus.ANSWERED or not result.answer:
        return _STATUS_LABEL.get(result.status, "未作答")
    return f"答案 {result.answer}"


def _osascript_notify(title: str, message: str) -> None:
    safe_msg = message.replace("\\", "\\\\").replace('"', '\\"')
    safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
    try:
        subprocess.run(
            [
                "osascript",
                "-e",
                f'display notification "{safe_msg}" with title "{safe_title}"',
            ],
            check=False,
            timeout=5,
        )
    except Exception as exc:  # 通知失败不影响主流程(终端已打印)
        logger.debug("osascript 通知失败:%s", exc)


def present(result: SolveResult) -> None:
    print("\n" + format_result(result) + "\n", flush=True)
    _osascript_notify("snapquiz", _summary(result))


def notify_error(message: str) -> None:
    print("⚠️ " + message, flush=True)
    _osascript_notify("snapquiz", message[:120])


# --------------------------------------------------------------------------
# GUI 模式：打包成 .app 双击运行时没有终端，print 会消失在虚空里
# --------------------------------------------------------------------------


def _osascript_dialog(text: str, *, title: str, buttons: str, timeout: int = 300) -> str:
    safe = text.replace("\\", "\\\\").replace('"', '\\"')
    script = (
        f'display dialog "{safe}" with title "{title}" '
        f"buttons {buttons} giving up after {timeout}"
    )
    try:
        done = subprocess.run(
            ["osascript", "-e", script], capture_output=True, timeout=timeout + 10,
            check=False,
        )
    except Exception as exc:
        logger.debug("osascript dialog 失败:%s", exc)
        return ""
    return done.stdout.decode("utf-8", errors="replace")


def present_in_dialog(result: SolveResult) -> None:
    """GUI 模式的结果呈现：把完整答案放进系统对话框。

    通知栏放不下解析（会被截断），所以答案走对话框、通知只做提醒。
    """

    print(format_result(result), flush=True)  # 从终端启动时仍然有用
    _osascript_dialog(
        format_result(result), title="snapquiz", buttons='{"好"}'
    )


def notify_error_in_dialog(message: str) -> None:
    print("⚠️ " + message, flush=True)
    _osascript_dialog(message, title="snapquiz 出错", buttons='{"好"}', timeout=60)
