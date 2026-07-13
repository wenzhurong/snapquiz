"""把模型返回的文本容错解析成 AnswerResult。

模型不一定严格吐 JSON(可能包 ```json 围栏、夹在解释文字里、或干脆是自然语言),
所以这里尽力抽取第一个 JSON 对象;实在抽不到就把整段文本当解析失败兜底。
"""
from __future__ import annotations

import json
import re
from typing import Optional

from snapquiz.llm.base import AnswerResult

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _coerce_confidence(value) -> Optional[float]:
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if 0.0 <= v <= 1.0:
        return v
    return None


def _first_json_object(text: str) -> Optional[dict]:
    """返回文本中第一个可解析的 JSON 对象(string-aware 的花括号配平)。"""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : i + 1]
                    try:
                        obj = json.loads(candidate)
                    except json.JSONDecodeError:
                        break  # 从下一个 '{' 重试
                    if isinstance(obj, dict):
                        return obj
                    break
        start = text.find("{", start + 1)
    return None


def parse_answer(text: str) -> AnswerResult:
    raw = text
    m = _FENCE_RE.search(text)
    candidate_text = m.group(1) if m else text

    obj = None
    stripped = candidate_text.strip()
    try:
        loaded = json.loads(stripped)
        if isinstance(loaded, dict):
            obj = loaded
    except json.JSONDecodeError:
        obj = _first_json_object(candidate_text)

    if obj is None:
        return AnswerResult(
            answer="", rationale=text, confidence=None, raw=raw, parsed_ok=False
        )

    return AnswerResult(
        answer=str(obj.get("answer", "")).strip(),
        rationale=str(obj.get("rationale", "")).strip(),
        confidence=_coerce_confidence(obj.get("confidence")),
        raw=raw,
        parsed_ok=True,
    )
