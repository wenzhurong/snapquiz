"""LLM 层的公共数据类型与 provider 接口(纯标准库,可安全被测试导入)。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass
class AnswerResult:
    """一次作答的结构化结果。

    parsed_ok=False 时表示模型没有返回可解析的 JSON,此时把整段文本放进
    rationale 兜底展示,answer 留空——呈现层据此提示「未能结构化解析」。
    """

    answer: str
    rationale: str
    confidence: Optional[float]
    raw: str
    parsed_ok: bool


class VlmProvider(Protocol):
    """视觉大模型 provider 接口。实现类把截图 + 提示发给模型,返回 AnswerResult。"""

    def answer(self, image_data_url: str, question_hint: Optional[str] = None) -> AnswerResult:
        ...
