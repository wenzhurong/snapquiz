"""GLM-4.6V-Flash provider(经 OpenAI 兼容接口)。

client 依赖注入,便于用假对象测试重试/解析逻辑;from_config 构造真实 OpenAI 客户端。
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from snapquiz.llm.base import AnswerResult
from snapquiz.llm.parse import parse_answer
from snapquiz.llm.prompt import build_messages

logger = logging.getLogger(__name__)


class GLMProvider:
    def __init__(
        self,
        model: str,
        client,
        max_retries: int = 2,
        backoff: Callable[[int], None] = time.sleep,
    ) -> None:
        self._model = model
        self._client = client
        self._max_retries = max_retries
        self._backoff = backoff

    @classmethod
    def from_config(cls, cfg) -> "GLMProvider":
        from openai import OpenAI

        client = OpenAI(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)
        return cls(model=cfg.model, client=client)

    def answer(self, image_data_url: str, question_hint: Optional[str] = None) -> AnswerResult:
        messages = build_messages(image_data_url, question_hint)
        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._client.chat.completions.create(
                    model=self._model, messages=messages
                )
                content = resp.choices[0].message.content or ""
                return parse_answer(content)
            except Exception as exc:  # 网络/服务端瞬时错误 → 退避重试
                last_exc = exc
                logger.warning("GLM 调用失败(第 %d 次):%s", attempt + 1, exc)
                if attempt < self._max_retries:
                    self._backoff(1.5 * (attempt + 1))
        raise RuntimeError(
            f"GLM 调用失败(已重试 {self._max_retries} 次):{last_exc}"
        ) from last_exc
