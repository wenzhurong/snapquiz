"""编排一次查询:权限自检(fail-closed)→ 截屏 → 作答 → 呈现。

所有外部依赖(截屏、模型、呈现、权限)都以可调用对象注入,便于测试与替换 provider。
"""
from __future__ import annotations

from typing import Callable, Optional

from snapquiz.llm.base import AnswerResult, VlmProvider


class Orchestrator:
    def __init__(
        self,
        provider: VlmProvider,
        capture_fn: Callable[[], str],
        present_fn: Callable[[AnswerResult], None],
        has_permission_fn: Callable[[], bool],
        on_denied: Callable[[], None],
        question_hint: Optional[str] = None,
    ) -> None:
        self._provider = provider
        self._capture_fn = capture_fn
        self._present_fn = present_fn
        self._has_permission_fn = has_permission_fn
        self._on_denied = on_denied
        self._question_hint = question_hint

    def run_once(self) -> None:
        if not self._has_permission_fn():
            self._on_denied()
            return
        image_data_url = self._capture_fn()
        result = self._provider.answer(image_data_url, self._question_hint)
        self._present_fn(result)
