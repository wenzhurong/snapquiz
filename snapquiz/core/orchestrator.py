"""已冻结的 MVP-0 编排器。

新的 ExecutionPlan/Egress 链接管前，本类只保留兼容签名；运行时不会调用
任何注入能力。
"""
from __future__ import annotations

from typing import Any, Callable, NoReturn, Optional

from snapquiz.core.legacy import raise_legacy_pipeline_disabled


class Orchestrator:
    def __init__(
        self,
        provider: Any,
        capture_fn: Callable[[], str],
        present_fn: Callable[[Any], None],
        has_permission_fn: Callable[[], bool],
        on_denied: Callable[[], None],
        question_hint: Optional[str] = None,
    ) -> None:
        # 不保留 capability 引用，避免调用方从 legacy 对象重新取出旁路能力。
        del provider, capture_fn, present_fn, has_permission_fn, on_denied, question_hint

    def run_once(self) -> NoReturn:
        raise_legacy_pipeline_disabled()
