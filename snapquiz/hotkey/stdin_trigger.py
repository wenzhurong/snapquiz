"""已冻结的 MVP-0 stdin 触发器。"""
from __future__ import annotations

from typing import Callable, NoReturn

from snapquiz.core.legacy import raise_legacy_pipeline_disabled


def run_stdin_trigger(on_trigger: Callable[[], None]) -> NoReturn:
    del on_trigger
    raise_legacy_pipeline_disabled()
