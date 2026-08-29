"""已冻结的 MVP-0 GLM provider。

Phase 1 的纯 Adapter 与授权 Transport 完成前，本类不得 prepare、retry、解析
凭据、构造 SDK 或发送请求。
"""
from __future__ import annotations

from typing import Any, Callable, NoReturn, Optional

from snapquiz.core.legacy import raise_legacy_pipeline_disabled


class GLMProvider:
    def __init__(
        self,
        model: str,
        client: Any,
        max_retries: int = 2,
        backoff: Optional[Callable[[int], None]] = None,
    ) -> None:
        # 保留构造签名仅用于给旧调用方一个确定的禁用终态，不保存发送能力。
        del model, client, max_retries, backoff

    @classmethod
    def from_config(cls, cfg) -> NoReturn:
        del cfg
        raise_legacy_pipeline_disabled()

    def answer(
        self, image_data_url: str, question_hint: Optional[str] = None
    ) -> NoReturn:
        del image_data_url, question_hint
        raise_legacy_pipeline_disabled()
