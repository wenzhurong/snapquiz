"""纯 Adapter 边界。

Adapter 只做两件事：把已授权的本地对象序列化成确切出站字节（``prepare``），
把已界定的响应字节解码成候选结果（``decode``）。它不读密钥、不建 client、
不重试、不 sleep、不联网 —— 那些属于 transport。

这条边界是 v3 里明确正确的设计，予以保留；改掉的只是参数类型：
原来是 ``PlannedExecution`` + ``StageInvocation``，现在是 ``Config``。
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from snapquiz.domain.adapter import AnswerCandidateResult, TransportResponse
from snapquiz.domain.outbound import OutboundRequest

if TYPE_CHECKING:  # 避免运行时循环导入
    from snapquiz.config import Config


class DirectMultimodalAdapter:
    """截图直接交给多模态模型的 Adapter 接口。"""

    __slots__ = ()

    adapter_family = ""
    adapter_version = ""

    def prepare(
        self,
        *,
        config: "Config",
        png: bytes,
        user_hint: Optional[str] = None,
    ) -> OutboundRequest:
        raise NotImplementedError

    def decode(
        self,
        *,
        prepared: OutboundRequest,
        response: TransportResponse,
    ) -> AnswerCandidateResult:
        raise NotImplementedError


__all__ = ["DirectMultimodalAdapter"]
