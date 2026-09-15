"""Adapter/Transport 边界上的不可变契约。

原 v3 版本里 ``TransportResponse`` 与 ``AnswerCandidateResult`` 各带
plan_id / stage_id / operation_id / plan_digest / invocation_digest 五类
PlannedExecution 记账字段。plan 机制随 v3 一同移除后它们不再指向任何东西，
因此这里只保留真正做事的那条相关性：**请求 envelope digest ↔ 响应体 digest ↔
候选结果**，三者逐层绑定，模型输出无法冒充成另一次请求的结果。

Provider 的原始响应文本永远不进入 SolveResult；候选载荷是不可信数据，
只有 result/validator.py 能把它变成可信结果。
"""
from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Optional

from snapquiz.domain._validation import (
    require_digest,
    require_optional_text,
    require_plain_int,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.solve import UsageSummary

TRANSPORT_RESPONSE_SCHEMA_VERSION = "snapquiz.transport-response.v2"
TRANSPORT_RESPONSE_BODY_SCHEMA_VERSION = "snapquiz.transport-response-body.v1"
ANSWER_CANDIDATE_SCHEMA_VERSION = "snapquiz.answer-candidate.v2"
MAX_PROVIDER_RESPONSE_BYTES = 2 * 1_024 * 1_024
MAX_PROVIDER_REQUEST_ID_CHARS = 256


class NormalizedRefusal(str, Enum):
    CONTENT_POLICY = "content_policy"


def _response_body_digest(body: bytes) -> Digest256:
    return digest256(
        "TransportResponseBody",
        TRANSPORT_RESPONSE_BODY_SCHEMA_VERSION,
        {"byte_size": len(body), "sha256": hashlib.sha256(body).hexdigest()},
    )


@runtime_final
class TransportResponse:
    """一次传输返回的、有上限的响应字节，绑定到发出的那个 envelope。"""

    __slots__ = (
        "request_envelope_digest",
        "http_status",
        "provider_request_id",
        "response_body_digest",
        "response_byte_size",
        "_body",
    )

    request_envelope_digest: Digest256
    http_status: int
    provider_request_id: Optional[str]
    response_body_digest: Digest256
    response_byte_size: int

    def __init__(
        self,
        *,
        request_envelope_digest: Digest256,
        http_status: int,
        body: bytes,
        provider_request_id: Optional[str] = None,
    ) -> None:
        require_digest(request_envelope_digest, "request_envelope_digest")
        require_plain_int(http_status, "http_status", minimum=100)
        if http_status > 599:
            raise ValueError("http_status must be <= 599")
        require_optional_text(
            provider_request_id,
            "provider_request_id",
            max_length=MAX_PROVIDER_REQUEST_ID_CHARS,
        )
        if type(body) is not bytes:
            raise ValueError("body must be immutable bytes")
        if len(body) > MAX_PROVIDER_RESPONSE_BYTES:
            raise ValueError("response body exceeds the local safety limit")

        set_ = object.__setattr__
        set_(self, "request_envelope_digest", request_envelope_digest)
        set_(self, "http_status", http_status)
        set_(self, "provider_request_id", provider_request_id)
        set_(self, "response_body_digest", _response_body_digest(body))
        set_(self, "response_byte_size", len(body))
        set_(self, "_body", body)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("TransportResponse is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "TransportResponse":
        return self

    def __repr__(self) -> str:
        return (
            f"TransportResponse(http_status={self.http_status}, "
            f"response_byte_size={self.response_byte_size}, body=<withheld>)"
        )

    @property
    def body(self) -> bytes:
        return self._body

    def validate_integrity(self) -> None:
        if _response_body_digest(self._body) != self.response_body_digest:
            raise ValueError("response body digest changed")


@runtime_final
class AnswerCandidateResult:
    """Adapter 解码出的**不可信**候选，绑定到它所回应的那个 envelope。"""

    __slots__ = (
        "request_envelope_digest",
        "response_body_digest",
        "candidate_payload",
        "refusal",
        "finish_reason",
        "provider_request_id",
        "usage",
    )

    request_envelope_digest: Digest256
    response_body_digest: Digest256
    candidate_payload: Optional[dict[str, Any]]
    refusal: Optional[NormalizedRefusal]
    finish_reason: Optional[str]
    provider_request_id: Optional[str]
    usage: UsageSummary

    def __init__(
        self,
        *,
        request_envelope_digest: Digest256,
        response_body_digest: Digest256,
        candidate_payload: Optional[dict[str, Any]],
        refusal: Optional[NormalizedRefusal] = None,
        finish_reason: Optional[str] = None,
        provider_request_id: Optional[str] = None,
        usage: Optional[UsageSummary] = None,
    ) -> None:
        require_digest(request_envelope_digest, "request_envelope_digest")
        require_digest(response_body_digest, "response_body_digest")
        if candidate_payload is not None and type(candidate_payload) is not dict:
            raise ValueError("candidate_payload must be a dict or None")
        if refusal is not None and type(refusal) is not NormalizedRefusal:
            raise ValueError("refusal must be NormalizedRefusal or None")
        if (candidate_payload is None) == (refusal is None):
            raise ValueError("exactly one of candidate_payload / refusal is required")
        require_optional_text(finish_reason, "finish_reason", max_length=64)
        require_optional_text(
            provider_request_id,
            "provider_request_id",
            max_length=MAX_PROVIDER_REQUEST_ID_CHARS,
        )
        if usage is not None and type(usage) is not UsageSummary:
            raise ValueError("usage must be UsageSummary or None")

        set_ = object.__setattr__
        set_(self, "request_envelope_digest", request_envelope_digest)
        set_(self, "response_body_digest", response_body_digest)
        set_(self, "candidate_payload", candidate_payload)
        set_(self, "refusal", refusal)
        set_(self, "finish_reason", finish_reason)
        set_(self, "provider_request_id", provider_request_id)
        set_(self, "usage", usage if usage is not None else UsageSummary())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AnswerCandidateResult is immutable")

    def __repr__(self) -> str:
        return (
            "AnswerCandidateResult("
            f"refusal={self.refusal!r}, finish_reason={self.finish_reason!r}, "
            "candidate_payload=<withheld>)"
        )

    def validate_binding(self, *, response: TransportResponse) -> None:
        """候选必须来自这次请求的这个响应体，否则拒绝。"""

        if type(response) is not TransportResponse:
            raise TypeError("response must be TransportResponse")
        if (
            self.request_envelope_digest != response.request_envelope_digest
            or self.response_body_digest != response.response_body_digest
        ):
            raise ValueError("candidate is bound to another request/response")


__all__ = [
    "ANSWER_CANDIDATE_SCHEMA_VERSION",
    "MAX_PROVIDER_REQUEST_ID_CHARS",
    "MAX_PROVIDER_RESPONSE_BYTES",
    "TRANSPORT_RESPONSE_SCHEMA_VERSION",
    "AnswerCandidateResult",
    "NormalizedRefusal",
    "TransportResponse",
]
