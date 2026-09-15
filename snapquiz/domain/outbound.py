"""Prepared, immutable outbound bytes and exact request-envelope digests."""
from __future__ import annotations

import hashlib
from uuid import UUID

from snapquiz.domain._validation import (
    HTTP_TOKEN_RE,
    require_canonical_http_url,
    require_digest,
    require_non_secret_header_name,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from enum import Enum


class QueryPolicyKind(str, Enum):
    """Canonical query-string policy. Phase 1 only ever uses EMPTY."""

    EMPTY = "empty"
    EXACT = "exact"


class CredentialInjectionSlot(str, Enum):
    """Where the secret is injected, decided before the bytes are prepared."""

    AUTHORIZATION_HEADER = "authorization_header"
    PROVIDER_HEADER = "provider_header"
    NOT_APPLICABLE = "not_applicable"


class OutboundDataKind(str, Enum):
    """What kinds of user data the outbound payload actually carries."""

    IMAGE = "image"
    OCR_TEXT = "ocr_text"
    USER_HINT = "user_hint"
    PROVIDER_RESPONSE_TEXT = "provider_response_text"

from snapquiz.domain.policy import ContractMarker

PREPARED_BODY_SCHEMA_VERSION = "snapquiz.prepared-outbound-body.v1"
NON_SECRET_HEADERS_SCHEMA_VERSION = "snapquiz.non-secret-headers.v1"
REQUEST_ENVELOPE_SCHEMA_VERSION = "snapquiz.request-envelope.v1"

@runtime_final
class NonSecretHeader:
    """Immutable header value that fails closed with dataclasses.asdict()."""

    lowercase_name: str
    normalized_value: str

    __slots__ = ("lowercase_name", "normalized_value")

    def __init__(self, *, lowercase_name: str, normalized_value: str) -> None:
        require_non_secret_header_name(lowercase_name, "lowercase_name")
        value = require_text(
            normalized_value, "normalized_value", max_length=4_096
        )
        if value != value.strip() or "\r" in value or "\n" in value:
            raise ValueError("header value must already be normalized")
        object.__setattr__(self, "lowercase_name", lowercase_name)
        object.__setattr__(self, "normalized_value", normalized_value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("NonSecretHeader is immutable")

    def __repr__(self) -> str:
        return f"NonSecretHeader(lowercase_name={self.lowercase_name!r}, normalized_value=<redacted>)"

    def __eq__(self, other: object) -> bool:
        return (
            type(other) is NonSecretHeader
            and self.lowercase_name == other.lowercase_name
            and self.normalized_value == other.normalized_value
        )

    def __hash__(self) -> int:
        return hash((self.lowercase_name, self.normalized_value))

    def __deepcopy__(self, memo: dict[int, object]) -> "NonSecretHeader":
        return self

    def as_digest_payload(self) -> dict[str, str]:
        return {
            "lowercase_name": self.lowercase_name,
            "normalized_value": self.normalized_value,
        }


@runtime_final
class OutboundRequest:
    """一次出站请求的确切字节，不可变。

    这是 v3 ``PreparedOutbound`` 的替代物。原版另有 plan_id / plan_digest /
    stage_id / operation_id / source_ids / source_digests 六个字段，全部是
    PlannedExecution 记账；plan 机制随 v3 一同移除后它们不再指向任何东西。

    保留的是真正有用的那条性质：``envelope_digest`` 覆盖 method/url/content-type/
    非密钥 header/body 全部内容，所以「预览时看到的」和「实际发出的」可以逐字节核对。
    密钥不在其中 —— 它在批准之后才注入，既不进 digest 也不进这个对象。
    """

    __slots__ = (
        "http_method",
        "canonical_url",
        "content_type",
        "non_secret_headers",
        "outbound_data",
        "body",
        "body_digest",
        "envelope_digest",
    )

    http_method: str
    canonical_url: str
    content_type: str
    non_secret_headers: tuple[NonSecretHeader, ...]
    outbound_data: tuple[OutboundDataKind, ...]
    body: bytes
    body_digest: Digest256
    envelope_digest: Digest256

    def __init__(
        self,
        *,
        http_method: str,
        canonical_url: str,
        content_type: str,
        non_secret_headers: tuple[NonSecretHeader, ...],
        outbound_data: tuple[OutboundDataKind, ...],
        body: bytes,
    ) -> None:
        if http_method != "POST":
            raise ValueError("Phase 1 只使用 POST")
        if not canonical_url.startswith("https://"):
            raise ValueError("出站 URL 必须是 https")
        if type(body) is not bytes or not body:
            raise ValueError("body must be non-empty bytes")
        if type(non_secret_headers) is not tuple:
            raise ValueError("non_secret_headers must be a tuple")
        if any(type(h) is not NonSecretHeader for h in non_secret_headers):
            raise ValueError("non_secret_headers must contain NonSecretHeader")
        if len({h.lowercase_name for h in non_secret_headers}) != len(
            non_secret_headers
        ):
            raise ValueError("non_secret_headers must have unique names")
        if type(outbound_data) is not tuple or not outbound_data:
            raise ValueError("outbound_data must be a non-empty tuple")
        if any(type(k) is not OutboundDataKind for k in outbound_data):
            raise ValueError("outbound_data must contain OutboundDataKind values")

        set_ = object.__setattr__
        set_(self, "http_method", http_method)
        set_(self, "canonical_url", canonical_url)
        set_(self, "content_type", content_type)
        set_(self, "non_secret_headers", non_secret_headers)
        set_(self, "outbound_data", outbound_data)
        set_(self, "body", body)
        set_(self, "body_digest", digest256(
            "OutboundBody", PREPARED_BODY_SCHEMA_VERSION,
            {"sha256": hashlib.sha256(body).hexdigest(), "byte_size": len(body)},
        ))
        set_(self, "envelope_digest", self._compute_envelope_digest())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("OutboundRequest is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "OutboundRequest":
        return self

    def _compute_envelope_digest(self) -> Digest256:
        return digest256(
            "OutboundRequest",
            REQUEST_ENVELOPE_SCHEMA_VERSION,
            {
                "http_method": self.http_method,
                "canonical_url": self.canonical_url,
                "content_type": self.content_type,
                "non_secret_headers": digest256(
                    "NonSecretHeaders",
                    NON_SECRET_HEADERS_SCHEMA_VERSION,
                    {"headers": tuple(
                        h.as_digest_payload() for h in self.non_secret_headers
                    )},
                ),
                "outbound_data": tuple(k.value for k in self.outbound_data),
                "body_digest": self.body_digest,
            },
        )

    @property
    def payload_byte_size(self) -> int:
        return len(self.body)

    def validate_integrity(self) -> None:
        """重算 envelope digest 并比对；预览之后、发送之前调用。"""

        if self._compute_envelope_digest() != self.envelope_digest:
            raise ValueError("outbound envelope changed after preparation")

    def safe_metadata(self) -> dict[str, object]:
        """结构化日志用；不含 body、不含任何用户内容。"""

        return {
            "http_method": self.http_method,
            "canonical_url": self.canonical_url,
            "content_type": self.content_type,
            "outbound_data": [k.value for k in self.outbound_data],
            "payload_byte_size": self.payload_byte_size,
            "envelope_digest_prefix": str(self.envelope_digest)[:12],
        }


__all__ = [
    "CredentialInjectionSlot",
    "NON_SECRET_HEADERS_SCHEMA_VERSION",
    "NonSecretHeader",
    "OutboundDataKind",
    "OutboundRequest",
    "PREPARED_BODY_SCHEMA_VERSION",
    "QueryPolicyKind",
    "REQUEST_ENVELOPE_SCHEMA_VERSION",
]
