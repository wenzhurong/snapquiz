"""Provider-neutral immutable contracts at the Adapter/Transport boundary."""
from __future__ import annotations

import hashlib
import json
from enum import Enum
from uuid import UUID

from snapquiz.domain._validation import (
    require_digest,
    require_optional_text,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, canonical_json_bytes, digest256
from snapquiz.domain.solve import UsageSummary

TRANSPORT_RESPONSE_SCHEMA_VERSION = "snapquiz.transport-response.v1"
TRANSPORT_RESPONSE_BODY_SCHEMA_VERSION = "snapquiz.transport-response-body.v1"
ANSWER_CANDIDATE_SCHEMA_VERSION = "snapquiz.answer-candidate.v1"
MAX_PROVIDER_RESPONSE_BYTES = 2 * 1_024 * 1_024
MAX_PROVIDER_REQUEST_ID_CHARS = 256

_ANSWER_CANDIDATE_AUTHORITY = object()


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
    """Bound, bounded response bytes produced by the future W08/W09 transport."""

    __slots__ = (
        "plan_id",
        "stage_id",
        "operation_id",
        "request_envelope_digest",
        "http_status",
        "provider_request_id",
        "response_body_digest",
        "response_byte_size",
        "_body",
    )

    def __init__(
        self,
        *,
        plan_id: UUID,
        stage_id: UUID,
        operation_id: UUID,
        request_envelope_digest: Digest256,
        http_status: int,
        provider_request_id: str | None,
        body: bytes,
    ) -> None:
        for name, value in (
            ("plan_id", plan_id),
            ("stage_id", stage_id),
            ("operation_id", operation_id),
        ):
            require_uuid(value, name)
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
        for name, value in (
            ("plan_id", plan_id),
            ("stage_id", stage_id),
            ("operation_id", operation_id),
            ("request_envelope_digest", request_envelope_digest),
            ("http_status", http_status),
            ("provider_request_id", provider_request_id),
            ("response_byte_size", len(body)),
            ("response_body_digest", _response_body_digest(body)),
            ("_body", body),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("TransportResponse is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "TransportResponse":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "TransportResponse("
            f"plan_id={self.plan_id!r}, stage_id={self.stage_id!r}, "
            f"operation_id={self.operation_id!r}, "
            f"http_status={self.http_status!r}, "
            f"response_byte_size={self.response_byte_size!r})"
        )

    @property
    def body(self) -> bytes:
        return self._body

    def validate_integrity(self) -> None:
        for name in ("plan_id", "stage_id", "operation_id"):
            require_uuid(getattr(self, name), name)
        require_digest(self.request_envelope_digest, "request_envelope_digest")
        require_digest(self.response_body_digest, "response_body_digest")
        require_plain_int(self.http_status, "http_status", minimum=100)
        if self.http_status > 599:
            raise ValueError("http_status must be <= 599")
        require_plain_int(
            self.response_byte_size,
            "response_byte_size",
            minimum=0,
        )
        require_optional_text(
            self.provider_request_id,
            "provider_request_id",
            max_length=MAX_PROVIDER_REQUEST_ID_CHARS,
        )
        if (
            type(self._body) is not bytes
            or len(self._body) != self.response_byte_size
            or len(self._body) > MAX_PROVIDER_RESPONSE_BYTES
            or _response_body_digest(self._body) != self.response_body_digest
        ):
            raise ValueError("transport response body integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "plan_id": str(self.plan_id),
            "stage_id": str(self.stage_id),
            "operation_id": str(self.operation_id),
            "http_status": self.http_status,
            "response_byte_size": self.response_byte_size,
            "has_provider_request_id": self.provider_request_id is not None,
        }


@runtime_final
class AnswerCandidateResult:
    """Untrusted candidate bound to one request, envelope and response body."""

    __slots__ = (
        "request_id",
        "plan_id",
        "plan_digest",
        "stage_id",
        "operation_id",
        "invocation_digest",
        "request_envelope_digest",
        "response_body_digest",
        "candidate_payload_digest",
        "refusal",
        "finish_reason",
        "provider_request_id",
        "usage",
        "candidate_digest",
        "_candidate_payload_bytes",
    )

    def __init__(
        self,
        *,
        request_id: UUID,
        plan_id: UUID,
        plan_digest: Digest256,
        stage_id: UUID,
        operation_id: UUID,
        invocation_digest: Digest256,
        request_envelope_digest: Digest256,
        response_body_digest: Digest256,
        candidate_payload: dict[str, object] | None,
        refusal: NormalizedRefusal | None,
        finish_reason: str | None,
        provider_request_id: str | None,
        usage: UsageSummary | None,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ANSWER_CANDIDATE_AUTHORITY:
            raise TypeError(
                "AnswerCandidateResult can only be created by a trusted Adapter"
            )
        for name, value in (
            ("request_id", request_id),
            ("plan_id", plan_id),
            ("stage_id", stage_id),
            ("operation_id", operation_id),
        ):
            require_uuid(value, name)
        for name, value in (
            ("plan_digest", plan_digest),
            ("invocation_digest", invocation_digest),
            ("request_envelope_digest", request_envelope_digest),
            ("response_body_digest", response_body_digest),
        ):
            require_digest(value, name)
        if candidate_payload is None:
            payload_bytes = b""
            if not isinstance(refusal, NormalizedRefusal):
                raise ValueError("an empty candidate requires a normalized refusal")
        else:
            if type(candidate_payload) is not dict or refusal is not None:
                raise ValueError("candidate payload and refusal are mutually exclusive")
            payload_bytes = canonical_json_bytes(candidate_payload)
        if finish_reason is not None:
            require_text(finish_reason, "finish_reason", max_length=128)
        require_optional_text(
            provider_request_id,
            "provider_request_id",
            max_length=MAX_PROVIDER_REQUEST_ID_CHARS,
        )
        if usage is not None and type(usage) is not UsageSummary:
            raise ValueError("usage must be UsageSummary or null")
        if (
            usage is not None
            and usage.input_tokens is not None
            and usage.output_tokens is not None
            and usage.total_tokens != usage.input_tokens + usage.output_tokens
        ):
            raise ValueError("usage total must equal input plus output tokens")
        candidate_payload_digest = digest256(
            "AnswerCandidatePayload",
            ANSWER_CANDIDATE_SCHEMA_VERSION,
            {
                "present": candidate_payload is not None,
                "sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "byte_size": len(payload_bytes),
            },
        )
        for name, value in (
            ("request_id", request_id),
            ("plan_id", plan_id),
            ("plan_digest", plan_digest),
            ("stage_id", stage_id),
            ("operation_id", operation_id),
            ("invocation_digest", invocation_digest),
            ("request_envelope_digest", request_envelope_digest),
            ("response_body_digest", response_body_digest),
            ("candidate_payload_digest", candidate_payload_digest),
            ("refusal", refusal),
            ("finish_reason", finish_reason),
            ("provider_request_id", provider_request_id),
            ("usage", usage),
            ("_candidate_payload_bytes", payload_bytes),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "candidate_digest",
            digest256(
                "AnswerCandidateResult",
                ANSWER_CANDIDATE_SCHEMA_VERSION,
                self._digest_payload(),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AnswerCandidateResult is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "AnswerCandidateResult":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "AnswerCandidateResult("
            f"request_id={self.request_id!r}, plan_id={self.plan_id!r}, "
            f"stage_id={self.stage_id!r}, operation_id={self.operation_id!r}, "
            f"has_candidate={bool(self._candidate_payload_bytes)!r}, "
            f"refusal={self.refusal!r}, finish_reason={self.finish_reason!r})"
        )

    @property
    def candidate_payload(self) -> dict[str, object] | None:
        if not self._candidate_payload_bytes:
            return None
        payload = json.loads(self._candidate_payload_bytes.decode("utf-8"))
        if type(payload) is not dict:
            raise ValueError("candidate payload integrity mismatch")
        return payload

    def _digest_payload(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "stage_id": self.stage_id,
            "operation_id": self.operation_id,
            "invocation_digest": self.invocation_digest,
            "request_envelope_digest": self.request_envelope_digest,
            "response_body_digest": self.response_body_digest,
            "candidate_payload_digest": self.candidate_payload_digest,
            "refusal": self.refusal.value if self.refusal is not None else None,
            "finish_reason": self.finish_reason,
            "provider_request_id": self.provider_request_id,
            "usage": (
                None
                if self.usage is None
                else {
                    "input_tokens": self.usage.input_tokens,
                    "output_tokens": self.usage.output_tokens,
                    "total_tokens": self.usage.total_tokens,
                }
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "AnswerCandidateResult",
            ANSWER_CANDIDATE_SCHEMA_VERSION,
            self._digest_payload(),
        )

    def validate_integrity(self) -> None:
        for name in ("request_id", "plan_id", "stage_id", "operation_id"):
            require_uuid(getattr(self, name), name)
        for name in (
            "plan_digest",
            "invocation_digest",
            "request_envelope_digest",
            "response_body_digest",
            "candidate_payload_digest",
            "candidate_digest",
        ):
            require_digest(getattr(self, name), name)
        if self.finish_reason is not None:
            require_text(self.finish_reason, "finish_reason", max_length=128)
        require_optional_text(
            self.provider_request_id,
            "provider_request_id",
            max_length=MAX_PROVIDER_REQUEST_ID_CHARS,
        )
        if self.usage is not None:
            if type(self.usage) is not UsageSummary:
                raise ValueError("candidate usage changed")
            checked_usage = UsageSummary(
                input_tokens=self.usage.input_tokens,
                output_tokens=self.usage.output_tokens,
                total_tokens=self.usage.total_tokens,
            )
            if checked_usage != self.usage or (
                checked_usage.input_tokens is not None
                and checked_usage.output_tokens is not None
                and checked_usage.total_tokens
                != checked_usage.input_tokens + checked_usage.output_tokens
            ):
                raise ValueError("candidate usage changed")
        if self._candidate_payload_bytes:
            payload = self.candidate_payload
            expected_payload_digest = digest256(
                "AnswerCandidatePayload",
                ANSWER_CANDIDATE_SCHEMA_VERSION,
                {
                    "present": True,
                    "sha256": hashlib.sha256(
                        self._candidate_payload_bytes
                    ).hexdigest(),
                    "byte_size": len(self._candidate_payload_bytes),
                },
            )
            if (
                type(payload) is not dict
                or canonical_json_bytes(payload) != self._candidate_payload_bytes
                or self.refusal is not None
            ):
                raise ValueError("candidate payload integrity mismatch")
        else:
            expected_payload_digest = digest256(
                "AnswerCandidatePayload",
                ANSWER_CANDIDATE_SCHEMA_VERSION,
                {
                    "present": False,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "byte_size": 0,
                },
            )
            if not isinstance(self.refusal, NormalizedRefusal):
                raise ValueError("candidate refusal integrity mismatch")
        if (
            expected_payload_digest != self.candidate_payload_digest
            or self.recompute_digest() != self.candidate_digest
        ):
            raise ValueError("answer candidate integrity mismatch")

    def validate_binding(
        self,
        *,
        request_id: UUID,
        plan_id: UUID,
        plan_digest: Digest256,
        stage_id: UUID,
        operation_id: UUID,
        invocation_digest: Digest256,
        request_envelope_digest: Digest256,
    ) -> None:
        self.validate_integrity()
        if (
            self.request_id != request_id
            or self.plan_id != plan_id
            or self.plan_digest != plan_digest
            or self.stage_id != stage_id
            or self.operation_id != operation_id
            or self.invocation_digest != invocation_digest
            or self.request_envelope_digest != request_envelope_digest
        ):
            raise ValueError("answer candidate is bound to another execution")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "request_id": str(self.request_id),
            "plan_id": str(self.plan_id),
            "stage_id": str(self.stage_id),
            "operation_id": str(self.operation_id),
            "has_candidate": bool(self._candidate_payload_bytes),
            "refusal": self.refusal.value if self.refusal is not None else None,
            "finish_reason": self.finish_reason,
            "has_provider_request_id": self.provider_request_id is not None,
            "has_usage": self.usage is not None,
        }


def _create_answer_candidate_result(**kwargs: object) -> AnswerCandidateResult:
    """Private construction hook used by audited Adapter implementations."""

    return AnswerCandidateResult(_authority=_ANSWER_CANDIDATE_AUTHORITY, **kwargs)


__all__ = [
    "ANSWER_CANDIDATE_SCHEMA_VERSION",
    "MAX_PROVIDER_REQUEST_ID_CHARS",
    "MAX_PROVIDER_RESPONSE_BYTES",
    "NormalizedRefusal",
    "TRANSPORT_RESPONSE_BODY_SCHEMA_VERSION",
    "TRANSPORT_RESPONSE_SCHEMA_VERSION",
    "AnswerCandidateResult",
    "TransportResponse",
]
