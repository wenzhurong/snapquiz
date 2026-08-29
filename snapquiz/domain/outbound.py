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
from snapquiz.domain.plan import (
    CredentialInjectionSlot,
    ExecutionPlan,
    OutboundDataKind,
    QueryPolicyKind,
)
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
class PreparedOutbound:
    """Immutable prepared bytes.

    This intentionally is not a dataclass: generic ``dataclasses.asdict``
    serializers must fail instead of walking into body/header/digest fields.
    Use :meth:`safe_metadata` for structured logs.
    """

    plan_id: UUID
    plan_digest: Digest256
    stage_id: UUID
    operation_id: UUID
    source_ids: tuple[UUID, ...]
    source_digests: tuple[Digest256, ...]
    capture_scope_fingerprint: Digest256 | ContractMarker
    http_method: str
    canonical_url: str
    content_type: str
    non_secret_headers: tuple[NonSecretHeader, ...]
    credential_binding_digest: Digest256 | ContractMarker
    outbound_data: tuple[OutboundDataKind, ...]
    body: bytes
    non_secret_headers_digest: Digest256
    body_digest: Digest256
    payload_byte_size: int
    request_envelope_digest: Digest256

    __slots__ = (
        "plan_id",
        "plan_digest",
        "stage_id",
        "operation_id",
        "source_ids",
        "source_digests",
        "capture_scope_fingerprint",
        "http_method",
        "canonical_url",
        "content_type",
        "non_secret_headers",
        "credential_binding_digest",
        "outbound_data",
        "body",
        "non_secret_headers_digest",
        "body_digest",
        "payload_byte_size",
        "request_envelope_digest",
    )

    def __init__(
        self,
        *,
        plan_id: UUID,
        plan_digest: Digest256,
        stage_id: UUID,
        operation_id: UUID,
        source_ids: tuple[UUID, ...],
        source_digests: tuple[Digest256, ...],
        capture_scope_fingerprint: Digest256 | ContractMarker,
        http_method: str,
        canonical_url: str,
        content_type: str,
        non_secret_headers: tuple[NonSecretHeader, ...],
        credential_binding_digest: Digest256 | ContractMarker,
        outbound_data: tuple[OutboundDataKind, ...],
        body: bytes,
    ) -> None:
        for name, value in (
            ("plan_id", plan_id),
            ("plan_digest", plan_digest),
            ("stage_id", stage_id),
            ("operation_id", operation_id),
            ("source_ids", source_ids),
            ("source_digests", source_digests),
            ("capture_scope_fingerprint", capture_scope_fingerprint),
            ("http_method", http_method),
            ("canonical_url", canonical_url),
            ("content_type", content_type),
            ("non_secret_headers", non_secret_headers),
            ("credential_binding_digest", credential_binding_digest),
            ("outbound_data", outbound_data),
            ("body", body),
        ):
            object.__setattr__(self, name, value)

        for name in ("plan_id", "stage_id", "operation_id"):
            require_uuid(getattr(self, name), name)
        require_digest(self.plan_digest, "plan_digest")
        if type(self.source_ids) is not tuple or not self.source_ids:
            raise ValueError("source_ids must be a non-empty tuple")
        if type(self.source_digests) is not tuple or not self.source_digests:
            raise ValueError("source_digests must be a non-empty tuple")
        if len(self.source_ids) != len(self.source_digests):
            raise ValueError("source ids and digests must have equal length")
        for source_id in self.source_ids:
            require_uuid(source_id, "source id")
        for source_digest in self.source_digests:
            require_digest(source_digest, "source digest")
        if len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("source_ids must be unique")
        if len(set(self.source_digests)) != len(self.source_digests):
            raise ValueError("source_digests must be unique")
        if self.capture_scope_fingerprint is not ContractMarker.NOT_APPLICABLE:
            if isinstance(self.capture_scope_fingerprint, ContractMarker):
                raise ValueError("capture_scope_fingerprint cannot be unknown")
            require_digest(
                self.capture_scope_fingerprint, "capture_scope_fingerprint"
            )
        method = require_text(self.http_method, "http_method", max_length=32)
        if method != method.upper() or HTTP_TOKEN_RE.fullmatch(method) is None:
            raise ValueError("http_method must be an uppercase HTTP token")
        self._validate_canonical_url()
        content_type = require_text(self.content_type, "content_type", max_length=256)
        if content_type != content_type.lower():
            raise ValueError("content_type must be normalized lowercase text")
        if type(self.non_secret_headers) is not tuple or not all(
            type(header) is NonSecretHeader for header in self.non_secret_headers
        ):
            raise ValueError("non_secret_headers must contain NonSecretHeader values")
        header_names = tuple(header.lowercase_name for header in self.non_secret_headers)
        if header_names != tuple(sorted(header_names)) or len(set(header_names)) != len(
            header_names
        ):
            raise ValueError("non_secret_headers must be unique and canonically sorted")
        if self.credential_binding_digest is not ContractMarker.NOT_APPLICABLE:
            if isinstance(self.credential_binding_digest, ContractMarker):
                raise ValueError("credential_binding_digest cannot be unknown")
            require_digest(self.credential_binding_digest, "credential_binding_digest")
        if type(self.outbound_data) is not tuple or not self.outbound_data:
            raise ValueError("outbound_data must be a non-empty tuple")
        if not all(isinstance(item, OutboundDataKind) for item in self.outbound_data):
            raise ValueError("outbound_data must contain OutboundDataKind values")
        canonical_data = tuple(sorted(self.outbound_data, key=lambda item: item.value))
        if self.outbound_data != canonical_data or len(set(self.outbound_data)) != len(
            self.outbound_data
        ):
            raise ValueError("outbound_data must be unique and canonically sorted")
        if OutboundDataKind.IMAGE in self.outbound_data:
            if self.capture_scope_fingerprint is ContractMarker.NOT_APPLICABLE:
                raise ValueError("image outbound requires a capture scope fingerprint")
        if type(self.body) is not bytes or not self.body:
            raise ValueError("body must be non-empty immutable bytes")

        object.__setattr__(self, "payload_byte_size", len(self.body))
        object.__setattr__(self, "body_digest", self._compute_body_digest())
        object.__setattr__(
            self,
            "non_secret_headers_digest",
            self._compute_non_secret_headers_digest(),
        )
        object.__setattr__(
            self,
            "request_envelope_digest",
            self._compute_request_envelope_digest(),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PreparedOutbound is immutable")

    def __repr__(self) -> str:
        return (
            "PreparedOutbound("
            f"plan_id={self.plan_id!r}, stage_id={self.stage_id!r}, "
            f"operation_id={self.operation_id!r}, http_method={self.http_method!r}, "
            f"canonical_url={self.canonical_url!r}, content_type={self.content_type!r}, "
            f"outbound_data={self.outbound_data!r}, payload_byte_size={self.payload_byte_size!r})"
        )

    def __deepcopy__(self, memo: dict[int, object]) -> "PreparedOutbound":
        return self

    def _validate_canonical_url(self) -> None:
        require_canonical_http_url(
            self.canonical_url, "canonical_url", allow_query=False
        )

    def _compute_body_digest(self) -> Digest256:
        return digest256(
            "PreparedOutboundBody",
            PREPARED_BODY_SCHEMA_VERSION,
            {
                "byte_size": len(self.body),
                "sha256": hashlib.sha256(self.body).hexdigest(),
            },
        )

    def _compute_non_secret_headers_digest(self) -> Digest256:
        return digest256(
            "NonSecretHeaders",
            NON_SECRET_HEADERS_SCHEMA_VERSION,
            tuple(header.as_digest_payload() for header in self.non_secret_headers),
        )

    def _compute_request_envelope_digest(self) -> Digest256:
        credential_digest = (
            self.credential_binding_digest.value
            if isinstance(self.credential_binding_digest, ContractMarker)
            else self.credential_binding_digest
        )
        return digest256(
            "RequestEnvelope",
            REQUEST_ENVELOPE_SCHEMA_VERSION,
            {
                "http_method": self.http_method,
                "canonical_url": self.canonical_url,
                "content_type": self.content_type,
                "non_secret_headers_digest": self.non_secret_headers_digest,
                "credential_binding_digest": credential_digest,
                "body_digest": self.body_digest,
                "payload_byte_size": self.payload_byte_size,
            },
        )

    def validate_integrity(self) -> None:
        """Recompute every derived digest to detect post-construction tampering."""

        if type(self.body) is not bytes or len(self.body) != self.payload_byte_size:
            raise ValueError("prepared outbound body size changed")
        if self.body_digest != self._compute_body_digest():
            raise ValueError("prepared outbound body digest changed")
        if self.non_secret_headers_digest != self._compute_non_secret_headers_digest():
            raise ValueError("prepared outbound header digest changed")
        if self.request_envelope_digest != self._compute_request_envelope_digest():
            raise ValueError("prepared outbound envelope digest changed")

    def safe_metadata(self) -> dict[str, object]:
        """Return a log-safe projection; never serialize this object with asdict()."""

        return {
            "plan_id": str(self.plan_id),
            "stage_id": str(self.stage_id),
            "operation_id": str(self.operation_id),
            "http_method": self.http_method,
            "canonical_url": self.canonical_url,
            "content_type": self.content_type,
            "outbound_data": tuple(item.value for item in self.outbound_data),
            "payload_byte_size": self.payload_byte_size,
            "plan_digest_prefix": str(self.plan_digest)[:12],
            "request_envelope_digest_prefix": str(self.request_envelope_digest)[:12],
        }


def validate_prepared_outbound_against_plan(
    prepared: PreparedOutbound, plan: ExecutionPlan
) -> None:
    """Bind one prepared envelope to one frozen plan network operation."""

    if type(prepared) is not PreparedOutbound:
        raise TypeError("prepared must be PreparedOutbound")
    if type(plan) is not ExecutionPlan:
        raise TypeError("plan must be ExecutionPlan")
    if plan.recompute_digest() != plan.plan_digest:
        raise ValueError("plan digest does not match the frozen plan")
    prepared.validate_integrity()
    if prepared.plan_id != plan.plan_id or prepared.plan_digest != plan.plan_digest:
        raise ValueError("prepared outbound is bound to another plan")
    stage = next((item for item in plan.stages if item.stage_id == prepared.stage_id), None)
    if stage is None:
        raise ValueError("prepared outbound stage is absent from the plan")
    operation = next(
        (
            item
            for item in stage.network_operations
            if item.operation_id == prepared.operation_id
        ),
        None,
    )
    if operation is None:
        raise ValueError("prepared outbound operation is absent from the stage")
    if prepared.http_method != operation.http_method:
        raise ValueError("prepared outbound method differs from the plan")
    if prepared.content_type != operation.content_type:
        raise ValueError("prepared outbound content type differs from the plan")
    if any(
        header.lowercase_name not in operation.allowed_non_secret_headers
        for header in prepared.non_secret_headers
    ):
        raise ValueError("prepared outbound contains an unplanned header")
    if prepared.outbound_data != operation.outbound_data:
        raise ValueError("prepared outbound data kinds differ from the plan")
    if operation.credential_injection_slot is CredentialInjectionSlot.NOT_APPLICABLE:
        expected_credential_digest: Digest256 | ContractMarker = (
            ContractMarker.NOT_APPLICABLE
        )
    else:
        expected_credential_digest = stage.credential_binding_digest
    if prepared.credential_binding_digest != expected_credential_digest:
        raise ValueError("prepared outbound credential binding differs from the plan")
    if "{" in operation.canonical_endpoint or "}" in operation.canonical_endpoint:
        raise ValueError("path-template expansion requires the routing policy layer")
    if operation.canonical_query_policy.kind is not QueryPolicyKind.EMPTY:
        raise ValueError("exact query policies require the M2 endpoint-profile gate")
    expected_url = operation.canonical_endpoint
    if prepared.canonical_url != expected_url:
        raise ValueError("prepared outbound URL differs from the planned endpoint")
