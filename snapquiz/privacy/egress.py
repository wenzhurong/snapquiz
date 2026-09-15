"""Exact outbound preview and one-shot egress approval contracts for W08.

This module is deliberately local-only.  It does not read credentials, build a
client, inspect the environment, or perform network I/O.  W09 may consume the
static authority produced here, but it must not weaken any binding.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
from threading import RLock
from typing import Callable, TypeVar
from uuid import UUID, uuid5

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.adapters.openai_chat_compatible import (
    OpenAIChatCompatibleAdapter,
)
from snapquiz.config.profiles import GLM_ADAPTER_FAMILY, GLM_ADAPTER_VERSION
from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CancelledError, EndpointPolicyError
from snapquiz.domain.outbound import (
    PreparedOutbound,
    validate_prepared_outbound_against_plan,
)
from snapquiz.domain.plan import ExecutionPlanStage, OutboundDataKind
from snapquiz.domain.policy import ContractMarker
from snapquiz.pipelines.contracts import StageInvocation
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentLedger,
    PrivacyGate,
    _ATOMIC_PRIVACY_AUTHORITY,
)
from snapquiz.routing.planner import PlannedExecution


EGRESS_PREVIEW_SCHEMA_VERSION = "snapquiz.egress-preview.v1"
EGRESS_PREVIEW_DECISION_SCHEMA_VERSION = "snapquiz.egress-preview-decision.v1"
EGRESS_APPROVAL_SCHEMA_VERSION = "snapquiz.egress-approval.v1"
EGRESS_POLICY_VERSION = "snapquiz.egress-policy.phase1-pass-through.v1"
EGRESS_APPROVAL_LIFETIME = timedelta(minutes=5)

_PREVIEW_AUTHORITY = object()
_PREVIEW_DECISION_AUTHORITY = object()
_APPROVAL_AUTHORITY = object()
_APPROVAL_LEDGER_AUTHORITY = object()
_EGRESS_SESSION_AUTHORITY = object()
_EGRESS_ATTEMPT_AUTHORITY = object()
_ENVELOPE_ATTESTATION_AUTHORITY = object()
_EGRESS_UUID_NAMESPACE = UUID("d0ac6789-4649-5e0f-8e80-30057112354a")
_T = TypeVar("_T")

_ENVELOPE_ATTESTATION_SCHEMA_VERSION = "snapquiz.envelope-attestation.v1"
_TRUSTED_DIRECT_MULTIMODAL_ADAPTERS = (
    (
        GLM_ADAPTER_FAMILY,
        GLM_ADAPTER_VERSION,
        OpenAIChatCompatibleAdapter,
    ),
)


def _trusted_adapter_catalog_match(
    *,
    adapter_family: str,
    adapter_version: str,
) -> type[DirectMultimodalAdapter] | None:
    """Return one exact catalog entry without provider-specific branching."""

    matches = tuple(
        adapter_type
        for family, version, adapter_type in _TRUSTED_DIRECT_MULTIMODAL_ADAPTERS
        if family == adapter_family and version == adapter_version
    )
    if len(matches) != 1:
        return None
    adapter_type = matches[0]
    try:
        is_adapter_type = (
            type(adapter_type) is type
            and issubclass(adapter_type, DirectMultimodalAdapter)
            and adapter_type is not DirectMultimodalAdapter
        )
    except TypeError:
        is_adapter_type = False
    if (
        not is_adapter_type
        or adapter_type.adapter_family != adapter_family
        or adapter_type.adapter_version != adapter_version
    ):
        return None
    return adapter_type


def _egress_error(message: str, *, stage: str = "egress_gate") -> EndpointPolicyError:
    return EndpointPolicyError(stage=stage, safe_message=message, retryable=False)


def _marker_payload(value: Digest256 | ContractMarker) -> object:
    return value.value if isinstance(value, ContractMarker) else value


def _billable_payload(value: bool | ContractMarker) -> object:
    return value.value if isinstance(value, ContractMarker) else value


def _preview_payload(preview: "EgressPreview") -> dict[str, object]:
    return {
        "policy_version": preview.policy_version,
        "request_id": preview.request_id,
        "plan_id": preview.plan_id,
        "plan_digest": preview.plan_digest,
        "planned_execution_digest": preview.planned_execution_digest,
        "registry_revision": preview.registry_revision,
        "registry_digest": preview.registry_digest,
        "privacy_authorization_id": preview.privacy_authorization_id,
        "privacy_authorization_digest": preview.privacy_authorization_digest,
        "stage_id": preview.stage_id,
        "operation_id": preview.operation_id,
        "invocation_id": preview.invocation_id,
        "invocation_digest": preview.invocation_digest,
        "source_ids": preview.source_ids,
        "source_digests": preview.source_digests,
        "capture_scope_fingerprint": _marker_payload(
            preview.capture_scope_fingerprint
        ),
        "provider_profile_id": preview.provider_profile_id,
        "http_method": preview.http_method,
        "canonical_url": preview.canonical_url,
        "content_type": preview.content_type,
        "non_secret_headers_digest": preview.non_secret_headers_digest,
        "credential_binding_digest": _marker_payload(
            preview.credential_binding_digest
        ),
        "outbound_data": tuple(item.value for item in preview.outbound_data),
        "body_digest": preview.body_digest,
        "payload_byte_size": preview.payload_byte_size,
        "request_envelope_digest": preview.request_envelope_digest,
        "preview_image_sha256": preview.preview_image_sha256,
        "preview_image_mime_type": preview.preview_image_mime_type,
        "preview_image_width_px": preview.preview_image_width_px,
        "preview_image_height_px": preview.preview_image_height_px,
        "user_hint_digest": preview.user_hint_digest,
    }


@runtime_final
class EgressPreview:
    """Ephemeral exact review subject handed only to the trusted UI boundary.

    The trusted controller must not persist the image or hint after its review
    action completes.  W08 drops its own references and never stores this
    object in an approval ledger, but cannot securely erase immutable bytes
    that are also owned by the capture and prepared-outbound authorities.
    """

    __slots__ = (
        "policy_version",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "registry_revision",
        "registry_digest",
        "privacy_authorization_id",
        "privacy_authorization_digest",
        "stage_id",
        "operation_id",
        "invocation_id",
        "invocation_digest",
        "source_ids",
        "source_digests",
        "capture_scope_fingerprint",
        "provider_profile_id",
        "http_method",
        "canonical_url",
        "content_type",
        "non_secret_headers_digest",
        "credential_binding_digest",
        "outbound_data",
        "body_digest",
        "payload_byte_size",
        "request_envelope_digest",
        "preview_image_sha256",
        "preview_image_mime_type",
        "preview_image_width_px",
        "preview_image_height_px",
        "user_hint_digest",
        "preview_subject_digest",
        "_image_bytes",
        "_user_hint",
    )

    def __init__(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PREVIEW_AUTHORITY:
            raise TypeError("EgressPreview can only be created by EgressGate")
        stage = next(
            item for item in planned.plan.stages if item.stage_id == invocation.stage_id
        )
        capture = invocation.input
        artifact = capture.artifact
        values = (
            ("policy_version", EGRESS_POLICY_VERSION),
            ("request_id", invocation.request_id),
            ("plan_id", prepared.plan_id),
            ("plan_digest", prepared.plan_digest),
            ("planned_execution_digest", planned.planned_execution_digest),
            ("registry_revision", planned.resolved_pipeline.registry_revision),
            ("registry_digest", planned.resolved_pipeline.registry_digest),
            ("privacy_authorization_id", authorization.authorization_id),
            ("privacy_authorization_digest", authorization.authorization_digest),
            ("stage_id", prepared.stage_id),
            ("operation_id", prepared.operation_id),
            ("invocation_id", invocation.invocation_id),
            ("invocation_digest", invocation.invocation_digest),
            ("source_ids", prepared.source_ids),
            ("source_digests", prepared.source_digests),
            ("capture_scope_fingerprint", prepared.capture_scope_fingerprint),
            ("provider_profile_id", stage.provider_profile_id),
            ("http_method", prepared.http_method),
            ("canonical_url", prepared.canonical_url),
            ("content_type", prepared.content_type),
            ("non_secret_headers_digest", prepared.non_secret_headers_digest),
            ("credential_binding_digest", prepared.credential_binding_digest),
            ("outbound_data", prepared.outbound_data),
            ("body_digest", prepared.body_digest),
            ("payload_byte_size", prepared.payload_byte_size),
            ("request_envelope_digest", prepared.request_envelope_digest),
            ("preview_image_sha256", capture.artifact_sha256),
            ("preview_image_mime_type", capture.artifact_mime_type),
            ("preview_image_width_px", capture.artifact_width_px),
            ("preview_image_height_px", capture.artifact_height_px),
            (
                "user_hint_digest",
                digest256(
                    "EgressPreviewUserHint",
                    EGRESS_PREVIEW_SCHEMA_VERSION,
                    {"user_hint": invocation.user_hint},
                ),
            ),
            ("_image_bytes", artifact.data),
            ("_user_hint", invocation.user_hint),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "preview_subject_digest",
            digest256(
                "EgressPreview",
                EGRESS_PREVIEW_SCHEMA_VERSION,
                _preview_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("EgressPreview is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "EgressPreview":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "EgressPreview("
            f"request_id={self.request_id!r}, stage_id={self.stage_id!r}, "
            f"operation_id={self.operation_id!r}, provider_profile_id="
            f"{self.provider_profile_id!r}, payload_byte_size="
            f"{self.payload_byte_size!r})"
        )

    @property
    def image_bytes(self) -> bytes:
        return self._image_bytes

    @property
    def user_hint(self) -> str | None:
        return self._user_hint

    def validate_integrity(self) -> None:
        require_digest(self.preview_subject_digest, "preview_subject_digest")
        require_digest(self.preview_image_sha256, "preview_image_sha256")
        require_digest(self.user_hint_digest, "user_hint_digest")
        if type(self._image_bytes) is not bytes or not self._image_bytes:
            raise ValueError("preview image bytes are invalid")
        if Digest256(hashlib.sha256(self._image_bytes).hexdigest()) != (
            self.preview_image_sha256
        ):
            raise ValueError("preview image bytes changed")
        if self.user_hint_digest != digest256(
            "EgressPreviewUserHint",
            EGRESS_PREVIEW_SCHEMA_VERSION,
            {"user_hint": self._user_hint},
        ):
            raise ValueError("preview user hint changed")
        if self.preview_subject_digest != digest256(
            "EgressPreview",
            EGRESS_PREVIEW_SCHEMA_VERSION,
            _preview_payload(self),
        ):
            raise ValueError("preview subject integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "request_id": str(self.request_id),
            "stage_id": str(self.stage_id),
            "operation_id": str(self.operation_id),
            "provider_profile_id": self.provider_profile_id,
            "http_method": self.http_method,
            "canonical_url": self.canonical_url,
            "outbound_data": tuple(item.value for item in self.outbound_data),
            "payload_byte_size": self.payload_byte_size,
            "preview_image_mime_type": self.preview_image_mime_type,
            "preview_image_width_px": self.preview_image_width_px,
            "preview_image_height_px": self.preview_image_height_px,
            "has_user_hint": self.user_hint is not None,
        }


def _decision_payload(decision: "EgressPreviewDecision") -> dict[str, object]:
    return {
        "decision_id": decision.decision_id,
        "preview_subject_digest": decision.preview_subject_digest,
        "decided_at": decision.decided_at,
        "approved": decision.approved,
    }


@runtime_final
class EgressPreviewDecision:
    """Factory-only result of one trusted review action."""

    __slots__ = (
        "decision_id",
        "preview_subject_digest",
        "decided_at",
        "approved",
        "decision_digest",
        "_preview",
    )

    def __init__(
        self,
        *,
        decision_id: UUID,
        preview_subject_digest: Digest256,
        decided_at: datetime,
        approved: bool,
        preview: EgressPreview,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PREVIEW_DECISION_AUTHORITY:
            raise TypeError(
                "EgressPreviewDecision can only be created by a PreviewController"
            )
        require_uuid(decision_id, "decision_id")
        require_digest(preview_subject_digest, "preview_subject_digest")
        require_aware_datetime(decided_at, "decided_at")
        if type(approved) is not bool:
            raise ValueError("approved must be bool")
        if type(preview) is not EgressPreview:
            raise TypeError("preview must be EgressPreview")
        preview.validate_integrity()
        if preview.preview_subject_digest != preview_subject_digest:
            raise ValueError("decision preview subject mismatch")
        for name, value in (
            ("decision_id", decision_id),
            ("preview_subject_digest", preview_subject_digest),
            ("decided_at", decided_at),
            ("approved", approved),
            ("_preview", preview),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "decision_digest",
            digest256(
                "EgressPreviewDecision",
                EGRESS_PREVIEW_DECISION_SCHEMA_VERSION,
                _decision_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("EgressPreviewDecision is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "EgressPreviewDecision":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "EgressPreviewDecision("
            f"decision_id={self.decision_id!r}, decided_at={self.decided_at!r}, "
            f"approved={self.approved!r})"
        )

    def validate_integrity(self) -> None:
        require_uuid(self.decision_id, "decision_id")
        require_digest(self.preview_subject_digest, "preview_subject_digest")
        require_digest(self.decision_digest, "decision_digest")
        require_aware_datetime(self.decided_at, "decided_at")
        if type(self.approved) is not bool:
            raise ValueError("preview decision state is invalid")
        if type(self._preview) is not EgressPreview:
            raise ValueError("preview decision authority changed")
        self._preview.validate_integrity()
        if self._preview.preview_subject_digest != self.preview_subject_digest:
            raise ValueError("preview decision subject changed")
        if self.decision_digest != digest256(
            "EgressPreviewDecision",
            EGRESS_PREVIEW_DECISION_SCHEMA_VERSION,
            _decision_payload(self),
        ):
            raise ValueError("preview decision integrity mismatch")


class EgressPreviewController:
    """Trusted UI boundary; never expose this capability to ordinary UI code.

    ``review`` may inspect the ephemeral image and hint only for the current
    action.  A production controller must release its UI buffers and references
    on approve, cancel, and failure.  W08 tests deliberately retain references
    in a deterministic fake so the exact-boundary contract can be asserted.
    """

    __slots__ = ()

    def review(self, preview: EgressPreview) -> EgressPreviewDecision:
        raise NotImplementedError

    @staticmethod
    def approve(
        preview: EgressPreview,
        *,
        decision_id: UUID,
        decided_at: datetime,
    ) -> EgressPreviewDecision:
        if type(preview) is not EgressPreview:
            raise TypeError("preview must be EgressPreview")
        return EgressPreviewDecision(
            decision_id=decision_id,
            preview_subject_digest=preview.preview_subject_digest,
            decided_at=decided_at,
            approved=True,
            preview=preview,
            _authority=_PREVIEW_DECISION_AUTHORITY,
        )

    @staticmethod
    def cancel(
        preview: EgressPreview,
        *,
        decision_id: UUID,
        decided_at: datetime,
    ) -> EgressPreviewDecision:
        if type(preview) is not EgressPreview:
            raise TypeError("preview must be EgressPreview")
        return EgressPreviewDecision(
            decision_id=decision_id,
            preview_subject_digest=preview.preview_subject_digest,
            decided_at=decided_at,
            approved=False,
            preview=preview,
            _authority=_PREVIEW_DECISION_AUTHORITY,
        )


def _approval_identifier_payload(approval: "EgressApproval") -> dict[str, object]:
    return {
        "policy_version": approval.policy_version,
        "request_id": approval.request_id,
        "plan_id": approval.plan_id,
        "plan_digest": approval.plan_digest,
        "planned_execution_digest": approval.planned_execution_digest,
        "registry_revision": approval.registry_revision,
        "registry_digest": approval.registry_digest,
        "privacy_authorization_id": approval.privacy_authorization_id,
        "privacy_authorization_digest": approval.privacy_authorization_digest,
        "stage_id": approval.stage_id,
        "operation_id": approval.operation_id,
        "invocation_id": approval.invocation_id,
        "invocation_digest": approval.invocation_digest,
        "source_ids": approval.source_ids,
        "source_digests": approval.source_digests,
        "capture_scope_fingerprint": _marker_payload(
            approval.capture_scope_fingerprint
        ),
        "preview_decision_id": approval.preview_decision_id,
        "preview_decision_digest": approval.preview_decision_digest,
        "http_method": approval.http_method,
        "canonical_url": approval.canonical_url,
        "content_type": approval.content_type,
        "non_secret_headers_digest": approval.non_secret_headers_digest,
        "credential_binding_digest": _marker_payload(
            approval.credential_binding_digest
        ),
        "outbound_data": tuple(item.value for item in approval.outbound_data),
        "body_digest": approval.body_digest,
        "payload_byte_size": approval.payload_byte_size,
        "request_envelope_digest": approval.request_envelope_digest,
        "max_network_attempts": approval.max_network_attempts,
        "billable": _billable_payload(approval.billable),
        "approved_at": approval.approved_at,
        "expires_at": approval.expires_at,
    }


def _approval_identifier_payload_from_preview(
    *,
    preview: EgressPreview,
    decision: EgressPreviewDecision,
    max_network_attempts: int,
    billable: bool | ContractMarker,
    approved_at: datetime,
    expires_at: datetime,
) -> dict[str, object]:
    return {
        "policy_version": preview.policy_version,
        "request_id": preview.request_id,
        "plan_id": preview.plan_id,
        "plan_digest": preview.plan_digest,
        "planned_execution_digest": preview.planned_execution_digest,
        "registry_revision": preview.registry_revision,
        "registry_digest": preview.registry_digest,
        "privacy_authorization_id": preview.privacy_authorization_id,
        "privacy_authorization_digest": preview.privacy_authorization_digest,
        "stage_id": preview.stage_id,
        "operation_id": preview.operation_id,
        "invocation_id": preview.invocation_id,
        "invocation_digest": preview.invocation_digest,
        "source_ids": preview.source_ids,
        "source_digests": preview.source_digests,
        "capture_scope_fingerprint": _marker_payload(
            preview.capture_scope_fingerprint
        ),
        "preview_decision_id": decision.decision_id,
        "preview_decision_digest": decision.decision_digest,
        "http_method": preview.http_method,
        "canonical_url": preview.canonical_url,
        "content_type": preview.content_type,
        "non_secret_headers_digest": preview.non_secret_headers_digest,
        "credential_binding_digest": _marker_payload(
            preview.credential_binding_digest
        ),
        "outbound_data": tuple(item.value for item in preview.outbound_data),
        "body_digest": preview.body_digest,
        "payload_byte_size": preview.payload_byte_size,
        "request_envelope_digest": preview.request_envelope_digest,
        "max_network_attempts": max_network_attempts,
        "billable": _billable_payload(billable),
        "approved_at": approved_at,
        "expires_at": expires_at,
    }


def _approval_id_for(payload: dict[str, object]) -> UUID:
    seed = digest256(
        "EgressApprovalIdentifier",
        EGRESS_APPROVAL_SCHEMA_VERSION,
        payload,
    )
    return uuid5(_EGRESS_UUID_NAMESPACE, str(seed))


def _approval_terms_payload(approval: "EgressApproval") -> dict[str, object]:
    return {
        "approval_id": approval.approval_id,
        **_approval_identifier_payload(approval),
    }


@runtime_final
class EgressApproval:
    """One immutable revision of permission for one exact outbound envelope."""

    __slots__ = (
        "approval_id",
        "policy_version",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "registry_revision",
        "registry_digest",
        "privacy_authorization_id",
        "privacy_authorization_digest",
        "stage_id",
        "operation_id",
        "invocation_id",
        "invocation_digest",
        "source_ids",
        "source_digests",
        "capture_scope_fingerprint",
        "preview_decision_id",
        "preview_decision_digest",
        "http_method",
        "canonical_url",
        "content_type",
        "non_secret_headers_digest",
        "credential_binding_digest",
        "outbound_data",
        "body_digest",
        "payload_byte_size",
        "request_envelope_digest",
        "max_network_attempts",
        "billable",
        "approved_at",
        "expires_at",
        "consumed_at",
        "revoked_at",
        "approval_terms_digest",
        "approval_digest",
        "_approval_ledger",
    )

    def __init__(
        self,
        *,
        approval_id: UUID,
        preview: EgressPreview,
        decision: EgressPreviewDecision,
        max_network_attempts: int,
        billable: bool | ContractMarker,
        approved_at: datetime,
        expires_at: datetime,
        consumed_at: datetime | None,
        revoked_at: datetime | None,
        approval_ledger: "EgressApprovalLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _APPROVAL_AUTHORITY:
            raise TypeError("EgressApproval can only be created by EgressGate")
        if type(preview) is not EgressPreview:
            raise TypeError("preview must be EgressPreview")
        if type(decision) is not EgressPreviewDecision:
            raise TypeError("decision must be EgressPreviewDecision")
        if type(approval_ledger) is not EgressApprovalLedger:
            raise TypeError("approval_ledger must be EgressApprovalLedger")
        values = (
            ("approval_id", approval_id),
            ("policy_version", preview.policy_version),
            ("request_id", preview.request_id),
            ("plan_id", preview.plan_id),
            ("plan_digest", preview.plan_digest),
            ("planned_execution_digest", preview.planned_execution_digest),
            ("registry_revision", preview.registry_revision),
            ("registry_digest", preview.registry_digest),
            ("privacy_authorization_id", preview.privacy_authorization_id),
            ("privacy_authorization_digest", preview.privacy_authorization_digest),
            ("stage_id", preview.stage_id),
            ("operation_id", preview.operation_id),
            ("invocation_id", preview.invocation_id),
            ("invocation_digest", preview.invocation_digest),
            ("source_ids", preview.source_ids),
            ("source_digests", preview.source_digests),
            ("capture_scope_fingerprint", preview.capture_scope_fingerprint),
            ("preview_decision_id", decision.decision_id),
            ("preview_decision_digest", decision.decision_digest),
            ("http_method", preview.http_method),
            ("canonical_url", preview.canonical_url),
            ("content_type", preview.content_type),
            ("non_secret_headers_digest", preview.non_secret_headers_digest),
            ("credential_binding_digest", preview.credential_binding_digest),
            ("outbound_data", preview.outbound_data),
            ("body_digest", preview.body_digest),
            ("payload_byte_size", preview.payload_byte_size),
            ("request_envelope_digest", preview.request_envelope_digest),
            ("max_network_attempts", max_network_attempts),
            ("billable", billable),
            ("approved_at", approved_at),
            ("expires_at", expires_at),
            ("consumed_at", consumed_at),
            ("revoked_at", revoked_at),
            ("_approval_ledger", approval_ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        self._validate_fields()
        if approval_id != _approval_id_for(_approval_identifier_payload(self)):
            raise ValueError("approval_id does not bind its terms")
        object.__setattr__(
            self,
            "approval_terms_digest",
            digest256(
                "EgressApprovalTerms",
                EGRESS_APPROVAL_SCHEMA_VERSION,
                _approval_terms_payload(self),
            ),
        )
        object.__setattr__(
            self,
            "approval_digest",
            digest256(
                "EgressApproval",
                EGRESS_APPROVAL_SCHEMA_VERSION,
                {
                    "approval_terms_digest": self.approval_terms_digest,
                    "consumed_at": self.consumed_at,
                    "revoked_at": self.revoked_at,
                },
            ),
        )

    def _validate_fields(self) -> None:
        for name in (
            "approval_id",
            "request_id",
            "plan_id",
            "privacy_authorization_id",
            "stage_id",
            "operation_id",
            "invocation_id",
            "preview_decision_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "plan_digest",
            "planned_execution_digest",
            "registry_digest",
            "privacy_authorization_digest",
            "invocation_digest",
            "preview_decision_digest",
            "non_secret_headers_digest",
            "body_digest",
            "request_envelope_digest",
        ):
            require_digest(getattr(self, name), name)
        require_text(self.policy_version, "policy_version")
        require_text(self.registry_revision, "registry_revision", max_length=512)
        require_text(self.http_method, "http_method", max_length=32)
        require_text(self.canonical_url, "canonical_url", max_length=4096)
        require_text(self.content_type, "content_type", max_length=256)
        if type(self.source_ids) is not tuple or not self.source_ids:
            raise ValueError("source_ids must be a non-empty tuple")
        if type(self.source_digests) is not tuple or len(self.source_digests) != len(
            self.source_ids
        ):
            raise ValueError("source_digests must align with source_ids")
        for value in self.source_ids:
            require_uuid(value, "source id")
        for value in self.source_digests:
            require_digest(value, "source digest")
        if self.capture_scope_fingerprint is not ContractMarker.NOT_APPLICABLE:
            require_digest(
                self.capture_scope_fingerprint, "capture_scope_fingerprint"
            )
        if self.credential_binding_digest is not ContractMarker.NOT_APPLICABLE:
            require_digest(
                self.credential_binding_digest, "credential_binding_digest"
            )
        if type(self.outbound_data) is not tuple or not self.outbound_data or not all(
            isinstance(item, OutboundDataKind) for item in self.outbound_data
        ):
            raise ValueError("outbound_data must contain outbound data kinds")
        require_plain_int(self.payload_byte_size, "payload_byte_size", minimum=1)
        require_plain_int(
            self.max_network_attempts, "max_network_attempts", minimum=1
        )
        if type(self.billable) is not bool and self.billable is not ContractMarker.UNKNOWN:
            raise ValueError("billable must be bool or unknown")
        require_aware_datetime(self.approved_at, "approved_at")
        require_aware_datetime(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expiry must be later than approval time")
        for name in ("consumed_at", "revoked_at"):
            value = getattr(self, name)
            if value is not None:
                require_aware_datetime(value, name)
                if value < self.approved_at:
                    raise ValueError(f"{name} cannot predate approval")
        if self.consumed_at is not None and self.consumed_at >= self.expires_at:
            raise ValueError("an expired approval cannot be consumed")
        if self.consumed_at is not None and self.revoked_at is not None:
            raise ValueError("approval cannot be both consumed and revoked")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("EgressApproval is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "EgressApproval":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "EgressApproval("
            f"approval_id={self.approval_id!r}, operation_id="
            f"{self.operation_id!r}, payload_byte_size={self.payload_byte_size!r}, "
            f"approved_at={self.approved_at!r}, expires_at={self.expires_at!r}, "
            f"consumed={self.consumed_at is not None!r}, "
            f"revoked={self.revoked_at is not None!r})"
        )

    def validate_integrity(self) -> None:
        self._validate_fields()
        if type(self._approval_ledger) is not EgressApprovalLedger:
            raise ValueError("approval ledger authority changed")
        if self.approval_id != _approval_id_for(_approval_identifier_payload(self)):
            raise ValueError("approval identifier integrity mismatch")
        if self.approval_terms_digest != digest256(
            "EgressApprovalTerms",
            EGRESS_APPROVAL_SCHEMA_VERSION,
            _approval_terms_payload(self),
        ):
            raise ValueError("approval terms integrity mismatch")
        if self.approval_digest != digest256(
            "EgressApproval",
            EGRESS_APPROVAL_SCHEMA_VERSION,
            {
                "approval_terms_digest": self.approval_terms_digest,
                "consumed_at": self.consumed_at,
                "revoked_at": self.revoked_at,
            },
        ):
            raise ValueError("approval integrity mismatch")

    def validate_active_at(self, now: datetime) -> None:
        require_aware_datetime(now, "now")
        self.validate_integrity()
        if now < self.approved_at:
            raise ValueError("approval is not active yet")
        if now >= self.expires_at:
            raise ValueError("approval has expired")
        if self.consumed_at is not None:
            raise ValueError("approval has already been consumed")
        if self.revoked_at is not None:
            raise ValueError("approval has been revoked")

    def _with_status(
        self,
        *,
        consumed_at: datetime | None,
        revoked_at: datetime | None,
        _authority: object | None = None,
    ) -> "EgressApproval":
        if _authority is not _APPROVAL_LEDGER_AUTHORITY:
            raise TypeError("approval state changes require its ledger")
        replacement = object.__new__(EgressApproval)
        for name in self.__slots__:
            if name not in ("consumed_at", "revoked_at", "approval_digest"):
                object.__setattr__(replacement, name, getattr(self, name))
        object.__setattr__(replacement, "consumed_at", consumed_at)
        object.__setattr__(replacement, "revoked_at", revoked_at)
        object.__setattr__(
            replacement,
            "approval_digest",
            digest256(
                "EgressApproval",
                EGRESS_APPROVAL_SCHEMA_VERSION,
                {
                    "approval_terms_digest": replacement.approval_terms_digest,
                    "consumed_at": consumed_at,
                    "revoked_at": revoked_at,
                },
            ),
        )
        replacement.validate_integrity()
        return replacement

    def safe_metadata(self) -> dict[str, object]:
        return {
            "approval_id": str(self.approval_id),
            "request_id": str(self.request_id),
            "stage_id": str(self.stage_id),
            "operation_id": str(self.operation_id),
            "http_method": self.http_method,
            "canonical_url": self.canonical_url,
            "outbound_data": tuple(item.value for item in self.outbound_data),
            "payload_byte_size": self.payload_byte_size,
            "max_network_attempts": self.max_network_attempts,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "consumed": self.consumed_at is not None,
            "revoked": self.revoked_at is not None,
        }


def _prepared_expectation_digest(prepared: PreparedOutbound) -> Digest256:
    """Hash every exact-envelope field without retaining outbound bytes."""

    if type(prepared) is not PreparedOutbound:
        raise TypeError("prepared must be PreparedOutbound")
    prepared.validate_integrity()
    return digest256(
        "PreparedOutboundExpectation",
        _ENVELOPE_ATTESTATION_SCHEMA_VERSION,
        {
            "plan_id": prepared.plan_id,
            "plan_digest": prepared.plan_digest,
            "stage_id": prepared.stage_id,
            "operation_id": prepared.operation_id,
            "source_ids": prepared.source_ids,
            "source_digests": prepared.source_digests,
            "capture_scope_fingerprint": _marker_payload(
                prepared.capture_scope_fingerprint
            ),
            "http_method": prepared.http_method,
            "canonical_url": prepared.canonical_url,
            "content_type": prepared.content_type,
            "non_secret_headers": tuple(
                header.as_digest_payload()
                for header in prepared.non_secret_headers
            ),
            "non_secret_headers_digest": prepared.non_secret_headers_digest,
            "credential_binding_digest": _marker_payload(
                prepared.credential_binding_digest
            ),
            "outbound_data": tuple(
                item.value for item in prepared.outbound_data
            ),
            "body_sha256": hashlib.sha256(prepared.body).hexdigest(),
            "body_digest": prepared.body_digest,
            "payload_byte_size": prepared.payload_byte_size,
            "request_envelope_digest": prepared.request_envelope_digest,
        },
    )


def _full_egress_subject_digest(
    *,
    planned: PlannedExecution,
    invocation: StageInvocation,
    prepared: PreparedOutbound,
    authorization: AuthorizationContext,
    stage: ExecutionPlanStage,
) -> Digest256:
    """Recompute the complete current authority and exact-envelope subject."""

    if type(planned) is not PlannedExecution:
        raise TypeError("planned must be PlannedExecution")
    if type(invocation) is not StageInvocation:
        raise TypeError("invocation must be StageInvocation")
    if type(prepared) is not PreparedOutbound:
        raise TypeError("prepared must be PreparedOutbound")
    if type(authorization) is not AuthorizationContext:
        raise TypeError("authorization must be AuthorizationContext")
    if type(stage) is not ExecutionPlanStage:
        raise TypeError("stage must be ExecutionPlanStage")
    planned.validate_integrity()
    invocation.validate_integrity()
    authorization.validate_integrity()
    validate_prepared_outbound_against_plan(prepared, planned.plan)
    current_stage = next(
        (
            candidate
            for candidate in planned.plan.stages
            if candidate.stage_id == invocation.stage_id
        ),
        None,
    )
    capture = invocation.input
    if (
        current_stage is not stage
        or invocation.request_id != planned.plan.request_id
        or invocation.plan_id != planned.plan.plan_id
        or invocation.plan_digest != planned.plan.plan_digest
        or invocation.planned_execution_digest
        != planned.planned_execution_digest
        or authorization.plan_id != planned.plan.plan_id
        or authorization.plan_digest != planned.plan.plan_digest
        or authorization.planned_execution_digest
        != planned.planned_execution_digest
        or prepared.plan_id != planned.plan.plan_id
        or prepared.plan_digest != planned.plan.plan_digest
        or prepared.stage_id != stage.stage_id
        or prepared.operation_id
        not in tuple(
            operation.operation_id for operation in stage.network_operations
        )
        or prepared.source_ids
        != (capture.capture_id, invocation.invocation_id)
        or prepared.source_digests
        != (capture.validation_digest, invocation.invocation_digest)
        or prepared.capture_scope_fingerprint != capture.scope_fingerprint
        or capture.privacy_authorization_id
        != authorization.authorization_id
        or capture.privacy_authorization_digest
        != authorization.authorization_digest
        or _trusted_adapter_catalog_match(
            adapter_family=stage.adapter_family,
            adapter_version=stage.adapter_version,
        )
        is None
    ):
        raise ValueError("egress subject binding changed")
    return digest256(
        "FullEgressSubject",
        _ENVELOPE_ATTESTATION_SCHEMA_VERSION,
        {
            "request_id": planned.plan.request_id,
            "plan_id": planned.plan.plan_id,
            "plan_digest": planned.plan.plan_digest,
            "planned_execution_digest": planned.planned_execution_digest,
            "registry_revision": planned.resolved_pipeline.registry_revision,
            "registry_digest": planned.resolved_pipeline.registry_digest,
            "privacy_authorization_id": authorization.authorization_id,
            "privacy_authorization_digest": authorization.authorization_digest,
            "consent_grant_ids": authorization.consent_grant_ids,
            "consent_grant_digests": authorization.consent_grant_digests,
            "stage": stage.as_digest_payload(),
            "invocation_id": invocation.invocation_id,
            "invocation_digest": invocation.invocation_digest,
            "solve_request_digest": invocation.solve_request_digest,
            "input_digest": invocation.input_digest,
            "capture_id": capture.capture_id,
            "capture_validation_digest": capture.validation_digest,
            "capture_scope_fingerprint": _marker_payload(
                capture.scope_fingerprint
            ),
            "adapter_family": stage.adapter_family,
            "adapter_version": stage.adapter_version,
            "prepared_expectation_digest": _prepared_expectation_digest(
                prepared
            ),
        },
    )


def _attestation_payload(
    attestation: "_EnvelopeAttestation",
) -> dict[str, object]:
    return {
        "approval_id": attestation.approval_id,
        "approval_terms_digest": attestation.approval_terms_digest,
        "adapter_family": attestation.adapter_family,
        "adapter_version": attestation.adapter_version,
        "subject_digest": attestation.subject_digest,
        "body_digest": attestation.body_digest,
        "payload_byte_size": attestation.payload_byte_size,
        "request_envelope_digest": attestation.request_envelope_digest,
    }


class _EnvelopeAttestation:
    """Private proof that Egress rebuilt one exact trusted Adapter envelope."""

    __slots__ = (
        "approval_id",
        "approval_terms_digest",
        "adapter_family",
        "adapter_version",
        "subject_digest",
        "body_digest",
        "payload_byte_size",
        "request_envelope_digest",
        "attestation_digest",
        "_approval_ledger",
    )

    def __init__(
        self,
        *,
        approval: EgressApproval,
        adapter_family: str,
        adapter_version: str,
        subject_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ENVELOPE_ATTESTATION_AUTHORITY:
            raise TypeError("envelope attestation requires EgressGate")
        require_text(adapter_family, "adapter_family", max_length=512)
        require_text(adapter_version, "adapter_version", max_length=512)
        require_digest(
            subject_digest,
            "subject_digest",
        )
        values = (
            ("approval_id", approval.approval_id),
            ("approval_terms_digest", approval.approval_terms_digest),
            ("adapter_family", adapter_family),
            ("adapter_version", adapter_version),
            (
                "subject_digest",
                subject_digest,
            ),
            ("body_digest", approval.body_digest),
            ("payload_byte_size", approval.payload_byte_size),
            (
                "request_envelope_digest",
                approval.request_envelope_digest,
            ),
            ("_approval_ledger", approval._approval_ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "attestation_digest",
            digest256(
                "EnvelopeAttestation",
                _ENVELOPE_ATTESTATION_SCHEMA_VERSION,
                _attestation_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("_EnvelopeAttestation is immutable")

    def validate_integrity(self) -> None:
        if type(self._approval_ledger) is not EgressApprovalLedger:
            raise ValueError("approval ledger authority changed")
        require_uuid(self.approval_id, "approval_id")
        require_digest(self.approval_terms_digest, "approval_terms_digest")
        require_text(self.adapter_family, "adapter_family", max_length=512)
        require_text(self.adapter_version, "adapter_version", max_length=512)
        require_digest(
            self.subject_digest,
            "subject_digest",
        )
        require_digest(self.body_digest, "body_digest")
        require_plain_int(
            self.payload_byte_size,
            "payload_byte_size",
            minimum=1,
        )
        require_digest(
            self.request_envelope_digest,
            "request_envelope_digest",
        )
        if self.attestation_digest != digest256(
            "EnvelopeAttestation",
            _ENVELOPE_ATTESTATION_SCHEMA_VERSION,
            _attestation_payload(self),
        ):
            raise ValueError("envelope attestation integrity mismatch")


@runtime_final
class EgressApprovalLedger:
    """Process-local authority for decision IDs and approval revisions.

    Preview and decision objects, image bytes, and user hints are never stored
    here.  A private digest-only trusted-envelope attestation is atomically
    retained with each decision-to-approval identifier binding.
    """

    __slots__ = (
        "_approvals",
        "_issued_terms",
        "_current_digests",
        "_preview_decisions",
        "_attestations",
        "_issued_attestation_digests",
        "_lock",
        "_revision",
        "_poisoned",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "_approvals", {})
        object.__setattr__(self, "_issued_terms", {})
        object.__setattr__(self, "_current_digests", {})
        object.__setattr__(self, "_preview_decisions", {})
        object.__setattr__(self, "_attestations", {})
        object.__setattr__(self, "_issued_attestation_digests", {})
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_revision", 0)
        object.__setattr__(self, "_poisoned", False)

    def _require_usable_locked(self, *, stage: str = "egress_gate") -> None:
        if self._poisoned:
            raise _egress_error(
                "出站批准账本状态无法完整证明，已封锁。",
                stage=stage,
            )

    def _poison_locked(self) -> None:
        if not self._poisoned:
            object.__setattr__(self, "_poisoned", True)
            object.__setattr__(self, "_revision", self._revision + 1)

    def _issue(
        self,
        approval: EgressApproval,
        *,
        attestation: _EnvelopeAttestation,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _APPROVAL_LEDGER_AUTHORITY:
            raise TypeError("egress approvals can only be issued by EgressGate")
        if type(approval) is not EgressApproval:
            raise TypeError("approval must be EgressApproval")
        try:
            approval.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _egress_error("出站批准完整性校验失败。") from error
        if type(attestation) is not _EnvelopeAttestation:
            raise TypeError("attestation must be _EnvelopeAttestation")
        try:
            attestation.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _egress_error("受信请求包络证明完整性校验失败。") from error
        if (
            attestation.approval_id != approval.approval_id
            or attestation.approval_terms_digest
            != approval.approval_terms_digest
            or attestation.body_digest != approval.body_digest
            or attestation.payload_byte_size != approval.payload_byte_size
            or attestation.request_envelope_digest
            != approval.request_envelope_digest
            or attestation._approval_ledger is not self
        ):
            raise _egress_error("受信请求包络证明未绑定当前出站批准。")
        with self._lock:
            self._require_usable_locked()
            try:
                approval.validate_integrity()
                attestation.validate_integrity()
            except (ValueError, TypeError, AttributeError) as error:
                raise _egress_error("出站批准或请求包络证明已失效。") from error
            if (
                approval._approval_ledger is not self
                or attestation._approval_ledger is not self
            ):
                raise _egress_error("出站批准不属于当前账本。")
            if any(
                approval.approval_id in mapping
                for mapping in (
                    self._approvals,
                    self._issued_terms,
                    self._current_digests,
                    self._attestations,
                    self._issued_attestation_digests,
                )
            ):
                raise _egress_error("出站批准标识已存在。")
            if approval.preview_decision_id in self._preview_decisions:
                raise _egress_error("同一次上传确认已经使用。")
            original_revision = self._revision
            entries = (
                (self._approvals, approval.approval_id, approval),
                (
                    self._issued_terms,
                    approval.approval_id,
                    approval.approval_terms_digest,
                ),
                (
                    self._current_digests,
                    approval.approval_id,
                    approval.approval_digest,
                ),
                (
                    self._preview_decisions,
                    approval.preview_decision_id,
                    approval.approval_id,
                ),
                (
                    self._attestations,
                    approval.approval_id,
                    attestation,
                ),
                (
                    self._issued_attestation_digests,
                    approval.approval_id,
                    attestation.attestation_digest,
                ),
            )
            publish_failure: BaseException | None = None
            rollback_proven = True
            try:
                for mapping, key, value in entries:
                    mapping[key] = value
                object.__setattr__(self, "_revision", original_revision + 1)
                self._require_current_locked(approval)
            except BaseException as error:
                publish_failure = error
                missing = object()
                for mapping, key, value in reversed(entries):
                    try:
                        current = mapping.get(key, missing)
                        if current is value:
                            del mapping[key]
                        elif current is not missing:
                            rollback_proven = False
                        if key in mapping:
                            rollback_proven = False
                    except BaseException:
                        rollback_proven = False
                if rollback_proven:
                    object.__setattr__(self, "_revision", original_revision)
                else:
                    self._poison_locked()
            if publish_failure is not None:
                if not rollback_proven:
                    raise _egress_error(
                        "出站批准与请求包络证明无法安全回滚，账本已封锁。"
                    )
                if isinstance(publish_failure, (KeyboardInterrupt, SystemExit)):
                    raise publish_failure
                raise _egress_error("出站批准与请求包络证明未能完整签发。")

    def _require_current_locked(self, approval: EgressApproval) -> None:
        self._require_usable_locked()
        if type(approval) is not EgressApproval:
            raise TypeError("approval must be EgressApproval")
        try:
            approval.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _egress_error("出站批准完整性校验失败。") from error
        current = self._approvals.get(approval.approval_id)
        attestation = self._attestations.get(approval.approval_id)
        attestation_valid = type(attestation) is _EnvelopeAttestation
        if attestation_valid:
            try:
                attestation.validate_integrity()
            except (ValueError, TypeError, AttributeError):
                attestation_valid = False
        if (
            current is not approval
            or approval._approval_ledger is not self
            or self._issued_terms.get(approval.approval_id)
            != approval.approval_terms_digest
            or self._current_digests.get(approval.approval_id)
            != approval.approval_digest
            or self._preview_decisions.get(approval.preview_decision_id)
            != approval.approval_id
            or not attestation_valid
            or attestation._approval_ledger is not self
            or attestation.approval_id != approval.approval_id
            or attestation.approval_terms_digest
            != approval.approval_terms_digest
            or attestation.body_digest != approval.body_digest
            or attestation.payload_byte_size != approval.payload_byte_size
            or attestation.request_envelope_digest
            != approval.request_envelope_digest
            or self._issued_attestation_digests.get(approval.approval_id)
            != attestation.attestation_digest
        ):
            raise _egress_error("出站批准不属于当前账本或状态已经变化。")

    def _require_subject_attestation_locked(
        self,
        *,
        approval: EgressApproval,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        planned_stage: ExecutionPlanStage,
        error_stage: str,
    ) -> None:
        """Match the full current authority subject under this ledger lock."""

        expectation_failed = False
        try:
            subject_digest = _full_egress_subject_digest(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                stage=planned_stage,
            )
        except (ValueError, TypeError, AttributeError):
            expectation_failed = True
            subject_digest = None
        if expectation_failed:
            raise _egress_error(
                "待发送完整 authority subject 校验失败。",
                stage=error_stage,
            )
        attestation = self._attestations.get(approval.approval_id)
        if (
            type(attestation) is not _EnvelopeAttestation
            or attestation.adapter_family != planned_stage.adapter_family
            or attestation.adapter_version != planned_stage.adapter_version
            or attestation.subject_digest != subject_digest
        ):
            raise _egress_error(
                "待发送 authority subject 与受信 Adapter 证明不一致。",
                stage=error_stage,
            )

    def _publish_lifecycle_transition_locked(
        self,
        *,
        current: EgressApproval,
        replacement: EgressApproval,
        error_stage: str,
        rollback_allowed: bool,
    ) -> None:
        """Publish both lifecycle indexes or fail closed as one transition."""

        original_revision = self._revision
        publish_failure: BaseException | None = None
        rollback_proven = False
        try:
            self._approvals[current.approval_id] = replacement
            self._current_digests[current.approval_id] = (
                replacement.approval_digest
            )
            object.__setattr__(self, "_revision", original_revision + 1)
            self._require_current_locked(replacement)
        except BaseException as error:
            publish_failure = error
            if rollback_allowed:
                try:
                    self._approvals[current.approval_id] = current
                    self._current_digests[current.approval_id] = (
                        current.approval_digest
                    )
                    object.__setattr__(self, "_revision", original_revision)
                    self._require_current_locked(current)
                    rollback_proven = True
                except BaseException:
                    rollback_proven = False
            if not rollback_proven:
                self._poison_locked()
        if publish_failure is None:
            return
        if rollback_proven and isinstance(
            publish_failure,
            (KeyboardInterrupt, SystemExit),
        ):
            raise publish_failure
        if rollback_proven:
            raise _egress_error(
                "出站批准状态变更未能完整提交。",
                stage=error_stage,
            )
        raise _egress_error(
            "出站批准状态无法完整证明，账本已封锁。",
            stage=error_stage,
        )

    def snapshot(self, approval_id: UUID) -> EgressApproval:
        require_uuid(approval_id, "approval_id")
        with self._lock:
            self._require_usable_locked()
            current = self._approvals.get(approval_id)
            if current is None:
                raise _egress_error("出站批准不存在。")
            self._require_current_locked(current)
            return current

    def validate_active(self, approval: EgressApproval, *, now: datetime) -> None:
        """Validate only this ledger's lifecycle state.

        This is not complete send authority: callers must also revalidate the
        exact ConsentLedger/AuthorizationContext and, in W09, registry lease,
        monotonic deadline, cancellation and budgets.
        """

        require_aware_datetime(now, "now")
        with self._lock:
            self._require_current_locked(approval)
            try:
                approval.validate_active_at(now)
            except ValueError as error:
                raise _egress_error("出站批准当前不可消费。") from error

    def revoke(self, *, approval_id: UUID, revoked_at: datetime) -> EgressApproval:
        require_uuid(approval_id, "approval_id")
        require_aware_datetime(revoked_at, "revoked_at")
        with self._lock:
            self._require_usable_locked()
            current = self._approvals.get(approval_id)
            if current is None:
                raise _egress_error("无法撤销不存在的出站批准。")
            self._require_current_locked(current)
            try:
                current.validate_active_at(revoked_at)
                replacement = current._with_status(
                    consumed_at=None,
                    revoked_at=revoked_at,
                    _authority=_APPROVAL_LEDGER_AUTHORITY,
                )
            except ValueError as error:
                raise _egress_error("出站批准当前不可撤销。") from error
            self._publish_lifecycle_transition_locked(
                current=current,
                replacement=replacement,
                error_stage="egress_gate",
                rollback_allowed=True,
            )
            return replacement

    def _consume_with(
        self,
        *,
        approval: EgressApproval,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        planned_stage: ExecutionPlanStage,
        now: datetime,
        action: Callable[[EgressApproval], _T],
        _authority: object | None = None,
    ) -> _T:
        """Consume first, then run a pure session-ledger transition.

        ``action`` may only construct and issue the static W08 session.  Secret
        resolution, credential handles, client construction and all I/O must
        happen after this method has returned and the consumed revision is
        visible in the approval ledger.  Consumption is deliberately
        irreversible: if session construction or issue fails, the approval is
        burned instead of being made reusable.
        """

        if _authority is not _EGRESS_SESSION_AUTHORITY:
            raise TypeError("approval consumption requires SendSessionFactory")
        require_aware_datetime(now, "now")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._lock:
            self._require_usable_locked(stage="send_session_factory")
            self._require_current_locked(approval)
            self._require_subject_attestation_locked(
                approval=approval,
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                planned_stage=planned_stage,
                error_stage="send_session_factory",
            )
            try:
                approval.validate_active_at(now)
                consumed = approval._with_status(
                    consumed_at=now,
                    revoked_at=None,
                    _authority=_APPROVAL_LEDGER_AUTHORITY,
                )
            except ValueError as error:
                raise _egress_error(
                    "出站批准当前不可消费。", stage="send_session_factory"
                ) from error
            # Consumption begins an irreversible one-shot handoff.  Any
            # unprovable partial write poisons the ledger instead of making
            # the original approval reusable.
            self._publish_lifecycle_transition_locked(
                current=approval,
                replacement=consumed,
                error_stage="send_session_factory",
                rollback_allowed=False,
            )
            return action(consumed)

    def _run_consumed_action(
        self,
        *,
        approval_id: UUID,
        approval_terms_digest: Digest256,
        consumed_approval_digest: Digest256,
        consumed_at: datetime,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        planned_stage: ExecutionPlanStage,
        now: datetime,
        action: Callable[[], _T],
        _authority: object | None = None,
    ) -> _T:
        """Run W09 authority checks under the consumed approval revision."""

        if _authority is not _EGRESS_ATTEMPT_AUTHORITY:
            raise TypeError("consumed approval checks require AttemptGate")
        require_uuid(approval_id, "approval_id")
        require_digest(approval_terms_digest, "approval_terms_digest")
        require_digest(consumed_approval_digest, "consumed_approval_digest")
        require_aware_datetime(consumed_at, "consumed_at")
        require_aware_datetime(now, "now")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._lock:
            self._require_usable_locked(stage="attempt_gate")
            current = self._approvals.get(approval_id)
            if current is None:
                raise _egress_error(
                    "发送会话引用的出站批准不存在。",
                    stage="attempt_gate",
                )
            self._require_current_locked(current)
            self._require_subject_attestation_locked(
                approval=current,
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                planned_stage=planned_stage,
                error_stage="attempt_gate",
            )
            if (
                current.approval_terms_digest != approval_terms_digest
                or current.approval_digest != consumed_approval_digest
                or current.consumed_at != consumed_at
                or current.revoked_at is not None
                or now < current.approved_at
                or now >= current.expires_at
            ):
                raise _egress_error(
                    "发送会话引用的出站批准状态已经失效。",
                    stage="attempt_gate",
                )
            return action()

    def safe_metadata(self) -> dict[str, int | bool]:
        with self._lock:
            return {
                "revision": self._revision,
                "approval_count": len(self._approvals),
                "preview_decision_count": len(self._preview_decisions),
                "poisoned": self._poisoned,
            }


def _validate_exact_egress_binding_core(
    *,
    planned: PlannedExecution,
    invocation: StageInvocation,
    prepared: PreparedOutbound,
    authorization: AuthorizationContext,
    consent_ledger: ConsentLedger,
    now: datetime,
) -> tuple[object, object]:
    """Validate fields not covered by request_envelope_digest itself."""

    if type(planned) is not PlannedExecution:
        raise TypeError("planned must be PlannedExecution")
    if type(invocation) is not StageInvocation:
        raise TypeError("invocation must be StageInvocation")
    if type(prepared) is not PreparedOutbound:
        raise TypeError("prepared must be PreparedOutbound")
    if type(authorization) is not AuthorizationContext:
        raise TypeError("authorization must be AuthorizationContext")
    if type(consent_ledger) is not ConsentLedger:
        raise TypeError("consent_ledger must be ConsentLedger")
    require_aware_datetime(now, "now")
    validation_failed = False
    try:
        planned.validate_integrity()
        invocation.validate_integrity()
        validate_prepared_outbound_against_plan(prepared, planned.plan)
    except EndpointPolicyError:
        raise
    except Exception:
        validation_failed = True
    if validation_failed:
        raise _egress_error("出站绑定完整性校验失败。")
    stage = next(
        (item for item in planned.plan.stages if item.stage_id == invocation.stage_id),
        None,
    )
    if stage is None:
        raise _egress_error("阶段输入不属于当前执行计划。")
    operation = next(
        (item for item in stage.network_operations if item.operation_id == prepared.operation_id),
        None,
    )
    capture = invocation.input
    expected_source_ids = (capture.capture_id, invocation.invocation_id)
    expected_source_digests = (capture.validation_digest, invocation.invocation_digest)
    if (
        operation is None
        or not planned.plan.preview_required
        or invocation.request_id != planned.plan.request_id
        or invocation.plan_id != planned.plan.plan_id
        or invocation.plan_digest != planned.plan.plan_digest
        or invocation.planned_execution_digest != planned.planned_execution_digest
        or prepared.stage_id != invocation.stage_id
        or prepared.source_ids != expected_source_ids
        or prepared.source_digests != expected_source_digests
        or prepared.capture_scope_fingerprint != capture.scope_fingerprint
        or capture.privacy_authorization_id != authorization.authorization_id
        or capture.privacy_authorization_digest != authorization.authorization_digest
    ):
        raise _egress_error("待发送内容未绑定当前截图、阶段或隐私授权。")
    try:
        grants = consent_ledger.snapshot_for_ids(authorization.consent_grant_ids)
    except EndpointPolicyError:
        raise
    except (ValueError, TypeError, AttributeError) as error:
        raise _egress_error("无法复核当前同意记录。") from error
    matching_grants = tuple(grant for grant in grants if grant.binding_id == stage.binding_id)
    if len(matching_grants) != 1:
        raise _egress_error("当前网络阶段没有唯一同意记录覆盖。")
    if any(grant.one_shot for grant in grants):
        network_stages = tuple(
            candidate
            for candidate in planned.plan.stages
            if candidate.network_operations
        )
        if (
            len(grants) != 1
            or not matching_grants[0].one_shot
            or len(network_stages) != 1
            or network_stages[0] is not stage
            or len(stage.network_operations) != 1
        ):
            raise _egress_error(
                "一次性同意暂不支持多阶段或多操作发送计划。"
            )
    granted_scope = matching_grants[0].capture_scope_fingerprint
    if granted_scope is not None and granted_scope != capture.scope_fingerprint:
        raise _egress_error("同意记录未覆盖当前截图区域。")
    return stage, operation


def _trusted_adapter_type(
    *,
    adapter_family: str,
    adapter_version: str,
) -> type[DirectMultimodalAdapter]:
    """Resolve only an exact built-in Adapter family/version pair."""

    adapter_type = _trusted_adapter_catalog_match(
        adapter_family=adapter_family,
        adapter_version=adapter_version,
    )
    if adapter_type is None:
        raise _egress_error("当前 Adapter 不在受信请求包络目录中。")
    return adapter_type


def _rebuild_trusted_envelope_once(
    *,
    planned: PlannedExecution,
    invocation: StageInvocation,
    prepared: PreparedOutbound,
    authorization: AuthorizationContext,
    stage: ExecutionPlanStage,
) -> tuple[str, str, Digest256]:
    """Perform Egress's sole trusted rebuild and return a digest-only proof."""

    adapter_family = getattr(stage, "adapter_family", None)
    adapter_version = getattr(stage, "adapter_version", None)
    if type(adapter_family) is not str or type(adapter_version) is not str:
        raise _egress_error("冻结阶段缺少受信 Adapter 标识。")
    adapter_type = _trusted_adapter_type(
        adapter_family=adapter_family,
        adapter_version=adapter_version,
    )
    rebuild_failed = False
    try:
        expected_prepared = adapter_type.prepare(
            planned=planned,
            invocation=invocation,
            operation_id=prepared.operation_id,
        )
        expectation_digest = _prepared_expectation_digest(prepared)
        expected_digest = _prepared_expectation_digest(expected_prepared)
    except EndpointPolicyError:
        raise
    except Exception:
        rebuild_failed = True
        expected_prepared = None
        expectation_digest = None
        expected_digest = None
    if rebuild_failed:
        raise _egress_error("无法重建受信 Adapter 请求包络。")
    if (
        expectation_digest != expected_digest
        or any(
            getattr(prepared, name) != getattr(expected_prepared, name)
            for name in PreparedOutbound.__slots__
        )
    ):
        raise _egress_error("待发送内容不是当前受信 Adapter 的精确输出。")
    subject_failed = False
    try:
        subject_digest = _full_egress_subject_digest(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            stage=stage,
        )
    except (ValueError, TypeError, AttributeError):
        subject_failed = True
        subject_digest = None
    if subject_failed:
        raise _egress_error("无法构造完整受信 authority subject。")
    assert subject_digest is not None
    return adapter_family, adapter_version, subject_digest


def _validate_exact_egress_binding(
    *,
    planned: PlannedExecution,
    invocation: StageInvocation,
    prepared: PreparedOutbound,
    authorization: AuthorizationContext,
    consent_ledger: ConsentLedger,
    now: datetime,
) -> tuple[object, object]:
    """Validate active privacy authority, then the exact outbound binding."""

    PrivacyGate().validate_authorization(
        planned=planned,
        authorization=authorization,
        ledger=consent_ledger,
        now=now,
    )
    return _validate_exact_egress_binding_core(
        planned=planned,
        invocation=invocation,
        prepared=prepared,
        authorization=authorization,
        consent_ledger=consent_ledger,
        now=now,
    )


def _validate_exact_egress_binding_for_session(
    *,
    planned: PlannedExecution,
    invocation: StageInvocation,
    prepared: PreparedOutbound,
    authorization: AuthorizationContext,
    consent_ledger: ConsentLedger,
    now: datetime,
    _authority: object | None = None,
) -> tuple[object, object]:
    """Validate exact binding after ConsentLedger session authorization."""

    if _authority is not _EGRESS_ATTEMPT_AUTHORITY:
        raise TypeError("session egress validation requires AttemptGate")
    return _validate_exact_egress_binding_core(
        planned=planned,
        invocation=invocation,
        prepared=prepared,
        authorization=authorization,
        consent_ledger=consent_ledger,
        now=now,
    )


@runtime_final
class EgressGate:
    """Review and issue one approval for one exact PreparedOutbound."""

    __slots__ = ()

    def approve(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        approval_ledger: EgressApprovalLedger,
        preview_controller: EgressPreviewController,
    ) -> EgressApproval:
        if type(approval_ledger) is not EgressApprovalLedger:
            raise TypeError("approval_ledger must be EgressApprovalLedger")
        if not isinstance(preview_controller, EgressPreviewController):
            raise TypeError("preview_controller must be EgressPreviewController")

        # Preliminary validation keeps malformed inputs away from the trusted UI.
        preliminary_now = authorization.authorized_at
        stage, operation = _validate_exact_egress_binding(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            now=preliminary_now,
        )
        (
            trusted_adapter_family,
            trusted_adapter_version,
            trusted_subject_digest,
        ) = _rebuild_trusted_envelope_once(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            stage=stage,
        )
        preview_failed = False
        try:
            preview = EgressPreview(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                _authority=_PREVIEW_AUTHORITY,
            )
        except Exception:
            preview_failed = True
            preview = None
        if preview_failed:
            raise _egress_error("无法从当前有效输入构造上传预览。")
        assert preview is not None
        controller_cancelled = False
        controller_failed = False
        try:
            decision = preview_controller.review(preview)
        except CancelledError:
            controller_cancelled = True
            decision = None
        except Exception:
            # Raise after leaving the except block so a controller exception
            # containing sensitive preview data is not retained as __context__.
            controller_failed = True
            decision = None
        if controller_cancelled:
            raise CancelledError(
                stage="egress_gate",
                safe_message="用户取消了本次上传。",
                retryable=False,
            )
        if controller_failed:
            raise _egress_error("上传预览控制器未能给出安全决定。")
        if type(decision) is not EgressPreviewDecision:
            raise _egress_error("上传预览控制器返回了无效决定。")
        try:
            decision.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _egress_error("上传预览决定完整性校验失败。") from error
        if decision.preview_subject_digest != preview.preview_subject_digest:
            raise _egress_error("上传预览决定不属于当前待发送内容。")
        if decision._preview is not preview:
            raise _egress_error("上传预览决定不是当前确认动作的原始凭证。")
        if decision.decided_at < invocation.input.validated_at:
            raise _egress_error("上传确认不能早于当前输入完成验证的时间。")
        wall_deadline = authorization.authorized_at + timedelta(
            milliseconds=planned.plan.timeout_budget_ms
        )
        if decision.decided_at >= wall_deadline:
            raise _egress_error("执行计划在上传确认前已经超时。")
        if not decision.approved:
            raise CancelledError(
                stage="egress_gate",
                safe_message="用户取消了本次上传。",
                retryable=False,
            )

        approved_at = decision.decided_at

        def issue() -> EgressApproval:
            current_stage, current_operation = _validate_exact_egress_binding(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                now=approved_at,
            )
            if (
                current_stage is not stage
                or current_operation is not operation
                or getattr(current_stage, "adapter_family", None)
                != trusted_adapter_family
                or getattr(current_stage, "adapter_version", None)
                != trusted_adapter_version
            ):
                raise _egress_error("预览后冻结计划或 Adapter 标识发生了变化。")
            current_subject_failed = False
            try:
                current_subject_digest = _full_egress_subject_digest(
                    planned=planned,
                    invocation=invocation,
                    prepared=prepared,
                    authorization=authorization,
                    stage=current_stage,
                )
            except (ValueError, TypeError, AttributeError):
                current_subject_failed = True
                current_subject_digest = None
            if current_subject_failed:
                raise _egress_error("预览后 authority subject 完整性校验失败。")
            if current_subject_digest != trusted_subject_digest:
                raise _egress_error("预览后 authority subject 发生了变化。")
            # Rebuild the ephemeral preview, but not the Adapter envelope, so a
            # callback-side mutation cannot reuse the earlier review subject.
            current_preview_failed = False
            try:
                current_preview = EgressPreview(
                    planned=planned,
                    invocation=invocation,
                    prepared=prepared,
                    authorization=authorization,
                    _authority=_PREVIEW_AUTHORITY,
                )
            except Exception:
                current_preview_failed = True
                current_preview = None
            if current_preview_failed:
                raise _egress_error("上传确认后输入已经不可用。")
            assert current_preview is not None
            if current_preview.preview_subject_digest != decision.preview_subject_digest:
                raise _egress_error("预览后待发送内容发生了变化。")
            expires_at = approved_at + EGRESS_APPROVAL_LIFETIME
            if authorization.valid_until is not None:
                expires_at = min(expires_at, authorization.valid_until)
            expires_at = min(expires_at, wall_deadline)
            if expires_at <= approved_at:
                raise _egress_error("出站批准在签发前已经过期。")
            approval_id = _approval_id_for(
                _approval_identifier_payload_from_preview(
                    preview=current_preview,
                    decision=decision,
                    max_network_attempts=stage.max_attempts_per_operation,
                    billable=operation.billable,
                    approved_at=approved_at,
                    expires_at=expires_at,
                )
            )
            approval = EgressApproval(
                approval_id=approval_id,
                preview=current_preview,
                decision=decision,
                max_network_attempts=stage.max_attempts_per_operation,
                billable=operation.billable,
                approved_at=approved_at,
                expires_at=expires_at,
                consumed_at=None,
                revoked_at=None,
                approval_ledger=approval_ledger,
                _authority=_APPROVAL_AUTHORITY,
            )
            attestation = _EnvelopeAttestation(
                approval=approval,
                adapter_family=trusted_adapter_family,
                adapter_version=trusted_adapter_version,
                subject_digest=trusted_subject_digest,
                _authority=_ENVELOPE_ATTESTATION_AUTHORITY,
            )
            approval_ledger._issue(
                approval,
                attestation=attestation,
                _authority=_APPROVAL_LEDGER_AUTHORITY,
            )
            return approval

        return PrivacyGate()._run_authorized_action(
            planned=planned,
            authorization=authorization,
            ledger=consent_ledger,
            now=approved_at,
            action=issue,
            _authority=_ATOMIC_PRIVACY_AUTHORITY,
        )


__all__ = [
    "EGRESS_APPROVAL_LIFETIME",
    "EGRESS_APPROVAL_SCHEMA_VERSION",
    "EGRESS_POLICY_VERSION",
    "EGRESS_PREVIEW_DECISION_SCHEMA_VERSION",
    "EGRESS_PREVIEW_SCHEMA_VERSION",
    "EgressApproval",
    "EgressApprovalLedger",
    "EgressGate",
    "EgressPreview",
    "EgressPreviewController",
    "EgressPreviewDecision",
]
