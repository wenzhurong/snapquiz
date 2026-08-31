"""Immutable consent grants and plan-bound privacy authorization.

Grant lifecycle state is kept behind an in-memory authority boundary so one
grant id cannot silently be rebound to different terms.  This is not durable
storage.  A durable store interface and migration semantics remain a later
work package; W05 intentionally accepts only the process-local ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from threading import RLock
from typing import Callable, TypeVar
from uuid import UUID, uuid5

from snapquiz.domain._validation import (
    HTTP_TOKEN_RE,
    require_aware_datetime,
    require_canonical_http_url,
    require_digest,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.capture import CaptureScopeKind
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.domain.plan import (
    CanonicalQueryPolicy,
    ComputeLocation,
    CredentialInjectionSlot,
    ExecutionPlanNetworkOperation,
    ExecutionPlanStage,
    NetworkOperationPurpose,
    NetworkScope,
    OutboundDataKind,
)
from snapquiz.domain.policy import (
    ContractMarker,
    PolicySnapshot,
    PolicyValue,
    policy_value_payload,
    require_policy_value,
    validate_policy_value_at,
)
from snapquiz.domain.solve import PipelineKind
from snapquiz.routing.planner import PlannedExecution

CONSENT_POLICY_VERSION = "snapquiz.privacy-consent.v1"
CONSENT_NETWORK_OPERATION_SCHEMA_VERSION = (
    "snapquiz.consent-network-operation.v1"
)
CONSENT_GRANT_SCHEMA_VERSION = "snapquiz.consent-grant.v1"
AUTHORIZATION_CONTEXT_SCHEMA_VERSION = "snapquiz.authorization-context.v1"

_GRANT_AUTHORITY = object()
_AUTHORIZATION_AUTHORITY = object()
_ATOMIC_PRIVACY_AUTHORITY = object()
_AUTHORIZATION_UUID_NAMESPACE = UUID("3f2f5b36-d01d-5094-bf86-0273671fe5dd")

_T = TypeVar("_T")


class UnknownPolicyDimension(str, Enum):
    COST = "cost"
    DATA = "data"
    PROCESSING_REGION = "processing_region"
    RETENTION = "retention"


def _privacy_error(message: str = "当前隐私授权不覆盖该执行计划。") -> EndpointPolicyError:
    return EndpointPolicyError(stage="privacy_gate", safe_message=message)


def _short_digest(value: Digest256) -> str:
    return str(value)[:12]


def _marker_or_text_payload(value: str | ContractMarker) -> str:
    return value.value if isinstance(value, ContractMarker) else value


def _require_not_applicable_or_text(
    value: object, name: str
) -> str | ContractMarker:
    if value is ContractMarker.NOT_APPLICABLE:
        return value
    if isinstance(value, ContractMarker):
        raise ValueError(f"{name} cannot be unknown")
    text = require_text(value, name, max_length=512)
    if text in (ContractMarker.NOT_APPLICABLE.value, ContractMarker.UNKNOWN.value):
        raise ValueError(f"{name} cannot encode a contract marker as text")
    return text


def _require_region(value: object) -> str | ContractMarker:
    if value is ContractMarker.UNKNOWN:
        return value
    if isinstance(value, ContractMarker):
        raise ValueError("processing_region cannot be not_applicable")
    text = require_text(value, "processing_region", max_length=128)
    if text in (ContractMarker.NOT_APPLICABLE.value, ContractMarker.UNKNOWN.value):
        raise ValueError("processing_region cannot encode a contract marker as text")
    return text


def _require_outbound_data(
    values: object,
) -> tuple[OutboundDataKind, ...]:
    if type(values) is not tuple or not values or not all(
        type(value) is OutboundDataKind for value in values
    ):
        raise ValueError("outbound_data must contain OutboundDataKind values")
    expected = tuple(sorted(values, key=lambda item: item.value))
    if values != expected or len(set(values)) != len(values):
        raise ValueError("outbound_data must be unique and canonically sorted")
    return values


def _required_unknown_dimensions(
    *,
    processing_region: str | ContractMarker,
    retention_policy: PolicyValue,
    data_policy: PolicyValue,
    cost_policy: PolicyValue,
) -> tuple[UnknownPolicyDimension, ...]:
    values: list[UnknownPolicyDimension] = []
    if processing_region is ContractMarker.UNKNOWN:
        values.append(UnknownPolicyDimension.PROCESSING_REGION)
    if retention_policy is ContractMarker.UNKNOWN:
        values.append(UnknownPolicyDimension.RETENTION)
    if data_policy is ContractMarker.UNKNOWN:
        values.append(UnknownPolicyDimension.DATA)
    if cost_policy is ContractMarker.UNKNOWN:
        values.append(UnknownPolicyDimension.COST)
    return tuple(sorted(values, key=lambda item: item.value))


def _require_unknown_confirmations(
    values: object,
    *,
    processing_region: str | ContractMarker,
    retention_policy: PolicyValue,
    data_policy: PolicyValue,
    cost_policy: PolicyValue,
) -> tuple[UnknownPolicyDimension, ...]:
    if type(values) is not tuple or not all(
        type(value) is UnknownPolicyDimension for value in values
    ):
        raise ValueError(
            "confirmed_unknown_policies must contain policy dimensions"
        )
    expected_order = tuple(sorted(values, key=lambda item: item.value))
    if values != expected_order or len(set(values)) != len(values):
        raise ValueError(
            "confirmed_unknown_policies must be unique and canonically sorted"
        )
    required = _required_unknown_dimensions(
        processing_region=processing_region,
        retention_policy=retention_policy,
        data_policy=data_policy,
        cost_policy=cost_policy,
    )
    if values != required:
        raise ValueError("every unknown policy dimension requires exact confirmation")
    return values


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class ConsentNetworkOperation:
    purpose: NetworkOperationPurpose
    http_method: str
    canonical_endpoint: str
    canonical_query_policy: CanonicalQueryPolicy
    content_type: str
    credential_injection_slot: CredentialInjectionSlot
    outbound_data: tuple[OutboundDataKind, ...]

    def __post_init__(self) -> None:
        if type(self.purpose) is not NetworkOperationPurpose:
            raise ValueError("purpose must be NetworkOperationPurpose")
        method = require_text(self.http_method, "http_method", max_length=32)
        if method != method.upper() or HTTP_TOKEN_RE.fullmatch(method) is None:
            raise ValueError("http_method must be an uppercase HTTP token")
        require_canonical_http_url(
            self.canonical_endpoint,
            "canonical_endpoint",
            allow_query=False,
        )
        if type(self.canonical_query_policy) is not CanonicalQueryPolicy:
            raise ValueError("canonical_query_policy must be CanonicalQueryPolicy")
        content_type = require_text(
            self.content_type, "content_type", max_length=256
        )
        if content_type != content_type.lower():
            raise ValueError("content_type must be normalized lowercase text")
        if type(self.credential_injection_slot) is not CredentialInjectionSlot:
            raise ValueError(
                "credential_injection_slot must be CredentialInjectionSlot"
            )
        _require_outbound_data(self.outbound_data)

    @classmethod
    def from_plan_operation(
        cls, operation: ExecutionPlanNetworkOperation
    ) -> "ConsentNetworkOperation":
        if type(operation) is not ExecutionPlanNetworkOperation:
            raise TypeError("operation must be ExecutionPlanNetworkOperation")
        return cls(
            purpose=operation.purpose,
            http_method=operation.http_method,
            canonical_endpoint=operation.canonical_endpoint,
            canonical_query_policy=operation.canonical_query_policy,
            content_type=operation.content_type,
            credential_injection_slot=operation.credential_injection_slot,
            outbound_data=operation.outbound_data,
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "purpose": self.purpose.value,
            "http_method": self.http_method,
            "canonical_endpoint": self.canonical_endpoint,
            "canonical_query_policy": self.canonical_query_policy.as_digest_payload(),
            "content_type": self.content_type,
            "credential_injection_slot": self.credential_injection_slot.value,
            "outbound_data": tuple(item.value for item in self.outbound_data),
        }

    def contract_digest(self) -> Digest256:
        return digest256(
            "ConsentNetworkOperation",
            CONSENT_NETWORK_OPERATION_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def covers(self, operation: ExecutionPlanNetworkOperation) -> bool:
        if type(operation) is not ExecutionPlanNetworkOperation:
            return False
        return (
            self.purpose is operation.purpose
            and self.http_method == operation.http_method
            and self.canonical_endpoint == operation.canonical_endpoint
            and self.canonical_query_policy == operation.canonical_query_policy
            and self.content_type == operation.content_type
            and self.credential_injection_slot
            is operation.credential_injection_slot
            and set(operation.outbound_data).issubset(self.outbound_data)
        )


def _grant_terms_payload(grant: "ConsentGrant") -> dict[str, object]:
    return {
        "grant_id": grant.grant_id,
        "request_id": grant.request_id,
        "policy_version": grant.policy_version,
        "binding_id": grant.binding_id,
        "provider_profile_id": grant.provider_profile_id,
        "provider_profile_digest": grant.provider_profile_digest,
        "pipeline_kind": grant.pipeline_kind.value,
        "endpoint_policy_version": grant.endpoint_policy_version,
        "network_policy_version": grant.network_policy_version,
        "tls_policy_ref": _marker_or_text_payload(grant.tls_policy_ref),
        "network_scope": grant.network_scope.value,
        "allowed_network_operations": tuple(
            operation.as_digest_payload()
            for operation in grant.allowed_network_operations
        ),
        "capture_scope_kind": grant.capture_scope_kind.value,
        "capture_scope_fingerprint": grant.capture_scope_fingerprint,
        "compute_location": grant.compute_location.value,
        "processing_region": _marker_or_text_payload(grant.processing_region),
        "retention_policy": policy_value_payload(grant.retention_policy),
        "data_policy": policy_value_payload(grant.data_policy),
        "cost_policy": policy_value_payload(grant.cost_policy),
        "confirmed_unknown_policies": tuple(
            value.value for value in grant.confirmed_unknown_policies
        ),
        "issued_at": grant.issued_at,
        "expires_at": grant.expires_at,
        "one_shot": grant.one_shot,
    }


def _grant_payload(grant: "ConsentGrant") -> dict[str, object]:
    return {
        "grant_terms_digest": grant.grant_terms_digest,
        "consumed_at": grant.consumed_at,
        "revoked_at": grant.revoked_at,
    }


@runtime_final
class ConsentGrant:
    """One immutable revision of a consent grant."""

    __slots__ = (
        "grant_id",
        "request_id",
        "policy_version",
        "binding_id",
        "provider_profile_id",
        "provider_profile_digest",
        "pipeline_kind",
        "endpoint_policy_version",
        "network_policy_version",
        "tls_policy_ref",
        "network_scope",
        "allowed_network_operations",
        "capture_scope_kind",
        "capture_scope_fingerprint",
        "compute_location",
        "processing_region",
        "retention_policy",
        "data_policy",
        "cost_policy",
        "confirmed_unknown_policies",
        "issued_at",
        "expires_at",
        "one_shot",
        "consumed_at",
        "revoked_at",
        "grant_terms_digest",
        "grant_digest",
    )

    def __init__(
        self,
        *,
        grant_id: UUID,
        request_id: UUID | None,
        policy_version: str,
        binding_id: str,
        provider_profile_id: str,
        provider_profile_digest: Digest256,
        pipeline_kind: PipelineKind,
        endpoint_policy_version: str,
        network_policy_version: str,
        tls_policy_ref: str | ContractMarker,
        network_scope: NetworkScope,
        allowed_network_operations: tuple[ConsentNetworkOperation, ...],
        capture_scope_kind: CaptureScopeKind,
        capture_scope_fingerprint: Digest256 | None,
        compute_location: ComputeLocation,
        processing_region: str | ContractMarker,
        retention_policy: PolicyValue,
        data_policy: PolicyValue,
        cost_policy: PolicyValue,
        confirmed_unknown_policies: tuple[UnknownPolicyDimension, ...],
        issued_at: datetime,
        expires_at: datetime | None,
        one_shot: bool,
        consumed_at: datetime | None,
        revoked_at: datetime | None,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _GRANT_AUTHORITY:
            raise TypeError("ConsentGrant can only be created by ConsentLedger")
        require_uuid(grant_id, "grant_id")
        if request_id is not None:
            require_uuid(request_id, "request_id")
        if policy_version != CONSENT_POLICY_VERSION:
            raise ValueError("unsupported consent policy_version")
        require_text(binding_id, "binding_id", max_length=512)
        require_text(
            provider_profile_id, "provider_profile_id", max_length=512
        )
        require_digest(provider_profile_digest, "provider_profile_digest")
        if type(pipeline_kind) is not PipelineKind:
            raise ValueError("pipeline_kind must be PipelineKind")
        require_text(
            endpoint_policy_version,
            "endpoint_policy_version",
            max_length=512,
        )
        require_text(
            network_policy_version,
            "network_policy_version",
            max_length=512,
        )
        checked_tls = _require_not_applicable_or_text(
            tls_policy_ref, "tls_policy_ref"
        )
        if type(network_scope) is not NetworkScope or network_scope is NetworkScope.NONE:
            raise ValueError("consent grant requires a concrete network_scope")
        if type(allowed_network_operations) is not tuple or not allowed_network_operations:
            raise ValueError("allowed_network_operations must be non-empty")
        if not all(
            type(operation) is ConsentNetworkOperation
            for operation in allowed_network_operations
        ):
            raise ValueError("allowed_network_operations contain an invalid value")
        operation_digests = tuple(
            operation.contract_digest()
            for operation in allowed_network_operations
        )
        if operation_digests != tuple(sorted(operation_digests)) or len(
            set(operation_digests)
        ) != len(operation_digests):
            raise ValueError(
                "allowed_network_operations must be unique and canonical"
            )
        if type(capture_scope_kind) is not CaptureScopeKind:
            raise ValueError("capture_scope_kind must be CaptureScopeKind")
        if capture_scope_fingerprint is not None:
            require_digest(
                capture_scope_fingerprint, "capture_scope_fingerprint"
            )
        if type(compute_location) is not ComputeLocation:
            raise ValueError("compute_location must be ComputeLocation")
        checked_region = _require_region(processing_region)
        require_policy_value(retention_policy, "retention_policy")
        require_policy_value(data_policy, "data_policy")
        require_policy_value(cost_policy, "cost_policy")
        confirmations = _require_unknown_confirmations(
            confirmed_unknown_policies,
            processing_region=checked_region,
            retention_policy=retention_policy,
            data_policy=data_policy,
            cost_policy=cost_policy,
        )
        require_aware_datetime(issued_at, "issued_at")
        if expires_at is not None:
            require_aware_datetime(expires_at, "expires_at")
            if expires_at <= issued_at:
                raise ValueError("expires_at must be later than issued_at")
        if type(one_shot) is not bool:
            raise ValueError("one_shot must be bool")
        for name, value in (
            ("consumed_at", consumed_at),
            ("revoked_at", revoked_at),
        ):
            if value is not None:
                require_aware_datetime(value, name)
                if value < issued_at:
                    raise ValueError(f"{name} cannot precede issued_at")
        if consumed_at is not None and not one_shot:
            raise ValueError("only one-shot grants can be consumed")
        if capture_scope_kind is CaptureScopeKind.FULL_SCREEN and (
            request_id is None or not one_shot
        ):
            raise ValueError(
                "full-screen grants must be request-bound and one-shot"
            )

        for name, value in (
            ("grant_id", grant_id),
            ("request_id", request_id),
            ("policy_version", policy_version),
            ("binding_id", binding_id),
            ("provider_profile_id", provider_profile_id),
            ("provider_profile_digest", provider_profile_digest),
            ("pipeline_kind", pipeline_kind),
            ("endpoint_policy_version", endpoint_policy_version),
            ("network_policy_version", network_policy_version),
            ("tls_policy_ref", checked_tls),
            ("network_scope", network_scope),
            ("allowed_network_operations", allowed_network_operations),
            ("capture_scope_kind", capture_scope_kind),
            ("capture_scope_fingerprint", capture_scope_fingerprint),
            ("compute_location", compute_location),
            ("processing_region", checked_region),
            ("retention_policy", retention_policy),
            ("data_policy", data_policy),
            ("cost_policy", cost_policy),
            ("confirmed_unknown_policies", confirmations),
            ("issued_at", issued_at),
            ("expires_at", expires_at),
            ("one_shot", one_shot),
            ("consumed_at", consumed_at),
            ("revoked_at", revoked_at),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "grant_terms_digest",
            digest256(
                "ConsentGrantTerms",
                CONSENT_GRANT_SCHEMA_VERSION,
                _grant_terms_payload(self),
            ),
        )
        object.__setattr__(
            self,
            "grant_digest",
            digest256(
                "ConsentGrant",
                CONSENT_GRANT_SCHEMA_VERSION,
                _grant_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ConsentGrant is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "ConsentGrant":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "ConsentGrant("
            f"grant_id={self.grant_id!r}, binding_id={self.binding_id!r}, "
            f"pipeline_kind={self.pipeline_kind.value!r}, "
            f"one_shot={self.one_shot!r}, "
            f"revoked={self.revoked_at is not None!r}, "
            f"consumed={self.consumed_at is not None!r}, "
            f"grant_digest_prefix={_short_digest(self.grant_digest)!r})"
        )

    def safe_metadata(self) -> dict[str, object]:
        return {
            "grant_id": str(self.grant_id),
            "binding_id": self.binding_id,
            "pipeline_kind": self.pipeline_kind.value,
            "capture_scope_kind": self.capture_scope_kind.value,
            "one_shot": self.one_shot,
            "revoked": self.revoked_at is not None,
            "consumed": self.consumed_at is not None,
            "grant_digest_prefix": _short_digest(self.grant_digest),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "ConsentGrant",
            CONSENT_GRANT_SCHEMA_VERSION,
            _grant_payload(self),
        )

    def recompute_terms_digest(self) -> Digest256:
        return digest256(
            "ConsentGrantTerms",
            CONSENT_GRANT_SCHEMA_VERSION,
            _grant_terms_payload(self),
        )

    def validate_integrity(self) -> None:
        try:
            canonical = ConsentGrant(
                grant_id=self.grant_id,
                request_id=self.request_id,
                policy_version=self.policy_version,
                binding_id=self.binding_id,
                provider_profile_id=self.provider_profile_id,
                provider_profile_digest=self.provider_profile_digest,
                pipeline_kind=self.pipeline_kind,
                endpoint_policy_version=self.endpoint_policy_version,
                network_policy_version=self.network_policy_version,
                tls_policy_ref=self.tls_policy_ref,
                network_scope=self.network_scope,
                allowed_network_operations=self.allowed_network_operations,
                capture_scope_kind=self.capture_scope_kind,
                capture_scope_fingerprint=self.capture_scope_fingerprint,
                compute_location=self.compute_location,
                processing_region=self.processing_region,
                retention_policy=self.retention_policy,
                data_policy=self.data_policy,
                cost_policy=self.cost_policy,
                confirmed_unknown_policies=self.confirmed_unknown_policies,
                issued_at=self.issued_at,
                expires_at=self.expires_at,
                one_shot=self.one_shot,
                consumed_at=self.consumed_at,
                revoked_at=self.revoked_at,
                _authority=_GRANT_AUTHORITY,
            )
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("consent grant integrity mismatch") from error
        if canonical.grant_terms_digest != self.grant_terms_digest:
            raise ValueError("consent grant terms integrity mismatch")
        if canonical.grant_digest != self.grant_digest:
            raise ValueError("consent grant integrity mismatch")

    def validate_active_at(self, now: datetime) -> None:
        require_aware_datetime(now, "now")
        self.validate_integrity()
        if now < self.issued_at:
            raise ValueError("consent grant is not active yet")
        if self.expires_at is not None and now >= self.expires_at:
            raise ValueError("consent grant has expired")
        if self.revoked_at is not None:
            raise ValueError("consent grant has been revoked")
        if self.consumed_at is not None:
            raise ValueError("one-shot consent grant has been consumed")
        for name, policy in (
            ("retention policy", self.retention_policy),
            ("data policy", self.data_policy),
            ("cost policy", self.cost_policy),
        ):
            validate_policy_value_at(policy, now, name=name)

    def _with_status(
        self,
        *,
        consumed_at: datetime | None,
        revoked_at: datetime | None,
    ) -> "ConsentGrant":
        return ConsentGrant(
            grant_id=self.grant_id,
            request_id=self.request_id,
            policy_version=self.policy_version,
            binding_id=self.binding_id,
            provider_profile_id=self.provider_profile_id,
            provider_profile_digest=self.provider_profile_digest,
            pipeline_kind=self.pipeline_kind,
            endpoint_policy_version=self.endpoint_policy_version,
            network_policy_version=self.network_policy_version,
            tls_policy_ref=self.tls_policy_ref,
            network_scope=self.network_scope,
            allowed_network_operations=self.allowed_network_operations,
            capture_scope_kind=self.capture_scope_kind,
            capture_scope_fingerprint=self.capture_scope_fingerprint,
            compute_location=self.compute_location,
            processing_region=self.processing_region,
            retention_policy=self.retention_policy,
            data_policy=self.data_policy,
            cost_policy=self.cost_policy,
            confirmed_unknown_policies=self.confirmed_unknown_policies,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            one_shot=self.one_shot,
            consumed_at=consumed_at,
            revoked_at=revoked_at,
            _authority=_GRANT_AUTHORITY,
        )


@runtime_final
class ConsentLedger:
    """Thread-safe in-memory authority for immutable grant revisions."""

    __slots__ = (
        "_lock",
        "_grants",
        "_issued_terms",
        "_current_grant_digests",
        "_revision",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_grants", {})
        object.__setattr__(self, "_issued_terms", {})
        object.__setattr__(self, "_current_grant_digests", {})
        object.__setattr__(self, "_revision", 0)

    def safe_metadata(self) -> dict[str, int]:
        with self._lock:
            return {
                "revision": self._revision,
                "grant_count": len(self._grants),
            }

    def issue_for_plan(
        self,
        *,
        planned: PlannedExecution,
        binding_id: str,
        grant_id: UUID,
        request_id: UUID | None,
        capture_scope_fingerprint: Digest256 | None,
        issued_at: datetime,
        expires_at: datetime | None,
        one_shot: bool,
        confirmed_unknown_policies: tuple[UnknownPolicyDimension, ...],
    ) -> ConsentGrant:
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        try:
            planned.validate_integrity()
        except ValueError as error:
            raise _privacy_error("执行计划完整性校验失败。") from error
        require_text(binding_id, "binding_id", max_length=512)
        require_uuid(grant_id, "grant_id")
        if request_id is not None and request_id != planned.plan.request_id:
            raise _privacy_error("同意记录未绑定当前请求。")

        stage = next(
            (
                candidate
                for candidate in planned.plan.stages
                if candidate.binding_id == binding_id
            ),
            None,
        )
        scope = next(
            (
                candidate
                for candidate in planned.plan.required_consent_scopes
                if candidate.binding_id == binding_id
            ),
            None,
        )
        if stage is None or scope is None or not stage.network_operations:
            raise _privacy_error("无法为计划外的网络阶段签发同意。")
        if (
            planned.plan.pipeline_kind is PipelineKind.DIRECT_MULTIMODAL
            and stage.compute_location
            in (ComputeLocation.REMOTE, ComputeLocation.UNKNOWN)
            and planned.plan.capture_scope_kind is CaptureScopeKind.FULL_SCREEN
        ):
            raise _privacy_error("第一阶段远程模型不允许全屏上传。")

        allowed_operations = tuple(
            sorted(
                (
                    ConsentNetworkOperation.from_plan_operation(operation)
                    for operation in stage.network_operations
                ),
                key=lambda operation: str(operation.contract_digest()),
            )
        )
        grant = ConsentGrant(
            grant_id=grant_id,
            request_id=request_id,
            policy_version=CONSENT_POLICY_VERSION,
            binding_id=stage.binding_id,
            provider_profile_id=stage.provider_profile_id,
            provider_profile_digest=stage.provider_profile_digest,
            pipeline_kind=planned.plan.pipeline_kind,
            endpoint_policy_version=stage.endpoint_policy_version,
            network_policy_version=stage.network_policy_version,
            tls_policy_ref=stage.tls_policy_ref,
            network_scope=stage.network_scope,
            allowed_network_operations=allowed_operations,
            capture_scope_kind=planned.plan.capture_scope_kind,
            capture_scope_fingerprint=capture_scope_fingerprint,
            compute_location=stage.compute_location,
            processing_region=stage.processing_region,
            retention_policy=scope.retention_policy,
            data_policy=scope.data_policy,
            cost_policy=scope.cost_policy,
            confirmed_unknown_policies=confirmed_unknown_policies,
            issued_at=issued_at,
            expires_at=expires_at,
            one_shot=one_shot,
            consumed_at=None,
            revoked_at=None,
            _authority=_GRANT_AUTHORITY,
        )
        with self._lock:
            if grant_id in self._grants:
                raise _privacy_error("同意记录标识已存在，不能替换原条款。")
            self._grants[grant_id] = grant
            self._issued_terms[grant_id] = grant.grant_terms_digest
            self._current_grant_digests[grant_id] = grant.grant_digest
            object.__setattr__(self, "_revision", self._revision + 1)
        return grant

    def snapshot_for_ids(
        self, grant_ids: tuple[UUID, ...]
    ) -> tuple[ConsentGrant, ...]:
        if type(grant_ids) is not tuple:
            raise TypeError("grant_ids must be a tuple")
        for grant_id in grant_ids:
            require_uuid(grant_id, "grant id")
        with self._lock:
            grants: list[ConsentGrant] = []
            for grant_id in grant_ids:
                grant = self._grants.get(grant_id)
                if grant is None:
                    raise _privacy_error("隐私授权引用的同意记录不存在。")
                self._validate_issued_terms(
                    grant,
                    expected_grant_id=grant_id,
                )
                grants.append(grant)
            return tuple(grants)

    def _validate_issued_terms(
        self,
        grant: ConsentGrant,
        *,
        expected_grant_id: UUID,
    ) -> None:
        if type(grant) is not ConsentGrant:
            raise _privacy_error("同意记录完整性校验失败。")
        if grant.grant_id != expected_grant_id:
            raise _privacy_error("同意记录标识与账本索引不一致。")
        try:
            grant.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _privacy_error("同意记录完整性校验失败。") from error
        if self._issued_terms.get(grant.grant_id) != grant.grant_terms_digest:
            raise _privacy_error("同意记录标识不能重新绑定其他条款。")
        if (
            self._current_grant_digests.get(grant.grant_id)
            != grant.grant_digest
        ):
            raise _privacy_error("同意记录状态版本与账本不一致。")

    def revoke(self, *, grant_id: UUID, revoked_at: datetime) -> ConsentGrant:
        require_uuid(grant_id, "grant_id")
        require_aware_datetime(revoked_at, "revoked_at")
        with self._lock:
            current = self._grants.get(grant_id)
            if current is None:
                raise _privacy_error("无法撤销不存在的同意记录。")
            self._validate_issued_terms(
                current,
                expected_grant_id=grant_id,
            )
            if current.revoked_at is not None:
                raise _privacy_error("同意记录已经撤销。")
            replacement = current._with_status(
                consumed_at=current.consumed_at,
                revoked_at=revoked_at,
            )
            self._grants[grant_id] = replacement
            self._current_grant_digests[grant_id] = replacement.grant_digest
            object.__setattr__(self, "_revision", self._revision + 1)
            return replacement

    def consume(self, *, grant_id: UUID, consumed_at: datetime) -> ConsentGrant:
        require_uuid(grant_id, "grant_id")
        require_aware_datetime(consumed_at, "consumed_at")
        with self._lock:
            current = self._grants.get(grant_id)
            if current is None:
                raise _privacy_error("无法消费不存在的同意记录。")
            self._validate_issued_terms(
                current,
                expected_grant_id=grant_id,
            )
            if not current.one_shot:
                raise _privacy_error("持久同意记录不能作为 one-shot 消费。")
            try:
                current.validate_active_at(consumed_at)
            except ValueError as error:
                raise _privacy_error("one-shot 同意记录当前不可消费。") from error
            replacement = current._with_status(
                consumed_at=consumed_at,
                revoked_at=current.revoked_at,
            )
            self._grants[grant_id] = replacement
            self._current_grant_digests[grant_id] = replacement.grant_digest
            object.__setattr__(self, "_revision", self._revision + 1)
            return replacement


def _authorization_payload(context: "AuthorizationContext") -> dict[str, object]:
    return {
        "authorization_id": context.authorization_id,
        "plan_id": context.plan_id,
        "plan_digest": context.plan_digest,
        "planned_execution_digest": context.planned_execution_digest,
        "consent_grant_ids": context.consent_grant_ids,
        "consent_grant_digests": context.consent_grant_digests,
        "authorized_at": context.authorized_at,
        "valid_until": context.valid_until,
    }


def _authorization_id_for(payload: dict[str, object]) -> UUID:
    seed = digest256(
        "AuthorizationIdentifier",
        AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
        payload,
    )
    return uuid5(_AUTHORIZATION_UUID_NAMESPACE, str(seed))


def _authorization_identifier_payload(
    *,
    plan_id: UUID,
    plan_digest: Digest256,
    planned_execution_digest: Digest256,
    consent_grant_ids: tuple[UUID, ...],
    consent_grant_digests: tuple[Digest256, ...],
    authorized_at: datetime,
    valid_until: datetime | None,
) -> dict[str, object]:
    return {
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "planned_execution_digest": planned_execution_digest,
        "consent_grant_ids": consent_grant_ids,
        "consent_grant_digests": consent_grant_digests,
        "authorized_at": authorized_at,
        "valid_until": valid_until,
    }


@runtime_final
class AuthorizationContext:
    """Plan- and grant-revision-bound privacy authorization."""

    __slots__ = (
        "authorization_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "consent_grant_ids",
        "consent_grant_digests",
        "authorized_at",
        "valid_until",
        "authorization_digest",
        "_consent_ledger",
    )

    def __init__(
        self,
        *,
        authorization_id: UUID,
        plan_id: UUID,
        plan_digest: Digest256,
        planned_execution_digest: Digest256,
        consent_grant_ids: tuple[UUID, ...],
        consent_grant_digests: tuple[Digest256, ...],
        authorized_at: datetime,
        valid_until: datetime | None,
        _consent_ledger: ConsentLedger | None = None,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _AUTHORIZATION_AUTHORITY:
            raise TypeError(
                "AuthorizationContext can only be created by PrivacyGate"
            )
        if type(_consent_ledger) is not ConsentLedger:
            raise TypeError(
                "AuthorizationContext requires its issuing ConsentLedger"
            )
        require_uuid(authorization_id, "authorization_id")
        require_uuid(plan_id, "plan_id")
        require_digest(plan_digest, "plan_digest")
        require_digest(
            planned_execution_digest, "planned_execution_digest"
        )
        if type(consent_grant_ids) is not tuple:
            raise ValueError("consent_grant_ids must be a tuple")
        if consent_grant_ids != tuple(sorted(consent_grant_ids, key=str)) or len(
            set(consent_grant_ids)
        ) != len(consent_grant_ids):
            raise ValueError("consent_grant_ids must be unique and canonical")
        if type(consent_grant_digests) is not tuple or len(
            consent_grant_digests
        ) != len(consent_grant_ids):
            raise ValueError("consent grant digests must align with ids")
        for grant_id in consent_grant_ids:
            require_uuid(grant_id, "consent grant id")
        for grant_digest in consent_grant_digests:
            require_digest(grant_digest, "consent grant digest")
        require_aware_datetime(authorized_at, "authorized_at")
        if valid_until is not None:
            require_aware_datetime(valid_until, "valid_until")
            if valid_until <= authorized_at:
                raise ValueError("valid_until must be later than authorized_at")
        expected_authorization_id = _authorization_id_for(
            _authorization_identifier_payload(
                plan_id=plan_id,
                plan_digest=plan_digest,
                planned_execution_digest=planned_execution_digest,
                consent_grant_ids=consent_grant_ids,
                consent_grant_digests=consent_grant_digests,
                authorized_at=authorized_at,
                valid_until=valid_until,
            )
        )
        if authorization_id != expected_authorization_id:
            raise ValueError("authorization_id does not bind this context")

        for name, value in (
            ("authorization_id", authorization_id),
            ("plan_id", plan_id),
            ("plan_digest", plan_digest),
            ("planned_execution_digest", planned_execution_digest),
            ("consent_grant_ids", consent_grant_ids),
            ("consent_grant_digests", consent_grant_digests),
            ("authorized_at", authorized_at),
            ("valid_until", valid_until),
            ("_consent_ledger", _consent_ledger),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "authorization_digest",
            digest256(
                "AuthorizationContext",
                AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
                _authorization_payload(self),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AuthorizationContext is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "AuthorizationContext":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "AuthorizationContext("
            f"authorization_id={self.authorization_id!r}, "
            f"plan_id={self.plan_id!r}, grant_count={len(self.consent_grant_ids)!r}, "
            f"valid_until={self.valid_until!r}, "
            f"authorization_digest_prefix={_short_digest(self.authorization_digest)!r})"
        )

    def safe_metadata(self) -> dict[str, object]:
        return {
            "authorization_id": str(self.authorization_id),
            "plan_id": str(self.plan_id),
            "plan_digest_prefix": _short_digest(self.plan_digest),
            "grant_count": len(self.consent_grant_ids),
            "valid_until": self.valid_until,
            "authorization_digest_prefix": _short_digest(
                self.authorization_digest
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "AuthorizationContext",
            AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
            _authorization_payload(self),
        )

    def validate_integrity(self) -> None:
        try:
            canonical = AuthorizationContext(
                authorization_id=self.authorization_id,
                plan_id=self.plan_id,
                plan_digest=self.plan_digest,
                planned_execution_digest=self.planned_execution_digest,
                consent_grant_ids=self.consent_grant_ids,
                consent_grant_digests=self.consent_grant_digests,
                authorized_at=self.authorized_at,
                valid_until=self.valid_until,
                _consent_ledger=self._consent_ledger,
                _authority=_AUTHORIZATION_AUTHORITY,
            )
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("authorization context integrity mismatch") from error
        if canonical.authorization_digest != self.authorization_digest:
            raise ValueError("authorization context integrity mismatch")


def _grant_covers_stage(
    grant: ConsentGrant,
    *,
    planned: PlannedExecution,
    stage: ExecutionPlanStage,
) -> bool:
    plan = planned.plan
    scope = next(
        (
            value
            for value in plan.required_consent_scopes
            if value.binding_id == stage.binding_id
        ),
        None,
    )
    if scope is None:
        return False
    if (
        grant.policy_version != CONSENT_POLICY_VERSION
        or (grant.request_id is not None and grant.request_id != plan.request_id)
        or grant.binding_id != stage.binding_id
        or grant.provider_profile_id != stage.provider_profile_id
        or grant.provider_profile_digest != stage.provider_profile_digest
        or grant.pipeline_kind is not plan.pipeline_kind
        or grant.endpoint_policy_version != stage.endpoint_policy_version
        or grant.network_policy_version != stage.network_policy_version
        or grant.tls_policy_ref != stage.tls_policy_ref
        or grant.network_scope is not stage.network_scope
        or grant.capture_scope_kind is not plan.capture_scope_kind
        or grant.compute_location is not stage.compute_location
        or grant.processing_region != stage.processing_region
        or grant.retention_policy != scope.retention_policy
        or grant.data_policy != scope.data_policy
        or grant.cost_policy != scope.cost_policy
        or len(grant.allowed_network_operations) != len(stage.network_operations)
    ):
        return False
    unused = list(grant.allowed_network_operations)
    for operation in stage.network_operations:
        matches = [
            candidate
            for candidate in unused
            if candidate.covers(operation)
        ]
        if len(matches) != 1:
            return False
        unused.remove(matches[0])
    return not unused


def _policy_expiries(
    planned: PlannedExecution, grants: tuple[ConsentGrant, ...]
) -> tuple[datetime, ...]:
    expiries: list[datetime] = []
    values: list[PolicyValue] = [planned.plan.cost_policy]
    for scope in planned.plan.required_consent_scopes:
        values.extend(
            (scope.retention_policy, scope.data_policy, scope.cost_policy)
        )
    for stage in planned.resolved_pipeline.stages:
        provider = stage.provider_profile
        values.extend(
            (
                provider.retention_policy,
                provider.data_policy,
                provider.cost_policy,
            )
        )
    for grant in grants:
        values.extend(
            (grant.retention_policy, grant.data_policy, grant.cost_policy)
        )
        if grant.expires_at is not None:
            expiries.append(grant.expires_at)
    for value in values:
        if type(value) is PolicySnapshot and value.expires_at is not None:
            expiries.append(value.expires_at)
    return tuple(expiries)


def _canonical_grant_pairs(
    grants: tuple[ConsentGrant, ...]
) -> tuple[tuple[UUID, Digest256], ...]:
    return tuple(
        sorted(
            ((grant.grant_id, grant.grant_digest) for grant in grants),
            key=lambda pair: str(pair[0]),
        )
    )


@runtime_final
class PrivacyGate:
    """Prove exact grant coverage and issue a time-bounded context."""

    __slots__ = ()

    def _run_authorized_action(
        self,
        *,
        planned: PlannedExecution,
        authorization: AuthorizationContext,
        ledger: ConsentLedger,
        now: datetime,
        action: Callable[[], _T],
        _authority: object | None = None,
    ) -> _T:
        """Linearize a trusted state transition against grant revisions."""

        if _authority is not _ATOMIC_PRIVACY_AUTHORITY:
            raise TypeError("atomic privacy actions require trusted core authority")
        if type(ledger) is not ConsentLedger:
            raise TypeError("ledger must be ConsentLedger")
        if not callable(action):
            raise TypeError("action must be callable")
        # The lock order for combined W06 transitions is always ConsentLedger
        # then CaptureAuthorizationLedger. No capture-ledger operation acquires
        # this lock, so revoke/consume and capture transitions are linearizable.
        with ledger._lock:
            self.validate_authorization(
                planned=planned,
                authorization=authorization,
                ledger=ledger,
                now=now,
            )
            return action()

    def authorize(
        self,
        *,
        planned: PlannedExecution,
        ledger: ConsentLedger,
        consent_grant_ids: tuple[UUID, ...],
        now: datetime,
    ) -> AuthorizationContext:
        try:
            grants = self._validate_selected_grants(
                planned=planned,
                ledger=ledger,
                consent_grant_ids=consent_grant_ids,
                now=now,
            )
        except EndpointPolicyError:
            raise
        except ValueError as error:
            raise _privacy_error("隐私授权输入完整性校验失败。") from error
        expiries = _policy_expiries(planned, grants)
        valid_until = min(expiries) if expiries else None
        if valid_until is not None and now >= valid_until:
            raise _privacy_error("同意或政策快照已经过期。")
        pairs = _canonical_grant_pairs(grants)
        identifier_payload = _authorization_identifier_payload(
            plan_id=planned.plan.plan_id,
            plan_digest=planned.plan.plan_digest,
            planned_execution_digest=planned.planned_execution_digest,
            consent_grant_ids=tuple(pair[0] for pair in pairs),
            consent_grant_digests=tuple(pair[1] for pair in pairs),
            authorized_at=now,
            valid_until=valid_until,
        )
        context = AuthorizationContext(
            authorization_id=_authorization_id_for(identifier_payload),
            plan_id=planned.plan.plan_id,
            plan_digest=planned.plan.plan_digest,
            planned_execution_digest=planned.planned_execution_digest,
            consent_grant_ids=tuple(pair[0] for pair in pairs),
            consent_grant_digests=tuple(pair[1] for pair in pairs),
            authorized_at=now,
            valid_until=valid_until,
            _consent_ledger=ledger,
            _authority=_AUTHORIZATION_AUTHORITY,
        )
        context.validate_integrity()
        return context

    def validate_authorization(
        self,
        *,
        planned: PlannedExecution,
        authorization: AuthorizationContext,
        ledger: ConsentLedger,
        now: datetime,
    ) -> None:
        if type(authorization) is not AuthorizationContext:
            raise TypeError("authorization must be AuthorizationContext")
        require_aware_datetime(now, "now")
        try:
            planned.validate_integrity()
            authorization.validate_integrity()
        except ValueError as error:
            raise _privacy_error("隐私授权完整性校验失败。") from error
        if (
            authorization._consent_ledger is not ledger
            or authorization.plan_id != planned.plan.plan_id
            or authorization.plan_digest != planned.plan.plan_digest
            or authorization.planned_execution_digest
            != planned.planned_execution_digest
        ):
            raise _privacy_error("隐私授权未绑定当前执行计划。")
        if now < authorization.authorized_at:
            raise _privacy_error("隐私授权尚未生效。")
        if (
            authorization.valid_until is not None
            and now >= authorization.valid_until
        ):
            raise _privacy_error("隐私授权已经过期。")
        try:
            grants = self._validate_selected_grants(
                planned=planned,
                ledger=ledger,
                consent_grant_ids=authorization.consent_grant_ids,
                now=now,
            )
        except EndpointPolicyError:
            raise
        except ValueError as error:
            raise _privacy_error("隐私授权输入完整性校验失败。") from error
        pairs = _canonical_grant_pairs(grants)
        if (
            tuple(pair[0] for pair in pairs)
            != authorization.consent_grant_ids
            or tuple(pair[1] for pair in pairs)
            != authorization.consent_grant_digests
        ):
            raise _privacy_error("隐私授权引用的同意条款已经变化。")
        expiries = _policy_expiries(planned, grants)
        expected_valid_until = min(expiries) if expiries else None
        if expected_valid_until != authorization.valid_until:
            raise _privacy_error("隐私授权有效期与当前条款不一致。")

    @staticmethod
    def _validate_selected_grants(
        *,
        planned: PlannedExecution,
        ledger: ConsentLedger,
        consent_grant_ids: tuple[UUID, ...],
        now: datetime,
    ) -> tuple[ConsentGrant, ...]:
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(ledger) is not ConsentLedger:
            raise TypeError("ledger must be ConsentLedger")
        require_aware_datetime(now, "now")
        planned.validate_integrity()
        if type(consent_grant_ids) is not tuple:
            raise TypeError("consent_grant_ids must be a tuple")
        if consent_grant_ids != tuple(
            sorted(consent_grant_ids, key=str)
        ) or len(set(consent_grant_ids)) != len(consent_grant_ids):
            raise _privacy_error("同意记录标识必须唯一且规范排序。")
        network_stages = tuple(
            stage for stage in planned.plan.stages if stage.network_operations
        )
        if len(consent_grant_ids) != len(network_stages):
            raise _privacy_error("每个网络阶段都必须由一个同意记录覆盖。")
        grants = ledger.snapshot_for_ids(consent_grant_ids)
        unmatched = list(grants)
        for stage in network_stages:
            matches: list[ConsentGrant] = []
            for grant in unmatched:
                try:
                    grant.validate_active_at(now)
                except ValueError:
                    continue
                if _grant_covers_stage(grant, planned=planned, stage=stage):
                    matches.append(grant)
            if len(matches) != 1:
                raise _privacy_error()
            unmatched.remove(matches[0])
        if unmatched:
            raise _privacy_error("存在未被当前执行计划使用的同意记录。")
        return grants


__all__ = [
    "AUTHORIZATION_CONTEXT_SCHEMA_VERSION",
    "CONSENT_GRANT_SCHEMA_VERSION",
    "CONSENT_NETWORK_OPERATION_SCHEMA_VERSION",
    "CONSENT_POLICY_VERSION",
    "AuthorizationContext",
    "ConsentGrant",
    "ConsentLedger",
    "ConsentNetworkOperation",
    "PrivacyGate",
    "UnknownPolicyDimension",
]
