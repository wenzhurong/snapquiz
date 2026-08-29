"""Immutable execution-plan snapshots for provider-neutral routing."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
from uuid import UUID

from snapquiz.domain._validation import (
    HTTP_TOKEN_RE,
    canonical_http_url_host,
    require_canonical_http_url,
    require_digest,
    require_non_secret_query_key,
    require_plain_int,
    require_non_secret_header_name,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.capture import CaptureConstraints, CaptureScopeKind
from snapquiz.domain.digest import (
    CANONICAL_SERIALIZER_VERSION,
    Digest256,
    digest256,
)
from snapquiz.domain.policy import (
    ContractMarker,
    PolicyValue,
    policy_value_payload,
    require_policy_value,
)
from snapquiz.domain.solve import PipelineKind, SOLVE_RESULT_SCHEMA_VERSION, StageRole

EXECUTION_PLAN_SCHEMA_VERSION = "snapquiz.execution-plan.v1"
_LAN_LITERAL_NETWORKS = tuple(
    ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)


class NetworkScope(str, Enum):
    NONE = "none"
    LOOPBACK = "loopback"
    LAN = "lan"
    INTERNET = "internet"


class ComputeLocation(str, Enum):
    LOCAL_VERIFIED = "local_verified"
    REMOTE = "remote"
    UNKNOWN = "unknown"


class NetworkOperationPurpose(str, Enum):
    UPLOAD = "upload"
    INFERENCE = "inference"
    DELETE = "delete"
    REMOTE_REPAIR = "remote_repair"
    MODEL_DISCOVERY = "model_discovery"


class QueryPolicyKind(str, Enum):
    EMPTY = "empty"
    EXACT = "exact"


class CredentialInjectionSlot(str, Enum):
    AUTHORIZATION_HEADER = "authorization_header"
    PROVIDER_HEADER = "provider_header"
    NOT_APPLICABLE = "not_applicable"


class OutboundDataKind(str, Enum):
    IMAGE = "image"
    OCR_TEXT = "ocr_text"
    USER_HINT = "user_hint"
    PROVIDER_RESPONSE_TEXT = "provider_response_text"


def _require_canonical_tuple(values: tuple[object, ...], name: str) -> None:
    if type(values) is not tuple:
        raise ValueError(f"{name} must be a tuple")
    normalized: list[str] = []
    for value in values:
        if type(value) is str:
            normalized.append(value)
        elif isinstance(value, Enum):
            normalized.append(str(value.value))
        else:
            raise ValueError(f"{name} contains an unsupported value type")
    canonical = tuple(
        value
        for _, value in sorted(
            zip(normalized, values), key=lambda item: item[0]
        )
    )
    if values != canonical or len(set(values)) != len(values):
        raise ValueError(f"{name} must be unique and in canonical sorted order")


def _require_explicit_endpoint(value: object) -> str:
    return require_canonical_http_url(
        value, "canonical_endpoint", allow_query=False
    )


def _is_loopback_endpoint(endpoint: str) -> bool:
    hostname = canonical_http_url_host(endpoint)
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _marker_or_text_payload(value: str | ContractMarker) -> str:
    return value.value if isinstance(value, ContractMarker) else value


def _require_not_applicable_or_text(value: object, name: str) -> str | ContractMarker:
    if value is ContractMarker.NOT_APPLICABLE:
        return value
    if isinstance(value, ContractMarker):
        raise ValueError(f"{name} cannot be unknown")
    text = require_text(value, name, max_length=512)
    if text in (ContractMarker.NOT_APPLICABLE.value, ContractMarker.UNKNOWN.value):
        raise ValueError(f"{name} cannot use a reserved marker as plain text")
    return text


def _require_region(value: object) -> str | ContractMarker:
    if value is ContractMarker.UNKNOWN:
        return value
    if isinstance(value, ContractMarker):
        raise ValueError("processing_region cannot be not_applicable")
    text = require_text(value, "processing_region", max_length=128)
    if text in (ContractMarker.NOT_APPLICABLE.value, ContractMarker.UNKNOWN.value):
        raise ValueError("processing_region cannot use a reserved marker as plain text")
    return text


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class CanonicalQueryPolicy:
    kind: QueryPolicyKind
    exact_items: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, QueryPolicyKind):
            raise ValueError("kind must be QueryPolicyKind")
        if type(self.exact_items) is not tuple:
            raise ValueError("exact_items must be a tuple")
        for item in self.exact_items:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError("exact query items must be (key, value) tuples")
            require_non_secret_query_key(item[0])
            require_text(item[1], "query value", max_length=1_024)
        if self.kind is QueryPolicyKind.EMPTY and self.exact_items:
            raise ValueError("empty query policy cannot carry exact items")
        if self.kind is QueryPolicyKind.EXACT:
            raise ValueError(
                "exact query policy is disabled until M2 binds a trusted endpoint profile"
            )
        if self.exact_items != tuple(sorted(self.exact_items)):
            raise ValueError("exact query items must be in canonical sorted order")
        if len({key for key, _ in self.exact_items}) != len(self.exact_items):
            raise ValueError("exact query keys must be unique")

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "exact_items": [
                {"key": key, "value": value} for key, value in self.exact_items
            ],
        }


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanNetworkOperation:
    operation_id: UUID
    purpose: NetworkOperationPurpose
    http_method: str
    canonical_endpoint: str
    canonical_query_policy: CanonicalQueryPolicy
    content_type: str
    allowed_non_secret_headers: tuple[str, ...]
    credential_injection_slot: CredentialInjectionSlot
    outbound_data: tuple[OutboundDataKind, ...]
    retention_policy: PolicyValue
    data_policy: PolicyValue
    billable: bool | ContractMarker

    def __post_init__(self) -> None:
        require_uuid(self.operation_id, "operation_id")
        if not isinstance(self.purpose, NetworkOperationPurpose):
            raise ValueError("purpose must be NetworkOperationPurpose")
        method = require_text(self.http_method, "http_method", max_length=32)
        if method != method.upper() or HTTP_TOKEN_RE.fullmatch(method) is None:
            raise ValueError("http_method must be an uppercase HTTP token")
        _require_explicit_endpoint(self.canonical_endpoint)
        if type(self.canonical_query_policy) is not CanonicalQueryPolicy:
            raise ValueError("canonical_query_policy must be CanonicalQueryPolicy")
        content_type = require_text(self.content_type, "content_type", max_length=256)
        if content_type != content_type.lower():
            raise ValueError("content_type must be normalized lowercase text")
        _require_canonical_tuple(self.allowed_non_secret_headers, "allowed_non_secret_headers")
        for header_name in self.allowed_non_secret_headers:
            require_non_secret_header_name(header_name, "allowed header name")
        if not isinstance(self.credential_injection_slot, CredentialInjectionSlot):
            raise ValueError("credential_injection_slot must be CredentialInjectionSlot")
        _require_canonical_tuple(self.outbound_data, "outbound_data")
        if not self.outbound_data or not all(
            isinstance(item, OutboundDataKind) for item in self.outbound_data
        ):
            raise ValueError("outbound_data must contain OutboundDataKind values")
        require_policy_value(self.retention_policy, "retention_policy")
        require_policy_value(self.data_policy, "data_policy")
        if type(self.billable) is not bool and self.billable is not ContractMarker.UNKNOWN:
            raise ValueError("billable must be bool or unknown")

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "purpose": self.purpose.value,
            "http_method": self.http_method,
            "canonical_endpoint": self.canonical_endpoint,
            "canonical_query_policy": self.canonical_query_policy.as_digest_payload(),
            "content_type": self.content_type,
            "allowed_non_secret_headers": self.allowed_non_secret_headers,
            "credential_injection_slot": self.credential_injection_slot.value,
            "outbound_data": tuple(item.value for item in self.outbound_data),
            "retention_policy": policy_value_payload(self.retention_policy),
            "data_policy": policy_value_payload(self.data_policy),
            "billable": (
                self.billable.value
                if isinstance(self.billable, ContractMarker)
                else self.billable
            ),
        }


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class RequiredConsentScope:
    binding_id: str
    provider_profile_id: str
    provider_profile_digest: Digest256 = field(repr=False)
    network_scope: NetworkScope
    compute_location: ComputeLocation
    processing_region: str | ContractMarker
    retention_policy: PolicyValue
    data_policy: PolicyValue
    cost_policy: PolicyValue
    network_operation_ids: tuple[UUID, ...]

    def __post_init__(self) -> None:
        require_text(self.binding_id, "binding_id")
        require_text(self.provider_profile_id, "provider_profile_id")
        require_digest(self.provider_profile_digest, "provider_profile_digest")
        if not isinstance(self.network_scope, NetworkScope) or self.network_scope is NetworkScope.NONE:
            raise ValueError("a consent scope requires a non-none network_scope")
        if not isinstance(self.compute_location, ComputeLocation):
            raise ValueError("compute_location must be ComputeLocation")
        _require_region(self.processing_region)
        require_policy_value(self.retention_policy, "retention_policy")
        require_policy_value(self.data_policy, "data_policy")
        require_policy_value(self.cost_policy, "cost_policy")
        if type(self.network_operation_ids) is not tuple or not self.network_operation_ids:
            raise ValueError("network_operation_ids must be a non-empty tuple")
        for operation_id in self.network_operation_ids:
            require_uuid(operation_id, "network operation id")
        if len(set(self.network_operation_ids)) != len(self.network_operation_ids):
            raise ValueError("network_operation_ids must be unique")
        if self.network_operation_ids != tuple(
            sorted(self.network_operation_ids, key=str)
        ):
            raise ValueError("network_operation_ids must be in canonical sorted order")

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "binding_id": self.binding_id,
            "provider_profile_id": self.provider_profile_id,
            "provider_profile_digest": self.provider_profile_digest,
            "network_scope": self.network_scope.value,
            "compute_location": self.compute_location.value,
            "processing_region": _marker_or_text_payload(self.processing_region),
            "retention_policy": policy_value_payload(self.retention_policy),
            "data_policy": policy_value_payload(self.data_policy),
            "cost_policy": policy_value_payload(self.cost_policy),
            "network_operation_ids": self.network_operation_ids,
        }


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanStage:
    stage_id: UUID
    role: StageRole
    binding_id: str
    provider_profile_id: str
    provider_profile_digest: Digest256 = field(repr=False)
    provider_id: str
    model_id: str | None
    component_id: str | None
    component_version: str | None
    adapter_family: str
    adapter_version: str
    capabilities_ref: str
    capabilities_digest: Digest256 = field(repr=False)
    endpoint_policy_version: str
    network_policy_version: str
    tls_policy_ref: str | ContractMarker
    credential_binding_ref: str | ContractMarker
    credential_binding_digest: Digest256 | ContractMarker = field(repr=False)
    network_scope: NetworkScope
    compute_location: ComputeLocation
    processing_region: str | ContractMarker
    max_attempts_per_operation: int
    network_operations: tuple[ExecutionPlanNetworkOperation, ...]

    def __post_init__(self) -> None:
        require_uuid(self.stage_id, "stage_id")
        if not isinstance(self.role, StageRole):
            raise ValueError("role must be StageRole")
        for name in (
            "binding_id",
            "provider_profile_id",
            "provider_id",
            "adapter_family",
            "adapter_version",
            "capabilities_ref",
            "endpoint_policy_version",
            "network_policy_version",
        ):
            require_text(getattr(self, name), name)
        require_digest(self.provider_profile_digest, "provider_profile_digest")
        require_digest(self.capabilities_digest, "capabilities_digest")
        for name in ("model_id", "component_id", "component_version"):
            value = getattr(self, name)
            if value is not None:
                require_text(value, name)
        if self.role in (StageRole.SOLVER, StageRole.TEXT_SOLVER):
            if self.model_id is None or self.component_id is not None or self.component_version is not None:
                raise ValueError("solver stages require only model_id")
        elif self.role is StageRole.OCR:
            if self.model_id is not None or self.component_id is None or self.component_version is None:
                raise ValueError("ocr stages require component_id and component_version only")
        _require_not_applicable_or_text(self.tls_policy_ref, "tls_policy_ref")
        _require_not_applicable_or_text(
            self.credential_binding_ref, "credential_binding_ref"
        )
        if self.credential_binding_digest is not ContractMarker.NOT_APPLICABLE:
            if isinstance(self.credential_binding_digest, ContractMarker):
                raise ValueError("credential_binding_digest cannot be unknown")
            require_digest(self.credential_binding_digest, "credential_binding_digest")
        ref_is_na = self.credential_binding_ref is ContractMarker.NOT_APPLICABLE
        digest_is_na = self.credential_binding_digest is ContractMarker.NOT_APPLICABLE
        if ref_is_na != digest_is_na:
            raise ValueError("credential binding ref and digest applicability must match")
        if not isinstance(self.network_scope, NetworkScope):
            raise ValueError("network_scope must be NetworkScope")
        if not isinstance(self.compute_location, ComputeLocation):
            raise ValueError("compute_location must be ComputeLocation")
        _require_region(self.processing_region)
        require_plain_int(
            self.max_attempts_per_operation,
            "max_attempts_per_operation",
            minimum=0,
        )
        if type(self.network_operations) is not tuple or not all(
            type(operation) is ExecutionPlanNetworkOperation
            for operation in self.network_operations
        ):
            raise ValueError("network_operations must contain plan operations")
        operation_ids = tuple(operation.operation_id for operation in self.network_operations)
        if len(set(operation_ids)) != len(operation_ids):
            raise ValueError("network operation ids must be unique within a stage")
        has_network = bool(self.network_operations)
        if has_network != (self.network_scope is not NetworkScope.NONE):
            raise ValueError("network_scope=none must exactly match an empty operation list")
        if has_network != (self.max_attempts_per_operation > 0):
            raise ValueError("network stages require attempts; local stages require zero")
        if not has_network and self.compute_location is not ComputeLocation.LOCAL_VERIFIED:
            raise ValueError(
                "a zero-network stage must be local_verified"
            )
        if (
            has_network
            and self.compute_location is ComputeLocation.LOCAL_VERIFIED
            and self.network_scope is not NetworkScope.LOOPBACK
        ):
            raise ValueError("local_verified network stages may use only loopback")
        if not has_network:
            if self.tls_policy_ref is not ContractMarker.NOT_APPLICABLE or not ref_is_na:
                raise ValueError("non-network stages cannot carry TLS or credential bindings")
        elif self.network_scope in (NetworkScope.LAN, NetworkScope.INTERNET):
            if self.tls_policy_ref is ContractMarker.NOT_APPLICABLE:
                raise ValueError("LAN/internet stages require an explicit TLS policy")
            if any(
                urlsplit(operation.canonical_endpoint).scheme != "https"
                for operation in self.network_operations
            ):
                raise ValueError("LAN/internet operations require HTTPS endpoints")
        for operation in self.network_operations:
            is_loopback = _is_loopback_endpoint(operation.canonical_endpoint)
            if self.network_scope is NetworkScope.LOOPBACK:
                if not is_loopback:
                    raise ValueError("loopback operations must target a loopback host")
                continue
            if is_loopback:
                raise ValueError("LAN/internet operations cannot target a loopback host")
            host = canonical_http_url_host(operation.canonical_endpoint)
            try:
                literal_ip = ip_address(host)
            except ValueError:
                continue
            if (
                literal_ip.is_unspecified
                or literal_ip.is_multicast
                or literal_ip.is_reserved
            ):
                raise ValueError("network operation targets a forbidden literal address")
            is_lan_literal = any(
                literal_ip in network
                for network in _LAN_LITERAL_NETWORKS
                if literal_ip.version == network.version
            )
            if self.network_scope is NetworkScope.LAN and not is_lan_literal:
                raise ValueError("LAN operations require an explicit LAN literal address")
            if self.network_scope is NetworkScope.INTERNET and not literal_ip.is_global:
                raise ValueError("internet operations require a global unicast literal address")
        for operation in self.network_operations:
            slot_is_na = (
                operation.credential_injection_slot
                is CredentialInjectionSlot.NOT_APPLICABLE
            )
            if slot_is_na != ref_is_na:
                raise ValueError("operation credential slot must match stage binding")

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "stage_id": self.stage_id,
            "role": self.role.value,
            "binding_id": self.binding_id,
            "provider_profile_id": self.provider_profile_id,
            "provider_profile_digest": self.provider_profile_digest,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "component_id": self.component_id,
            "component_version": self.component_version,
            "adapter_family": self.adapter_family,
            "adapter_version": self.adapter_version,
            "capabilities_ref": self.capabilities_ref,
            "capabilities_digest": self.capabilities_digest,
            "endpoint_policy_version": self.endpoint_policy_version,
            "network_policy_version": self.network_policy_version,
            "tls_policy_ref": _marker_or_text_payload(self.tls_policy_ref),
            "credential_binding_ref": _marker_or_text_payload(
                self.credential_binding_ref
            ),
            "credential_binding_digest": (
                self.credential_binding_digest.value
                if isinstance(self.credential_binding_digest, ContractMarker)
                else self.credential_binding_digest
            ),
            "network_scope": self.network_scope.value,
            "compute_location": self.compute_location.value,
            "processing_region": _marker_or_text_payload(self.processing_region),
            "max_attempts_per_operation": self.max_attempts_per_operation,
            "network_operations": tuple(
                operation.as_digest_payload() for operation in self.network_operations
            ),
        }


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlan:
    plan_id: UUID
    request_id: UUID
    pipeline_profile_id: str
    pipeline_profile_digest: Digest256 = field(repr=False)
    pipeline_kind: PipelineKind
    prompt_policy_digest: Digest256 = field(repr=False)
    result_validator_version: str
    image_preprocessing_policy_version: str
    capture_scope_kind: CaptureScopeKind
    capture_constraints: CaptureConstraints
    preview_required: bool
    required_consent_scopes: tuple[RequiredConsentScope, ...]
    stages: tuple[ExecutionPlanStage, ...]
    requested_result_schema_version: str
    max_output_tokens: int
    timeout_budget_ms: int
    max_network_calls_total: int
    max_billable_calls: int
    cost_policy: PolicyValue
    fallback_branches: tuple["ExecutionPlan", ...]
    canonical_serializer_version: str = field(
        default=CANONICAL_SERIALIZER_VERSION
    )
    plan_digest: Digest256 = field(init=False, repr=False)

    def __post_init__(self) -> None:
        require_uuid(self.plan_id, "plan_id")
        require_uuid(self.request_id, "request_id")
        require_text(self.pipeline_profile_id, "pipeline_profile_id")
        require_digest(self.pipeline_profile_digest, "pipeline_profile_digest")
        if not isinstance(self.pipeline_kind, PipelineKind):
            raise ValueError("pipeline_kind must be PipelineKind")
        require_digest(self.prompt_policy_digest, "prompt_policy_digest")
        require_text(self.result_validator_version, "result_validator_version")
        require_text(
            self.image_preprocessing_policy_version,
            "image_preprocessing_policy_version",
        )
        if not isinstance(self.capture_scope_kind, CaptureScopeKind):
            raise ValueError("capture_scope_kind must be CaptureScopeKind")
        if type(self.capture_constraints) is not CaptureConstraints:
            raise ValueError("capture_constraints must be CaptureConstraints")
        if self.capture_constraints.allowed_display_ids != tuple(
            sorted(self.capture_constraints.allowed_display_ids)
        ):
            raise ValueError("allowed_display_ids must be in canonical sorted order")
        expects_full_screen = self.capture_scope_kind is CaptureScopeKind.FULL_SCREEN
        if self.capture_constraints.allow_full_screen != expects_full_screen:
            raise ValueError("capture constraint must exactly match capture_scope_kind")
        if type(self.preview_required) is not bool:
            raise ValueError("preview_required must be bool")
        if type(self.required_consent_scopes) is not tuple or not all(
            type(scope) is RequiredConsentScope
            for scope in self.required_consent_scopes
        ):
            raise ValueError("required_consent_scopes must contain consent scopes")
        if type(self.stages) is not tuple or not self.stages or not all(
            type(stage) is ExecutionPlanStage for stage in self.stages
        ):
            raise ValueError("stages must contain at least one plan stage")
        if self.requested_result_schema_version != SOLVE_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported requested_result_schema_version")
        require_plain_int(self.max_output_tokens, "max_output_tokens", minimum=1)
        require_plain_int(self.timeout_budget_ms, "timeout_budget_ms", minimum=1)
        require_plain_int(
            self.max_network_calls_total, "max_network_calls_total", minimum=0
        )
        require_plain_int(self.max_billable_calls, "max_billable_calls", minimum=0)
        require_policy_value(self.cost_policy, "cost_policy")
        if type(self.fallback_branches) is not tuple or not all(
            type(branch) is ExecutionPlan for branch in self.fallback_branches
        ):
            raise ValueError("fallback_branches must contain ExecutionPlan values")
        if self.canonical_serializer_version != CANONICAL_SERIALIZER_VERSION:
            raise ValueError("unsupported canonical_serializer_version")

        self._validate_stage_shape()
        self._validate_operation_and_consent_bindings()
        branch_ids = tuple(branch.plan_id for branch in self.fallback_branches)
        if self.plan_id in branch_ids or len(set(branch_ids)) != len(branch_ids):
            raise ValueError("fallback branch plan ids must be unique and non-recursive")
        object.__setattr__(self, "plan_digest", self.recompute_digest())

    def _validate_stage_shape(self) -> None:
        stage_ids = tuple(stage.stage_id for stage in self.stages)
        binding_ids = tuple(stage.binding_id for stage in self.stages)
        if len(set(stage_ids)) != len(stage_ids):
            raise ValueError("stage ids must be unique")
        if len(set(binding_ids)) != len(binding_ids):
            raise ValueError("stage binding ids must be unique")
        roles = tuple(stage.role for stage in self.stages)
        if self.pipeline_kind is PipelineKind.DIRECT_MULTIMODAL:
            if roles != (StageRole.SOLVER,):
                raise ValueError("direct_multimodal requires exactly one solver stage")
        elif roles != (StageRole.OCR, StageRole.TEXT_SOLVER):
            raise ValueError("ocr_text requires ordered ocr and text_solver stages")

    def _validate_operation_and_consent_bindings(self) -> None:
        all_operations = {
            operation.operation_id: (stage, operation)
            for stage in self.stages
            for operation in stage.network_operations
        }
        operation_count = sum(len(stage.network_operations) for stage in self.stages)
        if len(all_operations) != operation_count:
            raise ValueError("network operation ids must be globally unique")

        consent_bindings: set[str] = set()
        consent_operation_ids: list[UUID] = []
        stages_by_binding = {stage.binding_id: stage for stage in self.stages}
        expected_consent_order = tuple(
            stage.binding_id for stage in self.stages if stage.network_operations
        )
        if tuple(scope.binding_id for scope in self.required_consent_scopes) != (
            expected_consent_order
        ):
            raise ValueError("consent scopes must follow network stage order")
        for scope in self.required_consent_scopes:
            if scope.binding_id in consent_bindings:
                raise ValueError("each network binding requires exactly one consent scope")
            consent_bindings.add(scope.binding_id)
            stage = stages_by_binding.get(scope.binding_id)
            if stage is None or not stage.network_operations:
                raise ValueError("consent scope must reference a network stage binding")
            if (
                scope.provider_profile_id != stage.provider_profile_id
                or scope.provider_profile_digest != stage.provider_profile_digest
                or scope.network_scope is not stage.network_scope
                or scope.compute_location is not stage.compute_location
                or scope.processing_region != stage.processing_region
            ):
                raise ValueError("consent scope must match its frozen stage snapshot")
            expected_ids = tuple(
                operation.operation_id for operation in stage.network_operations
            )
            if set(scope.network_operation_ids) != set(expected_ids):
                raise ValueError("consent scope must cover every operation of its binding")
            if scope.cost_policy != self.cost_policy:
                raise ValueError("consent cost policy must match the plan cost policy")
            for operation in stage.network_operations:
                if (
                    operation.retention_policy != scope.retention_policy
                    or operation.data_policy != scope.data_policy
                ):
                    raise ValueError("consent policies must match every bound operation")
            consent_operation_ids.extend(scope.network_operation_ids)

        if set(consent_operation_ids) != set(all_operations):
            raise ValueError("consent scopes must cover all and only network operations")
        if len(consent_operation_ids) != len(set(consent_operation_ids)):
            raise ValueError("a network operation cannot be covered more than once")

        potential_attempts = sum(
            len(stage.network_operations) * stage.max_attempts_per_operation
            for stage in self.stages
        )
        if operation_count == 0:
            if self.max_network_calls_total != 0 or self.max_billable_calls != 0:
                raise ValueError("local-only plans require zero network and billable budgets")
        elif not operation_count <= self.max_network_calls_total <= potential_attempts:
            raise ValueError(
                "network budget must cover each operation once and stay within attempt limits"
            )
        billable_operation_count = sum(
            1
            for _, operation in all_operations.values()
            if operation.billable is True or operation.billable is ContractMarker.UNKNOWN
        )
        has_billable_operation = billable_operation_count > 0
        if has_billable_operation:
            if not billable_operation_count <= self.max_billable_calls <= self.max_network_calls_total:
                raise ValueError(
                    "billable budget must cover each billable operation once and stay within network budget"
                )
        elif self.max_billable_calls != 0:
            raise ValueError("non-billable plans require a zero billable budget")

    def as_digest_payload(self) -> dict[str, object]:
        """Return all declared fields except this plan's own plan_digest."""

        return {
            "plan_id": self.plan_id,
            "canonical_serializer_version": self.canonical_serializer_version,
            "request_id": self.request_id,
            "pipeline_profile_id": self.pipeline_profile_id,
            "pipeline_profile_digest": self.pipeline_profile_digest,
            "pipeline_kind": self.pipeline_kind.value,
            "prompt_policy_digest": self.prompt_policy_digest,
            "result_validator_version": self.result_validator_version,
            "image_preprocessing_policy_version": self.image_preprocessing_policy_version,
            "capture_scope_kind": self.capture_scope_kind.value,
            "capture_constraints": {
                "allowed_display_ids": self.capture_constraints.allowed_display_ids,
                "max_width_px": self.capture_constraints.max_width_px,
                "max_height_px": self.capture_constraints.max_height_px,
                "max_pixels": self.capture_constraints.max_pixels,
                "max_bytes": self.capture_constraints.max_bytes,
                "allow_full_screen": self.capture_constraints.allow_full_screen,
            },
            "preview_required": self.preview_required,
            "required_consent_scopes": tuple(
                scope.as_digest_payload() for scope in self.required_consent_scopes
            ),
            "stages": tuple(stage.as_digest_payload() for stage in self.stages),
            "requested_result_schema_version": self.requested_result_schema_version,
            "max_output_tokens": self.max_output_tokens,
            "timeout_budget_ms": self.timeout_budget_ms,
            "max_network_calls_total": self.max_network_calls_total,
            "max_billable_calls": self.max_billable_calls,
            "cost_policy": policy_value_payload(self.cost_policy),
            "fallback_branches": tuple(
                {
                    "plan_digest": branch.plan_digest,
                    "plan": branch.as_digest_payload(),
                }
                for branch in self.fallback_branches
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "ExecutionPlan",
            EXECUTION_PLAN_SCHEMA_VERSION,
            self.as_digest_payload(),
            canonical_serializer_version=self.canonical_serializer_version,
        )


def validate_phase1_remote_direct_plan(plan: ExecutionPlan) -> None:
    """Fail closed unless a plan has the exact Phase 1 remote-direct shape."""

    if type(plan) is not ExecutionPlan:
        raise TypeError("plan must be ExecutionPlan")
    if plan.recompute_digest() != plan.plan_digest:
        raise ValueError("plan digest does not match the frozen plan")
    if plan.pipeline_kind is not PipelineKind.DIRECT_MULTIMODAL:
        raise ValueError("Phase 1 requires direct_multimodal")
    if plan.capture_scope_kind is not CaptureScopeKind.SELECTED_REGION:
        raise ValueError("Phase 1 remote plans require selected_region")
    if not plan.preview_required:
        raise ValueError("Phase 1 remote plans require outbound preview")
    if plan.fallback_branches:
        raise ValueError("Phase 1 plans require an empty fallback list")
    if len(plan.stages) != 1 or len(plan.required_consent_scopes) != 1:
        raise ValueError("Phase 1 requires one stage and one consent scope")
    stage = plan.stages[0]
    if stage.role is not StageRole.SOLVER:
        raise ValueError("Phase 1 direct stage must be solver")
    if stage.compute_location not in (ComputeLocation.REMOTE, ComputeLocation.UNKNOWN):
        raise ValueError("this validator only accepts remote or unknown compute")
    if stage.network_scope is not NetworkScope.INTERNET:
        raise ValueError("Phase 1 remote Provider must use internet scope")
    if stage.tls_policy_ref is ContractMarker.NOT_APPLICABLE:
        raise ValueError("Phase 1 requires an explicit TLS policy")
    if (
        stage.credential_binding_ref is ContractMarker.NOT_APPLICABLE
        or stage.credential_binding_digest is ContractMarker.NOT_APPLICABLE
    ):
        raise ValueError("Phase 1 requires an exact credential binding")
    if len(stage.network_operations) != 1:
        raise ValueError("Phase 1 requires one inline inference operation")
    operation = stage.network_operations[0]
    if operation.purpose is not NetworkOperationPurpose.INFERENCE:
        raise ValueError("Phase 1 permits only inference")
    if operation.http_method != "POST":
        raise ValueError("Phase 1 inference must use POST")
    if operation.credential_injection_slot is CredentialInjectionSlot.NOT_APPLICABLE:
        raise ValueError("Phase 1 inference requires an exact credential injection slot")
    if urlsplit(operation.canonical_endpoint).scheme != "https":
        raise ValueError("Phase 1 inference requires HTTPS")
    if operation.canonical_query_policy.kind is not QueryPolicyKind.EMPTY:
        raise ValueError("Phase 1 canonical query must be empty")
    if operation.outbound_data not in (
        (OutboundDataKind.IMAGE,),
        (OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT),
    ):
        raise ValueError("Phase 1 outbound data may contain only image and user_hint")
