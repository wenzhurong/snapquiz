"""Immutable, provider-neutral capability and profile snapshots.

These contracts are deliberately pure standard-library objects.  They do not
load configuration, resolve credentials, construct SDK clients, or perform
network I/O.  Digests are computed from explicit payloads and never accepted
from callers.
"""
from __future__ import annotations

import re
from enum import Enum
from urllib.parse import urlsplit, urlunsplit

from snapquiz.domain._validation import (
    HTTP_TOKEN_RE,
    require_canonical_http_url,
    require_digest,
    require_non_secret_header_name,
    require_non_secret_query_key,
    require_plain_int,
    require_text,
    runtime_final,
)
from snapquiz.domain.capture import CaptureScopeKind
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.plan import (
    CanonicalQueryPolicy,
    ComputeLocation,
    CredentialInjectionSlot,
    NetworkOperationPurpose,
    NetworkScope,
    OutboundDataKind,
    QueryPolicyKind,
    validate_endpoint_for_network_scope,
)
from snapquiz.domain.policy import (
    ContractMarker,
    PolicyValue,
    policy_value_payload,
    require_policy_value,
)
from snapquiz.domain.solve import PipelineKind, SOLVE_RESULT_SCHEMA_VERSION, StageRole

ENDPOINT_OPERATION_TEMPLATE_SCHEMA_VERSION = (
    "snapquiz.endpoint-operation-template.v1"
)
ENDPOINT_POLICY_SCHEMA_VERSION = "snapquiz.endpoint-policy.v1"
CREDENTIAL_BINDING_SCHEMA_VERSION = "snapquiz.credential-binding.v1"
PROVIDER_PROFILE_SCHEMA_VERSION = "snapquiz.provider-profile.v1"
MODEL_CAPABILITIES_SCHEMA_VERSION = "snapquiz.model-capabilities.v1"
STAGE_BINDING_SCHEMA_VERSION = "snapquiz.stage-binding.v1"
PIPELINE_PROFILE_SCHEMA_VERSION = "snapquiz.pipeline-profile.v1"

_ENV_CREDENTIAL_REF_RE = re.compile(r"^env:[A-Z][A-Z0-9_]{0,127}$")
_PARAMETER_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_MIME_TYPE_RE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)


class InputModality(str, Enum):
    IMAGE = "image"
    TEXT = "text"


class CapabilityRole(str, Enum):
    MULTIMODAL_SOLVER = "multimodal_solver"
    TEXT_SOLVER = "text_solver"


class ImageInputKind(str, Enum):
    DATA_URI = "data_uri"
    FILE_ID = "file_id"
    PUBLIC_URL = "public_url"
    RAW_BASE64 = "raw_base64"


class StructuredOutputKind(str, Enum):
    JSON_OBJECT = "json_object"
    JSON_SCHEMA = "json_schema"
    PROMPT_ONLY = "prompt_only"
    TOOL_SCHEMA = "tool_schema"


class ProviderApplicationState(str, Enum):
    DISABLED = "disabled"
    PROVIDER_DEFAULT = "provider_default"
    REQUIRED = "required"
    UNKNOWN = "unknown"


class RedirectPolicy(str, Enum):
    REJECT = "reject"


class CredentialValueScheme(str, Enum):
    BEARER = "bearer"
    RAW = "raw"


class _ImmutableSnapshot:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "_ImmutableSnapshot":
        del memo
        return self

    def __repr__(self) -> str:
        metadata = self.safe_metadata()
        rendered = ", ".join(f"{key}={value!r}" for key, value in metadata.items())
        return f"{type(self).__name__}({rendered})"

    def safe_metadata(self) -> dict[str, object]:
        raise NotImplementedError


def _set_attributes(instance: object, values: tuple[tuple[str, object], ...]) -> None:
    for name, value in values:
        object.__setattr__(instance, name, value)


def _require_exact_enum(value: object, enum_type: type[Enum], name: str) -> None:
    if type(value) is not enum_type:
        raise ValueError(f"{name} must be {enum_type.__name__}")


def _require_enum_tuple(
    values: object,
    enum_type: type[Enum],
    name: str,
    *,
    allow_empty: bool = False,
) -> tuple[Enum, ...]:
    if type(values) is not tuple or (not values and not allow_empty):
        qualifier = "a tuple" if allow_empty else "a non-empty tuple"
        raise ValueError(f"{name} must be {qualifier}")
    if not all(type(value) is enum_type for value in values):
        raise ValueError(f"{name} must contain only {enum_type.__name__} values")
    expected = tuple(sorted(values, key=lambda item: str(item.value)))
    if values != expected or len(set(values)) != len(values):
        raise ValueError(f"{name} must be unique and in canonical sorted order")
    return values


def _require_text_tuple(
    values: object,
    name: str,
    *,
    allow_empty: bool = False,
    max_length: int = 512,
) -> tuple[str, ...]:
    if type(values) is not tuple or (not values and not allow_empty):
        qualifier = "a tuple" if allow_empty else "a non-empty tuple"
        raise ValueError(f"{name} must be {qualifier}")
    for value in values:
        require_text(value, name, max_length=max_length)
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise ValueError(f"{name} must be unique and in canonical sorted order")
    return values


def _marker_or_text(
    value: object, name: str, *, allow_not_applicable: bool
) -> str | ContractMarker:
    if value is ContractMarker.UNKNOWN:
        return value
    if allow_not_applicable and value is ContractMarker.NOT_APPLICABLE:
        return value
    if isinstance(value, ContractMarker):
        raise ValueError(f"{name} uses an invalid contract marker")
    text = require_text(value, name, max_length=512)
    if text in (ContractMarker.UNKNOWN.value, ContractMarker.NOT_APPLICABLE.value):
        raise ValueError(f"{name} cannot encode a contract marker as text")
    return text


def _marker_payload(value: str | ContractMarker) -> str:
    return value.value if type(value) is ContractMarker else value


def _short_digest(value: Digest256) -> str:
    return str(value)[:12]


def _origin_for_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


@runtime_final
class EndpointOperationTemplate(_ImmutableSnapshot):
    __slots__ = (
        "operation_key",
        "purpose",
        "http_method",
        "canonical_endpoint",
        "canonical_query_policy",
        "content_type",
        "allowed_non_secret_headers",
        "credential_injection_slot",
        "outbound_data",
        "billable",
        "operation_template_digest",
    )

    def __init__(
        self,
        *,
        operation_key: str,
        purpose: NetworkOperationPurpose,
        http_method: str,
        canonical_endpoint: str,
        canonical_query_policy: CanonicalQueryPolicy,
        content_type: str,
        allowed_non_secret_headers: tuple[str, ...],
        credential_injection_slot: CredentialInjectionSlot,
        outbound_data: tuple[OutboundDataKind, ...],
        billable: bool | ContractMarker,
    ) -> None:
        require_text(operation_key, "operation_key")
        _require_exact_enum(purpose, NetworkOperationPurpose, "purpose")
        method = require_text(http_method, "http_method", max_length=32)
        if method != method.upper() or HTTP_TOKEN_RE.fullmatch(method) is None:
            raise ValueError("http_method must be an uppercase HTTP token")
        require_canonical_http_url(
            canonical_endpoint, "canonical_endpoint", allow_query=False
        )
        if type(canonical_query_policy) is not CanonicalQueryPolicy:
            raise ValueError("canonical_query_policy must be CanonicalQueryPolicy")
        if canonical_query_policy.kind is not QueryPolicyKind.EMPTY:
            raise ValueError("Phase 1 endpoint templates require an empty query")
        normalized_content_type = require_text(
            content_type, "content_type", max_length=256
        )
        if normalized_content_type != normalized_content_type.lower():
            raise ValueError("content_type must be normalized lowercase text")
        _require_text_tuple(
            allowed_non_secret_headers,
            "allowed_non_secret_headers",
            allow_empty=True,
            max_length=256,
        )
        for header in allowed_non_secret_headers:
            require_non_secret_header_name(header)
        _require_exact_enum(
            credential_injection_slot,
            CredentialInjectionSlot,
            "credential_injection_slot",
        )
        _require_enum_tuple(outbound_data, OutboundDataKind, "outbound_data")
        if type(billable) is not bool and billable is not ContractMarker.UNKNOWN:
            raise ValueError("billable must be bool or unknown")

        _set_attributes(
            self,
            (
                ("operation_key", operation_key),
                ("purpose", purpose),
                ("http_method", method),
                ("canonical_endpoint", canonical_endpoint),
                ("canonical_query_policy", canonical_query_policy),
                ("content_type", normalized_content_type),
                ("allowed_non_secret_headers", allowed_non_secret_headers),
                ("credential_injection_slot", credential_injection_slot),
                ("outbound_data", outbound_data),
                ("billable", billable),
            ),
        )
        object.__setattr__(
            self,
            "operation_template_digest",
            digest256(
                "EndpointOperationTemplate",
                ENDPOINT_OPERATION_TEMPLATE_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "operation_key": self.operation_key,
            "purpose": self.purpose.value,
            "http_method": self.http_method,
            "canonical_endpoint": self.canonical_endpoint,
            "canonical_query_policy": self.canonical_query_policy.as_digest_payload(),
            "content_type": self.content_type,
            "allowed_non_secret_headers": self.allowed_non_secret_headers,
            "credential_injection_slot": self.credential_injection_slot.value,
            "outbound_data": tuple(value.value for value in self.outbound_data),
            "billable": (
                self.billable.value
                if type(self.billable) is ContractMarker
                else self.billable
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "EndpointOperationTemplate",
            ENDPOINT_OPERATION_TEMPLATE_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        if self.recompute_digest() != self.operation_template_digest:
            raise ValueError("endpoint operation template integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "operation_key": self.operation_key,
            "purpose": self.purpose.value,
            "endpoint_origin": _origin_for_endpoint(self.canonical_endpoint),
            "digest_prefix": _short_digest(self.operation_template_digest),
        }


@runtime_final
class EndpointPolicySnapshot(_ImmutableSnapshot):
    __slots__ = (
        "endpoint_policy_version",
        "allowed_origins",
        "allowed_base_paths",
        "operation_templates",
        "allow_custom_endpoint",
        "redirect_policy",
        "network_scope",
        "network_policy_version",
        "tls_policy_ref",
        "endpoint_policy_digest",
    )

    def __init__(
        self,
        *,
        endpoint_policy_version: str,
        allowed_origins: tuple[str, ...],
        allowed_base_paths: tuple[str, ...],
        operation_templates: tuple[EndpointOperationTemplate, ...],
        allow_custom_endpoint: bool,
        redirect_policy: RedirectPolicy,
        network_scope: NetworkScope,
        network_policy_version: str,
        tls_policy_ref: str | ContractMarker,
    ) -> None:
        require_text(endpoint_policy_version, "endpoint_policy_version")
        _require_text_tuple(allowed_origins, "allowed_origins")
        for origin in allowed_origins:
            require_canonical_http_url(origin, "allowed origin", allow_query=False)
            if urlsplit(origin).path != "/":
                raise ValueError("allowed origins must use exactly the root path")
        _require_text_tuple(allowed_base_paths, "allowed_base_paths")
        for base_path in allowed_base_paths:
            if not base_path.startswith("/") or not base_path.endswith("/"):
                raise ValueError("allowed base paths must start and end with slash")
            probe = allowed_origins[0][:-1] + base_path
            require_canonical_http_url(probe, "allowed base path", allow_query=False)
        if type(operation_templates) is not tuple or not operation_templates:
            raise ValueError("operation_templates must be a non-empty tuple")
        if not all(type(value) is EndpointOperationTemplate for value in operation_templates):
            raise ValueError("operation_templates contain an invalid value")
        operation_keys = tuple(value.operation_key for value in operation_templates)
        if operation_keys != tuple(sorted(operation_keys)) or len(
            set(operation_keys)
        ) != len(operation_keys):
            raise ValueError("operation_templates must use unique, sorted keys")
        if type(allow_custom_endpoint) is not bool:
            raise ValueError("allow_custom_endpoint must be bool")
        _require_exact_enum(redirect_policy, RedirectPolicy, "redirect_policy")
        if redirect_policy is not RedirectPolicy.REJECT:
            raise ValueError("redirects must be rejected")
        _require_exact_enum(network_scope, NetworkScope, "network_scope")
        if network_scope is NetworkScope.NONE:
            raise ValueError("endpoint policy requires a network scope")
        require_text(network_policy_version, "network_policy_version")
        if tls_policy_ref is ContractMarker.NOT_APPLICABLE:
            tls_policy: str | ContractMarker = tls_policy_ref
        elif isinstance(tls_policy_ref, ContractMarker):
            raise ValueError("tls_policy_ref cannot be unknown")
        else:
            tls_policy = require_text(
                tls_policy_ref, "tls_policy_ref", max_length=512
            )
            if tls_policy in (
                ContractMarker.UNKNOWN.value,
                ContractMarker.NOT_APPLICABLE.value,
            ):
                raise ValueError(
                    "tls_policy_ref cannot encode a contract marker as text"
                )
        if (
            network_scope in (NetworkScope.LAN, NetworkScope.INTERNET)
            and tls_policy is ContractMarker.NOT_APPLICABLE
        ):
            raise ValueError("LAN/internet endpoint policy requires a TLS policy")

        for origin in allowed_origins:
            validate_endpoint_for_network_scope(origin, network_scope)

        for operation in operation_templates:
            operation.validate_integrity()
            endpoint_origin = _origin_for_endpoint(operation.canonical_endpoint)
            if endpoint_origin not in allowed_origins:
                raise ValueError("operation endpoint origin is not allowed")
            endpoint_path = urlsplit(operation.canonical_endpoint).path
            if not any(endpoint_path.startswith(prefix) for prefix in allowed_base_paths):
                raise ValueError("operation endpoint path is not allowed")

        _set_attributes(
            self,
            (
                ("endpoint_policy_version", endpoint_policy_version),
                ("allowed_origins", allowed_origins),
                ("allowed_base_paths", allowed_base_paths),
                ("operation_templates", operation_templates),
                ("allow_custom_endpoint", allow_custom_endpoint),
                ("redirect_policy", redirect_policy),
                ("network_scope", network_scope),
                ("network_policy_version", network_policy_version),
                ("tls_policy_ref", tls_policy),
            ),
        )
        object.__setattr__(
            self,
            "endpoint_policy_digest",
            digest256(
                "EndpointPolicySnapshot",
                ENDPOINT_POLICY_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "endpoint_policy_version": self.endpoint_policy_version,
            "allowed_origins": self.allowed_origins,
            "allowed_base_paths": self.allowed_base_paths,
            "operation_templates": tuple(
                {
                    "operation_template_digest": operation.operation_template_digest,
                    "operation_template": operation.as_digest_payload(),
                }
                for operation in self.operation_templates
            ),
            "allow_custom_endpoint": self.allow_custom_endpoint,
            "redirect_policy": self.redirect_policy.value,
            "network_scope": self.network_scope.value,
            "network_policy_version": self.network_policy_version,
            "tls_policy_ref": _marker_payload(self.tls_policy_ref),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "EndpointPolicySnapshot",
            ENDPOINT_POLICY_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        for operation in self.operation_templates:
            operation.validate_integrity()
        if self.recompute_digest() != self.endpoint_policy_digest:
            raise ValueError("endpoint policy integrity mismatch")

    def require_operation(self, operation_key: str) -> EndpointOperationTemplate:
        require_text(operation_key, "operation_key")
        for operation in self.operation_templates:
            if operation.operation_key == operation_key:
                return operation
        raise LookupError("unknown endpoint operation")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "endpoint_policy_version": self.endpoint_policy_version,
            "allowed_origins": self.allowed_origins,
            "digest_prefix": _short_digest(self.endpoint_policy_digest),
        }


@runtime_final
class CredentialBindingMetadata(_ImmutableSnapshot):
    __slots__ = (
        "credential_binding_ref",
        "credential_ref",
        "provider_id",
        "endpoint_policy_version",
        "endpoint_policy_digest",
        "network_policy_version",
        "tls_policy_ref",
        "credential_injection_slot",
        "credential_value_scheme",
        "credential_binding_digest",
    )

    def __init__(
        self,
        *,
        credential_binding_ref: str,
        credential_ref: str,
        provider_id: str,
        endpoint_policy: EndpointPolicySnapshot,
        credential_injection_slot: CredentialInjectionSlot,
        credential_value_scheme: CredentialValueScheme,
    ) -> None:
        require_text(credential_binding_ref, "credential_binding_ref", max_length=512)
        locator = require_text(credential_ref, "credential_ref", max_length=132)
        if _ENV_CREDENTIAL_REF_RE.fullmatch(locator) is None:
            raise ValueError("credential_ref must be a non-secret env locator")
        require_text(provider_id, "provider_id")
        if type(endpoint_policy) is not EndpointPolicySnapshot:
            raise ValueError("endpoint_policy must be EndpointPolicySnapshot")
        endpoint_policy.validate_integrity()
        _require_exact_enum(
            credential_injection_slot,
            CredentialInjectionSlot,
            "credential_injection_slot",
        )
        if credential_injection_slot is CredentialInjectionSlot.NOT_APPLICABLE:
            raise ValueError("credential binding requires an injection slot")
        _require_exact_enum(
            credential_value_scheme,
            CredentialValueScheme,
            "credential_value_scheme",
        )
        for operation in endpoint_policy.operation_templates:
            if operation.credential_injection_slot is not credential_injection_slot:
                raise ValueError("credential slot must match every endpoint operation")

        _set_attributes(
            self,
            (
                ("credential_binding_ref", credential_binding_ref),
                ("credential_ref", locator),
                ("provider_id", provider_id),
                ("endpoint_policy_version", endpoint_policy.endpoint_policy_version),
                ("endpoint_policy_digest", endpoint_policy.endpoint_policy_digest),
                ("network_policy_version", endpoint_policy.network_policy_version),
                ("tls_policy_ref", endpoint_policy.tls_policy_ref),
                ("credential_injection_slot", credential_injection_slot),
                ("credential_value_scheme", credential_value_scheme),
            ),
        )
        object.__setattr__(
            self,
            "credential_binding_digest",
            digest256(
                "CredentialBindingMetadata",
                CREDENTIAL_BINDING_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "credential_binding_ref": self.credential_binding_ref,
            "credential_ref": self.credential_ref,
            "provider_id": self.provider_id,
            "endpoint_policy_version": self.endpoint_policy_version,
            "endpoint_policy_digest": self.endpoint_policy_digest,
            "network_policy_version": self.network_policy_version,
            "tls_policy_ref": _marker_payload(self.tls_policy_ref),
            "credential_injection_slot": self.credential_injection_slot.value,
            "credential_value_scheme": self.credential_value_scheme.value,
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "CredentialBindingMetadata",
            CREDENTIAL_BINDING_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        if self.recompute_digest() != self.credential_binding_digest:
            raise ValueError("credential binding integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "credential_binding_ref": self.credential_binding_ref,
            "provider_id": self.provider_id,
            "digest_prefix": _short_digest(self.credential_binding_digest),
        }


@runtime_final
class ProviderProfileSnapshot(_ImmutableSnapshot):
    __slots__ = (
        "provider_profile_id",
        "provider_id",
        "adapter_family",
        "adapter_version",
        "api_version",
        "endpoint_policy",
        "credential_binding",
        "network_scope",
        "compute_location",
        "processing_region",
        "provider_application_state",
        "retention_policy",
        "data_policy",
        "cost_policy",
        "fixed_non_secret_parameters",
        "provider_profile_digest",
    )

    def __init__(
        self,
        *,
        provider_profile_id: str,
        provider_id: str,
        adapter_family: str,
        adapter_version: str,
        api_version: str,
        endpoint_policy: EndpointPolicySnapshot,
        credential_binding: CredentialBindingMetadata | ContractMarker,
        compute_location: ComputeLocation,
        processing_region: str | ContractMarker,
        provider_application_state: ProviderApplicationState,
        retention_policy: PolicyValue,
        data_policy: PolicyValue,
        cost_policy: PolicyValue,
        fixed_non_secret_parameters: tuple[tuple[str, str], ...] = (),
    ) -> None:
        for name, value in (
            ("provider_profile_id", provider_profile_id),
            ("provider_id", provider_id),
            ("adapter_family", adapter_family),
            ("adapter_version", adapter_version),
            ("api_version", api_version),
        ):
            require_text(value, name)
        if type(endpoint_policy) is not EndpointPolicySnapshot:
            raise ValueError("endpoint_policy must be EndpointPolicySnapshot")
        endpoint_policy.validate_integrity()
        if (
            type(credential_binding) is not CredentialBindingMetadata
            and credential_binding is not ContractMarker.NOT_APPLICABLE
        ):
            raise ValueError("credential_binding must be metadata or not_applicable")
        operations_require_credentials = any(
            operation.credential_injection_slot
            is not CredentialInjectionSlot.NOT_APPLICABLE
            for operation in endpoint_policy.operation_templates
        )
        has_credential_binding = type(credential_binding) is CredentialBindingMetadata
        if operations_require_credentials != has_credential_binding:
            raise ValueError(
                "credential binding must exactly match endpoint operation requirements"
            )
        if type(credential_binding) is CredentialBindingMetadata:
            credential_binding.validate_integrity()
            if credential_binding.provider_id != provider_id:
                raise ValueError("credential binding provider mismatch")
            if (
                credential_binding.endpoint_policy_version
                != endpoint_policy.endpoint_policy_version
                or credential_binding.endpoint_policy_digest
                != endpoint_policy.endpoint_policy_digest
            ):
                raise ValueError("credential binding endpoint policy mismatch")
        _require_exact_enum(compute_location, ComputeLocation, "compute_location")
        if (
            endpoint_policy.network_scope in (NetworkScope.LAN, NetworkScope.INTERNET)
            and compute_location is ComputeLocation.LOCAL_VERIFIED
        ):
            raise ValueError("LAN/internet profiles cannot claim local_verified compute")
        region = _marker_or_text(
            processing_region, "processing_region", allow_not_applicable=False
        )
        _require_exact_enum(
            provider_application_state,
            ProviderApplicationState,
            "provider_application_state",
        )
        require_policy_value(retention_policy, "retention_policy")
        require_policy_value(data_policy, "data_policy")
        require_policy_value(cost_policy, "cost_policy")
        if type(fixed_non_secret_parameters) is not tuple:
            raise ValueError("fixed_non_secret_parameters must be a tuple")
        for item in fixed_non_secret_parameters:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError("fixed parameters must be (name, value) tuples")
            name, value = item
            if type(name) is not str or _PARAMETER_NAME_RE.fullmatch(name) is None:
                raise ValueError("fixed parameter name is invalid")
            require_non_secret_query_key(name, "fixed parameter name")
            require_text(value, "fixed parameter value", max_length=1_024)
        if fixed_non_secret_parameters != tuple(sorted(fixed_non_secret_parameters)):
            raise ValueError("fixed parameters must be in canonical sorted order")
        if len({name for name, _ in fixed_non_secret_parameters}) != len(
            fixed_non_secret_parameters
        ):
            raise ValueError("fixed parameter names must be unique")

        _set_attributes(
            self,
            (
                ("provider_profile_id", provider_profile_id),
                ("provider_id", provider_id),
                ("adapter_family", adapter_family),
                ("adapter_version", adapter_version),
                ("api_version", api_version),
                ("endpoint_policy", endpoint_policy),
                ("credential_binding", credential_binding),
                ("network_scope", endpoint_policy.network_scope),
                ("compute_location", compute_location),
                ("processing_region", region),
                ("provider_application_state", provider_application_state),
                ("retention_policy", retention_policy),
                ("data_policy", data_policy),
                ("cost_policy", cost_policy),
                ("fixed_non_secret_parameters", fixed_non_secret_parameters),
            ),
        )
        object.__setattr__(
            self,
            "provider_profile_digest",
            digest256(
                "ProviderProfileSnapshot",
                PROVIDER_PROFILE_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    def as_digest_payload(self) -> dict[str, object]:
        credential_payload: object
        if type(self.credential_binding) is CredentialBindingMetadata:
            credential_payload = {
                "credential_binding_digest": self.credential_binding.credential_binding_digest,
                "credential_binding": self.credential_binding.as_digest_payload(),
            }
        else:
            credential_payload = ContractMarker.NOT_APPLICABLE.value
        return {
            "provider_profile_id": self.provider_profile_id,
            "provider_id": self.provider_id,
            "adapter_family": self.adapter_family,
            "adapter_version": self.adapter_version,
            "api_version": self.api_version,
            "endpoint_policy_digest": self.endpoint_policy.endpoint_policy_digest,
            "endpoint_policy": self.endpoint_policy.as_digest_payload(),
            "credential_binding": credential_payload,
            "network_scope": self.network_scope.value,
            "compute_location": self.compute_location.value,
            "processing_region": _marker_payload(self.processing_region),
            "provider_application_state": self.provider_application_state.value,
            "retention_policy": policy_value_payload(self.retention_policy),
            "data_policy": policy_value_payload(self.data_policy),
            "cost_policy": policy_value_payload(self.cost_policy),
            "fixed_non_secret_parameters": tuple(
                {"name": name, "value": value}
                for name, value in self.fixed_non_secret_parameters
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "ProviderProfileSnapshot",
            PROVIDER_PROFILE_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        self.endpoint_policy.validate_integrity()
        if type(self.credential_binding) is CredentialBindingMetadata:
            self.credential_binding.validate_integrity()
        if self.recompute_digest() != self.provider_profile_digest:
            raise ValueError("provider profile integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "provider_profile_id": self.provider_profile_id,
            "provider_id": self.provider_id,
            "adapter_family": self.adapter_family,
            "digest_prefix": _short_digest(self.provider_profile_digest),
        }


def _image_marker_payload(
    value: tuple[ImageInputKind, ...] | ContractMarker,
) -> object:
    if type(value) is ContractMarker:
        return value.value
    return tuple(item.value for item in value)


def _limit_marker_payload(value: int | ContractMarker) -> int | str:
    return value.value if type(value) is ContractMarker else value


def _mime_marker_payload(value: tuple[str, ...] | ContractMarker) -> object:
    return value.value if type(value) is ContractMarker else value


@runtime_final
class ModelCapabilitiesSnapshot(_ImmutableSnapshot):
    __slots__ = (
        "capabilities_ref",
        "provider_profile_id",
        "provider_profile_digest",
        "provider_id",
        "model_id",
        "input_modalities",
        "roles",
        "image_inputs",
        "structured_output",
        "supports_system_instruction",
        "supports_reasoning_control",
        "supports_usage",
        "api_version",
        "provider_application_state",
        "max_images",
        "max_image_bytes",
        "max_image_pixels",
        "max_output_tokens",
        "supported_mime_types",
        "data_residency",
        "network_scope",
        "compute_location",
        "capabilities_digest",
    )

    def __init__(
        self,
        *,
        capabilities_ref: str,
        provider_profile: ProviderProfileSnapshot,
        model_id: str,
        input_modalities: tuple[InputModality, ...],
        roles: tuple[CapabilityRole, ...],
        image_inputs: tuple[ImageInputKind, ...] | ContractMarker,
        structured_output: StructuredOutputKind,
        supports_system_instruction: bool,
        supports_reasoning_control: bool,
        supports_usage: bool,
        max_images: int | ContractMarker,
        max_image_bytes: int | ContractMarker,
        max_image_pixels: int | ContractMarker,
        max_output_tokens: int,
        supported_mime_types: tuple[str, ...] | ContractMarker,
        data_residency: str | ContractMarker,
    ) -> None:
        require_text(capabilities_ref, "capabilities_ref", max_length=512)
        if type(provider_profile) is not ProviderProfileSnapshot:
            raise ValueError("provider_profile must be ProviderProfileSnapshot")
        provider_profile.validate_integrity()
        require_text(model_id, "model_id")
        _require_enum_tuple(input_modalities, InputModality, "input_modalities")
        _require_enum_tuple(roles, CapabilityRole, "roles")
        _require_exact_enum(
            structured_output, StructuredOutputKind, "structured_output"
        )
        for name, value in (
            ("supports_system_instruction", supports_system_instruction),
            ("supports_reasoning_control", supports_reasoning_control),
            ("supports_usage", supports_usage),
        ):
            if type(value) is not bool:
                raise ValueError(f"{name} must be bool")
        require_plain_int(max_output_tokens, "max_output_tokens", minimum=1)
        residency = _marker_or_text(
            data_residency, "data_residency", allow_not_applicable=False
        )

        is_multimodal = CapabilityRole.MULTIMODAL_SOLVER in roles
        if is_multimodal:
            if input_modalities != (InputModality.IMAGE, InputModality.TEXT):
                raise ValueError("multimodal solver requires exact image and text modalities")
            _require_enum_tuple(image_inputs, ImageInputKind, "image_inputs")
            for name, value in (
                ("max_images", max_images),
                ("max_image_bytes", max_image_bytes),
                ("max_image_pixels", max_image_pixels),
            ):
                require_plain_int(value, name, minimum=1)
            _require_text_tuple(supported_mime_types, "supported_mime_types")
            for mime_type in supported_mime_types:
                if _MIME_TYPE_RE.fullmatch(mime_type) is None:
                    raise ValueError("supported MIME type is not normalized")
                if not mime_type.startswith("image/"):
                    raise ValueError("multimodal solver MIME types must be images")
        else:
            if roles != (CapabilityRole.TEXT_SOLVER,):
                raise ValueError("model capabilities require a supported solver role")
            if input_modalities != (InputModality.TEXT,):
                raise ValueError("text solver requires exact text-only modality")
            if image_inputs is not ContractMarker.NOT_APPLICABLE:
                raise ValueError("text solver image_inputs must be not_applicable")
            if any(
                value is not ContractMarker.NOT_APPLICABLE
                for value in (max_images, max_image_bytes, max_image_pixels)
            ):
                raise ValueError("text solver image limits must be not_applicable")
            if supported_mime_types is not ContractMarker.NOT_APPLICABLE:
                raise ValueError("text solver MIME types must be not_applicable")

        _set_attributes(
            self,
            (
                ("capabilities_ref", capabilities_ref),
                ("provider_profile_id", provider_profile.provider_profile_id),
                ("provider_profile_digest", provider_profile.provider_profile_digest),
                ("provider_id", provider_profile.provider_id),
                ("model_id", model_id),
                ("input_modalities", input_modalities),
                ("roles", roles),
                ("image_inputs", image_inputs),
                ("structured_output", structured_output),
                ("supports_system_instruction", supports_system_instruction),
                ("supports_reasoning_control", supports_reasoning_control),
                ("supports_usage", supports_usage),
                ("api_version", provider_profile.api_version),
                (
                    "provider_application_state",
                    provider_profile.provider_application_state,
                ),
                ("max_images", max_images),
                ("max_image_bytes", max_image_bytes),
                ("max_image_pixels", max_image_pixels),
                ("max_output_tokens", max_output_tokens),
                ("supported_mime_types", supported_mime_types),
                ("data_residency", residency),
                ("network_scope", provider_profile.network_scope),
                ("compute_location", provider_profile.compute_location),
            ),
        )
        object.__setattr__(
            self,
            "capabilities_digest",
            digest256(
                "ModelCapabilitiesSnapshot",
                MODEL_CAPABILITIES_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "capabilities_ref": self.capabilities_ref,
            "provider_profile_id": self.provider_profile_id,
            "provider_profile_digest": self.provider_profile_digest,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "input_modalities": tuple(value.value for value in self.input_modalities),
            "roles": tuple(value.value for value in self.roles),
            "image_inputs": _image_marker_payload(self.image_inputs),
            "structured_output": self.structured_output.value,
            "supports_system_instruction": self.supports_system_instruction,
            "supports_reasoning_control": self.supports_reasoning_control,
            "supports_usage": self.supports_usage,
            "api_version": self.api_version,
            "provider_application_state": self.provider_application_state.value,
            "max_images": _limit_marker_payload(self.max_images),
            "max_image_bytes": _limit_marker_payload(self.max_image_bytes),
            "max_image_pixels": _limit_marker_payload(self.max_image_pixels),
            "max_output_tokens": self.max_output_tokens,
            "supported_mime_types": _mime_marker_payload(self.supported_mime_types),
            "data_residency": _marker_payload(self.data_residency),
            "network_scope": self.network_scope.value,
            "compute_location": self.compute_location.value,
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "ModelCapabilitiesSnapshot",
            MODEL_CAPABILITIES_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        if self.recompute_digest() != self.capabilities_digest:
            raise ValueError("model capabilities integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "capabilities_ref": self.capabilities_ref,
            "provider_profile_id": self.provider_profile_id,
            "model_id": self.model_id,
            "digest_prefix": _short_digest(self.capabilities_digest),
        }


@runtime_final
class StageBindingSnapshot(_ImmutableSnapshot):
    __slots__ = (
        "binding_id",
        "role",
        "provider_profile_id",
        "provider_profile_digest",
        "provider_id",
        "model_id",
        "adapter_family",
        "adapter_version",
        "api_version",
        "capabilities_ref",
        "capabilities_digest",
        "selected_image_input",
        "selected_structured_output",
        "send_system_instruction",
        "send_reasoning_control",
        "expect_usage",
        "provider_application_state",
        "fixed_non_secret_parameters",
        "stage_binding_digest",
    )

    def __init__(
        self,
        *,
        binding_id: str,
        role: StageRole,
        provider_profile: ProviderProfileSnapshot,
        capabilities: ModelCapabilitiesSnapshot,
        selected_image_input: ImageInputKind | ContractMarker,
        selected_structured_output: StructuredOutputKind,
        send_system_instruction: bool,
        send_reasoning_control: bool,
        expect_usage: bool,
    ) -> None:
        require_text(binding_id, "binding_id", max_length=512)
        _require_exact_enum(role, StageRole, "role")
        if role not in (StageRole.SOLVER, StageRole.TEXT_SOLVER):
            raise ValueError("model stage bindings support only solver roles")
        if type(provider_profile) is not ProviderProfileSnapshot:
            raise ValueError("provider_profile must be ProviderProfileSnapshot")
        if type(capabilities) is not ModelCapabilitiesSnapshot:
            raise ValueError("capabilities must be ModelCapabilitiesSnapshot")
        provider_profile.validate_integrity()
        capabilities.validate_integrity()
        if (
            capabilities.provider_profile_id != provider_profile.provider_profile_id
            or capabilities.provider_profile_digest
            != provider_profile.provider_profile_digest
        ):
            raise ValueError("capabilities do not bind the provider profile")
        expected_capability_role = (
            CapabilityRole.MULTIMODAL_SOLVER
            if role is StageRole.SOLVER
            else CapabilityRole.TEXT_SOLVER
        )
        if expected_capability_role not in capabilities.roles:
            raise ValueError("stage role is not declared by capabilities")
        if role is StageRole.SOLVER:
            if type(selected_image_input) is not ImageInputKind:
                raise ValueError("multimodal binding requires one exact image input kind")
            if (
                type(capabilities.image_inputs) is not tuple
                or selected_image_input not in capabilities.image_inputs
            ):
                raise ValueError("selected image input is not declared by capabilities")
        elif selected_image_input is not ContractMarker.NOT_APPLICABLE:
            raise ValueError("text solver image input must be not_applicable")
        _require_exact_enum(
            selected_structured_output,
            StructuredOutputKind,
            "selected_structured_output",
        )
        if selected_structured_output is not capabilities.structured_output:
            raise ValueError("selected structured output is not the exact capability")
        for name, value, supported in (
            (
                "send_system_instruction",
                send_system_instruction,
                capabilities.supports_system_instruction,
            ),
            (
                "send_reasoning_control",
                send_reasoning_control,
                capabilities.supports_reasoning_control,
            ),
            ("expect_usage", expect_usage, capabilities.supports_usage),
        ):
            if type(value) is not bool:
                raise ValueError(f"{name} must be bool")
            if value and not supported:
                raise ValueError(f"{name} is not declared by capabilities")

        _set_attributes(
            self,
            (
                ("binding_id", binding_id),
                ("role", role),
                ("provider_profile_id", provider_profile.provider_profile_id),
                ("provider_profile_digest", provider_profile.provider_profile_digest),
                ("provider_id", provider_profile.provider_id),
                ("model_id", capabilities.model_id),
                ("adapter_family", provider_profile.adapter_family),
                ("adapter_version", provider_profile.adapter_version),
                ("api_version", provider_profile.api_version),
                ("capabilities_ref", capabilities.capabilities_ref),
                ("capabilities_digest", capabilities.capabilities_digest),
                ("selected_image_input", selected_image_input),
                ("selected_structured_output", selected_structured_output),
                ("send_system_instruction", send_system_instruction),
                ("send_reasoning_control", send_reasoning_control),
                ("expect_usage", expect_usage),
                (
                    "provider_application_state",
                    provider_profile.provider_application_state,
                ),
                (
                    "fixed_non_secret_parameters",
                    provider_profile.fixed_non_secret_parameters,
                ),
            ),
        )
        object.__setattr__(
            self,
            "stage_binding_digest",
            digest256(
                "StageBindingSnapshot",
                STAGE_BINDING_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "binding_id": self.binding_id,
            "role": self.role.value,
            "provider_profile_id": self.provider_profile_id,
            "provider_profile_digest": self.provider_profile_digest,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "adapter_family": self.adapter_family,
            "adapter_version": self.adapter_version,
            "api_version": self.api_version,
            "capabilities_ref": self.capabilities_ref,
            "capabilities_digest": self.capabilities_digest,
            "selected_image_input": (
                self.selected_image_input.value
                if isinstance(self.selected_image_input, Enum)
                else self.selected_image_input
            ),
            "selected_structured_output": self.selected_structured_output.value,
            "send_system_instruction": self.send_system_instruction,
            "send_reasoning_control": self.send_reasoning_control,
            "expect_usage": self.expect_usage,
            "provider_application_state": self.provider_application_state.value,
            "fixed_non_secret_parameters": tuple(
                {"name": name, "value": value}
                for name, value in self.fixed_non_secret_parameters
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "StageBindingSnapshot",
            STAGE_BINDING_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        if self.recompute_digest() != self.stage_binding_digest:
            raise ValueError("stage binding integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "binding_id": self.binding_id,
            "provider_profile_id": self.provider_profile_id,
            "model_id": self.model_id,
            "digest_prefix": _short_digest(self.stage_binding_digest),
        }


@runtime_final
class PipelineProfileSnapshot(_ImmutableSnapshot):
    __slots__ = (
        "pipeline_profile_id",
        "pipeline_kind",
        "stage_bindings",
        "prompt_policy_digest",
        "result_validator_version",
        "image_preprocessing_policy_version",
        "requested_result_schema_version",
        "capture_scope_kind",
        "preview_required",
        "timeout_budget_ms",
        "max_attempts_per_operation",
        "max_network_calls_total",
        "max_billable_calls",
        "max_output_tokens",
        "max_image_width_px",
        "max_image_height_px",
        "max_image_pixels",
        "max_image_bytes",
        "cost_policy",
        "fallback_binding_ids",
        "enabled",
        "pipeline_profile_digest",
    )

    def __init__(
        self,
        *,
        pipeline_profile_id: str,
        pipeline_kind: PipelineKind,
        stage_bindings: tuple[StageBindingSnapshot, ...],
        prompt_policy_digest: Digest256,
        result_validator_version: str,
        image_preprocessing_policy_version: str,
        requested_result_schema_version: str,
        capture_scope_kind: CaptureScopeKind,
        preview_required: bool,
        timeout_budget_ms: int,
        max_attempts_per_operation: int,
        max_network_calls_total: int,
        max_billable_calls: int,
        max_output_tokens: int,
        max_image_width_px: int,
        max_image_height_px: int,
        max_image_pixels: int,
        max_image_bytes: int,
        cost_policy: PolicyValue,
        fallback_binding_ids: tuple[str, ...] = (),
        enabled: bool = True,
    ) -> None:
        require_text(pipeline_profile_id, "pipeline_profile_id", max_length=512)
        _require_exact_enum(pipeline_kind, PipelineKind, "pipeline_kind")
        if type(stage_bindings) is not tuple or not stage_bindings:
            raise ValueError("stage_bindings must be a non-empty tuple")
        if not all(type(value) is StageBindingSnapshot for value in stage_bindings):
            raise ValueError("stage_bindings contain an invalid value")
        if len({value.binding_id for value in stage_bindings}) != len(stage_bindings):
            raise ValueError("stage binding ids must be unique")
        for binding in stage_bindings:
            binding.validate_integrity()
        if pipeline_kind is PipelineKind.DIRECT_MULTIMODAL:
            if tuple(binding.role for binding in stage_bindings) != (StageRole.SOLVER,):
                raise ValueError("direct_multimodal requires one solver binding")
        else:
            raise ValueError("ocr_text pipeline profiles are not implemented in Phase 1")
        require_digest(prompt_policy_digest, "prompt_policy_digest")
        require_text(result_validator_version, "result_validator_version")
        require_text(
            image_preprocessing_policy_version,
            "image_preprocessing_policy_version",
        )
        if requested_result_schema_version != SOLVE_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported requested_result_schema_version")
        _require_exact_enum(capture_scope_kind, CaptureScopeKind, "capture_scope_kind")
        if capture_scope_kind is not CaptureScopeKind.SELECTED_REGION:
            raise ValueError("Phase 1 remote profiles require selected_region")
        if type(preview_required) is not bool or not preview_required:
            raise ValueError("Phase 1 remote profiles require preview")
        for name, value in (
            ("timeout_budget_ms", timeout_budget_ms),
            ("max_attempts_per_operation", max_attempts_per_operation),
            ("max_network_calls_total", max_network_calls_total),
            ("max_output_tokens", max_output_tokens),
            ("max_image_width_px", max_image_width_px),
            ("max_image_height_px", max_image_height_px),
            ("max_image_pixels", max_image_pixels),
            ("max_image_bytes", max_image_bytes),
        ):
            require_plain_int(value, name, minimum=1)
        require_plain_int(
            max_billable_calls, "max_billable_calls", minimum=0
        )
        if max_network_calls_total > max_attempts_per_operation:
            raise ValueError("network budget exceeds the single operation attempt budget")
        if max_billable_calls > max_network_calls_total:
            raise ValueError("billable budget exceeds network budget")
        require_policy_value(cost_policy, "cost_policy")
        _require_text_tuple(
            fallback_binding_ids,
            "fallback_binding_ids",
            allow_empty=True,
            max_length=512,
        )
        if fallback_binding_ids:
            raise ValueError("Phase 1 runtime fallback is forbidden")
        if type(enabled) is not bool:
            raise ValueError("enabled must be bool")

        _set_attributes(
            self,
            (
                ("pipeline_profile_id", pipeline_profile_id),
                ("pipeline_kind", pipeline_kind),
                ("stage_bindings", stage_bindings),
                ("prompt_policy_digest", prompt_policy_digest),
                ("result_validator_version", result_validator_version),
                (
                    "image_preprocessing_policy_version",
                    image_preprocessing_policy_version,
                ),
                ("requested_result_schema_version", requested_result_schema_version),
                ("capture_scope_kind", capture_scope_kind),
                ("preview_required", preview_required),
                ("timeout_budget_ms", timeout_budget_ms),
                ("max_attempts_per_operation", max_attempts_per_operation),
                ("max_network_calls_total", max_network_calls_total),
                ("max_billable_calls", max_billable_calls),
                ("max_output_tokens", max_output_tokens),
                ("max_image_width_px", max_image_width_px),
                ("max_image_height_px", max_image_height_px),
                ("max_image_pixels", max_image_pixels),
                ("max_image_bytes", max_image_bytes),
                ("cost_policy", cost_policy),
                ("fallback_binding_ids", fallback_binding_ids),
                ("enabled", enabled),
            ),
        )
        object.__setattr__(
            self,
            "pipeline_profile_digest",
            digest256(
                "PipelineProfileSnapshot",
                PIPELINE_PROFILE_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "pipeline_profile_id": self.pipeline_profile_id,
            "pipeline_kind": self.pipeline_kind.value,
            "stage_bindings": tuple(
                {
                    "stage_binding_digest": binding.stage_binding_digest,
                    "stage_binding": binding.as_digest_payload(),
                }
                for binding in self.stage_bindings
            ),
            "prompt_policy_digest": self.prompt_policy_digest,
            "result_validator_version": self.result_validator_version,
            "image_preprocessing_policy_version": self.image_preprocessing_policy_version,
            "requested_result_schema_version": self.requested_result_schema_version,
            "capture_scope_kind": self.capture_scope_kind.value,
            "preview_required": self.preview_required,
            "timeout_budget_ms": self.timeout_budget_ms,
            "max_attempts_per_operation": self.max_attempts_per_operation,
            "max_network_calls_total": self.max_network_calls_total,
            "max_billable_calls": self.max_billable_calls,
            "max_output_tokens": self.max_output_tokens,
            "max_image_width_px": self.max_image_width_px,
            "max_image_height_px": self.max_image_height_px,
            "max_image_pixels": self.max_image_pixels,
            "max_image_bytes": self.max_image_bytes,
            "cost_policy": policy_value_payload(self.cost_policy),
            "fallback_binding_ids": self.fallback_binding_ids,
            "enabled": self.enabled,
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "PipelineProfileSnapshot",
            PIPELINE_PROFILE_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        for binding in self.stage_bindings:
            binding.validate_integrity()
        if self.recompute_digest() != self.pipeline_profile_digest:
            raise ValueError("pipeline profile integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "pipeline_profile_id": self.pipeline_profile_id,
            "pipeline_kind": self.pipeline_kind.value,
            "enabled": self.enabled,
            "digest_prefix": _short_digest(self.pipeline_profile_digest),
        }


__all__ = [
    "CREDENTIAL_BINDING_SCHEMA_VERSION",
    "ENDPOINT_OPERATION_TEMPLATE_SCHEMA_VERSION",
    "ENDPOINT_POLICY_SCHEMA_VERSION",
    "MODEL_CAPABILITIES_SCHEMA_VERSION",
    "PIPELINE_PROFILE_SCHEMA_VERSION",
    "PROVIDER_PROFILE_SCHEMA_VERSION",
    "STAGE_BINDING_SCHEMA_VERSION",
    "CapabilityRole",
    "CredentialBindingMetadata",
    "CredentialValueScheme",
    "EndpointOperationTemplate",
    "EndpointPolicySnapshot",
    "ImageInputKind",
    "InputModality",
    "ModelCapabilitiesSnapshot",
    "PipelineProfileSnapshot",
    "ProviderApplicationState",
    "ProviderProfileSnapshot",
    "RedirectPolicy",
    "StageBindingSnapshot",
    "StructuredOutputKind",
]
