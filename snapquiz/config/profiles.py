"""Controlled built-in profile factories.

Construction is deterministic and offline.  The frozen GLM binding remains
``experimental`` at Registry resolution time because no complete
VerificationRecord exists yet.
"""
from __future__ import annotations

from datetime import datetime, timezone

from snapquiz.adapters.prompt import PROMPT_POLICY_DIGEST, PROMPT_POLICY_REF
from snapquiz.domain.capabilities import (
    CapabilityRole,
    CredentialBindingMetadata,
    CredentialValueScheme,
    EndpointOperationTemplate,
    EndpointPolicySnapshot,
    ImageInputKind,
    InputModality,
    ModelCapabilitiesSnapshot,
    PipelineProfileSnapshot,
    ProviderApplicationState,
    ProviderProfileSnapshot,
    RedirectPolicy,
    StageBindingSnapshot,
    StructuredOutputKind,
)
from snapquiz.domain.capture import CaptureScopeKind
from snapquiz.domain.digest import Digest256
from snapquiz.domain.plan import (
    CanonicalQueryPolicy,
    ComputeLocation,
    CredentialInjectionSlot,
    NetworkOperationPurpose,
    NetworkScope,
    OutboundDataKind,
    QueryPolicyKind,
)
from snapquiz.domain.policy import ContractMarker
from snapquiz.domain.solve import PipelineKind, SOLVE_RESULT_SCHEMA_VERSION, StageRole
from snapquiz.result.validator import RESULT_VALIDATOR_VERSION
from snapquiz.routing.registry import RegistryAuthority, RegistrySnapshot

BUILTIN_REGISTRY_REVISION = "snapquiz.builtin-registry@2026-09-03-w09"
BUILTIN_REGISTRY_PUBLISHED_AT = datetime(2026, 8, 31, tzinfo=timezone.utc)

GLM_PROVIDER_ID = "zhipu"
GLM_MODEL_ID = "glm-4.6v-flash"
GLM_PROVIDER_PROFILE_ID = "provider.zhipu.official.v4"
GLM_CAPABILITIES_REF = "capabilities:zhipu/glm-4.6v-flash@2026-08-31"
GLM_BINDING_ID = "binding:zhipu/glm-4.6v-flash@openai-chat.v1"
GLM_PIPELINE_PROFILE_ID = "direct-zhipu-glm-4.6v-flash-v1"
GLM_ENDPOINT_POLICY_VERSION = "zhipu-official-chat-completions.v1"
GLM_NETWORK_POLICY_VERSION = "remote-https.v1"
GLM_TLS_POLICY_REF = "snapquiz.tls.system-default-h1.v1"
GLM_CREDENTIAL_BINDING_REF = "registry:zhipu-official-glm.v1"
GLM_CREDENTIAL_REF = "env:GLM_API_KEY"

GLM_ALLOWED_ORIGIN = "https://open.bigmodel.cn:443/"
GLM_ALLOWED_BASE_PATH = "/api/paas/v4/"
GLM_CHAT_COMPLETIONS_ENDPOINT = (
    "https://open.bigmodel.cn:443/api/paas/v4/chat/completions"
)
GLM_LEGACY_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"

GLM_ADAPTER_FAMILY = "openai_chat_compatible"
GLM_ADAPTER_VERSION = "snapquiz.openai-chat-compatible.glm-4.6v-flash.v1"
GLM_IMAGE_PREPROCESSING_POLICY_VERSION = (
    "snapquiz.image-preprocessing.canonical-png-pass-through.v1"
)
GLM_PROMPT_POLICY_REF = PROMPT_POLICY_REF
GLM_PROMPT_POLICY_DIGEST = PROMPT_POLICY_DIGEST


def build_builtin_registry() -> RegistrySnapshot:
    """Build the frozen Phase 1 GLM Registry generation without side effects."""

    operation = EndpointOperationTemplate(
        operation_key="inference",
        purpose=NetworkOperationPurpose.INFERENCE,
        http_method="POST",
        canonical_endpoint=GLM_CHAT_COMPLETIONS_ENDPOINT,
        canonical_query_policy=CanonicalQueryPolicy(kind=QueryPolicyKind.EMPTY),
        content_type="application/json",
        allowed_non_secret_headers=(),
        credential_injection_slot=CredentialInjectionSlot.AUTHORIZATION_HEADER,
        outbound_data=(OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT),
        billable=ContractMarker.UNKNOWN,
    )
    endpoint_policy = EndpointPolicySnapshot(
        endpoint_policy_version=GLM_ENDPOINT_POLICY_VERSION,
        allowed_origins=(GLM_ALLOWED_ORIGIN,),
        allowed_base_paths=(GLM_ALLOWED_BASE_PATH,),
        operation_templates=(operation,),
        allow_custom_endpoint=False,
        redirect_policy=RedirectPolicy.REJECT,
        network_scope=NetworkScope.INTERNET,
        network_policy_version=GLM_NETWORK_POLICY_VERSION,
        tls_policy_ref=GLM_TLS_POLICY_REF,
    )
    credential_binding = CredentialBindingMetadata(
        credential_binding_ref=GLM_CREDENTIAL_BINDING_REF,
        credential_ref=GLM_CREDENTIAL_REF,
        provider_id=GLM_PROVIDER_ID,
        endpoint_policy=endpoint_policy,
        credential_injection_slot=CredentialInjectionSlot.AUTHORIZATION_HEADER,
        credential_value_scheme=CredentialValueScheme.BEARER,
    )
    provider = ProviderProfileSnapshot(
        provider_profile_id=GLM_PROVIDER_PROFILE_ID,
        provider_id=GLM_PROVIDER_ID,
        adapter_family=GLM_ADAPTER_FAMILY,
        adapter_version=GLM_ADAPTER_VERSION,
        api_version="v4",
        endpoint_policy=endpoint_policy,
        credential_binding=credential_binding,
        compute_location=ComputeLocation.REMOTE,
        processing_region=ContractMarker.UNKNOWN,
        provider_application_state=ProviderApplicationState.UNKNOWN,
        retention_policy=ContractMarker.UNKNOWN,
        data_policy=ContractMarker.UNKNOWN,
        cost_policy=ContractMarker.UNKNOWN,
    )
    capabilities = ModelCapabilitiesSnapshot(
        capabilities_ref=GLM_CAPABILITIES_REF,
        provider_profile=provider,
        model_id=GLM_MODEL_ID,
        input_modalities=(InputModality.IMAGE, InputModality.TEXT),
        roles=(CapabilityRole.MULTIMODAL_SOLVER, CapabilityRole.TEXT_SOLVER),
        image_inputs=(ImageInputKind.PUBLIC_URL, ImageInputKind.RAW_BASE64),
        structured_output=StructuredOutputKind.PROMPT_ONLY,
        supports_system_instruction=True,
        supports_reasoning_control=True,
        supports_usage=True,
        # Conservative application acceptance bounds, not claims about the
        # Provider's permanent product limits.
        max_images=1,
        max_image_bytes=5_242_880,
        max_image_pixels=4_000_000,
        max_output_tokens=1_024,
        supported_mime_types=("image/jpeg", "image/png"),
        data_residency=ContractMarker.UNKNOWN,
    )
    stage_binding = StageBindingSnapshot(
        binding_id=GLM_BINDING_ID,
        role=StageRole.SOLVER,
        provider_profile=provider,
        capabilities=capabilities,
        selected_image_input=ImageInputKind.RAW_BASE64,
        selected_structured_output=StructuredOutputKind.PROMPT_ONLY,
        send_system_instruction=True,
        send_reasoning_control=False,
        expect_usage=True,
    )
    pipeline = PipelineProfileSnapshot(
        pipeline_profile_id=GLM_PIPELINE_PROFILE_ID,
        pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
        stage_bindings=(stage_binding,),
        prompt_policy_digest=GLM_PROMPT_POLICY_DIGEST,
        result_validator_version=RESULT_VALIDATOR_VERSION,
        image_preprocessing_policy_version=GLM_IMAGE_PREPROCESSING_POLICY_VERSION,
        requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
        capture_scope_kind=CaptureScopeKind.SELECTED_REGION,
        preview_required=True,
        timeout_budget_ms=40_000,
        max_attempts_per_operation=2,
        max_network_calls_total=2,
        max_billable_calls=2,
        max_output_tokens=1_024,
        max_image_width_px=4_096,
        max_image_height_px=4_096,
        max_image_pixels=4_000_000,
        max_image_bytes=5_242_880,
        cost_policy=ContractMarker.UNKNOWN,
        fallback_binding_ids=(),
        enabled=True,
    )
    return RegistrySnapshot(
        registry_revision=BUILTIN_REGISTRY_REVISION,
        published_at=BUILTIN_REGISTRY_PUBLISHED_AT,
        authority=RegistryAuthority.BUILTIN,
        provider_profiles=(provider,),
        capability_snapshots=(capabilities,),
        pipeline_profiles=(pipeline,),
    )


def builtin_registry_digest() -> Digest256:
    """Return the deterministic built-in generation digest."""

    return build_builtin_registry().registry_digest


__all__ = [
    "BUILTIN_REGISTRY_PUBLISHED_AT",
    "BUILTIN_REGISTRY_REVISION",
    "GLM_ADAPTER_FAMILY",
    "GLM_ADAPTER_VERSION",
    "GLM_ALLOWED_BASE_PATH",
    "GLM_ALLOWED_ORIGIN",
    "GLM_BINDING_ID",
    "GLM_CAPABILITIES_REF",
    "GLM_CHAT_COMPLETIONS_ENDPOINT",
    "GLM_CREDENTIAL_BINDING_REF",
    "GLM_CREDENTIAL_REF",
    "GLM_ENDPOINT_POLICY_VERSION",
    "GLM_IMAGE_PREPROCESSING_POLICY_VERSION",
    "GLM_LEGACY_BASE_URL",
    "GLM_MODEL_ID",
    "GLM_NETWORK_POLICY_VERSION",
    "GLM_PIPELINE_PROFILE_ID",
    "GLM_PROVIDER_ID",
    "GLM_PROVIDER_PROFILE_ID",
    "GLM_PROMPT_POLICY_DIGEST",
    "GLM_PROMPT_POLICY_REF",
    "GLM_TLS_POLICY_REF",
    "build_builtin_registry",
    "builtin_registry_digest",
]
