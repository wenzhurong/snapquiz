"""Deterministic, side-effect-free authorities and fixtures for W07 tests."""
from __future__ import annotations

import binascii
from datetime import timedelta
from types import SimpleNamespace
import struct
from uuid import UUID
import zlib

from snapquiz.capture.policy import CaptureAuthorizationLedger, CapturePolicy
from snapquiz.capture.validation import CaptureArtifactFactory, InputValidator
from snapquiz.config.profiles import GLM_PIPELINE_PROFILE_ID, build_builtin_registry
from snapquiz.domain.capabilities import (
    ModelCapabilitiesSnapshot,
    PipelineProfileSnapshot,
    ProviderProfileSnapshot,
    StageBindingSnapshot,
)
from snapquiz.domain.capture import CaptureConstraints, CaptureRect, CaptureScopeKind
from snapquiz.domain.intent import SOLVE_INTENT_SCHEMA_VERSION, OutputTokenLimit, SolveIntent
from snapquiz.domain.solve import SOLVE_RESULT_SCHEMA_VERSION
from snapquiz.pipelines.contracts import SolveRequestFactory, StageInvocationFactory
from snapquiz.routing.planner import RoutePlanner
from snapquiz.routing.registry import RegistrySnapshot

from tests.w06_helpers import (
    CAPTURE_ID,
    NOW,
    granted_permission,
    privacy_authorization,
    selected_scope,
    topology,
)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = binascii.crc32(kind)
    checksum = binascii.crc32(payload, checksum) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", checksum)
    )


def canonical_png_bytes() -> bytes:
    """Return a tiny canonical 4x2 RGB PNG with visible luma variation."""

    width, height = 4, 2
    pixels = bytearray()
    for index in range(width * height):
        value = 255 if index % 2 else 0
        pixels.extend((value, value, value))
    raw = b"".join(
        b"\x00" + bytes(pixels[row * width * 3 : (row + 1) * width * 3])
        for row in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(raw))
        + _png_chunk(b"IEND", b"")
    )


def registry_with_fixed_parameters(
    parameters: tuple[tuple[str, str], ...],
) -> RegistrySnapshot:
    """Return a valid built-in generation whose Adapter parameters are non-empty."""

    original = build_builtin_registry()
    old_provider = original.provider_profiles[0]
    old_capabilities = original.capability_snapshots[0]
    old_pipeline = original.pipeline_profiles[0]
    old_binding = old_pipeline.stage_bindings[0]
    provider = ProviderProfileSnapshot(
        provider_profile_id=old_provider.provider_profile_id,
        provider_id=old_provider.provider_id,
        adapter_family=old_provider.adapter_family,
        adapter_version=old_provider.adapter_version,
        api_version=old_provider.api_version,
        endpoint_policy=old_provider.endpoint_policy,
        credential_binding=old_provider.credential_binding,
        compute_location=old_provider.compute_location,
        processing_region=old_provider.processing_region,
        provider_application_state=old_provider.provider_application_state,
        retention_policy=old_provider.retention_policy,
        data_policy=old_provider.data_policy,
        cost_policy=old_provider.cost_policy,
        fixed_non_secret_parameters=parameters,
    )
    capabilities = ModelCapabilitiesSnapshot(
        capabilities_ref=old_capabilities.capabilities_ref,
        provider_profile=provider,
        model_id=old_capabilities.model_id,
        input_modalities=old_capabilities.input_modalities,
        roles=old_capabilities.roles,
        image_inputs=old_capabilities.image_inputs,
        structured_output=old_capabilities.structured_output,
        supports_system_instruction=old_capabilities.supports_system_instruction,
        supports_reasoning_control=old_capabilities.supports_reasoning_control,
        supports_usage=old_capabilities.supports_usage,
        max_images=old_capabilities.max_images,
        max_image_bytes=old_capabilities.max_image_bytes,
        max_image_pixels=old_capabilities.max_image_pixels,
        max_output_tokens=old_capabilities.max_output_tokens,
        supported_mime_types=old_capabilities.supported_mime_types,
        data_residency=old_capabilities.data_residency,
    )
    binding = StageBindingSnapshot(
        binding_id=old_binding.binding_id,
        role=old_binding.role,
        provider_profile=provider,
        capabilities=capabilities,
        selected_image_input=old_binding.selected_image_input,
        selected_structured_output=old_binding.selected_structured_output,
        send_system_instruction=old_binding.send_system_instruction,
        send_reasoning_control=old_binding.send_reasoning_control,
        expect_usage=old_binding.expect_usage,
    )
    pipeline = PipelineProfileSnapshot(
        pipeline_profile_id=old_pipeline.pipeline_profile_id,
        pipeline_kind=old_pipeline.pipeline_kind,
        stage_bindings=(binding,),
        prompt_policy_digest=old_pipeline.prompt_policy_digest,
        result_validator_version=old_pipeline.result_validator_version,
        image_preprocessing_policy_version=(
            old_pipeline.image_preprocessing_policy_version
        ),
        requested_result_schema_version=old_pipeline.requested_result_schema_version,
        capture_scope_kind=old_pipeline.capture_scope_kind,
        preview_required=old_pipeline.preview_required,
        timeout_budget_ms=old_pipeline.timeout_budget_ms,
        max_attempts_per_operation=old_pipeline.max_attempts_per_operation,
        max_network_calls_total=old_pipeline.max_network_calls_total,
        max_billable_calls=old_pipeline.max_billable_calls,
        max_output_tokens=old_pipeline.max_output_tokens,
        max_image_width_px=old_pipeline.max_image_width_px,
        max_image_height_px=old_pipeline.max_image_height_px,
        max_image_pixels=old_pipeline.max_image_pixels,
        max_image_bytes=old_pipeline.max_image_bytes,
        cost_policy=old_pipeline.cost_policy,
        fallback_binding_ids=old_pipeline.fallback_binding_ids,
        enabled=old_pipeline.enabled,
    )
    return RegistrySnapshot(
        registry_revision="snapquiz.builtin-registry@test-w07-fixed-params",
        published_at=original.published_at,
        authority=original.authority,
        provider_profiles=(provider,),
        capability_snapshots=(capabilities,),
        pipeline_profiles=(pipeline,),
    )


def make_w07_authorities(
    *,
    user_hint: str | None = None,
    locale: str = "zh-Hans-CN",
    request_id: UUID = UUID("30000000-0000-0000-0000-000000000001"),
    capture_id: UUID = CAPTURE_ID,
    registry: RegistrySnapshot | None = None,
    one_shot_consent: bool = False,
) -> SimpleNamespace:
    initial_topology = topology()
    intent = SolveIntent(
        schema_version=SOLVE_INTENT_SCHEMA_VERSION,
        request_id=request_id,
        pipeline_profile_id=GLM_PIPELINE_PROFILE_ID,
        capture_scope_preference=CaptureScopeKind.SELECTED_REGION,
        locale=locale,
        timeout_budget_ms=30_000,
        max_output_tokens=OutputTokenLimit.PROFILE_DEFAULT,
        requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
        user_hint=user_hint,
    )
    planned = RoutePlanner().plan(
        intent=intent,
        registry=build_builtin_registry() if registry is None else registry,
        trusted_capture_constraints=CaptureConstraints(
            allowed_display_ids=("display-1",),
            display_topology_revision=initial_topology.topology_revision,
            max_width_px=2_000,
            max_height_px=1_500,
            max_pixels=3_000_000,
            max_bytes=5_000_000,
            allow_full_screen=True,
        ),
        now=NOW,
    )
    scope = selected_scope(
        initial_topology,
        rect=CaptureRect(left=20, top=30, width=4, height=2),
    )
    consent_ledger, privacy = privacy_authorization(
        planned,
        scope_fingerprint=scope.fingerprint,
        one_shot=one_shot_consent,
    )
    capture_ledger = CaptureAuthorizationLedger()
    authorization = CapturePolicy().authorize(
        planned=planned,
        privacy_authorization=privacy,
        consent_ledger=consent_ledger,
        permission_observation=granted_permission(),
        topology=initial_topology,
        selected_scope=scope,
        capture_id=capture_id,
        capture_ledger=capture_ledger,
        now=NOW,
    )
    pre_capture_time = NOW + timedelta(seconds=1)
    consumed = CapturePolicy().prepare_capture(
        planned=planned,
        privacy_authorization=privacy,
        consent_ledger=consent_ledger,
        authorization=authorization,
        capture_ledger=capture_ledger,
        permission_observation=granted_permission(observed_at=pre_capture_time),
        topology=topology(observed_at=pre_capture_time),
        now=pre_capture_time,
    )
    captured_at = NOW + timedelta(seconds=2)
    artifact = CaptureArtifactFactory.create(
        consumed=consumed,
        capture_ledger=capture_ledger,
        data=canonical_png_bytes(),
        mime_type="image/png",
        width_px=4,
        height_px=2,
        captured_at=captured_at,
    )
    post_capture_time = NOW + timedelta(seconds=3)
    validated = InputValidator.validate(
        planned=planned,
        privacy_authorization=privacy,
        consent_ledger=consent_ledger,
        consumed=consumed,
        capture_ledger=capture_ledger,
        artifact=artifact,
        permission_observation=granted_permission(observed_at=post_capture_time),
        topology=topology(observed_at=post_capture_time),
        now=post_capture_time,
    )
    solve_request = SolveRequestFactory.create(
        planned=planned,
        intent=intent,
        validated_capture=validated,
    )
    stage = planned.plan.stages[0]
    invocation = StageInvocationFactory.create(
        planned=planned,
        solve_request=solve_request,
        stage_id=stage.stage_id,
    )
    return SimpleNamespace(
        intent=intent,
        planned=planned,
        validated=validated,
        solve_request=solve_request,
        invocation=invocation,
        operation=stage.network_operations[0],
        artifact=artifact,
        privacy=privacy,
        consent_ledger=consent_ledger,
        capture_ledger=capture_ledger,
    )
