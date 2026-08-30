"""Pure Registry-to-plan routing for the Phase 1 multimodal path.

This module deliberately has no clock, environment, credential, capture, SDK,
or network dependency.  Callers pass one wall-clock observation and a trusted
capture-constraint snapshot explicitly.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid5

from snapquiz.domain._validation import require_aware_datetime, runtime_final
from snapquiz.domain.capabilities import CredentialBindingMetadata
from snapquiz.domain.capture import CaptureConstraints, CaptureScopeKind
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import ConfigError
from snapquiz.domain.intent import OutputTokenLimit, SolveIntent
from snapquiz.domain.plan import (
    ExecutionPlan,
    ExecutionPlanNetworkOperation,
    ExecutionPlanStage,
    OutboundDataKind,
    RequiredConsentScope,
    validate_phase1_remote_direct_plan,
)
from snapquiz.domain.policy import (
    ContractMarker,
    validate_policy_value_at,
)
from snapquiz.domain.solve import PipelineKind
from snapquiz.routing.registry import (
    Availability,
    RegistryIntegrityError,
    RegistryLookupError,
    RegistrySnapshot,
    ResolvedPipelineProfile,
    ResolvedStageBinding,
)

ROUTE_PLANNER_SCHEMA_VERSION = "snapquiz.route-planner.v1"
PLANNED_EXECUTION_SCHEMA_VERSION = "snapquiz.planned-execution.v1"

_PLANNER_UUID_NAMESPACE = UUID("10f036ee-5208-5e28-9b12-943a816fe823")
_PLANNED_EXECUTION_AUTHORITY = object()


def _config_error(message: str) -> ConfigError:
    return ConfigError(stage="planning", safe_message=message)


def _short_digest(value: Digest256) -> str:
    return str(value)[:12]


def _derive_planning_uuid(kind: str, payload: dict[str, object]) -> UUID:
    seed = digest256(
        "RoutePlannerIdentifier",
        ROUTE_PLANNER_SCHEMA_VERSION,
        {"kind": kind, "payload": payload},
    )
    return uuid5(_PLANNER_UUID_NAMESPACE, f"{kind}:{seed}")


def _capture_constraints_payload(
    constraints: CaptureConstraints,
) -> dict[str, object]:
    return {
        "allowed_display_ids": constraints.allowed_display_ids,
        "max_width_px": constraints.max_width_px,
        "max_height_px": constraints.max_height_px,
        "max_pixels": constraints.max_pixels,
        "max_bytes": constraints.max_bytes,
        "allow_full_screen": constraints.allow_full_screen,
    }


def _plan_id_for(
    *,
    request_id: UUID,
    resolved: ResolvedPipelineProfile,
    capture_constraints: CaptureConstraints,
    capture_scope_kind: CaptureScopeKind,
    requested_result_schema_version: str,
    max_output_tokens: int,
    timeout_budget_ms: int,
    operation_outbound_data: tuple[tuple[OutboundDataKind, ...], ...],
) -> UUID:
    profile = resolved.pipeline_profile
    return _derive_planning_uuid(
        "plan",
        {
            "request_id": request_id,
            "registry_revision": resolved.registry_revision,
            "registry_digest": resolved.registry_digest,
            "pipeline_profile_id": profile.pipeline_profile_id,
            "pipeline_profile_digest": profile.pipeline_profile_digest,
            "capture_scope_kind": capture_scope_kind.value,
            "capture_constraints": _capture_constraints_payload(
                capture_constraints
            ),
            "requested_result_schema_version": requested_result_schema_version,
            "max_output_tokens": max_output_tokens,
            "timeout_budget_ms": timeout_budget_ms,
            "operation_outbound_data": tuple(
                tuple(item.value for item in values)
                for values in operation_outbound_data
            ),
        },
    )


def _stage_id_for(
    *, plan_id: UUID, index: int, resolved_stage: ResolvedStageBinding
) -> UUID:
    return _derive_planning_uuid(
        "stage",
        {
            "plan_id": plan_id,
            "index": index,
            "registry_digest": resolved_stage.registry_digest,
            "stage_binding_digest": resolved_stage.stage_binding.stage_binding_digest,
        },
    )


def _operation_id_for(
    *,
    plan_id: UUID,
    stage_id: UUID,
    index: int,
    operation_template_digest: Digest256,
) -> UUID:
    return _derive_planning_uuid(
        "operation",
        {
            "plan_id": plan_id,
            "stage_id": stage_id,
            "index": index,
            "operation_template_digest": operation_template_digest,
        },
    )


def _effective_outbound_data(
    template_values: tuple[OutboundDataKind, ...], *, has_user_hint: bool
) -> tuple[OutboundDataKind, ...]:
    if has_user_hint:
        return template_values
    return tuple(
        value
        for value in template_values
        if value is not OutboundDataKind.USER_HINT
    )


def _expected_outbound_variants(
    template_values: tuple[OutboundDataKind, ...],
) -> tuple[tuple[OutboundDataKind, ...], ...]:
    without_hint = _effective_outbound_data(
        template_values, has_user_hint=False
    )
    if without_hint == template_values:
        return (template_values,)
    return (without_hint, template_values)


def _credential_plan_values(
    resolved_stage: ResolvedStageBinding,
) -> tuple[str | ContractMarker, Digest256 | ContractMarker]:
    credential = resolved_stage.provider_profile.credential_binding
    if type(credential) is CredentialBindingMetadata:
        return (
            credential.credential_binding_ref,
            credential.credential_binding_digest,
        )
    return (ContractMarker.NOT_APPLICABLE, ContractMarker.NOT_APPLICABLE)


def _validate_resolved_policies_at(
    resolved: ResolvedPipelineProfile, now: datetime
) -> None:
    validate_policy_value_at(
        resolved.pipeline_profile.cost_policy,
        now,
        name="pipeline cost policy",
    )
    for index, stage in enumerate(resolved.stages):
        provider = stage.provider_profile
        for name, policy in (
            ("retention", provider.retention_policy),
            ("data", provider.data_policy),
            ("cost", provider.cost_policy),
        ):
            validate_policy_value_at(
                policy,
                now,
                name=f"stage {index} {name} policy",
            )


def _tighten_capture_constraints(
    trusted: CaptureConstraints, resolved: ResolvedPipelineProfile
) -> CaptureConstraints:
    profile = resolved.pipeline_profile
    capabilities = resolved.stages[0].capabilities
    if type(capabilities.max_image_pixels) is not int or type(
        capabilities.max_image_bytes
    ) is not int:
        raise _config_error("模型图片能力上限缺少精确证据。")
    return CaptureConstraints(
        allowed_display_ids=tuple(sorted(trusted.allowed_display_ids)),
        max_width_px=min(trusted.max_width_px, profile.max_image_width_px),
        max_height_px=min(trusted.max_height_px, profile.max_image_height_px),
        max_pixels=min(
            trusted.max_pixels,
            profile.max_image_pixels,
            capabilities.max_image_pixels,
        ),
        max_bytes=min(
            trusted.max_bytes,
            profile.max_image_bytes,
            capabilities.max_image_bytes,
        ),
        allow_full_screen=False,
    )


def _planned_execution_payload(
    plan: ExecutionPlan, resolved: ResolvedPipelineProfile
) -> dict[str, object]:
    return {
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "registry_revision": resolved.registry_revision,
        "registry_digest": resolved.registry_digest,
        "availability": resolved.availability.value,
        "pipeline_profile_digest": (
            resolved.pipeline_profile.pipeline_profile_digest
        ),
        "stage_binding_digests": tuple(
            stage.stage_binding.stage_binding_digest for stage in resolved.stages
        ),
    }


@runtime_final
class PlannedExecution:
    """An immutable Plan/Registry-generation pair.

    Adapters and privacy gates consume this pair, never a plan plus a fresh
    lookup against a mutable "current" Registry.
    """

    __slots__ = ("plan", "resolved_pipeline", "planned_execution_digest")

    def __init__(
        self,
        *,
        plan: ExecutionPlan,
        resolved_pipeline: ResolvedPipelineProfile,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PLANNED_EXECUTION_AUTHORITY:
            raise TypeError("PlannedExecution can only be created by RoutePlanner")
        if type(plan) is not ExecutionPlan:
            raise ValueError("plan must be ExecutionPlan")
        if type(resolved_pipeline) is not ResolvedPipelineProfile:
            raise ValueError("resolved_pipeline must be ResolvedPipelineProfile")
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "resolved_pipeline", resolved_pipeline)
        self._validate_pair()
        object.__setattr__(
            self,
            "planned_execution_digest",
            digest256(
                "PlannedExecution",
                PLANNED_EXECUTION_SCHEMA_VERSION,
                _planned_execution_payload(plan, resolved_pipeline),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("PlannedExecution is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "PlannedExecution":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "PlannedExecution("
            f"plan_id={self.plan.plan_id!r}, "
            f"pipeline_profile_id={self.plan.pipeline_profile_id!r}, "
            f"availability={self.resolved_pipeline.availability.value!r}, "
            "planned_execution_digest_prefix="
            f"{_short_digest(self.planned_execution_digest)!r})"
        )

    def safe_metadata(self) -> dict[str, object]:
        return {
            "plan_id": str(self.plan.plan_id),
            "plan_digest_prefix": _short_digest(self.plan.plan_digest),
            "registry_digest_prefix": _short_digest(
                self.resolved_pipeline.registry_digest
            ),
            "pipeline_profile_id": self.plan.pipeline_profile_id,
            "availability": self.resolved_pipeline.availability.value,
            "planned_execution_digest_prefix": _short_digest(
                self.planned_execution_digest
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "PlannedExecution",
            PLANNED_EXECUTION_SCHEMA_VERSION,
            _planned_execution_payload(self.plan, self.resolved_pipeline),
        )

    def validate_integrity(self) -> None:
        try:
            if type(self.plan) is not ExecutionPlan:
                raise ValueError("planned execution contains an invalid plan")
            if type(self.resolved_pipeline) is not ResolvedPipelineProfile:
                raise ValueError(
                    "planned execution contains an invalid resolution"
                )
            if type(self.planned_execution_digest) is not Digest256:
                raise ValueError("planned execution digest has an invalid type")
            self._validate_pair()
            if self.recompute_digest() != self.planned_execution_digest:
                raise ValueError("planned execution integrity mismatch")
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("planned execution integrity mismatch") from error

    def _validate_pair(self) -> None:
        plan = self.plan
        resolved = self.resolved_pipeline
        resolved.validate_integrity()
        validate_phase1_remote_direct_plan(plan)
        if resolved.availability is Availability.DISABLED:
            raise ValueError("disabled pipeline cannot be planned")

        profile = resolved.pipeline_profile
        if (
            plan.pipeline_profile_id != profile.pipeline_profile_id
            or plan.pipeline_profile_digest != profile.pipeline_profile_digest
            or plan.pipeline_kind is not profile.pipeline_kind
            or plan.prompt_policy_digest != profile.prompt_policy_digest
            or plan.result_validator_version != profile.result_validator_version
            or plan.image_preprocessing_policy_version
            != profile.image_preprocessing_policy_version
            or plan.capture_scope_kind is not profile.capture_scope_kind
            or plan.preview_required is not profile.preview_required
            or plan.requested_result_schema_version
            != profile.requested_result_schema_version
            or plan.max_network_calls_total != profile.max_network_calls_total
            or plan.max_billable_calls != profile.max_billable_calls
            or plan.cost_policy != profile.cost_policy
            or plan.fallback_branches
            or profile.fallback_binding_ids
        ):
            raise ValueError("plan does not match the resolved pipeline profile")
        if not (0 < plan.timeout_budget_ms <= profile.timeout_budget_ms):
            raise ValueError("plan timeout is outside the profile bound")
        if not (0 < plan.max_output_tokens <= profile.max_output_tokens):
            raise ValueError("plan output limit is outside the profile bound")
        if (
            any(
                operation.billable is True
                or operation.billable is ContractMarker.UNKNOWN
                for stage in plan.stages
                for operation in stage.network_operations
            )
            and plan.cost_policy is ContractMarker.NOT_APPLICABLE
        ):
            raise ValueError(
                "potentially billable plan requires a cost policy"
            )
        capture = plan.capture_constraints
        if (
            capture.max_width_px > profile.max_image_width_px
            or capture.max_height_px > profile.max_image_height_px
            or capture.max_pixels > profile.max_image_pixels
            or capture.max_bytes > profile.max_image_bytes
            or capture.allow_full_screen
        ):
            raise ValueError("plan capture constraints expand the profile")

        if len(plan.stages) != len(resolved.stages):
            raise ValueError("plan stage count does not match Registry resolution")
        operation_outbound_data = tuple(
            operation.outbound_data
            for stage in plan.stages
            for operation in stage.network_operations
        )
        expected_plan_id = _plan_id_for(
            request_id=plan.request_id,
            resolved=resolved,
            capture_constraints=plan.capture_constraints,
            capture_scope_kind=plan.capture_scope_kind,
            requested_result_schema_version=plan.requested_result_schema_version,
            max_output_tokens=plan.max_output_tokens,
            timeout_budget_ms=plan.timeout_budget_ms,
            operation_outbound_data=operation_outbound_data,
        )
        if plan.plan_id != expected_plan_id:
            raise ValueError("plan identifier does not bind this Registry generation")

        for stage_index, (plan_stage, resolved_stage) in enumerate(
            zip(plan.stages, resolved.stages)
        ):
            if resolved_stage.provider_profile.cost_policy != profile.cost_policy:
                raise ValueError(
                    "provider and pipeline cost policies must be identical"
                )
            self._validate_stage_pair(
                plan_id=plan.plan_id,
                stage_index=stage_index,
                plan_stage=plan_stage,
                resolved_stage=resolved_stage,
                max_attempts_per_operation=profile.max_attempts_per_operation,
            )

    @staticmethod
    def _validate_stage_pair(
        *,
        plan_id: UUID,
        stage_index: int,
        plan_stage: ExecutionPlanStage,
        resolved_stage: ResolvedStageBinding,
        max_attempts_per_operation: int,
    ) -> None:
        binding = resolved_stage.stage_binding
        provider = resolved_stage.provider_profile
        capabilities = resolved_stage.capabilities
        endpoint_policy = provider.endpoint_policy
        credential_ref, credential_digest = _credential_plan_values(resolved_stage)
        expected_stage_id = _stage_id_for(
            plan_id=plan_id,
            index=stage_index,
            resolved_stage=resolved_stage,
        )
        if (
            plan_stage.stage_id != expected_stage_id
            or plan_stage.role is not binding.role
            or plan_stage.binding_id != binding.binding_id
            or plan_stage.provider_profile_id != provider.provider_profile_id
            or plan_stage.provider_profile_digest
            != provider.provider_profile_digest
            or plan_stage.provider_id != provider.provider_id
            or plan_stage.model_id != capabilities.model_id
            or plan_stage.component_id is not None
            or plan_stage.component_version is not None
            or plan_stage.adapter_family != provider.adapter_family
            or plan_stage.adapter_version != provider.adapter_version
            or plan_stage.capabilities_ref != capabilities.capabilities_ref
            or plan_stage.capabilities_digest != capabilities.capabilities_digest
            or plan_stage.endpoint_policy_version
            != endpoint_policy.endpoint_policy_version
            or plan_stage.network_policy_version
            != endpoint_policy.network_policy_version
            or plan_stage.tls_policy_ref != endpoint_policy.tls_policy_ref
            or plan_stage.credential_binding_ref != credential_ref
            or plan_stage.credential_binding_digest != credential_digest
            or plan_stage.network_scope is not provider.network_scope
            or plan_stage.compute_location is not provider.compute_location
            or plan_stage.processing_region != provider.processing_region
            or plan_stage.max_attempts_per_operation
            != max_attempts_per_operation
        ):
            raise ValueError("plan stage does not match its Registry binding")

        templates = endpoint_policy.operation_templates
        if len(plan_stage.network_operations) != len(templates):
            raise ValueError("plan operation count does not match endpoint policy")
        for operation_index, (operation, template) in enumerate(
            zip(plan_stage.network_operations, templates)
        ):
            expected_operation_id = _operation_id_for(
                plan_id=plan_id,
                stage_id=plan_stage.stage_id,
                index=operation_index,
                operation_template_digest=template.operation_template_digest,
            )
            if (
                operation.operation_id != expected_operation_id
                or operation.purpose is not template.purpose
                or operation.http_method != template.http_method
                or operation.canonical_endpoint != template.canonical_endpoint
                or operation.canonical_query_policy
                != template.canonical_query_policy
                or operation.content_type != template.content_type
                or operation.allowed_non_secret_headers
                != template.allowed_non_secret_headers
                or operation.credential_injection_slot
                is not template.credential_injection_slot
                or operation.outbound_data
                not in _expected_outbound_variants(template.outbound_data)
                or operation.retention_policy != provider.retention_policy
                or operation.data_policy != provider.data_policy
                or operation.billable != template.billable
            ):
                raise ValueError("plan operation does not match endpoint policy")


@runtime_final
class RoutePlanner:
    """Build an immutable pre-capture Phase 1 plan from one Registry snapshot."""

    __slots__ = ()

    def plan(
        self,
        *,
        intent: SolveIntent,
        registry: RegistrySnapshot,
        trusted_capture_constraints: CaptureConstraints,
        now: datetime,
    ) -> PlannedExecution:
        if type(intent) is not SolveIntent:
            raise TypeError("intent must be SolveIntent")
        if type(registry) is not RegistrySnapshot:
            raise TypeError("registry must be RegistrySnapshot")
        if type(trusted_capture_constraints) is not CaptureConstraints:
            raise TypeError(
                "trusted_capture_constraints must be CaptureConstraints"
            )
        require_aware_datetime(now, "now")

        try:
            if now < registry.published_at:
                raise _config_error("模型 Registry 快照尚未生效。")
            resolved = registry.resolve_pipeline(intent.pipeline_profile_id)
        except ConfigError:
            raise
        except (
            RegistryLookupError,
            RegistryIntegrityError,
            ValueError,
            TypeError,
            AttributeError,
        ) as error:
            raise _config_error("无法从可信 Registry 解析模型管线。") from error
        profile = resolved.pipeline_profile
        if resolved.availability is Availability.DISABLED:
            raise _config_error("所选模型管线当前不可用。")
        if profile.pipeline_kind is not PipelineKind.DIRECT_MULTIMODAL:
            raise _config_error("第一阶段仅支持显式多模态直连管线。")
        if intent.capture_scope_preference is not profile.capture_scope_kind:
            raise _config_error("截图范围与所选模型管线不匹配。")
        if profile.capture_scope_kind is not CaptureScopeKind.SELECTED_REGION:
            raise _config_error("第一阶段远程模型只允许选区截图。")
        if any(
            stage.provider_profile.cost_policy != profile.cost_policy
            for stage in resolved.stages
        ):
            raise _config_error("模型管线与服务方费用政策不一致。")
        if (
            any(
                template.billable is True
                or template.billable is ContractMarker.UNKNOWN
                for stage in resolved.stages
                for template in stage.provider_profile.endpoint_policy.operation_templates
            )
            and profile.cost_policy is ContractMarker.NOT_APPLICABLE
        ):
            raise _config_error("可能计费的网络操作缺少费用政策。")
        try:
            _validate_resolved_policies_at(resolved, now)
        except ValueError as error:
            raise _config_error("模型政策快照尚未生效或已经过期。") from error

        capture_constraints = _tighten_capture_constraints(
            trusted_capture_constraints, resolved
        )
        max_output_tokens = (
            profile.max_output_tokens
            if intent.max_output_tokens is OutputTokenLimit.PROFILE_DEFAULT
            else min(intent.max_output_tokens, profile.max_output_tokens)
        )
        timeout_budget_ms = min(
            intent.timeout_budget_ms, profile.timeout_budget_ms
        )

        operation_outbound_data = tuple(
            _effective_outbound_data(
                template.outbound_data,
                has_user_hint=intent.user_hint is not None,
            )
            for resolved_stage in resolved.stages
            for template in resolved_stage.provider_profile.endpoint_policy.operation_templates
        )
        plan_id = _plan_id_for(
            request_id=intent.request_id,
            resolved=resolved,
            capture_constraints=capture_constraints,
            capture_scope_kind=profile.capture_scope_kind,
            requested_result_schema_version=profile.requested_result_schema_version,
            max_output_tokens=max_output_tokens,
            timeout_budget_ms=timeout_budget_ms,
            operation_outbound_data=operation_outbound_data,
        )

        stages: list[ExecutionPlanStage] = []
        consent_scopes: list[RequiredConsentScope] = []
        outbound_index = 0
        for stage_index, resolved_stage in enumerate(resolved.stages):
            provider = resolved_stage.provider_profile
            binding = resolved_stage.stage_binding
            capabilities = resolved_stage.capabilities
            endpoint_policy = provider.endpoint_policy
            stage_id = _stage_id_for(
                plan_id=plan_id,
                index=stage_index,
                resolved_stage=resolved_stage,
            )
            operations: list[ExecutionPlanNetworkOperation] = []
            for operation_index, template in enumerate(
                endpoint_policy.operation_templates
            ):
                operation_id = _operation_id_for(
                    plan_id=plan_id,
                    stage_id=stage_id,
                    index=operation_index,
                    operation_template_digest=template.operation_template_digest,
                )
                operations.append(
                    ExecutionPlanNetworkOperation(
                        operation_id=operation_id,
                        purpose=template.purpose,
                        http_method=template.http_method,
                        canonical_endpoint=template.canonical_endpoint,
                        canonical_query_policy=template.canonical_query_policy,
                        content_type=template.content_type,
                        allowed_non_secret_headers=(
                            template.allowed_non_secret_headers
                        ),
                        credential_injection_slot=(
                            template.credential_injection_slot
                        ),
                        outbound_data=operation_outbound_data[outbound_index],
                        retention_policy=provider.retention_policy,
                        data_policy=provider.data_policy,
                        billable=template.billable,
                    )
                )
                outbound_index += 1
            credential_ref, credential_digest = _credential_plan_values(
                resolved_stage
            )
            stage = ExecutionPlanStage(
                stage_id=stage_id,
                role=binding.role,
                binding_id=binding.binding_id,
                provider_profile_id=provider.provider_profile_id,
                provider_profile_digest=provider.provider_profile_digest,
                provider_id=provider.provider_id,
                model_id=capabilities.model_id,
                component_id=None,
                component_version=None,
                adapter_family=provider.adapter_family,
                adapter_version=provider.adapter_version,
                capabilities_ref=capabilities.capabilities_ref,
                capabilities_digest=capabilities.capabilities_digest,
                endpoint_policy_version=(
                    endpoint_policy.endpoint_policy_version
                ),
                network_policy_version=endpoint_policy.network_policy_version,
                tls_policy_ref=endpoint_policy.tls_policy_ref,
                credential_binding_ref=credential_ref,
                credential_binding_digest=credential_digest,
                network_scope=provider.network_scope,
                compute_location=provider.compute_location,
                processing_region=provider.processing_region,
                max_attempts_per_operation=(
                    profile.max_attempts_per_operation
                ),
                network_operations=tuple(operations),
            )
            stages.append(stage)
            if operations:
                consent_scopes.append(
                    RequiredConsentScope(
                        binding_id=binding.binding_id,
                        provider_profile_id=provider.provider_profile_id,
                        provider_profile_digest=(
                            provider.provider_profile_digest
                        ),
                        network_scope=provider.network_scope,
                        compute_location=provider.compute_location,
                        processing_region=provider.processing_region,
                        retention_policy=provider.retention_policy,
                        data_policy=provider.data_policy,
                        cost_policy=profile.cost_policy,
                        network_operation_ids=tuple(
                            sorted(
                                (
                                    operation.operation_id
                                    for operation in operations
                                ),
                                key=str,
                            )
                        ),
                    )
                )

        plan = ExecutionPlan(
            plan_id=plan_id,
            request_id=intent.request_id,
            pipeline_profile_id=profile.pipeline_profile_id,
            pipeline_profile_digest=profile.pipeline_profile_digest,
            pipeline_kind=profile.pipeline_kind,
            prompt_policy_digest=profile.prompt_policy_digest,
            result_validator_version=profile.result_validator_version,
            image_preprocessing_policy_version=(
                profile.image_preprocessing_policy_version
            ),
            capture_scope_kind=profile.capture_scope_kind,
            capture_constraints=capture_constraints,
            preview_required=profile.preview_required,
            required_consent_scopes=tuple(consent_scopes),
            stages=tuple(stages),
            requested_result_schema_version=(
                profile.requested_result_schema_version
            ),
            max_output_tokens=max_output_tokens,
            timeout_budget_ms=timeout_budget_ms,
            max_network_calls_total=profile.max_network_calls_total,
            max_billable_calls=profile.max_billable_calls,
            cost_policy=profile.cost_policy,
            fallback_branches=(),
        )
        validate_phase1_remote_direct_plan(plan)
        return PlannedExecution(
            plan=plan,
            resolved_pipeline=resolved,
            _authority=_PLANNED_EXECUTION_AUTHORITY,
        )


__all__ = [
    "PLANNED_EXECUTION_SCHEMA_VERSION",
    "ROUTE_PLANNER_SCHEMA_VERSION",
    "PlannedExecution",
    "RoutePlanner",
]
