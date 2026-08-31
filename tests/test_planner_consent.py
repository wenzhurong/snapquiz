import copy
import itertools
import subprocess
import sys
import textwrap
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Thread
from uuid import UUID

from snapquiz.config.profiles import (
    GLM_BINDING_ID,
    GLM_PIPELINE_PROFILE_ID,
    build_builtin_registry,
)
from snapquiz.domain.capabilities import (
    ModelCapabilitiesSnapshot,
    PipelineProfileSnapshot,
    ProviderProfileSnapshot,
    StageBindingSnapshot,
)
from snapquiz.domain.capture import CaptureConstraints, CaptureScopeKind
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import ConfigError, EndpointPolicyError
from snapquiz.domain.intent import (
    SOLVE_INTENT_SCHEMA_VERSION,
    OutputTokenLimit,
    SolveIntent,
)
from snapquiz.domain.plan import OutboundDataKind
from snapquiz.domain.policy import (
    ContractMarker,
    PolicySnapshot,
    validate_policy_value_at,
)
from snapquiz.domain.solve import SOLVE_RESULT_SCHEMA_VERSION
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentGrant,
    ConsentLedger,
    ConsentNetworkOperation,
    PrivacyGate,
    UnknownPolicyDimension,
)
from snapquiz.routing.planner import PlannedExecution, RoutePlanner
from snapquiz.routing.registry import (
    RegistryAuthority,
    RegistryIntegrityError,
    RegistrySnapshot,
)


NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
REQUEST_ID = UUID("00000000-0000-0000-0000-000000000001")
GRANT_ID = UUID("00000000-0000-0000-0000-000000000099")
ALL_UNKNOWN_CONFIRMATIONS = (
    UnknownPolicyDimension.COST,
    UnknownPolicyDimension.DATA,
    UnknownPolicyDimension.PROCESSING_REGION,
    UnknownPolicyDimension.RETENTION,
)


def _digest(char: str) -> Digest256:
    return Digest256(char * 64)


def _intent(
    *,
    request_id: UUID = REQUEST_ID,
    pipeline_profile_id: str = GLM_PIPELINE_PROFILE_ID,
    capture_scope: CaptureScopeKind = CaptureScopeKind.SELECTED_REGION,
    timeout_budget_ms: int = 30_000,
    max_output_tokens: int | OutputTokenLimit = OutputTokenLimit.PROFILE_DEFAULT,
    user_hint: str | None = None,
) -> SolveIntent:
    return SolveIntent(
        schema_version=SOLVE_INTENT_SCHEMA_VERSION,
        request_id=request_id,
        pipeline_profile_id=pipeline_profile_id,
        capture_scope_preference=capture_scope,
        locale="zh-Hans-CN",
        timeout_budget_ms=timeout_budget_ms,
        max_output_tokens=max_output_tokens,
        requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
        user_hint=user_hint,
    )


def _trusted_capture_constraints() -> CaptureConstraints:
    return CaptureConstraints(
        allowed_display_ids=("display-2", "display-1"),
        display_topology_revision=_digest("7"),
        max_width_px=3_000,
        max_height_px=2_000,
        max_pixels=6_000_000,
        max_bytes=6_000_000,
        allow_full_screen=True,
    )


def _planned(
    *,
    registry: RegistrySnapshot | None = None,
    intent: SolveIntent | None = None,
    now: datetime = NOW,
) -> PlannedExecution:
    return RoutePlanner().plan(
        intent=intent or _intent(),
        registry=registry or build_builtin_registry(),
        trusted_capture_constraints=_trusted_capture_constraints(),
        now=now,
    )


def _known_policy(
    name: str,
    *,
    verified_at: datetime = NOW - timedelta(days=1),
    expires_at: datetime | None = NOW + timedelta(days=30),
) -> PolicySnapshot:
    return PolicySnapshot(
        ref=f"policy://test/{name}/v1",
        content_digest=_digest("a"),
        verified_at=verified_at,
        expires_at=expires_at,
    )


def _registry_with_policies(
    *,
    processing_region=ContractMarker.UNKNOWN,
    retention_policy=ContractMarker.UNKNOWN,
    data_policy=ContractMarker.UNKNOWN,
    cost_policy=ContractMarker.UNKNOWN,
    pipeline_cost_policy=None,
    revision: str = "snapquiz.test-registry@policies-v1",
    published_at: datetime = NOW - timedelta(days=1),
) -> RegistrySnapshot:
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
        processing_region=processing_region,
        provider_application_state=old_provider.provider_application_state,
        retention_policy=retention_policy,
        data_policy=data_policy,
        cost_policy=cost_policy,
        fixed_non_secret_parameters=old_provider.fixed_non_secret_parameters,
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
        requested_result_schema_version=(
            old_pipeline.requested_result_schema_version
        ),
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
        cost_policy=(
            cost_policy
            if pipeline_cost_policy is None
            else pipeline_cost_policy
        ),
        fallback_binding_ids=old_pipeline.fallback_binding_ids,
        enabled=old_pipeline.enabled,
    )
    return RegistrySnapshot(
        registry_revision=revision,
        published_at=published_at,
        authority=RegistryAuthority.BUILTIN,
        provider_profiles=(provider,),
        capability_snapshots=(capabilities,),
        pipeline_profiles=(pipeline,),
    )


def _same_profiles_new_generation() -> RegistrySnapshot:
    original = build_builtin_registry()
    return RegistrySnapshot(
        registry_revision="snapquiz.builtin-registry@test-hot-reload",
        published_at=original.published_at + timedelta(seconds=1),
        authority=original.authority,
        provider_profiles=original.provider_profiles,
        capability_snapshots=original.capability_snapshots,
        pipeline_profiles=original.pipeline_profiles,
    )


def _issue(
    planned: PlannedExecution,
    *,
    ledger: ConsentLedger | None = None,
    grant_id: UUID = GRANT_ID,
    request_id: UUID | None = None,
    issued_at: datetime = NOW,
    expires_at: datetime | None = NOW + timedelta(days=30),
    one_shot: bool = False,
    confirmations: tuple[UnknownPolicyDimension, ...] = ALL_UNKNOWN_CONFIRMATIONS,
    fingerprint: Digest256 | None = None,
) -> tuple[ConsentLedger, ConsentGrant]:
    selected_ledger = ledger or ConsentLedger()
    grant = selected_ledger.issue_for_plan(
        planned=planned,
        binding_id=GLM_BINDING_ID,
        grant_id=grant_id,
        request_id=request_id,
        capture_scope_fingerprint=fingerprint,
        issued_at=issued_at,
        expires_at=expires_at,
        one_shot=one_shot,
        confirmed_unknown_policies=confirmations,
    )
    return selected_ledger, grant


class RoutePlannerContractTest(unittest.TestCase):
    def test_registry_maps_to_exact_plan_and_tightens_bounds(self):
        registry = build_builtin_registry()
        planned = _planned(
            registry=registry,
            intent=_intent(
                timeout_budget_ms=90_000,
                max_output_tokens=512,
            ),
        )
        plan = planned.plan
        resolved = planned.resolved_pipeline
        profile = resolved.pipeline_profile
        stage = plan.stages[0]
        resolved_stage = resolved.stages[0]
        provider = resolved_stage.provider_profile
        template = provider.endpoint_policy.operation_templates[0]
        operation = stage.network_operations[0]

        self.assertEqual(plan.request_id, REQUEST_ID)
        self.assertEqual(plan.pipeline_profile_id, profile.pipeline_profile_id)
        self.assertEqual(
            plan.pipeline_profile_digest, profile.pipeline_profile_digest
        )
        self.assertEqual(plan.timeout_budget_ms, profile.timeout_budget_ms)
        self.assertEqual(plan.max_output_tokens, 512)
        self.assertEqual(
            plan.capture_constraints.allowed_display_ids,
            ("display-1", "display-2"),
        )
        self.assertEqual(plan.capture_constraints.max_width_px, 3_000)
        self.assertEqual(plan.capture_constraints.max_height_px, 2_000)
        self.assertEqual(plan.capture_constraints.max_pixels, 4_000_000)
        self.assertEqual(plan.capture_constraints.max_bytes, 5_242_880)
        self.assertFalse(plan.capture_constraints.allow_full_screen)
        self.assertTrue(plan.preview_required)
        self.assertEqual(plan.fallback_branches, ())
        self.assertEqual(stage.binding_id, resolved_stage.stage_binding.binding_id)
        self.assertEqual(
            stage.provider_profile_digest, provider.provider_profile_digest
        )
        self.assertEqual(
            stage.capabilities_digest,
            resolved_stage.capabilities.capabilities_digest,
        )
        self.assertEqual(operation.http_method, template.http_method)
        self.assertEqual(
            operation.canonical_endpoint, template.canonical_endpoint
        )
        self.assertEqual(operation.outbound_data, (OutboundDataKind.IMAGE,))
        self.assertEqual(operation.retention_policy, provider.retention_policy)
        self.assertEqual(operation.data_policy, provider.data_policy)
        self.assertEqual(len(plan.required_consent_scopes), 1)
        self.assertEqual(
            plan.required_consent_scopes[0].network_operation_ids,
            (operation.operation_id,),
        )
        planned.validate_integrity()

    def test_default_equal_lower_and_higher_intent_are_deterministic(self):
        profile = build_builtin_registry().pipeline_profiles[0]
        cases = (
            (OutputTokenLimit.PROFILE_DEFAULT, profile.max_output_tokens),
            (profile.max_output_tokens, profile.max_output_tokens),
            (512, 512),
            (profile.max_output_tokens * 2, profile.max_output_tokens),
        )
        for requested, expected in cases:
            with self.subTest(requested=requested):
                first = _planned(intent=_intent(max_output_tokens=requested))
                second = _planned(intent=_intent(max_output_tokens=requested))
                self.assertEqual(first.plan.max_output_tokens, expected)
                self.assertEqual(first.plan.plan_id, second.plan.plan_id)
                self.assertEqual(first.plan.plan_digest, second.plan.plan_digest)
                self.assertEqual(
                    first.planned_execution_digest,
                    second.planned_execution_digest,
                )

    def test_user_hint_only_changes_declared_data_kind_not_repr(self):
        canary = "PRIVATE-HINT-CANARY"
        without_hint = _planned(intent=_intent(user_hint=None))
        with_hint = _planned(intent=_intent(user_hint=canary))
        self.assertEqual(
            without_hint.plan.stages[0].network_operations[0].outbound_data,
            (OutboundDataKind.IMAGE,),
        )
        self.assertEqual(
            with_hint.plan.stages[0].network_operations[0].outbound_data,
            (OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT),
        )
        self.assertNotEqual(without_hint.plan.plan_id, with_hint.plan.plan_id)
        self.assertNotIn(canary, repr(with_hint))
        self.assertNotIn(canary, repr(with_hint.safe_metadata()))

    def test_remote_full_screen_is_rejected_before_planning(self):
        with self.assertRaises(ConfigError):
            _planned(intent=_intent(capture_scope=CaptureScopeKind.FULL_SCREEN))

    def test_expired_and_future_policy_snapshots_are_rejected(self):
        expired = _known_policy(
            "expired",
            verified_at=NOW - timedelta(days=2),
            expires_at=NOW,
        )
        future = _known_policy(
            "future",
            verified_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(days=1),
        )
        for policy in (expired, future):
            registry = _registry_with_policies(
                retention_policy=policy,
                data_policy=policy,
                cost_policy=policy,
            )
            with self.subTest(policy=policy.ref), self.assertRaises(ConfigError):
                _planned(registry=registry)

    def test_provider_and_pipeline_cost_policy_must_be_identical(self):
        known = _known_policy("provider-cost")
        with self.assertRaises(RegistryIntegrityError):
            _registry_with_policies(
                cost_policy=known,
                pipeline_cost_policy=ContractMarker.UNKNOWN,
            )

    def test_potentially_billable_operation_requires_cost_policy(self):
        with self.assertRaises(RegistryIntegrityError):
            _registry_with_policies(
                cost_policy=ContractMarker.NOT_APPLICABLE,
            )

    def test_registry_lookup_integrity_and_future_publication_fail_as_config(self):
        with self.assertRaises(ConfigError):
            _planned(intent=_intent(pipeline_profile_id="missing/pipeline"))

        tampered = build_builtin_registry()
        object.__setattr__(tampered, "registry_digest", _digest("a"))
        with self.assertRaises(ConfigError):
            _planned(registry=tampered)

        malformed = build_builtin_registry()
        object.__setattr__(malformed, "published_at", None)
        with self.assertRaises(ConfigError):
            _planned(registry=malformed)

        future = _registry_with_policies(
            published_at=NOW + timedelta(microseconds=1),
        )
        with self.assertRaises(ConfigError):
            _planned(registry=future)

    def test_policy_validity_uses_half_open_interval(self):
        policy = _known_policy("boundary", expires_at=NOW)
        validate_policy_value_at(policy, NOW - timedelta(microseconds=1))
        with self.assertRaises(ValueError):
            validate_policy_value_at(policy, NOW)

    def test_hot_reload_creates_new_generation_without_mutating_old_pair(self):
        generation_a = build_builtin_registry()
        generation_b = _same_profiles_new_generation()
        planned_a = _planned(registry=generation_a)
        planned_b = _planned(registry=generation_b)
        self.assertNotEqual(
            generation_a.registry_digest, generation_b.registry_digest
        )
        self.assertNotEqual(planned_a.plan.plan_id, planned_b.plan.plan_id)
        self.assertNotEqual(planned_a.plan.plan_digest, planned_b.plan.plan_digest)
        planned_a.validate_integrity()
        self.assertEqual(
            planned_a.resolved_pipeline.registry_digest,
            generation_a.registry_digest,
        )

        object.__setattr__(
            planned_a, "resolved_pipeline", planned_b.resolved_pipeline
        )
        with self.assertRaises(ValueError):
            planned_a.validate_integrity()

    def test_planned_execution_is_private_immutable_and_not_a_dataclass(self):
        planned = _planned()
        with self.assertRaises(TypeError):
            PlannedExecution(
                plan=planned.plan,
                resolved_pipeline=planned.resolved_pipeline,
            )
        with self.assertRaises(AttributeError):
            planned.plan = planned.plan  # type: ignore[misc]
        with self.assertRaises(TypeError):
            asdict(planned)  # type: ignore[arg-type]
        self.assertIs(copy.deepcopy(planned), planned)

    def test_fresh_process_planning_has_no_external_side_effect_dependency(self):
        root = Path(__file__).resolve().parents[1]
        script = textwrap.dedent(
            """
            import importlib.abc
            import os
            import socket
            from datetime import datetime, timezone
            from uuid import UUID

            class PoisonFinder(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path, target=None):
                    if fullname.split('.')[0] in {'openai', 'mss', 'Quartz'}:
                        raise AssertionError('forbidden import: ' + fullname)
                    return None

            class PoisonEnv(dict):
                def __getitem__(self, key):
                    raise AssertionError('environment read')
                def get(self, key, default=None):
                    raise AssertionError('environment read')
                def __iter__(self):
                    raise AssertionError('environment enumeration')

            import sys
            sys.meta_path.insert(0, PoisonFinder())
            os.environ = PoisonEnv()
            os.getenv = lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError('getenv read')
            )
            socket.socket = lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError('socket creation')
            )
            socket.getaddrinfo = lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError('DNS lookup')
            )

            from snapquiz.config.profiles import (
                GLM_PIPELINE_PROFILE_ID,
                build_builtin_registry,
            )
            from snapquiz.domain.capture import CaptureConstraints, CaptureScopeKind
            from snapquiz.domain.digest import Digest256
            from snapquiz.domain.intent import (
                SOLVE_INTENT_SCHEMA_VERSION,
                OutputTokenLimit,
                SolveIntent,
            )
            from snapquiz.domain.solve import SOLVE_RESULT_SCHEMA_VERSION
            from snapquiz.privacy.consent import (
                ConsentLedger,
                PrivacyGate,
                UnknownPolicyDimension,
            )
            from snapquiz.routing.planner import RoutePlanner

            intent = SolveIntent(
                schema_version=SOLVE_INTENT_SCHEMA_VERSION,
                request_id=UUID('00000000-0000-0000-0000-000000000001'),
                pipeline_profile_id=GLM_PIPELINE_PROFILE_ID,
                capture_scope_preference=CaptureScopeKind.SELECTED_REGION,
                locale='zh-CN',
                timeout_budget_ms=30_000,
                max_output_tokens=OutputTokenLimit.PROFILE_DEFAULT,
                requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
            )
            planned = RoutePlanner().plan(
                intent=intent,
                registry=build_builtin_registry(),
                trusted_capture_constraints=CaptureConstraints(
                    allowed_display_ids=('display-1',),
                    display_topology_revision=Digest256('7' * 64),
                    max_width_px=2_000,
                    max_height_px=2_000,
                    max_pixels=4_000_000,
                    max_bytes=5_242_880,
                ),
                now=datetime(2026, 8, 29, tzinfo=timezone.utc),
            )
            planned.validate_integrity()
            ledger = ConsentLedger()
            grant = ledger.issue_for_plan(
                planned=planned,
                binding_id=planned.plan.stages[0].binding_id,
                grant_id=UUID('00000000-0000-0000-0000-000000000099'),
                request_id=None,
                capture_scope_fingerprint=None,
                issued_at=datetime(2026, 8, 29, tzinfo=timezone.utc),
                expires_at=None,
                one_shot=False,
                confirmed_unknown_policies=(
                    UnknownPolicyDimension.COST,
                    UnknownPolicyDimension.DATA,
                    UnknownPolicyDimension.PROCESSING_REGION,
                    UnknownPolicyDimension.RETENTION,
                ),
            )
            authorization = PrivacyGate().authorize(
                planned=planned,
                ledger=ledger,
                consent_grant_ids=(grant.grant_id,),
                now=datetime(2026, 8, 29, tzinfo=timezone.utc),
            )
            PrivacyGate().validate_authorization(
                planned=planned,
                authorization=authorization,
                ledger=ledger,
                now=datetime(2026, 8, 29, tzinfo=timezone.utc),
            )
            """
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


class ConsentAuthorizationContractTest(unittest.TestCase):
    def test_w05_identifier_and_digest_golden_vector(self):
        planned = _planned()
        ledger, grant = _issue(planned)
        authorization = PrivacyGate().authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        operation = planned.plan.stages[0].network_operations[0]
        consent_operation = ConsentNetworkOperation.from_plan_operation(
            operation
        )

        self.assertEqual(
            str(planned.plan.plan_id),
            "20e1e5e8-be58-5885-8ec3-11f106ffdddb",
        )
        self.assertEqual(
            str(planned.plan.stages[0].stage_id),
            "6a50fd6f-7fba-5584-9c6f-dd9b00bfa5e5",
        )
        self.assertEqual(
            str(operation.operation_id),
            "d95911bb-d4c4-5470-a601-93e01d7bde9c",
        )
        self.assertEqual(
            str(planned.plan.plan_digest),
            "58498029ed338f32149f5ffc98f63d679228cce6fdbd886b759609f2314183f8",
        )
        self.assertEqual(
            str(planned.planned_execution_digest),
            "79768471d7973c4819ae904831e066c0c95bf47411358d8152cfaf02ab4a1a1f",
        )
        self.assertEqual(
            str(consent_operation.contract_digest()),
            "f5466fbf090e1cd245689fa3783e51316c60e6e473b350c6f218c02fd2018e96",
        )
        self.assertEqual(
            str(grant.grant_terms_digest),
            "0488f1de1d5a72fa2267d1f5d39720d563216ba13d3556460b3aa5eb0960d244",
        )
        self.assertEqual(
            str(grant.grant_digest),
            "057591c84c46d19d4cb3785ecc23b666dda8f75b6a3453251af2e0ec976f97b5",
        )
        self.assertEqual(
            str(authorization.authorization_id),
            "14399e4e-e898-5a3b-88de-378b0f1fe52a",
        )
        self.assertEqual(
            str(authorization.authorization_digest),
            "19965376b15db70ba069316bae0c42ab0209635ee60f4c81a83b08486d144864",
        )

    def test_exact_unknown_confirmations_issue_and_authorize(self):
        planned = _planned()
        ledger, grant = _issue(planned)
        gate = PrivacyGate()
        authorization = gate.authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        self.assertEqual(authorization.plan_id, planned.plan.plan_id)
        self.assertEqual(authorization.plan_digest, planned.plan.plan_digest)
        self.assertEqual(
            authorization.planned_execution_digest,
            planned.planned_execution_digest,
        )
        self.assertEqual(authorization.consent_grant_ids, (grant.grant_id,))
        self.assertEqual(
            authorization.consent_grant_digests, (grant.grant_digest,)
        )
        self.assertEqual(authorization.valid_until, grant.expires_at)
        gate.validate_authorization(
            planned=planned,
            authorization=authorization,
            ledger=ledger,
            now=NOW + timedelta(seconds=1),
        )

    def test_all_unknown_confirmation_subsets_fail_except_exact_four(self):
        planned = _planned()
        dimensions = tuple(UnknownPolicyDimension)
        for size in range(len(dimensions) + 1):
            for subset in itertools.combinations(dimensions, size):
                canonical_subset = tuple(
                    sorted(subset, key=lambda item: item.value)
                )
                ledger = ConsentLedger()
                if canonical_subset == ALL_UNKNOWN_CONFIRMATIONS:
                    _issue(
                        planned,
                        ledger=ledger,
                        confirmations=canonical_subset,
                    )
                    self.assertEqual(ledger.safe_metadata()["grant_count"], 1)
                else:
                    with self.assertRaises(ValueError):
                        _issue(
                            planned,
                            ledger=ledger,
                            confirmations=canonical_subset,
                        )
                    self.assertEqual(ledger.safe_metadata()["grant_count"], 0)

    def test_duplicate_raw_and_extra_unknown_confirmations_are_rejected(self):
        planned = _planned()
        invalid_values = (
            (
                UnknownPolicyDimension.COST,
                UnknownPolicyDimension.COST,
                UnknownPolicyDimension.DATA,
                UnknownPolicyDimension.RETENTION,
            ),
            ("cost", "data", "retention"),
        )
        for value in invalid_values:
            ledger = ConsentLedger()
            with self.subTest(value=value), self.assertRaises(ValueError):
                _issue(
                    planned,
                    ledger=ledger,
                    confirmations=value,  # type: ignore[arg-type]
                )
            self.assertEqual(ledger.safe_metadata()["grant_count"], 0)

        known = _known_policy("known")
        known_plan = _planned(
            registry=_registry_with_policies(
                processing_region="test-region",
                retention_policy=known,
                data_policy=known,
                cost_policy=known,
            )
        )
        with self.assertRaises(ValueError):
            _issue(
                known_plan,
                confirmations=(UnknownPolicyDimension.COST,),
            )
        _, exact = _issue(known_plan, confirmations=())
        self.assertEqual(exact.confirmed_unknown_policies, ())

        unknown_region_plan = _planned(
            registry=_registry_with_policies(
                retention_policy=known,
                data_policy=known,
                cost_policy=known,
            )
        )
        _, region_only = _issue(
            unknown_region_plan,
            confirmations=(UnknownPolicyDimension.PROCESSING_REGION,),
        )
        self.assertEqual(
            region_only.confirmed_unknown_policies,
            (UnknownPolicyDimension.PROCESSING_REGION,),
        )

    def test_each_unknown_dimension_requires_its_exact_confirmation(self):
        known = _known_policy("single-dimension")
        base = {
            "processing_region": "test-region",
            "retention_policy": known,
            "data_policy": known,
            "cost_policy": known,
        }
        overrides = {
            UnknownPolicyDimension.PROCESSING_REGION: {
                "processing_region": ContractMarker.UNKNOWN,
            },
            UnknownPolicyDimension.RETENTION: {
                "retention_policy": ContractMarker.UNKNOWN,
            },
            UnknownPolicyDimension.DATA: {
                "data_policy": ContractMarker.UNKNOWN,
            },
            UnknownPolicyDimension.COST: {
                "cost_policy": ContractMarker.UNKNOWN,
            },
        }
        for dimension, override in overrides.items():
            with self.subTest(dimension=dimension.value):
                planned = _planned(
                    registry=_registry_with_policies(
                        **{**base, **override},
                    )
                )
                with self.assertRaises(ValueError):
                    _issue(planned, confirmations=())
                _, grant = _issue(planned, confirmations=(dimension,))
                self.assertEqual(
                    grant.confirmed_unknown_policies,
                    (dimension,),
                )

    def test_grant_expiry_boundary_is_half_open(self):
        planned = _planned()
        expiry = NOW + timedelta(seconds=1)
        ledger, grant = _issue(planned, expires_at=expiry)
        gate = PrivacyGate()
        authorization = gate.authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=expiry - timedelta(microseconds=1),
        )
        self.assertEqual(authorization.valid_until, expiry)
        with self.assertRaises(EndpointPolicyError):
            gate.validate_authorization(
                planned=planned,
                authorization=authorization,
                ledger=ledger,
                now=expiry,
            )
        with self.assertRaises(EndpointPolicyError):
            gate.authorize(
                planned=planned,
                ledger=ledger,
                consent_grant_ids=(grant.grant_id,),
                now=expiry,
            )

    def test_future_issue_request_mismatch_and_missing_grant_fail(self):
        planned = _planned()
        future_ledger, future_grant = _issue(
            planned,
            issued_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(days=1),
        )
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().authorize(
                planned=planned,
                ledger=future_ledger,
                consent_grant_ids=(future_grant.grant_id,),
                now=NOW,
            )
        mismatch_ledger = ConsentLedger()
        with self.assertRaises(EndpointPolicyError):
            _issue(
                planned,
                ledger=mismatch_ledger,
                request_id=UUID(
                    "00000000-0000-0000-0000-000000000002"
                ),
            )
        self.assertEqual(mismatch_ledger.safe_metadata()["grant_count"], 0)
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().authorize(
                planned=planned,
                ledger=ConsentLedger(),
                consent_grant_ids=(GRANT_ID,),
                now=NOW,
            )

    def test_revocation_changes_grant_revision_and_invalidates_context(self):
        planned = _planned()
        ledger, grant = _issue(planned)
        gate = PrivacyGate()
        authorization = gate.authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        revoked = ledger.revoke(
            grant_id=grant.grant_id,
            revoked_at=NOW + timedelta(seconds=1),
        )
        self.assertNotEqual(grant.grant_digest, revoked.grant_digest)
        with self.assertRaises(EndpointPolicyError):
            gate.validate_authorization(
                planned=planned,
                authorization=authorization,
                ledger=ledger,
                now=NOW + timedelta(seconds=2),
            )

    def test_duplicate_grant_id_cannot_replace_terms(self):
        planned = _planned()
        ledger, original = _issue(planned)
        with self.assertRaises(EndpointPolicyError):
            _issue(planned, ledger=ledger)
        current = ledger.snapshot_for_ids((GRANT_ID,))[0]
        self.assertIs(current, original)
        self.assertEqual(ledger.safe_metadata()["grant_count"], 1)

    def test_ledger_detects_same_id_terms_rebinding_even_with_recomputed_digests(self):
        planned = _planned()
        ledger, grant = _issue(planned)
        object.__setattr__(grant, "processing_region", "rebound-region")
        object.__setattr__(
            grant,
            "grant_terms_digest",
            grant.recompute_terms_digest(),
        )
        object.__setattr__(grant, "grant_digest", grant.recompute_digest())
        with self.assertRaises(EndpointPolicyError):
            ledger.snapshot_for_ids((grant.grant_id,))

    def test_ledger_detects_returned_status_revision_rollback(self):
        planned = _planned()
        for transition in ("revoke", "consume"):
            with self.subTest(transition=transition):
                ledger, grant = _issue(
                    planned,
                    one_shot=transition == "consume",
                )
                authorization = PrivacyGate().authorize(
                    planned=planned,
                    ledger=ledger,
                    consent_grant_ids=(grant.grant_id,),
                    now=NOW,
                )
                changed_at = NOW + timedelta(seconds=1)
                if transition == "revoke":
                    current = ledger.revoke(
                        grant_id=grant.grant_id,
                        revoked_at=changed_at,
                    )
                    object.__setattr__(current, "revoked_at", None)
                else:
                    current = ledger.consume(
                        grant_id=grant.grant_id,
                        consumed_at=changed_at,
                    )
                    object.__setattr__(current, "consumed_at", None)
                object.__setattr__(
                    current,
                    "grant_digest",
                    current.recompute_digest(),
                )
                current.validate_integrity()

                with self.assertRaises(EndpointPolicyError):
                    ledger.snapshot_for_ids((grant.grant_id,))
                with self.assertRaises(EndpointPolicyError):
                    PrivacyGate().validate_authorization(
                        planned=planned,
                        authorization=authorization,
                        ledger=ledger,
                        now=NOW + timedelta(seconds=2),
                    )

    def test_grant_object_cannot_alias_another_ledger_entry(self):
        planned = _planned()
        ledger, grant_a = _issue(planned)
        grant_b_id = UUID("00000000-0000-0000-0000-000000000098")
        _, grant_b = _issue(
            planned,
            ledger=ledger,
            grant_id=grant_b_id,
        )
        object.__setattr__(grant_a, "grant_id", grant_b.grant_id)
        object.__setattr__(
            grant_a,
            "grant_terms_digest",
            grant_a.recompute_terms_digest(),
        )
        object.__setattr__(
            grant_a,
            "grant_digest",
            grant_a.recompute_digest(),
        )
        grant_a.validate_integrity()

        with self.assertRaises(EndpointPolicyError):
            ledger.snapshot_for_ids((GRANT_ID,))
        self.assertIs(ledger.snapshot_for_ids((grant_b_id,))[0], grant_b)

    def test_one_shot_concurrent_consume_has_one_winner(self):
        planned = _planned()
        ledger, grant = _issue(planned, one_shot=True)
        gate = PrivacyGate()
        authorization = gate.authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        barrier = Barrier(3)
        outcomes: list[str] = []

        def consume() -> None:
            barrier.wait()
            try:
                ledger.consume(
                    grant_id=grant.grant_id,
                    consumed_at=NOW + timedelta(seconds=1),
                )
            except EndpointPolicyError:
                outcomes.append("rejected")
            else:
                outcomes.append("consumed")

        threads = (Thread(target=consume), Thread(target=consume))
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertCountEqual(outcomes, ("consumed", "rejected"))
        with self.assertRaises(EndpointPolicyError):
            gate.validate_authorization(
                planned=planned,
                authorization=authorization,
                ledger=ledger,
                now=NOW + timedelta(seconds=2),
            )

    def test_hint_grant_can_cover_narrower_plan_but_not_reverse(self):
        hint_plan = _planned(intent=_intent(user_hint="private"))
        image_plan = _planned(intent=_intent(user_hint=None))
        hint_ledger, hint_grant = _issue(hint_plan)
        PrivacyGate().authorize(
            planned=image_plan,
            ledger=hint_ledger,
            consent_grant_ids=(hint_grant.grant_id,),
            now=NOW,
        )

        image_ledger, image_grant = _issue(image_plan)
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().authorize(
                planned=hint_plan,
                ledger=image_ledger,
                consent_grant_ids=(image_grant.grant_id,),
                now=NOW,
            )

    def test_unselected_ledger_grant_is_harmless_but_selected_extra_fails(self):
        planned = _planned()
        ledger, first = _issue(planned)
        _, second = _issue(
            planned,
            ledger=ledger,
            grant_id=UUID("00000000-0000-0000-0000-000000000100"),
        )
        PrivacyGate().authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(first.grant_id,),
            now=NOW,
        )
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().authorize(
                planned=planned,
                ledger=ledger,
                consent_grant_ids=tuple(
                    sorted((first.grant_id, second.grant_id), key=str)
                ),
                now=NOW,
            )

    def test_fingerprint_is_bound_to_grant_but_deferred_to_egress(self):
        planned = _planned()
        fingerprint = _digest("f")
        ledger, grant = _issue(planned, fingerprint=fingerprint)
        authorization = PrivacyGate().authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        self.assertEqual(grant.capture_scope_fingerprint, fingerprint)
        self.assertEqual(
            authorization.consent_grant_digests, (grant.grant_digest,)
        )

    def test_old_context_cannot_authorize_new_registry_generation(self):
        planned_a = _planned()
        planned_b = _planned(registry=_same_profiles_new_generation())
        ledger, grant = _issue(planned_a)
        authorization = PrivacyGate().authorize(
            planned=planned_a,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().validate_authorization(
                planned=planned_b,
                authorization=authorization,
                ledger=ledger,
                now=NOW + timedelta(seconds=1),
            )

    def test_grant_and_authorization_tamper_and_generic_serialization_fail(self):
        planned = _planned()
        ledger, grant = _issue(planned)
        authorization = PrivacyGate().authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        with self.assertRaises(TypeError):
            ConsentGrant(  # type: ignore[call-arg]
                grant_id=grant.grant_id,
            )
        with self.assertRaises(TypeError):
            AuthorizationContext(  # type: ignore[call-arg]
                authorization_id=authorization.authorization_id,
            )
        with self.assertRaises(TypeError):
            asdict(grant)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            asdict(authorization)  # type: ignore[arg-type]
        object.__setattr__(authorization, "plan_digest", _digest("a"))
        with self.assertRaises(ValueError):
            authorization.validate_integrity()

    def test_recomputed_digest_cannot_alias_authorization_id(self):
        planned = _planned()
        ledger, grant = _issue(planned)
        gate = PrivacyGate()
        authorization = gate.authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        object.__setattr__(
            authorization,
            "authorization_id",
            UUID("00000000-0000-0000-0000-000000000123"),
        )
        object.__setattr__(
            authorization,
            "authorization_digest",
            authorization.recompute_digest(),
        )
        with self.assertRaises(ValueError):
            authorization.validate_integrity()
        with self.assertRaises(EndpointPolicyError):
            gate.validate_authorization(
                planned=planned,
                authorization=authorization,
                ledger=ledger,
                now=NOW,
            )

    def test_privacy_gate_normalizes_integrity_failures(self):
        planned = _planned()
        ledger, grant = _issue(planned)
        authorization = PrivacyGate().authorize(
            planned=planned,
            ledger=ledger,
            consent_grant_ids=(grant.grant_id,),
            now=NOW,
        )
        object.__setattr__(planned, "planned_execution_digest", _digest("a"))
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().validate_authorization(
                planned=planned,
                authorization=authorization,
                ledger=ledger,
                now=NOW,
            )

        malformed_plan = _planned()
        malformed_ledger, malformed_grant = _issue(malformed_plan)
        object.__setattr__(malformed_plan, "resolved_pipeline", None)
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().authorize(
                planned=malformed_plan,
                ledger=malformed_ledger,
                consent_grant_ids=(malformed_grant.grant_id,),
                now=NOW,
            )

        grant_plan = _planned()
        grant_ledger, malformed_grant = _issue(grant_plan)
        object.__setattr__(malformed_grant, "allowed_network_operations", None)
        with self.assertRaises(EndpointPolicyError):
            grant_ledger.snapshot_for_ids((malformed_grant.grant_id,))


if __name__ == "__main__":
    unittest.main()
