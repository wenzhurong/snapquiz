import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timedelta, timezone
from uuid import UUID

from snapquiz.domain.capture import CaptureConstraints, CaptureScopeKind
from snapquiz.domain.digest import CANONICAL_SERIALIZER_VERSION, Digest256
from snapquiz.domain.intent import (
    SOLVE_INTENT_SCHEMA_VERSION,
    OutputTokenLimit,
    SolveIntent,
)
from snapquiz.domain.outbound import (
    NonSecretHeader,
    PreparedOutbound,
    validate_prepared_outbound_against_plan,
)
from snapquiz.domain.plan import (
    CanonicalQueryPolicy,
    ComputeLocation,
    ContractMarker,
    CredentialInjectionSlot,
    ExecutionPlan,
    ExecutionPlanNetworkOperation,
    ExecutionPlanStage,
    NetworkOperationPurpose,
    NetworkScope,
    OutboundDataKind,
    QueryPolicyKind,
    RequiredConsentScope,
    validate_phase1_remote_direct_plan,
)
from snapquiz.domain.policy import PolicySnapshot
from snapquiz.domain.solve import PipelineKind, SOLVE_RESULT_SCHEMA_VERSION, StageRole


def _digest(char: str) -> Digest256:
    return Digest256(char * 64)


def _policy(*, content_digest: Digest256 = _digest("1")) -> PolicySnapshot:
    verified = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
    return PolicySnapshot(
        ref="policy://provider/data/v1",
        content_digest=content_digest,
        verified_at=verified,
        expires_at=verified + timedelta(days=30),
    )


def _remote_direct_plan(
    *,
    policy: PolicySnapshot | None = None,
    purpose: NetworkOperationPurpose = NetworkOperationPurpose.INFERENCE,
    capture_scope_kind: CaptureScopeKind = CaptureScopeKind.SELECTED_REGION,
    preview_required: bool = True,
    operation_ids: tuple[UUID, ...] | None = None,
) -> ExecutionPlan:
    selected_policy = policy or _policy()
    operation_id = UUID("00000000-0000-0000-0000-000000000303")
    operation = ExecutionPlanNetworkOperation(
        operation_id=operation_id,
        purpose=purpose,
        http_method="POST",
        canonical_endpoint="https://api.example.test:443/v1/chat/completions",
        canonical_query_policy=CanonicalQueryPolicy(kind=QueryPolicyKind.EMPTY),
        content_type="application/json",
        allowed_non_secret_headers=("accept", "x-client-version"),
        credential_injection_slot=CredentialInjectionSlot.AUTHORIZATION_HEADER,
        outbound_data=(OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT),
        retention_policy=selected_policy,
        data_policy=ContractMarker.UNKNOWN,
        billable=True,
    )
    stage = ExecutionPlanStage(
        stage_id=UUID("00000000-0000-0000-0000-000000000202"),
        role=StageRole.SOLVER,
        binding_id="binding.glm.test",
        provider_profile_id="profile.glm.test",
        provider_profile_digest=_digest("2"),
        provider_id="zhipu",
        model_id="glm-4v-test",
        component_id=None,
        component_version=None,
        adapter_family="openai_chat_compatible",
        adapter_version="adapter.v1",
        capabilities_ref="capabilities://glm/test/v1",
        capabilities_digest=_digest("3"),
        endpoint_policy_version="endpoint.v1",
        network_policy_version="network.v1",
        tls_policy_ref="tls://system/v1",
        credential_binding_ref="credential://glm/test",
        credential_binding_digest=_digest("4"),
        network_scope=NetworkScope.INTERNET,
        compute_location=ComputeLocation.REMOTE,
        processing_region="cn",
        max_attempts_per_operation=2,
        network_operations=(operation,),
    )
    consent = RequiredConsentScope(
        binding_id=stage.binding_id,
        provider_profile_id=stage.provider_profile_id,
        provider_profile_digest=stage.provider_profile_digest,
        network_scope=stage.network_scope,
        compute_location=stage.compute_location,
        processing_region=stage.processing_region,
        retention_policy=selected_policy,
        data_policy=ContractMarker.UNKNOWN,
        cost_policy=ContractMarker.UNKNOWN,
        network_operation_ids=operation_ids or (operation_id,),
    )
    return ExecutionPlan(
        plan_id=UUID("00000000-0000-0000-0000-000000000101"),
        request_id=UUID("00000000-0000-0000-0000-000000000001"),
        pipeline_profile_id="pipeline.glm.direct.test",
        pipeline_profile_digest=_digest("5"),
        pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
        prompt_policy_digest=_digest("6"),
        result_validator_version="solve-result-validator.v1",
        image_preprocessing_policy_version="image-policy.v1",
        capture_scope_kind=capture_scope_kind,
        capture_constraints=CaptureConstraints(
            allowed_display_ids=("display-1",),
            display_topology_revision=_digest("7"),
            max_width_px=2_000,
            max_height_px=2_000,
            max_pixels=4_000_000,
            max_bytes=5_000_000,
            allow_full_screen=capture_scope_kind is CaptureScopeKind.FULL_SCREEN,
        ),
        preview_required=preview_required,
        required_consent_scopes=(consent,),
        stages=(stage,),
        requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
        max_output_tokens=512,
        timeout_budget_ms=30_000,
        max_network_calls_total=2,
        max_billable_calls=2,
        cost_policy=ContractMarker.UNKNOWN,
        fallback_branches=(),
        canonical_serializer_version=CANONICAL_SERIALIZER_VERSION,
    )


def _prepared(
    plan: ExecutionPlan,
    *,
    body: bytes | None = None,
    canonical_url: str = "https://api.example.test:443/v1/chat/completions",
) -> PreparedOutbound:
    return PreparedOutbound(
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        stage_id=plan.stages[0].stage_id,
        operation_id=plan.stages[0].network_operations[0].operation_id,
        source_ids=(UUID("00000000-0000-0000-0000-000000000404"),),
        source_digests=(_digest("8"),),
        capture_scope_fingerprint=_digest("9"),
        http_method="POST",
        canonical_url=canonical_url,
        content_type="application/json",
        non_secret_headers=(
            NonSecretHeader(
                lowercase_name="accept", normalized_value="application/json"
            ),
            NonSecretHeader(
                lowercase_name="x-client-version", normalized_value="snapquiz-test"
            ),
        ),
        credential_binding_digest=_digest("4"),
        outbound_data=(OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT),
        body=(
            body
            if body is not None
            else '{"hint":"不要泄露","model":"glm-4v-test"}'.encode("utf-8")
        ),
    )


class PolicyAndIntentContractTest(unittest.TestCase):
    def test_policy_snapshot_is_immutable_and_timezone_bound(self):
        policy = _policy()
        with self.assertRaises(FrozenInstanceError):
            policy.ref = "policy://changed"  # type: ignore[misc]
        with self.assertRaises(ValueError):
            PolicySnapshot(
                ref="policy://bad",
                content_digest=_digest("1"),
                verified_at=datetime(2026, 8, 28),
                expires_at=None,
            )

    def test_intent_is_strict_and_repr_hides_user_hint(self):
        hint = "private study hint"
        intent = SolveIntent(
            schema_version=SOLVE_INTENT_SCHEMA_VERSION,
            request_id=UUID("00000000-0000-0000-0000-000000000001"),
            pipeline_profile_id="pipeline.glm.direct.test",
            capture_scope_preference=CaptureScopeKind.SELECTED_REGION,
            locale="zh-Hans-CN",
            timeout_budget_ms=30_000,
            max_output_tokens=OutputTokenLimit.PROFILE_DEFAULT,
            requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
            user_hint=hint,
        )
        self.assertNotIn(hint, repr(intent))
        with self.assertRaises(ValueError):
            SolveIntent(
                schema_version=SOLVE_INTENT_SCHEMA_VERSION,
                request_id=intent.request_id,
                pipeline_profile_id=intent.pipeline_profile_id,
                capture_scope_preference=intent.capture_scope_preference,
                locale="zh_CN",
                timeout_budget_ms=intent.timeout_budget_ms,
                max_output_tokens=intent.max_output_tokens,
                requested_result_schema_version=intent.requested_result_schema_version,
                user_hint=hint,
            )
        with self.assertRaises(ValueError):
            SolveIntent(
                schema_version=SOLVE_INTENT_SCHEMA_VERSION,
                request_id=intent.request_id,
                pipeline_profile_id=intent.pipeline_profile_id,
                capture_scope_preference=intent.capture_scope_preference,
                locale=intent.locale,
                timeout_budget_ms=True,
                max_output_tokens=intent.max_output_tokens,
                requested_result_schema_version=intent.requested_result_schema_version,
                user_hint=hint,
            )
        with self.assertRaises(TypeError):
            asdict(intent)  # type: ignore[arg-type]


class ExecutionPlanContractTest(unittest.TestCase):
    def test_phase1_plan_golden_digest_and_nested_policy(self):
        plan = _remote_direct_plan()
        validate_phase1_remote_direct_plan(plan)
        self.assertEqual(
            plan.plan_digest,
            "8e73f9968cf300e043244cac6a41104f1c9a055324adcefb831f9e8cb6f66131",
        )
        changed_policy_plan = _remote_direct_plan(policy=_policy(content_digest=_digest("a")))
        self.assertNotEqual(plan.plan_digest, changed_policy_plan.plan_digest)

    def test_plan_digest_excludes_only_its_own_digest(self):
        plan = _remote_direct_plan()
        expected = plan.plan_digest
        object.__setattr__(plan, "plan_digest", _digest("f"))
        self.assertEqual(plan.recompute_digest(), expected)
        with self.assertRaises(ValueError):
            validate_phase1_remote_direct_plan(plan)

    def test_phase1_rejects_full_screen_non_inference_and_no_preview(self):
        for plan in (
            _remote_direct_plan(capture_scope_kind=CaptureScopeKind.FULL_SCREEN),
            _remote_direct_plan(purpose=NetworkOperationPurpose.UPLOAD),
            _remote_direct_plan(preview_required=False),
        ):
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                validate_phase1_remote_direct_plan(plan)

    def test_consent_must_cover_exact_operation(self):
        with self.assertRaises(ValueError):
            _remote_direct_plan(
                operation_ids=(UUID("00000000-0000-0000-0000-000000000999"),)
            )

    def test_plan_is_deeply_immutable(self):
        plan = _remote_direct_plan()
        rendered = repr(plan)
        for full_digest in (
            plan.plan_digest,
            plan.pipeline_profile_digest,
            plan.prompt_policy_digest,
            plan.stages[0].provider_profile_digest,
            plan.stages[0].capabilities_digest,
            plan.stages[0].credential_binding_digest,
        ):
            self.assertNotIn(str(full_digest), rendered)
        with self.assertRaises(FrozenInstanceError):
            plan.max_output_tokens = 999  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            plan.stages[0].model_id = "changed"  # type: ignore[misc]

    def test_local_verified_and_zero_network_are_bidirectional(self):
        stage = _remote_direct_plan().stages[0]
        with self.assertRaises(ValueError):
            replace(stage, compute_location=ComputeLocation.LOCAL_VERIFIED)
        with self.assertRaises(ValueError):
            replace(
                stage,
                network_scope=NetworkScope.NONE,
                network_operations=(),
                max_attempts_per_operation=0,
                tls_policy_ref=ContractMarker.NOT_APPLICABLE,
                credential_binding_ref=ContractMarker.NOT_APPLICABLE,
                credential_binding_digest=ContractMarker.NOT_APPLICABLE,
            )
        loopback_operation = replace(
            stage.network_operations[0],
            canonical_endpoint="http://127.0.0.1:8080/inference",
        )
        loopback_stage = replace(
            stage,
            compute_location=ComputeLocation.LOCAL_VERIFIED,
            network_scope=NetworkScope.LOOPBACK,
            tls_policy_ref=ContractMarker.NOT_APPLICABLE,
            network_operations=(loopback_operation,),
        )
        self.assertEqual(loopback_stage.network_scope, NetworkScope.LOOPBACK)

    def test_reserved_marker_text_cannot_collide_with_marker_semantics(self):
        plan = _remote_direct_plan()
        stage = plan.stages[0]
        operation = stage.network_operations[0]
        with self.assertRaises(ValueError):
            replace(stage, processing_region="unknown")
        with self.assertRaises(ValueError):
            replace(stage, tls_policy_ref="not_applicable")
        with self.assertRaises(ValueError):
            replace(operation, retention_policy="unknown")

    def test_plan_header_allowlist_rejects_credential_names(self):
        operation = _remote_direct_plan().stages[0].network_operations[0]
        with self.assertRaises(ValueError):
            replace(operation, allowed_non_secret_headers=("authorization",))

    def test_budgets_cover_each_planned_operation_once(self):
        plan = _remote_direct_plan()
        stage = plan.stages[0]
        first_operation = stage.network_operations[0]
        second_operation = replace(
            first_operation,
            operation_id=UUID("00000000-0000-0000-0000-000000000304"),
        )
        two_operation_stage = replace(
            stage, network_operations=(first_operation, second_operation)
        )
        consent = replace(
            plan.required_consent_scopes[0],
            network_operation_ids=(
                first_operation.operation_id,
                second_operation.operation_id,
            ),
        )
        valid_two_operation_plan = replace(
            plan,
            stages=(two_operation_stage,),
            required_consent_scopes=(consent,),
            max_network_calls_total=2,
            max_billable_calls=2,
        )
        with self.assertRaises(ValueError):
            replace(valid_two_operation_plan, max_network_calls_total=1)
        with self.assertRaises(ValueError):
            replace(valid_two_operation_plan, max_billable_calls=1)

    def test_exact_query_policy_is_reserved_until_trusted_m2_profiles(self):
        with self.assertRaises(ValueError):
            CanonicalQueryPolicy(kind=QueryPolicyKind.EXACT)
        with self.assertRaises(ValueError):
            CanonicalQueryPolicy(
                kind=QueryPolicyKind.EXACT,
                exact_items=(("api-version", "2026-08-28"),),
            )
        with self.assertRaises(ValueError):
            CanonicalQueryPolicy(
                kind=QueryPolicyKind.EXACT,
                exact_items=(("api-version", "v1"), ("api-version", "v2")),
            )
        for credential_key in ("api-key", "api_key", "auth", "access-token"):
            with self.subTest(credential_key=credential_key), self.assertRaises(
                ValueError
            ):
                CanonicalQueryPolicy(
                    kind=QueryPolicyKind.EXACT,
                    exact_items=((credential_key, "must-not-enter-a-plan"),),
                )

    def test_endpoint_requires_exact_canonical_spelling(self):
        operation = _remote_direct_plan().stages[0].network_operations[0]
        malformed = (
            "https://API.EXAMPLE.TEST:443/v1/chat/completions",
            "https://api.example.test:0443/v1/chat/completions",
            "https://api.example.test.:443/v1/chat/completions",
            "https://api.example.test:443/v1/../admin",
            "https://api.example.test:443/v1/%63hat/completions",
            "https://api.example.test:443/v1/%2fadmin",
            "https://api.example.test:443/v1/%C0%AE%C0%AE/admin",
            "https://api.example.test:443/v1/%00/admin",
            "https://api.example.test:443/v1/%ED%A0%80/admin",
        )
        for endpoint in malformed:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                replace(operation, canonical_endpoint=endpoint)
        encoded_unicode = replace(
            operation,
            canonical_endpoint="https://api.example.test:443/v1/%C3%A9",
        )
        self.assertEqual(
            encoded_unicode.canonical_endpoint,
            "https://api.example.test:443/v1/%C3%A9",
        )

    def test_network_scope_rejects_mislabeled_literal_and_localhost_targets(self):
        stage = _remote_direct_plan().stages[0]
        cases = (
            (NetworkScope.INTERNET, "https://localhost:443/v1/chat/completions"),
            (NetworkScope.INTERNET, "https://foo.localhost:443/v1/chat/completions"),
            (NetworkScope.INTERNET, "https://127.0.0.1:443/v1/chat/completions"),
            (NetworkScope.INTERNET, "https://192.168.1.20:443/v1/chat/completions"),
            (NetworkScope.INTERNET, "https://[::1]:443/v1/chat/completions"),
            (NetworkScope.INTERNET, "https://224.0.0.1:443/v1/chat/completions"),
            (NetworkScope.INTERNET, "https://[ff02::1]:443/v1/chat/completions"),
            (NetworkScope.LAN, "https://localhost:443/v1/chat/completions"),
            (NetworkScope.LAN, "https://8.8.8.8:443/v1/chat/completions"),
            (NetworkScope.LAN, "https://0.0.0.0:443/v1/chat/completions"),
            (NetworkScope.LAN, "https://224.0.0.1:443/v1/chat/completions"),
        )
        for network_scope, endpoint in cases:
            operation = replace(stage.network_operations[0], canonical_endpoint=endpoint)
            with self.subTest(
                network_scope=network_scope, endpoint=endpoint
            ), self.assertRaises(ValueError):
                replace(
                    stage,
                    network_scope=network_scope,
                    network_operations=(operation,),
                )

    def test_literal_scope_classifier_accepts_explicit_lan_and_global_unicast(self):
        stage = _remote_direct_plan().stages[0]
        for network_scope, endpoint in (
            (NetworkScope.LAN, "https://192.168.1.20:443/v1/chat/completions"),
            (NetworkScope.INTERNET, "https://8.8.8.8:443/v1/chat/completions"),
            (
                NetworkScope.INTERNET,
                "https://[2606:4700:4700::1111]:443/v1/chat/completions",
            ),
        ):
            operation = replace(stage.network_operations[0], canonical_endpoint=endpoint)
            scoped_stage = replace(
                stage,
                network_scope=network_scope,
                network_operations=(operation,),
            )
            self.assertEqual(scoped_stage.network_scope, network_scope)

    def test_plan_rejects_overridable_operation_subclasses(self):
        with self.assertRaises(TypeError):
            class EvilOperation(ExecutionPlanNetworkOperation):
                pass


class PreparedOutboundContractTest(unittest.TestCase):
    def test_golden_digests_and_plan_binding(self):
        plan = _remote_direct_plan()
        prepared = _prepared(plan)
        validate_prepared_outbound_against_plan(prepared, plan)
        self.assertEqual(prepared.payload_byte_size, 45)
        self.assertEqual(
            prepared.body_digest,
            "d543f11966ec87c4f08f69976e8032dd5f92aba02d87856c5425a473e1ab0074",
        )
        self.assertEqual(
            prepared.non_secret_headers_digest,
            "34ea245889d9c5e3e783bd465be29155151b3c5a60839c6a7881cc9b1b6a920e",
        )
        self.assertEqual(
            prepared.request_envelope_digest,
            "03ff606c3ecea8ef0361004fedeecd566f56f9f672cfaad1a093d50686ba9292",
        )

    def test_repr_hides_body_header_values_and_full_digests(self):
        prepared = _prepared(_remote_direct_plan())
        rendered = repr(prepared)
        self.assertNotIn("不要泄露", rendered)
        self.assertNotIn("snapquiz-test", rendered)
        for full_digest in (
            prepared.plan_digest,
            prepared.source_digests[0],
            prepared.capture_scope_fingerprint,
            prepared.credential_binding_digest,
            prepared.body_digest,
            prepared.non_secret_headers_digest,
            prepared.request_envelope_digest,
        ):
            self.assertNotIn(str(full_digest), rendered)
        safe_metadata = prepared.safe_metadata()
        self.assertNotIn("body", safe_metadata)
        self.assertNotIn("non_secret_headers", safe_metadata)
        self.assertEqual(len(safe_metadata["plan_digest_prefix"]), 12)
        self.assertEqual(len(safe_metadata["request_envelope_digest_prefix"]), 12)
        with self.assertRaises(TypeError):
            asdict(prepared)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            asdict(prepared.non_secret_headers[0])  # type: ignore[arg-type]
        with self.assertRaises(AttributeError):
            prepared.body = b"changed"  # type: ignore[misc]

    def test_body_tampering_invalidates_prepared_outbound(self):
        plan = _remote_direct_plan()
        prepared = _prepared(plan)
        object.__setattr__(prepared, "body", b'{"changed":true}')
        with self.assertRaises(ValueError):
            prepared.validate_integrity()
        with self.assertRaises(ValueError):
            validate_prepared_outbound_against_plan(prepared, plan)

    def test_envelope_changes_when_body_changes(self):
        plan = _remote_direct_plan()
        first = _prepared(plan, body=b'{"value":1}')
        second = _prepared(plan, body=b'{"value":2}')
        self.assertNotEqual(first.body_digest, second.body_digest)
        self.assertNotEqual(
            first.request_envelope_digest, second.request_envelope_digest
        )

    def test_credential_like_headers_are_not_non_secret(self):
        for name in (
            "authorization",
            "content-length",
            "content-type",
            "cookie",
            "host",
            "x-api-key",
            "x_api_key",
            "x-provider-token",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                NonSecretHeader(lowercase_name=name, normalized_value="redacted")

    def test_unplanned_header_is_rejected_by_plan_binding(self):
        plan = _remote_direct_plan()
        base = _prepared(plan)
        prepared = PreparedOutbound(
            plan_id=base.plan_id,
            plan_digest=base.plan_digest,
            stage_id=base.stage_id,
            operation_id=base.operation_id,
            source_ids=base.source_ids,
            source_digests=base.source_digests,
            capture_scope_fingerprint=base.capture_scope_fingerprint,
            http_method=base.http_method,
            canonical_url=base.canonical_url,
            content_type=base.content_type,
            non_secret_headers=(
                NonSecretHeader(lowercase_name="x-extra", normalized_value="metadata"),
            ),
            credential_binding_digest=base.credential_binding_digest,
            outbound_data=base.outbound_data,
            body=base.body,
        )
        with self.assertRaises(ValueError):
            validate_prepared_outbound_against_plan(prepared, plan)

    def test_prepared_query_is_disabled_until_m2_endpoint_profiles(self):
        plan = _remote_direct_plan()
        with self.assertRaises(ValueError):
            _prepared(
                plan,
                canonical_url=(
                    "https://api.example.test:443/v1/chat/completions"
                    "?api-version=2026-08-28"
                ),
            )

    def test_prepared_and_header_subclasses_fail_closed(self):
        with self.assertRaises(TypeError):
            class EvilPrepared(PreparedOutbound):
                pass

        with self.assertRaises(TypeError):
            class EvilHeader(NonSecretHeader):
                pass


if __name__ == "__main__":
    unittest.main()
