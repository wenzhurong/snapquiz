import copy
import unittest
from dataclasses import asdict
from datetime import timedelta

from snapquiz.config.legacy_glm import (
    LegacyGlmMappingError,
    map_legacy_glm_profile,
)
from snapquiz.config.profiles import (
    BUILTIN_REGISTRY_PUBLISHED_AT,
    BUILTIN_REGISTRY_REVISION,
    GLM_ADAPTER_FAMILY,
    GLM_ADAPTER_VERSION,
    GLM_ALLOWED_BASE_PATH,
    GLM_ALLOWED_ORIGIN,
    GLM_BINDING_ID,
    GLM_CAPABILITIES_REF,
    GLM_CHAT_COMPLETIONS_ENDPOINT,
    GLM_CREDENTIAL_BINDING_REF,
    GLM_CREDENTIAL_REF,
    GLM_ENDPOINT_POLICY_VERSION,
    GLM_LEGACY_BASE_URL,
    GLM_MODEL_ID,
    GLM_NETWORK_POLICY_VERSION,
    GLM_PIPELINE_PROFILE_ID,
    GLM_PROVIDER_ID,
    GLM_PROVIDER_PROFILE_ID,
    GLM_TLS_POLICY_REF,
    build_builtin_registry,
    builtin_registry_digest,
)
from snapquiz.domain.capabilities import (
    CapabilityRole,
    CredentialValueScheme,
    ImageInputKind,
    InputModality,
    ProviderApplicationState,
    RedirectPolicy,
    StructuredOutputKind,
)
from snapquiz.domain.capture import CaptureScopeKind
from snapquiz.domain.digest import Digest256
from snapquiz.domain.plan import (
    ComputeLocation,
    CredentialInjectionSlot,
    NetworkOperationPurpose,
    NetworkScope,
    OutboundDataKind,
    QueryPolicyKind,
)
from snapquiz.domain.policy import ContractMarker
from snapquiz.domain.solve import PipelineKind, SOLVE_RESULT_SCHEMA_VERSION, StageRole
from snapquiz.routing.registry import (
    Availability,
    RegistryAuthority,
    RegistryIntegrityError,
    RegistryLookupError,
    RegistrySnapshot,
)


REGISTRY_GOLDEN_DIGEST = (
    "577f8882ea7260d8d665de1fc4484ee7675ee1983093df5c6673c921dc7c39c4"
)


class BuiltinRegistryContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = build_builtin_registry()
        self.provider = self.registry.provider_profiles[0]
        self.capabilities = self.registry.capability_snapshots[0]
        self.pipeline = self.registry.pipeline_profiles[0]
        self.endpoint = self.provider.endpoint_policy
        self.operation = self.endpoint.operation_templates[0]
        self.credential = self.provider.credential_binding
        self.binding = self.pipeline.stage_bindings[0]

    def test_builtin_registry_has_the_frozen_exact_glm_binding(self):
        self.assertEqual(self.registry.registry_revision, BUILTIN_REGISTRY_REVISION)
        self.assertEqual(self.registry.published_at, BUILTIN_REGISTRY_PUBLISHED_AT)
        self.assertIs(self.registry.authority, RegistryAuthority.BUILTIN)
        self.assertEqual(len(self.registry.provider_profiles), 1)
        self.assertEqual(len(self.registry.capability_snapshots), 1)
        self.assertEqual(len(self.registry.pipeline_profiles), 1)

        self.assertEqual(self.provider.provider_profile_id, GLM_PROVIDER_PROFILE_ID)
        self.assertEqual(self.provider.provider_id, GLM_PROVIDER_ID)
        self.assertEqual(self.provider.adapter_family, GLM_ADAPTER_FAMILY)
        self.assertEqual(self.provider.adapter_version, GLM_ADAPTER_VERSION)
        self.assertEqual(self.provider.api_version, "v4")
        self.assertIs(self.provider.network_scope, NetworkScope.INTERNET)
        self.assertIs(self.provider.compute_location, ComputeLocation.REMOTE)
        self.assertIs(self.provider.processing_region, ContractMarker.UNKNOWN)
        self.assertIs(
            self.provider.provider_application_state,
            ProviderApplicationState.UNKNOWN,
        )
        self.assertIs(self.provider.retention_policy, ContractMarker.UNKNOWN)
        self.assertIs(self.provider.data_policy, ContractMarker.UNKNOWN)
        self.assertIs(self.provider.cost_policy, ContractMarker.UNKNOWN)
        self.assertEqual(self.provider.fixed_non_secret_parameters, ())

        self.assertEqual(
            self.endpoint.endpoint_policy_version, GLM_ENDPOINT_POLICY_VERSION
        )
        self.assertEqual(self.endpoint.allowed_origins, (GLM_ALLOWED_ORIGIN,))
        self.assertEqual(self.endpoint.allowed_base_paths, (GLM_ALLOWED_BASE_PATH,))
        self.assertFalse(self.endpoint.allow_custom_endpoint)
        self.assertIs(self.endpoint.redirect_policy, RedirectPolicy.REJECT)
        self.assertEqual(
            self.endpoint.network_policy_version, GLM_NETWORK_POLICY_VERSION
        )
        self.assertEqual(self.endpoint.tls_policy_ref, GLM_TLS_POLICY_REF)
        self.assertEqual(self.operation.operation_key, "inference")
        self.assertIs(self.operation.purpose, NetworkOperationPurpose.INFERENCE)
        self.assertEqual(self.operation.http_method, "POST")
        self.assertEqual(
            self.operation.canonical_endpoint, GLM_CHAT_COMPLETIONS_ENDPOINT
        )
        self.assertIs(
            self.operation.canonical_query_policy.kind, QueryPolicyKind.EMPTY
        )
        self.assertEqual(self.operation.content_type, "application/json")
        self.assertEqual(self.operation.allowed_non_secret_headers, ())
        self.assertIs(
            self.operation.credential_injection_slot,
            CredentialInjectionSlot.AUTHORIZATION_HEADER,
        )
        self.assertEqual(
            self.operation.outbound_data,
            (OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT),
        )
        self.assertIs(self.operation.billable, ContractMarker.UNKNOWN)

        self.assertEqual(
            self.credential.credential_binding_ref,
            GLM_CREDENTIAL_BINDING_REF,
        )
        self.assertEqual(self.credential.credential_ref, GLM_CREDENTIAL_REF)
        self.assertEqual(self.credential.provider_id, GLM_PROVIDER_ID)
        self.assertIs(
            self.credential.credential_injection_slot,
            CredentialInjectionSlot.AUTHORIZATION_HEADER,
        )
        self.assertIs(
            self.credential.credential_value_scheme,
            CredentialValueScheme.BEARER,
        )
        self.assertEqual(
            self.credential.endpoint_policy_digest,
            self.endpoint.endpoint_policy_digest,
        )

        self.assertEqual(self.capabilities.capabilities_ref, GLM_CAPABILITIES_REF)
        self.assertEqual(self.capabilities.model_id, GLM_MODEL_ID)
        self.assertEqual(
            self.capabilities.provider_profile_digest,
            self.provider.provider_profile_digest,
        )
        self.assertEqual(
            self.capabilities.input_modalities,
            (InputModality.IMAGE, InputModality.TEXT),
        )
        self.assertEqual(
            self.capabilities.roles,
            (CapabilityRole.MULTIMODAL_SOLVER, CapabilityRole.TEXT_SOLVER),
        )
        self.assertEqual(
            self.capabilities.image_inputs,
            (ImageInputKind.PUBLIC_URL, ImageInputKind.RAW_BASE64),
        )
        self.assertIs(
            self.capabilities.structured_output,
            StructuredOutputKind.PROMPT_ONLY,
        )
        self.assertEqual(self.capabilities.max_images, 1)
        self.assertEqual(self.capabilities.max_image_bytes, 5_242_880)
        self.assertEqual(self.capabilities.max_image_pixels, 4_000_000)
        self.assertEqual(self.capabilities.max_output_tokens, 1_024)
        self.assertEqual(
            self.capabilities.supported_mime_types,
            ("image/jpeg", "image/png"),
        )

        self.assertEqual(self.pipeline.pipeline_profile_id, GLM_PIPELINE_PROFILE_ID)
        self.assertIs(self.pipeline.pipeline_kind, PipelineKind.DIRECT_MULTIMODAL)
        self.assertIs(self.pipeline.capture_scope_kind, CaptureScopeKind.SELECTED_REGION)
        self.assertTrue(self.pipeline.preview_required)
        self.assertTrue(self.pipeline.enabled)
        self.assertEqual(self.pipeline.fallback_binding_ids, ())
        self.assertEqual(self.pipeline.timeout_budget_ms, 40_000)
        self.assertEqual(self.pipeline.max_attempts_per_operation, 2)
        self.assertEqual(self.pipeline.max_network_calls_total, 2)
        self.assertEqual(self.pipeline.max_billable_calls, 2)
        self.assertEqual(self.pipeline.max_output_tokens, 1_024)
        self.assertEqual(
            self.pipeline.requested_result_schema_version,
            SOLVE_RESULT_SCHEMA_VERSION,
        )
        self.assertEqual(self.binding.binding_id, GLM_BINDING_ID)
        self.assertIs(self.binding.role, StageRole.SOLVER)
        self.assertEqual(
            self.binding.provider_profile_digest,
            self.provider.provider_profile_digest,
        )
        self.assertEqual(
            self.binding.capabilities_digest,
            self.capabilities.capabilities_digest,
        )
        self.assertIs(self.binding.selected_image_input, ImageInputKind.RAW_BASE64)
        self.assertIs(
            self.binding.selected_structured_output,
            StructuredOutputKind.PROMPT_ONLY,
        )
        self.assertTrue(self.binding.send_system_instruction)
        self.assertFalse(self.binding.send_reasoning_control)
        self.assertTrue(self.binding.expect_usage)
        self.assertEqual(
            self.binding.fixed_non_secret_parameters,
            self.provider.fixed_non_secret_parameters,
        )

    def test_resolution_is_exact_and_experimental(self):
        resolved = self.registry.resolve_pipeline(GLM_PIPELINE_PROFILE_ID)
        self.assertIs(resolved.availability, Availability.EXPERIMENTAL)
        self.assertEqual(resolved.registry_digest, self.registry.registry_digest)
        self.assertIs(resolved.pipeline_profile, self.pipeline)
        self.assertEqual(len(resolved.stages), 1)
        stage = resolved.stages[0]
        self.assertIs(stage.availability, Availability.EXPERIMENTAL)
        self.assertIs(stage.stage_binding, self.binding)
        self.assertIs(stage.provider_profile, self.provider)
        self.assertIs(stage.capabilities, self.capabilities)
        self.assertIsNot(resolved.availability, Availability.SUPPORTED)

    def _assert_lookup_does_not_echo(
        self, canary: str, expected_kind: str, callback
    ) -> None:
        with self.assertRaises(RegistryLookupError) as raised:
            callback()
        error = raised.exception
        self.assertEqual(error.code, "unknown_registry_entry")
        self.assertEqual(error.entry_kind, expected_kind)
        observable = (
            str(error),
            repr(error),
            error.args,
            error.safe_metadata(),
            getattr(error, "__dict__", {}),
        )
        self.assertNotIn(canary, repr(observable))

    def test_unknown_profile_model_and_pipeline_fail_without_echo(self):
        unknown_profile = "provider-CANARY-DO-NOT-ECHO"
        unknown_model = "model-CANARY-DO-NOT-ECHO"
        unknown_pipeline = "pipeline-CANARY-DO-NOT-ECHO"
        self._assert_lookup_does_not_echo(
            unknown_profile,
            "provider_profile",
            lambda: self.registry.require_provider_profile(unknown_profile),
        )
        self._assert_lookup_does_not_echo(
            unknown_model,
            "model_capability",
            lambda: self.registry.require_capabilities(
                provider_profile_id=GLM_PROVIDER_PROFILE_ID,
                model_id=unknown_model,
            ),
        )
        self._assert_lookup_does_not_echo(
            unknown_pipeline,
            "pipeline_profile",
            lambda: self.registry.resolve_pipeline(unknown_pipeline),
        )

    def test_registry_graph_is_deeply_immutable_and_not_generically_serializable(self):
        resolved = self.registry.resolve_pipeline(GLM_PIPELINE_PROFILE_ID)
        legacy = map_legacy_glm_profile(base_url=None, model=None)
        values = (
            self.registry,
            self.provider,
            self.endpoint,
            self.operation,
            self.credential,
            self.capabilities,
            self.binding,
            self.pipeline,
            resolved,
            resolved.stages[0],
            legacy,
        )
        for value in values:
            with self.subTest(value=type(value).__name__, serializer="asdict"):
                with self.assertRaises(TypeError):
                    asdict(value)  # type: ignore[arg-type]
            with self.subTest(value=type(value).__name__, serializer="vars"):
                with self.assertRaises(TypeError):
                    vars(value)
            self.assertIs(copy.deepcopy(value), value)

        with self.assertRaises(AttributeError):
            self.registry.registry_revision = "changed"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            self.provider.adapter_version = "changed"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            self.endpoint.allowed_origins = ()  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            self.credential.credential_ref = "env:OTHER"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            self.pipeline.stage_bindings = ()  # type: ignore[misc]

        self.assertNotIn(GLM_CREDENTIAL_REF, repr(self.credential))
        self.assertNotIn(GLM_CREDENTIAL_REF, repr(legacy))
        self.assertNotIn("credential_ref", legacy.safe_metadata())

    def test_digests_are_deterministic_and_tampering_is_detected(self):
        rebuilt = build_builtin_registry()
        self.assertEqual(self.registry.registry_digest, rebuilt.registry_digest)
        self.assertEqual(
            self.provider.provider_profile_digest,
            rebuilt.provider_profiles[0].provider_profile_digest,
        )
        self.assertEqual(
            self.capabilities.capabilities_digest,
            rebuilt.capability_snapshots[0].capabilities_digest,
        )
        self.assertEqual(
            self.pipeline.pipeline_profile_digest,
            rebuilt.pipeline_profiles[0].pipeline_profile_digest,
        )
        self.assertEqual(self.registry.recompute_digest(), self.registry.registry_digest)
        self.registry.validate_integrity()

        own_digest_tamper = build_builtin_registry()
        object.__setattr__(
            own_digest_tamper,
            "registry_digest",
            Digest256("f" * 64),
        )
        with self.assertRaises(RegistryIntegrityError):
            own_digest_tamper.validate_integrity()

        nested_tamper = build_builtin_registry()
        object.__setattr__(
            nested_tamper.provider_profiles[0],
            "adapter_version",
            "tampered-adapter-version",
        )
        with self.assertRaises(RegistryIntegrityError):
            nested_tamper.validate_integrity()

        resolved_tamper = build_builtin_registry().resolve_pipeline(
            GLM_PIPELINE_PROFILE_ID
        )
        object.__setattr__(
            resolved_tamper,
            "availability",
            Availability.SUPPORTED,
        )
        with self.assertRaises(RegistryIntegrityError):
            resolved_tamper.validate_integrity()

    def test_registry_digest_has_a_fixed_golden_vector(self):
        self.assertEqual(self.registry.registry_digest, REGISTRY_GOLDEN_DIGEST)
        self.assertEqual(builtin_registry_digest(), REGISTRY_GOLDEN_DIGEST)

    def test_new_generation_does_not_mutate_old_snapshot_or_resolution(self):
        old_digest = self.registry.registry_digest
        old_revision = self.registry.registry_revision
        old_provider = self.provider
        old_resolution = self.registry.resolve_pipeline(GLM_PIPELINE_PROFILE_ID)

        reloaded = RegistrySnapshot(
            registry_revision=f"{BUILTIN_REGISTRY_REVISION}.reload-1",
            published_at=BUILTIN_REGISTRY_PUBLISHED_AT + timedelta(seconds=1),
            authority=RegistryAuthority.BUILTIN,
            provider_profiles=self.registry.provider_profiles,
            capability_snapshots=self.registry.capability_snapshots,
            pipeline_profiles=self.registry.pipeline_profiles,
        )
        reloaded_resolution = reloaded.resolve_pipeline(GLM_PIPELINE_PROFILE_ID)

        self.assertNotEqual(reloaded.registry_digest, old_digest)
        self.assertEqual(self.registry.registry_digest, old_digest)
        self.assertEqual(self.registry.registry_revision, old_revision)
        self.assertIs(self.registry.provider_profiles[0], old_provider)
        self.assertEqual(old_resolution.registry_digest, old_digest)
        self.assertEqual(old_resolution.registry_revision, old_revision)
        self.assertEqual(reloaded_resolution.registry_digest, reloaded.registry_digest)
        self.assertEqual(
            reloaded_resolution.registry_revision,
            reloaded.registry_revision,
        )
        self.registry.validate_integrity()
        reloaded.validate_integrity()


class LegacyGlmMappingContractTest(unittest.TestCase):
    @staticmethod
    def _observable_error(error: BaseException) -> object:
        return (
            str(error),
            repr(error),
            error.args,
            getattr(error, "__dict__", {}),
        )

    def test_default_and_exact_legacy_metadata_map_to_the_frozen_binding(self):
        for mapped in (
            map_legacy_glm_profile(base_url=None, model=None),
            map_legacy_glm_profile(
                base_url=GLM_LEGACY_BASE_URL,
                model=GLM_MODEL_ID,
            ),
        ):
            self.assertEqual(mapped.pipeline_profile_id, GLM_PIPELINE_PROFILE_ID)
            self.assertEqual(
                mapped.deprecation_code,
                "legacy_glm_environment_names_deprecated",
            )
            self.assertNotIn(GLM_CREDENTIAL_REF, repr(mapped))
            self.assertNotIn("credential_ref", mapped.safe_metadata())
            resolved = build_builtin_registry().resolve_pipeline(
                mapped.pipeline_profile_id
            )
            self.assertEqual(
                resolved.stages[0].provider_profile.provider_profile_id,
                GLM_PROVIDER_PROFILE_ID,
            )
            self.assertEqual(
                resolved.stages[0].capabilities.model_id,
                GLM_MODEL_ID,
            )
            self.assertEqual(
                resolved.stages[0].provider_profile.credential_binding.credential_ref,
                GLM_CREDENTIAL_REF,
            )

    def test_legacy_mapping_requires_an_explicit_migration_selection(self):
        with self.assertRaises(TypeError):
            map_legacy_glm_profile()  # type: ignore[call-arg]

    def test_legacy_mapping_errors_do_not_echo_rejected_metadata(self):
        bad_base_url = "https://BASE-URL-CANARY.invalid/v1"
        with self.assertRaises(LegacyGlmMappingError) as bad_base:
            map_legacy_glm_profile(base_url=bad_base_url, model=GLM_MODEL_ID)
        self.assertNotIn(
            bad_base_url,
            repr(self._observable_error(bad_base.exception)),
        )

        bad_model = "MODEL-CANARY-DO-NOT-ECHO"
        with self.assertRaises(LegacyGlmMappingError) as bad_model_error:
            map_legacy_glm_profile(
                base_url=GLM_LEGACY_BASE_URL,
                model=bad_model,
            )
        self.assertNotIn(
            bad_model,
            repr(self._observable_error(bad_model_error.exception)),
        )


if __name__ == "__main__":
    unittest.main()
