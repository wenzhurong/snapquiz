from dataclasses import asdict
from enum import Enum
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

from snapquiz.config.legacy_glm import LegacyGlmProfileReference
from snapquiz.config.profiles import (
    GLM_ALLOWED_BASE_PATH,
    GLM_ALLOWED_ORIGIN,
    GLM_CAPABILITIES_REF,
    GLM_CHAT_COMPLETIONS_ENDPOINT,
    GLM_CREDENTIAL_REF,
    GLM_MODEL_ID,
    GLM_PIPELINE_PROFILE_ID,
    GLM_PROVIDER_PROFILE_ID,
    build_builtin_registry,
)
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
    ProviderProfileSnapshot,
    RedirectPolicy,
    StageBindingSnapshot,
    StructuredOutputKind,
)
from snapquiz.domain.plan import (
    CanonicalQueryPolicy,
    CredentialInjectionSlot,
    NetworkOperationPurpose,
    NetworkScope,
    OutboundDataKind,
    QueryPolicyKind,
)
from snapquiz.domain.policy import ContractMarker
from snapquiz.routing.registry import (
    Availability,
    RegistryAuthority,
    RegistryIntegrityError,
    RegistryLookupError,
    RegistrySnapshot,
    ResolvedPipelineProfile,
    ResolvedStageBinding,
)


def _operation_kwargs(operation: EndpointOperationTemplate) -> dict[str, object]:
    return {
        "operation_key": operation.operation_key,
        "purpose": operation.purpose,
        "http_method": operation.http_method,
        "canonical_endpoint": operation.canonical_endpoint,
        "canonical_query_policy": operation.canonical_query_policy,
        "content_type": operation.content_type,
        "allowed_non_secret_headers": operation.allowed_non_secret_headers,
        "credential_injection_slot": operation.credential_injection_slot,
        "outbound_data": operation.outbound_data,
        "billable": operation.billable,
    }


def _endpoint_policy_kwargs(policy: EndpointPolicySnapshot) -> dict[str, object]:
    return {
        "endpoint_policy_version": policy.endpoint_policy_version,
        "allowed_origins": policy.allowed_origins,
        "allowed_base_paths": policy.allowed_base_paths,
        "operation_templates": policy.operation_templates,
        "allow_custom_endpoint": policy.allow_custom_endpoint,
        "redirect_policy": policy.redirect_policy,
        "network_scope": policy.network_scope,
        "network_policy_version": policy.network_policy_version,
        "tls_policy_ref": policy.tls_policy_ref,
    }


def _capability_kwargs(
    capability: ModelCapabilitiesSnapshot,
    provider: ProviderProfileSnapshot,
) -> dict[str, object]:
    return {
        "capabilities_ref": capability.capabilities_ref,
        "provider_profile": provider,
        "model_id": capability.model_id,
        "input_modalities": capability.input_modalities,
        "roles": capability.roles,
        "image_inputs": capability.image_inputs,
        "structured_output": capability.structured_output,
        "supports_system_instruction": capability.supports_system_instruction,
        "supports_reasoning_control": capability.supports_reasoning_control,
        "supports_usage": capability.supports_usage,
        "max_images": capability.max_images,
        "max_image_bytes": capability.max_image_bytes,
        "max_image_pixels": capability.max_image_pixels,
        "max_output_tokens": capability.max_output_tokens,
        "supported_mime_types": capability.supported_mime_types,
        "data_residency": capability.data_residency,
    }


def _text_capability_kwargs(provider: ProviderProfileSnapshot) -> dict[str, object]:
    return {
        "capabilities_ref": "capabilities:test/text-only@v1",
        "provider_profile": provider,
        "model_id": "text-only-exact-v1",
        "input_modalities": (InputModality.TEXT,),
        "roles": (CapabilityRole.TEXT_SOLVER,),
        "image_inputs": ContractMarker.NOT_APPLICABLE,
        "structured_output": StructuredOutputKind.PROMPT_ONLY,
        "supports_system_instruction": True,
        "supports_reasoning_control": False,
        "supports_usage": False,
        "max_images": ContractMarker.NOT_APPLICABLE,
        "max_image_bytes": ContractMarker.NOT_APPLICABLE,
        "max_image_pixels": ContractMarker.NOT_APPLICABLE,
        "max_output_tokens": 512,
        "supported_mime_types": ContractMarker.NOT_APPLICABLE,
        "data_residency": ContractMarker.UNKNOWN,
    }


class RegistrySecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = build_builtin_registry()
        self.provider = self.registry.require_provider_profile(
            GLM_PROVIDER_PROFILE_ID
        )
        self.capability = self.registry.require_capabilities(
            provider_profile_id=GLM_PROVIDER_PROFILE_ID,
            model_id=GLM_MODEL_ID,
        )
        self.pipeline = self.registry.require_pipeline_profile(
            GLM_PIPELINE_PROFILE_ID
        )
        self.endpoint_policy = self.provider.endpoint_policy
        self.operation = self.endpoint_policy.require_operation("inference")

    def _registry_with_billable_budget(
        self, *, billable: bool, max_billable_calls: int
    ) -> RegistrySnapshot:
        operation = EndpointOperationTemplate(
            **{**_operation_kwargs(self.operation), "billable": billable}
        )
        endpoint_policy = EndpointPolicySnapshot(
            **{
                **_endpoint_policy_kwargs(self.endpoint_policy),
                "operation_templates": (operation,),
            }
        )
        old_credential = self.provider.credential_binding
        credential = CredentialBindingMetadata(
            credential_binding_ref=old_credential.credential_binding_ref,
            credential_ref=old_credential.credential_ref,
            provider_id=old_credential.provider_id,
            endpoint_policy=endpoint_policy,
            credential_injection_slot=old_credential.credential_injection_slot,
            credential_value_scheme=old_credential.credential_value_scheme,
        )
        provider = ProviderProfileSnapshot(
            provider_profile_id=self.provider.provider_profile_id,
            provider_id=self.provider.provider_id,
            adapter_family=self.provider.adapter_family,
            adapter_version=self.provider.adapter_version,
            api_version=self.provider.api_version,
            endpoint_policy=endpoint_policy,
            credential_binding=credential,
            compute_location=self.provider.compute_location,
            processing_region=self.provider.processing_region,
            provider_application_state=self.provider.provider_application_state,
            retention_policy=self.provider.retention_policy,
            data_policy=self.provider.data_policy,
            cost_policy=self.provider.cost_policy,
            fixed_non_secret_parameters=self.provider.fixed_non_secret_parameters,
        )
        capability = ModelCapabilitiesSnapshot(
            **_capability_kwargs(self.capability, provider)
        )
        old_binding = self.pipeline.stage_bindings[0]
        binding = StageBindingSnapshot(
            binding_id=old_binding.binding_id,
            role=old_binding.role,
            provider_profile=provider,
            capabilities=capability,
            selected_image_input=old_binding.selected_image_input,
            selected_structured_output=old_binding.selected_structured_output,
            send_system_instruction=old_binding.send_system_instruction,
            send_reasoning_control=old_binding.send_reasoning_control,
            expect_usage=old_binding.expect_usage,
        )
        pipeline = PipelineProfileSnapshot(
            pipeline_profile_id=self.pipeline.pipeline_profile_id,
            pipeline_kind=self.pipeline.pipeline_kind,
            stage_bindings=(binding,),
            prompt_policy_digest=self.pipeline.prompt_policy_digest,
            result_validator_version=self.pipeline.result_validator_version,
            image_preprocessing_policy_version=(
                self.pipeline.image_preprocessing_policy_version
            ),
            requested_result_schema_version=(
                self.pipeline.requested_result_schema_version
            ),
            capture_scope_kind=self.pipeline.capture_scope_kind,
            preview_required=self.pipeline.preview_required,
            timeout_budget_ms=self.pipeline.timeout_budget_ms,
            max_attempts_per_operation=self.pipeline.max_attempts_per_operation,
            max_network_calls_total=self.pipeline.max_network_calls_total,
            max_billable_calls=max_billable_calls,
            max_output_tokens=self.pipeline.max_output_tokens,
            max_image_width_px=self.pipeline.max_image_width_px,
            max_image_height_px=self.pipeline.max_image_height_px,
            max_image_pixels=self.pipeline.max_image_pixels,
            max_image_bytes=self.pipeline.max_image_bytes,
            cost_policy=self.pipeline.cost_policy,
            fallback_binding_ids=self.pipeline.fallback_binding_ids,
            enabled=self.pipeline.enabled,
        )
        return RegistrySnapshot(
            registry_revision=self.registry.registry_revision + ".nonbillable",
            published_at=self.registry.published_at,
            authority=RegistryAuthority.BUILTIN,
            provider_profiles=(provider,),
            capability_snapshots=(capability,),
            pipeline_profiles=(pipeline,),
        )

    def test_multimodal_capability_rejects_missing_or_forged_image_contracts(self):
        base = _capability_kwargs(self.capability, self.provider)
        invalid_overrides = (
            {"input_modalities": (InputModality.TEXT,)},
            {"input_modalities": (InputModality.IMAGE,)},
            {"input_modalities": ("image", "text")},
            {"image_inputs": ContractMarker.NOT_APPLICABLE},
            {"image_inputs": ()},
            {"image_inputs": ("data_uri",)},
            {"max_images": 0},
            {"max_images": True},
            {"max_image_bytes": ContractMarker.NOT_APPLICABLE},
            {"max_image_pixels": 0},
            {"supported_mime_types": ContractMarker.NOT_APPLICABLE},
            {"supported_mime_types": ("text/plain",)},
            {"supported_mime_types": ("image/png", "image/jpeg")},
        )

        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    ModelCapabilitiesSnapshot(**{**base, **overrides})

    def test_text_only_capability_requires_every_image_field_not_applicable(self):
        base = _text_capability_kwargs(self.provider)
        valid = ModelCapabilitiesSnapshot(**base)
        self.assertEqual(valid.input_modalities, (InputModality.TEXT,))
        self.assertIs(valid.image_inputs, ContractMarker.NOT_APPLICABLE)

        invalid_overrides = (
            {"input_modalities": (InputModality.IMAGE, InputModality.TEXT)},
            {"roles": (CapabilityRole.MULTIMODAL_SOLVER,)},
            {"image_inputs": ()},
            {"image_inputs": (ImageInputKind.DATA_URI,)},
            {"max_images": 1},
            {"max_image_bytes": 1},
            {"max_image_pixels": 1},
            {"supported_mime_types": ("image/png",)},
        )

        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    ModelCapabilitiesSnapshot(**{**base, **overrides})

    def test_capability_booleans_and_limits_are_type_exact(self):
        base = _capability_kwargs(self.capability, self.provider)
        for overrides in (
            {"supports_usage": 1},
            {"supports_reasoning_control": "true"},
            {"max_output_tokens": True},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    ModelCapabilitiesSnapshot(**{**base, **overrides})

    def test_billable_budget_exactly_matches_non_billable_operation(self):
        registry = self._registry_with_billable_budget(
            billable=False, max_billable_calls=0
        )
        resolved = registry.resolve_pipeline(GLM_PIPELINE_PROFILE_ID)
        self.assertEqual(
            resolved.pipeline_profile.max_billable_calls,
            0,
        )
        with self.assertRaises(RegistryIntegrityError):
            self._registry_with_billable_budget(
                billable=False, max_billable_calls=1
            )

    def test_credential_binding_accepts_only_an_exact_non_secret_env_locator(self):
        base = {
            "credential_binding_ref": "registry:test-binding.v1",
            "credential_ref": "env:TEST_PROVIDER_API_KEY",
            "provider_id": self.provider.provider_id,
            "endpoint_policy": self.endpoint_policy,
            "credential_injection_slot": (
                CredentialInjectionSlot.AUTHORIZATION_HEADER
            ),
            "credential_value_scheme": CredentialValueScheme.BEARER,
        }
        accepted = CredentialBindingMetadata(**base)
        self.assertEqual(accepted.credential_ref, "env:TEST_PROVIDER_API_KEY")

        class TextSubclass(str):
            pass

        invalid_refs = (
            "sk-live-super-secret",
            "raw:super-secret",
            "file:/tmp/provider-key",
            "keychain:provider-key",
            "exec:security find-generic-password",
            "http://metadata.invalid/key",
            "https://metadata.invalid/key",
            "${TEST_PROVIDER_API_KEY}",
            "env:",
            "env:test_provider_api_key",
            "env:1TEST_PROVIDER_API_KEY",
            "env:TEST-PROVIDER-API-KEY",
            "env:TEST_PROVIDER_API_KEY=super-secret",
            "env:TEST_PROVIDER_API_KEY\nSECOND=value",
            TextSubclass("env:TEST_PROVIDER_API_KEY"),
            None,
        )
        for credential_ref in invalid_refs:
            with self.subTest(credential_ref=type(credential_ref).__name__):
                with self.assertRaises(ValueError) as raised:
                    CredentialBindingMetadata(
                        **{**base, "credential_ref": credential_ref}
                    )
                self.assertNotIn("super-secret", str(raised.exception))

    def test_fixed_adapter_parameter_names_cannot_be_credential_shaped(self):
        provider_base = {
            "provider_profile_id": self.provider.provider_profile_id,
            "provider_id": self.provider.provider_id,
            "adapter_family": self.provider.adapter_family,
            "adapter_version": self.provider.adapter_version,
            "api_version": self.provider.api_version,
            "endpoint_policy": self.provider.endpoint_policy,
            "credential_binding": self.provider.credential_binding,
            "compute_location": self.provider.compute_location,
            "processing_region": self.provider.processing_region,
            "provider_application_state": self.provider.provider_application_state,
            "retention_policy": self.provider.retention_policy,
            "data_policy": self.provider.data_policy,
            "cost_policy": self.provider.cost_policy,
        }
        accepted = ProviderProfileSnapshot(
            **provider_base,
            fixed_non_secret_parameters=(("temperature", "0"),),
        )
        self.assertEqual(
            accepted.fixed_non_secret_parameters,
            (("temperature", "0"),),
        )
        for parameter_name in (
            "api_key",
            "authorization",
            "access_token",
            "password",
            "client_secret",
        ):
            with self.subTest(parameter_name=parameter_name):
                with self.assertRaises(ValueError):
                    ProviderProfileSnapshot(
                        **provider_base,
                        fixed_non_secret_parameters=(
                            (parameter_name, "SECRET-CANARY"),
                        ),
                    )

    def test_builtin_profile_pins_the_official_endpoint_and_rejects_redirects(self):
        self.assertEqual(self.endpoint_policy.allowed_origins, (GLM_ALLOWED_ORIGIN,))
        self.assertEqual(
            self.endpoint_policy.allowed_base_paths, (GLM_ALLOWED_BASE_PATH,)
        )
        self.assertEqual(
            self.operation.canonical_endpoint, GLM_CHAT_COMPLETIONS_ENDPOINT
        )
        self.assertFalse(self.endpoint_policy.allow_custom_endpoint)
        self.assertIs(self.endpoint_policy.redirect_policy, RedirectPolicy.REJECT)
        self.assertIs(
            self.operation.canonical_query_policy.kind, QueryPolicyKind.EMPTY
        )
        self.assertEqual(self.operation.canonical_query_policy.exact_items, ())

        policy_base = _endpoint_policy_kwargs(self.endpoint_policy)
        for redirect_policy in ("reject", object()):
            with self.subTest(redirect_policy=redirect_policy):
                with self.assertRaises(ValueError):
                    EndpointPolicySnapshot(
                        **{**policy_base, "redirect_policy": redirect_policy}
                    )
        with self.assertRaises(ValueError):
            EndpointPolicySnapshot(
                **{**policy_base, "allow_custom_endpoint": 1}
            )
        for tls_policy_ref in (
            ContractMarker.UNKNOWN,
            ContractMarker.NOT_APPLICABLE,
            "unknown",
            "not_applicable",
        ):
            with self.subTest(tls_policy_ref=tls_policy_ref):
                with self.assertRaises(ValueError):
                    EndpointPolicySnapshot(
                        **{**policy_base, "tls_policy_ref": tls_policy_ref}
                    )

    def test_official_endpoint_rejects_noncanonical_url_and_any_query(self):
        operation_base = _operation_kwargs(self.operation)
        invalid_endpoints = (
            "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "HTTPS://open.bigmodel.cn:443/api/paas/v4/chat/completions",
            "https://OPEN.bigmodel.cn:443/api/paas/v4/chat/completions",
            "https://open.bigmodel.cn.:443/api/paas/v4/chat/completions",
            "https://user@open.bigmodel.cn:443/api/paas/v4/chat/completions",
            GLM_CHAT_COMPLETIONS_ENDPOINT + "?mode=fast",
            GLM_CHAT_COMPLETIONS_ENDPOINT + "?",
            GLM_CHAT_COMPLETIONS_ENDPOINT + "#fragment",
            "https://open.bigmodel.cn:443/api/paas/v4/../chat/completions",
            "https://open.bigmodel.cn:443/api/paas/v4/%2E%2E/chat/completions",
            "https://open.bigmodel.cn:443/api/paas/v4/%2Fchat/completions",
            "https://open.bigmodel.cn:443/api/paas/v4/cafe%CC%81",
            "https://open.bigmodel.cn:443/api/paas/v4/%C0%AF",
        )
        for endpoint in invalid_endpoints:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    EndpointOperationTemplate(
                        **{**operation_base, "canonical_endpoint": endpoint}
                    )

        with self.assertRaises(ValueError):
            CanonicalQueryPolicy(
                kind=QueryPolicyKind.EXACT,
                exact_items=(("mode", "fast"),),
            )

    def test_official_endpoint_policy_rejects_other_origins_and_prefix_confusion(self):
        operation_base = _operation_kwargs(self.operation)
        policy_base = _endpoint_policy_kwargs(self.endpoint_policy)
        endpoints = (
            "https://evil.example:443/api/paas/v4/chat/completions",
            "https://open.bigmodel.cn:444/api/paas/v4/chat/completions",
            "http://open.bigmodel.cn:80/api/paas/v4/chat/completions",
            "https://open.bigmodel.cn:443/api/paas/v4evil/chat/completions",
            "https://open.bigmodel.cn:443/api/paas/v4",
            "https://open.bigmodel.cn:443/api/paas/v3/chat/completions",
        )
        for endpoint in endpoints:
            operation = EndpointOperationTemplate(
                **{**operation_base, "canonical_endpoint": endpoint}
            )
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    EndpointPolicySnapshot(
                        **{**policy_base, "operation_templates": (operation,)}
                    )

    def test_literal_address_must_match_declared_network_scope(self):
        operation_base = _operation_kwargs(self.operation)
        policy_base = _endpoint_policy_kwargs(self.endpoint_policy)
        mismatches = (
            (
                NetworkScope.INTERNET,
                "https://192.168.1.2:443/",
                "https://192.168.1.2:443/api/paas/v4/chat/completions",
            ),
            (
                NetworkScope.LAN,
                "https://8.8.8.8:443/",
                "https://8.8.8.8:443/api/paas/v4/chat/completions",
            ),
        )
        for network_scope, origin, endpoint in mismatches:
            operation = EndpointOperationTemplate(
                **{**operation_base, "canonical_endpoint": endpoint}
            )
            with self.subTest(network_scope=network_scope.value):
                with self.assertRaises(ValueError):
                    EndpointPolicySnapshot(
                        **{
                            **policy_base,
                            "allowed_origins": (origin,),
                            "operation_templates": (operation,),
                            "network_scope": network_scope,
                        }
                    )

        with self.assertRaises(ValueError):
            EndpointPolicySnapshot(
                **{
                    **policy_base,
                    "allowed_origins": (
                        "https://open.bigmodel.cn:443/api/paas/v4/",
                    ),
                }
            )

    def test_security_snapshots_are_runtime_final_and_reject_subclasses(self):
        final_types = (
            CanonicalQueryPolicy,
            EndpointOperationTemplate,
            EndpointPolicySnapshot,
            CredentialBindingMetadata,
            ProviderProfileSnapshot,
            ModelCapabilitiesSnapshot,
            StageBindingSnapshot,
            PipelineProfileSnapshot,
            RegistrySnapshot,
            ResolvedStageBinding,
            ResolvedPipelineProfile,
            LegacyGlmProfileReference,
        )
        for final_type in final_types:
            with self.subTest(final_type=final_type.__name__):
                with self.assertRaises(TypeError):
                    type("Forged" + final_type.__name__, (final_type,), {})

    def test_registry_and_security_constructor_inputs_are_type_exact(self):
        class TextSubclass(str):
            pass

        class FakePurpose(str, Enum):
            INFERENCE = "inference"

        with self.assertRaises(ValueError):
            self.registry.require_capabilities(
                provider_profile_id=TextSubclass(GLM_PROVIDER_PROFILE_ID),
                model_id=GLM_MODEL_ID,
            )

        operation_base = _operation_kwargs(self.operation)
        with self.assertRaises(ValueError):
            EndpointOperationTemplate(
                **{**operation_base, "purpose": FakePurpose.INFERENCE}
            )

        with self.assertRaises(ValueError):
            RegistrySnapshot(
                registry_revision=self.registry.registry_revision,
                published_at=self.registry.published_at,
                authority=RegistryAuthority.BUILTIN.value,
                provider_profiles=self.registry.provider_profiles,
                capability_snapshots=self.registry.capability_snapshots,
                pipeline_profiles=self.registry.pipeline_profiles,
            )

        resolved = self.registry.resolve_pipeline(GLM_PIPELINE_PROFILE_ID)
        resolved_stage = resolved.stages[0]
        with self.assertRaises(TypeError):
            ResolvedStageBinding(
                registry_revision=resolved_stage.registry_revision,
                registry_digest=resolved_stage.registry_digest,
                availability=Availability.SUPPORTED,
                stage_binding=resolved_stage.stage_binding,
                provider_profile=resolved_stage.provider_profile,
                capabilities=resolved_stage.capabilities,
            )
        with self.assertRaises(TypeError):
            ResolvedPipelineProfile(
                registry_revision=resolved.registry_revision,
                registry_digest=resolved.registry_digest,
                availability=Availability.SUPPORTED,
                pipeline_profile=resolved.pipeline_profile,
                stages=resolved.stages,
            )

    def test_unknown_model_variants_never_inherit_known_capabilities(self):
        self.assertIs(
            self.registry.require_capabilities(
                provider_profile_id=GLM_PROVIDER_PROFILE_ID,
                model_id=GLM_MODEL_ID,
            ),
            self.capability,
        )
        variants = (
            GLM_MODEL_ID.upper(),
            " " + GLM_MODEL_ID,
            GLM_MODEL_ID + " ",
            GLM_MODEL_ID + "-latest",
            GLM_MODEL_ID + "-vision",
            GLM_MODEL_ID.replace("-", "\N{FULLWIDTH HYPHEN-MINUS}", 1),
        )
        for candidate in variants:
            with self.subTest(candidate=candidate):
                with self.assertRaises(RegistryLookupError) as raised:
                    self.registry.require_capabilities(
                        provider_profile_id=GLM_PROVIDER_PROFILE_ID,
                        model_id=candidate,
                    )
                self.assertEqual(
                    raised.exception.safe_metadata(),
                    {
                        "code": "unknown_registry_entry",
                        "entry_kind": "model_capability",
                    },
                )
                self.assertNotIn(candidate, str(raised.exception))
                self.assertNotIn(candidate, repr(raised.exception))

        with self.assertRaises(RegistryLookupError):
            self.registry.require_capabilities(
                provider_profile_id=GLM_PROVIDER_PROFILE_ID + ".custom",
                model_id=GLM_MODEL_ID,
            )
        with self.assertRaises(RegistryLookupError):
            self.registry.require_capabilities_ref(GLM_CAPABILITIES_REF + ".latest")

    def test_repr_and_safe_metadata_hide_credential_locator_and_full_digests(self):
        resolved = self.registry.resolve_pipeline(GLM_PIPELINE_PROFILE_ID)
        credential_binding = self.provider.credential_binding
        self.assertIs(type(credential_binding), CredentialBindingMetadata)
        legacy = LegacyGlmProfileReference()
        objects = (
            self.operation,
            self.endpoint_policy,
            credential_binding,
            self.provider,
            self.capability,
            self.pipeline.stage_bindings[0],
            self.pipeline,
            self.registry,
            resolved.stages[0],
            resolved,
            legacy,
        )
        full_digests = tuple(
            str(value)
            for value in (
                self.operation.operation_template_digest,
                self.endpoint_policy.endpoint_policy_digest,
                credential_binding.credential_binding_digest,
                self.provider.provider_profile_digest,
                self.capability.capabilities_digest,
                self.pipeline.stage_bindings[0].stage_binding_digest,
                self.pipeline.pipeline_profile_digest,
                self.registry.registry_digest,
            )
        )

        for value in objects:
            with self.subTest(value=type(value).__name__):
                metadata = value.safe_metadata()
                rendered = repr(value) + "\n" + repr(metadata)
                self.assertNotIn(GLM_CREDENTIAL_REF, rendered)
                for digest in full_digests:
                    self.assertNotIn(digest, rendered)
                with self.assertRaises(TypeError):
                    asdict(value)

    def test_fresh_process_import_and_registry_build_have_no_external_side_effects(self):
        repository_root = Path(__file__).resolve().parents[1]
        secret = "registry-probe-secret-must-never-appear"
        script = textwrap.dedent(
            r'''
            import builtins
            import collections.abc
            import json
            import os
            import socket
            import sys

            action = sys.argv[1]
            original_environ = os.environ
            secret_keys = frozenset({
                "ANTHROPIC_API_KEY",
                "GLM_API_KEY",
                "OPENAI_API_KEY",
                "ZHIPU_API_KEY",
            })

            class GuardedEnvironment(collections.abc.MutableMapping):
                def __getitem__(self, key):
                    if key in secret_keys:
                        raise AssertionError("credential environment read")
                    return original_environ[key]

                def __setitem__(self, key, value):
                    if key in secret_keys:
                        raise AssertionError("credential environment write")
                    original_environ[key] = value

                def __delitem__(self, key):
                    if key in secret_keys:
                        raise AssertionError("credential environment delete")
                    del original_environ[key]

                def __iter__(self):
                    raise AssertionError("environment enumeration")

                def __len__(self):
                    return len(original_environ)

                def __contains__(self, key):
                    if key in secret_keys:
                        raise AssertionError("credential environment membership read")
                    return key in original_environ

                def copy(self):
                    raise AssertionError("environment copy")

            os.environ = GuardedEnvironment()

            forbidden_import_roots = frozenset({
                "AppKit",
                "Quartz",
                "dotenv",
                "mss",
                "openai",
                "pynput",
            })
            original_import = builtins.__import__

            def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name.split(".", 1)[0] in forbidden_import_roots:
                    raise AssertionError("optional SDK or capture import")
                return original_import(name, globals, locals, fromlist, level)

            def forbidden_network(*args, **kwargs):
                del args, kwargs
                raise AssertionError("network access")

            builtins.__import__ = guarded_import
            socket.socket = forbidden_network
            socket.create_connection = forbidden_network
            socket.getaddrinfo = forbidden_network
            socket.gethostbyname = forbidden_network
            socket.gethostbyname_ex = forbidden_network

            import snapquiz.config.profiles as profiles
            import snapquiz.routing.registry as registry_module

            assert registry_module.RegistrySnapshot.__module__ == "snapquiz.routing.registry"
            result = {"action": action, "status": "ok"}
            if action == "build":
                registry = profiles.build_builtin_registry()
                resolved = registry.resolve_pipeline(profiles.GLM_PIPELINE_PROFILE_ID)
                rendered = repr(registry) + repr(registry.safe_metadata())
                rendered += repr(resolved) + repr(resolved.safe_metadata())
                assert profiles.GLM_CREDENTIAL_REF not in rendered
                assert str(registry.registry_digest) not in rendered
                result["registry_digest_prefix"] = registry.safe_metadata()[
                    "registry_digest_prefix"
                ]

            for forbidden in forbidden_import_roots:
                assert forbidden not in sys.modules
            assert "snapquiz.capture.screen" not in sys.modules
            assert "snapquiz.llm.glm" not in sys.modules
            print(json.dumps(result, sort_keys=True))
            '''
        )
        child_environment = os.environ.copy()
        child_environment["GLM_API_KEY"] = secret
        child_environment["PYTHONDONTWRITEBYTECODE"] = "1"

        for action in ("import", "build"):
            completed = subprocess.run(
                [sys.executable, "-S", "-c", script, action],
                cwd=repository_root,
                env=child_environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            with self.subTest(action=action):
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertNotIn(secret, completed.stdout)
                self.assertNotIn(secret, completed.stderr)
                self.assertNotIn(GLM_CREDENTIAL_REF, completed.stdout)
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["action"], action)
                self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
