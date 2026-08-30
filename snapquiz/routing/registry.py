"""Immutable exact-match Registry snapshots for provider routing.

The Registry is an offline authority boundary.  It never reads environment
variables, resolves credential values, imports an SDK, or probes an endpoint.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_text,
    runtime_final,
)
from snapquiz.domain.capabilities import (
    CapabilityRole,
    ImageInputKind,
    ModelCapabilitiesSnapshot,
    PipelineProfileSnapshot,
    ProviderProfileSnapshot,
    StageBindingSnapshot,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.plan import NetworkOperationPurpose, OutboundDataKind
from snapquiz.domain.policy import ContractMarker
from snapquiz.domain.solve import PipelineKind, StageRole

REGISTRY_SNAPSHOT_SCHEMA_VERSION = "snapquiz.registry-snapshot.v1"
_RESOLUTION_AUTHORITY = object()


class RegistryAuthority(str, Enum):
    BUILTIN = "builtin"
    CUSTOM = "custom"


class Availability(str, Enum):
    DISABLED = "disabled"
    EXPERIMENTAL = "experimental"
    SUPPORTED = "supported"


class RegistryLookupError(LookupError):
    """An exact Registry key is absent.

    The queried value is intentionally not retained or rendered: values can
    originate in user-editable configuration and should not become log data.
    """

    __slots__ = ("code", "entry_kind")

    def __init__(self, *, entry_kind: str) -> None:
        self.code = "unknown_registry_entry"
        self.entry_kind = require_text(entry_kind, "entry_kind", max_length=64)
        super().__init__(f"unknown {self.entry_kind} registry entry")

    def safe_metadata(self) -> dict[str, str]:
        return {"code": self.code, "entry_kind": self.entry_kind}


class RegistryIntegrityError(ValueError):
    """A Registry graph is internally inconsistent or has been tampered with."""


def _short_digest(value: Digest256) -> str:
    return str(value)[:12]


def _set_attributes(instance: object, values: tuple[tuple[str, object], ...]) -> None:
    for name, value in values:
        object.__setattr__(instance, name, value)


@runtime_final
class ResolvedStageBinding:
    """One atomically resolved stage from one Registry generation."""

    __slots__ = (
        "registry_revision",
        "registry_digest",
        "availability",
        "stage_binding",
        "provider_profile",
        "capabilities",
    )

    def __init__(
        self,
        *,
        registry_revision: str,
        registry_digest: Digest256,
        availability: Availability,
        stage_binding: StageBindingSnapshot,
        provider_profile: ProviderProfileSnapshot,
        capabilities: ModelCapabilitiesSnapshot,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RESOLUTION_AUTHORITY:
            raise TypeError("ResolvedStageBinding can only be created by RegistrySnapshot")
        require_text(registry_revision, "registry_revision")
        if type(registry_digest) is not Digest256:
            raise ValueError("registry_digest must be Digest256")
        if type(availability) is not Availability:
            raise ValueError("availability must be Availability")
        if availability is Availability.SUPPORTED:
            raise ValueError("supported requires a verified Registry record")
        if type(stage_binding) is not StageBindingSnapshot:
            raise ValueError("stage_binding must be StageBindingSnapshot")
        if type(provider_profile) is not ProviderProfileSnapshot:
            raise ValueError("provider_profile must be ProviderProfileSnapshot")
        if type(capabilities) is not ModelCapabilitiesSnapshot:
            raise ValueError("capabilities must be ModelCapabilitiesSnapshot")
        _set_attributes(
            self,
            (
                ("registry_revision", registry_revision),
                ("registry_digest", registry_digest),
                ("availability", availability),
                ("stage_binding", stage_binding),
                ("provider_profile", provider_profile),
                ("capabilities", capabilities),
            ),
        )
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolvedStageBinding is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "ResolvedStageBinding":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "ResolvedStageBinding("
            f"registry_revision={self.registry_revision!r}, "
            f"availability={self.availability.value!r}, "
            f"binding_id={self.stage_binding.binding_id!r}, "
            f"provider_profile_id={self.provider_profile.provider_profile_id!r}, "
            f"model_id={self.capabilities.model_id!r}, "
            f"registry_digest_prefix={_short_digest(self.registry_digest)!r})"
        )

    def safe_metadata(self) -> dict[str, object]:
        return {
            "registry_revision": self.registry_revision,
            "registry_digest_prefix": _short_digest(self.registry_digest),
            "availability": self.availability.value,
            "binding_id": self.stage_binding.binding_id,
            "provider_profile_id": self.provider_profile.provider_profile_id,
            "model_id": self.capabilities.model_id,
        }

    def validate_integrity(self) -> None:
        if self.availability not in (
            Availability.DISABLED,
            Availability.EXPERIMENTAL,
        ):
            raise RegistryIntegrityError(
                "resolved stage lacks supported verification evidence"
            )
        self.stage_binding.validate_integrity()
        self.provider_profile.validate_integrity()
        self.capabilities.validate_integrity()
        if (
            self.stage_binding.provider_profile_id
            != self.provider_profile.provider_profile_id
            or self.stage_binding.provider_profile_digest
            != self.provider_profile.provider_profile_digest
            or self.stage_binding.capabilities_ref
            != self.capabilities.capabilities_ref
            or self.stage_binding.capabilities_digest
            != self.capabilities.capabilities_digest
            or self.stage_binding.model_id != self.capabilities.model_id
        ):
            raise RegistryIntegrityError("resolved stage mixes snapshot generations")


@runtime_final
class ResolvedPipelineProfile:
    """A pipeline and every stage resolved from one immutable generation."""

    __slots__ = (
        "registry_revision",
        "registry_digest",
        "availability",
        "pipeline_profile",
        "stages",
    )

    def __init__(
        self,
        *,
        registry_revision: str,
        registry_digest: Digest256,
        availability: Availability,
        pipeline_profile: PipelineProfileSnapshot,
        stages: tuple[ResolvedStageBinding, ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RESOLUTION_AUTHORITY:
            raise TypeError(
                "ResolvedPipelineProfile can only be created by RegistrySnapshot"
            )
        require_text(registry_revision, "registry_revision")
        if type(registry_digest) is not Digest256:
            raise ValueError("registry_digest must be Digest256")
        if type(availability) is not Availability:
            raise ValueError("availability must be Availability")
        if availability is Availability.SUPPORTED:
            raise ValueError("supported requires a verified Registry record")
        if type(pipeline_profile) is not PipelineProfileSnapshot:
            raise ValueError("pipeline_profile must be PipelineProfileSnapshot")
        if type(stages) is not tuple or not stages:
            raise ValueError("stages must be a non-empty tuple")
        if not all(type(stage) is ResolvedStageBinding for stage in stages):
            raise ValueError("stages contain an invalid value")
        if tuple(stage.stage_binding for stage in stages) != pipeline_profile.stage_bindings:
            raise ValueError("resolved stages do not match the pipeline profile")
        _set_attributes(
            self,
            (
                ("registry_revision", registry_revision),
                ("registry_digest", registry_digest),
                ("availability", availability),
                ("pipeline_profile", pipeline_profile),
                ("stages", stages),
            ),
        )
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolvedPipelineProfile is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "ResolvedPipelineProfile":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "ResolvedPipelineProfile("
            f"registry_revision={self.registry_revision!r}, "
            f"availability={self.availability.value!r}, "
            f"pipeline_profile_id={self.pipeline_profile.pipeline_profile_id!r}, "
            f"registry_digest_prefix={_short_digest(self.registry_digest)!r})"
        )

    def safe_metadata(self) -> dict[str, object]:
        return {
            "registry_revision": self.registry_revision,
            "registry_digest_prefix": _short_digest(self.registry_digest),
            "availability": self.availability.value,
            "pipeline_profile_id": self.pipeline_profile.pipeline_profile_id,
            "stage_count": len(self.stages),
        }

    def validate_integrity(self) -> None:
        self.pipeline_profile.validate_integrity()
        expected_availability = (
            Availability.EXPERIMENTAL
            if self.pipeline_profile.enabled
            else Availability.DISABLED
        )
        if self.availability is not expected_availability:
            raise RegistryIntegrityError(
                "resolved pipeline availability lacks exact Registry evidence"
            )
        if tuple(stage.stage_binding for stage in self.stages) != (
            self.pipeline_profile.stage_bindings
        ):
            raise RegistryIntegrityError(
                "resolved stages do not match the pipeline profile"
            )
        for stage in self.stages:
            stage.validate_integrity()
            if (
                stage.registry_revision != self.registry_revision
                or stage.registry_digest != self.registry_digest
                or stage.availability is not self.availability
            ):
                raise RegistryIntegrityError(
                    "resolved pipeline mixes Registry generations"
                )


@runtime_final
class RegistrySnapshot:
    """A content-addressed, deeply immutable Registry generation."""

    __slots__ = (
        "registry_revision",
        "published_at",
        "authority",
        "provider_profiles",
        "capability_snapshots",
        "pipeline_profiles",
        "registry_digest",
    )

    def __init__(
        self,
        *,
        registry_revision: str,
        published_at: datetime,
        authority: RegistryAuthority,
        provider_profiles: tuple[ProviderProfileSnapshot, ...],
        capability_snapshots: tuple[ModelCapabilitiesSnapshot, ...],
        pipeline_profiles: tuple[PipelineProfileSnapshot, ...],
    ) -> None:
        require_text(registry_revision, "registry_revision", max_length=512)
        require_aware_datetime(published_at, "published_at")
        if type(authority) is not RegistryAuthority:
            raise ValueError("authority must be RegistryAuthority")
        self._validate_canonical_collection(
            provider_profiles,
            ProviderProfileSnapshot,
            "provider_profiles",
            lambda item: item.provider_profile_id,
        )
        self._validate_canonical_collection(
            capability_snapshots,
            ModelCapabilitiesSnapshot,
            "capability_snapshots",
            lambda item: item.capabilities_ref,
        )
        self._validate_canonical_collection(
            pipeline_profiles,
            PipelineProfileSnapshot,
            "pipeline_profiles",
            lambda item: item.pipeline_profile_id,
        )

        _set_attributes(
            self,
            (
                ("registry_revision", registry_revision),
                ("published_at", published_at),
                ("authority", authority),
                ("provider_profiles", provider_profiles),
                ("capability_snapshots", capability_snapshots),
                ("pipeline_profiles", pipeline_profiles),
            ),
        )
        self._validate_graph()
        object.__setattr__(
            self,
            "registry_digest",
            digest256(
                "RegistrySnapshot",
                REGISTRY_SNAPSHOT_SCHEMA_VERSION,
                self.as_digest_payload(),
            ),
        )

    @staticmethod
    def _validate_canonical_collection(
        values: object,
        expected_type: type,
        name: str,
        key,
    ) -> None:
        if type(values) is not tuple or not values:
            raise RegistryIntegrityError(f"{name} must be a non-empty tuple")
        if not all(type(value) is expected_type for value in values):
            raise RegistryIntegrityError(f"{name} contain an invalid value")
        keys = tuple(key(value) for value in values)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise RegistryIntegrityError(f"{name} must use unique, sorted keys")

    def _validate_graph(self) -> None:
        providers = {
            profile.provider_profile_id: profile for profile in self.provider_profiles
        }
        capabilities_by_ref = {
            capability.capabilities_ref: capability
            for capability in self.capability_snapshots
        }
        capability_exact_keys: set[tuple[str, str]] = set()

        for provider in self.provider_profiles:
            try:
                provider.validate_integrity()
            except ValueError as error:
                raise RegistryIntegrityError("provider profile integrity failure") from error
            if (
                self.authority is RegistryAuthority.CUSTOM
                and provider.compute_location.value == "local_verified"
            ):
                raise RegistryIntegrityError(
                    "custom Registry cannot claim local_verified compute"
                )
            if (
                self.authority is RegistryAuthority.CUSTOM
                and provider.fixed_non_secret_parameters
            ):
                raise RegistryIntegrityError(
                    "custom Registry cannot supply adapter parameters"
                )

        for capability in self.capability_snapshots:
            try:
                capability.validate_integrity()
            except ValueError as error:
                raise RegistryIntegrityError("capability integrity failure") from error
            provider = providers.get(capability.provider_profile_id)
            if (
                provider is None
                or provider.provider_profile_digest
                != capability.provider_profile_digest
                or provider.provider_id != capability.provider_id
                or provider.api_version != capability.api_version
                or provider.network_scope is not capability.network_scope
                or provider.compute_location is not capability.compute_location
                or provider.provider_application_state
                is not capability.provider_application_state
            ):
                raise RegistryIntegrityError(
                    "capability does not match an exact provider profile"
                )
            exact_key = (capability.provider_profile_id, capability.model_id)
            if exact_key in capability_exact_keys:
                raise RegistryIntegrityError(
                    "duplicate exact provider-profile/model capability"
                )
            capability_exact_keys.add(exact_key)

        for pipeline in self.pipeline_profiles:
            try:
                pipeline.validate_integrity()
            except ValueError as error:
                raise RegistryIntegrityError("pipeline profile integrity failure") from error
            if pipeline.pipeline_kind is not PipelineKind.DIRECT_MULTIMODAL:
                raise RegistryIntegrityError("only direct_multimodal is available in Phase 1")
            for binding in pipeline.stage_bindings:
                self._validate_binding(binding, providers, capabilities_by_ref)

            direct_binding = pipeline.stage_bindings[0]
            capability = capabilities_by_ref[direct_binding.capabilities_ref]
            provider = providers[direct_binding.provider_profile_id]
            if CapabilityRole.MULTIMODAL_SOLVER not in capability.roles:
                raise RegistryIntegrityError("direct pipeline lacks multimodal capability")
            if direct_binding.selected_image_input not in (
                ImageInputKind.DATA_URI,
                ImageInputKind.RAW_BASE64,
            ):
                raise RegistryIntegrityError(
                    "Phase 1 direct pipeline requires an inline image encoding"
                )
            if pipeline.max_output_tokens > capability.max_output_tokens:
                raise RegistryIntegrityError("pipeline output limit exceeds capability")
            if (
                pipeline.max_image_bytes > capability.max_image_bytes
                or pipeline.max_image_pixels > capability.max_image_pixels
            ):
                raise RegistryIntegrityError("pipeline image limit exceeds capability")
            operations = provider.endpoint_policy.operation_templates
            if len(operations) != 1:
                raise RegistryIntegrityError("Phase 1 direct profile requires one operation")
            operation = operations[0]
            if (
                operation.purpose is not NetworkOperationPurpose.INFERENCE
                or OutboundDataKind.IMAGE not in operation.outbound_data
            ):
                raise RegistryIntegrityError(
                    "Phase 1 direct operation must be inline image inference"
                )
            if provider.cost_policy != pipeline.cost_policy:
                raise RegistryIntegrityError(
                    "provider and pipeline cost policies must be identical"
                )
            billable_operation_count = 1 if (
                operation.billable is True
                or operation.billable is ContractMarker.UNKNOWN
            ) else 0
            if billable_operation_count:
                if pipeline.cost_policy is ContractMarker.NOT_APPLICABLE:
                    raise RegistryIntegrityError(
                        "potentially billable operation requires a cost policy"
                    )
                if not (
                    billable_operation_count
                    <= pipeline.max_billable_calls
                    <= pipeline.max_network_calls_total
                ):
                    raise RegistryIntegrityError(
                        "billable budget does not cover the operation"
                    )
            elif pipeline.max_billable_calls != 0:
                raise RegistryIntegrityError(
                    "non-billable operation requires a zero billable budget"
                )

    @staticmethod
    def _validate_binding(
        binding: StageBindingSnapshot,
        providers: dict[str, ProviderProfileSnapshot],
        capabilities_by_ref: dict[str, ModelCapabilitiesSnapshot],
    ) -> None:
        try:
            binding.validate_integrity()
        except ValueError as error:
            raise RegistryIntegrityError("stage binding integrity failure") from error
        provider = providers.get(binding.provider_profile_id)
        capability = capabilities_by_ref.get(binding.capabilities_ref)
        if provider is None or capability is None:
            raise RegistryIntegrityError("stage binding references an unknown snapshot")
        if (
            provider.provider_profile_digest != binding.provider_profile_digest
            or provider.provider_id != binding.provider_id
            or provider.adapter_family != binding.adapter_family
            or provider.adapter_version != binding.adapter_version
            or provider.api_version != binding.api_version
            or provider.provider_application_state
            is not binding.provider_application_state
            or provider.fixed_non_secret_parameters
            != binding.fixed_non_secret_parameters
            or capability.capabilities_digest != binding.capabilities_digest
            or capability.provider_profile_id != binding.provider_profile_id
            or capability.model_id != binding.model_id
        ):
            raise RegistryIntegrityError("stage binding mixes snapshot generations")
        if (
            binding.role is StageRole.SOLVER
            and CapabilityRole.MULTIMODAL_SOLVER not in capability.roles
        ):
            raise RegistryIntegrityError("solver binding lacks multimodal capability")
        if (
            binding.role is StageRole.TEXT_SOLVER
            and CapabilityRole.TEXT_SOLVER not in capability.roles
        ):
            raise RegistryIntegrityError("text solver binding lacks text capability")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("RegistrySnapshot is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "RegistrySnapshot":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "RegistrySnapshot("
            f"registry_revision={self.registry_revision!r}, "
            f"authority={self.authority.value!r}, "
            f"provider_count={len(self.provider_profiles)!r}, "
            f"capability_count={len(self.capability_snapshots)!r}, "
            f"pipeline_count={len(self.pipeline_profiles)!r}, "
            f"registry_digest_prefix={_short_digest(self.registry_digest)!r})"
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "registry_revision": self.registry_revision,
            "published_at": self.published_at,
            "authority": self.authority.value,
            "provider_profiles": tuple(
                {
                    "provider_profile_digest": profile.provider_profile_digest,
                    "provider_profile": profile.as_digest_payload(),
                }
                for profile in self.provider_profiles
            ),
            "capability_snapshots": tuple(
                {
                    "capabilities_digest": capability.capabilities_digest,
                    "capabilities": capability.as_digest_payload(),
                }
                for capability in self.capability_snapshots
            ),
            "pipeline_profiles": tuple(
                {
                    "pipeline_profile_digest": pipeline.pipeline_profile_digest,
                    "pipeline_profile": pipeline.as_digest_payload(),
                }
                for pipeline in self.pipeline_profiles
            ),
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "RegistrySnapshot",
            REGISTRY_SNAPSHOT_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        self._validate_canonical_collection(
            self.provider_profiles,
            ProviderProfileSnapshot,
            "provider_profiles",
            lambda item: item.provider_profile_id,
        )
        self._validate_canonical_collection(
            self.capability_snapshots,
            ModelCapabilitiesSnapshot,
            "capability_snapshots",
            lambda item: item.capabilities_ref,
        )
        self._validate_canonical_collection(
            self.pipeline_profiles,
            PipelineProfileSnapshot,
            "pipeline_profiles",
            lambda item: item.pipeline_profile_id,
        )
        self._validate_graph()
        if self.recompute_digest() != self.registry_digest:
            raise RegistryIntegrityError("Registry snapshot integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "registry_revision": self.registry_revision,
            "authority": self.authority.value,
            "provider_count": len(self.provider_profiles),
            "capability_count": len(self.capability_snapshots),
            "pipeline_count": len(self.pipeline_profiles),
            "registry_digest_prefix": _short_digest(self.registry_digest),
        }

    def require_provider_profile(self, provider_profile_id: str) -> ProviderProfileSnapshot:
        require_text(provider_profile_id, "provider_profile_id", max_length=512)
        for profile in self.provider_profiles:
            if profile.provider_profile_id == provider_profile_id:
                return profile
        raise RegistryLookupError(entry_kind="provider_profile")

    def require_capabilities(
        self, *, provider_profile_id: str, model_id: str
    ) -> ModelCapabilitiesSnapshot:
        require_text(provider_profile_id, "provider_profile_id", max_length=512)
        require_text(model_id, "model_id", max_length=512)
        for capability in self.capability_snapshots:
            if (
                capability.provider_profile_id == provider_profile_id
                and capability.model_id == model_id
            ):
                return capability
        raise RegistryLookupError(entry_kind="model_capability")

    def require_capabilities_ref(self, capabilities_ref: str) -> ModelCapabilitiesSnapshot:
        require_text(capabilities_ref, "capabilities_ref", max_length=512)
        for capability in self.capability_snapshots:
            if capability.capabilities_ref == capabilities_ref:
                return capability
        raise RegistryLookupError(entry_kind="capability_ref")

    def require_pipeline_profile(self, pipeline_profile_id: str) -> PipelineProfileSnapshot:
        require_text(pipeline_profile_id, "pipeline_profile_id", max_length=512)
        for profile in self.pipeline_profiles:
            if profile.pipeline_profile_id == pipeline_profile_id:
                return profile
        raise RegistryLookupError(entry_kind="pipeline_profile")

    def resolve_pipeline(self, pipeline_profile_id: str) -> ResolvedPipelineProfile:
        self.validate_integrity()
        pipeline = self.require_pipeline_profile(pipeline_profile_id)
        availability = (
            Availability.EXPERIMENTAL if pipeline.enabled else Availability.DISABLED
        )
        resolved_stages = tuple(
            ResolvedStageBinding(
                registry_revision=self.registry_revision,
                registry_digest=self.registry_digest,
                availability=availability,
                stage_binding=binding,
                provider_profile=self.require_provider_profile(
                    binding.provider_profile_id
                ),
                capabilities=self.require_capabilities_ref(binding.capabilities_ref),
                _authority=_RESOLUTION_AUTHORITY,
            )
            for binding in pipeline.stage_bindings
        )
        return ResolvedPipelineProfile(
            registry_revision=self.registry_revision,
            registry_digest=self.registry_digest,
            availability=availability,
            pipeline_profile=pipeline,
            stages=resolved_stages,
            _authority=_RESOLUTION_AUTHORITY,
        )


__all__ = [
    "REGISTRY_SNAPSHOT_SCHEMA_VERSION",
    "Availability",
    "RegistryAuthority",
    "RegistryIntegrityError",
    "RegistryLookupError",
    "RegistrySnapshot",
    "ResolvedPipelineProfile",
    "ResolvedStageBinding",
]
