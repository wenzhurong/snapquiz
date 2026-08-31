"""Process-local Registry and transport-policy authority for W09.

The routing Registry is immutable, but a long-lived process can replace its
current generation.  A digest match alone is therefore not live authority.
This module issues an exact-object lease and keeps its current status behind a
ledger lock.  It deliberately performs no environment, credential, capture,
SDK, DNS, or network work.
"""
from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Callable, TypeVar
from uuid import UUID, uuid5

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.routing.planner import PlannedExecution
from snapquiz.routing.registry import RegistrySnapshot


REGISTRY_POLICY_LEASE_SCHEMA_VERSION = "snapquiz.registry-policy-lease.v1"
REGISTRY_POLICY_AUTHORITY_VERSION = "snapquiz.registry-policy-authority.v1"
TRANSPORT_BINDING_SCHEMA_VERSION = "snapquiz.transport-binding.v1"

_LEASE_AUTHORITY = object()
_CONTEXT_AUTHORITY = object()
_ATTEMPT_AUTHORITY = object()
_LEASE_UUID_NAMESPACE = UUID("c9d84f4f-2934-53cb-815d-f21b99171038")
_T = TypeVar("_T")


def _authority_error(
    message: str = "当前注册表或传输策略授权不可用。",
    *,
    stage: str = "registry_policy_authority",
) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage=stage,
        safe_message=message,
        retryable=False,
    )


def _short_digest(value: Digest256) -> str:
    return str(value)[:12]


def _transport_binding_payload(planned: PlannedExecution) -> dict[str, object]:
    """Return every Registry-backed value that can affect an outbound call."""

    resolved = planned.resolved_pipeline
    return {
        "authority_version": REGISTRY_POLICY_AUTHORITY_VERSION,
        "plan_id": planned.plan.plan_id,
        "plan_digest": planned.plan.plan_digest,
        "planned_execution_digest": planned.planned_execution_digest,
        "registry_revision": resolved.registry_revision,
        "registry_digest": resolved.registry_digest,
        "pipeline_profile_digest": (
            resolved.pipeline_profile.pipeline_profile_digest
        ),
        "pipeline_profile": resolved.pipeline_profile.as_digest_payload(),
        "stages": tuple(
            {
                "plan_stage": plan_stage.as_digest_payload(),
                "stage_binding_digest": (
                    resolved_stage.stage_binding.stage_binding_digest
                ),
                "stage_binding": resolved_stage.stage_binding.as_digest_payload(),
                "provider_profile_digest": (
                    resolved_stage.provider_profile.provider_profile_digest
                ),
                "provider_profile": (
                    resolved_stage.provider_profile.as_digest_payload()
                ),
                "endpoint_policy_digest": (
                    resolved_stage.provider_profile.endpoint_policy.endpoint_policy_digest
                ),
                "capabilities_digest": (
                    resolved_stage.capabilities.capabilities_digest
                ),
            }
            for plan_stage, resolved_stage in zip(
                planned.plan.stages,
                resolved.stages,
            )
        ),
    }


def _transport_binding_digest(planned: PlannedExecution) -> Digest256:
    return digest256(
        "RegistryPolicyTransportBinding",
        TRANSPORT_BINDING_SCHEMA_VERSION,
        _transport_binding_payload(planned),
    )


def _lease_identifier_payload(lease: "RegistryPolicyLease") -> dict[str, object]:
    return {
        "authority_version": lease.authority_version,
        "request_id": lease.request_id,
        "plan_id": lease.plan_id,
        "plan_digest": lease.plan_digest,
        "planned_execution_digest": lease.planned_execution_digest,
        "registry_revision": lease.registry_revision,
        "registry_digest": lease.registry_digest,
        "pipeline_profile_id": lease.pipeline_profile_id,
        "pipeline_profile_digest": lease.pipeline_profile_digest,
        "transport_binding_digest": lease.transport_binding_digest,
        "authority_epoch": lease.authority_epoch,
        "issued_at": lease.issued_at,
    }


def _lease_id_for(payload: dict[str, object]) -> UUID:
    seed = digest256(
        "RegistryPolicyLeaseIdentifier",
        REGISTRY_POLICY_LEASE_SCHEMA_VERSION,
        payload,
    )
    return uuid5(_LEASE_UUID_NAMESPACE, str(seed))


def _lease_terms_payload(lease: "RegistryPolicyLease") -> dict[str, object]:
    return {
        "lease_id": lease.lease_id,
        **_lease_identifier_payload(lease),
    }


def _planned_matches_exact_registry(
    planned: object,
    registry: RegistrySnapshot,
) -> bool:
    """Check exact Registry-generation identity without leaking bad input."""

    if type(planned) is not PlannedExecution:
        return False
    valid = True
    try:
        planned.validate_integrity()
        registry.validate_integrity()
        resolved = planned.resolved_pipeline
        profile = registry.require_pipeline_profile(
            planned.plan.pipeline_profile_id
        )
        if (
            resolved.registry_revision != registry.registry_revision
            or resolved.registry_digest != registry.registry_digest
            or resolved.pipeline_profile is not profile
            or planned.plan.pipeline_profile_digest
            != profile.pipeline_profile_digest
            or len(planned.plan.stages) != len(resolved.stages)
            or len(resolved.stages) != len(profile.stage_bindings)
        ):
            valid = False
        if valid:
            for plan_stage, resolved_stage, binding in zip(
                planned.plan.stages,
                resolved.stages,
                profile.stage_bindings,
            ):
                provider = registry.require_provider_profile(
                    plan_stage.provider_profile_id
                )
                capabilities = registry.require_capabilities_ref(
                    plan_stage.capabilities_ref
                )
                if (
                    resolved_stage.registry_revision
                    != registry.registry_revision
                    or resolved_stage.registry_digest != registry.registry_digest
                    or resolved_stage.stage_binding is not binding
                    or resolved_stage.provider_profile is not provider
                    or resolved_stage.capabilities is not capabilities
                    or plan_stage.provider_profile_digest
                    != provider.provider_profile_digest
                    or plan_stage.capabilities_digest
                    != capabilities.capabilities_digest
                    or plan_stage.endpoint_policy_version
                    != provider.endpoint_policy.endpoint_policy_version
                    or plan_stage.network_policy_version
                    != provider.endpoint_policy.network_policy_version
                    or plan_stage.tls_policy_ref
                    != provider.endpoint_policy.tls_policy_ref
                ):
                    valid = False
                    break
    except (ValueError, TypeError, AttributeError, LookupError):
        valid = False
    return valid


@runtime_final
class RegistryPolicyLease:
    """Factory-only immutable lease for one exact Registry generation."""

    __slots__ = (
        "lease_id",
        "authority_version",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "registry_revision",
        "registry_digest",
        "pipeline_profile_id",
        "pipeline_profile_digest",
        "transport_binding_digest",
        "authority_epoch",
        "issued_at",
        "lease_terms_digest",
        "lease_digest",
        "_registry_snapshot",
        "_planned_execution",
        "_authority_ledger",
    )

    def __init__(
        self,
        *,
        planned: PlannedExecution,
        registry: RegistrySnapshot,
        authority_epoch: int,
        issued_at: datetime,
        authority_ledger: "RegistryPolicyAuthorityLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _LEASE_AUTHORITY:
            raise TypeError(
                "RegistryPolicyLease can only be created by "
                "RegistryPolicyAuthorityLedger"
            )
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(registry) is not RegistrySnapshot:
            raise TypeError("registry must be RegistrySnapshot")
        require_plain_int(authority_epoch, "authority_epoch", minimum=1)
        require_aware_datetime(issued_at, "issued_at")
        if type(authority_ledger) is not RegistryPolicyAuthorityLedger:
            raise TypeError(
                "authority_ledger must be RegistryPolicyAuthorityLedger"
            )
        values = (
            ("authority_version", REGISTRY_POLICY_AUTHORITY_VERSION),
            ("request_id", planned.plan.request_id),
            ("plan_id", planned.plan.plan_id),
            ("plan_digest", planned.plan.plan_digest),
            ("planned_execution_digest", planned.planned_execution_digest),
            ("registry_revision", registry.registry_revision),
            ("registry_digest", registry.registry_digest),
            ("pipeline_profile_id", planned.plan.pipeline_profile_id),
            ("pipeline_profile_digest", planned.plan.pipeline_profile_digest),
            ("transport_binding_digest", _transport_binding_digest(planned)),
            ("authority_epoch", authority_epoch),
            ("issued_at", issued_at),
            ("_registry_snapshot", registry),
            ("_planned_execution", planned),
            ("_authority_ledger", authority_ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "lease_id",
            _lease_id_for(_lease_identifier_payload(self)),
        )
        object.__setattr__(
            self,
            "lease_terms_digest",
            digest256(
                "RegistryPolicyLeaseTerms",
                REGISTRY_POLICY_LEASE_SCHEMA_VERSION,
                _lease_terms_payload(self),
            ),
        )
        object.__setattr__(
            self,
            "lease_digest",
            digest256(
                "RegistryPolicyLease",
                REGISTRY_POLICY_LEASE_SCHEMA_VERSION,
                {"lease_terms_digest": self.lease_terms_digest},
            ),
        )
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("RegistryPolicyLease is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "RegistryPolicyLease":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "RegistryPolicyLease("
            f"lease_id={self.lease_id!r}, request_id={self.request_id!r}, "
            f"registry_revision={self.registry_revision!r}, "
            f"authority_epoch={self.authority_epoch!r}, "
            f"transport_binding_digest_prefix="
            f"{_short_digest(self.transport_binding_digest)!r})"
        )

    def validate_integrity(self) -> None:
        for name in ("lease_id", "request_id", "plan_id"):
            require_uuid(getattr(self, name), name)
        for name in (
            "plan_digest",
            "planned_execution_digest",
            "registry_digest",
            "pipeline_profile_digest",
            "transport_binding_digest",
            "lease_terms_digest",
            "lease_digest",
        ):
            require_digest(getattr(self, name), name)
        require_text(self.authority_version, "authority_version", max_length=256)
        if self.authority_version != REGISTRY_POLICY_AUTHORITY_VERSION:
            raise ValueError("unsupported registry-policy authority version")
        require_text(self.registry_revision, "registry_revision", max_length=512)
        require_text(
            self.pipeline_profile_id,
            "pipeline_profile_id",
            max_length=512,
        )
        require_plain_int(self.authority_epoch, "authority_epoch", minimum=1)
        require_aware_datetime(self.issued_at, "issued_at")
        if type(self._registry_snapshot) is not RegistrySnapshot:
            raise ValueError("lease Registry authority changed")
        if type(self._planned_execution) is not PlannedExecution:
            raise ValueError("lease plan authority changed")
        if type(self._authority_ledger) is not RegistryPolicyAuthorityLedger:
            raise ValueError("lease ledger authority changed")
        planned = self._planned_execution
        registry = self._registry_snapshot
        if (
            not _planned_matches_exact_registry(planned, registry)
            or self.request_id != planned.plan.request_id
            or self.plan_id != planned.plan.plan_id
            or self.plan_digest != planned.plan.plan_digest
            or self.planned_execution_digest
            != planned.planned_execution_digest
            or self.registry_revision != registry.registry_revision
            or self.registry_digest != registry.registry_digest
            or self.pipeline_profile_id != planned.plan.pipeline_profile_id
            or self.pipeline_profile_digest
            != planned.plan.pipeline_profile_digest
            or self.transport_binding_digest != _transport_binding_digest(planned)
            or self.lease_id
            != _lease_id_for(_lease_identifier_payload(self))
        ):
            raise ValueError("registry-policy lease binding changed")
        if self.lease_terms_digest != digest256(
            "RegistryPolicyLeaseTerms",
            REGISTRY_POLICY_LEASE_SCHEMA_VERSION,
            _lease_terms_payload(self),
        ):
            raise ValueError("registry-policy lease terms changed")
        if self.lease_digest != digest256(
            "RegistryPolicyLease",
            REGISTRY_POLICY_LEASE_SCHEMA_VERSION,
            {"lease_terms_digest": self.lease_terms_digest},
        ):
            raise ValueError("registry-policy lease integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "lease_id": str(self.lease_id),
            "request_id": str(self.request_id),
            "plan_id": str(self.plan_id),
            "registry_revision": self.registry_revision,
            "registry_digest_prefix": _short_digest(self.registry_digest),
            "pipeline_profile_id": self.pipeline_profile_id,
            "transport_binding_digest_prefix": _short_digest(
                self.transport_binding_digest
            ),
            "authority_epoch": self.authority_epoch,
            "issued_at": self.issued_at,
        }


@runtime_final
class RegistryPolicyAuthorityLedger:
    """Live exact-generation authority for Registry-policy leases."""

    __slots__ = (
        "_registry",
        "_leases",
        "_current_digests",
        "_request_ids",
        "_lock",
        "_epoch",
        "_revision",
        "_revoked",
    )

    def __init__(self, registry: RegistrySnapshot) -> None:
        if type(registry) is not RegistrySnapshot:
            raise TypeError("registry must be RegistrySnapshot")
        valid = True
        try:
            registry.validate_integrity()
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise _authority_error("注册表完整性校验失败。")
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(self, "_leases", {})
        object.__setattr__(self, "_current_digests", {})
        object.__setattr__(self, "_request_ids", {})
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_epoch", 1)
        object.__setattr__(self, "_revision", 0)
        object.__setattr__(self, "_revoked", False)

    def _require_current_lease_locked(
        self,
        *,
        lease: RegistryPolicyLease,
        planned: PlannedExecution,
    ) -> None:
        valid = type(lease) is RegistryPolicyLease
        if valid:
            try:
                lease.validate_integrity()
            except (ValueError, TypeError, AttributeError):
                valid = False
        if (
            not valid
            or self._revoked
            or lease._authority_ledger is not self
            or lease._registry_snapshot is not self._registry
            or lease._planned_execution is not planned
            or lease.authority_epoch != self._epoch
            or self._leases.get(lease.lease_id) is not lease
            or self._current_digests.get(lease.lease_id)
            != lease.lease_digest
            or self._request_ids.get(lease.request_id) != lease.lease_id
            or not _planned_matches_exact_registry(planned, self._registry)
        ):
            raise _authority_error(
                "注册表或传输策略授权已经变化。",
                stage="attempt_gate",
            )

    def _issue_with(
        self,
        *,
        planned: PlannedExecution,
        issued_at: datetime,
        action: Callable[[RegistryPolicyLease], _T],
        _authority: object | None = None,
    ) -> _T:
        """Issue under the authority lock, then enter CallContext's lock."""

        if _authority is not _CONTEXT_AUTHORITY:
            raise TypeError("registry-policy leases require RuntimeCallFactory")
        require_aware_datetime(issued_at, "issued_at")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._lock:
            if self._revoked or not _planned_matches_exact_registry(
                planned,
                self._registry,
            ):
                raise _authority_error(
                    "执行计划不属于当前注册表或策略世代。",
                    stage="call_context_factory",
                )
            if planned.plan.request_id in self._request_ids:
                raise _authority_error(
                    "当前请求已经创建注册表策略授权。",
                    stage="call_context_factory",
                )
            lease = RegistryPolicyLease(
                planned=planned,
                registry=self._registry,
                authority_epoch=self._epoch,
                issued_at=issued_at,
                authority_ledger=self,
                _authority=_LEASE_AUTHORITY,
            )
            self._leases[lease.lease_id] = lease
            self._current_digests[lease.lease_id] = lease.lease_digest
            self._request_ids[lease.request_id] = lease.lease_id
            try:
                result = action(lease)
            except BaseException:
                # The callback is a pure CallContext construction.  Roll back
                # the unpublished lease while this authority lock is held.
                del self._request_ids[lease.request_id]
                del self._current_digests[lease.lease_id]
                del self._leases[lease.lease_id]
                raise
            object.__setattr__(self, "_revision", self._revision + 1)
            return result

    def _run_active_action(
        self,
        *,
        lease: RegistryPolicyLease,
        planned: PlannedExecution,
        action: Callable[[], _T],
        _authority: object | None = None,
    ) -> _T:
        """Run AttemptGate checks under the current authority revision."""

        if _authority is not _ATTEMPT_AUTHORITY:
            raise TypeError("registry-policy checks require AttemptGate")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._lock:
            self._require_current_lease_locked(
                lease=lease,
                planned=planned,
            )
            return action()

    def snapshot(self, lease_id: UUID) -> RegistryPolicyLease:
        require_uuid(lease_id, "lease_id")
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise _authority_error("注册表策略授权不存在。")
            self._require_current_lease_locked(
                lease=lease,
                planned=lease._planned_execution,
            )
            return lease

    def revoke(self) -> None:
        """Invalidate every issued lease until an explicit Registry reload."""

        with self._lock:
            object.__setattr__(self, "_revoked", True)
            object.__setattr__(self, "_epoch", self._epoch + 1)
            object.__setattr__(self, "_revision", self._revision + 1)

    def reload(self, registry: RegistrySnapshot) -> None:
        """Activate one exact Registry object and invalidate older leases."""

        if type(registry) is not RegistrySnapshot:
            raise TypeError("registry must be RegistrySnapshot")
        valid = True
        try:
            registry.validate_integrity()
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise _authority_error("注册表完整性校验失败。")
        with self._lock:
            object.__setattr__(self, "_registry", registry)
            object.__setattr__(self, "_revoked", False)
            object.__setattr__(self, "_epoch", self._epoch + 1)
            object.__setattr__(self, "_revision", self._revision + 1)

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "revision": self._revision,
                "authority_epoch": self._epoch,
                "revoked": self._revoked,
                "registry_revision": self._registry.registry_revision,
                "registry_digest_prefix": _short_digest(
                    self._registry.registry_digest
                ),
                "lease_count": len(self._leases),
            }


__all__ = [
    "REGISTRY_POLICY_AUTHORITY_VERSION",
    "REGISTRY_POLICY_LEASE_SCHEMA_VERSION",
    "TRANSPORT_BINDING_SCHEMA_VERSION",
    "RegistryPolicyAuthorityLedger",
    "RegistryPolicyLease",
]
