"""Plan-bound, side-effect-free capture authorization for W06."""
from __future__ import annotations

from datetime import datetime
from threading import RLock
from uuid import UUID, uuid5

from snapquiz.capture.topology import DisplayTopologySnapshot
from snapquiz.core.permissions import PermissionGate, PermissionObservation
from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.capture import (
    CaptureArtifact,
    CaptureConstraints,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CaptureError
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentLedger,
    PrivacyGate,
    _ATOMIC_PRIVACY_AUTHORITY,
)
from snapquiz.routing.planner import PlannedExecution

CAPTURE_AUTHORIZATION_SCHEMA_VERSION = "snapquiz.capture-authorization.v1"
CAPTURE_ARTIFACT_CLAIM_SCHEMA_VERSION = "snapquiz.capture-artifact-claim.v1"
CAPTURE_POLICY_VERSION = "snapquiz.capture-policy.phase1-physical-region.v1"

_CAPTURE_AUTHORITY = object()
_CAPTURE_CONSUMPTION_AUTHORITY = object()
_CAPTURE_LEDGER_AUTHORITY = object()
_CAPTURE_ARTIFACT_AUTHORITY = object()
_CAPTURE_VALIDATION_AUTHORITY = object()
_CAPTURE_UUID_NAMESPACE = UUID("8b1249e6-08cb-50df-a318-2772e936a729")


def _capture_error(message: str) -> CaptureError:
    return CaptureError(stage="capture_policy", safe_message=message)


def _capture_artifact_claim_digest(artifact: CaptureArtifact) -> Digest256:
    if type(artifact) is not CaptureArtifact:
        raise TypeError("artifact must be CaptureArtifact")
    artifact.validate_integrity()
    return digest256(
        "CaptureArtifactClaim",
        CAPTURE_ARTIFACT_CLAIM_SCHEMA_VERSION,
        {
            "capture_id": artifact.id,
            "artifact_sha256": artifact.sha256,
            "mime_type": artifact.mime_type,
            "width_px": artifact.width_px,
            "height_px": artifact.height_px,
            "scope_fingerprint": artifact.scope.fingerprint,
            "captured_at": artifact.captured_at,
            "byte_size": artifact.byte_size,
        },
    )


def _constraints_payload(value: CaptureConstraints) -> dict[str, object]:
    return {
        "allowed_display_ids": value.allowed_display_ids,
        "display_topology_revision": value.display_topology_revision,
        "max_width_px": value.max_width_px,
        "max_height_px": value.max_height_px,
        "max_pixels": value.max_pixels,
        "max_bytes": value.max_bytes,
        "allow_full_screen": value.allow_full_screen,
    }


def _scope_payload(value: CaptureScope) -> dict[str, object]:
    return {
        "kind": value.kind.value,
        "display_id": value.display_id,
        "coordinate_space": value.coordinate_space.value,
        "rect": value.rect.as_digest_payload() if value.rect is not None else None,
        "display_geometry_revision": value.display_geometry_revision,
        "fingerprint": value.fingerprint,
    }


def _authorization_identifier_payload(
    *,
    capture_id: UUID,
    request_id: UUID,
    plan_id: UUID,
    plan_digest: Digest256,
    planned_execution_digest: Digest256,
    privacy_authorization_id: UUID,
    privacy_authorization_digest: Digest256,
    permission_observation_digest: Digest256,
    topology_revision: Digest256,
    scope: CaptureScope,
    constraints: CaptureConstraints,
    authorized_at: datetime,
    valid_until: datetime | None,
) -> dict[str, object]:
    return {
        "policy_version": CAPTURE_POLICY_VERSION,
        "capture_id": capture_id,
        "request_id": request_id,
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "planned_execution_digest": planned_execution_digest,
        "privacy_authorization_id": privacy_authorization_id,
        "privacy_authorization_digest": privacy_authorization_digest,
        "permission_observation_digest": permission_observation_digest,
        "topology_revision": topology_revision,
        "scope": _scope_payload(scope),
        "constraints": _constraints_payload(constraints),
        "authorized_at": authorized_at,
        "valid_until": valid_until,
    }


def _capture_authorization_id_for(payload: dict[str, object]) -> UUID:
    seed = digest256(
        "CaptureAuthorizationIdentifier",
        CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
        payload,
    )
    return uuid5(_CAPTURE_UUID_NAMESPACE, str(seed))


@runtime_final
class CaptureAuthorization:
    """One exact permission/topology/scope capability for an artifact id."""

    __slots__ = (
        "capture_authorization_id",
        "capture_id",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "privacy_authorization_id",
        "privacy_authorization_digest",
        "permission_observation_digest",
        "topology_revision",
        "scope",
        "constraints",
        "authorized_at",
        "valid_until",
        "capture_authorization_digest",
    )

    def __init__(
        self,
        *,
        capture_authorization_id: UUID,
        capture_id: UUID,
        request_id: UUID,
        plan_id: UUID,
        plan_digest: Digest256,
        planned_execution_digest: Digest256,
        privacy_authorization_id: UUID,
        privacy_authorization_digest: Digest256,
        permission_observation_digest: Digest256,
        topology_revision: Digest256,
        scope: CaptureScope,
        constraints: CaptureConstraints,
        authorized_at: datetime,
        valid_until: datetime | None,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_AUTHORITY:
            raise TypeError("CaptureAuthorization can only be created by CapturePolicy")
        for name, value in (
            ("capture_authorization_id", capture_authorization_id),
            ("capture_id", capture_id),
            ("request_id", request_id),
            ("plan_id", plan_id),
            ("privacy_authorization_id", privacy_authorization_id),
        ):
            require_uuid(value, name)
        for name, value in (
            ("plan_digest", plan_digest),
            ("planned_execution_digest", planned_execution_digest),
            ("privacy_authorization_digest", privacy_authorization_digest),
            ("permission_observation_digest", permission_observation_digest),
            ("topology_revision", topology_revision),
        ):
            require_digest(value, name)
        if type(scope) is not CaptureScope:
            raise ValueError("scope must be CaptureScope")
        scope.validate_integrity()
        if type(constraints) is not CaptureConstraints:
            raise ValueError("constraints must be CaptureConstraints")
        constraints.validate_integrity()
        require_aware_datetime(authorized_at, "authorized_at")
        if valid_until is not None:
            require_aware_datetime(valid_until, "valid_until")
            if valid_until <= authorized_at:
                raise ValueError("valid_until must be later than authorized_at")
        identifier_payload = _authorization_identifier_payload(
            capture_id=capture_id,
            request_id=request_id,
            plan_id=plan_id,
            plan_digest=plan_digest,
            planned_execution_digest=planned_execution_digest,
            privacy_authorization_id=privacy_authorization_id,
            privacy_authorization_digest=privacy_authorization_digest,
            permission_observation_digest=permission_observation_digest,
            topology_revision=topology_revision,
            scope=scope,
            constraints=constraints,
            authorized_at=authorized_at,
            valid_until=valid_until,
        )
        if capture_authorization_id != _capture_authorization_id_for(
            identifier_payload
        ):
            raise ValueError("capture authorization id does not bind its fields")
        for name, value in (
            ("capture_authorization_id", capture_authorization_id),
            ("capture_id", capture_id),
            ("request_id", request_id),
            ("plan_id", plan_id),
            ("plan_digest", plan_digest),
            ("planned_execution_digest", planned_execution_digest),
            ("privacy_authorization_id", privacy_authorization_id),
            ("privacy_authorization_digest", privacy_authorization_digest),
            ("permission_observation_digest", permission_observation_digest),
            ("topology_revision", topology_revision),
            ("scope", scope),
            ("constraints", constraints),
            ("authorized_at", authorized_at),
            ("valid_until", valid_until),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "capture_authorization_digest",
            digest256(
                "CaptureAuthorization",
                CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
                {
                    "capture_authorization_id": capture_authorization_id,
                    **identifier_payload,
                },
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CaptureAuthorization is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "CaptureAuthorization":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "CaptureAuthorization("
            f"capture_authorization_id={self.capture_authorization_id!r}, "
            f"capture_id={self.capture_id!r}, plan_id={self.plan_id!r}, "
            f"scope_fingerprint_prefix={str(self.scope.fingerprint)[:12]!r}, "
            f"valid_until={self.valid_until!r})"
        )

    def recompute_digest(self) -> Digest256:
        identifier_payload = _authorization_identifier_payload(
            capture_id=self.capture_id,
            request_id=self.request_id,
            plan_id=self.plan_id,
            plan_digest=self.plan_digest,
            planned_execution_digest=self.planned_execution_digest,
            privacy_authorization_id=self.privacy_authorization_id,
            privacy_authorization_digest=self.privacy_authorization_digest,
            permission_observation_digest=self.permission_observation_digest,
            topology_revision=self.topology_revision,
            scope=self.scope,
            constraints=self.constraints,
            authorized_at=self.authorized_at,
            valid_until=self.valid_until,
        )
        return digest256(
            "CaptureAuthorization",
            CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
            {
                "capture_authorization_id": self.capture_authorization_id,
                **identifier_payload,
            },
        )

    def validate_integrity(self) -> None:
        try:
            canonical = CaptureAuthorization(
                capture_authorization_id=self.capture_authorization_id,
                capture_id=self.capture_id,
                request_id=self.request_id,
                plan_id=self.plan_id,
                plan_digest=self.plan_digest,
                planned_execution_digest=self.planned_execution_digest,
                privacy_authorization_id=self.privacy_authorization_id,
                privacy_authorization_digest=self.privacy_authorization_digest,
                permission_observation_digest=self.permission_observation_digest,
                topology_revision=self.topology_revision,
                scope=self.scope,
                constraints=self.constraints,
                authorized_at=self.authorized_at,
                valid_until=self.valid_until,
                _authority=_CAPTURE_AUTHORITY,
            )
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("capture authorization integrity mismatch") from error
        if canonical.capture_authorization_digest != self.capture_authorization_digest:
            raise ValueError("capture authorization integrity mismatch")


@runtime_final
class ConsumedCaptureAuthorization:
    """Proof that one capture authorization was atomically consumed."""

    __slots__ = (
        "authorization",
        "consumed_at",
        "pre_capture_permission_observation_digest",
        "pre_capture_topology_snapshot_digest",
        "consumption_digest",
    )

    def __init__(
        self,
        *,
        authorization: CaptureAuthorization,
        consumed_at: datetime,
        pre_capture_permission_observation_digest: Digest256,
        pre_capture_topology_snapshot_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_CONSUMPTION_AUTHORITY:
            raise TypeError(
                "ConsumedCaptureAuthorization can only be created by its ledger"
            )
        if type(authorization) is not CaptureAuthorization:
            raise ValueError("authorization must be CaptureAuthorization")
        authorization.validate_integrity()
        require_aware_datetime(consumed_at, "consumed_at")
        require_digest(
            pre_capture_permission_observation_digest,
            "pre_capture_permission_observation_digest",
        )
        require_digest(
            pre_capture_topology_snapshot_digest,
            "pre_capture_topology_snapshot_digest",
        )
        if consumed_at < authorization.authorized_at:
            raise ValueError("capture authorization cannot be consumed early")
        if (
            authorization.valid_until is not None
            and consumed_at >= authorization.valid_until
        ):
            raise ValueError("capture authorization has expired")
        object.__setattr__(self, "authorization", authorization)
        object.__setattr__(self, "consumed_at", consumed_at)
        object.__setattr__(
            self,
            "pre_capture_permission_observation_digest",
            pre_capture_permission_observation_digest,
        )
        object.__setattr__(
            self,
            "pre_capture_topology_snapshot_digest",
            pre_capture_topology_snapshot_digest,
        )
        object.__setattr__(
            self,
            "consumption_digest",
            digest256(
                "ConsumedCaptureAuthorization",
                CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
                {
                    "capture_authorization_id": (
                        authorization.capture_authorization_id
                    ),
                    "capture_authorization_digest": (
                        authorization.capture_authorization_digest
                    ),
                    "consumed_at": consumed_at,
                    "pre_capture_permission_observation_digest": (
                        pre_capture_permission_observation_digest
                    ),
                    "pre_capture_topology_snapshot_digest": (
                        pre_capture_topology_snapshot_digest
                    ),
                },
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ConsumedCaptureAuthorization is immutable")

    def validate_integrity(self) -> None:
        try:
            canonical = ConsumedCaptureAuthorization(
                authorization=self.authorization,
                consumed_at=self.consumed_at,
                pre_capture_permission_observation_digest=(
                    self.pre_capture_permission_observation_digest
                ),
                pre_capture_topology_snapshot_digest=(
                    self.pre_capture_topology_snapshot_digest
                ),
                _authority=_CAPTURE_CONSUMPTION_AUTHORITY,
            )
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("capture consumption integrity mismatch") from error
        if canonical.consumption_digest != self.consumption_digest:
            raise ValueError("capture consumption integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "capture_authorization_id": str(
                self.authorization.capture_authorization_id
            ),
            "capture_id": str(self.authorization.capture_id),
            "consumed_at": self.consumed_at,
            "pre_capture_permission_digest_prefix": str(
                self.pre_capture_permission_observation_digest
            )[:12],
            "pre_capture_topology_digest_prefix": str(
                self.pre_capture_topology_snapshot_digest
            )[:12],
            "consumption_digest_prefix": str(self.consumption_digest)[:12],
        }


@runtime_final
class CaptureAuthorizationLedger:
    """Process-local one-shot authority for capture attempts."""

    __slots__ = (
        "_authorizations",
        "_authorization_digests",
        "_capture_ids",
        "_consumptions",
        "_consumption_digests",
        "_artifact_attempts",
        "_artifact_claims",
        "_validation_attempts",
        "_validated",
        "_lock",
        "_revision",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "_authorizations", {})
        object.__setattr__(self, "_authorization_digests", {})
        object.__setattr__(self, "_capture_ids", {})
        object.__setattr__(self, "_consumptions", {})
        object.__setattr__(self, "_consumption_digests", {})
        object.__setattr__(self, "_artifact_attempts", set())
        object.__setattr__(self, "_artifact_claims", {})
        object.__setattr__(self, "_validation_attempts", set())
        object.__setattr__(self, "_validated", set())
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_revision", 0)

    def _issue(
        self,
        authorization: CaptureAuthorization,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_LEDGER_AUTHORITY:
            raise TypeError(
                "capture authorizations can only be issued by CapturePolicy"
            )
        if type(authorization) is not CaptureAuthorization:
            raise TypeError("authorization must be CaptureAuthorization")
        try:
            authorization.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _capture_error("截图授权完整性校验失败。") from error
        with self._lock:
            identifier = authorization.capture_authorization_id
            if identifier in self._authorizations:
                raise _capture_error("截图授权标识已存在。")
            if authorization.capture_id in self._capture_ids:
                raise _capture_error("截图图像标识已经绑定其他授权。")
            self._authorizations[identifier] = authorization
            self._authorization_digests[identifier] = (
                authorization.capture_authorization_digest
            )
            self._capture_ids[authorization.capture_id] = identifier
            object.__setattr__(self, "_revision", self._revision + 1)

    def _consume(
        self,
        *,
        authorization: CaptureAuthorization,
        now: datetime,
        pre_capture_permission_observation_digest: Digest256,
        pre_capture_topology_snapshot_digest: Digest256,
        _authority: object | None = None,
    ) -> ConsumedCaptureAuthorization:
        if _authority is not _CAPTURE_LEDGER_AUTHORITY:
            raise TypeError("capture authorization consumption requires CapturePolicy")
        if type(authorization) is not CaptureAuthorization:
            raise TypeError("authorization must be CaptureAuthorization")
        capture_authorization_id = authorization.capture_authorization_id
        require_uuid(capture_authorization_id, "capture_authorization_id")
        require_aware_datetime(now, "now")
        require_digest(
            pre_capture_permission_observation_digest,
            "pre_capture_permission_observation_digest",
        )
        require_digest(
            pre_capture_topology_snapshot_digest,
            "pre_capture_topology_snapshot_digest",
        )
        with self._lock:
            registered_authorization = self._authorizations.get(
                capture_authorization_id
            )
            if (
                registered_authorization is None
                or authorization is not registered_authorization
                or registered_authorization.capture_authorization_id
                != capture_authorization_id
                or self._authorization_digests.get(capture_authorization_id)
                != registered_authorization.capture_authorization_digest
            ):
                raise _capture_error("截图授权不存在。")
            if capture_authorization_id in self._consumptions:
                raise _capture_error("截图授权已经消费。")
            try:
                consumed = ConsumedCaptureAuthorization(
                    authorization=authorization,
                    consumed_at=now,
                    pre_capture_permission_observation_digest=(
                        pre_capture_permission_observation_digest
                    ),
                    pre_capture_topology_snapshot_digest=(
                        pre_capture_topology_snapshot_digest
                    ),
                    _authority=_CAPTURE_CONSUMPTION_AUTHORITY,
                )
            except (ValueError, TypeError, AttributeError) as error:
                raise _capture_error("截图授权已经失效。") from error
            self._consumptions[capture_authorization_id] = consumed
            self._consumption_digests[capture_authorization_id] = (
                consumed.consumption_digest
            )
            object.__setattr__(self, "_revision", self._revision + 1)
            return consumed

    def _require_consumption_locked(
        self,
        consumed: ConsumedCaptureAuthorization,
    ) -> UUID:
        if type(consumed) is not ConsumedCaptureAuthorization:
            raise TypeError("consumed must be ConsumedCaptureAuthorization")
        try:
            consumed.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _capture_error("截图消费凭证完整性校验失败。") from error
        identifier = consumed.authorization.capture_authorization_id
        authorization = self._authorizations.get(identifier)
        registered_consumption = self._consumptions.get(identifier)
        registered_consumption_digest = self._consumption_digests.get(
            identifier
        )
        if (
            authorization is None
            or consumed.authorization is not authorization
            or consumed is not registered_consumption
            or self._authorization_digests.get(identifier)
            != consumed.authorization.capture_authorization_digest
            or registered_consumption_digest is None
            or registered_consumption_digest != consumed.consumption_digest
        ):
            raise _capture_error("截图消费凭证不属于当前授权账本。")
        return identifier

    def _start_artifact_attempt(
        self,
        *,
        consumed: ConsumedCaptureAuthorization,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_ARTIFACT_AUTHORITY:
            raise TypeError("artifact attempts require CaptureArtifactFactory")
        with self._lock:
            identifier = self._require_consumption_locked(consumed)
            if identifier in self._artifact_attempts:
                raise _capture_error("截图授权已经发起过图像生成。")
            self._artifact_attempts.add(identifier)
            object.__setattr__(self, "_revision", self._revision + 1)

    def _bind_artifact_claim(
        self,
        *,
        consumed: ConsumedCaptureAuthorization,
        artifact_claim_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_ARTIFACT_AUTHORITY:
            raise TypeError("artifact claims require CaptureArtifactFactory")
        require_digest(artifact_claim_digest, "artifact_claim_digest")
        with self._lock:
            identifier = self._require_consumption_locked(consumed)
            if identifier not in self._artifact_attempts:
                raise _capture_error("截图授权尚未发起图像生成。")
            if identifier in self._artifact_claims:
                raise _capture_error("截图授权已经绑定图像。")
            self._artifact_claims[identifier] = artifact_claim_digest
            object.__setattr__(self, "_revision", self._revision + 1)

    def _start_validation_attempt(
        self,
        *,
        consumed: ConsumedCaptureAuthorization,
        artifact_claim_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_VALIDATION_AUTHORITY:
            raise TypeError("validation attempts require InputValidator")
        require_digest(artifact_claim_digest, "artifact_claim_digest")
        with self._lock:
            identifier = self._require_consumption_locked(consumed)
            if self._artifact_claims.get(identifier) != artifact_claim_digest:
                raise _capture_error("截图图像与一次性生成记录不一致。")
            if identifier in self._validation_attempts:
                raise _capture_error("截图图像已经发起过输入校验。")
            self._validation_attempts.add(identifier)
            object.__setattr__(self, "_revision", self._revision + 1)

    def _complete_validation(
        self,
        *,
        consumed: ConsumedCaptureAuthorization,
        artifact_claim_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_VALIDATION_AUTHORITY:
            raise TypeError("validation completion requires InputValidator")
        require_digest(artifact_claim_digest, "artifact_claim_digest")
        with self._lock:
            identifier = self._require_consumption_locked(consumed)
            if (
                identifier not in self._validation_attempts
                or self._artifact_claims.get(identifier)
                != artifact_claim_digest
                or identifier in self._validated
            ):
                raise _capture_error("截图输入校验状态无效。")
            self._validated.add(identifier)
            object.__setattr__(self, "_revision", self._revision + 1)

    def safe_metadata(self) -> dict[str, int]:
        with self._lock:
            return {
                "revision": self._revision,
                "authorization_count": len(self._authorizations),
                "consumed_count": len(self._consumptions),
            }

    def safe_capture_metadata(
        self,
        *,
        consumed: ConsumedCaptureAuthorization,
    ) -> dict[str, object]:
        with self._lock:
            identifier = self._require_consumption_locked(consumed)
            claim = self._artifact_claims.get(identifier)
            return {
                "artifact_attempted": identifier in self._artifact_attempts,
                "artifact_claim_digest_prefix": (
                    str(claim)[:12] if claim is not None else None
                ),
                "validation_attempted": (
                    identifier in self._validation_attempts
                ),
                "validated": identifier in self._validated,
            }


@runtime_final
class CapturePolicy:
    """Resolve one Phase 1 physical-pixel selection without external I/O."""

    __slots__ = ()

    def authorize(
        self,
        *,
        planned: PlannedExecution,
        privacy_authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        permission_observation: PermissionObservation,
        topology: DisplayTopologySnapshot,
        selected_scope: CaptureScope,
        capture_id: UUID,
        capture_ledger: CaptureAuthorizationLedger,
        now: datetime,
    ) -> CaptureAuthorization:
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(privacy_authorization) is not AuthorizationContext:
            raise TypeError("privacy_authorization must be AuthorizationContext")
        if type(consent_ledger) is not ConsentLedger:
            raise TypeError("consent_ledger must be ConsentLedger")
        if type(permission_observation) is not PermissionObservation:
            raise TypeError("permission_observation must be PermissionObservation")
        if type(topology) is not DisplayTopologySnapshot:
            raise TypeError("topology must be DisplayTopologySnapshot")
        if type(selected_scope) is not CaptureScope:
            raise TypeError("selected_scope must be CaptureScope")
        if type(capture_ledger) is not CaptureAuthorizationLedger:
            raise TypeError("capture_ledger must be CaptureAuthorizationLedger")
        require_uuid(capture_id, "capture_id")
        require_aware_datetime(now, "now")

        PrivacyGate().validate_authorization(
            planned=planned,
            authorization=privacy_authorization,
            ledger=consent_ledger,
            now=now,
        )
        PermissionGate().require_granted(
            observation=permission_observation,
            now=now,
        )
        try:
            topology.validate_integrity()
            if topology.observed_at != now:
                raise ValueError(
                    "display topology must be observed at authorization time"
                )
            topology.validate_physical_selected_scope(selected_scope)
            planned.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _capture_error("截图选区或显示器拓扑无效。") from error

        plan = planned.plan
        constraints = plan.capture_constraints
        if (
            plan.capture_scope_kind is not CaptureScopeKind.SELECTED_REGION
            or selected_scope.kind is not CaptureScopeKind.SELECTED_REGION
            or selected_scope.coordinate_space is not CoordinateSpace.PHYSICAL_PIXELS
            or constraints.allow_full_screen
            or constraints.display_topology_revision
            != topology.topology_revision
        ):
            raise _capture_error("第一阶段只允许物理像素坐标的明确选区。")
        if selected_scope.display_id not in constraints.allowed_display_ids:
            raise _capture_error("截图选区不属于计划允许的显示器。")
        rect = selected_scope.rect
        if rect is None:
            raise _capture_error("截图选区不能为空。")
        if (
            rect.width > constraints.max_width_px
            or rect.height > constraints.max_height_px
            or rect.width * rect.height > constraints.max_pixels
        ):
            raise _capture_error("截图选区超过计划允许的范围。")
        grants = consent_ledger.snapshot_for_ids(
            privacy_authorization.consent_grant_ids
        )
        if any(
            grant.capture_scope_fingerprint is not None
            and grant.capture_scope_fingerprint != selected_scope.fingerprint
            for grant in grants
        ):
            raise _capture_error("截图选区与已批准的同意范围不一致。")

        identifier_payload = _authorization_identifier_payload(
            capture_id=capture_id,
            request_id=plan.request_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            planned_execution_digest=planned.planned_execution_digest,
            privacy_authorization_id=privacy_authorization.authorization_id,
            privacy_authorization_digest=(
                privacy_authorization.authorization_digest
            ),
            permission_observation_digest=(
                permission_observation.observation_digest
            ),
            topology_revision=topology.topology_revision,
            scope=selected_scope,
            constraints=constraints,
            authorized_at=now,
            valid_until=privacy_authorization.valid_until,
        )
        capture_authorization = CaptureAuthorization(
            capture_authorization_id=_capture_authorization_id_for(
                identifier_payload
            ),
            capture_id=capture_id,
            request_id=plan.request_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            planned_execution_digest=planned.planned_execution_digest,
            privacy_authorization_id=privacy_authorization.authorization_id,
            privacy_authorization_digest=(
                privacy_authorization.authorization_digest
            ),
            permission_observation_digest=(
                permission_observation.observation_digest
            ),
            topology_revision=topology.topology_revision,
            scope=selected_scope,
            constraints=constraints,
            authorized_at=now,
            valid_until=privacy_authorization.valid_until,
            _authority=_CAPTURE_AUTHORITY,
        )
        capture_authorization.validate_integrity()
        def issue_authorization() -> CaptureAuthorization:
            capture_ledger._issue(
                capture_authorization,
                _authority=_CAPTURE_LEDGER_AUTHORITY,
            )
            return capture_authorization

        return PrivacyGate()._run_authorized_action(
            planned=planned,
            authorization=privacy_authorization,
            ledger=consent_ledger,
            now=now,
            action=issue_authorization,
            _authority=_ATOMIC_PRIVACY_AUTHORITY,
        )

    def prepare_capture(
        self,
        *,
        planned: PlannedExecution,
        privacy_authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        authorization: CaptureAuthorization,
        capture_ledger: CaptureAuthorizationLedger,
        permission_observation: PermissionObservation,
        topology: DisplayTopologySnapshot,
        now: datetime,
    ) -> ConsumedCaptureAuthorization:
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(privacy_authorization) is not AuthorizationContext:
            raise TypeError("privacy_authorization must be AuthorizationContext")
        if type(consent_ledger) is not ConsentLedger:
            raise TypeError("consent_ledger must be ConsentLedger")
        if type(authorization) is not CaptureAuthorization:
            raise TypeError("authorization must be CaptureAuthorization")
        if type(capture_ledger) is not CaptureAuthorizationLedger:
            raise TypeError("capture_ledger must be CaptureAuthorizationLedger")
        if type(permission_observation) is not PermissionObservation:
            raise TypeError("permission_observation must be PermissionObservation")
        if type(topology) is not DisplayTopologySnapshot:
            raise TypeError("topology must be DisplayTopologySnapshot")
        require_aware_datetime(now, "now")
        PrivacyGate().validate_authorization(
            planned=planned,
            authorization=privacy_authorization,
            ledger=consent_ledger,
            now=now,
        )
        PermissionGate().require_granted(
            observation=permission_observation,
            now=now,
        )
        try:
            authorization.validate_integrity()
            topology.validate_integrity()
            if (
                authorization.plan_id != planned.plan.plan_id
                or authorization.plan_digest != planned.plan.plan_digest
                or authorization.planned_execution_digest
                != planned.planned_execution_digest
                or authorization.privacy_authorization_id
                != privacy_authorization.authorization_id
                or authorization.privacy_authorization_digest
                != privacy_authorization.authorization_digest
            ):
                raise ValueError("capture authorization binding changed")
            if topology.observed_at != now:
                raise ValueError("topology was not observed immediately before capture")
            if topology.topology_revision != authorization.topology_revision:
                raise ValueError("display topology changed before capture")
            topology.validate_physical_selected_scope(authorization.scope)
            grants = consent_ledger.snapshot_for_ids(
                privacy_authorization.consent_grant_ids
            )
            if any(
                grant.capture_scope_fingerprint is not None
                and grant.capture_scope_fingerprint
                != authorization.scope.fingerprint
                for grant in grants
            ):
                raise ValueError("capture scope no longer matches consent")
        except (ValueError, TypeError, AttributeError) as error:
            raise _capture_error("截图前的权限或显示器拓扑已经变化。") from error
        def consume_authorization() -> ConsumedCaptureAuthorization:
            return capture_ledger._consume(
                authorization=authorization,
                now=now,
                pre_capture_permission_observation_digest=(
                    permission_observation.observation_digest
                ),
                pre_capture_topology_snapshot_digest=topology.snapshot_digest,
                _authority=_CAPTURE_LEDGER_AUTHORITY,
            )

        return PrivacyGate()._run_authorized_action(
            planned=planned,
            authorization=privacy_authorization,
            ledger=consent_ledger,
            now=now,
            action=consume_authorization,
            _authority=_ATOMIC_PRIVACY_AUTHORITY,
        )


__all__ = [
    "CAPTURE_AUTHORIZATION_SCHEMA_VERSION",
    "CAPTURE_ARTIFACT_CLAIM_SCHEMA_VERSION",
    "CAPTURE_POLICY_VERSION",
    "CaptureAuthorization",
    "CaptureAuthorizationLedger",
    "CapturePolicy",
    "ConsumedCaptureAuthorization",
]
