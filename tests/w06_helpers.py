"""Pure, deterministic W06 fixtures shared by capture contract tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sys
import types
from unittest.mock import patch
from uuid import UUID

from snapquiz.capture.topology import (
    DisplayGeometrySnapshot,
    DisplayTopologySnapshot,
)
from snapquiz.config.profiles import (
    GLM_BINDING_ID,
    GLM_PIPELINE_PROFILE_ID,
    build_builtin_registry,
)
from snapquiz.core.permissions import (
    MacOSScreenPermissionProbe,
    PermissionObservation,
    ScreenPermissionState,
)
from snapquiz.domain.capture import (
    CaptureConstraints,
    CaptureRect,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
)
from snapquiz.domain.intent import (
    SOLVE_INTENT_SCHEMA_VERSION,
    OutputTokenLimit,
    SolveIntent,
)
from snapquiz.domain.solve import SOLVE_RESULT_SCHEMA_VERSION
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentLedger,
    PrivacyGate,
    UnknownPolicyDimension,
)
from snapquiz.routing.planner import PlannedExecution, RoutePlanner

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
REQUEST_ID = UUID("10000000-0000-0000-0000-000000000001")
GRANT_ID = UUID("10000000-0000-0000-0000-000000000002")
CAPTURE_ID = UUID("10000000-0000-0000-0000-000000000003")

ALL_UNKNOWN_CONFIRMATIONS = (
    UnknownPolicyDimension.COST,
    UnknownPolicyDimension.DATA,
    UnknownPolicyDimension.PROCESSING_REGION,
    UnknownPolicyDimension.RETENTION,
)


def topology(
    *,
    observed_at: datetime = NOW,
    primary_pixel_width: int = 2_560,
    primary_pixel_height: int = 1_600,
) -> DisplayTopologySnapshot:
    return DisplayTopologySnapshot(
        displays=(
            DisplayGeometrySnapshot(
                display_id="display-1",
                screen_point_bounds=CaptureRect(
                    left=0,
                    top=0,
                    width=1_280,
                    height=800,
                ),
                pixel_width_px=primary_pixel_width,
                pixel_height_px=primary_pixel_height,
            ),
            DisplayGeometrySnapshot(
                display_id="display-2",
                screen_point_bounds=CaptureRect(
                    left=1_280,
                    top=-120,
                    width=1_920,
                    height=1_080,
                ),
                pixel_width_px=1_920,
                pixel_height_px=1_080,
            ),
        ),
        observed_at=observed_at,
    )


def selected_scope(
    display_topology: DisplayTopologySnapshot,
    *,
    display_id: str = "display-1",
    rect: CaptureRect | None = None,
    coordinate_space: CoordinateSpace = CoordinateSpace.PHYSICAL_PIXELS,
    display_geometry_revision: str | None = None,
) -> CaptureScope:
    return CaptureScope(
        kind=CaptureScopeKind.SELECTED_REGION,
        display_id=display_id,
        coordinate_space=coordinate_space,
        rect=rect or CaptureRect(left=20, top=30, width=640, height=480),
        display_geometry_revision=(
            str(display_topology.topology_revision)
            if display_geometry_revision is None
            else display_geometry_revision
        ),
    )


def planned_execution(
    display_topology: DisplayTopologySnapshot,
    *,
    now: datetime = NOW,
    request_id: UUID = REQUEST_ID,
    allowed_display_ids: tuple[str, ...] = ("display-1",),
    max_width_px: int = 2_000,
    max_height_px: int = 1_500,
    max_pixels: int = 3_000_000,
) -> PlannedExecution:
    intent = SolveIntent(
        schema_version=SOLVE_INTENT_SCHEMA_VERSION,
        request_id=request_id,
        pipeline_profile_id=GLM_PIPELINE_PROFILE_ID,
        capture_scope_preference=CaptureScopeKind.SELECTED_REGION,
        locale="zh-Hans-CN",
        timeout_budget_ms=30_000,
        max_output_tokens=OutputTokenLimit.PROFILE_DEFAULT,
        requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
    )
    trusted_constraints = CaptureConstraints(
        allowed_display_ids=allowed_display_ids,
        display_topology_revision=display_topology.topology_revision,
        max_width_px=max_width_px,
        max_height_px=max_height_px,
        max_pixels=max_pixels,
        max_bytes=5_000_000,
        allow_full_screen=True,
    )
    return RoutePlanner().plan(
        intent=intent,
        registry=build_builtin_registry(),
        trusted_capture_constraints=trusted_constraints,
        now=now,
    )


def privacy_authorization(
    planned: PlannedExecution,
    *,
    now: datetime = NOW,
    expires_at: datetime | None = None,
    scope_fingerprint=None,
    grant_id: UUID = GRANT_ID,
    one_shot: bool = False,
) -> tuple[ConsentLedger, AuthorizationContext]:
    ledger = ConsentLedger()
    grant = ledger.issue_for_plan(
        planned=planned,
        binding_id=GLM_BINDING_ID,
        grant_id=grant_id,
        request_id=planned.plan.request_id,
        capture_scope_fingerprint=scope_fingerprint,
        issued_at=now,
        expires_at=expires_at or now + timedelta(hours=1),
        one_shot=one_shot,
        confirmed_unknown_policies=ALL_UNKNOWN_CONFIRMATIONS,
    )
    authorization = PrivacyGate().authorize(
        planned=planned,
        ledger=ledger,
        consent_grant_ids=(grant.grant_id,),
        now=now,
    )
    return ledger, authorization


def permission_observation(
    state: ScreenPermissionState,
    *,
    observed_at: datetime = NOW,
) -> PermissionObservation:
    """Create an observation through the real probe with an in-memory Quartz fake."""

    quartz = types.ModuleType("Quartz")
    if state is ScreenPermissionState.GRANTED:
        raw_result = True
    elif state is ScreenPermissionState.DENIED:
        raw_result = False
    elif state is ScreenPermissionState.UNKNOWN:
        raw_result = object()
    else:
        raise ValueError("state must be ScreenPermissionState")

    def preflight():
        return raw_result

    quartz.CGPreflightScreenCaptureAccess = preflight
    with (
        patch.object(sys, "platform", "darwin"),
        patch.dict(sys.modules, {"Quartz": quartz}),
    ):
        return MacOSScreenPermissionProbe().observe(now=observed_at)


def granted_permission(*, observed_at: datetime = NOW) -> PermissionObservation:
    return permission_observation(
        ScreenPermissionState.GRANTED,
        observed_at=observed_at,
    )
