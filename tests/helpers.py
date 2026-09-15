"""纯、确定性的测试 fixture。

从原 ``w06_helpers.py`` 抄出仍然适用的部分；Registry / PlannedExecution /
PrivacyAuthorization 相关的 helper 随 v3 一并移除。
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from snapquiz.capture.topology import (
    DisplayGeometrySnapshot,
    DisplayTopologySnapshot,
)
from snapquiz.domain.capture import (
    CaptureRect,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
)
from snapquiz.domain.solve import (
    PipelineKind,
    SolveProvenance,
    StageProvenance,
    StageRole,
)

NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
STAGE_ID = UUID("00000000-0000-0000-0000-000000000011")


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
                    left=0, top=0, width=1_280, height=800
                ),
                pixel_width_px=primary_pixel_width,
                pixel_height_px=primary_pixel_height,
            ),
            DisplayGeometrySnapshot(
                display_id="display-2",
                screen_point_bounds=CaptureRect(
                    left=1_280, top=-120, width=1_920, height=1_080
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


def provenance(*, latency_ms: int = 250) -> SolveProvenance:
    return SolveProvenance(
        pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
        stages=(
            StageProvenance(
                stage_id=STAGE_ID,
                role=StageRole.SOLVER,
                provider_id="zhipu",
                model_id="glm-4.6v-flash",
                adapter_family="openai_chat_compatible",
                adapter_version="2",
                attempts=1,
                network_calls=1,
                latency_ms=latency_ms,
            ),
        ),
    )


def solid_rgb(width: int, height: int, value: int = 128) -> bytes:
    """一幅纯色图：亮度跨度为 0，用来触发空白帧判定。"""

    return bytes([value, value, value]) * (width * height)


def gradient_rgb(width: int, height: int) -> bytes:
    """有明显亮度跨度的图，应当通过质量检查。"""

    out = bytearray()
    for y in range(height):
        for x in range(width):
            v = (x * 255) // max(width - 1, 1)
            out += bytes([v, v, v])
    return bytes(out)
