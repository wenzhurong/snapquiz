"""Immutable, provider-neutral display topology snapshots.

W06 consumes these snapshots as data only.  The real macOS topology source is
intentionally left for W12; no Quartz, screen, environment, or filesystem API
is imported or called here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_plain_int,
    require_text,
    runtime_final,
)
from snapquiz.domain.capture import (
    CaptureRect,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
)
from snapquiz.domain.digest import Digest256, digest256

DISPLAY_GEOMETRY_SCHEMA_VERSION = "snapquiz.display-geometry.v1"
DISPLAY_TOPOLOGY_SCHEMA_VERSION = "snapquiz.display-topology.v1"
MAX_DISPLAY_DIMENSION = 100_000


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class DisplayGeometrySnapshot:
    """One display's global point bounds and display-local pixel bounds."""

    display_id: str
    screen_point_bounds: CaptureRect
    pixel_width_px: int
    pixel_height_px: int
    geometry_digest: Digest256 = field(init=False, repr=False)

    def __post_init__(self) -> None:
        require_text(self.display_id, "display_id", max_length=256)
        if type(self.screen_point_bounds) is not CaptureRect:
            raise ValueError("screen_point_bounds must be CaptureRect")
        self.screen_point_bounds.validate_integrity()
        width = require_plain_int(
            self.pixel_width_px, "pixel_width_px", minimum=1
        )
        height = require_plain_int(
            self.pixel_height_px, "pixel_height_px", minimum=1
        )
        if (
            width > MAX_DISPLAY_DIMENSION
            or height > MAX_DISPLAY_DIMENSION
            or self.screen_point_bounds.width > MAX_DISPLAY_DIMENSION
            or self.screen_point_bounds.height > MAX_DISPLAY_DIMENSION
        ):
            raise ValueError("display geometry exceeds the hard dimension limit")
        object.__setattr__(self, "geometry_digest", self.recompute_digest())

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "display_id": self.display_id,
            "screen_point_bounds": self.screen_point_bounds.as_digest_payload(),
            "pixel_width_px": self.pixel_width_px,
            "pixel_height_px": self.pixel_height_px,
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "DisplayGeometrySnapshot",
            DISPLAY_GEOMETRY_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        try:
            canonical = DisplayGeometrySnapshot(
                display_id=self.display_id,
                screen_point_bounds=self.screen_point_bounds,
                pixel_width_px=self.pixel_width_px,
                pixel_height_px=self.pixel_height_px,
            )
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("display geometry integrity mismatch") from error
        if canonical.geometry_digest != self.geometry_digest:
            raise ValueError("display geometry integrity mismatch")

    def contains_physical_rect(self, rect: CaptureRect) -> bool:
        if type(rect) is not CaptureRect:
            return False
        try:
            rect.validate_integrity()
        except ValueError:
            return False
        return (
            rect.left >= 0
            and rect.top >= 0
            and rect.left + rect.width <= self.pixel_width_px
            and rect.top + rect.height <= self.pixel_height_px
        )


@runtime_final
class DisplayTopologySnapshot:
    """A canonical geometry generation observed at one explicit wall time."""

    __slots__ = (
        "displays",
        "observed_at",
        "topology_revision",
        "snapshot_digest",
    )

    def __init__(
        self,
        *,
        displays: tuple[DisplayGeometrySnapshot, ...],
        observed_at: datetime,
    ) -> None:
        if type(displays) is not tuple or not displays:
            raise ValueError("displays must be a non-empty tuple")
        if not all(type(display) is DisplayGeometrySnapshot for display in displays):
            raise ValueError("displays contain an invalid geometry snapshot")
        display_ids = tuple(display.display_id for display in displays)
        if display_ids != tuple(sorted(display_ids)) or len(set(display_ids)) != len(
            display_ids
        ):
            raise ValueError("displays must use unique canonical display ids")
        for display in displays:
            display.validate_integrity()
        require_aware_datetime(observed_at, "observed_at")
        object.__setattr__(self, "displays", displays)
        object.__setattr__(self, "observed_at", observed_at)
        topology_revision = digest256(
            "DisplayTopologyRevision",
            DISPLAY_TOPOLOGY_SCHEMA_VERSION,
            {
                "displays": tuple(
                    {
                        "geometry_digest": display.geometry_digest,
                        "geometry": display.as_digest_payload(),
                    }
                    for display in displays
                )
            },
        )
        object.__setattr__(self, "topology_revision", topology_revision)
        object.__setattr__(
            self,
            "snapshot_digest",
            digest256(
                "DisplayTopologySnapshot",
                DISPLAY_TOPOLOGY_SCHEMA_VERSION,
                {
                    "topology_revision": topology_revision,
                    "observed_at": observed_at,
                },
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DisplayTopologySnapshot is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "DisplayTopologySnapshot":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "DisplayTopologySnapshot("
            f"display_count={len(self.displays)!r}, "
            f"observed_at={self.observed_at!r}, "
            f"topology_revision_prefix={str(self.topology_revision)[:12]!r})"
        )

    def validate_integrity(self) -> None:
        try:
            canonical = DisplayTopologySnapshot(
                displays=self.displays,
                observed_at=self.observed_at,
            )
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("display topology integrity mismatch") from error
        if (
            canonical.topology_revision != self.topology_revision
            or canonical.snapshot_digest != self.snapshot_digest
        ):
            raise ValueError("display topology integrity mismatch")

    def require_display(self, display_id: str) -> DisplayGeometrySnapshot:
        require_text(display_id, "display_id", max_length=256)
        for display in self.displays:
            if display.display_id == display_id:
                return display
        raise LookupError("unknown display")

    def validate_physical_selected_scope(self, scope: CaptureScope) -> None:
        if type(scope) is not CaptureScope:
            raise TypeError("scope must be CaptureScope")
        try:
            self.validate_integrity()
            scope.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("capture scope or topology integrity mismatch") from error
        if scope.kind is not CaptureScopeKind.SELECTED_REGION:
            raise ValueError("W06 accepts selected_region only")
        if scope.coordinate_space is not CoordinateSpace.PHYSICAL_PIXELS:
            raise ValueError(
                "screen-point capture awaits the trusted W12 scale transform"
            )
        if scope.display_geometry_revision != str(self.topology_revision):
            raise ValueError("capture scope references a stale display topology")
        try:
            display = self.require_display(scope.display_id)
        except LookupError as error:
            raise ValueError("capture scope references an unknown display") from error
        if scope.rect is None or not display.contains_physical_rect(scope.rect):
            raise ValueError("capture scope is outside the selected display")
        if (
            scope.rect.left == 0
            and scope.rect.top == 0
            and scope.rect.width == display.pixel_width_px
            and scope.rect.height == display.pixel_height_px
        ):
            raise ValueError(
                "a whole-display rectangle is not a Phase 1 selected region"
            )


__all__ = [
    "DISPLAY_GEOMETRY_SCHEMA_VERSION",
    "DISPLAY_TOPOLOGY_SCHEMA_VERSION",
    "MAX_DISPLAY_DIMENSION",
    "DisplayGeometrySnapshot",
    "DisplayTopologySnapshot",
]
