"""Provider-neutral, immutable capture contracts."""
from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CaptureError, PayloadTooLargeError

CAPTURE_SCOPE_SCHEMA_VERSION = "snapquiz.capture-scope.v1"
SUPPORTED_IMAGE_MIME_TYPES = frozenset({"image/png", "image/jpeg"})


class CaptureScopeKind(str, Enum):
    SELECTED_REGION = "selected_region"
    FULL_SCREEN = "full_screen"


class CoordinateSpace(str, Enum):
    SCREEN_POINTS = "screen_points"
    PHYSICAL_PIXELS = "physical_pixels"


@runtime_final
@dataclass(frozen=True, slots=True)
class CaptureRect:
    left: int
    top: int
    width: int
    height: int

    def __post_init__(self) -> None:
        if type(self.left) is not int or type(self.top) is not int:
            raise ValueError("rect left/top must be integers")
        require_plain_int(self.width, "rect width", minimum=1)
        require_plain_int(self.height, "rect height", minimum=1)

    def as_digest_payload(self) -> dict[str, int]:
        return {
            "left": self.left,
            "top": self.top,
            "width": self.width,
            "height": self.height,
        }

    def validate_integrity(self) -> None:
        CaptureRect(
            left=self.left,
            top=self.top,
            width=self.width,
            height=self.height,
        )


@runtime_final
@dataclass(frozen=True, slots=True)
class CaptureScope:
    kind: CaptureScopeKind
    display_id: str
    coordinate_space: CoordinateSpace
    rect: Optional[CaptureRect]
    display_geometry_revision: str
    fingerprint: Digest256 = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.kind) is not CaptureScopeKind:
            raise ValueError("kind must be CaptureScopeKind")
        if type(self.coordinate_space) is not CoordinateSpace:
            raise ValueError("coordinate_space must be CoordinateSpace")
        require_text(self.display_id, "display_id")
        require_text(
            self.display_geometry_revision,
            "display_geometry_revision",
        )
        if self.kind is CaptureScopeKind.SELECTED_REGION and type(
            self.rect
        ) is not CaptureRect:
            raise ValueError("selected_region requires a CaptureRect")
        if self.kind is CaptureScopeKind.FULL_SCREEN and self.rect is not None:
            raise ValueError("full_screen must not carry a rect")

        payload = {
            "kind": self.kind.value,
            "display_id": self.display_id,
            "coordinate_space": self.coordinate_space.value,
            "rect": self.rect.as_digest_payload() if self.rect is not None else None,
            "display_geometry_revision": self.display_geometry_revision,
        }
        object.__setattr__(
            self,
            "fingerprint",
            digest256("CaptureScope", CAPTURE_SCOPE_SCHEMA_VERSION, payload),
        )

    def recompute_fingerprint(self) -> Digest256:
        return digest256(
            "CaptureScope",
            CAPTURE_SCOPE_SCHEMA_VERSION,
            {
                "kind": self.kind.value,
                "display_id": self.display_id,
                "coordinate_space": self.coordinate_space.value,
                "rect": (
                    self.rect.as_digest_payload()
                    if self.rect is not None
                    else None
                ),
                "display_geometry_revision": self.display_geometry_revision,
            },
        )

    def validate_integrity(self) -> None:
        try:
            if self.rect is not None:
                self.rect.validate_integrity()
            canonical = CaptureScope(
                kind=self.kind,
                display_id=self.display_id,
                coordinate_space=self.coordinate_space,
                rect=self.rect,
                display_geometry_revision=self.display_geometry_revision,
            )
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("capture scope integrity mismatch") from error
        if canonical.fingerprint != self.fingerprint:
            raise ValueError("capture scope integrity mismatch")


@runtime_final
class CaptureArtifact:
    """Immutable sensitive image holder that generic dataclass serializers reject."""

    __slots__ = (
        "id",
        "data",
        "mime_type",
        "width_px",
        "height_px",
        "scope",
        "captured_at",
        "byte_size",
        "sha256",
    )

    id: UUID
    data: bytes
    mime_type: str
    width_px: int
    height_px: int
    scope: CaptureScope
    captured_at: datetime
    byte_size: int
    sha256: Digest256

    def __init__(
        self,
        *,
        id: UUID,
        data: bytes,
        mime_type: str,
        width_px: int,
        height_px: int,
        scope: CaptureScope,
        captured_at: datetime,
    ) -> None:
        require_uuid(id, "id")
        if type(data) is not bytes or not data:
            raise ValueError("data must be non-empty immutable bytes")
        if type(mime_type) is not str or mime_type not in SUPPORTED_IMAGE_MIME_TYPES:
            raise ValueError("mime_type must be image/png or image/jpeg")
        require_plain_int(width_px, "width_px", minimum=1)
        require_plain_int(height_px, "height_px", minimum=1)
        if type(scope) is not CaptureScope:
            raise ValueError("scope must be a CaptureScope")
        require_aware_datetime(captured_at, "captured_at")

        object.__setattr__(self, "id", id)
        object.__setattr__(self, "data", data)
        object.__setattr__(self, "mime_type", mime_type)
        object.__setattr__(self, "width_px", width_px)
        object.__setattr__(self, "height_px", height_px)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "captured_at", captured_at)
        object.__setattr__(self, "byte_size", len(data))
        object.__setattr__(self, "sha256", Digest256(hashlib.sha256(data).hexdigest()))

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise FrozenInstanceError("CaptureArtifact is immutable")

    def __repr__(self) -> str:
        return (
            "CaptureArtifact("
            f"id={self.id!r}, mime_type={self.mime_type!r}, "
            f"width_px={self.width_px!r}, height_px={self.height_px!r}, "
            f"scope={self.scope!r}, captured_at={self.captured_at!r}, "
            f"byte_size={self.byte_size!r})"
        )

    def validate_integrity(self) -> None:
        try:
            canonical = CaptureArtifact(
                id=self.id,
                data=self.data,
                mime_type=self.mime_type,
                width_px=self.width_px,
                height_px=self.height_px,
                scope=self.scope,
                captured_at=self.captured_at,
            )
            self.scope.validate_integrity()
        except ValueError:
            raise
        except (TypeError, AttributeError) as error:
            raise ValueError("capture artifact integrity mismatch") from error
        if (
            canonical.byte_size != self.byte_size
            or canonical.sha256 != self.sha256
        ):
            raise ValueError("capture artifact integrity mismatch")


@runtime_final
@dataclass(frozen=True, slots=True)
class CaptureConstraints:
    allowed_display_ids: tuple[str, ...]
    display_topology_revision: Digest256
    max_width_px: int
    max_height_px: int
    max_pixels: int
    max_bytes: int
    allow_full_screen: bool = False

    def __post_init__(self) -> None:
        if type(self.allowed_display_ids) is not tuple or not self.allowed_display_ids:
            raise ValueError("allowed_display_ids must be a non-empty tuple")
        if len(set(self.allowed_display_ids)) != len(self.allowed_display_ids):
            raise ValueError("allowed_display_ids must not contain duplicates")
        for display_id in self.allowed_display_ids:
            require_text(display_id, "allowed display id")
        require_digest(
            self.display_topology_revision,
            "display_topology_revision",
        )
        require_plain_int(self.max_width_px, "max_width_px", minimum=1)
        require_plain_int(self.max_height_px, "max_height_px", minimum=1)
        require_plain_int(self.max_pixels, "max_pixels", minimum=1)
        require_plain_int(self.max_bytes, "max_bytes", minimum=1)
        if type(self.allow_full_screen) is not bool:
            raise ValueError("allow_full_screen must be bool")

    def validate_integrity(self) -> None:
        CaptureConstraints(
            allowed_display_ids=self.allowed_display_ids,
            display_topology_revision=self.display_topology_revision,
            max_width_px=self.max_width_px,
            max_height_px=self.max_height_px,
            max_pixels=self.max_pixels,
            max_bytes=self.max_bytes,
            allow_full_screen=self.allow_full_screen,
        )


def validate_capture_artifact(
    artifact: CaptureArtifact,
    constraints: CaptureConstraints,
    *,
    stage: str = "input_validation",
) -> None:
    """Validate a captured image against the immutable plan constraints."""

    if type(artifact) is not CaptureArtifact:
        raise TypeError("artifact must be CaptureArtifact")
    if type(constraints) is not CaptureConstraints:
        raise TypeError("constraints must be CaptureConstraints")
    try:
        artifact.validate_integrity()
        constraints.validate_integrity()
    except (ValueError, TypeError, AttributeError) as error:
        raise CaptureError(
            stage=stage, safe_message="截图内容或范围完整性校验失败。"
        ) from error
    if hashlib.sha256(artifact.data).hexdigest() != artifact.sha256:
        raise CaptureError(stage=stage, safe_message="截图内容完整性校验失败。")
    if artifact.scope.display_id not in constraints.allowed_display_ids:
        raise CaptureError(stage=stage, safe_message="截图来自计划外的显示器。")
    if artifact.scope.display_geometry_revision != str(
        constraints.display_topology_revision
    ):
        raise CaptureError(stage=stage, safe_message="截图引用了过期的显示器拓扑。")
    if (
        artifact.scope.kind is CaptureScopeKind.FULL_SCREEN
        and not constraints.allow_full_screen
    ):
        raise CaptureError(stage=stage, safe_message="当前执行计划不允许全屏截图。")
    if (
        artifact.width_px > constraints.max_width_px
        or artifact.height_px > constraints.max_height_px
        or artifact.width_px * artifact.height_px > constraints.max_pixels
        or artifact.byte_size > constraints.max_bytes
    ):
        raise PayloadTooLargeError(stage=stage)
    rect = artifact.scope.rect
    if (
        artifact.scope.kind is CaptureScopeKind.SELECTED_REGION
        and artifact.scope.coordinate_space is CoordinateSpace.PHYSICAL_PIXELS
        and (
            rect is None
            or artifact.width_px != rect.width
            or artifact.height_px != rect.height
        )
    ):
        raise CaptureError(
            stage=stage,
            safe_message="截图尺寸未精确绑定物理像素选区。",
        )
