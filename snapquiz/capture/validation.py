"""Strict, side-effect-free capture artifact validation for W06.

W06 deliberately accepts one canonical PNG subset only: non-interlaced,
8-bit RGB or RGBA images containing exactly IHDR, contiguous IDAT chunks and
IEND.  JPEG and real screen-capture backends remain outside this milestone.
"""
from __future__ import annotations

import binascii
import struct
import zlib
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from types import TracebackType

from snapquiz.capture.policy import (
    CAPTURE_POLICY_VERSION,
    CaptureAuthorization,
    CaptureAuthorizationLedger,
    ConsumedCaptureAuthorization,
    _CAPTURE_ARTIFACT_AUTHORITY,
    _CAPTURE_VALIDATION_AUTHORITY,
    _capture_artifact_claim_digest,
)
from snapquiz.capture.topology import DisplayTopologySnapshot
from snapquiz.core.permissions import PermissionGate, PermissionObservation
from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.capture import (
    CaptureArtifact,
    CaptureConstraints,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
    validate_capture_artifact,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CaptureError, PayloadTooLargeError
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentLedger,
    PrivacyGate,
    _ATOMIC_PRIVACY_AUTHORITY,
)
from snapquiz.routing.planner import PlannedExecution

CANONICAL_PNG_POLICY_VERSION = "snapquiz.canonical-png.phase1.v1"
VALIDATED_CAPTURE_SCHEMA_VERSION = "snapquiz.validated-capture.v1"
MAX_CANONICAL_PNG_CHUNKS = 1_024
MAX_CANONICAL_DECODED_BYTES = 64 * 1_024 * 1_024
BLACK_LUMA_MAX = 8
MIN_VISIBLE_LUMA_SPAN = 8

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_VALIDATED_CAPTURE_AUTHORITY = object()


def _capture_error(stage: str, message: str) -> CaptureError:
    return CaptureError(stage=stage, safe_message=message)


def _require_bound_authorization(
    consumed: ConsumedCaptureAuthorization,
) -> CaptureAuthorization:
    if type(consumed) is not ConsumedCaptureAuthorization:
        raise TypeError("consumed must be ConsumedCaptureAuthorization")
    try:
        consumed.validate_integrity()
    except (TypeError, ValueError, AttributeError) as error:
        raise _capture_error(
            "capture_artifact_factory",
            "截图授权完整性校验失败。",
        ) from error
    return consumed.authorization


@runtime_final
class CaptureArtifactFactory:
    """Materialize exactly one artifact from one atomically consumed permit."""

    __slots__ = ()

    @staticmethod
    def create(
        *,
        consumed: ConsumedCaptureAuthorization,
        capture_ledger: CaptureAuthorizationLedger,
        data: bytes,
        mime_type: str,
        width_px: int,
        height_px: int,
        captured_at: datetime,
    ) -> CaptureArtifact:
        if type(capture_ledger) is not CaptureAuthorizationLedger:
            raise TypeError("capture_ledger must be CaptureAuthorizationLedger")
        authorization = _require_bound_authorization(consumed)
        capture_ledger._start_artifact_attempt(
            consumed=consumed,
            _authority=_CAPTURE_ARTIFACT_AUTHORITY,
        )
        try:
            require_aware_datetime(captured_at, "captured_at")
            require_plain_int(width_px, "width_px", minimum=1)
            require_plain_int(height_px, "height_px", minimum=1)
            authorization.scope.validate_integrity()
            authorization.constraints.validate_integrity()
        except (TypeError, ValueError, AttributeError) as error:
            raise _capture_error(
                "capture_artifact_factory",
                "截图元数据或授权范围无效。",
            ) from error
        if type(data) is not bytes or not data:
            raise _capture_error(
                "capture_artifact_factory",
                "截图数据必须是非空的不可变字节。",
            )
        if mime_type != "image/png":
            raise _capture_error(
                "capture_artifact_factory",
                "W06 仅接受规范 PNG 截图。",
            )
        rect = authorization.scope.rect
        if (
            authorization.scope.kind is not CaptureScopeKind.SELECTED_REGION
            or authorization.scope.coordinate_space
            is not CoordinateSpace.PHYSICAL_PIXELS
            or rect is None
            or width_px != rect.width
            or height_px != rect.height
        ):
            raise _capture_error(
                "capture_artifact_factory",
                "截图尺寸未精确绑定已授权选区。",
            )
        if captured_at < consumed.consumed_at or (
            authorization.valid_until is not None
            and captured_at >= authorization.valid_until
        ):
            raise _capture_error(
                "capture_artifact_factory",
                "截图时间不在授权有效期内。",
            )
        constraints = authorization.constraints
        if (
            width_px > constraints.max_width_px
            or height_px > constraints.max_height_px
            or width_px * height_px > constraints.max_pixels
            or len(data) > constraints.max_bytes
        ):
            raise PayloadTooLargeError(stage="capture_artifact_factory")
        try:
            artifact = CaptureArtifact(
                id=authorization.capture_id,
                data=data,
                mime_type=mime_type,
                width_px=width_px,
                height_px=height_px,
                scope=authorization.scope,
                captured_at=captured_at,
            )
            validate_capture_artifact(
                artifact,
                constraints,
                stage="capture_artifact_factory",
            )
        except (CaptureError, PayloadTooLargeError):
            raise
        except (TypeError, ValueError, AttributeError) as error:
            raise _capture_error(
                "capture_artifact_factory",
                "截图图像合同无效。",
            ) from error
        capture_ledger._bind_artifact_claim(
            consumed=consumed,
            artifact_claim_digest=_capture_artifact_claim_digest(artifact),
            _authority=_CAPTURE_ARTIFACT_AUTHORITY,
        )
        return artifact


@dataclass(frozen=True, slots=True)
class _PngInspection:
    width_px: int
    height_px: int
    color_type: int
    visible_pixel_count: int
    luma_min: int
    luma_max: int


def _paeth_predictor(left: int, up: int, upper_left: int) -> int:
    prediction = left + up - upper_left
    left_distance = abs(prediction - left)
    up_distance = abs(prediction - up)
    upper_left_distance = abs(prediction - upper_left)
    if left_distance <= up_distance and left_distance <= upper_left_distance:
        return left
    if up_distance <= upper_left_distance:
        return up
    return upper_left


def _read_canonical_png_chunks(data: bytes) -> tuple[bytes, bytes]:
    if not data.startswith(_PNG_SIGNATURE):
        raise ValueError("invalid PNG signature")
    offset = len(_PNG_SIGNATURE)
    chunk_count = 0
    ihdr: bytes | None = None
    idat_chunks: list[bytes] = []
    saw_iend = False
    while offset < len(data):
        chunk_count += 1
        if chunk_count > MAX_CANONICAL_PNG_CHUNKS:
            raise ValueError("too many PNG chunks")
        if len(data) - offset < 12:
            raise ValueError("truncated PNG chunk")
        chunk_length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + chunk_length
        crc_end = payload_end + 4
        if payload_end < payload_start or crc_end > len(data):
            raise ValueError("truncated PNG chunk payload")
        payload = data[payload_start:payload_end]
        expected_crc = int.from_bytes(data[payload_end:crc_end], "big")
        actual_crc = binascii.crc32(chunk_type)
        actual_crc = binascii.crc32(payload, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError("PNG chunk CRC mismatch")
        if chunk_count == 1:
            if chunk_type != b"IHDR" or chunk_length != 13:
                raise ValueError("PNG must start with one 13-byte IHDR")
            ihdr = payload
        elif chunk_type == b"IDAT":
            if ihdr is None or saw_iend:
                raise ValueError("PNG IDAT ordering is invalid")
            idat_chunks.append(payload)
        elif chunk_type == b"IEND":
            if chunk_length != 0 or not idat_chunks:
                raise ValueError("PNG IEND ordering is invalid")
            saw_iend = True
            offset = crc_end
            if offset != len(data):
                raise ValueError("PNG contains trailing data")
            break
        else:
            # Ancillary chunks, palettes, color profiles, text and APNG control
            # chunks are excluded so the accepted representation is unambiguous.
            raise ValueError("PNG contains a non-canonical chunk")
        offset = crc_end
    if ihdr is None or not idat_chunks or not saw_iend:
        raise ValueError("PNG is incomplete")
    compressed = b"".join(idat_chunks)
    if not compressed:
        raise ValueError("PNG IDAT stream is empty")
    return ihdr, compressed


def _decode_bounded_png(
    *,
    data: bytes,
    constraints: CaptureConstraints,
    declared_width_px: int,
    declared_height_px: int,
) -> _PngInspection:
    if len(data) > constraints.max_bytes:
        raise PayloadTooLargeError(stage="input_validation")
    try:
        ihdr, compressed = _read_canonical_png_chunks(data)
        (
            width_px,
            height_px,
            bit_depth,
            color_type,
            compression_method,
            filter_method,
            interlace_method,
        ) = struct.unpack(">IIBBBBB", ihdr)
    except (ValueError, struct.error) as error:
        raise _capture_error(
            "input_validation",
            "截图不是完整、规范的 PNG 图像。",
        ) from error
    if (
        width_px < 1
        or height_px < 1
        or width_px != declared_width_px
        or height_px != declared_height_px
    ):
        raise _capture_error(
            "input_validation",
            "PNG 的真实尺寸与截图元数据不一致。",
        )
    if (
        width_px > constraints.max_width_px
        or height_px > constraints.max_height_px
        or width_px * height_px > constraints.max_pixels
    ):
        raise PayloadTooLargeError(stage="input_validation")
    if (
        bit_depth != 8
        or color_type not in (2, 6)
        or compression_method != 0
        or filter_method != 0
        or interlace_method != 0
    ):
        raise _capture_error(
            "input_validation",
            "PNG 编码不属于 W06 允许的规范子集。",
        )
    channels = 3 if color_type == 2 else 4
    row_size = width_px * channels
    decoded_size = height_px * (row_size + 1)
    if decoded_size > MAX_CANONICAL_DECODED_BYTES:
        raise PayloadTooLargeError(stage="input_validation")
    try:
        decompressor = zlib.decompressobj()
        decoded = decompressor.decompress(compressed, decoded_size + 1)
    except zlib.error as error:
        raise _capture_error(
            "input_validation",
            "PNG 压缩数据无法完整解码。",
        ) from error
    if len(decoded) > decoded_size or decompressor.unconsumed_tail:
        raise PayloadTooLargeError(stage="input_validation")
    if (
        len(decoded) != decoded_size
        or not decompressor.eof
        or decompressor.unused_data
    ):
        raise _capture_error(
            "input_validation",
            "PNG 压缩数据长度或结束标记无效。",
        )

    previous_row = bytearray(row_size)
    cursor = 0
    visible_pixel_count = 0
    luma_min = 255
    luma_max = 0
    for _ in range(height_px):
        filter_type = decoded[cursor]
        cursor += 1
        if filter_type > 4:
            raise _capture_error(
                "input_validation",
                "PNG 使用了不受支持的扫描线过滤器。",
            )
        filtered_row = decoded[cursor : cursor + row_size]
        cursor += row_size
        row = bytearray(row_size)
        for index, raw_value in enumerate(filtered_row):
            left = row[index - channels] if index >= channels else 0
            up = previous_row[index]
            upper_left = (
                previous_row[index - channels] if index >= channels else 0
            )
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = up
            elif filter_type == 3:
                predictor = (left + up) // 2
            else:
                predictor = _paeth_predictor(left, up, upper_left)
            row[index] = (raw_value + predictor) & 0xFF
        for pixel_start in range(0, row_size, channels):
            if channels == 4 and row[pixel_start + 3] != 255:
                raise _capture_error(
                    "input_validation",
                    "W06 的 RGBA 截图必须完全不透明。",
                )
            red = row[pixel_start]
            green = row[pixel_start + 1]
            blue = row[pixel_start + 2]
            luma = (77 * red + 150 * green + 29 * blue) >> 8
            visible_pixel_count += 1
            luma_min = min(luma_min, luma)
            luma_max = max(luma_max, luma)
        previous_row = row

    if visible_pixel_count == 0:
        raise _capture_error(
            "input_validation",
            "截图图像完全透明。",
        )
    if luma_max <= BLACK_LUMA_MAX:
        raise _capture_error(
            "input_validation",
            "截图图像为黑帧或接近黑帧。",
        )
    if luma_max - luma_min < MIN_VISIBLE_LUMA_SPAN:
        raise _capture_error(
            "input_validation",
            "截图图像为空白或缺少可辨识变化。",
        )
    return _PngInspection(
        width_px=width_px,
        height_px=height_px,
        color_type=color_type,
        visible_pixel_count=visible_pixel_count,
        luma_min=luma_min,
        luma_max=luma_max,
    )


def _validated_payload(
    *,
    capture_id: object,
    request_id: object,
    plan_id: object,
    plan_digest: object,
    planned_execution_digest: object,
    privacy_authorization_id: object,
    privacy_authorization_digest: object,
    capture_authorization_id: object,
    capture_authorization_digest: object,
    consumption_digest: object,
    post_permission_observation_digest: object,
    topology_revision: object,
    topology_snapshot_digest: object,
    scope_fingerprint: object,
    artifact_sha256: object,
    artifact_mime_type: object,
    artifact_width_px: object,
    artifact_height_px: object,
    artifact_byte_size: object,
    artifact_captured_at: object,
    image_preprocessing_policy_version: object,
    validated_at: object,
) -> dict[str, object]:
    return {
        "capture_policy_version": CAPTURE_POLICY_VERSION,
        "png_policy_version": CANONICAL_PNG_POLICY_VERSION,
        "capture_id": capture_id,
        "request_id": request_id,
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "planned_execution_digest": planned_execution_digest,
        "privacy_authorization_id": privacy_authorization_id,
        "privacy_authorization_digest": privacy_authorization_digest,
        "capture_authorization_id": capture_authorization_id,
        "capture_authorization_digest": capture_authorization_digest,
        "consumption_digest": consumption_digest,
        "post_permission_observation_digest": (
            post_permission_observation_digest
        ),
        "topology_revision": topology_revision,
        "topology_snapshot_digest": topology_snapshot_digest,
        "scope_fingerprint": scope_fingerprint,
        "artifact_sha256": artifact_sha256,
        "artifact_mime_type": artifact_mime_type,
        "artifact_width_px": artifact_width_px,
        "artifact_height_px": artifact_height_px,
        "artifact_byte_size": artifact_byte_size,
        "artifact_captured_at": artifact_captured_at,
        "image_preprocessing_policy_version": (
            image_preprocessing_policy_version
        ),
        "validated_at": validated_at,
    }


@runtime_final
class ValidatedCapture:
    """Authority-only sensitive lease accepted by downstream W07+ code."""

    __slots__ = (
        "capture_id",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "privacy_authorization_id",
        "privacy_authorization_digest",
        "capture_authorization_id",
        "capture_authorization_digest",
        "consumption_digest",
        "post_permission_observation_digest",
        "topology_revision",
        "topology_snapshot_digest",
        "scope_fingerprint",
        "artifact_sha256",
        "artifact_mime_type",
        "artifact_width_px",
        "artifact_height_px",
        "artifact_byte_size",
        "artifact_captured_at",
        "image_preprocessing_policy_version",
        "validated_at",
        "validation_digest",
        "_artifact",
        "_released",
        "_lock",
    )

    def __init__(
        self,
        *,
        artifact: CaptureArtifact,
        planned: PlannedExecution,
        authorization: CaptureAuthorization,
        consumed: ConsumedCaptureAuthorization,
        post_permission_observation: PermissionObservation,
        topology: DisplayTopologySnapshot,
        validated_at: datetime,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _VALIDATED_CAPTURE_AUTHORITY:
            raise TypeError("ValidatedCapture can only be created by InputValidator")
        if type(artifact) is not CaptureArtifact:
            raise ValueError("artifact must be CaptureArtifact")
        plan = planned.plan
        values = (
            ("capture_id", artifact.id),
            ("request_id", authorization.request_id),
            ("plan_id", authorization.plan_id),
            ("plan_digest", authorization.plan_digest),
            (
                "planned_execution_digest",
                authorization.planned_execution_digest,
            ),
            (
                "privacy_authorization_id",
                authorization.privacy_authorization_id,
            ),
            (
                "privacy_authorization_digest",
                authorization.privacy_authorization_digest,
            ),
            (
                "capture_authorization_id",
                authorization.capture_authorization_id,
            ),
            (
                "capture_authorization_digest",
                authorization.capture_authorization_digest,
            ),
            ("consumption_digest", consumed.consumption_digest),
            (
                "post_permission_observation_digest",
                post_permission_observation.observation_digest,
            ),
            ("topology_revision", topology.topology_revision),
            ("topology_snapshot_digest", topology.snapshot_digest),
            ("scope_fingerprint", artifact.scope.fingerprint),
            ("artifact_sha256", artifact.sha256),
            ("artifact_mime_type", artifact.mime_type),
            ("artifact_width_px", artifact.width_px),
            ("artifact_height_px", artifact.height_px),
            ("artifact_byte_size", artifact.byte_size),
            ("artifact_captured_at", artifact.captured_at),
            (
                "image_preprocessing_policy_version",
                plan.image_preprocessing_policy_version,
            ),
            ("validated_at", validated_at),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "validation_digest",
            digest256(
                "ValidatedCapture",
                VALIDATED_CAPTURE_SCHEMA_VERSION,
                self._digest_payload(),
            ),
        )
        object.__setattr__(self, "_artifact", artifact)
        object.__setattr__(self, "_released", False)
        object.__setattr__(self, "_lock", RLock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ValidatedCapture metadata is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "ValidatedCapture":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "ValidatedCapture("
            f"capture_id={self.capture_id!r}, plan_id={self.plan_id!r}, "
            f"released={self.is_released!r}, "
            f"validation_digest_prefix={str(self.validation_digest)[:12]!r})"
        )

    @property
    def is_released(self) -> bool:
        with self._lock:
            return self._released

    @property
    def artifact(self) -> CaptureArtifact:
        with self._lock:
            if self._released or self._artifact is None:
                raise _capture_error(
                    "validated_capture",
                    "截图图像引用已经释放。",
                )
            return self._artifact

    def _digest_payload(self) -> dict[str, object]:
        return _validated_payload(
            capture_id=self.capture_id,
            request_id=self.request_id,
            plan_id=self.plan_id,
            plan_digest=self.plan_digest,
            planned_execution_digest=self.planned_execution_digest,
            privacy_authorization_id=self.privacy_authorization_id,
            privacy_authorization_digest=self.privacy_authorization_digest,
            capture_authorization_id=self.capture_authorization_id,
            capture_authorization_digest=self.capture_authorization_digest,
            consumption_digest=self.consumption_digest,
            post_permission_observation_digest=(
                self.post_permission_observation_digest
            ),
            topology_revision=self.topology_revision,
            topology_snapshot_digest=self.topology_snapshot_digest,
            scope_fingerprint=self.scope_fingerprint,
            artifact_sha256=self.artifact_sha256,
            artifact_mime_type=self.artifact_mime_type,
            artifact_width_px=self.artifact_width_px,
            artifact_height_px=self.artifact_height_px,
            artifact_byte_size=self.artifact_byte_size,
            artifact_captured_at=self.artifact_captured_at,
            image_preprocessing_policy_version=(
                self.image_preprocessing_policy_version
            ),
            validated_at=self.validated_at,
        )

    def recompute_digest(self) -> Digest256:
        return digest256(
            "ValidatedCapture",
            VALIDATED_CAPTURE_SCHEMA_VERSION,
            self._digest_payload(),
        )

    def validate_integrity(self) -> None:
        for name in (
            "capture_id",
            "request_id",
            "plan_id",
            "privacy_authorization_id",
            "capture_authorization_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "plan_digest",
            "planned_execution_digest",
            "privacy_authorization_digest",
            "capture_authorization_digest",
            "consumption_digest",
            "post_permission_observation_digest",
            "topology_revision",
            "topology_snapshot_digest",
            "scope_fingerprint",
            "artifact_sha256",
            "validation_digest",
        ):
            require_digest(getattr(self, name), name)
        require_text(
            self.image_preprocessing_policy_version,
            "image_preprocessing_policy_version",
            max_length=256,
        )
        if self.artifact_mime_type != "image/png":
            raise ValueError("validated capture MIME type changed")
        require_plain_int(
            self.artifact_width_px,
            "artifact_width_px",
            minimum=1,
        )
        require_plain_int(
            self.artifact_height_px,
            "artifact_height_px",
            minimum=1,
        )
        require_plain_int(
            self.artifact_byte_size,
            "artifact_byte_size",
            minimum=1,
        )
        require_aware_datetime(
            self.artifact_captured_at,
            "artifact_captured_at",
        )
        require_aware_datetime(self.validated_at, "validated_at")
        if self.recompute_digest() != self.validation_digest:
            raise ValueError("validated capture digest changed")
        with self._lock:
            if type(self._released) is not bool:
                raise ValueError("validated capture release state is invalid")
            if not self._released:
                if type(self._artifact) is not CaptureArtifact:
                    raise ValueError("validated capture artifact is missing")
                self._artifact.validate_integrity()
                if (
                    self._artifact.id != self.capture_id
                    or self._artifact.sha256 != self.artifact_sha256
                    or self._artifact.scope.fingerprint != self.scope_fingerprint
                    or self._artifact.mime_type != self.artifact_mime_type
                    or self._artifact.width_px != self.artifact_width_px
                    or self._artifact.height_px != self.artifact_height_px
                    or self._artifact.byte_size != self.artifact_byte_size
                    or self._artifact.captured_at != self.artifact_captured_at
                ):
                    raise ValueError("validated capture artifact changed")
            elif self._artifact is not None:
                raise ValueError("released capture still retains its artifact")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "capture_id": str(self.capture_id),
            "request_id": str(self.request_id),
            "plan_id": str(self.plan_id),
            "mime_type": self.artifact_mime_type,
            "width_px": self.artifact_width_px,
            "height_px": self.artifact_height_px,
            "byte_size": self.artifact_byte_size,
            "artifact_sha256_prefix": str(self.artifact_sha256)[:12],
            "validation_digest_prefix": str(self.validation_digest)[:12],
            "validated_at": self.validated_at,
            "released": self.is_released,
        }

    def release(self) -> bool:
        """Drop this lease's image reference; immutable bytes are not wiped."""

        with self._lock:
            if self._released:
                return False
            object.__setattr__(self, "_artifact", None)
            object.__setattr__(self, "_released", True)
            return True

    def __enter__(self) -> "ValidatedCapture":
        if self.is_released:
            raise _capture_error(
                "validated_capture",
                "截图图像引用已经释放。",
            )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.release()


@runtime_final
class InputValidator:
    """Issue one downstream authority after post-capture revalidation."""

    __slots__ = ()

    @staticmethod
    def validate(
        *,
        planned: PlannedExecution,
        privacy_authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        consumed: ConsumedCaptureAuthorization,
        capture_ledger: CaptureAuthorizationLedger,
        artifact: CaptureArtifact,
        permission_observation: PermissionObservation,
        topology: DisplayTopologySnapshot,
        now: datetime,
    ) -> ValidatedCapture:
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(privacy_authorization) is not AuthorizationContext:
            raise TypeError("privacy_authorization must be AuthorizationContext")
        if type(consent_ledger) is not ConsentLedger:
            raise TypeError("consent_ledger must be ConsentLedger")
        if type(consumed) is not ConsumedCaptureAuthorization:
            raise TypeError("consumed must be ConsumedCaptureAuthorization")
        if type(capture_ledger) is not CaptureAuthorizationLedger:
            raise TypeError("capture_ledger must be CaptureAuthorizationLedger")
        if type(artifact) is not CaptureArtifact:
            raise TypeError("artifact must be CaptureArtifact")
        if type(permission_observation) is not PermissionObservation:
            raise TypeError("permission_observation must be PermissionObservation")
        if type(topology) is not DisplayTopologySnapshot:
            raise TypeError("topology must be DisplayTopologySnapshot")
        try:
            require_aware_datetime(now, "now")
        except ValueError as error:
            raise _capture_error(
                "input_validation",
                "截图校验时间无效。",
            ) from error
        authorization = consumed.authorization
        try:
            consumed.validate_integrity()
            authorization.validate_integrity()
            artifact.validate_integrity()
            artifact_claim_digest = _capture_artifact_claim_digest(artifact)
        except (TypeError, ValueError, AttributeError) as error:
            raise _capture_error(
                "input_validation",
                "截图图像或消费凭证完整性校验失败。",
            ) from error
        capture_ledger._start_validation_attempt(
            consumed=consumed,
            artifact_claim_digest=artifact_claim_digest,
            _authority=_CAPTURE_VALIDATION_AUTHORITY,
        )
        PrivacyGate().validate_authorization(
            planned=planned,
            authorization=privacy_authorization,
            ledger=consent_ledger,
            now=now,
        )
        PermissionGate.require_granted(
            observation=permission_observation,
            now=now,
        )
        try:
            planned.validate_integrity()
            consumed.validate_integrity()
            authorization.validate_integrity()
            topology.validate_integrity()
            artifact.validate_integrity()
            authorization.constraints.validate_integrity()
            if topology.observed_at != now:
                raise ValueError("topology is not a post-capture snapshot")
            if topology.topology_revision != authorization.topology_revision:
                raise ValueError("display topology changed during capture")
            topology.validate_physical_selected_scope(authorization.scope)
            validate_capture_artifact(
                artifact,
                authorization.constraints,
                stage="input_validation",
            )
        except (CaptureError, PayloadTooLargeError):
            raise
        except (TypeError, ValueError, AttributeError) as error:
            raise _capture_error(
                "input_validation",
                "截图、计划或显示器拓扑完整性校验失败。",
            ) from error

        plan = planned.plan
        if (
            authorization.request_id != plan.request_id
            or authorization.plan_id != plan.plan_id
            or authorization.plan_digest != plan.plan_digest
            or authorization.planned_execution_digest
            != planned.planned_execution_digest
            or authorization.privacy_authorization_id
            != privacy_authorization.authorization_id
            or authorization.privacy_authorization_digest
            != privacy_authorization.authorization_digest
            or authorization.constraints != plan.capture_constraints
            or authorization.scope.display_geometry_revision
            != str(topology.topology_revision)
        ):
            raise _capture_error(
                "input_validation",
                "截图授权未精确绑定当前执行计划。",
            )
        grants = consent_ledger.snapshot_for_ids(
            privacy_authorization.consent_grant_ids
        )
        if any(
            grant.capture_scope_fingerprint is not None
            and grant.capture_scope_fingerprint
            != authorization.scope.fingerprint
            for grant in grants
        ):
            raise _capture_error(
                "input_validation",
                "截图选区不再匹配当前同意范围。",
            )
        if authorization.valid_until is not None and now >= authorization.valid_until:
            raise _capture_error(
                "input_validation",
                "截图授权在校验前已经过期。",
            )
        if (
            artifact.id != authorization.capture_id
            or artifact.scope != authorization.scope
            or artifact.captured_at < consumed.consumed_at
            or artifact.captured_at > now
        ):
            raise _capture_error(
                "input_validation",
                "截图图像未精确绑定一次性授权。",
            )
        rect = authorization.scope.rect
        if (
            rect is None
            or artifact.width_px != rect.width
            or artifact.height_px != rect.height
            or artifact.mime_type != "image/png"
        ):
            raise _capture_error(
                "input_validation",
                "截图编码或真实选区尺寸不一致。",
            )
        capabilities = planned.resolved_pipeline.stages[0].capabilities
        supported_mime_types = capabilities.supported_mime_types
        if (
            type(supported_mime_types) is not tuple
            or artifact.mime_type not in supported_mime_types
        ):
            raise _capture_error(
                "input_validation",
                "当前 Registry 能力快照不接受 PNG 图像。",
            )
        _decode_bounded_png(
            data=artifact.data,
            constraints=authorization.constraints,
            declared_width_px=artifact.width_px,
            declared_height_px=artifact.height_px,
        )
        def complete_validation() -> ValidatedCapture:
            capture_ledger._complete_validation(
                consumed=consumed,
                artifact_claim_digest=artifact_claim_digest,
                _authority=_CAPTURE_VALIDATION_AUTHORITY,
            )
            validated = ValidatedCapture(
                artifact=artifact,
                planned=planned,
                authorization=authorization,
                consumed=consumed,
                post_permission_observation=permission_observation,
                topology=topology,
                validated_at=now,
                _authority=_VALIDATED_CAPTURE_AUTHORITY,
            )
            validated.validate_integrity()
            return validated

        return PrivacyGate()._run_authorized_action(
            planned=planned,
            authorization=privacy_authorization,
            ledger=consent_ledger,
            now=now,
            action=complete_validation,
            _authority=_ATOMIC_PRIVACY_AUTHORITY,
        )


__all__ = [
    "BLACK_LUMA_MAX",
    "CANONICAL_PNG_POLICY_VERSION",
    "MAX_CANONICAL_DECODED_BYTES",
    "MAX_CANONICAL_PNG_CHUNKS",
    "MIN_VISIBLE_LUMA_SPAN",
    "VALIDATED_CAPTURE_SCHEMA_VERSION",
    "CaptureArtifactFactory",
    "InputValidator",
    "ValidatedCapture",
]
