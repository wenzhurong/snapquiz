import hashlib
import unittest
from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timezone
from uuid import UUID

from snapquiz.domain.capture import (
    CaptureArtifact,
    CaptureConstraints,
    CaptureRect,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
    validate_capture_artifact,
)
from snapquiz.domain.errors import CaptureError, PayloadTooLargeError


def selected_scope(**overrides):
    values = {
        "kind": CaptureScopeKind.SELECTED_REGION,
        "display_id": "display-1",
        "coordinate_space": CoordinateSpace.PHYSICAL_PIXELS,
        "rect": CaptureRect(left=10, top=-20, width=640, height=480),
        "display_geometry_revision": "geometry-v1",
    }
    values.update(overrides)
    return CaptureScope(**values)


def artifact(scope=None, **overrides):
    values = {
        "id": UUID("00000000-0000-0000-0000-000000000001"),
        "data": b"synthetic-image-bytes",
        "mime_type": "image/png",
        "width_px": 640,
        "height_px": 480,
        "scope": scope or selected_scope(),
        "captured_at": datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return CaptureArtifact(**values)


def constraints(**overrides):
    values = {
        "allowed_display_ids": ("display-1",),
        "max_width_px": 2_000,
        "max_height_px": 2_000,
        "max_pixels": 4_000_000,
        "max_bytes": 1_000_000,
        "allow_full_screen": False,
    }
    values.update(overrides)
    return CaptureConstraints(**values)


class CaptureContractTest(unittest.TestCase):
    def test_security_value_objects_are_runtime_final(self):
        for cls in (CaptureRect, CaptureScope, CaptureArtifact, CaptureConstraints):
            with self.subTest(cls=cls), self.assertRaises(TypeError):
                type(f"Evil{cls.__name__}", (cls,), {})

    def test_scope_fingerprint_is_deterministic_and_geometry_bound(self):
        first = selected_scope()
        same = selected_scope()
        changed = selected_scope(display_geometry_revision="geometry-v2")
        self.assertEqual(first.fingerprint, same.fingerprint)
        self.assertNotEqual(first.fingerprint, changed.fingerprint)
        self.assertEqual(
            first.fingerprint,
            "96f1d0e42c8f16210619fb4a8f4368adece94fe78aba9c02c93be9f70418ecfb",
        )

    def test_selected_region_requires_rect(self):
        with self.assertRaises(ValueError):
            selected_scope(rect=None)

    def test_full_screen_must_not_carry_rect(self):
        with self.assertRaises(ValueError):
            selected_scope(kind=CaptureScopeKind.FULL_SCREEN)

    def test_artifact_computes_content_metadata(self):
        value = artifact()
        self.assertEqual(value.byte_size, len(value.data))
        self.assertEqual(value.sha256, hashlib.sha256(value.data).hexdigest())
        self.assertNotIn("synthetic-image-bytes", repr(value))
        self.assertNotIn(str(value.sha256), repr(value))
        with self.assertRaises(TypeError):
            asdict(value)
        with self.assertRaises(FrozenInstanceError):
            value.width_px = 1

    def test_artifact_rejects_mutable_bytes_and_naive_time(self):
        with self.assertRaises(ValueError):
            artifact(data=bytearray(b"mutable"))
        with self.assertRaises(ValueError):
            artifact(captured_at=datetime(2026, 8, 28, 12, 0))
        with self.assertRaises(ValueError):
            artifact(captured_at="2026-08-28T12:00:00Z")
        with self.assertRaises(ValueError):
            artifact(mime_type=[])

    def test_validator_rechecks_content_and_scope_integrity(self):
        value = artifact()
        object.__setattr__(value, "data", b"mutated")
        with self.assertRaises(CaptureError):
            validate_capture_artifact(value, constraints())

        value = artifact()
        object.__setattr__(
            value.scope, "fingerprint", type(value.scope.fingerprint)("0" * 64)
        )
        with self.assertRaises(CaptureError):
            validate_capture_artifact(value, constraints())

    def test_constraints_accept_valid_selected_region(self):
        self.assertIsNone(validate_capture_artifact(artifact(), constraints()))

    def test_constraints_reject_full_screen_by_default(self):
        scope = CaptureScope(
            kind=CaptureScopeKind.FULL_SCREEN,
            display_id="display-1",
            coordinate_space=CoordinateSpace.PHYSICAL_PIXELS,
            rect=None,
            display_geometry_revision="geometry-v1",
        )
        with self.assertRaises(CaptureError):
            validate_capture_artifact(artifact(scope), constraints())

    def test_constraints_reject_unknown_display(self):
        with self.assertRaises(CaptureError):
            validate_capture_artifact(
                artifact(selected_scope(display_id="display-2")), constraints()
            )

    def test_constraints_reject_dimension_pixel_and_byte_limits(self):
        cases = (
            (artifact(width_px=2_001), constraints()),
            (artifact(width_px=1_000, height_px=1_000), constraints(max_pixels=999_999)),
            (artifact(data=b"12345"), constraints(max_bytes=4)),
        )
        for value, policy in cases:
            with self.subTest(value=value), self.assertRaises(PayloadTooLargeError):
                validate_capture_artifact(value, policy)


if __name__ == "__main__":
    unittest.main()
