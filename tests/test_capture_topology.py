import unittest
from datetime import timedelta

from snapquiz.capture.topology import (
    MAX_DISPLAY_DIMENSION,
    DisplayGeometrySnapshot,
    DisplayTopologySnapshot,
)
from snapquiz.domain.capture import (
    CaptureRect,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
)
from snapquiz.domain.digest import Digest256

from tests.w06_helpers import NOW, selected_scope, topology


class DisplayTopologyContractTest(unittest.TestCase):
    def test_canonical_topology_revision_is_geometry_only(self):
        first = topology(observed_at=NOW)
        later = topology(observed_at=NOW + timedelta(seconds=1))

        self.assertEqual(first.topology_revision, later.topology_revision)
        self.assertNotEqual(first.snapshot_digest, later.snapshot_digest)
        self.assertEqual(
            tuple(display.display_id for display in first.displays),
            ("display-1", "display-2"),
        )
        first.validate_integrity()
        later.validate_integrity()

    def test_topology_requires_nonempty_sorted_unique_exact_snapshots(self):
        valid = topology()
        first, second = valid.displays

        cases = (
            (),
            (second, first),
            (first, first),
            [first, second],
        )
        for displays in cases:
            with self.subTest(displays=displays), self.assertRaises(ValueError):
                DisplayTopologySnapshot(  # type: ignore[arg-type]
                    displays=displays,
                    observed_at=NOW,
                )

    def test_geometry_bounds_are_display_local_physical_pixels(self):
        display = topology().require_display("display-1")

        accepted = (
            CaptureRect(left=0, top=0, width=1, height=1),
            CaptureRect(left=0, top=0, width=2_560, height=1_600),
            CaptureRect(left=2_559, top=1_599, width=1, height=1),
        )
        rejected = (
            CaptureRect(left=-1, top=0, width=1, height=1),
            CaptureRect(left=0, top=-1, width=1, height=1),
            CaptureRect(left=2_560, top=0, width=1, height=1),
            CaptureRect(left=0, top=1_600, width=1, height=1),
            CaptureRect(left=2_559, top=0, width=2, height=1),
        )
        for rect in accepted:
            with self.subTest(rect=rect):
                self.assertTrue(display.contains_physical_rect(rect))
        for rect in rejected:
            with self.subTest(rect=rect):
                self.assertFalse(display.contains_physical_rect(rect))

    def test_selected_physical_scope_must_match_topology_and_display(self):
        value = topology()
        value.validate_physical_selected_scope(selected_scope(value))

        cases = (
            selected_scope(
                value,
                display_geometry_revision=str(Digest256("a" * 64)),
            ),
            selected_scope(value, display_id="missing-display"),
            selected_scope(
                value,
                coordinate_space=CoordinateSpace.SCREEN_POINTS,
            ),
            selected_scope(
                value,
                rect=CaptureRect(left=2_500, top=0, width=100, height=100),
            ),
        )
        for scope in cases:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                value.validate_physical_selected_scope(scope)

    def test_whole_display_rectangle_and_full_screen_scope_are_rejected(self):
        value = topology()
        whole_display = selected_scope(
            value,
            rect=CaptureRect(left=0, top=0, width=2_560, height=1_600),
        )
        full_screen = CaptureScope(
            kind=CaptureScopeKind.FULL_SCREEN,
            display_id="display-1",
            coordinate_space=CoordinateSpace.PHYSICAL_PIXELS,
            rect=None,
            display_geometry_revision=str(value.topology_revision),
        )

        for scope in (whole_display, full_screen):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                value.validate_physical_selected_scope(scope)

    def test_integrity_validation_detects_geometry_and_topology_tampering(self):
        geometry = topology().displays[0]
        object.__setattr__(geometry, "geometry_digest", Digest256("b" * 64))
        with self.assertRaises(ValueError):
            geometry.validate_integrity()

        value = topology()
        object.__setattr__(value, "topology_revision", Digest256("c" * 64))
        with self.assertRaises(ValueError):
            value.validate_integrity()

        value = topology()
        object.__setattr__(value, "snapshot_digest", Digest256("d" * 64))
        with self.assertRaises(ValueError):
            value.validate_integrity()

    def test_geometry_hard_limit_and_unknown_display_fail_closed(self):
        with self.assertRaises(ValueError):
            DisplayGeometrySnapshot(
                display_id="oversized",
                screen_point_bounds=CaptureRect(left=0, top=0, width=1, height=1),
                pixel_width_px=MAX_DISPLAY_DIMENSION + 1,
                pixel_height_px=1,
            )
        with self.assertRaises(LookupError):
            topology().require_display("unknown")


if __name__ == "__main__":
    unittest.main()
