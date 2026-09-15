import unittest

from snapquiz.capture.screen import region_to_monitor
from snapquiz.capture.validation import (
    CaptureQualityError,
    check_dimensions,
    check_frame_quality,
    check_png_size,
)
from tests.helpers import gradient_rgb, solid_rgb

PRIMARY = {"left": 0, "top": 0, "width": 1280, "height": 800}


class RegionTest(unittest.TestCase):
    def test_explicit_region_is_used(self):
        self.assertEqual(
            region_to_monitor((10, 20, 640, 480), PRIMARY),
            {"left": 10, "top": 20, "width": 640, "height": 480},
        )

    def test_none_region_is_refused_not_fullscreen(self):
        """原审计第 2 条:未配置区域时默认抓全屏会把隐私内容一并上传。"""

        with self.assertRaises(ValueError):
            region_to_monitor(None, PRIMARY)


class FrameQualityTest(unittest.TestCase):
    def test_gradient_passes(self):
        check_frame_quality(gradient_rgb(64, 8), 64, 8)

    def test_black_frame_is_refused(self):
        with self.assertRaises(CaptureQualityError) as ctx:
            check_frame_quality(solid_rgb(64, 8, value=0), 64, 8)
        self.assertIn("黑帧", str(ctx.exception))

    def test_blank_frame_is_refused(self):
        with self.assertRaises(CaptureQualityError) as ctx:
            check_frame_quality(solid_rgb(64, 8, value=200), 64, 8)
        self.assertIn("空白", str(ctx.exception))

    def test_buffer_length_must_match_dimensions(self):
        with self.assertRaises(CaptureQualityError):
            check_frame_quality(solid_rgb(10, 10), 64, 8)

    def test_dimension_limits(self):
        check_dimensions(640, 480)
        for w, h in ((0, 10), (10, 0), (20_000, 10), (10, 20_000)):
            with self.subTest(w=w, h=h), self.assertRaises(CaptureQualityError):
                check_dimensions(w, h)

    def test_png_size_limits(self):
        check_png_size(b"x" * 1024)
        with self.assertRaises(CaptureQualityError):
            check_png_size(b"")
        with self.assertRaises(CaptureQualityError):
            check_png_size(b"x" * (9 * 1024 * 1024))

    def test_error_text_carries_no_pixels(self):
        try:
            check_frame_quality(solid_rgb(64, 8, value=0), 64, 8)
        except CaptureQualityError as exc:
            self.assertNotIn("\x00", str(exc))


if __name__ == "__main__":
    unittest.main()
