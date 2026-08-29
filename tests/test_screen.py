import unittest

from snapquiz.capture.screen import capture_data_url, capture_png_bytes, region_to_monitor
from snapquiz.core.legacy import LegacyPipelineDisabledError


class RegionToMonitorTest(unittest.TestCase):
    def test_none_region_is_rejected_instead_of_full_screen(self):
        primary = {"left": 0, "top": 0, "width": 1440, "height": 900}
        with self.assertRaises(ValueError):
            region_to_monitor(None, primary)

    def test_region_tuple_becomes_monitor_dict(self):
        primary = {"left": 0, "top": 0, "width": 1440, "height": 900}
        self.assertEqual(
            region_to_monitor((10, 20, 300, 400), primary),
            {"left": 10, "top": 20, "width": 300, "height": 400},
        )

    def test_legacy_capture_entrypoints_are_disabled(self):
        for capture in (capture_png_bytes, capture_data_url):
            with self.subTest(capture=capture.__name__):
                with self.assertRaises(LegacyPipelineDisabledError):
                    capture((10, 20, 300, 400))


if __name__ == "__main__":
    unittest.main()
