import unittest

from snapquiz.capture.screen import region_to_monitor


class RegionToMonitorTest(unittest.TestCase):
    def test_none_region_returns_primary(self):
        primary = {"left": 0, "top": 0, "width": 1440, "height": 900}
        self.assertEqual(region_to_monitor(None, primary), primary)

    def test_region_tuple_becomes_monitor_dict(self):
        primary = {"left": 0, "top": 0, "width": 1440, "height": 900}
        self.assertEqual(
            region_to_monitor((10, 20, 300, 400), primary),
            {"left": 10, "top": 20, "width": 300, "height": 400},
        )


if __name__ == "__main__":
    unittest.main()
