import unittest

from snapquiz.core.legacy import LegacyPipelineDisabledError
from snapquiz.hotkey.global_hotkey import run_global_hotkey, to_pynput_hotkey
from snapquiz.hotkey.stdin_trigger import run_stdin_trigger


class ToPynputHotkeyTest(unittest.TestCase):
    def test_cmd_shift_space(self):
        self.assertEqual(to_pynput_hotkey("cmd+shift+space"), "<cmd>+<shift>+<space>")

    def test_single_letter_stays_bare(self):
        self.assertEqual(to_pynput_hotkey("ctrl+alt+a"), "<ctrl>+<alt>+a")

    def test_aliases_normalized(self):
        self.assertEqual(to_pynput_hotkey("command+option+space"), "<cmd>+<alt>+<space>")

    def test_whitespace_and_case_tolerated(self):
        self.assertEqual(to_pynput_hotkey(" Cmd + Shift + Space "), "<cmd>+<shift>+<space>")

    def test_legacy_stdin_trigger_is_disabled_without_callback(self):
        calls = []
        with self.assertRaises(LegacyPipelineDisabledError):
            run_stdin_trigger(lambda: calls.append("trigger"))
        self.assertEqual(calls, [])

    def test_legacy_global_hotkey_is_disabled_without_callback(self):
        calls = []
        with self.assertRaises(LegacyPipelineDisabledError):
            run_global_hotkey("cmd+shift+space", lambda: calls.append("trigger"))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
