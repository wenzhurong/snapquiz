import unittest

from snapquiz.platform._pynput import run_global_hotkey, to_pynput_hotkey
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

    def test_stdin_trigger_calls_back_and_exits_cleanly(self):
        import io
        from unittest.mock import patch

        calls = []
        with patch("sys.stdin", io.StringIO("\n\n")):
            run_stdin_trigger(lambda: calls.append("trigger"))
        self.assertEqual(calls, ["trigger", "trigger"])

    def test_stdin_trigger_survives_eof_immediately(self):
        import io
        from unittest.mock import patch

        calls = []
        with patch("sys.stdin", io.StringIO("")):
            run_stdin_trigger(lambda: calls.append("trigger"))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
