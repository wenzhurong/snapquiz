import unittest

from snapquiz.hotkey.global_hotkey import to_pynput_hotkey


class ToPynputHotkeyTest(unittest.TestCase):
    def test_cmd_shift_space(self):
        self.assertEqual(to_pynput_hotkey("cmd+shift+space"), "<cmd>+<shift>+<space>")

    def test_single_letter_stays_bare(self):
        self.assertEqual(to_pynput_hotkey("ctrl+alt+a"), "<ctrl>+<alt>+a")

    def test_aliases_normalized(self):
        self.assertEqual(to_pynput_hotkey("command+option+space"), "<cmd>+<alt>+<space>")

    def test_whitespace_and_case_tolerated(self):
        self.assertEqual(to_pynput_hotkey(" Cmd + Shift + Space "), "<cmd>+<shift>+<space>")


if __name__ == "__main__":
    unittest.main()
