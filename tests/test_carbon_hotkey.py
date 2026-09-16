import unittest
from unittest.mock import patch

from snapquiz.hotkey.carbon_hotkey import (
    MODIFIERS,
    VIRTUAL_KEYS,
    HotkeyUnavailable,
    parse_hotkey,
)
from snapquiz.hotkey.global_hotkey import to_pynput_hotkey


class ParseHotkeyTest(unittest.TestCase):
    """只测得动纯解析部分 —— 真正的「收不收得到事件」必须人按键,见类末注释。"""

    def test_default_hotkey(self):
        key, mods = parse_hotkey("cmd+shift+space")
        self.assertEqual(key, VIRTUAL_KEYS["space"])
        self.assertEqual(mods, MODIFIERS["cmd"] | MODIFIERS["shift"])

    def test_aliases_are_accepted(self):
        self.assertEqual(parse_hotkey("command+option+a"), parse_hotkey("cmd+alt+a"))
        self.assertEqual(parse_hotkey("control+shift+z"), parse_hotkey("ctrl+shift+z"))

    def test_case_and_whitespace_tolerated(self):
        self.assertEqual(parse_hotkey(" Cmd + Shift + Space "),
                         parse_hotkey("cmd+shift+space"))

    def test_modifier_order_does_not_matter(self):
        self.assertEqual(parse_hotkey("shift+cmd+space"), parse_hotkey("cmd+shift+space"))

    def test_bare_key_is_refused(self):
        """没有修饰键的热键会吞掉普通按键,必须拒绝。"""

        with self.assertRaises(ValueError):
            parse_hotkey("space")

    def test_missing_main_key_is_refused(self):
        for spec in ("cmd+", "cmd+shift", ""):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                parse_hotkey(spec)

    def test_two_main_keys_is_refused(self):
        with self.assertRaises(ValueError):
            parse_hotkey("cmd+a+b")

    def test_unknown_key_is_refused(self):
        with self.assertRaises(ValueError):
            parse_hotkey("cmd+shift+nosuchkey")

    def test_carbon_masks_are_not_cocoa_masks(self):
        """Carbon 用自己一套修饰键掩码,写错会静默注册成别的组合。"""

        self.assertEqual(MODIFIERS["cmd"], 0x0100)
        self.assertEqual(MODIFIERS["shift"], 0x0200)
        self.assertEqual(MODIFIERS["alt"], 0x0800)
        self.assertEqual(MODIFIERS["ctrl"], 0x1000)

    def test_both_backends_accept_the_same_spec_strings(self):
        """换后端不该让用户改配置。"""

        for spec in ("cmd+shift+space", "ctrl+alt+a", "command+option+space"):
            with self.subTest(spec=spec):
                parse_hotkey(spec)          # Carbon
                to_pynput_hotkey(spec)      # pynput

    def test_missing_cocoa_reports_unavailable(self):
        from snapquiz.hotkey import carbon_hotkey

        with patch.object(
            carbon_hotkey, "_ensure_gui_process",
            side_effect=HotkeyUnavailable("需要 pyobjc-framework-Cocoa"),
        ):
            with self.assertRaises(HotkeyUnavailable):
                carbon_hotkey.CarbonHotkey("cmd+shift+space", lambda: None)

    # 注意:「注册成功」(OSStatus 0) 证明不了热键可用 —— 实测非 bundle 进程会
    # 注册成功却永远收不到事件。而 CGEventPost 合成的按键**不会**触发热键分发
    # (连系统自己的 Cmd+Shift+3 都不触发),所以这件事无法自动化验证。
    # 用 `snapquiz --carbon-selftest` 由人按一次键确认。


if __name__ == "__main__":
    unittest.main()
