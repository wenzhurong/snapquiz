"""真·全局热键(基于 pynput)。

注意:pynput 的全局键盘监听在 macOS 上需要「辅助功能(Accessibility)」权限。
这是 MVP-0 为了让你尽快体验「随处按键触发」而做的务实选择;架构里的
零权限 Carbon(RegisterEventHotKey)方案留待 MVP-1(可能改用签名 Swift helper)。

to_pynput_hotkey 是纯函数(可测);监听循环用 pynput(惰性 import)。
"""
from __future__ import annotations

from typing import Callable

_ALIASES = {
    "command": "cmd",
    "cmd": "cmd",
    "win": "cmd",
    "super": "cmd",
    "meta": "cmd",
    "control": "ctrl",
    "ctrl": "ctrl",
    "option": "alt",
    "alt": "alt",
    "shift": "shift",
}


def to_pynput_hotkey(spec: str) -> str:
    """把 'cmd+shift+space' 转成 pynput 的 '<cmd>+<shift>+<space>'。

    单字符键(如 'a')保持裸写,具名键/修饰键用 <...> 包裹。
    """
    tokens = []
    for raw in spec.split("+"):
        part = raw.strip().lower()
        if not part:
            continue
        part = _ALIASES.get(part, part)
        tokens.append(part if len(part) == 1 else f"<{part}>")
    return "+".join(tokens)


def run_global_hotkey(hotkey_spec: str, on_trigger: Callable[[], None]) -> None:
    """阻塞运行全局热键监听,直到进程被中断。"""
    from pynput import keyboard

    combo = to_pynput_hotkey(hotkey_spec)
    print(f"全局热键已就绪:{hotkey_spec}(需已授予辅助功能权限)。Ctrl+C 退出。", flush=True)
    with keyboard.GlobalHotKeys({combo: on_trigger}) as listener:
        listener.join()
