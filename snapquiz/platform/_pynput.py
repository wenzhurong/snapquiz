"""全局热键的 pynput 后端。

pynput 走的是 CGEventTap，**需要 macOS 的辅助功能权限** —— 那个权限等于允许
程序读取你所有按键并控制电脑。零权限的 Carbon 后端见 ``_carbon.py``；
B0-2 验证通过后这个文件应当整个删掉（见 SPEC_B0_PLATFORM §3）。

原文档：

注意:pynput 的全局键盘监听在 macOS 上需要「辅助功能(Accessibility)」权限。
这是 MVP-0 为了让你尽快体验「随处按键触发」而做的务实选择;架构里的
零权限 Carbon(RegisterEventHotKey)方案留待 MVP-1(可能改用签名 Swift helper)。

to_pynput_hotkey 是纯函数(可测);监听循环用 pynput(惰性 import)。
"""
from __future__ import annotations

from typing import Callable

from snapquiz.platform.base import HotkeyUnavailable

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


class PynputHotkeyHandle:
    """符合 ``platform.base.HotkeyHandle`` 的句柄。

    pynput 的监听器自带线程，所以这个后端天然是非阻塞的 ——
    不需要宿主提供事件循环。
    """

    __slots__ = ("_listener",)

    def __init__(self, listener) -> None:
        self._listener = listener

    def unregister(self) -> None:
        try:
            self._listener.stop()
        except Exception:  # pragma: no cover - 停一个已停的监听器
            pass


def install(spec: str, on_trigger: Callable[[], None]) -> PynputHotkeyHandle:
    """装上热键并立即返回。"""

    try:
        from pynput import keyboard
    except ImportError as exc:
        raise HotkeyUnavailable(
            "需要 pynput：pip install -e \".[hotkey]\""
        ) from exc

    combo = to_pynput_hotkey(spec)
    listener = keyboard.GlobalHotKeys({combo: on_trigger})
    listener.start()
    return PynputHotkeyHandle(listener)


def run_global_hotkey(hotkey_spec: str, on_trigger: Callable[[], None]) -> None:
    """阻塞运行,直到进程被中断。保留给终端开发模式。"""

    from pynput import keyboard

    combo = to_pynput_hotkey(hotkey_spec)
    print(f"全局热键已就绪:{hotkey_spec}(需已授予辅助功能权限)。Ctrl+C 退出。", flush=True)
    with keyboard.GlobalHotKeys({combo: on_trigger}) as listener:
        listener.join()
