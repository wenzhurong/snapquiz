"""已冻结的 MVP-0 全局热键入口。

键位规范化保持为纯函数；监听器入口在 v3 安全链完成前 fail-closed。
"""
from __future__ import annotations

from typing import Callable, NoReturn

from snapquiz.core.legacy import raise_legacy_pipeline_disabled

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


def run_global_hotkey(
    hotkey_spec: str, on_trigger: Callable[[], None]
) -> NoReturn:
    """拒绝启动旧监听器，不 import pynput、不调用回调。"""

    del hotkey_spec, on_trigger
    raise_legacy_pipeline_disabled()
