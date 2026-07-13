"""stdin 触发(MVP-0 默认):聚焦终端按 Enter 触发一次答题。

零权限、零额外依赖,用来最快验证「截屏 → GLM → 答案」核心链路。
"""
from __future__ import annotations

from typing import Callable


def run_stdin_trigger(on_trigger: Callable[[], None]) -> None:
    print("按 Enter 触发一次答题(Ctrl+C / Ctrl+D 退出)...", flush=True)
    try:
        while True:
            input()
            on_trigger()
    except (EOFError, KeyboardInterrupt):
        print("\n再见。", flush=True)
