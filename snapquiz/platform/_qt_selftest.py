"""在**真正的 Qt 事件循环**里验证零权限热键 —— B0-2。

## 为什么需要这个

`_carbon.py` 的 Carbon 热键注册成功（OSStatus 0）却收不到事件。四种进程形态
都试过，其中**三种是手搓的事件泵，不是真正的 NSApplication 循环**。
Qt 在 macOS 上跑的恰好是真正的 NSApplication 循环 —— 这是待验证的假设。

## 为什么必须人来按

macOS 的热键分发层**忽略 `CGEventPost` 合成的按键**。实测过：合成系统自己的
Cmd+Shift+3 截图热键，桌面上不会出现截图。所以自动化验证在原理上不可能。

## 为什么带对照组

上一轮我差点从「Carbon 收不到」直接得出「Carbon 不可用」，而真相是测试装置
本身验证不了这件事。pynput 是已知可用的对照组：

| carbon | pynput | 结论 |
|---|---|---|
| ✅ | ✅ | Carbon 可用 → 删 pynput，摆脱辅助功能权限 |
| ❌ | ✅ | Carbon 在 Qt 里也收不到 → 删 `_carbon.py`，留 pynput |
| ❌ | ❌ | **测试装置有问题**，不能下任何结论 |

## 为什么每个后端跑在独立子进程里

同进程先装 Carbon 再装 pynput 会 SIGTRAP（实测 exit 133）。根因在 Carbon 这
边的 ctypes 绑定，但**不该让一个待验证后端的缺陷污染对照组** —— 那正好会制造
上表第三行那种「都没收到」的假象。子进程隔离一劳永逸。
"""
from __future__ import annotations

import subprocess
import sys
from typing import Optional

#: 三个修饰键 + J，macOS 自身没有占用，冲突概率低。
DEFAULT_SELFTEST_HOTKEY = "ctrl+alt+cmd+j"
DEFAULT_WAIT_SECONDS = 20.0

EXIT_FIRED = 0
EXIT_NOT_FIRED = 10
EXIT_CANNOT_INSTALL = 20

_BACKENDS = (
    ("carbon", "Carbon（零权限，待验证）"),
    ("pynput", "pynput（需辅助功能权限，对照组）"),
)


# ---------------------------------------------------------------------------
# 子进程：只装一个后端，跑一轮 Qt 循环
# ---------------------------------------------------------------------------


def _child(backend: str, spec: str, seconds: float) -> int:
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print('需要 PySide6:pip install -e ".[gui]"', file=sys.stderr)
        return EXIT_CANNOT_INSTALL

    app = QApplication.instance() or QApplication([])
    try:  # 有 window server 连接但不占 Dock
        from AppKit import NSApplication, NSApplicationActivationPolicyAccessory

        NSApplication.sharedApplication().setActivationPolicy_(
            NSApplicationActivationPolicyAccessory
        )
    except Exception:
        pass

    if backend == "carbon":
        from snapquiz.platform import _carbon as impl
    else:
        from snapquiz.platform import _pynput as impl

    from snapquiz.platform.base import HotkeyUnavailable

    fired: list[int] = []

    try:
        handle = impl.install(spec, lambda: (fired.append(1), app.quit()))
    except HotkeyUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CANNOT_INSTALL

    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(app.quit)
    timer.start(int(seconds * 1000))
    try:
        app.exec()  # ← 真正的 NSApplication 循环，整个实验的关键
    finally:
        timer.stop()
        try:
            handle.unregister()
        except Exception:
            pass
    return EXIT_FIRED if fired else EXIT_NOT_FIRED


# ---------------------------------------------------------------------------
# 父进程：依次跑两个后端，汇总
# ---------------------------------------------------------------------------


def _trial(backend: str, spec: str, seconds: float) -> Optional[bool]:
    """返回 True=收到、False=没收到、None=装不上。"""

    completed = subprocess.run(
        [sys.executable, "-m", "snapquiz.platform._qt_selftest",
         "--backend", backend, "--spec", spec, "--seconds", str(seconds)],
        capture_output=True,
        text=True,
    )
    if completed.returncode == EXIT_FIRED:
        return True
    if completed.returncode == EXIT_NOT_FIRED:
        return False
    detail = (completed.stderr or "").strip().splitlines()
    if detail:
        print(f"   ⚠️ {detail[-1]}")
    elif completed.returncode < 0 or completed.returncode > 128:
        print(f"   ⚠️ 子进程异常退出(signal/exit {completed.returncode})")
    return None


def run(
    spec: str = DEFAULT_SELFTEST_HOTKEY,
    seconds: float = DEFAULT_WAIT_SECONDS,
) -> bool:
    """跑完整实验。返回「Carbon 可用」。"""

    print("=" * 68)
    print("B0-2:在 Qt 事件循环里验证零权限热键")
    print("=" * 68)
    print()
    print(f"  组合     {spec}")
    print(f"  要按     2 次 —— 两个后端各一次,会分别提示")
    print(f"  每次等   {seconds:.0f} 秒")
    print()
    print("  为什么要你按:macOS 的热键分发层忽略程序合成的按键,这件事")
    print("  在原理上无法自动验证。第二轮 pynput 是对照组 —— 没有它,")
    print("  「两个都没收到」会被误读成「Carbon 不行」。")
    print()

    results: dict[str, Optional[bool]] = {}
    for backend, label in _BACKENDS:
        print(f"── {label} ──")
        print(f"   现在请按 {spec} ……", flush=True)
        results[backend] = _trial(backend, spec, seconds)
        print("   " + {True: "✅ 收到", False: "❌ 没收到", None: "— 装不上"}[
            results[backend]])
        print()

    carbon, pynput = results.get("carbon"), results.get("pynput")

    print("=" * 68)
    if carbon:
        print("✅ Carbon 零权限热键在 Qt 事件循环里**可用**。")
        print("   → 删掉 _pynput.py,.app 从此不再需要辅助功能权限。")
        return True
    if pynput:
        print("❌ Carbon 在 Qt 循环里仍然收不到事件;pynput 正常。")
        print("   → 删掉 _carbon.py(297 行),保留 pynput。不留死代码。")
        return False
    print("⚠️ 两个后端都没收到 —— **测试装置本身有问题,不能下结论**。")
    print("   可能:组合被别的程序占用 / 终端没有辅助功能权限 / 没按到。")
    print(f"   换个组合再试:--selftest-hotkey ctrl+alt+cmd+k")
    return False


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="snapquiz.platform._qt_selftest")
    parser.add_argument("--backend", choices=("carbon", "pynput"))
    parser.add_argument("--spec", default=DEFAULT_SELFTEST_HOTKEY)
    parser.add_argument("--seconds", type=float, default=DEFAULT_WAIT_SECONDS)
    args = parser.parse_args(argv)

    if args.backend is None:  # 直接跑本模块 = 跑完整实验
        return EXIT_FIRED if run(args.spec, args.seconds) else EXIT_NOT_FIRED
    return _child(args.backend, args.spec, args.seconds)


__all__ = [
    "DEFAULT_SELFTEST_HOTKEY",
    "DEFAULT_WAIT_SECONDS",
    "EXIT_CANNOT_INSTALL",
    "EXIT_FIRED",
    "EXIT_NOT_FIRED",
    "run",
]


if __name__ == "__main__":
    raise SystemExit(_main())
