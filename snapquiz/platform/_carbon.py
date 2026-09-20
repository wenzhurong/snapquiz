"""零权限全局热键：Carbon ``RegisterEventHotKey``。

为什么值得做：现在的 ``pynput`` 走的是 CGEventTap，需要 macOS 的**辅助功能**
权限 —— 授予它等于允许该程序读取你所有按键并控制电脑。为一个截图工具开这个
口子不划算。Carbon 的 ``RegisterEventHotKey`` 注册全局热键**不需要任何权限**，
因为它不是在监听所有按键，而是向系统登记「这一个组合归我」。

实现上有两处绕不过去的坑，都已实测：

1. **pyobjc 只暴露了一半。** ``Carbon.RegisterEventHotKey`` 有，但
   ``InstallEventHandler`` / ``GetApplicationEventTarget`` 没有 —— 只注册不装
   handler 是收不到事件的。所以这里用 ``ctypes`` 直接调 Carbon.framework。
2. **必须是 GUI 进程。** 光注册会返回 OSStatus 0 却永远收不到事件。需要先建立
   ``NSApplication`` 拿到 window server 连接，并且事件要由 NSApplication 的
   事件泵分发 —— 裸 ``NSRunLoop`` 不管 Carbon 事件。

``selftest()`` 用来在目标环境里确认这条路真的通，因为「注册成功」本身
证明不了任何事。
"""
from __future__ import annotations

import ctypes
import logging
import time
from typing import Callable, Optional

from snapquiz.platform.base import HotkeyConflict, HotkeyUnavailable

logger = logging.getLogger(__name__)

CARBON_PATH = "/System/Library/Frameworks/Carbon.framework/Carbon"

# Carbon 虚拟键码（与键盘布局无关）。只列常用的；其余用 kVK_ANSI_* 数值。
VIRTUAL_KEYS = {
    "space": 49, "return": 36, "enter": 36, "tab": 48, "escape": 53, "esc": 53,
    "delete": 51, "a": 0, "s": 1, "d": 2, "f": 3, "h": 4, "g": 5, "z": 6,
    "x": 7, "c": 8, "v": 9, "b": 11, "q": 12, "w": 13, "e": 14, "r": 15,
    "y": 16, "t": 17, "o": 31, "u": 32, "i": 34, "p": 35, "l": 37, "j": 38,
    "k": 40, "n": 45, "m": 46,
    "f1": 122, "f2": 120, "f3": 99, "f4": 118, "f5": 96, "f6": 97,
    "f7": 98, "f8": 100, "f9": 101, "f10": 109, "f11": 103, "f12": 111,
    "f19": 80,
}

# Carbon 修饰键掩码（不是 Cocoa 的那套）。
MODIFIERS = {
    "cmd": 0x0100, "command": 0x0100, "meta": 0x0100, "super": 0x0100, "win": 0x0100,
    "shift": 0x0200,
    "alt": 0x0800, "option": 0x0800, "opt": 0x0800,
    "ctrl": 0x1000, "control": 0x1000,
}


class _EventTypeSpec(ctypes.Structure):
    _fields_ = [("eventClass", ctypes.c_uint32), ("eventKind", ctypes.c_uint32)]


class _EventHotKeyID(ctypes.Structure):
    _fields_ = [("signature", ctypes.c_uint32), ("id", ctypes.c_uint32)]


_HANDLER_PROTO = ctypes.CFUNCTYPE(
    ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
)


def _fourcc(text: str) -> int:
    return int.from_bytes(text.encode("ascii"), "big")


K_EVENT_CLASS_KEYBOARD = _fourcc("keyb")
K_EVENT_HOTKEY_PRESSED = 5
SIGNATURE = _fourcc("snpq")


def parse_hotkey(spec: str) -> tuple[int, int]:
    """``"cmd+shift+space"`` → ``(虚拟键码, Carbon 修饰键掩码)``。"""

    modifiers = 0
    key_code: Optional[int] = None
    for raw in spec.split("+"):
        token = raw.strip().lower()
        if not token:
            continue
        if token in MODIFIERS:
            modifiers |= MODIFIERS[token]
        elif token in VIRTUAL_KEYS:
            if key_code is not None:
                raise ValueError(f"热键 {spec!r} 里有多个主键")
            key_code = VIRTUAL_KEYS[token]
        else:
            raise ValueError(f"无法识别的按键 {token!r}(热键:{spec!r})")
    if key_code is None:
        raise ValueError(f"热键 {spec!r} 缺少主键")
    if not modifiers:
        raise ValueError(f"热键 {spec!r} 至少要带一个修饰键,否则会吞掉普通按键")
    return key_code, modifiers


class _CarbonRuntime:
    """把 ctypes 声明集中在一处，避免散落在调用点。"""

    def __init__(self) -> None:
        try:
            self.lib = ctypes.CDLL(CARBON_PATH)
        except OSError as exc:
            raise HotkeyUnavailable(f"加载 Carbon.framework 失败:{exc}") from exc

        lib = self.lib
        lib.GetApplicationEventTarget.restype = ctypes.c_void_p
        lib.InstallEventHandler.restype = ctypes.c_int32
        # ⚠️ 第三个参数是 ItemCount，在 64 位 macOS 上是 `unsigned long`（64 位），
        # 不是 UInt32。声明成 c_uint32 会让被调方读到高 32 位的垃圾，
        # inNumTypes 变成一个巨大的数 —— 于是 handler 注册到一堆越界读出来的
        # 事件类型上。实测症状：outRef 拿到 6 这种非法指针值、热键永远收不到
        # 事件、之后任何键盘事件都可能把进程打成 SIGTRAP。
        lib.InstallEventHandler.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
            ctypes.POINTER(_EventTypeSpec), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.RegisterEventHotKey.restype = ctypes.c_int32
        lib.RegisterEventHotKey.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, _EventHotKeyID,
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.UnregisterEventHotKey.restype = ctypes.c_int32
        lib.UnregisterEventHotKey.argtypes = [ctypes.c_void_p]
        lib.RemoveEventHandler.restype = ctypes.c_int32
        lib.RemoveEventHandler.argtypes = [ctypes.c_void_p]


def _ensure_gui_process():
    """建立 NSApplication，否则注册会「成功」但永远收不到事件。

    ``accessory`` 策略 = 有 window server 连接但不占 Dock。
    """

    try:
        from AppKit import NSApplication, NSApplicationActivationPolicyAccessory
    except ImportError as exc:
        raise HotkeyUnavailable("需要 pyobjc-framework-Cocoa") from exc

    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
    return app


class CarbonHotkey:
    """注册一个全局热键并在 NSApplication 事件泵里分发它。"""

    def __init__(self, spec: str, on_trigger: Callable[[], None]) -> None:
        self._key_code, self._modifiers = parse_hotkey(spec)
        self._spec = spec
        self._on_trigger = on_trigger
        self._runtime = _CarbonRuntime()
        self._app = _ensure_gui_process()
        self._hotkey_ref = ctypes.c_void_p()
        self._handler_ref = ctypes.c_void_p()
        self._stop = False
        # CFUNCTYPE 回调必须自己保活，否则会被 GC 掉、系统回调进野指针。
        self._callback = _HANDLER_PROTO(self._dispatch)

    def _dispatch(self, call_ref, event, user_data) -> int:
        del call_ref, event, user_data
        try:
            self._on_trigger()
        except Exception:
            logger.exception("热键回调抛错")
        return 0  # noErr

    def install(self) -> None:
        lib = self._runtime.lib
        target = lib.GetApplicationEventTarget()
        if not target:
            raise HotkeyUnavailable("拿不到 application event target")

        spec = _EventTypeSpec(K_EVENT_CLASS_KEYBOARD, K_EVENT_HOTKEY_PRESSED)
        status = lib.InstallEventHandler(
            target, ctypes.cast(self._callback, ctypes.c_void_p), 1,
            ctypes.byref(spec), None, ctypes.byref(self._handler_ref),
        )
        if status != 0:
            raise HotkeyUnavailable(f"InstallEventHandler 失败 (OSStatus {status})")

        status = lib.RegisterEventHotKey(
            self._key_code, self._modifiers, _EventHotKeyID(SIGNATURE, 1),
            target, 0, ctypes.byref(self._hotkey_ref),
        )
        if status != 0:
            # -9878 = eventHotKeyExistsErr：组合已被别的 app 占用（D8）。
            if status == -9878:
                raise HotkeyConflict(self._spec, "eventHotKeyExistsErr")
            raise HotkeyUnavailable(
                f"注册热键 {self._spec} 失败 (OSStatus {status})"
            )

    def stop(self) -> None:
        self._stop = True

    def pump(self, *, timeout: Optional[float] = None, strategy: str = "manual") -> None:
        """跑事件泵直到 ``stop()`` 或超时。

        两种策略都保留，因为**无法在本机自动验证哪种有效**：macOS 的热键分发层
        忽略 ``CGEventPost`` 合成的按键（实测连系统自己的 Cmd+Shift+3 都不触发），
        所以只有真人按键能验证。``selftest()`` 会让用户按一次，两种都试。

        - ``manual``：``nextEventMatchingMask`` + ``sendEvent:``。可随时停止。
        - ``run``：真正的 ``NSApp.run()``。更接近 Carbon 文档里的标准姿势，
          但只能从主线程（热键回调或 NSTimer）里 ``stop_``。
        """

        if strategy == "run":
            self._pump_with_nsapp_run(timeout)
            return

        from AppKit import NSAnyEventMask, NSDefaultRunLoopMode
        from Foundation import NSDate

        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._stop:
            if deadline is not None and time.monotonic() >= deadline:
                return
            event = self._app.nextEventMatchingMask_untilDate_inMode_dequeue_(
                NSAnyEventMask,
                NSDate.dateWithTimeIntervalSinceNow_(0.1),
                NSDefaultRunLoopMode,
                True,
            )
            if event is not None:
                self._app.sendEvent_(event)

    def _pump_with_nsapp_run(self, timeout: Optional[float]) -> None:
        """``NSApp.run()`` 版本。用 NSTimer 在主线程上停它 ——
        从别的线程 ``stop_`` 不可靠。"""

        from Foundation import NSTimer

        app = self._app
        if timeout is not None:
            NSTimer.scheduledTimerWithTimeInterval_repeats_block_(
                timeout, False, lambda _timer: app.stop_(None)
            )
        app.run()

    def uninstall(self) -> None:
        """解注册热键**并移除事件 handler**。

        ⚠️ 只解注册热键是不够的：handler 是一个 ctypes 回调，留在系统的
        application event target 上；本对象被 GC 之后 ``self._callback``
        随之释放，系统就持有了一个**指向已释放内存的函数指针**，下一个键盘
        事件到来时进程 SIGTRAP。

        这是 B0-2 的对照组实验撞出来的：同进程先跑 Carbon 再跑 pynput，
        第二轮必崩（exit 133）。单独跑任何一个都正常，所以很容易误判成
        「pynput 和 Qt 不兼容」。
        """

        lib = self._runtime.lib
        if self._hotkey_ref:
            lib.UnregisterEventHotKey(self._hotkey_ref)
            self._hotkey_ref = ctypes.c_void_p()
        if self._handler_ref:
            lib.RemoveEventHandler(self._handler_ref)
            self._handler_ref = ctypes.c_void_p()


class CarbonHotkeyHandle:
    """符合 ``platform.base.HotkeyHandle`` 的句柄。

    注意：装上不等于会收到事件 —— Carbon 事件要由**宿主的** NSApplication
    循环分发。B0-5 之后宿主是 Qt；在那之前调用方得自己 ``pump``。
    """

    __slots__ = ("_hotkey",)

    def __init__(self, hotkey: "CarbonHotkey") -> None:
        self._hotkey = hotkey

    def unregister(self) -> None:
        self._hotkey.stop()
        self._hotkey.uninstall()

    def pump(self, *, timeout: Optional[float] = None, strategy: str = "manual") -> None:
        """仅供尚未把循环交给 Qt 的宿主使用。"""

        self._hotkey.pump(timeout=timeout, strategy=strategy)


def install(spec: str, on_trigger: Callable[[], None]) -> CarbonHotkeyHandle:
    """装上热键并立即返回。不阻塞、不起循环。"""

    hotkey = CarbonHotkey(spec, on_trigger)
    hotkey.install()
    return CarbonHotkeyHandle(hotkey)


def run_carbon_hotkey(spec: str, on_trigger: Callable[[], None]) -> None:
    """阻塞运行，直到进程被中断。签名与 ``run_global_hotkey`` 一致。"""

    hotkey = CarbonHotkey(spec, on_trigger)
    hotkey.install()
    try:
        hotkey.pump()
    finally:
        hotkey.uninstall()


def selftest(spec: str = "cmd+shift+space", seconds: float = 15.0) -> bool:
    """在**当前进程形态下**确认这条路真的通。需要你亲手按一次组合键。

    为什么必须人来按：macOS 的热键分发层**忽略 CGEventPost 合成的按键** ——
    实测连系统自己的 Cmd+Shift+3 截图热键都不会被合成事件触发。所以
    「注册成功」（OSStatus 0）本身证明不了任何事，自检只能等真实按键。

    两种事件泵各试一轮，一次按键就能知道哪种（如果有的话）可用。
    """

    for strategy, label in (("manual", "nextEventMatchingMask"), ("run", "NSApp.run()")):
        fired: list[float] = []
        try:
            hotkey = CarbonHotkey(spec, lambda: fired.append(time.monotonic()))
            hotkey.install()
        except (HotkeyUnavailable, ValueError) as exc:
            print(f"❌ {exc}")
            return False

        print(f"\n[{label}] 已注册 {spec},全程未请求任何权限。")
        print(f"   请在 {seconds:.0f} 秒内按一次 {spec} ……", flush=True)
        try:
            def _stop_on_fire() -> None:
                fired.append(time.monotonic())
                hotkey.stop()
                hotkey._app.stop_(None)

            hotkey._on_trigger = _stop_on_fire
            hotkey.pump(timeout=seconds, strategy=strategy)
        finally:
            hotkey.uninstall()

        if fired:
            print(f"✅ 收到触发 —— Carbon 零权限热键可用,事件泵用 {label}。")
            return True
        print(f"   [{label}] 没收到。")

    print("\n❌ 两种事件泵都没收到。注册成功(OSStatus 0)但事件不投递,")
    print("   说明当前进程形态拿不到热键投递资格。继续用 pynput(需辅助功能权限)。")
    return False
