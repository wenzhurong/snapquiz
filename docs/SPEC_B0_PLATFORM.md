# B0：平台层抽象 — 规格

> **状态**：待执行。这是 v2（双端 + 设置页 + 双答案模式）的第一步，
> 也是**前置**：在它完成之前不写任何新 UI，否则每个功能都要写两遍。
>
> 本文只管 B0。B1–B5 的决策记录在 §1，是为了固定 B0 的接口形状，不是实施细则。
>
> 篇幅刻意压到最短。这个项目死过一次，死因之一就是 1,571 行的规范文档
> （见 [`RECOVERY_PLAN.md`](./RECOVERY_PLAN.md)）。

---

## 1. 已定决策（约束本 spec）

| # | 决策 | 定于 |
|---|---|---|
| D1 | GUI 用 **PySide6** | 2026-09-18 |
| D2 | 延时模式用**会话级批准** + 常驻指示器；允许用户完全关掉逐次确认 | 2026-09-18 |
| D3 | 目标形态以 **.app / .exe 为主**，终端版降级为开发调试工具 | 2026-09-16 |
| D4 | 网络**跟随系统代理** | 2026-09-16 |
| D5 | 全屏自动识别：**先做方案 A**（一遍过），用评测集在「速度 / 准确度 / token」三者间定夺是否升级到方案 B（先框后解） | 2026-09-18 |
| D6 | 一张截图里的**多个问题要能同时作答** | 2026-09-18 |
| D7 | 截图**本地留存**；归档不上传，不额外承担隐私账 | 2026-09-18 |
| D8 | 热键冲突要给**可读提示**，不能静默失败 | 2026-09-18 |
| D9 | 用**正交化**控制组合爆炸：平台 × 模式不相乘 | 2026-09-18 |

D5/D6 影响 B0 的接口形状（截图要能返回整屏、结果要能是 N 个），其余不影响。

---

## 2. 关键发现：平台层比原先设想的小一个数量级

上一轮我列了 8 项平台能力。**选定 PySide6 之后，其中 6 项变成跨端的**。以下全部在本机实测：

| 能力 | 原计划 | 实测结论 |
|---|---|---|
| 截屏 | mss（跨端） | **`QScreen.grabWindow` 可替代 mss** |
| 显示器拓扑 + DPI | 各端自己写 | **`QGuiApplication.screens()` 跨端给全**（含 `devicePixelRatio`） |
| 拖框选区 | macOS 用 `screencapture`，Windows **没有等价物** | **透明无边框全屏窗 + `QRubberBand` 跨端**，Windows 侧最难的问题消失 |
| 图片预览 | qlmanage / 各端 | `QDialog` + `QPixmap` |
| 对话框 | osascript / Win32 | `QMessageBox` |
| 通知 | osascript / toast | `QSystemTrayIcon.showMessage` |
| 托盘/菜单栏 + 退出 | 无（现在是「运行中」对话框的 hack） | **`QSystemTrayIcon` 可用**，顺手解决退出问题 |
| **全局热键** | Carbon / RegisterHotKey | **PySide6 没有**。`QShortcut` 只在应用有焦点时生效 |
| **屏幕录制权限** | Quartz TCC | Qt 不管。macOS 需要，**Windows 根本没这个权限** |

实测数据：

```
QSystemTrayIcon.isSystemTrayAvailable()  True
QGuiApplication.screens()                内建 1512x982 DPR=2.0
                                         G2721P 1920x1080 DPR=1.0
透明无边框窗 + QRubberBand                可用
QScreen.grabWindow(0)                    3024x1964（Retina 物理像素）
```

**所以 `Platform` 接口只剩两件事。**

---

## 3. 接口

```python
# snapquiz/platform/base.py

class HotkeyConflict(Exception):
    """组合已被其他程序占用（D8：必须给出可读提示，不能静默失败）。"""
    def __init__(self, spec: str, detail: str) -> None: ...


class HotkeyHandle(Protocol):
    def unregister(self) -> None: ...


class Platform(Protocol):
    name: str                       # "darwin" | "windows"

    # —— 屏幕录制权限（Windows 上是 no-op，恒返回 granted）——
    def screen_permission(self) -> PermissionObservation: ...
    def request_screen_permission(self) -> bool: ...

    # —— 全局热键。实现挂进 Qt 的事件循环，不自己起循环 ——
    def install_hotkey(self, spec: str, on_trigger: Callable[[], None]) -> HotkeyHandle: ...
```

就这三个方法。其余一律走 PySide6，**一份实现，两端通用**。

### 热键实现挂进 Qt 事件循环

两端都不另起事件循环 —— Qt 拥有主循环，平台实现只往里挂钩子：

- **macOS**：`RegisterEventHotKey` + `InstallEventHandler`（现有 `carbon_hotkey.py`）。
  Qt 在 macOS 上跑的就是 `NSApplication` 循环，Carbon 事件由它分发。
- **Windows**：`RegisterHotKey` 把 `WM_HOTKEY` 投到线程消息队列，
  用 `QAbstractNativeEventFilter` 截获。

> ### ⚠ 这条同时是 Task 9 的一个待验证假设
>
> Task 9 的 Carbon 热键**注册成功但收不到事件**，四种进程形态都试过
> （见 RECOVERY_PLAN 的 Task 9 记录）。其中三种是我手搓的事件泵，
> **不是真正的 NSApplication 循环**。
>
> **Qt 提供的恰好是真正的 NSApplication 循环。** 所以 B0 里要重跑一次
> `--hotkey-selftest`，这次跑在 `QApplication.exec()` 里面。
> 如果通过，pynput 和它带来的辅助功能权限一起删掉。
> 如果还是不通过，删掉 `carbon_hotkey.py` 那 297 行，保留 pynput —— **不留着当"以后再说"的死代码**。

---

## 4. 迁移：哪些文件搬到哪里

| 现在 | 去向 | 说明 |
|---|---|---|
| `capture/select.py`（`screencapture -i -s`） | **删**，换成 Qt 覆盖窗 | 跨端，且 Windows 侧唯一的难点消失 |
| `capture/screen.py`（mss） | **删**，换成 `QScreen.grabWindow` | 少一个依赖 |
| `capture/topology.py`（243 行**死代码**） | **删**，换成 `QGuiApplication.screens()` | 它的职责 Qt 免费给了，顺带修掉「固定选区无坐标校验」 |
| `capture/validation.py` 的 Cocoa 解码 | 换成 `QImage` | 黑帧/空白帧判定逻辑保留 |
| `privacy/preview.py` 的 qlmanage | 换成 `QDialog` | **预览必须从出站字节解出**这条不变量不动 |
| `present/notify.py` 的 osascript | 换成 `QMessageBox` / 托盘通知 | |
| `app.py` 里的 osascript 对话框 + `_run_gui` | 换成 Qt + 托盘 | 「运行中」对话框的退出 hack 作废 |
| `core/permissions.py` | → `platform/darwin.py` | Windows 版返回恒 granted |
| `hotkey/carbon_hotkey.py` | → `platform/darwin.py` | 见 §3 的待验证 |
| `hotkey/global_hotkey.py`（pynput） | 视 Carbon 验证结果**二选一删掉** | 不并存 |
| `setup.py`（py2app） | 换成 **PyInstaller**（两端通用） | |
| 领域层 / Adapter / 传输 / 校验 / Provider 表（4,073 行） | **一行不改** | |

---

## 5. 已知陷阱（全部实测，写下来免得后面重新踩）

**① PySide6 装下来 1,223 MB，但我们只要 88 MB。**

```
QtWebEngineCore        476 MB   ← 不需要
QtGui + QtWidgets + QtCore  88 MB   ← 需要的全部
```

打包器只带被 import 的模块。另有 `PySide6-Essentials` 包可进一步收窄。
**`.app` 预计从 44 MB 涨到 ~150 MB。**

**② `grabWindow` 的 DPR 行为要显式处理。**
在 DPR=2.0 的屏上请求 400×300 逻辑像素，返回 800×600 物理像素；
DPR=1.0 的屏上**也返回了 800×600**。坐标是屏幕局部的（实测两块屏内容不同），
但返回尺寸与 DPR 的关系不是想当然的 —— **必须按 `devicePixelRatio` 显式换算并写测试**。

**③ Qt 与 mss 同进程会段错误。**
实测在一个脚本里先用 Qt 再用 mss，进程直接 139。迁移期间不要让两者共存，
一次性换掉。

**④ PySide6 没有全局热键。** 别指望 `QShortcut`，它只在应用有焦点时生效。

---

## 5.5 附：全屏模式的三方平衡（D5 的实测依据）

D5 说"先做方案 A，用评测集定夺"。我量了载荷，**数据可能会让你提前改主意**，
所以记在这里，到 B4 时直接用。

同一块屏（3024×1964 物理像素）实测：

| | 像素 | PNG | 相对全屏 |
|---|---|---:|---:|
| 全屏原分辨率 | 3024×1964 | 984 KB | 1.00× |
| **缩到 1/4（只用于定位题目）** | 756×491 | 118 KB | **0.12×** |
| 裁出的单题（900×700 逻辑） | 1800×1400 | 199 KB | 0.20× |

关键一条：**找题目在哪，不需要看清文字。** 检测那一遍可以用缩到 1/4 的图，
载荷只有 12%。于是方案 B 的改良版：

**方案 B′ = 缩图检测 + 原图裁剪 + 逐题求解**

| 每屏题数 | 方案 A（全屏一遍过） | 方案 B′ | |
|---:|---:|---:|---|
| 1 | 984 KB | 118 + 199 = **317 KB** | B′ 省 68% |
| 2 | 984 KB | 118 + 398 = **516 KB** | B′ 省 48% |
| 3 | 984 KB | 118 + 597 = **715 KB** | B′ 省 27% |
| 4 | 984 KB | 118 + 796 = 914 KB | 打平 |
| 5+ | 984 KB | 更贵 | A 胜 |

**所以"B 比 A 贵"这个直觉是错的** —— 在每屏 1–3 题（也就是绝大多数情况）时
B′ 反而更省，因为 A 是拿全分辨率整屏去同时做"检测 + 解答"两件事。

三方平衡：

| | 速度 | token | 准确度 |
|---|---|---|---|
| A | 1 次调用，最快 | 每屏恒定 984 KB | 整屏干扰多；N 题要在一条回复里讲完 |
| B′ | 2 轮（第二轮 N 题可并行），约 1.5× | 1–3 题时更省 | 每题独占全分辨率裁图，应当更准 |

**D6（多问题同时作答）会把天平推向 B′**：方案 A 必须在一条回复里产出 N 个答案，
而且**归档时每个答案绑不到自己的那块图** —— 而 B2/B3 的复习界面恰恰需要
"这道题长什么样"。

### 建议的折中：方案 A+

先做 A，但**要求模型同时返回每道题的 bounding box**，我们本地按 box 裁图存档：

- 速度与 token 与 A 相同（一次调用）
- 归档里每题有自己的图（B′ 的好处）
- 风险：模型给的 box 可能不准 —— 这恰好是评测集要测的东西之一

**对 B0 的唯一影响**：数据模型从现在起就要能表达
**一张截图 → N 个问题 → N 个答案 + N 个 box**，不能假设 1:1。
`SolveResult` 目前是单答案的，B2 建表时要按 N 设计。

---

## 6. 本次不做（防止范围蔓延）

B0 **只搬不加**。以下一律不在本次：

- 设置页（B1）
- SQLite / 练习组 / 截图归档（B2）
- 延时模式与队列（B3）
- 全屏自动识别与多问题（B4）
- Windows 实现（B5）—— B0 只立接口并让 macOS 实现填进去

唯一允许的「顺带修」：固定选区的坐标校验（因为 `topology.py` 正是为此而留，
而它现在是死代码，删它的时候顺手把职责接上比留着更省事）。

---

## 7. 验收

**验收句**（用户可自己复现，不是"测试全绿"）：

> 双击 `SnapQuiz.app`，菜单栏出现图标；按热键弹出跨端实现的拖框选区，
> 选完看到预览、确认后拿到答案；从菜单栏退出。全程没有任何 osascript 弹窗。

机器可验证的补充判据：

```bash
# 核心代码里不该再有平台调用
grep -rn "osascript\|qlmanage\|screencapture\|Quartz\|AppKit" snapquiz/ \
  --include="*.py" | grep -v "^snapquiz/platform/"
# → 应当为空

python -m unittest discover -s tests    # 现有 206 个用例不得回归
```

---

## 8. 工作拆分

### B0-2 进行中（2026-09-19）：装置就绪，等人工按键

`snapquiz/platform/_qt_selftest.py`。实验设计上做了两处改动，都是被现实逼出来的：

**① 带对照组。** 同一个 Qt 循环里依次测 Carbon 与 pynput：

| carbon | pynput | 结论 |
|---|---|---|
| ✅ | ✅/❌ | Carbon 可用 → 删 `_pynput.py`，摆脱辅助功能权限 |
| ❌ | ✅ | Carbon 在 Qt 里也收不到 → 删 `_carbon.py`(297 行) |
| ❌ | ❌ | **装置有问题，不下结论** |

第三行是重点：上一轮我差点直接从「Carbon 收不到」判「Carbon 不可用」，
而真相是测试装置验证不了。没有对照组就区分不开这两种情况。

**② 每个后端跑在独立子进程里。** 同进程先装 Carbon 再装 pynput 会 SIGTRAP
（实测 exit 133）。根因在 Carbon 这边的 ctypes 绑定 —— 但**不该让待验证后端的
缺陷污染对照组**，那正好会伪造出上表第三行。

#### 顺带修掉的一个真 bug

`CarbonHotkey.uninstall()` 只解注册热键，**从不移除事件 handler**。handler 是
一个 ctypes 回调，留在系统的 application event target 上；对象被 GC 后
`self._callback` 随之释放，系统就持有了**指向已释放内存的函数指针**，
下一个键盘事件到来即崩。已补 `RemoveEventHandler`。

（顺带查证过但**不是**原因的：`InstallEventHandler` 第三个参数 `ItemCount`
在 64 位 macOS 上是 `unsigned long` 而非 `UInt32`，已一并改正；
符号地址正常、OSStatus 返回 0、`outRef` 是小整数 3/6 —— HIToolbox 用的
应该就是小句柄，不是非法指针。）

### B0-1 已完成（2026-09-18）

```
snapquiz/platform/
    base.py       接口 + 纯类型（三个方法：两个权限 + 一个热键）
    __init__.py   current() 工厂 + hotkey_selftest() 临时诊断
    darwin.py     macOS 实现
    _carbon.py    零权限热键后端（待 B0-2 验证）
    _pynput.py    需辅助功能权限的后端（当前默认）
```

删除 `core/permissions.py`；`hotkey/{carbon,global}_hotkey.py` 搬进 platform。
`core/` 只剩 busyguard 与 orchestrator，`hotkey/` 只剩 stdin_trigger（平台无关）。

**判据已写成测试**（`test_platform.PlatformSeamTest`）：扫描 `snapquiz/` 下每个
文件，`snapquiz/platform/` 之外出现 Quartz / Carbon / pynput 即失败。以后回归不了。

实跑发现并修掉的两件事：

1. **`app.py` 直接 import 了 `platform._carbon` / `platform._pynput`**，绕过接口。
   seam 测试当场抓到。改走 `install_hotkey()`；自检改走
   `platform.hotkey_selftest()`；`--carbon-selftest` 顺势改名
   `--hotkey-selftest`（flag 名不该绑死后端）。
2. **显式 `--trigger stdin` 被 GUI 自动检测覆盖了。** 在没有 tty 的环境
   （CI、管道、harness）里，用户明确指定的触发方式会被静默改成 hotkey。
   改成：`--gui` > 显式 `--trigger` > 自动检测。

测试 208 → 221。

| 步 | 内容 | 验收 |
|---|---|---|
| ~~B0-1~~ | ~~立 `platform/base.py` 接口 + `platform/darwin.py`~~ **✅ 2026-09-18** | 已达成，并把判据写成了测试 |
| B0-2 | **在 `QApplication.exec()` 里重跑 `--hotkey-selftest`** ⏳ 待人工按键 | 通过则删 pynput，不通过则删 carbon_hotkey |
| B0-3 | 截屏与拓扑换 Qt，删 mss 与 `topology.py`，顺带接上坐标校验 | 双屏各截一次，DPR 换算有测试 |
| B0-4 | 选区覆盖窗（透明全屏 + QRubberBand） | 在第二块屏上也能正确拖框 |
| B0-5 | 预览 / 对话框 / 通知 / 托盘换 Qt，删 `_run_gui` 的退出 hack | 从菜单栏能退出 |
| B0-6 | 打包换 PyInstaller | 双击能跑，体积记录在案 |

每步单独提交。**不要用裸的「继续推进」派发** —— 带上步号与验收句。
