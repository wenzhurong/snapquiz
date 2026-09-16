"""py2app 打包配置：把 snapquiz 做成可双击的 SnapQuiz.app。

    pip install -e ".[app]"
    python setup.py py2app          # 产物在 dist/SnapQuiz.app

**不签名**。这够你自己用：双击启动、拖进「应用程序」、屏幕录制权限记在
SnapQuiz 自己名下（而不是终端）。发给别人才需要 Apple Developer 账号
签名 + 公证（$99/年），见 docs/RECOVERY_PLAN.md 阶段 C。

两个关键设置：

- ``LSUIElement = True``：不要 Dock 图标。这是个热键驱动的后台工具，
  而且它没有 NSApplication 事件循环，放个 Dock 图标只会得到一个按 Cmd-Q
  没反应的僵尸图标。退出走「运行中」对话框上的退出按钮（见 app._run_gui）。
- ``CFBundleIdentifier`` 必须**稳定**：macOS 的 TCC（屏幕录制授权）按
  bundle id + 代码签名记账。改了 id 就等于换了一个 app，之前授的权限作废。
"""
from setuptools import setup

APP = ["snapquiz/__main__.py"]

OPTIONS = {
    "argv_emulation": False,
    "packages": [
        "snapquiz",
        "httpx",
        "httpcore",
        "certifi",
        "idna",
        "anyio",
        "h11",
        "mss",
        "dotenv",
        "pynput",
    ],
    "includes": ["AppKit", "Foundation", "Quartz"],
    "plist": {
        "CFBundleName": "SnapQuiz",
        "CFBundleDisplayName": "SnapQuiz",
        "CFBundleIdentifier": "com.wenzhurong.snapquiz",
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleVersion": "0.1.0",
        "LSMinimumSystemVersion": "12.0",
        # 后台代理，不占 Dock。
        "LSUIElement": True,
        "NSHumanReadableCopyright": "Personal study tool. Unsigned build.",
    },
}

setup(
    name="SnapQuiz",
    app=APP,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
