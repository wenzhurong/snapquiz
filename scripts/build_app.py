"""构建 dist/SnapQuiz.app（不签名）。

    python scripts/build_app.py

为什么需要这个脚本而不是直接 `python setup.py py2app`：
py2app 0.28 不支持 `install_requires`，而 setuptools 会把 `pyproject.toml`
的 `[project].dependencies` 映射成它，于是直接跑会报
`error: install_requires is no longer supported`。

这里在构建期间把 `pyproject.toml` 临时挪开，**用 try/finally 保证一定还原** ——
构建失败、Ctrl-C 都不会把你的 pyproject 弄丢。
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
STASHED = ROOT / "pyproject.toml.py2app-stash"
APP = ROOT / "dist" / "SnapQuiz.app"


def main() -> int:
    if not PYPROJECT.exists():
        if STASHED.exists():
            STASHED.rename(PYPROJECT)
            print("发现上次构建残留的 stash,已还原 pyproject.toml。")
        else:
            print("找不到 pyproject.toml", file=sys.stderr)
            return 1

    for stale in (ROOT / "build", ROOT / "dist"):
        shutil.rmtree(stale, ignore_errors=True)

    PYPROJECT.rename(STASHED)
    try:
        completed = subprocess.run(
            [sys.executable, "setup.py", "py2app"], cwd=ROOT, check=False
        )
    finally:
        # 无论成功、失败还是被中断,都必须还原。
        if STASHED.exists():
            STASHED.rename(PYPROJECT)

    if completed.returncode != 0:
        print("\n构建失败。", file=sys.stderr)
        return completed.returncode

    print(f"\n✅ 构建完成:{APP}")
    print("   拖进「应用程序」后双击即可。首次运行会请求屏幕录制与辅助功能权限,")
    print("   这次权限记在 SnapQuiz 自己名下,不再是终端。")
    print("   未签名,所以第一次可能要右键 →「打开」才放行。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
