"""交互式拖框选区，直接用 macOS 自带的 ``screencapture -i -s``。

为什么不自己写选择器：macOS 已经提供了一个所有人都认识的十字准星，
按 Esc 取消、按空格切窗口模式，行为和系统截图完全一致。自己用 NSPanel
画一个，要处理多显示器、Retina、旋转、坐标系转换，是好几百行且更容易出错。

代价是**拿不到选区坐标** —— `screencapture` 只给图不给位置。所以：

- 交互模式（本模块）：每次现拖。适合题目位置会变的情况，也是默认。
- 固定模式（``SNAPQUIZ_REGION``）：坐标写死，一键直出，不弹准星。

坐标级的「选区记忆」需要自己实现选择器才能拿到位置，留到阶段 B。
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile

from snapquiz.capture.validation import (
    check_frame_quality_png,
    check_png_size,
)

SELECT_TIMEOUT_SECONDS = 180


class SelectionCancelled(Exception):
    """用户按 Esc 取消了选区。此时必须零网络、零密钥解析。"""


class SelectionFailed(Exception):
    """screencapture 没能产出可用的图片。"""


def select_region_png() -> bytes:
    """弹出系统十字准星，返回用户框选区域的 PNG bytes。

    图片不落盘保留：写进 0700 临时目录，读完立刻删。
    """

    directory = pathlib.Path(tempfile.mkdtemp(prefix="snapquiz-select-"))
    os.chmod(directory, 0o700)
    target = directory / "selection.png"
    try:
        try:
            completed = subprocess.run(
                # -i 交互 / -s 只允许鼠标框选(不进窗口模式) / -x 静音
                ["screencapture", "-i", "-s", "-x", str(target)],
                timeout=SELECT_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SelectionCancelled("选区超时未完成") from exc
        except FileNotFoundError as exc:
            raise SelectionFailed("找不到 screencapture(仅 macOS 可用)") from exc

        # 用户按 Esc 时 screencapture 仍返回 0,但不会写出文件。
        if completed.returncode != 0 or not target.exists():
            raise SelectionCancelled("已取消选区")

        png = target.read_bytes()
    finally:
        try:
            target.unlink(missing_ok=True)
            directory.rmdir()
        except OSError:
            pass

    if not png:
        raise SelectionCancelled("已取消选区")

    check_png_size(png)
    check_frame_quality_png(png)
    return png
