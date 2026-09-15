"""屏幕截取：抓取指定区域 → 校验 → PNG bytes。

``region_to_monitor`` 是纯函数（可测）；实际抓屏用 mss（惰性 import，仅运行时需要）。
region 采用屏幕「点」坐标（与系统截图工具一致）；Retina 下 mss 以物理像素成像，
得到高清图，足够模型看清。

与 MVP-0 的唯一行为差异：``region is None`` 直接拒绝，不回退全屏。
默认全屏会把聊天、终端、通知一并传到云端，这是原审计列出的第 2 号问题。
"""
from __future__ import annotations

from typing import Optional

from snapquiz.capture.validation import (
    check_dimensions,
    check_frame_quality,
    check_png_size,
)
from snapquiz.config import Region


def region_to_monitor(region: Optional[Region], primary_monitor: dict) -> dict:
    if region is None:
        raise ValueError("默认全屏已禁用,必须提供明确选区")
    left, top, width, height = region
    return {"left": left, "top": top, "width": width, "height": height}


def capture_png_bytes(region: Optional[Region] = None) -> bytes:
    """抓一次图并返回 PNG bytes。内容不落盘。"""

    import mss
    import mss.tools

    with mss.mss() as sct:
        # sct.monitors[0] 是所有显示器的并集;[1] 是主显示器
        monitor = region_to_monitor(region, sct.monitors[1])
        shot = sct.grab(monitor)
        width_px, height_px = shot.size
        check_dimensions(width_px, height_px)
        check_frame_quality(shot.rgb, width_px, height_px)
        png = mss.tools.to_png(shot.rgb, shot.size)

    check_png_size(png)
    return png
