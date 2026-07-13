"""屏幕截取:抓取区域 → PNG → base64 data URL。

region_to_monitor 是纯函数(可测);实际抓屏用 mss(惰性 import,仅运行时需要)。
region 采用屏幕「点」坐标(与系统截图工具一致);Retina 下 mss 会以物理像素成像,
得到高清图,足够模型看清。
"""
from __future__ import annotations

import base64
from typing import Optional

from snapquiz.config import Region


def region_to_monitor(region: Optional[Region], primary_monitor: dict) -> dict:
    if region is None:
        return primary_monitor
    left, top, width, height = region
    return {"left": left, "top": top, "width": width, "height": height}


def capture_png_bytes(region: Optional[Region] = None) -> bytes:
    import mss
    import mss.tools

    with mss.mss() as sct:
        # sct.monitors[0] 是所有显示器的并集;[1] 是主显示器
        monitor = region_to_monitor(region, sct.monitors[1])
        shot = sct.grab(monitor)
        return mss.tools.to_png(shot.rgb, shot.size)


def capture_data_url(region: Optional[Region] = None) -> str:
    png = capture_png_bytes(region)
    b64 = base64.b64encode(png).decode("ascii")
    return f"data:image/png;base64,{b64}"
