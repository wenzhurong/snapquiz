"""已冻结的 MVP-0 截屏实现。

纯坐标转换仍可测试，但默认全屏和所有 legacy 实际截屏入口都已禁用。
"""
from __future__ import annotations

from typing import Optional

from snapquiz.config import Region
from snapquiz.core.legacy import raise_legacy_pipeline_disabled


def region_to_monitor(region: Optional[Region], primary_monitor: dict) -> dict:
    if region is None:
        raise ValueError("默认全屏已禁用，必须提供明确选区")
    left, top, width, height = region
    return {"left": left, "top": top, "width": width, "height": height}


def capture_png_bytes(region: Optional[Region] = None) -> bytes:
    del region
    raise_legacy_pipeline_disabled()


def capture_data_url(region: Optional[Region] = None) -> str:
    del region
    raise_legacy_pipeline_disabled()
