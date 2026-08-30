"""已隔离的 MVP-0 环境配置解析器；当前产品入口不会调用它。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple

DEFAULT_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"
DEFAULT_MODEL = "glm-4.6v-flash"
DEFAULT_HOTKEY = "cmd+shift+space"
DEFAULT_TIMEOUT = 30.0

Region = Tuple[int, int, int, int]


class ConfigError(Exception):
    """配置缺失或非法。"""


@dataclass
class Config:
    api_key: str = field(repr=False)
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    hotkey: str = DEFAULT_HOTKEY
    timeout: float = DEFAULT_TIMEOUT
    region: Optional[Region] = None  # 迁移期字段；load_config 强制显式正尺寸区域


def _parse_region(raw: str) -> Region:
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) != 4:
        raise ConfigError(
            f"SNAPQUIZ_REGION 需为 'left,top,width,height' 四个整数,收到:{raw!r}"
        )
    try:
        nums = tuple(int(p) for p in parts)
    except ValueError:
        raise ConfigError(f"SNAPQUIZ_REGION 必须是整数,收到:{raw!r}")
    if nums[2] <= 0 or nums[3] <= 0:
        raise ConfigError("SNAPQUIZ_REGION 的 width/height 必须为正整数")
    return nums  # type: ignore[return-value]


def load_config(env: Mapping[str, str]) -> Config:
    api_key = (env.get("GLM_API_KEY") or "").strip()
    if not api_key:
        raise ConfigError(
            "缺少 GLM_API_KEY。请在 .env 里填入智谱开放平台的 API Key(见 .env.example)。"
        )

    base_url = (env.get("GLM_BASE_URL") or DEFAULT_BASE_URL).strip()
    if base_url != DEFAULT_BASE_URL:
        raise ConfigError("legacy GLM_BASE_URL 只允许固定的官方 endpoint")

    model = (env.get("GLM_MODEL") or DEFAULT_MODEL).strip()
    if model != DEFAULT_MODEL:
        raise ConfigError("legacy GLM_MODEL 只允许冻结的默认模型")

    region_raw = (env.get("SNAPQUIZ_REGION") or "").strip()
    if not region_raw:
        raise ConfigError("MVP-0 默认全屏已禁用；必须提供明确的 SNAPQUIZ_REGION")
    region = _parse_region(region_raw)

    return Config(
        api_key=api_key,
        base_url=base_url,
        model=model,
        hotkey=(env.get("SNAPQUIZ_HOTKEY") or DEFAULT_HOTKEY).strip(),
        region=region,
    )
