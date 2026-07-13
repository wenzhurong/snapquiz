"""从环境变量加载配置(纯函数,便于测试)。

app.py 会先 load_dotenv() 再把 os.environ 传进来。
"""
from __future__ import annotations

from dataclasses import dataclass
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
    api_key: str
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    hotkey: str = DEFAULT_HOTKEY
    timeout: float = DEFAULT_TIMEOUT
    region: Optional[Region] = None  # (left, top, width, height);None=全屏


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
    return nums  # type: ignore[return-value]


def load_config(env: Mapping[str, str]) -> Config:
    api_key = (env.get("GLM_API_KEY") or "").strip()
    if not api_key:
        raise ConfigError(
            "缺少 GLM_API_KEY。请在 .env 里填入智谱开放平台的 API Key(见 .env.example)。"
        )

    region_raw = env.get("SNAPQUIZ_REGION")
    region = _parse_region(region_raw) if region_raw else None

    return Config(
        api_key=api_key,
        base_url=(env.get("GLM_BASE_URL") or DEFAULT_BASE_URL).strip(),
        model=(env.get("GLM_MODEL") or DEFAULT_MODEL).strip(),
        hotkey=(env.get("SNAPQUIZ_HOTKEY") or DEFAULT_HOTKEY).strip(),
        region=region,
    )
