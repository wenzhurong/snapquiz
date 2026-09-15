"""环境配置解析。

保留冻结版 legacy_config 已经做对的三件事：endpoint 钉死官方地址、model 走白名单、
选区必须显式给出（不回退全屏）。改掉的一件：``Config`` 不再持有 API key 明文 ——
它只记住 key 从哪个环境变量来，真正取值发生在出站批准之后（见 transport.client）。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional, Tuple

DEFAULT_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"
CHAT_COMPLETIONS_PATH = "/chat/completions"
DEFAULT_MODEL = "glm-4.6v-flash"
DEFAULT_HOTKEY = "cmd+shift+space"
DEFAULT_TIMEOUT = 30.0
API_KEY_ENV = "GLM_API_KEY"

# 只允许已知的智谱视觉模型；未知模型名不得继承已知能力。
ALLOWED_MODELS = frozenset({"glm-4.6v-flash", "glm-4.6v"})

Region = Tuple[int, int, int, int]  # left, top, width, height（屏幕「点」坐标）

MAX_REGION_EDGE = 8_192


class ConfigError(Exception):
    """配置缺失或非法。"""


@dataclass(frozen=True)
class Config:
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    hotkey: str = DEFAULT_HOTKEY
    timeout: float = DEFAULT_TIMEOUT
    region: Optional[Region] = None
    api_key_env: str = API_KEY_ENV

    @property
    def endpoint_url(self) -> str:
        return self.base_url + CHAT_COMPLETIONS_PATH


def _parse_region(raw: str) -> Region:
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) != 4:
        raise ConfigError(
            f"SNAPQUIZ_REGION 需为 'left,top,width,height' 四个整数,收到:{raw!r}"
        )
    try:
        nums = tuple(int(p) for p in parts)
    except ValueError:
        raise ConfigError(f"SNAPQUIZ_REGION 必须是整数,收到:{raw!r}") from None
    if nums[2] <= 0 or nums[3] <= 0:
        raise ConfigError("SNAPQUIZ_REGION 的 width/height 必须为正整数")
    if nums[2] > MAX_REGION_EDGE or nums[3] > MAX_REGION_EDGE:
        raise ConfigError(f"选区单边不得超过 {MAX_REGION_EDGE} 点")
    return nums  # type: ignore[return-value]


def load_config(env: Mapping[str, str]) -> Config:
    """从环境变量构造配置。不读取 API key 的值,只确认它存在。"""

    if not (env.get(API_KEY_ENV) or "").strip():
        raise ConfigError(
            f"缺少 {API_KEY_ENV}。请在 .env 里填入智谱开放平台的 API Key(见 .env.example)。"
        )

    base_url = (env.get("GLM_BASE_URL") or DEFAULT_BASE_URL).strip().rstrip("/")
    if base_url != DEFAULT_BASE_URL:
        raise ConfigError(
            f"GLM_BASE_URL 只允许官方 endpoint {DEFAULT_BASE_URL};"
            "自定义地址会把截图和密钥一起送到未验证的主机。"
        )

    model = (env.get("GLM_MODEL") or DEFAULT_MODEL).strip()
    if model not in ALLOWED_MODELS:
        raise ConfigError(
            f"GLM_MODEL={model!r} 不在白名单内;当前允许:{sorted(ALLOWED_MODELS)}"
        )

    region_raw = (env.get("SNAPQUIZ_REGION") or "").strip()
    if not region_raw:
        raise ConfigError(
            "必须提供 SNAPQUIZ_REGION='left,top,width,height'。"
            "默认全屏已禁用,避免把聊天、终端、通知一并上传。"
        )

    timeout_raw = (env.get("SNAPQUIZ_TIMEOUT") or "").strip()
    try:
        timeout = float(timeout_raw) if timeout_raw else DEFAULT_TIMEOUT
    except ValueError:
        raise ConfigError(f"SNAPQUIZ_TIMEOUT 必须是数字,收到:{timeout_raw!r}") from None
    if not 0 < timeout <= 300:
        raise ConfigError("SNAPQUIZ_TIMEOUT 必须在 (0, 300] 秒之间")

    return Config(
        base_url=base_url,
        model=model,
        hotkey=(env.get("SNAPQUIZ_HOTKEY") or DEFAULT_HOTKEY).strip(),
        timeout=timeout,
        region=_parse_region(region_raw),
    )


def resolve_api_key(cfg: Config) -> str:
    """在出站批准之后才调用。返回值是明文密钥,不得记录、不得进入异常消息。"""

    value = (os.environ.get(cfg.api_key_env) or "").strip()
    if not value:
        raise ConfigError(f"{cfg.api_key_env} 在发送时不可用")
    return value
