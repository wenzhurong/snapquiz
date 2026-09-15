"""环境配置解析。

保留冻结版 legacy_config 已经做对的三件事：endpoint 钉死、model 走白名单、
选区必须显式给出（不回退全屏）。改掉的一件：``Config`` 不再持有 API key 明文 ——
它只记住 key 从哪个环境变量来，真正取值发生在出站批准之后（见 transport.client）。

Provider 之间的差异全在 ``providers.ProviderProfile`` 里，这里只负责从环境变量
选出一个 profile 并校验模型名。
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple

from snapquiz.providers import DEFAULT_PROVIDER, ProviderProfile, resolve_profile

DEFAULT_HOTKEY = "cmd+shift+space"
DEFAULT_TIMEOUT = 30.0

Region = Tuple[int, int, int, int]  # left, top, width, height（屏幕「点」坐标）

MAX_REGION_EDGE = 8_192


class ConfigError(Exception):
    """配置缺失或非法。"""


@dataclass(frozen=True)
class Config:
    provider: ProviderProfile
    model: str
    hotkey: str = DEFAULT_HOTKEY
    timeout: float = 0.0  # 0 = 用 provider 的默认值，见 __post_init__
    region: Optional[Region] = None
    #: opencode Go 路由要求的 x-opencode-session。它不是密钥，会进 envelope digest。
    session_id: str = field(default_factory=lambda: f"ses_{uuid.uuid4().hex}")

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            object.__setattr__(self, "timeout", self.provider.default_timeout)

    @property
    def endpoint_url(self) -> str:
        return self.provider.endpoint_url

    @property
    def api_key_env(self) -> str:
        return self.provider.key_env

    @property
    def provider_profile_id(self) -> str:
        return self.provider.profile_id

    @property
    def is_reasoning_model(self) -> bool:
        return self.model in self.provider.reasoning_models


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


def load_config(env: Mapping[str, str], *, require_region: bool = True) -> Config:
    """从环境变量构造配置。不读取 API key 的值,只确认它存在。

    ``require_region=False`` 只给以文件为输入的冒烟用 —— 那条路径不截屏,
    选区无意义。产品入口必须保持 ``True``。
    """

    provider_name = (env.get("SNAPQUIZ_PROVIDER") or DEFAULT_PROVIDER.value).strip()
    try:
        profile = resolve_profile(provider_name)
    except KeyError as exc:
        raise ConfigError(str(exc)) from None

    if not (env.get(profile.key_env) or "").strip():
        raise ConfigError(
            f"缺少 {profile.key_env}(provider={profile.provider_id.value})。"
            "请在 .env 里填入,见 .env.example。"
        )

    # endpoint 不接受来自环境的覆盖:自定义地址会把截图和密钥一起送到未验证的主机。
    override = (env.get("SNAPQUIZ_BASE_URL") or "").strip().rstrip("/")
    if override and override != profile.base_url:
        raise ConfigError(
            f"SNAPQUIZ_BASE_URL 只允许 {profile.provider_id.value} 的官方地址 "
            f"{profile.base_url}"
        )

    model = (env.get("SNAPQUIZ_MODEL") or env.get("GLM_MODEL") or "").strip()
    model = model or profile.default_model
    if model not in profile.allowed_models:
        raise ConfigError(
            f"模型 {model!r} 不在 {profile.provider_id.value} 的白名单内;"
            f"当前允许:{sorted(profile.allowed_models)}"
        )

    region_raw = (env.get("SNAPQUIZ_REGION") or "").strip()
    if not region_raw and require_region:
        raise ConfigError(
            "必须提供 SNAPQUIZ_REGION='left,top,width,height'。"
            "默认全屏已禁用,避免把聊天、终端、通知一并上传。"
        )

    timeout_raw = (env.get("SNAPQUIZ_TIMEOUT") or "").strip()
    try:
        timeout = float(timeout_raw) if timeout_raw else profile.default_timeout
    except ValueError:
        raise ConfigError(f"SNAPQUIZ_TIMEOUT 必须是数字,收到:{timeout_raw!r}") from None
    if not 0 < timeout <= 600:
        raise ConfigError("SNAPQUIZ_TIMEOUT 必须在 (0, 600] 秒之间")

    session_id = (env.get("OPENCODE_SESSION") or "").strip()
    extra = {"session_id": session_id} if session_id else {}

    return Config(
        provider=profile,
        model=model,
        hotkey=(env.get("SNAPQUIZ_HOTKEY") or DEFAULT_HOTKEY).strip(),
        timeout=timeout,
        region=_parse_region(region_raw) if region_raw else None,
        **extra,
    )


def resolve_api_key(cfg: Config) -> str:
    """在出站批准之后才调用。返回值是明文密钥,不得记录、不得进入异常消息。"""

    value = (os.environ.get(cfg.api_key_env) or "").strip()
    if not value:
        raise ConfigError(f"{cfg.api_key_env} 在发送时不可用")
    return value
