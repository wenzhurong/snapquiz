"""Provider 档案：一张静态表，不是 Registry。

v3 时期的 Registry/Plan 机制有 3,643 行，为的是同一件事：让核心不写死单一
Provider。但那套东西引入了贯穿每一层的 PlannedExecution 穿线（见
docs/RECOVERY_PLAN.md §1）。这里用一张冻结的表达成同样的目的：

- 核心逻辑（capture / prepare / transport / validate）不含任何 Provider 分支；
- 每个 Provider 的差异全部收在 ``ProviderProfile`` 的字段里；
- 新增 Provider = 加一条表项 + 在 ``PROFILES`` 注册，不动其他任何文件。

两个 Provider 都是 OpenAI Chat Completions 兼容，因此共用同一个 Adapter。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ProviderId(str, Enum):
    ZHIPU = "zhipu"
    OPENCODE_GO = "opencode_go"


class ErrorScheme(str, Enum):
    """Provider 在 HTTP 状态之外还提供哪种业务错误信息。"""

    #: 智谱：响应体 error.code 是四位数字，见 adapters/glm_errors.py
    GLM_NUMERIC = "glm_numeric"
    #: opencode：响应体 error.type 是字符串。实测它对「模型不存在」也返回 401，
    #: 所以**必须**看 type 才能把 ModelError 和真正的 AuthError 分开。
    OPENCODE_TYPED = "opencode_typed"
    #: 只有 HTTP 状态可用。
    HTTP_ONLY = "http_only"


@dataclass(frozen=True)
class ProviderProfile:
    provider_id: ProviderId
    profile_id: str
    base_url: str
    chat_path: str
    key_env: str
    default_model: str
    allowed_models: frozenset
    #: 把思维链放在 reasoning_content 的模型。token 预算必须同时覆盖它与 content。
    reasoning_models: frozenset
    error_scheme: ErrorScheme
    #: 出站 max_tokens。推理模型的预算必须同时覆盖思维链与最终答案。
    max_output_tokens: int = 1024
    #: 默认超时。推理模型慢得多，用同一个 30 秒会稳定超时。
    default_timeout: float = 30.0
    #: opencode Go 路由要求每个请求带 x-opencode-session，否则 MissingSessionID。
    requires_session_header: bool = False

    @property
    def endpoint_url(self) -> str:
        return self.base_url + self.chat_path


ZHIPU = ProviderProfile(
    provider_id=ProviderId.ZHIPU,
    profile_id="zhipu.glm",
    base_url="https://open.bigmodel.cn/api/paas/v4",
    chat_path="/chat/completions",
    key_env="GLM_API_KEY",
    default_model="glm-4.6v",
    # 2026-09-15 实测（tests/fixtures/sample_question.png，单次调用）：
    #   glm-4.6v        ✅ 13.5 s / 330 tok   推理模型
    #   glm-4v-flash    ✅  4.3 s / 136 tok   非推理，最快
    #   glm-4v          ✅ 可用
    #   glm-4.5v        ✅ 裸 API 可用（未跑完整链路）
    #   glm-4.6v-flash  ⚠️ 3 次里 2 次 1305「访问量过大」
    #   glm-4.5-air     ❌ 1210 纯文本，拒收图片
    allowed_models=frozenset(
        {"glm-4.6v", "glm-4.6v-flash", "glm-4.5v", "glm-4v", "glm-4v-flash"}
    ),
    reasoning_models=frozenset({"glm-4.6v", "glm-4.6v-flash", "glm-4.5v"}),
    error_scheme=ErrorScheme.GLM_NUMERIC,
    max_output_tokens=1024,      # 实测 glm-4.6v 用掉 374，够用
    default_timeout=30.0,        # 实测 7.3 s
)

OPENCODE_GO = ProviderProfile(
    provider_id=ProviderId.OPENCODE_GO,
    profile_id="opencode_go.mimo",
    base_url="https://opencode.ai/zen/go/v1",
    chat_path="/chat/completions",
    key_env="OPENCODE_API_KEY",
    default_model="mimo-v2.5",
    # 2026-09-15 实测：
    #   mimo-v2.5       ✅ 答对，但**很慢**：max_tokens=8192 时耗时 141 秒、
    #                      completion 1172 tok。它是推理模型，输出在 message.reasoning，
    #                      content 要等推理结束才出现；max_tokens=1024 时
    #                      finish_reason="length"、content=None，什么都拿不到。
    #   mimo-v2.5-pro   ❌ 404「No endpoints found that support image」——纯文本
    #   mimo-v2-omni    ✅ 接受图片（未跑完整链路）
    allowed_models=frozenset({"mimo-v2.5", "mimo-v2-omni"}),
    reasoning_models=frozenset({"mimo-v2.5", "mimo-v2-omni"}),
    error_scheme=ErrorScheme.OPENCODE_TYPED,
    max_output_tokens=8192,      # 1024 不够：实测全被思维链吃光
    default_timeout=240.0,       # 实测 141 秒，留足余量
    requires_session_header=True,
)

PROFILES = {
    ProviderId.ZHIPU: ZHIPU,
    ProviderId.OPENCODE_GO: OPENCODE_GO,
}

DEFAULT_PROVIDER = ProviderId.ZHIPU


def resolve_profile(name: str) -> ProviderProfile:
    try:
        return PROFILES[ProviderId(name)]
    except ValueError:
        raise KeyError(
            f"未知 provider {name!r};当前支持:{sorted(p.value for p in PROFILES)}"
        ) from None


__all__ = [
    "DEFAULT_PROVIDER",
    "OPENCODE_GO",
    "PROFILES",
    "ZHIPU",
    "ErrorScheme",
    "ProviderId",
    "ProviderProfile",
    "resolve_profile",
]
