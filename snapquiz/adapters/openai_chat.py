"""OpenAI Chat Completions 兼容的纯 Adapter。

``prepare`` 生成确定性的出站字节，``decode`` 把有界响应解成不可信候选。
两者都不读环境、不建 SDK、不 sleep、不重试、不联网。

**一个 Adapter 服务所有 Provider**：智谱 GLM 与 opencode Go 都是 OpenAI Chat
Completions 兼容，差异（endpoint / 模型白名单 / 必需 header / 错误方案）全部
收在 ``providers.ProviderProfile`` 里，这里不含任何 Provider 分支。

线格与 tests/fixtures/glm_request.json（v3 时期对着智谱官方文档固化的 golden）
保持一致：顶层只有 model / messages / max_tokens，user 消息是
``[image_url, text]`` 两段，图片走 base64 data URI。已对两个 Provider 实测通过。
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Optional

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.adapters.provider_errors import DECODE_STAGE, strict_json_bytes
from snapquiz.adapters.prompt import SYSTEM_INSTRUCTION, build_user_instruction
from snapquiz.domain.adapter import (
    AnswerCandidateResult,
    NormalizedRefusal,
    TransportResponse,
)
from snapquiz.domain.errors import InvalidOutputError
from snapquiz.domain.outbound import (
    NonSecretHeader,
    OutboundDataKind,
    OutboundRequest,
)
from snapquiz.domain.solve import UsageSummary

ADAPTER_FAMILY = "openai_chat_compatible"
ADAPTER_VERSION = "3"
MAX_OUTPUT_TOKENS = 1024


class OutputBudgetExhausted(InvalidOutputError):
    """max_tokens 被思维链耗尽，模型没来得及给出答案。

    推理模型（见 config.REASONING_MODELS）的 token 预算必须同时覆盖
    reasoning_content 与 content；不足时服务端返回 finish_reason="length"
    且 content 为空字符串。
    """


# 实测（2026-09-15，glm-4v-flash）：即使 system prompt 明确写了
# "no Markdown, code fence, commentary"，模型仍然会把 JSON 包在 ```json 围栏里。
# 这是**传输层的包装**，不是内容问题，所以在严格解析前剥掉它。
# 剥掉之后里面的 JSON 仍然走完整严格解析（重复 key / NaN / 超深嵌套一律拒绝），
# 结果对象也仍然要过 validate_solve_result 的九字段精确校验。
# 注意不要退回 MVP-0 那种"在任意文本里捞第一个 JSON 对象"的宽松做法 ——
# 那会让模型的解释性文字混进结果。这里只接受**整段内容恰好是一个围栏**。
_FENCE_RE = re.compile(
    r"\A\s*```(?:[A-Za-z0-9_+-]{0,20})?[ \t]*\r?\n(?P<body>.*?)\r?\n?```\s*\Z",
    re.DOTALL,
)


def _unwrap_code_fence(content: str) -> str:
    match = _FENCE_RE.match(content)
    return match.group("body") if match else content


_ACCEPT = NonSecretHeader(
    lowercase_name="accept", normalized_value="application/json"
)


def _invalid(profile_id: str) -> InvalidOutputError:
    return InvalidOutputError(stage=DECODE_STAGE, provider_profile_id=profile_id)


def _text(value: object, *, max_length: int, profile_id: str) -> Optional[str]:
    if value is None:
        return None
    if type(value) is not str or len(value) > max_length:
        raise _invalid(profile_id)
    return value


def _usage(value: object, profile_id: str) -> UsageSummary:
    if value is None:
        return UsageSummary()
    if type(value) is not dict:
        raise _invalid(profile_id)
    out: dict[str, Optional[int]] = {}
    for wire, field in (
        ("prompt_tokens", "input_tokens"),
        ("completion_tokens", "output_tokens"),
        ("total_tokens", "total_tokens"),
    ):
        raw = value.get(wire)
        if raw is None:
            out[field] = None
        elif type(raw) is int and raw >= 0:
            out[field] = raw
        else:
            raise _invalid(profile_id)
    try:
        return UsageSummary(**out)
    except ValueError:
        raise _invalid(profile_id) from None


class OpenAIChatAdapter(DirectMultimodalAdapter):
    """无状态的 OpenAI-Chat-compatible 绑定，对所有 Provider 通用。"""

    __slots__ = ()

    adapter_family = ADAPTER_FAMILY
    adapter_version = ADAPTER_VERSION

    def prepare(self, *, config, png: bytes, user_hint: Optional[str] = None):
        if type(png) is not bytes or not png:
            raise ValueError("png must be non-empty bytes")

        data_uri = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
        body_obj: dict[str, Any] = {
            "model": config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_INSTRUCTION},
                {
                    "role": "user",
                    "content": [
                        {"type": "image_url", "image_url": {"url": data_uri}},
                        {
                            "type": "text",
                            "text": build_user_instruction(
                                locale="zh-CN", user_hint=user_hint
                            ),
                        },
                    ],
                },
            ],
            # 明确上限：不设时官方默认 16384，远大于所需，平白增加成本与延迟。
            # 具体数值按 Provider 走：推理模型的预算要同时覆盖思维链与答案。
            "max_tokens": config.provider.max_output_tokens,
        }
        body = json.dumps(
            body_obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

        kinds = [OutboundDataKind.IMAGE]
        if user_hint:
            kinds.append(OutboundDataKind.USER_HINT)

        headers = [_ACCEPT]
        if config.provider.requires_session_header:
            # opencode Go 的路由层强制要求；缺了会返回 MissingSessionID。
            # 它不是密钥，所以是 non-secret header，会进 envelope digest 并被预览。
            headers.append(
                NonSecretHeader(
                    lowercase_name="x-opencode-session",
                    normalized_value=config.session_id,
                )
            )

        return OutboundRequest(
            http_method="POST",
            canonical_url=config.endpoint_url,
            content_type="application/json",
            non_secret_headers=tuple(headers),
            outbound_data=tuple(kinds),
            body=body,
        )

    def decode(
        self,
        *,
        prepared: OutboundRequest,
        response: TransportResponse,
        provider_profile_id: str = "unknown",
    ) -> AnswerCandidateResult:
        pid = provider_profile_id
        response.validate_integrity()
        if response.request_envelope_digest != prepared.envelope_digest:
            raise _invalid(pid)

        try:
            wrapper = strict_json_bytes(response.body)
        except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
            raise _invalid(pid) from None
        if type(wrapper) is not dict:
            raise _invalid(pid)

        choices = wrapper.get("choices")
        if type(choices) is not list or len(choices) != 1:
            raise _invalid(pid)
        choice = choices[0]
        if type(choice) is not dict:
            raise _invalid(pid)
        # 刻意用 `is not 0` 语义的显式类型检查：False 不能冒充 index 0。
        index = choice.get("index")
        if type(index) is not int or type(index) is bool or index != 0:
            raise _invalid(pid)

        message = choice.get("message")
        if type(message) is not dict or message.get("role") != "assistant":
            raise _invalid(pid)
        if message.get("tool_calls") is not None or message.get("audio") is not None:
            raise _invalid(pid)

        finish_reason = _text(choice.get("finish_reason"), max_length=64, profile_id=pid)
        request_id = _text(wrapper.get("request_id"), max_length=256, profile_id=pid)
        usage = _usage(wrapper.get("usage"), pid)

        if wrapper.get("model") != prepared_model(prepared):
            raise _invalid(pid)

        content = message.get("content")
        if content is None or type(content) is not str or not content.strip():
            if finish_reason == "length":
                # 推理模型的典型失败：思维链吃光了 token 预算，content 为空。
                # 这不是"模型乱答"，而是预算配置问题，值得单独报出来。
                raise OutputBudgetExhausted(
                    stage=DECODE_STAGE, provider_profile_id=pid
                )
            raise _invalid(pid)

        if finish_reason == "sensitive":
            return AnswerCandidateResult(
                request_envelope_digest=prepared.envelope_digest,
                response_body_digest=response.response_body_digest,
                candidate_payload=None,
                refusal=NormalizedRefusal.CONTENT_POLICY,
                finish_reason=finish_reason,
                provider_request_id=request_id,
                usage=usage,
            )

        try:
            payload = strict_json_bytes(_unwrap_code_fence(content).encode("utf-8"))
        except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
            raise _invalid(pid) from None
        if type(payload) is not dict:
            raise _invalid(pid)

        return AnswerCandidateResult(
            request_envelope_digest=prepared.envelope_digest,
            response_body_digest=response.response_body_digest,
            candidate_payload=payload,
            finish_reason=finish_reason,
            provider_request_id=request_id,
            usage=usage,
        )


def prepared_model(prepared: OutboundRequest) -> str:
    """从已准备好的 body 里读回 model，用于核对响应里的 model 字段。"""

    return json.loads(prepared.body.decode("utf-8"))["model"]


__all__ = [
    "ADAPTER_FAMILY",
    "ADAPTER_VERSION",
    "MAX_OUTPUT_TOKENS",
    "OpenAIChatAdapter",
    "OutputBudgetExhausted",
]
