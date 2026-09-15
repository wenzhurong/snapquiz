"""GLM / OpenAI-Chat-compatible 纯 Adapter。

``prepare`` 生成确定性的出站字节，``decode`` 把有界响应解成不可信候选。
两者都不读环境、不建 SDK、不 sleep、不重试、不联网。

线格与 tests/fixtures/glm_request.json（v3 时期对着智谱官方文档固化的 golden）
保持一致：顶层只有 model / messages / max_tokens，user 消息是
``[image_url, text]`` 两段，图片走 base64 data URI。
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Optional

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.adapters.glm_errors import DECODE_STAGE, strict_json_bytes
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

GLM_ADAPTER_FAMILY = "openai_chat_compatible"
GLM_ADAPTER_VERSION = "2"
GLM_PROVIDER_ID = "zhipu"
PROVIDER_PROFILE_ID = "zhipu.glm-4.6v"
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


def _invalid() -> InvalidOutputError:
    return InvalidOutputError(
        stage=DECODE_STAGE, provider_profile_id=PROVIDER_PROFILE_ID
    )


def _text(value: object, *, max_length: int) -> Optional[str]:
    if value is None:
        return None
    if type(value) is not str or len(value) > max_length:
        raise _invalid()
    return value


def _usage(value: object) -> UsageSummary:
    if value is None:
        return UsageSummary()
    if type(value) is not dict:
        raise _invalid()
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
            raise _invalid()
    try:
        return UsageSummary(**out)
    except ValueError:
        raise _invalid() from None


class GlmChatAdapter(DirectMultimodalAdapter):
    """无状态的 GLM 绑定。"""

    __slots__ = ()

    adapter_family = GLM_ADAPTER_FAMILY
    adapter_version = GLM_ADAPTER_VERSION

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
            # 明确上限：官方默认 16384，远大于简短答题所需，会平白增加成本与延迟。
            "max_tokens": MAX_OUTPUT_TOKENS,
        }
        body = json.dumps(
            body_obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

        kinds = [OutboundDataKind.IMAGE]
        if user_hint:
            kinds.append(OutboundDataKind.USER_HINT)

        return OutboundRequest(
            http_method="POST",
            canonical_url=config.endpoint_url,
            content_type="application/json",
            non_secret_headers=(_ACCEPT,),
            outbound_data=tuple(kinds),
            body=body,
        )

    def decode(
        self, *, prepared: OutboundRequest, response: TransportResponse
    ) -> AnswerCandidateResult:
        response.validate_integrity()
        if response.request_envelope_digest != prepared.envelope_digest:
            raise _invalid()

        try:
            wrapper = strict_json_bytes(response.body)
        except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
            raise _invalid() from None
        if type(wrapper) is not dict:
            raise _invalid()

        choices = wrapper.get("choices")
        if type(choices) is not list or len(choices) != 1:
            raise _invalid()
        choice = choices[0]
        if type(choice) is not dict:
            raise _invalid()
        # 刻意用 `is not 0` 语义的显式类型检查：False 不能冒充 index 0。
        index = choice.get("index")
        if type(index) is not int or type(index) is bool or index != 0:
            raise _invalid()

        message = choice.get("message")
        if type(message) is not dict or message.get("role") != "assistant":
            raise _invalid()
        if message.get("tool_calls") is not None or message.get("audio") is not None:
            raise _invalid()

        finish_reason = _text(choice.get("finish_reason"), max_length=64)
        request_id = _text(wrapper.get("request_id"), max_length=256)
        usage = _usage(wrapper.get("usage"))

        if wrapper.get("model") != prepared_model(prepared):
            raise _invalid()

        content = message.get("content")
        if content is None or type(content) is not str or not content.strip():
            if finish_reason == "length":
                # 推理模型的典型失败：思维链吃光了 token 预算，content 为空。
                # 这不是"模型乱答"，而是预算配置问题，值得单独报出来。
                raise OutputBudgetExhausted(
                    stage=DECODE_STAGE, provider_profile_id=PROVIDER_PROFILE_ID
                )
            raise _invalid()

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
            raise _invalid() from None
        if type(payload) is not dict:
            raise _invalid()

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
    "OutputBudgetExhausted",
    "GLM_ADAPTER_FAMILY",
    "GLM_ADAPTER_VERSION",
    "GLM_PROVIDER_ID",
    "PROVIDER_PROFILE_ID",
    "GlmChatAdapter",
]
