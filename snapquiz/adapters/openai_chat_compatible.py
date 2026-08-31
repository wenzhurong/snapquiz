"""Pure GLM OpenAI-Chat-compatible Adapter for W07.

The Adapter serializes already-authorized local authorities into exact bytes
and decodes bounded response fixtures.  It never reads credentials, constructs
an SDK client, retries, sleeps, or performs file/network I/O.
"""
from __future__ import annotations

import base64
import json
import math
from typing import Any
from uuid import UUID

from snapquiz.adapters.prompt import (
    PROMPT_POLICY_DIGEST,
    SYSTEM_INSTRUCTION,
    build_user_instruction,
)
from snapquiz.capture.validation import ValidatedCapture
from snapquiz.config.profiles import (
    GLM_ADAPTER_FAMILY,
    GLM_ADAPTER_VERSION,
    GLM_IMAGE_PREPROCESSING_POLICY_VERSION,
)
from snapquiz.domain._validation import require_uuid, runtime_final
from snapquiz.domain.adapter import (
    AnswerCandidateResult,
    TransportResponse,
    _create_answer_candidate_result,
)
from snapquiz.domain.capabilities import ImageInputKind, StructuredOutputKind
from snapquiz.domain.digest import canonical_json_bytes
from snapquiz.domain.errors import (
    AuthError,
    ConfigError,
    ContentPolicyError,
    EndpointPolicyError,
    InvalidOutputError,
    PayloadTooLargeError,
    ProviderRequestError,
    ProviderServerError,
    ProviderUnavailableError,
    RateLimitError,
    TimeoutError,
)
from snapquiz.domain.outbound import (
    PreparedOutbound,
    validate_prepared_outbound_against_plan,
)
from snapquiz.domain.plan import NetworkOperationPurpose, OutboundDataKind
from snapquiz.domain.solve import PipelineKind, StageRole, UsageSummary
from snapquiz.pipelines.contracts import StageInvocation
from snapquiz.routing.planner import PlannedExecution

ADAPTER_DECODE_STAGE = "adapter_decode"
ADAPTER_PREPARE_STAGE = "adapter_prepare"
MAX_JSON_DEPTH = 32
MAX_JSON_NUMBER_CHARS = 128

_PROVIDER_AUTH_ERROR_CODES = frozenset(
    {
        "1000",
        "1001",
        "1003",
        "1005",
        "1220",
        "1309",
        "1311",
        "1314",
        "1315",
    }
)
_PROVIDER_REQUEST_ERROR_CODES = frozenset(
    {
        "1113",
        "1210",
        "1211",
        "1212",
        "1213",
        "1214",
        "1215",
        "1221",
        "1222",
    }
)
_PROVIDER_SERVER_ERROR_CODES = frozenset({"1200", "1230", "1234"})
_PROVIDER_NON_RETRYABLE_LIMIT_ERROR_CODES = frozenset(
    {
        "1308",
        "1310",
        "1313",
        "1316",
        "1317",
        "1318",
        "1319",
        "1320",
        "1321",
    }
)
_PROVIDER_ERROR_HTTP_STATUS = {
    "1000": 401,
    "1001": 401,
    "1003": 401,
    "1005": 401,
    "1113": 429,
    "1200": 500,
    "1210": 400,
    "1211": 400,
    "1212": 400,
    "1213": 400,
    "1214": 400,
    "1215": 400,
    "1220": 403,
    "1221": 400,
    "1222": 400,
    "1230": 500,
    "1234": 500,
    "1261": 400,
    "1301": 400,
    "1302": 429,
    "1305": 429,
    "1308": 429,
    "1309": 429,
    "1310": 429,
    "1311": 429,
    "1313": 429,
    "1314": 429,
    "1315": 429,
    "1316": 429,
    "1317": 429,
    "1318": 429,
    "1319": 429,
    "1320": 429,
    "1321": 429,
}


def _config_error(message: str, provider_profile_id: str | None = None) -> ConfigError:
    return ConfigError(
        stage=ADAPTER_PREPARE_STAGE,
        safe_message=message,
        provider_profile_id=provider_profile_id,
    )


def _invalid_output(provider_profile_id: str) -> InvalidOutputError:
    return InvalidOutputError(
        stage=ADAPTER_DECODE_STAGE,
        provider_profile_id=provider_profile_id,
    )


def _strict_int(value: str) -> int:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON integer exceeds local limit")
    return int(value)


def _strict_float(value: str) -> float:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON number exceeds local limit")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number must be finite")
    return parsed


def _reject_constant(value: str) -> None:
    del value
    raise ValueError("non-finite JSON constants are forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _validate_json_depth(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON exceeds local nesting limit")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            _validate_json_depth(item, depth=depth + 1)
    elif type(value) is list:
        for item in value:
            _validate_json_depth(item, depth=depth + 1)


def _strict_json_text(value: str) -> Any:
    parsed = json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_int=_strict_int,
        parse_float=_strict_float,
        parse_constant=_reject_constant,
    )
    _validate_json_depth(parsed)
    # Also rejects unpaired surrogate escapes and unsupported numeric values.
    canonical_json_bytes(parsed)
    return parsed


def _strict_json_bytes(value: bytes) -> Any:
    if value.startswith(b"\xef\xbb\xbf"):
        raise ValueError("UTF-8 BOM is forbidden")
    return _strict_json_text(value.decode("utf-8", errors="strict"))


def _candidate_object(content: str) -> dict[str, object]:
    candidate_text = content
    fence_prefixes = ("```json\n", "```\n")
    matched_prefix = next(
        (prefix for prefix in fence_prefixes if content.startswith(prefix)),
        None,
    )
    if matched_prefix is not None:
        if not content.endswith("\n```") or content.count("```") != 2:
            raise ValueError("candidate fence is not one whole wrapper")
        candidate_text = content[len(matched_prefix) : -4]
    elif "```" in content:
        raise ValueError("partial candidate fences are forbidden")
    candidate = _strict_json_text(candidate_text)
    if type(candidate) is not dict:
        raise ValueError("candidate must be one JSON object")
    return candidate


def _response_id(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ValueError("provider request id is invalid")
    if value != value.strip() or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value):
        raise ValueError("provider request id is invalid")
    return value


def _usage(value: object) -> UsageSummary:
    if type(value) is not dict:
        raise ValueError("usage must be an object")
    mapped: list[int] = []
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        item = value.get(key)
        if type(item) is not int or item < 0:
            raise ValueError("usage tokens must be non-negative integers")
        mapped.append(item)
    if mapped[2] != mapped[0] + mapped[1]:
        raise ValueError("usage total must equal prompt plus completion tokens")
    return UsageSummary(
        input_tokens=mapped[0],
        output_tokens=mapped[1],
        total_tokens=mapped[2],
    )


def _validate_execution_binding(
    *,
    planned: PlannedExecution,
    invocation: StageInvocation,
    operation_id: UUID,
) -> tuple[object, object, object]:
    if type(planned) is not PlannedExecution:
        raise TypeError("planned must be PlannedExecution")
    if type(invocation) is not StageInvocation:
        raise TypeError("invocation must be StageInvocation")
    require_uuid(operation_id, "operation_id")
    try:
        planned.validate_integrity()
        invocation.validate_integrity()
    except (TypeError, ValueError, AttributeError) as error:
        raise _config_error("执行计划或阶段输入完整性校验失败。") from error

    plan = planned.plan
    stage_index = next(
        (
            index
            for index, stage in enumerate(plan.stages)
            if stage.stage_id == invocation.stage_id
        ),
        None,
    )
    if stage_index is None:
        raise _config_error("阶段输入不属于冻结执行计划。")
    stage = plan.stages[stage_index]
    operation = next(
        (item for item in stage.network_operations if item.operation_id == operation_id),
        None,
    )
    if operation is None:
        raise _config_error("网络操作不属于冻结阶段。", stage.provider_profile_id)
    resolved = planned.resolved_pipeline.stages[stage_index]
    binding = resolved.stage_binding
    capabilities = resolved.capabilities
    provider = resolved.provider_profile
    if (
        plan.pipeline_kind is not PipelineKind.DIRECT_MULTIMODAL
        or len(plan.stages) != 1
        or len(stage.network_operations) != 1
        or stage.role is not StageRole.SOLVER
        or operation.purpose is not NetworkOperationPurpose.INFERENCE
        or invocation.request_id != plan.request_id
        or invocation.plan_id != plan.plan_id
        or invocation.plan_digest != plan.plan_digest
        or invocation.planned_execution_digest != planned.planned_execution_digest
        or invocation.input_digest != invocation.input.validation_digest
        or provider.adapter_family != GLM_ADAPTER_FAMILY
        or provider.adapter_version != GLM_ADAPTER_VERSION
        or stage.adapter_family != GLM_ADAPTER_FAMILY
        or stage.adapter_version != GLM_ADAPTER_VERSION
        or binding.selected_image_input is not ImageInputKind.RAW_BASE64
        or binding.selected_structured_output is not StructuredOutputKind.PROMPT_ONLY
        or not binding.send_system_instruction
        or binding.send_reasoning_control
        or not binding.expect_usage
        or binding.fixed_non_secret_parameters != ()
        or plan.prompt_policy_digest != PROMPT_POLICY_DIGEST
        or plan.image_preprocessing_policy_version
        != GLM_IMAGE_PREPROCESSING_POLICY_VERSION
        or invocation.input.image_preprocessing_policy_version
        != GLM_IMAGE_PREPROCESSING_POLICY_VERSION
        or capabilities.model_id != stage.model_id
    ):
        raise _config_error(
            "冻结阶段不满足当前多模态 Adapter 合同。",
            stage.provider_profile_id,
        )
    expected_outbound = (
        (OutboundDataKind.IMAGE,)
        if invocation.user_hint is None
        else (OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT)
    )
    if operation.outbound_data != expected_outbound:
        raise _config_error(
            "阶段输入数据种类与冻结操作不匹配。",
            stage.provider_profile_id,
        )
    return stage, operation, resolved


def _map_http_error(status: int, provider_profile_id: str) -> None:
    kwargs = {
        "stage": ADAPTER_DECODE_STAGE,
        "provider_profile_id": provider_profile_id,
    }
    if 300 <= status <= 399:
        raise EndpointPolicyError(**kwargs)
    if status in (401, 403):
        raise AuthError(**kwargs)
    if status in (408, 504):
        raise TimeoutError(**kwargs)
    if status == 413:
        raise PayloadTooLargeError(**kwargs)
    if status == 429:
        raise RateLimitError(**kwargs)
    if status == 503:
        raise ProviderUnavailableError(**kwargs)
    if 500 <= status <= 599:
        raise ProviderServerError(**kwargs)
    if 400 <= status <= 499:
        raise ProviderRequestError(**kwargs)
    if status != 200:
        raise InvalidOutputError(**kwargs)


def _provider_error_code(body: bytes) -> str | None:
    """Extract only a strict GLM business code; never retain its message."""

    try:
        wrapper = _strict_json_bytes(body)
    except (
        UnicodeError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
        json.JSONDecodeError,
    ):
        return None
    if type(wrapper) is not dict:
        return None
    error = wrapper.get("error")
    if type(error) is not dict:
        return None
    code = error.get("code")
    if type(code) is str:
        if len(code) != 4 or not code.isascii() or not code.isdecimal():
            return None
        return code
    if type(code) is int and 1000 <= code <= 9999:
        return str(code)
    return None


def _map_provider_error(
    *,
    status: int,
    body: bytes,
    provider_profile_id: str,
) -> None:
    """Prefer a documented GLM business code, then let HTTP mapping decide."""

    if not 400 <= status <= 599:
        return
    code = _provider_error_code(body)
    if code is None or _PROVIDER_ERROR_HTTP_STATUS.get(code) != status:
        return
    kwargs = {
        "stage": ADAPTER_DECODE_STAGE,
        "provider_profile_id": provider_profile_id,
    }
    if code in _PROVIDER_AUTH_ERROR_CODES:
        raise AuthError(**kwargs)
    if code in _PROVIDER_REQUEST_ERROR_CODES:
        raise ProviderRequestError(**kwargs)
    if code in _PROVIDER_SERVER_ERROR_CODES:
        raise ProviderServerError(**kwargs)
    if code == "1302":
        raise RateLimitError(**kwargs)
    if code in _PROVIDER_NON_RETRYABLE_LIMIT_ERROR_CODES:
        raise RateLimitError(retryable=False, **kwargs)
    if code == "1261":
        raise PayloadTooLargeError(**kwargs)
    if code == "1301":
        raise ContentPolicyError(**kwargs)
    if code == "1305":
        raise ProviderUnavailableError(**kwargs)


@runtime_final
class OpenAIChatCompatibleAdapter:
    """Stateless exact Adapter for the built-in GLM binding."""

    __slots__ = ()

    @staticmethod
    def prepare(
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        operation_id: UUID,
    ) -> PreparedOutbound:
        stage, operation, resolved = _validate_execution_binding(
            planned=planned,
            invocation=invocation,
            operation_id=operation_id,
        )
        capture = invocation.input
        if type(capture) is not ValidatedCapture:
            raise TypeError("invocation input must be ValidatedCapture")
        try:
            capture.validate_integrity()
            # Successful acquisition is the synchronous prepare linearization
            # point. A later release does not retroactively cancel these bytes.
            artifact = capture.artifact
            artifact.validate_integrity()
        except (TypeError, ValueError, AttributeError) as error:
            raise _config_error(
                "已校验截图完整性校验失败。",
                stage.provider_profile_id,
            ) from error
        capabilities = resolved.capabilities
        if (
            artifact.id != capture.capture_id
            or artifact.mime_type != "image/png"
            or artifact.mime_type not in capabilities.supported_mime_types
            or artifact.byte_size > capabilities.max_image_bytes
            or artifact.width_px * artifact.height_px > capabilities.max_image_pixels
            or artifact.byte_size > planned.plan.capture_constraints.max_bytes
            or artifact.width_px > planned.plan.capture_constraints.max_width_px
            or artifact.height_px > planned.plan.capture_constraints.max_height_px
            or artifact.width_px * artifact.height_px
            > planned.plan.capture_constraints.max_pixels
        ):
            raise _config_error(
                "截图不满足冻结的图片输入合同。",
                stage.provider_profile_id,
            )
        encoded_image = base64.b64encode(artifact.data).decode("ascii")
        body = canonical_json_bytes(
            {
                "max_tokens": planned.plan.max_output_tokens,
                "messages": [
                    {"content": SYSTEM_INSTRUCTION, "role": "system"},
                    {
                        "content": [
                            {
                                "image_url": {"url": encoded_image},
                                "type": "image_url",
                            },
                            {
                                "text": build_user_instruction(
                                    locale=invocation.locale,
                                    user_hint=invocation.user_hint,
                                ),
                                "type": "text",
                            },
                        ],
                        "role": "user",
                    },
                ],
                "model": capabilities.model_id,
            }
        )
        prepared = PreparedOutbound(
            plan_id=planned.plan.plan_id,
            plan_digest=planned.plan.plan_digest,
            stage_id=stage.stage_id,
            operation_id=operation.operation_id,
            source_ids=(capture.capture_id, invocation.invocation_id),
            source_digests=(capture.validation_digest, invocation.invocation_digest),
            capture_scope_fingerprint=capture.scope_fingerprint,
            http_method=operation.http_method,
            canonical_url=operation.canonical_endpoint,
            content_type=operation.content_type,
            non_secret_headers=(),
            credential_binding_digest=stage.credential_binding_digest,
            outbound_data=operation.outbound_data,
            body=body,
        )
        validate_prepared_outbound_against_plan(prepared, planned.plan)
        return prepared

    @staticmethod
    def decode(
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        response: TransportResponse,
    ) -> AnswerCandidateResult:
        if type(prepared) is not PreparedOutbound:
            raise TypeError("prepared must be PreparedOutbound")
        if type(response) is not TransportResponse:
            raise TypeError("response must be TransportResponse")
        stage, operation, resolved = _validate_execution_binding(
            planned=planned,
            invocation=invocation,
            operation_id=prepared.operation_id,
        )
        try:
            validate_prepared_outbound_against_plan(prepared, planned.plan)
        except (TypeError, ValueError, AttributeError) as error:
            raise _config_error(
                "出站请求与冻结执行计划不匹配。",
                stage.provider_profile_id,
            ) from error
        if (
            prepared.stage_id != stage.stage_id
            or prepared.operation_id != operation.operation_id
            or prepared.source_ids != (
                invocation.input.capture_id,
                invocation.invocation_id,
            )
            or prepared.source_digests != (
                invocation.input.validation_digest,
                invocation.invocation_digest,
            )
            or prepared.capture_scope_fingerprint
            != invocation.input.scope_fingerprint
            or response.plan_id != planned.plan.plan_id
            or response.stage_id != stage.stage_id
            or response.operation_id != operation.operation_id
            or response.request_envelope_digest != prepared.request_envelope_digest
        ):
            raise EndpointPolicyError(
                stage=ADAPTER_DECODE_STAGE,
                provider_profile_id=stage.provider_profile_id,
            )
        try:
            response.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _invalid_output(stage.provider_profile_id) from None
        _map_provider_error(
            status=response.http_status,
            body=response.body,
            provider_profile_id=stage.provider_profile_id,
        )
        _map_http_error(response.http_status, stage.provider_profile_id)
        try:
            wrapper = _strict_json_bytes(response.body)
            if type(wrapper) is not dict:
                raise ValueError("response wrapper must be an object")
            if wrapper.get("model") != resolved.capabilities.model_id:
                raise ValueError("response model does not match the frozen binding")
            choices = wrapper.get("choices")
            if type(choices) is not list or len(choices) != 1:
                raise ValueError("response must contain exactly one choice")
            choice = choices[0]
            if type(choice) is not dict:
                raise ValueError("response choice is invalid")
            choice_index = choice.get("index")
            if type(choice_index) is not int or choice_index != 0:
                raise ValueError("response choice index is invalid")
            finish_reason = choice.get("finish_reason")
            if type(finish_reason) is not str:
                raise ValueError("response finish reason is invalid")
            if finish_reason in ("sensitive", "content_filter"):
                raise ContentPolicyError(
                    stage=ADAPTER_DECODE_STAGE,
                    provider_profile_id=stage.provider_profile_id,
                )
            if finish_reason == "network_error":
                raise ProviderServerError(
                    stage=ADAPTER_DECODE_STAGE,
                    provider_profile_id=stage.provider_profile_id,
                )
            if finish_reason == "model_context_window_exceeded":
                raise PayloadTooLargeError(
                    stage=ADAPTER_DECODE_STAGE,
                    provider_profile_id=stage.provider_profile_id,
                )
            if finish_reason != "stop":
                raise ValueError("response did not finish with a complete answer")
            message = choice.get("message")
            if type(message) is not dict or message.get("role") != "assistant":
                raise ValueError("response message is invalid")
            if message.get("tool_calls") not in (None, []):
                raise ValueError("unexpected tool call response")
            if message.get("audio") is not None:
                raise ValueError("unexpected audio response")
            reasoning = message.get("reasoning_content")
            if reasoning is not None and type(reasoning) is not str:
                raise ValueError("reasoning content has an invalid type")
            content = message.get("content")
            if type(content) is not str or not content.strip():
                raise ValueError("response content is empty")
            candidate = _candidate_object(content)
            usage = _usage(wrapper.get("usage"))
            body_request_id = _response_id(
                wrapper.get("request_id", wrapper.get("id"))
            )
            provider_request_id = response.provider_request_id or body_request_id
            if (
                response.provider_request_id is not None
                and body_request_id is not None
                and response.provider_request_id != body_request_id
            ):
                raise ValueError("provider request ids disagree")
            return _create_answer_candidate_result(
                request_id=planned.plan.request_id,
                plan_id=planned.plan.plan_id,
                plan_digest=planned.plan.plan_digest,
                stage_id=stage.stage_id,
                operation_id=operation.operation_id,
                invocation_digest=invocation.invocation_digest,
                request_envelope_digest=prepared.request_envelope_digest,
                response_body_digest=response.response_body_digest,
                candidate_payload=candidate,
                refusal=None,
                finish_reason=finish_reason,
                provider_request_id=provider_request_id,
                usage=usage,
            )
        except (
            ContentPolicyError,
            PayloadTooLargeError,
            ProviderServerError,
        ):
            raise
        except (
            UnicodeError,
            ValueError,
            TypeError,
            OverflowError,
            RecursionError,
            json.JSONDecodeError,
        ):
            raise _invalid_output(stage.provider_profile_id) from None


__all__ = [
    "ADAPTER_DECODE_STAGE",
    "ADAPTER_PREPARE_STAGE",
    "MAX_JSON_DEPTH",
    "OpenAIChatCompatibleAdapter",
]
