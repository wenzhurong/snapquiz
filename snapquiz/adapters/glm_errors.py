"""GLM 错误映射与严格 JSON 解码。

这两部分是 v3 里经得起复用的成果，直接从 `openai_chat_compatible.py` 抄出：

- 智谱官方 34 个业务错误码的 status / typed error / 可重试性全矩阵。欠费、权限、
  周期额度这类不会自行恢复的错误被明确标记为不可重试，不会被当成瞬时故障反复重试。
  出处：https://docs.bigmodel.cn/cn/api/api-code
- 严格 JSON 解码：拒绝重复 key、BOM、NaN/Infinity、超深嵌套、超长数字。
  模型输出是不可信数据，宽松解析会让坏输出冒充结果。

Provider 的原始 message / body 永远不进入异常，只保留 typed error 和错误码。
"""
from __future__ import annotations

import json
import math
from typing import Any

from snapquiz.domain.digest import canonical_json_bytes
from snapquiz.domain.errors import (
    AuthError,
    ContentPolicyError,
    InvalidOutputError,
    PayloadTooLargeError,
    ProviderRequestError,
    ProviderServerError,
    ProviderUnavailableError,
    RateLimitError,
    TimeoutError,
)

DECODE_STAGE = "adapter_decode"
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


def map_http_error(status: int, provider_profile_id: str) -> None:
    kwargs = {
        "stage": DECODE_STAGE,
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


def map_provider_error(
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
        "stage": DECODE_STAGE,
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


strict_json_text = _strict_json_text
strict_json_bytes = _strict_json_bytes

__all__ = [
    "DECODE_STAGE",
    "MAX_JSON_DEPTH",
    "map_http_error",
    "map_provider_error",
    "strict_json_bytes",
    "strict_json_text",
]
