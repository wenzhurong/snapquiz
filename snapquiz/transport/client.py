"""出站传输：发送 Adapter 已准备好的确切字节。

这 ~90 行替代了 v3 的 44,000 行传输栈（独立 DNS 解析子进程 + 自定义 wire 协议 +
supervisor 四层 + 手写 HTTP/1.1 + Darwin 进程身份归属 + native C）。
那套东西防御的是被污染的 libc resolver、DNS rebinding、同进程恶意插件窃取
capability —— 对一个单用户本地工具、调用一个固定官方域名、用自己的 key 来说，
这些威胁不成立。详见 docs/RECOVERY_PLAN.md。

保留的不变量：
- 不自动重试（v3 与 MVP-0 审计都指出对 4xx 重试是错的）
- 不跟随 3xx（重定向可以把截图和密钥送到别处）
- 响应体有上限
- 密钥只在这里注入，不进 OutboundRequest、不进 envelope digest、不进日志
- 发送前重算 envelope digest，确保「预览的」就是「发出的」
"""
from __future__ import annotations

import logging

from snapquiz.adapters.glm_errors import map_http_error, map_provider_error
from snapquiz.domain.adapter import MAX_PROVIDER_RESPONSE_BYTES, TransportResponse
from snapquiz.domain.errors import NetworkError, TimeoutError as SnapTimeoutError
from snapquiz.domain.outbound import OutboundRequest
from snapquiz.transport.tls import require_safe_tls_environment

logger = logging.getLogger(__name__)

TRANSPORT_STAGE = "transport"


def send_once(
    prepared: OutboundRequest,
    *,
    api_key: str,
    timeout: float,
    provider_profile_id: str,
) -> TransportResponse:
    """发送一次。没有重试循环 —— 重试策略属于调用方，且必须共享同一预算。"""

    import httpx

    require_safe_tls_environment()
    # 预览之后、发送之前的最后一道核对：字节没有被换掉。
    prepared.validate_integrity()

    headers = {
        h.lowercase_name: h.normalized_value for h in prepared.non_secret_headers
    }
    headers["content-type"] = prepared.content_type
    # 密钥在此刻才进入内存中的请求头，且不写回 prepared。
    headers["authorization"] = f"Bearer {api_key}"

    logger.info("outbound %s", prepared.safe_metadata())

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            transport=httpx.HTTPTransport(retries=0),
        ) as client:
            response = client.request(
                prepared.http_method,
                prepared.canonical_url,
                content=prepared.body,
                headers=headers,
            )
    except httpx.TimeoutException as exc:
        raise SnapTimeoutError(
            stage=TRANSPORT_STAGE, provider_profile_id=provider_profile_id
        ) from None
    except httpx.HTTPError:
        # 不让 httpx 的异常文本外泄，它可能包含完整 URL 与 header 名。
        raise NetworkError(
            stage=TRANSPORT_STAGE, provider_profile_id=provider_profile_id
        ) from None
    finally:
        headers["authorization"] = ""

    body = response.content
    if len(body) > MAX_PROVIDER_RESPONSE_BYTES:
        raise NetworkError(
            stage=TRANSPORT_STAGE, provider_profile_id=provider_profile_id
        )

    if response.status_code != 200:
        # 先看智谱业务错误码（能区分「限流可重试」与「周期额度已耗尽」），
        # 未命中再回落到 HTTP 状态映射。
        map_provider_error(
            status=response.status_code,
            body=body,
            provider_profile_id=provider_profile_id,
        )
        map_http_error(response.status_code, provider_profile_id)

    return TransportResponse(
        request_envelope_digest=prepared.envelope_digest,
        http_status=response.status_code,
        body=body,
        provider_request_id=_provider_request_id(response),
    )


def _provider_request_id(response) -> str | None:
    """智谱把请求 id 放在响应头里；取不到就算了，它只用于对账。"""

    value = response.headers.get("x-request-id")
    if type(value) is str and 0 < len(value) <= 256:
        return value
    return None
