"""Stable operation errors for the v3 pipeline.

The classes intentionally carry only safe, structured metadata.  Raw SDK
exceptions and Provider response bodies must not cross this boundary.
"""
from __future__ import annotations

from typing import Optional


class OperationError(Exception):
    default_code = "operation_error"
    default_message = "操作失败。"
    default_retryable = False

    def __init__(
        self,
        *,
        stage: str,
        retryable: Optional[bool] = None,
        safe_message: Optional[str] = None,
        provider_profile_id: Optional[str] = None,
        attempt: Optional[int] = None,
    ) -> None:
        if type(stage) is not str or not stage.strip():
            raise ValueError("stage must be a non-empty string")
        message = self.default_message if safe_message is None else safe_message
        if type(message) is not str or not message.strip() or len(message) > 500:
            raise ValueError("safe_message must be a non-empty string of at most 500 chars")
        if provider_profile_id is not None and (
            type(provider_profile_id) is not str or not provider_profile_id.strip()
        ):
            raise ValueError("provider_profile_id must be a non-empty string when present")
        if attempt is not None and (type(attempt) is not int or attempt < 1):
            raise ValueError("attempt must be a positive integer when present")
        if retryable is not None and type(retryable) is not bool:
            raise ValueError("retryable must be bool when present")

        self.code = self.default_code
        self.stage = stage
        self.retryable = self.default_retryable if retryable is None else retryable
        self.safe_message = message
        self.provider_profile_id = provider_profile_id
        self.attempt = attempt
        super().__init__(message)


class ConfigError(OperationError):
    default_code = "config_error"
    default_message = "配置无效。"


class PermissionDeniedError(OperationError):
    default_code = "permission_denied"
    default_message = "未获得屏幕录制权限。"


class CaptureError(OperationError):
    default_code = "capture_error"
    default_message = "无法安全获取题目图像。"


class EndpointPolicyError(OperationError):
    default_code = "endpoint_policy_error"
    default_message = "目标服务地址未通过安全策略。"


class AuthError(OperationError):
    default_code = "auth_error"
    default_message = "模型服务认证失败。"


class RateLimitError(OperationError):
    default_code = "rate_limit_error"
    default_message = "模型服务当前请求过多。"
    default_retryable = True


class NetworkError(OperationError):
    default_code = "network_error"
    default_message = "无法连接模型服务。"
    default_retryable = True


class TimeoutError(OperationError):
    default_code = "timeout_error"
    default_message = "模型服务请求超时。"
    default_retryable = True


class ProviderUnavailableError(OperationError):
    default_code = "provider_unavailable"
    default_message = "模型服务暂时不可用。"
    default_retryable = True


class ProviderRequestError(OperationError):
    default_code = "provider_request_error"
    default_message = "模型服务拒绝了请求。"


class ProviderServerError(OperationError):
    default_code = "provider_server_error"
    default_message = "模型服务发生错误。"
    default_retryable = True


class ContentPolicyError(OperationError):
    default_code = "content_policy_error"
    default_message = "模型服务未处理该内容。"


class PayloadTooLargeError(OperationError):
    default_code = "payload_too_large"
    default_message = "题目图像超过允许大小。"


class InvalidOutputError(OperationError):
    default_code = "invalid_output"
    default_message = "模型返回的结果格式无效。"


class CancelledError(OperationError):
    default_code = "cancelled"
    default_message = "操作已取消。"


class OcrProviderError(OperationError):
    default_code = "ocr_provider_error"
    default_message = "OCR 服务发生错误。"
