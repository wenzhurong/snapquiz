import json
import os
import unittest
from unittest.mock import patch

from snapquiz.adapters.glm import PROVIDER_PROFILE_ID, GlmChatAdapter
from snapquiz.config import Config
from snapquiz.domain.errors import AuthError, NetworkError, RateLimitError
from snapquiz.transport.tls import (
    FORBIDDEN_TLS_ENVIRONMENT_KEYS,
    TlsEnvironmentUnsafe,
    require_safe_tls_environment,
)

try:
    import httpx
except ImportError:  # pragma: no cover - httpx 是运行依赖，纯逻辑测试可跳过
    httpx = None

PNG = b"\x89PNG\r\n\x1a\nfake"
SUCCESS = json.dumps(
    {
        "model": "glm-4.6v-flash",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "schema_version": "snapquiz.solve-result.v2",
                            "status": "answered",
                            "question_summary": "q",
                            "answer": "A",
                            "rationale": "r",
                            "confidence": None,
                            "confidence_kind": "none",
                            "confidence_calibration_ref": None,
                            "warnings": [],
                        }
                    ),
                },
                "finish_reason": "stop",
            }
        ],
    }
).encode()


class TlsEnvironmentTest(unittest.TestCase):
    def test_clean_environment_passes(self):
        with patch.dict(os.environ, {}, clear=False):
            for key in FORBIDDEN_TLS_ENVIRONMENT_KEYS:
                os.environ.pop(key, None)
            require_safe_tls_environment()

    def test_each_forbidden_key_blocks_sending(self):
        for key in FORBIDDEN_TLS_ENVIRONMENT_KEYS:
            with self.subTest(key=key), patch.dict(os.environ, {key: ""}):
                with self.assertRaises(TlsEnvironmentUnsafe) as ctx:
                    require_safe_tls_environment()
                self.assertIn(key, str(ctx.exception))

    def test_error_names_the_key_not_its_value(self):
        with patch.dict(os.environ, {"SSLKEYLOGFILE": "/tmp/secret-path.log"}):
            with self.assertRaises(TlsEnvironmentUnsafe) as ctx:
                require_safe_tls_environment()
            self.assertNotIn("secret-path", str(ctx.exception))


@unittest.skipIf(httpx is None, "httpx not installed")
class SendOnceTest(unittest.TestCase):
    def setUp(self):
        from snapquiz.transport.client import send_once

        self.send_once = send_once
        self.cfg = Config(region=(0, 0, 640, 480))
        self.prepared = GlmChatAdapter().prepare(config=self.cfg, png=PNG)
        for key in FORBIDDEN_TLS_ENVIRONMENT_KEYS:
            if key in os.environ:
                self.skipTest(f"环境里有 {key}")

    def _with(self, handler):
        real = httpx.Client

        def factory(**kwargs):
            kwargs.pop("transport", None)
            return real(transport=httpx.MockTransport(handler), **kwargs)

        return patch.object(httpx, "Client", factory)

    def test_sends_prepared_bytes_verbatim(self):
        seen = {}

        def handler(request):
            seen["method"] = request.method
            seen["url"] = str(request.url)
            seen["headers"] = dict(request.headers)
            seen["body"] = request.content
            return httpx.Response(200, content=SUCCESS)

        with self._with(handler):
            response = self.send_once(
                self.prepared, api_key="zp-secret",
                timeout=5, provider_profile_id=PROVIDER_PROFILE_ID,
            )

        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["url"], self.cfg.endpoint_url)
        self.assertEqual(seen["body"], self.prepared.body, "发出的字节必须等于预览的字节")
        self.assertEqual(seen["headers"]["authorization"], "Bearer zp-secret")
        self.assertEqual(
            response.request_envelope_digest, self.prepared.envelope_digest
        )

    def test_secret_never_enters_the_prepared_request(self):
        self.assertNotIn(b"zp-secret", self.prepared.body)
        self.assertNotIn("zp-secret", repr(self.prepared))
        self.assertNotIn("zp-secret", json.dumps(self.prepared.safe_metadata()))

    def test_business_error_code_wins_over_http_status(self):
        def handler(request):
            return httpx.Response(
                401, content=json.dumps({"error": {"code": "1000", "message": "内部细节"}}).encode()
            )

        with self._with(handler), self.assertRaises(AuthError) as ctx:
            self.send_once(self.prepared, api_key="x", timeout=5,
                           provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertNotIn("内部细节", repr(ctx.exception))

    def test_rate_limit_retryability_reaches_the_caller(self):
        def make(code):
            def handler(request):
                return httpx.Response(429, content=json.dumps({"error": {"code": code}}).encode())
            return handler

        with self._with(make("1302")), self.assertRaises(RateLimitError) as transient:
            self.send_once(self.prepared, api_key="x", timeout=5,
                           provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertTrue(transient.exception.retryable)

        with self._with(make("1310")), self.assertRaises(RateLimitError) as exhausted:
            self.send_once(self.prepared, api_key="x", timeout=5,
                           provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertFalse(exhausted.exception.retryable)

    def test_oversized_response_is_refused(self):
        def handler(request):
            return httpx.Response(200, content=b"x" * (3 * 1024 * 1024))

        with self._with(handler), self.assertRaises(NetworkError):
            self.send_once(self.prepared, api_key="x", timeout=5,
                           provider_profile_id=PROVIDER_PROFILE_ID)

    def test_network_error_text_does_not_leak_url_or_headers(self):
        def handler(request):
            raise httpx.ConnectError("failed to connect to open.bigmodel.cn")

        with self._with(handler), self.assertRaises(NetworkError) as ctx:
            self.send_once(self.prepared, api_key="zp-secret", timeout=5,
                           provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertNotIn("zp-secret", repr(ctx.exception))
        self.assertNotIn("bigmodel", repr(ctx.exception))

    def test_tls_environment_is_checked_before_any_request(self):
        called = []

        def handler(request):
            called.append(1)
            return httpx.Response(200, content=SUCCESS)

        with patch.dict(os.environ, {"SSLKEYLOGFILE": "/tmp/x"}), self._with(handler):
            with self.assertRaises(TlsEnvironmentUnsafe):
                self.send_once(self.prepared, api_key="x", timeout=5,
                               provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertEqual(called, [], "TLS 环境不安全时不得发出请求")


if __name__ == "__main__":
    unittest.main()
