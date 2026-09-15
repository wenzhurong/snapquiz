import json
import pathlib
import unittest

from snapquiz.adapters.glm import PROVIDER_PROFILE_ID, GlmChatAdapter
from snapquiz.config import Config
from snapquiz.domain.adapter import NormalizedRefusal, TransportResponse
from snapquiz.domain.errors import (
    AuthError,
    ContentPolicyError,
    InvalidOutputError,
    PayloadTooLargeError,
    ProviderServerError,
    RateLimitError,
)
from snapquiz.adapters.glm_errors import map_http_error, map_provider_error
from snapquiz.domain.outbound import NonSecretHeader, OutboundDataKind, OutboundRequest
from snapquiz.result.validator import validate_answer_candidate
from tests.helpers import provenance

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
PNG = b"\x89PNG\r\n\x1a\nfake-pixels"


def cfg():
    return Config(region=(0, 0, 640, 480))


def err_body(code):
    return json.dumps({"error": {"code": code, "message": "略"}}).encode()


class PrepareTest(unittest.TestCase):
    def test_wire_shape_matches_golden(self):
        golden = json.loads((FIXTURES / "glm_request.json").read_text())
        body = json.loads(GlmChatAdapter().prepare(config=cfg(), png=PNG).body)
        self.assertEqual(sorted(body), sorted(golden))
        self.assertEqual(
            [p["type"] for p in body["messages"][1]["content"]],
            [p["type"] for p in golden["messages"][1]["content"]],
        )
        self.assertEqual(body["max_tokens"], golden["max_tokens"])

    def test_prepare_is_deterministic(self):
        a = GlmChatAdapter().prepare(config=cfg(), png=PNG)
        b = GlmChatAdapter().prepare(config=cfg(), png=PNG)
        self.assertEqual(a.body, b.body)
        self.assertEqual(a.envelope_digest, b.envelope_digest)

    def test_hint_changes_declared_outbound_data(self):
        without = GlmChatAdapter().prepare(config=cfg(), png=PNG)
        with_hint = GlmChatAdapter().prepare(config=cfg(), png=PNG, user_hint="这是几何题")
        self.assertNotIn(OutboundDataKind.USER_HINT, without.outbound_data)
        self.assertIn(OutboundDataKind.USER_HINT, with_hint.outbound_data)
        self.assertNotEqual(without.envelope_digest, with_hint.envelope_digest)

    def test_url_is_pinned_https_official(self):
        prepared = GlmChatAdapter().prepare(config=cfg(), png=PNG)
        self.assertTrue(prepared.canonical_url.startswith("https://open.bigmodel.cn/"))

    def test_no_credential_headers_in_prepared_bytes(self):
        prepared = GlmChatAdapter().prepare(config=cfg(), png=PNG)
        names = {h.lowercase_name for h in prepared.non_secret_headers}
        self.assertNotIn("authorization", names)
        self.assertNotIn(b"Bearer", prepared.body)


class DecodeTest(unittest.TestCase):
    def setUp(self):
        self.adapter = GlmChatAdapter()
        self.prepared = self.adapter.prepare(config=cfg(), png=PNG)

    def _resp(self, body):
        return TransportResponse(
            request_envelope_digest=self.prepared.envelope_digest,
            http_status=200,
            body=body,
        )

    def test_golden_success_decodes_and_validates(self):
        response = self._resp((FIXTURES / "glm_success.json").read_bytes())
        candidate = self.adapter.decode(prepared=self.prepared, response=response)
        result = validate_answer_candidate(
            candidate,
            response=response,
            provenance=provenance(),
            provider_profile_id=PROVIDER_PROFILE_ID,
        )
        self.assertEqual(result.answer, "2")

    def test_candidate_from_another_response_is_refused(self):
        raw = (FIXTURES / "glm_success.json").read_bytes()
        good = self._resp(raw)
        other = self._resp(raw.replace("得到二".encode(), "得到三".encode()))
        candidate = self.adapter.decode(prepared=self.prepared, response=other)
        with self.assertRaises(InvalidOutputError):
            validate_answer_candidate(
                candidate, response=good, provenance=provenance()
            )

    def test_envelope_mismatch_is_refused(self):
        other = self.adapter.prepare(config=cfg(), png=PNG + b"x")
        with self.assertRaises(InvalidOutputError):
            self.adapter.decode(
                prepared=other, response=self._resp((FIXTURES / "glm_success.json").read_bytes())
            )

    def test_malformed_responses_are_refused(self):
        cases = {
            "空 choices": b'{"choices":[]}',
            "两个 choice": b'{"choices":[{"index":0},{"index":1}]}',
            "False 冒充 index 0": b'{"model":"glm-4.6v-flash","choices":[{"index":false,"message":{"role":"assistant","content":"{}"}}]}',
            "content 非 JSON": '{"model":"glm-4.6v-flash","choices":[{"index":0,"message":{"role":"assistant","content":"抱歉"}}]}'.encode(),
            "空 content": b'{"model":"glm-4.6v-flash","choices":[{"index":0,"message":{"role":"assistant","content":"  "}}]}',
            "错误 model": b'{"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"{}"}}]}',
            "重复 key": b'{"model":"glm-4.6v-flash","model":"x","choices":[]}',
            "BOM": b'\xef\xbb\xbf{"choices":[]}',
            "NaN": b'{"model":"glm-4.6v-flash","usage":{"total_tokens":NaN},"choices":[]}',
        }
        for label, body in cases.items():
            with self.subTest(label=label), self.assertRaises(InvalidOutputError):
                self.adapter.decode(prepared=self.prepared, response=self._resp(body))

    def test_sensitive_finish_reason_becomes_refusal_not_answer(self):
        body = json.dumps(
            {
                "model": "glm-4.6v-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "{}"},
                        "finish_reason": "sensitive",
                    }
                ],
            }
        ).encode()
        candidate = self.adapter.decode(prepared=self.prepared, response=self._resp(body))
        self.assertEqual(candidate.refusal, NormalizedRefusal.CONTENT_POLICY)
        self.assertIsNone(candidate.candidate_payload)
        with self.assertRaises(InvalidOutputError):
            validate_answer_candidate(
                candidate, response=self._resp(body), provenance=provenance()
            )


class ErrorMappingTest(unittest.TestCase):
    def test_http_status_mapping(self):
        for status, exc in (
            (401, AuthError),
            (429, RateLimitError),
            (413, PayloadTooLargeError),
            (500, ProviderServerError),
        ):
            with self.subTest(status=status), self.assertRaises(exc):
                map_http_error(status, PROVIDER_PROFILE_ID)

    def test_business_code_distinguishes_retryable_quota(self):
        """1302 是瞬时限流(可重试);1310 是周期额度耗尽(重试只会继续失败)。"""

        with self.assertRaises(RateLimitError) as transient:
            map_provider_error(status=429, body=err_body("1302"),
                               provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertTrue(transient.exception.retryable)

        with self.assertRaises(RateLimitError) as exhausted:
            map_provider_error(status=429, body=err_body("1310"),
                               provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertFalse(exhausted.exception.retryable)

    def test_content_policy_code(self):
        with self.assertRaises(ContentPolicyError):
            map_provider_error(status=400, body=err_body("1301"),
                               provider_profile_id=PROVIDER_PROFILE_ID)

    def test_unknown_code_falls_through_to_http_mapping(self):
        map_provider_error(status=418, body=b"{}", provider_profile_id=PROVIDER_PROFILE_ID)

    def test_provider_message_never_reaches_the_exception(self):
        body = json.dumps(
            {"error": {"code": "1000", "message": "SECRET-INTERNAL-DETAIL"}}
        ).encode()
        with self.assertRaises(AuthError) as ctx:
            map_provider_error(status=401, body=body,
                               provider_profile_id=PROVIDER_PROFILE_ID)
        self.assertNotIn("SECRET-INTERNAL-DETAIL", repr(ctx.exception))


class OutboundRequestTest(unittest.TestCase):
    def test_credential_bearing_header_names_are_refused(self):
        for name in ("authorization", "x-api-key", "auth-token", "my-secret", "x-token"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                NonSecretHeader(lowercase_name=name, normalized_value="v")

    def test_http_url_is_refused(self):
        with self.assertRaises(ValueError):
            OutboundRequest(
                http_method="POST",
                canonical_url="http://open.bigmodel.cn/x",
                content_type="application/json",
                non_secret_headers=(),
                outbound_data=(OutboundDataKind.IMAGE,),
                body=b"{}",
            )

    def test_integrity_check_detects_nothing_when_untouched(self):
        GlmChatAdapter().prepare(config=cfg(), png=PNG).validate_integrity()

    def test_safe_metadata_has_no_body(self):
        meta = GlmChatAdapter().prepare(config=cfg(), png=PNG).safe_metadata()
        self.assertNotIn("body", meta)
        self.assertGreater(meta["payload_byte_size"], 0)


if __name__ == "__main__":
    unittest.main()
