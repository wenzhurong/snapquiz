import json
import pathlib
import unittest

from snapquiz.adapters.openai_chat import (
    OpenAIChatAdapter,
    OutputBudgetExhausted,
    _unwrap_code_fence,
)
from snapquiz.config import Config
from snapquiz.providers import OPENCODE_GO, ZHIPU
from snapquiz.domain.adapter import NormalizedRefusal, TransportResponse
from snapquiz.domain.errors import (
    AuthError,
    ContentPolicyError,
    InvalidOutputError,
    PayloadTooLargeError,
    ProviderServerError,
    RateLimitError,
)
from snapquiz.adapters.provider_errors import map_http_error, map_provider_error
from snapquiz.domain.outbound import NonSecretHeader, OutboundDataKind, OutboundRequest
from snapquiz.result.validator import validate_answer_candidate
from tests.helpers import provenance

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
PNG = b"\x89PNG\r\n\x1a\nfake-pixels"


# golden fixture 录的是 glm-4.6v-flash 的响应；测试显式钉住它，
# 不依赖 profile 的 default_model（那个会随实测可用性变化）。
FIXTURE_MODEL = "glm-4.6v-flash"
PROFILE_ID = ZHIPU.profile_id


def cfg(model=FIXTURE_MODEL, profile=ZHIPU):
    return Config(provider=profile, model=model, region=(0, 0, 640, 480),
                  session_id="ses_test")


def err_body(code):
    return json.dumps({"error": {"code": code, "message": "略"}}).encode()


class PrepareTest(unittest.TestCase):
    def test_wire_shape_matches_golden(self):
        golden = json.loads((FIXTURES / "glm_request.json").read_text())
        body = json.loads(OpenAIChatAdapter().prepare(config=cfg(), png=PNG).body)
        self.assertEqual(sorted(body), sorted(golden))
        self.assertEqual(
            [p["type"] for p in body["messages"][1]["content"]],
            [p["type"] for p in golden["messages"][1]["content"]],
        )
        self.assertEqual(body["max_tokens"], golden["max_tokens"])

    def test_prepare_is_deterministic(self):
        a = OpenAIChatAdapter().prepare(config=cfg(), png=PNG)
        b = OpenAIChatAdapter().prepare(config=cfg(), png=PNG)
        self.assertEqual(a.body, b.body)
        self.assertEqual(a.envelope_digest, b.envelope_digest)

    def test_hint_changes_declared_outbound_data(self):
        without = OpenAIChatAdapter().prepare(config=cfg(), png=PNG)
        with_hint = OpenAIChatAdapter().prepare(config=cfg(), png=PNG, user_hint="这是几何题")
        self.assertNotIn(OutboundDataKind.USER_HINT, without.outbound_data)
        self.assertIn(OutboundDataKind.USER_HINT, with_hint.outbound_data)
        self.assertNotEqual(without.envelope_digest, with_hint.envelope_digest)

    def test_url_is_pinned_https_official(self):
        prepared = OpenAIChatAdapter().prepare(config=cfg(), png=PNG)
        self.assertTrue(prepared.canonical_url.startswith("https://open.bigmodel.cn/"))

    def test_no_credential_headers_in_prepared_bytes(self):
        prepared = OpenAIChatAdapter().prepare(config=cfg(), png=PNG)
        names = {h.lowercase_name for h in prepared.non_secret_headers}
        self.assertNotIn("authorization", names)
        self.assertNotIn(b"Bearer", prepared.body)


class DecodeTest(unittest.TestCase):
    def setUp(self):
        self.adapter = OpenAIChatAdapter()
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
            provider_profile_id=PROFILE_ID,
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


class ProviderDifferenceTest(unittest.TestCase):
    """两个 Provider 的差异必须全部落在 profile 上,核心不含分支。"""

    def test_opencode_gets_the_required_session_header(self):
        prepared = OpenAIChatAdapter().prepare(
            config=cfg(model="mimo-v2.5", profile=OPENCODE_GO), png=PNG
        )
        names = {h.lowercase_name: h.normalized_value
                 for h in prepared.non_secret_headers}
        self.assertEqual(names.get("x-opencode-session"), "ses_test")

    def test_zhipu_does_not_get_the_session_header(self):
        prepared = OpenAIChatAdapter().prepare(config=cfg(), png=PNG)
        names = {h.lowercase_name for h in prepared.non_secret_headers}
        self.assertNotIn("x-opencode-session", names)

    def test_session_header_is_covered_by_the_envelope_digest(self):
        """它会被预览,所以必须进 digest —— 换了 session 就是另一次请求。"""

        a = OpenAIChatAdapter().prepare(
            config=Config(provider=OPENCODE_GO, model="mimo-v2.5",
                          region=(0, 0, 1, 1), session_id="ses_a"), png=PNG)
        b = OpenAIChatAdapter().prepare(
            config=Config(provider=OPENCODE_GO, model="mimo-v2.5",
                          region=(0, 0, 1, 1), session_id="ses_b"), png=PNG)
        self.assertEqual(a.body, b.body, "session 不进 body")
        self.assertNotEqual(a.envelope_digest, b.envelope_digest)

    def test_each_provider_uses_its_own_endpoint_and_budget(self):
        z = OpenAIChatAdapter().prepare(config=cfg(), png=PNG)
        o = OpenAIChatAdapter().prepare(
            config=cfg(model="mimo-v2.5", profile=OPENCODE_GO), png=PNG)
        self.assertIn("open.bigmodel.cn", z.canonical_url)
        self.assertIn("opencode.ai", o.canonical_url)
        self.assertEqual(json.loads(z.body)["max_tokens"], ZHIPU.max_output_tokens)
        self.assertEqual(json.loads(o.body)["max_tokens"], OPENCODE_GO.max_output_tokens)

    def test_mimo_style_empty_content_is_budget_exhaustion(self):
        """实测 mimo-v2.5 在预算不足时:content=None、输出全在 reasoning。"""

        prepared = OpenAIChatAdapter().prepare(
            config=cfg(model="mimo-v2.5", profile=OPENCODE_GO), png=PNG)
        body = json.dumps({
            "model": "mimo-v2.5",
            "choices": [{"index": 0, "finish_reason": "length",
                         "message": {"role": "assistant", "content": None,
                                     "reasoning": "Let me think about primes...",
                                     "refusal": None}}],
            "usage": {"prompt_tokens": 1177, "completion_tokens": 1024,
                      "total_tokens": 2201},
        }).encode()
        response = TransportResponse(
            request_envelope_digest=prepared.envelope_digest,
            http_status=200, body=body)
        with self.assertRaises(OutputBudgetExhausted):
            OpenAIChatAdapter().decode(
                prepared=prepared, response=response,
                provider_profile_id=OPENCODE_GO.profile_id)


class RealWorldResponseTest(unittest.TestCase):
    """这些形状来自 2026-09-15 对真实 GLM 的实测，不是想象出来的。"""

    def setUp(self):
        self.adapter = OpenAIChatAdapter()
        self.prepared = self.adapter.prepare(config=cfg(), png=PNG)

    def _resp(self, body):
        return TransportResponse(
            request_envelope_digest=self.prepared.envelope_digest,
            http_status=200,
            body=body,
        )

    def _wrapped(self, content, finish="stop"):
        return json.dumps({
            "model": FIXTURE_MODEL,
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": content},
                         "finish_reason": finish}],
        }).encode()

    ANSWER = {
        "schema_version": "snapquiz.solve-result.v2", "status": "answered",
        "question_summary": "下列四个数中，哪一个是质数？", "answer": "C. 29",
        "rationale": "只有 29 是质数。", "confidence": 1,
        "confidence_kind": "model_self_reported",
        "confidence_calibration_ref": None, "warnings": [],
    }

    def test_markdown_fenced_json_is_accepted(self):
        """实测:即使 prompt 明令禁止,模型仍会用 ```json 围栏包住答案。"""

        fenced = "```json\n" + json.dumps(self.ANSWER, ensure_ascii=False) + "\n```"
        candidate = self.adapter.decode(
            prepared=self.prepared, response=self._resp(self._wrapped(fenced))
        )
        self.assertEqual(candidate.candidate_payload["answer"], "C. 29")

    def test_integer_confidence_is_accepted(self):
        """实测:模型给的是 confidence: 1(int),不是 1.0。"""

        result = validate_answer_candidate(
            self.adapter.decode(
                prepared=self.prepared,
                response=self._resp(self._wrapped(json.dumps(self.ANSWER))),
            ),
            response=self._resp(self._wrapped(json.dumps(self.ANSWER))),
            provenance=provenance(),
        )
        self.assertEqual(result.confidence, 1)

    def test_fence_unwrapping_stays_strict(self):
        """只接受「整段内容恰好是一个围栏」,不退回 MVP-0 的任意捞取。"""

        self.assertEqual(_unwrap_code_fence('```json\n{"a":1}\n```'), '{"a":1}')
        self.assertEqual(_unwrap_code_fence('```\n{"a":1}\n```'), '{"a":1}')
        self.assertEqual(_unwrap_code_fence('{"a":1}'), '{"a":1}')
        # 围栏外有解释文字 → 不剥,后续严格解析会拒绝
        for noisy in ('让我想想:```json\n{"a":1}\n```', '```json\n{"a":1}\n``` 完毕'):
            self.assertEqual(_unwrap_code_fence(noisy), noisy)

    def test_commentary_around_fence_is_still_refused(self):
        noisy = '好的,答案是:```json\n' + json.dumps(self.ANSWER) + '\n```'
        with self.assertRaises(InvalidOutputError):
            self.adapter.decode(
                prepared=self.prepared, response=self._resp(self._wrapped(noisy))
            )

    def test_reasoning_budget_exhaustion_is_its_own_error(self):
        """推理模型的典型失败:思维链吃光 max_tokens,content 为空、finish=length。

        实测 glm-4.6v + max_tokens=50 时 reasoning_tokens=49、content=''。
        这是预算配置问题,不该和"模型乱答"混为一谈。
        """

        body = json.dumps({
            "model": FIXTURE_MODEL,
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": "",
                                     "reasoning_content": "用户现在需要判断哪个数是质数..."},
                         "finish_reason": "length"}],
            "usage": {"prompt_tokens": 1091, "completion_tokens": 50,
                      "total_tokens": 1141},
        }).encode()
        with self.assertRaises(OutputBudgetExhausted):
            self.adapter.decode(prepared=self.prepared, response=self._resp(body))

    def test_empty_content_without_length_stays_generic(self):
        with self.assertRaises(InvalidOutputError) as ctx:
            self.adapter.decode(
                prepared=self.prepared, response=self._resp(self._wrapped("", finish="stop"))
            )
        self.assertNotIsInstance(ctx.exception, OutputBudgetExhausted)


class ErrorMappingTest(unittest.TestCase):
    def test_http_status_mapping(self):
        for status, exc in (
            (401, AuthError),
            (429, RateLimitError),
            (413, PayloadTooLargeError),
            (500, ProviderServerError),
        ):
            with self.subTest(status=status), self.assertRaises(exc):
                map_http_error(status, PROFILE_ID)

    def test_business_code_distinguishes_retryable_quota(self):
        """1302 是瞬时限流(可重试);1310 是周期额度耗尽(重试只会继续失败)。"""

        with self.assertRaises(RateLimitError) as transient:
            map_provider_error(status=429, body=err_body("1302"),
                               provider_profile_id=PROFILE_ID)
        self.assertTrue(transient.exception.retryable)

        with self.assertRaises(RateLimitError) as exhausted:
            map_provider_error(status=429, body=err_body("1310"),
                               provider_profile_id=PROFILE_ID)
        self.assertFalse(exhausted.exception.retryable)

    def test_content_policy_code(self):
        with self.assertRaises(ContentPolicyError):
            map_provider_error(status=400, body=err_body("1301"),
                               provider_profile_id=PROFILE_ID)

    def test_unknown_code_falls_through_to_http_mapping(self):
        map_provider_error(status=418, body=b"{}", provider_profile_id=PROFILE_ID)

    def test_provider_message_never_reaches_the_exception(self):
        body = json.dumps(
            {"error": {"code": "1000", "message": "SECRET-INTERNAL-DETAIL"}}
        ).encode()
        with self.assertRaises(AuthError) as ctx:
            map_provider_error(status=401, body=body,
                               provider_profile_id=PROFILE_ID)
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
        OpenAIChatAdapter().prepare(config=cfg(), png=PNG).validate_integrity()

    def test_safe_metadata_has_no_body(self):
        meta = OpenAIChatAdapter().prepare(config=cfg(), png=PNG).safe_metadata()
        self.assertNotIn("body", meta)
        self.assertGreater(meta["payload_byte_size"], 0)


if __name__ == "__main__":
    unittest.main()
