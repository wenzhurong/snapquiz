from __future__ import annotations

import base64
import copy
from dataclasses import asdict
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from threading import Barrier, Lock, Thread
import time
import unittest
from unittest.mock import patch

from snapquiz.adapters.openai_chat_compatible import OpenAIChatCompatibleAdapter
from snapquiz.domain.adapter import (
    MAX_PROVIDER_RESPONSE_BYTES,
    TransportResponse,
)
from snapquiz.domain.errors import (
    AuthError,
    CaptureError,
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
from snapquiz.domain.intent import SOLVE_INTENT_SCHEMA_VERSION, OutputTokenLimit, SolveIntent
from snapquiz.domain.solve import (
    SOLVE_RESULT_SCHEMA_VERSION,
    PipelineKind,
    SolveProvenance,
    StageProvenance,
)
from snapquiz.pipelines.contracts import (
    SolveRequest,
    SolveRequestFactory,
    StageInvocation,
)
from snapquiz.result.validator import validate_answer_candidate

from tests.w07_helpers import (
    canonical_png_bytes,
    make_w07_authorities,
    registry_with_fixed_parameters,
)


FIXTURES = Path(__file__).with_name("fixtures")


def _fixture(name: str) -> bytes:
    value = (FIXTURES / name).read_bytes()
    return value[:-1] if value.endswith(b"\n") else value


def _prepared(authorities):
    return OpenAIChatCompatibleAdapter.prepare(
        planned=authorities.planned,
        invocation=authorities.invocation,
        operation_id=authorities.operation.operation_id,
    )


def _response(
    authorities,
    prepared,
    *,
    body: bytes | None = None,
    status: int = 200,
    provider_request_id: str | None = "request-test-1",
    plan_id=None,
    stage_id=None,
    operation_id=None,
    envelope_digest=None,
) -> TransportResponse:
    return TransportResponse(
        plan_id=prepared.plan_id if plan_id is None else plan_id,
        stage_id=prepared.stage_id if stage_id is None else stage_id,
        operation_id=(
            prepared.operation_id if operation_id is None else operation_id
        ),
        request_envelope_digest=(
            prepared.request_envelope_digest
            if envelope_digest is None
            else envelope_digest
        ),
        http_status=status,
        provider_request_id=provider_request_id,
        body=_fixture("w07_glm_success.json") if body is None else body,
    )


def _success_wrapper(*, content: str, finish_reason: str = "stop", usage=None):
    return {
        "id": "task-test-1",
        "request_id": "request-test-1",
        "model": "glm-4.6v-flash",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish_reason,
            }
        ],
        "usage": (
            {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
            if usage is None
            else usage
        ),
    }


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


class _ForbiddenEnvironment:
    def _reject(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("environment access")

    __getitem__ = _reject
    __iter__ = _reject
    __len__ = _reject
    __contains__ = _reject
    get = _reject
    keys = _reject
    items = _reject
    values = _reject


class RequestInvocationContractTest(unittest.TestCase):
    def test_intent_request_invocation_digest_chain_is_fixed(self):
        authorities = make_w07_authorities()
        self.assertEqual(
            str(authorities.intent.intent_digest),
            "353bf56190026dc7b0777c1eda65daa3badc6d93ee8892741d26822dfc2e2287",
        )
        self.assertEqual(
            str(authorities.planned.planned_execution_digest),
            "9653fc96b8fed95ed32936be9473cd584f05841d0dcaa3dab6df3c97fa711e8e",
        )
        self.assertEqual(
            str(authorities.solve_request.solve_request_digest),
            "7ddc092547ff0157055de75275c1a4c0db76261ff8edd2543c1e73bd479bc6fe",
        )
        self.assertEqual(
            str(authorities.invocation.invocation_id),
            "6166071f-14ff-590e-9e2c-356d9238747e",
        )
        self.assertEqual(
            str(authorities.invocation.invocation_digest),
            "058052c484226774fa2083a7eb25a0e6b03f26234e01a765f07ed3a6cb10402b",
        )

    def test_request_and_invocation_are_private_immutable_and_redacted(self):
        canary = "PRIVATE-HINT-CANARY"
        authorities = make_w07_authorities(user_hint=canary)
        with self.assertRaises(TypeError):
            SolveRequest(
                planned=authorities.planned,
                intent=authorities.intent,
                validated_capture=authorities.validated,
            )
        with self.assertRaises(TypeError):
            StageInvocation(
                planned=authorities.planned,
                solve_request=authorities.solve_request,
                stage_id=authorities.planned.plan.stages[0].stage_id,
            )
        for value in (authorities.solve_request, authorities.invocation):
            self.assertNotIn(canary, repr(value))
            self.assertNotIn(canary, repr(value.safe_metadata()))
            with self.assertRaises(TypeError):
                asdict(value)  # type: ignore[arg-type]
            self.assertIs(copy.deepcopy(value), value)
        with self.assertRaises(AttributeError):
            authorities.solve_request.locale = "en"  # type: ignore[misc]
        digest_prefix = str(authorities.planned.planned_execution_digest)[:12]
        self.assertNotIn(digest_prefix, repr(authorities.planned))
        self.assertNotIn(digest_prefix, repr(authorities.planned.safe_metadata()))
        self.assertNotIn(digest_prefix, repr(authorities.privacy.safe_metadata()))

    def test_original_intent_digest_prevents_same_presence_hint_swap(self):
        authorities = make_w07_authorities(user_hint="original")
        replacement = SolveIntent(
            schema_version=SOLVE_INTENT_SCHEMA_VERSION,
            request_id=authorities.intent.request_id,
            pipeline_profile_id=authorities.intent.pipeline_profile_id,
            capture_scope_preference=authorities.intent.capture_scope_preference,
            locale=authorities.intent.locale,
            timeout_budget_ms=authorities.intent.timeout_budget_ms,
            max_output_tokens=OutputTokenLimit.PROFILE_DEFAULT,
            requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
            user_hint="replacement",
        )
        self.assertNotEqual(replacement.intent_digest, authorities.intent.intent_digest)
        with self.assertRaises(ConfigError):
            SolveRequestFactory.create(
                planned=authorities.planned,
                intent=replacement,
                validated_capture=authorities.validated,
            )

    def test_request_factory_rejects_raw_capture_and_released_capture(self):
        authorities = make_w07_authorities()
        with self.assertRaises(TypeError):
            SolveRequestFactory.create(
                planned=authorities.planned,
                intent=authorities.intent,
                validated_capture=authorities.artifact,  # type: ignore[arg-type]
            )
        authorities.validated.release()
        with self.assertRaises(CaptureError):
            SolveRequestFactory.create(
                planned=authorities.planned,
                intent=authorities.intent,
                validated_capture=authorities.validated,
            )


class PrepareContractTest(unittest.TestCase):
    def test_exact_request_fixture_and_envelope_golden(self):
        authorities = make_w07_authorities()
        prepared = _prepared(authorities)
        self.assertEqual(prepared.body, _fixture("w07_glm_request.json"))
        self.assertEqual(prepared.payload_byte_size, 1_805)
        self.assertEqual(
            str(prepared.body_digest),
            "b1a966d2b7102f4b0c8aced7df05c6012847064a6cc97f7510107db133877e6f",
        )
        self.assertEqual(
            str(prepared.non_secret_headers_digest),
            "b8ff11951b39d11d9937a414d1cd090aec3b65699a001acb17d940d8e1da93ef",
        )
        self.assertEqual(
            str(prepared.request_envelope_digest),
            "0a6cba2d01d34886a93054a26d20b9b1c85fed0cf5075d3e78ef693bba20dbbd",
        )
        self.assertEqual(
            prepared.source_ids,
            (authorities.validated.capture_id, authorities.invocation.invocation_id),
        )
        self.assertEqual(
            prepared.source_digests,
            (
                authorities.validated.validation_digest,
                authorities.invocation.invocation_digest,
            ),
        )
        self.assertEqual(
            prepared.capture_scope_fingerprint,
            authorities.validated.scope_fingerprint,
        )

    def test_png_is_raw_standard_base64_exactly_once(self):
        prepared = _prepared(make_w07_authorities())
        body = json.loads(prepared.body)
        encoded = body["messages"][1]["content"][0]["image_url"]["url"]
        self.assertEqual(encoded, base64.b64encode(canonical_png_bytes()).decode("ascii"))
        self.assertEqual(base64.b64decode(encoded, validate=True), canonical_png_bytes())
        self.assertNotIn("data:image", encoded)
        self.assertNotIn("http", encoded)
        self.assertNotIn("\n", encoded)

    def test_prepare_is_deterministic_repeatable_and_stateless(self):
        authorities = make_w07_authorities()
        first = _prepared(authorities)
        second = _prepared(authorities)
        self.assertEqual(first.body, second.body)
        self.assertEqual(first.request_envelope_digest, second.request_envelope_digest)
        self.assertFalse(authorities.validated.is_released)
        adapter = OpenAIChatCompatibleAdapter()
        self.assertFalse(hasattr(adapter, "__dict__"))
        with self.assertRaises(TypeError):
            type("EvilAdapter", (OpenAIChatCompatibleAdapter,), {})

    def test_hint_is_authority_bound_and_never_in_repr(self):
        canary = "HINT-CANARY-私密"
        authorities = make_w07_authorities(user_hint=canary)
        prepared = _prepared(authorities)
        self.assertIn(canary, prepared.body.decode("utf-8"))
        self.assertNotIn(canary, repr(prepared))
        self.assertNotIn(canary, repr(authorities.invocation))

    def test_release_before_prepare_fails_closed(self):
        authorities = make_w07_authorities()
        authorities.validated.release()
        with self.assertRaises(CaptureError):
            _prepared(authorities)

    def test_prepare_release_race_has_only_two_linearized_outcomes(self):
        for _ in range(12):
            authorities = make_w07_authorities()
            barrier = Barrier(2)
            outcomes: list[object] = []
            lock = Lock()

            def prepare_worker():
                barrier.wait()
                try:
                    value = _prepared(authorities)
                except BaseException as error:  # test captures exact allowed class
                    value = error
                with lock:
                    outcomes.append(value)

            def release_worker():
                barrier.wait()
                authorities.validated.release()

            threads = (Thread(target=prepare_worker), Thread(target=release_worker))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(len(outcomes), 1)
            outcome = outcomes[0]
            self.assertTrue(
                isinstance(outcome, (CaptureError,))
                or getattr(outcome, "body", None) == _fixture("w07_glm_request.json")
            )

    def test_parallel_prepare_is_identical_and_does_not_consume_send_authority(self):
        authorities = make_w07_authorities()
        barrier = Barrier(3)
        results = []
        lock = Lock()

        def worker():
            barrier.wait()
            prepared = _prepared(authorities)
            with lock:
                results.append(prepared)

        threads = (Thread(target=worker), Thread(target=worker))
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].body, results[1].body)
        self.assertEqual(
            results[0].request_envelope_digest,
            results[1].request_envelope_digest,
        )

    def test_plan_or_capture_tamper_fails_before_serialization(self):
        authorities = make_w07_authorities()
        object.__setattr__(
            authorities.planned,
            "planned_execution_digest",
            authorities.planned.plan.plan_digest,
        )
        with self.assertRaises(ConfigError):
            _prepared(authorities)

    def test_unconsumed_fixed_adapter_parameters_fail_closed(self):
        authorities = make_w07_authorities(
            registry=registry_with_fixed_parameters((("temperature", "0"),))
        )
        with self.assertRaises(ConfigError):
            _prepared(authorities)


class DecodeContractTest(unittest.TestCase):
    def setUp(self):
        self.authorities = make_w07_authorities()
        self.prepared = _prepared(self.authorities)

    def decode(self, response: TransportResponse):
        return OpenAIChatCompatibleAdapter.decode(
            planned=self.authorities.planned,
            invocation=self.authorities.invocation,
            prepared=self.prepared,
            response=response,
        )

    def test_success_fixture_returns_bound_candidate_then_strict_result(self):
        candidate = self.decode(_response(self.authorities, self.prepared))
        candidate.validate_binding(
            request_id=self.authorities.planned.plan.request_id,
            plan_id=self.prepared.plan_id,
            plan_digest=self.prepared.plan_digest,
            stage_id=self.prepared.stage_id,
            operation_id=self.prepared.operation_id,
            invocation_digest=self.authorities.invocation.invocation_digest,
            request_envelope_digest=self.prepared.request_envelope_digest,
        )
        resolved = self.authorities.planned.resolved_pipeline.stages[0]
        stage = self.authorities.planned.plan.stages[0]
        provenance = SolveProvenance(
            pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
            plan_id=self.prepared.plan_id,
            stages=(
                StageProvenance(
                    stage_id=stage.stage_id,
                    role=stage.role,
                    binding_id=stage.binding_id,
                    provider_profile_id=stage.provider_profile_id,
                    provider_profile_digest=stage.provider_profile_digest,
                    provider_id=stage.provider_id,
                    model_id=stage.model_id,
                    component_id=None,
                    component_version=None,
                    adapter_family=stage.adapter_family,
                    adapter_version=stage.adapter_version,
                    capabilities_ref=stage.capabilities_ref,
                    capabilities_digest=stage.capabilities_digest,
                    attempts=1,
                    network_calls=1,
                    latency_ms=10,
                    usage=candidate.usage,
                ),
            ),
        )
        result = validate_answer_candidate(
            candidate,
            provenance=provenance,
            request_id=self.authorities.planned.plan.request_id,
            plan_id=self.prepared.plan_id,
            plan_digest=self.prepared.plan_digest,
            stage_id=self.prepared.stage_id,
            operation_id=self.prepared.operation_id,
            invocation_digest=self.authorities.invocation.invocation_digest,
            request_envelope_digest=self.prepared.request_envelope_digest,
            provider_profile_id=resolved.provider_profile.provider_profile_id,
        )
        self.assertEqual(result.answer, "2")
        self.assertEqual(candidate.usage.total_tokens, 120)
        self.assertNotIn("把两个一相加", repr(candidate))
        self.assertNotIn("把两个一相加", repr(candidate.safe_metadata()))
        with self.assertRaises(TypeError):
            asdict(candidate)  # type: ignore[arg-type]

    def test_candidate_binding_rejects_cross_invocation(self):
        candidate = self.decode(_response(self.authorities, self.prepared))
        other = make_w07_authorities(
            request_id=type(self.authorities.intent.request_id)(
                "30000000-0000-0000-0000-000000000099"
            )
        )
        with self.assertRaises(ValueError):
            candidate.validate_binding(
                request_id=other.planned.plan.request_id,
                plan_id=other.planned.plan.plan_id,
                plan_digest=other.planned.plan.plan_digest,
                stage_id=other.planned.plan.stages[0].stage_id,
                operation_id=other.operation.operation_id,
                invocation_digest=other.invocation.invocation_digest,
                request_envelope_digest=self.prepared.request_envelope_digest,
            )

    def test_exact_single_whole_json_fence_is_the_only_repair(self):
        payload = json.loads(_fixture("w07_glm_success.json"))
        content = payload["choices"][0]["message"]["content"]
        for fenced in (f"```json\n{content}\n```", f"```\n{content}\n```"):
            with self.subTest(prefix=fenced[:7]):
                body = _json_bytes(_success_wrapper(content=fenced))
                candidate = self.decode(
                    _response(self.authorities, self.prepared, body=body)
                )
                self.assertEqual(candidate.candidate_payload["answer"], "2")
        for malformed in (
            f"answer follows: {content}",
            f"```json\n{content}\n``` trailing",
            f"prefix ```json\n{content}\n```",
        ):
            with self.subTest(malformed=malformed[:12]), self.assertRaises(
                InvalidOutputError
            ):
                self.decode(
                    _response(
                        self.authorities,
                        self.prepared,
                        body=_json_bytes(_success_wrapper(content=malformed)),
                    )
                )

    def test_strict_json_and_usage_fail_closed(self):
        valid = json.loads(_fixture("w07_glm_success.json"))
        content = valid["choices"][0]["message"]["content"]
        cases = (
            b"\xef\xbb\xbf" + _fixture("w07_glm_success.json"),
            b'{"model":"glm-4.6v-flash","model":"glm-4.6v-flash"}',
            _json_bytes({**valid, "choices": []}),
            _json_bytes({**valid, "choices": valid["choices"] * 2}),
            _json_bytes(_success_wrapper(content=content, usage={
                "prompt_tokens": True,
                "completion_tokens": 20,
                "total_tokens": 120,
            })),
            _json_bytes(_success_wrapper(content=content, usage={
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 7,
            })),
            _json_bytes(_success_wrapper(content='{"x":1,"x":2}')),
        )
        for body in cases:
            with self.subTest(body=body[:24]), self.assertRaises(InvalidOutputError):
                self.decode(_response(self.authorities, self.prepared, body=body))

    def test_choice_and_response_fields_are_non_coercing(self):
        valid = json.loads(_fixture("w07_glm_success.json"))
        cases = []
        for index in (False, 0.0):
            value = copy.deepcopy(valid)
            value["choices"][0]["index"] = index
            cases.append(value)
        wrong_model = copy.deepcopy(valid)
        wrong_model["model"] = "another-model"
        cases.append(wrong_model)
        for key, value in (
            ("tool_calls", [{"id": "unexpected"}]),
            ("audio", {"id": "unexpected"}),
            ("content", ""),
        ):
            wrapper = copy.deepcopy(valid)
            wrapper["choices"][0]["message"][key] = value
            cases.append(wrapper)
        for wrapper in cases:
            with self.subTest(wrapper=repr(wrapper)[:80]), self.assertRaises(
                InvalidOutputError
            ):
                self.decode(
                    _response(
                        self.authorities,
                        self.prepared,
                        body=_json_bytes(wrapper),
                    )
                )

        mismatched_request_id = copy.deepcopy(valid)
        mismatched_request_id["request_id"] = "another-request"
        with self.assertRaises(InvalidOutputError):
            self.decode(
                _response(
                    self.authorities,
                    self.prepared,
                    body=_json_bytes(mismatched_request_id),
                )
            )

    def test_finish_reason_mapping(self):
        content = json.loads(_fixture("w07_glm_success.json"))["choices"][0]["message"]["content"]
        cases = (
            ("sensitive", ContentPolicyError),
            ("content_filter", ContentPolicyError),
            ("network_error", ProviderServerError),
            ("model_context_window_exceeded", PayloadTooLargeError),
            ("length", InvalidOutputError),
            ("tool_calls", InvalidOutputError),
            ("unknown", InvalidOutputError),
        )
        for finish_reason, expected in cases:
            with self.subTest(finish_reason=finish_reason), self.assertRaises(expected):
                self.decode(
                    _response(
                        self.authorities,
                        self.prepared,
                        body=_json_bytes(
                            _success_wrapper(
                                content=content,
                                finish_reason=finish_reason,
                            )
                        ),
                    )
                )

    def test_http_status_mapping_never_exposes_error_body(self):
        canary = b"RAW-PROVIDER-ERROR-CANARY"
        cases = (
            (301, EndpointPolicyError, False),
            (400, ProviderRequestError, False),
            (401, AuthError, False),
            (403, AuthError, False),
            (404, ProviderRequestError, False),
            (408, TimeoutError, True),
            (413, PayloadTooLargeError, False),
            (422, ProviderRequestError, False),
            (429, RateLimitError, True),
            (500, ProviderServerError, True),
            (502, ProviderServerError, True),
            (503, ProviderUnavailableError, True),
            (504, TimeoutError, True),
            (201, InvalidOutputError, False),
        )
        for status, expected, retryable in cases:
            with self.subTest(status=status):
                with self.assertRaises(expected) as raised:
                    self.decode(
                        _response(
                            self.authorities,
                            self.prepared,
                            body=canary,
                            status=status,
                            provider_request_id=None,
                        )
                    )
                self.assertEqual(raised.exception.retryable, retryable)
                self.assertNotIn(canary.decode(), str(raised.exception))
                self.assertIsNone(raised.exception.__context__)

    def test_glm_business_error_code_precedes_http_fallback(self):
        cases = (
            ("w07_glm_error_content_policy.json", 400, ContentPolicyError, False),
            ("w07_glm_error_prompt_too_long.json", 400, PayloadTooLargeError, False),
            ("w07_glm_error_rate_limit.json", 429, RateLimitError, True),
            ("w07_glm_error_quota_limit.json", 429, RateLimitError, False),
            ("w07_glm_error_unavailable.json", 429, ProviderUnavailableError, True),
            ("w07_glm_error_unpaid.json", 429, ProviderRequestError, False),
            ("w07_glm_error_model_permission.json", 429, AuthError, False),
        )
        for fixture, status, expected, retryable in cases:
            body = _fixture(fixture)
            canary = json.loads(body)["error"]["message"]
            with self.subTest(fixture=fixture), self.assertRaises(expected) as raised:
                self.decode(
                    _response(
                        self.authorities,
                        self.prepared,
                        body=body,
                        status=status,
                        provider_request_id=None,
                    )
                )
            self.assertEqual(raised.exception.retryable, retryable)
            self.assertNotIn(canary, str(raised.exception))
            self.assertNotIn(canary, repr(vars(raised.exception)))

        full_matrix = (
            ("1000", 401, AuthError, False),
            ("1001", 401, AuthError, False),
            ("1003", 401, AuthError, False),
            ("1005", 401, AuthError, False),
            ("1113", 429, ProviderRequestError, False),
            ("1200", 500, ProviderServerError, True),
            ("1210", 400, ProviderRequestError, False),
            ("1211", 400, ProviderRequestError, False),
            ("1212", 400, ProviderRequestError, False),
            ("1213", 400, ProviderRequestError, False),
            ("1214", 400, ProviderRequestError, False),
            ("1215", 400, ProviderRequestError, False),
            ("1220", 403, AuthError, False),
            ("1221", 400, ProviderRequestError, False),
            ("1222", 400, ProviderRequestError, False),
            ("1230", 500, ProviderServerError, True),
            ("1234", 500, ProviderServerError, True),
            ("1261", 400, PayloadTooLargeError, False),
            ("1301", 400, ContentPolicyError, False),
            ("1302", 429, RateLimitError, True),
            ("1305", 429, ProviderUnavailableError, True),
            ("1308", 429, RateLimitError, False),
            ("1309", 429, AuthError, False),
            ("1310", 429, RateLimitError, False),
            ("1311", 429, AuthError, False),
            ("1313", 429, RateLimitError, False),
            ("1314", 429, AuthError, False),
            ("1315", 429, AuthError, False),
            ("1316", 429, RateLimitError, False),
            ("1317", 429, RateLimitError, False),
            ("1318", 429, RateLimitError, False),
            ("1319", 429, RateLimitError, False),
            ("1320", 429, RateLimitError, False),
            ("1321", 429, RateLimitError, False),
        )
        self.assertEqual(len(full_matrix), 34)
        for code, status, expected, retryable in full_matrix:
            canary = f"BUSINESS-CODE-{code}-MESSAGE-CANARY"
            body = _json_bytes({"error": {"code": code, "message": canary}})
            with self.subTest(code=code), self.assertRaises(expected) as raised:
                self.decode(
                    _response(
                        self.authorities,
                        self.prepared,
                        body=body,
                        status=status,
                        provider_request_id=None,
                    )
                )
            self.assertEqual(raised.exception.retryable, retryable)
            self.assertNotIn(canary, str(raised.exception))
            self.assertNotIn(canary, repr(vars(raised.exception)))

        malformed = (
            b'{"error":{"code":"1301","code":"1261"}}',
            b'{"error":{"code":"130100000000000000000"}}',
            b'{"error":{"code":false}}',
            b'{"error":{"code":"9999"}}',
        )
        for body in malformed:
            with self.subTest(body=body), self.assertRaises(RateLimitError):
                self.decode(
                    _response(
                        self.authorities,
                        self.prepared,
                        body=body,
                        status=429,
                        provider_request_id=None,
                    )
                )
        with self.assertRaises(ProviderServerError):
            self.decode(
                _response(
                    self.authorities,
                    self.prepared,
                    body=_fixture("w07_glm_error_content_policy.json"),
                    status=500,
                    provider_request_id=None,
                )
            )

    def test_transport_response_and_candidate_tamper_fail_closed(self):
        with self.assertRaises(ValueError):
            _response(
                self.authorities,
                self.prepared,
                body=b"x" * (MAX_PROVIDER_RESPONSE_BYTES + 1),
            )
        with self.assertRaises(ValueError):
            _response(
                self.authorities,
                self.prepared,
                provider_request_id="unsafe\nrequest-id",
            )

        response = _response(self.authorities, self.prepared)
        object.__setattr__(response, "_body", b"x" * response.response_byte_size)
        with self.assertRaises(InvalidOutputError):
            self.decode(response)

        one_byte = _response(self.authorities, self.prepared, body=b"x")
        object.__setattr__(one_byte, "response_byte_size", True)
        with self.assertRaises(InvalidOutputError):
            self.decode(one_byte)

        candidate = self.decode(_response(self.authorities, self.prepared))
        object.__setattr__(candidate, "provider_request_id", "unsafe\nrequest-id")
        with self.assertRaises(ValueError):
            candidate.validate_integrity()

    def test_prepared_source_tamper_fails_before_response_decode(self):
        object.__setattr__(self.prepared, "source_digests", ())
        with self.assertRaises(EndpointPolicyError):
            self.decode(
                _response(
                    self.authorities,
                    self.prepared,
                    body=b"RAW-CANARY-NOT-JSON",
                )
            )

    def test_response_correlation_fails_before_body_decode(self):
        other = make_w07_authorities(
            request_id=type(self.authorities.intent.request_id)(
                "30000000-0000-0000-0000-000000000088"
            )
        )
        mutations = (
            {"plan_id": other.planned.plan.plan_id},
            {"stage_id": other.planned.plan.stages[0].stage_id},
            {"operation_id": other.operation.operation_id},
            {"envelope_digest": other.planned.plan.plan_digest},
        )
        for values in mutations:
            with self.subTest(values=tuple(values)), self.assertRaises(
                EndpointPolicyError
            ):
                self.decode(
                    _response(
                        self.authorities,
                        self.prepared,
                        body=b"RAW-CANARY-NOT-JSON",
                        **values,
                    )
                )


class AdapterPurityTest(unittest.TestCase):
    def test_prepare_and_decode_do_no_file_env_sleep_or_network_io(self):
        authorities = make_w07_authorities()
        success = _fixture("w07_glm_success.json")

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("external side effect")

        with (
            patch("builtins.open", forbidden),
            patch("os.getenv", forbidden),
            patch.object(os, "environ", _ForbiddenEnvironment()),
            patch.object(socket, "socket", forbidden),
            patch.object(socket, "create_connection", forbidden),
            patch.object(socket, "getaddrinfo", forbidden),
            patch.object(time, "sleep", forbidden),
            patch("snapquiz.config.profiles.build_builtin_registry", forbidden),
        ):
            prepared = _prepared(authorities)
            response = _response(
                authorities,
                prepared,
                body=success,
            )
            candidate = OpenAIChatCompatibleAdapter.decode(
                planned=authorities.planned,
                invocation=authorities.invocation,
                prepared=prepared,
                response=response,
            )
        self.assertEqual(candidate.candidate_payload["answer"], "2")

    def test_fresh_import_has_no_optional_sdk_or_capture_backend(self):
        full_import_script = """
import builtins
import os
from pathlib import Path
import socket
import sys
import time

def forbidden(*args, **kwargs):
    raise AssertionError('external side effect')

class ForbiddenEnvironment:
    __getitem__ = forbidden
    __iter__ = forbidden
    __len__ = forbidden
    __contains__ = forbidden
    get = forbidden
    keys = forbidden
    items = forbidden
    values = forbidden

builtins.open = forbidden
Path.open = forbidden
Path.read_bytes = forbidden
Path.read_text = forbidden
os.getenv = forbidden
os.environ = ForbiddenEnvironment()
socket.socket = forbidden
socket.create_connection = forbidden
socket.getaddrinfo = forbidden
time.sleep = forbidden

import snapquiz.adapters.openai_chat_compatible
for name in ('openai', 'httpx', 'requests', 'zhipuai', 'zai', 'mss', 'Quartz'):
    assert name not in sys.modules, name
for name in ('snapquiz.llm.glm', 'snapquiz.llm.prompt', 'snapquiz.llm.parse'):
    assert name not in sys.modules, name
"""
        registry_script = """
import sys
import snapquiz.config.profiles as profiles

assert 'snapquiz.adapters.openai_chat_compatible' not in sys.modules

def forbidden(*args, **kwargs):
    raise AssertionError('Registry reread')

profiles.build_builtin_registry = forbidden
import snapquiz.adapters.openai_chat_compatible
"""
        for script in (full_import_script, registry_script):
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
