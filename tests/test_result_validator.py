import json
import math
import unittest
from dataclasses import FrozenInstanceError, asdict
from uuid import UUID

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import InvalidOutputError
from snapquiz.domain.solve import (
    ConfidenceKind,
    PipelineKind,
    SOLVE_RESULT_SCHEMA_VERSION,
    SolveProvenance,
    SolveStatus,
    StageRole,
    StageProvenance,
)
from snapquiz.result.validator import validate_solve_result


def provenance():
    stage = StageProvenance(
        stage_id=UUID("00000000-0000-0000-0000-000000000011"),
        role=StageRole.SOLVER,
        binding_id="zhipu-glm-4.6v-flash",
        provider_profile_id="zhipu-official",
        provider_profile_digest=Digest256("1" * 64),
        provider_id="zhipu",
        model_id="glm-4.6v-flash",
        component_id=None,
        component_version=None,
        adapter_family="openai_chat_compatible",
        adapter_version="v1",
        capabilities_ref="capabilities:zhipu-glm-4.6v-flash:v1",
        capabilities_digest=Digest256("2" * 64),
        attempts=1,
        network_calls=1,
        latency_ms=250,
    )
    return SolveProvenance(
        pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
        plan_id=UUID("00000000-0000-0000-0000-000000000010"),
        stages=(stage,),
    )


def answered_candidate(**overrides):
    value = {
        "schema_version": SOLVE_RESULT_SCHEMA_VERSION,
        "status": "answered",
        "question_summary": "2 + 2 等于多少？",
        "answer": "4",
        "rationale": "整数加法得到 4。",
        "confidence": None,
        "confidence_kind": "none",
        "confidence_calibration_ref": None,
        "warnings": [],
    }
    value.update(overrides)
    return value


class ResultValidatorTest(unittest.TestCase):
    def test_result_value_objects_are_runtime_final(self):
        result = validate_solve_result(answered_candidate(), provenance=provenance())
        for cls in (StageProvenance, SolveProvenance, type(result)):
            with self.subTest(cls=cls), self.assertRaises(TypeError):
                type(f"Evil{cls.__name__}", (cls,), {})

    def test_valid_answered_result_is_immutable_and_has_no_raw(self):
        result = validate_solve_result(answered_candidate(), provenance=provenance())
        self.assertEqual(result.status, SolveStatus.ANSWERED)
        self.assertEqual(result.answer, "4")
        self.assertFalse(hasattr(result, "raw"))
        self.assertNotIn("整数加法", repr(result))
        with self.assertRaises(TypeError):
            asdict(result)
        with self.assertRaises(FrozenInstanceError):
            result.answer = "5"

    def test_model_self_reported_confidence_is_explicit(self):
        result = validate_solve_result(
            answered_candidate(confidence=0.8, confidence_kind="model_self_reported"),
            provenance=provenance(),
        )
        self.assertEqual(result.confidence_kind, ConfidenceKind.MODEL_SELF_REPORTED)
        self.assertIsNone(result.confidence_calibration_ref)

    def test_model_candidate_cannot_self_promote_to_calibrated(self):
        candidates = (
            answered_candidate(confidence=0.8, confidence_kind="calibrated"),
            answered_candidate(
                confidence=0.8,
                confidence_kind="calibrated",
                confidence_calibration_ref="calibration:algebra:v1",
            ),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(InvalidOutputError):
                validate_solve_result(candidate, provenance=provenance())

    def test_provenance_rejects_invalid_stage_identity_and_topology(self):
        base_stage = provenance().stages[0]
        with self.assertRaises(ValueError):
            StageProvenance(
                **{
                    name: getattr(base_stage, name)
                    for name in base_stage.__dataclass_fields__
                    if name not in {"role", "model_id", "component_id", "component_version"}
                },
                role=StageRole.OCR,
                model_id="must-not-exist",
                component_id="ocr",
                component_version="v1",
            )
        with self.assertRaises(ValueError):
            SolveProvenance(
                pipeline_kind=PipelineKind.OCR_TEXT,
                plan_id=provenance().plan_id,
                stages=provenance().stages,
            )

    def test_null_confidence_cannot_claim_calibration(self):
        with self.assertRaises(InvalidOutputError):
            validate_solve_result(
                answered_candidate(confidence=None, confidence_kind="calibrated"),
                provenance=provenance(),
            )

    def test_non_answered_status_requires_null_answer(self):
        for status in ("insufficient_input", "refused", "unsupported_input"):
            candidate = answered_candidate(
                status=status,
                question_summary=None,
                answer=None,
                rationale="当前输入不足以可靠作答。",
            )
            with self.subTest(status=status):
                self.assertEqual(
                    validate_solve_result(candidate, provenance=provenance()).status.value,
                    status,
                )
            with self.subTest(status=status, invalid="answer"), self.assertRaises(
                InvalidOutputError
            ):
                validate_solve_result(
                    {**candidate, "answer": "不应存在"}, provenance=provenance()
                )

    def test_missing_extra_and_empty_objects_fail(self):
        candidates = (
            {},
            {key: value for key, value in answered_candidate().items() if key != "answer"},
            {**answered_candidate(), "raw": "must not cross boundary"},
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(InvalidOutputError):
                validate_solve_result(candidate, provenance=provenance())

    def test_wrong_types_are_not_coerced(self):
        candidates = (
            answered_candidate(answer=4),
            answered_candidate(confidence="0.8", confidence_kind="model_self_reported"),
            answered_candidate(confidence=True, confidence_kind="model_self_reported"),
            answered_candidate(warnings="none"),
            answered_candidate(warnings=[1]),
            answered_candidate(question_summary=None),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(InvalidOutputError):
                validate_solve_result(candidate, provenance=provenance())

    def test_non_plain_string_keys_are_rejected_before_comparison(self):
        class StringKey(str):
            pass

        candidate = answered_candidate()
        candidate[StringKey("answer")] = candidate.pop("answer")
        with self.assertRaises(InvalidOutputError) as raised:
            validate_solve_result(candidate, provenance=provenance())
        self.assertIsNone(raised.exception.__context__)

    def test_invalid_numbers_and_enum_values_fail(self):
        candidates = (
            answered_candidate(confidence=-0.1, confidence_kind="model_self_reported"),
            answered_candidate(confidence=1.1, confidence_kind="model_self_reported"),
            answered_candidate(confidence=math.nan, confidence_kind="model_self_reported"),
            answered_candidate(status="maybe"),
            answered_candidate(confidence_kind="probably"),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(InvalidOutputError):
                validate_solve_result(candidate, provenance=provenance())

    def test_invalid_enum_does_not_expose_raw_value_through_exception_chain(self):
        private_text = "model-output-that-must-not-reach-diagnostics"
        with self.assertRaises(InvalidOutputError) as raised:
            validate_solve_result(
                answered_candidate(status=private_text), provenance=provenance()
            )
        self.assertNotIn(private_text, str(raised.exception))
        self.assertIsNone(raised.exception.__context__)

    def test_stage_provenance_rejects_more_network_calls_than_attempts(self):
        base_stage = provenance().stages[0]
        values = {
            name: getattr(base_stage, name) for name in base_stage.__dataclass_fields__
        }
        values.update(attempts=0, network_calls=1)
        with self.assertRaises(ValueError):
            StageProvenance(**values)

    def test_length_limits_fail_closed(self):
        candidates = (
            answered_candidate(answer="x" * 4_001),
            answered_candidate(rationale="x" * 8_001),
            answered_candidate(warnings=["x" * 501]),
            answered_candidate(warnings=["warning"] * 21),
        )
        for candidate in candidates:
            with self.subTest(field_sizes={k: len(v) if hasattr(v, "__len__") else None for k, v in candidate.items()}), self.assertRaises(
                InvalidOutputError
            ):
                validate_solve_result(candidate, provenance=provenance())

    def test_unsafe_unicode_and_terminal_controls_fail_closed(self):
        unpaired_surrogate = json.loads('"\\ud800"')
        candidates = (
            answered_candidate(answer=unpaired_surrogate),
            answered_candidate(rationale="safe\x1b[31munsafe"),
            answered_candidate(warnings=["safe\x7funsafe"]),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                InvalidOutputError
            ) as raised:
                validate_solve_result(candidate, provenance=provenance())
            self.assertIsNone(raised.exception.__context__)

    def test_error_exposes_only_stable_safe_metadata(self):
        with self.assertRaises(InvalidOutputError) as raised:
            validate_solve_result(
                answered_candidate(answer=None),
                provenance=provenance(),
                provider_profile_id="zhipu-official",
            )
        self.assertEqual(raised.exception.code, "invalid_output")
        self.assertEqual(raised.exception.stage, "result_validation")
        self.assertEqual(raised.exception.provider_profile_id, "zhipu-official")
        self.assertNotIn("zhipu-official", raised.exception.safe_message)


if __name__ == "__main__":
    unittest.main()
