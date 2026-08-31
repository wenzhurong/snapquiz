"""Strict, non-coercing validation for untrusted model result candidates."""
from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from snapquiz.domain.adapter import AnswerCandidateResult
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import InvalidOutputError
from snapquiz.domain.solve import (
    ConfidenceKind,
    MAX_WARNINGS,
    SolveProvenance,
    SolveResult,
    SolveStatus,
)

RESULT_VALIDATOR_VERSION = "snapquiz.result-validator.v1"

_EXPECTED_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "question_summary",
        "answer",
        "rationale",
        "confidence",
        "confidence_kind",
        "confidence_calibration_ref",
        "warnings",
    }
)


def _fail(provider_profile_id: Optional[str]) -> InvalidOutputError:
    return InvalidOutputError(
        stage="result_validation", provider_profile_id=provider_profile_id
    )


def _nullable_string(value: Any, provider_profile_id: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if type(value) is not str:
        raise _fail(provider_profile_id)
    return value


def validate_solve_result(
    candidate: dict[str, Any],
    *,
    provenance: SolveProvenance,
    provider_profile_id: Optional[str] = None,
) -> SolveResult:
    """Validate a model candidate and construct the only trusted result type.

    No value is coerced.  Provenance is supplied by the local executor and is
    intentionally not accepted from model output.
    """

    if type(candidate) is not dict:
        raise _fail(provider_profile_id)
    if not isinstance(provenance, SolveProvenance):
        raise TypeError("provenance must be SolveProvenance")
    if len(candidate) != len(_EXPECTED_FIELDS):
        raise _fail(provider_profile_id)
    candidate_keys = tuple(candidate.keys())
    if any(type(key) is not str for key in candidate_keys):
        raise _fail(provider_profile_id)
    if frozenset(candidate_keys) != _EXPECTED_FIELDS:
        raise _fail(provider_profile_id)

    try:
        schema_version = candidate["schema_version"]
        status_raw = candidate["status"]
        rationale = candidate["rationale"]
        confidence_raw = candidate["confidence"]
        confidence_kind_raw = candidate["confidence_kind"]
        warnings_raw = candidate["warnings"]

        if type(schema_version) is not str:
            raise _fail(provider_profile_id)
        if type(status_raw) is not str or type(confidence_kind_raw) is not str:
            raise _fail(provider_profile_id)
        if status_raw not in {status.value for status in SolveStatus}:
            raise _fail(provider_profile_id)
        if confidence_kind_raw not in {
            ConfidenceKind.NONE.value,
            ConfidenceKind.MODEL_SELF_REPORTED.value,
            ConfidenceKind.CALIBRATED.value,
        }:
            raise _fail(provider_profile_id)
        # A model may self-report confidence, but it cannot assert that a score
        # was calibrated.  A future local calibration service must construct
        # that trusted state from pinned evidence outside this candidate path.
        if confidence_kind_raw == ConfidenceKind.CALIBRATED.value:
            raise _fail(provider_profile_id)
        if type(rationale) is not str:
            raise _fail(provider_profile_id)
        if confidence_raw is not None and type(confidence_raw) not in (int, float):
            raise _fail(provider_profile_id)
        if (
            type(warnings_raw) is not list
            or len(warnings_raw) > MAX_WARNINGS
            or not all(type(warning) is str for warning in warnings_raw)
        ):
            raise _fail(provider_profile_id)

        return SolveResult(
            schema_version=schema_version,
            status=SolveStatus(status_raw),
            question_summary=_nullable_string(
                candidate["question_summary"], provider_profile_id
            ),
            answer=_nullable_string(candidate["answer"], provider_profile_id),
            rationale=rationale,
            confidence=confidence_raw,
            confidence_kind=ConfidenceKind(confidence_kind_raw),
            confidence_calibration_ref=_nullable_string(
                candidate["confidence_calibration_ref"], provider_profile_id
            ),
            warnings=tuple(warnings_raw),
            provenance=provenance,
        )
    except InvalidOutputError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError):
        # Invalid enum values may include raw model text in their ValueError.
        # Suppress that context so the typed boundary exposes only safe metadata.
        pass
    raise _fail(provider_profile_id)


def validate_answer_candidate(
    candidate: AnswerCandidateResult,
    *,
    provenance: SolveProvenance,
    request_id: UUID,
    plan_id: UUID,
    plan_digest: Digest256,
    stage_id: UUID,
    operation_id: UUID,
    invocation_digest: Digest256,
    request_envelope_digest: Digest256,
    provider_profile_id: Optional[str] = None,
) -> SolveResult:
    """Validate correlation before converting an Adapter candidate.

    The explicit expected bindings must come from the active executor context;
    model output and the candidate object cannot select their own provenance.
    """

    if type(candidate) is not AnswerCandidateResult:
        raise TypeError("candidate must be AnswerCandidateResult")
    if type(provenance) is not SolveProvenance:
        raise TypeError("provenance must be SolveProvenance")
    try:
        candidate.validate_binding(
            request_id=request_id,
            plan_id=plan_id,
            plan_digest=plan_digest,
            stage_id=stage_id,
            operation_id=operation_id,
            invocation_digest=invocation_digest,
            request_envelope_digest=request_envelope_digest,
        )
        payload = candidate.candidate_payload
        if (
            payload is None
            or candidate.refusal is not None
            or provenance.plan_id != plan_id
            or tuple(stage.stage_id for stage in provenance.stages) != (stage_id,)
        ):
            raise ValueError("candidate correlation mismatch")
    except (TypeError, ValueError, AttributeError):
        raise _fail(provider_profile_id) from None
    return validate_solve_result(
        payload,
        provenance=provenance,
        provider_profile_id=provider_profile_id,
    )
