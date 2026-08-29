"""Immutable result and provenance contracts for the v3 pipeline."""
from __future__ import annotations

import math
from dataclasses import FrozenInstanceError, dataclass
from enum import Enum
from typing import Optional
from uuid import UUID

from snapquiz.domain._validation import runtime_final
from snapquiz.domain.digest import Digest256

SOLVE_RESULT_SCHEMA_VERSION = "snapquiz.solve-result.v2"
MAX_QUESTION_SUMMARY_CHARS = 2_000
MAX_ANSWER_CHARS = 4_000
MAX_RATIONALE_CHARS = 8_000
MAX_WARNING_CHARS = 500
MAX_WARNINGS = 20


class PipelineKind(str, Enum):
    DIRECT_MULTIMODAL = "direct_multimodal"
    OCR_TEXT = "ocr_text"


class SolveStatus(str, Enum):
    ANSWERED = "answered"
    INSUFFICIENT_INPUT = "insufficient_input"
    REFUSED = "refused"
    UNSUPPORTED_INPUT = "unsupported_input"


class StageRole(str, Enum):
    SOLVER = "solver"
    OCR = "ocr"
    TEXT_SOLVER = "text_solver"


class ConfidenceKind(str, Enum):
    MODEL_SELF_REPORTED = "model_self_reported"
    CALIBRATED = "calibrated"
    NONE = "none"


def _optional_non_empty_text(value: Optional[str], name: str, limit: int) -> None:
    if value is None:
        return
    if (
        type(value) is not str
        or len(value) > limit
        or not value.strip()
        or _contains_unsafe_codepoint(value)
    ):
        raise ValueError(f"{name} must be null or a non-empty string <= {limit} chars")


def _required_non_empty_text(value: str, name: str, limit: int) -> None:
    if (
        type(value) is not str
        or len(value) > limit
        or not value.strip()
        or _contains_unsafe_codepoint(value)
    ):
        raise ValueError(f"{name} must be a non-empty string <= {limit} chars")


def _contains_unsafe_codepoint(value: str) -> bool:
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            return True
        if (codepoint < 0x20 and char not in "\t\n\r") or 0x7F <= codepoint <= 0x9F:
            return True
    return False


@runtime_final
@dataclass(frozen=True, slots=True)
class UsageSummary:
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{name} must be a non-negative integer or null")


@runtime_final
@dataclass(frozen=True, slots=True)
class StageProvenance:
    stage_id: UUID
    role: StageRole
    binding_id: str
    provider_profile_id: str
    provider_profile_digest: Digest256
    provider_id: str
    model_id: Optional[str]
    component_id: Optional[str]
    component_version: Optional[str]
    adapter_family: str
    adapter_version: str
    capabilities_ref: str
    capabilities_digest: Digest256
    attempts: int
    network_calls: int
    latency_ms: int
    usage: Optional[UsageSummary] = None

    def __post_init__(self) -> None:
        if type(self.stage_id) is not UUID:
            raise ValueError("stage_id must be a UUID")
        if not isinstance(self.role, StageRole):
            raise ValueError("role must be StageRole")
        for name in (
            "binding_id",
            "provider_profile_id",
            "provider_id",
            "adapter_family",
            "adapter_version",
            "capabilities_ref",
        ):
            _required_non_empty_text(getattr(self, name), name, 256)
        if type(self.provider_profile_digest) is not Digest256:
            raise ValueError("provider_profile_digest must be Digest256")
        if type(self.capabilities_digest) is not Digest256:
            raise ValueError("capabilities_digest must be Digest256")
        _optional_non_empty_text(self.model_id, "model_id", 256)
        _optional_non_empty_text(self.component_id, "component_id", 256)
        _optional_non_empty_text(self.component_version, "component_version", 256)
        if self.role in (StageRole.SOLVER, StageRole.TEXT_SOLVER):
            if self.model_id is None:
                raise ValueError("solver stages require model_id")
            if self.component_id is not None or self.component_version is not None:
                raise ValueError("solver stages must not carry component identity")
        elif self.role is StageRole.OCR:
            if self.model_id is not None:
                raise ValueError("ocr stages must not carry model_id")
            if self.component_id is None or self.component_version is None:
                raise ValueError("ocr stages require component_id and component_version")
        for name in ("attempts", "network_calls", "latency_ms"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.network_calls > self.attempts:
            raise ValueError("network_calls must not exceed attempts")
        if self.usage is not None and type(self.usage) is not UsageSummary:
            raise ValueError("usage must be UsageSummary or null")


@runtime_final
@dataclass(frozen=True, slots=True)
class SolveProvenance:
    pipeline_kind: PipelineKind
    plan_id: UUID
    stages: tuple[StageProvenance, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.pipeline_kind, PipelineKind):
            raise ValueError("pipeline_kind must be PipelineKind")
        if type(self.plan_id) is not UUID:
            raise ValueError("plan_id must be a UUID")
        if type(self.stages) is not tuple or not self.stages:
            raise ValueError("stages must be a non-empty tuple")
        if not all(type(stage) is StageProvenance for stage in self.stages):
            raise ValueError("stages must contain only StageProvenance values")
        stage_ids = tuple(stage.stage_id for stage in self.stages)
        if len(set(stage_ids)) != len(stage_ids):
            raise ValueError("stage ids must be unique")
        roles = tuple(stage.role for stage in self.stages)
        if self.pipeline_kind is PipelineKind.DIRECT_MULTIMODAL:
            if roles != (StageRole.SOLVER,):
                raise ValueError("direct_multimodal requires exactly one solver stage")
        elif roles != (StageRole.OCR, StageRole.TEXT_SOLVER):
            raise ValueError("ocr_text requires ordered ocr and text_solver stages")


@runtime_final
class SolveResult:
    """Trusted result whose user content cannot be exported by dataclasses.asdict."""

    __slots__ = (
        "schema_version",
        "status",
        "question_summary",
        "answer",
        "rationale",
        "confidence",
        "confidence_kind",
        "confidence_calibration_ref",
        "warnings",
        "provenance",
    )

    schema_version: str
    status: SolveStatus
    question_summary: Optional[str]
    answer: Optional[str]
    rationale: str
    confidence: Optional[float]
    confidence_kind: ConfidenceKind
    confidence_calibration_ref: Optional[str]
    warnings: tuple[str, ...]
    provenance: SolveProvenance

    def __init__(
        self,
        *,
        schema_version: str,
        status: SolveStatus,
        question_summary: Optional[str],
        answer: Optional[str],
        rationale: str,
        confidence: Optional[float],
        confidence_kind: ConfidenceKind,
        confidence_calibration_ref: Optional[str],
        warnings: tuple[str, ...],
        provenance: SolveProvenance,
    ) -> None:
        if schema_version != SOLVE_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported SolveResult schema_version")
        if not isinstance(status, SolveStatus):
            raise ValueError("status must be SolveStatus")
        if not isinstance(confidence_kind, ConfidenceKind):
            raise ValueError("confidence_kind must be ConfidenceKind")
        _optional_non_empty_text(
            question_summary, "question_summary", MAX_QUESTION_SUMMARY_CHARS
        )
        _optional_non_empty_text(answer, "answer", MAX_ANSWER_CHARS)
        _required_non_empty_text(rationale, "rationale", MAX_RATIONALE_CHARS)

        if status is SolveStatus.ANSWERED:
            if question_summary is None or answer is None:
                raise ValueError("answered requires question_summary and answer")
        elif answer is not None:
            raise ValueError("non-answered status requires answer=null")

        if confidence is None:
            if confidence_kind is not ConfidenceKind.NONE:
                raise ValueError("null confidence requires confidence_kind=none")
            if confidence_calibration_ref is not None:
                raise ValueError("null confidence requires no calibration ref")
        else:
            if type(confidence) not in (int, float) or not math.isfinite(confidence):
                raise ValueError("confidence must be a finite number or null")
            if not 0 <= confidence <= 1:
                raise ValueError("confidence must be between 0 and 1")
            if confidence_kind is ConfidenceKind.NONE:
                raise ValueError("numeric confidence requires a confidence kind")
            if confidence_kind is ConfidenceKind.CALIBRATED:
                _required_non_empty_text(
                    confidence_calibration_ref,
                    "confidence_calibration_ref",
                    256,
                )
            elif confidence_calibration_ref is not None:
                raise ValueError("model self-reported confidence cannot carry calibration ref")

        if type(warnings) is not tuple or len(warnings) > MAX_WARNINGS:
            raise ValueError(f"warnings must be a tuple with at most {MAX_WARNINGS} items")
        for warning in warnings:
            _required_non_empty_text(warning, "warning", MAX_WARNING_CHARS)
        if type(provenance) is not SolveProvenance:
            raise ValueError("provenance must be SolveProvenance")

        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "question_summary", question_summary)
        object.__setattr__(self, "answer", answer)
        object.__setattr__(self, "rationale", rationale)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "confidence_kind", confidence_kind)
        object.__setattr__(
            self, "confidence_calibration_ref", confidence_calibration_ref
        )
        object.__setattr__(self, "warnings", warnings)
        object.__setattr__(self, "provenance", provenance)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise FrozenInstanceError("SolveResult is immutable")

    def __repr__(self) -> str:
        return (
            "SolveResult("
            f"schema_version={self.schema_version!r}, status={self.status!r}, "
            f"confidence_kind={self.confidence_kind!r}, "
            f"pipeline_kind={self.provenance.pipeline_kind!r}, "
            f"plan_id={self.provenance.plan_id!r})"
        )
