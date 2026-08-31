"""Post-capture request and per-stage invocation authorities.

These contracts freeze the exact pre-capture ``SolveIntent`` together with the
W05 plan generation and W06 validated capture.  They perform no I/O and grant
no permission to send data; W08 owns that separate one-shot authority.
"""
from __future__ import annotations

from uuid import UUID, uuid5

from snapquiz.capture.validation import ValidatedCapture
from snapquiz.domain._validation import require_digest, require_text, require_uuid, runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import ConfigError
from snapquiz.domain.intent import OutputTokenLimit, SolveIntent
from snapquiz.domain.plan import OutboundDataKind
from snapquiz.domain.solve import StageRole
from snapquiz.routing.planner import PlannedExecution

SOLVE_REQUEST_SCHEMA_VERSION = "snapquiz.solve-request.v1"
STAGE_INVOCATION_SCHEMA_VERSION = "snapquiz.stage-invocation.v1"

_SOLVE_REQUEST_AUTHORITY = object()
_STAGE_INVOCATION_AUTHORITY = object()
_INVOCATION_UUID_NAMESPACE = UUID("54f5ffb5-0aed-5d0d-887c-0139a2eb1bbf")


def _config_error(stage: str, message: str) -> ConfigError:
    return ConfigError(stage=stage, safe_message=message)


def _hint_digest(user_hint: str | None) -> Digest256:
    return digest256(
        "SolveRequestUserHint",
        SOLVE_REQUEST_SCHEMA_VERSION,
        {"present": user_hint is not None, "value": user_hint},
    )


def _invocation_id_for(
    *,
    request_id: UUID,
    plan_id: UUID,
    stage_id: UUID,
    solve_request_digest: Digest256,
) -> UUID:
    seed = digest256(
        "StageInvocationIdentifier",
        STAGE_INVOCATION_SCHEMA_VERSION,
        {
            "request_id": request_id,
            "plan_id": plan_id,
            "stage_id": stage_id,
            "solve_request_digest": solve_request_digest,
        },
    )
    return uuid5(_INVOCATION_UUID_NAMESPACE, str(seed))


def _validate_intent_plan_pair(
    planned: PlannedExecution,
    intent: SolveIntent,
) -> None:
    if type(planned) is not PlannedExecution:
        raise TypeError("planned must be PlannedExecution")
    if type(intent) is not SolveIntent:
        raise TypeError("intent must be SolveIntent")
    try:
        planned.validate_integrity()
        intent.validate_integrity()
    except (TypeError, ValueError, AttributeError) as error:
        raise _config_error(
            "solve_request",
            "请求意图或执行计划完整性校验失败。",
        ) from error

    plan = planned.plan
    profile = planned.resolved_pipeline.pipeline_profile
    if (
        planned.solve_intent_digest != intent.intent_digest
        or plan.request_id != intent.request_id
        or plan.pipeline_profile_id != intent.pipeline_profile_id
        or plan.capture_scope_kind is not intent.capture_scope_preference
        or plan.requested_result_schema_version
        != intent.requested_result_schema_version
        or plan.timeout_budget_ms > intent.timeout_budget_ms
    ):
        raise _config_error(
            "solve_request",
            "请求意图与冻结执行计划不匹配。",
        )
    expected_output_tokens = (
        profile.max_output_tokens
        if intent.max_output_tokens is OutputTokenLimit.PROFILE_DEFAULT
        else min(intent.max_output_tokens, profile.max_output_tokens)
    )
    if plan.max_output_tokens != expected_output_tokens:
        raise _config_error(
            "solve_request",
            "请求输出限制与冻结执行计划不匹配。",
        )

    operation = plan.stages[0].network_operations[0]
    expected_outbound = (
        (OutboundDataKind.IMAGE,)
        if intent.user_hint is None
        else (OutboundDataKind.IMAGE, OutboundDataKind.USER_HINT)
    )
    if operation.outbound_data != expected_outbound:
        raise _config_error(
            "solve_request",
            "请求数据种类与冻结执行计划不匹配。",
        )


def _validate_capture_pair(
    planned: PlannedExecution,
    validated_capture: ValidatedCapture,
) -> None:
    if type(validated_capture) is not ValidatedCapture:
        raise TypeError("validated_capture must be ValidatedCapture")
    try:
        validated_capture.validate_integrity()
    except (TypeError, ValueError, AttributeError) as error:
        raise _config_error(
            "solve_request",
            "已校验截图完整性校验失败。",
        ) from error
    plan = planned.plan
    if (
        validated_capture.request_id != plan.request_id
        or validated_capture.plan_id != plan.plan_id
        or validated_capture.plan_digest != plan.plan_digest
        or validated_capture.planned_execution_digest
        != planned.planned_execution_digest
        or validated_capture.image_preprocessing_policy_version
        != plan.image_preprocessing_policy_version
    ):
        raise _config_error(
            "solve_request",
            "已校验截图与冻结执行计划不匹配。",
        )
    # A successful read is the synchronous active-lease linearization point.
    # The local alias is intentionally discarded; release is not secure wipe.
    artifact = validated_capture.artifact
    if artifact.id != validated_capture.capture_id:
        raise _config_error(
            "solve_request",
            "已校验截图引用与元数据不匹配。",
        )
    del artifact


@runtime_final
class SolveRequest:
    """Immutable post-capture request; construction is factory-only."""

    __slots__ = (
        "schema_version",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "solve_intent_digest",
        "capture_id",
        "input_digest",
        "requested_result_schema_version",
        "locale",
        "user_hint_digest",
        "solve_request_digest",
        "_intent",
        "_input",
        "_user_hint",
    )

    def __init__(
        self,
        *,
        planned: PlannedExecution,
        intent: SolveIntent,
        validated_capture: ValidatedCapture,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _SOLVE_REQUEST_AUTHORITY:
            raise TypeError("SolveRequest can only be created by SolveRequestFactory")
        values = (
            ("schema_version", SOLVE_REQUEST_SCHEMA_VERSION),
            ("request_id", planned.plan.request_id),
            ("plan_id", planned.plan.plan_id),
            ("plan_digest", planned.plan.plan_digest),
            ("planned_execution_digest", planned.planned_execution_digest),
            ("solve_intent_digest", intent.intent_digest),
            ("capture_id", validated_capture.capture_id),
            ("input_digest", validated_capture.validation_digest),
            (
                "requested_result_schema_version",
                planned.plan.requested_result_schema_version,
            ),
            ("locale", intent.locale),
            ("user_hint_digest", _hint_digest(intent.user_hint)),
            ("_intent", intent),
            ("_input", validated_capture),
            ("_user_hint", intent.user_hint),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "solve_request_digest",
            digest256(
                "SolveRequest",
                SOLVE_REQUEST_SCHEMA_VERSION,
                self._digest_payload(),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SolveRequest is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "SolveRequest":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "SolveRequest("
            f"request_id={self.request_id!r}, plan_id={self.plan_id!r}, "
            f"capture_id={self.capture_id!r}, "
            f"has_user_hint={self._user_hint is not None!r})"
        )

    @property
    def input(self) -> ValidatedCapture:
        return self._input

    @property
    def user_hint(self) -> str | None:
        return self._user_hint

    def _digest_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "planned_execution_digest": self.planned_execution_digest,
            "solve_intent_digest": self.solve_intent_digest,
            "capture_id": self.capture_id,
            "input_digest": self.input_digest,
            "requested_result_schema_version": (
                self.requested_result_schema_version
            ),
            "locale": self.locale,
            "user_hint_present": self._user_hint is not None,
            "user_hint_digest": self.user_hint_digest,
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "SolveRequest",
            SOLVE_REQUEST_SCHEMA_VERSION,
            self._digest_payload(),
        )

    def validate_integrity(self) -> None:
        require_text(self.schema_version, "schema_version")
        if self.schema_version != SOLVE_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported SolveRequest schema_version")
        for name in ("request_id", "plan_id", "capture_id"):
            require_uuid(getattr(self, name), name)
        for name in (
            "plan_digest",
            "planned_execution_digest",
            "solve_intent_digest",
            "input_digest",
            "user_hint_digest",
            "solve_request_digest",
        ):
            require_digest(getattr(self, name), name)
        require_text(self.locale, "locale", max_length=63)
        require_text(
            self.requested_result_schema_version,
            "requested_result_schema_version",
        )
        if type(self._intent) is not SolveIntent:
            raise ValueError("SolveRequest intent authority changed")
        self._intent.validate_integrity()
        if type(self._input) is not ValidatedCapture:
            raise ValueError("SolveRequest input authority changed")
        self._input.validate_integrity()
        if (
            self._input.capture_id != self.capture_id
            or self._input.validation_digest != self.input_digest
            or self._intent.intent_digest != self.solve_intent_digest
            or self._intent.request_id != self.request_id
            or self._intent.locale != self.locale
            or self._intent.user_hint != self._user_hint
            or _hint_digest(self._user_hint) != self.user_hint_digest
            or self.recompute_digest() != self.solve_request_digest
        ):
            raise ValueError("SolveRequest integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "request_id": str(self.request_id),
            "plan_id": str(self.plan_id),
            "capture_id": str(self.capture_id),
            "has_user_hint": self._user_hint is not None,
        }


@runtime_final
class SolveRequestFactory:
    __slots__ = ()

    @staticmethod
    def create(
        *,
        planned: PlannedExecution,
        intent: SolveIntent,
        validated_capture: ValidatedCapture,
    ) -> SolveRequest:
        _validate_intent_plan_pair(planned, intent)
        _validate_capture_pair(planned, validated_capture)
        return SolveRequest(
            planned=planned,
            intent=intent,
            validated_capture=validated_capture,
            _authority=_SOLVE_REQUEST_AUTHORITY,
        )


@runtime_final
class StageInvocation:
    """One exact stage input derived from one immutable SolveRequest."""

    __slots__ = (
        "invocation_id",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "stage_id",
        "solve_request_digest",
        "input_digest",
        "invocation_digest",
        "_solve_request",
        "_input",
    )

    def __init__(
        self,
        *,
        planned: PlannedExecution,
        solve_request: SolveRequest,
        stage_id: UUID,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _STAGE_INVOCATION_AUTHORITY:
            raise TypeError(
                "StageInvocation can only be created by StageInvocationFactory"
            )
        values = (
            (
                "invocation_id",
                _invocation_id_for(
                    request_id=solve_request.request_id,
                    plan_id=solve_request.plan_id,
                    stage_id=stage_id,
                    solve_request_digest=solve_request.solve_request_digest,
                ),
            ),
            ("request_id", solve_request.request_id),
            ("plan_id", solve_request.plan_id),
            ("plan_digest", solve_request.plan_digest),
            ("planned_execution_digest", planned.planned_execution_digest),
            ("stage_id", stage_id),
            ("solve_request_digest", solve_request.solve_request_digest),
            ("input_digest", solve_request.input_digest),
            ("_solve_request", solve_request),
            ("_input", solve_request.input),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "invocation_digest",
            digest256(
                "StageInvocation",
                STAGE_INVOCATION_SCHEMA_VERSION,
                self._digest_payload(),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("StageInvocation is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "StageInvocation":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "StageInvocation("
            f"invocation_id={self.invocation_id!r}, "
            f"plan_id={self.plan_id!r}, stage_id={self.stage_id!r})"
        )

    @property
    def input(self) -> ValidatedCapture:
        return self._input

    @property
    def locale(self) -> str:
        return self._solve_request.locale

    @property
    def user_hint(self) -> str | None:
        return self._solve_request.user_hint

    def _digest_payload(self) -> dict[str, object]:
        return {
            "invocation_id": self.invocation_id,
            "request_id": self.request_id,
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "planned_execution_digest": self.planned_execution_digest,
            "stage_id": self.stage_id,
            "solve_request_digest": self.solve_request_digest,
            "input_digest": self.input_digest,
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "StageInvocation",
            STAGE_INVOCATION_SCHEMA_VERSION,
            self._digest_payload(),
        )

    def validate_integrity(self) -> None:
        for name in ("invocation_id", "request_id", "plan_id", "stage_id"):
            require_uuid(getattr(self, name), name)
        for name in (
            "plan_digest",
            "planned_execution_digest",
            "solve_request_digest",
            "input_digest",
            "invocation_digest",
        ):
            require_digest(getattr(self, name), name)
        if type(self._solve_request) is not SolveRequest:
            raise ValueError("StageInvocation request authority changed")
        self._solve_request.validate_integrity()
        if (
            self.invocation_id
            != _invocation_id_for(
                request_id=self.request_id,
                plan_id=self.plan_id,
                stage_id=self.stage_id,
                solve_request_digest=self.solve_request_digest,
            )
            or self._input is not self._solve_request.input
            or self._input.validation_digest != self.input_digest
            or self._solve_request.solve_request_digest
            != self.solve_request_digest
            or self.recompute_digest() != self.invocation_digest
        ):
            raise ValueError("StageInvocation integrity mismatch")

    def safe_metadata(self) -> dict[str, str]:
        return {
            "invocation_id": str(self.invocation_id),
            "request_id": str(self.request_id),
            "plan_id": str(self.plan_id),
            "stage_id": str(self.stage_id),
        }


@runtime_final
class StageInvocationFactory:
    __slots__ = ()

    @staticmethod
    def create(
        *,
        planned: PlannedExecution,
        solve_request: SolveRequest,
        stage_id: UUID,
    ) -> StageInvocation:
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(solve_request) is not SolveRequest:
            raise TypeError("solve_request must be SolveRequest")
        require_uuid(stage_id, "stage_id")
        try:
            planned.validate_integrity()
            solve_request.validate_integrity()
        except (TypeError, ValueError, AttributeError) as error:
            raise _config_error(
                "stage_invocation",
                "执行请求完整性校验失败。",
            ) from error
        plan = planned.plan
        stage = next((item for item in plan.stages if item.stage_id == stage_id), None)
        if (
            stage is None
            or stage.role is not StageRole.SOLVER
            or solve_request.request_id != plan.request_id
            or solve_request.plan_id != plan.plan_id
            or solve_request.plan_digest != plan.plan_digest
            or solve_request.planned_execution_digest
            != planned.planned_execution_digest
            or solve_request.solve_intent_digest != planned.solve_intent_digest
            or solve_request.input.plan_id != plan.plan_id
        ):
            raise _config_error(
                "stage_invocation",
                "执行请求与冻结阶段不匹配。",
            )
        return StageInvocation(
            planned=planned,
            solve_request=solve_request,
            stage_id=stage_id,
            _authority=_STAGE_INVOCATION_AUTHORITY,
        )


__all__ = [
    "SOLVE_REQUEST_SCHEMA_VERSION",
    "STAGE_INVOCATION_SCHEMA_VERSION",
    "SolveRequest",
    "SolveRequestFactory",
    "StageInvocation",
    "StageInvocationFactory",
]
