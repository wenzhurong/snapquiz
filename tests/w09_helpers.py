"""Deterministic offline helpers for W09 runtime-authority tests."""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

from snapquiz.adapters.openai_chat_compatible import OpenAIChatCompatibleAdapter
from snapquiz.capture.policy import CaptureAuthorizationLedger, CapturePolicy
from snapquiz.capture.validation import CaptureArtifactFactory, InputValidator
from snapquiz.config.profiles import (
    GLM_BINDING_ID,
    GLM_PIPELINE_PROFILE_ID,
    build_builtin_registry,
)
from snapquiz.domain.capture import CaptureConstraints, CaptureRect, CaptureScopeKind
from snapquiz.domain.intent import (
    SOLVE_INTENT_SCHEMA_VERSION,
    OutputTokenLimit,
    SolveIntent,
)
from snapquiz.domain.solve import SOLVE_RESULT_SCHEMA_VERSION
from snapquiz.pipelines.contracts import SolveRequestFactory, StageInvocationFactory
from snapquiz.privacy.consent import ConsentLedger
from snapquiz.routing.planner import RoutePlanner
from snapquiz.runtime.authority import RegistryPolicyAuthorityLedger
from snapquiz.runtime.clock import ClockSample, RuntimeClock
from snapquiz.runtime.context import (
    CallContextLedger,
    RuntimeCallFactory,
    _TEST_CLOCK_AUTHORITY,
)

from tests.w06_helpers import (
    ALL_UNKNOWN_CONFIRMATIONS,
    CAPTURE_ID,
    GRANT_ID,
    NOW,
    granted_permission,
    selected_scope,
    topology,
)
from tests.w07_helpers import canonical_png_bytes


class ManualRuntimeClock(RuntimeClock):
    """A zero-I/O clock whose samples are serialized by CallContextLedger."""

    __slots__ = ("wall_time", "monotonic_ns", "sampling_interval_ns")

    def __init__(
        self,
        *,
        wall_time: datetime = NOW,
        monotonic_ns: int = 10_000_000_000,
        sampling_interval_ns: int = 0,
    ) -> None:
        self.wall_time = wall_time
        self.monotonic_ns = monotonic_ns
        self.sampling_interval_ns = sampling_interval_ns

    def sample(self) -> ClockSample:
        return self._make_sample(
            wall_time=self.wall_time,
            monotonic_before_ns=self.monotonic_ns,
            monotonic_after_ns=(
                self.monotonic_ns + self.sampling_interval_ns
            ),
        )

    def advance(
        self,
        *,
        milliseconds: int = 0,
        wall_delta: timedelta | None = None,
    ) -> None:
        self.monotonic_ns += milliseconds * 1_000_000
        self.wall_time += (
            timedelta(milliseconds=milliseconds)
            if wall_delta is None
            else wall_delta
        )


def make_w09_runtime(
    *,
    request_id: UUID = UUID("30000000-0000-0000-0000-000000000001"),
    one_shot_consent: bool = False,
    grant_expires_at: datetime | None = NOW + timedelta(hours=1),
) -> SimpleNamespace:
    events: list[str] = []
    registry = build_builtin_registry()
    initial_topology = topology()
    intent = SolveIntent(
        schema_version=SOLVE_INTENT_SCHEMA_VERSION,
        request_id=request_id,
        pipeline_profile_id=GLM_PIPELINE_PROFILE_ID,
        capture_scope_preference=CaptureScopeKind.SELECTED_REGION,
        locale="zh-Hans-CN",
        timeout_budget_ms=30_000,
        max_output_tokens=OutputTokenLimit.PROFILE_DEFAULT,
        requested_result_schema_version=SOLVE_RESULT_SCHEMA_VERSION,
    )
    planned = RoutePlanner().plan(
        intent=intent,
        registry=registry,
        trusted_capture_constraints=CaptureConstraints(
            allowed_display_ids=("display-1",),
            display_topology_revision=initial_topology.topology_revision,
            max_width_px=2_000,
            max_height_px=1_500,
            max_pixels=3_000_000,
            max_bytes=5_000_000,
            allow_full_screen=True,
        ),
        now=NOW,
    )
    events.append("plan")
    scope = selected_scope(
        initial_topology,
        rect=CaptureRect(left=20, top=30, width=4, height=2),
    )
    consent_ledger = ConsentLedger()
    grant = consent_ledger.issue_for_plan(
        planned=planned,
        binding_id=GLM_BINDING_ID,
        grant_id=GRANT_ID,
        request_id=planned.plan.request_id,
        capture_scope_fingerprint=scope.fingerprint,
        issued_at=NOW,
        expires_at=grant_expires_at,
        one_shot=one_shot_consent,
        confirmed_unknown_policies=ALL_UNKNOWN_CONFIRMATIONS,
    )
    events.append("consent_grant")
    authority_ledger = RegistryPolicyAuthorityLedger(registry)
    clock = ManualRuntimeClock()
    context_ledger = CallContextLedger._for_testing(
        authority_ledger=authority_ledger,
        clock=clock,
        _authority=_TEST_CLOCK_AUTHORITY,
    )
    authorization, context, cancellation_source = (
        RuntimeCallFactory.authorize_and_start(
            planned=planned,
            consent_ledger=consent_ledger,
            consent_grant_ids=(grant.grant_id,),
            authority_ledger=authority_ledger,
            context_ledger=context_ledger,
        )
    )
    events.append("call_context")

    capture_ledger = CaptureAuthorizationLedger()
    capture_authorization = CapturePolicy().authorize(
        planned=planned,
        privacy_authorization=authorization,
        consent_ledger=consent_ledger,
        permission_observation=granted_permission(),
        topology=initial_topology,
        selected_scope=scope,
        capture_id=CAPTURE_ID,
        capture_ledger=capture_ledger,
        now=NOW,
    )
    events.append("capture_authorization")
    pre_capture_time = NOW + timedelta(seconds=1)
    consumed_capture = CapturePolicy().prepare_capture(
        planned=planned,
        privacy_authorization=authorization,
        consent_ledger=consent_ledger,
        authorization=capture_authorization,
        capture_ledger=capture_ledger,
        permission_observation=granted_permission(
            observed_at=pre_capture_time
        ),
        topology=topology(observed_at=pre_capture_time),
        now=pre_capture_time,
    )
    events.append("capture_consumed")
    captured_at = NOW + timedelta(seconds=2)
    artifact = CaptureArtifactFactory.create(
        consumed=consumed_capture,
        capture_ledger=capture_ledger,
        data=canonical_png_bytes(),
        mime_type="image/png",
        width_px=4,
        height_px=2,
        captured_at=captured_at,
    )
    events.append("capture_artifact")
    post_capture_time = NOW + timedelta(seconds=3)
    validated = InputValidator.validate(
        planned=planned,
        privacy_authorization=authorization,
        consent_ledger=consent_ledger,
        consumed=consumed_capture,
        capture_ledger=capture_ledger,
        artifact=artifact,
        permission_observation=granted_permission(
            observed_at=post_capture_time
        ),
        topology=topology(observed_at=post_capture_time),
        now=post_capture_time,
    )
    events.append("capture_validated")
    solve_request = SolveRequestFactory.create(
        planned=planned,
        intent=intent,
        validated_capture=validated,
    )
    stage = planned.plan.stages[0]
    invocation = StageInvocationFactory.create(
        planned=planned,
        solve_request=solve_request,
        stage_id=stage.stage_id,
    )
    events.append("stage_invocation")
    operation = stage.network_operations[0]
    prepared = OpenAIChatCompatibleAdapter.prepare(
        planned=planned,
        invocation=invocation,
        operation_id=operation.operation_id,
    )
    events.append("prepared_outbound")
    return SimpleNamespace(
        intent=intent,
        planned=planned,
        privacy=authorization,
        consent_ledger=consent_ledger,
        capture_ledger=capture_ledger,
        validated=validated,
        solve_request=solve_request,
        invocation=invocation,
        operation=operation,
        artifact=artifact,
        prepared=prepared,
        registry=registry,
        authority_ledger=authority_ledger,
        clock=clock,
        context_ledger=context_ledger,
        runtime_authorization=authorization,
        grant=grant,
        call_context=context,
        cancellation_source=cancellation_source,
        events=tuple(events),
    )


__all__ = ["ManualRuntimeClock", "make_w09_runtime"]
