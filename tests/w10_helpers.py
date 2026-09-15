"""Deterministic, fully offline fixtures for the W10 multimodal executor."""
from __future__ import annotations

import hashlib
from contextlib import ExitStack, contextmanager
from datetime import timedelta
from types import SimpleNamespace
from typing import Callable
from unittest import mock
from uuid import UUID

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.adapters.openai_chat_compatible import OpenAIChatCompatibleAdapter
from snapquiz.capture.policy import CapturePolicy
from snapquiz.capture.validation import CaptureArtifactFactory, InputValidator
from snapquiz.config.profiles import (
    GLM_ADAPTER_FAMILY,
    GLM_ADAPTER_VERSION,
    GLM_BINDING_ID,
    GLM_PIPELINE_PROFILE_ID,
    build_builtin_registry,
)
from snapquiz.core.permissions import ScreenPermissionState
from snapquiz.domain.adapter import AnswerCandidateResult, TransportResponse
from snapquiz.domain.capture import CaptureConstraints, CaptureRect, CaptureScopeKind
from snapquiz.domain.digest import canonical_json_bytes
from snapquiz.domain.intent import (
    SOLVE_INTENT_SCHEMA_VERSION,
    OutputTokenLimit,
    SolveIntent,
)
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.domain.solve import SOLVE_RESULT_SCHEMA_VERSION
from snapquiz.pipelines.contracts import (
    SolveRequestFactory,
    StageInvocation,
    StageInvocationFactory,
)
import snapquiz.pipelines.multimodal as multimodal_module
from snapquiz.pipelines.multimodal import (
    CapturedFrame,
    CaptureObservation,
    MultimodalCaptureSource,
    MultimodalCancellation,
    MultimodalPipelineExecutor,
    RemoteTransport,
    UnwiredRemoteTransport,
    _TEST_PIPELINE_AUTHORITY,
)
from snapquiz.privacy.consent import ConsentLedger
from snapquiz.privacy.egress import (
    EgressGate,
    EgressPreview,
    EgressPreviewController,
    EgressPreviewDecision,
)
from snapquiz.routing.planner import PlannedExecution, RoutePlanner
from snapquiz.runtime.authority import RegistryPolicyAuthorityLedger
from snapquiz.runtime.attempt import AttemptGate
from snapquiz.runtime.context import (
    CallContextLedger,
    RuntimeCallFactory,
    _TEST_CLOCK_AUTHORITY,
)
from snapquiz.transport import _exact_transport as exact_transport
from snapquiz.transport.http import (
    PreparedResolverAttempt,
    coordinate_resolver_attempt,
    issue_resolver_cleanup_ticket,
)
from snapquiz.transport.session import SendSessionFactory

from tests.test_w09_exact_transport import (
    _NumericEdge,
    _NumericFactory,
    _TlsFactory,
    _clean_tls_environment,
    _poison_network,
)
from tests.test_w09_resolver_coordinator import (
    DNS_START_ID,
    LIFECYCLE_ID,
    READY_PUBLICATION_ID,
    TRANSPORT_CLAIM_ID,
    VALID_SECRET,
    _make_authorized_credential,
    _components,
    _poison_real_io,
)
from tests.w06_helpers import (
    ALL_UNKNOWN_CONFIRMATIONS,
    CAPTURE_ID,
    GRANT_ID,
    NOW,
    permission_observation,
    selected_scope,
    topology,
)
from tests.w07_helpers import canonical_png_bytes
from tests.w09_helpers import ManualRuntimeClock


PREVIEW_DECISION_ID = UUID("81000000-0000-0000-0000-000000000001")

_ANSWER_PAYLOAD = {
    "schema_version": SOLVE_RESULT_SCHEMA_VERSION,
    "status": "answered",
    "question_summary": "1 + 1",
    "answer": "2",
    "rationale": "把两个一相加得到二。",
    "confidence": 0.9,
    "confidence_kind": "model_self_reported",
    "confidence_calibration_ref": None,
    "warnings": [],
}

SUCCESS_RESPONSE_BODY = canonical_json_bytes(
    {
        "id": "task-w10-offline",
        "request_id": "request-w10-offline",
        "model": "glm-4.6v-flash",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": canonical_json_bytes(_ANSWER_PAYLOAD).decode("utf-8"),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120,
        },
    }
)


def http_response(body: bytes, *, status: int = 200, reason: str = "OK") -> bytes:
    """Build the exact bounded HTTP/1.1 bytes consumed by W09's parser."""

    return (
        f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
        + b"content-type: application/json\r\n"
        + b"content-length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )


class RecordingCaptureSource(MultimodalCaptureSource):
    __slots__ = (
        "events",
        "authorization_state",
        "pre_capture_state",
        "post_capture_state",
        "after_authorization_observation",
        "on_capture",
        "capture_calls",
    )

    def __init__(
        self,
        events: list[str],
        *,
        authorization_state: ScreenPermissionState = ScreenPermissionState.GRANTED,
        pre_capture_state: ScreenPermissionState = ScreenPermissionState.GRANTED,
        post_capture_state: ScreenPermissionState = ScreenPermissionState.GRANTED,
        after_authorization_observation: Callable[[], None] | None = None,
        on_capture: Callable[[], None] | None = None,
    ) -> None:
        self.events = events
        self.authorization_state = authorization_state
        self.pre_capture_state = pre_capture_state
        self.post_capture_state = post_capture_state
        self.after_authorization_observation = after_authorization_observation
        self.on_capture = on_capture
        self.capture_calls = 0

    @staticmethod
    def _make_observation(
        state: ScreenPermissionState,
        now,
    ) -> CaptureObservation:
        return MultimodalCaptureSource.observation(
            permission=permission_observation(state, observed_at=now),
            topology=topology(observed_at=now),
        )

    def observe_for_authorization(
        self,
        *,
        planned: PlannedExecution,
        now,
    ) -> CaptureObservation:
        del planned
        self.events.append("observe_authorization")
        observation = self._make_observation(self.authorization_state, now)
        if self.after_authorization_observation is not None:
            self.after_authorization_observation()
        return observation

    def observe_before_capture(
        self,
        *,
        authorization,
        now,
    ) -> CaptureObservation:
        del authorization
        self.events.append("observe_before_capture")
        return self._make_observation(self.pre_capture_state, now)

    def capture_once(self, *, consumed) -> CapturedFrame:
        del consumed
        self.events.append("capture_once")
        self.capture_calls += 1
        if self.on_capture is not None:
            self.on_capture()
        return MultimodalCaptureSource.frame(
            data=canonical_png_bytes(),
            mime_type="image/png",
            width_px=4,
            height_px=2,
        )

    def observe_after_capture(
        self,
        *,
        consumed,
        frame: CapturedFrame,
        now,
    ) -> CaptureObservation:
        del consumed, frame
        self.events.append("observe_after_capture")
        return self._make_observation(self.post_capture_state, now)


class RecordingPreviewController(EgressPreviewController):
    __slots__ = (
        "events",
        "approved",
        "reviews",
        "last_image_sha256",
        "last_preview_subject_digest",
    )

    def __init__(self, events: list[str], *, approved: bool = True) -> None:
        self.events = events
        self.approved = approved
        self.reviews = 0
        self.last_image_sha256: str | None = None
        self.last_preview_subject_digest = None

    def review(self, preview: EgressPreview) -> EgressPreviewDecision:
        self.events.append("preview_review")
        self.reviews += 1
        self.last_image_sha256 = hashlib.sha256(preview.image_bytes).hexdigest()
        self.last_preview_subject_digest = preview.preview_subject_digest
        factory = self.approve if self.approved else self.cancel
        return factory(
            preview,
            decision_id=PREVIEW_DECISION_ID,
            decided_at=NOW,
        )


class RecordingAdapter(DirectMultimodalAdapter):
    __slots__ = ("events", "delegate", "validated", "prepare_calls", "decode_calls")

    adapter_family = GLM_ADAPTER_FAMILY
    adapter_version = GLM_ADAPTER_VERSION

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.delegate = OpenAIChatCompatibleAdapter()
        self.validated = None
        self.prepare_calls = 0
        self.decode_calls = 0

    def prepare(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        operation_id: UUID,
    ) -> PreparedOutbound:
        self.prepare_calls += 1
        self.events.append(f"adapter_prepare:{self.prepare_calls}")
        self.validated = invocation.input
        return self.delegate.prepare(
            planned=planned,
            invocation=invocation,
            operation_id=operation_id,
        )

    def decode(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        response: TransportResponse,
    ) -> AnswerCandidateResult:
        self.decode_calls += 1
        self.events.append("adapter_decode")
        return self.delegate.decode(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            response=response,
        )


class OfflineExactTransport(RemoteTransport):
    """Use W09's private test authority and fake numeric/TLS owners only."""

    __slots__ = (
        "events",
        "numeric_edge",
        "numeric_factory",
        "tls_factory",
        "calls",
        "prepared_attempts",
    )

    def __init__(self, events: list[str], *, response_body: bytes) -> None:
        self.events = events
        self.numeric_edge = _NumericEdge()
        self.numeric_factory = _NumericFactory(self.numeric_edge)
        self.tls_factory = _TlsFactory(
            edge_options={
                "reads": (http_response(response_body), b""),
            }
        )
        self.calls = 0
        self.prepared_attempts: list[PreparedResolverAttempt] = []

    def send_once(
        self,
        prepared_attempt: PreparedResolverAttempt,
    ) -> TransportResponse:
        self.events.append("transport_send")
        self.calls += 1
        self.prepared_attempts.append(prepared_attempt)
        with _clean_tls_environment(), _poison_network():
            response = exact_transport._send_exact_with_test_edges(
                prepared_attempt,
                numeric_edge_factory=self.numeric_factory,
                tls_edge_factory=self.tls_factory,
                _authority=exact_transport._TEST_TRANSPORT_AUTHORITY,
            )
        self.events.append("transport_return")
        return response


class RecordingUnwiredTransport(RemoteTransport):
    __slots__ = ("events", "calls", "prepared_attempts", "delegate")

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls = 0
        self.prepared_attempts: list[PreparedResolverAttempt] = []
        self.delegate = UnwiredRemoteTransport()

    def send_once(
        self,
        prepared_attempt: PreparedResolverAttempt,
    ) -> TransportResponse:
        self.events.append("transport_send")
        self.calls += 1
        self.prepared_attempts.append(prepared_attempt)
        return self.delegate.send_once(prepared_attempt)


def make_w10_fixture(
    *,
    request_id: UUID = UUID("80000000-0000-0000-0000-000000000001"),
    pre_capture_state: ScreenPermissionState = ScreenPermissionState.GRANTED,
    preview_approved: bool = True,
    response_body: bytes = SUCCESS_RESPONSE_BODY,
    unwired_transport: bool = False,
    registry=None,
) -> SimpleNamespace:
    if registry is None:
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
    scope = selected_scope(
        initial_topology,
        rect=CaptureRect(left=20, top=30, width=4, height=2),
    )
    consent_ledger = ConsentLedger()
    grant = consent_ledger.issue_for_plan(
        planned=planned,
        binding_id=GLM_BINDING_ID,
        grant_id=GRANT_ID,
        request_id=request_id,
        capture_scope_fingerprint=scope.fingerprint,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        one_shot=False,
        confirmed_unknown_policies=ALL_UNKNOWN_CONFIRMATIONS,
    )
    authority_ledger = RegistryPolicyAuthorityLedger(registry)
    clock = ManualRuntimeClock()
    context_ledger = CallContextLedger._for_testing(
        authority_ledger=authority_ledger,
        clock=clock,
        _authority=_TEST_CLOCK_AUTHORITY,
    )
    launcher, credential_resolver, credential_source, spawner, kernel, events = (
        _components()
    )
    capture_source = RecordingCaptureSource(
        events,
        pre_capture_state=pre_capture_state,
    )
    preview_controller = RecordingPreviewController(
        events,
        approved=preview_approved,
    )
    adapter = RecordingAdapter(events)
    transport: RemoteTransport
    if unwired_transport:
        transport = RecordingUnwiredTransport(events)
    else:
        transport = OfflineExactTransport(events, response_body=response_body)
    executor = MultimodalPipelineExecutor._for_testing(
        adapter=adapter,
        capture_source=capture_source,
        preview_controller=preview_controller,
        launcher=launcher,
        credential_resolver=credential_resolver,
        transport=transport,
        _authority=_TEST_PIPELINE_AUTHORITY,
    )
    return SimpleNamespace(
        registry=registry,
        intent=intent,
        planned=planned,
        selected_scope=scope,
        consent_ledger=consent_ledger,
        grant=grant,
        authority_ledger=authority_ledger,
        clock=clock,
        context_ledger=context_ledger,
        launcher=launcher,
        credential_resolver=credential_resolver,
        credential_source=credential_source,
        spawner=spawner,
        kernel=kernel,
        events=events,
        capture_source=capture_source,
        preview_controller=preview_controller,
        adapter=adapter,
        transport=transport,
        executor=executor,
    )


@contextmanager
def offline_w10_execution():
    """Forbid ambient I/O and supply only deterministic resolver UUIDs."""

    with ExitStack() as stack:
        stack.enter_context(_poison_real_io())
        stack.enter_context(
            mock.patch(
                "snapquiz.transport.resolver.uuid4",
                side_effect=(
                    READY_PUBLICATION_ID,
                    LIFECYCLE_ID,
                    TRANSPORT_CLAIM_ID,
                    DNS_START_ID,
                ),
            )
        )
        yield


def execute_fixture(
    fixture: SimpleNamespace,
    *,
    cancellation: MultimodalCancellation | None = None,
):
    with offline_w10_execution():
        return fixture.executor.execute(
            planned=fixture.planned,
            intent=fixture.intent,
            consent_ledger=fixture.consent_ledger,
            consent_grant_ids=(fixture.grant.grant_id,),
            authority_ledger=fixture.authority_ledger,
            context_ledger=fixture.context_ledger,
            selected_scope=fixture.selected_scope,
            capture_id=CAPTURE_ID,
            cancellation=cancellation,
        )


def make_active_foreign_prepared_attempt() -> SimpleNamespace:
    """Create a distinct active W09 owner for return-alias tests."""

    runtime, gate, credential_permit = _make_authorized_credential()
    launcher, credential_resolver, source, spawner, kernel, events = (
        _components()
    )
    cleanup_ticket = issue_resolver_cleanup_ticket()
    with _poison_real_io(), mock.patch(
        "snapquiz.transport.resolver.uuid4",
        side_effect=(
            READY_PUBLICATION_ID,
            LIFECYCLE_ID,
            TRANSPORT_CLAIM_ID,
            DNS_START_ID,
        ),
    ):
        prepared = coordinate_resolver_attempt(
            launcher=launcher,
            credential_resolver=credential_resolver,
            gate=gate,
            credential_permit=credential_permit,
            cleanup_ticket=cleanup_ticket,
        )
    return SimpleNamespace(
        runtime=runtime,
        gate=gate,
        credential_permit=credential_permit,
        launcher=launcher,
        credential_resolver=credential_resolver,
        source=source,
        spawner=spawner,
        kernel=kernel,
        events=events,
        cleanup_ticket=cleanup_ticket,
        prepared=prepared,
    )


@contextmanager
def trace_w10_composition(events: list[str]):
    """Record the executor's internal authority boundaries in one order log."""

    def static_wrapper(label: str, original):
        def traced(*args, **kwargs):
            events.append(label)
            return original(*args, **kwargs)

        return staticmethod(traced)

    def method_wrapper(label: str, original):
        def traced(owner, *args, **kwargs):
            events.append(label)
            return original(owner, *args, **kwargs)

        return traced

    def function_wrapper(label: str, original):
        def traced(*args, **kwargs):
            events.append(label)
            return original(*args, **kwargs)

        return traced

    static_boundaries = (
        (
            RuntimeCallFactory,
            "authorize_and_start",
            "runtime_start",
        ),
        (CaptureArtifactFactory, "create", "artifact_create"),
        (InputValidator, "validate", "input_validate"),
        (SolveRequestFactory, "create", "solve_request"),
        (StageInvocationFactory, "create", "stage_invocation"),
        (SendSessionFactory, "create", "send_session"),
    )
    method_boundaries = (
        (CapturePolicy, "authorize", "capture_authorize"),
        (CapturePolicy, "prepare_capture", "capture_consume"),
        (CallContextLedger, "_claim_capture_start", "capture_start_claim"),
        (EgressGate, "approve", "egress_approve"),
        (
            AttemptGate,
            "authorize_credential_resolution",
            "credential_permit",
        ),
    )
    function_boundaries = (
        ("issue_resolver_cleanup_ticket", "cleanup_ticket"),
        ("coordinate_resolver_attempt", "resolver_attempt"),
        ("validate_answer_candidate", "result_validate"),
    )
    with ExitStack() as stack:
        for owner, name, label in static_boundaries:
            original = getattr(owner, name)
            stack.enter_context(
                mock.patch.object(
                    owner,
                    name,
                    new=static_wrapper(label, original),
                )
            )
        for owner, name, label in method_boundaries:
            original = getattr(owner, name)
            stack.enter_context(
                mock.patch.object(
                    owner,
                    name,
                    new=method_wrapper(label, original),
                )
            )
        for name, label in function_boundaries:
            original = getattr(multimodal_module, name)
            stack.enter_context(
                mock.patch.object(
                    multimodal_module,
                    name,
                    new=function_wrapper(label, original),
                )
            )
        yield


__all__ = [
    "OfflineExactTransport",
    "RecordingAdapter",
    "RecordingCaptureSource",
    "RecordingPreviewController",
    "RecordingUnwiredTransport",
    "SUCCESS_RESPONSE_BODY",
    "VALID_SECRET",
    "execute_fixture",
    "http_response",
    "make_active_foreign_prepared_attempt",
    "make_w10_fixture",
    "offline_w10_execution",
    "trace_w10_composition",
]
