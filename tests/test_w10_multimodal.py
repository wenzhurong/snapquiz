"""End-to-end offline acceptance and failure matrix for W10."""
from __future__ import annotations

import hashlib
import threading
import unittest
from unittest import mock
from uuid import UUID

from snapquiz.adapters.openai_chat_compatible import (
    OpenAIChatCompatibleAdapter,
)
from snapquiz.core.permissions import ScreenPermissionState
from snapquiz.domain.adapter import (
    TransportResponse,
    _create_answer_candidate_result,
)
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import (
    CancelledError,
    ConfigError,
    EndpointPolicyError,
    InvalidOutputError,
    OperationError,
    PermissionDeniedError,
    TimeoutError,
)
from snapquiz.domain.solve import PipelineKind, SolveStatus
from snapquiz.pipelines.multimodal import (
    PRODUCTION_MULTIMODAL_PIPELINE_AVAILABLE,
    MultimodalCancellation,
    MultimodalPipelineExecutor,
    _TEST_PIPELINE_AUTHORITY,
)
import snapquiz.pipelines.multimodal as multimodal_module
from snapquiz.runtime.attempt import AttemptGate
from snapquiz.runtime.context import (
    CallContextLedger,
    CancellationReason,
    RuntimeCallFactory,
)
from snapquiz.transport.http import ResolverCleanupTicket

from tests.w07_helpers import canonical_png_bytes
from tests.w10_helpers import (
    OfflineExactTransport,
    RecordingAdapter,
    SUCCESS_RESPONSE_BODY,
    VALID_SECRET,
    execute_fixture,
    make_active_foreign_prepared_attempt,
    make_w10_fixture,
    trace_w10_composition,
)


class WrongCorrelationTransport(OfflineExactTransport):
    """Return an internally valid response bound to another execution."""

    def send_once(self, prepared_attempt):
        response = super().send_once(prepared_attempt)
        return TransportResponse(
            plan_id=UUID("82000000-0000-0000-0000-000000000001"),
            stage_id=UUID("82000000-0000-0000-0000-000000000002"),
            operation_id=UUID("82000000-0000-0000-0000-000000000003"),
            request_envelope_digest=Digest256("f" * 64),
            http_status=response.http_status,
            provider_request_id=response.provider_request_id,
            body=response.body,
        )


class WrongResponseDigestAdapter(RecordingAdapter):
    """Adversarial test adapter that rewrites only response provenance."""

    def decode(self, **kwargs):
        candidate = super().decode(**kwargs)
        return _create_answer_candidate_result(
            request_id=candidate.request_id,
            plan_id=candidate.plan_id,
            plan_digest=candidate.plan_digest,
            stage_id=candidate.stage_id,
            operation_id=candidate.operation_id,
            invocation_digest=candidate.invocation_digest,
            request_envelope_digest=candidate.request_envelope_digest,
            response_body_digest=Digest256("e" * 64),
            candidate_payload=candidate.candidate_payload,
            refusal=candidate.refusal,
            finish_reason=candidate.finish_reason,
            provider_request_id=candidate.provider_request_id,
            usage=candidate.usage,
        )


class W10MultimodalPipelineTest(unittest.TestCase):
    def _replace_executor(self, fixture, *, adapter=None, transport=None) -> None:
        if adapter is not None:
            fixture.adapter = adapter
        if transport is not None:
            fixture.transport = transport
        fixture.executor = MultimodalPipelineExecutor._for_testing(
            adapter=fixture.adapter,
            capture_source=fixture.capture_source,
            preview_controller=fixture.preview_controller,
            launcher=fixture.launcher,
            credential_resolver=fixture.credential_resolver,
            transport=fixture.transport,
            _authority=_TEST_PIPELINE_AUTHORITY,
        )

    def _context(self, fixture):
        return fixture.context_ledger.snapshot(fixture.planned.plan.request_id)

    def _budgets(self, fixture) -> tuple[int, ...]:
        context = self._context(fixture)
        return tuple(
            fixture.context_ledger.snapshot_budget(item).consumed
            for item in (
                *context.operation_budgets,
                context.global_network_budget,
                context.billable_budget,
            )
        )

    def _assert_terminal_context(self, fixture) -> None:
        context = self._context(fixture)
        with self.assertRaises(OperationError) as raised:
            fixture.context_ledger.sample_active(context)
        self.assertEqual(raised.exception.stage, "call_context")
        metadata = fixture.context_ledger.safe_metadata()
        self.assertEqual(metadata["pending_start_count"], 0)
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)

    def _assert_failure_is_safe(self, error: OperationError) -> None:
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        rendered = str(error)
        for forbidden in (
            "synthetic-token",
            "8.8.8.8",
            "request-w10-offline",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_happy_path_has_exact_order_one_send_provenance_and_cleanup(self):
        fixture = make_w10_fixture()

        with trace_w10_composition(fixture.events):
            result = execute_fixture(fixture)

        self.assertIs(result.status, SolveStatus.ANSWERED)
        self.assertEqual(result.question_summary, "1 + 1")
        self.assertEqual(result.answer, "2")
        self.assertIs(result.provenance.pipeline_kind, PipelineKind.DIRECT_MULTIMODAL)
        self.assertEqual(result.provenance.plan_id, fixture.planned.plan.plan_id)
        self.assertEqual(len(result.provenance.stages), 1)
        provenance = result.provenance.stages[0]
        planned_stage = fixture.planned.plan.stages[0]
        self.assertEqual(provenance.stage_id, planned_stage.stage_id)
        self.assertEqual(provenance.binding_id, planned_stage.binding_id)
        self.assertEqual(provenance.provider_profile_id, planned_stage.provider_profile_id)
        self.assertEqual(provenance.model_id, planned_stage.model_id)
        self.assertEqual(provenance.attempts, 1)
        self.assertEqual(provenance.network_calls, 1)
        self.assertEqual(provenance.latency_ms, 0)
        self.assertEqual(provenance.usage.total_tokens, 120)

        self.assertEqual(
            fixture.events,
            [
                "runtime_start",
                "observe_authorization",
                "capture_authorize",
                "observe_before_capture",
                "capture_consume",
                "capture_start_claim",
                "capture_once",
                "artifact_create",
                "observe_after_capture",
                "input_validate",
                "solve_request",
                "stage_invocation",
                "adapter_prepare:1",
                "egress_approve",
                "preview_review",
                "send_session",
                "credential_permit",
                "cleanup_ticket",
                "resolver_attempt",
                "spawn",
                "ready_read",
                "credential_read",
                "start_write",
                "result_read",
                "result_eof",
                "reap",
                "close_pipes",
                "transport_send",
                "transport_return",
                "adapter_decode",
                "result_validate",
            ],
        )
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.preview_controller.reviews, 1)
        self.assertEqual(
            fixture.preview_controller.last_image_sha256,
            hashlib.sha256(canonical_png_bytes()).hexdigest(),
        )
        self.assertEqual(fixture.credential_source.calls, ["env:GLM_API_KEY"])
        self.assertEqual(len(fixture.credential_source.returned), 1)
        self.assertTrue(
            all(value == 0 for value in fixture.credential_source.returned[0])
        )

        transport = fixture.transport
        self.assertIsInstance(transport, OfflineExactTransport)
        self.assertEqual(transport.calls, 1)
        self.assertEqual(len(transport.numeric_factory.calls), 1)
        self.assertEqual(transport.numeric_edge.connect_calls, 1)
        self.assertEqual(len(transport.tls_factory.edges), 1)
        tls = transport.tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 1)
        self.assertEqual(bytes(tls.sent).count(VALID_SECRET), 1)
        self.assertIn(
            b"POST /api/paas/v4/chat/completions HTTP/1.1\r\n",
            bytes(tls.sent),
        )
        self.assertEqual(len(transport.prepared_attempts), 1)
        prepared_attempt = transport.prepared_attempts[0]
        self.assertTrue(prepared_attempt.is_closed)
        self.assertTrue(prepared_attempt.credential_handle.is_closed)
        self.assertTrue(fixture.adapter.validated.is_released)
        self.assertEqual(self._budgets(fixture), (1, 1, 1))
        self._assert_terminal_context(fixture)

    def test_full_pipeline_prepares_twice_and_downstream_never_reprepares(self):
        fixture = make_w10_fixture()
        original_prepare = OpenAIChatCompatibleAdapter.prepare

        with mock.patch.object(
            OpenAIChatCompatibleAdapter,
            "prepare",
            wraps=original_prepare,
        ) as prepare:
            result = execute_fixture(fixture)

        self.assertIs(result.status, SolveStatus.ANSWERED)
        self.assertEqual(fixture.adapter.prepare_calls, 1)
        # The caller prepares once and Egress independently rebuilds once.
        # Session, AttemptGate, resolver, and transport use the ledger proof.
        self.assertEqual(prepare.call_count, 2)

    def test_pre_capture_permission_denial_has_zero_capture_preview_secret_or_network(self):
        fixture = make_w10_fixture(
            pre_capture_state=ScreenPermissionState.DENIED,
        )

        with self.assertRaises(PermissionDeniedError) as raised:
            execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(
            fixture.events,
            ["observe_authorization", "observe_before_capture"],
        )
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.adapter.prepare_calls, 0)
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.spawner.requests, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))
        self._assert_terminal_context(fixture)

    def test_egress_cancel_has_no_credential_resolution_or_network(self):
        fixture = make_w10_fixture(preview_approved=False)

        with self.assertRaises(CancelledError) as raised:
            execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "egress_gate")
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.preview_controller.reviews, 1)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.spawner.requests, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))
        self.assertTrue(fixture.adapter.validated.is_released)
        self._assert_terminal_context(fixture)

    def test_invalid_response_is_not_retried_and_all_owners_are_closed(self):
        fixture = make_w10_fixture(response_body=b"{}")

        with self.assertRaises(InvalidOutputError) as raised:
            execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "adapter_decode")
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.preview_controller.reviews, 1)
        self.assertEqual(fixture.credential_source.calls, ["env:GLM_API_KEY"])
        self.assertTrue(
            all(value == 0 for value in fixture.credential_source.returned[0])
        )
        transport = fixture.transport
        self.assertIsInstance(transport, OfflineExactTransport)
        self.assertEqual(transport.calls, 1)
        self.assertEqual(len(transport.numeric_factory.calls), 1)
        self.assertEqual(transport.numeric_edge.connect_calls, 1)
        self.assertEqual(len(transport.tls_factory.edges), 1)
        self.assertEqual(transport.tls_factory.edges[0].write_calls, 1)
        self.assertEqual(fixture.adapter.decode_calls, 1)
        self.assertTrue(transport.prepared_attempts[0].is_closed)
        self.assertTrue(transport.prepared_attempts[0].credential_handle.is_closed)
        self.assertTrue(fixture.adapter.validated.is_released)
        self.assertEqual(self._budgets(fixture), (1, 1, 1))
        self._assert_terminal_context(fixture)

    def test_production_factory_fails_closed_before_dependency_construction(self):
        self.assertFalse(PRODUCTION_MULTIMODAL_PIPELINE_AVAILABLE)

        with self.assertRaises(EndpointPolicyError) as raised:
            MultimodalPipelineExecutor.production()

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "multimodal_pipeline")

    def test_sample_active_observes_cancellation_before_capture(self):
        fixture = make_w10_fixture()

        def cancel_context() -> None:
            context = self._context(fixture)
            changed = fixture.context_ledger.cancel(
                context.cancellation_token,
                reason=CancellationReason.USER_REQUEST,
            )
            self.assertTrue(changed)

        fixture.capture_source.after_authorization_observation = cancel_context

        with self.assertRaises(CancelledError) as raised:
            execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "call_context")
        self.assertEqual(fixture.events, ["observe_authorization"])
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))
        self._assert_terminal_context(fixture)

    def test_sample_active_observes_deadline_before_capture(self):
        fixture = make_w10_fixture()

        def expire_context() -> None:
            fixture.clock.advance(milliseconds=30_000)

        fixture.capture_source.after_authorization_observation = expire_context

        with self.assertRaises(TimeoutError) as raised:
            execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "call_context")
        self.assertEqual(fixture.events, ["observe_authorization"])
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(self._budgets(fixture), (0, 0, 0))
        self._assert_terminal_context(fixture)

    def test_pre_cancelled_handle_stops_before_first_observation(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        self.assertTrue(cancellation.cancel())

        with self.assertRaises(CancelledError) as raised:
            execute_fixture(fixture, cancellation=cancellation)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(fixture.events, [])
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertTrue(cancellation.is_finished)
        self._assert_terminal_context(fixture)

    def test_cancel_after_capture_consume_before_start_claim_has_zero_capture(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        original = CallContextLedger._claim_capture_start

        def cancel_then_claim(owner, context, **kwargs):
            self.assertTrue(cancellation.cancel())
            return original(owner, context, **kwargs)

        with mock.patch.object(
            CallContextLedger,
            "_claim_capture_start",
            new=cancel_then_claim,
        ):
            with self.assertRaises(CancelledError) as raised:
                execute_fixture(fixture, cancellation=cancellation)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self._assert_terminal_context(fixture)

    def test_cancel_after_capture_start_allows_one_capture_but_no_propagation(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        fixture.capture_source.on_capture = cancellation.cancel

        with self.assertRaises(CancelledError) as raised:
            execute_fixture(fixture, cancellation=cancellation)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 1)
        self.assertEqual(fixture.preview_controller.reviews, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self._assert_terminal_context(fixture)

    def test_authority_revoke_between_capture_consume_and_claim_has_zero_capture(self):
        fixture = make_w10_fixture()
        original = CallContextLedger._claim_capture_start

        def revoke_then_claim(owner, context, **kwargs):
            fixture.authority_ledger.revoke()
            return original(owner, context, **kwargs)

        with mock.patch.object(
            CallContextLedger,
            "_claim_capture_start",
            new=revoke_then_claim,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "call_context")
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self._assert_terminal_context(fixture)

    def test_deadline_at_capture_start_claim_has_zero_capture(self):
        fixture = make_w10_fixture()
        original = CallContextLedger._claim_capture_start

        def expire_then_claim(owner, context, **kwargs):
            fixture.clock.advance(milliseconds=30_000)
            return original(owner, context, **kwargs)

        with mock.patch.object(
            CallContextLedger,
            "_claim_capture_start",
            new=expire_then_claim,
        ):
            with self.assertRaises(TimeoutError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self._assert_terminal_context(fixture)

    def test_transport_response_correlation_is_checked_before_decode(self):
        fixture = make_w10_fixture()
        transport = WrongCorrelationTransport(
            fixture.events,
            response_body=SUCCESS_RESPONSE_BODY,
        )
        self._replace_executor(fixture, transport=transport)

        with self.assertRaises(EndpointPolicyError) as raised:
            execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "multimodal_transport")
        self.assertEqual(transport.calls, 1)
        self.assertEqual(fixture.adapter.decode_calls, 0)
        self._assert_terminal_context(fixture)

    def test_candidate_must_bind_the_exact_transport_response_digest(self):
        fixture = make_w10_fixture()
        adapter = WrongResponseDigestAdapter(fixture.events)
        self._replace_executor(fixture, adapter=adapter)

        with self.assertRaises(InvalidOutputError) as raised:
            execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "adapter_decode")
        self.assertEqual(fixture.transport.calls, 1)
        self.assertEqual(adapter.decode_calls, 1)
        self._assert_terminal_context(fixture)

    def test_context_factory_return_loss_is_recovered_without_capture(self):
        fixture = make_w10_fixture()
        original = RuntimeCallFactory.authorize_and_start

        def commit_then_raise(**kwargs):
            original(**kwargs)
            raise RuntimeError("synthetic context return loss")

        with mock.patch.object(
            RuntimeCallFactory,
            "authorize_and_start",
            new=staticmethod(commit_then_raise),
        ):
            with self.assertRaises(ConfigError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(fixture.capture_source.capture_calls, 0)
        self.assertEqual(fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"], 0)
        self._assert_terminal_context(fixture)

    def test_credential_permit_return_loss_is_recovered_before_secret_read(self):
        fixture = make_w10_fixture()
        original = AttemptGate.authorize_credential_resolution

        def commit_then_raise(owner, **kwargs):
            original(owner, **kwargs)
            raise RuntimeError("synthetic permit return loss")

        with mock.patch.object(
            AttemptGate,
            "authorize_credential_resolution",
            new=commit_then_raise,
        ):
            with self.assertRaises(ConfigError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"], 0)
        self._assert_terminal_context(fixture)

    def test_foreign_resolver_return_is_rejected_before_transport_or_adoption(self):
        fixture = make_w10_fixture()
        foreign = make_active_foreign_prepared_attempt()
        original = multimodal_module.coordinate_resolver_attempt
        current_returns = []

        def return_foreign_after_current_commit(**kwargs):
            current_returns.append(original(**kwargs))
            return foreign.prepared

        try:
            with mock.patch.object(
                multimodal_module,
                "coordinate_resolver_attempt",
                new=return_foreign_after_current_commit,
            ):
                with self.assertRaises(ConfigError) as raised:
                    execute_fixture(fixture)

            self._assert_failure_is_safe(raised.exception)
            self.assertEqual(raised.exception.stage, "multimodal_pipeline")
            self.assertEqual(fixture.transport.calls, 0)
            self.assertEqual(len(current_returns), 1)
            self.assertTrue(current_returns[0].is_closed)
            self.assertTrue(fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"] == 0)
            self.assertFalse(foreign.prepared.is_closed)
            self.assertFalse(foreign.cleanup_ticket.is_terminal)
            self._assert_terminal_context(fixture)
        finally:
            if not foreign.prepared.is_closed:
                foreign.prepared.close()
            foreign.runtime.context_ledger.close(foreign.runtime.call_context)

        self.assertTrue(foreign.cleanup_ticket.is_terminal)

    def test_truthy_resolver_return_observer_is_rejected_before_transport(self):
        fixture = make_w10_fixture()

        with mock.patch.object(
            ResolverCleanupTicket,
            "_prepared_is_exact_for_caller",
            return_value=object(),
        ):
            with self.assertRaises(ConfigError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "multimodal_pipeline")
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()[
                "pending_cleanup_count"
            ],
            0,
        )
        self._assert_terminal_context(fixture)

    def test_cleanup_winning_after_resolver_observation_stops_before_wire(self):
        fixture = make_w10_fixture()
        ticket_published = threading.Event()
        release_observer = threading.Event()
        tickets: list[ResolverCleanupTicket] = []
        outcomes: list[object] = []
        original_issue = multimodal_module.issue_resolver_cleanup_ticket
        original_observer = ResolverCleanupTicket._prepared_is_exact_for_caller

        def issue_and_publish():
            ticket = original_issue()
            tickets.append(ticket)
            return ticket

        def observe_then_block(owner, *args, **kwargs):
            observed = original_observer(owner, *args, **kwargs)
            ticket_published.set()
            if not release_observer.wait(timeout=5):
                raise AssertionError("test did not release resolver observer")
            return observed

        def run() -> None:
            try:
                outcomes.append(execute_fixture(fixture))
            except BaseException as error:
                outcomes.append(error)

        with (
            mock.patch.object(
                multimodal_module,
                "issue_resolver_cleanup_ticket",
                new=issue_and_publish,
            ),
            mock.patch.object(
                ResolverCleanupTicket,
                "_prepared_is_exact_for_caller",
                new=observe_then_block,
            ),
        ):
            thread = threading.Thread(target=run)
            thread.start()
            try:
                self.assertTrue(ticket_published.wait(timeout=5))
                self.assertEqual(len(tickets), 1)
                self.assertTrue(tickets[0].retry_cleanup())
                self.assertTrue(tickets[0].is_terminal)
            finally:
                release_observer.set()
                thread.join(timeout=10)

        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcomes), 1)
        self.assertIsInstance(outcomes[0], OperationError)
        self._assert_failure_is_safe(outcomes[0])
        self.assertEqual(fixture.transport.calls, 1)
        self.assertEqual(fixture.transport.numeric_factory.calls, [])
        self.assertEqual(fixture.transport.numeric_edge.connect_calls, 0)
        self.assertEqual(fixture.transport.tls_factory.edges, [])
        self.assertTrue(fixture.credential_source.returned)
        self.assertTrue(
            all(value == 0 for value in fixture.credential_source.returned[0])
        )
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )
        self._assert_terminal_context(fixture)

    def test_noop_credential_publication_is_rejected_before_gate_commit(self):
        fixture = make_w10_fixture()

        def no_op_publication(owner, permit):
            del owner
            return permit

        with mock.patch.object(
            multimodal_module._RunState,
            "publish_credential_permit",
            new=no_op_publication,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "attempt_gate")
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(
            fixture.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self._assert_terminal_context(fixture)

    def test_truthy_non_boolean_publication_observer_is_rejected(self):
        fixture = make_w10_fixture()

        with mock.patch.object(
            multimodal_module._RunState,
            "credential_permit_is_current",
            new=lambda owner, permit: object(),
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "attempt_gate")
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(
            fixture.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self._assert_terminal_context(fixture)

    def test_unproven_context_close_retains_and_later_delivers_original_result(self):
        fixture = make_w10_fixture()
        original = CallContextLedger.close

        with mock.patch.object(
            CallContextLedger,
            "close",
            new=lambda owner, context: False,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                execute_fixture(fixture)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(raised.exception.stage, "multimodal_cleanup")
        metadata = fixture.executor.pending_cleanup_metadata()
        self.assertEqual(metadata["pending_cleanup_count"], 1)
        calls_before = (
            fixture.capture_source.capture_calls,
            len(fixture.credential_source.calls),
            fixture.transport.calls,
        )
        result = fixture.executor.retry_cleanup_and_finalize(
            fixture.planned.plan.request_id
        )
        self.assertEqual(result.answer, "2")
        self.assertEqual(
            calls_before,
            (
                fixture.capture_source.capture_calls,
                len(fixture.credential_source.calls),
                fixture.transport.calls,
            ),
        )
        self.assertEqual(fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"], 0)
        self._assert_terminal_context(fixture)
        self.assertIsNotNone(original)

    def test_context_close_commit_then_raise_is_observed_as_terminal(self):
        fixture = make_w10_fixture()
        original = CallContextLedger.close

        def commit_then_raise(owner, context):
            original(owner, context)
            raise KeyboardInterrupt

        with mock.patch.object(
            CallContextLedger,
            "close",
            new=commit_then_raise,
        ):
            result = execute_fixture(fixture)

        self.assertEqual(result.answer, "2")
        self.assertEqual(fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"], 0)
        self._assert_terminal_context(fixture)

    def test_resolver_cleanup_fault_is_retained_and_never_replays_pipeline(self):
        fixture = make_w10_fixture()
        fixture.kernel.close_fault = RuntimeError("synthetic close failure")

        with self.assertRaises(EndpointPolicyError) as raised:
            execute_fixture(fixture)

        self.assertEqual(raised.exception.stage, "multimodal_cleanup")
        self.assertEqual(fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"], 1)
        calls_before = (
            fixture.capture_source.capture_calls,
            len(fixture.credential_source.calls),
            fixture.transport.calls,
        )
        external_cleanup_counts = tuple(
            fixture.events.count(event)
            for event in ("terminate", "reap", "close_pipes")
        )
        fixture.kernel.close_fault = None
        with self.assertRaises(EndpointPolicyError) as cleanup_failure:
            fixture.executor.retry_cleanup_and_finalize(
                fixture.planned.plan.request_id
            )
        self._assert_failure_is_safe(cleanup_failure.exception)
        self.assertEqual(cleanup_failure.exception.stage, "multimodal_cleanup")
        self.assertEqual(
            calls_before,
            (
                fixture.capture_source.capture_calls,
                len(fixture.credential_source.calls),
                fixture.transport.calls,
            ),
        )
        self.assertEqual(
            tuple(
                fixture.events.count(event)
                for event in ("terminate", "reap", "close_pipes")
            ),
            external_cleanup_counts,
        )
        self.assertEqual(fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"], 1)

    def test_cancel_before_result_publication_prevents_answer_delivery(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        original = multimodal_module.validate_answer_candidate

        def cancel_before_return(*args, **kwargs):
            result = original(*args, **kwargs)
            self.assertTrue(cancellation.cancel())
            return result

        with mock.patch.object(
            multimodal_module,
            "validate_answer_candidate",
            new=cancel_before_return,
        ):
            with self.assertRaises(CancelledError) as raised:
                execute_fixture(fixture, cancellation=cancellation)

        self._assert_failure_is_safe(raised.exception)
        self.assertEqual(fixture.transport.calls, 1)
        self._assert_terminal_context(fixture)

    def test_result_publication_claim_wins_over_later_cancel(self):
        fixture = make_w10_fixture()
        cancellation = MultimodalCancellation()
        original = CallContextLedger._claim_result_publication

        def claim_then_cancel(owner, context, **kwargs):
            sample = original(owner, context, **kwargs)
            self.assertTrue(cancellation.cancel())
            return sample

        with mock.patch.object(
            CallContextLedger,
            "_claim_result_publication",
            new=claim_then_cancel,
        ):
            result = execute_fixture(fixture, cancellation=cancellation)

        self.assertEqual(result.answer, "2")
        self.assertEqual(fixture.transport.calls, 1)
        self._assert_terminal_context(fixture)

    def test_executor_is_single_flight_across_different_request_ids(self):
        fixture = make_w10_fixture()
        second = make_w10_fixture(
            request_id=UUID("83000000-0000-0000-0000-000000000001")
        )
        entered = threading.Event()
        release = threading.Event()
        first_outcome = []

        def block_after_observation():
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("test barrier timed out")

        fixture.capture_source.after_authorization_observation = (
            block_after_observation
        )

        def run_first():
            try:
                first_outcome.append(execute_fixture(fixture))
            except BaseException as error:
                first_outcome.append(error)

        worker = threading.Thread(target=run_first)
        worker.start()
        self.assertTrue(entered.wait(timeout=5))
        try:
            with self.assertRaises(ConfigError) as raised:
                fixture.executor.execute(
                    planned=second.planned,
                    intent=second.intent,
                    consent_ledger=second.consent_ledger,
                    consent_grant_ids=(second.grant.grant_id,),
                    authority_ledger=second.authority_ledger,
                    context_ledger=second.context_ledger,
                    selected_scope=second.selected_scope,
                    capture_id=UUID("83000000-0000-0000-0000-000000000002"),
                )
            self._assert_failure_is_safe(raised.exception)
        finally:
            release.set()
            worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(first_outcome), 1)
        self.assertNotIsInstance(first_outcome[0], BaseException)


if __name__ == "__main__":
    unittest.main()
