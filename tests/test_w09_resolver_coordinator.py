"""Offline tests for the sole W09-B2a resolver coordinator."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import timedelta
import copy
import inspect
import json
import pickle
from threading import Barrier, Thread
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.config.profiles import GLM_NETWORK_POLICY_VERSION
from snapquiz.domain.digest import canonical_json_bytes, digest256
from snapquiz.domain.errors import ConfigError, EndpointPolicyError
from snapquiz.privacy.egress import EgressApprovalLedger, EgressGate
from snapquiz.runtime.attempt import (
    AttemptGate,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.runtime.context import CallContextLedger
import snapquiz.transport.resolver as resolver_module
from snapquiz.transport.address_policy import (
    INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
    INTERNET_PUBLIC_ADDRESS_POLICY_REF,
    RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
)
from snapquiz.transport.credentials import CredentialResolver
from snapquiz.transport.http import (
    PreparedResolverAttempt,
    coordinate_resolver_attempt,
)
from snapquiz.transport.resolver import (
    READY_FRAME,
    PreAttemptResolverGuard,
    ResolverHelperLauncher,
    ResolverResultReceipt,
    _RESOLVER_LIFECYCLE_AUTHORITY,
    start_frame_digest,
)
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime


SESSION_ISSUED_AT = NOW + timedelta(seconds=5)
LIFECYCLE_ID = UUID("71000000-0000-0000-0000-000000000001")
TRANSPORT_CLAIM_ID = UUID("71000000-0000-0000-0000-000000000002")
DNS_START_ID = UUID("71000000-0000-0000-0000-000000000003")
CREDENTIAL_PUBLICATION_ID = UUID(
    "71000000-0000-0000-0000-000000000004"
)
OTHER_CREDENTIAL_PUBLICATION_ID = UUID(
    "71000000-0000-0000-0000-000000000005"
)
READY_PUBLICATION_ID = UUID("71000000-0000-0000-0000-000000000006")
TAMPER_PUBLICATION_ID = UUID("72000000-0000-0000-0000-000000000001")
TAMPER_LIFECYCLE_ID = UUID("72000000-0000-0000-0000-000000000002")
TAMPER_CLAIM_ID = UUID("72000000-0000-0000-0000-000000000003")
TAMPER_DNS_START_ID = UUID("72000000-0000-0000-0000-000000000004")
EXECUTABLE = "/opt/snapquiz/libexec/resolver-helper"
VALID_SECRET = b"synthetic-token.ABC_123~+/=="


def _result_transcript(
    start: dict[str, object],
    exact_start_frame_digest,
    address: str = "8.8.8.8",
) -> bytes:
    """Build one exact RESULT echo from the frame written by the coordinator."""

    return canonical_json_bytes(
        {
            "address_policy_digest": start["network_policy_digest"],
            "address_policy_ref": start["network_policy_ref"],
            "attempt_permit_digest": start["attempt_permit_digest"],
            "attempt_permit_id": start["attempt_permit_id"],
            "canonical_hostname": start["hostname"],
            "dns_start_id": start["dns_start_id"],
            "kind": "RESULT",
            "network_policy_version": GLM_NETWORK_POLICY_VERSION,
            "port": start["port"],
            "schema_version": RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
            "status": "ok",
            "start_frame_digest": str(exact_start_frame_digest),
            "terminal_guard_digest": start["terminal_guard_digest"],
            "terminal_guard_id": start["terminal_guard_id"],
            "transport_claim_id": start["transport_claim_id"],
            "candidates": [
                {
                    "address": address,
                    "family": "AF_INET",
                    "port": 443,
                    "protocol": "IPPROTO_TCP",
                    "socket_type": "SOCK_STREAM",
                }
            ],
        }
    )


class _FakeKernel:
    def __init__(
        self,
        events: list[str],
        *,
        result_address: str,
        cleanup_fault: BaseException | None = None,
        close_fault: BaseException | None = None,
    ) -> None:
        self._chunks = [READY_FRAME]
        self.events = events
        self.writes: list[bytes] = []
        self.result_address = result_address
        self.cleanup_fault = cleanup_fault
        self.close_fault = close_fault

    def read_stdout(self, max_bytes: int) -> bytes:
        if not self.writes:
            self.events.append("ready_read")
        elif self._chunks:
            self.events.append("result_read")
        else:
            self.events.append("result_eof")
        if not self._chunks:
            return b""
        selected = self._chunks.pop(0)
        if len(selected) <= max_bytes:
            return selected
        self._chunks.insert(0, selected[max_bytes:])
        return selected[:max_bytes]

    def write_stdin(self, frame: bytes) -> None:
        self.events.append("start_write")
        self.writes.append(frame)
        start = json.loads(frame)
        self._chunks.append(
            _result_transcript(
                start,
                start_frame_digest(frame),
                self.result_address,
            )
            + b"\n"
        )

    def terminate(self) -> None:
        self.events.append("terminate")
        if self.cleanup_fault is not None:
            raise self.cleanup_fault

    def reap(self) -> int:
        self.events.append("reap")
        return 0

    def close_pipes(self) -> None:
        self.events.append("close_pipes")
        if self.close_fault is not None:
            raise self.close_fault


class _FakeSpawner:
    def __init__(self, kernel: _FakeKernel, events: list[str]) -> None:
        self.kernel = kernel
        self.events = events
        self.requests = []

    def spawn(self, request, *, publication):
        self.events.append("spawn")
        self.requests.append(request)
        publication.publish(self.kernel)
        return self.kernel


class _FakeSource:
    def __init__(
        self,
        events: list[str],
        value: bytes | BaseException = VALID_SECRET,
    ) -> None:
        self.events = events
        self.value = value
        self.calls: list[str] = []
        self.returned: list[bytearray] = []

    def read_exact(self, locator: str) -> bytearray:
        self.events.append("credential_read")
        self.calls.append(locator)
        if isinstance(self.value, BaseException):
            raise self.value
        selected = bytearray(self.value)
        self.returned.append(selected)
        return selected


def _make_authorized_credential():
    runtime = make_w09_runtime()
    approval_ledger = EgressApprovalLedger()
    approval = EgressGate().approve(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval_ledger=approval_ledger,
        preview_controller=FixedPreviewController(),
    )
    runtime.clock.advance(milliseconds=5_000)
    session_ledger = SendSessionLedger()
    session = SendSessionFactory.create(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval=approval,
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        now=SESSION_ISSUED_AT,
    )
    gate = AttemptGate()
    credential = gate.authorize_credential_resolution(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        session=session,
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        authority_ledger=runtime.authority_ledger,
        context=runtime.call_context,
        context_ledger=runtime.context_ledger,
    )
    return runtime, gate, credential


def _components(
    *,
    result_address: str = "8.8.8.8",
    source_value=VALID_SECRET,
    cleanup_fault: BaseException | None = None,
    close_fault: BaseException | None = None,
):
    events: list[str] = []
    kernel = _FakeKernel(
        events,
        result_address=result_address,
        cleanup_fault=cleanup_fault,
        close_fault=close_fault,
    )
    spawner = _FakeSpawner(kernel, events)
    launcher = ResolverHelperLauncher(spawner, executable=EXECUTABLE)
    source = _FakeSource(events, source_value)
    resolver = CredentialResolver(source)
    return launcher, resolver, source, spawner, kernel, events


def _cleanup_counts(kernel: _FakeKernel) -> tuple[int, int, int]:
    return (
        kernel.events.count("terminate"),
        kernel.events.count("reap"),
        kernel.events.count("close_pipes"),
    )


def _recompute_capability_digest(capability) -> None:
    object.__setattr__(
        capability,
        "capability_digest",
        resolver_module._lifecycle_capability_digest(
            publication_id=capability.publication_id,
            lifecycle_id=capability.lifecycle_id,
            transport_claim_id=capability.transport_claim_id,
            dns_start_id=capability.dns_start_id,
            spawn_request_digest=capability.spawn_request_digest,
        ),
    )


def _consumed_budgets(runtime) -> tuple[int, ...]:
    budgets = (
        *runtime.call_context.operation_budgets,
        runtime.call_context.global_network_budget,
        runtime.call_context.billable_budget,
    )
    return tuple(item.snapshot().consumed for item in budgets)


@contextmanager
def _poison_real_io():
    poison = AssertionError("real I/O is forbidden in coordinator tests")
    with ExitStack() as stack:
        for target in (
            "builtins.open",
            "os.getenv",
            "os.posix_spawn",
            "socket.getaddrinfo",
            "socket.socket",
            "socket.create_connection",
            "subprocess.Popen",
        ):
            stack.enter_context(patch(target, side_effect=poison))
        yield


class W09ResolverCoordinatorTest(unittest.TestCase):
    def _coordinate(
        self,
        launcher,
        resolver,
        gate,
        credential,
        *,
        observer=None,
    ):
        with _poison_real_io(), patch(
            "snapquiz.transport.resolver.uuid4",
            side_effect=(
                READY_PUBLICATION_ID,
                LIFECYCLE_ID,
                TRANSPORT_CLAIM_ID,
                DNS_START_ID,
            ),
        ):
            return coordinate_resolver_attempt(
                launcher=launcher,
                credential_resolver=resolver,
                gate=gate,
                credential_permit=credential,
                observer=observer,
            )

    def _reserve_capability(self, launcher, *, reservation_owner=None):
        owner = object() if reservation_owner is None else reservation_owner
        with patch(
            "snapquiz.transport.resolver.uuid4",
            side_effect=(
                READY_PUBLICATION_ID,
                LIFECYCLE_ID,
                TRANSPORT_CLAIM_ID,
                DNS_START_ID,
            ),
        ) as generated:
            capability = launcher._reserve_lifecycle_capability(
                reservation_owner=owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        self.assertEqual(generated.call_count, 4)
        return capability, owner

    def _make_terminal_guard_for_tamper(self, launcher):
        capability, reservation_owner = self._reserve_capability(launcher)
        pre_guard = launcher._launch_ready(
            capability=capability,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertTrue(
            launcher._consume_ready_publication(
                capability,
                pre_guard,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        return pre_guard._transfer(
            attempt_permit_id=UUID(
                "73000000-0000-0000-0000-000000000001"
            ),
            attempt_permit_digest=digest256(
                "ResolverTerminalGuardTamperAttempt",
                "test.v1",
                {"case": "terminal-guard-snapshot"},
            ),
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )

    def test_strict_order_exact_proofs_and_explicit_close(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()

        prepared = self._coordinate(launcher, resolver, gate, credential)

        self.assertIs(type(prepared), PreparedResolverAttempt)
        self.assertEqual(
            events[:8],
            [
                "spawn",
                "ready_read",
                "credential_read",
                "start_write",
                "result_read",
                "result_eof",
                "reap",
                "close_pipes",
            ],
        )
        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(len(source.calls), 1)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(len(kernel.writes), 1)
        start = json.loads(kernel.writes[0])
        capability = prepared._terminal_guard._capability
        self.assertEqual(capability.publication_id, READY_PUBLICATION_ID)
        self.assertEqual(capability.lifecycle_id, LIFECYCLE_ID)
        self.assertEqual(capability.transport_claim_id, TRANSPORT_CLAIM_ID)
        self.assertEqual(capability.dns_start_id, DNS_START_ID)
        self.assertEqual(prepared.transport_claim_id, TRANSPORT_CLAIM_ID)
        self.assertEqual(prepared.dns_start_id, DNS_START_ID)
        self.assertEqual(prepared.result_receipt.lifecycle_id, LIFECYCLE_ID)
        self.assertEqual(
            prepared.result_receipt.transport_claim_id,
            TRANSPORT_CLAIM_ID,
        )
        self.assertEqual(prepared.result_receipt.dns_start_id, DNS_START_ID)
        self.assertEqual(start["transport_claim_id"], str(TRANSPORT_CLAIM_ID))
        self.assertEqual(start["terminal_guard_id"], str(prepared.terminal_guard_id))
        self.assertEqual(start["dns_start_id"], str(DNS_START_ID))
        self.assertEqual(
            start["network_policy_ref"],
            INTERNET_PUBLIC_ADDRESS_POLICY_REF,
        )
        self.assertEqual(start["hostname"], "open.bigmodel.cn")
        self.assertEqual(start["port"], 443)
        self.assertEqual(
            prepared.resolution_set.selected.canonical_text,
            "8.8.8.8",
        )
        self.assertIs(
            prepared.attempt_permit._attempt_gate,
            gate,
        )
        self.assertFalse(prepared.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertTrue(prepared.result_receipt.stdout_eof)
        self.assertTrue(prepared.result_receipt.child_reaped)
        self.assertEqual(prepared.result_receipt.child_exit_status, 0)
        self.assertTrue(prepared.result_receipt.helper_pipes_closed)
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

        self.assertTrue(prepared.close())
        self.assertFalse(prepared.close())
        self.assertTrue(prepared.is_closed)
        self.assertTrue(prepared.credential_handle.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_public_signature_rejects_caller_generated_role_ids_before_spawn(self):
        _, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, _, events = _components()
        parameters = inspect.signature(coordinate_resolver_attempt).parameters
        self.assertNotIn("lifecycle_id", parameters)
        self.assertNotIn("transport_claim_id", parameters)
        self.assertNotIn("dns_start_id", parameters)

        try:
            with _poison_real_io(), self.assertRaises(TypeError):
                coordinate_resolver_attempt(
                    launcher=launcher,
                    credential_resolver=resolver,
                    gate=gate,
                    credential_permit=credential,
                    lifecycle_id=LIFECYCLE_ID,
                    transport_claim_id=TRANSPORT_CLAIM_ID,
                    dns_start_id=DNS_START_ID,
                )
            self.assertEqual(spawner.requests, [])
            self.assertEqual(source.calls, [])
            self.assertNotIn("spawn", events)
            self.assertEqual(launcher._ready_publications, {})
        finally:
            gate.abandon_credential_resolution(credential)

    def test_result_is_factory_only_noncopyable_and_nonserializable(self):
        _, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, _, _ = _components()
        prepared = self._coordinate(launcher, resolver, gate, credential)
        try:
            with self.assertRaises(TypeError):
                PreparedResolverAttempt(  # type: ignore[call-arg]
                    gate=gate,
                    credential_resolver=resolver,
                    terminal_guard=prepared._terminal_guard,
                    credential_handle=prepared.credential_handle,
                    attempt_permit=prepared.attempt_permit,
                    result_receipt=prepared.result_receipt,
                    resolution_set=prepared.resolution_set,
                    transport_claim_id=prepared.transport_claim_id,
                    dns_start_id=prepared.dns_start_id,
                )
            with self.assertRaises(TypeError):
                copy.copy(prepared)
            with self.assertRaises(TypeError):
                copy.deepcopy(prepared)
            with self.assertRaises(TypeError):
                pickle.dumps(prepared)
        finally:
            prepared.close()

    def test_production_launcher_fails_before_secret_and_abandons_permit(self):
        runtime, gate, credential = _make_authorized_credential()
        events: list[str] = []
        source = _FakeSource(events)
        resolver = CredentialResolver(source)
        launcher = ResolverHelperLauncher.production(executable=EXECUTABLE)

        with self.assertRaises(ConfigError) as raised:
            self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "resolver_helper")
        self.assertEqual(source.calls, [])
        self.assertEqual(launcher._ready_publications, {})
        self.assertTrue(credential._released)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )

    def test_secret_failure_cleans_pre_owner_without_attempt(self):
        runtime, gate, credential = _make_authorized_credential()
        components = _components(source_value=RuntimeError("source detail"))
        launcher, resolver, source, _, kernel, events = components

        with self.assertRaises(ConfigError) as raised:
            self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "credential_resolver")
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(events[:3], ["spawn", "ready_read", "credential_read"])
        self.assertNotIn("start_write", events)
        self.assertEqual(source.calls.__len__(), 1)
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )

    def test_credential_claim_normal_noop_reads_no_secret_and_cleans_all(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "credential claim transaction 未提交",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(source.calls, [])
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        credential_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(credential_state.status, "abandoned")
        self.assertIsNone(credential_state.resolver_claim_id)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_ready_consume_normal_noop_is_rejected_before_secret(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()

        with patch.object(
            ResolverHelperLauncher,
            "_consume_ready_publication",
            return_value=True,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "READY publication 未提交消费",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(source.calls, [])
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})
        credential_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(credential_state.status, "abandoned")
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_resolve_return_publication_failure_recovers_and_closes_handle(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = CredentialResolver.resolve

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic resolve return publication")

        with patch.object(
            CredentialResolver,
            "resolve",
            new=return_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "resolve return publication",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertTrue(published[0].is_closed)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        state = resolver._ledger._states[published[0]]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_lost_handle_recovery_normal_noop_uses_independent_cleanup(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = CredentialResolver.resolve

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic lost handle")

        with (
            patch.object(
                CredentialResolver,
                "resolve",
                new=return_then_raise,
            ),
            patch.object(
                CredentialResolver,
                "_recover_published_handle_for_cleanup",
                return_value=True,
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "lost handle"):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        state = resolver._ledger._states[published[0]]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertIsNone(state.permit)
        self.assertIsNone(state.gate)
        self.assertIsNone(state.publication_id)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_lost_handle_gate_recovery_noop_uses_independent_state_path(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = CredentialResolver.resolve

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic lost handle")

        with (
            patch.object(
                CredentialResolver,
                "resolve",
                new=return_then_raise,
            ),
            patch.object(
                AttemptGate,
                "_recover_resolved_credential_for_cleanup",
                return_value=True,
            ) as recovery,
        ):
            with self.assertRaisesRegex(RuntimeError, "lost handle"):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(recovery.call_count, 2)
        self.assertEqual(len(published), 1)
        handle = published[0]
        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertTrue(handle.is_closed)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        with self.assertRaises(EndpointPolicyError):
            gate.reserve_attempt(
                credential_permit=credential,
                credential_handle_id=handle.handle_id,
                credential_handle_digest=handle.handle_digest,
            )

    def test_resolve_normal_return_alias_recovers_real_handle(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = CredentialResolver.resolve

        def return_alias(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            return object()

        with patch.object(
            CredentialResolver,
            "resolve",
            new=return_alias,
        ):
            with self.assertRaises(AttributeError):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        real_handle = published[0]
        self.assertTrue(real_handle.is_closed)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        state = resolver._ledger._states[real_handle]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertIsNone(state.permit)
        self.assertIsNone(state.gate)
        self.assertIsNone(state.publication_id)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_resolve_valid_other_handle_alias_is_not_consumed(self):
        other_runtime, other_gate, other_credential = (
            _make_authorized_credential()
        )
        (
            _,
            other_resolver,
            other_source,
            _,
            other_kernel,
            other_events,
        ) = _components()
        other_handle = other_resolver.resolve(
            other_credential,
            publication_id=OTHER_CREDENTIAL_PUBLICATION_ID,
        )

        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = CredentialResolver.resolve

        def return_other_handle(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            return other_handle

        try:
            with patch.object(
                CredentialResolver,
                "resolve",
                new=return_other_handle,
            ):
                with self.assertRaises(EndpointPolicyError):
                    self._coordinate(launcher, resolver, gate, credential)

            self.assertEqual(len(published), 1)
            real_handle = published[0]
            real_state = resolver._ledger._states[real_handle]
            self.assertEqual(real_state.status, "closed")
            self.assertIsNone(real_state.secret)
            self.assertIsNone(real_state.permit)
            self.assertIsNone(real_state.gate)
            self.assertIsNone(real_state.publication_id)
            self.assertTrue(real_handle.is_closed)
            self.assertTrue(all(value == 0 for value in source.returned[0]))
            self.assertNotIn("start_write", events)
            self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})
            self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                0,
            )
            self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

            other_state = other_resolver._ledger._states[other_handle]
            self.assertEqual(other_state.status, "active")
            self.assertEqual(bytes(other_state.secret), VALID_SECRET)
            self.assertFalse(other_handle.is_closed)
            self.assertNotIn("start_write", other_events)
            self.assertEqual(_cleanup_counts(other_kernel), (0, 0, 0))
            self.assertEqual(
                other_gate.safe_metadata()["active_session_count"],
                1,
            )
            self.assertEqual(
                other_runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                1,
            )
            self.assertEqual(_consumed_budgets(other_runtime), (0, 0, 0))
        finally:
            self.assertTrue(other_resolver.close(other_handle))

        self.assertTrue(other_handle.is_closed)
        self.assertTrue(all(value == 0 for value in other_source.returned[0]))
        self.assertEqual(
            other_gate.safe_metadata()["active_session_count"],
            0,
        )
        self.assertEqual(
            other_runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )

    def test_failed_second_coordinate_cannot_recover_first_publication(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        first = resolver.resolve(
            credential,
            publication_id=CREDENTIAL_PUBLICATION_ID,
        )

        with patch(
            "snapquiz.transport.http.uuid4",
            side_effect=[OTHER_CREDENTIAL_PUBLICATION_ID],
        ):
            with self.assertRaises(EndpointPolicyError):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertFalse(first.is_closed)
        state = resolver._ledger._states[first]
        self.assertEqual(state.status, "active")
        self.assertEqual(
            state.publication_id,
            CREDENTIAL_PUBLICATION_ID,
        )
        gate_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(gate_state.status, "resolved")
        self.assertEqual(
            gate_state.resolved_publication_id,
            CREDENTIAL_PUBLICATION_ID,
        )
        self.assertEqual(len(source.calls), 1)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertFalse(
            resolver._recover_published_handle_for_cleanup(
                credential,
                publication_id=OTHER_CREDENTIAL_PUBLICATION_ID,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            resolver._recover_published_handle_for_cleanup(
                credential,
                publication_id=CREDENTIAL_PUBLICATION_ID,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(first.is_closed)
        self.assertIsNone(state.publication_id)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_launch_return_publication_failure_recovers_exact_ready_guard(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = ResolverHelperLauncher._launch_ready

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic READY return publication")

        with patch.object(
            ResolverHelperLauncher,
            "_launch_ready",
            new=return_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "READY return publication",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].safe_metadata()["state"], "terminal")
        self.assertEqual(source.calls, [])
        self.assertNotIn("credential_read", events)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_reservation_return_publication_failure_recovers_exact_owner(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, _, events = _components()
        published = []
        original = ResolverHelperLauncher._reserve_lifecycle_capability

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic READY reservation publication")

        with patch.object(
            ResolverHelperLauncher,
            "_reserve_lifecycle_capability",
            new=return_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "READY reservation publication",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(spawner.requests, [])
        self.assertEqual(source.calls, [])
        self.assertNotIn("credential_read", events)
        self.assertNotIn("start_write", events)
        self.assertTrue(credential._released)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_reservation_normal_return_alias_recovers_exact_owner(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()
        published = []
        original = ResolverHelperLauncher._reserve_lifecycle_capability

        def return_alias(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            return object()

        with patch.object(
            ResolverHelperLauncher,
            "_reserve_lifecycle_capability",
            new=return_alias,
        ):
            with self.assertRaises(EndpointPolicyError):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertEqual(spawner.requests, [])
        self.assertEqual(source.calls, [])
        self.assertNotIn("spawn", events)
        self.assertNotIn("credential_read", events)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        self.assertTrue(credential._released)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_reservation_valid_other_owner_alias_is_not_consumed(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()
        other_owner = object()
        with patch(
            "snapquiz.transport.resolver.uuid4",
            side_effect=(
                UUID("74000000-0000-0000-0000-000000000001"),
                UUID("74000000-0000-0000-0000-000000000002"),
                UUID("74000000-0000-0000-0000-000000000003"),
                UUID("74000000-0000-0000-0000-000000000004"),
            ),
        ):
            other_ticket = launcher._reserve_lifecycle_capability(
                reservation_owner=other_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )

        published = []
        original = ResolverHelperLauncher._reserve_lifecycle_capability

        def return_other_owner_ticket(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            return other_ticket

        try:
            with patch.object(
                ResolverHelperLauncher,
                "_reserve_lifecycle_capability",
                new=return_other_owner_ticket,
            ):
                with self.assertRaises(EndpointPolicyError):
                    self._coordinate(launcher, resolver, gate, credential)

            self.assertEqual(len(published), 1)
            self.assertNotIn(published[0].publication_id, launcher._ready_publications)
            other_state = launcher._ready_publications[
                other_ticket.publication_id
            ]
            self.assertIs(other_state.ticket, other_ticket)
            self.assertIs(
                other_state.capability_snapshot.reservation_owner,
                other_owner,
            )
            self.assertEqual(other_state.status, "reserved")
            self.assertIsNone(other_state.guard)
            self.assertIsNone(other_state.ledger)
            self.assertIsNone(other_state.launch_owner)
            self.assertEqual(spawner.requests, [])
            self.assertEqual(source.calls, [])
            self.assertNotIn("spawn", events)
            self.assertNotIn("credential_read", events)
            self.assertNotIn("start_write", events)
            self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
            self.assertTrue(credential._released)
            self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                0,
            )
            self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))
        finally:
            self.assertTrue(
                launcher._recover_lifecycle_reservation(
                    reservation_owner=other_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            )
        self.assertEqual(launcher._ready_publications, {})

    def test_launch_return_tamper_recovers_snapshot_guard_for_cleanup(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()
        published = []
        original = ResolverHelperLauncher._launch_ready

        def return_tamper_then_raise(selected, *args, **kwargs):
            guard = original(selected, *args, **kwargs)
            published.append(guard)
            capability = kwargs["capability"]
            object.__setattr__(
                capability,
                "publication_id",
                TAMPER_PUBLICATION_ID,
            )
            _recompute_capability_digest(capability)
            raise RuntimeError("synthetic tampered READY return publication")

        with patch.object(
            ResolverHelperLauncher,
            "_launch_ready",
            new=return_tamper_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "tampered READY return publication",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].safe_metadata()["state"], "terminal")
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(source.calls, [])
        self.assertNotIn("credential_read", events)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertTrue(credential._released)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_launch_return_guard_tamper_still_cleans_ledger_owner_in_place(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()
        published = []
        original = ResolverHelperLauncher._launch_ready

        def return_tamper_then_raise(selected, *args, **kwargs):
            guard = original(selected, *args, **kwargs)
            published.append(guard)
            object.__setattr__(guard, "lifecycle_id", TAMPER_LIFECYCLE_ID)
            raise RuntimeError("synthetic tampered READY guard return")

        with patch.object(
            ResolverHelperLauncher,
            "_launch_ready",
            new=return_tamper_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "tampered READY guard return",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].lifecycle_id, TAMPER_LIFECYCLE_ID)
        self.assertEqual(published[0].safe_metadata()["state"], "terminal")
        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(source.calls, [])
        self.assertNotIn("credential_read", events)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertTrue(credential._released)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_transfer_return_tamper_recovers_exact_terminal_owner(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = PreAttemptResolverGuard._transfer

        def return_tamper_then_raise(selected, *args, **kwargs):
            guard = original(selected, *args, **kwargs)
            published.append(guard)
            capability = selected._capability
            object.__setattr__(
                capability,
                "transport_claim_id",
                TAMPER_CLAIM_ID,
            )
            _recompute_capability_digest(capability)
            raise RuntimeError("synthetic tampered transfer return publication")

        with patch.object(
            PreAttemptResolverGuard,
            "_transfer",
            new=return_tamper_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "tampered transfer return publication",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].safe_metadata()["state"], "terminal")
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "finished")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_launch_claim_postcommit_failure_cancels_exact_invocation(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()
        original = ResolverHelperLauncher._claim_ready_launch

        def commit_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise RuntimeError("synthetic launch claim postcommit")

        with patch.object(
            ResolverHelperLauncher,
            "_claim_ready_launch",
            new=commit_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "launch claim postcommit",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(spawner.requests, [])
        self.assertEqual(source.calls, [])
        self.assertNotIn("spawn", events)
        self.assertNotIn("credential_read", events)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        self.assertTrue(credential._released)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_cancel_postcommit_fault_preserves_primary_and_cleans_guard(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()
        original_cancel = ResolverHelperLauncher._cancel_ready_launch

        def fail_publication(selected, *args, **kwargs):
            del selected, args, kwargs
            raise RuntimeError("synthetic READY publication primary")

        def cancel_then_raise(selected, *args, **kwargs):
            original_cancel(selected, *args, **kwargs)
            raise RuntimeError("synthetic cancel postcommit")

        with (
            patch.object(
                ResolverHelperLauncher,
                "_publish_ready_guard",
                new=fail_publication,
            ),
            patch.object(
                ResolverHelperLauncher,
                "_cancel_ready_launch",
                new=cancel_then_raise,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "READY publication primary",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(source.calls, [])
        self.assertNotIn("credential_read", events)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertTrue(credential._released)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_capability_tamper_rejects_before_spawn_and_owner_recovers(self):
        mutations = (
            ("publication_id", TAMPER_PUBLICATION_ID, True),
            ("lifecycle_id", TAMPER_LIFECYCLE_ID, True),
            ("transport_claim_id", TAMPER_CLAIM_ID, True),
            ("dns_start_id", TAMPER_DNS_START_ID, True),
            ("_launcher", object(), False),
            ("_reservation_owner", object(), False),
        )
        for field, replacement, recompute_digest in mutations:
            with self.subTest(field=field):
                launcher, _, _, spawner, kernel, events = _components()
                capability, reservation_owner = self._reserve_capability(
                    launcher
                )
                object.__setattr__(capability, field, replacement)
                if recompute_digest:
                    _recompute_capability_digest(capability)

                with self.assertRaises(EndpointPolicyError):
                    launcher._launch_ready(
                        capability=capability,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )

                self.assertEqual(spawner.requests, [])
                self.assertNotIn("spawn", events)
                self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
                self.assertTrue(
                    launcher._recover_lifecycle_reservation(
                        reservation_owner=reservation_owner,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )
                )
                self.assertEqual(launcher._ready_publications, {})

    def test_reserved_spawn_request_tamper_rejects_before_spawn(self):
        launcher, _, _, spawner, kernel, events = _components()
        capability, reservation_owner = self._reserve_capability(launcher)
        original_digest = launcher._request.request_digest
        object.__setattr__(
            launcher._request,
            "executable",
            "/opt/snapquiz/libexec/tampered-resolver-helper",
        )
        self.assertEqual(launcher._request.request_digest, original_digest)

        guard = None
        try:
            with _poison_real_io(), self.assertRaises(EndpointPolicyError):
                guard = launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

            self.assertEqual(spawner.requests, [])
            self.assertEqual(events, [])
            self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        finally:
            self.assertTrue(
                launcher._recover_lifecycle_reservation(
                    reservation_owner=reservation_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            )
            if guard is not None:
                guard.cleanup()

    def test_reserved_launcher_spawner_alias_rejects_before_spawn(self):
        launcher, _, _, original_spawner, original_kernel, events = (
            _components()
        )
        capability, reservation_owner = self._reserve_capability(launcher)
        replacement_events: list[str] = []
        replacement_kernel = _FakeKernel(
            replacement_events,
            result_address="8.8.8.8",
        )
        replacement_spawner = _FakeSpawner(
            replacement_kernel,
            replacement_events,
        )
        object.__setattr__(launcher, "_spawner", replacement_spawner)

        guard = None
        try:
            with _poison_real_io(), self.assertRaises(EndpointPolicyError):
                guard = launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

            self.assertEqual(original_spawner.requests, [])
            self.assertEqual(replacement_spawner.requests, [])
            self.assertEqual(events, [])
            self.assertEqual(replacement_events, [])
            self.assertEqual(_cleanup_counts(original_kernel), (0, 0, 0))
            self.assertEqual(_cleanup_counts(replacement_kernel), (0, 0, 0))
        finally:
            self.assertTrue(
                launcher._recover_lifecycle_reservation(
                    reservation_owner=reservation_owner,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            )
            if guard is not None:
                guard.cleanup()

    def test_terminal_guard_tamper_rejects_start_before_external_io(self):
        mutations = (
            ("transport_claim_id", TAMPER_CLAIM_ID),
            ("terminal_guard_id", TAMPER_DNS_START_ID),
            (
                "terminal_guard_digest",
                digest256(
                    "TamperedResolverTerminalGuard",
                    "test.v1",
                    {"field": "terminal_guard_digest"},
                ),
            ),
        )
        for field, replacement in mutations:
            with self.subTest(field=field), _poison_real_io():
                launcher, _, _, _, kernel, events = _components()
                terminal_guard = self._make_terminal_guard_for_tamper(
                    launcher
                )
                before = tuple(events)
                object.__setattr__(terminal_guard, field, replacement)
                try:
                    with self.assertRaises(EndpointPolicyError):
                        terminal_guard._start(
                            hostname="open.bigmodel.cn",
                            port=443,
                            network_policy_ref=(
                                INTERNET_PUBLIC_ADDRESS_POLICY_REF
                            ),
                            network_policy_digest=(
                                INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST
                            ),
                            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                        )
                    self.assertEqual(tuple(events), before)
                    self.assertEqual(kernel.writes, [])
                finally:
                    terminal_guard.cleanup()

    def test_terminal_guard_tamper_rejects_result_before_read_or_reap(self):
        mutations = (
            ("transport_claim_id", TAMPER_CLAIM_ID),
            ("terminal_guard_id", TAMPER_DNS_START_ID),
            (
                "terminal_guard_digest",
                digest256(
                    "TamperedResolverTerminalGuard",
                    "test.v1",
                    {"field": "terminal_guard_digest"},
                ),
            ),
        )
        for field, replacement in mutations:
            with self.subTest(field=field), _poison_real_io():
                launcher, _, _, _, kernel, events = _components()
                terminal_guard = self._make_terminal_guard_for_tamper(
                    launcher
                )
                terminal_guard._start(
                    hostname="open.bigmodel.cn",
                    port=443,
                    network_policy_ref=INTERNET_PUBLIC_ADDRESS_POLICY_REF,
                    network_policy_digest=(
                        INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST
                    ),
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
                before = tuple(events)
                object.__setattr__(terminal_guard, field, replacement)
                try:
                    with self.assertRaises(EndpointPolicyError):
                        terminal_guard._read_result_receipt(
                            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                        )
                    self.assertEqual(tuple(events), before)
                    self.assertEqual(events.count("result_read"), 0)
                    self.assertEqual(events.count("reap"), 0)
                finally:
                    terminal_guard.cleanup()

    def test_forged_capability_alias_rejects_before_spawn(self):
        launcher, _, _, spawner, kernel, events = _components()
        capability, reservation_owner = self._reserve_capability(launcher)
        forged = object.__new__(type(capability))
        for field in type(capability).__slots__:
            object.__setattr__(forged, field, getattr(capability, field))

        with self.assertRaises(EndpointPolicyError):
            launcher._launch_ready(
                capability=forged,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )

        self.assertEqual(spawner.requests, [])
        self.assertNotIn("spawn", events)
        self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        self.assertTrue(
            launcher._recover_lifecycle_reservation(
                reservation_owner=reservation_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        self.assertEqual(launcher._ready_publications, {})

    def test_capability_cross_launcher_and_replay_reject_before_spawn(self):
        launcher, _, _, spawner, kernel, _ = _components()
        other_launcher, _, _, other_spawner, other_kernel, _ = _components()
        capability, reservation_owner = self._reserve_capability(launcher)

        self.assertFalse(
            launcher._recover_lifecycle_reservation(
                reservation_owner=object(),
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        with self.assertRaises(EndpointPolicyError):
            other_launcher._launch_ready(
                capability=capability,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        self.assertEqual(spawner.requests, [])
        self.assertEqual(other_spawner.requests, [])

        winning_launch_owner = object()
        guard = launcher._launch_ready(
            capability=capability,
            launch_owner=winning_launch_owner,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertEqual(len(spawner.requests), 1)
        with self.assertRaises(EndpointPolicyError):
            launcher._launch_ready(
                capability=capability,
                launch_owner=object(),
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        self.assertEqual(len(spawner.requests), 1)
        self.assertFalse(
            launcher._recover_lifecycle_reservation(
                reservation_owner=reservation_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )

        self.assertTrue(
            launcher._recover_ready_publication_for_cleanup(
                capability,
                launch_owner=winning_launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        self.assertEqual(guard.safe_metadata()["state"], "terminal")
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(_cleanup_counts(other_kernel), (0, 0, 0))

    def test_same_capability_concurrent_launch_spawns_exactly_once(self):
        launcher, _, _, spawner, kernel, _ = _components()
        capability, _ = self._reserve_capability(launcher)
        barrier = Barrier(3)
        winners = []
        errors = []
        loser_recoveries = []

        def launch() -> None:
            launch_owner = object()
            barrier.wait()
            try:
                winners.append(
                    (
                        launcher._launch_ready(
                            capability=capability,
                            launch_owner=launch_owner,
                            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                        ),
                        launch_owner,
                    )
                )
            except BaseException as error:
                errors.append(error)
                loser_recoveries.append(
                    launcher._recover_ready_publication_for_cleanup(
                        capability,
                        launch_owner=launch_owner,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )
                )

        threads = (Thread(target=launch), Thread(target=launch))
        with _poison_real_io():
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(errors), 1)
        self.assertIs(type(errors[0]), EndpointPolicyError)
        self.assertEqual(loser_recoveries, [False])
        self.assertEqual(len(spawner.requests), 1)
        winning_guard, winning_owner = winners[0]
        self.assertTrue(
            launcher._recover_ready_publication_for_cleanup(
                capability,
                launch_owner=winning_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        self.assertEqual(winning_guard.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_reserve_return_publication_failure_recovers_and_abandons_attempt(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()
        published = []
        original = AttemptGate.reserve_attempt

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic reserve return publication")

        with patch.object(
            AttemptGate,
            "reserve_attempt",
            new=return_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "reserve return publication",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        attempt_state = gate._attempt_permits[
            published[0].attempt_permit_id
        ]
        self.assertEqual(attempt_state.status, "abandoned")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_reserve_attempt_normal_return_alias_recovers_real_attempt(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = AttemptGate.reserve_attempt

        def return_alias(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            return object()

        with patch.object(
            AttemptGate,
            "reserve_attempt",
            new=return_alias,
        ):
            with self.assertRaises(TypeError):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        real_attempt = published[0]
        self.assertTrue(real_attempt._released)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})
        attempt_state = gate._attempt_permits[real_attempt.attempt_permit_id]
        self.assertIs(attempt_state.permit, real_attempt)
        self.assertEqual(attempt_state.status, "abandoned")
        self.assertIsNone(attempt_state.transport_claim_id)
        self.assertIsNone(attempt_state.terminal_guard_id)
        self.assertIsNone(attempt_state.terminal_guard_digest)
        self.assertIsNone(attempt_state.context)
        self.assertIsNone(attempt_state.context_ledger)
        credential_state = gate._credential_permits[
            attempt_state.credential_permit_id
        ]
        self.assertEqual(credential_state.status, "finished")
        self.assertIsNone(credential_state.context)
        self.assertIsNone(credential_state.context_ledger)
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_reserve_attempt_valid_other_gate_alias_is_not_claimed(self):
        other_runtime, other_gate, other_credential = (
            _make_authorized_credential()
        )
        (
            _,
            other_resolver,
            other_source,
            _,
            _,
            other_events,
        ) = _components()
        other_handle = other_resolver.resolve(
            other_credential,
            publication_id=OTHER_CREDENTIAL_PUBLICATION_ID,
        )
        other_attempt = other_gate.reserve_attempt(
            credential_permit=other_credential,
            credential_handle_id=other_handle.handle_id,
            credential_handle_digest=other_handle.handle_digest,
        )

        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        claim_calls = []
        original_reserve = AttemptGate.reserve_attempt
        original_claim = AttemptGate._claim_attempt

        def return_other_gate_attempt(selected, *args, **kwargs):
            published.append(original_reserve(selected, *args, **kwargs))
            return other_attempt

        def record_claim(selected, permit, *args, **kwargs):
            claim_calls.append((selected, permit, kwargs.copy()))
            return original_claim(selected, permit, *args, **kwargs)

        try:
            with (
                patch.object(
                    AttemptGate,
                    "reserve_attempt",
                    new=return_other_gate_attempt,
                ),
                patch.object(
                    AttemptGate,
                    "_claim_attempt",
                    new=record_claim,
                ),
            ):
                with self.assertRaises(EndpointPolicyError):
                    self._coordinate(launcher, resolver, gate, credential)

            self.assertEqual(len(published), 1)
            real_attempt = published[0]
            real_state = gate._attempt_permits[
                real_attempt.attempt_permit_id
            ]
            self.assertEqual(real_state.status, "abandoned")
            self.assertTrue(real_attempt._released)
            self.assertEqual(len(claim_calls), 1)
            selected_gate, selected_attempt, claim_kwargs = claim_calls[0]
            self.assertIs(selected_gate, gate)
            self.assertIs(selected_attempt, other_attempt)
            self.assertIs(
                claim_kwargs["expected_credential_permit"],
                credential,
            )
            self.assertEqual(
                claim_kwargs["expected_credential_handle_id"],
                real_state.credential_handle_id,
            )
            self.assertEqual(
                claim_kwargs["expected_credential_handle_digest"],
                real_state.credential_handle_digest,
            )

            self.assertNotIn("start_write", events)
            self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
            main_handle_state = next(iter(resolver._ledger._states.values()))
            self.assertEqual(main_handle_state.status, "closed")
            self.assertIsNone(main_handle_state.secret)
            self.assertTrue(all(value == 0 for value in source.returned[0]))
            self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "in_flight_attempt_count"
                ],
                0,
            )
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                0,
            )
            self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

            other_state = other_gate._attempt_permits[
                other_attempt.attempt_permit_id
            ]
            self.assertEqual(other_state.status, "active")
            self.assertIsNone(other_state.transport_claim_id)
            self.assertIsNone(other_state.terminal_guard_id)
            self.assertIsNone(other_state.terminal_guard_digest)
            self.assertIsNone(other_state.dns_start_id)
            self.assertIsNone(other_state.credential_borrow_id)
            self.assertFalse(other_attempt._released)
            other_handle_state = other_resolver._ledger._states[other_handle]
            self.assertEqual(other_handle_state.status, "active")
            self.assertIsNotNone(other_handle_state.secret)
            self.assertEqual(bytes(other_handle_state.secret), VALID_SECRET)
            self.assertTrue(
                all(value == 0 for value in other_source.returned[0])
            )
            self.assertNotIn("start_write", other_events)
            self.assertEqual(
                other_gate.safe_metadata()["active_session_count"],
                1,
            )
            self.assertEqual(
                other_runtime.context_ledger.safe_metadata()[
                    "in_flight_attempt_count"
                ],
                1,
            )
            self.assertEqual(_consumed_budgets(other_runtime), (1, 1, 1))
        finally:
            self.assertTrue(
                other_gate.abandon_attempt(
                    other_attempt,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertTrue(other_resolver.close(other_handle))

        self.assertTrue(other_attempt._released)
        self.assertTrue(other_handle.is_closed)
        self.assertTrue(all(value == 0 for value in other_source.returned[0]))
        self.assertEqual(
            other_runtime.context_ledger.safe_metadata()[
                "in_flight_attempt_count"
            ],
            0,
        )

    def test_reserve_return_proof_tamper_cleanup_uses_attempt_ledger_snapshot(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = AttemptGate.reserve_attempt
        tampered_digest = digest256(
            "TamperedAttemptPermit",
            "test.v1",
            {"window": "reserve-return"},
        )

        def return_tamper_then_raise(selected, *args, **kwargs):
            attempt = original(selected, *args, **kwargs)
            published.append(attempt)
            object.__setattr__(
                attempt,
                "attempt_permit_digest",
                tampered_digest,
            )
            raise RuntimeError("synthetic reserve return proof tamper")

        with patch.object(
            AttemptGate,
            "reserve_attempt",
            new=return_tamper_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "reserve return proof tamper",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].attempt_permit_digest, tampered_digest)
        self.assertTrue(published[0]._released)
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertIs(attempt_state.permit, published[0])
        self.assertEqual(attempt_state.status, "abandoned")
        self.assertIsNone(attempt_state.transport_claim_id)
        self.assertIsNone(attempt_state.terminal_guard_id)
        self.assertIsNone(attempt_state.terminal_guard_digest)
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_transfer_return_publication_failure_recovers_actual_guard(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()
        published = []
        original = PreAttemptResolverGuard._transfer

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic transfer return publication")

        with patch.object(
            PreAttemptResolverGuard,
            "_transfer",
            new=return_then_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "transfer return publication",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].safe_metadata()["state"], "terminal")
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "finished")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_transfer_valid_other_terminal_guard_alias_is_not_consumed(self):
        (
            other_launcher,
            _,
            _,
            _,
            other_kernel,
            other_events,
        ) = _components()
        with _poison_real_io():
            other_guard = self._make_terminal_guard_for_tamper(
                other_launcher
            )

        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = PreAttemptResolverGuard._transfer

        def return_other_terminal_guard(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            return other_guard

        try:
            with patch.object(
                PreAttemptResolverGuard,
                "_transfer",
                new=return_other_terminal_guard,
            ):
                with self.assertRaises(EndpointPolicyError):
                    self._coordinate(launcher, resolver, gate, credential)

            self.assertEqual(len(published), 1)
            self.assertEqual(
                published[0].safe_metadata()["state"],
                "terminal",
            )
            self.assertNotIn("start_write", events)
            self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})
            attempt_state = next(iter(gate._attempt_permits.values()))
            self.assertEqual(attempt_state.status, "finished")
            handle_state = next(iter(resolver._ledger._states.values()))
            self.assertEqual(handle_state.status, "closed")
            self.assertIsNone(handle_state.secret)
            self.assertTrue(all(value == 0 for value in source.returned[0]))
            self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "in_flight_attempt_count"
                ],
                0,
            )
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                0,
            )
            self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

            self.assertEqual(other_guard.safe_metadata()["state"], "transferred")
            self.assertNotIn("start_write", other_events)
            self.assertEqual(_cleanup_counts(other_kernel), (0, 0, 0))
            self.assertEqual(other_launcher._ready_publications, {})
            self.assertEqual(len(other_launcher._lifecycle_recovery), 1)
        finally:
            self.assertTrue(other_guard.cleanup())

        self.assertEqual(other_guard.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(other_kernel), (1, 1, 1))
        self.assertEqual(other_launcher._ready_publications, {})
        self.assertEqual(other_launcher._lifecycle_recovery, {})

    def test_publication_recovery_rejects_wrong_permit_and_proofs(self):
        _, gate, credential = _make_authorized_credential()
        _, other_gate, other_credential = _make_authorized_credential()
        launcher, resolver, _, _, _, _ = _components()
        handle = resolver.resolve(
            credential,
            publication_id=CREDENTIAL_PUBLICATION_ID,
        )
        try:
            self.assertFalse(
                resolver._recover_published_handle_for_cleanup(
                    other_credential,
                    publication_id=CREDENTIAL_PUBLICATION_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertFalse(
                resolver._recover_published_handle_for_cleanup(
                    credential,
                    publication_id=OTHER_CREDENTIAL_PUBLICATION_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertFalse(
                gate._recover_published_attempt_for_cleanup(
                    credential_permit=credential,
                    credential_handle_id=handle.handle_id,
                    credential_handle_digest=handle.handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )

            attempt = gate.reserve_attempt(
                credential_permit=credential,
                credential_handle_id=handle.handle_id,
                credential_handle_digest=handle.handle_digest,
            )
            self.assertFalse(
                gate._recover_published_attempt_for_cleanup(
                    credential_permit=credential,
                    credential_handle_id=LIFECYCLE_ID,
                    credential_handle_digest=handle.handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertFalse(
                gate._recover_published_attempt_for_cleanup(
                    credential_permit=credential,
                    credential_handle_id=handle.handle_id,
                    credential_handle_digest=digest256(
                        "WrongHandleProof",
                        "test.v1",
                        {"wrong": True},
                    ),
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            capability, _ = self._reserve_capability(launcher)
            gate._claim_attempt(
                attempt,
                claim_id=capability.transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            pre_guard = launcher._launch_ready(
                capability=capability,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            self.assertTrue(
                launcher._consume_ready_publication(
                    capability,
                    pre_guard,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            )
            terminal_guard = pre_guard._transfer(
                attempt_permit_id=attempt.attempt_permit_id,
                attempt_permit_digest=attempt.attempt_permit_digest,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            self.assertFalse(
                pre_guard._recover_transferred_guard_for_cleanup(
                    attempt_permit_id=DNS_START_ID,
                    attempt_permit_digest=attempt.attempt_permit_digest,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            )
            self.assertFalse(
                pre_guard._recover_transferred_guard_for_cleanup(
                    attempt_permit_id=attempt.attempt_permit_id,
                    attempt_permit_digest=digest256(
                        "WrongAttemptProof",
                        "test.v1",
                        {"wrong": True},
                    ),
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            )
            self.assertTrue(
                pre_guard._recover_transferred_guard_for_cleanup(
                    attempt_permit_id=attempt.attempt_permit_id,
                    attempt_permit_digest=attempt.attempt_permit_digest,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )
            )
            self.assertEqual(terminal_guard.safe_metadata()["state"], "terminal")
            gate.finish_attempt(
                attempt,
                claim_id=capability.transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            resolver.close(handle)
        finally:
            other_gate.abandon_credential_resolution(other_credential)

    def test_precommit_claim_failure_abandons_attempt_and_closes_handle(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()

        with patch.object(
            AttemptGate,
            "_claim_attempt",
            side_effect=RuntimeError("synthetic claim precommit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "claim precommit"):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))
        states = tuple(resolver._ledger._states.values())
        self.assertEqual(len(states), 1)
        self.assertEqual(states[0].status, "closed")
        self.assertIsNone(states[0].secret)

    def test_claim_transaction_normal_noop_rolls_back_and_cleans_all(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        original = AttemptGate._run_authority_path

        def no_op_claim(selected, **kwargs):
            action = kwargs["final_action"]
            if "_claim_attempt.<locals>.claim" in action.__qualname__:
                return None
            return original(selected, **kwargs)

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            new=no_op_claim,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "claim transaction 未提交",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "abandoned")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)

    def test_budget_reservation_normal_noop_cleans_handle_and_context(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()

        with patch.object(
            CallContextLedger,
            "_reserve_attempt_budgets",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "reservation transaction 未提交",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(gate._attempt_permits, {})
        credential_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(credential_state.status, "abandoned")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_postcommit_claim_failure_finishes_exact_owner_without_start(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()
        original = AttemptGate._claim_attempt

        def commit_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise RuntimeError("synthetic claim postcommit")

        with patch.object(AttemptGate, "_claim_attempt", new=commit_then_raise):
            with self.assertRaisesRegex(RuntimeError, "claim postcommit"):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))
        state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)

    def test_claim_observer_failure_cannot_misclassify_normal_commit(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()

        with patch.object(
            AttemptGate,
            "_attempt_claim_is_owned",
            return_value=False,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "resolver_coordinator")
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)

    def test_postcommit_guard_bind_failure_uses_exact_guard_cleanup(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()
        original = AttemptGate._bind_terminal_guard

        def commit_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise RuntimeError("synthetic bind postcommit")

        with patch.object(
            AttemptGate,
            "_bind_terminal_guard",
            new=commit_then_raise,
        ):
            with self.assertRaisesRegex(RuntimeError, "bind postcommit"):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_guard_observer_failure_retains_normal_bind_for_cleanup(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()

        with patch.object(
            AttemptGate,
            "_terminal_guard_is_bound",
            return_value=False,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "resolver_coordinator")
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)

    def test_start_return_guard_tamper_uses_fixed_terminal_snapshot_for_cleanup(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = resolver_module.AttemptTerminalGuard._start

        def start_then_tamper_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            published.append(selected)
            object.__setattr__(
                selected,
                "terminal_guard_id",
                TAMPER_DNS_START_ID,
            )
            raise RuntimeError("synthetic START return guard tamper")

        with patch.object(
            resolver_module.AttemptTerminalGuard,
            "_start",
            new=start_then_tamper_raise,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "START return guard tamper",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(len(published), 1)
        self.assertEqual(
            published[0].terminal_guard_id,
            TAMPER_DNS_START_ID,
        )
        self.assertEqual(events.count("start_write"), 1)
        self.assertNotIn("result_read", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(published[0].safe_metadata()["state"], "terminal")
        self.assertEqual(launcher._lifecycle_recovery, {})
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "finished")
        self.assertIsNone(attempt_state.transport_claim_id)
        self.assertIsNone(attempt_state.terminal_guard_id)
        self.assertIsNone(attempt_state.terminal_guard_digest)
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_postcommit_dns_error_is_observed_but_never_starts(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()
        original = AttemptGate._commit_dns_start

        def commit_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise RuntimeError("synthetic DNS postcommit")

        with patch.object(
            AttemptGate,
            "_commit_dns_start",
            new=commit_then_raise,
        ):
            with self.assertRaisesRegex(RuntimeError, "DNS postcommit"):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_dns_transaction_normal_noop_rolls_back_and_cleans_all(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        original = AttemptGate._run_authority_path

        def no_op_dns_start(selected, **kwargs):
            action = kwargs["final_action"]
            if "_commit_dns_start.<locals>.commit" in action.__qualname__:
                return None
            return original(selected, **kwargs)

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            new=no_op_dns_start,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "DNS START transaction 未提交",
            ):
                self._coordinate(launcher, resolver, gate, credential)

        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "finished")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)

    def test_uncertain_dns_proof_blocks_start_and_cleans_every_owner(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()

        with patch.object(
            AttemptGate,
            "_dns_start_is_committed",
            return_value=False,
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "resolver_coordinator")
        self.assertNotIn("start_write", events)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

    def test_rejected_result_starts_once_then_closes_all_owned_state(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components(
            result_address="127.0.0.1"
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "address_policy")
        self.assertEqual(events.count("start_write"), 1)
        self.assertEqual(events.count("result_read"), 1)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))
        state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)

    def test_result_attestation_observer_fault_closes_gate_and_credential(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components()
        observations = []

        def fail_after_attestation(event, metadata):
            observations.append((event, metadata["state"]))
            if event == "result_attested":
                raise RuntimeError("result attestation observer fault")

        with self.assertRaisesRegex(RuntimeError, "attestation observer"):
            self._coordinate(
                launcher,
                resolver,
                gate,
                credential,
                observer=fail_after_attestation,
            )

        self.assertIn(("result_attested", "result_attested"), observations)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)

    def test_close_never_repeats_attested_helper_actions(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components()
        prepared = self._coordinate(launcher, resolver, gate, credential)
        kernel.cleanup_fault = RuntimeError("terminate must stay unreachable")

        self.assertTrue(prepared.close())
        self.assertTrue(prepared.is_closed)
        self.assertTrue(prepared.credential_handle.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        handle_state = resolver._ledger._states[prepared.credential_handle]
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)

    def test_close_uses_frozen_ledger_after_public_guard_ledger_tamper(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        prepared = self._coordinate(launcher, resolver, gate, credential)
        terminal_guard = prepared._terminal_guard
        real_ledger = prepared._terminal_guard_ledger_snapshot
        tampered_ledger = object()
        object.__setattr__(terminal_guard, "_ledger", tampered_ledger)

        self.assertIs(terminal_guard._ledger, tampered_ledger)
        self.assertFalse(real_ledger.is_terminal())
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(len(launcher._lifecycle_recovery), 1)

        self.assertTrue(prepared.close())

        self.assertTrue(prepared.is_closed)
        self.assertTrue(real_ledger.is_terminal())
        self.assertIs(terminal_guard._ledger, tampered_ledger)
        self.assertEqual(events.count("start_write"), 1)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})
        attempt_state = gate._attempt_permits[
            prepared.attempt_permit.attempt_permit_id
        ]
        credential_state = gate._credential_permits[
            attempt_state.credential_permit_id
        ]
        self.assertEqual(attempt_state.status, "finished")
        self.assertEqual(credential_state.status, "finished")
        self.assertIsNone(attempt_state.context)
        self.assertIsNone(attempt_state.context_ledger)
        self.assertIsNone(credential_state.context)
        self.assertIsNone(credential_state.context_ledger)
        handle_state = resolver._ledger._states[prepared.credential_handle]
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "in_flight_attempt_count"
            ],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))
        self.assertFalse(prepared.close())

    def test_close_uses_ledger_recovery_when_public_finish_faults(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components()
        prepared = self._coordinate(launcher, resolver, gate, credential)

        with patch.object(
            AttemptGate,
            "finish_attempt",
            side_effect=RuntimeError("synthetic finish precommit"),
        ):
            self.assertTrue(prepared.close())

        self.assertTrue(prepared.is_closed)
        self.assertTrue(prepared.credential_handle.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        handle_state = resolver._ledger._states[prepared.credential_handle]
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        attempt_state = gate._attempt_permits[
            prepared.attempt_permit.attempt_permit_id
        ]
        credential_state = gate._credential_permits[
            attempt_state.credential_permit_id
        ]
        self.assertIsNone(attempt_state.context)
        self.assertIsNone(attempt_state.context_ledger)
        self.assertIsNone(credential_state.context)
        self.assertIsNone(credential_state.context_ledger)
        self.assertFalse(prepared.close())

    def test_close_uses_private_attempt_snapshot_after_public_id_tamper(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components()
        prepared = self._coordinate(launcher, resolver, gate, credential)
        attempt_state = gate._attempt_permits[
            prepared.attempt_permit.attempt_permit_id
        ]
        credential_state = gate._credential_permits[
            attempt_state.credential_permit_id
        ]
        object.__setattr__(
            prepared.attempt_permit,
            "attempt_permit_id",
            TAMPER_PUBLICATION_ID,
        )

        self.assertTrue(prepared.close())

        self.assertTrue(prepared.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(attempt_state.status, "finished")
        self.assertEqual(credential_state.status, "finished")
        self.assertIsNone(attempt_state.context)
        self.assertIsNone(attempt_state.context_ledger)
        self.assertIsNone(credential_state.context)
        self.assertIsNone(credential_state.context_ledger)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        handle_state = resolver._ledger._states[
            prepared.credential_handle
        ]
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)

    def test_close_does_not_mistake_tampered_handle_for_terminal(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components()
        prepared = self._coordinate(launcher, resolver, gate, credential)
        handle_state = resolver._ledger._states[prepared.credential_handle]
        object.__setattr__(
            prepared.credential_handle,
            "handle_id",
            TAMPER_PUBLICATION_ID,
        )

        with patch.object(
            CredentialResolver,
            "close",
            side_effect=RuntimeError("synthetic credential close precommit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "close precommit"):
                prepared.close()

        self.assertFalse(prepared.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(handle_state.status, "active")
        self.assertIsNotNone(handle_state.secret)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )

        with self.assertRaises(EndpointPolicyError):
            prepared.close()
        self.assertTrue(prepared.is_closed)
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertFalse(prepared.close())

    def test_failure_does_not_drop_recovery_anchor_on_cleanup_fault(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components(
            close_fault=RuntimeError("synthetic close failure"),
        )

        with self.assertRaisesRegex(RuntimeError, "synthetic close failure"):
            self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            1,
        )
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "io_claimed")
        self.assertEqual(attempt_state.transport_claim_id, TRANSPORT_CLAIM_ID)
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "active")
        self.assertIsNotNone(handle_state.secret)

    def test_failure_uses_ledger_recovery_when_public_finish_faults(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components(
            result_address="127.0.0.1"
        )

        with patch.object(
            AttemptGate,
            "finish_attempt",
            side_effect=RuntimeError("synthetic finish precommit"),
        ):
            with self.assertRaises(EndpointPolicyError) as raised:
                self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "address_policy")
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "finished")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        credential_state = next(iter(gate._credential_permits.values()))
        self.assertIsNone(attempt_state.context)
        self.assertIsNone(attempt_state.context_ledger)
        self.assertIsNone(credential_state.context)
        self.assertIsNone(credential_state.context_ledger)


if __name__ == "__main__":
    unittest.main()
