"""Offline tests for the sole W09-B2a resolver coordinator."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import timedelta
import copy
import json
import pickle
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
from snapquiz.transport.address_policy import (
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
    ) -> None:
        self._chunks = [READY_FRAME]
        self.events = events
        self.writes: list[bytes] = []
        self.result_address = result_address
        self.cleanup_fault = cleanup_fault

    def read_stdout(self, max_bytes: int) -> bytes:
        self.events.append(
            "ready_read" if not self.writes else "result_read"
        )
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

    def reap(self) -> None:
        self.events.append("reap")

    def close_pipes(self) -> None:
        self.events.append("close_pipes")


class _FakeSpawner:
    def __init__(self, kernel: _FakeKernel, events: list[str]) -> None:
        self.kernel = kernel
        self.events = events
        self.requests = []

    def spawn(self, request):
        self.events.append("spawn")
        self.requests.append(request)
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
):
    events: list[str] = []
    kernel = _FakeKernel(
        events,
        result_address=result_address,
        cleanup_fault=cleanup_fault,
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
    def _coordinate(self, launcher, resolver, gate, credential):
        with _poison_real_io():
            return coordinate_resolver_attempt(
                launcher=launcher,
                credential_resolver=resolver,
                gate=gate,
                credential_permit=credential,
                lifecycle_id=LIFECYCLE_ID,
                transport_claim_id=TRANSPORT_CLAIM_ID,
                dns_start_id=DNS_START_ID,
            )

    def test_strict_order_exact_proofs_and_explicit_close(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, spawner, kernel, events = _components()

        prepared = self._coordinate(launcher, resolver, gate, credential)

        self.assertIs(type(prepared), PreparedResolverAttempt)
        self.assertEqual(
            events[:5],
            [
                "spawn",
                "ready_read",
                "credential_read",
                "start_write",
                "result_read",
            ],
        )
        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(len(source.calls), 1)
        self.assertTrue(all(value == 0 for value in source.returned[0]))
        self.assertEqual(len(kernel.writes), 1)
        start = json.loads(kernel.writes[0])
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
        self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

        self.assertTrue(prepared.close())
        self.assertFalse(prepared.close())
        self.assertTrue(prepared.is_closed)
        self.assertTrue(prepared.credential_handle.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))

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
                    transport_claim_id=TRANSPORT_CLAIM_ID,
                    dns_start_id=DNS_START_ID,
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

        with _poison_real_io(), self.assertRaises(ConfigError) as raised:
            coordinate_resolver_attempt(
                launcher=launcher,
                credential_resolver=resolver,
                gate=gate,
                credential_permit=credential,
                lifecycle_id=LIFECYCLE_ID,
                transport_claim_id=TRANSPORT_CLAIM_ID,
                dns_start_id=DNS_START_ID,
            )

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

    def test_failed_second_coordinate_cannot_recover_first_publication(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        first = resolver.resolve(
            credential,
            publication_id=CREDENTIAL_PUBLICATION_ID,
        )

        with patch(
            "snapquiz.transport.http.uuid4",
            side_effect=[
                READY_PUBLICATION_ID,
                OTHER_CREDENTIAL_PUBLICATION_ID,
            ],
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
        self.assertIsNone(
            resolver._recover_published_handle(
                credential,
                publication_id=OTHER_CREDENTIAL_PUBLICATION_ID,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertIs(
            resolver._recover_published_handle(
                credential,
                publication_id=CREDENTIAL_PUBLICATION_ID,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            ),
            first,
        )
        self.assertTrue(resolver.close(first))
        self.assertTrue(first.is_closed)
        self.assertIsNone(state.publication_id)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(_consumed_budgets(runtime), (0, 0, 0))

    def test_launch_return_publication_failure_recovers_exact_ready_guard(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, source, _, kernel, events = _components()
        published = []
        original = ResolverHelperLauncher.launch_ready

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic READY return publication")

        with patch.object(
            ResolverHelperLauncher,
            "launch_ready",
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
        original = ResolverHelperLauncher._reserve_ready_publication

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic READY reservation publication")

        with patch.object(
            ResolverHelperLauncher,
            "_reserve_ready_publication",
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

    def test_ready_publication_collision_and_wrong_guard_fail_closed(self):
        launcher, _, _, spawner, kernel, _ = _components()
        other_launcher, _, _, _, other_kernel, _ = _components()
        reservation_owner = object()
        ticket = launcher._reserve_ready_publication(
            publication_id=READY_PUBLICATION_ID,
            lifecycle_id=LIFECYCLE_ID,
            reservation_owner=reservation_owner,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        guard = launcher.launch_ready(
            lifecycle_id=LIFECYCLE_ID,
            publication_ticket=ticket,
        )
        self.assertEqual(len(spawner.requests), 1)

        with self.assertRaises(EndpointPolicyError):
            launcher._reserve_ready_publication(
                publication_id=READY_PUBLICATION_ID,
                lifecycle_id=LIFECYCLE_ID,
                reservation_owner=object(),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        self.assertEqual(len(spawner.requests), 1)
        self.assertFalse(
            launcher._recover_ready_reservation(
                publication_id=READY_PUBLICATION_ID,
                lifecycle_id=LIFECYCLE_ID,
                reservation_owner=object(),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

        wrong_guard = other_launcher.launch_ready(
            lifecycle_id=LIFECYCLE_ID,
        )
        try:
            self.assertFalse(
                launcher._consume_ready_publication(
                    ticket,
                    wrong_guard,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertIs(
                launcher._recover_ready_publication(
                    ticket,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                ),
                guard,
            )
            self.assertEqual(launcher._ready_publications, {})
        finally:
            guard.cleanup()
            wrong_guard.cleanup()
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(_cleanup_counts(other_kernel), (1, 1, 1))

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

    def test_transfer_return_publication_failure_recovers_actual_guard(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, events = _components()
        published = []
        original = PreAttemptResolverGuard.transfer

        def return_then_raise(selected, *args, **kwargs):
            published.append(original(selected, *args, **kwargs))
            raise RuntimeError("synthetic transfer return publication")

        with patch.object(
            PreAttemptResolverGuard,
            "transfer",
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

    def test_publication_recovery_rejects_wrong_permit_and_proofs(self):
        _, gate, credential = _make_authorized_credential()
        _, other_gate, other_credential = _make_authorized_credential()
        launcher, resolver, _, _, _, _ = _components()
        handle = resolver.resolve(
            credential,
            publication_id=CREDENTIAL_PUBLICATION_ID,
        )
        try:
            self.assertIsNone(
                resolver._recover_published_handle(
                    other_credential,
                    publication_id=CREDENTIAL_PUBLICATION_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertIsNone(
                resolver._recover_published_handle(
                    credential,
                    publication_id=OTHER_CREDENTIAL_PUBLICATION_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertIs(
                resolver._recover_published_handle(
                    credential,
                    publication_id=CREDENTIAL_PUBLICATION_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                ),
                handle,
            )
            self.assertIsNone(
                gate._recover_published_attempt(
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
            self.assertIsNone(
                gate._recover_published_attempt(
                    credential_permit=credential,
                    credential_handle_id=LIFECYCLE_ID,
                    credential_handle_digest=handle.handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertIsNone(
                gate._recover_published_attempt(
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
            self.assertIs(
                gate._recover_published_attempt(
                    credential_permit=credential,
                    credential_handle_id=handle.handle_id,
                    credential_handle_digest=handle.handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                ),
                attempt,
            )

            gate._claim_attempt(
                attempt,
                claim_id=TRANSPORT_CLAIM_ID,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            pre_guard = launcher.launch_ready(lifecycle_id=LIFECYCLE_ID)
            terminal_guard = pre_guard.transfer(
                attempt_permit_id=attempt.attempt_permit_id,
                attempt_permit_digest=attempt.attempt_permit_digest,
                transport_claim_id=TRANSPORT_CLAIM_ID,
            )
            self.assertIsNone(
                pre_guard._recover_transferred_guard(
                    attempt_permit_id=attempt.attempt_permit_id,
                    attempt_permit_digest=attempt.attempt_permit_digest,
                    transport_claim_id=DNS_START_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertIsNone(
                pre_guard._recover_transferred_guard(
                    attempt_permit_id=attempt.attempt_permit_id,
                    attempt_permit_digest=digest256(
                        "WrongAttemptProof",
                        "test.v1",
                        {"wrong": True},
                    ),
                    transport_claim_id=TRANSPORT_CLAIM_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertIs(
                pre_guard._recover_transferred_guard(
                    attempt_permit_id=attempt.attempt_permit_id,
                    attempt_permit_digest=attempt.attempt_permit_digest,
                    transport_claim_id=TRANSPORT_CLAIM_ID,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                ),
                terminal_guard,
            )
            terminal_guard.cleanup()
            gate.finish_attempt(
                attempt,
                claim_id=TRANSPORT_CLAIM_ID,
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
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))
        state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)

    def test_close_keeps_gate_and_handle_when_helper_cleanup_is_unproven(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components(
            cleanup_fault=RuntimeError("synthetic terminate failure")
        )
        prepared = self._coordinate(launcher, resolver, gate, credential)

        with self.assertRaises(EndpointPolicyError) as raised:
            prepared.close()

        self.assertEqual(raised.exception.stage, "resolver_helper")
        self.assertFalse(prepared.is_closed)
        self.assertFalse(prepared.credential_handle.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            1,
        )
        attempt_state = gate._attempt_permits[
            prepared.attempt_permit.attempt_permit_id
        ]
        self.assertEqual(attempt_state.status, "io_claimed")
        self.assertEqual(attempt_state.transport_claim_id, TRANSPORT_CLAIM_ID)
        handle_state = resolver._ledger._states[prepared.credential_handle]
        self.assertEqual(handle_state.status, "active")
        self.assertIsNotNone(handle_state.secret)

    def test_close_retains_handle_until_attempt_finish_is_proven(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components()
        prepared = self._coordinate(launcher, resolver, gate, credential)

        with patch.object(
            AttemptGate,
            "finish_attempt",
            side_effect=RuntimeError("synthetic finish precommit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "finish precommit"):
                prepared.close()

        self.assertFalse(prepared.is_closed)
        self.assertFalse(prepared.credential_handle.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            1,
        )
        handle_state = resolver._ledger._states[prepared.credential_handle]
        self.assertEqual(handle_state.status, "active")
        self.assertIsNotNone(handle_state.secret)

        self.assertTrue(prepared.close())
        self.assertTrue(prepared.is_closed)
        self.assertTrue(prepared.credential_handle.is_closed)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )

    def test_failure_does_not_drop_recovery_anchor_on_cleanup_fault(self):
        runtime, gate, credential = _make_authorized_credential()
        launcher, resolver, _, _, kernel, _ = _components(
            result_address="127.0.0.1",
            cleanup_fault=RuntimeError("synthetic terminate failure"),
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            self._coordinate(launcher, resolver, gate, credential)

        self.assertEqual(raised.exception.stage, "address_policy")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
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

    def test_failure_retains_handle_when_gate_finish_is_unproven(self):
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
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            1,
        )
        attempt_state = next(iter(gate._attempt_permits.values()))
        self.assertEqual(attempt_state.status, "io_claimed")
        handle_state = next(iter(resolver._ledger._states.values()))
        self.assertEqual(handle_state.status, "active")
        self.assertIsNotNone(handle_state.secret)


if __name__ == "__main__":
    unittest.main()
