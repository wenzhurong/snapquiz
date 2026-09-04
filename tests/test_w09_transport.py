"""W09-B4 cross-layer resource, fault, race, and cleanup matrix.

This suite does not turn on a production Transport.  It inventories the
independent lower-layer evidence and adds one coordinator-to-Transport fault
sweep that proves a claimed attempt retains its consumed budget, reaches a
terminal owner state, and cannot start a second socket or request.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import errno
import importlib
import os
from pathlib import Path
from threading import Lock
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from snapquiz.domain.errors import CancelledError, OperationError
from snapquiz.runtime.attempt import _TRANSPORT_ATTEMPT_AUTHORITY
from snapquiz.runtime.context import CancellationReason
from snapquiz.transport import _darwin_keychain_source as keychain_source
from snapquiz.transport import _darwin_resolver_async_adapter as resolver_adapter
from snapquiz.transport import _darwin_resolver_owner as native_resolver_owner
from snapquiz.transport import _darwin_tls_owner as native_tls_owner
from snapquiz.transport import _darwin_transport_adapter as transport_adapter
from snapquiz.transport import _exact_tls as exact_tls
from snapquiz.transport import _exact_transport as exact_transport
from snapquiz.transport import _numeric_connect as numeric_connect
from snapquiz.transport import _production_readiness as production_readiness
from snapquiz.transport import _resolver_helper_dns as resolver_helper_dns
from snapquiz.transport import _resolver_output_cache as resolver_output_cache
from snapquiz.transport import _resolver_startup_composition as startup_composition
from snapquiz.transport import _resolver_supervisor_async as supervisor_async
from snapquiz.transport.credentials import CredentialResolver
from snapquiz.transport.http import (
    PreparedResolverAttempt,
    coordinate_resolver_attempt,
    issue_resolver_cleanup_ticket,
)
from snapquiz.transport.resolver import (
    COMPLETE,
    PENDING,
    ResolverHelperLauncher,
)

from tests.test_w09_exact_transport import (
    _NumericEdge,
    _NumericFactory,
    _TlsEdge,
    _TlsFactory,
    _assert_safe,
    _drive,
    _prepared,
)
from tests.test_w09_resolver_coordinator import _consumed_budgets
from tests.test_w09_resolver_coordinator import (
    DNS_START_ID,
    EXECUTABLE,
    LIFECYCLE_ID,
    READY_PUBLICATION_ID,
    TRANSPORT_CLAIM_ID,
    _FakeSource,
    _make_authorized_credential,
)
from tests.test_w09_resolver_helper_dns import _spawn_fixture
from tests.test_w09_resolver_supervisor_async import _new_stack


_EXPECTED_LOCAL_RESOURCES = frozenset(
    {
        "attempt-budget-in-flight",
        "credential-source-buffer-view",
        "durable-output-cache-ack",
        "helper-publication-process-pipes",
        "http1-policy-digest-readiness",
        "http1-policy-digest-wire",
        "supervisor-worker-construction-publication",
        "supervisor-operation-worker-late-child",
        "resolver-control-stdout-dns",
        "resolution-candidate-set",
        "numeric-raw-socket",
        "tls-policy-context",
        "tls-socket-handoff",
        "request-secret-buffer-wire",
        "response-parser-buffer",
        "cleanup-ticket-owner-chain",
        "wait-primitive-no-persistent-selector",
        "darwin-process-local-liveness",
        "darwin-process-channel-construction",
        "darwin-event-watcher-local-liveness",
        "darwin-watcher-construction-publication",
        "darwin-peer-construction-publication",
        "darwin-monitored-session-publication",
        "startup-composition-boundaries",
        "first-byte-linearization",
        "transport-claim-race",
        "redirect-no-second-request",
        "s3-s4d-s5-coordinator-cancel-chain",
        "s3-s4d-s5-coordinator-transport-chain",
        "darwin-keychain-staged-credential-owner",
        "native-resolver-process-output-owner",
        "native-resolver-async-adapter",
        "native-numeric-socket-owner",
        "native-tls-pair-owner",
        "native-numeric-tls-transfer",
        "native-build-input-output-provenance",
        "production-readiness-native-interface-inventory",
    }
)

_EXPECTED_DIMENSIONS = frozenset(
    {
        "acquisition",
        "base_exception",
        "budget_no_refund",
        "cancel",
        "cleanup",
        "credential",
        "durability",
        "framing",
        "liveness",
        "native_ownership",
        "no_retry",
        "peer",
        "policy_drift",
        "production_readiness",
        "provenance",
        "race",
        "replay",
        "wire",
    }
)

# Every test id is deliberately unique.  The matrix is a regression inventory,
# not a replacement for the referenced executable tests.
_B4_LOCAL_COVERAGE = (
    (
        "attempt-budget-in-flight",
        ("base_exception", "budget_no_refund", "cleanup", "no_retry"),
        "tests.test_w09_transport.W09TransportB4MatrixTest."
        "test_claimed_attempt_baseexception_matrix_is_terminal_budget_burned_and_not_retried",
    ),
    (
        "credential-source-buffer-view",
        ("acquisition", "base_exception", "cleanup"),
        "tests.test_w09_credentials.W09CredentialResolverTest."
        "test_validation_base_exception_zeroizes_source_and_gate_activity",
    ),
    (
        "durable-output-cache-ack",
        ("base_exception", "cleanup", "replay"),
        "tests.test_w09_resolver_supervisor_async.ResolverSupervisorAsyncTest."
        "test_durable_ready_result_eof_are_cached_and_exactly_acked",
    ),
    (
        "helper-publication-process-pipes",
        ("acquisition", "base_exception", "cleanup"),
        "tests.test_w09_resolver_lifecycle.W09ResolverLifecycleTest."
        "test_spawn_publish_then_raise_cleans_anchored_kernel_and_registries",
    ),
    (
        "http1-policy-digest-wire",
        ("policy_drift", "wire"),
        "tests.test_w09_exact_transport.ExactTransportSuccessTest."
        "test_http1_policy_digest_is_bound_into_wire_evidence",
    ),
    (
        "http1-policy-digest-readiness",
        ("policy_drift",),
        "tests.test_w09_production_readiness."
        "ProductionReadinessAssessmentTest."
        "test_http1_attestation_digest_drift_fails_closed",
    ),
    (
        "supervisor-worker-construction-publication",
        ("acquisition", "base_exception", "cleanup", "replay"),
        "tests.test_w09_resolver_supervisor_async.ResolverSupervisorAsyncTest."
        "test_worker_construction_publication_survives_true_callee_return_event",
    ),
    (
        "supervisor-operation-worker-late-child",
        ("base_exception", "cleanup", "race"),
        "tests.test_w09_resolver_supervisor_async.ResolverSupervisorAsyncTest."
        "test_broker_crash_before_late_spawn_cleans_frozen_child_once",
    ),
    (
        "resolver-control-stdout-dns",
        ("cancel", "cleanup", "no_retry"),
        "tests.test_w09_resolver_helper_dns.ResolverHelperDnsProcessTest."
        "test_control_eof_and_second_record_terminate_blocked_resolution",
    ),
    (
        "resolution-candidate-set",
        ("framing", "peer"),
        "tests.test_w09_address_policy.W09AddressNormalizationTest."
        "test_frozen_ipv4_and_ipv6_ranges_reject_entire_set",
    ),
    (
        "numeric-raw-socket",
        ("acquisition", "base_exception", "cleanup", "no_retry"),
        "tests.test_w09_numeric_connect.NumericConnectFailureTest."
        "test_partial_acquisition_and_baseexception_matrix_closes_once",
    ),
    (
        "tls-policy-context",
        ("acquisition", "base_exception"),
        "tests.test_w09_exact_tls.ExactTlsPolicyTest."
        "test_forbidden_environment_presence_fails_before_context_creation",
    ),
    (
        "tls-socket-handoff",
        ("acquisition", "base_exception", "cleanup"),
        "tests.test_w09_exact_transport.ExactTransportPublicationRecoveryTest."
        "test_tls_factory_return_interrupt_observes_committed_handoff",
    ),
    (
        "request-secret-buffer-wire",
        ("base_exception", "cleanup", "no_retry", "wire"),
        "tests.test_w09_exact_transport.ExactTransportPendingAndWireFailureTest."
        "test_partial_wire_fault_never_reencodes_or_reconnects",
    ),
    (
        "response-parser-buffer",
        ("cleanup", "framing", "no_retry"),
        "tests.test_w09_exact_http1.ExactHttp1CodecTest."
        "test_response_requires_exact_non_ambiguous_framing",
    ),
    (
        "cleanup-ticket-owner-chain",
        ("base_exception", "cleanup", "replay"),
        "tests.test_w09_resolver_coordinator.W09ResolverCoordinatorTest."
        "test_business_primary_survives_uncertain_helper_cleanup",
    ),
    (
        "wait-primitive-no-persistent-selector",
        ("acquisition", "cleanup"),
        "tests.test_w09_transport.W09TransportB4MatrixTest."
        "test_transport_waits_acquire_no_persistent_selector_resource",
    ),
    (
        "darwin-process-local-liveness",
        ("cancel", "cleanup", "liveness"),
        "tests.test_w09_native_resolver_process.DarwinResolverProcessTests."
        "test_cancel_cleanup_terminates_reaps_and_closes_a_blocked_result",
    ),
    (
        "darwin-process-channel-construction",
        ("acquisition", "base_exception", "cleanup", "replay"),
        "tests.test_w09_native_resolver_process.DarwinResolverProcessTests."
        "test_channel_factory_return_event_is_exactly_cleaned_without_replay",
    ),
    (
        "darwin-event-watcher-local-liveness",
        ("base_exception", "cleanup", "liveness", "replay"),
        "tests.test_w09_darwin_process_events.DarwinProcessEventWatcherTests."
        "test_close_return_gap_is_poisoned_and_never_replayed",
    ),
    (
        "darwin-watcher-construction-publication",
        ("acquisition", "base_exception", "cleanup", "replay"),
        "tests.test_w09_darwin_suspended_identity."
        "DarwinSuspendedIdentityTests."
        "test_watcher_true_return_event_is_cleaned_without_rewatch_or_respawn",
    ),
    (
        "darwin-peer-construction-publication",
        ("acquisition", "base_exception", "cleanup", "replay"),
        "tests.test_w09_darwin_suspended_identity."
        "DarwinSuspendedIdentityTests."
        "test_peer_true_return_event_is_cleaned_without_reaccept_or_respawn",
    ),
    (
        "darwin-monitored-session-publication",
        ("acquisition", "base_exception", "cleanup", "liveness", "replay"),
        "tests.test_w09_darwin_suspended_identity."
        "DarwinSuspendedIdentityTests."
        "test_final_session_true_return_event_reuses_exact_session_without_io",
    ),
    (
        "startup-composition-boundaries",
        ("acquisition", "race", "replay"),
        "tests.test_w09_resolver_startup_composition.ResolverStartupCompositionTests."
        "test_concurrent_bootstrap_replay_poison_blocks_all_boundaries",
    ),
    (
        "first-byte-linearization",
        ("base_exception", "race", "replay", "wire"),
        "tests.test_w09_wire_commit.WireCommitTest."
        "test_async_interrupt_during_partial_transition_is_retryable",
    ),
    (
        "transport-claim-race",
        ("acquisition", "cleanup", "race"),
        "tests.test_w09_exact_transport.ExactTransportPendingAndWireFailureTest."
        "test_concurrent_transport_claim_has_one_wire_winner",
    ),
    (
        "redirect-no-second-request",
        ("no_retry", "wire"),
        "tests.test_w09_exact_transport.ExactTransportSuccessTest."
        "test_302_is_returned_without_redirect_retry_or_second_connect",
    ),
    (
        "s3-s4d-s5-coordinator-transport-chain",
        ("acquisition", "cleanup", "liveness", "no_retry", "wire"),
        "tests.test_w09_transport.W09TransportB4MatrixTest."
        "test_local_s3_s4d_s5_coordinator_reaches_exact_transport",
    ),
    (
        "s3-s4d-s5-coordinator-cancel-chain",
        ("budget_no_refund", "cancel", "cleanup", "liveness", "no_retry"),
        "tests.test_w09_transport.W09TransportB4MatrixTest."
        "test_local_s3_s4d_s5_cancel_after_start_reaps_without_transport",
    ),
    (
        "darwin-keychain-staged-credential-owner",
        ("acquisition", "base_exception", "cleanup", "credential", "race", "replay"),
        "tests.test_w09_keychain_credential_bridge."
        "W09KeychainCredentialBridgeTest."
        "test_persistent_ledger_zero_fault_retains_exact_retry_owner",
    ),
    (
        "native-resolver-process-output-owner",
        ("acquisition", "cleanup", "durability", "liveness", "replay"),
        "tests.test_w09_native_resolver_owner."
        "DarwinResolverOwnerFoundationTest."
        "test_output_slot_redelivers_exact_bytes_and_ack_loss_is_idempotent",
    ),
    (
        "native-resolver-async-adapter",
        ("base_exception", "cleanup", "durability", "liveness", "race", "replay"),
        "tests.test_w09_darwin_resolver_async_adapter."
        "DarwinResolverAsyncAdapterTest."
        "test_ambiguous_signal_does_not_strand_independent_cleanup_lanes",
    ),
    (
        "native-numeric-socket-owner",
        ("acquisition", "cleanup", "native_ownership", "no_retry", "peer", "replay"),
        "tests.test_w09_darwin_numeric_owner.DarwinNumericOwnerTests."
        "test_constructor_return_event_recovers_published_token_without_recreate",
    ),
    (
        "native-tls-pair-owner",
        ("acquisition", "base_exception", "cleanup", "native_ownership", "no_retry", "replay"),
        "tests.test_w09_darwin_tls_owner.DarwinTlsOwnerTests."
        "test_constructor_return_gap_retains_published_cleanup_owner",
    ),
    (
        "native-numeric-tls-transfer",
        ("acquisition", "cleanup", "native_ownership", "race", "replay", "wire"),
        "tests.test_w09_darwin_transport_adapter.DarwinTransportAdapterTests."
        "test_atomic_transfer_uses_same_raw_and_only_tls_closes_it",
    ),
    (
        "native-build-input-output-provenance",
        ("acquisition", "provenance"),
        "tests.test_w09_native_build.W09NativeBuildTest."
        "test_linker_inode_replacement_is_reopened_sealed_and_hashed",
    ),
    (
        "production-readiness-native-interface-inventory",
        ("policy_drift", "production_readiness"),
        "tests.test_w09_production_readiness.ProductionReadinessManifestTest."
        "test_required_versions_and_native_interfaces_are_exactly_frozen",
    ),
)


class _TestDurableFixtureChild:
    """Test-only durable adapter around the network-free S5 process fixture.

    The S4d unit tests independently prove publication/ACK interruption
    recovery.  This adapter only supplies a normal-path local composition: it
    accumulates the actual fixture pipe to one READY/RESULT frame, publishes it
    into the S4d cache, and clears its local slot only after an exact ACK.
    """

    def __init__(self, child, *, on_start=None) -> None:
        self.pid = child.pid
        self.child = child
        self.on_start = on_start
        self._lock = Lock()
        self._buffer = bytearray()
        self._buffer_kind: str | None = None
        self._slot = None
        self._acked_delivery_ids: set[object] = set()
        self.observe_count = 0
        self.ack_count = 0
        self.start_count = 0

    def read_stdout(self, max_bytes: int, *, max_wait_ns: int) -> object:
        return self.child.read_stdout(max_bytes, max_wait_ns=max_wait_ns)

    def observe_stdout_durable(
        self,
        max_bytes: int,
        *,
        publication,
        max_wait_ns: int,
    ) -> object:
        with self._lock:
            if self._slot is not None:
                selected = publication.publish(self._slot.payload)
                if selected is not self._slot:
                    raise AssertionError("S5 durable slot identity changed")
                return COMPLETE

            kind = publication.kind.value
            if self._buffer_kind not in (None, kind):
                raise AssertionError("S5 durable frame kind changed")
            self._buffer_kind = kind
            allowance = max_bytes - len(self._buffer)
            if allowance <= 0:
                raise AssertionError("S5 durable frame exceeds its bound")
            selected = self.child.read_stdout(
                allowance,
                max_wait_ns=max_wait_ns,
            )
            if selected is PENDING:
                return selected
            if type(selected) is not bytes or len(selected) > allowance:
                raise AssertionError("S5 fixture read contract changed")
            self._buffer.extend(selected)
            if kind == "EOF":
                if self._buffer:
                    raise AssertionError("S5 emitted trailing output")
                payload = b""
            else:
                newline = self._buffer.find(b"\n")
                if newline < 0:
                    return PENDING
                if newline != len(self._buffer) - 1:
                    raise AssertionError("S5 emitted a second output frame")
                payload = bytes(self._buffer)
            observation = publication.publish(payload)
            self._slot = observation
            self._buffer.clear()
            self._buffer_kind = None
            self.observe_count += 1
            return COMPLETE

    def ack_stdout_durable(
        self,
        observation,
        *,
        max_wait_ns: int,
    ) -> object:
        del max_wait_ns
        with self._lock:
            if observation.delivery_id in self._acked_delivery_ids:
                return COMPLETE
            if observation is not self._slot:
                raise AssertionError("S5 durable ACK owner changed")
            self._acked_delivery_ids.add(observation.delivery_id)
            self._slot = None
            self.ack_count += 1
            return COMPLETE

    def write_start_datagram(
        self,
        frame: bytes,
        *,
        max_wait_ns: int,
    ) -> object:
        selected = self.child.write_start_datagram(
            frame,
            max_wait_ns=max_wait_ns,
        )
        if selected is COMPLETE and self.start_count == 0:
            self.start_count = 1
            if self.on_start is not None:
                self.on_start()
        return selected

    def terminate_exact(self, pid: int, *, max_wait_ns: int) -> object:
        return self.child.terminate_exact(pid, max_wait_ns=max_wait_ns)

    def reap_exact(self, pid: int, *, max_wait_ns: int) -> object:
        if pid != self.pid:
            raise AssertionError("S5 exact PID changed")
        if self.child._terminate_called:
            return self.child.reap_exact(pid, max_wait_ns=max_wait_ns)
        stream = self.child.process.stdout
        if stream is None:
            raise AssertionError("S5 stdout owner is absent")
        self.child._poll(stream.fileno(), 1, max_wait_ns)
        status = self.child.process.poll()
        if status is None:
            return PENDING
        return status if status >= 0 else 256 + (-status)

    def close_exact(self, *, max_wait_ns: int) -> object:
        return self.child.close_exact(max_wait_ns=max_wait_ns)


class _FixtureSpawnWorker:
    """Spawn the actual S5 fixture only when the S4 worker is armed."""

    def __init__(self, mode: str, *, on_start=None) -> None:
        self.mode = mode
        self.on_start = on_start
        self.calls: list[object] = []
        self.child: _TestDurableFixtureChild | None = None
        self._manager = None
        self._lock = Lock()

    def spawn(self, binding, *, publication):
        with self._lock:
            publication.begin()
            if self._manager is not None or self.child is not None:
                raise AssertionError("S5 fixture spawn replay")
            self.calls.append(binding)
            manager = _spawn_fixture(self.mode)
            try:
                child = manager.__enter__()
            except BaseException:
                raise
            self._manager = manager
            self.child = _TestDurableFixtureChild(
                child,
                on_start=self.on_start,
            )
            publication.publish(self.child)
            return None

    def close(self) -> None:
        with self._lock:
            manager = self._manager
            self._manager = None
        if manager is not None:
            manager.__exit__(None, None, None)


def _coordinate_local_fixture(
    *,
    worker: _FixtureSpawnWorker,
    gate,
    credential,
    ticket,
):
    channel, spawner = _new_stack(worker)
    launcher = ResolverHelperLauncher(spawner, executable=EXECUTABLE)
    events: list[str] = []
    source = _FakeSource(events)
    credential_resolver = CredentialResolver(source)
    worker.channel = channel
    worker.source = source
    worker.credential_resolver = credential_resolver
    with (
        mock.patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("parent DNS is forbidden"),
        ),
        mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("parent connect is forbidden"),
        ),
        mock.patch(
            "snapquiz.transport.resolver.uuid4",
            side_effect=(
                READY_PUBLICATION_ID,
                LIFECYCLE_ID,
                TRANSPORT_CLAIM_ID,
                DNS_START_ID,
            ),
        ),
    ):
        prepared = coordinate_resolver_attempt(
            launcher=launcher,
            credential_resolver=credential_resolver,
            gate=gate,
            credential_permit=credential,
            cleanup_ticket=ticket,
        )
    return prepared, credential_resolver, source, channel


def _raise_interrupt(label: str):
    def selected(*args, **kwargs):
        del args, kwargs
        raise KeyboardInterrupt("b4-private-fault:" + label)

    return selected


class W09TransportB4MatrixTest(unittest.TestCase):
    def _assert_terminal_without_refund(self, bundle) -> None:
        self.assertTrue(bundle.prepared.is_closed)
        self.assertEqual(bundle.prepared.safe_metadata()["state"], "closed")
        self.assertTrue(bundle.cleanup_ticket.is_terminal)
        self.assertTrue(bundle.prepared.credential_handle.is_closed)
        self.assertTrue(bundle.credential._released)
        self.assertTrue(
            bundle.gate._attempt_is_terminal(
                bundle.prepared.attempt_permit,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertEqual(bundle.gate.safe_metadata()["active_session_count"], 0)
        self.assertEqual(_consumed_budgets(bundle.runtime), (1, 1, 1))

    def _assert_no_second_transport(self, bundle) -> None:
        second_numeric = _NumericEdge()
        second_numeric_factory = _NumericFactory(second_numeric)
        second_tls_factory = _TlsFactory()
        with self.assertRaises(OperationError) as raised:
            _drive(bundle, second_numeric_factory, second_tls_factory)
        _assert_safe(self, raised.exception)
        self.assertEqual(second_numeric_factory.calls, [])
        self.assertEqual(second_numeric.connect_calls, 0)
        self.assertEqual(second_numeric.close_calls, 0)
        self.assertEqual(second_tls_factory.calls, [])

    def test_local_s3_s4d_s5_coordinator_reaches_exact_transport(self):
        runtime, gate, credential = _make_authorized_credential()
        ticket = issue_resolver_cleanup_ticket()
        worker = _FixtureSpawnWorker("success")
        prepared = None
        try:
            prepared, credential_resolver, source, channel = (
                _coordinate_local_fixture(
                    worker=worker,
                    gate=gate,
                    credential=credential,
                    ticket=ticket,
                )
            )
            bundle = SimpleNamespace(
                runtime=runtime,
                gate=gate,
                credential=credential,
                resolver=credential_resolver,
                source=source,
                prepared=prepared,
                cleanup_ticket=ticket,
            )
            numeric = _NumericEdge()
            tls_factory = _TlsFactory()
            response = _drive(bundle, _NumericFactory(numeric), tls_factory)

            self.assertEqual(response.http_status, 200)
            self.assertEqual(response.body, b"ok")
            self.assertEqual(len(worker.calls), 1)
            self.assertIsNotNone(worker.child)
            assert worker.child is not None
            self.assertEqual(worker.child.start_count, 1)
            self.assertEqual(worker.child.observe_count, 3)
            self.assertEqual(worker.child.ack_count, 3)
            self.assertEqual(len(worker.child._acked_delivery_ids), 3)
            self.assertEqual(worker.child.child.process.returncode, 0)
            self.assertTrue(worker.child.child._closed)
            self.assertEqual(numeric.connect_calls, 1)
            self.assertEqual(numeric.close_calls, 1)
            self.assertEqual(len(tls_factory.edges), 1)
            self.assertEqual(tls_factory.edges[0].write_calls, 1)
            self.assertEqual(tls_factory.edges[0].close_calls, 1)
            self.assertFalse(channel.session_closed)
            self.assertEqual(
                channel.safe_metadata()["durable_output_slot_count"],
                0,
            )
            self._assert_terminal_without_refund(bundle)
            self._assert_no_second_transport(bundle)
        finally:
            if prepared is not None and not prepared.is_closed:
                prepared.close()
            worker.close()

    def test_local_s3_s4d_s5_cancel_after_start_reaps_without_transport(self):
        runtime, gate, credential = _make_authorized_credential()
        ticket = issue_resolver_cleanup_ticket()
        worker = _FixtureSpawnWorker(
            "block",
            on_start=lambda: runtime.cancellation_source.cancel(
                reason=CancellationReason.USER_REQUEST
            ),
        )
        numeric_factory = _NumericFactory(_NumericEdge())
        try:
            with self.assertRaises(CancelledError) as raised:
                _coordinate_local_fixture(
                    worker=worker,
                    gate=gate,
                    credential=credential,
                    ticket=ticket,
                )
            _assert_safe(self, raised.exception)
            deadline = time.monotonic() + 3
            while not ticket.is_terminal and time.monotonic() < deadline:
                ticket.retry_cleanup()
                time.sleep(0.005)

            self.assertTrue(ticket.is_terminal)
            self.assertEqual(_consumed_budgets(runtime), (1, 1, 1))
            self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
            self.assertTrue(credential._released)
            self.assertEqual(numeric_factory.calls, [])
            self.assertEqual(len(worker.calls), 1)
            self.assertIsNotNone(worker.child)
            assert worker.child is not None
            self.assertEqual(worker.child.start_count, 1)
            self.assertEqual(worker.child.observe_count, 1)
            self.assertEqual(worker.child.ack_count, 1)
            self.assertEqual(len(worker.child._acked_delivery_ids), 1)
            self.assertTrue(worker.child.child._terminate_called)
            self.assertTrue(worker.child.child._closed)
            self.assertIsNotNone(worker.child.child.process.returncode)
            self.assertTrue(all(not value for value in worker.source.returned))
            self.assertFalse(worker.channel.session_closed)
            self.assertEqual(
                worker.channel.safe_metadata()["durable_output_slot_count"],
                0,
            )
        finally:
            worker.close()

    def test_claimed_attempt_baseexception_matrix_is_terminal_budget_burned_and_not_retried(self):
        # These are the distinct resource acquisition/use boundaries after the
        # PreparedResolverAttempt has transferred ownership to Transport.
        cases = (
            "tls-policy-context",
            "numeric-edge-factory",
            "raw-set-nonblocking",
            "raw-connect",
            "raw-wait",
            "raw-so-error",
            "raw-peer",
            "tls-edge-factory",
            "tls-handshake",
            "tls-wait",
            "tls-negotiated-values",
            "credential-borrow-view",
            "request-buffer",
            "request-write",
            "response-parser",
            "response-read",
            "response-value",
        )
        for failure_point in cases:
            with self.subTest(failure_point=failure_point):
                bundle = _prepared()
                self.assertEqual(_consumed_budgets(bundle.runtime), (1, 1, 1))
                numeric = _NumericEdge()
                numeric_factory = _NumericFactory(numeric)
                tls_options: dict[str, object] = {}
                patches = ExitStack()

                if failure_point == "tls-policy-context":
                    patches.enter_context(
                        mock.patch.object(
                            exact_tls,
                            "_new_exact_tls_policy",
                            side_effect=KeyboardInterrupt(
                                "b4-private-fault:tls-policy-context"
                            ),
                        )
                    )
                elif failure_point == "numeric-edge-factory":
                    numeric_factory = _NumericFactory(
                        numeric,
                        fault=KeyboardInterrupt(
                            "b4-private-fault:numeric-edge-factory"
                        ),
                    )
                elif failure_point.startswith("raw-"):
                    fail_at = {
                        "raw-set-nonblocking": "set_nonblocking",
                        "raw-connect": "connect_once",
                        "raw-wait": "wait_writable",
                        "raw-so-error": "socket_error",
                        "raw-peer": "peername",
                    }[failure_point]
                    numeric = _NumericEdge(
                        connect_result=(
                            errno.EINPROGRESS
                            if failure_point in ("raw-wait", "raw-so-error")
                            else 0
                        ),
                        fail_at=fail_at,
                    )
                    numeric_factory = _NumericFactory(numeric)
                elif failure_point == "tls-edge-factory":
                    pass
                elif failure_point == "tls-handshake":
                    tls_options["handshake"] = (
                        KeyboardInterrupt("b4-private-fault:tls-handshake"),
                    )
                elif failure_point == "tls-wait":
                    tls_options["handshake"] = ("want_read",)
                    patches.enter_context(
                        mock.patch.object(
                            _TlsEdge,
                            "wait_ready",
                            side_effect=KeyboardInterrupt(
                                "b4-private-fault:tls-wait"
                            ),
                        )
                    )
                elif failure_point == "tls-negotiated-values":
                    tls_options["on_negotiated"] = _raise_interrupt(
                        "tls-negotiated-values"
                    )
                elif failure_point == "credential-borrow-view":
                    patches.enter_context(
                        mock.patch.object(
                            CredentialResolver,
                            "_borrow_once_with_owner",
                            side_effect=KeyboardInterrupt(
                                "b4-private-fault:credential-borrow-view"
                            ),
                        )
                    )
                elif failure_point == "request-buffer":
                    patches.enter_context(
                        mock.patch.object(
                            exact_transport.exact_http1,
                            "_encode_exact_http1_request",
                            side_effect=KeyboardInterrupt(
                                "b4-private-fault:request-buffer"
                            ),
                        )
                    )
                elif failure_point == "request-write":
                    tls_options["writes"] = (
                        KeyboardInterrupt("b4-private-fault:request-write"),
                    )
                elif failure_point == "response-parser":
                    patches.enter_context(
                        mock.patch.object(
                            exact_transport.exact_http1,
                            "_new_exact_http1_response_parser",
                            side_effect=KeyboardInterrupt(
                                "b4-private-fault:response-parser"
                            ),
                        )
                    )
                elif failure_point == "response-read":
                    tls_options["reads"] = (
                        KeyboardInterrupt("b4-private-fault:response-read"),
                    )
                elif failure_point == "response-value":
                    patches.enter_context(
                        mock.patch.object(
                            exact_transport,
                            "TransportResponse",
                            side_effect=KeyboardInterrupt(
                                "b4-private-fault:response-value"
                            ),
                        )
                    )

                tls_factory = _TlsFactory(
                    edge_options=tls_options,
                    fault=(
                        KeyboardInterrupt(
                            "b4-private-fault:tls-edge-factory"
                        )
                        if failure_point == "tls-edge-factory"
                        else None
                    ),
                )
                with patches, self.assertRaises(OperationError) as raised:
                    _drive(bundle, numeric_factory, tls_factory)
                _assert_safe(self, raised.exception)

                self.assertLessEqual(len(numeric_factory.calls), 1)
                self.assertLessEqual(numeric.connect_calls, 1)
                self.assertLessEqual(len(tls_factory.calls), 1)
                self.assertLessEqual(len(tls_factory.edges), 1)
                if tls_factory.edges:
                    self.assertLessEqual(tls_factory.edges[0].write_calls, 1)
                    self.assertEqual(tls_factory.edges[0].close_calls, 1)
                if numeric_factory.calls and failure_point != "numeric-edge-factory":
                    self.assertEqual(numeric.close_calls, 1)
                self._assert_terminal_without_refund(bundle)
                self._assert_no_second_transport(bundle)

    def test_transport_claim_fault_and_unproven_close_remain_ticket_recoverable(self):
        # A fault before Transport claim has no Transport-owned resource.  The
        # caller's ticket remains the sole recovery capability and closes the
        # already budgeted resolver attempt without opening a socket.
        bundle = _prepared()
        numeric_factory = _NumericFactory(_NumericEdge())
        with mock.patch.object(
            PreparedResolverAttempt,
            "_claim_transport",
            side_effect=KeyboardInterrupt("b4-private-fault:claim"),
        ), self.assertRaises(OperationError) as raised:
            _drive(bundle, numeric_factory, _TlsFactory())
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric_factory.calls, [])
        self.assertFalse(bundle.cleanup_ticket.is_terminal)
        self.assertEqual(bundle.prepared.safe_metadata()["state"], "active")
        self.assertEqual(_consumed_budgets(bundle.runtime), (1, 1, 1))
        self.assertTrue(bundle.cleanup_ticket.retry_cleanup())
        self._assert_terminal_without_refund(bundle)
        self._assert_no_second_transport(bundle)

        # If socket close itself is not yet externally proven, Attempt/Gate and
        # secret ownership must remain live until the same ticket observes the
        # exact resource terminal on a later cleanup-only retry.
        bundle = _prepared()
        numeric = _NumericEdge(pre_close_failures=2)
        with self.assertRaises(OperationError) as raised:
            _drive(
                bundle,
                _NumericFactory(numeric),
                _TlsFactory(
                    fault=KeyboardInterrupt("b4-private-fault:tls-factory")
                ),
            )
        _assert_safe(self, raised.exception)
        self.assertFalse(bundle.cleanup_ticket.is_terminal)
        self.assertFalse(bundle.prepared.is_closed)
        self.assertEqual(
            bundle.prepared.safe_metadata()["state"],
            "cleanup_pending",
        )
        self.assertFalse(bundle.prepared.credential_handle.is_closed)
        self.assertFalse(bundle.credential._released)
        self.assertEqual(numeric.close_calls, 0)
        self.assertEqual(_consumed_budgets(bundle.runtime), (1, 1, 1))
        self.assertTrue(bundle.cleanup_ticket.retry_cleanup())
        self.assertEqual(numeric.close_calls, 1)
        self._assert_terminal_without_refund(bundle)
        self._assert_no_second_transport(bundle)

    def test_transport_waits_acquire_no_persistent_selector_resource(self):
        root = Path(__file__).resolve().parents[1]
        modules = (
            root / "snapquiz" / "transport" / "_numeric_connect.py",
            root / "snapquiz" / "transport" / "_exact_transport.py",
        )
        select_calls: list[tuple[str, str]] = []
        for path in modules:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names
            }
            self.assertNotIn("selectors", imported)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "select"
                ):
                    select_calls.append((path.name, node.func.attr))
        self.assertEqual(
            select_calls,
            [
                ("_numeric_connect.py", "select"),
                ("_exact_transport.py", "select"),
            ],
        )

    def test_coverage_manifest_is_complete_unique_and_executable(self):
        resources = {row[0] for row in _B4_LOCAL_COVERAGE}
        dimensions = {
            dimension
            for _, row_dimensions, _ in _B4_LOCAL_COVERAGE
            for dimension in row_dimensions
        }
        test_ids = [row[2] for row in _B4_LOCAL_COVERAGE]
        self.assertEqual(resources, _EXPECTED_LOCAL_RESOURCES)
        self.assertEqual(dimensions, _EXPECTED_DIMENSIONS)
        self.assertEqual(len(test_ids), len(set(test_ids)))

        for test_id in test_ids:
            with self.subTest(test_id=test_id):
                module_name, class_name, method_name = test_id.rsplit(".", 2)
                module = importlib.import_module(module_name)
                case = getattr(module, class_name)
                self.assertTrue(issubclass(case, unittest.TestCase))
                self.assertTrue(method_name.startswith("test_"))
                self.assertTrue(callable(getattr(case, method_name)))

    def test_local_matrix_does_not_claim_production_exit_gates(self):
        self.assertFalse(
            supervisor_async.PRODUCTION_DURABLE_OUTPUT_INTEGRATION_AVAILABLE
        )
        self.assertFalse(
            startup_composition.PRODUCTION_STARTUP_INTEGRATION_AVAILABLE
        )
        self.assertFalse(numeric_connect.PRODUCTION_GATE_INTEGRATION_AVAILABLE)
        self.assertFalse(numeric_connect.OPAQUE_NUMERIC_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(exact_transport.PRODUCTION_APP_INTEGRATION_AVAILABLE)
        self.assertFalse(exact_transport.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(resolver_helper_dns._PRODUCTION_AVAILABLE)
        self.assertFalse(
            resolver_output_cache.PRODUCTION_DURABLE_OUTPUT_CONTRACT_AVAILABLE
        )
        self.assertFalse(
            keychain_source.PRODUCTION_DARWIN_KEYCHAIN_SOURCE_AVAILABLE
        )
        self.assertFalse(
            native_resolver_owner.PRODUCTION_NATIVE_RESOLVER_OWNER_AVAILABLE
        )
        self.assertFalse(
            resolver_adapter.PRODUCTION_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE
        )
        self.assertFalse(native_tls_owner.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(
            transport_adapter.DARWIN_NATIVE_TRANSFER_ADAPTER_PRODUCTION_AVAILABLE
        )
        self.assertFalse(
            production_readiness.PRODUCTION_READINESS_AUTHORITY_AVAILABLE
        )
        self.assertFalse(
            production_readiness.PRODUCTION_TRANSPORT_INTEGRATION_AVAILABLE
        )


if __name__ == "__main__":
    unittest.main()
