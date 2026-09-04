"""Pure W09-B2b-S1 broker/proxy supervisor contract tests."""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import subprocess
import sys
from threading import Event, Thread
import time
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_supervisor_contract as supervisor


EPOCH_ID = UUID("82000000-0000-0000-0000-000000000001")
OPERATION_ID = UUID("82000000-0000-0000-0000-000000000002")
LIFECYCLE_ID = UUID("82000000-0000-0000-0000-000000000003")
PUBLICATION_ID = UUID("82000000-0000-0000-0000-000000000004")
PROOF_ID = UUID("82000000-0000-0000-0000-000000000005")
PROXY_ID = UUID("82000000-0000-0000-0000-000000000013")
ATTACH_ID = UUID("82000000-0000-0000-0000-000000000006")
ARM_ID = UUID("82000000-0000-0000-0000-000000000007")
CANCEL_ID = UUID("82000000-0000-0000-0000-000000000008")
SPAWN_ID = UUID("82000000-0000-0000-0000-000000000009")
READY_ID = UUID("82000000-0000-0000-0000-00000000000a")
START_ID = UUID("82000000-0000-0000-0000-00000000000b")
RESULT_ID = UUID("82000000-0000-0000-0000-00000000000c")
TERMINAL_ID = UUID("82000000-0000-0000-0000-00000000000d")
RELEASE_ID = UUID("82000000-0000-0000-0000-00000000000e")
TERMINATE_ID = UUID("82000000-0000-0000-0000-00000000000f")
REAP_ID = UUID("82000000-0000-0000-0000-000000000010")
CLOSE_ID = UUID("82000000-0000-0000-0000-000000000011")
OTHER_ID = UUID("82000000-0000-0000-0000-000000000012")
SPAWN_DIGEST = Digest256("a" * 64)
CANCEL_DIGEST = Digest256("b" * 64)
OTHER_CANCEL_DIGEST = Digest256("c" * 64)
RESULT_DIGEST = Digest256("d" * 64)
START_DIGEST = Digest256("f" * 64)
EOF_ACK_DIGEST = Digest256("e" * 64)
_SESSIONS_BY_PROXY = {}


class _BrokerHarness:
    _CONTROL = {
        "arm",
        "attach",
        "cancel",
        "query",
        "query_reply",
        "release",
        "reserve",
    }
    _EVENTS = {
        "claim_start",
        "commit_start",
        "complete_spawn",
        "mark_ready",
        "mark_result",
        "mark_success_cleanup_ready",
    }
    _CLEANUP = {
        "attest_terminal",
        "claim_close",
        "claim_reap",
        "claim_terminate",
        "compact_released",
        "complete_close",
        "complete_reap",
        "complete_terminate",
        "poison_epoch",
        "released_tombstone",
    }

    def __init__(self, ports):
        self.ports = ports

    def __getattr__(self, name):
        if name in self._CONTROL:
            return getattr(self.ports.control, name)
        if name in self._EVENTS:
            return getattr(self.ports.events, name)
        if name in self._CLEANUP:
            return getattr(self.ports.cleanup, name)
        return getattr(self.ports.ledger, name)


def _binding(**overrides):
    values = {
        "epoch_id": EPOCH_ID,
        "operation_id": OPERATION_ID,
        "lifecycle_id": LIFECYCLE_ID,
        "publication_id": PUBLICATION_ID,
        "spawn_request_digest": SPAWN_DIGEST,
    }
    values.update(overrides)
    return supervisor._new_supervisor_operation_binding(**values)


def _query_id(index):
    return UUID(int=0x82000000000000000000000000000100 + index)


def _redigest(attestation):
    selected = digest256(
        "ResolverSupervisorOperationAttestation",
        supervisor.SUPERVISOR_ATTESTATION_SCHEMA_VERSION,
        supervisor._attestation_payload(attestation),
    )
    object.__setattr__(attestation, "attestation_digest", selected)
    object.__setattr__(attestation, "_issued_digest", selected)
    return attestation


def _reserved_with_session():
    binding = _binding()
    ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
    broker = _BrokerHarness(ports)
    reserved = broker.reserve(binding)
    session = ports.parent_session
    proxy, publication = session.prepare_proxy(
        reservation=reserved,
        proxy_id=PROXY_ID,
        proof_id=PROOF_ID,
    )
    _SESSIONS_BY_PROXY[id(proxy)] = session
    return binding, broker, proxy, publication, reserved, session


def _reserved():
    binding, broker, proxy, publication, reserved, _ = _reserved_with_session()
    return binding, broker, proxy, publication, reserved


def _attached(*, acknowledge: bool = True):
    binding, broker, proxy, publication, _ = _reserved()
    publication.commit(proxy)
    proof = publication.observe(proxy)
    proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
    attached = broker.attach(
        binding,
        proof=proof,
        command_id=ATTACH_ID,
    )
    if acknowledge:
        proxy.observe_attach_ack(attached)
    return binding, broker, proxy, publication, attached


def _armed(*, acknowledge: bool = True):
    binding, broker, proxy, publication, _ = _attached()
    proxy.begin_arm(command_id=ARM_ID)
    armed = broker.arm(binding, command_id=ARM_ID)
    if acknowledge:
        proxy.observe_arm_ack(armed)
    return binding, broker, proxy, publication, armed


def _child_owned():
    binding, broker, proxy, publication, _ = _armed()
    child = broker.complete_spawn(
        binding,
        event_id=SPAWN_ID,
        child_created=True,
    )
    proxy.observe_status(child)
    return binding, broker, proxy, publication, child


def _ready():
    binding, broker, proxy, publication, _ = _child_owned()
    ready = broker.mark_ready(binding, event_id=READY_ID)
    proxy.observe_status(ready)
    return binding, broker, proxy, publication, ready


def _cancelled_child():
    binding, broker, proxy, publication, _ = _armed()
    proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
    cancelled = broker.cancel(
        binding,
        command_id=CANCEL_ID,
        payload_digest=CANCEL_DIGEST,
    )
    proxy.observe_cancel_ack(cancelled)
    child = broker.complete_spawn(
        binding,
        event_id=SPAWN_ID,
        child_created=True,
    )
    proxy.observe_status(child)
    return binding, broker, proxy, publication, child


def _finish_cancelled_child(binding, broker, proxy):
    broker.claim_terminate(binding, action_id=TERMINATE_ID)
    broker.complete_terminate(binding, action_id=TERMINATE_ID)
    broker.claim_reap(binding, action_id=REAP_ID)
    broker.complete_reap(binding, action_id=REAP_ID)
    broker.claim_close(binding, action_id=CLOSE_ID)
    broker.complete_close(binding, action_id=CLOSE_ID)
    terminal = broker.attest_terminal(
        binding,
        attestation_id=TERMINAL_ID,
        status=256 + 9,
    )
    proxy.observe_status(terminal)
    return terminal


def _released_for_compaction():
    binding, broker, proxy, publication, _ = _attached()
    proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
    proxy.observe_cancel_ack(
        broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
    )
    proxy.begin_release(tombstone_id=RELEASE_ID)
    released = broker.release(binding, tombstone_id=RELEASE_ID)
    proxy.observe_release_ack(released)
    return binding, broker, proxy, publication, released


class ResolverSupervisorContractTest(unittest.TestCase):
    def test_module_is_private_dependency_isolated_and_pure(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_resolver_supervisor_contract.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertEqual(
            imported,
            {
                "__future__",
                "enum",
                "snapquiz.domain._validation",
                "snapquiz.domain.digest",
                "snapquiz.domain.errors",
                "threading",
                "typing",
                "uuid",
            },
        )
        script = """
import builtins
import importlib
import os
import socket
import subprocess
import sys
import time
from unittest.mock import patch

import snapquiz.transport
before = set(sys.modules)

def forbidden(*args, **kwargs):
    raise AssertionError((args, kwargs))

with patch.object(builtins, 'open', side_effect=forbidden), patch.object(
    socket, 'socket', side_effect=forbidden
), patch.object(subprocess, 'Popen', side_effect=forbidden), patch.object(
    time, 'monotonic_ns', side_effect=forbidden
), patch.object(os, 'getenv', side_effect=forbidden):
    module = importlib.import_module(
        'snapquiz.transport._resolver_supervisor_contract'
    )

new_modules = set(sys.modules) - before
assert new_modules == {
    'snapquiz.transport._resolver_supervisor_contract'
}, sorted(new_modules)
assert module.__all__ == ()
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=source_path.parents[2],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("pure supervisor contract touched external I/O")

        with patch("builtins.open", side_effect=forbidden), patch(
            "socket.socket", side_effect=forbidden
        ), patch("subprocess.Popen", side_effect=forbidden), patch(
            "time.monotonic_ns", side_effect=forbidden
        ), patch("os.getenv", side_effect=forbidden):
            binding, broker, proxy, publication, snapshot = _reserved()
            self.assertEqual(snapshot.state.value, "reserved")
            self.assertFalse(publication.safe_metadata()["committed"])
            self.assertFalse(proxy.safe_metadata()["business_allowed"])
            self.assertEqual(broker.safe_metadata()["operation_count"], 1)

    def test_state_vocabularies_and_value_objects_are_frozen(self):
        self.assertEqual(
            {state.value for state in supervisor._BrokerOperationState},
            {
                "reserved",
                "attached",
                "spawn_inflight",
                "cancel_wait_spawn",
                "child_owned",
                "ready",
                "started",
                "result_pending_terminal",
                "terminal_attested",
                "released",
                "poisoned",
            },
        )
        self.assertEqual(
            {state.value for state in supervisor._ParentProxyState},
            {
                "attach_unknown",
                "attached_unarmed",
                "arm_unknown",
                "active",
                "cancel_not_attested",
                "cancel_latched_wait_terminal",
                "terminal_attested",
                "release_not_attested",
                "released",
                "poisoned",
            },
        )
        binding, broker, _, _, snapshot = _reserved()
        self.assertIs(copy.copy(binding), binding)
        self.assertIs(copy.deepcopy(binding), binding)
        self.assertIs(copy.copy(snapshot), snapshot)
        self.assertIs(copy.deepcopy(snapshot), snapshot)
        with self.assertRaises(AttributeError):
            binding.operation_id = OTHER_ID
        with self.assertRaises(AttributeError):
            snapshot.revision = 99
        with self.assertRaises(TypeError):
            class ForgedBinding(supervisor._SupervisorOperationBinding):
                pass
        with self.assertRaises(TypeError):
            class ForgedAttestation(supervisor._SupervisorOperationAttestation):
                pass
        object.__setattr__(binding, "operation_id", OTHER_ID)
        with self.assertRaises(ValueError):
            binding.validate_integrity()
        self.assertEqual(broker.safe_metadata()["operation_count"], 1)

    def test_broker_control_event_and_cleanup_roles_are_not_interchangeable(self):
        ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        other_ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        binding = _binding()
        with self.assertRaises(TypeError):
            ports.ledger.reserve(binding)
        reserved = ports.control.reserve(binding)
        self.assertEqual(reserved.state.value, "reserved")
        with self.assertRaises(TypeError):
            ports.ledger.complete_spawn(
                binding,
                event_id=SPAWN_ID,
                child_created=True,
                _authority=ports.control,
            )
        with self.assertRaises(AttributeError):
            ports.events.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        with self.assertRaises(TypeError):
            supervisor._SupervisorBrokerLedger(epoch_id=EPOCH_ID)
        with self.assertRaises(TypeError):
            ports.ledger.reserve(binding, _authority=other_ports.control)
        with self.assertRaises(TypeError):
            ports.ledger.complete_spawn(
                binding,
                event_id=SPAWN_ID,
                child_created=True,
                _authority=other_ports.events,
            )
        with self.assertRaises(TypeError):
            ports.ledger.poison_epoch(
                reason=supervisor._PoisonReason.LIVENESS_LOST,
                _authority=other_ports.cleanup,
            )
        self.assertFalse(ports.ledger.safe_metadata()["poisoned"])

    def test_reserve_is_zero_child_content_bound_and_idempotent(self):
        binding, broker, _, _, reserved = _reserved()
        replay = broker.reserve(binding)
        self.assertEqual(reserved.revision, 0)
        self.assertEqual(replay.revision, 0)
        self.assertEqual(replay.attestation_digest, reserved.attestation_digest)
        self.assertFalse(replay.child_ever_owned)
        self.assertIsNone(replay.arm_command_id)
        self.assertFalse(replay.start_committed)
        self.assertEqual(broker.safe_metadata()["operation_count"], 1)

    def test_parent_session_rejects_stale_reserved_snapshot_without_poisoning_terminal(self):
        binding = _binding()
        ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        broker = _BrokerHarness(ports)
        reserved = broker.reserve(binding)
        terminal = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        self.assertEqual(terminal.state.value, "terminal_attested")

        with self.assertRaises(EndpointPolicyError):
            ports.parent_session.prepare_proxy(
                reservation=reserved,
                proxy_id=PROXY_ID,
                proof_id=PROOF_ID,
            )

        current = broker.query(binding)
        self.assertEqual(current.state.value, "terminal_attested")
        self.assertEqual(current.poison_reason, None)
        released = broker.release(binding, tombstone_id=RELEASE_ID)
        self.assertEqual(released.state.value, "released")

    def test_publication_noop_or_failure_cannot_attach_or_arm(self):
        for failure in ("noop", "raise"):
            with self.subTest(failure=failure):
                binding, broker, proxy, publication, _ = _reserved()
                if failure == "raise":
                    with self.assertRaises(RuntimeError):
                        raise RuntimeError("synthetic publication failure")
                with self.assertRaises(EndpointPolicyError):
                    publication.observe(proxy)
                with self.assertRaises(EndpointPolicyError):
                    broker.arm(binding, command_id=ARM_ID)
                poisoned = broker.query(binding)
                self.assertEqual(poisoned.state.value, "poisoned")
                self.assertFalse(poisoned.child_ever_owned)
                self.assertIsNone(poisoned.arm_command_id)

    def test_commit_then_raise_remains_observable_for_exact_attach(self):
        binding, broker, proxy, publication, _ = _reserved()
        try:
            publication.commit(proxy)
            raise RuntimeError("synthetic post-commit failure")
        except RuntimeError:
            pass
        proof = publication.observe(proxy)
        proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
        attached = broker.attach(binding, proof=proof, command_id=ATTACH_ID)
        proxy.observe_attach_ack(attached)
        self.assertEqual(attached.state.value, "attached")
        self.assertEqual(proxy.safe_metadata()["state"], "attached_unarmed")
        self.assertIs(publication.observe(proxy), proof)
        self.assertEqual(
            broker.attach(
                binding,
                proof=proof,
                command_id=ATTACH_ID,
            ).revision,
            attached.revision,
        )

    def test_attach_ack_loss_requires_query_attestation_before_arm(self):
        binding, broker, proxy, _, attached = _attached(acknowledge=False)
        self.assertEqual(proxy.safe_metadata()["state"], "attach_unknown")
        with self.assertRaises(EndpointPolicyError):
            proxy.require_business_allowed()
        proxy.observe_status(broker.query(binding))
        self.assertEqual(proxy.safe_metadata()["state"], "attached_unarmed")
        proxy.begin_arm(command_id=ARM_ID)
        armed = broker.arm(binding, command_id=ARM_ID)
        proxy.observe_arm_ack(armed)
        self.assertEqual(proxy.safe_metadata()["state"], "active")
        self.assertEqual(attached.revision + 1, armed.revision)

    def test_happy_attach_arm_submits_spawn_once_without_child(self):
        binding, broker, proxy, _, armed = _armed()
        replay = broker.arm(binding, command_id=ARM_ID)
        self.assertEqual(armed.state.value, "spawn_inflight")
        self.assertEqual(replay.revision, armed.revision)
        self.assertFalse(armed.child_ever_owned)
        self.assertEqual(proxy.safe_metadata()["state"], "active")
        proxy.require_business_allowed()

    def test_arm_ack_loss_requires_exact_query_and_never_rearms(self):
        binding, broker, proxy, _, armed = _armed(acknowledge=False)
        self.assertEqual(proxy.safe_metadata()["state"], "arm_unknown")
        proxy.observe_status(broker.query(binding))
        self.assertEqual(proxy.safe_metadata()["state"], "active")
        proxy.require_business_allowed()
        with self.assertRaises(EndpointPolicyError):
            proxy.begin_arm(command_id=ARM_ID)
        self.assertEqual(proxy.safe_metadata()["state"], "poisoned")
        self.assertEqual(broker.query(binding).revision, armed.revision)

    def test_cancel_ack_loss_allows_only_exact_replay_or_query(self):
        binding, broker, proxy, _, _ = _armed()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        cancelled = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        self.assertEqual(proxy.safe_metadata()["state"], "cancel_not_attested")
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        replay = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        self.assertEqual(replay.revision, cancelled.revision)
        proxy.observe_status(broker.query(binding))
        self.assertEqual(
            proxy.safe_metadata()["state"],
            "cancel_latched_wait_terminal",
        )
        with self.assertRaises(EndpointPolicyError):
            broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=OTHER_CANCEL_DIGEST,
            )
        self.assertEqual(broker.query(binding).state.value, "poisoned")

    def test_cancel_before_arm_terminates_zero_child_operation(self):
        binding, broker, proxy, _, _ = _attached()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        terminal = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        proxy.observe_cancel_ack(terminal)
        self.assertEqual(terminal.state.value, "terminal_attested")
        self.assertEqual(terminal.terminal_kind.value, "zero_child_cancel")
        self.assertFalse(terminal.child_ever_owned)
        self.assertFalse(terminal.start_committed)
        attestation_id, kind, status = proxy.terminal_attestation()
        self.assertEqual(attestation_id, CANCEL_ID)
        self.assertEqual(kind.value, "zero_child_cancel")
        self.assertIsNone(status)

    def test_cancel_before_spawn_late_success_is_owned_and_cleaned_once(self):
        binding, broker, proxy, _, _ = _armed()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        waiting = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        proxy.observe_cancel_ack(waiting)
        self.assertEqual(waiting.state.value, "cancel_wait_spawn")
        child = broker.complete_spawn(
            binding,
            event_id=SPAWN_ID,
            child_created=True,
        )
        proxy.observe_status(child)
        self.assertTrue(child.child_ever_owned)
        self.assertFalse(child.start_committed)
        self.assertEqual(child.cleanup_phase.value, "terminate_required")
        claimed = broker.claim_terminate(binding, action_id=TERMINATE_ID)
        self.assertEqual(claimed.cleanup_phase.value, "terminate_claimed")
        terminate = broker.complete_terminate(binding, action_id=TERMINATE_ID)
        self.assertEqual(terminate.cleanup_phase.value, "reap_required")
        self.assertEqual(
            broker.complete_terminate(binding, action_id=TERMINATE_ID).revision,
            terminate.revision,
        )
        broker.claim_reap(binding, action_id=REAP_ID)
        broker.complete_reap(binding, action_id=REAP_ID)
        broker.claim_close(binding, action_id=CLOSE_ID)
        closed = broker.complete_close(binding, action_id=CLOSE_ID)
        self.assertEqual(closed.cleanup_phase.value, "complete")
        terminal = broker.attest_terminal(
            binding,
            attestation_id=TERMINAL_ID,
            status=265,
        )
        proxy.observe_status(terminal)
        self.assertEqual(proxy.safe_metadata()["state"], "terminal_attested")

    def test_cancel_before_spawn_late_failure_is_zero_child_terminal(self):
        binding, broker, proxy, _, _ = _armed()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        proxy.observe_cancel_ack(
            broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        terminal = broker.complete_spawn(
            binding,
            event_id=SPAWN_ID,
            child_created=False,
        )
        proxy.observe_status(terminal)
        self.assertFalse(terminal.child_ever_owned)
        self.assertEqual(terminal.terminal_kind.value, "spawn_failed")
        self.assertEqual(terminal.terminal_status, 70)
        self.assertFalse(terminal.start_committed)

    def test_spawn_first_then_cancel_preserves_child_and_single_cleanup(self):
        binding, broker, proxy, _, child = _child_owned()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        cancelled = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        proxy.observe_cancel_ack(cancelled)
        self.assertTrue(cancelled.child_ever_owned)
        self.assertEqual(cancelled.state.value, "child_owned")
        self.assertEqual(cancelled.cleanup_phase.value, "terminate_required")
        self.assertEqual(child.revision + 1, cancelled.revision)
        self.assertFalse(cancelled.start_committed)

    def test_cancel_and_start_permutations_commit_zero_or_one_start(self):
        with self.subTest(order="cancel_first"):
            binding, broker, proxy, _, _ = _ready()
            proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
            cancelled = broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            self.assertFalse(cancelled.start_committed)
            ignored = broker.claim_start(
                binding,
                command_id=START_ID,
                payload_digest=START_DIGEST,
            )
            self.assertFalse(ignored.start_committed)
            self.assertIsNone(ignored.start_command_id)
        with self.subTest(order="start_first"):
            binding, broker, proxy, _, _ = _ready()
            broker.claim_start(
                binding,
                command_id=START_ID,
                payload_digest=START_DIGEST,
            )
            started = broker.commit_start(binding, command_id=START_ID)
            proxy.observe_status(started)
            proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
            cancelled = broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            self.assertTrue(cancelled.start_committed)
            replay = broker.commit_start(binding, command_id=START_ID)
            self.assertEqual(replay.revision, cancelled.revision)
            self.assertEqual(replay.start_command_id, START_ID)

    def test_result_terminal_and_release_require_exact_order(self):
        binding, broker, proxy, _, _ = _ready()
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        started = broker.commit_start(binding, command_id=START_ID)
        proxy.observe_status(started)
        result = broker.mark_result(
            binding,
            event_id=RESULT_ID,
            result_digest=RESULT_DIGEST,
        )
        proxy.observe_status(result)
        with self.assertRaises(EndpointPolicyError):
            proxy.begin_release(tombstone_id=RELEASE_ID)
        self.assertEqual(proxy.safe_metadata()["state"], "poisoned")

        binding, broker, proxy, _, _ = _ready()
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        started = broker.commit_start(binding, command_id=START_ID)
        proxy.observe_status(started)
        result = broker.mark_result(
            binding,
            event_id=RESULT_ID,
            result_digest=RESULT_DIGEST,
        )
        proxy.observe_status(result)
        broker.mark_success_cleanup_ready(
            binding,
            event_id=_query_id(7000),
            durable_eof_ack_digest=EOF_ACK_DIGEST,
        )
        broker.claim_reap(binding, action_id=REAP_ID)
        broker.complete_reap(binding, action_id=REAP_ID)
        broker.claim_close(binding, action_id=CLOSE_ID)
        broker.complete_close(binding, action_id=CLOSE_ID)
        terminal = broker.attest_terminal(
            binding,
            attestation_id=TERMINAL_ID,
            status=0,
        )
        proxy.observe_status(terminal)
        self.assertFalse(proxy.can_release_operation_refs())
        proxy.begin_release(tombstone_id=RELEASE_ID)
        released = broker.release(binding, tombstone_id=RELEASE_ID)
        proxy.observe_release_ack(released)
        self.assertTrue(proxy.can_release_operation_refs())

    def test_stale_query_cannot_rollback_and_same_revision_conflict_poisons(self):
        binding, broker, proxy, publication, armed = _armed()
        child = broker.complete_spawn(
            binding,
            event_id=SPAWN_ID,
            child_created=True,
        )
        proxy.observe_status(child)
        self.assertEqual(proxy.safe_metadata()["observed_revision"], child.revision)
        proxy.observe_status(armed)
        self.assertEqual(proxy.safe_metadata()["observed_revision"], child.revision)

        conflicting = broker.query(binding)
        object.__setattr__(conflicting, "cancel_command_id", CANCEL_ID)
        object.__setattr__(
            conflicting,
            "cancel_payload_digest",
            CANCEL_DIGEST,
        )
        object.__setattr__(conflicting, "cancel_latched", True)
        object.__setattr__(
            conflicting,
            "cleanup_phase",
            supervisor._BrokerCleanupPhase.TERMINATE_REQUIRED,
        )
        _redigest(conflicting)
        conflicting.validate_integrity()
        self.assertEqual(conflicting.revision, child.revision)
        with self.assertRaises(EndpointPolicyError):
            proxy.observe_status(conflicting)
        self.assertEqual(proxy.safe_metadata()["state"], "poisoned")

    def test_attestations_and_publication_proofs_bind_exact_broker_owner(self):
        with self.assertRaises(TypeError):
            supervisor._SupervisorParentSessionLedger(
                epoch_id=EPOCH_ID,
                broker_ledger=object(),
            )

        with self.subTest(case="same_broker_noncanonical_session"):
            binding = _binding()
            ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
            broker = _BrokerHarness(ports)
            reserved = broker.reserve(binding)
            sibling = supervisor._SupervisorParentSessionLedger(
                epoch_id=EPOCH_ID,
                broker_ledger=ports.ledger,
                _authority=supervisor._BROKER_LEDGER_AUTHORITY,
            )
            with self.assertRaises(EndpointPolicyError):
                sibling.prepare_proxy(
                    reservation=reserved,
                    proxy_id=PROXY_ID,
                    proof_id=PROOF_ID,
                )
            proxy, _ = ports.parent_session.prepare_proxy(
                reservation=reserved,
                proxy_id=PROXY_ID,
                proof_id=PROOF_ID,
            )
            self.assertEqual(proxy.safe_metadata()["state"], "attach_unknown")

        with self.subTest(case="foreign_reservation"):
            binding = _binding()
            ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
            other_ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
            broker = _BrokerHarness(ports)
            other_broker = _BrokerHarness(other_ports)
            reserved = broker.reserve(binding)
            other_reserved = other_broker.reserve(binding)
            proxy, _ = ports.parent_session.prepare_proxy(
                reservation=reserved,
                proxy_id=PROXY_ID,
                proof_id=PROOF_ID,
            )
            with self.assertRaises(EndpointPolicyError):
                ports.parent_session.prepare_proxy(
                    reservation=other_reserved,
                    proxy_id=PROXY_ID,
                    proof_id=PROOF_ID,
                )
            with self.assertRaises(EndpointPolicyError):
                proxy.observe_status(other_reserved)
            self.assertEqual(proxy.safe_metadata()["state"], "poisoned")

        with self.subTest(case="foreign_proof"):
            binding = _binding()
            ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
            other_ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
            broker = _BrokerHarness(ports)
            other_broker = _BrokerHarness(other_ports)
            reserved = broker.reserve(binding)
            other_broker.reserve(binding)
            proxy, publication = ports.parent_session.prepare_proxy(
                reservation=reserved,
                proxy_id=PROXY_ID,
                proof_id=PROOF_ID,
            )
            publication.commit(proxy)
            proof = publication.observe(proxy)
            proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
            attached = broker.attach(
                binding,
                proof=proof,
                command_id=ATTACH_ID,
            )
            proxy.observe_attach_ack(attached)

            with self.assertRaises(EndpointPolicyError):
                other_broker.attach(
                    binding,
                    proof=proof,
                    command_id=ATTACH_ID,
                )
            other_poisoned = other_broker.query(binding)
            self.assertEqual(other_poisoned.state.value, "poisoned")
            self.assertFalse(other_poisoned.child_ever_owned)
            proxy.begin_arm(command_id=ARM_ID)
            proxy.observe_arm_ack(broker.arm(binding, command_id=ARM_ID))
            self.assertEqual(proxy.safe_metadata()["state"], "active")

    def test_each_binding_mismatch_poisons_without_child_or_start(self):
        mutations = (
            {"epoch_id": OTHER_ID},
            {"operation_id": OTHER_ID},
            {"lifecycle_id": OTHER_ID},
            {"publication_id": OTHER_ID},
            {"spawn_request_digest": Digest256("e" * 64)},
        )
        for mutation in mutations:
            with self.subTest(mutation=tuple(mutation)):
                binding, broker, _, _, _ = _reserved()
                wrong = _binding(**mutation)
                with self.assertRaises(EndpointPolicyError):
                    broker.query(wrong)
                poisoned = broker.query(binding)
                self.assertEqual(poisoned.state.value, "poisoned")
                self.assertFalse(poisoned.child_ever_owned)
                self.assertFalse(poisoned.start_committed)

    def test_epoch_liveness_or_os_uncertainty_poisons_active_operations(self):
        for reason in (
            supervisor._PoisonReason.EPOCH_LOST,
            supervisor._PoisonReason.LIVENESS_LOST,
            supervisor._PoisonReason.OS_ACTION_UNCERTAIN,
        ):
            with self.subTest(reason=reason.value):
                binding, broker, proxy, _, _ = _armed()
                broker.poison_epoch(reason=reason)
                poisoned = broker.query(binding)
                self.assertEqual(poisoned.state.value, "poisoned")
                with self.assertRaises(EndpointPolicyError):
                    proxy.observe_status(poisoned)
                self.assertEqual(proxy.safe_metadata()["state"], "poisoned")
                with self.assertRaises(EndpointPolicyError):
                    broker.reserve(
                        _binding(operation_id=OTHER_ID)
                    )

    def test_release_ack_loss_recovers_from_exact_tombstone_query(self):
        binding, broker, proxy, _, _ = _attached()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        terminal = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        proxy.observe_cancel_ack(terminal)
        proxy.begin_release(tombstone_id=RELEASE_ID)
        released = broker.release(binding, tombstone_id=RELEASE_ID)
        self.assertEqual(proxy.safe_metadata()["state"], "release_not_attested")
        self.assertFalse(proxy.can_release_operation_refs())
        proxy.begin_release(tombstone_id=RELEASE_ID)
        replay = broker.release(binding, tombstone_id=RELEASE_ID)
        self.assertEqual(replay.revision, released.revision)
        proxy.observe_status(broker.query(binding))
        self.assertEqual(proxy.safe_metadata()["state"], "released")
        self.assertTrue(proxy.can_release_operation_refs())

    def test_eight_stable_pending_observations_enter_cleanup_waiting(self):
        binding, broker, proxy, _, _ = _cancelled_child()
        session = _SESSIONS_BY_PROXY[id(proxy)]
        for index in range(supervisor.SUPERVISOR_CLEANUP_PENDING_LIMIT - 1):
            counted = session.observe_cleanup_pending(
                proxy=proxy,
                reply=broker.query_reply(binding, query_id=_query_id(index)),
            )
            self.assertTrue(counted)
            self.assertEqual(proxy.safe_metadata()["cleanup_state"], "polling")
            self.assertEqual(proxy.safe_metadata()["cleanup_pending_count"], index + 1)
        session.observe_cleanup_pending(
            proxy=proxy,
            reply=broker.query_reply(
                binding,
                query_id=_query_id(supervisor.SUPERVISOR_CLEANUP_PENDING_LIMIT),
            ),
        )
        metadata = proxy.safe_metadata()
        self.assertEqual(metadata["cleanup_state"], "cleanup_waiting_supervisor")
        self.assertTrue(metadata["operation_recovery_refs_held"])
        self.assertFalse(metadata["business_allowed"])
        self.assertEqual(broker.query(binding).state.value, "child_owned")

    def test_cleanup_waiting_only_observes_late_terminal_then_releases(self):
        binding, broker, proxy, _, _ = _cancelled_child()
        session = _SESSIONS_BY_PROXY[id(proxy)]
        for _ in range(supervisor.SUPERVISOR_CLEANUP_PENDING_LIMIT + 2):
            index = proxy.safe_metadata()["cleanup_pending_count"]
            session.observe_cleanup_pending(
                proxy=proxy,
                reply=broker.query_reply(binding, query_id=_query_id(index)),
            )
        proxy.observe_status(broker.query(binding))
        self.assertEqual(
            proxy.safe_metadata()["cleanup_state"],
            "cleanup_waiting_supervisor",
        )
        with self.assertRaises(EndpointPolicyError):
            proxy.require_business_allowed()
        terminal = _finish_cancelled_child(binding, broker, proxy)
        self.assertEqual(terminal.state.value, "terminal_attested")
        self.assertTrue(proxy.safe_metadata()["operation_recovery_refs_held"])
        proxy.begin_release(tombstone_id=RELEASE_ID)
        proxy.observe_release_ack(
            broker.release(binding, tombstone_id=RELEASE_ID)
        )
        metadata = proxy.safe_metadata()
        self.assertEqual(metadata["cleanup_state"], "terminal")
        self.assertFalse(metadata["operation_recovery_refs_held"])

    def test_publication_proof_is_bound_to_reserved_snapshot_and_exact_proxy(self):
        binding, broker, proxy, publication, reserved = _reserved()
        other_ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        other_broker = _BrokerHarness(other_ports)
        other_reserved = other_broker.reserve(binding)
        other_proxy, _ = other_ports.parent_session.prepare_proxy(
            reservation=other_reserved,
            proxy_id=PROXY_ID,
            proof_id=PROOF_ID,
        )
        with self.assertRaises(EndpointPolicyError):
            publication.commit(other_proxy)
        self.assertFalse(publication.safe_metadata()["committed"])
        with self.assertRaises(EndpointPolicyError):
            publication.observe(proxy)
        publication.commit(proxy)
        proof = publication.observe(proxy)
        with self.assertRaises(EndpointPolicyError):
            publication.commit(other_proxy)
        with self.assertRaises(EndpointPolicyError):
            other_proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
        self.assertEqual(other_proxy.safe_metadata()["state"], "poisoned")
        self.assertEqual(broker.query(binding).state.value, "reserved")

        binding, broker, proxy, publication, reserved = _reserved()
        other_ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        other_broker = _BrokerHarness(other_ports)
        other_reserved = other_broker.reserve(binding)
        other_proxy, other_publication = (
            other_ports.parent_session.prepare_proxy(
                reservation=other_reserved,
                proxy_id=PROXY_ID,
                proof_id=PROOF_ID,
            )
        )
        publication.commit(proxy)
        other_publication.commit(other_proxy)
        proof = publication.observe(proxy)
        other_proof = other_publication.observe(other_proxy)
        self.assertIsNot(proof, other_proof)
        self.assertEqual(proof.proof_digest, other_proof.proof_digest)

        proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
        attached = broker.attach(
            binding,
            proof=proof,
            command_id=ATTACH_ID,
        )
        proxy.observe_attach_ack(attached)
        other_proxy.begin_attach(proof=other_proof, command_id=ATTACH_ID)
        with self.assertRaises(EndpointPolicyError):
            other_proxy.observe_attach_ack(attached)
        self.assertEqual(other_proxy.safe_metadata()["state"], "poisoned")
        with self.assertRaises(EndpointPolicyError):
            broker.attach(
                binding,
                proof=other_proof,
                command_id=ATTACH_ID,
            )
        self.assertEqual(broker.query(binding).state.value, "poisoned")
        self.assertEqual(proxy.safe_metadata()["state"], "attached_unarmed")

    def test_epoch_or_liveness_loss_during_uncommitted_start_is_os_uncertain(self):
        for reason in (
            supervisor._PoisonReason.EPOCH_LOST,
            supervisor._PoisonReason.LIVENESS_LOST,
        ):
            with self.subTest(reason=reason.value):
                binding, broker, proxy, _, _ = _ready()
                broker.claim_start(
                    binding,
                    command_id=START_ID,
                    payload_digest=START_DIGEST,
                )
                broker.poison_epoch(reason=reason)

                metadata = broker.safe_metadata()
                self.assertEqual(
                    metadata["global_poison_reason"],
                    supervisor._PoisonReason.OS_ACTION_UNCERTAIN.value,
                )
                poisoned = broker.query(binding)
                self.assertEqual(
                    poisoned.poison_reason,
                    supervisor._PoisonReason.OS_ACTION_UNCERTAIN,
                )
                self.assertFalse(poisoned.start_committed)
                with self.assertRaises(EndpointPolicyError):
                    broker.commit_start(binding, command_id=START_ID)
                with self.assertRaises(EndpointPolicyError):
                    proxy.observe_status(poisoned)

    def test_other_operation_mutation_during_uncommitted_start_is_globally_uncertain(self):
        for mutation in (
            "cancel",
            "invalid_result",
            "poisoned_target",
            "invalid_uuid",
            "invalid_start_digest",
        ):
            with self.subTest(mutation=mutation):
                binding, broker, _, _, _ = _ready()
                other = _binding(
                    operation_id=OTHER_ID,
                    lifecycle_id=_query_id(120),
                    publication_id=_query_id(121),
                )
                broker.reserve(other)
                if mutation == "poisoned_target":
                    with self.assertRaises(EndpointPolicyError):
                        broker.arm(other, command_id=ARM_ID)
                    self.assertEqual(
                        broker.query(other).state.value,
                        "poisoned",
                    )
                broker.claim_start(
                    binding,
                    command_id=START_ID,
                    payload_digest=START_DIGEST,
                )

                with self.assertRaises(EndpointPolicyError):
                    if mutation in ("cancel", "poisoned_target"):
                        broker.cancel(
                            other,
                            command_id=CANCEL_ID,
                            payload_digest=CANCEL_DIGEST,
                        )
                    elif mutation == "invalid_uuid":
                        broker.cancel(
                            other,
                            command_id="not-a-uuid",
                            payload_digest=CANCEL_DIGEST,
                        )
                    elif mutation == "invalid_start_digest":
                        broker.claim_start(
                            binding,
                            command_id=START_ID,
                            payload_digest="not-a-digest",
                        )
                    else:
                        broker.mark_result(
                            other,
                            event_id=RESULT_ID,
                            result_digest=RESULT_DIGEST,
                        )

                self.assertEqual(
                    broker.safe_metadata()["global_poison_reason"],
                    supervisor._PoisonReason.OS_ACTION_UNCERTAIN.value,
                )
                first = broker.query(binding)
                second = broker.query(other)
                self.assertEqual(first.state.value, "poisoned")
                self.assertEqual(second.state.value, "poisoned")
                self.assertFalse(first.start_committed)
                self.assertIsNone(second.cancel_command_id)
                self.assertIsNone(second.result_event_id)
                with self.assertRaises(EndpointPolicyError):
                    broker.commit_start(binding, command_id=START_ID)

    def test_parent_session_liveness_loss_freezes_active_proxy_without_reply(self):
        _, _, proxy, _, _ = _armed()
        session = _SESSIONS_BY_PROXY[id(proxy)]
        proxy.require_business_allowed()
        session.observe_liveness_lost(epoch_id=EPOCH_ID)
        self.assertEqual(proxy.safe_metadata()["state"], "poisoned")
        with self.assertRaises(EndpointPolicyError):
            proxy.require_business_allowed()
        self.assertTrue(proxy.safe_metadata()["operation_recovery_refs_held"])

    def test_attestation_rejects_impossible_facts_and_forward_state_regression(self):
        _, _, _, _, child = _child_owned()
        object.__setattr__(child, "terminal_status", 99)
        _redigest(child)
        with self.assertRaises(ValueError):
            child.validate_integrity()

        binding, broker, proxy, _, child = _child_owned()
        regression = broker.query(binding)
        object.__setattr__(regression, "revision", child.revision + 1)
        object.__setattr__(regression, "state", supervisor._BrokerOperationState.ATTACHED)
        object.__setattr__(regression, "arm_command_id", None)
        object.__setattr__(regression, "spawn_event_id", None)
        object.__setattr__(regression, "spawn_created", None)
        object.__setattr__(regression, "child_ever_owned", False)
        _redigest(regression)
        regression.validate_integrity()
        with self.assertRaises(EndpointPolicyError):
            proxy.observe_status(regression)
        self.assertEqual(proxy.safe_metadata()["state"], "poisoned")

    def test_cleanup_pending_requires_unique_exact_query_proofs(self):
        binding, broker, proxy, _, _ = _cancelled_child()
        session = _SESSIONS_BY_PROXY[id(proxy)]
        reply = broker.query_reply(binding, query_id=_query_id(40))
        self.assertTrue(
            session.observe_cleanup_pending(proxy=proxy, reply=reply)
        )
        self.assertFalse(
            session.observe_cleanup_pending(
                proxy=proxy,
                reply=broker.query_reply(binding, query_id=_query_id(40)),
            )
        )
        self.assertEqual(proxy.safe_metadata()["cleanup_pending_count"], 1)
        self.assertTrue(
            session.observe_cleanup_pending(
                proxy=proxy,
                reply=broker.query_reply(binding, query_id=_query_id(41)),
            )
        )
        self.assertEqual(proxy.safe_metadata()["cleanup_pending_count"], 2)

    def test_cancel_latched_wait_terminal_is_read_only_and_terminal_retry_noop(self):
        binding, broker, proxy, _, _ = _armed()
        self.assertTrue(
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        proxy.observe_cancel_ack(
            broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        self.assertFalse(
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        self.assertEqual(
            proxy.safe_metadata()["state"],
            "cancel_latched_wait_terminal",
        )
        with self.assertRaises(EndpointPolicyError):
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=OTHER_CANCEL_DIGEST,
            )

        binding, broker, proxy, _, _ = _cancelled_child()
        _finish_cancelled_child(binding, broker, proxy)
        self.assertFalse(
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        self.assertTrue(proxy.begin_release(tombstone_id=RELEASE_ID))
        proxy.observe_release_ack(
            broker.release(binding, tombstone_id=RELEASE_ID)
        )
        self.assertFalse(proxy.begin_release(tombstone_id=RELEASE_ID))
        self.assertFalse(
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )

    def test_uncommitted_command_queries_never_invent_acknowledgements(self):
        binding, broker, proxy, publication, _ = _reserved()
        publication.commit(proxy)
        proof = publication.observe(proxy)
        proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
        proxy.observe_status(broker.query(binding))
        self.assertEqual(proxy.safe_metadata()["state"], "attach_unknown")
        attached = broker.attach(binding, proof=proof, command_id=ATTACH_ID)
        proxy.observe_status(attached)
        self.assertEqual(proxy.safe_metadata()["state"], "attached_unarmed")

        proxy.begin_arm(command_id=ARM_ID)
        proxy.observe_status(broker.query(binding))
        self.assertEqual(proxy.safe_metadata()["state"], "arm_unknown")
        armed = broker.arm(binding, command_id=ARM_ID)
        proxy.observe_status(armed)
        self.assertEqual(proxy.safe_metadata()["state"], "active")

        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        proxy.observe_status(broker.query(binding))
        self.assertEqual(proxy.safe_metadata()["state"], "cancel_not_attested")
        self.assertTrue(
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )

    def test_start_claim_binds_payload_and_result_closes_business_authority(self):
        binding, broker, proxy, _, _ = _ready()
        claimed = broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        replay = broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        self.assertEqual(replay.revision, claimed.revision)
        self.assertFalse(claimed.start_committed)
        started = broker.commit_start(binding, command_id=START_ID)
        proxy.observe_status(started)
        result = broker.mark_result(
            binding,
            event_id=RESULT_ID,
            result_digest=RESULT_DIGEST,
        )
        proxy.observe_status(result)
        self.assertFalse(proxy.safe_metadata()["business_allowed"])
        with self.assertRaises(EndpointPolicyError):
            proxy.require_business_allowed()

        binding, broker, _, _, _ = _ready()
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        with self.assertRaises(EndpointPolicyError):
            broker.claim_start(
                binding,
                command_id=START_ID,
                payload_digest=OTHER_CANCEL_DIGEST,
            )
        self.assertEqual(broker.query(binding).state.value, "poisoned")

    def test_cancel_during_uncommitted_start_claim_is_globally_uncertain(self):
        binding, broker, _, _, _ = _ready()
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        with self.assertRaises(EndpointPolicyError):
            broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        poisoned = broker.query(binding)
        self.assertEqual(poisoned.state.value, "poisoned")
        self.assertEqual(poisoned.poison_reason.value, "os_action_uncertain")
        self.assertEqual(poisoned.start_command_id, START_ID)
        self.assertEqual(poisoned.start_payload_digest, START_DIGEST)
        self.assertFalse(poisoned.start_committed)
        self.assertIsNone(poisoned.cancel_command_id)
        self.assertTrue(broker.safe_metadata()["poisoned"])
        self.assertEqual(
            broker.safe_metadata()["global_poison_reason"],
            "os_action_uncertain",
        )
        with self.assertRaises(EndpointPolicyError):
            broker.commit_start(binding, command_id=START_ID)

    def test_terminal_during_uncommitted_start_claim_is_globally_uncertain(self):
        binding, broker, _, _, _ = _ready()
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        with self.assertRaises(EndpointPolicyError):
            broker.attest_terminal(
                binding,
                attestation_id=TERMINAL_ID,
                status=0,
            )
        poisoned = broker.query(binding)
        self.assertEqual(poisoned.state.value, "poisoned")
        self.assertEqual(poisoned.poison_reason.value, "os_action_uncertain")
        self.assertEqual(poisoned.start_command_id, START_ID)
        self.assertFalse(poisoned.start_committed)
        self.assertIsNone(poisoned.terminal_attestation_id)
        self.assertEqual(
            broker.safe_metadata()["global_poison_reason"],
            "os_action_uncertain",
        )
        with self.assertRaises(EndpointPolicyError):
            broker.commit_start(binding, command_id=START_ID)

    def test_result_during_uncommitted_start_claim_is_globally_uncertain(self):
        binding, broker, _, _, _ = _ready()
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        with self.assertRaises(EndpointPolicyError):
            broker.mark_result(
                binding,
                event_id=RESULT_ID,
                result_digest=RESULT_DIGEST,
            )
        poisoned = broker.query(binding)
        self.assertEqual(poisoned.state.value, "poisoned")
        self.assertEqual(poisoned.poison_reason.value, "os_action_uncertain")
        self.assertEqual(poisoned.start_command_id, START_ID)
        self.assertFalse(poisoned.start_committed)
        self.assertIsNone(poisoned.result_event_id)
        self.assertEqual(
            broker.safe_metadata()["global_poison_reason"],
            "os_action_uncertain",
        )

    def test_cleanup_actions_are_claimed_before_completion_and_uncertainty_replays_zero(self):
        binding, broker, _, _, _ = _cancelled_child()
        with self.assertRaises(EndpointPolicyError):
            broker.complete_terminate(binding, action_id=TERMINATE_ID)
        poisoned = broker.query(binding)
        self.assertEqual(poisoned.state.value, "poisoned")
        claimed = broker.claim_terminate(binding, action_id=TERMINATE_ID)
        self.assertEqual(claimed.cleanup_phase.value, "terminate_claimed")

        binding, broker, _, _, _ = _cancelled_child()
        broker.claim_terminate(binding, action_id=TERMINATE_ID)
        with self.assertRaises(EndpointPolicyError):
            broker.claim_terminate(binding, action_id="not-a-uuid")
        poisoned = broker.query(binding)
        self.assertEqual(poisoned.state.value, "poisoned")
        self.assertEqual(poisoned.poison_reason.value, "os_action_uncertain")
        self.assertEqual(
            broker.ports.ledger._operations[
                binding.operation_id
            ].uncertain_cleanup_action_id,
            TERMINATE_ID,
        )

        binding, broker, _, _, _ = _cancelled_child()
        claimed = broker.claim_terminate(binding, action_id=TERMINATE_ID)
        replay = broker.claim_terminate(binding, action_id=TERMINATE_ID)
        self.assertEqual(replay.revision, claimed.revision)
        broker.poison_epoch(reason=supervisor._PoisonReason.OS_ACTION_UNCERTAIN)
        with self.assertRaises(EndpointPolicyError):
            broker.claim_terminate(binding, action_id=TERMINATE_ID)
        with self.assertRaises(EndpointPolicyError):
            broker.complete_terminate(binding, action_id=TERMINATE_ID)

        binding, broker, _, _, _ = _cancelled_child()
        broker.poison_epoch(reason=supervisor._PoisonReason.OS_ACTION_UNCERTAIN)
        broker.claim_terminate(binding, action_id=TERMINATE_ID)
        broker.complete_terminate(binding, action_id=TERMINATE_ID)
        broker.claim_reap(binding, action_id=REAP_ID)
        broker.complete_reap(binding, action_id=REAP_ID)
        broker.claim_close(binding, action_id=CLOSE_ID)
        cleaned = broker.complete_close(binding, action_id=CLOSE_ID)
        self.assertEqual(cleaned.state.value, "poisoned")
        self.assertEqual(cleaned.cleanup_phase.value, "complete")

    def test_epoch_or_liveness_loss_freezes_each_claimed_cleanup_action(self):
        phases = (
            ("terminate", "claim_terminate", "complete_terminate", TERMINATE_ID),
            ("reap", "claim_reap", "complete_reap", REAP_ID),
            ("close", "claim_close", "complete_close", CLOSE_ID),
        )
        for reason in (
            supervisor._PoisonReason.EPOCH_LOST,
            supervisor._PoisonReason.LIVENESS_LOST,
        ):
            for phase, claim_name, complete_name, action_id in phases:
                with self.subTest(reason=reason.value, phase=phase):
                    binding, broker, _, _, _ = _cancelled_child()
                    broker.claim_terminate(binding, action_id=TERMINATE_ID)
                    if phase in ("reap", "close"):
                        broker.complete_terminate(
                            binding,
                            action_id=TERMINATE_ID,
                        )
                        broker.claim_reap(binding, action_id=REAP_ID)
                    if phase == "close":
                        broker.complete_reap(binding, action_id=REAP_ID)
                        broker.claim_close(binding, action_id=CLOSE_ID)

                    broker.poison_epoch(reason=reason)
                    metadata = broker.safe_metadata()
                    self.assertEqual(
                        metadata["global_poison_reason"],
                        supervisor._PoisonReason.OS_ACTION_UNCERTAIN.value,
                    )
                    poisoned = broker.query(binding)
                    self.assertEqual(
                        poisoned.poison_reason,
                        supervisor._PoisonReason.OS_ACTION_UNCERTAIN,
                    )
                    self.assertEqual(
                        broker.ports.ledger._operations[
                            binding.operation_id
                        ].uncertain_cleanup_action_id,
                        action_id,
                    )
                    with self.assertRaises(EndpointPolicyError):
                        getattr(broker, claim_name)(
                            binding,
                            action_id=action_id,
                        )
                    with self.assertRaises(EndpointPolicyError):
                        getattr(broker, complete_name)(
                            binding,
                            action_id=action_id,
                        )

    def test_cleanup_query_preserves_or_converges_exact_release_state(self):
        with self.subTest(case="terminal_duplicate"):
            binding, broker, proxy, _, _ = _attached()
            session = _SESSIONS_BY_PROXY[id(proxy)]
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            terminal = broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            proxy.observe_cancel_ack(terminal)
            proxy.begin_release(tombstone_id=RELEASE_ID)
            self.assertFalse(
                session.observe_cleanup_pending(
                    proxy=proxy,
                    reply=broker.query_reply(
                        binding,
                        query_id=_query_id(130),
                    ),
                )
            )
            self.assertEqual(
                proxy.safe_metadata()["state"],
                "release_not_attested",
            )
            self.assertTrue(proxy.begin_release(tombstone_id=RELEASE_ID))

        with self.subTest(case="released_ack_loss_and_duplicate"):
            binding, broker, proxy, _, _ = _attached()
            session = _SESSIONS_BY_PROXY[id(proxy)]
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            proxy.observe_cancel_ack(
                broker.cancel(
                    binding,
                    command_id=CANCEL_ID,
                    payload_digest=CANCEL_DIGEST,
                )
            )
            proxy.begin_release(tombstone_id=RELEASE_ID)
            broker.release(binding, tombstone_id=RELEASE_ID)
            self.assertFalse(
                session.observe_cleanup_pending(
                    proxy=proxy,
                    reply=broker.query_reply(
                        binding,
                        query_id=_query_id(131),
                    ),
                )
            )
            self.assertEqual(proxy.safe_metadata()["state"], "released")
            self.assertTrue(proxy.can_release_operation_refs())
            self.assertFalse(
                session.observe_cleanup_pending(
                    proxy=proxy,
                    reply=broker.query_reply(
                        binding,
                        query_id=_query_id(132),
                    ),
                )
            )
            self.assertEqual(proxy.safe_metadata()["state"], "released")
            self.assertTrue(proxy.can_release_operation_refs())

    def test_cleanup_pending_capability_includes_exact_action_phase(self):
        phases = (
            ("terminate", "reap", "claim_reap", "complete_reap"),
            ("reap", "close", "claim_close", "complete_close"),
            ("close", "terminate", "claim_terminate", "complete_terminate"),
        )
        for current_phase, wrong_phase, wrong_claim, wrong_complete in phases:
            for wrong_method in (wrong_claim, wrong_complete):
                with self.subTest(
                    current=current_phase,
                    wrong=wrong_phase,
                    method=wrong_method,
                ):
                    binding, broker, _, _, _ = _cancelled_child()
                    broker.claim_terminate(binding, action_id=TERMINATE_ID)
                    if current_phase in ("reap", "close"):
                        broker.complete_terminate(
                            binding,
                            action_id=TERMINATE_ID,
                        )
                        broker.claim_reap(
                            binding,
                            action_id=TERMINATE_ID,
                        )
                    if current_phase == "close":
                        broker.complete_reap(
                            binding,
                            action_id=TERMINATE_ID,
                        )
                        broker.claim_close(
                            binding,
                            action_id=TERMINATE_ID,
                        )

                    with self.assertRaises(EndpointPolicyError):
                        getattr(broker, wrong_method)(
                            binding,
                            action_id=TERMINATE_ID,
                        )
                    self.assertEqual(
                        broker.safe_metadata()["global_poison_reason"],
                        supervisor._PoisonReason.OS_ACTION_UNCERTAIN.value,
                    )
                    poisoned = broker.query(binding)
                    self.assertEqual(poisoned.state.value, "poisoned")
                    self.assertEqual(
                        broker.ports.ledger._operations[
                            binding.operation_id
                        ].uncertain_cleanup_action_id,
                        TERMINATE_ID,
                    )

    def test_pending_cleanup_blocks_mutation_of_locally_poisoned_operation(self):
        binding, broker, _, _, _ = _cancelled_child()
        other = _binding(
            operation_id=OTHER_ID,
            lifecycle_id=_query_id(140),
            publication_id=_query_id(141),
        )
        broker.reserve(other)
        with self.assertRaises(EndpointPolicyError):
            broker.arm(other, command_id=ARM_ID)
        self.assertFalse(broker.safe_metadata()["poisoned"])
        broker.claim_terminate(binding, action_id=TERMINATE_ID)

        with self.assertRaises(EndpointPolicyError):
            broker.cancel(
                other,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )

        self.assertEqual(
            broker.safe_metadata()["global_poison_reason"],
            supervisor._PoisonReason.OS_ACTION_UNCERTAIN.value,
        )
        self.assertEqual(broker.query(binding).state.value, "poisoned")
        self.assertEqual(
            broker.ports.ledger._operations[
                binding.operation_id
            ].uncertain_cleanup_action_id,
            TERMINATE_ID,
        )
        with self.assertRaises(EndpointPolicyError):
            broker.complete_terminate(binding, action_id=TERMINATE_ID)

    def test_new_cleanup_uncertainty_marker_advances_poisoned_revision_once(self):
        binding, broker, _, _, _ = _cancelled_child()
        broker.poison_epoch(
            reason=supervisor._PoisonReason.OS_ACTION_UNCERTAIN
        )
        broker.claim_terminate(binding, action_id=TERMINATE_ID)
        claimed = broker.query(binding)

        broker.poison_epoch(
            reason=supervisor._PoisonReason.OS_ACTION_UNCERTAIN
        )
        frozen = broker.query(binding)
        self.assertEqual(frozen.revision, claimed.revision + 1)
        self.assertNotEqual(
            frozen.attestation_digest,
            claimed.attestation_digest,
        )
        self.assertEqual(
            broker.ports.ledger._operations[
                binding.operation_id
            ].uncertain_cleanup_action_id,
            TERMINATE_ID,
        )
        broker.poison_epoch(
            reason=supervisor._PoisonReason.OS_ACTION_UNCERTAIN
        )
        self.assertEqual(broker.query(binding).revision, frozen.revision)
        with self.assertRaises(EndpointPolicyError):
            broker.complete_terminate(binding, action_id=TERMINATE_ID)

    def test_parent_ack_application_recovers_after_accept_commit_then_raise(self):
        original = supervisor._SupervisorParentProxy._accept_locked

        def exercise(proxy, observe, attestation, expected_state):
            raised = False

            def commit_then_raise(instance, value):
                nonlocal raised
                accepted = original(instance, value)
                if instance is proxy and not raised:
                    raised = True
                    raise KeyboardInterrupt("synthetic accept interruption")
                return accepted

            with patch.object(
                supervisor._SupervisorParentProxy,
                "_accept_locked",
                new=commit_then_raise,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    observe(attestation)
                observe(attestation)
            self.assertEqual(proxy.safe_metadata()["state"], expected_state)

        with self.subTest(observer="attach"):
            _, _, proxy, _, attached = _attached(acknowledge=False)
            exercise(proxy, proxy.observe_attach_ack, attached, "attached_unarmed")

        with self.subTest(observer="arm"):
            binding, broker, proxy, _, _ = _attached()
            proxy.begin_arm(command_id=ARM_ID)
            armed = broker.arm(binding, command_id=ARM_ID)
            exercise(proxy, proxy.observe_arm_ack, armed, "active")
            proxy.require_business_allowed()

        with self.subTest(observer="cancel"):
            binding, broker, proxy, _, _ = _armed()
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            cancelled = broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            exercise(
                proxy,
                proxy.observe_cancel_ack,
                cancelled,
                "cancel_latched_wait_terminal",
            )

        with self.subTest(observer="status_terminal"):
            binding, broker, proxy, _, _ = _cancelled_child()
            broker.claim_terminate(binding, action_id=TERMINATE_ID)
            broker.complete_terminate(binding, action_id=TERMINATE_ID)
            broker.claim_reap(binding, action_id=REAP_ID)
            broker.complete_reap(binding, action_id=REAP_ID)
            broker.claim_close(binding, action_id=CLOSE_ID)
            broker.complete_close(binding, action_id=CLOSE_ID)
            terminal = broker.attest_terminal(
                binding,
                attestation_id=TERMINAL_ID,
                status=256 + 9,
            )
            exercise(
                proxy,
                proxy.observe_status,
                terminal,
                "terminal_attested",
            )

        with self.subTest(observer="release"):
            binding, broker, proxy, _, _ = _attached()
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            proxy.observe_cancel_ack(
                broker.cancel(
                    binding,
                    command_id=CANCEL_ID,
                    payload_digest=CANCEL_DIGEST,
                )
            )
            proxy.begin_release(tombstone_id=RELEASE_ID)
            released = broker.release(binding, tombstone_id=RELEASE_ID)
            exercise(proxy, proxy.observe_release_ack, released, "released")
            self.assertTrue(proxy.can_release_operation_refs())

    def test_operation_protocol_poison_is_local_but_epoch_loss_is_global(self):
        ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        broker = _BrokerHarness(ports)
        first = _binding()
        second = _binding(
            operation_id=OTHER_ID,
            lifecycle_id=_query_id(80),
            publication_id=_query_id(81),
        )
        broker.reserve(first)
        broker.reserve(second)
        pre_poison_reply = broker.query_reply(first, query_id=_query_id(90))
        with self.assertRaises(EndpointPolicyError):
            broker.arm(first, command_id=ARM_ID)
        self.assertEqual(broker.query(first).state.value, "poisoned")
        poison_reply = broker.query_reply(first, query_id=_query_id(90))
        self.assertEqual(poison_reply.attestation.state.value, "poisoned")
        self.assertNotEqual(
            poison_reply.reply_digest,
            pre_poison_reply.reply_digest,
        )
        self.assertEqual(broker.query(second).state.value, "reserved")
        self.assertFalse(broker.safe_metadata()["poisoned"])
        broker.poison_epoch(reason=supervisor._PoisonReason.LIVENESS_LOST)
        self.assertEqual(broker.query(second).state.value, "poisoned")
        self.assertTrue(broker.safe_metadata()["poisoned"])

    def test_global_liveness_poison_keeps_exact_late_child_cleanup_authority(self):
        binding, broker, proxy, _, _ = _armed()
        broker.poison_epoch(reason=supervisor._PoisonReason.LIVENESS_LOST)
        late_child = broker.complete_spawn(
            binding,
            event_id=SPAWN_ID,
            child_created=True,
        )
        self.assertEqual(late_child.state.value, "poisoned")
        self.assertTrue(late_child.child_ever_owned)
        self.assertEqual(
            late_child.cleanup_phase.value,
            "terminate_required",
        )
        broker.claim_terminate(binding, action_id=TERMINATE_ID)
        broker.complete_terminate(binding, action_id=TERMINATE_ID)
        broker.claim_reap(binding, action_id=REAP_ID)
        broker.complete_reap(binding, action_id=REAP_ID)
        broker.claim_close(binding, action_id=CLOSE_ID)
        cleaned = broker.complete_close(binding, action_id=CLOSE_ID)
        self.assertEqual(cleaned.state.value, "poisoned")
        self.assertEqual(cleaned.cleanup_phase.value, "complete")
        self.assertTrue(broker.safe_metadata()["poisoned"])
        self.assertEqual(
            broker.safe_metadata()["global_poison_reason"],
            "liveness_lost",
        )
        with self.assertRaises(EndpointPolicyError):
            broker.attest_terminal(
                binding,
                attestation_id=TERMINAL_ID,
                status=0,
            )
        with self.assertRaises(EndpointPolicyError):
            broker.reserve(_binding(operation_id=OTHER_ID))
        with self.assertRaises(EndpointPolicyError):
            proxy.observe_status(cleaned)
        self.assertFalse(proxy.can_release_operation_refs())

    def test_late_business_events_after_cancel_are_ignored_without_epoch_poison(self):
        binding, broker, _, _, cancelled = _cancelled_child()
        late_ready = broker.mark_ready(binding, event_id=READY_ID)
        self.assertEqual(late_ready.revision, cancelled.revision)
        self.assertIsNone(late_ready.ready_event_id)
        late_start = broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        self.assertIsNone(late_start.start_command_id)
        self.assertEqual(broker.query(binding).state.value, "child_owned")
        self.assertFalse(broker.safe_metadata()["poisoned"])

    def test_delayed_attach_and_arm_acks_do_not_rollback_cancel_intent(self):
        binding, broker, proxy, _, attached = _attached(acknowledge=False)
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        proxy.observe_attach_ack(attached)
        self.assertEqual(proxy.safe_metadata()["state"], "cancel_not_attested")
        proxy.observe_cancel_ack(
            broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        self.assertEqual(proxy.safe_metadata()["state"], "terminal_attested")

        binding, broker, proxy, _, armed = _armed(acknowledge=False)
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        proxy.observe_arm_ack(armed)
        self.assertEqual(proxy.safe_metadata()["state"], "cancel_not_attested")
        proxy.observe_cancel_ack(
            broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        self.assertEqual(
            proxy.safe_metadata()["state"],
            "cancel_latched_wait_terminal",
        )

    def test_cancel_winning_before_attach_or_arm_command_converges_terminal(self):
        for command in ("attach", "arm"):
            with self.subTest(command=command):
                if command == "attach":
                    binding, broker, proxy, publication, _ = _reserved()
                    publication.commit(proxy)
                    proof = publication.observe(proxy)
                    proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
                else:
                    binding, broker, proxy, _, _ = _attached()
                    proxy.begin_arm(command_id=ARM_ID)

                proxy.begin_cancel(
                    command_id=CANCEL_ID,
                    payload_digest=CANCEL_DIGEST,
                )
                terminal = broker.cancel(
                    binding,
                    command_id=CANCEL_ID,
                    payload_digest=CANCEL_DIGEST,
                )
                if command == "attach":
                    late_ack = broker.attach(
                        binding,
                        proof=proof,
                        command_id=ATTACH_ID,
                    )
                    proxy.observe_attach_ack(late_ack)
                else:
                    late_ack = broker.arm(binding, command_id=ARM_ID)
                    proxy.observe_arm_ack(late_ack)

                self.assertEqual(late_ack.revision, terminal.revision)
                self.assertEqual(
                    broker.query(binding).state.value,
                    "terminal_attested",
                )
                self.assertEqual(
                    proxy.safe_metadata()["state"],
                    "terminal_attested",
                )
                proxy.begin_release(tombstone_id=RELEASE_ID)
                proxy.observe_release_ack(
                    broker.release(binding, tombstone_id=RELEASE_ID)
                )
                self.assertTrue(proxy.can_release_operation_refs())

    def test_terminal_status_rejects_foreign_attachment_command_binding(self):
        binding, broker, proxy, publication, _ = _reserved()
        publication.commit(proxy)
        proof = publication.observe(proxy)
        proxy.begin_attach(proof=proof, command_id=ATTACH_ID)
        broker.attach(binding, proof=proof, command_id=OTHER_ID)
        proxy.begin_cancel(
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        terminal = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )

        with self.assertRaises(EndpointPolicyError):
            proxy.observe_status(terminal)

        self.assertEqual(proxy.safe_metadata()["state"], "poisoned")
        self.assertEqual(broker.query(binding).state.value, "terminal_attested")
        self.assertEqual(
            broker.release(binding, tombstone_id=RELEASE_ID).state.value,
            "released",
        )

    def test_terminal_winning_before_parent_cancel_keeps_release_authority(self):
        for parent_state in (
            "terminal_attested",
            "release_not_attested",
            "released",
        ):
            with self.subTest(parent_state=parent_state):
                binding, broker, proxy, _, _ = _child_owned()
                terminal = broker.attest_terminal(
                    binding,
                    attestation_id=TERMINAL_ID,
                    status=0,
                )
                proxy.observe_status(terminal)
                if parent_state in ("release_not_attested", "released"):
                    proxy.begin_release(tombstone_id=RELEASE_ID)
                if parent_state == "released":
                    proxy.observe_release_ack(
                        broker.release(binding, tombstone_id=RELEASE_ID)
                    )

                self.assertFalse(
                    proxy.begin_cancel(
                        command_id=CANCEL_ID,
                        payload_digest=CANCEL_DIGEST,
                    )
                )
                self.assertEqual(
                    proxy.safe_metadata()["state"],
                    parent_state,
                )
                if parent_state == "terminal_attested":
                    proxy.begin_release(tombstone_id=RELEASE_ID)
                if parent_state != "released":
                    proxy.observe_release_ack(
                        broker.release(binding, tombstone_id=RELEASE_ID)
                    )
                self.assertTrue(proxy.can_release_operation_refs())

    def test_old_command_ack_can_converge_exact_requested_release(self):
        for command in ("attach", "arm", "cancel"):
            with self.subTest(command=command):
                binding, broker, proxy, publication, _ = _cancelled_child()
                proof = publication.observe(proxy)
                _finish_cancelled_child(binding, broker, proxy)
                proxy.begin_release(tombstone_id=RELEASE_ID)
                broker.release(binding, tombstone_id=RELEASE_ID)

                if command == "attach":
                    replay = broker.attach(
                        binding,
                        proof=proof,
                        command_id=ATTACH_ID,
                    )
                    proxy.observe_attach_ack(replay)
                elif command == "arm":
                    replay = broker.arm(binding, command_id=ARM_ID)
                    proxy.observe_arm_ack(replay)
                else:
                    replay = broker.cancel(
                        binding,
                        command_id=CANCEL_ID,
                        payload_digest=CANCEL_DIGEST,
                    )
                    proxy.observe_cancel_ack(replay)

                self.assertEqual(proxy.safe_metadata()["state"], "released")
                self.assertTrue(proxy.can_release_operation_refs())

    def test_old_terminal_command_ack_preserves_pending_release_intent(self):
        for command in ("attach", "arm", "cancel"):
            with self.subTest(command=command):
                binding, broker, proxy, publication, _ = _cancelled_child()
                proof = publication.observe(proxy)
                _finish_cancelled_child(binding, broker, proxy)
                proxy.begin_release(tombstone_id=RELEASE_ID)

                if command == "attach":
                    duplicate = broker.attach(
                        binding,
                        proof=proof,
                        command_id=ATTACH_ID,
                    )
                    proxy.observe_attach_ack(duplicate)
                elif command == "arm":
                    duplicate = broker.arm(binding, command_id=ARM_ID)
                    proxy.observe_arm_ack(duplicate)
                else:
                    duplicate = broker.cancel(
                        binding,
                        command_id=CANCEL_ID,
                        payload_digest=CANCEL_DIGEST,
                    )
                    proxy.observe_cancel_ack(duplicate)

                self.assertEqual(
                    proxy.safe_metadata()["state"],
                    "release_not_attested",
                )
                self.assertTrue(proxy.begin_release(tombstone_id=RELEASE_ID))
                proxy.observe_release_ack(
                    broker.release(binding, tombstone_id=RELEASE_ID)
                )
                self.assertTrue(proxy.can_release_operation_refs())

        for command in ("attach", "arm"):
            with self.subTest(command=command, terminal="natural"):
                binding, broker, proxy, publication, _ = _child_owned()
                proof = publication.observe(proxy)
                terminal = broker.attest_terminal(
                    binding,
                    attestation_id=TERMINAL_ID,
                    status=0,
                )
                proxy.observe_status(terminal)
                proxy.begin_release(tombstone_id=RELEASE_ID)

                if command == "attach":
                    duplicate = broker.attach(
                        binding,
                        proof=proof,
                        command_id=ATTACH_ID,
                    )
                    proxy.observe_attach_ack(duplicate)
                else:
                    duplicate = broker.arm(
                        binding,
                        command_id=ARM_ID,
                    )
                    proxy.observe_arm_ack(duplicate)

                self.assertEqual(
                    proxy.safe_metadata()["state"],
                    "release_not_attested",
                )
                proxy.observe_release_ack(
                    broker.release(binding, tombstone_id=RELEASE_ID)
                )
                self.assertTrue(proxy.can_release_operation_refs())

        with self.subTest(command="cancel_terminal_won_before_latch"):
            binding, broker, proxy, _, _ = _child_owned()
            proxy.begin_cancel(
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            terminal = broker.attest_terminal(
                binding,
                attestation_id=TERMINAL_ID,
                status=0,
            )
            proxy.observe_status(terminal)
            proxy.begin_release(tombstone_id=RELEASE_ID)
            broker.release(binding, tombstone_id=RELEASE_ID)
            replay = broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
            self.assertFalse(replay.cancel_latched)
            proxy.observe_cancel_ack(replay)
            self.assertEqual(proxy.safe_metadata()["state"], "released")
            self.assertTrue(proxy.can_release_operation_refs())

    def test_unrequested_release_never_authorizes_operation_ref_release(self):
        binding, broker, proxy, _, _ = _attached()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        terminal = broker.cancel(
            binding,
            command_id=CANCEL_ID,
            payload_digest=CANCEL_DIGEST,
        )
        proxy.observe_cancel_ack(terminal)
        released = broker.release(binding, tombstone_id=RELEASE_ID)
        with self.assertRaises(EndpointPolicyError):
            proxy.observe_status(released)
        self.assertFalse(proxy.can_release_operation_refs())
        self.assertEqual(proxy.safe_metadata()["state"], "poisoned")

    def test_active_operation_and_per_operation_query_caps_fail_closed(self):
        ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        broker = _BrokerHarness(ports)
        bindings = []
        for index in range(supervisor.SUPERVISOR_ACTIVE_OPERATION_LIMIT):
            binding = _binding(
                operation_id=_query_id(1000 + index),
                lifecycle_id=_query_id(2000 + index),
                publication_id=_query_id(3000 + index),
            )
            bindings.append(binding)
            broker.reserve(binding)
        self.assertEqual(
            broker.safe_metadata()["operation_count"],
            supervisor.SUPERVISOR_ACTIVE_OPERATION_LIMIT,
        )
        self.assertEqual(broker.reserve(bindings[0]).revision, 0)
        with self.assertRaises(EndpointPolicyError):
            broker.reserve(
                _binding(
                    operation_id=_query_id(4000),
                    lifecycle_id=_query_id(4001),
                    publication_id=_query_id(4002),
                )
            )
        self.assertFalse(broker.safe_metadata()["poisoned"])

        ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        broker = _BrokerHarness(ports)
        binding = _binding()
        broker.reserve(binding)
        replies = []
        for index in range(
            supervisor.SUPERVISOR_QUERY_REPLY_LIMIT_PER_OPERATION
        ):
            replies.append(
                broker.query_reply(binding, query_id=_query_id(5000 + index))
            )
        self.assertIs(
            broker.query_reply(binding, query_id=_query_id(5000)),
            replies[0],
        )
        with self.assertRaises(EndpointPolicyError):
            broker.query_reply(binding, query_id=_query_id(6000))
        metadata = broker.safe_metadata()
        self.assertEqual(
            metadata["query_reply_count"],
            supervisor.SUPERVISOR_QUERY_REPLY_LIMIT_PER_OPERATION,
        )
        self.assertFalse(metadata["poisoned"])

    def test_compaction_publishes_primitive_tombstone_and_drops_all_refs(self):
        binding, broker, proxy, publication, released = _released_for_compaction()
        for index in range(3):
            broker.query_reply(binding, query_id=_query_id(6100 + index))
        ledger = broker.ports.ledger
        session = broker.ports.parent_session
        self.assertIn(binding.operation_id, ledger._operations)
        self.assertIn(binding.operation_id, session._operations)
        with self.assertRaises(TypeError):
            supervisor._SupervisorReleasedOperationTombstone(
                binding=binding,
                release_tombstone_id=RELEASE_ID,
                release_attestation_digest=released.attestation_digest,
                released_attestation=released,
            )

        tombstone = broker.compact_released(
            binding,
            RELEASE_ID,
            released.attestation_digest,
        )
        self.assertIs(broker.released_tombstone(binding), tombstone)
        self.assertNotIn(binding.operation_id, ledger._operations)
        self.assertNotIn(binding.operation_id, session._operations)
        self.assertFalse(
            any(key[0] == binding.operation_id for key in ledger._query_replies)
        )
        self.assertFalse(hasattr(tombstone, "binding"))
        self.assertFalse(hasattr(tombstone, "proxy"))
        self.assertFalse(hasattr(tombstone, "publication"))
        self.assertFalse(hasattr(tombstone, "attestation"))
        for name in tombstone.__slots__:
            value = getattr(tombstone, name)
            self.assertIn(
                type(value),
                (
                    UUID,
                    Digest256,
                    int,
                    bool,
                    type(None),
                    supervisor._BrokerOperationState,
                    supervisor._BrokerCleanupPhase,
                    supervisor._TerminalKind,
                    supervisor._PoisonReason,
                ),
            )
        self.assertIs(
            broker.compact_released(
                binding,
                RELEASE_ID,
                released.attestation_digest,
            ),
            tombstone,
        )
        with self.assertRaises(EndpointPolicyError):
            broker.reserve(binding)
        metadata = broker.safe_metadata()
        self.assertEqual(metadata["operation_count"], 0)
        self.assertEqual(metadata["query_reply_count"], 0)

        self.assertEqual(metadata["released_tombstone_count"], 1)
        self.assertFalse(metadata["poisoned"])
        self.assertTrue(proxy.can_release_operation_refs())
        self.assertIsNotNone(publication)
        replay = broker.query(binding)
        self.assertEqual(replay.state.value, "released")
        self.assertEqual(
            replay.attestation_digest,
            released.attestation_digest,
        )
        self.assertIsNone(replay._attachment_proof)
        self.assertIs(
            broker.release(binding, tombstone_id=RELEASE_ID).state,
            supervisor._BrokerOperationState.RELEASED,
        )
        reply = broker.query_reply(binding, query_id=_query_id(6199))
        self.assertEqual(
            reply.attestation.attestation_digest,
            released.attestation_digest,
        )
        self.assertFalse(
            any(key[0] == binding.operation_id for key in ledger._query_replies)
        )
        self.assertNotIn(binding.operation_id, ledger._operations)
        self.assertNotIn(binding.operation_id, session._operations)

    def test_parent_liveness_fanout_never_holds_parent_and_proxy_locks(self):
        binding, broker, proxy, _, released = _released_for_compaction()
        session = broker.ports.parent_session
        finished = Event()
        errors = []

        def lose_liveness():
            try:
                session.observe_liveness_lost(epoch_id=EPOCH_ID)
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()

        self.assertTrue(proxy._lock.acquire(False))
        thread = Thread(target=lose_liveness)
        thread.start()
        parent_released = False
        try:
            for _ in range(200):
                if session._lock.acquire(False):
                    try:
                        parent_released = session._poisoned
                    finally:
                        session._lock.release()
                    if parent_released:
                        break
                time.sleep(0.001)
            self.assertTrue(parent_released)
            tombstone = broker.compact_released(
                binding,
                RELEASE_ID,
                released.attestation_digest,
            )
            self.assertEqual(tombstone.operation_id, binding.operation_id)
        finally:
            proxy._lock.release()
        thread.join(0.5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(finished.is_set())
        self.assertEqual(errors, [])
        self.assertEqual(session.safe_metadata()["operation_count"], 0)

    def test_compaction_waits_for_parent_release_ack(self):
        binding, broker, proxy, _, _ = _attached()
        proxy.begin_cancel(command_id=CANCEL_ID, payload_digest=CANCEL_DIGEST)
        proxy.observe_cancel_ack(
            broker.cancel(
                binding,
                command_id=CANCEL_ID,
                payload_digest=CANCEL_DIGEST,
            )
        )
        proxy.begin_release(tombstone_id=RELEASE_ID)
        released = broker.release(binding, tombstone_id=RELEASE_ID)
        with self.assertRaises(EndpointPolicyError):
            broker.compact_released(
                binding,
                RELEASE_ID,
                released.attestation_digest,
            )
        self.assertIsNone(broker.released_tombstone(binding))
        self.assertIn(binding.operation_id, broker.ports.ledger._operations)
        self.assertIn(
            binding.operation_id,
            broker.ports.parent_session._operations,
        )
        proxy.observe_release_ack(released)
        self.assertIsNotNone(
            broker.compact_released(
                binding,
                RELEASE_ID,
                released.attestation_digest,
            )
        )

    def test_success_cleanup_poll_requires_explicit_child_exit_attestation(self):
        binding, broker, proxy, _, _ = _ready()
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        proxy.observe_status(broker.commit_start(binding, command_id=START_ID))
        proxy.observe_status(
            broker.mark_result(
                binding,
                event_id=RESULT_ID,
                result_digest=RESULT_DIGEST,
            )
        )
        with self.assertRaises(EndpointPolicyError):
            broker.attest_terminal(
                binding,
                attestation_id=TERMINAL_ID,
                status=0,
            )
        self.assertEqual(broker.query(binding).state.value, "poisoned")

        binding, broker, proxy, _, _ = _ready()
        session = _SESSIONS_BY_PROXY[id(proxy)]
        broker.claim_start(
            binding,
            command_id=START_ID,
            payload_digest=START_DIGEST,
        )
        proxy.observe_status(broker.commit_start(binding, command_id=START_ID))
        result = broker.mark_result(
            binding,
            event_id=RESULT_ID,
            result_digest=RESULT_DIGEST,
        )
        proxy.observe_status(result)
        cleanup_ready = broker.mark_success_cleanup_ready(
            binding,
            event_id=_query_id(6151),
            durable_eof_ack_digest=EOF_ACK_DIGEST,
        )
        replay = broker.mark_success_cleanup_ready(
            binding,
            event_id=_query_id(6151),
            durable_eof_ack_digest=EOF_ACK_DIGEST,
        )
        self.assertEqual(cleanup_ready.cleanup_phase.value, "reap_required")
        self.assertEqual(replay.revision, cleanup_ready.revision)
        self.assertEqual(
            cleanup_ready.success_cleanup_event_id,
            _query_id(6151),
        )
        self.assertEqual(
            cleanup_ready.durable_eof_ack_digest,
            EOF_ACK_DIGEST,
        )
        proxy.observe_status(cleanup_ready)
        self.assertTrue(
            session.observe_cleanup_pending(
                proxy=proxy,
                reply=broker.query_reply(
                    binding,
                    query_id=_query_id(6150),
                ),
            )
        )
        self.assertEqual(proxy.safe_metadata()["cleanup_state"], "polling")
        self.assertFalse(proxy.safe_metadata()["business_allowed"])
        with self.assertRaises(EndpointPolicyError):
            proxy.terminal_attestation()

        broker.claim_reap(binding, action_id=REAP_ID)
        broker.complete_reap(binding, action_id=REAP_ID)
        broker.claim_close(binding, action_id=CLOSE_ID)
        broker.complete_close(binding, action_id=CLOSE_ID)
        terminal = broker.attest_terminal(
            binding,
            attestation_id=TERMINAL_ID,
            status=0,
        )
        proxy.observe_status(terminal)
        self.assertEqual(proxy.terminal_attestation()[2], 0)

    def test_compaction_retry_recovers_each_publication_or_delete_gap(self):
        class _CommitThenRaiseSetdefault(dict):
            def __init__(self, values):
                super().__init__(values)
                self.raised = False

            def setdefault(self, key, default=None):
                selected = super().setdefault(key, default)
                if not self.raised:
                    self.raised = True
                    raise KeyboardInterrupt("synthetic setdefault return gap")
                return selected

        class _CommitThenRaisePop(dict):
            def __init__(self, values):
                super().__init__(values)
                self.raised = False

            def pop(self, key, default=None):
                selected = super().pop(key, default)
                if not self.raised:
                    self.raised = True
                    raise KeyboardInterrupt("synthetic pop return gap")
                return selected

        for target in ("tombstone", "queries", "parent", "operation"):
            with self.subTest(target=target):
                binding, broker, _, _, released = _released_for_compaction()
                broker.query_reply(binding, query_id=_query_id(6200))
                ledger = broker.ports.ledger
                session = broker.ports.parent_session
                if target == "tombstone":
                    object.__setattr__(
                        ledger,
                        "_released_tombstones",
                        _CommitThenRaiseSetdefault(ledger._released_tombstones),
                    )
                elif target == "queries":
                    object.__setattr__(
                        ledger,
                        "_query_replies",
                        _CommitThenRaisePop(ledger._query_replies),
                    )
                elif target == "parent":
                    object.__setattr__(
                        session,
                        "_operations",
                        _CommitThenRaisePop(session._operations),
                    )
                else:
                    object.__setattr__(
                        ledger,
                        "_operations",
                        _CommitThenRaisePop(ledger._operations),
                    )
                with self.assertRaises(KeyboardInterrupt):
                    broker.compact_released(
                        binding,
                        RELEASE_ID,
                        released.attestation_digest,
                    )
                retained = broker.released_tombstone(binding)
                self.assertIsNotNone(retained)
                replay = broker.compact_released(
                    binding,
                    RELEASE_ID,
                    released.attestation_digest,
                )
                self.assertIs(replay, retained)
                self.assertNotIn(binding.operation_id, ledger._operations)
                self.assertNotIn(binding.operation_id, session._operations)
                self.assertFalse(
                    any(
                        key[0] == binding.operation_id
                        for key in ledger._query_replies
                    )
                )

    def test_success_cleanup_requires_exact_result_and_eof_ack_identity(self):
        binding, broker, _, _, _ = _ready()
        with self.assertRaises(EndpointPolicyError):
            broker.mark_success_cleanup_ready(
                binding,
                event_id=_query_id(6160),
                durable_eof_ack_digest=EOF_ACK_DIGEST,
            )
        self.assertEqual(broker.query(binding).state.value, "poisoned")

        conflicts = (
            (_query_id(6162), EOF_ACK_DIGEST),
            (_query_id(6161), OTHER_CANCEL_DIGEST),
        )
        for changed_event, changed_digest in conflicts:
            with self.subTest(
                changed_event=changed_event,
                changed_digest=changed_digest,
            ):
                binding, broker, proxy, _, _ = _ready()
                broker.claim_start(
                    binding,
                    command_id=START_ID,
                    payload_digest=START_DIGEST,
                )
                proxy.observe_status(
                    broker.commit_start(binding, command_id=START_ID)
                )
                proxy.observe_status(
                    broker.mark_result(
                        binding,
                        event_id=RESULT_ID,
                        result_digest=RESULT_DIGEST,
                    )
                )
                broker.mark_success_cleanup_ready(
                    binding,
                    event_id=_query_id(6161),
                    durable_eof_ack_digest=EOF_ACK_DIGEST,
                )
                with self.assertRaises(EndpointPolicyError):
                    broker.mark_success_cleanup_ready(
                        binding,
                        event_id=changed_event,
                        durable_eof_ack_digest=changed_digest,
                    )
                self.assertEqual(
                    broker.query(binding).state.value,
                    "poisoned",
                )

    def test_released_tombstone_identity_conflicts_poison_epoch(self):
        binding, broker, _, _, released = _released_for_compaction()
        broker.compact_released(
            binding,
            RELEASE_ID,
            released.attestation_digest,
        )
        changed = _binding(lifecycle_id=OTHER_ID)
        with self.assertRaises(EndpointPolicyError):
            broker.released_tombstone(changed)
        self.assertTrue(broker.safe_metadata()["poisoned"])

        binding, broker, _, _, released = _released_for_compaction()
        broker.compact_released(
            binding,
            RELEASE_ID,
            released.attestation_digest,
        )
        with self.assertRaises(EndpointPolicyError):
            broker.compact_released(
                binding,
                OTHER_ID,
                released.attestation_digest,
            )
        self.assertTrue(broker.safe_metadata()["poisoned"])

    def test_released_tombstone_cap_never_evicts_same_epoch_history(self):
        ports = supervisor._new_supervisor_broker(epoch_id=EPOCH_ID)
        broker = _BrokerHarness(ports)
        first_binding = None
        first_tombstone = None
        for index in range(supervisor.SUPERVISOR_RELEASED_TOMBSTONE_LIMIT):
            binding = _binding(
                operation_id=_query_id(10000 + index),
                lifecycle_id=_query_id(11000 + index),
                publication_id=_query_id(12000 + index),
            )
            broker.reserve(binding)
            terminal = broker.cancel(
                binding,
                command_id=_query_id(13000 + index),
                payload_digest=CANCEL_DIGEST,
            )
            release_id = _query_id(14000 + index)
            released = broker.release(binding, tombstone_id=release_id)
            tombstone = broker.compact_released(
                binding,
                release_id,
                released.attestation_digest,
            )
            if first_binding is None:
                first_binding = binding
                first_tombstone = tombstone
            self.assertEqual(terminal.state.value, "terminal_attested")

        overflow = _binding(
            operation_id=_query_id(15000),
            lifecycle_id=_query_id(15001),
            publication_id=_query_id(15002),
        )
        for _ in range(1_000):
            with self.assertRaises(EndpointPolicyError):
                broker.reserve(overflow)
        metadata = broker.safe_metadata()
        self.assertEqual(
            metadata["released_tombstone_count"],
            supervisor.SUPERVISOR_RELEASED_TOMBSTONE_LIMIT,
        )
        self.assertEqual(metadata["operation_count"], 0)
        self.assertFalse(metadata["poisoned"])
        self.assertIs(broker.released_tombstone(first_binding), first_tombstone)

    def test_locally_poisoned_child_retains_cleanup_only_authority(self):
        binding, broker, _, _, _ = _child_owned()
        with self.assertRaises(EndpointPolicyError):
            broker.mark_result(
                binding,
                event_id=RESULT_ID,
                result_digest=RESULT_DIGEST,
            )
        poisoned = broker.query(binding)
        self.assertEqual(poisoned.state.value, "poisoned")
        self.assertEqual(poisoned.cleanup_phase.value, "terminate_required")
        broker.claim_terminate(binding, action_id=TERMINATE_ID)
        broker.complete_terminate(binding, action_id=TERMINATE_ID)
        broker.claim_reap(binding, action_id=REAP_ID)
        broker.complete_reap(binding, action_id=REAP_ID)
        broker.claim_close(binding, action_id=CLOSE_ID)
        cleaned = broker.complete_close(binding, action_id=CLOSE_ID)
        self.assertEqual(cleaned.state.value, "poisoned")
        self.assertEqual(cleaned.cleanup_phase.value, "complete")


if __name__ == "__main__":
    unittest.main()
