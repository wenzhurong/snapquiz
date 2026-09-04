"""W09-B2b-S4 async spawn, START and late-cleanup integration tests."""
from __future__ import annotations

import ast
import gc
import inspect
import os
from pathlib import Path
import subprocess
import sys
import threading
from threading import Event, Lock, RLock, Thread
import time
import unittest
from unittest.mock import patch
from uuid import UUID
import weakref

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import CancelledError, EndpointPolicyError
from snapquiz.runtime.context import CancellationReason
from snapquiz.transport import _resolver_output_cache as output
from snapquiz.transport import _resolver_supervisor_async as async_module
from snapquiz.transport import _resolver_supervisor_contract as contract
from snapquiz.transport import _resolver_supervisor_proxy as proxy_module
from snapquiz.transport import _resolver_supervisor_wire as wire
from snapquiz.transport import resolver


EPOCH_ID = UUID("8c000000-0000-0000-0000-000000000001")
CHANNEL_ID = UUID("8c000000-0000-0000-0000-000000000002")
LIFECYCLE_ID = UUID("8c000000-0000-0000-0000-000000000003")
PUBLICATION_ID = UUID("8c000000-0000-0000-0000-000000000004")
WAIT_NS = 17_000_000


class _FakeResolverLedger:
    def __init__(self, request, *, lifecycle_id, publication_id):
        self.lifecycle_id = lifecycle_id
        self._capability_snapshot = type(
            "Snapshot",
            (),
            {
                "lifecycle_id": lifecycle_id,
                "publication_id": publication_id,
                "spawn_request_digest": request.request_digest,
            },
        )()
        self._owner = object()
        self._pre_owner = self._owner
        self._lock = RLock()
        self._state = "created"
        self._kernel = None

    def attach_kernel(self, owner, kernel):
        if owner is not self._owner or self._state != "created":
            raise RuntimeError("fake publication changed")
        self._kernel = kernel
        self._state = "spawned"

    def is_exact_kernel_attached(self, owner, kernel):
        return (
            owner is self._owner
            and self._pre_owner is owner
            and self._kernel is kernel
            and self._state == "spawned"
        )

    def recover_kernel_publication_for_cleanup(self, owner, kernel):
        if owner is not self._owner:
            return False
        if self._state == "created" and self._kernel is None:
            self._kernel = kernel
            self._state = "spawned"
        return self._kernel is kernel and self._state == "spawned"


def _request_and_publication(
    *,
    lifecycle_id=LIFECYCLE_ID,
    publication_id=PUBLICATION_ID,
):
    request = resolver.ResolverHelperSpawnRequest(executable="/bin/echo")
    ledger = _FakeResolverLedger(
        request,
        lifecycle_id=lifecycle_id,
        publication_id=publication_id,
    )
    publication = object.__new__(resolver._KernelPublication)
    object.__setattr__(publication, "_ledger", ledger)
    object.__setattr__(publication, "_owner", ledger._owner)
    object.__setattr__(publication, "_lock", RLock())
    object.__setattr__(publication, "_kernel", None)
    return request, publication


class _FakeChild:
    def __init__(
        self,
        *,
        pid=41001,
        stdout=(resolver.READY_FRAME,),
        start_result=resolver.COMPLETE,
        block_start=False,
    ):
        self.pid = pid
        self.stdout = list(stdout)
        self.start_result = start_result
        self.block_start = block_start
        self.start_entered = Event()
        self.start_release = Event()
        self.read_count = 0
        self.durable_observe_count = 0
        self.durable_ack_calls = 0
        self.durable_ack_effects = []
        self.durable_slot = None
        self.writes = []
        self.terminate_pids = []
        self.reap_pids = []
        self.close_count = 0

    def read_stdout(self, max_bytes, *, max_wait_ns):
        self.assert_wait(max_wait_ns)
        self.read_count += 1
        if not self.stdout:
            return resolver.PENDING
        selected = self.stdout.pop(0)
        if selected is resolver.PENDING:
            return selected
        if len(selected) > max_bytes:
            raise AssertionError("test child frame exceeds poll")
        return selected

    def observe_stdout_durable(
        self,
        max_bytes,
        *,
        publication,
        max_wait_ns,
    ):
        """Nondestructively select one payload and publish before return."""

        self.assert_wait(max_wait_ns)
        if self.durable_slot is not None:
            selected = self.durable_slot
            if selected.kind is not publication.kind:
                raise AssertionError("durable output publication changed")
            publication.publish(selected.payload)
            return resolver.COMPLETE
        if publication.kind.value == "EOF":
            payload = b""
        elif not self.stdout:
            return resolver.PENDING
        else:
            payload = self.stdout[0]
        if len(payload) > max_bytes:
            raise AssertionError("test child durable frame exceeds poll")
        selected = publication.publish(payload)
        self.durable_slot = selected
        self.durable_observe_count += 1
        return resolver.COMPLETE

    def ack_stdout_durable(self, observation, *, max_wait_ns):
        self.assert_wait(max_wait_ns)
        self.durable_ack_calls += 1
        if observation.delivery_id in self.durable_ack_effects:
            return resolver.COMPLETE
        if self.durable_slot is not observation:
            raise AssertionError("durable output ACK changed")
        if observation.kind.value != "EOF":
            if not self.stdout or self.stdout[0] != observation.payload:
                raise AssertionError("durable output source changed")
            self.stdout.pop(0)
        self.durable_ack_effects.append(observation.delivery_id)
        self.durable_slot = None
        return resolver.COMPLETE

    def write_start_datagram(self, frame, *, max_wait_ns):
        self.assert_wait(max_wait_ns)
        self.writes.append(frame)
        self.start_entered.set()
        if self.block_start:
            self.start_release.wait(0.5)
        if isinstance(self.start_result, BaseException):
            raise self.start_result
        return self.start_result

    def terminate_exact(self, pid, *, max_wait_ns):
        self.assert_wait(max_wait_ns)
        if pid != self.pid or self.terminate_pids:
            raise AssertionError("terminate was not exact-once for frozen pid")
        self.terminate_pids.append(pid)
        return resolver.COMPLETE

    def reap_exact(self, pid, *, max_wait_ns):
        self.assert_wait(max_wait_ns)
        if pid != self.pid or self.reap_pids:
            raise AssertionError("reap was not exact-once for frozen pid")
        self.reap_pids.append(pid)
        return 9

    def close_exact(self, *, max_wait_ns):
        self.assert_wait(max_wait_ns)
        if self.close_count:
            raise AssertionError("close was not exact-once")
        self.close_count += 1
        return resolver.COMPLETE

    @staticmethod
    def assert_wait(max_wait_ns):
        if type(max_wait_ns) is not int or max_wait_ns <= 0:
            raise AssertionError("child action must be bounded")


class _Worker:
    def __init__(self, child, *, blocked=False, on_spawn=None):
        self.child = child
        self.blocked = blocked
        self.on_spawn = on_spawn
        self.started = Event()
        self.release = Event()
        self.returned = Event()
        self.calls = []

    def spawn(self, binding, *, publication):
        publication.begin()
        self.calls.append(binding)
        if self.child is None:
            publication.fail_before_create()
        else:
            publication.publish(self.child)
        self.started.set()
        if self.on_spawn is not None:
            self.on_spawn()
        if self.blocked:
            self.release.wait(1)
        self.returned.set()
        return None


class _FactoryWorker:
    def __init__(self):
        self.lock = Lock()
        self.children = {}

    def spawn(self, binding, *, publication):
        publication.begin()
        with self.lock:
            child = _FakeChild(pid=42000 + len(self.children))
            publication.publish(child)
            self.children[binding.operation_id] = child
            return None


class _SequenceWorker:
    def __init__(self, children):
        self.lock = Lock()
        self.children = list(children)
        self.calls = []

    def spawn(self, binding, *, publication):
        publication.begin()
        with self.lock:
            self.calls.append(binding)
            if not self.children:
                publication.fail_before_create()
                raise AssertionError("unexpected worker spawn")
            child = self.children.pop(0)
            publication.publish(child)
            return None


class _DropAckChannel:
    def __init__(self, inner, drop_kinds):
        self.inner = inner
        self.epoch_id = inner.epoch_id
        self.control_channel_id = inner.control_channel_id
        self.ports = inner.ports
        self.drop_kinds = list(drop_kinds)
        self.frames = []
        self.proofs = []

    def exchange(self, frame_bytes, **kwargs):
        command = wire._decode_supervisor_wire_frame(frame_bytes)
        self.frames.append(frame_bytes)
        self.proofs.append(kwargs.get("local_publication_proof"))
        result = self.inner.exchange(frame_bytes, **kwargs)
        if self.drop_kinds and command.kind.value == self.drop_kinds[0]:
            self.drop_kinds.pop(0)
            return resolver.PENDING
        return result

    def bind_spawner(self, spawner):
        return self.inner.bind_spawner(spawner)

    def prepare_proxy(self, **kwargs):
        return self.inner.prepare_proxy(**kwargs)

    def read_stdout(self, *args, **kwargs):
        return self.inner.read_stdout(*args, **kwargs)

    def write_stdin(self, *args, **kwargs):
        return self.inner.write_stdin(*args, **kwargs)

    def write_start_once(self, *args, **kwargs):
        return self.inner.write_start_once(*args, **kwargs)

    def confirm_cancel_delegated(self, **kwargs):
        return self.inner.confirm_cancel_delegated(**kwargs)

    def observe_cleanup_pending(self, **kwargs):
        return self.inner.observe_cleanup_pending(**kwargs)

    def close_operation_pipes(self, *args, **kwargs):
        return self.inner.close_operation_pipes(*args, **kwargs)


def _new_stack(worker, *, drop_kinds=()):
    channel = async_module._new_async_supervisor_channel(
        epoch_id=EPOCH_ID,
        control_channel_id=CHANNEL_ID,
        spawn_worker=worker,
    )
    selected_channel = (
        _DropAckChannel(channel, drop_kinds) if drop_kinds else channel
    )
    spawner = proxy_module._new_supervisor_helper_spawner(
        channel=selected_channel
    )
    return channel, spawner


def _drive_active(spawner, request, publication, *, limit=12):
    for _ in range(limit):
        selected = spawner.spawn(
            request,
            publication=publication,
            max_wait_ns=WAIT_NS,
        )
        if selected is not resolver.PENDING:
            return selected
    raise AssertionError("async proxy did not become active")


def _wait_ready(kernel):
    for _ in range(200):
        selected = kernel.read_stdout(64, max_wait_ns=WAIT_NS)
        if selected is resolver.READY_FRAME or selected == resolver.READY_FRAME:
            return selected
        if selected is not resolver.PENDING:
            raise AssertionError(f"unexpected READY poll: {selected!r}")
        time.sleep(0.001)
    raise AssertionError("worker result was not consumed")


def _wait_durable_output(kernel, maximum, *, limit=200):
    for _ in range(limit):
        selected = kernel.observe_stdout_durable(
            maximum,
            max_wait_ns=WAIT_NS,
        )
        if selected is not resolver.PENDING:
            return selected
        time.sleep(0.001)
    raise AssertionError("durable output was not observed")


def _wait_reap(kernel):
    for _ in range(20):
        selected = kernel.reap(max_wait_ns=WAIT_NS)
        if selected is not resolver.PENDING:
            return selected
    raise AssertionError("supervisor cleanup did not attest terminal")


def _start_frame():
    return resolver.encode_start_frame(
        hostname="open.bigmodel.cn",
        port=443,
        network_policy_ref="snapquiz.internet-public-address-policy.v1",
        network_policy_digest=Digest256("b" * 64),
        attempt_permit_id=UUID("8c000000-0000-0000-0000-000000000011"),
        attempt_permit_digest=Digest256("c" * 64),
        transport_claim_id=UUID("8c000000-0000-0000-0000-000000000012"),
        terminal_guard_id=UUID("8c000000-0000-0000-0000-000000000013"),
        terminal_guard_digest=Digest256("d" * 64),
        dns_start_id=UUID("8c000000-0000-0000-0000-000000000014"),
    )


def _inject_released_tombstones(owner, count):
    for index in range(count):
        operation_id = UUID(int=index + 1)
        owner._released_operations[operation_id] = (
            UUID(int=10_000 + index),
            operation_id,
            UUID(int=20_000 + index),
            UUID(int=30_000 + index),
            Digest256(f"{index + 1:064x}"),
            Digest256(f"{index + 1:064x}"),
            UUID(int=40_000 + index),
        )


def _call_with_line_interrupt(function, needle, call, *, occurrence=1):
    lines, first_line = inspect.getsourcelines(function)
    matches = [
        first_line + index
        for index, line in enumerate(lines)
        if needle in line
    ]
    if len(matches) < occurrence:
        raise AssertionError(f"trace target not found: {needle!r}")
    target_line = matches[occurrence - 1]
    target_code = function.__code__
    previous = sys.gettrace()
    fired = False

    def interrupt(frame, event, arg):
        nonlocal fired
        del arg
        if (
            not fired
            and event == "line"
            and frame.f_code is target_code
            and frame.f_lineno == target_line
        ):
            fired = True
            raise KeyboardInterrupt("synthetic async interruption")
        return interrupt

    sys.settrace(interrupt)
    try:
        return call()
    finally:
        sys.settrace(previous)


class ResolverSupervisorAsyncTest(unittest.TestCase):
    def test_durable_ready_result_eof_are_cached_and_exactly_acked(self):
        result_frame = b'{"kind":"RESULT"}\n'
        child = _FakeChild(stdout=(resolver.READY_FRAME, result_frame))
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)

        ready = _wait_durable_output(kernel, 64)
        self.assertEqual(ready.kind, output._ResolverOutputKind.READY)
        self.assertEqual(ready.payload, resolver.READY_FRAME)
        self.assertIs(_wait_durable_output(kernel, 64), ready)
        self.assertEqual(child.durable_observe_count, 1)
        self.assertIs(
            kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )

        self.assertIs(
            kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        result = _wait_durable_output(kernel, len(result_frame))
        self.assertEqual(result.kind, output._ResolverOutputKind.RESULT)
        self.assertEqual(result.payload, result_frame)
        self.assertIs(_wait_durable_output(kernel, len(result_frame)), result)
        record = next(iter(channel.ports.ledger._operations.values()))
        operation = next(iter(channel.event_owner._operations.values()))
        self.assertEqual(record.result_event_id, operation.result_event_id)
        self.assertEqual(
            record.result_digest,
            resolver.result_transcript_digest(result_frame[:-1]),
        )
        self.assertIs(
            kernel.acknowledge_stdout_durable(result, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )

        eof = _wait_durable_output(kernel, 1)
        self.assertEqual(eof.kind, output._ResolverOutputKind.EOF)
        self.assertEqual(eof.payload, b"")
        eof_ack_calls = child.durable_ack_calls
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner.acknowledge_stdout_durable,
                "if not self._commit_eof_cleanup_ready(",
                lambda: kernel.acknowledge_stdout_durable(
                    eof,
                    max_wait_ns=WAIT_NS,
                ),
                occurrence=2,
            )
        interrupted = channel.ports.control.query(kernel._binding)
        self.assertIsNone(interrupted.success_cleanup_event_id)
        self.assertIs(
            interrupted.cleanup_phase,
            contract._BrokerCleanupPhase.NONE,
        )
        self.assertIs(
            kernel.acknowledge_stdout_durable(eof, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child.durable_ack_calls, eof_ack_calls + 1)
        self.assertEqual(child.durable_observe_count, 3)
        self.assertEqual(len(child.durable_ack_effects), 3)
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["durable_output_slot_count"], 0)
        self.assertEqual(metadata["durable_output_tombstone_count"], 3)

    def test_success_cleanup_requires_exact_durable_eof_ack_before_reap(self):
        result_frame = b'{"kind":"RESULT"}\n'
        child = _FakeChild(stdout=(resolver.READY_FRAME, result_frame))
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)

        ready = _wait_durable_output(kernel, 64)
        self.assertIs(
            kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        result = _wait_durable_output(kernel, len(result_frame))
        self.assertIs(
            kernel.acknowledge_stdout_durable(result, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        eof = _wait_durable_output(kernel, 1)

        for _ in range(3):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
        before = channel.ports.control.query(kernel._binding)
        self.assertIs(
            before.cleanup_phase,
            contract._BrokerCleanupPhase.NONE,
        )
        self.assertIsNone(before.success_cleanup_event_id)
        self.assertEqual(child.terminate_pids, [])
        self.assertEqual(child.reap_pids, [])
        self.assertEqual(child.close_count, 0)

        self.assertIs(
            kernel.acknowledge_stdout_durable(eof, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        ready_to_reap = channel.ports.control.query(kernel._binding)
        self.assertIsNotNone(ready_to_reap.success_cleanup_event_id)
        self.assertIsNotNone(ready_to_reap.durable_eof_ack_digest)
        self.assertIs(
            ready_to_reap.cleanup_phase,
            contract._BrokerCleanupPhase.REAP_REQUIRED,
        )
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        race_winner = channel.ports.control.query(kernel._binding)
        self.assertFalse(race_winner.cancel_latched)
        self.assertFalse(channel.ports.ledger.safe_metadata()["poisoned"])

        self.assertEqual(_wait_reap(kernel), 9)
        terminal = channel.ports.control.query(kernel._binding)
        self.assertIs(
            terminal.state,
            contract._BrokerOperationState.TERMINAL_ATTESTED,
        )
        self.assertEqual(child.terminate_pids, [])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_success_marker_interrupt_prevents_emergency_terminate(self):
        result_frame = b'{"kind":"RESULT"}\n'
        child = _FakeChild(
            pid=41009,
            stdout=(resolver.READY_FRAME, result_frame),
        )
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=71_011),
            publication_id=UUID(int=71_012),
        )
        kernel = _drive_active(spawner, request, publication)
        ready = _wait_durable_output(kernel, 64)
        self.assertIs(
            kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        result = _wait_durable_output(kernel, len(result_frame))
        self.assertIs(
            kernel.acknowledge_stdout_durable(result, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        eof = _wait_durable_output(kernel, 1)

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner._commit_eof_cleanup_ready,
                'operation.terminate_state = "complete"',
                lambda: kernel.acknowledge_stdout_durable(
                    eof,
                    max_wait_ns=WAIT_NS,
                ),
            )
        authority = channel.ports.control.query(kernel._binding)
        operation = next(iter(channel.event_owner._operations.values()))
        self.assertIsNotNone(authority.success_cleanup_event_id)
        self.assertIs(
            authority.cleanup_phase,
            contract._BrokerCleanupPhase.REAP_REQUIRED,
        )
        self.assertEqual(operation.terminate_state, "idle")

        channel.event_owner.observe_broker_crash()
        self.assertEqual(child.terminate_pids, [])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertTrue(operation.emergency_cleaned)

    def test_cancel_before_durable_eof_ack_keeps_cancel_cleanup_winner(self):
        result_frame = b'{"kind":"RESULT"}\n'
        child = _FakeChild(stdout=(resolver.READY_FRAME, result_frame))
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=71_001),
            publication_id=UUID(int=71_002),
        )
        kernel = _drive_active(spawner, request, publication)
        ready = _wait_durable_output(kernel, 64)
        self.assertIs(
            kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        result = _wait_durable_output(kernel, len(result_frame))
        self.assertIs(
            kernel.acknowledge_stdout_durable(result, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        eof = _wait_durable_output(kernel, 1)

        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.acknowledge_stdout_durable(eof, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        winner = channel.ports.control.query(kernel._binding)
        self.assertTrue(winner.cancel_latched)
        self.assertIsNone(winner.success_cleanup_event_id)
        self.assertFalse(channel.ports.ledger.safe_metadata()["poisoned"])
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_queued_cancel_linearizes_before_later_durable_eof_ack(self):
        result_frame = b'{"kind":"RESULT"}\n'
        child = _FakeChild(
            pid=41019,
            stdout=(resolver.READY_FRAME, result_frame),
        )
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=71_021),
            publication_id=UUID(int=71_022),
        )
        kernel = _drive_active(spawner, request, publication)
        ready = _wait_durable_output(kernel, 64)
        self.assertIs(
            kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        result = _wait_durable_output(kernel, len(result_frame))
        self.assertIs(
            kernel.acknowledge_stdout_durable(result, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        eof = _wait_durable_output(kernel, 1)

        # Queue CANCEL at its insertion-order linearization point, but keep the
        # event owner busy so the initiating call cannot process it yet.
        self.assertTrue(channel.event_owner._lock.acquire(blocking=False))
        try:
            self.assertIs(
                kernel.terminate(max_wait_ns=WAIT_NS),
                resolver.PENDING,
            )
        finally:
            channel.event_owner._lock.release()
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "pending_control_event_count"
            ],
            1,
        )

        durable_ack_calls = child.durable_ack_calls
        self.assertIs(
            kernel.acknowledge_stdout_durable(eof, max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        cancel_winner = channel.ports.control.query(kernel._binding)
        self.assertTrue(cancel_winner.cancel_latched)
        self.assertIsNone(cancel_winner.success_cleanup_event_id)
        self.assertIsNone(cancel_winner.durable_eof_ack_digest)
        self.assertEqual(child.durable_ack_calls, durable_ack_calls)
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "pending_control_event_count"
            ],
            0,
        )

        self.assertIs(
            kernel.acknowledge_stdout_durable(eof, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        after_ack = channel.ports.control.query(kernel._binding)
        self.assertTrue(after_ack.cancel_latched)
        self.assertIsNone(after_ack.success_cleanup_event_id)
        self.assertIsNone(after_ack.durable_eof_ack_digest)
        self.assertEqual(child.durable_ack_calls, durable_ack_calls + 1)
        while kernel.terminate(max_wait_ns=WAIT_NS) is resolver.PENDING:
            pass
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertFalse(channel.ports.ledger.safe_metadata()["poisoned"])

    def test_cleanup_broker_callback_return_gaps_never_replay_os_actions(self):
        callback_names = (
            "claim_terminate",
            "complete_terminate",
            "claim_reap",
            "complete_reap",
            "claim_close",
            "complete_close",
            "attest_terminal",
        )
        for index, callback_name in enumerate(callback_names):
            with self.subTest(callback=callback_name):
                child = _FakeChild(pid=41030 + index)
                channel, spawner = _new_stack(_Worker(child))
                request, publication = _request_and_publication(
                    lifecycle_id=UUID(int=71_100 + index * 2),
                    publication_id=UUID(int=71_101 + index * 2),
                )
                kernel = _drive_active(spawner, request, publication)
                _wait_ready(kernel)
                cleanup_type = type(channel.ports.cleanup)
                original = getattr(cleanup_type, callback_name)
                committed = []

                def commit_then_interrupt(
                    selected,
                    *args,
                    __original=original,
                    __name=callback_name,
                    **kwargs,
                ):
                    result = __original(selected, *args, **kwargs)
                    committed.append(result)
                    raise KeyboardInterrupt(
                        f"synthetic {__name} return gap"
                    )

                with patch.object(
                    cleanup_type,
                    callback_name,
                    new=commit_then_interrupt,
                ):
                    while (
                        kernel.terminate(max_wait_ns=WAIT_NS)
                        is resolver.PENDING
                    ):
                        pass
                    status = _wait_reap(kernel)
                    while (
                        kernel.close_pipes(max_wait_ns=WAIT_NS)
                        is resolver.PENDING
                    ):
                        pass

                self.assertEqual(len(committed), 1)
                self.assertEqual(status, 9)
                self.assertEqual(child.terminate_pids, [child.pid])
                self.assertEqual(child.reap_pids, [child.pid])
                self.assertEqual(child.close_count, 1)
                self.assertFalse(
                    channel.ports.ledger.safe_metadata()["poisoned"]
                )
                self.assertEqual(len(channel.ports.ledger._operations), 0)
                self.assertEqual(
                    len(channel.ports.parent_session._operations),
                    0,
                )
                self.assertEqual(len(channel.event_owner._operations), 0)
                self.assertEqual(len(channel.event_owner._proxies), 0)
                self.assertEqual(
                    spawner.safe_metadata()["operation_count"],
                    0,
                )

    def test_child_publish_then_interrupt_recovers_without_second_observe(self):
        child = _FakeChild(stdout=(resolver.READY_FRAME,))
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(100):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if channel.event_owner.safe_metadata()["frozen_child_count"]:
                break

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                _FakeChild.observe_stdout_durable,
                "return resolver.COMPLETE",
                lambda: kernel.observe_stdout_durable(
                    64,
                    max_wait_ns=WAIT_NS,
                ),
                occurrence=2,
            )
        self.assertEqual(child.durable_observe_count, 1)
        ready = _wait_durable_output(kernel, 64)
        self.assertEqual(ready.payload, resolver.READY_FRAME)
        self.assertEqual(child.durable_observe_count, 1)
        self.assertEqual(
            channel.event_owner.safe_metadata()["durable_output_slot_count"],
            1,
        )

    def test_supervisor_return_interrupt_replays_same_cached_observation(self):
        child = _FakeChild(stdout=(resolver.READY_FRAME,))
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(100):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if channel.event_owner.safe_metadata()["frozen_child_count"]:
                break

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner.observe_stdout_durable,
                "if selected is resolver.PENDING",
                lambda: kernel.observe_stdout_durable(
                    64,
                    max_wait_ns=WAIT_NS,
                ),
            )
        operation = next(iter(channel.event_owner._operations.values()))
        publication_sink = operation.output_publication
        cached = operation.output_cache.current(publication_sink)
        self.assertIs(_wait_durable_output(kernel, 64), cached)
        self.assertEqual(child.durable_observe_count, 1)

    def test_ack_interrupt_retries_child_idempotently_then_tombstone_replays(self):
        child = _FakeChild(stdout=(resolver.READY_FRAME,))
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        ready = _wait_durable_output(kernel, 64)

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner.acknowledge_stdout_durable,
                "if acked is resolver.PENDING",
                lambda: kernel.acknowledge_stdout_durable(
                    ready,
                    max_wait_ns=WAIT_NS,
                ),
            )
        self.assertEqual(len(child.durable_ack_effects), 1)
        self.assertIs(
            kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child.durable_ack_calls, 2)
        self.assertEqual(len(child.durable_ack_effects), 1)

        # A lost return after the tombstone store performs no second child ACK.
        child2 = _FakeChild(pid=41002, stdout=(resolver.READY_FRAME,))
        channel2, spawner2 = _new_stack(_Worker(child2))
        request2, publication2 = _request_and_publication(
            lifecycle_id=UUID("8c000000-0000-0000-0000-000000000093"),
            publication_id=UUID("8c000000-0000-0000-0000-000000000094"),
        )
        kernel2 = _drive_active(spawner2, request2, publication2)
        ready2 = _wait_durable_output(kernel2, 64)
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner.acknowledge_stdout_durable,
                "operation.output_publication = None",
                lambda: kernel2.acknowledge_stdout_durable(
                    ready2,
                    max_wait_ns=WAIT_NS,
                ),
                occurrence=2,
            )
        self.assertIs(
            kernel2.acknowledge_stdout_durable(ready2, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child2.durable_ack_calls, 1)
        operation2 = next(iter(channel2.event_owner._operations.values()))
        self.assertIsNone(operation2.output_publication)
        self.assertFalse(
            operation2.output_cache.safe_metadata()["slot_present"]
        )
        self.assertEqual(
            operation2.output_cache.safe_metadata()["tombstone_count"],
            1,
        )

    def test_cached_ack_survives_cancel_but_new_observation_is_blocked(self):
        child = _FakeChild(stdout=(resolver.READY_FRAME,))
        _, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        ready = _wait_durable_output(kernel, 64)
        self.assertIs(kernel.terminate(max_wait_ns=WAIT_NS), resolver.COMPLETE)
        self.assertIs(
            kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        with self.assertRaisesRegex(EndpointPolicyError, "cleanup"):
            kernel.observe_stdout_durable(64, max_wait_ns=WAIT_NS)
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        metadata = kernel._channel.safe_metadata()
        self.assertEqual(metadata["operation_count"], 0)
        self.assertEqual(metadata["frozen_child_count"], 0)
        self.assertEqual(metadata["durable_output_slot_count"], 0)
        self.assertEqual(metadata["durable_output_tombstone_count"], 0)
        self.assertEqual(metadata["released_operation_tombstone_count"], 1)

    def test_private_async_layer_has_no_production_or_process_wiring(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_resolver_supervisor_async.py"
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
        self.assertFalse(
            imported & {"ctypes", "os", "select", "socket", "subprocess"}
        )
        resolver_source = Path(resolver.__file__).read_text(encoding="utf-8")
        self.assertNotIn("_resolver_supervisor_async", resolver_source)
        launcher = resolver.ResolverHelperLauncher.production(
            executable="/bin/echo"
        )
        self.assertIs(
            type(launcher._spawner),
            resolver.FailClosedProductionHelperSpawner,
        )

    def test_spawn_ready_start_cancel_is_one_linearized_lifecycle(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)

        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        frame = _start_frame()
        self.assertIs(
            kernel.write_stdin(frame, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.write_stdin(frame, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child.writes, [frame])
        record = next(iter(channel.ports.ledger._operations.values()))
        operation = next(iter(channel.event_owner._operations.values()))
        handshake = next(iter(spawner._operations.values()))
        retained_cache = operation.output_cache
        retained_thread = operation.worker_thread
        self.assertEqual(record.state.value, "started")
        self.assertTrue(record.start_committed)

        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertFalse(channel.session_closed)
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["operation_count"], 0)
        self.assertEqual(metadata["frozen_child_count"], 0)
        self.assertEqual(metadata["released_operation_tombstone_count"], 1)
        self.assertIsNone(operation.frozen_child)
        self.assertIsNone(operation.worker_thread)
        self.assertIsNone(operation.start_record)
        self.assertIsNone(operation.output_cache)
        self.assertIsNone(operation.output_publication)
        self.assertNotIn(operation, channel.event_owner._operations.values())
        self.assertNotIn(kernel._proxy, channel.event_owner._proxies.values())
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertIsNone(publication._kernel)
        self.assertIsNone(handshake.publication)
        self.assertIsNone(handshake.reservation)
        self.assertIsNone(handshake.proxy)
        self.assertIsNone(handshake.proxy_publication)
        self.assertIsNone(handshake.kernel)
        self.assertIsNone(handshake.publication_proof)
        self.assertEqual(handshake.commands, {})
        self.assertEqual(handshake.queries, {})
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel.ports.ledger._query_replies), 0)
        self.assertEqual(len(channel.ports.parent_session._operations), 0)
        self.assertEqual(len(channel._base._replays), 0)
        self.assertEqual(len(channel._base._stdout_by_operation), 0)
        self.assertEqual(len(channel._base._stdin_by_operation), 0)
        self.assertEqual(len(channel._base._closed_operations), 0)
        self.assertEqual(len(channel._base._terminal_tombstones), 1)
        self.assertEqual(len(channel.ports.ledger._released_tombstones), 1)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertIsNotNone(retained_cache)
        self.assertIsNotNone(retained_thread)
        tombstone = next(
            iter(channel.event_owner._released_operations.values())
        )
        self.assertTrue(
            all(type(value) in (UUID, Digest256) for value in tombstone)
        )
        self.assertFalse(any(value is child for value in tombstone))
        channel_tombstone = next(
            iter(channel._base._terminal_tombstones.values())
        )
        release_replay = next(
            replay
            for replay in channel_tombstone.replays
            if wire._decode_supervisor_wire_frame(replay.frame_bytes).kind
            is wire._SupervisorWireKind.RELEASE
        )
        late = channel.exchange(
            release_replay.frame_bytes,
            max_wait_ns=WAIT_NS,
        )
        self.assertEqual(late.wire_bytes, release_replay.response_wire_bytes)
        self.assertEqual(
            late.attestation.attestation_digest,
            channel_tombstone.release_attestation_digest,
        )
        self.assertIs(
            type(late.attestation),
            proxy_module._PrimitiveAttestationReplay,
        )
        self.assertFalse(
            any(
                value in (child, kernel._proxy, kernel)
                for replay in channel_tombstone.replays
                for value in (
                    replay.local_proof_snapshot,
                    replay.response_attestation,
                )
            )
        )
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel._base._replays), 0)
        self.assertIs(
            channel.event_owner.close_operation_pipes(
                kernel._binding,
                kernel._proxy_id,
                max_wait_ns=WAIT_NS,
            ),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child.close_count, 1)
        self.assertEqual(
            channel._base.safe_metadata()["operation_pipe_close_count"],
            1,
        )
        query_count = channel.received_kinds.count("QUERY")
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(channel.received_kinds.count("QUERY"), query_count)
        self.assertEqual(_wait_reap(kernel), 9)
        first_query = channel.ports.control.query(kernel._binding)
        second_query = channel.ports.control.query(kernel._binding)
        self.assertEqual(first_query.state.value, "released")
        self.assertEqual(
            first_query.attestation_digest,
            second_query.attestation_digest,
        )

    def test_terminal_replay_conflict_is_definite_through_async_channel(self):
        child = _FakeChild(pid=41270)
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=72_101),
            publication_id=UUID(int=72_102),
        )
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        tombstone = next(iter(channel._base._terminal_tombstones.values()))
        replay = next(
            selected
            for selected in tombstone.replays
            if wire._decode_supervisor_wire_frame(selected.frame_bytes).kind
            is wire._SupervisorWireKind.RELEASE
        )
        original = wire._decode_supervisor_wire_frame(replay.frame_bytes)
        payload = dict(original.payload)
        payload["tombstone_id"] = UUID(int=72_103)
        conflict = wire._new_supervisor_wire_frame(
            kind=original.kind,
            epoch_id=original.epoch_id,
            operation_id=original.operation_id,
            control_channel_id=original.control_channel_id,
            operation_binding_digest=original.operation_binding_digest,
            frame_id=original.frame_id,
            payload=payload,
        )

        with self.assertRaises(
            proxy_module._DefiniteSupervisorProtocolError
        ):
            channel.exchange(
                wire._encode_supervisor_wire_frame(conflict),
                max_wait_ns=WAIT_NS,
            )
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertTrue(channel.ports.ledger.safe_metadata()["poisoned"])

    def test_terminal_compaction_store_and_pop_gaps_retry_without_reclose(self):
        def terminal_stack(offset):
            child = _FakeChild(pid=41200 + offset)
            channel, spawner = _new_stack(_Worker(child))
            request, publication = _request_and_publication(
                lifecycle_id=UUID(int=50_000 + offset),
                publication_id=UUID(int=60_000 + offset),
            )
            kernel = _drive_active(spawner, request, publication)
            _wait_ready(kernel)
            self.assertIs(
                kernel.terminate(max_wait_ns=WAIT_NS),
                resolver.COMPLETE,
            )
            self.assertEqual(_wait_reap(kernel), 9)
            return child, channel, spawner, publication, kernel

        child, channel, spawner, publication, kernel = terminal_stack(1)
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                proxy_module._InMemorySupervisorChannel.close_operation_pipes,
                "retained.validate_binding",
                lambda: kernel.close_pipes(max_wait_ns=WAIT_NS),
            )
        self.assertEqual(len(channel._base._terminal_tombstones), 1)
        self.assertEqual(len(channel.ports.ledger._operations), 1)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel._base._replays), 0)
        self.assertEqual(child.close_count, 1)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertIsNone(publication._kernel)

        child, channel, spawner, publication, kernel = terminal_stack(2)
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner.close_operation_pipes,
                "if retained != snapshot:",
                lambda: kernel.close_pipes(max_wait_ns=WAIT_NS),
                occurrence=2,
            )
        self.assertEqual(len(channel.event_owner._released_operations), 1)
        self.assertEqual(len(channel.event_owner._operations), 1)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(child.close_count, 1)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertIsNone(publication._kernel)

        child, channel, spawner, publication, kernel = terminal_stack(3)
        for index in range(
            proxy_module.SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT - 1
        ):
            channel._base._terminal_tombstones[UUID(int=index + 1)] = (
                "primitive-terminal-placeholder",
                index,
            )
        _inject_released_tombstones(
            channel.event_owner,
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES - 1,
        )
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                proxy_module._SupervisorHelperSpawner._retire_kernel,
                "publication = operation.publication",
                lambda: kernel.close_pipes(max_wait_ns=WAIT_NS),
            )
        handshake = next(iter(spawner._operations.values()))
        self.assertIs(
            handshake.phase,
            proxy_module._HandshakePhase.RETIRED,
        )
        self.assertIsNotNone(handshake.publication)
        self.assertFalse(channel.epoch_rotation_ready())
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertIsNone(publication._kernel)
        self.assertEqual(child.close_count, 1)
        self.assertTrue(channel.event_owner._control_inbox_lock.acquire(False))
        try:
            self.assertFalse(channel.epoch_rotation_ready())
        finally:
            channel.event_owner._control_inbox_lock.release()
        self.assertTrue(channel.epoch_rotation_ready())

    def test_release_ack_loss_queries_then_compacts_without_replaying_close(self):
        child = _FakeChild(pid=41250)
        channel, spawner = _new_stack(_Worker(child), drop_kinds=("RELEASE",))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=71_001),
            publication_id=UUID(int=71_002),
        )
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)

        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        self.assertEqual(len(channel.ports.ledger._operations), 1)
        self.assertEqual(len(channel._base._terminal_tombstones), 0)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(channel.received_kinds.count("RELEASE"), 1)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel.ports.ledger._query_replies), 0)
        self.assertEqual(len(channel.ports.parent_session._operations), 0)
        self.assertEqual(len(channel._base._replays), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertIsNone(publication._kernel)
        self.assertEqual(child.close_count, 1)
        self.assertEqual(
            channel._base.safe_metadata()["operation_pipe_close_count"],
            1,
        )

    def test_late_child_after_release_is_cleaned_without_operation_resurrection(self):
        child = _FakeChild(pid=41260)
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=72_001),
            publication_id=UUID(int=72_002),
        )
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )

        late = _FakeChild(pid=41261)
        channel.event_owner._publish_worker_outcome(
            async_module._SpawnOutcome(
                operation_id=kernel._binding.operation_id,
                child=late,
                failed=False,
            )
        )
        self.assertIs(
            channel.event_owner.pump(max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        self.assertEqual(late.terminate_pids, [late.pid])
        self.assertEqual(late.reap_pids, [])
        self.assertEqual(late.close_count, 0)
        self.assertIs(
            channel.event_owner.pump(max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        self.assertEqual(late.reap_pids, [late.pid])
        self.assertEqual(late.close_count, 0)
        self.assertIs(
            channel.event_owner.pump(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(late.close_count, 1)
        channel.event_owner._publish_worker_outcome(
            async_module._SpawnOutcome(
                operation_id=kernel._binding.operation_id,
                child=late,
                failed=False,
            )
        )
        self.assertIs(
            channel.event_owner.pump(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(late.terminate_pids, [late.pid])
        self.assertEqual(late.reap_pids, [late.pid])
        self.assertEqual(late.close_count, 1)
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "pending_outcome_operation_count"
            ],
            0,
        )
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "late_child_tombstone_count"
            ],
            1,
        )
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "pending_outcome_operation_count"
            ],
            0,
        )
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel._base._terminal_tombstones), 1)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)

    def test_late_child_published_during_compaction_is_cleaned_before_complete(self):
        child = _FakeChild(pid=41264)
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=72_021),
            publication_id=UUID(int=72_022),
        )
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)

        late = _FakeChild(pid=41265)
        owner_type = type(channel.event_owner)
        original = owner_type._compact_released_operation
        injected = False

        def inject_then_compact(owner, operation_id):
            nonlocal injected
            if not injected:
                injected = True
                owner._publish_worker_outcome(
                    async_module._SpawnOutcome(
                        operation_id=operation_id,
                        child=late,
                        failed=False,
                    )
                )
            return original(owner, operation_id)

        with patch.object(
            owner_type,
            "_compact_released_operation",
            new=inject_then_compact,
        ):
            self.assertIs(
                kernel.close_pipes(max_wait_ns=WAIT_NS),
                resolver.PENDING,
            )
            self.assertEqual(late.terminate_pids, [late.pid])
            self.assertEqual(late.reap_pids, [])
            self.assertEqual(late.close_count, 0)
            for _ in range(8):
                selected = kernel.close_pipes(max_wait_ns=WAIT_NS)
                if selected is resolver.COMPLETE:
                    break
            self.assertIs(selected, resolver.COMPLETE)

        self.assertEqual(late.terminate_pids, [late.pid])
        self.assertEqual(late.reap_pids, [late.pid])
        self.assertEqual(late.close_count, 1)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertEqual(child.close_count, 1)

    def test_late_child_pending_actions_remain_durable_until_exact_cleanup(self):
        class _SlowLateChild(_FakeChild):
            def __init__(self):
                super().__init__(pid=41262)
                self.terminate_calls = 0
                self.reap_calls = 0
                self.close_calls = 0

            def terminate_exact(self, pid, *, max_wait_ns):
                self.assert_wait(max_wait_ns)
                self.terminate_calls += 1
                if self.terminate_calls == 1:
                    return resolver.PENDING
                if pid != self.pid or self.terminate_pids:
                    raise AssertionError("late terminate replayed an effect")
                self.terminate_pids.append(pid)
                return resolver.COMPLETE

            def reap_exact(self, pid, *, max_wait_ns):
                self.assert_wait(max_wait_ns)
                self.reap_calls += 1
                if self.reap_calls == 1:
                    return resolver.PENDING
                if pid != self.pid or self.reap_pids:
                    raise AssertionError("late reap replayed an effect")
                self.reap_pids.append(pid)
                return 9

            def close_exact(self, *, max_wait_ns):
                self.assert_wait(max_wait_ns)
                self.close_calls += 1
                if self.close_calls == 1:
                    return resolver.PENDING
                if self.close_count:
                    raise AssertionError("late close replayed an effect")
                self.close_count += 1
                return resolver.COMPLETE

        child = _FakeChild(pid=41263)
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=72_011),
            publication_id=UUID(int=72_012),
        )
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )

        late = _SlowLateChild()
        channel.event_owner._publish_worker_outcome(
            async_module._SpawnOutcome(
                operation_id=kernel._binding.operation_id,
                child=late,
                failed=False,
            )
        )
        for _ in range(5):
            self.assertIs(
                channel.event_owner.pump(max_wait_ns=WAIT_NS),
                resolver.PENDING,
            )
        self.assertIs(
            channel.event_owner.pump(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(late.terminate_calls, 2)
        self.assertEqual(late.reap_calls, 2)
        self.assertEqual(late.close_calls, 2)
        self.assertEqual(late.terminate_pids, [late.pid])
        self.assertEqual(late.reap_pids, [late.pid])
        self.assertEqual(late.close_count, 1)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)

    def test_broker_crash_advances_only_one_pending_late_child_step(self):
        class _CrashPendingChild(_FakeChild):
            def __init__(self):
                super().__init__(pid=41266)
                self.terminate_calls = 0

            def terminate_exact(self, pid, *, max_wait_ns):
                self.assert_wait(max_wait_ns)
                self.terminate_calls += 1
                if self.terminate_calls <= 3:
                    return resolver.PENDING
                if pid != self.pid or self.terminate_pids:
                    raise AssertionError("late terminate replayed an effect")
                self.terminate_pids.append(pid)
                return resolver.COMPLETE

        child = _FakeChild(pid=41267)
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=72_031),
            publication_id=UUID(int=72_032),
        )
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )

        late = _CrashPendingChild()
        channel.event_owner._publish_worker_outcome(
            async_module._SpawnOutcome(
                operation_id=kernel._binding.operation_id,
                child=late,
                failed=False,
            )
        )
        channel.event_owner.observe_broker_crash()
        self.assertEqual(late.terminate_calls, 1)
        self.assertEqual(len(channel.event_owner._events), 1)
        self.assertTrue(channel.event_owner._lock.acquire(False))
        channel.event_owner._lock.release()

        for _ in range(8):
            selected = channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if selected is resolver.COMPLETE:
                break
        self.assertIs(selected, resolver.COMPLETE)
        self.assertEqual(late.terminate_calls, 4)
        self.assertEqual(late.terminate_pids, [late.pid])
        self.assertEqual(late.reap_pids, [late.pid])
        self.assertEqual(late.close_count, 1)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)

    def test_changed_binding_for_released_operation_poison_fails_closed(self):
        child = _FakeChild()
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        self.assertIs(kernel.terminate(max_wait_ns=WAIT_NS), resolver.COMPLETE)
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        changed = contract._new_supervisor_operation_binding(
            epoch_id=kernel._binding.epoch_id,
            operation_id=kernel._binding.operation_id,
            lifecycle_id=UUID("8c000000-0000-0000-0000-000000000181"),
            publication_id=kernel._binding.publication_id,
            spawn_request_digest=kernel._binding.spawn_request_digest,
        )
        with self.assertRaisesRegex(EndpointPolicyError, "changed|变化"):
            channel.event_owner.close_operation_pipes(
                changed,
                kernel._proxy_id,
                max_wait_ns=WAIT_NS,
            )
        metadata = channel.event_owner.safe_metadata()
        self.assertTrue(metadata["crashed"])
        self.assertEqual(metadata["released_operation_tombstone_count"], 1)

    def test_released_tombstone_limit_rejects_257th_without_eviction(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        _inject_released_tombstones(
            channel.event_owner,
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES,
        )
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(
            metadata["released_operation_tombstone_count"],
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES,
        )
        self.assertEqual(
            metadata["released_operation_tombstone_limit"],
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES,
        )
        request, publication = _request_and_publication()
        for _ in range(12):
            with self.assertRaisesRegex(EndpointPolicyError, "capacity"):
                spawner.spawn(
                    request,
                    publication=publication,
                    max_wait_ns=WAIT_NS,
                )
        metadata = channel.event_owner.safe_metadata()
        self.assertFalse(metadata["crashed"])
        self.assertEqual(
            metadata["released_operation_tombstone_count"],
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES,
        )
        self.assertEqual(worker.calls, [])

    def test_released_and_active_share_the_256_operation_admission_cap(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        _drive_active(spawner, request, publication)
        _inject_released_tombstones(
            channel.event_owner,
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES - 1,
        )

        other_channel, other_spawner = _new_stack(_Worker(_FakeChild()))
        other_request, other_publication = _request_and_publication(
            lifecycle_id=UUID("8c000000-0000-0000-0000-000000000191"),
            publication_id=UUID("8c000000-0000-0000-0000-000000000192"),
        )
        other_kernel = _drive_active(
            other_spawner,
            other_request,
            other_publication,
        )

        with self.assertRaisesRegex(EndpointPolicyError, "capacity"):
            channel.event_owner.register_proxy(other_kernel._proxy)
        metadata = channel.event_owner.safe_metadata()
        self.assertFalse(metadata["crashed"])
        self.assertEqual(metadata["operation_count"], 1)
        self.assertEqual(
            metadata["released_operation_tombstone_count"],
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES - 1,
        )
        self.assertEqual(len(channel.event_owner._proxies), 1)
        self.assertEqual(len(worker.calls), 1)

    def test_pending_worker_outcomes_remain_inside_active_admission_cap(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        _inject_released_tombstones(
            channel.event_owner,
            async_module._MAX_ACTIVE_OPERATIONS,
        )
        for index in range(async_module._MAX_ACTIVE_OPERATIONS):
            channel.event_owner._publish_worker_outcome(
                async_module._SpawnOutcome(
                    operation_id=UUID(int=index + 1),
                    child=_FakeChild(pid=42_000 + index),
                    failed=False,
                )
            )
        request, publication = _request_and_publication()

        for _ in range(1_000):
            with self.assertRaisesRegex(EndpointPolicyError, "capacity"):
                spawner.spawn(
                    request,
                    publication=publication,
                    max_wait_ns=WAIT_NS,
                )

        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(
            metadata["pending_outcome_operation_count"],
            async_module._MAX_ACTIVE_OPERATIONS,
        )
        self.assertEqual(metadata["pending_event_count"], 64)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(worker.calls, [])

    def test_concurrent_outcome_publication_keeps_all_snapshot_readers_safe(self):
        channel, _ = _new_stack(_Worker(_FakeChild()))
        owner = channel.event_owner
        _inject_released_tombstones(owner, async_module._MAX_ACTIVE_OPERATIONS)
        operation_ids = [
            UUID(int=index + 1)
            for index in range(async_module._MAX_ACTIVE_OPERATIONS)
        ]
        for index, operation_id in enumerate(operation_ids[:32]):
            owner._publish_worker_outcome(
                async_module._SpawnOutcome(
                    operation_id=operation_id,
                    child=_FakeChild(pid=47_000 + index),
                    failed=False,
                )
            )

        start = Event()
        failures = []

        def publish_remaining():
            try:
                start.wait(0.5)
                for index, operation_id in enumerate(operation_ids[32:]):
                    owner._publish_worker_outcome(
                        async_module._SpawnOutcome(
                            operation_id=operation_id,
                            child=_FakeChild(pid=47_100 + index),
                            failed=False,
                        )
                    )
                    time.sleep(0)
            except BaseException as error:
                failures.append(error)

        publisher = Thread(target=publish_remaining)
        previous_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            publisher.start()
            start.set()
            while publisher.is_alive():
                try:
                    owner.preflight_admission()
                except proxy_module._DefiniteSupervisorCapacityError:
                    pass
                owner.safe_metadata()
                owner.epoch_rotation_ready()
            publisher.join(1)
        finally:
            sys.setswitchinterval(previous_interval)
        self.assertFalse(publisher.is_alive())
        self.assertEqual(failures, [])
        metadata = owner.safe_metadata()
        self.assertEqual(
            metadata["pending_outcome_operation_count"],
            async_module._MAX_ACTIVE_OPERATIONS,
        )
        self.assertEqual(
            metadata["pending_event_count"],
            async_module._MAX_ACTIVE_OPERATIONS,
        )

    def test_cancel_wins_before_late_spawn_and_suppresses_ready_start(self):
        child = _FakeChild()
        worker = _Worker(child, blocked=True)
        channel, spawner = _new_stack(worker, drop_kinds=("RELEASE",))
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.started.wait(0.5))

        binding = kernel._binding
        normal_limit = (
            proxy_module.SUPERVISOR_REPLAY_LIMIT_PER_OPERATION
            - proxy_module.SUPERVISOR_TERMINAL_REPLAY_RESERVE
        )
        for sequence in range(
            normal_limit - len(channel._base._replays)
        ):
            frame = wire._new_supervisor_wire_frame(
                kind=wire._SupervisorWireKind.QUERY,
                epoch_id=binding.epoch_id,
                operation_id=binding.operation_id,
                control_channel_id=channel.control_channel_id,
                operation_binding_digest=binding.binding_digest,
                frame_id=proxy_module._bound_role_uuid(
                    binding,
                    "pre-cancel-saturation-frame",
                    sequence,
                ),
                payload={
                    "proxy_id": kernel._proxy_id,
                    "query_id": proxy_module._bound_role_uuid(
                        binding,
                        "pre-cancel-saturation-query",
                        sequence,
                    ),
                },
            )
            self.assertIsNot(
                channel.exchange(
                    wire._encode_supervisor_wire_frame(frame),
                    max_wait_ns=WAIT_NS,
                ),
                resolver.PENDING,
            )
        self.assertEqual(len(channel._base._replays), normal_limit)
        query_replies_before_cancel = channel.ports.ledger.safe_metadata()[
            "query_reply_count"
        ]

        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        for _ in range(100):
            self.assertIs(kernel.reap(max_wait_ns=WAIT_NS), resolver.PENDING)
        self.assertEqual(
            kernel._proxy.safe_metadata()["cleanup_state"],
            "cleanup_waiting_supervisor",
        )
        self.assertLessEqual(
            channel._base.safe_metadata()["active_replay_count"],
            proxy_module.SUPERVISOR_REPLAY_LIMIT_PER_OPERATION,
        )
        self.assertEqual(
            channel.ports.ledger.safe_metadata()["query_reply_count"],
            query_replies_before_cancel
            + contract.SUPERVISOR_CLEANUP_PENDING_LIMIT,
        )

        worker.release.set()
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(200):
            status = kernel.reap(max_wait_ns=WAIT_NS)
            if status is not resolver.PENDING:
                break
            time.sleep(0.001)
        self.assertEqual(status, 9)
        self.assertEqual(child.stdout, [resolver.READY_FRAME])
        self.assertEqual(child.writes, [])
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(len(channel._base._replays), 0)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertFalse(channel.session_closed)

    def test_spawn_takeover_wins_then_cancel_still_cleans_exact_child(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(100):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if channel.event_owner.safe_metadata()["frozen_child_count"] == 1:
                break
            time.sleep(0.001)

        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertEqual(child.stdout, [resolver.READY_FRAME])
        self.assertEqual(child.writes, [])
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_cancel_then_late_spawn_failure_stays_zero_child(self):
        worker = _Worker(None, blocked=True)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.started.wait(0.5))
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )

        worker.release.set()
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(200):
            status = kernel.reap(max_wait_ns=WAIT_NS)
            if status is not resolver.PENDING:
                break
            time.sleep(0.001)
        self.assertEqual(status, 70)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        released = channel.ports.control.query(kernel._binding)
        self.assertFalse(released.child_ever_owned)
        self.assertFalse(released.spawn_created)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(
            channel.event_owner.safe_metadata()["frozen_child_count"],
            0,
        )
        self.assertFalse(channel.session_closed)

    def test_arm_and_cancel_ack_loss_query_without_duplicate_actions(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(
            worker,
            drop_kinds=("ARM", "CANCEL"),
        )
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)

        self.assertIs(kernel.terminate(max_wait_ns=WAIT_NS), resolver.PENDING)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertEqual(channel.received_kinds.count("ARM"), 1)
        self.assertEqual(channel.received_kinds.count("CANCEL"), 1)
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertLessEqual(
            channel.event_owner.safe_metadata()[
                "pending_control_event_count"
            ],
            1,
        )

    def test_lost_arm_ack_accepts_exact_zero_child_terminal_successor(self):
        worker = _Worker(None)
        channel, spawner = _new_stack(worker, drop_kinds=("ARM",))
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=73_001),
            publication_id=UUID(int=73_002),
        )

        for _ in range(12):
            selected = spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            )
            if worker.started.is_set():
                break
        self.assertIs(selected, resolver.PENDING)
        self.assertTrue(worker.returned.wait(0.5))
        kernel = _drive_active(spawner, request, publication)

        self.assertEqual(_wait_reap(kernel), 70)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(channel.received_kinds.count("ARM"), 1)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertEqual(len(channel.ports.ledger._operations), 0)

    def test_published_cancel_is_valid_across_all_handshake_phases(self):
        cases = (
            ((), "attach_send", False),
            (("ATTACH",), "attach_query", False),
            ((), "arm_send", False),
            (("ARM",), "arm_query", True),
        )
        for index, (drop_kinds, target_phase, child_started) in enumerate(
            cases
        ):
            with self.subTest(phase=target_phase):
                child = _FakeChild(pid=41300 + index)
                worker = _Worker(child, blocked=True)
                channel, spawner = _new_stack(
                    worker,
                    drop_kinds=drop_kinds,
                )
                request, publication = _request_and_publication(
                    lifecycle_id=UUID(int=73_100 + index * 2),
                    publication_id=UUID(int=73_101 + index * 2),
                )

                for _ in range(12):
                    selected = spawner.spawn(
                        request,
                        publication=publication,
                        max_wait_ns=WAIT_NS,
                    )
                    operation = next(iter(spawner._operations.values()))
                    if operation.phase.value == target_phase:
                        break
                self.assertIs(selected, resolver.PENDING)
                self.assertEqual(operation.phase.value, target_phase)
                self.assertIsNotNone(publication._kernel)
                self.assertEqual(worker.started.is_set(), child_started)

                kernel = publication._kernel
                self.assertIs(
                    kernel.terminate(max_wait_ns=WAIT_NS),
                    resolver.COMPLETE,
                )
                self.assertIs(
                    spawner.spawn(
                        request,
                        publication=publication,
                        max_wait_ns=WAIT_NS,
                    ),
                    kernel,
                )
                self.assertEqual(operation.phase.value, "active")
                self.assertFalse(
                    channel.ports.ledger.safe_metadata()["poisoned"]
                )

                if child_started:
                    worker.release.set()
                    self.assertTrue(worker.returned.wait(0.5))
                    self.assertEqual(_wait_reap(kernel), 9)
                    self.assertEqual(child.terminate_pids, [child.pid])
                    self.assertEqual(child.reap_pids, [child.pid])
                    self.assertEqual(child.close_count, 1)
                else:
                    self.assertEqual(_wait_reap(kernel), 0)
                    self.assertEqual(worker.calls, [])
                    self.assertEqual(child.terminate_pids, [])
                    self.assertEqual(child.reap_pids, [])
                    self.assertEqual(child.close_count, 0)
                self.assertIs(
                    kernel.close_pipes(max_wait_ns=WAIT_NS),
                    resolver.COMPLETE,
                )
                self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
                self.assertEqual(len(channel.ports.ledger._operations), 0)

    def test_failed_publication_pending_anchor_retransmits_cleanup_exactly(self):
        worker = _Worker(_FakeChild(pid=41320))
        channel = async_module._new_async_supervisor_channel(
            epoch_id=EPOCH_ID,
            control_channel_id=CHANNEL_ID,
            spawn_worker=worker,
        )
        wrapped = _DropAckChannel(channel, ("CANCEL", "RELEASE"))
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=wrapped,
            publication_observer=lambda publication, kernel: False,
        )
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=73_200),
            publication_id=UUID(int=73_201),
        )

        self.assertIs(
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            ),
            resolver.PENDING,
        )
        operation = next(iter(spawner._operations.values()))
        self.assertIs(
            operation.phase,
            proxy_module._HandshakePhase.PUBLICATION_CLEANUP_CANCEL,
        )
        self.assertIs(
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            ),
            resolver.PENDING,
        )
        self.assertIs(
            operation.phase,
            proxy_module._HandshakePhase.PUBLICATION_CLEANUP_CANCEL,
        )
        self.assertEqual(spawner.safe_metadata()["operation_count"], 1)
        self.assertEqual(len(channel.ports.ledger._operations), 1)
        cancel = operation.commands[wire._SupervisorWireKind.CANCEL]

        self.assertIs(
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            ),
            resolver.PENDING,
        )
        self.assertIs(
            operation.phase,
            proxy_module._HandshakePhase.PUBLICATION_CLEANUP_RELEASE,
        )
        self.assertIs(
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            ),
            resolver.PENDING,
        )
        self.assertIs(
            operation.phase,
            proxy_module._HandshakePhase.PUBLICATION_CLEANUP_RELEASE,
        )
        release = operation.commands[wire._SupervisorWireKind.RELEASE]
        self.assertIs(
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            ),
            resolver.PENDING,
        )
        with self.assertRaises(EndpointPolicyError):
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            )

        cancel_bytes = wire._encode_supervisor_wire_frame(cancel)
        release_bytes = wire._encode_supervisor_wire_frame(release)
        cancel_sends = [
            frame
            for frame in wrapped.frames
            if wire._decode_supervisor_wire_frame(frame).kind
            is wire._SupervisorWireKind.CANCEL
        ]
        release_sends = [
            frame
            for frame in wrapped.frames
            if wire._decode_supervisor_wire_frame(frame).kind
            is wire._SupervisorWireKind.RELEASE
        ]
        self.assertEqual(cancel_sends, [cancel_bytes, cancel_bytes])
        self.assertEqual(release_sends, [release_bytes, release_bytes])
        self.assertEqual(channel.received_kinds.count("CANCEL"), 1)
        self.assertEqual(channel.received_kinds.count("RELEASE"), 1)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel.ports.parent_session._operations), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(worker.calls, [])

    def test_failed_publication_close_return_gap_retries_without_leak(self):
        worker = _Worker(_FakeChild(pid=41321))
        channel = async_module._new_async_supervisor_channel(
            epoch_id=EPOCH_ID,
            control_channel_id=CHANNEL_ID,
            spawn_worker=worker,
        )
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel,
            publication_observer=lambda publication, kernel: False,
        )
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=73_210),
            publication_id=UUID(int=73_211),
        )
        for _ in range(3):
            self.assertIs(
                spawner.spawn(
                    request,
                    publication=publication,
                    max_wait_ns=WAIT_NS,
                ),
                resolver.PENDING,
            )
        operation = next(iter(spawner._operations.values()))
        self.assertIs(
            operation.phase,
            proxy_module._HandshakePhase.PUBLICATION_CLEANUP_CLOSE,
        )

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                proxy_module._SupervisorHelperSpawner
                ._advance_publication_failure_cleanup,
                'object.__setattr__(kernel, "_operation_pipes_closed", True)',
                lambda: spawner.spawn(
                    request,
                    publication=publication,
                    max_wait_ns=WAIT_NS,
                ),
            )
        self.assertEqual(spawner.safe_metadata()["operation_count"], 1)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(
            channel._base.safe_metadata()["operation_pipe_close_count"],
            1,
        )
        with self.assertRaises(EndpointPolicyError):
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            )
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(
            channel._base.safe_metadata()["operation_pipe_close_count"],
            1,
        )
        self.assertEqual(worker.calls, [])

    def test_failed_publication_65_operation_flood_never_consumes_active_cap(self):
        child = _FakeChild(pid=41322)
        worker = _Worker(child)
        channel = async_module._new_async_supervisor_channel(
            epoch_id=EPOCH_ID,
            control_channel_id=CHANNEL_ID,
            spawn_worker=worker,
        )
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel,
            publication_observer=lambda publication, kernel: False,
        )

        for index in range(
            proxy_module.SUPERVISOR_ACTIVE_OPERATION_LIMIT + 1
        ):
            request, publication = _request_and_publication(
                lifecycle_id=UUID(int=74_000 + index * 2),
                publication_id=UUID(int=74_001 + index * 2),
            )
            for _ in range(12):
                try:
                    selected = spawner.spawn(
                        request,
                        publication=publication,
                        max_wait_ns=WAIT_NS,
                    )
                except EndpointPolicyError:
                    break
                self.assertIs(selected, resolver.PENDING)
            else:
                self.fail("failed publication cleanup did not converge")

        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel.ports.ledger._query_replies), 0)
        self.assertEqual(len(channel.ports.parent_session._operations), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(
            len(channel._base._terminal_tombstones),
            proxy_module.SUPERVISOR_ACTIVE_OPERATION_LIMIT + 1,
        )
        self.assertEqual(
            len(channel.event_owner._released_operations),
            proxy_module.SUPERVISOR_ACTIVE_OPERATION_LIMIT + 1,
        )
        self.assertEqual(worker.calls, [])
        self.assertEqual(child.writes, [])
        self.assertEqual(child.terminate_pids, [])
        self.assertEqual(child.reap_pids, [])

    def test_real_lifecycle_failed_publication_clears_every_cleanup_registry(self):
        from tests.test_w09_resolver_lifecycle import _make_stop_authority

        _, _, _, stop_authority = _make_stop_authority()
        worker = _Worker(_FakeChild(pid=41323))
        channel = async_module._new_async_supervisor_channel(
            epoch_id=EPOCH_ID,
            control_channel_id=CHANNEL_ID,
            spawn_worker=worker,
        )
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel,
            publication_observer=lambda publication, kernel: False,
        )
        launcher = resolver.ResolverHelperLauncher(
            spawner,
            executable="/bin/echo",
        )
        ticket = launcher._reserve_lifecycle_capability(
            reservation_owner=object(),
            stop_authority=stop_authority,
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )

        with self.assertRaises(EndpointPolicyError):
            launcher._launch_ready(
                capability=ticket,
                _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
            )

        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel.ports.ledger._query_replies), 0)
        self.assertEqual(len(channel.ports.parent_session._operations), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertEqual(worker.calls, [])

    def test_spawn_done_commit_then_raise_queries_after_durable_takeover(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        event_type = type(channel.ports.events)
        original = event_type.complete_spawn
        calls = []

        def commit_then_raise(selected, binding, *, event_id, child_created):
            operation = channel.event_owner._operations[binding.operation_id]
            self.assertIs(operation.child, child)
            self.assertEqual(operation.child_pid, child.pid)
            result = original(
                selected,
                binding,
                event_id=event_id,
                child_created=child_created,
            )
            calls.append(event_id)
            raise RuntimeError("synthetic SPAWN_DONE ACK loss")

        with patch.object(
            event_type,
            "complete_spawn",
            new=commit_then_raise,
        ):
            kernel = _drive_active(spawner, request, publication)
            _wait_ready(kernel)

        self.assertEqual(len(calls), 1)
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertTrue(record.child_ever_owned)
        self.assertEqual(record.spawn_event_id, calls[0])

    def test_spawn_done_normal_noop_retries_exact_event_without_new_child(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        event_type = type(channel.ports.events)
        original = event_type.complete_spawn
        calls = []

        def noop_once(selected, binding, *, event_id, child_created):
            calls.append((event_id, child_created))
            if len(calls) == 1:
                return channel.ports.control.query(binding)
            return original(
                selected,
                binding,
                event_id=event_id,
                child_created=child_created,
            )

        with patch.object(event_type, "complete_spawn", new=noop_once):
            kernel = _drive_active(spawner, request, publication)
            _wait_ready(kernel)

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(len(worker.calls), 1)
        self.assertEqual(
            channel.event_owner.safe_metadata()["frozen_child_count"],
            1,
        )

    def test_cancel_and_start_permutations_are_serialized(self):
        with self.subTest(winner="cancel"):
            child = _FakeChild()
            worker = _Worker(child)
            _, spawner = _new_stack(worker)
            request, publication = _request_and_publication()
            kernel = _drive_active(spawner, request, publication)
            _wait_ready(kernel)
            self.assertIs(
                kernel.terminate(max_wait_ns=WAIT_NS),
                resolver.COMPLETE,
            )
            with self.assertRaises(EndpointPolicyError):
                kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS)
            self.assertEqual(child.writes, [])

        with self.subTest(winner="start"):
            child = _FakeChild(block_start=True)
            worker = _Worker(child)
            _, spawner = _new_stack(worker)
            request, publication = _request_and_publication()
            kernel = _drive_active(spawner, request, publication)
            _wait_ready(kernel)
            results = []

            def write_start():
                results.append(
                    kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS)
                )

            writer = Thread(target=write_start)
            writer.start()
            self.assertTrue(child.start_entered.wait(0.5))
            self.assertIs(kernel.terminate(max_wait_ns=WAIT_NS), resolver.PENDING)
            child.start_release.set()
            writer.join(0.5)
            self.assertEqual(results, [resolver.COMPLETE])
            self.assertIs(
                kernel.terminate(max_wait_ns=WAIT_NS),
                resolver.COMPLETE,
            )
            self.assertEqual(len(child.writes), 1)

    def test_contended_owner_queues_cancel_before_query_and_blocks_start(self):
        first_child = _FakeChild(pid=41101, block_start=True)
        second_child = _FakeChild(pid=41102)
        worker = _SequenceWorker((first_child, second_child))
        channel, spawner = _new_stack(worker)
        first_request, first_publication = _request_and_publication()
        second_request, second_publication = _request_and_publication(
            lifecycle_id=UUID(
                "8c000000-0000-0000-0000-000000000031"
            ),
            publication_id=UUID(
                "8c000000-0000-0000-0000-000000000032"
            ),
        )
        first_kernel = _drive_active(
            spawner,
            first_request,
            first_publication,
        )
        self.assertEqual(_wait_ready(first_kernel), resolver.READY_FRAME)
        second_kernel = _drive_active(
            spawner,
            second_request,
            second_publication,
        )
        self.assertEqual(_wait_ready(second_kernel), resolver.READY_FRAME)

        start_results = []
        writer = Thread(
            target=lambda: start_results.append(
                first_kernel.write_stdin(
                    _start_frame(),
                    max_wait_ns=WAIT_NS,
                )
            )
        )
        writer.start()
        self.assertTrue(first_child.start_entered.wait(0.5))

        # The event owner is in the indivisible START critical section.  The
        # other operation's CANCEL is durably queued, not silently discarded.
        self.assertIs(
            second_kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        with self.assertRaisesRegex(EndpointPolicyError, "cleanup"):
            second_kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS)
        self.assertEqual(second_child.writes, [])

        first_child.start_release.set()
        writer.join(0.5)
        self.assertEqual(start_results, [resolver.COMPLETE])
        # The retry re-delivers the same cached frame, selects the older queued
        # CANCEL and returns its exact ACK.  The broker mutation happens once.
        self.assertIs(
            second_kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(channel.received_kinds.count("CANCEL"), 1)
        self.assertEqual(_wait_reap(second_kernel), 9)
        self.assertEqual(second_child.terminate_pids, [second_child.pid])
        self.assertEqual(second_child.reap_pids, [second_child.pid])
        self.assertEqual(second_child.close_count, 1)
        self.assertFalse(channel.session_closed)

    def test_unknown_start_outcome_globally_poisoned_and_never_replayed(self):
        child = _FakeChild(start_result=RuntimeError("unknown write"))
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        frame = _start_frame()

        with self.assertRaisesRegex(EndpointPolicyError, "outcome"):
            kernel.write_stdin(frame, max_wait_ns=WAIT_NS)
        with self.assertRaises(EndpointPolicyError):
            kernel.write_stdin(frame, max_wait_ns=WAIT_NS)
        self.assertEqual(child.writes, [frame])
        metadata = channel.ports.ledger.safe_metadata()
        self.assertTrue(metadata["poisoned"])
        self.assertEqual(
            metadata["global_poison_reason"],
            "os_action_uncertain",
        )
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_start_commit_then_raise_is_query_recovered_without_rewrite(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        event_type = type(channel.ports.events)
        original = event_type.commit_start

        def commit_then_raise(selected, binding, *, command_id):
            original(selected, binding, command_id=command_id)
            raise RuntimeError("synthetic ACK loss")

        with patch.object(event_type, "commit_start", new=commit_then_raise):
            self.assertIs(
                kernel.write_stdin(_start_frame(), max_wait_ns=WAIT_NS),
                resolver.COMPLETE,
            )
        self.assertEqual(len(child.writes), 1)
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertTrue(record.start_committed)

    def test_ready_return_interrupt_is_cached_and_never_rereads_stream(self):
        child = _FakeChild(stdout=(resolver.READY_FRAME, b"result\n"))
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)

        for _ in range(100):
            result = _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner._read_ready_once,
                "if selected is resolver.PENDING",
                lambda: kernel.read_stdout(64, max_wait_ns=WAIT_NS),
            )
            if result is not resolver.PENDING:
                break
            time.sleep(0.001)
        self.assertEqual(result, resolver.READY_FRAME)
        self.assertEqual(child.read_count, 1)
        self.assertEqual(
            kernel.read_stdout(64, max_wait_ns=WAIT_NS),
            resolver.READY_FRAME,
        )
        self.assertEqual(child.read_count, 1)
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertEqual(record.state.value, "ready")

    def test_ready_mark_return_interrupt_queries_cached_frame(self):
        child = _FakeChild(stdout=(resolver.READY_FRAME, b"result\n"))
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(100):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if channel.event_owner.safe_metadata()["frozen_child_count"]:
                break

        result = _call_with_line_interrupt(
            async_module._AsyncSupervisorEventOwner._attest_cached_ready,
            "if self._ready_is_attested(operation, ready)",
            lambda: kernel.read_stdout(64, max_wait_ns=WAIT_NS),
        )
        self.assertEqual(result, resolver.READY_FRAME)
        self.assertEqual(child.read_count, 1)
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertEqual(record.state.value, "ready")

    def test_ready_mark_noop_retries_broker_event_without_stream_reread(self):
        child = _FakeChild(stdout=(resolver.READY_FRAME, b"result\n"))
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        event_type = type(channel.ports.events)
        original = event_type.mark_ready
        calls = 0

        def noop_once(selected, binding, *, event_id):
            nonlocal calls
            calls += 1
            if calls == 1:
                return channel.ports.control.query(binding)
            return original(selected, binding, event_id=event_id)

        with patch.object(event_type, "mark_ready", new=noop_once):
            for _ in range(100):
                result = kernel.read_stdout(64, max_wait_ns=WAIT_NS)
                if child.read_count:
                    break
            self.assertIs(result, resolver.PENDING)
            self.assertEqual(child.read_count, 1)
            self.assertEqual(
                kernel.read_stdout(64, max_wait_ns=WAIT_NS),
                resolver.READY_FRAME,
            )
        self.assertEqual(child.read_count, 1)
        self.assertEqual(calls, 2)

    def test_start_claim_return_interrupt_queries_then_writes_once(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        frame = _start_frame()

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner.write_start_once,
                "claimed_state = self._start_observation",
                lambda: kernel.write_stdin(frame, max_wait_ns=WAIT_NS),
            )
        for _ in range(10):
            result = kernel.write_stdin(frame, max_wait_ns=WAIT_NS)
            if result is resolver.COMPLETE:
                break
        self.assertIs(result, resolver.COMPLETE)
        self.assertEqual(child.writes, [frame])
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertTrue(record.start_committed)

    def test_start_interrupt_after_unknown_before_write_poison_is_global(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)

        with self.assertRaises(EndpointPolicyError):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner._advance_start_action,
                "written = child.write_start_datagram",
                lambda: kernel.write_stdin(
                    _start_frame(),
                    max_wait_ns=WAIT_NS,
                ),
            )
        self.assertEqual(child.writes, [])
        metadata = channel.ports.ledger.safe_metadata()
        self.assertTrue(metadata["poisoned"])
        self.assertEqual(
            metadata["global_poison_reason"],
            "os_action_uncertain",
        )

    def test_start_write_return_interrupt_commits_without_rewrite(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        frame = _start_frame()

        result = _call_with_line_interrupt(
            async_module._AsyncSupervisorEventOwner._advance_start_action,
            'operation.start_state = "write_complete"',
            lambda: kernel.write_stdin(frame, max_wait_ns=WAIT_NS),
        )
        self.assertIs(result, resolver.COMPLETE)
        self.assertEqual(child.writes, [frame])
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertTrue(record.start_committed)

    def test_start_commit_return_interrupt_queries_without_rewrite(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        frame = _start_frame()

        result = _call_with_line_interrupt(
            async_module._AsyncSupervisorEventOwner._commit_written_start,
            "observed = self._start_observation",
            lambda: kernel.write_stdin(frame, max_wait_ns=WAIT_NS),
        )
        self.assertIs(result, resolver.COMPLETE)
        self.assertEqual(child.writes, [frame])
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertTrue(record.start_committed)

    def test_spawn_freeze_interrupt_keeps_outcome_until_broker_attested(self):
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner._accept_outcome,
                "if self._crash_reason is not None",
                lambda: channel.event_owner.pump(max_wait_ns=WAIT_NS),
            )
        operation = next(iter(channel.event_owner._operations.values()))
        self.assertIs(operation.child, child)
        self.assertFalse(operation.outcome_consumed)
        self.assertEqual(
            channel.event_owner.safe_metadata()["pending_event_count"],
            1,
        )
        self.assertIs(
            channel.event_owner.pump(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        self.assertTrue(operation.outcome_consumed)

    def test_spawn_commit_return_interrupt_replays_event_without_child_loss(self):
        child = _FakeChild(pid=41105)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner._complete_spawn,
                "attestation.spawn_event_id",
                lambda: channel.event_owner.pump(max_wait_ns=WAIT_NS),
            )
        operation = next(iter(channel.event_owner._operations.values()))
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertEqual(record.spawn_event_id, operation.spawn_event_id)
        self.assertFalse(operation.outcome_consumed)
        self.assertEqual(
            channel.event_owner.safe_metadata()["pending_event_count"],
            1,
        )
        channel.event_owner.pump(max_wait_ns=WAIT_NS)
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        self.assertTrue(operation.outcome_consumed)
        self.assertIs(operation.child, child)

    def test_event_retire_return_interrupt_occurs_only_after_postconditions(self):
        child = _FakeChild(pid=41106)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))
        owner_type = type(channel.event_owner)
        original = owner_type._retire_event
        interrupted = False

        def retire_then_interrupt(selected, event, *, max_wait_ns):
            nonlocal interrupted
            result = original(
                selected,
                event,
                max_wait_ns=max_wait_ns,
            )
            if not interrupted and type(event) is async_module._SpawnOutcome:
                interrupted = True
                raise KeyboardInterrupt("synthetic retire return interrupt")
            return result

        with patch.object(owner_type, "_retire_event", new=retire_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                channel.event_owner.pump(max_wait_ns=WAIT_NS)
        operation = next(iter(channel.event_owner._operations.values()))
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertTrue(operation.outcome_consumed)
        self.assertEqual(record.spawn_event_id, operation.spawn_event_id)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)

    def test_worker_start_interrupt_without_ident_fails_closed_and_retains_source(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()

        with self.assertRaisesRegex(EndpointPolicyError, "ARM ack"):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner._begin_worker,
                "thread.start()",
                lambda: _drive_active(spawner, request, publication),
            )
        self.assertEqual(len(worker.calls), 0)
        metadata = channel.event_owner.safe_metadata()
        self.assertTrue(metadata["crashed"])
        self.assertEqual(metadata["worker_source_count"], 1)
        self.assertEqual(metadata["pending_event_count"], 0)
        self.assertFalse(channel.epoch_rotation_ready())
        record = next(iter(channel.ports.ledger._operations.values()))
        self.assertIs(
            record.poison_reason,
            contract._PoisonReason.OS_ACTION_UNCERTAIN,
        )
        self.assertFalse(record.child_ever_owned)
        self.assertFalse(record.spawn_created)

    def test_worker_start_return_interrupt_observes_exact_thread_once(self):
        child = _FakeChild(pid=41107)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()

        kernel = _call_with_line_interrupt(
            async_module._AsyncSupervisorEventOwner._begin_worker,
            'operation.worker_state = "started"',
            lambda: _drive_active(spawner, request, publication),
            occurrence=2,
        )
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        self.assertEqual(len(worker.calls), 1)
        self.assertEqual(
            channel.event_owner.safe_metadata()["worker_started_count"],
            1,
        )

    def test_worker_construction_publication_survives_true_callee_return_event(self):
        child = _FakeChild(pid=41108)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        target_code = type(worker).spawn.__code__
        fired = Event()

        def interrupt(frame, event, arg):
            del arg
            if (
                not fired.is_set()
                and event == "return"
                and frame.f_code is target_code
            ):
                fired.set()
                raise KeyboardInterrupt("synthetic callee return interruption")
            return interrupt

        previous = threading.gettrace()
        threading.settrace(interrupt)
        try:
            kernel = _drive_active(spawner, request, publication)
            self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        finally:
            threading.settrace(previous)

        self.assertTrue(fired.is_set())
        self.assertEqual(len(worker.calls), 1)
        operation = next(iter(channel.event_owner._operations.values()))
        self.assertIs(operation.child, child)
        self.assertTrue(operation.outcome_consumed)
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["worker_source_count"], 0)
        self.assertEqual(metadata["worker_construction_publication_count"], 0)
        self.assertEqual(metadata["worker_construction_child_count"], 0)
        self.assertFalse(metadata["crashed"])
        self.assertIs(
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            ),
            kernel,
        )
        self.assertEqual(len(worker.calls), 1)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        terminal = channel.event_owner.safe_metadata()
        self.assertEqual(terminal["worker_source_count"], 0)
        self.assertEqual(
            terminal["worker_construction_publication_count"],
            0,
        )
        self.assertEqual(terminal["operation_count"], 0)

    def test_worker_construction_publication_survives_publish_return_event(self):
        child = _FakeChild(pid=41118)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        target_code = async_module._SpawnConstructionPublication.publish.__code__
        fired = Event()

        def interrupt(frame, event, arg):
            del arg
            if (
                not fired.is_set()
                and event == "return"
                and frame.f_code is target_code
            ):
                fired.set()
                raise KeyboardInterrupt("synthetic publication return interruption")
            return interrupt

        previous = threading.gettrace()
        threading.settrace(interrupt)
        try:
            kernel = _drive_active(spawner, request, publication)
            self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        finally:
            threading.settrace(previous)

        self.assertTrue(fired.is_set())
        self.assertEqual(len(worker.calls), 1)
        operation = next(iter(channel.event_owner._operations.values()))
        self.assertIs(operation.child, child)
        self.assertTrue(operation.outcome_consumed)
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["worker_source_count"], 0)
        self.assertEqual(metadata["worker_construction_publication_count"], 0)
        self.assertEqual(metadata["worker_construction_child_count"], 0)
        self.assertFalse(metadata["crashed"])

    def test_worker_construction_publication_survives_outcome_return_event(self):
        child = _FakeChild(pid=41119)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        target_code = (
            async_module._AsyncSupervisorEventOwner
            ._publish_worker_outcome.__code__
        )
        fired = Event()

        def interrupt(frame, event, arg):
            del arg
            if (
                not fired.is_set()
                and event == "return"
                and frame.f_code is target_code
            ):
                fired.set()
                raise KeyboardInterrupt("synthetic outcome return interruption")
            return interrupt

        previous = threading.gettrace()
        threading.settrace(interrupt)
        try:
            kernel = _drive_active(spawner, request, publication)
            self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        finally:
            threading.settrace(previous)

        self.assertTrue(fired.is_set())
        self.assertEqual(len(worker.calls), 1)
        operation = next(iter(channel.event_owner._operations.values()))
        self.assertIs(operation.child, child)
        self.assertTrue(operation.outcome_consumed)
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["worker_source_count"], 0)
        self.assertEqual(metadata["worker_construction_publication_count"], 0)
        self.assertEqual(metadata["pending_outcome_operation_count"], 0)
        self.assertFalse(metadata["crashed"])

    def test_worker_construction_recovery_covers_every_post_spawn_line_gap(self):
        cases = (
            (
                async_module._AsyncSupervisorEventOwner._run_worker,
                "while True:",
            ),
            (
                async_module._AsyncSupervisorEventOwner
                ._publish_construction_outcomes,
                "snapshot = publication.snapshot()",
            ),
            (
                async_module._AsyncSupervisorEventOwner
                ._publish_construction_outcomes,
                "outcome = _SpawnOutcome(",
            ),
            (
                async_module._EventInbox.publish_outcome,
                "self._outcome_operation_ids.add",
            ),
            (
                async_module._EventInbox.publish_outcome,
                "retained = self._ordered.setdefault",
            ),
            (
                async_module._AsyncSupervisorEventOwner
                ._publish_construction_outcomes,
                "self._publish_worker_outcome(outcome)",
            ),
        )
        for index, (target, needle) in enumerate(cases):
            with self.subTest(needle=needle):
                child = _FakeChild(pid=41130 + index)
                worker = _Worker(child)
                channel, spawner = _new_stack(worker)
                request, publication = _request_and_publication(
                    lifecycle_id=UUID(int=91_100 + index * 2),
                    publication_id=UUID(int=91_101 + index * 2),
                )
                lines, first_line = inspect.getsourcelines(target)
                target_line = next(
                    first_line + offset
                    for offset, line in enumerate(lines)
                    if needle in line
                )
                fired = Event()

                def interrupt(frame, event, arg):
                    del arg
                    if (
                        not fired.is_set()
                        and event == "line"
                        and frame.f_code is target.__code__
                        and frame.f_lineno == target_line
                    ):
                        fired.set()
                        raise KeyboardInterrupt(
                            "synthetic post-spawn line interruption"
                        )
                    return interrupt

                previous = threading.gettrace()
                previous_excepthook = threading.excepthook
                threading.settrace(interrupt)
                threading.excepthook = lambda args: None
                try:
                    kernel = _drive_active(spawner, request, publication)
                    self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
                finally:
                    threading.settrace(previous)
                    threading.excepthook = previous_excepthook
                self.assertTrue(fired.is_set())
                self.assertEqual(len(worker.calls), 1)
                operation = next(
                    iter(channel.event_owner._operations.values())
                )
                self.assertIs(operation.child, child)
                metadata = channel.event_owner.safe_metadata()
                self.assertEqual(metadata["worker_source_count"], 0)
                self.assertEqual(
                    metadata["worker_construction_publication_count"],
                    0,
                )
                self.assertFalse(metadata["crashed"])

    def test_outcome_index_precedes_event_visibility_and_blocks_rotation(self):
        class _BlockBeforeIndexAdd(set):
            def __init__(self):
                super().__init__()
                self.entered = Event()
                self.release = Event()

            def add(self, value):
                self.entered.set()
                self.release.wait(1)
                return super().add(value)

        child = _FakeChild(pid=41138)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        blocked = _BlockBeforeIndexAdd()
        channel.event_owner._events._outcome_operation_ids = blocked
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(blocked.entered.wait(0.5))

        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["pending_event_count"], 0)
        self.assertEqual(metadata["pending_outcome_operation_count"], 0)
        self.assertEqual(metadata["worker_source_count"], 1)
        self.assertEqual(metadata["worker_construction_publication_count"], 1)
        self.assertFalse(channel.event_owner.epoch_rotation_ready())
        self.assertFalse(channel.epoch_rotation_ready())

        blocked.release.set()
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        for _ in range(20):
            selected = kernel.close_pipes(max_wait_ns=WAIT_NS)
            if selected is resolver.COMPLETE:
                break
        self.assertIs(selected, resolver.COMPLETE)
        self.assertEqual(len(worker.calls), 1)
        self.assertEqual(child.close_count, 1)

    def test_consumed_outcome_receipt_blocks_commit_ack_loss_redelivery(self):
        class _CommitEventThenRaise(dict):
            def __init__(self, values):
                super().__init__(values)
                self.entered = Event()
                self.release = Event()
                self.spawn_setdefault_calls = 0

            def setdefault(self, key, value=None):
                retained = super().setdefault(key, value)
                if key[0] == "spawn":
                    self.spawn_setdefault_calls += 1
                    if not self.entered.is_set():
                        self.entered.set()
                        self.release.wait(1)
                        raise KeyboardInterrupt(
                            "synthetic outcome commit ACK loss"
                        )
                return retained

        child = _FakeChild(pid=41139)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        committed = _CommitEventThenRaise(
            channel.event_owner._events._ordered
        )
        channel.event_owner._events._ordered = committed
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=91_260),
            publication_id=UUID(int=91_261),
        )
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(committed.entered.wait(0.5))
        construction = next(
            iter(channel.event_owner._worker_publications.values())
        )
        thread = construction.worker_thread()

        # The event owner may consume and terminally clean the child while
        # the producer still cannot observe its committed setdefault return.
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        live = channel.event_owner.safe_metadata()
        self.assertEqual(live["operation_count"], 0)
        self.assertEqual(live["worker_source_count"], 1)
        self.assertEqual(live["outcome_delivery_receipt_count"], 1)

        committed.release.set()
        thread.join(0.5)
        self.assertFalse(thread.is_alive())
        for _ in range(20):
            selected = kernel.close_pipes(max_wait_ns=WAIT_NS)
            if selected is resolver.COMPLETE:
                break

        self.assertIs(selected, resolver.COMPLETE)
        self.assertEqual(len(worker.calls), 1)
        self.assertGreaterEqual(committed.spawn_setdefault_calls, 2)
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        terminal = channel.event_owner.safe_metadata()
        self.assertFalse(terminal["crashed"])
        self.assertEqual(terminal["pending_event_count"], 0)
        self.assertEqual(terminal["pending_outcome_operation_count"], 0)
        self.assertEqual(terminal["outcome_delivery_receipt_count"], 0)
        self.assertEqual(terminal["worker_source_count"], 0)
        self.assertEqual(
            terminal["worker_construction_publication_count"],
            0,
        )

    def test_live_worker_after_event_commit_blocks_256th_epoch_rotation(self):
        class _CommitEventThenBlock(dict):
            def __init__(self, values):
                super().__init__(values)
                self.entered = Event()
                self.release = Event()

            def setdefault(self, key, value=None):
                retained = super().setdefault(key, value)
                if key[0] == "spawn" and not self.entered.is_set():
                    self.entered.set()
                    self.release.wait(1)
                return retained

        worker = _FactoryWorker()
        channel, spawner = _new_stack(worker)
        for index in range(
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES - 1
        ):
            prior_request, prior_publication = _request_and_publication(
                lifecycle_id=UUID(int=92_000 + index * 2),
                publication_id=UUID(int=92_001 + index * 2),
            )
            prior_kernel = _drive_active(
                spawner,
                prior_request,
                prior_publication,
            )
            self.assertEqual(
                _wait_ready(prior_kernel),
                resolver.READY_FRAME,
            )
            self.assertIs(
                prior_kernel.terminate(max_wait_ns=WAIT_NS),
                resolver.COMPLETE,
            )
            self.assertEqual(_wait_reap(prior_kernel), 9)
            for _ in range(20):
                selected = prior_kernel.close_pipes(max_wait_ns=WAIT_NS)
                if selected is resolver.COMPLETE:
                    break
            self.assertIs(selected, resolver.COMPLETE)
        self.assertEqual(
            channel._base.safe_metadata()["terminal_tombstone_count"],
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES - 1,
        )
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "released_operation_tombstone_count"
            ],
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES - 1,
        )
        blocked = _CommitEventThenBlock(
            channel.event_owner._events._ordered
        )
        channel.event_owner._events._ordered = blocked
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=91_250),
            publication_id=UUID(int=91_251),
        )
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(blocked.entered.wait(0.5))
        child = worker.children[kernel._binding.operation_id]
        construction = next(
            iter(channel.event_owner._worker_publications.values())
        )
        thread = construction.worker_thread()

        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(_wait_reap(kernel), 9)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(
            metadata["released_operation_tombstone_count"],
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES,
        )
        self.assertEqual(metadata["pending_event_count"], 0)
        self.assertEqual(metadata["pending_outcome_operation_count"], 1)
        self.assertEqual(metadata["outcome_delivery_receipt_count"], 1)
        self.assertEqual(metadata["worker_source_count"], 1)
        self.assertEqual(metadata["worker_construction_publication_count"], 1)
        self.assertTrue(thread.is_alive())
        self.assertFalse(channel.event_owner.epoch_rotation_ready())
        self.assertFalse(channel.epoch_rotation_ready())

        blocked.release.set()
        thread.join(0.5)
        self.assertFalse(thread.is_alive())
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["pending_outcome_operation_count"], 0)
        self.assertEqual(metadata["worker_source_count"], 0)
        self.assertEqual(metadata["worker_construction_publication_count"], 0)
        self.assertTrue(channel.event_owner.epoch_rotation_ready())
        self.assertTrue(channel.epoch_rotation_ready())
        self.assertEqual(
            len(worker.children),
            async_module._MAX_RELEASED_OPERATION_TOMBSTONES,
        )
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_nonconforming_worker_true_return_never_forges_zero_child_completion(self):
        class _NonconformingWorker:
            def __init__(self):
                self.child = _FakeChild(pid=41140)
                self.calls = 0
                self.returned = Event()

            def spawn(self, binding, *, publication):
                del binding, publication
                self.calls += 1
                self.returned.set()
                return self.child

        worker = _NonconformingWorker()
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        target_code = type(worker).spawn.__code__
        fired = Event()

        def interrupt(frame, event, arg):
            del arg
            if (
                not fired.is_set()
                and event == "return"
                and frame.f_code is target_code
            ):
                fired.set()
                raise KeyboardInterrupt("synthetic nonconforming return gap")
            return interrupt

        previous = threading.gettrace()
        threading.settrace(interrupt)
        try:
            kernel = _drive_active(spawner, request, publication)
            self.assertTrue(worker.returned.wait(0.5))
        finally:
            threading.settrace(previous)
        for _ in range(20):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if channel.ports.ledger.safe_metadata()["poisoned"]:
                break

        self.assertTrue(fired.is_set())
        self.assertEqual(worker.calls, 1)
        record = channel.ports.control.query(kernel._binding)
        self.assertFalse(record.spawn_created)
        self.assertFalse(record.child_ever_owned)
        metadata = channel.event_owner.safe_metadata()
        self.assertTrue(metadata["crashed"])
        self.assertEqual(metadata["worker_source_count"], 1)
        self.assertEqual(metadata["worker_construction_publication_count"], 1)
        self.assertEqual(worker.child.close_count, 0)
        self.assertFalse(channel.epoch_rotation_ready())

    def test_begun_empty_worker_failure_stays_uncertain_and_nonterminal(self):
        class _BegunEmptyWorker:
            def __init__(self):
                self.calls = 0
                self.finished = Event()

            def spawn(self, binding, *, publication):
                del binding
                self.calls += 1
                publication.begin()
                self.finished.set()
                raise KeyboardInterrupt("nested construction return gap")

        worker = _BegunEmptyWorker()
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.finished.wait(0.5))
        for _ in range(20):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if channel.ports.ledger.safe_metadata()["poisoned"]:
                break

        record = channel.ports.control.query(kernel._binding)
        self.assertEqual(worker.calls, 1)
        self.assertFalse(record.spawn_created)
        self.assertFalse(record.child_ever_owned)
        metadata = channel.event_owner.safe_metadata()
        self.assertTrue(metadata["crashed"])
        self.assertEqual(metadata["worker_source_count"], 1)
        self.assertEqual(metadata["worker_construction_publication_count"], 1)
        self.assertFalse(channel.epoch_rotation_ready())

    def test_worker_publication_is_one_shot_and_extras_remain_worker_owned(self):
        class _ExtraPublishingWorker:
            def __init__(self):
                self.children = [
                    _FakeChild(pid=48_000 + index)
                    for index in range(1_001)
                ]
                self.calls = 0
                self.rejections = 0
                self.finished = Event()

            def spawn(self, binding, *, publication):
                del binding
                self.calls += 1
                publication.begin()
                publication.publish(self.children[0])
                for child in self.children[1:]:
                    try:
                        publication.publish(child)
                    except EndpointPolicyError:
                        self.rejections += 1
                self.finished.set()
                return None

        worker = _ExtraPublishingWorker()
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.finished.wait(0.5))
        for _ in range(20):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if worker.children[0].close_count:
                break

        self.assertEqual(worker.calls, 1)
        self.assertEqual(worker.rejections, 1_000)
        record = channel.ports.control.query(kernel._binding)
        self.assertFalse(record.spawn_created)
        self.assertFalse(record.child_ever_owned)
        self.assertEqual(
            worker.children[0].terminate_pids,
            [worker.children[0].pid],
        )
        self.assertEqual(
            worker.children[0].reap_pids,
            [worker.children[0].pid],
        )
        self.assertEqual(worker.children[0].close_count, 1)
        self.assertTrue(
            all(
                child.close_count == 0
                and child.terminate_pids == []
                and child.reap_pids == []
                for child in worker.children[1:]
            )
        )
        metadata = channel.event_owner.safe_metadata()
        self.assertTrue(metadata["crashed"])
        self.assertEqual(metadata["worker_source_count"], 0)
        self.assertEqual(metadata["worker_construction_publication_count"], 0)
        self.assertEqual(metadata["worker_construction_child_count"], 0)

    def test_worker_publication_identity_poison_recovers_exact_child_for_cleanup(self):
        child = _FakeChild(pid=41141)
        worker = _Worker(child, blocked=True)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.started.wait(0.5))
        operation = next(iter(channel.event_owner._operations.values()))
        construction = operation.worker_publication
        object.__setattr__(
            construction,
            "binding_digest",
            Digest256("7" * 64),
        )
        worker.release.set()
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(20):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if child.close_count:
                break

        self.assertEqual(len(worker.calls), 1)
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        record = channel.ports.control.query(kernel._binding)
        self.assertFalse(record.spawn_created)
        self.assertFalse(record.child_ever_owned)
        metadata = channel.event_owner.safe_metadata()
        self.assertTrue(metadata["crashed"])
        self.assertEqual(metadata["worker_source_count"], 0)
        self.assertEqual(metadata["worker_construction_publication_count"], 0)

    def test_terminal_close_waits_for_worker_publication_heavy_ref_release(self):
        child = _FakeChild(pid=41142)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        def interrupt_after_first_pop(selected):
            selected._state.pop("frozen", None)
            raise KeyboardInterrupt("synthetic construction release gap")

        with patch.object(
            async_module._SpawnConstructionPublication,
            "release_child",
            new=interrupt_after_first_pop,
        ):
            kernel = _drive_active(spawner, request, publication)
            self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
            self.assertIs(
                kernel.terminate(max_wait_ns=WAIT_NS),
                resolver.COMPLETE,
            )
            self.assertEqual(_wait_reap(kernel), 9)
            self.assertIs(
                kernel.close_pipes(max_wait_ns=WAIT_NS),
                resolver.PENDING,
            )
            metadata = channel.event_owner.safe_metadata()
            self.assertEqual(
                metadata["worker_construction_publication_count"],
                1,
            )
            self.assertEqual(metadata["worker_construction_child_count"], 1)

        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(metadata["worker_construction_publication_count"], 0)
        self.assertEqual(metadata["worker_construction_child_count"], 0)
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_terminal_close_waits_for_worker_publication_release_return_gap(self):
        child = _FakeChild(pid=41143)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        original = async_module._SpawnConstructionPublication.release_child

        def release_then_interrupt(selected):
            original(selected)
            raise KeyboardInterrupt("synthetic construction release return gap")

        with patch.object(
            async_module._SpawnConstructionPublication,
            "release_child",
            new=release_then_interrupt,
        ):
            kernel = _drive_active(spawner, request, publication)
            self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
            self.assertIs(
                kernel.terminate(max_wait_ns=WAIT_NS),
                resolver.COMPLETE,
            )
            self.assertEqual(_wait_reap(kernel), 9)
            self.assertIs(
                kernel.close_pipes(max_wait_ns=WAIT_NS),
                resolver.PENDING,
            )
            metadata = channel.event_owner.safe_metadata()
            self.assertEqual(
                metadata["worker_construction_publication_count"],
                1,
            )
            self.assertEqual(metadata["worker_construction_child_count"], 0)

        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "worker_construction_publication_count"
            ],
            0,
        )
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_queued_control_append_interrupt_replays_exact_reserve(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner._queue_control,
                "return _CONTROL_INBOX_QUEUED",
                lambda: spawner.spawn(
                    request,
                    publication=publication,
                    max_wait_ns=WAIT_NS,
                ),
            )
        self.assertEqual(len(channel.event_owner._events), 1)
        _drive_active(spawner, request, publication)
        self.assertEqual(channel.received_kinds.count("RESERVE"), 1)

    def test_prepublication_lock_busy_retransmits_exact_handshake_frames(self):
        cases = (
            ("RESERVE", 0),
            ("ATTACH", 1),
            ("ARM", 2),
        )
        next_identity = 80_000
        for lock_name in ("inbox", "base"):
            for kind_name, setup_calls in cases:
                with self.subTest(lock=lock_name, kind=kind_name):
                    next_identity += 10
                    child = _FakeChild(pid=45_000 + next_identity)
                    worker = _Worker(child)
                    channel, spawner = _new_stack(
                        worker,
                        drop_kinds=("NEVER",),
                    )
                    request, publication = _request_and_publication(
                        lifecycle_id=UUID(int=next_identity),
                        publication_id=UUID(int=next_identity + 1),
                    )
                    for _ in range(setup_calls):
                        self.assertIs(
                            spawner.spawn(
                                request,
                                publication=publication,
                                max_wait_ns=WAIT_NS,
                            ),
                            resolver.PENDING,
                        )
                    selected_lock = (
                        channel.event_owner._control_inbox_lock
                        if lock_name == "inbox"
                        else channel._base._lock
                    )
                    self.assertTrue(selected_lock.acquire(blocking=False))
                    try:
                        self.assertIs(
                            spawner.spawn(
                                request,
                                publication=publication,
                                max_wait_ns=WAIT_NS,
                            ),
                            resolver.PENDING,
                        )
                        operation = next(iter(spawner._operations.values()))
                        kind = wire._SupervisorWireKind(kind_name)
                        cached = operation.commands[kind]
                        self.assertEqual(
                            channel.event_owner.safe_metadata()[
                                "pending_control_event_count"
                            ],
                            0 if lock_name == "inbox" else 1,
                        )
                    finally:
                        selected_lock.release()

                    kernel = _drive_active(spawner, request, publication)
                    sent = [
                        frame
                        for frame in spawner._channel.frames
                        if wire._decode_supervisor_wire_frame(frame).kind
                        is kind
                    ]
                    self.assertEqual(len(sent), 2)
                    self.assertEqual(sent[0], sent[1])
                    self.assertEqual(
                        sent[0],
                        wire._encode_supervisor_wire_frame(cached),
                    )
                    self.assertEqual(channel.received_kinds.count(kind_name), 1)
                    self.assertEqual(
                        next(iter(channel.ports.ledger._operations.values()))
                        .revision,
                        2,
                    )
                    _wait_ready(kernel)
                    while kernel.terminate(max_wait_ns=WAIT_NS) is resolver.PENDING:
                        pass
                    self.assertEqual(_wait_reap(kernel), 9)
                    while kernel.close_pipes(max_wait_ns=WAIT_NS) is resolver.PENDING:
                        pass
                    self.assertEqual(child.terminate_pids, [child.pid])
                    self.assertEqual(child.reap_pids, [child.pid])
                    self.assertEqual(child.close_count, 1)

    def test_prepublication_lock_busy_retransmits_cancel_and_release(self):
        for index, lock_name in enumerate(("inbox", "base")):
            with self.subTest(lock=lock_name):
                child = _FakeChild(pid=46_000 + index)
                channel, spawner = _new_stack(
                    _Worker(child),
                    drop_kinds=("NEVER",),
                )
                request, publication = _request_and_publication(
                    lifecycle_id=UUID(int=81_000 + index * 2),
                    publication_id=UUID(int=81_001 + index * 2),
                )
                kernel = _drive_active(spawner, request, publication)
                _wait_ready(kernel)
                selected_lock = (
                    channel.event_owner._control_inbox_lock
                    if lock_name == "inbox"
                    else channel._base._lock
                )

                self.assertTrue(selected_lock.acquire(blocking=False))
                try:
                    self.assertIs(
                        kernel.terminate(max_wait_ns=WAIT_NS),
                        resolver.PENDING,
                    )
                    cancel_frame = kernel._cancel_frame
                    self.assertIsNotNone(cancel_frame)
                finally:
                    selected_lock.release()
                while kernel.terminate(max_wait_ns=WAIT_NS) is resolver.PENDING:
                    pass
                cancel_sends = [
                    frame
                    for frame in spawner._channel.frames
                    if wire._decode_supervisor_wire_frame(frame).kind
                    is wire._SupervisorWireKind.CANCEL
                ]
                self.assertEqual(len(cancel_sends), 2)
                self.assertEqual(cancel_sends[0], cancel_sends[1])
                self.assertEqual(
                    cancel_sends[0],
                    wire._encode_supervisor_wire_frame(cancel_frame),
                )
                self.assertEqual(channel.received_kinds.count("CANCEL"), 1)
                self.assertEqual(_wait_reap(kernel), 9)

                self.assertTrue(selected_lock.acquire(blocking=False))
                try:
                    self.assertIs(
                        kernel.close_pipes(max_wait_ns=WAIT_NS),
                        resolver.PENDING,
                    )
                    release_frame = kernel._release_frame
                    self.assertIsNotNone(release_frame)
                finally:
                    selected_lock.release()
                while kernel.close_pipes(max_wait_ns=WAIT_NS) is resolver.PENDING:
                    pass
                release_sends = [
                    frame
                    for frame in spawner._channel.frames
                    if wire._decode_supervisor_wire_frame(frame).kind
                    is wire._SupervisorWireKind.RELEASE
                ]
                self.assertEqual(len(release_sends), 2)
                self.assertEqual(release_sends[0], release_sends[1])
                self.assertEqual(
                    release_sends[0],
                    wire._encode_supervisor_wire_frame(release_frame),
                )
                self.assertEqual(channel.received_kinds.count("RELEASE"), 1)
                self.assertEqual(child.terminate_pids, [child.pid])
                self.assertEqual(child.reap_pids, [child.pid])
                self.assertEqual(child.close_count, 1)

    def test_cancel_and_release_frame_assignment_interrupts_retry_exact_send(self):
        child = _FakeChild(pid=46_010)
        channel, spawner = _new_stack(
            _Worker(child),
            drop_kinds=("NEVER",),
        )
        request, publication = _request_and_publication(
            lifecycle_id=UUID(int=81_010),
            publication_id=UUID(int=81_011),
        )
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                proxy_module._SupervisorHelperKernel.terminate,
                "result = self._exchange(",
                lambda: kernel.terminate(max_wait_ns=WAIT_NS),
            )
        self.assertIsNotNone(kernel._cancel_frame)
        self.assertEqual(channel.received_kinds.count("CANCEL"), 0)
        while kernel.terminate(max_wait_ns=WAIT_NS) is resolver.PENDING:
            pass
        self.assertEqual(channel.received_kinds.count("CANCEL"), 1)
        self.assertEqual(_wait_reap(kernel), 9)

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                proxy_module._SupervisorHelperKernel._close_pipes_locked,
                "result = self._exchange(",
                lambda: kernel.close_pipes(max_wait_ns=WAIT_NS),
            )
        self.assertIsNotNone(kernel._release_frame)
        self.assertEqual(channel.received_kinds.count("RELEASE"), 0)
        while kernel.close_pipes(max_wait_ns=WAIT_NS) is resolver.PENDING:
            pass
        self.assertEqual(channel.received_kinds.count("RELEASE"), 1)
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)

    def test_pending_exact_control_retries_share_one_bounded_inbox_entry(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        base_lock = channel._base._lock
        self.assertTrue(base_lock.acquire(blocking=False))
        try:
            self.assertIs(
                spawner.spawn(
                    request,
                    publication=publication,
                    max_wait_ns=WAIT_NS,
                ),
                resolver.PENDING,
            )
            event = channel.event_owner._events[0]
            self.assertIs(type(event), async_module._QueuedControl)
            for _ in range(200):
                self.assertIs(
                    channel.exchange(
                        event.frame_bytes,
                        max_wait_ns=WAIT_NS,
                    ),
                    resolver.PENDING,
                )
                metadata = channel.event_owner.safe_metadata()
                self.assertEqual(metadata["pending_control_event_count"], 1)
                self.assertEqual(metadata["pending_event_count"], 1)
        finally:
            base_lock.release()
        _drive_active(spawner, request, publication)
        self.assertEqual(channel.received_kinds.count("RESERVE"), 1)

    def test_completed_exact_control_retry_never_reenters_pending_inbox(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        replay = next(
            selected
            for selected in channel._base._replays.values()
            if wire._decode_supervisor_wire_frame(selected.frame_bytes).kind
            is wire._SupervisorWireKind.RESERVE
        )

        def forbidden_publish(*args, **kwargs):
            del args, kwargs
            raise AssertionError("completed retry entered pending inbox")

        with patch.object(
            async_module._EventInbox,
            "publish_control",
            new=forbidden_publish,
        ):
            response = channel.exchange(
                replay.frame_bytes,
                max_wait_ns=WAIT_NS,
            )
        self.assertIsNot(response, resolver.PENDING)
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "pending_control_event_count"
            ],
            0,
        )
        self.assertEqual(channel.received_kinds.count("RESERVE"), 1)

    def test_completed_frame_id_alias_by_query_globally_poisons(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        _wait_ready(kernel)
        replay = next(
            selected
            for selected in channel._base._replays.values()
            if wire._decode_supervisor_wire_frame(selected.frame_bytes).kind
            is wire._SupervisorWireKind.RESERVE
        )
        original = wire._decode_supervisor_wire_frame(replay.frame_bytes)
        operation = next(iter(channel.event_owner._operations.values()))
        conflict = wire._new_supervisor_wire_frame(
            kind=wire._SupervisorWireKind.QUERY,
            epoch_id=original.epoch_id,
            operation_id=original.operation_id,
            control_channel_id=original.control_channel_id,
            operation_binding_digest=original.operation_binding_digest,
            frame_id=original.frame_id,
            payload={
                "proxy_id": operation.proxy_id,
                "query_id": UUID(
                    "8c000000-0000-0000-0006-000000000001"
                ),
            },
        )
        with self.assertRaises(EndpointPolicyError):
            channel.exchange(
                wire._encode_supervisor_wire_frame(conflict),
                max_wait_ns=WAIT_NS,
            )
        metadata = channel.ports.ledger.safe_metadata()
        self.assertTrue(metadata["poisoned"])
        self.assertEqual(
            metadata["global_poison_reason"],
            "liveness_lost",
        )
        channel.event_owner.observe_broker_crash()

    def test_same_pending_frame_id_with_changed_binding_globally_poisons(self):
        worker = _Worker(_FakeChild())
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        base_lock = channel._base._lock
        self.assertTrue(base_lock.acquire(blocking=False))
        try:
            self.assertIs(
                spawner.spawn(
                    request,
                    publication=publication,
                    max_wait_ns=WAIT_NS,
                ),
                resolver.PENDING,
            )
        finally:
            base_lock.release()
        pending = channel.event_owner._events[0]
        original = pending.command
        changed_digest = Digest256("e" * 64)
        changed_binding = contract._new_supervisor_operation_binding(
            epoch_id=original.epoch_id,
            operation_id=original.operation_id,
            lifecycle_id=original.payload["lifecycle_id"],
            publication_id=original.payload["publication_id"],
            spawn_request_digest=changed_digest,
        )
        conflict = wire._new_supervisor_wire_frame(
            kind=wire._SupervisorWireKind.RESERVE,
            epoch_id=original.epoch_id,
            operation_id=original.operation_id,
            control_channel_id=original.control_channel_id,
            operation_binding_digest=changed_binding.binding_digest,
            frame_id=original.frame_id,
            payload={
                "lifecycle_id": original.payload["lifecycle_id"],
                "publication_id": original.payload["publication_id"],
                "spawn_request_digest": changed_digest,
            },
        )
        with self.assertRaises(EndpointPolicyError):
            channel.exchange(
                wire._encode_supervisor_wire_frame(conflict),
                max_wait_ns=WAIT_NS,
            )
        metadata = channel.ports.ledger.safe_metadata()
        self.assertTrue(metadata["poisoned"])
        self.assertEqual(
            metadata["global_poison_reason"],
            "liveness_lost",
        )

    def test_unique_control_flood_stops_at_the_fixed_pending_limit(self):
        worker = _Worker(_FakeChild())
        channel, _ = _new_stack(worker)
        base_lock = channel._base._lock
        self.assertTrue(base_lock.acquire(blocking=False))
        try:
            for index in range(async_module._MAX_PENDING_CONTROL_EVENTS + 1):
                binding = contract._new_supervisor_operation_binding(
                    epoch_id=EPOCH_ID,
                    operation_id=UUID(
                        f"8c000000-0000-0000-0002-{index + 1:012d}"
                    ),
                    lifecycle_id=UUID(
                        f"8c000000-0000-0000-0003-{index + 1:012d}"
                    ),
                    publication_id=UUID(
                        f"8c000000-0000-0000-0004-{index + 1:012d}"
                    ),
                    spawn_request_digest=Digest256(f"{index + 1:064x}"),
                )
                command = wire._new_supervisor_wire_frame(
                    kind=wire._SupervisorWireKind.RESERVE,
                    epoch_id=EPOCH_ID,
                    operation_id=binding.operation_id,
                    control_channel_id=CHANNEL_ID,
                    operation_binding_digest=binding.binding_digest,
                    frame_id=UUID(
                        f"8c000000-0000-0000-0005-{index + 1:012d}"
                    ),
                    payload={
                        "lifecycle_id": binding.lifecycle_id,
                        "publication_id": binding.publication_id,
                        "spawn_request_digest": (
                            binding.spawn_request_digest
                        ),
                    },
                )
                encoded = wire._encode_supervisor_wire_frame(command)
                if index < async_module._MAX_PENDING_CONTROL_EVENTS:
                    self.assertIs(
                        channel.exchange(encoded, max_wait_ns=WAIT_NS),
                        resolver.PENDING,
                    )
                else:
                    with self.assertRaises(EndpointPolicyError):
                        channel.exchange(encoded, max_wait_ns=WAIT_NS)
        finally:
            base_lock.release()
        metadata = channel.event_owner.safe_metadata()
        self.assertEqual(
            metadata["pending_control_event_count"],
            async_module._MAX_PENDING_CONTROL_EVENTS,
        )
        self.assertTrue(metadata["crashed"])

    def test_emergency_pre_action_interrupt_freezes_unknown_without_replay(self):
        child = _FakeChild(pid=41104)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        _drive_active(spawner, request, publication)
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(100):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if channel.event_owner.safe_metadata()["frozen_child_count"]:
                break
            time.sleep(0.001)

        _call_with_line_interrupt(
            async_module._AsyncSupervisorEventOwner._emergency_cleanup_child,
            "result = child.terminate_exact",
            channel.event_owner.observe_broker_crash,
        )
        operation = next(iter(channel.event_owner._operations.values()))
        self.assertEqual(operation.terminate_state, "unknown")
        self.assertFalse(operation.emergency_cleaned)
        self.assertEqual(child.terminate_pids, [])
        channel.event_owner.observe_broker_crash()
        self.assertEqual(child.terminate_pids, [])

    def test_poison_reason_is_the_single_durable_crash_marker(self):
        child = _FakeChild(pid=41109)
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        _drive_active(spawner, request, publication)

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner
                ._poison_unknown_os_action,
                "self._ensure_global_poison()",
                channel.event_owner._poison_unknown_os_action,
            )
        self.assertTrue(channel.event_owner.safe_metadata()["crashed"])
        channel.event_owner.pump(max_wait_ns=WAIT_NS)
        metadata = channel.ports.ledger.safe_metadata()
        self.assertTrue(metadata["poisoned"])
        self.assertEqual(
            metadata["global_poison_reason"],
            "os_action_uncertain",
        )

    def test_broker_crash_before_late_spawn_cleans_frozen_child_once(self):
        class _PendingCrashChild(_FakeChild):
            def __init__(self):
                super().__init__(pid=41103)
                self.terminate_calls = 0
                self.reap_calls = 0
                self.close_calls = 0

            def terminate_exact(self, pid, *, max_wait_ns):
                self.assert_wait(max_wait_ns)
                self.terminate_calls += 1
                if self.terminate_calls == 1:
                    return resolver.PENDING
                return super().terminate_exact(pid, max_wait_ns=max_wait_ns)

            def reap_exact(self, pid, *, max_wait_ns):
                self.assert_wait(max_wait_ns)
                self.reap_calls += 1
                if self.reap_calls == 1:
                    return resolver.PENDING
                return super().reap_exact(pid, max_wait_ns=max_wait_ns)

            def close_exact(self, *, max_wait_ns):
                self.assert_wait(max_wait_ns)
                self.close_calls += 1
                if self.close_calls == 1:
                    return resolver.PENDING
                return super().close_exact(max_wait_ns=max_wait_ns)

        child = _PendingCrashChild()
        worker = _Worker(child, blocked=True)
        channel, spawner = _new_stack(worker)
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertTrue(worker.started.wait(0.5))

        channel.event_owner.observe_broker_crash()
        worker.release.set()
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(100):
            channel.event_owner.pump(max_wait_ns=WAIT_NS)
            if child.close_count:
                break
            time.sleep(0.001)

        self.assertEqual(child.stdout, [resolver.READY_FRAME])
        self.assertEqual(child.writes, [])
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertEqual(child.terminate_calls, 2)
        self.assertEqual(child.reap_calls, 2)
        self.assertEqual(child.close_calls, 2)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertEqual(
            channel.event_owner.safe_metadata()["frozen_child_count"],
            1,
        )
        with self.assertRaises(EndpointPolicyError):
            kernel.read_stdout(64, max_wait_ns=WAIT_NS)
        self.assertFalse(channel.session_closed)

    def test_real_resolver_guard_uses_event_owner_for_single_start(self):
        from tests.test_w09_resolver_lifecycle import _make_stop_authority

        _, _, _, stop_authority = _make_stop_authority()
        child = _FakeChild()
        worker = _Worker(child)
        channel, spawner = _new_stack(worker)
        launcher = resolver.ResolverHelperLauncher(
            spawner,
            executable="/bin/echo",
        )
        ticket = launcher._reserve_lifecycle_capability(
            reservation_owner=object(),
            stop_authority=stop_authority,
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )
        pre = launcher._launch_ready(
            capability=ticket,
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertTrue(
            launcher._consume_ready_publication(
                ticket,
                pre,
                _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        attempt = pre._transfer(
            attempt_permit_id=UUID(
                "8c000000-0000-0000-0000-000000000021"
            ),
            attempt_permit_digest=Digest256("e" * 64),
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )
        attempt._start(
            hostname="open.bigmodel.cn",
            port=443,
            network_policy_ref="snapquiz.internet-public-address-policy.v1",
            network_policy_digest=Digest256("f" * 64),
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )

        self.assertEqual(len(child.writes), 1)
        record = next(iter(channel.ports.ledger._operations.values()))
        async_operation = next(
            iter(channel.event_owner._operations.values())
        )
        worker_thread = async_operation.worker_thread
        kernel = attempt._ledger._kernel
        parent_proxy = kernel._proxy
        child_ref = weakref.ref(child)
        thread_ref = weakref.ref(worker_thread)
        kernel_ref = weakref.ref(kernel)
        proxy_ref = weakref.ref(parent_proxy)
        self.assertEqual(record.state.value, "started")
        self.assertTrue(record.start_committed)
        self.assertTrue(attempt.cleanup())
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertFalse(channel.session_closed)
        self.assertEqual(len(channel.ports.ledger._operations), 0)
        self.assertEqual(len(channel.ports.ledger._query_replies), 0)
        self.assertEqual(len(channel.ports.parent_session._operations), 0)
        self.assertEqual(len(channel._base._replays), 0)
        self.assertEqual(len(channel._base._stdout_by_operation), 0)
        self.assertEqual(len(channel._base._stdin_by_operation), 0)
        self.assertEqual(len(channel._base._closed_operations), 0)
        self.assertEqual(len(channel.event_owner._operations), 0)
        self.assertEqual(len(channel.event_owner._proxies), 0)
        self.assertEqual(len(channel.event_owner._events), 0)
        self.assertEqual(
            channel.event_owner.safe_metadata()[
                "worker_construction_publication_count"
            ],
            0,
        )
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)

        worker.child = None
        del record
        del async_operation
        del worker_thread
        del kernel
        del parent_proxy
        del child
        gc.collect()
        self.assertIsNone(child_ref())
        self.assertIsNone(thread_ref())
        self.assertIsNone(kernel_ref())
        self.assertIsNone(proxy_ref())

    def test_resolver_cleanup_waits_then_ticket_retry_releases_late_child(self):
        from tests.test_w09_resolver_lifecycle import _make_stop_authority

        runtime, _, _, stop_authority = _make_stop_authority()
        child = _FakeChild()
        worker = _Worker(
            child,
            blocked=True,
            on_spawn=lambda: runtime.cancellation_source.cancel(
                reason=CancellationReason.USER_REQUEST
            ),
        )
        channel, spawner = _new_stack(worker)
        launcher = resolver.ResolverHelperLauncher(
            spawner,
            executable="/bin/echo",
        )
        reservation_owner = object()
        launch_owner = object()
        ticket = launcher._reserve_lifecycle_capability(
            reservation_owner=reservation_owner,
            stop_authority=stop_authority,
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )

        with self.assertRaises(CancelledError):
            launcher._launch_ready(
                capability=ticket,
                launch_owner=launch_owner,
                _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
            )
        recovery = launcher._lifecycle_recovery[ticket.publication_id]
        self.assertEqual(
            recovery.ledger.safe_metadata()["state"],
            "cleanup_waiting_supervisor",
        )
        kernel = recovery.ledger._kernel
        self.assertEqual(
            kernel._proxy.safe_metadata()["cleanup_pending_count"],
            contract.SUPERVISOR_CLEANUP_PENDING_LIMIT,
        )

        worker.release.set()
        self.assertTrue(worker.returned.wait(0.5))
        for _ in range(100):
            complete = launcher._recover_ready_publication_for_cleanup(
                ticket,
                launch_owner=launch_owner,
                _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
            )
            if complete:
                break
            time.sleep(0.001)
        self.assertTrue(complete)
        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertEqual(child.terminate_pids, [child.pid])
        self.assertEqual(child.reap_pids, [child.pid])
        self.assertEqual(child.close_count, 1)
        self.assertFalse(channel.session_closed)

    def test_concurrent_spawn_soak_freezes_one_unique_child_per_operation(self):
        worker = _FactoryWorker()
        channel, spawner = _new_stack(worker)
        inputs = [
            _request_and_publication(
                lifecycle_id=UUID(
                    f"8c000000-0000-0000-0010-{index + 1:012d}"
                ),
                publication_id=UUID(
                    f"8c000000-0000-0000-0020-{index + 1:012d}"
                ),
            )
            for index in range(8)
        ]
        kernels = [None] * len(inputs)
        failures = []

        def activate(index):
            request, publication = inputs[index]
            try:
                for _ in range(5000):
                    selected = spawner.spawn(
                        request,
                        publication=publication,
                        max_wait_ns=WAIT_NS,
                    )
                    if selected is not resolver.PENDING:
                        kernels[index] = selected
                        return
                    time.sleep(0.0001)
                raise AssertionError("concurrent spawn did not converge")
            except BaseException as error:
                failures.append(error)

        threads = [
            Thread(target=activate, args=(index,))
            for index in range(len(inputs))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        self.assertFalse(failures)
        self.assertTrue(all(kernel is not None for kernel in kernels))

        for kernel in kernels:
            _wait_ready(kernel)
            while kernel.terminate(max_wait_ns=WAIT_NS) is resolver.PENDING:
                pass
            self.assertIsInstance(_wait_reap(kernel), int)
            while kernel.close_pipes(max_wait_ns=WAIT_NS) is resolver.PENDING:
                pass

        self.assertEqual(len(worker.children), len(inputs))
        self.assertEqual(
            len({child.pid for child in worker.children.values()}),
            len(inputs),
        )
        self.assertEqual(channel.received_kinds.count("RESERVE"), len(inputs))
        self.assertEqual(channel.received_kinds.count("ATTACH"), len(inputs))
        self.assertEqual(channel.received_kinds.count("ARM"), len(inputs))
        for child in worker.children.values():
            self.assertEqual(child.terminate_pids, [child.pid])
            self.assertEqual(child.reap_pids, [child.pid])
            self.assertEqual(child.close_count, 1)
        self.assertFalse(channel.session_closed)


class _ProcessChild:
    def __init__(self):
        fixture = Path(__file__).parent / "fixtures" / "resolver_async_child.py"
        self.process = subprocess.Popen(
            [sys.executable, str(fixture)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.pid = self.process.pid
        self.terminate_pids = []
        self.reap_pids = []
        self.close_count = 0

    def read_stdout(self, max_bytes, *, max_wait_ns):
        del max_bytes, max_wait_ns
        return resolver.PENDING

    def write_start_datagram(self, frame, *, max_wait_ns):
        del frame, max_wait_ns
        raise AssertionError("soak child never receives START")

    def terminate_exact(self, pid, *, max_wait_ns):
        del max_wait_ns
        if pid != self.pid or self.terminate_pids:
            raise AssertionError("wrong process terminate")
        self.terminate_pids.append(pid)
        self.process.kill()
        return resolver.COMPLETE

    def reap_exact(self, pid, *, max_wait_ns):
        del max_wait_ns
        if pid != self.pid or self.reap_pids:
            raise AssertionError("wrong process reap")
        self.reap_pids.append(pid)
        waited_pid, status = os.waitpid(pid, 0)
        if waited_pid != pid:
            raise AssertionError("waitpid reaped a foreign child")
        self.process.returncode = os.waitstatus_to_exitcode(status)
        return self.process.returncode

    def close_exact(self, *, max_wait_ns):
        del max_wait_ns
        if self.close_count:
            raise AssertionError("process pipes closed twice")
        self.close_count += 1
        for stream in (
            self.process.stdin,
            self.process.stdout,
            self.process.stderr,
        ):
            if stream is not None:
                stream.close()
        return resolver.COMPLETE

    def force_cleanup(self):
        if self.process.returncode is None:
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=1)
            except (ChildProcessError, subprocess.TimeoutExpired):
                pass
        for stream in (
            self.process.stdin,
            self.process.stdout,
            self.process.stderr,
        ):
            if stream is not None and not stream.closed:
                stream.close()


class ResolverSupervisorProcessSoakTest(unittest.TestCase):
    def test_broker_crash_soak_reaps_exact_pid_and_closes_every_pipe(self):
        fd_root = Path("/dev/fd")
        baseline = len(tuple(fd_root.iterdir()))
        children = []
        for index in range(6):
            child = _ProcessChild()
            self.addCleanup(child.force_cleanup)
            children.append(child)
            worker = _Worker(child)
            channel = async_module._new_async_supervisor_channel(
                epoch_id=UUID(f"8c000000-0000-0000-0001-{index + 1:012d}"),
                control_channel_id=UUID(
                    f"8c000000-0000-0000-0002-{index + 1:012d}"
                ),
                spawn_worker=worker,
            )
            spawner = proxy_module._new_supervisor_helper_spawner(
                channel=channel
            )
            request, publication = _request_and_publication()
            _drive_active(spawner, request, publication)
            self.assertTrue(worker.returned.wait(0.5))
            for _ in range(100):
                channel.event_owner.pump(max_wait_ns=WAIT_NS)
                if channel.event_owner.safe_metadata()["frozen_child_count"]:
                    break
                time.sleep(0.001)
            channel.event_owner.observe_broker_crash()
            self.assertFalse(channel.session_closed)

        for child in children:
            self.assertEqual(child.terminate_pids, [child.pid])
            self.assertEqual(child.reap_pids, [child.pid])
            self.assertEqual(child.close_count, 1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
        self.assertLessEqual(len(tuple(fd_root.iterdir())), baseline + 2)


if __name__ == "__main__":
    unittest.main()
