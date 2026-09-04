"""W09-B2b-S3 durable resolver-supervisor proxy integration tests."""
from __future__ import annotations

import ast
from pathlib import Path
from threading import Event, RLock, Thread
from time import monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_supervisor_proxy as proxy_module
from snapquiz.transport import _resolver_supervisor_wire as wire
from snapquiz.transport import resolver


EPOCH_ID = UUID("8b000000-0000-0000-0000-000000000001")
CHANNEL_ID = UUID("8b000000-0000-0000-0000-000000000002")
LIFECYCLE_ID = UUID("8b000000-0000-0000-0000-000000000003")
PUBLICATION_ID = UUID("8b000000-0000-0000-0000-000000000004")
WAIT_NS = 17_000_000


class _FakeResolverLedger:
    def __init__(self, request, *, lifecycle_id, publication_id):
        self.lifecycle_id = lifecycle_id
        self._capability_snapshot = SimpleNamespace(
            lifecycle_id=lifecycle_id,
            publication_id=publication_id,
            spawn_request_digest=request.request_digest,
        )
        self._owner = object()
        self._pre_owner = self._owner
        self._lock = RLock()
        self._state = "created"
        self._kernel = None

    def attach_kernel(self, owner, kernel):
        if owner is not self._owner or self._state != "created":
            raise RuntimeError("fake resolver publication changed")
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
    return request, publication, ledger


class _ChannelWrapper:
    """Drop/raise after an exact inner commit while preserving the session."""

    def __init__(self, inner, scripts=None):
        self.inner = inner
        self.epoch_id = inner.epoch_id
        self.control_channel_id = inner.control_channel_id
        self.ports = inner.ports
        self.scripts = {
            key: list(value) for key, value in (scripts or {}).items()
        }
        self.exchange_waits = []
        self.exchange_kinds = []
        self.exchange_frames = []
        self.exchange_proofs = []

    def exchange(
        self,
        frame_bytes,
        *,
        max_wait_ns,
        local_publication_proof=None,
    ):
        command = wire._decode_supervisor_wire_frame(frame_bytes)
        self.exchange_waits.append(max_wait_ns)
        self.exchange_kinds.append(command.kind.value)
        self.exchange_frames.append(frame_bytes)
        self.exchange_proofs.append(local_publication_proof)
        actions = self.scripts.get(command.kind.value, [])
        action = actions.pop(0) if actions else "deliver"
        if action == "no-op":
            return resolver.PENDING
        result = self.inner.exchange(
            frame_bytes,
            max_wait_ns=max_wait_ns,
            local_publication_proof=local_publication_proof,
        )
        if action == "drop":
            return resolver.PENDING
        if action == "raise":
            raise RuntimeError("synthetic channel return fault")
        return result

    def bind_spawner(self, spawner):
        return self.inner.bind_spawner(spawner)

    def read_stdout(self, *args, **kwargs):
        return self.inner.read_stdout(*args, **kwargs)

    def prepare_proxy(self, **kwargs):
        return self.inner.prepare_proxy(**kwargs)

    def write_stdin(self, *args, **kwargs):
        return self.inner.write_stdin(*args, **kwargs)

    def close_operation_pipes(self, *args, **kwargs):
        return self.inner.close_operation_pipes(*args, **kwargs)


def _channel(*, stdout_results=(), scripts=None):
    inner = proxy_module._new_in_memory_supervisor_channel(
        epoch_id=EPOCH_ID,
        control_channel_id=CHANNEL_ID,
        stdout_results=tuple(stdout_results),
    )
    if scripts is None:
        return inner, inner
    return _ChannelWrapper(inner, scripts), inner


def _spawn(spawner, request, publication):
    return spawner.spawn(
        request,
        publication=publication,
        max_wait_ns=WAIT_NS,
    )


def _drive_active(spawner, request, publication, *, limit=12):
    results = []
    for _ in range(limit):
        selected = _spawn(spawner, request, publication)
        results.append(selected)
        if selected is not resolver.PENDING:
            return selected, results
    raise AssertionError("supervisor proxy did not become active")


def _drive_publication_failure(spawner, request, publication, *, limit=12):
    pending_count = 0
    for _ in range(limit):
        try:
            selected = _spawn(spawner, request, publication)
        except BaseException as error:
            return error, pending_count
        if selected is not resolver.PENDING:
            raise AssertionError("failed publication returned a kernel")
        pending_count += 1
    raise AssertionError("failed publication cleanup did not converge")


class ResolverSupervisorProxyTest(unittest.TestCase):
    def test_private_module_is_not_production_wired_or_io_backed(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_resolver_supervisor_proxy.py"
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
            imported
            & {
                "ctypes",
                "os",
                "select",
                "socket",
                "subprocess",
            }
        )
        resolver_source = (
            Path(resolver.__file__).read_text(encoding="utf-8")
        )
        self.assertNotIn("_resolver_supervisor_proxy", resolver_source)
        launcher = resolver.ResolverHelperLauncher.production(
            executable="/bin/echo"
        )
        self.assertIs(
            type(launcher._spawner),
            resolver.FailClosedProductionHelperSpawner,
        )

    def test_reserve_publication_attach_arm_exact_reentry(self):
        request, publication, ledger = _request_and_publication()
        channel, inner = _channel(
            stdout_results=(resolver.PENDING, resolver.READY_FRAME)
        )
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        first = _spawn(spawner, request, publication)
        self.assertIs(first, resolver.PENDING)
        self.assertEqual(inner.received_kinds, ("RESERVE",))
        record = next(iter(inner.ports.ledger._operations.values()))
        self.assertEqual(record.state.value, "reserved")
        self.assertFalse(record.child_ever_owned)
        self.assertIs(publication._kernel, ledger._kernel)

        second = _spawn(spawner, request, publication)
        self.assertIs(second, resolver.PENDING)
        self.assertEqual(inner.received_kinds, ("RESERVE", "ATTACH"))

        kernel = _spawn(spawner, request, publication)
        self.assertIs(kernel, publication._kernel)
        self.assertEqual(
            inner.received_kinds,
            ("RESERVE", "ATTACH", "ARM"),
        )
        self.assertEqual(record.state.value, "spawn_inflight")
        self.assertFalse(record.child_ever_owned)
        self.assertIs(
            kernel.read_stdout(64, max_wait_ns=WAIT_NS),
            resolver.PENDING,
        )
        self.assertEqual(
            kernel.read_stdout(64, max_wait_ns=WAIT_NS),
            resolver.READY_FRAME,
        )
        with self.assertRaises(EndpointPolicyError):
            kernel.write_stdin(b"synthetic-start\n", max_wait_ns=WAIT_NS)
        self.assertFalse(kernel.safe_metadata()["owns_pid"])

    def test_real_resolver_launcher_accepts_proxy_only_after_arm(self):
        # Use the existing AttemptGate-issued stop authority so this exercises
        # the real resolver lifecycle ledger and publication sink, not only the
        # focused fake used by the fault tests below.
        from tests.test_w09_resolver_lifecycle import _make_stop_authority

        _, _, _, stop_authority = _make_stop_authority()
        channel, inner = _channel(
            stdout_results=(resolver.PENDING, resolver.READY_FRAME)
        )
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        launcher = resolver.ResolverHelperLauncher(
            spawner,
            executable="/bin/echo",
        )
        capability = launcher._reserve_lifecycle_capability(
            reservation_owner=object(),
            stop_authority=stop_authority,
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )

        guard = launcher._launch_ready(
            capability=capability,
            _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertEqual(inner.received_kinds, ("RESERVE", "ATTACH", "ARM"))
        operation = next(iter(spawner._operations.values()))
        self.assertEqual(operation.phase.value, "active")
        self.assertTrue(
            launcher._consume_ready_publication(
                capability,
                guard,
                _authority=resolver._RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )

        # S4 is not wired, so explicitly publish a zero-child spawn failure to
        # prove the current resolver cleanup can consume terminal/release facts.
        inner.ports.events.complete_spawn(
            operation.binding,
            event_id=UUID("8b000000-0000-0000-0000-000000000099"),
            child_created=False,
        )
        self.assertTrue(guard.cleanup())
        self.assertEqual(guard.safe_metadata()["state"], "terminal")
        self.assertFalse(inner.session_closed)

    def test_reserve_ack_loss_retransmits_exact_frame_without_second_mutation(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel(scripts={"RESERVE": ["raise"]})
        publish_calls = []
        original = resolver._KernelPublication.publish

        def counted(selected, kernel):
            publish_calls.append(kernel)
            return original(selected, kernel)

        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        with patch.object(resolver._KernelPublication, "publish", counted):
            self.assertIs(
                _spawn(spawner, request, publication),
                resolver.PENDING,
            )
            self.assertIs(
                _spawn(spawner, request, publication),
                resolver.PENDING,
            )
            kernel, _ = _drive_active(spawner, request, publication)

        self.assertIs(kernel, publication._kernel)
        self.assertEqual(channel.exchange_kinds.count("RESERVE"), 2)
        self.assertEqual(channel.exchange_kinds.count("QUERY"), 0)
        self.assertEqual(channel.exchange_frames[0], channel.exchange_frames[1])
        self.assertEqual(inner.received_kinds.count("RESERVE"), 1)
        self.assertEqual(len(publish_calls), 1)
        self.assertEqual(len(inner.ports.ledger._operations), 1)

    def test_resolver_publication_commit_then_raise_cleans_zero_child(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        original = resolver._KernelPublication.publish
        calls = []

        def publish_then_raise(selected, kernel):
            calls.append(kernel)
            original(selected, kernel)
            raise RuntimeError("synthetic publication return fault")

        with patch.object(
            resolver._KernelPublication,
            "publish",
            publish_then_raise,
        ):
            error, pending_count = _drive_publication_failure(
                spawner,
                request,
                publication,
            )

        self.assertIsInstance(error, RuntimeError)
        self.assertGreaterEqual(pending_count, 3)
        self.assertIsNone(publication._kernel)
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            inner.received_kinds,
            ("RESERVE", "CANCEL", "RELEASE"),
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)
        self.assertEqual(len(inner.ports.parent_session._operations), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)

    def test_publication_observer_fault_reenters_without_republish(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        observations = []
        publish_calls = []
        original = resolver._KernelPublication.publish

        def counted_publish(selected, kernel):
            publish_calls.append(kernel)
            return original(selected, kernel)

        def observer(selected, kernel):
            observations.append(kernel)
            if len(observations) == 1:
                raise RuntimeError("synthetic observer fault")
            return proxy_module._intrinsic_publication_observer(
                selected,
                kernel,
            )

        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel,
            publication_observer=observer,
        )
        with patch.object(
            resolver._KernelPublication,
            "publish",
            counted_publish,
        ):
            self.assertIs(
                _spawn(spawner, request, publication),
                resolver.PENDING,
            )
            self.assertEqual(inner.received_kinds, ("RESERVE",))
            self.assertIs(
                _spawn(spawner, request, publication),
                resolver.PENDING,
            )
            kernel, _ = _drive_active(spawner, request, publication)

        self.assertIs(kernel, publication._kernel)
        self.assertEqual(len(publish_calls), 1)
        self.assertGreaterEqual(len(observations), 2)
        self.assertEqual(inner.received_kinds.count("RESERVE"), 1)

    def test_publication_observer_noop_fails_before_attach(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel,
            publication_observer=lambda selected, kernel: False,
        )

        error, pending_count = _drive_publication_failure(
            spawner,
            request,
            publication,
        )
        self.assertIsInstance(error, EndpointPolicyError)
        self.assertGreaterEqual(pending_count, 3)
        self.assertEqual(
            inner.received_kinds,
            ("RESERVE", "CANCEL", "RELEASE"),
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)
        self.assertEqual(len(inner.ports.parent_session._operations), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)

    def test_keyboard_interrupt_after_publication_commit_is_not_swallowed(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        original = resolver._KernelPublication.publish

        def publish_then_interrupt(selected, kernel):
            original(selected, kernel)
            raise KeyboardInterrupt("synthetic interrupt")

        with patch.object(
            resolver._KernelPublication,
            "publish",
            publish_then_interrupt,
        ):
            error, pending_count = _drive_publication_failure(
                spawner,
                request,
                publication,
            )
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertRegex(str(error), "synthetic")
        self.assertGreaterEqual(pending_count, 3)
        self.assertIsNone(publication._kernel)
        self.assertEqual(
            inner.received_kinds,
            ("RESERVE", "CANCEL", "RELEASE"),
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)

    def test_publication_precommit_interrupt_is_anchored_then_cleaned(self):
        request, publication, ledger = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        def interrupt_before_publish(selected, kernel):
            del selected, kernel
            raise KeyboardInterrupt("synthetic precommit interrupt")

        with patch.object(
            resolver._KernelPublication,
            "publish",
            interrupt_before_publish,
        ):
            error, pending_count = _drive_publication_failure(
                spawner,
                request,
                publication,
            )
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertGreaterEqual(pending_count, 3)
        self.assertIsNone(publication._kernel)
        self.assertIsNotNone(ledger._kernel)
        self.assertTrue(ledger._kernel._operation_pipes_closed)
        self.assertEqual(
            inner.received_kinds,
            ("RESERVE", "CANCEL", "RELEASE"),
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)
        self.assertEqual(len(inner.ports.parent_session._operations), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)

    def test_publication_observer_interrupt_cleans_committed_anchor(self):
        request, publication, ledger = _request_and_publication()
        channel, inner = _channel()

        def observe_then_interrupt(selected, kernel):
            self.assertTrue(
                proxy_module._intrinsic_publication_observer(
                    selected,
                    kernel,
                )
            )
            raise KeyboardInterrupt("synthetic observer interrupt")

        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel,
            publication_observer=observe_then_interrupt,
        )
        error, pending_count = _drive_publication_failure(
            spawner,
            request,
            publication,
        )
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertGreaterEqual(pending_count, 3)
        self.assertIsNone(publication._kernel)
        self.assertIsNotNone(ledger._kernel)
        self.assertTrue(ledger._kernel._operation_pipes_closed)
        self.assertEqual(
            inner.received_kinds,
            ("RESERVE", "CANCEL", "RELEASE"),
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)
        self.assertEqual(len(inner.ports.parent_session._operations), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)

    def test_normal_return_publication_noop_fails_closed_at_zero_child(self):
        request, publication, ledger = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        with patch.object(
            resolver._KernelPublication,
            "publish",
            lambda selected, kernel: None,
        ):
            error, pending_count = _drive_publication_failure(
                spawner,
                request,
                publication,
            )
        self.assertIsInstance(error, EndpointPolicyError)
        self.assertEqual(error.stage, "resolver_supervisor_proxy")
        self.assertGreaterEqual(pending_count, 3)
        self.assertEqual(
            inner.received_kinds,
            ("RESERVE", "CANCEL", "RELEASE"),
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)
        self.assertEqual(len(inner.ports.parent_session._operations), 0)
        self.assertEqual(spawner.safe_metadata()["operation_count"], 0)
        self.assertIsNone(publication._kernel)
        self.assertIsNotNone(ledger._kernel)
        self.assertTrue(ledger._kernel._operation_pipes_closed)

    def test_attach_ack_loss_retransmits_exact_frame_and_proof(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel(scripts={"ATTACH": ["drop"]})
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        kernel = _spawn(spawner, request, publication)

        self.assertIs(kernel, publication._kernel)
        self.assertEqual(
            channel.exchange_kinds,
            ["RESERVE", "ATTACH", "ATTACH", "ARM"],
        )
        self.assertEqual(channel.exchange_frames[1], channel.exchange_frames[2])
        self.assertIs(channel.exchange_proofs[1], channel.exchange_proofs[2])
        self.assertEqual(inner.received_kinds.count("ATTACH"), 1)
        self.assertEqual(inner.received_kinds.count("RESERVE"), 1)

    def test_attach_prepublication_pending_retransmits_exact_frame(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel(scripts={"ATTACH": ["no-op"]})
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        kernel, _ = _drive_active(spawner, request, publication)
        self.assertIs(kernel, publication._kernel)
        record = next(iter(inner.ports.ledger._operations.values()))
        self.assertEqual(record.state.value, "spawn_inflight")
        self.assertFalse(record.child_ever_owned)
        self.assertEqual(
            channel.exchange_kinds,
            ["RESERVE", "ATTACH", "ATTACH", "ARM"],
        )
        self.assertEqual(channel.exchange_frames[1], channel.exchange_frames[2])
        self.assertIs(channel.exchange_proofs[1], channel.exchange_proofs[2])

    def test_arm_ack_loss_retransmits_exact_frame_before_returning(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel(scripts={"ARM": ["raise"]})
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertEqual(
            channel.exchange_kinds,
            ["RESERVE", "ATTACH", "ARM"],
        )
        kernel = _spawn(spawner, request, publication)

        self.assertIs(kernel, publication._kernel)
        self.assertEqual(
            channel.exchange_kinds,
            ["RESERVE", "ATTACH", "ARM", "ARM"],
        )
        self.assertEqual(channel.exchange_frames[2], channel.exchange_frames[3])
        self.assertEqual(inner.received_kinds.count("ARM"), 1)
        self.assertEqual(inner.received_kinds.count("RESERVE"), 1)

    def test_arm_prepublication_pending_retransmits_without_duplicate_mutation(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel(scripts={"ARM": ["no-op"]})
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        kernel = _spawn(spawner, request, publication)
        self.assertIs(kernel, publication._kernel)
        record = next(iter(inner.ports.ledger._operations.values()))
        self.assertEqual(record.state.value, "spawn_inflight")
        self.assertFalse(record.child_ever_owned)
        self.assertEqual(
            channel.exchange_kinds,
            ["RESERVE", "ATTACH", "ARM", "ARM"],
        )
        self.assertEqual(channel.exchange_frames[2], channel.exchange_frames[3])

    def test_channel_replays_one_exact_command_without_second_mutation(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        operation = next(iter(spawner._operations.values()))
        reserve = operation.commands[wire._SupervisorWireKind.RESERVE]
        encoded = wire._encode_supervisor_wire_frame(reserve)

        first = inner.exchange(encoded, max_wait_ns=WAIT_NS)
        second = inner.exchange(encoded, max_wait_ns=WAIT_NS)
        self.assertIs(first, second)
        self.assertEqual(len(inner.ports.ledger._operations), 1)
        self.assertEqual(inner.received_kinds.count("RESERVE"), 1)

    def test_control_frame_rejects_foreign_proxy_before_arm_mutation(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        operation = next(iter(spawner._operations.values()))
        foreign = wire._new_supervisor_wire_frame(
            kind=wire._SupervisorWireKind.ARM,
            epoch_id=operation.binding.epoch_id,
            operation_id=operation.binding.operation_id,
            control_channel_id=CHANNEL_ID,
            operation_binding_digest=operation.binding.binding_digest,
            frame_id=UUID("8b000000-0000-0000-0000-000000000098"),
            payload={
                "command_id": operation.arm_command_id,
                "proxy_id": UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            },
        )

        with self.assertRaises(EndpointPolicyError):
            inner.exchange(
                wire._encode_supervisor_wire_frame(foreign),
                max_wait_ns=WAIT_NS,
            )
        record = inner.ports.ledger._operations[operation.binding.operation_id]
        self.assertEqual(record.state.value, "attached")
        self.assertIsNone(record.arm_command_id)

    def test_operation_data_queues_cannot_cross_two_active_proxies(self):
        first_request, first_publication, _ = _request_and_publication()
        second_request, second_publication, _ = _request_and_publication(
            lifecycle_id=UUID("8b000000-0000-0000-0000-000000000013"),
            publication_id=UUID("8b000000-0000-0000-0000-000000000014"),
        )
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        first_kernel, _ = _drive_active(
            spawner,
            first_request,
            first_publication,
        )
        second_kernel, _ = _drive_active(
            spawner,
            second_request,
            second_publication,
        )
        operations = list(spawner._operations.values())
        first_operation = operations[0]
        second_operation = operations[1]
        inner.script_operation_io(
            first_operation.binding,
            first_operation.proxy_id,
            stdout_results=(b"for-operation-one",),
        )
        inner.script_operation_io(
            second_operation.binding,
            second_operation.proxy_id,
            stdout_results=(b"for-operation-two",),
        )

        self.assertEqual(
            second_kernel.read_stdout(64, max_wait_ns=WAIT_NS),
            b"for-operation-two",
        )
        self.assertEqual(
            first_kernel.read_stdout(64, max_wait_ns=WAIT_NS),
            b"for-operation-one",
        )

    def test_each_spawn_call_has_at_most_one_bounded_exchange(self):
        request, publication, _ = _request_and_publication()
        channel, _ = _channel(scripts={"ARM": ["drop"]})
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        before = 0
        for _ in range(4):
            _spawn(spawner, request, publication)
            after = len(channel.exchange_waits)
            self.assertLessEqual(after - before, 1)
            before = after
        self.assertTrue(channel.exchange_waits)
        self.assertTrue(all(item == WAIT_NS for item in channel.exchange_waits))
        with self.assertRaises(ValueError):
            spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=proxy_module.MAX_SUPERVISOR_PROXY_WAIT_NS + 1,
            )

    def test_spawn_does_not_wait_for_contended_publication_lock(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        held = Event()
        release = Event()

        def hold_publication_lock():
            with publication._lock:
                held.set()
                release.wait(0.25)

        holder = Thread(target=hold_publication_lock)
        holder.start()
        self.assertTrue(held.wait(0.25))
        started = monotonic()
        try:
            selected = spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=1_000_000,
            )
        finally:
            elapsed = monotonic() - started
            release.set()
            holder.join(0.5)

        self.assertIs(selected, resolver.PENDING)
        self.assertLess(elapsed, 0.1)
        self.assertEqual(inner.received_kinds, ("RESERVE",))
        self.assertIsNone(publication._kernel)

    def test_published_zero_child_proxy_cleans_without_closing_session(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )

        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        kernel = publication._kernel
        self.assertIsNotNone(kernel)
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(kernel.reap(max_wait_ns=WAIT_NS), 0)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertFalse(inner.session_closed)
        metadata = inner.safe_metadata()
        self.assertEqual(metadata["operation_pipe_close_count"], 1)
        self.assertFalse(metadata["session_closed"])
        self.assertTrue(kernel.safe_metadata()["operation_pipes_closed"])

    def test_exact_active_reentry_returns_same_kernel_without_new_frames(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        kernel, _ = _drive_active(spawner, request, publication)
        kinds = inner.received_kinds

        for _ in range(5):
            self.assertIs(_spawn(spawner, request, publication), kernel)
        self.assertEqual(inner.received_kinds, kinds)
        self.assertEqual(len(inner.ports.ledger._operations), 1)

    def test_reentry_with_different_publication_is_rejected(self):
        request, publication, _ = _request_and_publication()
        channel, _ = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(
            channel=channel
        )
        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)

        _, other_publication, _ = _request_and_publication()
        with self.assertRaises(EndpointPolicyError):
            _spawn(spawner, request, other_publication)

    def test_one_channel_rejects_a_second_spawner_owner(self):
        channel, _ = _channel()
        first = proxy_module._new_supervisor_helper_spawner(channel=channel)
        self.assertIsNotNone(first)
        with self.assertRaises(EndpointPolicyError):
            proxy_module._new_supervisor_helper_spawner(channel=channel)

    def test_255_terminal_plus_one_active_stops_1000_new_admissions(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        for index in range(
            proxy_module.SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT - 1
        ):
            inner._terminal_tombstones[UUID(int=index + 1)] = (
                "primitive-terminal-placeholder",
                index,
            )
        spawner = proxy_module._new_supervisor_helper_spawner(channel=channel)

        self.assertIs(_spawn(spawner, request, publication), resolver.PENDING)
        self.assertEqual(len(inner.ports.ledger._operations), 1)
        self.assertEqual(len(spawner._operations), 1)
        received = inner.received_kinds
        other_request, other_publication, _ = _request_and_publication(
            lifecycle_id=UUID(int=70_001),
            publication_id=UUID(int=70_002),
        )
        for _ in range(1_000):
            with self.assertRaisesRegex(EndpointPolicyError, "capacity"):
                _spawn(spawner, other_request, other_publication)
        self.assertEqual(len(inner.ports.ledger._operations), 1)
        self.assertEqual(len(spawner._operations), 1)
        self.assertEqual(inner.received_kinds, received)
        self.assertFalse(inner.epoch_rotation_ready())

        kernel = publication._kernel
        self.assertIs(
            kernel.terminate(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(kernel.reap(max_wait_ns=WAIT_NS), 0)
        self.assertIs(
            kernel.close_pipes(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)
        self.assertEqual(len(spawner._operations), 0)
        self.assertEqual(
            len(inner._terminal_tombstones),
            proxy_module.SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT,
        )
        self.assertTrue(inner.epoch_rotation_ready())

    def test_new_epoch_rejects_old_epoch_frame_without_state_mutation(self):
        request, _, _ = _request_and_publication()
        operation_id = proxy_module._operation_role_uuid(
            epoch_id=EPOCH_ID,
            lifecycle_id=LIFECYCLE_ID,
            publication_id=PUBLICATION_ID,
            spawn_request_digest=request.request_digest,
            role="operation",
        )
        binding = proxy_module.contract._new_supervisor_operation_binding(
            epoch_id=EPOCH_ID,
            operation_id=operation_id,
            lifecycle_id=LIFECYCLE_ID,
            publication_id=PUBLICATION_ID,
            spawn_request_digest=request.request_digest,
        )
        stale = wire._new_supervisor_wire_frame(
            kind=wire._SupervisorWireKind.RESERVE,
            epoch_id=binding.epoch_id,
            operation_id=binding.operation_id,
            control_channel_id=CHANNEL_ID,
            operation_binding_digest=binding.binding_digest,
            frame_id=proxy_module._bound_role_uuid(
                binding,
                "stale-epoch-reserve",
            ),
            payload={
                "lifecycle_id": binding.lifecycle_id,
                "publication_id": binding.publication_id,
                "spawn_request_digest": binding.spawn_request_digest,
            },
        )
        current = proxy_module._new_in_memory_supervisor_channel(
            epoch_id=UUID("8b000000-0000-0000-0000-000000000101"),
            control_channel_id=CHANNEL_ID,
        )

        with self.assertRaises(EndpointPolicyError):
            current.exchange(
                wire._encode_supervisor_wire_frame(stale),
                max_wait_ns=WAIT_NS,
            )
        self.assertEqual(current.received_kinds, ())
        self.assertEqual(current.safe_metadata()["active_operation_count"], 0)
        self.assertEqual(current.safe_metadata()["active_replay_count"], 0)
        self.assertFalse(current.ports.ledger.safe_metadata()["poisoned"])

    def test_spawner_active_capacity_refusal_precedes_channel_mutation(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(channel=channel)
        for index in range(proxy_module.SUPERVISOR_ACTIVE_OPERATION_LIMIT):
            spawner._operations[UUID(int=index + 1)] = object()
        for _ in range(1_000):
            with self.assertRaisesRegex(EndpointPolicyError, "capacity"):
                _spawn(spawner, request, publication)
        self.assertEqual(
            len(spawner._operations),
            proxy_module.SUPERVISOR_ACTIVE_OPERATION_LIMIT,
        )
        self.assertEqual(len(inner.ports.ledger._operations), 0)
        self.assertEqual(len(inner._replays), 0)
        self.assertEqual(inner.received_kinds, ())

    def test_per_operation_replay_and_received_history_are_bounded(self):
        request, publication, _ = _request_and_publication()
        channel, inner = _channel()
        spawner = proxy_module._new_supervisor_helper_spawner(channel=channel)
        kernel, _ = _drive_active(spawner, request, publication)
        binding = kernel._binding
        first_frame = None
        first_response = None
        remaining = (
            proxy_module.SUPERVISOR_REPLAY_LIMIT_PER_OPERATION
            - proxy_module.SUPERVISOR_TERMINAL_REPLAY_RESERVE
            - len(inner._replays)
        )
        for sequence in range(remaining):
            frame = wire._new_supervisor_wire_frame(
                kind=wire._SupervisorWireKind.QUERY,
                epoch_id=binding.epoch_id,
                operation_id=binding.operation_id,
                control_channel_id=inner.control_channel_id,
                operation_binding_digest=binding.binding_digest,
                frame_id=proxy_module._bound_role_uuid(
                    binding,
                    "bounded-replay-frame",
                    sequence,
                ),
                payload={
                    "proxy_id": kernel._proxy_id,
                    "query_id": proxy_module._bound_role_uuid(
                        binding,
                        "bounded-replay-query",
                        sequence,
                    ),
                },
            )
            response = inner.exchange(
                wire._encode_supervisor_wire_frame(frame),
                max_wait_ns=WAIT_NS,
            )
            if first_frame is None:
                first_frame = frame
                first_response = response
        self.assertEqual(
            len(inner._replays),
            proxy_module.SUPERVISOR_REPLAY_LIMIT_PER_OPERATION
            - proxy_module.SUPERVISOR_TERMINAL_REPLAY_RESERVE,
        )
        overflow = wire._new_supervisor_wire_frame(
            kind=wire._SupervisorWireKind.QUERY,
            epoch_id=binding.epoch_id,
            operation_id=binding.operation_id,
            control_channel_id=inner.control_channel_id,
            operation_binding_digest=binding.binding_digest,
            frame_id=proxy_module._bound_role_uuid(
                binding,
                "bounded-replay-frame",
                remaining,
            ),
            payload={
                "proxy_id": kernel._proxy_id,
                "query_id": proxy_module._bound_role_uuid(
                    binding,
                    "bounded-replay-query",
                    remaining,
                ),
            },
        )
        with self.assertRaisesRegex(
            EndpointPolicyError,
            "capacity|terminal replay reserve",
        ):
            inner.exchange(
                wire._encode_supervisor_wire_frame(overflow),
                max_wait_ns=WAIT_NS,
            )
        self.assertIs(
            inner.exchange(
                wire._encode_supervisor_wire_frame(first_frame),
                max_wait_ns=WAIT_NS,
            ),
            first_response,
        )

        with inner._lock:
            for _ in range(1_000):
                inner._append_received_locked("QUERY")
        self.assertEqual(
            len(inner.received_kinds),
            proxy_module.SUPERVISOR_RECEIVED_HISTORY_LIMIT,
        )


if __name__ == "__main__":
    unittest.main()
