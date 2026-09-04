"""W09 local native-owner to async-supervisor composition evidence."""
from __future__ import annotations

import ast
import inspect
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from threading import RLock, Thread
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_resolver_async_adapter as adapter
from snapquiz.transport import _darwin_resolver_owner as native_owner
from snapquiz.transport import _resolver_output_cache as output_cache
from snapquiz.transport import _resolver_supervisor_async as async_supervisor
from snapquiz.transport import _resolver_supervisor_contract as contract
from snapquiz.transport import _resolver_supervisor_proxy as proxy_module
from snapquiz.transport import resolver


EPOCH_ID = UUID("8f000000-0000-0000-0000-000000000001")
CHANNEL_ID = UUID("8f000000-0000-0000-0000-000000000002")
LIFECYCLE_ID = UUID("8f000000-0000-0000-0000-000000000003")
PUBLICATION_ID = UUID("8f000000-0000-0000-0000-000000000004")
WAIT_NS = 17_000_000
RAW_PID = 42_001
RAW_FDS = (101, 102, 103, 104)
RESULT_FRAME = b'{"addresses":["192.0.2.10"]}\n'


class _FakeResolverLedger:
    def __init__(self, request):
        self.lifecycle_id = LIFECYCLE_ID
        self._capability_snapshot = type(
            "Snapshot",
            (),
            {
                "lifecycle_id": LIFECYCLE_ID,
                "publication_id": PUBLICATION_ID,
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


class _Fixture:
    def __init__(
        self,
        *,
        liveness=(True,),
        ambiguous_create_return=False,
    ):
        self._liveness = list(liveness)
        self.ambiguous_create_return = ambiguous_create_return
        self.create_calls = []
        self.liveness_calls = []
        self.output_calls = []
        self.control_calls = []
        self.signal_calls = []
        self.wait_calls = []
        self.close_calls = []
        self.outputs = (
            native_owner._FixtureOutput(
                output_cache._ResolverOutputKind.READY,
                output_cache.READY_OUTPUT_PAYLOAD,
            ),
            native_owner._FixtureOutput(
                output_cache._ResolverOutputKind.RESULT,
                RESULT_FRAME,
            ),
            native_owner._FixtureOutput(
                output_cache._ResolverOutputKind.EOF,
                b"",
            ),
        )

    def create_process(self, max_wait_ns):
        self.create_calls.append(max_wait_ns)
        return native_owner._CreatedOwnerResources(RAW_PID, *RAW_FDS)

    def after_create_publication(self, max_wait_ns):
        if self.ambiguous_create_return:
            raise KeyboardInterrupt(
                f"synthetic create return gap after {max_wait_ns}ns"
            )

    def signal_process(self, pid, signal_number, max_wait_ns):
        self.signal_calls.append((pid, signal_number, max_wait_ns))

    def wait_process(self, pid, max_wait_ns):
        self.wait_calls.append((pid, max_wait_ns))
        return 9

    def close_fd(self, fd, role, max_wait_ns):
        self.close_calls.append((fd, role, max_wait_ns))

    def write_control(self, fd, frame, max_wait_ns):
        self.control_calls.append((fd, frame, max_wait_ns))

    def read_output(self, fd, sequence, capacity, max_wait_ns):
        self.output_calls.append((fd, sequence, capacity, max_wait_ns))
        return self.outputs[sequence]

    def check_liveness(self, fd, max_wait_ns):
        self.liveness_calls.append((fd, max_wait_ns))
        if not self._liveness:
            raise AssertionError("liveness checkpoint was replayed")
        return self._liveness.pop(0)


def _request_and_publication():
    request = resolver.ResolverHelperSpawnRequest(executable="/bin/echo")
    ledger = _FakeResolverLedger(request)
    publication = object.__new__(resolver._KernelPublication)
    object.__setattr__(publication, "_ledger", ledger)
    object.__setattr__(publication, "_owner", ledger._owner)
    object.__setattr__(publication, "_lock", RLock())
    object.__setattr__(publication, "_kernel", None)
    return request, publication


def _binding(request):
    operation_id = proxy_module._operation_role_uuid(
        epoch_id=EPOCH_ID,
        lifecycle_id=LIFECYCLE_ID,
        publication_id=PUBLICATION_ID,
        spawn_request_digest=request.request_digest,
        role="operation",
    )
    return contract._new_supervisor_operation_binding(
        epoch_id=EPOCH_ID,
        operation_id=operation_id,
        lifecycle_id=LIFECYCLE_ID,
        publication_id=PUBLICATION_ID,
        spawn_request_digest=request.request_digest,
    )


def _start_frame():
    return resolver.encode_start_frame(
        hostname="open.bigmodel.cn",
        port=443,
        network_policy_ref="snapquiz.internet-public-address-policy.v1",
        network_policy_digest=Digest256("b" * 64),
        attempt_permit_id=UUID("8f000000-0000-0000-0000-000000000011"),
        attempt_permit_digest=Digest256("c" * 64),
        transport_claim_id=UUID("8f000000-0000-0000-0000-000000000012"),
        terminal_guard_id=UUID("8f000000-0000-0000-0000-000000000013"),
        terminal_guard_digest=Digest256("d" * 64),
        dns_start_id=UUID("8f000000-0000-0000-0000-000000000014"),
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

    def interrupt(frame, event, argument):
        nonlocal fired
        del argument
        if (
            not fired
            and event == "line"
            and frame.f_code is target_code
            and frame.f_lineno == target_line
        ):
            fired = True
            raise KeyboardInterrupt("synthetic composition interruption")
        return interrupt

    sys.settrace(interrupt)
    try:
        return call()
    finally:
        sys.settrace(previous)


class DarwinResolverAsyncAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        suffix = ".dylib" if sys.platform == "darwin" else ".so"
        cls.library_path = Path(cls._temporary.name) / f"resolver_owner{suffix}"
        source = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "native"
            / "darwin_resolver_owner.c"
        )
        command = [
            "clang",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-O2",
        ]
        command.extend(
            ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
        )
        command.extend([str(source), "-o", str(cls.library_path)])
        subprocess.run(command, check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def _stack(self, fixture):
        request, publication = _request_and_publication()
        binding = _binding(request)
        plan = adapter._new_unwired_darwin_resolver_async_plan(
            binding=binding,
            library_path=self.library_path,
            fixture=fixture,
            max_wait_ns=WAIT_NS,
        )
        worker = adapter._new_unwired_darwin_resolver_async_worker((plan,))
        channel = async_supervisor._new_async_supervisor_channel(
            epoch_id=EPOCH_ID,
            control_channel_id=CHANNEL_ID,
            spawn_worker=worker,
        )
        spawner = proxy_module._new_supervisor_helper_spawner(channel=channel)
        return request, publication, binding, plan, worker, channel, spawner

    @staticmethod
    def _drive_active(spawner, request, publication, *, limit=400):
        for _ in range(limit):
            selected = spawner.spawn(
                request,
                publication=publication,
                max_wait_ns=WAIT_NS,
            )
            if selected is not resolver.PENDING:
                return selected
            time.sleep(0.001)
        raise AssertionError("async native composition did not become active")

    @staticmethod
    def _observe(kernel, maximum, *, limit=400):
        for _ in range(limit):
            selected = kernel.observe_stdout_durable(
                maximum,
                max_wait_ns=WAIT_NS,
            )
            if selected is not resolver.PENDING:
                return selected
            time.sleep(0.001)
        raise AssertionError("durable native output was not observed")

    @staticmethod
    def _complete(call, *, limit=400):
        for _ in range(limit):
            selected = call()
            if selected is not resolver.PENDING:
                return selected
            time.sleep(0.001)
        raise AssertionError("bounded operation did not complete")

    def test_import_is_inert_and_production_flags_remain_false(self):
        source = Path(adapter.__file__)
        tree = ast.parse(source.read_text(encoding="utf-8"))
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertFalse(
            called_names & {"fork", "open", "pipe", "socket", "spawn", "waitpid"}
        )
        self.assertTrue(adapter.LOCAL_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE)
        self.assertFalse(adapter.PRODUCTION_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE)
        self.assertFalse(native_owner.PRODUCTION_NATIVE_RESOLVER_OWNER_AVAILABLE)
        self.assertFalse(
            async_supervisor.PRODUCTION_DURABLE_OUTPUT_INTEGRATION_AVAILABLE
        )
        self.assertNotIn(
            "_darwin_resolver_async_adapter",
            Path(resolver.__file__).read_text(encoding="utf-8"),
        )

        # Importing this module above only defined factories/classes.  The
        # native library is first loaded by the explicit plan factory.
        self.assertNotIn("_default_plan", vars(adapter))

    def test_preheld_plan_liveness_and_durable_redelivery_compose_exactly(self):
        fixture = _Fixture(liveness=(resolver.PENDING, True))
        request, publication, _, plan, worker, channel, spawner = self._stack(fixture)
        self.assertEqual(plan.safe_metadata()["native_owner_state"], "new")
        self.assertEqual(worker.safe_metadata()["caller_preheld_plan_count"], 1)
        kernel = self._drive_active(spawner, request, publication)

        ready = self._observe(kernel, 64)
        self.assertEqual(ready.kind, output_cache._ResolverOutputKind.READY)
        self.assertEqual(ready.payload, resolver.READY_FRAME)
        self.assertIs(self._observe(kernel, 64), ready)
        self.assertEqual(len(fixture.output_calls), 1)
        self.assertIs(
            self._complete(
                lambda: kernel.acknowledge_stdout_durable(
                    ready,
                    max_wait_ns=WAIT_NS,
                )
            ),
            resolver.COMPLETE,
        )

        self.assertIs(
            self._complete(
                lambda: kernel.write_stdin(
                    _start_frame(),
                    max_wait_ns=WAIT_NS,
                )
            ),
            resolver.COMPLETE,
        )
        result = self._observe(kernel, len(RESULT_FRAME))
        self.assertEqual(result.payload, RESULT_FRAME)
        self.assertIs(self._observe(kernel, len(RESULT_FRAME)), result)
        self.assertIs(
            self._complete(
                lambda: kernel.acknowledge_stdout_durable(
                    result,
                    max_wait_ns=WAIT_NS,
                )
            ),
            resolver.COMPLETE,
        )
        eof = self._observe(kernel, 1)
        self.assertEqual(eof.kind, output_cache._ResolverOutputKind.EOF)
        self.assertIs(
            self._complete(
                lambda: kernel.acknowledge_stdout_durable(
                    eof,
                    max_wait_ns=WAIT_NS,
                )
            ),
            resolver.COMPLETE,
        )

        self.assertIs(
            self._complete(lambda: kernel.terminate(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )
        self.assertEqual(
            self._complete(lambda: kernel.reap(max_wait_ns=WAIT_NS)),
            9,
        )
        self.assertIs(
            self._complete(lambda: kernel.close_pipes(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )

        self.assertEqual(fixture.create_calls, [WAIT_NS])
        self.assertEqual(fixture.liveness_calls, [(RAW_FDS[3], WAIT_NS)] * 2)
        self.assertEqual(len(fixture.output_calls), 3)
        self.assertEqual(fixture.signal_calls, [])
        self.assertEqual(fixture.wait_calls, [(RAW_PID, WAIT_NS)])
        self.assertEqual(
            fixture.close_calls,
            [(fd, role, WAIT_NS) for role, fd in enumerate(RAW_FDS)],
        )
        self.assertEqual(plan._owner.safe_metadata()["output_acked_count"], 3)
        self.assertFalse(channel.ports.ledger.safe_metadata()["poisoned"])
        self.assertTrue(plan.safe_metadata()["caller_preheld"])
        self.assertTrue(plan.safe_metadata()["published"])

    def test_child_has_no_legacy_read_or_raw_identity_cleanup_surface(self):
        fixture = _Fixture()
        request, publication, _, plan, _, _, spawner = self._stack(fixture)
        kernel = self._drive_active(spawner, request, publication)
        for _ in range(400):
            if fixture.liveness_calls:
                break
            kernel._channel.event_owner.pump(max_wait_ns=WAIT_NS)
            time.sleep(0.001)
        child = plan._child
        self.assertFalse(hasattr(child, "read_stdout"))
        self.assertNotEqual(child.pid, RAW_PID)
        self.assertGreaterEqual(child.pid, 1 << 128)
        self.assertNotIn("pid", child.safe_metadata())
        self.assertNotIn("fds", child.safe_metadata())
        with self.assertRaisesRegex(EndpointPolicyError, "opaque identity"):
            child.terminate_exact(child.pid + 1, max_wait_ns=WAIT_NS)
        self.assertEqual(fixture.signal_calls, [])
        with self.assertRaisesRegex(EndpointPolicyError, "durable-only"):
            kernel.read_stdout(64, max_wait_ns=WAIT_NS)
        self.assertEqual(fixture.output_calls, [])

        self.assertIs(
            self._complete(lambda: kernel.terminate(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )
        self.assertEqual(
            self._complete(lambda: kernel.reap(max_wait_ns=WAIT_NS)),
            9,
        )
        self.assertIs(
            self._complete(lambda: kernel.close_pipes(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )
        self.assertEqual(len(fixture.signal_calls), 1)
        self.assertEqual(fixture.signal_calls[0][0], RAW_PID)
        self.assertEqual(fixture.wait_calls, [(RAW_PID, WAIT_NS)])
        self.assertEqual(len(fixture.close_calls), 4)

    def test_failed_liveness_poisons_before_output_and_cleans_once(self):
        fixture = _Fixture(liveness=(False,))
        request, publication, _, _, _, channel, spawner = self._stack(fixture)
        kernel = self._drive_active(spawner, request, publication)
        del kernel
        for _ in range(400):
            try:
                channel.event_owner.pump(max_wait_ns=WAIT_NS)
            except EndpointPolicyError:
                pass
            if len(fixture.close_calls) == 4:
                break
            time.sleep(0.001)

        metadata = channel.ports.ledger.safe_metadata()
        self.assertTrue(metadata["poisoned"])
        self.assertEqual(metadata["global_poison_reason"], "liveness_lost")
        self.assertEqual(fixture.liveness_calls, [(RAW_FDS[3], WAIT_NS)])
        self.assertEqual(fixture.output_calls, [])
        self.assertEqual(len(fixture.signal_calls), 1)
        self.assertEqual(len(fixture.wait_calls), 1)
        self.assertEqual(len(fixture.close_calls), 4)

    def test_native_create_return_gap_keeps_one_cleanup_authority(self):
        fixture = _Fixture(ambiguous_create_return=True)
        request, publication, _, plan, _, channel, spawner = self._stack(fixture)
        self._drive_active(spawner, request, publication)
        for _ in range(400):
            try:
                channel.event_owner.pump(max_wait_ns=WAIT_NS)
            except EndpointPolicyError:
                pass
            if len(fixture.close_calls) == 4:
                break
            time.sleep(0.001)

        self.assertEqual(fixture.create_calls, [WAIT_NS])
        self.assertEqual(plan.safe_metadata()["native_owner_state"], "recovery_owned")
        self.assertTrue(plan.safe_metadata()["published"])
        self.assertEqual(fixture.output_calls, [])
        self.assertEqual(len(fixture.signal_calls), 1)
        self.assertEqual(len(fixture.wait_calls), 1)
        self.assertEqual(len(fixture.close_calls), 4)
        self.assertTrue(channel.ports.ledger.safe_metadata()["poisoned"])

    def test_preheld_anchor_recovers_native_success_before_python_publish(self):
        fixture = _Fixture()
        request, _ = _request_and_publication()
        binding = _binding(request)
        plan = adapter._new_unwired_darwin_resolver_async_plan(
            binding=binding,
            library_path=self.library_path,
            fixture=fixture,
            max_wait_ns=WAIT_NS,
        )
        publication = async_supervisor._SpawnConstructionPublication(
            operation_id=binding.operation_id,
            binding_digest=binding.binding_digest,
        )
        publication.begin()
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                adapter._DarwinResolverAsyncConstructionPlan.construct_and_publish,
                "publication.publish(self._child)",
                lambda: plan.construct_and_publish(
                    binding=binding,
                    publication=publication,
                ),
                occurrence=2,
            )

        begun, failed, frozen, _, conflicted = publication.snapshot()
        self.assertTrue(begun)
        self.assertFalse(failed)
        self.assertFalse(conflicted)
        self.assertIs(frozen.child, plan._child)
        self.assertEqual(fixture.create_calls, [WAIT_NS])

        # Reentry finalizes only the exact Python publication; native create
        # cannot run a second time.
        plan.construct_and_publish(binding=binding, publication=publication)
        self.assertEqual(fixture.create_calls, [WAIT_NS])
        self.assertIs(
            plan._child.checkpoint_liveness_exact(max_wait_ns=WAIT_NS),
            True,
        )
        self.assertIs(
            plan._child.terminate_exact(
                plan._child.pid,
                max_wait_ns=WAIT_NS,
            ),
            resolver.COMPLETE,
        )
        self.assertEqual(
            plan._child.reap_exact(
                plan._child.pid,
                max_wait_ns=WAIT_NS,
            ),
            9,
        )
        self.assertIs(
            plan._child.close_exact(max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(len(fixture.signal_calls), 1)
        self.assertEqual(len(fixture.wait_calls), 1)
        self.assertEqual(len(fixture.close_calls), 4)

    def test_full_fixture_path_uses_no_process_dns_socket_or_fd_primitive(self):
        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("composition touched a real system primitive")

        fixture = _Fixture()
        with patch.object(os, "kill", side_effect=forbidden), patch.object(
            os,
            "close",
            side_effect=forbidden,
        ), patch.object(
            os,
            "waitpid",
            side_effect=forbidden,
        ), patch.object(
            subprocess,
            "Popen",
            side_effect=forbidden,
        ), patch.object(
            socket,
            "socket",
            side_effect=forbidden,
        ), patch.object(
            socket,
            "getaddrinfo",
            side_effect=forbidden,
        ):
            request, publication, _, _, _, _, spawner = self._stack(fixture)
            kernel = self._drive_active(spawner, request, publication)
            ready = self._observe(kernel, 64)
            self.assertIs(
                self._complete(
                    lambda: kernel.acknowledge_stdout_durable(
                        ready,
                        max_wait_ns=WAIT_NS,
                    )
                ),
                resolver.COMPLETE,
            )
            self.assertIs(
                self._complete(lambda: kernel.terminate(max_wait_ns=WAIT_NS)),
                resolver.COMPLETE,
            )
            self.assertEqual(
                self._complete(lambda: kernel.reap(max_wait_ns=WAIT_NS)),
                9,
            )
            self.assertIs(
                self._complete(
                    lambda: kernel.close_pipes(max_wait_ns=WAIT_NS)
                ),
                resolver.COMPLETE,
            )
        self.assertEqual(len(fixture.signal_calls), 1)
        self.assertEqual(len(fixture.wait_calls), 1)
        self.assertEqual(len(fixture.close_calls), 4)

    def test_integrated_observe_and_ack_return_gaps_never_reread(self):
        fixture = _Fixture()
        request, publication, _, plan, _, _, spawner = self._stack(fixture)
        kernel = self._drive_active(spawner, request, publication)
        child_type = type(plan._child)
        original_observe = child_type.observe_stdout_durable
        observe_interrupted = False

        def observe_then_interrupt(selected, *args, **kwargs):
            nonlocal observe_interrupted
            result = original_observe(selected, *args, **kwargs)
            if not observe_interrupted:
                observe_interrupted = True
                raise KeyboardInterrupt("synthetic native observe return gap")
            return result

        with patch.object(
            child_type,
            "observe_stdout_durable",
            new=observe_then_interrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                self._observe(kernel, 64)
            ready = self._observe(kernel, 64)
        self.assertEqual(ready.payload, resolver.READY_FRAME)
        self.assertEqual(len(fixture.output_calls), 1)

        original_ack = child_type.ack_stdout_durable
        ack_interrupted = False

        def ack_then_interrupt(selected, *args, **kwargs):
            nonlocal ack_interrupted
            result = original_ack(selected, *args, **kwargs)
            if not ack_interrupted:
                ack_interrupted = True
                raise KeyboardInterrupt("synthetic native ACK return gap")
            return result

        with patch.object(
            child_type,
            "ack_stdout_durable",
            new=ack_then_interrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                kernel.acknowledge_stdout_durable(ready, max_wait_ns=WAIT_NS)
            self.assertIs(
                self._complete(
                    lambda: kernel.acknowledge_stdout_durable(
                        ready,
                        max_wait_ns=WAIT_NS,
                    )
                ),
                resolver.COMPLETE,
            )
        self.assertEqual(len(fixture.output_calls), 1)
        self.assertEqual(plan._owner.safe_metadata()["output_acked_count"], 1)

        self.assertIs(
            self._complete(lambda: kernel.terminate(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )
        self.assertEqual(
            self._complete(lambda: kernel.reap(max_wait_ns=WAIT_NS)),
            9,
        )
        self.assertIs(
            self._complete(lambda: kernel.close_pipes(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )

    def test_ambiguous_signal_does_not_strand_independent_cleanup_lanes(self):
        class _AmbiguousSignalFixture(_Fixture):
            def signal_process(self, pid, signal_number, max_wait_ns):
                self.signal_calls.append((pid, signal_number, max_wait_ns))
                raise KeyboardInterrupt("synthetic signal return gap")

        fixture = _AmbiguousSignalFixture()
        request, publication, _, plan, _, channel, spawner = self._stack(fixture)
        kernel = self._drive_active(spawner, request, publication)
        self._observe(kernel, 64)
        self.assertIs(
            self._complete(lambda: kernel.terminate(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )
        for _ in range(400):
            try:
                channel.event_owner.pump(max_wait_ns=WAIT_NS)
            except EndpointPolicyError:
                pass
            if len(fixture.close_calls) == 4:
                break
            time.sleep(0.001)

        self.assertEqual(len(fixture.signal_calls), 1)
        emergency_wait = proxy_module.MAX_SUPERVISOR_PROXY_WAIT_NS
        self.assertEqual(fixture.wait_calls, [(RAW_PID, emergency_wait)])
        self.assertEqual(
            fixture.close_calls,
            [(fd, role, emergency_wait) for role, fd in enumerate(RAW_FDS)],
        )
        metadata = plan._owner.safe_metadata()
        self.assertEqual(metadata["signal_state"], "uncertain")
        self.assertTrue(metadata["reap_done"])
        self.assertTrue(metadata["all_fds_closed"])
        self.assertTrue(channel.ports.ledger.safe_metadata()["poisoned"])

        for _ in range(8):
            try:
                channel.event_owner.pump(max_wait_ns=WAIT_NS)
            except EndpointPolicyError:
                pass
        self.assertEqual(len(fixture.signal_calls), 1)
        self.assertEqual(len(fixture.wait_calls), 1)
        self.assertEqual(len(fixture.close_calls), 4)

    def test_native_callback_reentry_fails_fast_without_event_owner_deadlock(self):
        class _ReentrantFixture(_Fixture):
            def __init__(self):
                super().__init__()
                self.channel = None
                self.reentry = None

            def check_liveness(self, fd, max_wait_ns):
                self.liveness_calls.append((fd, max_wait_ns))
                owner = self.channel.event_owner
                self.reentry = (
                    owner.safe_metadata(),
                    owner.epoch_rotation_ready(),
                    owner.observe_broker_crash(),
                    owner.pump(max_wait_ns=max_wait_ns),
                )
                return True

        fixture = _ReentrantFixture()
        request, publication, _, _, _, channel, spawner = self._stack(fixture)
        fixture.channel = channel
        kernel = self._drive_active(spawner, request, publication)
        observed = []

        def drive_observation():
            try:
                observed.append(self._observe(kernel, 64))
            except BaseException as error:
                observed.append(error)

        driver = Thread(target=drive_observation, daemon=True)
        driver.start()
        driver.join(2)
        self.assertFalse(driver.is_alive(), "native callback reentry deadlocked")
        self.assertEqual(len(observed), 1)
        self.assertNotIsInstance(observed[0], BaseException)
        metadata, rotation_ready, crash_result, pump_result = fixture.reentry
        self.assertEqual(metadata, {"snapshot_busy": True})
        self.assertFalse(rotation_ready)
        self.assertIs(crash_result, resolver.PENDING)
        self.assertIs(pump_result, resolver.PENDING)

        self.assertIs(
            self._complete(lambda: kernel.terminate(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )
        self.assertEqual(
            self._complete(lambda: kernel.reap(max_wait_ns=WAIT_NS)),
            9,
        )
        self.assertIs(
            self._complete(lambda: kernel.close_pipes(max_wait_ns=WAIT_NS)),
            resolver.COMPLETE,
        )


if __name__ == "__main__":
    unittest.main()
