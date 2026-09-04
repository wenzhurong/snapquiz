"""Offline acceptance for the unwired native resolver-owner foundation."""
from __future__ import annotations

from contextlib import ExitStack
import importlib
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_output_cache as output_cache
from snapquiz.transport import resolver


MODULE_NAME = "snapquiz.transport._darwin_resolver_owner"
SOURCE = (
    Path(__file__).parents[1]
    / "snapquiz"
    / "transport"
    / "native"
    / "darwin_resolver_owner.c"
)
WAIT_NS = 1_000_000


def _native_module():
    return importlib.import_module(MODULE_NAME)


class _FixtureSyscalls:
    def __init__(
        self,
        module,
        *,
        create_ambiguous=False,
        create_ambiguous_after_publication=False,
        invalid_resources=False,
        signal_ambiguous=False,
        wait_ambiguous=False,
        close_ambiguous_role=None,
        signal_entered=None,
        signal_release=None,
        publication_entered=None,
        publication_release=None,
    ):
        self.module = module
        self.create_ambiguous = create_ambiguous
        self.create_ambiguous_after_publication = (
            create_ambiguous_after_publication
        )
        self.invalid_resources = invalid_resources
        self.signal_ambiguous = signal_ambiguous
        self.wait_ambiguous = wait_ambiguous
        self.close_ambiguous_role = close_ambiguous_role
        self.signal_entered = signal_entered
        self.signal_release = signal_release
        self.publication_entered = publication_entered
        self.publication_release = publication_release
        self.create_calls = 0
        self.create_waits = []
        self.signal_calls = []
        self.wait_calls = []
        self.close_calls = []
        self.control_calls = []
        self.output_calls = []
        self.liveness_calls = []
        self.outputs = [
            module._FixtureOutput(
                output_cache._ResolverOutputKind.READY,
                output_cache.READY_OUTPUT_PAYLOAD,
            ),
            module._FixtureOutput(
                output_cache._ResolverOutputKind.RESULT,
                b'{"addresses":["192.0.2.10"]}\n',
            ),
            module._FixtureOutput(
                output_cache._ResolverOutputKind.EOF,
                b"",
            ),
        ]

    def create_process(self, max_wait_ns):
        self.create_calls += 1
        self.create_waits.append(max_wait_ns)
        if self.create_ambiguous:
            raise KeyboardInterrupt("synthetic ambiguous create boundary")
        output_fd = 101 if self.invalid_resources else 102
        return self.module._CreatedOwnerResources(
            pid=42_001,
            control_fd=101,
            output_fd=output_fd,
            diagnostics_fd=103,
            liveness_fd=104,
        )

    def after_create_publication(self, max_wait_ns):
        if self.publication_entered is not None:
            self.publication_entered.set()
        if self.publication_release is not None:
            if not self.publication_release.wait(timeout=5):
                raise TimeoutError("synthetic publication release timed out")
        if self.create_ambiguous_after_publication:
            raise KeyboardInterrupt(
                f"synthetic lost create return after {max_wait_ns}ns"
            )

    def signal_process(self, pid, signal_number, max_wait_ns):
        self.signal_calls.append((pid, signal_number, max_wait_ns))
        if self.signal_entered is not None:
            self.signal_entered.set()
        if self.signal_release is not None:
            if not self.signal_release.wait(timeout=5):
                raise TimeoutError("synthetic signal release timed out")
        if self.signal_ambiguous:
            raise KeyboardInterrupt("synthetic ambiguous signal boundary")

    def wait_process(self, pid, max_wait_ns):
        self.wait_calls.append((pid, max_wait_ns))
        if self.wait_ambiguous:
            raise KeyboardInterrupt("synthetic ambiguous wait boundary")
        return 9

    def close_fd(self, fd, role, max_wait_ns):
        self.close_calls.append((fd, role, max_wait_ns))
        if role == self.close_ambiguous_role:
            raise KeyboardInterrupt("synthetic ambiguous close boundary")

    def write_control(self, fd, frame, max_wait_ns):
        self.control_calls.append((fd, frame, max_wait_ns))

    def read_output(self, fd, sequence, capacity, max_wait_ns):
        self.output_calls.append((fd, sequence, capacity, max_wait_ns))
        if sequence >= len(self.outputs):
            return resolver.PENDING
        return self.outputs[sequence]

    def check_liveness(self, fd, max_wait_ns):
        self.liveness_calls.append((fd, max_wait_ns))
        return True


def _cache():
    return output_cache._new_resolver_output_cache(
        epoch_id=UUID("8e000000-0000-0000-0000-000000000001"),
        operation_id=UUID("8e000000-0000-0000-0000-000000000002"),
        proxy_id=UUID("8e000000-0000-0000-0000-000000000003"),
        operation_binding_digest=Digest256("8" * 64),
    )


def _interrupt_method_return(method, call):
    target_code = method.__code__
    interrupted = False

    def interrupt_return(frame, event, argument):
        nonlocal interrupted
        del argument
        if frame.f_code is target_code and event == "return" and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("synthetic native bridge return loss")
        return interrupt_return

    previous_trace = sys.gettrace()
    try:
        sys.settrace(interrupt_return)
        try:
            call()
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("native bridge return loss was not raised")
    finally:
        sys.settrace(previous_trace)
    if not interrupted:
        raise AssertionError("native bridge return was not interrupted")


class DarwinResolverOwnerFoundationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if compiler is None:
            raise unittest.SkipTest("clang is required for native owner tests")
        cls._temporary = tempfile.TemporaryDirectory(
            prefix="snapquiz-native-owner-"
        )
        suffix = ".dylib" if sys.platform == "darwin" else ".so"
        cls.library = Path(cls._temporary.name) / f"resolver-owner{suffix}"
        command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror"]
        if sys.platform == "darwin":
            command.extend(("-dynamiclib", "-o", str(cls.library), str(SOURCE)))
        else:
            command.extend(
                ("-shared", "-fPIC", "-o", str(cls.library), str(SOURCE))
            )
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def _slot(self, **fixture_options):
        module = _native_module()
        fixture = _FixtureSyscalls(module, **fixture_options)
        slot = module._new_unwired_darwin_resolver_owner_slot(self.library)
        return module, fixture, slot

    def test_import_is_inert_and_production_flag_remains_false(self):
        previous = sys.modules.pop(MODULE_NAME, None)
        del previous

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("module import touched a native boundary")

        try:
            with patch("ctypes.CDLL", side_effect=forbidden), patch.object(
                socket,
                "socket",
                side_effect=forbidden,
            ), patch.object(
                socket,
                "getaddrinfo",
                side_effect=forbidden,
            ), patch.object(
                subprocess,
                "Popen",
                side_effect=forbidden,
            ):
                module = importlib.import_module(MODULE_NAME)
                self.assertTrue(
                    module.LOCAL_NATIVE_RESOLVER_OWNER_FOUNDATION_AVAILABLE
                )
                self.assertFalse(module.PRODUCTION_NATIVE_RESOLVER_OWNER_AVAILABLE)
        finally:
            sys.modules.pop(MODULE_NAME, None)
            importlib.import_module(MODULE_NAME)

    def test_preheld_slot_closes_construction_return_gap_without_replay(self):
        module, fixture, slot = self._slot()
        _interrupt_method_return(
            module._DarwinResolverOwnerSlot.construct,
            lambda: slot.construct(fixture, max_wait_ns=WAIT_NS),
        )

        self.assertEqual(fixture.create_calls, 1)
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["state"], "child_owned")
        self.assertTrue(metadata["pid_owned"])
        self.assertEqual(metadata["owned_fd_count"], 4)
        self.assertNotIn("pid", metadata)
        self.assertNotIn("owned_fds", metadata)

        slot.construct(fixture, max_wait_ns=WAIT_NS)
        self.assertEqual(fixture.create_calls, 1)
        self.assertEqual(slot.pid, 42_001)

    def test_published_create_then_ambiguous_return_retains_recovery_owner(self):
        _, fixture, slot = self._slot(
            create_ambiguous_after_publication=True
        )
        with self.assertRaises(EndpointPolicyError):
            slot.construct(fixture, max_wait_ns=WAIT_NS)
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["state"], "recovery_owned")
        self.assertEqual(metadata["publication"], "created")
        self.assertTrue(metadata["pid_owned"])
        self.assertFalse(metadata["uncertainty_tombstone"])
        self.assertNotIn("pid", metadata)
        self.assertNotIn("owned_fds", metadata)

        self.assertIs(
            slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(slot.reap_exact(slot.pid, max_wait_ns=WAIT_NS), 9)
        self.assertIs(slot.close_exact(max_wait_ns=WAIT_NS), resolver.COMPLETE)
        self.assertEqual(fixture.create_calls, 1)
        with self.assertRaises(EndpointPolicyError):
            slot.construct(fixture, max_wait_ns=WAIT_NS)
        self.assertEqual(fixture.create_calls, 1)

    def test_published_construction_snapshot_is_coherent_without_identifiers(self):
        entered = threading.Event()
        release = threading.Event()
        _, fixture, slot = self._slot(
            publication_entered=entered,
            publication_release=release,
        )
        outcome = []

        def construct():
            try:
                slot.construct(fixture, max_wait_ns=WAIT_NS)
                outcome.append(resolver.COMPLETE)
            except BaseException as error:
                outcome.append(error)

        worker = threading.Thread(target=construct)
        worker.start()
        self.assertTrue(entered.wait(timeout=3))
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["state"], "constructing")
        self.assertEqual(metadata["publication"], "created")
        self.assertTrue(metadata["pid_owned"])
        self.assertEqual(metadata["owned_fd_count"], 4)
        self.assertNotIn("pid", metadata)
        self.assertNotIn("owned_fds", metadata)
        release.set()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, [resolver.COMPLETE])
        self.assertEqual(slot.safe_metadata()["state"], "child_owned")
        slot.construct(fixture, max_wait_ns=WAIT_NS)
        self.assertEqual(fixture.create_calls, 1)

    def test_missing_or_invalid_create_publication_is_permanent_tombstone(self):
        for options in (
            {"create_ambiguous": True},
            {"invalid_resources": True},
        ):
            with self.subTest(options=options):
                _, fixture, slot = self._slot(**options)
                with self.assertRaises(EndpointPolicyError):
                    slot.construct(fixture, max_wait_ns=WAIT_NS)
                metadata = slot.safe_metadata()
                self.assertEqual(metadata["state"], "create_uncertain")
                self.assertTrue(metadata["uncertainty_tombstone"])
                self.assertFalse(metadata["pid_owned"])
                self.assertEqual(metadata["owned_fd_count"], 0)
                self.assertNotIn("pid", metadata)
                self.assertNotIn("owned_fds", metadata)

                with self.assertRaises(EndpointPolicyError):
                    slot.construct(fixture, max_wait_ns=WAIT_NS)
                self.assertEqual(fixture.create_calls, 1)
                for action in (
                    lambda: slot.terminate_exact(42_001, max_wait_ns=WAIT_NS),
                    lambda: slot.reap_exact(42_001, max_wait_ns=WAIT_NS),
                    lambda: slot.close_exact(max_wait_ns=WAIT_NS),
                ):
                    with self.assertRaises(EndpointPolicyError):
                        action()
                self.assertEqual(fixture.signal_calls, [])
                self.assertEqual(fixture.wait_calls, [])
                self.assertEqual(fixture.close_calls, [])

    def test_control_liveness_signal_wait_close_and_deadlines_are_exact(self):
        module, fixture, slot = self._slot()
        slot.construct(fixture, max_wait_ns=WAIT_NS)
        frame = b"synthetic-control-frame-without-target\n"

        self.assertIs(
            slot.write_start_datagram(frame, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertIs(
            slot.write_start_datagram(frame, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(fixture.control_calls, [(101, frame, WAIT_NS)])

        self.assertTrue(slot.poll_liveness_exact(max_wait_ns=WAIT_NS))
        self.assertTrue(slot.poll_liveness_exact(max_wait_ns=WAIT_NS))
        self.assertEqual(fixture.liveness_calls, [(104, WAIT_NS)])

        _interrupt_method_return(
            module._DarwinResolverOwnerSlot.terminate_exact,
            lambda: slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS),
        )
        self.assertIs(
            slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(fixture.signal_calls, [(42_001, signal.SIGKILL, WAIT_NS)])

        _interrupt_method_return(
            module._DarwinResolverOwnerSlot.reap_exact,
            lambda: slot.reap_exact(slot.pid, max_wait_ns=WAIT_NS),
        )
        self.assertEqual(slot.reap_exact(slot.pid, max_wait_ns=WAIT_NS), 9)
        self.assertEqual(fixture.wait_calls, [(42_001, WAIT_NS)])

        _interrupt_method_return(
            module._DarwinResolverOwnerSlot.close_exact,
            lambda: slot.close_exact(max_wait_ns=WAIT_NS),
        )
        self.assertIs(slot.close_exact(max_wait_ns=WAIT_NS), resolver.COMPLETE)
        self.assertEqual(
            fixture.close_calls,
            [
                (101, 0, WAIT_NS),
                (102, 1, WAIT_NS),
                (103, 2, WAIT_NS),
                (104, 3, WAIT_NS),
            ],
        )
        metadata = slot.safe_metadata()
        self.assertTrue(metadata["signal_done"])
        self.assertTrue(metadata["reap_done"])
        self.assertEqual(metadata["wait_status"], 9)
        self.assertTrue(metadata["all_fds_closed"])
        self.assertTrue(metadata["liveness_known"])
        self.assertEqual(fixture.create_waits, [WAIT_NS])

    def test_ambiguous_signal_does_not_block_wait_or_descriptor_cleanup(self):
        _, fixture, slot = self._slot(signal_ambiguous=True)
        slot.construct(fixture, max_wait_ns=WAIT_NS)
        with self.assertRaises(EndpointPolicyError):
            slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS)
        with self.assertRaises(EndpointPolicyError):
            slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS)
        self.assertEqual(len(fixture.signal_calls), 1)

        self.assertEqual(slot.reap_exact(slot.pid, max_wait_ns=WAIT_NS), 9)
        self.assertIs(slot.close_exact(max_wait_ns=WAIT_NS), resolver.COMPLETE)
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["state"], "child_owned")
        self.assertEqual(metadata["signal_state"], "uncertain")
        self.assertTrue(metadata["reap_done"])
        self.assertTrue(metadata["all_fds_closed"])
        self.assertEqual(len(fixture.wait_calls), 1)
        self.assertEqual(len(fixture.close_calls), 4)

    def test_ambiguous_wait_is_not_replayed_and_fds_still_close(self):
        _, fixture, slot = self._slot(wait_ambiguous=True)
        slot.construct(fixture, max_wait_ns=WAIT_NS)
        with self.assertRaises(EndpointPolicyError):
            slot.reap_exact(slot.pid, max_wait_ns=WAIT_NS)
        with self.assertRaises(EndpointPolicyError):
            slot.reap_exact(slot.pid, max_wait_ns=WAIT_NS)
        self.assertEqual(len(fixture.wait_calls), 1)

        # An ambiguous reap could already have released/reused the PID, so a
        # later signal fails closed. Descriptor cleanup is identity-independent.
        with self.assertRaises(EndpointPolicyError):
            slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS)
        self.assertEqual(fixture.signal_calls, [])
        self.assertIs(slot.close_exact(max_wait_ns=WAIT_NS), resolver.COMPLETE)
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["reap_state"], "uncertain")
        self.assertTrue(metadata["all_fds_closed"])
        self.assertEqual(len(fixture.close_calls), 4)

    def test_ambiguous_close_is_per_role_and_other_roles_still_close(self):
        _, fixture, slot = self._slot(close_ambiguous_role=1)
        slot.construct(fixture, max_wait_ns=WAIT_NS)
        with self.assertRaises(EndpointPolicyError):
            slot.close_exact(max_wait_ns=WAIT_NS)
        self.assertEqual(
            [item[1] for item in fixture.close_calls],
            [0, 1, 2, 3],
        )
        calls_after_first = list(fixture.close_calls)
        with self.assertRaises(EndpointPolicyError):
            slot.close_exact(max_wait_ns=WAIT_NS)
        self.assertEqual(fixture.close_calls, calls_after_first)
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["closed_fd_count"], 3)
        self.assertEqual(metadata["close_uncertain_count"], 1)
        self.assertEqual(
            metadata["close_states"],
            ("done", "uncertain", "done", "done"),
        )

    def test_snapshot_is_race_free_and_fail_closed_while_mutation_runs(self):
        entered = threading.Event()
        release = threading.Event()
        _, fixture, slot = self._slot(
            signal_entered=entered,
            signal_release=release,
        )
        slot.construct(fixture, max_wait_ns=WAIT_NS)
        outcome = []

        def terminate():
            try:
                outcome.append(
                    slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS)
                )
            except BaseException as error:
                outcome.append(error)

        worker = threading.Thread(target=terminate)
        worker.start()
        self.assertTrue(entered.wait(timeout=3))
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["state"], "snapshot_busy")
        self.assertTrue(metadata["snapshot_busy"])
        self.assertNotIn("pid", metadata)
        self.assertNotIn("owned_fds", metadata)
        release.set()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, [resolver.COMPLETE])
        self.assertEqual(slot.safe_metadata()["signal_state"], "done")

    def test_max_wait_is_bounded_before_callback_and_native_validates_it(self):
        module, fixture, slot = self._slot()
        for invalid in (0, -1, True, module.NATIVE_RESOLVER_MAX_WAIT_NS + 1):
            with self.subTest(invalid=invalid):
                with self.assertRaises((TypeError, ValueError)):
                    slot.construct(fixture, max_wait_ns=invalid)
        self.assertEqual(fixture.create_calls, 0)

        slot.construct(fixture, max_wait_ns=WAIT_NS)
        native_result = slot._native.library.sq_resolver_owner_signal(
            slot._pointer,
            slot.pid,
            signal.SIGKILL,
            0,
        )
        self.assertEqual(native_result, module._OWNER_INVALID)
        self.assertEqual(fixture.signal_calls, [])
        self.assertIs(
            slot.terminate_exact(slot.pid, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )
        self.assertEqual(fixture.signal_calls[0][2], WAIT_NS)

    def test_output_slot_redelivers_exact_bytes_and_ack_loss_is_idempotent(self):
        module, fixture, slot = self._slot()
        slot.construct(fixture, max_wait_ns=WAIT_NS)
        cache = _cache()
        kinds = (
            output_cache._ResolverOutputKind.READY,
            output_cache._ResolverOutputKind.RESULT,
            output_cache._ResolverOutputKind.EOF,
        )

        for sequence, kind in enumerate(kinds):
            with self.subTest(sequence=sequence):
                publication = cache.new_publication(sequence=sequence, kind=kind)
                self.assertIs(
                    slot.observe_stdout_durable(
                        module.NATIVE_RESOLVER_MAX_OUTPUT_BYTES,
                        publication=publication,
                        max_wait_ns=WAIT_NS,
                    ),
                    resolver.COMPLETE,
                )
                observation = cache.current(publication)
                self.assertIsNotNone(observation)
                reads_after_first_delivery = len(fixture.output_calls)
                self.assertIs(
                    slot.observe_stdout_durable(
                        module.NATIVE_RESOLVER_MAX_OUTPUT_BYTES,
                        publication=publication,
                        max_wait_ns=WAIT_NS,
                    ),
                    resolver.COMPLETE,
                )
                self.assertIs(cache.current(publication), observation)
                self.assertEqual(len(fixture.output_calls), reads_after_first_delivery)

                if sequence == 0:
                    _interrupt_method_return(
                        module._DarwinResolverOwnerSlot.ack_stdout_durable,
                        lambda: slot.ack_stdout_durable(
                            observation,
                            max_wait_ns=WAIT_NS,
                        ),
                    )
                self.assertIs(
                    slot.ack_stdout_durable(
                        observation,
                        max_wait_ns=WAIT_NS,
                    ),
                    resolver.COMPLETE,
                )
                cache.acknowledge(observation)

        self.assertEqual(
            [(item[1], item[3]) for item in fixture.output_calls],
            [(0, WAIT_NS), (1, WAIT_NS), (2, WAIT_NS)],
        )
        metadata = slot.safe_metadata()
        self.assertEqual(metadata["output_acked_count"], 3)
        self.assertEqual(metadata["next_output_sequence"], 3)
        self.assertFalse(metadata["output_slot_present"])

    def test_fixture_path_uses_no_process_dns_socket_or_credentials(self):
        _, fixture, slot = self._slot()

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("offline owner touched a forbidden primitive")

        with ExitStack() as stack:
            stack.enter_context(patch.object(socket, "socket", side_effect=forbidden))
            stack.enter_context(
                patch.object(socket, "getaddrinfo", side_effect=forbidden)
            )
            stack.enter_context(
                patch.object(subprocess, "Popen", side_effect=forbidden)
            )
            for name in ("fork", "posix_spawn", "posix_spawnp"):
                if hasattr(os, name):
                    stack.enter_context(patch.object(os, name, side_effect=forbidden))
            slot.construct(fixture, max_wait_ns=WAIT_NS)
            slot.write_start_datagram(b"offline\n", max_wait_ns=WAIT_NS)
            self.assertTrue(slot.poll_liveness_exact(max_wait_ns=WAIT_NS))

        self.assertEqual(fixture.create_calls, 1)
        self.assertEqual(fixture.control_calls, [(101, b"offline\n", WAIT_NS)])


if __name__ == "__main__":
    unittest.main()
