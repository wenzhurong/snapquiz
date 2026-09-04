"""Darwin-local S2b-I2a suspended identity integration tests."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import ctypes
import os
from pathlib import Path
import pickle
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_process_identity as identity
from snapquiz.transport import _darwin_suspended_identity as suspended
from snapquiz.transport.resolver import (
    FailClosedProductionHelperSpawner,
    ResolverHelperLauncher,
)


FIXTURE_SOURCE = Path(__file__).with_name("fixtures") / "darwin_identity_peer.c"
SPAWN_SHIM_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "snapquiz"
    / "transport"
    / "native"
    / "darwin_spawn_outcome.c"
)
FIXTURE_IDENTIFIER = "ai.snapquiz.suspended-identity-peer"
CS_VALID = 0x00000001
CS_ADHOC = 0x00000002
CS_GET_TASK_ALLOW = 0x00000004
CS_FORCED_LV = 0x00000010
CS_INVALID_ALLOWED = 0x00000020
CS_HARD = 0x00000100
CS_KILL = 0x00000200
CS_ENFORCEMENT = 0x00001000
CS_RUNTIME = 0x00010000
CS_KILLED = 0x01000000
CS_DEBUGGED = 0x10000000
CS_SIGNED = 0x20000000
REQUIRED_DYNAMIC_STATUS = (
    CS_VALID
    | CS_FORCED_LV
    | CS_HARD
    | CS_KILL
    | CS_ENFORCEMENT
    | CS_RUNTIME
    | CS_SIGNED
)
FORBIDDEN_DYNAMIC_STATUS = (
    CS_GET_TASK_ALLOW | CS_INVALID_ALLOWED | CS_KILLED | CS_DEBUGGED
)


def _assert_safe_error(test: unittest.TestCase, error: EndpointPolicyError) -> None:
    test.assertEqual(error.stage, "resolver_supervisor_suspended_identity")
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertTrue(error.__suppress_context__)
    test.assertNotIn("/private/", str(error))
    test.assertNotIn("CDHash", str(error))


@unittest.skipUnless(sys.platform == "darwin", "Darwin suspended identity")
class DarwinSuspendedIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not Path("/usr/bin/clang").is_file() or not Path(
            "/usr/bin/codesign"
        ).is_file():
            raise unittest.SkipTest("Apple clang and codesign are required")
        cls._build_root = tempfile.TemporaryDirectory(
            prefix="snapquiz-suspended-identity-build-",
            dir="/tmp",
        )
        output = Path(cls._build_root.name) / "identity-peer"
        shim_output = Path(cls._build_root.name) / "darwin-spawn-outcome.dylib"
        subprocess.run(
            [
                "/usr/bin/clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Os",
                str(FIXTURE_SOURCE),
                "-o",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "/usr/bin/clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Os",
                "-dynamiclib",
                str(SPAWN_SHIM_SOURCE),
                "-o",
                str(shim_output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--identifier",
                FIXTURE_IDENTIFIER,
                "--options",
                "runtime",
                "--timestamp=none",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--identifier",
                "ai.snapquiz.spawn-outcome",
                "--timestamp=none",
                str(shim_output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        report = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(output)],
            check=False,
            capture_output=True,
            text=True,
        )
        match = re.search(
            r"(?m)^CDHash=([0-9a-f]{40})$",
            report.stdout + report.stderr,
        )
        if report.returncode != 0 or match is None:
            raise unittest.SkipTest("could not inspect local ad-hoc fixture")
        cls.executable = str(output.resolve())
        cls.native_spawn_shim = str(shim_output.resolve())
        cls.cdhash = match.group(1)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._build_root.cleanup()

    def _policy(self, **overrides):
        values = {
            "expected_executable": self.executable,
            "expected_code_identifier": FIXTURE_IDENTIFIER,
            "expected_team_identifier": None,
            "expected_code_directory_hash": self.cdhash,
            "expected_effective_user_id": os.geteuid(),
            "required_static_code_flags": CS_ADHOC | CS_RUNTIME,
            "forbidden_static_code_flags": 0,
            "required_dynamic_code_status": REQUIRED_DYNAMIC_STATUS,
            "forbidden_dynamic_code_status": FORBIDDEN_DYNAMIC_STATUS,
            "expected_adhoc": True,
        }
        values.update(overrides)
        return identity._new_local_darwin_process_identity_policy(**values)

    @contextmanager
    def _listener(self):
        with tempfile.TemporaryDirectory(prefix="sq-suspended-", dir="/tmp") as root:
            socket_path = str((Path(root) / "identity.sock").resolve())
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.setblocking(False)
            listener.bind(socket_path)
            os.chmod(socket_path, 0o600)
            listener.listen(2)
            try:
                yield Path(root), socket_path, listener
            finally:
                listener.close()

    def _start(self, listener, socket_path, **kwargs):
        construction_owner = kwargs.pop(
            "construction_owner",
            suspended._new_monitored_identity_construction_owner(),
        )
        result = suspended._start_local_darwin_monitored_identity(
            construction_owner=construction_owner,
            listener=listener,
            socket_path=socket_path,
            policy=kwargs.pop("policy", self._policy()),
            max_peer_wait_ns=2_000_000_000,
            native_spawn_shim=self.native_spawn_shim,
            **kwargs,
        )
        if result is not None:
            raise AssertionError("monitored identity factory returned a resource")
        session = construction_owner.session()
        construction_owner.transfer_session(session)
        return session

    def test_suspended_constructor_token_binding_and_monitored_session(self):
        with self._listener() as (root, socket_path, listener):
            sentinel = str((root / "constructor-entered").resolve())
            observed_at_resume: list[bool] = []
            original = identity._signal_process_with_audit_token

            def signal_wrapper(*, raw_audit_token, signal_number):
                if signal_number == signal.SIGCONT:
                    observed_at_resume.append(Path(sentinel).exists())
                return original(
                    raw_audit_token=raw_audit_token,
                    signal_number=signal_number,
                )

            with mock.patch.object(
                identity,
                "_signal_process_with_audit_token",
                side_effect=signal_wrapper,
            ):
                session = self._start(
                    listener,
                    socket_path,
                    constructor_sentinel=sentinel,
                )
                self.assertEqual(observed_at_resume, [False])
                deadline = time.monotonic() + 1
                while not Path(sentinel).exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(Path(sentinel).exists())
                session.require_current(max_wait_ns=0)
                metadata = session.safe_metadata()
                self.assertTrue(metadata["spawn_start_suspended_requested"])
                self.assertFalse(metadata["spawn_started_suspended_attested"])
                self.assertTrue(metadata["resume_used_audit_token"])
                self.assertTrue(metadata["connection_peer_identity_attested"])
                self.assertTrue(metadata["identity_change_monitor_armed"])
                self.assertTrue(
                    metadata["continuous_monitor_armed_at_publication"]
                )
                self.assertFalse(metadata["production_bundle_attested"])
                self.assertFalse(metadata["native_atomic_owner_attested"])
                self.assertFalse(
                    metadata["native_atomic_spawn_publication_attested"]
                )
                self.assertTrue(
                    metadata["native_atomic_spawn_publication_observed"]
                )
                self.assertFalse(metadata["native_spawn_shim_trusted"])
                self.assertFalse(metadata["startup_order_attested"])
                self.assertFalse(metadata["operation_api_available"])
                self.assertFalse(metadata["transport_available"])
                self.assertNotIn("audit_token", metadata)
                self.assertNotIn("executable", metadata)
                proof = session.proof
                self.assertIs(copy.copy(proof), proof)
                self.assertIs(copy.deepcopy(proof), proof)
                with self.assertRaises(TypeError):
                    pickle.dumps(proof)
                with self.assertRaises(AttributeError):
                    proof.process_id = 1
                self.assertTrue(session.shutdown(max_wait_ns=2_000_000_000))
                self.assertTrue(session.shutdown(max_wait_ns=2_000_000_000))

    def test_watcher_true_return_event_is_cleaned_without_rewatch_or_respawn(self):
        with self._listener() as (_, socket_path, listener):
            owner = suspended._new_monitored_identity_construction_owner()
            policy = self._policy()
            spawned: list[int] = []
            observed_watchers = []
            original_spawn = suspended._spawn_suspended
            original_factory = suspended._events._new_darwin_process_event_watcher
            target_code = original_factory.__code__
            interrupted = False

            def capture_spawn(**kwargs):
                pid = original_spawn(**kwargs)
                spawned.append(pid)
                return pid

            def interrupt_return(frame, event, argument):
                nonlocal interrupted
                if frame.f_code is target_code and event == "return" and not interrupted:
                    interrupted = True
                    watcher = frame.f_locals.get("watcher")
                    self.assertIs(
                        type(watcher),
                        suspended._events._DarwinProcessEventWatcher,
                    )
                    observed_watchers.append(watcher)
                    self.assertIsNone(argument)
                    raise KeyboardInterrupt("synthetic watcher return event")
                return interrupt_return

            def start() -> None:
                suspended._start_local_darwin_monitored_identity(
                    construction_owner=owner,
                    listener=listener,
                    socket_path=socket_path,
                    policy=policy,
                    max_peer_wait_ns=2_000_000_000,
                    native_spawn_shim=self.native_spawn_shim,
                )

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    suspended,
                    "_spawn_suspended",
                    side_effect=capture_spawn,
                ):
                    sys.settrace(interrupt_return)
                    with self.assertRaises(EndpointPolicyError) as raised:
                        start()
            finally:
                sys.settrace(previous_trace)
            _assert_safe_error(self, raised.exception)
            self.assertTrue(interrupted)
            self.assertEqual(len(spawned), 1)
            self.assertEqual(len(observed_watchers), 1)
            self.assertTrue(observed_watchers[0]._closed)
            self.assertFalse(owner._slot.has_retained_resource())
            self.assertEqual(owner._slot._state, "failed_terminal")
            with self.assertRaises(ChildProcessError):
                os.waitpid(spawned[0], os.WNOHANG)

            def forbidden(*args, **kwargs):
                del args, kwargs
                raise AssertionError("failed identity construction was replayed")

            with mock.patch.object(
                suspended,
                "_spawn_suspended",
                side_effect=forbidden,
            ), mock.patch.object(
                suspended._events,
                "_new_darwin_process_event_watcher",
                side_effect=forbidden,
            ), mock.patch.object(
                suspended,
                "_wait_for_peer",
                side_effect=forbidden,
            ), self.assertRaises(EndpointPolicyError):
                start()
            self.assertFalse(owner._slot.has_retained_resource())

    def test_peer_true_return_event_is_cleaned_without_reaccept_or_respawn(self):
        with self._listener() as (_, socket_path, listener):
            owner = suspended._new_monitored_identity_construction_owner()
            policy = self._policy()
            spawned: list[int] = []
            observed_peers = []
            original_spawn = suspended._spawn_suspended
            target_code = suspended._wait_for_peer.__code__
            interrupted = False

            def capture_spawn(**kwargs):
                pid = original_spawn(**kwargs)
                spawned.append(pid)
                return pid

            def interrupt_return(frame, event, argument):
                nonlocal interrupted
                if frame.f_code is target_code and event == "return" and not interrupted:
                    interrupted = True
                    peer = frame.f_locals.get("peer")
                    self.assertIs(type(peer), socket.socket)
                    observed_peers.append(peer)
                    self.assertIsNone(argument)
                    raise KeyboardInterrupt("synthetic peer return event")
                return interrupt_return

            def start() -> None:
                suspended._start_local_darwin_monitored_identity(
                    construction_owner=owner,
                    listener=listener,
                    socket_path=socket_path,
                    policy=policy,
                    max_peer_wait_ns=2_000_000_000,
                    native_spawn_shim=self.native_spawn_shim,
                )

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    suspended,
                    "_spawn_suspended",
                    side_effect=capture_spawn,
                ):
                    sys.settrace(interrupt_return)
                    with self.assertRaises(EndpointPolicyError) as raised:
                        start()
            finally:
                sys.settrace(previous_trace)
            _assert_safe_error(self, raised.exception)
            self.assertTrue(interrupted)
            self.assertEqual(len(spawned), 1)
            self.assertEqual(len(observed_peers), 1)
            self.assertEqual(observed_peers[0].fileno(), -1)
            self.assertFalse(owner._slot.has_retained_resource())
            self.assertEqual(owner._slot._state, "failed_terminal")
            with self.assertRaises(ChildProcessError):
                os.waitpid(spawned[0], os.WNOHANG)

            def forbidden(*args, **kwargs):
                del args, kwargs
                raise AssertionError("failed identity construction was replayed")

            with mock.patch.object(
                suspended,
                "_spawn_suspended",
                side_effect=forbidden,
            ), mock.patch.object(
                suspended._events,
                "_new_darwin_process_event_watcher",
                side_effect=forbidden,
            ), mock.patch.object(
                suspended,
                "_wait_for_peer",
                side_effect=forbidden,
            ), self.assertRaises(EndpointPolicyError):
                start()
            self.assertFalse(owner._slot.has_retained_resource())

    def test_final_session_true_return_event_reuses_exact_session_without_io(self):
        with self._listener() as (_, socket_path, listener):
            owner = suspended._new_monitored_identity_construction_owner()
            policy = self._policy()
            spawned: list[int] = []
            observed_sessions = []
            calls = {"spawn": 0, "watch": 0, "accept": 0}
            original_start = suspended._start_local_darwin_monitored_identity
            original_spawn = suspended._spawn_suspended
            original_watcher = suspended._events._new_darwin_process_event_watcher
            original_peer = suspended._wait_for_peer
            target_code = original_start.__code__
            interrupted = False

            def capture_spawn(**kwargs):
                calls["spawn"] += 1
                pid = original_spawn(**kwargs)
                spawned.append(pid)
                return pid

            def capture_watcher(*args, **kwargs):
                calls["watch"] += 1
                return original_watcher(*args, **kwargs)

            def capture_peer(**kwargs):
                calls["accept"] += 1
                return original_peer(**kwargs)

            def interrupt_return(frame, event, argument):
                nonlocal interrupted
                if frame.f_code is target_code and event == "return" and not interrupted:
                    interrupted = True
                    session = frame.f_locals.get("session")
                    self.assertIs(
                        type(session),
                        suspended._LocalDarwinMonitoredIdentitySession,
                    )
                    observed_sessions.append(session)
                    self.assertIsNone(argument)
                    raise KeyboardInterrupt("synthetic session return event")
                return interrupt_return

            def start() -> None:
                return original_start(
                    construction_owner=owner,
                    listener=listener,
                    socket_path=socket_path,
                    policy=policy,
                    max_peer_wait_ns=2_000_000_000,
                    native_spawn_shim=self.native_spawn_shim,
                )

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    suspended,
                    "_spawn_suspended",
                    side_effect=capture_spawn,
                ), mock.patch.object(
                    suspended._events,
                    "_new_darwin_process_event_watcher",
                    side_effect=capture_watcher,
                ), mock.patch.object(
                    suspended,
                    "_wait_for_peer",
                    side_effect=capture_peer,
                ):
                    sys.settrace(interrupt_return)
                    with self.assertRaises(KeyboardInterrupt):
                        start()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(interrupted)
            self.assertEqual(calls, {"spawn": 1, "watch": 1, "accept": 1})
            self.assertEqual(len(spawned), 1)
            self.assertEqual(len(observed_sessions), 1)
            session = observed_sessions[0]
            self.assertIs(owner.session(), session)
            self.assertTrue(owner._slot.has_retained_resource())

            def forbidden(*args, **kwargs):
                del args, kwargs
                raise AssertionError("published identity session performed new I/O")

            with mock.patch.object(
                suspended,
                "_spawn_suspended",
                side_effect=forbidden,
            ), mock.patch.object(
                suspended._events,
                "_new_darwin_process_event_watcher",
                side_effect=forbidden,
            ), mock.patch.object(
                suspended,
                "_wait_for_peer",
                side_effect=forbidden,
            ):
                self.assertIsNone(start())
            self.assertIs(owner.session(), session)
            owner.transfer_session(session)
            self.assertFalse(owner._slot.has_retained_resource())
            self.assertEqual(owner._slot._state, "transferred")
            self.assertTrue(session.shutdown(max_wait_ns=2_000_000_000))

    def test_wrong_identity_never_resumes_constructor_and_reaps_child(self):
        with self._listener() as (root, socket_path, listener):
            sentinel = str((root / "must-not-exist").resolve())
            spawned: list[int] = []
            original = suspended._spawn_suspended

            def capture_spawn(**kwargs):
                pid = original(**kwargs)
                spawned.append(pid)
                return pid

            with mock.patch.object(
                suspended,
                "_spawn_suspended",
                side_effect=capture_spawn,
            ), self.assertRaises(EndpointPolicyError) as raised:
                self._start(
                    listener,
                    socket_path,
                    policy=self._policy(expected_code_directory_hash="0" * 40),
                    constructor_sentinel=sentinel,
                )
            _assert_safe_error(self, raised.exception)
            self.assertFalse(Path(sentinel).exists())
            self.assertEqual(len(spawned), 1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(spawned[0], os.WNOHANG)

    def test_resume_failure_is_not_replayed_and_child_is_reaped(self):
        with self._listener() as (root, socket_path, listener):
            sentinel = str((root / "must-not-exist").resolve())
            original = identity._signal_process_with_audit_token
            resume_calls = 0

            def fail_resume(*, raw_audit_token, signal_number):
                nonlocal resume_calls
                if signal_number == signal.SIGCONT:
                    resume_calls += 1
                    raise RuntimeError("synthetic resume failure")
                return original(
                    raw_audit_token=raw_audit_token,
                    signal_number=signal_number,
                )

            with mock.patch.object(
                identity,
                "_signal_process_with_audit_token",
                side_effect=fail_resume,
            ), self.assertRaises(EndpointPolicyError) as raised:
                self._start(
                    listener,
                    socket_path,
                    constructor_sentinel=sentinel,
                )
            _assert_safe_error(self, raised.exception)
            self.assertEqual(resume_calls, 1)
            self.assertFalse(Path(sentinel).exists())

    def test_spawn_commit_then_raise_recovers_exact_suspended_child(self):
        with self._listener() as (_, socket_path, listener):
            spawned: list[int] = []
            original = suspended._spawn_suspended

            def spawn_then_raise(**kwargs):
                pid = original(**kwargs)
                spawned.append(pid)
                raise KeyboardInterrupt

            with mock.patch.object(
                suspended,
                "_spawn_suspended",
                side_effect=spawn_then_raise,
            ), self.assertRaises(EndpointPolicyError) as raised:
                self._start(listener, socket_path)
            _assert_safe_error(self, raised.exception)
            self.assertEqual(len(spawned), 1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(spawned[0], os.WNOHANG)

    def test_native_spawn_return_then_raise_recovers_from_committed_cell(self):
        with self._listener() as (_, socket_path, listener):
            spawned: list[int] = []
            original_load = suspended._load_spawn_shim

            def load_wrapped(path):
                native = original_load(path)

                def call_then_raise(*args):
                    result = native(*args)
                    outcome = ctypes.cast(
                        args[0],
                        ctypes.POINTER(suspended._NativeSpawnOutcome),
                    ).contents
                    spawned.append(outcome.pid)
                    self.assertEqual(result, 0)
                    self.assertEqual(outcome.state, 2)
                    raise KeyboardInterrupt

                return call_then_raise

            with mock.patch.object(
                suspended,
                "_load_spawn_shim",
                side_effect=load_wrapped,
            ), self.assertRaises(EndpointPolicyError) as raised:
                self._start(listener, socket_path)
            _assert_safe_error(self, raised.exception)
            self.assertEqual(len(spawned), 1)
            self.assertGreater(spawned[0], 0)
            with self.assertRaises(ChildProcessError):
                os.waitpid(spawned[0], os.WNOHANG)

    def test_exit_exec_and_fork_before_publication_fail_closed(self):
        for mode in (
            "exit-after-connect",
            "exec-after-connect",
            "fork-exec-writer",
        ):
            with self.subTest(mode=mode), self._listener() as (
                _,
                socket_path,
                listener,
            ), self.assertRaises(EndpointPolicyError) as raised:
                self._start(listener, socket_path, fixture_mode=mode)
            _assert_safe_error(self, raised.exception)

    def test_exec_and_fork_after_publication_permanently_poison_session(self):
        for mode in (
            "delayed-exec-after-connect",
            "delayed-fork-exec-writer",
        ):
            with self.subTest(mode=mode), self._listener() as (
                _,
                socket_path,
                listener,
            ):
                session = self._start(listener, socket_path, fixture_mode=mode)
                time.sleep(0.4)
                with self.assertRaises(EndpointPolicyError) as raised:
                    session.require_current(max_wait_ns=0)
                _assert_safe_error(self, raised.exception)
                with self.assertRaises(EndpointPolicyError):
                    session.require_current(max_wait_ns=0)
                self.assertTrue(session.shutdown(max_wait_ns=2_000_000_000))

    def test_wrong_connector_wins_once_and_forces_clean_failure(self):
        with self._listener() as (_, socket_path, listener):
            attacker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            attacker.connect(socket_path)
            try:
                with self.assertRaises(EndpointPolicyError) as raised:
                    self._start(listener, socket_path)
                _assert_safe_error(self, raised.exception)
            finally:
                attacker.close()

    def test_import_and_production_launcher_remain_unwired(self):
        root = Path(__file__).resolve().parents[1]
        script = r'''
import ctypes
import os
import select
import socket

def poison(*args, **kwargs):
    raise AssertionError("external capability used during import")

ctypes.CDLL = poison
os.open = poison
select.kqueue = poison
socket.socket = poison
import snapquiz.transport._darwin_suspended_identity
'''
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        launcher = ResolverHelperLauncher.production(executable=self.executable)
        self.assertIs(type(launcher._spawner), FailClosedProductionHelperSpawner)


if __name__ == "__main__":
    unittest.main()
