"""Darwin-local acceptance tests for the S2a supervisor bootstrap harness."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_resolver_supervisor as supervisor
from snapquiz.transport.resolver import (
    FailClosedProductionHelperSpawner,
    ResolverHelperLauncher,
)


FIXTURE = Path(__file__).with_name("fixtures") / "resolver_supervisor_probe.py"
READY_WAIT_NS = 5_000_000_000
CLEANUP_WAIT_NS = 2_000_000_000


def _ids(prefix: int = 0x91) -> tuple[UUID, ...]:
    return tuple(
        UUID(f"{prefix:02x}000000-0000-0000-0000-{index:012d}")
        for index in range(1, 7)
    )


def _make_binding(policy, *, prefix: int = 0x91):
    identifiers = _ids(prefix)
    return supervisor._new_supervisor_bootstrap_binding(
        bootstrap_id=identifiers[0],
        epoch_id=identifiers[1],
        challenge_id=identifiers[2],
        control_channel_id=identifiers[3],
        parent_liveness_id=identifiers[4],
        supervisor_liveness_id=identifiers[5],
        local_probe_policy_digest=policy.policy_digest,
        executable_sha256=policy.executable_sha256,
    )


@contextmanager
def _case(mode: str = "success", *, prefix: int = 0x91):
    with tempfile.TemporaryDirectory(
        prefix="snapquiz-supervisor-bootstrap-"
    ) as root:
        copied = Path(root) / f"resolver_supervisor_probe__{mode}.py"
        shutil.copy2(FIXTURE, copied)
        copied.chmod(0o700)
        executable = copied.resolve()
        executable_sha256 = Digest256(
            hashlib.sha256(executable.read_bytes()).hexdigest()
        )
        policy = supervisor._new_local_supervisor_probe_policy(
            executable=str(executable),
            executable_sha256=executable_sha256,
        )
        binding = _make_binding(policy, prefix=prefix)
        with patch.object(supervisor, "_PROCESS_BOOTSTRAP", None):
            bootstrap = (
                supervisor._new_darwin_resolver_supervisor_bootstrap()
            )
            try:
                yield bootstrap, policy, binding
            finally:
                for _ in range(3):
                    if bootstrap.cleanup(max_wait_ns=CLEANUP_WAIT_NS):
                        break


def _assert_fd_closed(test: unittest.TestCase, fd: int) -> None:
    with test.assertRaises(OSError) as raised:
        os.fstat(fd)
    test.assertEqual(raised.exception.errno, errno.EBADF)


def _assert_safe_error(test: unittest.TestCase, error: EndpointPolicyError) -> None:
    test.assertEqual(error.stage, "resolver_supervisor_bootstrap")
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertTrue(error.__suppress_context__)
    test.assertNotIn("/private/", str(error))


@unittest.skipUnless(sys.platform == "darwin", "Darwin supervisor bootstrap")
class DarwinResolverSupervisorBootstrapTests(unittest.TestCase):
    def test_factory_is_process_singleton_and_values_are_factory_owned(self):
        with patch.object(supervisor, "_PROCESS_BOOTSTRAP", None):
            first = supervisor._new_darwin_resolver_supervisor_bootstrap()
            second = supervisor._new_darwin_resolver_supervisor_bootstrap()
            self.assertIs(first, second)
        with self.assertRaises(TypeError):
            supervisor._DarwinResolverSupervisorBootstrap()
        with self.assertRaises(TypeError):
            supervisor._LocalSupervisorProbePolicy(
                executable="/bin/false",
                executable_sha256=Digest256("0" * 64),
            )

    def test_real_success_exact_reentry_and_clean_shutdown_close_all_fds(self):
        captured_channels: list[object] = []
        captured_leases: list[object] = []
        spawn_count = 0
        original_channels = supervisor._create_bootstrap_channels
        original_attest = supervisor._attest_local_probe
        original_spawn = supervisor._spawn_local_probe

        def create_channels(acquisition):
            channels = original_channels(acquisition)
            captured_channels.append(channels)
            return channels

        def attest(policy, acquisition):
            lease = original_attest(policy, acquisition)
            captured_leases.append(lease)
            return lease

        def spawn(**kwargs):
            nonlocal spawn_count
            spawn_count += 1
            return original_spawn(**kwargs)

        with _case() as (bootstrap, policy, binding):
            with (
                patch.object(
                    supervisor,
                    "_create_bootstrap_channels",
                    side_effect=create_channels,
                ),
                patch.object(
                    supervisor,
                    "_attest_local_probe",
                    side_effect=attest,
                ),
                patch.object(
                    supervisor,
                    "_spawn_local_probe",
                    side_effect=spawn,
                ),
            ):
                session = bootstrap.start(
                    policy=policy,
                    binding=binding,
                    max_ready_wait_ns=READY_WAIT_NS,
                )
                self.assertIs(
                    session,
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    ),
                )
                self.assertEqual(spawn_count, 1)
                metadata = session.safe_metadata()
                self.assertEqual(metadata["state"], "ready_attested")
                self.assertEqual(metadata["broker_operation_count"], 0)
                self.assertFalse(metadata["operation_api_available"])
                self.assertFalse(metadata["transport_available"])
                self.assertFalse(metadata["actual_process_identity_attested"])
                owner_metadata = bootstrap._owner.safe_metadata()
                self.assertEqual(owner_metadata["child_endpoint_count"], 0)
                self.assertEqual(owner_metadata["parent_endpoint_count"], 4)
                self.assertTrue(owner_metadata["pid_bound"])
                self.assertTrue(owner_metadata["ready_observed"])
                channels = captured_channels[0]
                for fd in channels.child_fds():
                    _assert_fd_closed(self, fd)
                _assert_fd_closed(self, captured_leases[0].fd)
                self.assertTrue(session.shutdown(max_wait_ns=CLEANUP_WAIT_NS))
                self.assertTrue(session.shutdown(max_wait_ns=CLEANUP_WAIT_NS))

            self.assertEqual(spawn_count, 1)
            self.assertEqual(session.safe_metadata()["state"], "terminal_attested")
            self.assertEqual(
                bootstrap.safe_metadata()["state"],
                "terminal_attested",
            )
            self.assertTrue(session.safe_metadata()["poison_fanout_complete"])
            self.assertTrue(bootstrap._owner.safe_metadata()["clean_exit"])
            for fd in captured_channels[0].all_fds():
                _assert_fd_closed(self, fd)
            with self.assertRaises(EndpointPolicyError) as raised:
                bootstrap.start(
                    policy=policy,
                    binding=binding,
                    max_ready_wait_ns=READY_WAIT_NS,
                )
            _assert_safe_error(self, raised.exception)
            self.assertEqual(
                bootstrap.safe_metadata()["state"],
                "terminal_attested",
            )
            self.assertIsNone(
                bootstrap.safe_metadata()["global_poison_reason"]
            )

    def test_real_probe_does_not_inherit_environment_or_fd_canaries(self):
        low_fd = os.open(FIXTURE, os.O_RDONLY)
        high_fd: int | None = None
        try:
            os.set_inheritable(low_fd, True)
            soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            high_floor = min(4_096, max(64, soft_limit - 2))
            high_fd = fcntl.fcntl(low_fd, fcntl.F_DUPFD, high_floor)
            os.set_inheritable(high_fd, True)
            with (
                patch.dict(
                    os.environ,
                    {"SNAPQUIZ_SUPERVISOR_PARENT_CANARY": "must-not-cross"},
                ),
                _case(prefix=0x92) as (bootstrap, policy, binding),
            ):
                session = bootstrap.start(
                    policy=policy,
                    binding=binding,
                    max_ready_wait_ns=READY_WAIT_NS,
                )
                pid = bootstrap._owner._pid
                self.assertIs(type(pid), int)
                process_rows = subprocess.run(
                    ["ps", "-axo", "pid=,ppid="],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.splitlines()
                descendants = [
                    row
                    for row in process_rows
                    if len(row.split()) == 2
                    and int(row.split()[1]) == pid
                ]
                self.assertEqual(descendants, [])
                self.assertTrue(session.shutdown(max_wait_ns=CLEANUP_WAIT_NS))
        finally:
            if high_fd is not None:
                os.close(high_fd)
            os.close(low_fd)

    def test_path_policy_binds_path_and_bytes_before_spawn(self):
        with tempfile.TemporaryDirectory(
            prefix="snapquiz-supervisor-policy-"
        ) as root:
            first = Path(root) / "first.py"
            second = Path(root) / "second.py"
            shutil.copy2(FIXTURE, first)
            shutil.copy2(FIXTURE, second)
            first.chmod(0o700)
            second.chmod(0o700)
            first = first.resolve()
            second = second.resolve()
            digest = Digest256(hashlib.sha256(first.read_bytes()).hexdigest())
            policy_a = supervisor._new_local_supervisor_probe_policy(
                executable=str(first),
                executable_sha256=digest,
            )
            policy_b = supervisor._new_local_supervisor_probe_policy(
                executable=str(second),
                executable_sha256=digest,
            )
            self.assertNotEqual(policy_a.policy_digest, policy_b.policy_digest)
            binding_a = _make_binding(policy_a, prefix=0x93)
            with patch.object(supervisor, "_PROCESS_BOOTSTRAP", None):
                bootstrap = supervisor._new_darwin_resolver_supervisor_bootstrap()
                with patch.object(supervisor, "_spawn_local_probe") as spawn:
                    with self.assertRaises(EndpointPolicyError) as raised:
                        bootstrap.start(
                            policy=policy_b,
                            binding=binding_a,
                            max_ready_wait_ns=READY_WAIT_NS,
                        )
                    _assert_safe_error(self, raised.exception)
                    spawn.assert_not_called()
                self.assertFalse(bootstrap.safe_metadata()["attempted"])

    def test_pre_spawn_path_failures_close_claimed_lease(self):
        modes = ("wrong_digest", "group_writable", "symlink")
        for offset, mode in enumerate(modes):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory(
                    prefix="snapquiz-supervisor-path-failure-"
                ) as root:
                    copied = Path(root) / "probe.py"
                    shutil.copy2(FIXTURE, copied)
                    copied.chmod(0o700)
                    selected = copied.resolve()
                    digest = Digest256(
                        hashlib.sha256(selected.read_bytes()).hexdigest()
                    )
                    if mode == "wrong_digest":
                        digest = Digest256("0" * 64)
                    elif mode == "group_writable":
                        copied.chmod(0o720)
                    elif mode == "symlink":
                        link = Path(root) / "link.py"
                        link.symlink_to(copied)
                        selected = link
                    policy = supervisor._new_local_supervisor_probe_policy(
                        executable=str(selected),
                        executable_sha256=digest,
                    )
                    binding = _make_binding(policy, prefix=0x94 + offset)
                    with patch.object(supervisor, "_PROCESS_BOOTSTRAP", None):
                        bootstrap = supervisor._new_darwin_resolver_supervisor_bootstrap()
                        with patch.object(supervisor, "_spawn_local_probe") as spawn:
                            with self.assertRaises(EndpointPolicyError):
                                bootstrap.start(
                                    policy=policy,
                                    binding=binding,
                                    max_ready_wait_ns=READY_WAIT_NS,
                                )
                            spawn.assert_not_called()
                        self.assertTrue(
                            bootstrap.cleanup(max_wait_ns=CLEANUP_WAIT_NS)
                        )
                        metadata = bootstrap.safe_metadata()
                        self.assertEqual(metadata["state"], "failed_clean")
                        self.assertFalse(metadata["recovery_refs_held"])

    def test_real_ready_failures_are_global_and_never_respawn(self):
        modes = (
            "exit_before_ready",
            "stderr",
            "block_ready",
            "wrong_epoch",
            "wrong_bootstrap",
            "wrong_policy",
            "wrong_digest",
            "wrong_pid",
            "extra_key",
        )
        for offset, mode in enumerate(modes):
            with self.subTest(mode=mode):
                spawn_count = 0
                original_spawn = supervisor._spawn_local_probe

                def spawn(**kwargs):
                    nonlocal spawn_count
                    spawn_count += 1
                    return original_spawn(**kwargs)

                with _case(mode, prefix=0xA0 + offset) as (
                    bootstrap,
                    policy,
                    binding,
                ):
                    with patch.object(
                        supervisor,
                        "_spawn_local_probe",
                        side_effect=spawn,
                    ):
                        with self.assertRaises(EndpointPolicyError) as raised:
                            bootstrap.start(
                                policy=policy,
                                binding=binding,
                                max_ready_wait_ns=100_000_000,
                            )
                        _assert_safe_error(self, raised.exception)
                        self.assertTrue(
                            bootstrap.cleanup(max_wait_ns=CLEANUP_WAIT_NS)
                        )
                        with self.assertRaises(EndpointPolicyError):
                            bootstrap.start(
                                policy=policy,
                                binding=binding,
                                max_ready_wait_ns=READY_WAIT_NS,
                            )
                    self.assertEqual(spawn_count, 1)
                    metadata = bootstrap.safe_metadata()
                    self.assertEqual(metadata["state"], "global_poisoned")
                    self.assertFalse(metadata["session_committed"])
                    self.assertFalse(metadata["recovery_refs_held"])

    def test_duplicate_exit_and_liveness_records_never_recover_ready(self):
        modes = ("double_ready", "liveness_byte", "exit_after_ready")
        for offset, mode in enumerate(modes):
            with self.subTest(mode=mode):
                with _case(mode, prefix=0xB0 + offset) as (
                    bootstrap,
                    policy,
                    binding,
                ):
                    session = None
                    try:
                        session = bootstrap.start(
                            policy=policy,
                            binding=binding,
                            max_ready_wait_ns=READY_WAIT_NS,
                        )
                    except EndpointPolicyError:
                        pass
                    if session is not None:
                        deadline = time.monotonic_ns() + READY_WAIT_NS
                        while time.monotonic_ns() < deadline:
                            try:
                                session.require_live(max_wait_ns=25_000_000)
                            except EndpointPolicyError:
                                break
                        else:
                            self.fail(f"{mode} remained live")
                    self.assertEqual(
                        bootstrap.safe_metadata()["state"],
                        "global_poisoned",
                    )
                    with self.assertRaises(EndpointPolicyError):
                        bootstrap.start(
                            policy=policy,
                            binding=binding,
                            max_ready_wait_ns=READY_WAIT_NS,
                        )
                    self.assertTrue(
                        bootstrap.cleanup(max_wait_ns=CLEANUP_WAIT_NS)
                    )

    def test_stubborn_probe_is_killed_once_and_exactly_reaped(self):
        captured_channels: list[object] = []
        original_channels = supervisor._create_bootstrap_channels

        def create_channels(acquisition):
            channels = original_channels(acquisition)
            captured_channels.append(channels)
            return channels

        with _case("stubborn", prefix=0xB8) as (
            bootstrap,
            policy,
            binding,
        ):
            with patch.object(
                supervisor,
                "_create_bootstrap_channels",
                side_effect=create_channels,
            ):
                session = bootstrap.start(
                    policy=policy,
                    binding=binding,
                    max_ready_wait_ns=READY_WAIT_NS,
                )
            exact_pid = bootstrap._owner._pid
            kill_calls: list[tuple[int, int]] = []
            wait_calls: list[tuple[int, int]] = []
            real_kill = os.kill
            real_waitpid = os.waitpid

            def kill(pid: int, sig: int):
                kill_calls.append((pid, sig))
                return real_kill(pid, sig)

            def waitpid(pid: int, options: int):
                wait_calls.append((pid, options))
                return real_waitpid(pid, options)

            with (
                patch.object(supervisor.os, "kill", side_effect=kill),
                patch.object(supervisor.os, "waitpid", side_effect=waitpid),
            ):
                self.assertTrue(session.shutdown(max_wait_ns=1_000_000_000))
                self.assertTrue(session.shutdown(max_wait_ns=100_000_000))
            self.assertEqual(kill_calls, [(exact_pid, supervisor.signal.SIGKILL)])
            self.assertTrue(wait_calls)
            self.assertTrue(
                all(
                    pid == exact_pid and options == os.WNOHANG
                    for pid, options in wait_calls
                )
            )
            self.assertNotIn(-1, [pid for pid, _ in wait_calls])
            self.assertFalse(bootstrap._owner.safe_metadata()["clean_exit"])
            self.assertTrue(bootstrap._owner.safe_metadata()["locally_terminal"])
            self.assertEqual(
                session.safe_metadata()["state"],
                "global_poisoned",
            )
            self.assertTrue(session.safe_metadata()["poison_fanout_complete"])
            self.assertFalse(session.safe_metadata()["recovery_refs_held"])
            for fd in captured_channels[0].all_fds():
                _assert_fd_closed(self, fd)

    def test_real_parent_death_eof_does_not_leave_probe_running(self):
        harness = """
import hashlib
import os
from pathlib import Path
import sys
from uuid import UUID
from snapquiz.domain.digest import Digest256
from snapquiz.transport import _darwin_resolver_supervisor as s
p = Path(sys.argv[1]).resolve()
d = Digest256(hashlib.sha256(p.read_bytes()).hexdigest())
policy = s._new_local_supervisor_probe_policy(
    executable=str(p), executable_sha256=d
)
ids = [UUID(f'd1000000-0000-0000-0000-{i:012d}') for i in range(1, 7)]
binding = s._new_supervisor_bootstrap_binding(
    bootstrap_id=ids[0], epoch_id=ids[1], challenge_id=ids[2],
    control_channel_id=ids[3], parent_liveness_id=ids[4],
    supervisor_liveness_id=ids[5],
    local_probe_policy_digest=policy.policy_digest,
    executable_sha256=d,
)
bootstrap = s._new_darwin_resolver_supervisor_bootstrap()
bootstrap.start(
    policy=policy, binding=binding, max_ready_wait_ns=2_000_000_000
)
print(bootstrap._owner._pid, flush=True)
os._exit(0)
"""
        with tempfile.TemporaryDirectory(
            prefix="snapquiz-supervisor-parent-death-"
        ) as root:
            copied = Path(root) / "resolver_supervisor_probe.py"
            shutil.copy2(FIXTURE, copied)
            copied.chmod(0o700)
            process = subprocess.Popen(
                [sys.executable, "-c", harness, str(copied.resolve())],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, error)
            child_pid = int(output.strip())
            deadline = time.monotonic_ns() + READY_WAIT_NS
            while time.monotonic_ns() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                try:
                    os.kill(child_pid, supervisor.signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.fail("supervisor probe survived parent-death EOF")

    def test_claimed_acquisition_return_interrupts_are_cleaned(self):
        original_attest = supervisor._attest_local_probe
        captured_lease: list[int] = []

        def interrupted_attest(policy, acquisition):
            lease = original_attest(policy, acquisition)
            captured_lease.append(lease.fd)
            raise KeyboardInterrupt

        with _case(prefix=0xC0) as (bootstrap, policy, binding):
            with patch.object(
                supervisor,
                "_attest_local_probe",
                side_effect=interrupted_attest,
            ):
                with self.assertRaises(EndpointPolicyError):
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
            _assert_fd_closed(self, captured_lease[0])
            self.assertEqual(bootstrap.safe_metadata()["state"], "failed_clean")

        original_channels = supervisor._create_bootstrap_channels
        captured_fds: list[int] = []

        def interrupted_channels(acquisition):
            channels = original_channels(acquisition)
            captured_fds.extend(channels.all_fds())
            raise KeyboardInterrupt

        with _case(prefix=0xC1) as (bootstrap, policy, binding):
            with patch.object(
                supervisor,
                "_create_bootstrap_channels",
                side_effect=interrupted_channels,
            ):
                with self.assertRaises(EndpointPolicyError):
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
            for fd in captured_fds:
                _assert_fd_closed(self, fd)
            self.assertEqual(bootstrap.safe_metadata()["state"], "failed_clean")

    def test_raw_syscall_return_gap_is_poisoned_not_reported_clean(self):
        captured_open: list[int] = []
        real_open = os.open

        def interrupted_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            captured_open.append(fd)
            raise KeyboardInterrupt

        with _case(prefix=0xC2) as (bootstrap, policy, binding):
            with patch.object(supervisor.os, "open", side_effect=interrupted_open):
                with self.assertRaises(EndpointPolicyError):
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
            metadata = bootstrap.safe_metadata()
            self.assertEqual(metadata["state"], "global_poisoned")
            self.assertTrue(metadata["recovery_refs_held"])
            os.fstat(captured_open[0])
            real_close = os.close
            real_close(captured_open[0])

        captured_pipe: list[int] = []
        real_pipe = os.pipe

        def interrupted_pipe():
            pair = real_pipe()
            captured_pipe.extend(pair)
            raise KeyboardInterrupt

        with _case(prefix=0xC3) as (bootstrap, policy, binding):
            with patch.object(supervisor.os, "pipe", side_effect=interrupted_pipe):
                with self.assertRaises(EndpointPolicyError):
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
            metadata = bootstrap.safe_metadata()
            self.assertEqual(metadata["state"], "global_poisoned")
            self.assertTrue(metadata["recovery_refs_held"])
            for fd in captured_pipe:
                os.fstat(fd)
                os.close(fd)

    def test_native_handle_unknown_windows_never_report_clean_or_replay(self):
        original_configure = supervisor._configure_spawn_functions
        captured_handle_values: list[int] = []
        native_destroy: list[object] = []

        def configure(libc):
            functions = list(original_configure(libc))
            real_init = functions[0]
            native_destroy.append(functions[1])

            def init_then_interrupt(pointer):
                result = real_init(pointer)
                if result != 0:
                    return result
                selected = ctypes.cast(
                    pointer,
                    ctypes.POINTER(ctypes.c_void_p),
                ).contents.value
                if type(selected) is int and selected > 0:
                    captured_handle_values.append(selected)
                raise KeyboardInterrupt

            functions[0] = init_then_interrupt
            return tuple(functions)

        with _case(prefix=0xC8) as (bootstrap, policy, binding):
            with patch.object(
                supervisor,
                "_configure_spawn_functions",
                side_effect=configure,
            ):
                with self.assertRaises(EndpointPolicyError):
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
            self.assertEqual(len(captured_handle_values), 1)
            metadata = bootstrap.safe_metadata()
            self.assertEqual(metadata["state"], "global_poisoned")
            self.assertTrue(metadata["recovery_refs_held"])
            self.assertFalse(bootstrap.cleanup(max_wait_ns=CLEANUP_WAIT_NS))
            storage = ctypes.c_void_p(captured_handle_values[0])
            self.assertEqual(native_destroy[0](ctypes.byref(storage)), 0)

        acquisition = supervisor._BootstrapAcquisitionOwner(
            _authority=supervisor._ACQUISITION_AUTHORITY
        )
        acquisition.begin_native_handle_initialization(
            "file_actions",
            _authority=supervisor._ACQUISITION_AUTHORITY,
        )
        destroy_calls = 0

        def destroy_then_interrupt(_pointer):
            nonlocal destroy_calls
            destroy_calls += 1
            raise KeyboardInterrupt

        acquisition.claim_native_handle(
            "file_actions",
            storage=ctypes.c_void_p(1),
            destroy=destroy_then_interrupt,
            _authority=supervisor._ACQUISITION_AUTHORITY,
        )
        self.assertFalse(acquisition.cleanup(max_wait_ns=CLEANUP_WAIT_NS))
        self.assertFalse(acquisition.cleanup(max_wait_ns=CLEANUP_WAIT_NS))
        self.assertEqual(destroy_calls, 1)
        self.assertTrue(acquisition.recovery_refs_held())

    def test_low_numbered_pipe_fds_are_owned_before_policy_rejection(self):
        acquisition = supervisor._BootstrapAcquisitionOwner(
            _authority=supervisor._ACQUISITION_AUTHORITY
        )
        pairs = iter(((0, 3), (4, 5), (6, 7), (8, 9)))
        closed: list[int] = []
        with patch.object(supervisor.os, "pipe", side_effect=lambda: next(pairs)):
            with self.assertRaises(supervisor._BootstrapBoundaryFailure):
                supervisor._create_bootstrap_channels(acquisition)
        self.assertEqual(
            acquisition.safe_metadata()["raw_descriptor_count"],
            8,
        )
        with patch.object(
            supervisor.os,
            "close",
            side_effect=lambda fd: closed.append(fd),
        ):
            self.assertTrue(acquisition.cleanup(max_wait_ns=CLEANUP_WAIT_NS))
        self.assertEqual(closed, [0, 3, 4, 5, 6, 7, 8, 9])
        self.assertFalse(acquisition.recovery_refs_held())

    def test_kill_return_interruption_is_not_replayed_and_can_be_reaped(self):
        with _case("stubborn", prefix=0xC9) as (
            bootstrap,
            policy,
            binding,
        ):
            session = bootstrap.start(
                policy=policy,
                binding=binding,
                max_ready_wait_ns=READY_WAIT_NS,
            )
            exact_pid = bootstrap._owner._pid
            real_kill = os.kill
            kill_calls: list[tuple[int, int]] = []

            def kill_then_interrupt(pid: int, sig: int):
                kill_calls.append((pid, sig))
                real_kill(pid, sig)
                raise KeyboardInterrupt

            with patch.object(
                supervisor.os,
                "kill",
                side_effect=kill_then_interrupt,
            ):
                self.assertFalse(
                    session.shutdown(max_wait_ns=1_000_000_000)
                )
            owner_metadata = bootstrap._owner.safe_metadata()
            self.assertEqual(owner_metadata["parent_endpoint_count"], 0)
            self.assertEqual(owner_metadata["child_endpoint_count"], 0)
            self.assertTrue(
                session.shutdown(max_wait_ns=CLEANUP_WAIT_NS)
            )
            self.assertEqual(
                kill_calls,
                [(exact_pid, supervisor.signal.SIGKILL)],
            )
            self.assertTrue(bootstrap._owner.locally_terminal())
            self.assertFalse(session.safe_metadata()["recovery_refs_held"])

    def test_uncertain_spawn_closes_known_fds_without_pid_actions(self):
        with _case(prefix=0xCA) as (_, policy, binding):
            del policy
            acquisition = supervisor._BootstrapAcquisitionOwner(
                _authority=supervisor._ACQUISITION_AUTHORITY
            )
            channels = supervisor._create_bootstrap_channels(acquisition)
            owner = acquisition.build_process_owner(
                binding=binding,
                _authority=supervisor._ACQUISITION_AUTHORITY,
            )
            owner._spawn_state = supervisor._SpawnState.UNCERTAIN
            owner._spawn_pid_cell.value = 42_424
            with (
                patch.object(
                    supervisor.os,
                    "kill",
                    side_effect=AssertionError("uncertain PID killed"),
                ),
                patch.object(
                    supervisor.os,
                    "waitpid",
                    side_effect=AssertionError("uncertain PID waited"),
                ),
            ):
                with self.assertRaises(
                    supervisor._BootstrapBoundaryFailure
                ):
                    owner.shutdown(max_wait_ns=100_000_000)
            for fd in channels.all_fds():
                _assert_fd_closed(self, fd)
            metadata = owner.safe_metadata()
            self.assertEqual(metadata["parent_endpoint_count"], 0)
            self.assertEqual(metadata["child_endpoint_count"], 0)
            self.assertFalse(metadata["locally_terminal"])

    def test_partial_session_publication_poison_fanout_precedes_cleanup(self):
        captured: list[object] = []

        def publish_session_then_interrupt(
            instance,
            *,
            broker_ports,
            session,
        ):
            object.__setattr__(instance, "_session", session)
            captured.extend((broker_ports, session))
            raise KeyboardInterrupt

        with _case(prefix=0xCB) as (bootstrap, policy, binding):
            with patch.object(
                supervisor._DarwinResolverSupervisorBootstrap,
                "_commit_ready",
                new=publish_session_then_interrupt,
            ):
                with self.assertRaises(EndpointPolicyError):
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
            self.assertEqual(len(captured), 2)
            broker_ports, session = captured
            self.assertEqual(
                bootstrap.safe_metadata()["state"],
                "global_poisoned",
            )
            self.assertIsNotNone(
                broker_ports.ledger.safe_metadata()["global_poison_reason"]
            )
            self.assertTrue(
                broker_ports.parent_session.safe_metadata()["poisoned"]
            )
            self.assertTrue(session.safe_metadata()["poison_fanout_complete"])
            self.assertTrue(bootstrap.cleanup(max_wait_ns=CLEANUP_WAIT_NS))

    def test_prepared_publication_interrupt_finishes_one_shot_cleanly(self):
        with _case(prefix=0xCC) as (bootstrap, policy, binding):
            original_transition = type(bootstrap._state_ledger).transition
            injection_count = 0

            def transition(instance, state, *, _authority):
                nonlocal injection_count
                result = original_transition(
                    instance,
                    state,
                    _authority=_authority,
                )
                if (
                    instance is bootstrap._state_ledger
                    and state is supervisor._BootstrapState.PREPARED
                    and injection_count == 0
                ):
                    injection_count += 1
                    raise KeyboardInterrupt
                return result

            with patch.object(
                type(bootstrap._state_ledger),
                "transition",
                new=transition,
            ):
                with self.assertRaises(EndpointPolicyError) as raised:
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
                _assert_safe_error(self, raised.exception)
            self.assertEqual(injection_count, 1)
            metadata = bootstrap.safe_metadata()
            self.assertTrue(metadata["attempted"])
            self.assertEqual(metadata["state"], "failed_clean")
            self.assertFalse(metadata["recovery_refs_held"])
            with self.assertRaises(EndpointPolicyError):
                bootstrap.start(
                    policy=policy,
                    binding=binding,
                    max_ready_wait_ns=READY_WAIT_NS,
                )

    def test_same_thread_reentry_between_prepared_and_attempt_is_rejected(self):
        with _case(prefix=0xCD) as (bootstrap, policy, binding):
            original_transition = type(bootstrap._state_ledger).transition
            original_channels = supervisor._create_bootstrap_channels
            nested_errors: list[EndpointPolicyError] = []
            channel_count = 0

            def transition(instance, state, *, _authority):
                result = original_transition(
                    instance,
                    state,
                    _authority=_authority,
                )
                if (
                    instance is bootstrap._state_ledger
                    and state is supervisor._BootstrapState.PREPARED
                    and not nested_errors
                ):
                    try:
                        bootstrap.start(
                            policy=policy,
                            binding=binding,
                            max_ready_wait_ns=READY_WAIT_NS,
                        )
                    except EndpointPolicyError as error:
                        nested_errors.append(error)
                return result

            def create_channels(acquisition):
                nonlocal channel_count
                channel_count += 1
                return original_channels(acquisition)

            with (
                patch.object(
                    type(bootstrap._state_ledger),
                    "transition",
                    new=transition,
                ),
                patch.object(
                    supervisor,
                    "_create_bootstrap_channels",
                    side_effect=create_channels,
                ),
            ):
                session = bootstrap.start(
                    policy=policy,
                    binding=binding,
                    max_ready_wait_ns=READY_WAIT_NS,
                )
            self.assertEqual(len(nested_errors), 1)
            _assert_safe_error(self, nested_errors[0])
            self.assertEqual(channel_count, 1)
            self.assertTrue(session.shutdown(max_wait_ns=CLEANUP_WAIT_NS))
            self.assertFalse(bootstrap.safe_metadata()["recovery_refs_held"])

    def test_busy_error_inside_attempt_always_runs_owner_recovery(self):
        original_attest = supervisor._attest_local_probe
        captured_lease: list[int] = []

        def attest_then_reenter(policy, acquisition):
            lease = original_attest(policy, acquisition)
            captured_lease.append(lease.fd)
            bootstrap.start(
                policy=policy,
                binding=binding,
                max_ready_wait_ns=READY_WAIT_NS,
            )

        with _case(prefix=0xCE) as (bootstrap, policy, binding):
            with patch.object(
                supervisor,
                "_attest_local_probe",
                side_effect=attest_then_reenter,
            ):
                with self.assertRaises(EndpointPolicyError) as raised:
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
                _assert_safe_error(self, raised.exception)
            _assert_fd_closed(self, captured_lease[0])
            metadata = bootstrap.safe_metadata()
            self.assertEqual(metadata["state"], "failed_clean")
            self.assertFalse(metadata["recovery_refs_held"])

        original_spawn = supervisor._spawn_local_probe
        captured_channels: list[object] = []
        original_channels = supervisor._create_bootstrap_channels

        def create_channels(acquisition):
            channels = original_channels(acquisition)
            captured_channels.append(channels)
            return channels

        def spawn_then_reenter(**kwargs):
            original_spawn(**kwargs)
            bootstrap.start(
                policy=policy,
                binding=binding,
                max_ready_wait_ns=READY_WAIT_NS,
            )

        with _case(prefix=0xCF) as (bootstrap, policy, binding):
            with (
                patch.object(
                    supervisor,
                    "_create_bootstrap_channels",
                    side_effect=create_channels,
                ),
                patch.object(
                    supervisor,
                    "_spawn_local_probe",
                    side_effect=spawn_then_reenter,
                ),
            ):
                with self.assertRaises(EndpointPolicyError) as raised:
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
                _assert_safe_error(self, raised.exception)
            metadata = bootstrap.safe_metadata()
            self.assertEqual(metadata["state"], "global_poisoned")
            self.assertIsNotNone(metadata["global_poison_reason"])
            self.assertFalse(metadata["recovery_refs_held"])
            for fd in captured_channels[0].all_fds():
                _assert_fd_closed(self, fd)

    def test_commit_then_interrupt_recovers_only_the_same_session(self):
        original_commit = supervisor._DarwinResolverSupervisorBootstrap._commit_ready
        original_spawn = supervisor._spawn_local_probe
        spawn_count = 0

        def commit_then_interrupt(instance, **kwargs):
            original_commit(instance, **kwargs)
            raise KeyboardInterrupt

        def spawn(**kwargs):
            nonlocal spawn_count
            spawn_count += 1
            return original_spawn(**kwargs)

        with _case(prefix=0xC4) as (bootstrap, policy, binding):
            with (
                patch.object(
                    supervisor._DarwinResolverSupervisorBootstrap,
                    "_commit_ready",
                    new=commit_then_interrupt,
                ),
                patch.object(
                    supervisor,
                    "_spawn_local_probe",
                    side_effect=spawn,
                ),
            ):
                with self.assertRaises(EndpointPolicyError) as raised:
                    bootstrap.start(
                        policy=policy,
                        binding=binding,
                        max_ready_wait_ns=READY_WAIT_NS,
                    )
                _assert_safe_error(self, raised.exception)
            recovered = bootstrap.start(
                policy=policy,
                binding=binding,
                max_ready_wait_ns=READY_WAIT_NS,
            )
            self.assertIs(recovered, bootstrap._session)
            self.assertEqual(spawn_count, 1)
            self.assertTrue(recovered.shutdown(max_wait_ns=CLEANUP_WAIT_NS))

    def test_retained_wait_status_finishes_without_replaying_waitpid(self):
        with _case(prefix=0xC6) as (_, policy, binding):
            del policy
            acquisition = supervisor._BootstrapAcquisitionOwner(
                _authority=supervisor._ACQUISITION_AUTHORITY
            )
            channels = supervisor._create_bootstrap_channels(acquisition)
            owner = acquisition.build_process_owner(
                binding=binding,
                _authority=supervisor._ACQUISITION_AUTHORITY,
            )
            owner._spawn_state = supervisor._SpawnState.SUCCEEDED
            owner._pid = 42_424
            owner._spawn_pid_cell.value = 42_424
            owner._wait_state = supervisor._WaitState.IN_FLIGHT
            owner._wait_status = 0
            with patch.object(
                supervisor.os,
                "waitpid",
                side_effect=AssertionError("waitpid replayed"),
            ):
                with owner._lock:
                    self.assertEqual(owner._wait_nohang_locked(), 0)
                    self.assertTrue(owner._finish_terminal_locked())
            self.assertTrue(owner.locally_terminal())
            for fd in channels.all_fds():
                _assert_fd_closed(self, fd)

    def test_process_owner_aggregates_close_fault_without_replay(self):
        with _case(prefix=0xC7) as (_, policy, binding):
            del policy
            acquisition = supervisor._BootstrapAcquisitionOwner(
                _authority=supervisor._ACQUISITION_AUTHORITY
            )
            channels = supervisor._create_bootstrap_channels(acquisition)
            owner = acquisition.build_process_owner(
                binding=binding,
                _authority=supervisor._ACQUISITION_AUTHORITY,
            )
            real_close = os.close
            faulted = False

            def close_then_interrupt(fd: int):
                nonlocal faulted
                real_close(fd)
                if not faulted:
                    faulted = True
                    raise KeyboardInterrupt

            with patch.object(
                supervisor.os,
                "close",
                side_effect=close_then_interrupt,
            ):
                with self.assertRaises(
                    supervisor._BootstrapBoundaryFailure
                ):
                    owner.close_all_without_child()
            for fd in channels.all_fds():
                _assert_fd_closed(self, fd)
            self.assertFalse(owner.locally_terminal())
            self.assertTrue(owner.safe_metadata()["locally_terminal"] is False)

    def test_partial_poison_fanout_converges_before_cleanup_success(self):
        with _case(prefix=0xC5) as (bootstrap, policy, binding):
            session = bootstrap.start(
                policy=policy,
                binding=binding,
                max_ready_wait_ns=READY_WAIT_NS,
            )
            port_type = type(session._broker_ports.cleanup)
            original_poison = port_type.poison_epoch
            calls = 0

            def fail_once(port, *, reason):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise KeyboardInterrupt
                return original_poison(port, reason=reason)

            with patch.object(port_type, "poison_epoch", new=fail_once):
                with session._lock:
                    with self.assertRaises(
                        supervisor._BootstrapBoundaryFailure
                    ):
                        session._fanout_poison_locked(
                            supervisor._PoisonReason.LIVENESS_LOST
                        )
            self.assertEqual(
                bootstrap.safe_metadata()["state"],
                "global_poisoned",
            )
            self.assertFalse(session.safe_metadata()["poison_fanout_complete"])
            self.assertTrue(session.shutdown(max_wait_ns=CLEANUP_WAIT_NS))
            metadata = session.safe_metadata()
            self.assertTrue(metadata["poison_fanout_complete"])
            self.assertEqual(
                metadata["broker_global_poison_reason"],
                "liveness_lost",
            )
            self.assertFalse(metadata["recovery_refs_held"])

    def test_production_launcher_remains_fail_closed_and_unwired(self):
        launcher = ResolverHelperLauncher.production(
            executable="/nonexistent/snapquiz-resolver"
        )
        self.assertIs(type(launcher._spawner), FailClosedProductionHelperSpawner)
        resolver_source = (
            Path(supervisor.__file__).with_name("resolver.py").read_text(
                encoding="utf-8"
            )
        )
        self.assertNotIn("_darwin_resolver_supervisor", resolver_source)


if __name__ == "__main__":
    unittest.main()
