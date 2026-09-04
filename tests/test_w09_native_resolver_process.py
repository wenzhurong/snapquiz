"""Darwin-only offline acceptance tests for the strict resolver process edge."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import errno
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
from threading import Timer
import time
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import CancelledError, ConfigError, EndpointPolicyError
from snapquiz.runtime.context import CancellationReason
from snapquiz.transport.resolver import (
    COMPLETE,
    MAX_START_FRAME_BYTES,
    PENDING,
    READY_FRAME,
    FailClosedProductionHelperSpawner,
    ResolverHelperLauncher,
    ResolverHelperSpawnRequest,
    _RESOLVER_LIFECYCLE_AUTHORITY,
    encode_start_frame,
)
from tests.test_w09_resolver_lifecycle import (
    _STOP_AUTHORITY,
    _make_stop_authority,
)


MODULE_NAME = "snapquiz.transport._darwin_resolver_process"
FIXTURE = Path(__file__).with_name("fixtures") / "resolver_process_probe.py"
POLL_WAIT_NS = 25_000_000
POLL_DEADLINE_NS = 3_000_000_000
START_FRAME = encode_start_frame(
    hostname=".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61)),
    port=65_535,
    network_policy_ref="r" * 256,
    network_policy_digest=Digest256("1" * 64),
    attempt_permit_id=UUID("81000000-0000-0000-0000-000000000001"),
    attempt_permit_digest=Digest256("2" * 64),
    transport_claim_id=UUID("81000000-0000-0000-0000-000000000002"),
    terminal_guard_id=UUID("81000000-0000-0000-0000-000000000003"),
    terminal_guard_digest=Digest256("3" * 64),
    dns_start_id=UUID("81000000-0000-0000-0000-000000000004"),
)
PARENT_SECRET = "synthetic-parent-secret-must-not-cross-exec"


def _native_module():
    return importlib.import_module(MODULE_NAME)


@contextmanager
def _probe_executable(mode: str = "success"):
    with tempfile.TemporaryDirectory(prefix="snapquiz-resolver-probe-") as root:
        selected = Path(root) / f"resolver_process_probe__{mode}.py"
        shutil.copy2(FIXTURE, selected)
        selected.chmod(0o700)
        yield str(selected)


def _launch_guard(executable: str):
    spawner = _native_module().DarwinResolverProcessSpawner()
    launcher = ResolverHelperLauncher(spawner, executable=executable)
    capability = launcher._reserve_lifecycle_capability(
        reservation_owner=object(),
        stop_authority=_STOP_AUTHORITY,
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    )
    guard = launcher._launch_ready(
        capability=capability,
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    )
    if not launcher._consume_ready_publication(
        capability,
        guard,
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    ):
        guard.cleanup()
        raise AssertionError("READY publication was not consumed")
    kernel = guard._ledger._kernel
    if kernel is None:
        guard.cleanup()
        raise AssertionError("published native kernel is missing")
    return launcher, guard, kernel


def _poll_value(call, *, label: str):
    deadline_ns = time.monotonic_ns() + POLL_DEADLINE_NS
    while time.monotonic_ns() < deadline_ns:
        selected = call()
        if selected is not PENDING:
            return selected
    raise AssertionError(f"{label} remained PENDING")


def _write_frame(kernel, frame: bytes = START_FRAME) -> None:
    selected = _poll_value(
        lambda: kernel.write_stdin(frame, max_wait_ns=POLL_WAIT_NS),
        label="write_stdin",
    )
    if selected is not COMPLETE:
        raise AssertionError("write_stdin returned an invalid completion value")


def _read_chunk(kernel, maximum: int = 4_096) -> bytes:
    selected = _poll_value(
        lambda: kernel.read_stdout(maximum, max_wait_ns=POLL_WAIT_NS),
        label="read_stdout",
    )
    if type(selected) is not bytes:
        raise AssertionError("read_stdout returned a non-bytes value")
    return selected


def _reap(kernel) -> int:
    selected = _poll_value(
        lambda: kernel.reap(max_wait_ns=POLL_WAIT_NS),
        label="reap",
    )
    if type(selected) is not int:
        raise AssertionError("reap returned a non-int status")
    return selected


def _close_pipes(kernel) -> None:
    selected = _poll_value(
        lambda: kernel.close_pipes(max_wait_ns=POLL_WAIT_NS),
        label="close_pipes",
    )
    if selected is not COMPLETE:
        raise AssertionError("close_pipes returned an invalid completion value")


def _parent_fds(kernel) -> tuple[int, int, int]:
    fds = (kernel._stdin_fd, kernel._stdout_fd, kernel._stderr_fd)
    if any(type(fd) is not int or fd < 3 for fd in fds):
        raise AssertionError("native kernel has invalid parent descriptors")
    return fds


def _assert_fds_closed(test: unittest.TestCase, fds: tuple[int, ...]) -> None:
    for fd in fds:
        with test.assertRaises(OSError) as raised:
            os.fstat(fd)
        test.assertEqual(raised.exception.errno, errno.EBADF)


def _construct_process_channels(module):
    construction = module._ProcessChannelConstructionSlot(
        _authority=module._CHANNEL_CONSTRUCTION_AUTHORITY,
    )
    result = module._create_process_channels(construction)
    if result is not None:
        raise AssertionError("process channel factory returned a resource")
    return construction, construction.channels()


class DarwinResolverProcessTests(unittest.TestCase):
    def test_import_and_construct_do_not_create_processes_or_descriptors(self):
        previous = sys.modules.pop(MODULE_NAME, None)
        del previous

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("import/construct touched a process primitive")

        try:
            with ExitStack() as stack:
                for name in (
                    "fork",
                    "pipe",
                    "pipe2",
                    "posix_spawn",
                    "posix_spawnp",
                ):
                    if hasattr(os, name):
                        stack.enter_context(
                            patch.object(os, name, side_effect=forbidden)
                        )
                stack.enter_context(
                    patch.object(subprocess, "Popen", side_effect=forbidden)
                )
                stack.enter_context(
                    patch.object(socket, "socketpair", side_effect=forbidden)
                )
                stack.enter_context(
                    patch.object(ctypes, "CDLL", side_effect=forbidden)
                )
                module = importlib.import_module(MODULE_NAME)
                spawner = module.DarwinResolverProcessSpawner()
                self.assertIs(
                    type(spawner),
                    module.DarwinResolverProcessSpawner,
                )
        finally:
            # Do not retain a module-level alias to a primitive patched above.
            sys.modules.pop(MODULE_NAME, None)
            importlib.import_module(MODULE_NAME)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_real_process_success_has_fixed_environment_and_closed_fds(self):
        inherited_fd = os.open(FIXTURE, os.O_RDONLY)
        high_inherited_fd = None
        try:
            os.set_inheritable(inherited_fd, True)
            soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            high_floor = (
                4_096 if soft_limit > 4_096 else max(3, soft_limit // 2)
            )
            high_inherited_fd = fcntl.fcntl(
                inherited_fd,
                fcntl.F_DUPFD,
                high_floor,
            )
            self.assertLess(high_inherited_fd, 8_192)
            os.set_inheritable(high_inherited_fd, True)
            with _probe_executable() as executable, patch.dict(
                os.environ,
                {"SNAPQUIZ_RESOLVER_PROCESS_PARENT_CANARY": PARENT_SECRET},
            ):
                launcher, guard, kernel = _launch_guard(executable)
                self.assertEqual(
                    launcher.safe_metadata()["environment"],
                    (("LANG", "C"), ("LC_ALL", "C")),
                )
                self.assertFalse(launcher.safe_metadata()["shell"])
                self.assertTrue(launcher.safe_metadata()["close_fds"])
                parent_fds = _parent_fds(kernel)
                try:
                    with patch.object(
                        os,
                        "write",
                        side_effect=OSError(errno.ENOBUFS, "synthetic"),
                    ):
                        self.assertIs(
                            kernel.write_stdin(
                                START_FRAME,
                                max_wait_ns=POLL_WAIT_NS,
                            ),
                            PENDING,
                        )
                    _write_frame(kernel)

                    def forbidden_replay(*args, **kwargs):
                        del args, kwargs
                        raise AssertionError("completed START was replayed")

                    with patch.object(os, "write", side_effect=forbidden_replay):
                        self.assertIs(
                            kernel.write_stdin(
                                START_FRAME,
                                max_wait_ns=POLL_WAIT_NS,
                            ),
                            COMPLETE,
                        )
                        with self.assertRaises(EndpointPolicyError):
                            kernel.write_stdin(
                                START_FRAME[:-1] + b" ",
                                max_wait_ns=POLL_WAIT_NS,
                            )
                    frame = _read_chunk(kernel)
                    self.assertTrue(frame.endswith(b"\n"))
                    self.assertNotIn(PARENT_SECRET.encode("ascii"), frame)
                    payload = json.loads(frame)
                    self.assertEqual(payload["kind"], "RESULT")
                    self.assertTrue(payload["environment_allowlist_only"])
                    self.assertTrue(payload["parent_environment_canary_absent"])
                    self.assertEqual(payload["extra_fd_count"], 0)
                    self.assertTrue(payload["stdin_is_unix_datagram"])
                    self.assertTrue(payload["stdin_reverse_write_blocked"])
                    self.assertGreater(len(START_FRAME), 512)
                    self.assertLessEqual(len(START_FRAME), MAX_START_FRAME_BYTES)
                    self.assertEqual(
                        payload["start_frame_byte_size"],
                        len(START_FRAME),
                    )
                    self.assertEqual(
                        payload["start_frame_sha256"],
                        hashlib.sha256(START_FRAME).hexdigest(),
                    )
                    self.assertEqual(_read_chunk(kernel, 1), b"")
                    self.assertEqual(_reap(kernel), 0)
                    _close_pipes(kernel)
                    _assert_fds_closed(self, parent_fds)
                finally:
                    guard.cleanup()
                self.assertEqual(launcher._ready_publications, {})
                self.assertEqual(launcher._lifecycle_recovery, {})
        finally:
            if high_inherited_fd is not None:
                os.close(high_inherited_fd)
            os.close(inherited_fd)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_cancel_cleanup_terminates_reaps_and_closes_a_blocked_result(self):
        with _probe_executable("block_result") as executable:
            launcher, guard, kernel = _launch_guard(executable)
            parent_fds = _parent_fds(kernel)
            cleaned = False
            try:
                _write_frame(kernel)
                self.assertIs(
                    kernel.read_stdout(1, max_wait_ns=1_000_000),
                    PENDING,
                )
            finally:
                cleaned = guard.cleanup()

            self.assertTrue(cleaned)
            _assert_fds_closed(self, parent_fds)
            metadata = guard.safe_metadata()
            self.assertEqual(metadata["state"], "terminal")
            self.assertTrue(metadata["child_reaped"])
            self.assertTrue(metadata["helper_pipes_closed"])
            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})

    def test_production_launcher_remains_fail_closed_and_uses_no_native_edge(self):
        launcher = ResolverHelperLauncher.production(
            executable="/opt/snapquiz/libexec/resolver-helper",
        )
        self.assertIs(type(launcher._spawner), FailClosedProductionHelperSpawner)
        capability = launcher._reserve_lifecycle_capability(
            reservation_owner=object(),
            stop_authority=_STOP_AUTHORITY,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("production touched the experimental native edge")

        with patch.object(socket, "socketpair", side_effect=forbidden), patch.object(
            ctypes,
            "CDLL",
            side_effect=forbidden,
        ):
            with self.assertRaises(ConfigError):
                launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_channel_factory_return_event_is_exactly_cleaned_without_replay(self):
        module = _native_module()
        spawner = module.DarwinResolverProcessSpawner()
        observed_slots = []
        observed_fds = []
        close_calls = []
        socketpair_calls = 0
        pipe_calls = 0
        interrupted = False
        original_factory = module._create_process_channels
        original_socketpair = socket.socketpair
        original_pipe = os.pipe
        original_close = os.close

        def checked_factory(construction):
            self.assertIs(spawner._channel_construction, construction)
            observed_slots.append(construction)
            return original_factory(construction)

        def counted_socketpair(*args, **kwargs):
            nonlocal socketpair_calls
            socketpair_calls += 1
            return original_socketpair(*args, **kwargs)

        def counted_pipe(*args, **kwargs):
            nonlocal pipe_calls
            pipe_calls += 1
            return original_pipe(*args, **kwargs)

        def counted_close(fd):
            close_calls.append(fd)
            return original_close(fd)

        target_code = original_factory.__code__

        def interrupt_factory_return(frame, event, argument):
            nonlocal interrupted
            if frame.f_code is target_code and event == "return" and not interrupted:
                interrupted = True
                channels = frame.f_locals.get("channels")
                self.assertIs(type(channels), module._ProcessChannels)
                observed_fds.extend(channels.all_fds())
                self.assertIsNone(argument)
                raise KeyboardInterrupt("synthetic channel factory return event")
            return interrupt_factory_return

        with _probe_executable() as executable:
            launcher = ResolverHelperLauncher(spawner, executable=executable)
            capability = launcher._reserve_lifecycle_capability(
                reservation_owner=object(),
                stop_authority=_STOP_AUTHORITY,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            previous_trace = sys.gettrace()
            try:
                with patch.object(
                    module,
                    "_create_process_channels",
                    new=checked_factory,
                ), patch.object(
                    socket,
                    "socketpair",
                    side_effect=counted_socketpair,
                ), patch.object(
                    os,
                    "pipe",
                    side_effect=counted_pipe,
                ), patch.object(
                    os,
                    "close",
                    side_effect=counted_close,
                ):
                    sys.settrace(interrupt_factory_return)
                    with self.assertRaises(EndpointPolicyError):
                        launcher._launch_ready(
                            capability=capability,
                            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                        )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(interrupted)
            self.assertEqual(len(observed_slots), 1)
            self.assertEqual(len(observed_fds), 6)
            self.assertEqual(socketpair_calls, 1)
            self.assertEqual(pipe_calls, 2)
            self.assertEqual(
                {fd: close_calls.count(fd) for fd in observed_fds},
                {fd: 1 for fd in observed_fds},
            )
            _assert_fds_closed(self, tuple(observed_fds))
            construction = observed_slots[0]
            self.assertIs(spawner._channel_construction, construction)
            self.assertTrue(construction.is_terminal())
            self.assertFalse(construction.has_retained_channels())
            self.assertIsNone(construction._channels)
            self.assertEqual(construction._remaining_fds, ())
            self.assertIsNone(construction._uncertain_fd)
            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})

            replay_launcher = ResolverHelperLauncher(spawner, executable=executable)
            replay_capability = replay_launcher._reserve_lifecycle_capability(
                reservation_owner=object(),
                stop_authority=_STOP_AUTHORITY,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )

            def forbidden_acquisition(*args, **kwargs):
                del args, kwargs
                raise AssertionError("aborted channel construction was replayed")

            with patch.object(
                socket,
                "socketpair",
                side_effect=forbidden_acquisition,
            ), patch.object(
                os,
                "pipe",
                side_effect=forbidden_acquisition,
            ):
                with self.assertRaises(EndpointPolicyError):
                    replay_launcher._launch_ready(
                        capability=replay_capability,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )
            self.assertIs(spawner._channel_construction, construction)
            self.assertTrue(construction.is_terminal())
            self.assertFalse(construction.has_retained_channels())
            self.assertEqual(replay_launcher._ready_publications, {})
            self.assertEqual(replay_launcher._lifecycle_recovery, {})

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_runtime_cancel_terminates_a_helper_blocked_before_ready(self):
        runtime, _, _, stop_authority = _make_stop_authority()
        with _probe_executable("block_ready") as executable:
            launcher = ResolverHelperLauncher(
                _native_module().DarwinResolverProcessSpawner(),
                executable=executable,
            )
            capability = launcher._reserve_lifecycle_capability(
                reservation_owner=object(),
                stop_authority=stop_authority,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            cancel = Timer(
                0.1,
                lambda: runtime.cancellation_source.cancel(
                    reason=CancellationReason.USER_REQUEST
                ),
            )
            cancel.daemon = True
            cancel.start()
            try:
                with self.assertRaises(CancelledError):
                    launcher._launch_ready(
                        capability=capability,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )
            finally:
                cancel.cancel()
                cancel.join(timeout=1)

            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_spawn_pid_cell_survives_a_post_return_bind_failure(self):
        module = _native_module()
        spawner = module.DarwinResolverProcessSpawner()
        observed_kernels = []
        observed_fds = []

        def fail_after_spawn(kernel):
            self.assertGreater(kernel._spawn_pid_cell.value, 0)
            observed_kernels.append(kernel)
            observed_fds.extend(_parent_fds(kernel) + tuple(kernel._child_fds))
            raise KeyboardInterrupt

        with _probe_executable("block_ready") as executable:
            launcher = ResolverHelperLauncher(spawner, executable=executable)
            capability = launcher._reserve_lifecycle_capability(
                reservation_owner=object(),
                stop_authority=_STOP_AUTHORITY,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            with patch.object(
                module._DarwinResolverProcessKernel,
                "_bind_spawned_pid_from_cell",
                new=fail_after_spawn,
            ):
                with self.assertRaises(EndpointPolicyError):
                    launcher._launch_ready(
                        capability=capability,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )

        deadline_ns = time.monotonic_ns() + POLL_DEADLINE_NS
        while spawner._recovery is not None and time.monotonic_ns() < deadline_ns:
            spawner._service_recovery(max_wait_ns=POLL_WAIT_NS)
        self.assertEqual(len(observed_kernels), 1)
        kernel = observed_kernels[0]
        self.assertIsNone(spawner._recovery)
        self.assertTrue(kernel._locally_terminal())
        self.assertEqual(kernel._spawn_pid_cell.value, 0)
        self.assertEqual(len(observed_fds), 6)
        _assert_fds_closed(self, tuple(observed_fds))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_failed_spawn_ignores_an_undefined_positive_pid_cell(self):
        module = _native_module()
        construction, channels = _construct_process_channels(module)
        observed_fds = channels.all_fds()
        request = ResolverHelperSpawnRequest(executable="/usr/bin/true")
        frozen = module._freeze_spawn_request(request)
        kernel = module._DarwinResolverProcessKernel(
            pid=None,
            channels=channels,
            frozen=frozen,
            _authority=module._KERNEL_CONSTRUCTION_AUTHORITY,
        )
        construction.transfer_to_kernel(channels, kernel)
        foreign_pid = os.getpid()

        def successful_primitive(*args, **kwargs):
            del args, kwargs
            return 0

        def failed_spawn(pid_pointer, *args, **kwargs):
            del args, kwargs
            ctypes.cast(
                pid_pointer,
                ctypes.POINTER(ctypes.c_int),
            ).contents.value = foreign_pid
            return errno.ENOENT

        spawn_functions = (successful_primitive,) * 12 + (failed_spawn,)
        try:
            with patch.object(
                module.ctypes,
                "CDLL",
                return_value=object(),
            ), patch.object(
                module,
                "_configure_libc_spawn_functions",
                return_value=spawn_functions,
            ):
                with self.assertRaises(module._NativeBoundaryFailure):
                    module._native_posix_spawn(frozen, channels, kernel)

            self.assertEqual(kernel._spawn_call_state, module._SPAWN_FAILED)
            self.assertEqual(kernel._spawn_pid_cell.value, 0)
            spawner = module.DarwinResolverProcessSpawner()
            spawner._recovery = kernel

            def forbidden_process_action(*args, **kwargs):
                del args, kwargs
                raise AssertionError("failed spawn used an undefined PID")

            with patch.object(
                os,
                "kill",
                side_effect=forbidden_process_action,
            ), patch.object(
                os,
                "waitpid",
                side_effect=forbidden_process_action,
            ):
                self.assertTrue(
                    spawner._service_recovery(max_wait_ns=POLL_WAIT_NS)
                )
            self.assertIsNone(spawner._recovery)
            self.assertTrue(kernel._locally_terminal())
            _assert_fds_closed(self, observed_fds)
        finally:
            module._close_raw_fds(observed_fds)

        for scenario in (
            "unattested_positive_pid",
            "success_without_positive_pid",
            "failed_before_cell_clear",
        ):
            with self.subTest(scenario=scenario):
                construction, channels = _construct_process_channels(module)
                observed_fds = channels.all_fds()
                kernel = module._DarwinResolverProcessKernel(
                    pid=None,
                    channels=channels,
                    frozen=frozen,
                    _authority=module._KERNEL_CONSTRUCTION_AUTHORITY,
                )
                construction.transfer_to_kernel(channels, kernel)
                spawner = module.DarwinResolverProcessSpawner()
                try:
                    kernel._begin_spawn_call()
                    if scenario == "unattested_positive_pid":
                        kernel._spawn_pid_cell.value = foreign_pid
                    elif scenario == "success_without_positive_pid":
                        with self.assertRaises(module._NativeBoundaryFailure):
                            kernel._record_successful_spawn_call()
                    else:
                        kernel._spawn_pid_cell.value = foreign_pid
                        # Model an async exception after the authoritative
                        # failure state landed but before the undefined output
                        # cell was cleared.
                        kernel._spawn_call_state = module._SPAWN_FAILED
                    spawner._recovery = kernel

                    def forbidden_unattested_action(*args, **kwargs):
                        del args, kwargs
                        raise AssertionError(
                            "unattested PID reached kill/waitpid"
                        )

                    with patch.object(
                        os,
                        "kill",
                        side_effect=forbidden_unattested_action,
                    ), patch.object(
                        os,
                        "waitpid",
                        side_effect=forbidden_unattested_action,
                    ):
                        self.assertTrue(
                            spawner._service_recovery(
                                max_wait_ns=POLL_WAIT_NS
                            )
                        )
                        if scenario == "failed_before_cell_clear":
                            self.assertIsNone(spawner._recovery)
                        else:
                            for _ in range(2):
                                self.assertTrue(
                                    spawner._service_recovery(
                                        max_wait_ns=POLL_WAIT_NS
                                    )
                                )
                            self.assertIs(spawner._recovery, kernel)
                    if scenario == "failed_before_cell_clear":
                        self.assertEqual(kernel._spawn_pid_cell.value, 0)
                        self.assertTrue(kernel._locally_terminal())
                        _assert_fds_closed(self, observed_fds)
                    else:
                        self.assertEqual(
                            kernel._spawn_call_state,
                            module._SPAWN_UNCERTAIN,
                        )
                        self.assertFalse(kernel._locally_terminal())
                finally:
                    spawner._recovery = None
                    module._close_raw_fds(observed_fds)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_reap_fast_path_repairs_interrupted_terminal_bookkeeping(self):
        module = _native_module()
        original_finish = (
            module._DarwinResolverProcessKernel._finish_reap_bookkeeping_locked
        )
        for completed_steps in range(4):
            with self.subTest(completed_steps=completed_steps):
                construction, channels = _construct_process_channels(module)
                observed_fds = channels.all_fds()
                frozen = module._freeze_spawn_request(
                    ResolverHelperSpawnRequest(executable="/usr/bin/true")
                )
                kernel = module._DarwinResolverProcessKernel(
                    pid=42_424,
                    channels=channels,
                    frozen=frozen,
                    _authority=module._KERNEL_CONSTRUCTION_AUTHORITY,
                )
                construction.transfer_to_kernel(channels, kernel)
                kernel._waited_status = 0
                kernel._reap_status = 0
                interrupted = False

                def interrupt_once(selected_kernel):
                    nonlocal interrupted
                    if not interrupted:
                        interrupted = True
                        if completed_steps >= 1:
                            selected_kernel._waited_status = None
                        if completed_steps >= 2:
                            selected_kernel._pid = None
                        if completed_steps >= 3:
                            selected_kernel._spawn_pid_cell.value = 0
                        raise KeyboardInterrupt
                    return original_finish(selected_kernel)

                try:
                    with patch.object(
                        module._DarwinResolverProcessKernel,
                        "_finish_reap_bookkeeping_locked",
                        new=interrupt_once,
                    ):
                        with self.assertRaises(KeyboardInterrupt):
                            kernel.reap(max_wait_ns=POLL_WAIT_NS)
                        self.assertEqual(
                            kernel.reap(max_wait_ns=POLL_WAIT_NS),
                            0,
                        )
                    kernel._close_child_fds_after_spawn()
                    _close_pipes(kernel)
                    self.assertTrue(kernel._locally_terminal())
                    _assert_fds_closed(self, observed_fds)
                finally:
                    module._close_raw_fds(observed_fds)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_unattested_waitpid_return_is_poisoned_without_replay(self):
        module = _native_module()
        construction, channels = _construct_process_channels(module)
        observed_fds = channels.all_fds()
        frozen = module._freeze_spawn_request(
            ResolverHelperSpawnRequest(executable="/usr/bin/true")
        )
        pid = os.posix_spawn(
            "/usr/bin/true",
            ("/usr/bin/true",),
            {"LANG": "C", "LC_ALL": "C"},
        )
        kernel = module._DarwinResolverProcessKernel(
            pid=pid,
            channels=channels,
            frozen=frozen,
            _authority=module._KERNEL_CONSTRUCTION_AUTHORITY,
        )
        construction.transfer_to_kernel(channels, kernel)
        original_wifexited = os.WIFEXITED
        interrupted = False

        def interrupt_after_waitpid(status):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt
            return original_wifexited(status)

        try:
            kernel._close_child_fds_after_spawn()
            deadline_ns = time.monotonic_ns() + POLL_DEADLINE_NS
            with patch.object(os, "WIFEXITED", new=interrupt_after_waitpid):
                while not interrupted and time.monotonic_ns() < deadline_ns:
                    try:
                        self.assertIs(
                            kernel.reap(max_wait_ns=POLL_WAIT_NS),
                            PENDING,
                        )
                    except KeyboardInterrupt:
                        pass
            self.assertTrue(interrupted)
            self.assertEqual(kernel._wait_call_state, module._WAIT_IN_FLIGHT)

            def forbidden_waitpid_replay(*args, **kwargs):
                del args, kwargs
                raise AssertionError("unattested waitpid result was replayed")

            with patch.object(
                os,
                "waitpid",
                side_effect=forbidden_waitpid_replay,
            ):
                with self.assertRaises(EndpointPolicyError):
                    kernel.reap(max_wait_ns=POLL_WAIT_NS)
            self.assertEqual(kernel._wait_call_state, module._WAIT_UNCERTAIN)
            self.assertTrue(kernel._reap_uncertain)
            self.assertFalse(kernel._locally_terminal())
            _close_pipes(kernel)
            _assert_fds_closed(self, observed_fds)
        finally:
            module._close_raw_fds(observed_fds)
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_nonzero_exit_status_is_preserved_for_lifecycle_cleanup(self):
        with _probe_executable("nonzero") as executable:
            launcher, guard, kernel = _launch_guard(executable)
            cleaned = False
            try:
                _write_frame(kernel)
                self.assertTrue(_read_chunk(kernel).endswith(b"\n"))
                self.assertEqual(_read_chunk(kernel, 1), b"")
            finally:
                cleaned = guard.cleanup()

            self.assertTrue(cleaned)
            metadata = guard.safe_metadata()
            self.assertEqual(metadata["child_exit_status"], 7)
            self.assertTrue(metadata["child_reaped"])
            self.assertTrue(metadata["helper_pipes_closed"])
            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_stderr_overflow_fails_closed_without_exposing_stderr(self):
        with _probe_executable("stderr_overflow") as executable:
            spawner = _native_module().DarwinResolverProcessSpawner()
            launcher = ResolverHelperLauncher(spawner, executable=executable)
            capability = launcher._reserve_lifecycle_capability(
                reservation_owner=object(),
                stop_authority=_STOP_AUTHORITY,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )

            with self.assertRaises(EndpointPolicyError) as raised:
                launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

            error = raised.exception
            self.assertEqual(error.stage, "resolver_helper")
            self.assertFalse(error.retryable)
            self.assertNotIn("EEEE", str(error))
            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})

    @unittest.skipUnless(sys.platform == "darwin", "Darwin process boundary")
    def test_late_stderr_overflow_cannot_reuse_a_cached_exit_zero(self):
        with _probe_executable("late_stderr_overflow") as executable:
            launcher, guard, kernel = _launch_guard(executable)
            try:
                _write_frame(kernel)
                self.assertTrue(_read_chunk(kernel).endswith(b"\n"))
                self.assertEqual(_read_chunk(kernel, 1), b"")
                self.assertEqual(_reap(kernel), 74)
            finally:
                cleaned = guard.cleanup()

            self.assertTrue(cleaned)
            metadata = guard.safe_metadata()
            self.assertEqual(metadata["child_exit_status"], 74)
            self.assertTrue(metadata["child_reaped"])
            self.assertTrue(metadata["helper_pipes_closed"])
            self.assertEqual(launcher._ready_publications, {})
            self.assertEqual(launcher._lifecycle_recovery, {})


if __name__ == "__main__":
    unittest.main()
