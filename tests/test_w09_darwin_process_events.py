"""Darwin-local tests for the S2b-I2 process-event watcher foundation."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import ctypes
import os
from pathlib import Path
import pickle
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_process_events as events


WAIT_NS = 2_000_000_000


def _assert_safe_error(
    test: unittest.TestCase,
    error: EndpointPolicyError,
) -> None:
    test.assertEqual(error.stage, "resolver_supervisor_process_events")
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertTrue(error.__suppress_context__)


class _WatcherPublication:
    def __init__(self) -> None:
        self.watcher = None

    def watcher_for_process(self, process_id: int):
        if self.watcher is None:
            return None
        if self.watcher.process_id != process_id:
            raise ValueError("watcher process changed")
        return self.watcher

    def publish_watcher(self, watcher) -> None:
        if self.watcher is not None:
            raise ValueError("watcher publication replay")
        self.watcher = watcher

    def owns_watcher(self, watcher) -> bool:
        return self.watcher is watcher


def _new_watcher(process_id: int):
    publication = _WatcherPublication()
    result = events._new_darwin_process_event_watcher(
        process_id,
        publication=publication,
    )
    if result is not None or publication.watcher is None:
        raise AssertionError("watcher was not published")
    watcher = publication.watcher
    publication.watcher = None
    return watcher


@contextmanager
def _blocked_python_process(action: str):
    ready_read, ready_write = os.pipe()
    gate_read, gate_write = os.pipe()
    source = r'''
import os, sys, time
ready_fd = int(sys.argv[1])
gate_fd = int(sys.argv[2])
action = sys.argv[3]
os.write(ready_fd, b"r")
os.close(ready_fd)
if os.read(gate_fd, 1) != b"g":
    raise SystemExit(70)
os.close(gate_fd)
if action == "exec":
    os.execv("/bin/sleep", ("sleep", "30"))
if action == "fork":
    child = os.fork()
    if child == 0:
        os._exit(0)
    os.waitpid(child, 0)
    time.sleep(30)
raise SystemExit(71)
'''
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            source,
            str(ready_write),
            str(gate_read),
            action,
        ],
        pass_fds=(ready_write, gate_read),
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.close(ready_write)
    os.close(gate_read)
    try:
        if os.read(ready_read, 1) != b"r":
            raise AssertionError("fixture did not reach its gate")
        yield process, gate_write
    finally:
        os.close(ready_read)
        try:
            os.close(gate_write)
        except OSError:
            pass
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def _spawn_suspended_sleep() -> tuple[int, object, object]:
    libc = ctypes.CDLL(None, use_errno=True)
    attributes = ctypes.c_void_p()
    if libc.posix_spawnattr_init(ctypes.byref(attributes)) != 0:
        raise RuntimeError("spawn attr init failed")
    libc.posix_spawnattr_setflags.argtypes = (
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_short,
    )
    libc.posix_spawnattr_setflags.restype = ctypes.c_int
    if (
        libc.posix_spawnattr_setflags(
            ctypes.byref(attributes),
            ctypes.c_short(0x0080),
        )
        != 0
    ):
        libc.posix_spawnattr_destroy(ctypes.byref(attributes))
        raise RuntimeError("spawn attr flags failed")
    argv = (ctypes.c_char_p * 3)(b"/bin/sleep", b"30", None)
    environment = (ctypes.c_char_p * 2)(b"LANG=C", None)
    pid = ctypes.c_int()
    libc.posix_spawn.argtypes = (
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_char_p),
    )
    libc.posix_spawn.restype = ctypes.c_int
    if (
        libc.posix_spawn(
            ctypes.byref(pid),
            b"/bin/sleep",
            None,
            ctypes.byref(attributes),
            argv,
            environment,
        )
        != 0
        or pid.value <= 0
    ):
        libc.posix_spawnattr_destroy(ctypes.byref(attributes))
        raise RuntimeError("suspended spawn failed")
    return pid.value, libc, attributes


@unittest.skipUnless(sys.platform == "darwin", "Darwin process events")
class DarwinProcessEventWatcherTests(unittest.TestCase):
    def test_factory_owned_immutable_nonserializable_and_safe_metadata(self):
        process = subprocess.Popen(["/bin/sleep", "30"], close_fds=True)
        watcher = None
        try:
            watcher = _new_watcher(process.pid)
            watcher.require_quiet()
            metadata = watcher.safe_metadata()
            self.assertEqual(metadata["process_id"], process.pid)
            self.assertTrue(metadata["process_event_watch_active"])
            self.assertTrue(metadata["process_event_watch_attested"])
            self.assertFalse(metadata["poisoned"])
            self.assertFalse(metadata["production_eligible"])
            self.assertFalse(metadata["transport_available"])
            self.assertEqual(metadata["event_kinds"], ())
            self.assertIs(type(watcher.registration_digest), Digest256)
            self.assertEqual(
                metadata["registration_digest"],
                str(watcher.registration_digest),
            )
            self.assertNotIn("fd", metadata)
            self.assertNotIn("fflags", metadata)
            self.assertIs(copy.copy(watcher), watcher)
            self.assertIs(copy.deepcopy(watcher), watcher)
            with self.assertRaises(TypeError):
                pickle.dumps(watcher)
            with self.assertRaises(AttributeError):
                watcher.process_id = process.pid + 1
            with self.assertRaises(TypeError):
                events._DarwinProcessEventWatcher(
                    process_id=process.pid,
                    bindings=object(),
                )
            object.__setattr__(
                watcher,
                "registration_digest",
                str(watcher.registration_digest),
            )
            with self.assertRaises(ValueError):
                watcher.validate_integrity()
        finally:
            if watcher is not None:
                watcher.close()
            process.kill()
            process.wait(timeout=5)

    def test_suspended_process_registers_quiet_then_exit_is_classified(self):
        pid, libc, attributes = _spawn_suspended_sleep()
        watcher = None
        try:
            watcher = _new_watcher(pid)
            watcher.require_quiet(max_wait_ns=10_000_000)
            self.assertEqual(os.waitpid(pid, os.WNOHANG), (0, 0))
            os.kill(pid, signal.SIGCONT)
            os.kill(pid, signal.SIGKILL)
            with self.assertRaises(EndpointPolicyError) as raised:
                watcher.require_quiet(max_wait_ns=WAIT_NS)
            _assert_safe_error(self, raised.exception)
            metadata = watcher.safe_metadata()
            self.assertEqual(metadata["event_kinds"], ("exit",))
            self.assertTrue(metadata["poisoned"])
            self.assertFalse(metadata["process_event_watch_active"])
            with patch.object(
                events,
                "_receive_process_event",
                side_effect=AssertionError("poisoned watcher polled again"),
            ):
                with self.assertRaises(EndpointPolicyError):
                    watcher.require_quiet()
            os.waitpid(pid, 0)
            pid = 0
        finally:
            if watcher is not None:
                self.assertTrue(watcher.close())
                self.assertTrue(watcher.close())
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            libc.posix_spawnattr_destroy(ctypes.byref(attributes))

    def test_future_exec_is_permanently_classified(self):
        with _blocked_python_process("exec") as (process, gate):
            watcher = _new_watcher(process.pid)
            try:
                watcher.require_quiet()
                self.assertEqual(os.write(gate, b"g"), 1)
                with self.assertRaises(EndpointPolicyError) as raised:
                    watcher.require_quiet(max_wait_ns=WAIT_NS)
                _assert_safe_error(self, raised.exception)
                self.assertEqual(
                    watcher.safe_metadata()["event_kinds"],
                    ("exec",),
                )
            finally:
                watcher.close()

    def test_future_fork_is_permanently_classified(self):
        with _blocked_python_process("fork") as (process, gate):
            watcher = _new_watcher(process.pid)
            try:
                watcher.require_quiet()
                self.assertEqual(os.write(gate, b"g"), 1)
                with self.assertRaises(EndpointPolicyError) as raised:
                    watcher.require_quiet(max_wait_ns=WAIT_NS)
                _assert_safe_error(self, raised.exception)
                self.assertEqual(
                    watcher.safe_metadata()["event_kinds"],
                    ("fork",),
                )
            finally:
                watcher.close()

    def test_aggregated_events_have_stable_classification(self):
        process = subprocess.Popen(["/bin/sleep", "30"], close_fds=True)
        watcher = _new_watcher(process.pid)
        synthetic = events._KEvent(
            ident=process.pid,
            filter=events._EVFILT_PROC,
            flags=events._REGISTRATION_FLAGS,
            fflags=(events._NOTE_EXEC | events._NOTE_FORK | events._NOTE_EXIT),
            data=0,
            udata=None,
        )
        try:
            with patch.object(
                events,
                "_receive_process_event",
                return_value=synthetic,
            ):
                with self.assertRaises(EndpointPolicyError):
                    watcher.require_quiet()
            self.assertEqual(
                watcher.safe_metadata()["event_kinds"],
                ("exec", "fork", "exit"),
            )
        finally:
            watcher.close()
            process.kill()
            process.wait(timeout=5)

    def test_malformed_event_and_poll_uncertainty_poison(self):
        for mode in ("malformed", "exception"):
            process = subprocess.Popen(["/bin/sleep", "30"], close_fds=True)
            watcher = _new_watcher(process.pid)
            try:
                value = (
                    events._KEvent(
                        ident=process.pid + 1,
                        filter=events._EVFILT_PROC,
                        flags=events._REGISTRATION_FLAGS,
                        fflags=events._NOTE_EXEC,
                        data=0,
                        udata=None,
                    )
                    if mode == "malformed"
                    else events._EventBoundaryFailure()
                )
                patcher = (
                    patch.object(
                        events,
                        "_receive_process_event",
                        return_value=value,
                    )
                    if mode == "malformed"
                    else patch.object(
                        events,
                        "_receive_process_event",
                        side_effect=value,
                    )
                )
                with patcher, self.assertRaises(EndpointPolicyError) as raised:
                    watcher.require_quiet()
                _assert_safe_error(self, raised.exception)
                self.assertEqual(
                    watcher.safe_metadata()["event_kinds"],
                    ("unknown",),
                )
                self.assertTrue(watcher.safe_metadata()["poisoned"])
            finally:
                watcher.close()
                process.kill()
                process.wait(timeout=5)

    def test_registration_failure_closes_known_kqueue_once(self):
        closed: list[int] = []
        original_close = os.close

        def record_close(fd: int) -> None:
            closed.append(fd)
            original_close(fd)

        with (
            patch.object(
                events,
                "_register_process_filter",
                side_effect=events._EventBoundaryFailure,
            ),
            patch.object(events.os, "close", side_effect=record_close),
            self.assertRaises(EndpointPolicyError) as raised,
        ):
            _new_watcher(os.getpid())
        _assert_safe_error(self, raised.exception)
        self.assertEqual(len(closed), 1)
        with self.assertRaises(OSError):
            os.fstat(closed[0])

    def test_close_return_gap_is_poisoned_and_never_replayed(self):
        process = subprocess.Popen(["/bin/sleep", "30"], close_fds=True)
        watcher = _new_watcher(process.pid)
        selected_fd = watcher._kqueue_fd
        original_close = os.close
        close_calls: list[int] = []

        def close_then_raise(fd: int) -> None:
            close_calls.append(fd)
            original_close(fd)
            raise KeyboardInterrupt

        try:
            with patch.object(events.os, "close", side_effect=close_then_raise):
                self.assertFalse(watcher.close())
            self.assertEqual(close_calls, [selected_fd])
            with patch.object(
                events.os,
                "close",
                side_effect=AssertionError("close replayed"),
            ):
                self.assertFalse(watcher.close())
            metadata = watcher.safe_metadata()
            self.assertTrue(metadata["close_uncertain"])
            self.assertFalse(metadata["closed"])
            self.assertTrue(metadata["poisoned"])
            self.assertFalse(metadata["process_event_watch_active"])
        finally:
            process.kill()
            process.wait(timeout=5)

    def test_invalid_pid_and_wait_are_rejected_before_external_io(self):
        for invalid in (True, 0, -1, "1"):
            with (
                self.subTest(invalid=invalid),
                patch.object(
                    events.ctypes,
                    "CDLL",
                    side_effect=AssertionError("external I/O reached"),
                ),
                self.assertRaises((TypeError, ValueError)),
            ):
                _new_watcher(invalid)
        process = subprocess.Popen(["/bin/sleep", "30"], close_fds=True)
        watcher = _new_watcher(process.pid)
        try:
            for invalid in (-1, events.MAX_PROCESS_EVENT_WAIT_NS + 1, True):
                with self.subTest(wait=invalid), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    watcher.require_quiet(max_wait_ns=invalid)
            watcher.require_quiet()
        finally:
            watcher.close()
            process.kill()
            process.wait(timeout=5)

    def test_import_is_zero_io(self):
        root = Path(__file__).resolve().parents[1]
        script = r'''
import ctypes
import os

def poison(*args, **kwargs):
    raise AssertionError("external capability used during import")

ctypes.CDLL = poison
os.open = poison
os.pipe = poison
os.set_inheritable = poison
import snapquiz.transport._darwin_process_events
'''
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
