"""Darwin-only strict process boundary for the resolver helper.

The adapter is intentionally not wired into ``ResolverHelperLauncher.production``
yet.  Importing this module and constructing its spawner perform no process,
file, environment, or network operation.  The first external action happens in
``spawn`` after the existing resolver lifecycle has supplied its publication
sink and bounded wait slice.

``posix_spawn`` itself is one synchronous Darwin syscall and cannot be
interrupted by this adapter's wait slice.  Consequently this first slice is an
experimental boundary, not a hard spawn-deadline proof, and remains deliberately
disconnected from ``production()``.  START uses one local ``AF_UNIX/SOCK_DGRAM``
record rather than a stream pipe: both socket buffers are explicitly enlarged
and a maximum-size, target-free canary is round-tripped before spawn.  This
preserves a full-or-zero record for every currently permitted START frame even
though Darwin's stream ``PIPE_BUF`` is only 512 bytes.

Only fixed metadata from :class:`ResolverHelperSpawnRequest` reaches the child:
an absolute executable, a frozen two-item argv, and the request's two-entry
minimal environment.  Darwin ``libc.posix_spawn`` is used directly so
``POSIX_SPAWN_CLOEXEC_DEFAULT`` is an explicit, testable requirement rather
than an assumption about a higher-level wrapper.
"""
from __future__ import annotations

import ctypes
import errno
from functools import wraps
import os
import select
import signal
import socket
import sys
from threading import Lock, RLock
from typing import NamedTuple, NoReturn

from snapquiz.domain._validation import require_digest, require_plain_int, runtime_final
from snapquiz.domain.digest import digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport.resolver import (
    COMPLETE,
    MAX_HELPER_STDERR_BYTES,
    MAX_READY_FRAME_BYTES,
    MAX_RESULT_FRAME_BYTES,
    MAX_START_FRAME_BYTES,
    PENDING,
    RESOLVER_HELPER_PROTOCOL_VERSION,
    ResolverHelperSpawnRequest,
    _KernelPublication,
    _require_executable,
)


__all__ = ("DarwinResolverProcessSpawner",)


_POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
_POSIX_SPAWN_SETSIGDEF = 0x0004
_POSIX_SPAWN_SETSIGMASK = 0x0008
_POSIX_SPAWN_FLAGS = (
    _POSIX_SPAWN_CLOEXEC_DEFAULT
    | _POSIX_SPAWN_SETSIGDEF
    | _POSIX_SPAWN_SETSIGMASK
)
_HELPER_ARG = "--snapquiz-resolver-helper-v2"
_HELPER_ENVIRONMENT = (("LANG", "C"), ("LC_ALL", "C"))
_STDIN_FILENO = 0
_STDOUT_FILENO = 1
_STDERR_FILENO = 2
_STDERR_READ_CHUNK_BYTES = 1_024
_STDERR_POLICY_EXIT_STATUS = 74
_SIGNAL_STATUS_BASE = 256
_CONTROL_SOCKET_BUFFER_BYTES = MAX_START_FRAME_BYTES * 4
_KERNEL_CONSTRUCTION_AUTHORITY = object()
_CHANNEL_CONSTRUCTION_AUTHORITY = object()
_SPAWN_NOT_CALLED = "not_called"
_SPAWN_IN_FLIGHT = "in_flight"
_SPAWN_FAILED = "failed"
_SPAWN_SUCCEEDED = "succeeded"
_SPAWN_UNCERTAIN = "uncertain"
_WAIT_NOT_CALLED = "not_called"
_WAIT_IN_FLIGHT = "in_flight"
_WAIT_COMPLETED = "completed"
_WAIT_UNCERTAIN = "uncertain"


def _process_error(safe_message: str) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_helper",
        retryable=False,
        safe_message=safe_message,
    )


def _raise_process_error(
    safe_message: str = "resolver helper 进程边界失败。",
) -> NoReturn:
    """Raise a content-free error without retaining an OS exception chain."""

    error = _process_error(safe_message)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


class _NativeBoundaryFailure(Exception):
    """Content-free internal marker; never crosses the adapter boundary."""


class _KernelBusy(Exception):
    """Internal identity signal for a concurrent bounded kernel operation."""


class _NonblockingRLock:
    """Context-manager facade that never waits behind another poll/sleep."""

    __slots__ = ("_lock",)

    def __init__(self) -> None:
        self._lock = RLock()

    def __enter__(self) -> "_NonblockingRLock":
        if not self._lock.acquire(blocking=False):
            raise _KernelBusy
        return self

    def __exit__(self, *ignored: object) -> None:
        del ignored
        self._lock.release()


def _return_pending_when_busy(method):
    """Keep every public HelperKernel call within its own wait slice."""

    @wraps(method)
    def guarded(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except _KernelBusy:
            return PENDING

    return guarded


class _FrozenSpawnRequest(NamedTuple):
    executable: bytes
    argv: tuple[bytes, bytes]
    environment: tuple[bytes, bytes]
    max_start_frame_bytes: int
    max_stderr_bytes: int


class _ProcessChannels(NamedTuple):
    child_stdin: int
    parent_stdin: int
    parent_stdout: int
    child_stdout: int
    parent_stderr: int
    child_stderr: int

    def all_fds(self) -> tuple[int, ...]:
        return (
            self.child_stdin,
            self.parent_stdin,
            self.parent_stdout,
            self.child_stdout,
            self.parent_stderr,
            self.child_stderr,
        )

    def child_fds(self) -> tuple[int, int, int]:
        return (self.child_stdin, self.child_stdout, self.child_stderr)


class _ProcessChannelConstructionSlot:
    """Caller-held owner for one completed six-descriptor construction.

    The caller installs this slot before entering ``_create_process_channels``.
    The factory publishes the complete descriptor tuple into the slot and
    returns no resource.  A Python exception delivered at the factory's return
    event therefore leaves an exact cleanup authority reachable from the
    spawner instead of stranding all six descriptors between RETURN and the
    caller's STORE operation.

    This closes only that Python publication window.  It deliberately does not
    claim that ``socketpair()``, ``pipe()``, or ``socket.detach()`` creates and
    publishes a native descriptor atomically; that opaque-owner requirement is
    still a production blocker for this experimental adapter.
    """

    __slots__ = (
        "_state",
        "_channels",
        "_remaining_fds",
        "_uncertain_fd",
        "_lock",
        "_close_lock",
    )

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _CHANNEL_CONSTRUCTION_AUTHORITY:
            raise TypeError("process channel construction requires its spawner")
        self._state = "empty"
        self._channels: _ProcessChannels | None = None
        self._remaining_fds: tuple[int, ...] = ()
        self._uncertain_fd: int | None = None
        self._lock = Lock()
        # Never hold the publication lock across ``os.close``.  The action lock
        # prevents two recovery callers from closing the same numeric fd while
        # still allowing state inspection without a callback lock inversion.
        self._close_lock = Lock()

    def claim_factory(self) -> bool:
        """Claim the sole factory call, or reuse its durable publication."""

        with self._lock:
            if self._state == "channels" and self._channels is not None:
                return False
            if self._state != "empty" or self._channels is not None:
                raise ValueError("process channel construction replay is forbidden")
            self._state = "constructing"
            return True

    def publish_channels(self, channels: _ProcessChannels) -> None:
        if type(channels) is not _ProcessChannels:
            raise TypeError("process channels publication is invalid")
        fds = channels.all_fds()
        if len(fds) != 6 or len(set(fds)) != 6 or any(
            type(fd) is not int or fd < 3 for fd in fds
        ):
            raise ValueError("process channels publication is invalid")
        with self._lock:
            if self._state != "constructing" or self._channels is not None:
                raise ValueError("process channels publication replay is forbidden")
            self._channels = channels
            self._remaining_fds = fds
            self._state = "channels"

    def channels(self) -> _ProcessChannels:
        with self._lock:
            if self._state != "channels" or self._channels is None:
                raise ValueError("process channels are unavailable")
            return self._channels

    def owns_channels(self, channels: object) -> bool:
        with self._lock:
            return self._state in ("channels", "closing") and (
                self._channels is channels
            )

    @staticmethod
    def _kernel_owns_channels(
        kernel: object,
        channels: _ProcessChannels,
    ) -> bool:
        return (
            type(kernel) is _DarwinResolverProcessKernel
            and kernel._stdin_fd == channels.parent_stdin
            and kernel._stdout_fd == channels.parent_stdout
            and kernel._stderr_fd == channels.parent_stderr
            and tuple(kernel._child_fds) == channels.child_fds()
        )

    def transfer_to_kernel(
        self,
        channels: _ProcessChannels,
        kernel: object,
    ) -> None:
        """Release the tuple only after the exact kernel is durably anchored."""

        if not self._kernel_owns_channels(kernel, channels):
            raise ValueError("process kernel owns different channels")
        with self._lock:
            if self._state != "channels" or self._channels is not channels:
                raise ValueError("process channel owner changed")
            if self._uncertain_fd is not None:
                raise ValueError("process channel close outcome is uncertain")
            self._state = "transferred"
            self._channels = None
            self._remaining_fds = ()

    def transferred(self) -> bool:
        with self._lock:
            return (
                self._state == "transferred"
                and self._channels is None
                and not self._remaining_fds
                and self._uncertain_fd is None
            )

    def is_terminal(self) -> bool:
        with self._lock:
            return (
                self._state in ("closed", "transferred")
                and self._channels is None
                and not self._remaining_fds
                and self._uncertain_fd is None
            )

    def has_retained_channels(self) -> bool:
        with self._lock:
            return self._channels is not None

    def close_once(self) -> None:
        """Close each published fd at most once and retain any unknown outcome."""

        with self._close_lock:
            while True:
                with self._lock:
                    if self._state in ("closed", "transferred"):
                        return
                    if self._state == "empty":
                        self._state = "closed"
                        self._channels = None
                        self._remaining_fds = ()
                        return
                    if self._state == "constructing":
                        # The slot cannot prove whether an opaque native call
                        # returned before Python published its result.  Retain a
                        # nonterminal tombstone instead of claiming cleanup.
                        self._state = "construction_uncertain"
                        _raise_process_error(
                            "resolver helper IPC 原生构造结果不确定。"
                        )
                    if self._state == "construction_uncertain":
                        _raise_process_error(
                            "resolver helper IPC 原生构造结果不确定。"
                        )
                    if self._state not in ("channels", "closing"):
                        _raise_process_error(
                            "resolver helper IPC 构造状态无效。"
                        )
                    if self._channels is None:
                        _raise_process_error(
                            "resolver helper IPC 构造所有权无效。"
                        )
                    if self._uncertain_fd is not None:
                        _raise_process_error(
                            "resolver helper IPC 关闭结果不确定。"
                        )
                    if not self._remaining_fds:
                        self._state = "closed"
                        self._channels = None
                        return
                    fd = self._remaining_fds[0]
                    # Claim before the external action.  If an async exception
                    # lands after the kernel close but before local commit, the
                    # fd is retained as uncertain and is never replayed.
                    self._remaining_fds = self._remaining_fds[1:]
                    self._uncertain_fd = fd
                    self._state = "closing"
                try:
                    os.close(fd)
                except BaseException:
                    _raise_process_error(
                        "resolver helper IPC 关闭结果不确定。"
                    )
                with self._lock:
                    if (
                        self._state != "closing"
                        or self._channels is None
                        or self._uncertain_fd != fd
                    ):
                        _raise_process_error(
                            "resolver helper IPC 关闭提交失败。"
                        )
                    self._uncertain_fd = None
                    self._state = "channels"


def _freeze_spawn_request(request: ResolverHelperSpawnRequest) -> _FrozenSpawnRequest:
    """Copy and revalidate every spawn field before creating any descriptor."""

    try:
        executable = request.executable
        argv = request.argv
        environment = request.environment
        protocol_version = request.protocol_version
        shell = request.shell
        close_fds = request.close_fds
        max_ready = request.max_ready_frame_bytes
        max_start = request.max_start_frame_bytes
        max_result = request.max_result_frame_bytes
        max_stderr = request.max_stderr_bytes
        request_digest = require_digest(request.request_digest, "request_digest")
        if type(executable) is not str:
            raise _NativeBoundaryFailure
        checked_executable = _require_executable(executable)
        if (
            type(protocol_version) is not str
            or protocol_version != RESOLVER_HELPER_PROTOCOL_VERSION
            or type(argv) is not tuple
            or len(argv) != 2
            or type(argv[0]) is not str
            or type(argv[1]) is not str
            or argv != (checked_executable, _HELPER_ARG)
            or type(environment) is not tuple
            or len(environment) != 2
            or any(type(item) is not tuple or len(item) != 2 for item in environment)
            or any(
                type(name) is not str or type(value) is not str
                for name, value in environment
            )
            or environment != _HELPER_ENVIRONMENT
            or shell is not False
            or close_fds is not True
            or type(max_ready) is not int
            or max_ready != MAX_READY_FRAME_BYTES
            or type(max_start) is not int
            or max_start != MAX_START_FRAME_BYTES
            or type(max_result) is not int
            or max_result != MAX_RESULT_FRAME_BYTES
            or type(max_stderr) is not int
            or max_stderr != MAX_HELPER_STDERR_BYTES
        ):
            raise _NativeBoundaryFailure

        frozen_metadata = {
            "protocol_version": protocol_version,
            "executable": checked_executable,
            "argv": argv,
            "environment": environment,
            "shell": shell,
            "close_fds": close_fds,
            "max_ready_frame_bytes": max_ready,
            "max_start_frame_bytes": max_start,
            "max_result_frame_bytes": max_result,
            "max_stderr_bytes": max_stderr,
        }
        if request_digest != digest256(
            "ResolverHelperSpawnRequest",
            RESOLVER_HELPER_PROTOCOL_VERSION,
            frozen_metadata,
        ):
            raise _NativeBoundaryFailure

        executable_bytes = os.fsencode(checked_executable)
        argv_bytes = (os.fsencode(argv[0]), os.fsencode(argv[1]))
        environment_bytes = tuple(
            f"{name}={value}".encode("ascii") for name, value in environment
        )
        if (
            not executable_bytes
            or b"\x00" in executable_bytes
            or any(not item or b"\x00" in item for item in argv_bytes)
            or any(not item or b"\x00" in item for item in environment_bytes)
        ):
            raise _NativeBoundaryFailure
    except BaseException:
        _raise_process_error("resolver helper 启动配置无效。")

    return _FrozenSpawnRequest(
        executable=bytes(executable_bytes),
        argv=(bytes(argv_bytes[0]), bytes(argv_bytes[1])),
        environment=(
            bytes(environment_bytes[0]),
            bytes(environment_bytes[1]),
        ),
        max_start_frame_bytes=max_start,
        max_stderr_bytes=max_stderr,
    )


def _close_raw_fds(fds: tuple[int, ...]) -> None:
    """Best-effort emergency close for descriptors not yet owned by a kernel."""

    for fd in fds:
        try:
            os.close(fd)
        except BaseException:
            pass


def _create_process_channels(
    construction: _ProcessChannelConstructionSlot,
) -> None:
    """Create then publish one record channel plus two output pipes."""

    if type(construction) is not _ProcessChannelConstructionSlot:
        raise TypeError("construction must be _ProcessChannelConstructionSlot")
    try:
        if not construction.claim_factory():
            return None
    except BaseException:
        _raise_process_error()

    opened_pipes: list[int] = []
    detached_sockets: list[int] = []
    parent_control: socket.socket | None = None
    child_control: socket.socket | None = None
    channels: _ProcessChannels | None = None
    try:
        parent_control, child_control = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_DGRAM,
        )
        if (
            parent_control.family != socket.AF_UNIX
            or child_control.family != socket.AF_UNIX
            or parent_control.type & socket.SOCK_DGRAM != socket.SOCK_DGRAM
            or child_control.type & socket.SOCK_DGRAM != socket.SOCK_DGRAM
        ):
            raise _NativeBoundaryFailure
        for endpoint in (parent_control, child_control):
            endpoint.set_inheritable(False)
            endpoint.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_SNDBUF,
                _CONTROL_SOCKET_BUFFER_BYTES,
            )
            endpoint.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_RCVBUF,
                _CONTROL_SOCKET_BUFFER_BYTES,
            )
            if (
                endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                < _CONTROL_SOCKET_BUFFER_BYTES
                or endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                < _CONTROL_SOCKET_BUFFER_BYTES
            ):
                raise _NativeBoundaryFailure

        # Darwin's default AF_UNIX datagram buffers reject a 4096-byte record.
        # Exercise this exact pair while both ends are local and nonblocking;
        # the target-free record is consumed before either descriptor can be
        # inherited by a child.
        parent_control.setblocking(False)
        child_control.setblocking(False)
        canary = b"\x00" * MAX_START_FRAME_BYTES
        sent = parent_control.send(canary)
        received, ancillary, message_flags, _ = child_control.recvmsg(
            MAX_START_FRAME_BYTES + 1,
            256,
        )
        truncation_flags = socket.MSG_TRUNC | socket.MSG_CTRUNC
        if (
            type(sent) is not int
            or sent != len(canary)
            or received != canary
            or ancillary
            or message_flags & truncation_flags
        ):
            raise _NativeBoundaryFailure
        # Restore the one-way capability that a stdin pipe provided.  The
        # helper may receive the single START record but cannot send records or
        # SCM_RIGHTS back through fd 0; the parent cannot receive on this edge.
        parent_control.shutdown(socket.SHUT_RD)
        child_control.shutdown(socket.SHUT_WR)
        child_control.setblocking(True)

        parent_stdout, child_stdout = os.pipe()
        opened_pipes.extend((parent_stdout, child_stdout))
        parent_stderr, child_stderr = os.pipe()
        opened_pipes.extend((parent_stderr, child_stderr))
        control_fds = (parent_control.fileno(), child_control.fileno())
        all_fds = control_fds + tuple(opened_pipes)
        if len(set(all_fds)) != 6 or any(fd < 3 for fd in all_fds):
            raise _NativeBoundaryFailure

        for fd in opened_pipes:
            os.set_inheritable(fd, False)
        for fd in (parent_stdout, parent_stderr):
            os.set_blocking(fd, False)

        parent_stdin = parent_control.detach()
        detached_sockets.append(parent_stdin)
        child_stdin = child_control.detach()
        detached_sockets.append(child_stdin)
        channels = _ProcessChannels(
            child_stdin=child_stdin,
            parent_stdin=parent_stdin,
            parent_stdout=parent_stdout,
            child_stdout=child_stdout,
            parent_stderr=parent_stderr,
            child_stderr=child_stderr,
        )
        construction.publish_channels(channels)
        # A resource must never cross this factory's Python return boundary.
        return None
    except BaseException:
        published = channels is not None and construction.owns_channels(channels)
        if not published:
            _close_raw_fds(tuple(opened_pipes) + tuple(detached_sockets))
        for endpoint in (parent_control, child_control):
            if endpoint is not None:
                try:
                    endpoint.close()
                except BaseException:
                    pass
        _raise_process_error()


def _configure_libc_spawn_functions(libc: object) -> tuple[object, ...]:
    """Resolve the fixed Darwin spawn surface without using a library path."""

    try:
        actions_init = libc.posix_spawn_file_actions_init
        actions_destroy = libc.posix_spawn_file_actions_destroy
        actions_adddup2 = libc.posix_spawn_file_actions_adddup2
        actions_addclose = libc.posix_spawn_file_actions_addclose
        attr_init = libc.posix_spawnattr_init
        attr_destroy = libc.posix_spawnattr_destroy
        attr_setflags = libc.posix_spawnattr_setflags
        attr_setsigdefault = libc.posix_spawnattr_setsigdefault
        attr_setsigmask = libc.posix_spawnattr_setsigmask
        sigemptyset = libc.sigemptyset
        sigfillset = libc.sigfillset
        sigdelset = libc.sigdelset
        spawn = libc.posix_spawn

        opaque_pointer_pointer = ctypes.POINTER(ctypes.c_void_p)
        char_pointer_pointer = ctypes.POINTER(ctypes.c_char_p)
        signal_set_pointer = ctypes.POINTER(ctypes.c_uint32)
        actions_init.argtypes = [opaque_pointer_pointer]
        actions_destroy.argtypes = [opaque_pointer_pointer]
        actions_adddup2.argtypes = [opaque_pointer_pointer, ctypes.c_int, ctypes.c_int]
        actions_addclose.argtypes = [opaque_pointer_pointer, ctypes.c_int]
        attr_init.argtypes = [opaque_pointer_pointer]
        attr_destroy.argtypes = [opaque_pointer_pointer]
        attr_setflags.argtypes = [opaque_pointer_pointer, ctypes.c_short]
        attr_setsigdefault.argtypes = [opaque_pointer_pointer, signal_set_pointer]
        attr_setsigmask.argtypes = [opaque_pointer_pointer, signal_set_pointer]
        sigemptyset.argtypes = [signal_set_pointer]
        sigfillset.argtypes = [signal_set_pointer]
        sigdelset.argtypes = [signal_set_pointer, ctypes.c_int]
        spawn.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
            opaque_pointer_pointer,
            opaque_pointer_pointer,
            char_pointer_pointer,
            char_pointer_pointer,
        ]
        for function in (
            actions_init,
            actions_destroy,
            actions_adddup2,
            actions_addclose,
            attr_init,
            attr_destroy,
            attr_setflags,
            attr_setsigdefault,
            attr_setsigmask,
            sigemptyset,
            sigfillset,
            sigdelset,
            spawn,
        ):
            function.restype = ctypes.c_int
        return (
            actions_init,
            actions_destroy,
            actions_adddup2,
            actions_addclose,
            attr_init,
            attr_destroy,
            attr_setflags,
            attr_setsigdefault,
            attr_setsigmask,
            sigemptyset,
            sigfillset,
            sigdelset,
            spawn,
        )
    except BaseException:
        raise _NativeBoundaryFailure from None


def _native_posix_spawn(
    frozen: _FrozenSpawnRequest,
    channels: _ProcessChannels,
    kernel: "_DarwinResolverProcessKernel",
) -> None:
    """Run exactly one Darwin ``libc.posix_spawn`` with fixed file actions."""

    actions = ctypes.c_void_p()
    attributes = ctypes.c_void_p()
    actions_initialized = False
    attributes_initialized = False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        (
            actions_init,
            actions_destroy,
            actions_adddup2,
            actions_addclose,
            attr_init,
            attr_destroy,
            attr_setflags,
            attr_setsigdefault,
            attr_setsigmask,
            sigemptyset,
            sigfillset,
            sigdelset,
            posix_spawn,
        ) = _configure_libc_spawn_functions(libc)

        if actions_init(ctypes.byref(actions)) != 0:
            raise _NativeBoundaryFailure
        actions_initialized = True
        if attr_init(ctypes.byref(attributes)) != 0:
            raise _NativeBoundaryFailure
        attributes_initialized = True
        if (
            attr_setflags(
                ctypes.byref(attributes),
                ctypes.c_short(_POSIX_SPAWN_FLAGS),
            )
            != 0
        ):
            raise _NativeBoundaryFailure
        empty_signal_mask = ctypes.c_uint32(0)
        default_signal_set = ctypes.c_uint32(0)
        if sigemptyset(ctypes.byref(empty_signal_mask)) != 0:
            raise _NativeBoundaryFailure
        if sigfillset(ctypes.byref(default_signal_set)) != 0:
            raise _NativeBoundaryFailure
        if sigdelset(ctypes.byref(default_signal_set), signal.SIGKILL) != 0:
            raise _NativeBoundaryFailure
        if sigdelset(ctypes.byref(default_signal_set), signal.SIGSTOP) != 0:
            raise _NativeBoundaryFailure
        if (
            attr_setsigmask(
                ctypes.byref(attributes),
                ctypes.byref(empty_signal_mask),
            )
            != 0
            or attr_setsigdefault(
                ctypes.byref(attributes),
                ctypes.byref(default_signal_set),
            )
            != 0
        ):
            raise _NativeBoundaryFailure

        for source_fd, target_fd in (
            (channels.child_stdin, _STDIN_FILENO),
            (channels.child_stdout, _STDOUT_FILENO),
            (channels.child_stderr, _STDERR_FILENO),
        ):
            if (
                actions_adddup2(
                    ctypes.byref(actions),
                    source_fd,
                    target_fd,
                )
                != 0
            ):
                raise _NativeBoundaryFailure
        for fd in channels.all_fds():
            if actions_addclose(ctypes.byref(actions), fd) != 0:
                raise _NativeBoundaryFailure

        argv_array_type = ctypes.c_char_p * (len(frozen.argv) + 1)
        environment_array_type = ctypes.c_char_p * (len(frozen.environment) + 1)
        argv = argv_array_type(*frozen.argv, None)
        environment = environment_array_type(*frozen.environment, None)
        # From this point until the returned status is recorded, Python cannot
        # know whether libc created a child.  Recovery must treat that window as
        # poison and, in particular, must not trust the undefined PID output of
        # a failed POSIX spawn.
        kernel._begin_spawn_call()
        result = posix_spawn(
            ctypes.byref(kernel._spawn_pid_cell),
            frozen.executable,
            ctypes.byref(actions),
            ctypes.byref(attributes),
            argv,
            environment,
        )
        if result != 0:
            kernel._record_failed_spawn_call()
            raise _NativeBoundaryFailure
        kernel._record_successful_spawn_call()
        # Only a zero libc result followed by an exact positive-PID check makes
        # the retained cell authoritative.  A later bind fault can therefore
        # recover this child, while the unrecorded C-return window stays
        # deliberately poisoned until a native atomic shim replaces it.
        kernel._bind_spawned_pid_from_cell()
    except _NativeBoundaryFailure:
        raise
    except BaseException:
        raise _NativeBoundaryFailure from None
    finally:
        if attributes_initialized:
            try:
                attr_destroy(ctypes.byref(attributes))
            except BaseException:
                pass
        if actions_initialized:
            try:
                actions_destroy(ctypes.byref(actions))
            except BaseException:
                pass


def _bounded_select(
    read_fds: tuple[int, ...],
    write_fds: tuple[int, ...],
    max_wait_ns: int,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Perform one EINTR-safe readiness poll without ``FD_SETSIZE`` limits."""

    interests: dict[int, int] = {}
    for fd in read_fds:
        interests[fd] = interests.get(fd, 0) | select.POLLIN | select.POLLHUP
    for fd in write_fds:
        interests[fd] = interests.get(fd, 0) | select.POLLOUT
    timeout_ms = max_wait_ns // 1_000_000
    try:
        poller = select.poll()
        for fd, mask in interests.items():
            poller.register(fd, mask)
        events = poller.poll(timeout_ms)
    except OSError as error:
        if error.errno == errno.EINTR:
            return (), ()
        _raise_process_error()
    except BaseException:
        _raise_process_error()
    readable: list[int] = []
    writable: list[int] = []
    for fd, event_mask in events:
        if event_mask & (select.POLLERR | select.POLLNVAL):
            _raise_process_error()
        if fd in read_fds and event_mask & (select.POLLIN | select.POLLHUP):
            readable.append(fd)
        if fd in write_fds:
            if event_mask & select.POLLHUP:
                _raise_process_error()
            if event_mask & select.POLLOUT:
                writable.append(fd)
    return tuple(readable), tuple(writable)


def _bounded_pause(max_wait_ns: int) -> None:
    """Wait no longer than the whole-millisecond portion of one slice."""

    timeout_ms = max_wait_ns // 1_000_000
    if timeout_ms <= 0:
        return
    try:
        select.poll().poll(timeout_ms)
    except OSError as error:
        if error.errno != errno.EINTR:
            _raise_process_error()
    except BaseException:
        _raise_process_error()


@runtime_final
class _DarwinResolverProcessKernel:
    """Exact owner of one spawned helper PID and its parent IPC endpoints."""

    __slots__ = (
        "_pid",
        "_spawn_pid_cell",
        "_spawn_call_state",
        "_stdin_fd",
        "_stdout_fd",
        "_stderr_fd",
        "_child_fds",
        "_max_start_frame_bytes",
        "_max_stderr_bytes",
        "_stderr_byte_count",
        "_stderr_eof",
        "_stderr_overflow",
        "_stdout_eof",
        "_start_frame",
        "_start_state",
        "_kill_state",
        "_wait_call_state",
        "_waited_status",
        "_reap_status",
        "_reap_uncertain",
        "_pipe_close_uncertain",
        "_lock",
    )

    def __init__(
        self,
        *,
        pid: int | None,
        channels: _ProcessChannels,
        frozen: _FrozenSpawnRequest,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _KERNEL_CONSTRUCTION_AUTHORITY:
            raise TypeError("Darwin resolver kernel requires its spawner")
        object.__setattr__(self, "_pid", pid)
        object.__setattr__(self, "_spawn_pid_cell", ctypes.c_int(pid or 0))
        object.__setattr__(
            self,
            "_spawn_call_state",
            _SPAWN_SUCCEEDED if pid is not None else _SPAWN_NOT_CALLED,
        )
        object.__setattr__(self, "_stdin_fd", channels.parent_stdin)
        object.__setattr__(self, "_stdout_fd", channels.parent_stdout)
        object.__setattr__(self, "_stderr_fd", channels.parent_stderr)
        object.__setattr__(self, "_child_fds", list(channels.child_fds()))
        object.__setattr__(
            self,
            "_max_start_frame_bytes",
            frozen.max_start_frame_bytes,
        )
        object.__setattr__(self, "_max_stderr_bytes", frozen.max_stderr_bytes)
        object.__setattr__(self, "_stderr_byte_count", 0)
        object.__setattr__(self, "_stderr_eof", False)
        object.__setattr__(self, "_stderr_overflow", False)
        object.__setattr__(self, "_stdout_eof", False)
        object.__setattr__(self, "_start_frame", None)
        object.__setattr__(self, "_start_state", "not_started")
        object.__setattr__(self, "_kill_state", "not_attempted")
        object.__setattr__(self, "_wait_call_state", _WAIT_NOT_CALLED)
        object.__setattr__(self, "_waited_status", None)
        object.__setattr__(self, "_reap_status", None)
        object.__setattr__(self, "_reap_uncertain", False)
        object.__setattr__(self, "_pipe_close_uncertain", False)
        object.__setattr__(self, "_lock", _NonblockingRLock())

    def _begin_spawn_call(self) -> None:
        with self._lock:
            if (
                self._spawn_call_state != _SPAWN_NOT_CALLED
                or self._pid is not None
                or self._spawn_pid_cell.value != 0
            ):
                raise _NativeBoundaryFailure
            self._spawn_call_state = _SPAWN_IN_FLIGHT

    def _record_failed_spawn_call(self) -> None:
        """Reject libc's undefined failure-path PID without ever owning it."""

        with self._lock:
            if self._spawn_call_state != _SPAWN_IN_FLIGHT:
                raise _NativeBoundaryFailure
            # Publish the authoritative failed state before clearing the
            # undefined output.  An async exception between these assignments
            # still leaves recovery forbidden from signalling the cell value.
            self._spawn_call_state = _SPAWN_FAILED
            self._spawn_pid_cell.value = 0

    def _record_successful_spawn_call(self) -> None:
        """Attest the PID cell only after libc returned exact success."""

        with self._lock:
            pid = self._spawn_pid_cell.value
            if (
                self._spawn_call_state != _SPAWN_IN_FLIGHT
                or type(pid) is not int
                or pid <= 0
            ):
                self._spawn_call_state = _SPAWN_UNCERTAIN
                raise _NativeBoundaryFailure
            self._spawn_call_state = _SPAWN_SUCCEEDED

    def _spawn_recovery_state(self) -> str:
        """Return the safe recovery classification without trusting raw PID."""

        with self._lock:
            state = self._spawn_call_state
            if state == _SPAWN_IN_FLIGHT:
                # The Python boundary did not attest libc's result.  A child
                # may or may not exist, so recovery must retain ownership and
                # must never signal or wait on the raw output cell.
                self._spawn_call_state = _SPAWN_UNCERTAIN
                state = _SPAWN_UNCERTAIN
            if state == _SPAWN_FAILED:
                self._pid = None
                self._spawn_pid_cell.value = 0
            if state not in (
                _SPAWN_NOT_CALLED,
                _SPAWN_FAILED,
                _SPAWN_SUCCEEDED,
                _SPAWN_UNCERTAIN,
            ):
                raise _NativeBoundaryFailure
            return state

    def _bind_spawned_pid_from_cell(self) -> None:
        pid = self._spawn_pid_cell.value
        if type(pid) is not int or pid <= 0:
            raise _NativeBoundaryFailure
        with self._lock:
            if (
                self._spawn_call_state != _SPAWN_SUCCEEDED
                or self._pid is not None
            ):
                raise _NativeBoundaryFailure
            self._pid = pid

    def _spawned_pid_locked(self) -> int:
        pid = self._pid
        if pid is None:
            cell_pid = self._spawn_pid_cell.value
            if (
                self._spawn_call_state == _SPAWN_SUCCEEDED
                and type(cell_pid) is int
                and cell_pid > 0
            ):
                # Recovery may reach this path after spawn returned but before
                # the normal cache bind completed.
                self._pid = cell_pid
                pid = cell_pid
        if type(pid) is not int or pid <= 0:
            _raise_process_error()
        return pid

    def _close_child_fds_after_spawn(self) -> None:
        """Close the parent's copies without ever replaying an uncertain close."""

        close_failed = False
        with self._lock:
            if self._pipe_close_uncertain:
                _raise_process_error()
            while self._child_fds:
                fd = self._child_fds[-1]
                try:
                    os.close(fd)
                    self._child_fds.pop()
                except BaseException:
                    self._pipe_close_uncertain = True
                    close_failed = True
                    break
        if close_failed:
            _raise_process_error()

    def _close_stderr_locked(self) -> None:
        fd = self._stderr_fd
        if fd is None:
            return
        if self._pipe_close_uncertain:
            _raise_process_error("resolver helper IPC 关闭结果不确定。")
        try:
            os.close(fd)
            self._stderr_fd = None
        except BaseException:
            self._pipe_close_uncertain = True
            _raise_process_error()

    def _drain_stderr_locked(self, *, fail_on_overflow: bool = True) -> None:
        """Drain/discard at most 4096 bytes plus one overflow sentinel byte."""

        if self._stderr_overflow:
            if fail_on_overflow:
                _raise_process_error("resolver helper stderr 超过上限。")
            return
        fd = self._stderr_fd
        if fd is None or self._stderr_eof:
            return
        while True:
            remaining = self._max_stderr_bytes - self._stderr_byte_count
            read_size = min(_STDERR_READ_CHUNK_BYTES, remaining) if remaining else 1
            try:
                chunk = os.read(fd, read_size)
            except BlockingIOError:
                return
            except InterruptedError:
                return
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                    return
                _raise_process_error()
            except BaseException:
                _raise_process_error()
            if type(chunk) is not bytes or len(chunk) > read_size:
                _raise_process_error()
            if not chunk:
                self._stderr_eof = True
                self._close_stderr_locked()
                return
            if remaining == 0:
                self._stderr_overflow = True
                try:
                    self._close_stderr_locked()
                finally:
                    if fail_on_overflow:
                        _raise_process_error("resolver helper stderr 超过上限。")
                return
            self._stderr_byte_count += len(chunk)

    def _drain_stderr_for_reap_locked(self) -> None:
        """Never let late diagnostics prevent the already-claimed exact reap."""

        try:
            self._drain_stderr_locked(fail_on_overflow=False)
        except BaseException:
            self._stderr_overflow = True
            try:
                self._close_stderr_locked()
            except BaseException:
                pass

    @_return_pending_when_busy
    def read_stdout(self, max_bytes: int, *, max_wait_ns: int) -> object:
        checked_maximum = require_plain_int(max_bytes, "max_bytes", minimum=1)
        checked_wait = require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        with self._lock:
            self._drain_stderr_locked()
            fd = self._stdout_fd
            if fd is None:
                if self._stdout_eof:
                    return b""
                _raise_process_error()
            read_fds = (fd,) + (() if self._stderr_fd is None else (self._stderr_fd,))
            readable, _ = _bounded_select(read_fds, (), checked_wait)
            if self._stderr_fd is not None and self._stderr_fd in readable:
                self._drain_stderr_locked()
            if fd not in readable:
                return PENDING
            try:
                chunk = os.read(fd, checked_maximum)
            except BlockingIOError:
                return PENDING
            except InterruptedError:
                return PENDING
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                    return PENDING
                _raise_process_error()
            except BaseException:
                _raise_process_error()
            if type(chunk) is not bytes or len(chunk) > checked_maximum:
                _raise_process_error()
            if not chunk:
                self._stdout_eof = True
                return b""
            return chunk

    @_return_pending_when_busy
    def write_stdin(self, frame: bytes, *, max_wait_ns: int) -> object:
        if type(frame) is not bytes or not frame:
            raise TypeError("frame must be non-empty immutable bytes")
        checked_wait = require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        with self._lock:
            if len(frame) > self._max_start_frame_bytes:
                _raise_process_error("resolver helper START frame 无法原子写入。")
            if self._start_state == "complete":
                if self._start_frame == frame:
                    return COMPLETE
                _raise_process_error("resolver helper START frame 已提交。")
            if self._start_state == "uncertain":
                _raise_process_error("resolver helper START 写入结果不确定。")
            if self._start_state != "not_started":
                _raise_process_error()
            fd = self._stdin_fd
            if fd is None:
                _raise_process_error()
            self._drain_stderr_locked()
            read_fds = () if self._stderr_fd is None else (self._stderr_fd,)
            readable, writable = _bounded_select(read_fds, (fd,), checked_wait)
            if self._stderr_fd is not None and self._stderr_fd in readable:
                self._drain_stderr_locked()
            if fd not in writable:
                return PENDING

            self._start_state = "in_flight"
            try:
                written = os.write(fd, frame)
            except BlockingIOError:
                self._start_state = "not_started"
                return PENDING
            except InterruptedError:
                self._start_state = "not_started"
                return PENDING
            except OSError as error:
                if error.errno in (
                    errno.EAGAIN,
                    errno.EWOULDBLOCK,
                    errno.EINTR,
                    errno.ENOBUFS,
                ):
                    self._start_state = "not_started"
                    return PENDING
                self._start_state = "uncertain"
                _raise_process_error("resolver helper START 写入结果不确定。")
            except BaseException:
                self._start_state = "uncertain"
                _raise_process_error("resolver helper START 写入结果不确定。")
            if type(written) is not int or written != len(frame):
                self._start_state = "uncertain"
                _raise_process_error("resolver helper START 写入结果不确定。")
            self._start_frame = bytes(frame)
            self._start_state = "complete"
            return COMPLETE

    @_return_pending_when_busy
    def terminate(self, *, max_wait_ns: int) -> object:
        require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        with self._lock:
            if self._reap_status is not None:
                self._finish_reap_bookkeeping_locked()
                return COMPLETE
            # Reap an already-dead child before signalling.  This narrows the
            # PID-reuse window when a process-global reaper is absent; an
            # external SIGCHLD reaper remains outside this first slice's proof.
            wait_result = self._waitpid_nohang_locked()
            if wait_result is not PENDING or self._waited_status is not None:
                return COMPLETE
            if self._kill_state == "complete":
                return COMPLETE
            if self._kill_state == "uncertain":
                _raise_process_error("resolver helper 终止结果不确定。")
            if self._kill_state != "not_attempted":
                _raise_process_error()
            self._kill_state = "in_flight"
            try:
                os.kill(self._spawned_pid_locked(), signal.SIGKILL)
            except ProcessLookupError:
                self._kill_state = "complete"
                return COMPLETE
            except OSError as error:
                if error.errno == errno.ESRCH:
                    self._kill_state = "complete"
                    return COMPLETE
                self._kill_state = "uncertain"
                _raise_process_error("resolver helper 终止结果不确定。")
            except BaseException:
                self._kill_state = "uncertain"
                _raise_process_error("resolver helper 终止结果不确定。")
            self._kill_state = "complete"
            return COMPLETE

    def _waitpid_nohang_locked(self) -> object:
        if self._reap_uncertain:
            _raise_process_error("resolver helper 回收结果不确定。")
        if self._reap_status is not None:
            return self._finish_reap_bookkeeping_locked()
        if self._waited_status is not None:
            return self._finalize_waited_status_locked()
        if self._wait_call_state in (_WAIT_IN_FLIGHT, _WAIT_UNCERTAIN):
            self._wait_call_state = _WAIT_UNCERTAIN
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        if self._wait_call_state != _WAIT_NOT_CALLED:
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        # Mark before crossing into libc.  If Python is interrupted after the
        # child was reaped but before its status is retained, later recovery
        # must poison instead of replaying waitpid against a reusable PID.
        self._wait_call_state = _WAIT_IN_FLIGHT
        try:
            pid = self._spawned_pid_locked()
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            self._wait_call_state = _WAIT_NOT_CALLED
            return PENDING
        except OSError as error:
            if error.errno == errno.EINTR:
                self._wait_call_state = _WAIT_NOT_CALLED
                return PENDING
            self._wait_call_state = _WAIT_UNCERTAIN
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        except BaseException:
            self._wait_call_state = _WAIT_UNCERTAIN
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        if waited_pid == 0:
            self._wait_call_state = _WAIT_NOT_CALLED
            return PENDING
        if type(waited_pid) is not int or waited_pid != pid:
            self._wait_call_state = _WAIT_UNCERTAIN
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        if type(status) is not int or status < 0:
            self._wait_call_state = _WAIT_UNCERTAIN
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        # The HelperKernel contract uses a non-negative *plain* status rather
        # than waitpid's encoded word.  Preserve a normal exit code exactly;
        # use a disjoint reversible 256 + signal domain for signal death so
        # cleanup can commit the existing non-negative ledger contract without
        # confusing SIGKILL with a normal exit(137).
        if os.WIFEXITED(status):
            plain_status = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            plain_status = _SIGNAL_STATUS_BASE + os.WTERMSIG(status)
        else:
            self._wait_call_state = _WAIT_UNCERTAIN
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        if type(plain_status) is not int or plain_status < 0:
            self._wait_call_state = _WAIT_UNCERTAIN
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        self._waited_status = plain_status
        self._wait_call_state = _WAIT_COMPLETED
        return self._finalize_waited_status_locked()

    def _finalize_waited_status_locked(self) -> object:
        """Publish a wait status only after stderr is terminal or rejected."""

        plain_status = self._waited_status
        if type(plain_status) is not int or plain_status < 0:
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        # Exact waitpid has already proved every child writer is closed.  Drain
        # the bounded remainder now; an interrupted read remains PENDING but
        # must never cause waitpid to be replayed or the already-reaped PID to
        # be signalled.
        self._drain_stderr_for_reap_locked()
        if not self._stderr_eof and not self._stderr_overflow:
            return PENDING
        if self._stderr_overflow and plain_status == 0:
            # The child was reaped exactly, but a diagnostics overflow must not
            # be allowed to attest a publishable successful helper outcome.
            plain_status = _STDERR_POLICY_EXIT_STATUS
        self._reap_status = plain_status
        return self._finish_reap_bookkeeping_locked()

    def _finish_reap_bookkeeping_locked(self) -> int:
        """Idempotently finish the tail after terminal status publication."""

        plain_status = self._reap_status
        if type(plain_status) is not int or plain_status < 0:
            self._reap_uncertain = True
            _raise_process_error("resolver helper 回收结果不确定。")
        # Status is the durable local fact.  Keeping these assignments
        # idempotent lets the next reap/recovery call finish after an async
        # BaseException at any boundary below.
        self._waited_status = None
        self._pid = None
        self._spawn_pid_cell.value = 0
        self._wait_call_state = _WAIT_COMPLETED
        return plain_status

    @_return_pending_when_busy
    def reap(self, *, max_wait_ns: int) -> object:
        checked_wait = require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        with self._lock:
            if self._reap_status is not None:
                return self._finish_reap_bookkeeping_locked()
            self._drain_stderr_for_reap_locked()
            result = self._waitpid_nohang_locked()
            if result is not PENDING:
                return result
            stderr_fd = self._stderr_fd
            if stderr_fd is None:
                _bounded_pause(checked_wait)
            else:
                try:
                    readable, _ = _bounded_select(
                        (stderr_fd,),
                        (),
                        checked_wait,
                    )
                    if stderr_fd in readable:
                        self._drain_stderr_for_reap_locked()
                except BaseException:
                    self._stderr_overflow = True
                    try:
                        self._close_stderr_locked()
                    except BaseException:
                        pass
            return self._waitpid_nohang_locked()

    @_return_pending_when_busy
    def close_pipes(self, *, max_wait_ns: int) -> object:
        require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        close_failed = False
        with self._lock:
            if self._pipe_close_uncertain:
                _raise_process_error("resolver helper IPC 关闭结果不确定。")
            for attribute in ("_stdin_fd", "_stdout_fd", "_stderr_fd"):
                fd = getattr(self, attribute)
                if fd is None:
                    continue
                try:
                    os.close(fd)
                    setattr(self, attribute, None)
                except BaseException:
                    self._pipe_close_uncertain = True
                    close_failed = True
                    break
            while not close_failed and self._child_fds:
                fd = self._child_fds[-1]
                try:
                    os.close(fd)
                    self._child_fds.pop()
                except BaseException:
                    self._pipe_close_uncertain = True
                    close_failed = True
                    break
            if self._pipe_close_uncertain:
                close_failed = True
        if close_failed:
            _raise_process_error("resolver helper pipe 关闭结果不确定。")
        return COMPLETE

    def _locally_terminal(self) -> bool:
        try:
            with self._lock:
                return (
                    (
                        self._spawn_call_state
                        in (_SPAWN_NOT_CALLED, _SPAWN_FAILED)
                        or (
                            self._spawn_call_state == _SPAWN_SUCCEEDED
                            and self._reap_status is not None
                        )
                    )
                    and self._pid is None
                    and self._spawn_pid_cell.value <= 0
                    and self._wait_call_state
                    in (_WAIT_NOT_CALLED, _WAIT_COMPLETED)
                    and self._waited_status is None
                    and self._stdin_fd is None
                    and self._stdout_fd is None
                    and self._stderr_fd is None
                    and not self._child_fds
                    and not self._reap_uncertain
                    and not self._pipe_close_uncertain
                )
        except _KernelBusy:
            return False


@runtime_final
class DarwinResolverProcessSpawner:
    """Strict Darwin ``HelperSpawner``; deliberately not production-wired."""

    __slots__ = ("_lock", "_recovery", "_channel_construction")

    def __init__(self) -> None:
        # Lock/slot initialization is intentionally the only construction work.
        self._lock = Lock()
        self._recovery: _DarwinResolverProcessKernel | None = None
        self._channel_construction: _ProcessChannelConstructionSlot | None = None

    def _recover_kernel(
        self,
        kernel: _DarwinResolverProcessKernel,
        *,
        max_wait_ns: int,
    ) -> bool:
        """Best effort in strict action order while preserving uncertain state."""

        # Parent copies of the child endpoints must close before reap can prove
        # stdout/stderr EOF.  This is also required when spawn succeeded but a
        # post-return PID-cache bind failed before the normal close step.
        try:
            kernel._close_child_fds_after_spawn()
        except BaseException:
            pass
        try:
            spawn_state = kernel._spawn_recovery_state()
        except BaseException:
            return False
        if spawn_state in (_SPAWN_NOT_CALLED, _SPAWN_FAILED):
            try:
                kernel.close_pipes(max_wait_ns=max_wait_ns)
            except BaseException:
                pass
            return kernel._locally_terminal()
        if spawn_state != _SPAWN_SUCCEEDED:
            # An unattested libc return may have created a child, but the PID
            # cell is not authoritative.  Retain the recovery anchor and never
            # risk wait/kill against an unrelated process.
            return False
        try:
            kernel.terminate(max_wait_ns=max_wait_ns)
        except BaseException:
            pass
        reaped = False
        try:
            reap_result = kernel.reap(max_wait_ns=max_wait_ns)
            reaped = reap_result is not PENDING
        except BaseException:
            pass
        if reaped:
            try:
                kernel.close_pipes(max_wait_ns=max_wait_ns)
            except BaseException:
                pass
        return kernel._locally_terminal()

    def _service_recovery(self, *, max_wait_ns: int) -> bool:
        kernel = self._recovery
        had_recovery = kernel is not None
        if kernel is not None and (
            kernel._locally_terminal()
            or self._recover_kernel(kernel, max_wait_ns=max_wait_ns)
        ):
            self._recovery = None
        return had_recovery

    def _service_channel_construction(self) -> bool:
        """Advance an aborted construction without ever acquiring new fds."""

        construction = self._channel_construction
        if construction is None:
            return False
        try:
            construction.close_once()
        except BaseException:
            pass
        # Keep even a terminal, reference-free tombstone.  A caller that saw an
        # interrupted construction must create a fresh spawner for a new attempt;
        # this spawner can never confuse a retry with the interrupted operation.
        return True

    @staticmethod
    def _publication_owns_kernel(
        publication: _KernelPublication,
        kernel: _DarwinResolverProcessKernel,
    ) -> bool:
        """Observe the existing ledger attachment before local recovery."""

        try:
            return publication._ledger.is_exact_kernel_attached(
                publication._owner,
                kernel,
            )
        except BaseException:
            return False

    def spawn(
        self,
        request: ResolverHelperSpawnRequest,
        *,
        publication: _KernelPublication,
        max_wait_ns: int,
    ) -> object:
        if type(request) is not ResolverHelperSpawnRequest:
            raise TypeError("request must be ResolverHelperSpawnRequest")
        if type(publication) is not _KernelPublication:
            raise TypeError("publication must be _KernelPublication")
        checked_wait = require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        frozen = _freeze_spawn_request(request)
        if sys.platform != "darwin":
            _raise_process_error("resolver helper 原生进程边界不可用。")
        if not self._lock.acquire(blocking=False):
            return PENDING
        kernel: _DarwinResolverProcessKernel | None = None
        try:
            if self._service_channel_construction():
                construction = self._channel_construction
                if construction is not None and not construction.is_terminal():
                    _raise_process_error(
                        "resolver helper IPC recovery 尚未完成。"
                    )
                _raise_process_error(
                    "resolver helper IPC 构造不可重放。"
                )
            if self._service_recovery(max_wait_ns=checked_wait):
                if self._recovery is not None:
                    _raise_process_error("resolver helper recovery 尚未完成。")
                # Do not combine prior recovery and a new spawn in one slice.
                return PENDING

            construction = _ProcessChannelConstructionSlot(
                _authority=_CHANNEL_CONSTRUCTION_AUTHORITY,
            )
            self._channel_construction = construction
            channels: _ProcessChannels | None = None
            try:
                _create_process_channels(construction)
                channels = construction.channels()
                # Allocate and anchor the complete FD owner before posix_spawn.
                kernel = _DarwinResolverProcessKernel(
                    pid=None,
                    channels=channels,
                    frozen=frozen,
                    _authority=_KERNEL_CONSTRUCTION_AUTHORITY,
                )
                self._recovery = kernel
                construction.transfer_to_kernel(channels, kernel)
                self._channel_construction = None
            except BaseException:
                kernel_anchored = kernel is not None and self._recovery is kernel
                if kernel_anchored:
                    try:
                        if (
                            channels is not None
                            and construction.owns_channels(channels)
                        ):
                            construction.transfer_to_kernel(channels, kernel)
                    except BaseException:
                        pass
                    if construction.transferred():
                        self._channel_construction = None
                        self._recover_kernel(kernel, max_wait_ns=checked_wait)
                        if kernel._locally_terminal():
                            self._recovery = None
                else:
                    try:
                        construction.close_once()
                    except BaseException:
                        pass
                _raise_process_error()

            try:
                _native_posix_spawn(frozen, channels, kernel)
            except BaseException:
                self._recover_kernel(kernel, max_wait_ns=checked_wait)
                if kernel._locally_terminal():
                    self._recovery = None
                _raise_process_error()

            try:
                kernel._close_child_fds_after_spawn()
                publication.publish(kernel)
            except BaseException:
                if self._publication_owns_kernel(publication, kernel):
                    # Ownership already linearized into the lifecycle ledger;
                    # the outer guard is now the only cleanup authority.
                    self._recovery = None
                else:
                    self._recover_kernel(kernel, max_wait_ns=checked_wait)
                    if kernel._locally_terminal():
                        self._recovery = None
                _raise_process_error()

            self._recovery = None
            return kernel
        finally:
            self._lock.release()
