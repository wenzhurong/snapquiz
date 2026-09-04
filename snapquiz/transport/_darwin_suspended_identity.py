"""Darwin-local suspended-spawn identity integration foundation.

This private W09-B2b-S2b-I2a module binds four facts for one development
Mach-O process: the child was created with ``POSIX_SPAWN_START_SUSPENDED``;
an exact ``EVFILT_PROC`` watcher was armed before resume; the suspended image
passed dynamic Security.framework validation; and the process that connected
after resume carried the exact same kernel audit token.

It deliberately does not provide a resolver operation API or production
authority.  The accepted executable and native spawn shim may be ad-hoc test
artifacts, Python still owns the signal/wait/close lifecycle windows, and no
signed application bundle manifest exists in this repository.  Those facts
remain explicit in safe metadata and prevent this foundation from being used
as the production W09 switch.
"""
from __future__ import annotations

import ctypes
from enum import Enum
import hashlib
import os
import select
import signal
import socket
import stat
import sys
from threading import Lock, RLock
import time
from typing import NamedTuple, NoReturn

from snapquiz.domain._validation import require_plain_int, runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_process_identity as _identity
from snapquiz.transport import _darwin_process_events as _events


__all__ = ()


DARWIN_SUSPENDED_IDENTITY_PROOF_SCHEMA_VERSION = (
    "snapquiz.darwin-suspended-identity-proof.v1"
)
DARWIN_SUSPENDED_IDENTITY_SCOPE = (
    "darwin_suspended_monitored_development"
)
MAX_IDENTITY_PEER_WAIT_NS = 5_000_000_000

_POSIX_SPAWN_START_SUSPENDED = 0x0080
_POSIX_SPAWN_SETSIGDEF = 0x0004
_POSIX_SPAWN_SETSIGMASK = 0x0008
_POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
_POSIX_SPAWN_FLAGS = (
    _POSIX_SPAWN_START_SUSPENDED
    | _POSIX_SPAWN_SETSIGDEF
    | _POSIX_SPAWN_SETSIGMASK
    | _POSIX_SPAWN_CLOEXEC_DEFAULT
)
_SOL_LOCAL = 0
_LOCAL_PEERTOKEN = 0x006
_PROOF_AUTHORITY = object()
_SESSION_AUTHORITY = object()
_CONSTRUCTION_OWNER_AUTHORITY = object()
_SPAWN_OUTCOME_ABI = 0x53514932
_SPAWN_OUTCOME_MAGIC = 0x5351504F


class _NativeSpawnOutcome(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("result", ctypes.c_int32),
        ("pid", ctypes.c_int32),
        ("magic", ctypes.c_uint32),
    )


class _SuspendedIdentityBoundaryFailure(Exception):
    """Content-free internal failure marker."""


class _SessionState(str, Enum):
    ACTIVE = "active"
    POISONED = "poisoned"
    TERMINAL = "terminal"


class _SpawnPublicationState(str, Enum):
    NEW = "new"
    IN_FLIGHT = "in_flight"
    FAILED = "failed"
    SUCCEEDED = "succeeded"
    UNCERTAIN = "uncertain"


class _SuspendedSpawnPublication:
    """Pre-published recovery cell for the Python spawn boundary.

    The outer owner creates and retains this cell before entering the native
    shim.  A conforming shim commits the spawn result before returning, which
    lets the outer owner recover a created PID after a Python-side interruption.
    The caller-supplied shim is not a production trust anchor, so this class
    records an observed mechanism rather than attesting its implementation.
    """

    __slots__ = ("outcome", "state")

    def __init__(self) -> None:
        self.outcome = _NativeSpawnOutcome(
            abi=_SPAWN_OUTCOME_ABI,
            state=0,
            result=-(1 << 31),
            pid=0,
            magic=0,
        )
        self.state = _SpawnPublicationState.NEW

    def begin(self) -> None:
        if self.state is not _SpawnPublicationState.NEW:
            raise _SuspendedIdentityBoundaryFailure
        self.state = _SpawnPublicationState.IN_FLIGHT

    def _refresh_native_commit(self) -> bool:
        outcome = self.outcome
        if (
            outcome.abi != _SPAWN_OUTCOME_ABI
            or outcome.state != 2
            or outcome.magic != _SPAWN_OUTCOME_MAGIC
            or outcome.result < 0
        ):
            return False
        if outcome.result == 0 and outcome.pid > 0:
            self.state = _SpawnPublicationState.SUCCEEDED
            return True
        if outcome.result != 0 and outcome.pid == 0:
            self.state = _SpawnPublicationState.FAILED
            return True
        return False

    def commit_result(self, wrapper_result: object) -> None:
        if self.state is not _SpawnPublicationState.IN_FLIGHT:
            raise _SuspendedIdentityBoundaryFailure
        if type(wrapper_result) is not int or wrapper_result != 0:
            self.state = _SpawnPublicationState.UNCERTAIN
            raise _SuspendedIdentityBoundaryFailure
        if not self._refresh_native_commit():
            self.state = _SpawnPublicationState.UNCERTAIN
            raise _SuspendedIdentityBoundaryFailure
        if self.state is _SpawnPublicationState.FAILED:
            raise _SuspendedIdentityBoundaryFailure

    def mark_uncertain_if_inflight(self) -> None:
        if self.state is _SpawnPublicationState.IN_FLIGHT:
            if not self._refresh_native_commit():
                self.state = _SpawnPublicationState.UNCERTAIN

    def recover_committed_pid(self) -> int | None:
        if (
            self.state is _SpawnPublicationState.SUCCEEDED
            and type(self.outcome.pid) is int
            and self.outcome.pid > 0
        ):
            return self.outcome.pid
        return None


def _suspended_identity_error(
    safe_message: str = "resolver supervisor suspended identity 不可用。",
) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_supervisor_suspended_identity",
        retryable=False,
        safe_message=safe_message,
    )


def _raise_suspended_identity_error(
    safe_message: str = "resolver supervisor suspended identity 不可用。",
) -> NoReturn:
    error = _suspended_identity_error(safe_message)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _require_wait_ns(value: object, name: str, *, minimum: int) -> int:
    checked = require_plain_int(value, name, minimum=minimum)
    if checked > MAX_IDENTITY_PEER_WAIT_NS:
        raise ValueError(f"{name} exceeds the identity wait limit")
    return checked


def _require_socket_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or len(os.fsencode(value)) >= 104
    ):
        raise ValueError("socket_path must be a short normalized absolute path")
    return value


def _require_fixture_mode(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value not in (
        "exit-after-connect",
        "delayed-exec-after-connect",
        "delayed-fork-exec-writer",
        "exec-after-connect",
        "fork-exec-writer",
    ):
        raise ValueError("fixture_mode is invalid")
    return value


def _require_constructor_sentinel(value: object) -> str | None:
    if value is None:
        return None
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or len(os.fsencode(value)) > 1_024
    ):
        raise ValueError("constructor_sentinel must be a normalized path")
    return value


def _require_native_shim_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or len(os.fsencode(value)) > 4_095
    ):
        raise ValueError("native_spawn_shim must be a normalized absolute path")
    return value


def _observe_native_shim(path: str) -> Digest256:
    try:
        if os.path.realpath(path) != path:
            raise _SuspendedIdentityBoundaryFailure
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > 2 * 1024 * 1024
        ):
            raise _SuspendedIdentityBoundaryFailure
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or opened.st_mtime_ns != before.st_mtime_ns
            ):
                raise _SuspendedIdentityBoundaryFailure
            hasher = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 2 * 1024 * 1024:
                    raise _SuspendedIdentityBoundaryFailure
                hasher.update(chunk)
            if total != opened.st_size:
                raise _SuspendedIdentityBoundaryFailure
            return Digest256(hasher.hexdigest())
        finally:
            os.close(descriptor)
    except _SuspendedIdentityBoundaryFailure:
        raise
    except BaseException:
        raise _SuspendedIdentityBoundaryFailure from None


def _validate_listener(listener: object, socket_path: str) -> socket.socket:
    if type(listener) is not socket.socket:
        raise TypeError("listener must be an exact socket")
    if (
        listener.family != socket.AF_UNIX
        or listener.type != socket.SOCK_STREAM
        or listener.fileno() < 0
        or listener.getsockname() != socket_path
    ):
        raise ValueError("listener does not match the private socket path")
    if os.get_inheritable(listener.fileno()):
        raise ValueError("listener must be non-inheritable")
    socket_stat = os.lstat(socket_path)
    if (
        not stat.S_ISSOCK(socket_stat.st_mode)
        or socket_stat.st_uid != os.geteuid()
        or socket_stat.st_mode & 0o077
    ):
        raise ValueError("listener path permissions are invalid")
    return listener


def _configure_spawn_functions(libc: object) -> tuple[object, ...]:
    pointer_pointer = ctypes.POINTER(ctypes.c_void_p)
    signal_set_pointer = ctypes.POINTER(ctypes.c_uint32)
    attr_init = libc.posix_spawnattr_init
    attr_destroy = libc.posix_spawnattr_destroy
    attr_setflags = libc.posix_spawnattr_setflags
    attr_setsigdefault = libc.posix_spawnattr_setsigdefault
    attr_setsigmask = libc.posix_spawnattr_setsigmask
    sigemptyset = libc.sigemptyset
    sigfillset = libc.sigfillset
    sigdelset = libc.sigdelset
    attr_init.argtypes = (pointer_pointer,)
    attr_destroy.argtypes = (pointer_pointer,)
    attr_setflags.argtypes = (pointer_pointer, ctypes.c_short)
    attr_setsigdefault.argtypes = (pointer_pointer, signal_set_pointer)
    attr_setsigmask.argtypes = (pointer_pointer, signal_set_pointer)
    sigemptyset.argtypes = (signal_set_pointer,)
    sigfillset.argtypes = (signal_set_pointer,)
    sigdelset.argtypes = (signal_set_pointer, ctypes.c_int)
    for function in (
        attr_init,
        attr_destroy,
        attr_setflags,
        attr_setsigdefault,
        attr_setsigmask,
        sigemptyset,
        sigfillset,
        sigdelset,
    ):
        function.restype = ctypes.c_int
    return (
        attr_init,
        attr_destroy,
        attr_setflags,
        attr_setsigdefault,
        attr_setsigmask,
        sigemptyset,
        sigfillset,
        sigdelset,
    )


def _load_spawn_shim(path: str) -> object:
    try:
        library = ctypes.CDLL(path, use_errno=True)
        function = library.sq_posix_spawn_publish
        function.argtypes = (
            ctypes.POINTER(_NativeSpawnOutcome),
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
        )
        function.restype = ctypes.c_int32
        return function
    except BaseException:
        raise _SuspendedIdentityBoundaryFailure from None


def _spawn_suspended(
    *,
    executable: str,
    socket_path: str,
    fixture_mode: str | None,
    constructor_sentinel: str | None,
    publication: _SuspendedSpawnPublication,
    native_spawn_shim: str,
) -> int:
    if type(publication) is not _SuspendedSpawnPublication:
        raise TypeError("publication must be SuspendedSpawnPublication")
    attributes = ctypes.c_void_p()
    initialized = False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        (
            attr_init,
            attr_destroy,
            attr_setflags,
            attr_setsigdefault,
            attr_setsigmask,
            sigemptyset,
            sigfillset,
            sigdelset,
        ) = _configure_spawn_functions(libc)
        posix_spawn_publish = _load_spawn_shim(native_spawn_shim)
        if attr_init(ctypes.byref(attributes)) != 0:
            raise _SuspendedIdentityBoundaryFailure
        initialized = True
        if (
            attr_setflags(
                ctypes.byref(attributes),
                ctypes.c_short(_POSIX_SPAWN_FLAGS),
            )
            != 0
        ):
            raise _SuspendedIdentityBoundaryFailure
        empty_signal_mask = ctypes.c_uint32(0)
        default_signal_set = ctypes.c_uint32(0)
        if (
            sigemptyset(ctypes.byref(empty_signal_mask)) != 0
            or sigfillset(ctypes.byref(default_signal_set)) != 0
            or sigdelset(ctypes.byref(default_signal_set), signal.SIGKILL) != 0
            or sigdelset(ctypes.byref(default_signal_set), signal.SIGSTOP) != 0
            or attr_setsigmask(
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
            raise _SuspendedIdentityBoundaryFailure

        argv_text = (executable, socket_path) + (
            () if fixture_mode is None else (fixture_mode,)
        )
        argv_bytes = tuple(os.fsencode(item) for item in argv_text)
        environment_text = ["LANG=C", "LC_ALL=C"]
        if constructor_sentinel is not None:
            environment_text.append(
                "SNAPQUIZ_I2_CONSTRUCTOR_SENTINEL=" + constructor_sentinel
            )
        environment_bytes = tuple(item.encode("ascii") for item in environment_text)
        if any(not item or b"\x00" in item for item in argv_bytes):
            raise _SuspendedIdentityBoundaryFailure
        argv_type = ctypes.c_char_p * (len(argv_bytes) + 1)
        environment_type = ctypes.c_char_p * (len(environment_bytes) + 1)
        argv = argv_type(*argv_bytes, None)
        environment = environment_type(*environment_bytes, None)
        publication.begin()
        result = posix_spawn_publish(
            ctypes.byref(publication.outcome),
            os.fsencode(executable),
            None,
            ctypes.byref(attributes),
            argv,
            environment,
        )
        publication.commit_result(result)
        return publication.outcome.pid
    except _SuspendedIdentityBoundaryFailure:
        publication.mark_uncertain_if_inflight()
        raise
    except BaseException:
        publication.mark_uncertain_if_inflight()
        raise _SuspendedIdentityBoundaryFailure from None
    finally:
        if initialized:
            try:
                result = attr_destroy(ctypes.byref(attributes))
            except BaseException:
                raise _SuspendedIdentityBoundaryFailure from None
            if result != 0:
                raise _SuspendedIdentityBoundaryFailure


def _wait_for_peer(
    *,
    listener: socket.socket,
    watcher: object,
    max_wait_ns: int,
    publication: object,
) -> None:
    required = ("peer_for_listener", "publish_peer", "owns_peer")
    if not all(callable(getattr(publication, name, None)) for name in required):
        raise TypeError("peer publication is invalid")
    try:
        existing = publication.peer_for_listener(listener)
    except BaseException:
        raise _SuspendedIdentityBoundaryFailure from None
    if existing is not None:
        if type(existing) is not socket.socket or existing.fileno() < 0:
            raise _SuspendedIdentityBoundaryFailure
        return None

    deadline = time.monotonic_ns() + max_wait_ns
    while True:
        watcher.require_quiet(max_wait_ns=0)
        remaining = deadline - time.monotonic_ns()
        if remaining <= 0:
            raise _SuspendedIdentityBoundaryFailure
        try:
            readable, _, _ = select.select(
                (listener,),
                (),
                (),
                min(remaining, 50_000_000) / 1_000_000_000,
            )
        except InterruptedError:
            continue
        except BaseException:
            raise _SuspendedIdentityBoundaryFailure from None
        watcher.require_quiet(max_wait_ns=0)
        if not readable:
            continue
        try:
            peer, address = listener.accept()
        except BlockingIOError:
            continue
        except BaseException:
            raise _SuspendedIdentityBoundaryFailure from None
        if address not in ("", None):
            peer.close()
            raise _SuspendedIdentityBoundaryFailure
        try:
            peer.set_inheritable(False)
            peer.setblocking(False)
            publication.publish_peer(peer)
            # The caller-held publication remains the owner across this return.
            return None
        except BaseException:
            try:
                published = publication.owns_peer(peer)
            except BaseException:
                published = False
            if not published:
                try:
                    peer.close()
                except BaseException:
                    pass
            raise _SuspendedIdentityBoundaryFailure from None


def _pre_identity_payload(value: object) -> dict[str, object]:
    return {
        "code_directory_hash": value.code_directory_hash,
        "code_identifier": value.code_identifier,
        "dynamic_code_status": value.dynamic_code_status,
        "executable": value.executable,
        "process_id": value.process_id,
        "static_code_flags": value.static_code_flags,
        "team_identifier": value.team_identifier,
    }


@runtime_final
class _DarwinMonitoredIdentityProof:
    """Immutable proof of the successful I2a publication boundary."""

    __slots__ = (
        "process_id",
        "process_version",
        "policy_digest",
        "pre_resume_identity_digest",
        "connection_identity_digest",
        "watch_registration_digest",
        "native_spawn_shim_digest",
        "proof_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        process_id: int,
        process_version: int,
        policy_digest: Digest256,
        pre_resume_identity_digest: Digest256,
        connection_identity_digest: Digest256,
        watch_registration_digest: Digest256,
        native_spawn_shim_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PROOF_AUTHORITY:
            raise TypeError("monitored identity proof requires its factory")
        values = {
            "process_id": require_plain_int(process_id, "process_id", minimum=1),
            "process_version": require_plain_int(
                process_version,
                "process_version",
                minimum=1,
            ),
            "policy_digest": policy_digest,
            "pre_resume_identity_digest": pre_resume_identity_digest,
            "connection_identity_digest": connection_identity_digest,
            "watch_registration_digest": watch_registration_digest,
            "native_spawn_shim_digest": native_spawn_shim_digest,
        }
        if any(type(value) is not Digest256 for value in tuple(values.values())[2:]):
            raise TypeError("monitored identity proof digests are invalid")
        selected = digest256(
            "DarwinMonitoredIdentityProof",
            DARWIN_SUSPENDED_IDENTITY_PROOF_SCHEMA_VERSION,
            {
                **values,
                "continuous_monitor_armed_at_publication": True,
                "identity_scope": DARWIN_SUSPENDED_IDENTITY_SCOPE,
                "native_atomic_owner_attested": False,
                "native_atomic_spawn_publication_attested": False,
                "native_atomic_spawn_publication_observed": True,
                "native_spawn_shim_trusted": False,
                "production_bundle_attested": False,
                "resume_used_audit_token": True,
                "spawn_start_suspended_requested": True,
                "spawn_started_suspended_attested": False,
            },
        )
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "proof_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinMonitoredIdentityProof is immutable")

    def __copy__(self) -> "_DarwinMonitoredIdentityProof":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_DarwinMonitoredIdentityProof":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("DarwinMonitoredIdentityProof cannot be serialized")

    def validate_integrity(self) -> None:
        values = {
            "process_id": require_plain_int(self.process_id, "process_id", minimum=1),
            "process_version": require_plain_int(
                self.process_version,
                "process_version",
                minimum=1,
            ),
            "policy_digest": self.policy_digest,
            "pre_resume_identity_digest": self.pre_resume_identity_digest,
            "connection_identity_digest": self.connection_identity_digest,
            "watch_registration_digest": self.watch_registration_digest,
            "native_spawn_shim_digest": self.native_spawn_shim_digest,
        }
        if any(type(value) is not Digest256 for value in tuple(values.values())[2:]):
            raise ValueError("monitored identity proof digest type failed")
        selected = digest256(
            "DarwinMonitoredIdentityProof",
            DARWIN_SUSPENDED_IDENTITY_PROOF_SCHEMA_VERSION,
            {
                **values,
                "continuous_monitor_armed_at_publication": True,
                "identity_scope": DARWIN_SUSPENDED_IDENTITY_SCOPE,
                "native_atomic_owner_attested": False,
                "native_atomic_spawn_publication_attested": False,
                "native_atomic_spawn_publication_observed": True,
                "native_spawn_shim_trusted": False,
                "production_bundle_attested": False,
                "resume_used_audit_token": True,
                "spawn_start_suspended_requested": True,
                "spawn_started_suspended_attested": False,
            },
        )
        if (
            type(self.proof_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.proof_digest != selected
            or self._issued_digest != selected
        ):
            raise ValueError("monitored identity proof integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "connection_peer_identity_attested": True,
            "continuous_monitor_armed_at_publication": True,
            "identity_scope": DARWIN_SUSPENDED_IDENTITY_SCOPE,
            "native_atomic_owner_attested": False,
            "native_atomic_spawn_publication_attested": False,
            "native_atomic_spawn_publication_observed": True,
            "native_spawn_shim_trusted": False,
            "process_id": self.process_id,
            "process_version": self.process_version,
            "production_bundle_attested": False,
            "proof_digest": str(self.proof_digest),
            "resume_used_audit_token": True,
            "spawn_start_suspended_requested": True,
            "spawn_started_suspended_attested": False,
            "startup_order_attested": False,
            "transport_available": False,
        }


@runtime_final
class _LocalDarwinMonitoredIdentitySession:
    """Own the peer, watcher, PID generation, and exact reap boundary."""

    __slots__ = (
        "proof",
        "_lock",
        "_watcher",
        "_peer",
        "_raw_audit_token",
        "_pid",
        "_state",
        "_kill_attempted",
        "_wait_status",
    )

    def __init__(
        self,
        *,
        proof: _DarwinMonitoredIdentityProof,
        watcher: object,
        peer: socket.socket,
        raw_audit_token: bytes,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _SESSION_AUTHORITY:
            raise TypeError("monitored identity session requires its factory")
        proof.validate_integrity()
        object.__setattr__(self, "proof", proof)
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_watcher", watcher)
        object.__setattr__(self, "_peer", peer)
        object.__setattr__(self, "_raw_audit_token", raw_audit_token)
        object.__setattr__(self, "_pid", proof.process_id)
        object.__setattr__(self, "_state", _SessionState.ACTIVE)
        object.__setattr__(self, "_kill_attempted", False)
        object.__setattr__(self, "_wait_status", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("LocalDarwinMonitoredIdentitySession is immutable")

    def __reduce__(self):
        raise TypeError("LocalDarwinMonitoredIdentitySession cannot be serialized")

    def _poison_locked(self) -> None:
        object.__setattr__(self, "_state", _SessionState.POISONED)

    def require_current(self, *, max_wait_ns: int = 0) -> None:
        checked_wait = _require_wait_ns(max_wait_ns, "max_wait_ns", minimum=0)
        with self._lock:
            if self._state is not _SessionState.ACTIVE:
                _raise_suspended_identity_error(
                    "resolver supervisor monitored identity 已失效。"
                )
            try:
                self._watcher.require_quiet(max_wait_ns=checked_wait)
                waited_pid, status = os.waitpid(self._pid, os.WNOHANG)
                if waited_pid != 0:
                    object.__setattr__(self, "_wait_status", status)
                    self._poison_locked()
                    raise _SuspendedIdentityBoundaryFailure
                self._watcher.require_quiet(max_wait_ns=0)
            except BaseException:
                self._poison_locked()
                _raise_suspended_identity_error(
                    "resolver supervisor monitored identity 已失效。"
                )

    def shutdown(self, *, max_wait_ns: int) -> bool:
        checked_wait = _require_wait_ns(max_wait_ns, "max_wait_ns", minimum=1)
        with self._lock:
            if self._state is _SessionState.TERMINAL:
                return True
            peer = self._peer
            if peer is not None:
                object.__setattr__(self, "_peer", None)
                try:
                    peer.close()
                except BaseException:
                    self._poison_locked()
                    return False
            deadline = time.monotonic_ns() + checked_wait
            while self._wait_status is None and time.monotonic_ns() < deadline:
                try:
                    waited_pid, status = os.waitpid(self._pid, os.WNOHANG)
                except BaseException:
                    self._poison_locked()
                    return False
                if waited_pid == self._pid:
                    object.__setattr__(self, "_wait_status", status)
                    break
                if waited_pid != 0:
                    self._poison_locked()
                    return False
                time.sleep(0.005)
            if self._wait_status is None:
                if self._kill_attempted:
                    return False
                object.__setattr__(self, "_kill_attempted", True)
                try:
                    _identity._signal_process_with_audit_token(
                        raw_audit_token=self._raw_audit_token,
                        signal_number=signal.SIGKILL,
                    )
                except BaseException:
                    self._poison_locked()
                    return False
                while time.monotonic_ns() < deadline:
                    try:
                        waited_pid, status = os.waitpid(self._pid, os.WNOHANG)
                    except BaseException:
                        self._poison_locked()
                        return False
                    if waited_pid == self._pid:
                        object.__setattr__(self, "_wait_status", status)
                        break
                    if waited_pid != 0:
                        self._poison_locked()
                        return False
                    time.sleep(0.005)
            if self._wait_status is None:
                self._poison_locked()
                return False
            if not self._watcher.close():
                self._poison_locked()
                return False
            object.__setattr__(self, "_raw_audit_token", b"")
            object.__setattr__(self, "_pid", 0)
            object.__setattr__(self, "_state", _SessionState.TERMINAL)
            return True

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            proof = self.proof.safe_metadata()
            watcher = self._watcher.safe_metadata()
            return {
                **proof,
                "identity_change_monitor_armed": watcher[
                    "process_event_watch_active"
                ],
                "operation_api_available": False,
                "session_state": self._state.value,
                "transport_available": False,
            }


class _MonitoredIdentityConstructionBinding(NamedTuple):
    listener: socket.socket
    socket_path: str
    policy_digest: Digest256
    max_peer_wait_ns: int
    fixture_mode: str | None
    constructor_sentinel: str | None
    native_spawn_shim: str


class _MonitoredIdentityConstructionSlot:
    """Durable owner of the watcher -> peer -> session publication chain."""

    __slots__ = (
        "_binding",
        "_state",
        "_pid",
        "_raw_audit_token",
        "_watcher",
        "_peer",
        "_session",
        "_lock",
        "_cleanup_lock",
    )

    def __init__(self) -> None:
        self._binding: _MonitoredIdentityConstructionBinding | None = None
        self._state = "empty"
        self._pid: int | None = None
        self._raw_audit_token: bytes | None = None
        self._watcher: object | None = None
        self._peer: socket.socket | None = None
        self._session: _LocalDarwinMonitoredIdentitySession | None = None
        self._lock = RLock()
        self._cleanup_lock = Lock()

    def claim_binding(self, binding: _MonitoredIdentityConstructionBinding) -> str:
        if type(binding) is not _MonitoredIdentityConstructionBinding:
            raise TypeError("monitored identity construction binding is invalid")
        with self._lock:
            if self._state == "empty":
                self._binding = binding
                self._state = "constructing"
                return "construct"
            if self._binding != binding:
                raise ValueError("monitored identity construction binding changed")
            if self._state == "session" and self._session is not None:
                return "session"
            if self._state == "transferred":
                raise ValueError("monitored identity session was already transferred")
            return "recover"

    def publish_process(self, process_id: int) -> None:
        pid = require_plain_int(process_id, "process_id", minimum=1)
        with self._lock:
            if self._state not in ("constructing", "watcher", "peer"):
                raise ValueError("monitored identity process publication is invalid")
            if self._pid is None:
                self._pid = pid
            elif self._pid != pid:
                raise ValueError("monitored identity process changed")

    def publish_audit_token(self, raw_audit_token: bytes) -> None:
        if type(raw_audit_token) is not bytes or not raw_audit_token:
            raise TypeError("monitored identity audit token is invalid")
        with self._lock:
            if self._pid is None or self._state not in (
                "constructing",
                "watcher",
                "peer",
            ):
                raise ValueError("monitored identity process is unavailable")
            if self._raw_audit_token is None:
                self._raw_audit_token = raw_audit_token
            elif self._raw_audit_token != raw_audit_token:
                raise ValueError("monitored identity audit token changed")

    def watcher_for_process(self, process_id: int):
        pid = require_plain_int(process_id, "process_id", minimum=1)
        with self._lock:
            if self._pid is not None and self._pid != pid:
                raise ValueError("monitored identity watcher process changed")
            return self._watcher

    def publish_watcher(self, watcher: object) -> None:
        if type(watcher) is not _events._DarwinProcessEventWatcher:
            raise TypeError("monitored identity watcher is invalid")
        with self._lock:
            if (
                self._state != "constructing"
                or self._pid is None
                or watcher.process_id != self._pid
                or self._watcher is not None
            ):
                raise ValueError("monitored identity watcher publication is invalid")
            self._watcher = watcher
            self._state = "watcher"

    def owns_watcher(self, watcher: object) -> bool:
        with self._lock:
            return self._watcher is watcher

    def watcher(self) -> object:
        with self._lock:
            if self._watcher is None or self._state not in (
                "watcher",
                "peer",
                "session",
            ):
                raise ValueError("monitored identity watcher is unavailable")
            return self._watcher

    def peer_for_listener(self, listener: socket.socket):
        with self._lock:
            if self._binding is None or self._binding.listener is not listener:
                raise ValueError("monitored identity listener changed")
            return self._peer

    def publish_peer(self, peer: socket.socket) -> None:
        if type(peer) is not socket.socket or peer.fileno() < 0:
            raise TypeError("monitored identity peer is invalid")
        with self._lock:
            if self._state != "watcher" or self._peer is not None:
                raise ValueError("monitored identity peer publication is invalid")
            self._peer = peer
            self._state = "peer"

    def owns_peer(self, peer: object) -> bool:
        with self._lock:
            return self._peer is peer

    def peer(self) -> socket.socket:
        with self._lock:
            if self._state not in ("peer", "session") or self._peer is None:
                raise ValueError("monitored identity peer is unavailable")
            return self._peer

    def publish_session(
        self,
        session: _LocalDarwinMonitoredIdentitySession,
    ) -> None:
        if type(session) is not _LocalDarwinMonitoredIdentitySession:
            raise TypeError("monitored identity session is invalid")
        with self._lock:
            if (
                self._state != "peer"
                or self._pid is None
                or self._watcher is None
                or self._peer is None
                or session._pid != self._pid
                or session._watcher is not self._watcher
                or session._peer is not self._peer
                or self._session is not None
            ):
                raise ValueError("monitored identity session publication is invalid")
            self._session = session
            self._state = "session"

    def session(self) -> _LocalDarwinMonitoredIdentitySession:
        with self._lock:
            if self._state != "session" or self._session is None:
                raise ValueError("monitored identity session is unavailable")
            return self._session

    def transfer_session(
        self,
        session: _LocalDarwinMonitoredIdentitySession,
    ) -> None:
        with self._lock:
            if self._state != "session" or self._session is not session:
                raise ValueError("monitored identity session owner changed")
            self._state = "transferred"
            self._binding = None
            self._pid = None
            self._raw_audit_token = None
            self._watcher = None
            self._peer = None
            self._session = None

    def cleanup(self, *, max_wait_ns: int) -> bool:
        """Clean only identities already published into this exact slot."""

        with self._cleanup_lock:
            with self._lock:
                if self._state == "failed_terminal":
                    return True
                if self._state in ("empty", "transferred"):
                    return self._state == "transferred"
                self._state = "cleanup"
                session = self._session
                pid = self._pid
                raw_audit_token = self._raw_audit_token
                peer = self._peer
                watcher = self._watcher

            if session is not None:
                try:
                    terminal = session.shutdown(max_wait_ns=max_wait_ns)
                except BaseException:
                    terminal = session._state is _SessionState.TERMINAL
            else:
                terminal = _cleanup_failed_start(
                    pid=pid,
                    raw_audit_token=raw_audit_token,
                    peer=peer,
                    watcher=watcher,
                    max_wait_ns=max_wait_ns,
                )
            if terminal:
                with self._lock:
                    self._state = "failed_terminal"
                    self._pid = None
                    self._raw_audit_token = None
                    self._watcher = None
                    self._peer = None
                    self._session = None
            return terminal

    def has_retained_resource(self) -> bool:
        with self._lock:
            return any(
                resource is not None
                for resource in (self._watcher, self._peer, self._session)
            )


class _MonitoredIdentityConstructionOwner:
    """Caller-preheld facade that survives every factory return event."""

    __slots__ = ("_slot",)

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _CONSTRUCTION_OWNER_AUTHORITY:
            raise TypeError("monitored identity owner requires its factory")
        self._slot = _MonitoredIdentityConstructionSlot()

    def session(self) -> _LocalDarwinMonitoredIdentitySession:
        return self._slot.session()

    def transfer_session(
        self,
        session: _LocalDarwinMonitoredIdentitySession,
    ) -> None:
        self._slot.transfer_session(session)

    def cleanup(self, *, max_wait_ns: int) -> bool:
        return self._slot.cleanup(max_wait_ns=max_wait_ns)


def _new_monitored_identity_construction_owner(
) -> _MonitoredIdentityConstructionOwner:
    return _MonitoredIdentityConstructionOwner(
        _authority=_CONSTRUCTION_OWNER_AUTHORITY,
    )


def _cleanup_failed_start(
    *,
    pid: int | None,
    raw_audit_token: bytes | None,
    peer: socket.socket | None,
    watcher: object | None,
    max_wait_ns: int,
) -> bool:
    peer_closed = peer is None
    if peer is not None:
        try:
            peer.close()
            peer_closed = peer.fileno() == -1
        except BaseException:
            peer_closed = False
    process_terminal = not (type(pid) is int and pid > 0)
    if type(pid) is int and pid > 0:
        try:
            if raw_audit_token is not None:
                _identity._signal_process_with_audit_token(
                    raw_audit_token=raw_audit_token,
                    signal_number=signal.SIGKILL,
                )
            else:
                os.kill(pid, signal.SIGKILL)
        except BaseException:
            pass
        deadline = time.monotonic_ns() + max_wait_ns
        while time.monotonic_ns() < deadline:
            try:
                waited_pid, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                process_terminal = True
                break
            except BaseException:
                break
            if waited_pid == pid:
                process_terminal = True
                break
            if waited_pid != 0:
                break
            time.sleep(0.005)
    watcher_closed = watcher is None
    if watcher is not None:
        try:
            watcher_closed = watcher.close() is True
        except BaseException:
            watcher_closed = False
    return peer_closed and process_terminal and watcher_closed


def _start_local_darwin_monitored_identity(
    *,
    construction_owner: _MonitoredIdentityConstructionOwner,
    listener: socket.socket,
    socket_path: str,
    policy: _identity._LocalDarwinProcessIdentityPolicy,
    max_peer_wait_ns: int,
    fixture_mode: str | None = None,
    constructor_sentinel: str | None = None,
    native_spawn_shim: str,
) -> None:
    """Start and publish one development Mach-O identity session."""

    if type(construction_owner) is not _MonitoredIdentityConstructionOwner:
        raise TypeError("construction_owner must be MonitoredIdentityConstructionOwner")
    if type(policy) is not _identity._LocalDarwinProcessIdentityPolicy:
        raise TypeError("policy must be LocalDarwinProcessIdentityPolicy")
    checked_path = _require_socket_path(socket_path)
    checked_mode = _require_fixture_mode(fixture_mode)
    checked_sentinel = _require_constructor_sentinel(constructor_sentinel)
    checked_shim = _require_native_shim_path(native_spawn_shim)
    checked_wait = _require_wait_ns(
        max_peer_wait_ns,
        "max_peer_wait_ns",
        minimum=1,
    )
    _validate_listener(listener, checked_path)
    try:
        policy.validate_integrity()
    except (AttributeError, TypeError, ValueError):
        _raise_suspended_identity_error()
    if sys.platform != "darwin":
        _raise_suspended_identity_error()
    construction = construction_owner._slot
    binding = _MonitoredIdentityConstructionBinding(
        listener=listener,
        socket_path=checked_path,
        policy_digest=policy.policy_digest,
        max_peer_wait_ns=checked_wait,
        fixture_mode=checked_mode,
        constructor_sentinel=checked_sentinel,
        native_spawn_shim=checked_shim,
    )
    try:
        disposition = construction.claim_binding(binding)
    except BaseException:
        _raise_suspended_identity_error()
    if disposition == "session":
        return None
    if disposition == "recover":
        try:
            construction.cleanup(max_wait_ns=checked_wait)
        except BaseException:
            pass
        _raise_suspended_identity_error(
            "resolver supervisor monitored identity 构造不可重放。"
        )
    if disposition != "construct":
        _raise_suspended_identity_error()
    try:
        native_spawn_shim_digest = _observe_native_shim(checked_shim)
    except BaseException:
        _raise_suspended_identity_error()

    pid: int | None = None
    spawn_publication = _SuspendedSpawnPublication()
    raw_audit_token: bytes | None = None
    watcher: object | None = None
    peer: socket.socket | None = None
    try:
        pid = _spawn_suspended(
            executable=policy.expected_executable,
            socket_path=checked_path,
            fixture_mode=checked_mode,
            constructor_sentinel=checked_sentinel,
            publication=spawn_publication,
            native_spawn_shim=checked_shim,
        )
        construction.publish_process(pid)
        _events._new_darwin_process_event_watcher(
            pid,
            publication=construction,
        )
        watcher = construction.watcher()
        watcher.require_quiet(max_wait_ns=0)
        raw_audit_token = _identity._copy_process_audit_token(
            expected_process_id=pid,
        )
        construction.publish_audit_token(raw_audit_token)
        pre_identity = _identity._observe_running_code_by_pid(
            expected_process_id=pid,
            policy=policy,
        )
        watcher.require_quiet(max_wait_ns=0)
        _identity._signal_process_with_audit_token(
            raw_audit_token=raw_audit_token,
            signal_number=signal.SIGCONT,
        )
        _wait_for_peer(
            listener=listener,
            watcher=watcher,
            max_wait_ns=checked_wait,
            publication=construction,
        )
        peer = construction.peer()
        peer_token = peer.getsockopt(
            _SOL_LOCAL,
            _LOCAL_PEERTOKEN,
            len(raw_audit_token),
        )
        if peer_token != raw_audit_token:
            raise _SuspendedIdentityBoundaryFailure
        connection = _identity._attest_darwin_connection_peer(
            peer_socket=peer,
            expected_process_id=pid,
            policy=policy,
        )
        if (
            connection.process_id != pre_identity.process_id
            or connection.executable != pre_identity.executable
            or connection.code_identifier != pre_identity.code_identifier
            or connection.team_identifier != pre_identity.team_identifier
            or connection.code_directory_hash
            != pre_identity.code_directory_hash
            or connection.static_code_flags != pre_identity.static_code_flags
        ):
            raise _SuspendedIdentityBoundaryFailure
        watcher.require_quiet(max_wait_ns=0)
        pre_digest = digest256(
            "DarwinPreResumeRunningCode",
            DARWIN_SUSPENDED_IDENTITY_PROOF_SCHEMA_VERSION,
            _pre_identity_payload(pre_identity),
        )
        proof = _DarwinMonitoredIdentityProof(
            process_id=pid,
            process_version=connection.process_version,
            policy_digest=policy.policy_digest,
            pre_resume_identity_digest=pre_digest,
            connection_identity_digest=connection.attestation_digest,
            watch_registration_digest=watcher.registration_digest,
            native_spawn_shim_digest=native_spawn_shim_digest,
            _authority=_PROOF_AUTHORITY,
        )
        session = _LocalDarwinMonitoredIdentitySession(
            proof=proof,
            watcher=watcher,
            peer=peer,
            raw_audit_token=raw_audit_token,
            _authority=_SESSION_AUTHORITY,
        )
        construction.publish_session(session)
        session.require_current(max_wait_ns=0)
        # The caller-held owner retains the exact session across RETURN.  The
        # caller may then retrieve and explicitly transfer that same identity.
        return None
    except BaseException:
        committed_pid = spawn_publication.recover_committed_pid()
        if pid is None and committed_pid is not None:
            pid = committed_pid
        if pid is not None:
            try:
                construction.publish_process(pid)
            except BaseException:
                pass
        if raw_audit_token is not None:
            try:
                construction.publish_audit_token(raw_audit_token)
            except BaseException:
                pass
        try:
            construction.cleanup(max_wait_ns=checked_wait)
        except BaseException:
            pass
        _raise_suspended_identity_error()
