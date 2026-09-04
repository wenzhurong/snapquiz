"""Darwin-only process-event watcher foundation.

This private W09-B2b-S2b-I2 module is deliberately development-only and is
not wired into the resolver supervisor or the production resolver.  Its sole
job is to attach one ``EVFILT_PROC`` knote to one exact positive PID and make
``NOTE_EXEC``, ``NOTE_FORK``, or ``NOTE_EXIT`` a permanent, content-free
failure.  Process identity, spawn ownership, signalling, reaping, descendant
ownership, and bundle provenance remain separate contracts.

Importing this module performs no framework, descriptor, process, file, or
network operation.  The explicit factory is the first external boundary.
"""
from __future__ import annotations

import ctypes
from enum import Enum
import os
import sys
from threading import Lock, RLock
from typing import NoReturn

from snapquiz.domain._validation import require_plain_int, runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError


__all__ = ()


DARWIN_PROCESS_EVENT_WATCH_SCHEMA_VERSION = (
    "snapquiz.darwin-process-event-watch.v1"
)
DARWIN_PROCESS_EVENT_WATCH_SCOPE = "darwin_kqueue_process_events_development"
MAX_PROCESS_EVENT_WAIT_NS = 5_000_000_000


_EVFILT_PROC = -5
_EV_ADD = 0x0001
_EV_ONESHOT = 0x0010
_EV_CLEAR = 0x0020
_EV_RECEIPT = 0x0040
_EV_EOF = 0x8000
_EV_ERROR = 0x4000
_NOTE_EXIT = 0x80000000
_NOTE_FORK = 0x40000000
_NOTE_EXEC = 0x20000000
_PROCESS_NOTES = _NOTE_EXIT | _NOTE_FORK | _NOTE_EXEC
_REGISTRATION_FLAGS = _EV_ADD | _EV_CLEAR | _EV_RECEIPT
_REGISTRATION_RECEIPT_FLAGS = _REGISTRATION_FLAGS | _EV_ERROR
_ALLOWED_EVENT_FLAGS = _REGISTRATION_FLAGS | _EV_ONESHOT | _EV_EOF
_WATCHER_AUTHORITY = object()


class _EventKind(str, Enum):
    EXEC = "exec"
    FORK = "fork"
    EXIT = "exit"
    UNKNOWN = "unknown"


class _WatchState(str, Enum):
    NEW = "new"
    OPEN_IN_FLIGHT = "open_in_flight"
    OPEN = "open"
    REGISTER_IN_FLIGHT = "register_in_flight"
    ACTIVE = "active"
    POISONED = "poisoned"
    CLOSED = "closed"
    CLOSE_UNCERTAIN = "close_uncertain"


class _EventBoundaryFailure(Exception):
    """Content-free internal marker that never crosses this module."""


class _KEvent(ctypes.Structure):
    # Darwin declares struct kevent under #pragma pack(4).  I2 supports only
    # the 64-bit ABI already required by its dynamic-code identity sibling.
    _pack_ = 4
    _fields_ = (
        ("ident", ctypes.c_uint64),
        ("filter", ctypes.c_int16),
        ("flags", ctypes.c_uint16),
        ("fflags", ctypes.c_uint32),
        ("data", ctypes.c_int64),
        ("udata", ctypes.c_void_p),
    )


class _Timespec(ctypes.Structure):
    _fields_ = (
        ("tv_sec", ctypes.c_long),
        ("tv_nsec", ctypes.c_long),
    )


def _event_error(
    safe_message: str = "resolver supervisor process watcher 不可用。",
) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_supervisor_process_events",
        retryable=False,
        safe_message=safe_message,
    )


def _raise_event_error(
    safe_message: str = "resolver supervisor process watcher 不可用。",
) -> NoReturn:
    error = _event_error(safe_message)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _require_wait_ns(value: object) -> int:
    selected = require_plain_int(value, "max_wait_ns", minimum=0)
    if selected > MAX_PROCESS_EVENT_WAIT_NS:
        raise ValueError(
            f"max_wait_ns must be <= {MAX_PROCESS_EVENT_WAIT_NS}"
        )
    return selected


class _DarwinKqueueBindings:
    """Typed libc bindings instantiated only by the explicit factory."""

    __slots__ = ("kevent", "kqueue")

    def __init__(self) -> None:
        if sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise _EventBoundaryFailure
        if (
            ctypes.sizeof(_KEvent) != 32
            or _KEvent.ident.offset != 0
            or _KEvent.filter.offset != 8
            or _KEvent.flags.offset != 10
            or _KEvent.fflags.offset != 12
            or _KEvent.data.offset != 16
            or _KEvent.udata.offset != 24
            or ctypes.sizeof(_Timespec) != 16
        ):
            raise _EventBoundaryFailure
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            kqueue = libc.kqueue
            kevent = libc.kevent
            kqueue.argtypes = ()
            kqueue.restype = ctypes.c_int
            kevent.argtypes = (
                ctypes.c_int,
                ctypes.POINTER(_KEvent),
                ctypes.c_int,
                ctypes.POINTER(_KEvent),
                ctypes.c_int,
                ctypes.POINTER(_Timespec),
            )
            kevent.restype = ctypes.c_int
        except BaseException:
            raise _EventBoundaryFailure from None
        self.kqueue = kqueue
        self.kevent = kevent


def _register_process_filter(
    bindings: _DarwinKqueueBindings,
    *,
    kqueue_fd: int,
    process_id: int,
) -> None:
    """Add one exact proc filter and require its synchronous receipt."""

    change = _KEvent(
        ident=process_id,
        filter=_EVFILT_PROC,
        flags=_REGISTRATION_FLAGS,
        fflags=_PROCESS_NOTES,
        data=0,
        udata=None,
    )
    receipt = _KEvent()
    zero = _Timespec(tv_sec=0, tv_nsec=0)
    try:
        ctypes.set_errno(0)
        result = bindings.kevent(
            kqueue_fd,
            ctypes.byref(change),
            1,
            ctypes.byref(receipt),
            1,
            ctypes.byref(zero),
        )
    except BaseException:
        raise _EventBoundaryFailure from None
    if (
        type(result) is not int
        or result != 1
        or receipt.ident != process_id
        or receipt.filter != _EVFILT_PROC
        or receipt.flags != _REGISTRATION_RECEIPT_FLAGS
        or receipt.fflags != _PROCESS_NOTES
        or receipt.data != 0
        or receipt.udata
    ):
        raise _EventBoundaryFailure


def _receive_process_event(
    bindings: _DarwinKqueueBindings,
    *,
    kqueue_fd: int,
    max_wait_ns: int,
) -> _KEvent | None:
    event = _KEvent()
    timeout = _Timespec(
        tv_sec=max_wait_ns // 1_000_000_000,
        tv_nsec=max_wait_ns % 1_000_000_000,
    )
    try:
        ctypes.set_errno(0)
        result = bindings.kevent(
            kqueue_fd,
            None,
            0,
            ctypes.byref(event),
            1,
            ctypes.byref(timeout),
        )
    except BaseException:
        raise _EventBoundaryFailure from None
    if type(result) is not int or result not in (0, 1):
        raise _EventBoundaryFailure
    return None if result == 0 else event


def _classify_event(event: _KEvent, *, process_id: int) -> tuple[_EventKind, ...]:
    if (
        type(event) is not _KEvent
        or event.ident != process_id
        or event.filter != _EVFILT_PROC
        or event.flags & _EV_ERROR
        or event.flags & ~_ALLOWED_EVENT_FLAGS
        or event.fflags & ~_PROCESS_NOTES
        or event.fflags & _PROCESS_NOTES == 0
        or event.data != 0
        or event.udata
    ):
        raise _EventBoundaryFailure
    selected: list[_EventKind] = []
    for flag, kind in (
        (_NOTE_EXEC, _EventKind.EXEC),
        (_NOTE_FORK, _EventKind.FORK),
        (_NOTE_EXIT, _EventKind.EXIT),
    ):
        if event.fflags & flag:
            selected.append(kind)
    if not selected:
        raise _EventBoundaryFailure
    return tuple(selected)


@runtime_final
class _DarwinProcessEventWatcher:
    """Exact owner of one active kqueue process-event registration."""

    __slots__ = (
        "process_id",
        "registration_digest",
        "_issued_registration_digest",
        "_bindings",
        "_kqueue_fd",
        "_state",
        "_registration_attested",
        "_event_kinds",
        "_poisoned",
        "_closed",
        "_close_attempted",
        "_close_uncertain",
        "_operation_lock",
        "_state_lock",
    )

    def __init__(
        self,
        *,
        process_id: int,
        bindings: _DarwinKqueueBindings,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _WATCHER_AUTHORITY:
            raise TypeError("Darwin process watcher requires its factory")
        pid = require_plain_int(process_id, "process_id", minimum=1)
        if type(bindings) is not _DarwinKqueueBindings:
            raise TypeError("bindings must be DarwinKqueueBindings")
        object.__setattr__(self, "process_id", pid)
        object.__setattr__(self, "registration_digest", None)
        object.__setattr__(self, "_issued_registration_digest", None)
        object.__setattr__(self, "_bindings", bindings)
        object.__setattr__(self, "_kqueue_fd", None)
        object.__setattr__(self, "_state", _WatchState.NEW)
        object.__setattr__(self, "_registration_attested", False)
        object.__setattr__(self, "_event_kinds", ())
        object.__setattr__(self, "_poisoned", False)
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_close_attempted", False)
        object.__setattr__(self, "_close_uncertain", False)
        object.__setattr__(self, "_operation_lock", Lock())
        object.__setattr__(self, "_state_lock", RLock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinProcessEventWatcher identity is immutable")

    def __copy__(self) -> "_DarwinProcessEventWatcher":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_DarwinProcessEventWatcher":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("DarwinProcessEventWatcher cannot be serialized")

    def _registration_payload(self) -> dict[str, object]:
        return {
            "event_filter": "EVFILT_PROC",
            "event_flags": ("NOTE_EXEC", "NOTE_FORK", "NOTE_EXIT"),
            "process_id": self.process_id,
            "production_eligible": False,
            "scope": DARWIN_PROCESS_EVENT_WATCH_SCOPE,
        }

    def _open_and_register(self) -> None:
        with self._state_lock:
            if self._state is not _WatchState.NEW:
                raise _EventBoundaryFailure
            object.__setattr__(self, "_state", _WatchState.OPEN_IN_FLIGHT)
        try:
            selected = self._bindings.kqueue()
        except BaseException:
            self._latch_unknown()
            raise _EventBoundaryFailure from None
        if type(selected) is not int or selected < 0:
            self._latch_unknown()
            raise _EventBoundaryFailure
        with self._state_lock:
            object.__setattr__(self, "_kqueue_fd", selected)
            object.__setattr__(self, "_state", _WatchState.OPEN)
        try:
            if selected < 3:
                raise _EventBoundaryFailure
            os.set_inheritable(selected, False)
            if os.get_inheritable(selected):
                raise _EventBoundaryFailure
            with self._state_lock:
                object.__setattr__(
                    self,
                    "_state",
                    _WatchState.REGISTER_IN_FLIGHT,
                )
            _register_process_filter(
                self._bindings,
                kqueue_fd=selected,
                process_id=self.process_id,
            )
            registration_digest = digest256(
                "DarwinProcessEventWatchRegistration",
                DARWIN_PROCESS_EVENT_WATCH_SCHEMA_VERSION,
                self._registration_payload(),
            )
            with self._state_lock:
                object.__setattr__(
                    self,
                    "registration_digest",
                    registration_digest,
                )
                object.__setattr__(
                    self,
                    "_issued_registration_digest",
                    registration_digest,
                )
                object.__setattr__(self, "_registration_attested", True)
                object.__setattr__(self, "_state", _WatchState.ACTIVE)
        except BaseException:
            self._latch_unknown()
            raise _EventBoundaryFailure from None

    def _latch_unknown(self) -> None:
        with self._state_lock:
            if _EventKind.UNKNOWN not in self._event_kinds:
                object.__setattr__(
                    self,
                    "_event_kinds",
                    self._event_kinds + (_EventKind.UNKNOWN,),
                )
            object.__setattr__(self, "_poisoned", True)
            if not self._closed and not self._close_uncertain:
                object.__setattr__(self, "_state", _WatchState.POISONED)

    def _latch_events(self, kinds: tuple[_EventKind, ...]) -> None:
        with self._state_lock:
            merged = list(self._event_kinds)
            for kind in kinds:
                if kind not in merged:
                    merged.append(kind)
            object.__setattr__(self, "_event_kinds", tuple(merged))
            object.__setattr__(self, "_poisoned", True)
            object.__setattr__(self, "_state", _WatchState.POISONED)

    def validate_integrity(self) -> None:
        require_plain_int(self.process_id, "process_id", minimum=1)
        selected = digest256(
            "DarwinProcessEventWatchRegistration",
            DARWIN_PROCESS_EVENT_WATCH_SCHEMA_VERSION,
            self._registration_payload(),
        )
        if (
            not self._registration_attested
            or type(self.registration_digest) is not Digest256
            or type(self._issued_registration_digest) is not Digest256
            or self.registration_digest != selected
            or self._issued_registration_digest != selected
        ):
            raise ValueError("Darwin process watcher integrity failed")

    def require_quiet(self, *, max_wait_ns: int = 0) -> None:
        """Require no observed exec, fork, or exit within one bounded wait."""

        checked_wait = _require_wait_ns(max_wait_ns)
        if not self._operation_lock.acquire(blocking=False):
            _raise_event_error("resolver supervisor process watcher 正在使用。")
        try:
            try:
                self.validate_integrity()
            except (AttributeError, TypeError, ValueError):
                self._latch_unknown()
                _raise_event_error()
            with self._state_lock:
                if self._poisoned:
                    _raise_event_error(
                        "resolver supervisor process identity 已变化。"
                    )
                if (
                    self._closed
                    or self._close_uncertain
                    or self._state is not _WatchState.ACTIVE
                    or type(self._kqueue_fd) is not int
                ):
                    _raise_event_error()
                selected_fd = self._kqueue_fd
            try:
                event = _receive_process_event(
                    self._bindings,
                    kqueue_fd=selected_fd,
                    max_wait_ns=checked_wait,
                )
                if event is None:
                    return
                kinds = _classify_event(event, process_id=self.process_id)
            except BaseException:
                self._latch_unknown()
                _raise_event_error()
            self._latch_events(kinds)
            _raise_event_error("resolver supervisor process identity 已变化。")
        finally:
            self._operation_lock.release()

    def close(self) -> bool:
        """Close the kqueue at most once; never replay an uncertain fd close."""

        if not self._operation_lock.acquire(blocking=False):
            return False
        try:
            with self._state_lock:
                if self._closed:
                    return True
                if self._close_uncertain or self._close_attempted:
                    return False
                fd = self._kqueue_fd
                if type(fd) is not int or fd < 0:
                    object.__setattr__(self, "_close_uncertain", True)
                    object.__setattr__(self, "_poisoned", True)
                    object.__setattr__(
                        self,
                        "_state",
                        _WatchState.CLOSE_UNCERTAIN,
                    )
                    return False
                # Retire the numeric descriptor before close.  If an async
                # interruption lands after the kernel action, no later call can
                # close an unrelated descriptor that reused this number.
                object.__setattr__(self, "_kqueue_fd", None)
                object.__setattr__(self, "_close_attempted", True)
            try:
                os.close(fd)
            except BaseException:
                with self._state_lock:
                    object.__setattr__(self, "_close_uncertain", True)
                    object.__setattr__(self, "_poisoned", True)
                    object.__setattr__(
                        self,
                        "_state",
                        _WatchState.CLOSE_UNCERTAIN,
                    )
                return False
            with self._state_lock:
                object.__setattr__(self, "_closed", True)
                object.__setattr__(self, "_state", _WatchState.CLOSED)
            return True
        finally:
            self._operation_lock.release()

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        with self._state_lock:
            return {
                "close_uncertain": self._close_uncertain,
                "closed": self._closed,
                "event_kinds": tuple(kind.value for kind in self._event_kinds),
                "process_event_watch_active": (
                    self._state is _WatchState.ACTIVE
                    and not self._poisoned
                    and not self._closed
                    and type(self._kqueue_fd) is int
                ),
                "process_event_watch_attested": self._registration_attested,
                "process_id": self.process_id,
                "poisoned": self._poisoned,
                "production_eligible": False,
                "registration_digest": str(self.registration_digest),
                "scope": DARWIN_PROCESS_EVENT_WATCH_SCOPE,
                "state": self._state.value,
                "transport_available": False,
            }


def _new_darwin_process_event_watcher(
    process_id: int,
    *,
    publication: object,
) -> None:
    """Open and publish one watcher without returning the live resource."""

    pid = require_plain_int(process_id, "process_id", minimum=1)
    required = ("watcher_for_process", "publish_watcher", "owns_watcher")
    if not all(callable(getattr(publication, name, None)) for name in required):
        raise TypeError("watcher publication is invalid")
    try:
        existing = publication.watcher_for_process(pid)
    except BaseException:
        _raise_event_error()
    if existing is not None:
        if (
            type(existing) is not _DarwinProcessEventWatcher
            or existing.process_id != pid
        ):
            _raise_event_error()
        try:
            existing.validate_integrity()
        except BaseException:
            _raise_event_error()
        return None

    watcher: _DarwinProcessEventWatcher | None = None
    try:
        bindings = _DarwinKqueueBindings()
        watcher = _DarwinProcessEventWatcher(
            process_id=pid,
            bindings=bindings,
            _authority=_WATCHER_AUTHORITY,
        )
        watcher._open_and_register()
        watcher.validate_integrity()
        publication.publish_watcher(watcher)
        # The caller-held publication remains the owner across this return.
        return None
    except BaseException:
        try:
            published = watcher is not None and publication.owns_watcher(watcher)
        except BaseException:
            published = False
        if watcher is not None and not published:
            try:
                watcher.close()
            except BaseException:
                pass
        _raise_event_error()
