"""Unwired Python bridge for the W09 native resolver-owner foundation.

The bridge loads only an explicitly supplied development library. Importing it
does not touch a process, descriptor, credential, DNS, socket, or network. The
caller owns native storage before construction, and the injected create
callback publishes its outcome directly into that storage. This is executable
offline evidence, not a production-availability claim.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import signal
from typing import NamedTuple, NoReturn

from snapquiz.domain._validation import require_plain_int, runtime_final
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_output_cache as output_cache
from snapquiz.transport import resolver


__all__ = ()


LOCAL_NATIVE_RESOLVER_OWNER_FOUNDATION_AVAILABLE = True
PRODUCTION_NATIVE_RESOLVER_OWNER_AVAILABLE = False

NATIVE_RESOLVER_OWNER_ABI = 0x53515234
NATIVE_RESOLVER_OWNER_VTABLE_ABI = 0x53515632
NATIVE_RESOLVER_CALLBACK_MAGIC = 0x53514342
NATIVE_RESOLVER_OUTPUT_VIEW_MAGIC = 0x53514F56
NATIVE_RESOLVER_SNAPSHOT_MAGIC = 0x5351534E

NATIVE_RESOLVER_FD_COUNT = 4
NATIVE_RESOLVER_MAX_CONTROL_BYTES = 4_096
NATIVE_RESOLVER_MAX_OUTPUT_BYTES = 16_385
NATIVE_RESOLVER_MAX_WAIT_NS = 50_000_000

_OWNER_OK = 0
_OWNER_PENDING = 1
_OWNER_FAILED = 2
_OWNER_UNCERTAIN = 3
_OWNER_INVALID = 4
_OWNER_BUSY = 5

_CALLBACK_RETURNED = 0
_CALLBACK_AMBIGUOUS = 1

_ACTION_COMPLETE = 1
_ACTION_PENDING = 2

_OUTPUT_KIND_TO_NATIVE = {
    output_cache._ResolverOutputKind.READY: 1,
    output_cache._ResolverOutputKind.RESULT: 2,
    output_cache._ResolverOutputKind.EOF: 3,
}
_NATIVE_TO_OUTPUT_KIND = {
    value: key for key, value in _OUTPUT_KIND_TO_NATIVE.items()
}

_OWNER_STATES = {
    0: "new",
    1: "constructing",
    2: "child_owned",
    3: "recovery_owned",
    4: "create_failed",
    5: "create_uncertain",
}
_PUBLICATIONS = {
    0: "none",
    1: "created",
    2: "failed",
    3: "invalid",
}
_UNCERTAINTY_REASONS = {
    0: None,
    1: "create_return_ambiguous",
    2: "create_publication_invalid_or_missing",
}
_LANE_STATES = {
    0: "idle",
    1: "in_flight",
    2: "done",
    3: "uncertain",
    4: "failed",
}


def _owner_error(message: str) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="resolver_supervisor",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_owner_error(
    message: str = "native resolver owner 边界失败。",
) -> NoReturn:
    raise _owner_error(message) from None


def _checked_wait(max_wait_ns: object) -> int:
    selected = require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
    if selected > NATIVE_RESOLVER_MAX_WAIT_NS:
        raise ValueError("max_wait_ns exceeds native resolver deadline limit")
    return selected


class _CreatedOwnerResources(NamedTuple):
    """Exact synthetic outcome published by an injected create callback."""

    pid: int
    control_fd: int
    output_fd: int
    diagnostics_fd: int
    liveness_fd: int


class _KnownCreateFailure(NamedTuple):
    """A create failure proving that no process or descriptor exists."""

    error_code: int


class _KnownActionFailure(NamedTuple):
    """A callback-returned, non-ambiguous syscall failure."""

    error_code: int


class _FixtureOutput(NamedTuple):
    kind: output_cache._ResolverOutputKind
    payload: bytes


class _ActionResult(ctypes.Structure):
    _fields_ = (
        ("magic", ctypes.c_uint32),
        ("outcome", ctypes.c_uint32),
        ("error_code", ctypes.c_int32),
        ("value", ctypes.c_int32),
        ("byte_count", ctypes.c_uint32),
    )


class _OutputView(ctypes.Structure):
    _fields_ = (
        ("magic", ctypes.c_uint32),
        ("sequence", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("byte_count", ctypes.c_uint32),
    )


class _OwnerSnapshot(ctypes.Structure):
    _fields_ = (
        ("magic", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("publication", ctypes.c_uint32),
        ("uncertainty_reason", ctypes.c_uint32),
        ("pid", ctypes.c_int32),
        ("fds", ctypes.c_int32 * NATIVE_RESOLVER_FD_COUNT),
        ("closed_mask", ctypes.c_uint32),
        ("signal_state", ctypes.c_uint32),
        ("wait_state", ctypes.c_uint32),
        ("wait_status", ctypes.c_int32),
        ("close_states", ctypes.c_uint32 * NATIVE_RESOLVER_FD_COUNT),
        ("control_state", ctypes.c_uint32),
        ("next_output_sequence", ctypes.c_uint32),
        ("output_state", ctypes.c_uint32),
        ("output_slot_present", ctypes.c_uint32),
        ("output_slot_kind", ctypes.c_uint32),
        ("output_slot_bytes", ctypes.c_uint32),
        ("output_acked_mask", ctypes.c_uint32),
        ("liveness_state", ctypes.c_uint32),
        ("liveness_value", ctypes.c_int32),
    )


_CreateCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint64,
)
_SignalCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_int32,
    ctypes.c_int32,
    ctypes.c_uint64,
    ctypes.POINTER(_ActionResult),
)
_WaitCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_int32,
    ctypes.c_uint64,
    ctypes.POINTER(_ActionResult),
)
_CloseCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_int32,
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.POINTER(_ActionResult),
)
_ControlCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_int32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.POINTER(_ActionResult),
)
_OutputCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_int32,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.POINTER(_ActionResult),
)
_LivenessCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_int32,
    ctypes.c_uint64,
    ctypes.POINTER(_ActionResult),
)


class _OwnerVTable(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("create_process", _CreateCallback),
        ("signal_process", _SignalCallback),
        ("wait_process", _WaitCallback),
        ("close_fd", _CloseCallback),
        ("write_control", _ControlCallback),
        ("read_output", _OutputCallback),
        ("check_liveness", _LivenessCallback),
    )


def _complete_action(
    result: ctypes.POINTER(_ActionResult),
    *,
    value: int = 0,
    byte_count: int = 0,
) -> int:
    selected = result.contents
    selected.error_code = 0
    selected.value = value
    selected.byte_count = byte_count
    selected.outcome = _ACTION_COMPLETE
    selected.magic = NATIVE_RESOLVER_CALLBACK_MAGIC
    return _CALLBACK_RETURNED


def _pending_action(result: ctypes.POINTER(_ActionResult)) -> int:
    selected = result.contents
    selected.error_code = 0
    selected.value = 0
    selected.byte_count = 0
    selected.outcome = _ACTION_PENDING
    selected.magic = NATIVE_RESOLVER_CALLBACK_MAGIC
    return _CALLBACK_RETURNED


def _failed_action(
    result: ctypes.POINTER(_ActionResult),
    failure: _KnownActionFailure,
) -> int:
    selected = result.contents
    selected.error_code = failure.error_code
    selected.value = 0
    selected.byte_count = 0
    selected.outcome = _ACTION_COMPLETE
    selected.magic = NATIVE_RESOLVER_CALLBACK_MAGIC
    return _CALLBACK_RETURNED


def _i32(value: object, fallback: int) -> int:
    if type(value) is int and -(2**31) <= value <= 2**31 - 1:
        return value
    return fallback


class _CallbackBundle:
    """Own every Python callback thunk for exactly one native slot."""

    __slots__ = (
        "native",
        "fixture",
        "create_process",
        "signal_process",
        "wait_process",
        "close_fd",
        "write_control",
        "read_output",
        "check_liveness",
        "vtable",
    )

    def __init__(self, native: "_NativeOwnerLibrary", fixture: object) -> None:
        self.native = native
        self.fixture = fixture
        self.create_process = _CreateCallback(self._create_process)
        self.signal_process = _SignalCallback(self._signal_process)
        self.wait_process = _WaitCallback(self._wait_process)
        self.close_fd = _CloseCallback(self._close_fd)
        self.write_control = _ControlCallback(self._write_control)
        self.read_output = _OutputCallback(self._read_output)
        self.check_liveness = _LivenessCallback(self._check_liveness)
        self.vtable = _OwnerVTable(
            NATIVE_RESOLVER_OWNER_VTABLE_ABI,
            ctypes.sizeof(_OwnerVTable),
            self.create_process,
            self.signal_process,
            self.wait_process,
            self.close_fd,
            self.write_control,
            self.read_output,
            self.check_liveness,
        )

    def _create_process(self, context, owner_storage, max_wait_ns) -> int:
        del context
        try:
            selected = self.fixture.create_process(max_wait_ns)
        except BaseException:
            return _CALLBACK_AMBIGUOUS
        try:
            if type(selected) is _KnownCreateFailure:
                publication = (
                    self.native.library.sq_resolver_owner_publish_create_failed(
                        owner_storage,
                        _i32(selected.error_code, 0),
                    )
                )
            elif type(selected) is _CreatedOwnerResources:
                values = tuple(selected)
                raw = (
                    _i32(selected.pid, 0),
                    _i32(selected.control_fd, -1),
                    _i32(selected.output_fd, -1),
                    _i32(selected.diagnostics_fd, -1),
                    _i32(selected.liveness_fd, -1),
                )
                descriptors = (ctypes.c_int32 * NATIVE_RESOLVER_FD_COUNT)(
                    *raw[1:]
                )
                publication = self.native.library.sq_resolver_owner_publish_created(
                    owner_storage,
                    raw[0],
                    descriptors,
                )
                if any(type(value) is not int for value in values):
                    publication = _OWNER_UNCERTAIN
            else:
                publication = (
                    self.native.library.sq_resolver_owner_publish_create_failed(
                        owner_storage,
                        0,
                    )
                )
            if publication != _OWNER_OK:
                return _CALLBACK_AMBIGUOUS
            after_publication = getattr(
                self.fixture,
                "after_create_publication",
                None,
            )
            if after_publication is not None:
                after_publication(max_wait_ns)
        except BaseException:
            return _CALLBACK_AMBIGUOUS
        return _CALLBACK_RETURNED

    def _signal_process(
        self,
        context,
        pid,
        signal_number,
        max_wait_ns,
        result,
    ) -> int:
        del context
        try:
            selected = self.fixture.signal_process(
                pid,
                signal_number,
                max_wait_ns,
            )
            if type(selected) is _KnownActionFailure:
                return _failed_action(result, selected)
            if selected is not None:
                return _CALLBACK_RETURNED
            return _complete_action(result)
        except BaseException:
            return _CALLBACK_AMBIGUOUS

    def _wait_process(self, context, pid, max_wait_ns, result) -> int:
        del context
        try:
            selected = self.fixture.wait_process(pid, max_wait_ns)
            if selected is resolver.PENDING:
                return _pending_action(result)
            if type(selected) is _KnownActionFailure:
                return _failed_action(result, selected)
            if (
                type(selected) is not int
                or selected < 0
                or selected > 0x7FFFFFFF
            ):
                return _CALLBACK_RETURNED
            return _complete_action(result, value=selected)
        except BaseException:
            return _CALLBACK_AMBIGUOUS

    def _close_fd(self, context, fd, role, max_wait_ns, result) -> int:
        del context
        try:
            selected = self.fixture.close_fd(fd, role, max_wait_ns)
            if type(selected) is _KnownActionFailure:
                return _failed_action(result, selected)
            if selected is not None:
                return _CALLBACK_RETURNED
            return _complete_action(result)
        except BaseException:
            return _CALLBACK_AMBIGUOUS

    def _write_control(
        self,
        context,
        fd,
        frame,
        byte_count,
        max_wait_ns,
        result,
    ) -> int:
        del context
        try:
            payload = ctypes.string_at(frame, byte_count)
            selected = self.fixture.write_control(fd, payload, max_wait_ns)
            if selected is resolver.PENDING:
                return _pending_action(result)
            if type(selected) is _KnownActionFailure:
                return _failed_action(result, selected)
            if selected is not None:
                return _CALLBACK_RETURNED
            return _complete_action(result)
        except BaseException:
            return _CALLBACK_AMBIGUOUS

    def _read_output(
        self,
        context,
        fd,
        sequence,
        target,
        capacity,
        max_wait_ns,
        result,
    ) -> int:
        del context
        try:
            selected = self.fixture.read_output(
                fd,
                sequence,
                capacity,
                max_wait_ns,
            )
            if selected is resolver.PENDING:
                return _pending_action(result)
            if type(selected) is _KnownActionFailure:
                return _failed_action(result, selected)
            if type(selected) is not _FixtureOutput:
                return _CALLBACK_RETURNED
            if (
                type(selected.kind) is not output_cache._ResolverOutputKind
                or type(selected.payload) is not bytes
            ):
                return _CALLBACK_RETURNED
            payload = selected.payload
            native_kind = _OUTPUT_KIND_TO_NATIVE[selected.kind]
            if len(payload) <= capacity and payload:
                ctypes.memmove(target, payload, len(payload))
            return _complete_action(
                result,
                value=native_kind,
                byte_count=len(payload),
            )
        except BaseException:
            return _CALLBACK_AMBIGUOUS

    def _check_liveness(
        self,
        context,
        fd,
        max_wait_ns,
        result,
    ) -> int:
        del context
        try:
            selected = self.fixture.check_liveness(fd, max_wait_ns)
            if selected is resolver.PENDING:
                return _pending_action(result)
            if type(selected) is _KnownActionFailure:
                return _failed_action(result, selected)
            if type(selected) is not bool:
                return _CALLBACK_RETURNED
            return _complete_action(result, value=int(selected))
        except BaseException:
            return _CALLBACK_AMBIGUOUS


class _NativeOwnerLibrary:
    __slots__ = ("path", "library", "owner_size")

    def __init__(self, path: str | os.PathLike[str]) -> None:
        selected = Path(path)
        if not selected.is_absolute():
            raise ValueError("native owner library path must be absolute")
        try:
            library = ctypes.CDLL(os.fspath(selected))
            self._configure(library)
            owner_size = library.sq_resolver_owner_size()
            abi = library.sq_resolver_owner_abi()
            vtable_abi = library.sq_resolver_owner_vtable_abi()
            control_maximum = library.sq_resolver_owner_max_control_bytes()
            output_maximum = library.sq_resolver_owner_max_output_bytes()
            wait_maximum = library.sq_resolver_owner_max_wait_ns()
        except BaseException:
            _raise_owner_error("native resolver owner library 无效。")
        if (
            type(owner_size) is not int
            or owner_size < 1
            or owner_size > 1_048_576
            or abi != NATIVE_RESOLVER_OWNER_ABI
            or vtable_abi != NATIVE_RESOLVER_OWNER_VTABLE_ABI
            or control_maximum != NATIVE_RESOLVER_MAX_CONTROL_BYTES
            or output_maximum != NATIVE_RESOLVER_MAX_OUTPUT_BYTES
            or wait_maximum != NATIVE_RESOLVER_MAX_WAIT_NS
        ):
            _raise_owner_error("native resolver owner ABI 不匹配。")
        self.path = selected
        self.library = library
        self.owner_size = owner_size

    @staticmethod
    def _configure(library: object) -> None:
        library.sq_resolver_owner_size.argtypes = []
        library.sq_resolver_owner_size.restype = ctypes.c_size_t
        library.sq_resolver_owner_abi.argtypes = []
        library.sq_resolver_owner_abi.restype = ctypes.c_uint32
        library.sq_resolver_owner_vtable_abi.argtypes = []
        library.sq_resolver_owner_vtable_abi.restype = ctypes.c_uint32
        library.sq_resolver_owner_max_control_bytes.argtypes = []
        library.sq_resolver_owner_max_control_bytes.restype = ctypes.c_uint32
        library.sq_resolver_owner_max_output_bytes.argtypes = []
        library.sq_resolver_owner_max_output_bytes.restype = ctypes.c_uint32
        library.sq_resolver_owner_max_wait_ns.argtypes = []
        library.sq_resolver_owner_max_wait_ns.restype = ctypes.c_uint64
        library.sq_resolver_owner_prepare.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.sq_resolver_owner_prepare.restype = ctypes.c_int32
        library.sq_resolver_owner_publish_created.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.POINTER(ctypes.c_int32),
        ]
        library.sq_resolver_owner_publish_created.restype = ctypes.c_int32
        library.sq_resolver_owner_publish_create_failed.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int32,
        ]
        library.sq_resolver_owner_publish_create_failed.restype = ctypes.c_int32
        library.sq_resolver_owner_construct.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_OwnerVTable),
            ctypes.c_void_p,
            ctypes.c_uint64,
        ]
        library.sq_resolver_owner_construct.restype = ctypes.c_int32
        library.sq_resolver_owner_signal.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.c_int32,
            ctypes.c_uint64,
        ]
        library.sq_resolver_owner_signal.restype = ctypes.c_int32
        library.sq_resolver_owner_wait.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_int32),
        ]
        library.sq_resolver_owner_wait.restype = ctypes.c_int32
        library.sq_resolver_owner_signal_owned.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.c_uint64,
        ]
        library.sq_resolver_owner_signal_owned.restype = ctypes.c_int32
        library.sq_resolver_owner_wait_owned.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_int32),
        ]
        library.sq_resolver_owner_wait_owned.restype = ctypes.c_int32
        library.sq_resolver_owner_close.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
        ]
        library.sq_resolver_owner_close.restype = ctypes.c_int32
        library.sq_resolver_owner_write_control.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32,
            ctypes.c_uint64,
        ]
        library.sq_resolver_owner_write_control.restype = ctypes.c_int32
        library.sq_resolver_owner_observe_output.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.POINTER(_OutputView),
        ]
        library.sq_resolver_owner_observe_output.restype = ctypes.c_int32
        library.sq_resolver_owner_ack_output.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
        ]
        library.sq_resolver_owner_ack_output.restype = ctypes.c_int32
        library.sq_resolver_owner_check_liveness.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_int32),
        ]
        library.sq_resolver_owner_check_liveness.restype = ctypes.c_int32
        library.sq_resolver_owner_snapshot.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_OwnerSnapshot),
        ]
        library.sq_resolver_owner_snapshot.restype = ctypes.c_int32


def _native_buffer(payload: bytes):
    size = max(1, len(payload))
    selected = (ctypes.c_uint8 * size)()
    if payload:
        ctypes.memmove(selected, payload, len(payload))
    return selected


@runtime_final
class _DarwinResolverOwnerSlot:
    """Caller-preheld native storage and unwired child-compatible bridge."""

    __slots__ = (
        "_native",
        "_words",
        "_pointer",
        "_callbacks",
        "_fixture",
    )

    def __init__(self, library_path: str | os.PathLike[str]) -> None:
        native = _NativeOwnerLibrary(library_path)
        word_count = (native.owner_size + ctypes.sizeof(ctypes.c_uint64) - 1) // (
            ctypes.sizeof(ctypes.c_uint64)
        )
        words = (ctypes.c_uint64 * word_count)()
        pointer = ctypes.cast(words, ctypes.c_void_p)
        result = native.library.sq_resolver_owner_prepare(
            pointer,
            ctypes.sizeof(words),
        )
        if result != _OWNER_OK:
            _raise_owner_error("native resolver owner slot 无法初始化。")
        object.__setattr__(self, "_native", native)
        object.__setattr__(self, "_words", words)
        object.__setattr__(self, "_pointer", pointer)
        object.__setattr__(self, "_callbacks", None)
        object.__setattr__(self, "_fixture", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinResolverOwnerSlot identity is immutable")

    def construct(self, fixture: object, *, max_wait_ns: int) -> None:
        selected_wait = _checked_wait(max_wait_ns)
        callbacks = self._callbacks
        if callbacks is None:
            callbacks = _CallbackBundle(self._native, fixture)
            object.__setattr__(self, "_callbacks", callbacks)
            object.__setattr__(self, "_fixture", fixture)
        elif fixture is not self._fixture:
            _raise_owner_error("native resolver owner construction 已变化。")
        result = self._native.library.sq_resolver_owner_construct(
            self._pointer,
            ctypes.byref(callbacks.vtable),
            None,
            selected_wait,
        )
        if result != _OWNER_OK:
            _raise_owner_error()

    def _snapshot(self) -> _OwnerSnapshot:
        snapshot = _OwnerSnapshot()
        result = self._native.library.sq_resolver_owner_snapshot(
            self._pointer,
            ctypes.byref(snapshot),
        )
        if result != _OWNER_OK or snapshot.magic != NATIVE_RESOLVER_SNAPSHOT_MAGIC:
            _raise_owner_error("native resolver owner snapshot 无效。")
        return snapshot

    @property
    def pid(self) -> int:
        snapshot = self._snapshot()
        state = _OWNER_STATES.get(snapshot.state)
        if (
            state not in ("child_owned", "recovery_owned")
            or snapshot.publication != 1
            or snapshot.pid <= 0
        ):
            _raise_owner_error("native resolver owner PID 不可用。")
        return snapshot.pid

    def write_start_datagram(self, frame: bytes, *, max_wait_ns: int) -> object:
        selected_wait = _checked_wait(max_wait_ns)
        if (
            type(frame) is not bytes
            or not frame
            or len(frame) > NATIVE_RESOLVER_MAX_CONTROL_BYTES
        ):
            raise ValueError("control frame must be bounded non-empty bytes")
        payload = _native_buffer(frame)
        result = self._native.library.sq_resolver_owner_write_control(
            self._pointer,
            payload,
            len(frame),
            selected_wait,
        )
        return self._completion(result)

    def observe_stdout_durable(
        self,
        max_bytes: int,
        *,
        publication: object,
        max_wait_ns: int,
    ) -> object:
        selected_wait = _checked_wait(max_wait_ns)
        maximum = require_plain_int(max_bytes, "max_bytes", minimum=1)
        if maximum > NATIVE_RESOLVER_MAX_OUTPUT_BYTES:
            raise ValueError("max_bytes exceeds native resolver output limit")
        if type(publication) is not output_cache._ResolverOutputPublication:
            raise TypeError("publication must be ResolverOutputPublication")
        payload = (ctypes.c_uint8 * maximum)()
        view = _OutputView()
        result = self._native.library.sq_resolver_owner_observe_output(
            self._pointer,
            maximum,
            payload,
            maximum,
            selected_wait,
            ctypes.byref(view),
        )
        selected = self._completion(result)
        if selected is resolver.PENDING:
            return selected
        kind = _NATIVE_TO_OUTPUT_KIND.get(view.kind)
        if (
            view.magic != NATIVE_RESOLVER_OUTPUT_VIEW_MAGIC
            or kind is not publication.kind
            or view.sequence != publication.sequence
            or view.byte_count > maximum
        ):
            _raise_owner_error("native resolver output publication 无效。")
        publication.publish(bytes(payload[: view.byte_count]))
        return resolver.COMPLETE

    def ack_stdout_durable(
        self,
        observation: object,
        *,
        max_wait_ns: int,
    ) -> object:
        _checked_wait(max_wait_ns)
        if type(observation) is not output_cache._ResolverOutputObservation:
            raise TypeError("observation must be ResolverOutputObservation")
        try:
            observation.validate_integrity()
            native_kind = _OUTPUT_KIND_TO_NATIVE[observation.kind]
            digest = bytes.fromhex(str(observation.observation_digest))
        except (AttributeError, KeyError, TypeError, ValueError):
            _raise_owner_error("native resolver output ACK 无效。")
        if len(digest) != 32:
            _raise_owner_error("native resolver output ACK digest 无效。")
        payload = _native_buffer(observation.payload)
        digest_buffer = _native_buffer(digest)
        result = self._native.library.sq_resolver_owner_ack_output(
            self._pointer,
            observation.sequence,
            native_kind,
            payload,
            len(observation.payload),
            digest_buffer,
        )
        return self._completion(result)

    def terminate_exact(
        self,
        pid: int,
        *,
        max_wait_ns: int,
    ) -> object:
        selected_wait = _checked_wait(max_wait_ns)
        checked_pid = require_plain_int(pid, "pid", minimum=1)
        result = self._native.library.sq_resolver_owner_signal(
            self._pointer,
            checked_pid,
            signal.SIGKILL,
            selected_wait,
        )
        return self._completion(result)

    def reap_exact(self, pid: int, *, max_wait_ns: int) -> object:
        selected_wait = _checked_wait(max_wait_ns)
        checked_pid = require_plain_int(pid, "pid", minimum=1)
        status = ctypes.c_int32(-1)
        result = self._native.library.sq_resolver_owner_wait(
            self._pointer,
            checked_pid,
            selected_wait,
            ctypes.byref(status),
        )
        selected = self._completion(result)
        return selected if selected is resolver.PENDING else status.value

    def terminate_owned_exact(self, *, max_wait_ns: int) -> object:
        """Signal the exact native-owned child without exporting its PID."""

        selected_wait = _checked_wait(max_wait_ns)
        result = self._native.library.sq_resolver_owner_signal_owned(
            self._pointer,
            signal.SIGKILL,
            selected_wait,
        )
        return self._completion(result)

    def reap_owned_exact(self, *, max_wait_ns: int) -> object:
        """Wait for the exact native-owned child without exporting its PID."""

        selected_wait = _checked_wait(max_wait_ns)
        status = ctypes.c_int32(-1)
        result = self._native.library.sq_resolver_owner_wait_owned(
            self._pointer,
            selected_wait,
            ctypes.byref(status),
        )
        selected = self._completion(result)
        return selected if selected is resolver.PENDING else status.value

    def close_exact(self, *, max_wait_ns: int) -> object:
        selected_wait = _checked_wait(max_wait_ns)
        result = self._native.library.sq_resolver_owner_close(
            self._pointer,
            selected_wait,
        )
        return self._completion(result)

    def poll_liveness_exact(self, *, max_wait_ns: int) -> object:
        selected_wait = _checked_wait(max_wait_ns)
        selected = ctypes.c_int32(-1)
        result = self._native.library.sq_resolver_owner_check_liveness(
            self._pointer,
            selected_wait,
            ctypes.byref(selected),
        )
        completion = self._completion(result)
        return completion if completion is resolver.PENDING else bool(selected.value)

    @staticmethod
    def _completion(result: int) -> object:
        if result == _OWNER_OK:
            return resolver.COMPLETE
        if result in (_OWNER_PENDING, _OWNER_BUSY):
            return resolver.PENDING
        if result in (_OWNER_FAILED, _OWNER_UNCERTAIN, _OWNER_INVALID):
            _raise_owner_error()
        _raise_owner_error("native resolver owner result 无效。")

    def safe_metadata(self) -> dict[str, object]:
        snapshot = _OwnerSnapshot()
        result = self._native.library.sq_resolver_owner_snapshot(
            self._pointer,
            ctypes.byref(snapshot),
        )
        if result == _OWNER_BUSY:
            return {
                "state": "snapshot_busy",
                "snapshot_busy": True,
                "production_available": PRODUCTION_NATIVE_RESOLVER_OWNER_AVAILABLE,
            }
        if result != _OWNER_OK or snapshot.magic != NATIVE_RESOLVER_SNAPSHOT_MAGIC:
            _raise_owner_error("native resolver owner snapshot 无效。")
        state = _OWNER_STATES.get(snapshot.state, "invalid")
        publication = _PUBLICATIONS.get(snapshot.publication, "invalid")
        uncertainty_reason = _UNCERTAINTY_REASONS.get(
            snapshot.uncertainty_reason,
            "invalid",
        )
        slot_kind = _NATIVE_TO_OUTPUT_KIND.get(snapshot.output_slot_kind)
        close_states = tuple(
            _LANE_STATES.get(value, "invalid") for value in snapshot.close_states
        )
        exact_owned = publication == "created" and state in (
            "constructing",
            "child_owned",
            "recovery_owned",
        )
        return {
            "state": state,
            "snapshot_busy": False,
            "publication": publication,
            "uncertainty_reason": uncertainty_reason,
            "uncertainty_tombstone": state == "create_uncertain",
            "pid_owned": exact_owned,
            "owned_fd_count": NATIVE_RESOLVER_FD_COUNT if exact_owned else 0,
            "closed_fd_count": int(snapshot.closed_mask).bit_count(),
            "all_fds_closed": snapshot.closed_mask == 0b1111,
            "signal_state": _LANE_STATES.get(snapshot.signal_state, "invalid"),
            "signal_done": snapshot.signal_state == 2,
            "reap_state": _LANE_STATES.get(snapshot.wait_state, "invalid"),
            "reap_done": snapshot.wait_state == 2,
            "wait_status": snapshot.wait_status if snapshot.wait_state == 2 else None,
            "close_states": close_states,
            "close_uncertain_count": close_states.count("uncertain"),
            "close_failed_count": close_states.count("failed"),
            "control_state": _LANE_STATES.get(snapshot.control_state, "invalid"),
            "control_done": snapshot.control_state == 2,
            "next_output_sequence": snapshot.next_output_sequence,
            "output_state": _LANE_STATES.get(snapshot.output_state, "invalid"),
            "output_slot_present": bool(snapshot.output_slot_present),
            "output_slot_kind": (
                slot_kind.value
                if snapshot.output_slot_present and slot_kind is not None
                else None
            ),
            "output_slot_bytes": snapshot.output_slot_bytes,
            "output_acked_count": int(snapshot.output_acked_mask).bit_count(),
            "liveness_state": _LANE_STATES.get(
                snapshot.liveness_state,
                "invalid",
            ),
            "liveness_known": snapshot.liveness_state == 2,
            "liveness_value": (
                bool(snapshot.liveness_value)
                if snapshot.liveness_state == 2
                else None
            ),
            "production_available": PRODUCTION_NATIVE_RESOLVER_OWNER_AVAILABLE,
        }


def _new_unwired_darwin_resolver_owner_slot(
    library_path: str | os.PathLike[str],
) -> _DarwinResolverOwnerSlot:
    """Create caller-held storage without constructing an owned resource."""

    return _DarwinResolverOwnerSlot(library_path)
