"""Darwin-local opaque numeric socket owner foundation for W09-B2b-S6.

The native ABI owns the descriptor from creation through its terminal close.
Python receives only a 256-bit opaque bearer token and content-free state/proof
metadata; it never receives a descriptor or ``socket.socket``.  The token is a
process-local handle, not production provenance or an authorization decision.
Creation and every operation publish a durable native outcome before returning,
so a Python return-event interruption can recover by querying the same token.

This module is deliberately test-injected and unwired.  It contains no default
syscall table, performs no work at import, and cannot enable the production
transport flags in :mod:`snapquiz.transport._numeric_connect`.  A signed,
fixed-bundle native table and an opaque TLS-token transfer are later production
integration requirements.
"""
from __future__ import annotations

import ctypes
import errno
from pathlib import Path
import socket
import sys
from threading import Lock
from typing import NoReturn

from snapquiz.domain._validation import require_plain_int, runtime_final
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport.address_policy import AddressFamily, ResolvedAddress


__all__ = ()


DARWIN_NUMERIC_OWNER_ABI = 0x53514E31
DARWIN_NUMERIC_OWNER_SCOPE = "darwin_opaque_numeric_owner_local_offline"
DARWIN_NUMERIC_OWNER_MAX_WAIT_NS = 50_000_000
DARWIN_OWNER_TRANSFER_CONTRACT_ABI = 0x53515846
DARWIN_OWNER_TRANSFER_CONTRACT_SIZE = 32
DARWIN_OWNER_TRANSFER_CONTRACT_VERSION = 1

_PUBLICATION_NEW = 0
_PUBLICATION_COMMITTED = 2
_CREATE_PUBLICATION_MAGIC = 0x5351504E
_OUTCOME_MAGIC = 0x53514F4E

_STATUS_OK = 0
_STATUS_PENDING = 1
_STATUS_CLOSED = 2
_STATUS_FAILED = 3
_STATUS_UNCERTAIN = 4
_STATUS_INVALID_TOKEN = 5
_STATUS_INVALID_STATE = 6
_STATUS_BUSY = 7
_STATUS_INVALID_ARGUMENT = 8
_STATUS_CAPACITY = 9

_OWNER_EMPTY = 0
_OWNER_CREATE_IN_FLIGHT = 1
_OWNER_CREATED = 2
_OWNER_CONNECT_IN_FLIGHT = 3
_OWNER_PENDING = 4
_OWNER_POLL_IN_FLIGHT = 5
_OWNER_VERIFY_IN_FLIGHT = 6
_OWNER_CONNECTED = 7
_OWNER_FAILED = 8
_OWNER_CONNECT_UNCERTAIN = 9
_OWNER_POLL_UNCERTAIN = 10
_OWNER_VERIFY_UNCERTAIN = 11
_OWNER_CLOSE_IN_FLIGHT = 12
_OWNER_CLOSED = 13
_OWNER_CLOSE_UNCERTAIN = 14
_OWNER_CREATE_UNCERTAIN = 15
_OWNER_TRANSFER_IN_FLIGHT = 16
_OWNER_TRANSFERRED = 17
_OWNER_TRANSFER_UNCERTAIN = 18

_STATE_NAMES = {
    _OWNER_EMPTY: "empty",
    _OWNER_CREATE_IN_FLIGHT: "create_in_flight",
    _OWNER_CREATED: "created",
    _OWNER_CONNECT_IN_FLIGHT: "connect_in_flight",
    _OWNER_PENDING: "pending",
    _OWNER_POLL_IN_FLIGHT: "poll_in_flight",
    _OWNER_VERIFY_IN_FLIGHT: "verify_in_flight",
    _OWNER_CONNECTED: "connected",
    _OWNER_FAILED: "failed",
    _OWNER_CONNECT_UNCERTAIN: "connect_uncertain",
    _OWNER_POLL_UNCERTAIN: "poll_uncertain",
    _OWNER_VERIFY_UNCERTAIN: "verify_uncertain",
    _OWNER_CLOSE_IN_FLIGHT: "close_in_flight",
    _OWNER_CLOSED: "closed",
    _OWNER_CLOSE_UNCERTAIN: "close_uncertain",
    _OWNER_CREATE_UNCERTAIN: "create_uncertain",
    _OWNER_TRANSFER_IN_FLIGHT: "transfer_in_flight",
    _OWNER_TRANSFERRED: "transferred",
    _OWNER_TRANSFER_UNCERTAIN: "transfer_uncertain",
}

_FACTORY_AUTHORITY = object()
_CONSTRUCTION_AUTHORITY = object()
_OWNER_AUTHORITY = object()
_LOCAL_TEST_AUTHORITY = object()
_TRANSFER_ADAPTER_AUTHORITY = object()


def _owner_error(
    safe_message: str = "opaque numeric socket owner 不可用。",
) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="numeric_connect",
        retryable=False,
        safe_message=safe_message,
    )
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_owner_error(
    safe_message: str = "opaque numeric socket owner 不可用。",
) -> NoReturn:
    raise _owner_error(safe_message) from None


class _NativeCreatePublication(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("publication_state", ctypes.c_uint32),
        ("status", ctypes.c_int32),
        ("owner_state", ctypes.c_int32),
        ("token", ctypes.c_uint8 * 32),
        ("magic", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    )

    def __init__(self) -> None:
        super().__init__()
        self.abi = DARWIN_NUMERIC_OWNER_ABI
        self.publication_state = _PUBLICATION_NEW


class _NativeOutcome(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("publication_state", ctypes.c_uint32),
        ("status", ctypes.c_int32),
        ("owner_state", ctypes.c_int32),
        ("error_code", ctypes.c_int32),
        ("connect_count", ctypes.c_uint32),
        ("close_count", ctypes.c_uint32),
        ("peer_exact", ctypes.c_uint32),
        ("family", ctypes.c_uint32),
        ("nonblocking", ctypes.c_uint32),
        ("magic", ctypes.c_uint32),
    )

    def __init__(self) -> None:
        super().__init__()
        self.abi = DARWIN_NUMERIC_OWNER_ABI
        self.publication_state = _PUBLICATION_NEW


class _NativeToken(ctypes.Structure):
    _fields_ = (("bytes", ctypes.c_uint8 * 32),)

    def __init__(self, token: bytes) -> None:
        super().__init__()
        if type(token) is not bytes or len(token) != 32 or not any(token):
            raise ValueError("opaque numeric token must be 32 non-zero bytes")
        self.bytes[:] = token


def _publication_token(publication: _NativeCreatePublication) -> bytes:
    return bytes(publication.token)


def _require_committed_outcome(outcome: _NativeOutcome) -> _NativeOutcome:
    if (
        type(outcome) is not _NativeOutcome
        or outcome.abi != DARWIN_NUMERIC_OWNER_ABI
        or outcome.publication_state != _PUBLICATION_COMMITTED
        or outcome.magic != _OUTCOME_MAGIC
        or outcome.owner_state not in _STATE_NAMES
        or outcome.connect_count > 1
        or outcome.close_count > 1
        or outcome.peer_exact not in (0, 1)
        or outcome.nonblocking not in (0, 1)
        or outcome.family not in (int(socket.AF_INET), int(socket.AF_INET6))
    ):
        _raise_owner_error()
    return outcome


class _NativeBindings:
    """Typed functions from one explicitly supplied local test dylib."""

    __slots__ = (
        "library",
        "transfer_contract_abi",
        "transfer_contract_size",
        "transfer_contract_version",
        "create",
        "connect",
        "poll",
        "query",
        "transfer",
        "close",
        "retire",
    )

    def __init__(self, native_library_path: str) -> None:
        if sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8:
            _raise_owner_error()
        if type(native_library_path) is not str or not native_library_path:
            raise TypeError("native_library_path must be a non-empty string")
        selected = Path(native_library_path)
        if not selected.is_absolute() or not selected.is_file():
            raise ValueError("native_library_path must be an absolute file")
        try:
            library = ctypes.CDLL(str(selected), use_errno=True)
            abi = library.sq_numeric_owner_abi
            abi.argtypes = ()
            abi.restype = ctypes.c_uint32
            vtable_size = library.sq_numeric_syscalls_size
            vtable_size.argtypes = ()
            vtable_size.restype = ctypes.c_uint32
            transfer_contract_abi = (
                library.sq_numeric_transfer_contract_abi
            )
            transfer_contract_size = (
                library.sq_numeric_transfer_contract_size
            )
            transfer_contract_version = (
                library.sq_numeric_transfer_contract_version
            )
            for function in (
                transfer_contract_abi,
                transfer_contract_size,
                transfer_contract_version,
            ):
                function.argtypes = ()
                function.restype = ctypes.c_uint32
            create = library.sq_numeric_owner_create_publish
            create.argtypes = (
                ctypes.POINTER(_NativeCreatePublication),
                ctypes.c_int32,
                ctypes.c_int32,
                ctypes.c_int32,
                ctypes.c_void_p,
            )
            connect = library.sq_numeric_owner_connect_publish
            connect.argtypes = (
                ctypes.POINTER(_NativeToken),
                ctypes.c_int32,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_uint32,
                ctypes.c_uint16,
                ctypes.POINTER(_NativeOutcome),
            )
            poll = library.sq_numeric_owner_poll_publish
            poll.argtypes = (
                ctypes.POINTER(_NativeToken),
                ctypes.c_uint64,
                ctypes.POINTER(_NativeOutcome),
            )
            query = library.sq_numeric_owner_query_publish
            query.argtypes = (
                ctypes.POINTER(_NativeToken),
                ctypes.POINTER(_NativeOutcome),
            )
            transfer = library.sq_numeric_owner_transfer_publish
            transfer.argtypes = (
                ctypes.POINTER(_NativeToken),
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(_NativeOutcome),
            )
            close = library.sq_numeric_owner_close_publish
            close.argtypes = (
                ctypes.POINTER(_NativeToken),
                ctypes.POINTER(_NativeOutcome),
            )
            retire = library.sq_numeric_owner_retire
            retire.argtypes = (ctypes.POINTER(_NativeToken),)
            for function in (
                create,
                connect,
                poll,
                query,
                transfer,
                close,
                retire,
            ):
                function.restype = ctypes.c_int32
            if (
                abi() != DARWIN_NUMERIC_OWNER_ABI
                or vtable_size() <= 0
                or transfer_contract_abi()
                != DARWIN_OWNER_TRANSFER_CONTRACT_ABI
                or transfer_contract_size()
                != DARWIN_OWNER_TRANSFER_CONTRACT_SIZE
                or transfer_contract_version()
                != DARWIN_OWNER_TRANSFER_CONTRACT_VERSION
            ):
                raise ValueError("native numeric owner ABI mismatch")
        except BaseException:
            _raise_owner_error()
        self.library = library
        self.transfer_contract_abi = transfer_contract_abi
        self.transfer_contract_size = transfer_contract_size
        self.transfer_contract_version = transfer_contract_version
        self.create = create
        self.connect = connect
        self.poll = poll
        self.query = query
        self.transfer = transfer
        self.close = close
        self.retire = retire


def _invoke_operation(function: object, *arguments: object) -> _NativeOutcome:
    outcome = _NativeOutcome()
    try:
        result = function(*arguments, ctypes.byref(outcome))  # type: ignore[operator]
    except BaseException:
        # The native cell is authoritative when a Python return event is
        # interrupted after the operation committed.
        if outcome.publication_state != _PUBLICATION_COMMITTED:
            _raise_owner_error()
        result = 0
    if type(result) is not int or result != 0:
        _raise_owner_error()
    return _require_committed_outcome(outcome)


@runtime_final
class _DarwinNumericOwnerFactory:
    """Injection-only factory; it carries no production syscall table."""

    __slots__ = ("_bindings", "_vtable")

    def __init__(
        self,
        *,
        bindings: _NativeBindings,
        syscall_vtable: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _FACTORY_AUTHORITY:
            raise TypeError("Darwin numeric owner factories require authority")
        if type(bindings) is not _NativeBindings:
            raise TypeError("bindings must be NativeBindings")
        if type(syscall_vtable) is not int or syscall_vtable <= 0:
            raise ValueError("syscall_vtable must be an opaque positive pointer")
        object.__setattr__(self, "_bindings", bindings)
        object.__setattr__(self, "_vtable", syscall_vtable)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinNumericOwnerFactory is immutable")

    def new_construction(self) -> "_DarwinNumericConstruction":
        return _DarwinNumericConstruction(
            factory=self,
            _authority=_CONSTRUCTION_AUTHORITY,
        )


@runtime_final
class _DarwinNumericConstruction:
    """Caller-preheld owner for the native create/publication return gap."""

    __slots__ = (
        "_factory",
        "_publication",
        "_family",
        "_state",
        "_owner",
        "_lock",
        "_close_lock",
    )

    def __init__(
        self,
        *,
        factory: _DarwinNumericOwnerFactory,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CONSTRUCTION_AUTHORITY:
            raise TypeError("numeric constructions require their factory")
        if type(factory) is not _DarwinNumericOwnerFactory:
            raise TypeError("factory must be DarwinNumericOwnerFactory")
        object.__setattr__(self, "_factory", factory)
        object.__setattr__(self, "_publication", _NativeCreatePublication())
        object.__setattr__(self, "_family", None)
        object.__setattr__(self, "_state", "empty")
        object.__setattr__(self, "_owner", None)
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_close_lock", Lock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinNumericConstruction is externally immutable")

    def _begin(self, family: int) -> _NativeCreatePublication:
        with self._lock:
            if self._state != "empty":
                raise ValueError("numeric owner construction replay is forbidden")
            object.__setattr__(self, "_family", family)
            object.__setattr__(self, "_state", "in_flight")
            return self._publication

    def _sync_publication(self) -> None:
        with self._lock:
            publication = self._publication
            if publication.publication_state != _PUBLICATION_COMMITTED:
                return
            if (
                publication.abi != DARWIN_NUMERIC_OWNER_ABI
                or publication.magic != _CREATE_PUBLICATION_MAGIC
                or publication.reserved != 0
            ):
                object.__setattr__(self, "_state", "uncertain")
                return
            token = _publication_token(publication)
            if any(token) and publication.status in (
                _STATUS_OK,
                _STATUS_UNCERTAIN,
            ):
                object.__setattr__(
                    self,
                    "_state",
                    "published"
                    if publication.status == _STATUS_OK
                    else "uncertain",
                )
            elif not any(token):
                object.__setattr__(self, "_state", "failed_terminal")
            else:
                object.__setattr__(self, "_state", "uncertain")

    def owner(self) -> "_DarwinOpaqueNumericSocketOwner":
        self._sync_publication()
        with self._lock:
            if type(self._owner) is _DarwinOpaqueNumericSocketOwner:
                return self._owner
            publication = self._publication
            token = _publication_token(publication)
            if (
                self._state not in ("published", "uncertain")
                or not any(token)
                or type(self._family) is not int
            ):
                _raise_owner_error()
            owner = _DarwinOpaqueNumericSocketOwner(
                bindings=self._factory._bindings,
                token=token,
                family=self._family,
                _authority=_OWNER_AUTHORITY,
            )
            object.__setattr__(self, "_owner", owner)
            return owner

    def close_once(self) -> None:
        """Recover and close a published token without recreating a socket."""

        with self._close_lock:
            self._sync_publication()
            with self._lock:
                state = self._state
            if state in ("empty", "failed_terminal", "closed"):
                with self._lock:
                    object.__setattr__(self, "_state", "closed")
                return
            owner = self.owner()
            try:
                owner.close_once()
            finally:
                if owner.closed:
                    with self._lock:
                        object.__setattr__(self, "_state", "closed")

    def is_terminal(self) -> bool:
        self._sync_publication()
        with self._lock:
            if self._state in ("failed_terminal", "closed"):
                return True
            owner = self._owner
        return type(owner) is _DarwinOpaqueNumericSocketOwner and owner.closed

    def safe_metadata(self) -> dict[str, object]:
        self._sync_publication()
        with self._lock:
            return {
                "scope": DARWIN_NUMERIC_OWNER_SCOPE,
                "state": self._state,
                "native_create_publication_committed": (
                    self._publication.publication_state
                    == _PUBLICATION_COMMITTED
                ),
                "opaque_token_present": any(
                    _publication_token(self._publication)
                ),
                "raw_descriptor_exposed": False,
                "production_available": False,
            }


@runtime_final
class _DarwinOpaqueNumericSocketOwner:
    """Python capability for one native-owned descriptor and exact peer."""

    __slots__ = (
        "_bindings",
        "_token",
        "_issued_token",
        "_family",
        "_selected",
        "_retired",
        "_operation_lock",
    )

    def __init__(
        self,
        *,
        bindings: _NativeBindings,
        token: bytes,
        family: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _OWNER_AUTHORITY:
            raise TypeError("opaque numeric owners require their construction")
        if (
            type(bindings) is not _NativeBindings
            or type(token) is not bytes
            or len(token) != 32
            or not any(token)
            or family not in (int(socket.AF_INET), int(socket.AF_INET6))
        ):
            raise ValueError("opaque numeric owner binding is invalid")
        object.__setattr__(self, "_bindings", bindings)
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_issued_token", token)
        object.__setattr__(self, "_family", family)
        object.__setattr__(self, "_selected", None)
        object.__setattr__(self, "_retired", False)
        object.__setattr__(self, "_operation_lock", Lock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinOpaqueNumericSocketOwner is immutable")

    def __copy__(self) -> object:
        raise TypeError("DarwinOpaqueNumericSocketOwner cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("DarwinOpaqueNumericSocketOwner cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("DarwinOpaqueNumericSocketOwner cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("DarwinOpaqueNumericSocketOwner cannot be serialized")

    def __repr__(self) -> str:
        return (
            "DarwinOpaqueNumericSocketOwner("
            f"family={self._family_label()!r}, state={self._safe_state()!r})"
        )

    def _family_label(self) -> str:
        return "AF_INET" if self._family == int(socket.AF_INET) else "AF_INET6"

    def _validate_token(self) -> None:
        if (
            type(self._token) is not bytes
            or len(self._token) != 32
            or not any(self._token)
            or self._token != self._issued_token
            or self._retired
        ):
            _raise_owner_error()

    def _query(self) -> _NativeOutcome:
        self._validate_token()
        token = _NativeToken(self._token)
        outcome = _invoke_operation(self._bindings.query, ctypes.byref(token))
        if outcome.status == _STATUS_INVALID_TOKEN:
            _raise_owner_error()
        if outcome.family != self._family:
            _raise_owner_error()
        return outcome

    def _safe_state(self) -> str:
        try:
            outcome = self._query()
        except BaseException:
            return "unavailable"
        return _STATE_NAMES[outcome.owner_state]

    def connect_once(self, selected: ResolvedAddress) -> int:
        """Initiate exactly one connect and retain native exact-peer evidence."""

        if type(selected) is not ResolvedAddress:
            raise TypeError("selected must be ResolvedAddress")
        try:
            selected.validate_integrity()
        except BaseException:
            _raise_owner_error()
        expected_family = (
            int(socket.AF_INET)
            if selected.family is AddressFamily.IPV4
            else int(socket.AF_INET6)
        )
        if expected_family != self._family:
            _raise_owner_error()
        packed = selected.packed
        packed_buffer = (ctypes.c_uint8 * len(packed)).from_buffer_copy(packed)
        token = _NativeToken(self._token)
        with self._operation_lock:
            self._validate_token()
            if self._selected is not None:
                _raise_owner_error()
            # Bind expected peer before crossing the native call.  If Python is
            # interrupted later, query recovers the native one-connect outcome.
            object.__setattr__(self, "_selected", selected)
            outcome = _invoke_operation(
                self._bindings.connect,
                ctypes.byref(token),
                expected_family,
                packed_buffer,
                len(packed),
                selected.port,
            )
        if outcome.status == _STATUS_PENDING:
            return errno.EINPROGRESS
        if (
            outcome.status == _STATUS_OK
            and outcome.owner_state == _OWNER_CONNECTED
            and outcome.connect_count == 1
            and outcome.peer_exact == 1
        ):
            return 0
        _raise_owner_error()

    def confirm_nonblocking(self) -> None:
        """Attest that native creation committed nonblocking mode."""

        outcome = self._query()
        if (
            outcome.nonblocking == 1
            and outcome.owner_state
            in (
                _OWNER_CREATED,
                _OWNER_PENDING,
                _OWNER_CONNECTED,
            )
        ):
            return
        _raise_owner_error()

    def poll(self, *, max_wait_ns: int) -> bool:
        checked_wait = require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        if checked_wait > DARWIN_NUMERIC_OWNER_MAX_WAIT_NS:
            raise ValueError(
                "max_wait_ns exceeds the opaque numeric owner bound"
            )
        token = _NativeToken(self._token)
        with self._operation_lock:
            self._validate_token()
            if type(self._selected) is not ResolvedAddress:
                _raise_owner_error()
            outcome = _invoke_operation(
                self._bindings.poll,
                ctypes.byref(token),
                checked_wait,
            )
        if outcome.status == _STATUS_PENDING:
            return False
        if (
            outcome.status == _STATUS_OK
            and outcome.owner_state == _OWNER_CONNECTED
            and outcome.connect_count == 1
            and outcome.peer_exact == 1
        ):
            return True
        _raise_owner_error()

    def socket_error(self) -> int:
        """Return zero only for native SO_ERROR=0 plus exact peer evidence."""

        outcome = self._query()
        if (
            outcome.status == _STATUS_OK
            and outcome.owner_state == _OWNER_CONNECTED
            and outcome.connect_count == 1
            and outcome.peer_exact == 1
        ):
            return 0
        _raise_owner_error()

    def peername(self) -> tuple[object, ...]:
        """Return the selected tuple only after native exact peer attestation."""

        if self.socket_error() != 0:
            _raise_owner_error()
        selected = self._selected
        if type(selected) is not ResolvedAddress:
            _raise_owner_error()
        return selected.numeric_sockaddr

    def close_once(self) -> None:
        """Claim one native close action; never replay an uncertain result."""

        with self._operation_lock:
            self._validate_token()
            token = _NativeToken(self._token)
            outcome = _invoke_operation(
                self._bindings.close,
                ctypes.byref(token),
            )
        if (
            outcome.status == _STATUS_CLOSED
            and (
                (
                    outcome.owner_state == _OWNER_CLOSED
                    and outcome.close_count == 1
                )
                or (
                    outcome.owner_state == _OWNER_TRANSFERRED
                    and outcome.close_count == 0
                )
            )
        ):
            return
        _raise_owner_error()

    def _transfer_to_tls(
        self,
        *,
        native_accept: ctypes.c_void_p,
        native_context: ctypes.c_void_p,
        _authority: object | None = None,
    ) -> None:
        """Atomically hand the exact connected descriptor to a C acceptor."""

        if _authority is not _TRANSFER_ADAPTER_AUTHORITY:
            raise TypeError("numeric transfer requires adapter authority")
        if (
            type(native_accept) is not ctypes.c_void_p
            or type(native_accept.value) is not int
            or native_accept.value <= 0
            or type(native_context) is not ctypes.c_void_p
            or type(native_context.value) is not int
            or native_context.value <= 0
        ):
            raise ValueError("native TLS transfer target is invalid")
        with self._operation_lock:
            self._validate_token()
            token = _NativeToken(self._token)
            outcome = _invoke_operation(
                self._bindings.transfer,
                ctypes.byref(token),
                native_accept,
                native_context,
            )
        if (
            outcome.status == _STATUS_OK
            and outcome.owner_state == _OWNER_TRANSFERRED
            and outcome.connect_count == 1
            and outcome.close_count == 0
            and outcome.peer_exact == 1
            and outcome.nonblocking == 1
        ):
            return
        _raise_owner_error("opaque numeric socket 原生交接未提交。")

    @property
    def closed(self) -> bool:
        try:
            outcome = self._query()
        except BaseException:
            return False
        return (
            (
                outcome.status == _STATUS_CLOSED
                and outcome.owner_state == _OWNER_CLOSED
                and outcome.close_count == 1
            )
            or (
                outcome.owner_state == _OWNER_TRANSFERRED
                and outcome.close_count == 0
                and outcome.connect_count == 1
                and outcome.peer_exact == 1
            )
        )

    def safe_metadata(self) -> dict[str, object]:
        outcome = self._query()
        return {
            "scope": DARWIN_NUMERIC_OWNER_SCOPE,
            "state": _STATE_NAMES[outcome.owner_state],
            "family": self._family_label(),
            "connect_initiation_count": outcome.connect_count,
            "close_initiation_count": outcome.close_count,
            "peer_exactly_matched": outcome.peer_exact == 1,
            "nonblocking_attested": outcome.nonblocking == 1,
            "native_outcome_publication": True,
            "opaque_token_present": True,
            "raw_descriptor_exposed": False,
            "production_available": False,
        }

    def _retire_for_test(self) -> None:
        """Retire a closed registry tombstone; local acceptance seam only."""

        with self._operation_lock:
            self._validate_token()
            if not self.closed:
                _raise_owner_error()
            try:
                token = _NativeToken(self._token)
                result = self._bindings.retire(ctypes.byref(token))
            except BaseException:
                _raise_owner_error()
            if type(result) is not int or result != 0:
                _raise_owner_error()
            object.__setattr__(self, "_retired", True)

    def _retire_after_tls_close(
        self,
        *,
        _authority: object | None = None,
    ) -> None:
        """Release a descriptor-free transfer tombstone after TLS takes over."""

        if _authority is not _TRANSFER_ADAPTER_AUTHORITY:
            raise TypeError("numeric transfer retirement requires authority")
        with self._operation_lock:
            if self._retired:
                return
            self._validate_token()
            outcome = self._query()
            if (
                outcome.owner_state
                not in (_OWNER_TRANSFERRED, _OWNER_TRANSFER_UNCERTAIN)
                or outcome.connect_count != 1
                or outcome.close_count != 0
                or outcome.peer_exact != 1
            ):
                _raise_owner_error()
            interrupted = False
            failed = False
            try:
                token = _NativeToken(self._token)
                result = self._bindings.retire(ctypes.byref(token))
            except BaseException:
                interrupted = True
                try:
                    token = _NativeToken(self._token)
                    result = self._bindings.retire(ctypes.byref(token))
                except BaseException:
                    failed = True
            if failed:
                _raise_owner_error()
            if type(result) is not int or (
                result != 0 and not (interrupted and result == errno.ENOENT)
            ):
                _raise_owner_error()
            object.__setattr__(self, "_retired", True)


def _new_local_darwin_numeric_owner_factory(
    *,
    native_library_path: str,
    syscall_vtable: object,
    _authority: object | None = None,
) -> _DarwinNumericOwnerFactory:
    """Load the explicit local-test ABI; never discover a production dylib."""

    if _authority is not _LOCAL_TEST_AUTHORITY:
        raise TypeError("local native numeric injection requires test authority")
    if isinstance(syscall_vtable, ctypes.c_void_p):
        pointer = syscall_vtable.value
    elif type(syscall_vtable) is int:
        pointer = syscall_vtable
    else:
        raise TypeError("syscall_vtable must be an opaque native pointer")
    if type(pointer) is not int or pointer <= 0:
        raise ValueError("syscall_vtable pointer is invalid")
    bindings = _NativeBindings(native_library_path)
    return _DarwinNumericOwnerFactory(
        bindings=bindings,
        syscall_vtable=pointer,
        _authority=_FACTORY_AUTHORITY,
    )


def _create_local_darwin_numeric_owner(
    construction: _DarwinNumericConstruction,
    *,
    family: int,
    socket_type: int,
    protocol: int,
    _authority: object | None = None,
) -> None:
    """Create and natively publish one opaque owner; return no resource."""

    if _authority is not _LOCAL_TEST_AUTHORITY:
        raise TypeError("local numeric construction requires test authority")
    if type(construction) is not _DarwinNumericConstruction:
        raise TypeError("construction must be DarwinNumericConstruction")
    checked_family = require_plain_int(family, "family", minimum=1)
    checked_type = require_plain_int(socket_type, "socket_type", minimum=1)
    checked_protocol = require_plain_int(protocol, "protocol", minimum=1)
    if checked_family not in (int(socket.AF_INET), int(socket.AF_INET6)):
        raise ValueError("family must be AF_INET or AF_INET6")
    if checked_type != int(socket.SOCK_STREAM):
        raise ValueError("socket_type must be SOCK_STREAM")
    if checked_protocol != int(socket.IPPROTO_TCP):
        raise ValueError("protocol must be IPPROTO_TCP")
    publication = construction._begin(checked_family)
    try:
        result = construction._factory._bindings.create(
            ctypes.byref(publication),
            checked_family,
            checked_type,
            checked_protocol,
            ctypes.c_void_p(construction._factory._vtable),
        )
    except BaseException:
        construction._sync_publication()
        if publication.publication_state != _PUBLICATION_COMMITTED:
            _raise_owner_error()
        result = 0
    construction._sync_publication()
    if type(result) is not int or result != 0:
        _raise_owner_error()
    if publication.status != _STATUS_OK:
        _raise_owner_error()
    if construction.safe_metadata()["state"] != "published":
        _raise_owner_error()
    return None
