"""Opaque native TLS-pair owner for W09 local/offline verification.

This private module binds the narrow ABI in ``native/darwin_tls_owner.c``.
The ABI owns raw and TLS handles together, publishes that ownership into a
caller-preheld native cell before returning, and exposes only a 32-byte opaque
token to Python.  Handshake/write/read results are cached by operation id so a
Python return interruption can query the committed result without replaying a
possibly wire-visible operation.

The module performs no dynamic loading, SSL setup, DNS, socket construction,
or network operation at import time.  Its vtable is injected only by private
local tests.  It is not wired to the product Transport and is not production
availability evidence.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
from threading import Lock
from typing import NoReturn

from snapquiz.domain._validation import runtime_final
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _exact_tls as exact_tls


__all__ = ()


DARWIN_TLS_OWNER_ABI = "snapquiz.darwin-opaque-tls-owner.v1"
DARWIN_TLS_POLICY_EVIDENCE_SCHEMA_VERSION = (
    "snapquiz.darwin-opaque-tls-policy-evidence.v1"
)
DARWIN_TLS_OWNER_FOUNDATION_AVAILABLE = True
OPAQUE_TLS_SOCKET_OWNER_AVAILABLE = False
MAX_NATIVE_TLS_READ_BYTES = 16 * 1024
MAX_NATIVE_TLS_WRITE_BYTES = 9 * 1024 * 1024
MAX_NATIVE_TLS_WAIT_NS = 50_000_000
DARWIN_OWNER_TRANSFER_CONTRACT_ABI = 0x53515846
DARWIN_OWNER_TRANSFER_CONTRACT_SIZE = 32
DARWIN_OWNER_TRANSFER_CONTRACT_VERSION = 1

_PUBLICATION_AUTHORITY = object()
_BINDINGS_AUTHORITY = object()
_TOKEN_AUTHORITY = object()
_OWNER_AUTHORITY = object()
_EVIDENCE_AUTHORITY = object()
_TEST_TLS_OWNER_AUTHORITY = object()

_RESULT_ABI = 0x53515452
_EVIDENCE_ABI = 0x53515445
_SNAPSHOT_ABI = 0x53515453
_READINESS_ABI = 0x53515457
_VTABLE_ABI = 0x53515456
_VTABLE_VERSION = 1

_CALL_COMMITTED = 0
_CALL_NOT_ISSUED = 1
_CALL_AMBIGUOUS = 2

_IO_COMPLETE = 1
_IO_WANT_READ = 2
_IO_WANT_WRITE = 3
_IO_DATA = 4
_IO_EOF = 5
_IO_NOT_ISSUED = 6
_IO_AMBIGUOUS = 7

_OWNER_ACTIVE = 1
_OWNER_POISONED = 2
_OWNER_CLOSED = 3

_CLOSE_TERMINAL = 1
_CLOSE_RETRYABLE = 2
_CLOSE_UNCERTAIN = 3

_POLICY_FLAGS = 0x01 | 0x02 | 0x04

_WAIT_READ = 1
_WAIT_WRITE = 2
_WAIT_READY = 1
_WAIT_NOT_READY = 2
_WAIT_NOT_ISSUED = 3
_WAIT_AMBIGUOUS = 4


class _CTlsToken(ctypes.Structure):
    _fields_ = (("bytes", ctypes.c_uint8 * 32),)


class _CTlsOperationResult(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("outcome", ctypes.c_uint32),
        ("operation_id", ctypes.c_uint64),
        ("count", ctypes.c_uint64),
    )


class _CTlsPolicyEvidence(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("tls_version", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("hostname_digest", ctypes.c_uint64),
        ("policy_digest", ctypes.c_uint8 * 32),
    )


class _CTlsSnapshot(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("owner_state", ctypes.c_uint32),
        ("policy_attested", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("handshake_calls", ctypes.c_uint64),
        ("write_calls", ctypes.c_uint64),
        ("read_calls", ctypes.c_uint64),
        ("negotiated_calls", ctypes.c_uint64),
        ("tls_close_actions", ctypes.c_uint64),
        ("raw_close_actions", ctypes.c_uint64),
        ("last_handshake_operation_id", ctypes.c_uint64),
        ("last_write_operation_id", ctypes.c_uint64),
        ("last_read_operation_id", ctypes.c_uint64),
    )


class _CTlsReadinessSnapshot(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("transferred_raw", ctypes.c_uint32),
        ("last_direction", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("wait_calls", ctypes.c_uint64),
        ("last_max_wait_ns", ctypes.c_uint64),
    )


class _CPythonBuffer(ctypes.Structure):
    """Private CPython ``Py_buffer`` layout for zero-copy readonly views."""

    _fields_ = (
        ("buf", ctypes.c_void_p),
        ("obj", ctypes.c_void_p),
        ("length", ctypes.c_ssize_t),
        ("itemsize", ctypes.c_ssize_t),
        ("readonly", ctypes.c_int),
        ("ndim", ctypes.c_int),
        ("format", ctypes.c_char_p),
        ("shape", ctypes.POINTER(ctypes.c_ssize_t)),
        ("strides", ctypes.POINTER(ctypes.c_ssize_t)),
        ("suboffsets", ctypes.POINTER(ctypes.c_ssize_t)),
        ("internal", ctypes.c_void_p),
    )


_CreatePairCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_size_t),
)
_HandshakeCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint32),
)
_WriteCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_size_t),
)
_ReadCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_size_t),
)
_NegotiatedCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)
_CloseCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_size_t,
)
_ObserveClosedCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint32),
)


class _CTlsVtable(ctypes.Structure):
    _fields_ = (
        ("abi", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("create_pair", _CreatePairCallback),
        ("handshake", _HandshakeCallback),
        ("write", _WriteCallback),
        ("read", _ReadCallback),
        ("negotiated", _NegotiatedCallback),
        ("close_tls", _CloseCallback),
        ("close_raw", _CloseCallback),
        ("tls_is_closed", _ObserveClosedCallback),
        ("raw_is_closed", _ObserveClosedCallback),
    )


def _tls_owner_error(
    safe_message: str = "TLS 原生所有权边界不可用。",
) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="darwin_tls_owner",
        retryable=False,
        safe_message=safe_message,
    )
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_tls_owner_error(
    safe_message: str = "TLS 原生所有权边界不可用。",
) -> NoReturn:
    raise _tls_owner_error(safe_message) from None


def _require_operation_id(value: object) -> int:
    if type(value) is not int or not 1 <= value <= (1 << 64) - 1:
        raise ValueError("operation_id must be an exact positive uint64")
    return value


def _fnv1a(value: bytes) -> int:
    selected = 14_695_981_039_346_656_037
    for item in value:
        selected ^= item
        selected = (selected * 1_099_511_628_211) & ((1 << 64) - 1)
    return selected


def _token_bytes(token: _CTlsToken) -> bytes:
    return bytes(ctypes.string_at(ctypes.byref(token), ctypes.sizeof(token)))


def _token_struct(value: bytes) -> _CTlsToken:
    if type(value) is not bytes or len(value) != ctypes.sizeof(_CTlsToken):
        raise ValueError("opaque TLS token has an invalid shape")
    return _CTlsToken.from_buffer_copy(value)


@runtime_final
class _OpaqueTlsToken:
    __slots__ = ("_value", "_issued_digest")

    def __init__(
        self,
        value: bytes,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TOKEN_AUTHORITY:
            raise TypeError("opaque TLS tokens require native publication")
        checked = bytes(value)
        if len(checked) != 32:
            raise ValueError("opaque TLS token has an invalid shape")
        object.__setattr__(self, "_value", checked)
        object.__setattr__(self, "_issued_digest", hashlib.sha256(checked).digest())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("OpaqueTlsToken is immutable")

    def __copy__(self) -> "_OpaqueTlsToken":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_OpaqueTlsToken":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("OpaqueTlsToken cannot be serialized")

    def _as_c(self, *, _authority: object) -> _CTlsToken:
        if _authority is not _OWNER_AUTHORITY:
            raise TypeError("opaque TLS token access requires its owner")
        if (
            type(self._value) is not bytes
            or len(self._value) != 32
            or type(self._issued_digest) is not bytes
            or hashlib.sha256(self._value).digest() != self._issued_digest
        ):
            _raise_tls_owner_error()
        return _token_struct(self._value)


@runtime_final
class _TlsPolicyEvidence:
    __slots__ = (
        "hostname",
        "policy_digest",
        "tls_version",
        "_hostname_digest",
    )

    def __init__(
        self,
        *,
        hostname: str,
        policy_digest: Digest256,
        tls_version: str,
        hostname_digest: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _EVIDENCE_AUTHORITY:
            raise TypeError("TLS policy evidence requires native attestation")
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "policy_digest", policy_digest)
        object.__setattr__(self, "tls_version", tls_version)
        object.__setattr__(self, "_hostname_digest", hostname_digest)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("TlsPolicyEvidence is immutable")

    def __copy__(self) -> "_TlsPolicyEvidence":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_TlsPolicyEvidence":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("TlsPolicyEvidence cannot be serialized")

    def validate_integrity(self) -> None:
        checked_hostname = exact_tls._require_canonical_hostname(self.hostname)
        if (
            type(self.policy_digest) is not Digest256
            or self.tls_version not in ("TLSv1.2", "TLSv1.3")
            or type(self._hostname_digest) is not int
            or _fnv1a(checked_hostname.encode("ascii")) != self._hostname_digest
        ):
            _raise_tls_owner_error("TLS 原生策略证据无效。")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "alpn": "http/1.1",
            "hostname": self.hostname,
            "hostname_verified": True,
            "native_owner_abi": DARWIN_TLS_OWNER_ABI,
            "policy_digest_prefix": str(self.policy_digest)[:12],
            "tls_version": self.tls_version,
        }


class _DarwinTlsOwnerBindings:
    """Typed functions from one explicitly supplied local test library."""

    __slots__ = (
        "publication_size",
        "vtable_size",
        "transfer_contract_abi",
        "transfer_contract_size",
        "transfer_contract_version",
        "adopt_vtable_size",
        "transfer_context_size",
        "publication_init",
        "transfer_context_init",
        "accept_transfer",
        "transfer_context_deinit",
        "create_publish",
        "snapshot_token",
        "handshake",
        "wait_ready",
        "write",
        "read",
        "attest_policy",
        "close",
        "snapshot",
        "readiness_snapshot",
        "test_fail_next_write_allocation",
        "release",
        "publication_deinit",
    )

    def __init__(
        self,
        library: object,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BINDINGS_AUTHORITY:
            raise TypeError("native TLS bindings require their private loader")
        try:
            publication_size = library.sq_tls_publication_size
            vtable_size = library.sq_tls_vtable_size
            adopt_vtable_size = library.sq_tls_adopt_vtable_size
            transfer_context_size = (
                library.sq_tls_numeric_transfer_context_size
            )
            transfer_contract_abi = library.sq_tls_transfer_contract_abi
            transfer_contract_size = library.sq_tls_transfer_contract_size
            transfer_contract_version = (
                library.sq_tls_transfer_contract_version
            )
            publication_init = library.sq_tls_publication_init
            transfer_context_init = (
                library.sq_tls_numeric_transfer_context_init
            )
            accept_transfer = library.sq_tls_accept_numeric_transfer
            transfer_context_deinit = (
                library.sq_tls_numeric_transfer_context_deinit
            )
            create_publish = library.sq_tls_create_publish
            snapshot_token = library.sq_tls_snapshot_token
            handshake = library.sq_tls_handshake
            wait_ready = library.sq_tls_wait_ready
            write = library.sq_tls_write
            read = library.sq_tls_read
            attest_policy = library.sq_tls_attest_policy
            close = library.sq_tls_close
            snapshot = library.sq_tls_snapshot
            readiness_snapshot = library.sq_tls_readiness_snapshot
            test_fail_next_write_allocation = (
                library.sq_tls_test_fail_next_write_allocation
            )
            release = library.sq_tls_release
            publication_deinit = library.sq_tls_publication_deinit
        except BaseException:
            _raise_tls_owner_error()
        publication_size.argtypes = ()
        publication_size.restype = ctypes.c_size_t
        vtable_size.argtypes = ()
        vtable_size.restype = ctypes.c_size_t
        adopt_vtable_size.argtypes = ()
        adopt_vtable_size.restype = ctypes.c_size_t
        transfer_context_size.argtypes = ()
        transfer_context_size.restype = ctypes.c_size_t
        for function in (
            transfer_contract_abi,
            transfer_contract_size,
            transfer_contract_version,
        ):
            function.argtypes = ()
            function.restype = ctypes.c_uint32
        publication_init.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        transfer_context_init.argtypes = (
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsVtable),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
        )
        accept_transfer.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.c_int32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )
        transfer_context_deinit.argtypes = (ctypes.c_void_p,)
        create_publish.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsVtable),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
        )
        snapshot_token.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
        )
        handshake.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.c_uint64,
            ctypes.POINTER(_CTlsOperationResult),
        )
        wait_ready.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint32),
        )
        write.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(_CTlsOperationResult),
        )
        read.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.c_uint64,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(_CTlsOperationResult),
        )
        attest_policy.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.POINTER(_CTlsPolicyEvidence),
        )
        close.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.POINTER(ctypes.c_uint32),
        )
        snapshot.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.POINTER(_CTlsSnapshot),
        )
        readiness_snapshot.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
            ctypes.POINTER(_CTlsReadinessSnapshot),
        )
        test_fail_next_write_allocation.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
        )
        release.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_CTlsToken),
        )
        publication_deinit.argtypes = (ctypes.c_void_p,)
        for function in (
            publication_init,
            transfer_context_init,
            accept_transfer,
            transfer_context_deinit,
            create_publish,
            snapshot_token,
            handshake,
            wait_ready,
            write,
            read,
            attest_policy,
            close,
            snapshot,
            readiness_snapshot,
            test_fail_next_write_allocation,
            release,
            publication_deinit,
        ):
            function.restype = ctypes.c_int32
        if (
            transfer_contract_abi()
            != DARWIN_OWNER_TRANSFER_CONTRACT_ABI
            or transfer_contract_size()
            != DARWIN_OWNER_TRANSFER_CONTRACT_SIZE
            or transfer_contract_version()
            != DARWIN_OWNER_TRANSFER_CONTRACT_VERSION
        ):
            _raise_tls_owner_error("TLS 原生交接 ABI 不匹配。")
        self.publication_size = publication_size
        self.vtable_size = vtable_size
        self.transfer_contract_abi = transfer_contract_abi
        self.transfer_contract_size = transfer_contract_size
        self.transfer_contract_version = transfer_contract_version
        self.adopt_vtable_size = adopt_vtable_size
        self.transfer_context_size = transfer_context_size
        self.publication_init = publication_init
        self.transfer_context_init = transfer_context_init
        self.accept_transfer = accept_transfer
        self.transfer_context_deinit = transfer_context_deinit
        self.create_publish = create_publish
        self.snapshot_token = snapshot_token
        self.handshake = handshake
        self.wait_ready = wait_ready
        self.write = write
        self.read = read
        self.attest_policy = attest_policy
        self.close = close
        self.snapshot = snapshot
        self.readiness_snapshot = readiness_snapshot
        self.test_fail_next_write_allocation = test_fail_next_write_allocation
        self.release = release
        self.publication_deinit = publication_deinit


def _load_bindings_for_test(
    library_path: str,
    *,
    _authority: object | None = None,
) -> _DarwinTlsOwnerBindings:
    if _authority is not _TEST_TLS_OWNER_AUTHORITY:
        raise TypeError("native TLS test loading requires private authority")
    if type(library_path) is not str or not library_path:
        raise ValueError("library_path must be non-empty text")
    try:
        library = ctypes.CDLL(library_path, use_errno=True)
    except BaseException:
        _raise_tls_owner_error()
    return _DarwinTlsOwnerBindings(
        library,
        _authority=_BINDINGS_AUTHORITY,
    )


def _native_create_publish(
    bindings: _DarwinTlsOwnerBindings,
    storage: ctypes.c_void_p,
    vtable: _CTlsVtable,
    context: ctypes.c_void_p,
    hostname: ctypes.Array[ctypes.c_uint8],
    policy_digest: ctypes.Array[ctypes.c_uint8],
) -> int:
    return bindings.create_publish(
        storage,
        ctypes.byref(vtable),
        context,
        hostname,
        len(hostname),
        policy_digest,
    )


class _OpaqueTlsPublication:
    """Caller-preheld native cell that survives constructor return gaps."""

    __slots__ = (
        "_bindings",
        "_storage_buffer",
        "_storage",
        "_owner",
        "_creating",
        "_deinitialized",
        "_lock",
        "_keepalive",
    )

    def __init__(
        self,
        bindings: _DarwinTlsOwnerBindings,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PUBLICATION_AUTHORITY:
            raise TypeError("opaque TLS publications require their factory")
        if type(bindings) is not _DarwinTlsOwnerBindings:
            raise TypeError("bindings must be DarwinTlsOwnerBindings")
        size = bindings.publication_size()
        if type(size) is not int or not 16 <= size <= 1 << 20:
            _raise_tls_owner_error()
        if bindings.vtable_size() != ctypes.sizeof(_CTlsVtable):
            _raise_tls_owner_error()
        storage_buffer = ctypes.create_string_buffer(size)
        storage = ctypes.cast(storage_buffer, ctypes.c_void_p)
        if bindings.publication_init(storage, size) != 0:
            _raise_tls_owner_error()
        self._bindings = bindings
        self._storage_buffer = storage_buffer
        self._storage = storage
        self._owner: _OpaqueTlsOwner | None = None
        self._creating = False
        self._deinitialized = False
        self._lock = Lock()
        self._keepalive: object | None = None

    def _recover_token(self) -> _OpaqueTlsToken | None:
        token = _CTlsToken()
        try:
            status = self._bindings.snapshot_token(
                self._storage,
                ctypes.byref(token),
            )
        except BaseException:
            # Snapshotting is read-only.  A return-gap interruption can be
            # recovered by taking the same native snapshot once more.
            token = _CTlsToken()
            try:
                status = self._bindings.snapshot_token(
                    self._storage,
                    ctypes.byref(token),
                )
            except BaseException:
                _raise_tls_owner_error()
        if status in (errno.ENOENT, errno.ESTALE):
            return None
        if status != 0:
            _raise_tls_owner_error()
        return _OpaqueTlsToken(
            _token_bytes(token),
            _authority=_TOKEN_AUTHORITY,
        )

    def _create(
        self,
        *,
        vtable: _CTlsVtable,
        context: ctypes.c_void_p,
        hostname: str,
        policy_digest: Digest256,
        keepalive: object,
    ) -> None:
        checked_hostname = exact_tls._require_canonical_hostname(hostname)
        if type(policy_digest) is not Digest256:
            raise ValueError("policy_digest must be Digest256")
        if type(vtable) is not _CTlsVtable:
            raise TypeError("vtable must be CTlsVtable")
        if type(context) is not ctypes.c_void_p:
            raise TypeError("context must be c_void_p")
        hostname_bytes = checked_hostname.encode("ascii")
        hostname_buffer = (ctypes.c_uint8 * len(hostname_bytes))(
            *hostname_bytes
        )
        digest_bytes = bytes.fromhex(str(policy_digest))
        digest_buffer = (ctypes.c_uint8 * len(digest_bytes))(*digest_bytes)
        native_status: int | None = None
        with self._lock:
            if (
                self._deinitialized
                or self._creating
                or self._owner is not None
            ):
                raise ValueError("opaque TLS publication replay is forbidden")
            self._creating = True
        try:
            try:
                native_status = _native_create_publish(
                    self._bindings,
                    self._storage,
                    vtable,
                    context,
                    hostname_buffer,
                    digest_buffer,
                )
            finally:
                token = self._recover_token()
                with self._lock:
                    if token is not None and self._owner is None:
                        self._keepalive = keepalive
                        self._owner = _OpaqueTlsOwner(
                            publication=self,
                            token=token,
                            hostname=checked_hostname,
                            policy_digest=policy_digest,
                            _authority=_OWNER_AUTHORITY,
                        )
        finally:
            with self._lock:
                self._creating = False
        if native_status != 0:
            _raise_tls_owner_error()

    def _recover_transferred(
        self,
        *,
        hostname: str,
        policy_digest: Digest256,
        keepalive: object,
    ) -> None:
        """Materialize the facade for an already committed C-to-C handoff."""

        checked_hostname = exact_tls._require_canonical_hostname(hostname)
        if type(policy_digest) is not Digest256:
            raise ValueError("policy_digest must be Digest256")
        with self._lock:
            if self._deinitialized or self._creating:
                raise ValueError("opaque TLS publication is unavailable")
            if self._owner is not None:
                if (
                    self._owner._hostname != checked_hostname
                    or self._owner._policy_digest != policy_digest
                ):
                    _raise_tls_owner_error()
                return
            self._creating = True
        try:
            token = self._recover_token()
            if token is None:
                _raise_tls_owner_error("TLS 原生交接未发布所有权。")
            with self._lock:
                if self._owner is None:
                    self._keepalive = keepalive
                    self._owner = _OpaqueTlsOwner(
                        publication=self,
                        token=token,
                        hostname=checked_hostname,
                        policy_digest=policy_digest,
                        _authority=_OWNER_AUTHORITY,
                    )
        finally:
            with self._lock:
                self._creating = False

    def has_owner(self) -> bool:
        with self._lock:
            return self._owner is not None

    def owner(self) -> "_OpaqueTlsOwner":
        with self._lock:
            if self._owner is None:
                raise ValueError("opaque TLS owner is unavailable")
            return self._owner

    def owns(self, owner: object) -> bool:
        with self._lock:
            return self._owner is owner

    def _forget_released(self, owner: "_OpaqueTlsOwner") -> None:
        with self._lock:
            if self._owner is not owner:
                raise ValueError("opaque TLS publication owner changed")
            self._owner = None
            self._keepalive = None

    def deinitialize(self) -> None:
        with self._lock:
            if self._deinitialized:
                return
            if self._creating:
                raise ValueError("opaque TLS publication creation is active")
            if self._owner is not None:
                raise ValueError("opaque TLS owner must be released first")
            interrupted = False
            try:
                status = self._bindings.publication_deinit(self._storage)
            except BaseException:
                interrupted = True
                try:
                    status = self._bindings.publication_deinit(self._storage)
                except BaseException:
                    _raise_tls_owner_error()
            if status != 0 and not (interrupted and status == errno.EINVAL):
                _raise_tls_owner_error()
            self._deinitialized = True


@runtime_final
class _OpaqueTlsOwner:
    """Python facade containing only an opaque publication and token."""

    __slots__ = (
        "_publication",
        "_token",
        "_hostname",
        "_policy_digest",
        "_released",
        "_release_lock",
    )

    def __init__(
        self,
        *,
        publication: _OpaqueTlsPublication,
        token: _OpaqueTlsToken,
        hostname: str,
        policy_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _OWNER_AUTHORITY:
            raise TypeError("opaque TLS owners require native publication")
        self._publication = publication
        self._token = token
        self._hostname = hostname
        self._policy_digest = policy_digest
        self._released = False
        self._release_lock = Lock()

    def __copy__(self) -> "_OpaqueTlsOwner":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_OpaqueTlsOwner":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("OpaqueTlsOwner cannot be serialized")

    def _call_token(self) -> _CTlsToken:
        if self._released or not self._publication.owns(self):
            _raise_tls_owner_error("TLS 原生所有权 token 已失效。")
        return self._token._as_c(_authority=_OWNER_AUTHORITY)

    @staticmethod
    def _validate_result(
        result: _CTlsOperationResult,
        *,
        operation_id: int,
    ) -> None:
        if (
            result.abi != _RESULT_ABI
            or result.operation_id != operation_id
        ):
            _raise_tls_owner_error()

    def handshake_step(self, *, operation_id: int) -> str:
        checked_id = _require_operation_id(operation_id)
        token = self._call_token()
        result = _CTlsOperationResult()
        status = self._publication._bindings.handshake(
            self._publication._storage,
            ctypes.byref(token),
            checked_id,
            ctypes.byref(result),
        )
        if status != 0:
            _raise_tls_owner_error()
        self._validate_result(result, operation_id=checked_id)
        outcomes = {
            _IO_COMPLETE: "complete",
            _IO_WANT_READ: "want_read",
            _IO_WANT_WRITE: "want_write",
            _IO_NOT_ISSUED: "not_issued",
            _IO_AMBIGUOUS: "ambiguous",
        }
        selected = outcomes.get(result.outcome)
        if selected is None or result.count != 0:
            _raise_tls_owner_error()
        return selected

    def wait_ready(self, *, direction: str, max_wait_ns: int) -> bool:
        if direction == "want_read":
            native_direction = _WAIT_READ
        elif direction == "want_write":
            native_direction = _WAIT_WRITE
        else:
            raise ValueError("TLS wait direction is invalid")
        if (
            type(max_wait_ns) is not int
            or not 1 <= max_wait_ns <= MAX_NATIVE_TLS_WAIT_NS
        ):
            raise ValueError("TLS wait bound is invalid")
        token = self._call_token()
        outcome = ctypes.c_uint32()
        status = self._publication._bindings.wait_ready(
            self._publication._storage,
            ctypes.byref(token),
            native_direction,
            max_wait_ns,
            ctypes.byref(outcome),
        )
        if status != 0:
            _raise_tls_owner_error("TLS 原生有界 readiness 不可用。")
        if outcome.value == _WAIT_READY:
            return True
        if outcome.value in (_WAIT_NOT_READY, _WAIT_NOT_ISSUED):
            return False
        if outcome.value == _WAIT_AMBIGUOUS:
            _raise_tls_owner_error("TLS 原生 readiness 结果不确定。")
        _raise_tls_owner_error("TLS 原生 readiness 结果无效。")

    def write_once(
        self,
        value: bytes | memoryview,
        *,
        operation_id: int,
    ) -> tuple[str, int]:
        checked_id = _require_operation_id(operation_id)
        lease: _CPythonBuffer | None = None
        release_buffer = ctypes.pythonapi.PyBuffer_Release
        release_buffer.argtypes = (ctypes.POINTER(_CPythonBuffer),)
        release_buffer.restype = None
        if type(value) is bytes:
            selected_length = len(value)
            if not selected_length:
                raise ValueError("TLS write value must not be empty")
            if selected_length > MAX_NATIVE_TLS_WRITE_BYTES:
                raise ValueError(
                    "TLS write value exceeds the native owner limit"
                )
            buffer = (ctypes.c_uint8 * selected_length).from_buffer_copy(value)
        elif type(value) is memoryview:
            if (
                value.ndim != 1
                or not value.c_contiguous
                or not value.readonly
                or value.format not in ("B", "b", "c")
            ):
                raise ValueError(
                    "TLS write view must be readonly contiguous bytes"
                )
            selected_length = value.nbytes
            if not selected_length:
                raise ValueError("TLS write value must not be empty")
            if selected_length > MAX_NATIVE_TLS_WRITE_BYTES:
                raise ValueError(
                    "TLS write value exceeds the native owner limit"
                )
            try:
                lease = _CPythonBuffer()
                get_buffer = ctypes.pythonapi.PyObject_GetBuffer
                get_buffer.argtypes = (
                    ctypes.py_object,
                    ctypes.POINTER(_CPythonBuffer),
                    ctypes.c_int,
                )
                get_buffer.restype = ctypes.c_int
                if get_buffer(value, ctypes.byref(lease), 0) != 0:
                    raise ValueError("readonly buffer acquisition failed")
                if (
                    type(lease.buf) is not int
                    or lease.buf <= 0
                    or lease.length != selected_length
                ):
                    raise ValueError("readonly buffer acquisition changed")
                buffer = ctypes.cast(
                    lease.buf,
                    ctypes.POINTER(ctypes.c_uint8),
                )
            except BaseException:
                if lease is not None and lease.obj:
                    release_buffer(ctypes.byref(lease))
                _raise_tls_owner_error()
        else:
            raise TypeError("TLS write value must be bytes or memoryview")
        token = self._call_token()
        result = _CTlsOperationResult()
        try:
            status = self._publication._bindings.write(
                self._publication._storage,
                ctypes.byref(token),
                checked_id,
                buffer,
                selected_length,
                ctypes.byref(result),
            )
        finally:
            if lease is not None and lease.obj:
                release_buffer(ctypes.byref(lease))
        if status != 0:
            _raise_tls_owner_error()
        self._validate_result(result, operation_id=checked_id)
        if (
            result.outcome == _IO_COMPLETE
            and 0 < result.count <= selected_length
        ):
            return "written", result.count
        if result.outcome == _IO_WANT_READ and result.count == 0:
            return "want_read", 0
        if result.outcome == _IO_WANT_WRITE and result.count == 0:
            return "want_write", 0
        if result.outcome == _IO_NOT_ISSUED and result.count == 0:
            return "not_issued", 0
        if result.outcome == _IO_AMBIGUOUS and result.count == 0:
            return "ambiguous", 0
        _raise_tls_owner_error()

    def read_once(
        self,
        maximum: int,
        *,
        operation_id: int,
    ) -> tuple[str, bytes | None]:
        checked_id = _require_operation_id(operation_id)
        if (
            type(maximum) is not int
            or not 1 <= maximum <= MAX_NATIVE_TLS_READ_BYTES
        ):
            raise ValueError("TLS read maximum is invalid")
        output = (ctypes.c_uint8 * maximum)()
        token = self._call_token()
        result = _CTlsOperationResult()
        status = self._publication._bindings.read(
            self._publication._storage,
            ctypes.byref(token),
            checked_id,
            maximum,
            output,
            maximum,
            ctypes.byref(result),
        )
        if status != 0:
            _raise_tls_owner_error()
        self._validate_result(result, operation_id=checked_id)
        if result.outcome == _IO_DATA and 0 < result.count <= maximum:
            return "data", bytes(output[: result.count])
        if result.outcome == _IO_EOF and result.count == 0:
            return "data", b""
        if result.outcome == _IO_WANT_READ and result.count == 0:
            return "want_read", None
        if result.outcome == _IO_WANT_WRITE and result.count == 0:
            return "want_write", None
        if result.outcome == _IO_NOT_ISSUED and result.count == 0:
            return "not_issued", None
        if result.outcome == _IO_AMBIGUOUS and result.count == 0:
            return "ambiguous", None
        _raise_tls_owner_error()

    def attest_policy(self) -> _TlsPolicyEvidence:
        token = self._call_token()
        evidence = _CTlsPolicyEvidence()
        status = self._publication._bindings.attest_policy(
            self._publication._storage,
            ctypes.byref(token),
            ctypes.byref(evidence),
        )
        if status != 0 or evidence.abi != _EVIDENCE_ABI:
            _raise_tls_owner_error("TLS 原生策略证据无效。")
        if evidence.flags != _POLICY_FLAGS or evidence.reserved != 0:
            _raise_tls_owner_error("TLS 原生策略证据无效。")
        policy_digest = Digest256(bytes(evidence.policy_digest).hex())
        if policy_digest != self._policy_digest:
            _raise_tls_owner_error("TLS 原生策略证据无效。")
        tls_version = {12: "TLSv1.2", 13: "TLSv1.3"}.get(
            evidence.tls_version
        )
        if tls_version is None:
            _raise_tls_owner_error("TLS 原生策略证据无效。")
        selected = _TlsPolicyEvidence(
            hostname=self._hostname,
            policy_digest=policy_digest,
            tls_version=tls_version,
            hostname_digest=evidence.hostname_digest,
            _authority=_EVIDENCE_AUTHORITY,
        )
        selected.validate_integrity()
        return selected

    def _snapshot(self) -> _CTlsSnapshot:
        token = self._call_token()
        snapshot = _CTlsSnapshot()
        status = self._publication._bindings.snapshot(
            self._publication._storage,
            ctypes.byref(token),
            ctypes.byref(snapshot),
        )
        if (
            status != 0
            or snapshot.abi != _SNAPSHOT_ABI
            or snapshot.reserved != 0
            or snapshot.owner_state not in (
                _OWNER_ACTIVE,
                _OWNER_POISONED,
                _OWNER_CLOSED,
            )
            or snapshot.policy_attested not in (0, 1)
        ):
            _raise_tls_owner_error()
        return snapshot

    def _readiness_snapshot(self) -> _CTlsReadinessSnapshot:
        token = self._call_token()
        snapshot = _CTlsReadinessSnapshot()
        status = self._publication._bindings.readiness_snapshot(
            self._publication._storage,
            ctypes.byref(token),
            ctypes.byref(snapshot),
        )
        if (
            status != 0
            or snapshot.abi != _READINESS_ABI
            or snapshot.transferred_raw not in (0, 1)
            or snapshot.last_direction not in (0, _WAIT_READ, _WAIT_WRITE)
            or snapshot.reserved != 0
            or snapshot.last_max_wait_ns > MAX_NATIVE_TLS_WAIT_NS
        ):
            _raise_tls_owner_error()
        return snapshot

    @property
    def closed(self) -> bool:
        if self._released:
            return True
        return self._snapshot().owner_state == _OWNER_CLOSED

    def close_once(self) -> None:
        token = self._call_token()
        outcome = ctypes.c_uint32()
        status = self._publication._bindings.close(
            self._publication._storage,
            ctypes.byref(token),
            ctypes.byref(outcome),
        )
        if status != 0:
            _raise_tls_owner_error()
        if outcome.value == _CLOSE_TERMINAL:
            return
        if outcome.value == _CLOSE_RETRYABLE:
            _raise_tls_owner_error("TLS 原生关闭尚未提交，可安全重试。")
        if outcome.value == _CLOSE_UNCERTAIN:
            _raise_tls_owner_error("TLS 原生关闭结果不确定。")
        _raise_tls_owner_error()

    def release(self) -> None:
        with self._release_lock:
            if self._released:
                return
            token = self._call_token()
            interrupted = False
            try:
                status = self._publication._bindings.release(
                    self._publication._storage,
                    ctypes.byref(token),
                )
            except BaseException:
                interrupted = True
                try:
                    status = self._publication._bindings.release(
                        self._publication._storage,
                        ctypes.byref(token),
                    )
                except BaseException:
                    _raise_tls_owner_error(
                        "TLS 原生所有权尚未终结。"
                    )
            if status != 0 and not (interrupted and status == errno.ESTALE):
                _raise_tls_owner_error("TLS 原生所有权尚未终结。")
            self._released = True
            self._publication._forget_released(self)

    def _fail_next_write_allocation_for_test(
        self,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TEST_TLS_OWNER_AUTHORITY:
            raise TypeError("TLS allocation fault injection is test-only")
        token = self._call_token()
        if self._publication._bindings.test_fail_next_write_allocation(
            self._publication._storage,
            ctypes.byref(token),
        ) != 0:
            _raise_tls_owner_error()

    def safe_metadata(self) -> dict[str, object]:
        snapshot = self._snapshot()
        readiness = self._readiness_snapshot()
        state = {
            _OWNER_ACTIVE: "active",
            _OWNER_POISONED: "poisoned",
            _OWNER_CLOSED: "closed",
        }[snapshot.owner_state]
        return {
            "abi": DARWIN_TLS_OWNER_ABI,
            "handshake_calls": snapshot.handshake_calls,
            "last_handshake_operation_id": (
                snapshot.last_handshake_operation_id or None
            ),
            "last_read_operation_id": snapshot.last_read_operation_id or None,
            "last_write_operation_id": snapshot.last_write_operation_id or None,
            "negotiated_calls": snapshot.negotiated_calls,
            "policy_attested": bool(snapshot.policy_attested),
            "production_available": OPAQUE_TLS_SOCKET_OWNER_AVAILABLE,
            "raw_close_actions": snapshot.raw_close_actions,
            "read_calls": snapshot.read_calls,
            "state": state,
            "tls_close_actions": snapshot.tls_close_actions,
            "transferred_raw": bool(readiness.transferred_raw),
            "wait_calls": readiness.wait_calls,
            "last_wait_direction": {
                0: None,
                _WAIT_READ: "want_read",
                _WAIT_WRITE: "want_write",
            }[readiness.last_direction],
            "last_max_wait_ns": readiness.last_max_wait_ns or None,
            "write_calls": snapshot.write_calls,
        }


def _new_publication_for_test(
    bindings: _DarwinTlsOwnerBindings,
    *,
    _authority: object | None = None,
) -> _OpaqueTlsPublication:
    if _authority is not _TEST_TLS_OWNER_AUTHORITY:
        raise TypeError("opaque TLS test publication requires private authority")
    return _OpaqueTlsPublication(
        bindings,
        _authority=_PUBLICATION_AUTHORITY,
    )


def _publish_owner_with_test_vtable(
    *,
    publication: _OpaqueTlsPublication,
    vtable: _CTlsVtable,
    context: ctypes.c_void_p,
    hostname: str,
    policy_digest: Digest256,
    keepalive: object,
    _authority: object | None = None,
) -> None:
    if _authority is not _TEST_TLS_OWNER_AUTHORITY:
        raise TypeError("opaque TLS test factory requires private authority")
    if type(publication) is not _OpaqueTlsPublication:
        raise TypeError("publication must be OpaqueTlsPublication")
    publication._create(
        vtable=vtable,
        context=context,
        hostname=hostname,
        policy_digest=policy_digest,
        keepalive=keepalive,
    )
