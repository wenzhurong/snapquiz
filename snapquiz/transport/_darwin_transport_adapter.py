"""Local/offline atomic bridge from the Darwin numeric owner to TLS.

The numeric descriptor crosses only a C-to-C callback.  Python retains opaque
numeric/TLS bearer tokens plus content-free evidence; it never receives the
descriptor or a socket object.  This module is private, injection-only, and is
not production wiring.
"""
from __future__ import annotations

import ctypes
import errno
import sys
from threading import Lock
from typing import Callable, NoReturn

from snapquiz.domain._validation import runtime_final
from snapquiz.domain.adapter import TransportResponse
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_numeric_owner as numeric_owner
from snapquiz.transport import _darwin_tls_owner as tls_owner
from snapquiz.transport import _exact_tls as exact_tls
from snapquiz.transport import _exact_transport as exact_transport
from snapquiz.transport import _numeric_connect as numeric_connect
from snapquiz.transport.address_policy import ResolvedAddress, ResolutionSet
from snapquiz.transport.http import PreparedResolverAttempt


__all__ = ()


DARWIN_NATIVE_TRANSFER_ADAPTER_ABI = (
    "snapquiz.darwin-native-transfer-adapter.v1"
)
DARWIN_NATIVE_TRANSFER_ADAPTER_FOUNDATION_AVAILABLE = True
DARWIN_NATIVE_TRANSFER_ADAPTER_PRODUCTION_AVAILABLE = False

_FACTORY_AUTHORITY = object()
_EDGE_AUTHORITY = object()
_TLS_EDGE_AUTHORITY = object()
_TRANSFER_CONTEXT_AUTHORITY = object()
_LOCAL_TEST_AUTHORITY = object()


def _adapter_error(
    safe_message: str = "Darwin 原生 Transport 交接不可用。",
) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="darwin_transport_adapter",
        retryable=False,
        safe_message=safe_message,
    )
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_adapter_error(
    safe_message: str = "Darwin 原生 Transport 交接不可用。",
) -> NoReturn:
    raise _adapter_error(safe_message) from None


@runtime_final
class _NativeTlsTransferContext:
    """Caller-preheld native context for one descriptor handoff."""

    __slots__ = ("_bindings", "_buffer", "pointer", "_active")

    def __init__(
        self,
        *,
        bindings: tls_owner._DarwinTlsOwnerBindings,
        publication: tls_owner._OpaqueTlsPublication,
        tls_vtable: tls_owner._CTlsVtable,
        adopt_vtable: ctypes.c_void_p,
        context: ctypes.c_void_p,
        hostname: str,
        policy_digest: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TRANSFER_CONTEXT_AUTHORITY:
            raise TypeError("native transfer contexts require their factory")
        if type(bindings) is not tls_owner._DarwinTlsOwnerBindings:
            raise TypeError("bindings must be DarwinTlsOwnerBindings")
        if type(publication) is not tls_owner._OpaqueTlsPublication:
            raise TypeError("publication must be OpaqueTlsPublication")
        if type(tls_vtable) is not tls_owner._CTlsVtable:
            raise TypeError("tls_vtable must be CTlsVtable")
        if (
            type(adopt_vtable) is not ctypes.c_void_p
            or type(adopt_vtable.value) is not int
            or adopt_vtable.value <= 0
            or type(context) is not ctypes.c_void_p
            or type(context.value) is not int
            or context.value <= 0
        ):
            raise ValueError("native transfer vtable binding is invalid")
        checked_hostname = exact_tls._require_canonical_hostname(hostname)
        if type(policy_digest) is not Digest256:
            raise TypeError("policy_digest must be Digest256")
        size = bindings.transfer_context_size()
        if type(size) is not int or not 64 <= size <= 1 << 20:
            _raise_adapter_error()
        buffer = ctypes.create_string_buffer(size)
        pointer = ctypes.cast(buffer, ctypes.c_void_p)
        hostname_bytes = checked_hostname.encode("ascii")
        hostname_buffer = (ctypes.c_uint8 * len(hostname_bytes))(
            *hostname_bytes
        )
        digest_bytes = bytes.fromhex(str(policy_digest))
        digest_buffer = (ctypes.c_uint8 * len(digest_bytes))(*digest_bytes)
        status = bindings.transfer_context_init(
            pointer,
            size,
            publication._storage,
            ctypes.byref(tls_vtable),
            adopt_vtable,
            context,
            hostname_buffer,
            len(hostname_buffer),
            digest_buffer,
        )
        if status != 0:
            _raise_adapter_error()
        object.__setattr__(self, "_bindings", bindings)
        object.__setattr__(self, "_buffer", buffer)
        object.__setattr__(self, "pointer", pointer)
        object.__setattr__(self, "_active", True)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("NativeTlsTransferContext is immutable")

    def deinitialize(self) -> None:
        if not self._active:
            return
        interrupted = False
        try:
            status = self._bindings.transfer_context_deinit(self.pointer)
        except BaseException:
            interrupted = True
            try:
                status = self._bindings.transfer_context_deinit(self.pointer)
            except BaseException:
                _raise_adapter_error(
                    "Darwin 原生交接上下文尚未终结。"
                )
        if status != 0 and not (interrupted and status == errno.EINVAL):
            _raise_adapter_error("Darwin 原生交接上下文尚未终结。")
        object.__setattr__(self, "_active", False)


@runtime_final
class _DarwinNumericEdgeAdapter:
    """Exact numeric-edge interface backed only by an opaque native token."""

    __slots__ = (
        "_construction",
        "_owner",
        "_selected",
        "_selected_digest",
        "_nonblocking_attested",
        "_transfer_state",
        "_lock",
    )

    def __init__(
        self,
        *,
        construction: numeric_owner._DarwinNumericConstruction,
        owner: numeric_owner._DarwinOpaqueNumericSocketOwner,
        selected: ResolvedAddress,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _EDGE_AUTHORITY:
            raise TypeError("Darwin numeric adapters require their factory")
        if type(construction) is not numeric_owner._DarwinNumericConstruction:
            raise TypeError("construction must be DarwinNumericConstruction")
        if type(owner) is not numeric_owner._DarwinOpaqueNumericSocketOwner:
            raise TypeError("owner must be DarwinOpaqueNumericSocketOwner")
        if type(selected) is not ResolvedAddress:
            raise TypeError("selected must be ResolvedAddress")
        selected.validate_integrity()
        object.__setattr__(self, "_construction", construction)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_selected", selected)
        object.__setattr__(self, "_selected_digest", selected.address_digest)
        object.__setattr__(self, "_nonblocking_attested", False)
        object.__setattr__(self, "_transfer_state", "numeric")
        object.__setattr__(self, "_lock", Lock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinNumericEdgeAdapter is immutable")

    def _validate_selected(self) -> None:
        try:
            self._selected.validate_integrity()
            if self._selected.address_digest != self._selected_digest:
                raise ValueError("numeric adapter selection changed")
        except BaseException:
            _raise_adapter_error()

    def set_nonblocking(self) -> None:
        with self._lock:
            if self._transfer_state != "numeric":
                _raise_adapter_error()
            self._owner.confirm_nonblocking()
            object.__setattr__(self, "_nonblocking_attested", True)

    def connect_once(self, sockaddr: tuple[object, ...]) -> int:
        with self._lock:
            self._validate_selected()
            if (
                self._transfer_state != "numeric"
                or not self._nonblocking_attested
                or type(sockaddr) is not tuple
                or sockaddr != self._selected.numeric_sockaddr
            ):
                _raise_adapter_error()
            return self._owner.connect_once(self._selected)

    def wait_writable(self, *, max_wait_ns: int) -> bool:
        with self._lock:
            if self._transfer_state != "numeric":
                _raise_adapter_error()
            return self._owner.poll(max_wait_ns=max_wait_ns)

    def socket_error(self) -> int:
        with self._lock:
            if self._transfer_state != "numeric":
                _raise_adapter_error()
            return self._owner.socket_error()

    def peername(self) -> tuple[object, ...]:
        with self._lock:
            if self._transfer_state != "numeric":
                _raise_adapter_error()
            return self._owner.peername()

    def _sync_transfer_state(self) -> str:
        with self._lock:
            if self._transfer_state != "numeric":
                return self._transfer_state
            metadata = self._owner.safe_metadata()
            state = metadata.get("state")
            if state == "transferred":
                object.__setattr__(self, "_transfer_state", "transferred")
            elif state == "transfer_uncertain":
                object.__setattr__(
                    self,
                    "_transfer_state",
                    "transfer_uncertain",
                )
            return self._transfer_state

    def _transfer_to_tls(self, transfer: _NativeTlsTransferContext) -> None:
        if type(transfer) is not _NativeTlsTransferContext:
            raise TypeError("transfer must be NativeTlsTransferContext")
        with self._lock:
            if self._transfer_state != "numeric":
                _raise_adapter_error()
            self._owner._transfer_to_tls(
                native_accept=ctypes.cast(
                    transfer._bindings.accept_transfer,
                    ctypes.c_void_p,
                ),
                native_context=transfer.pointer,
                _authority=numeric_owner._TRANSFER_ADAPTER_AUTHORITY,
            )
            object.__setattr__(self, "_transfer_state", "transferred")

    def _retire_transfer_tombstone(self) -> None:
        with self._lock:
            if self._transfer_state == "retired":
                return
            if self._transfer_state not in (
                "transferred",
                "transfer_uncertain",
            ):
                _raise_adapter_error()
            failed = False
            try:
                self._owner._retire_after_tls_close(
                    _authority=numeric_owner._TRANSFER_ADAPTER_AUTHORITY,
                )
            except BaseException:
                failed = True
            if failed:
                _raise_adapter_error("numeric 交接 tombstone 尚未终结。")
            object.__setattr__(self, "_transfer_state", "retired")

    def close_once(self) -> None:
        with self._lock:
            state = self._transfer_state
            if state in ("transferred", "transfer_uncertain", "retired"):
                return
            self._construction.close_once()
            if self._construction.is_terminal():
                object.__setattr__(self, "_transfer_state", "closed")

    @property
    def closed(self) -> bool:
        with self._lock:
            if self._transfer_state in (
                "transferred",
                "transfer_uncertain",
                "retired",
                "closed",
            ):
                return True
            return self._construction.is_terminal()

    def safe_metadata(self) -> dict[str, object]:
        state = self._sync_transfer_state()
        metadata = self._owner.safe_metadata()
        return {
            "abi": DARWIN_NATIVE_TRANSFER_ADAPTER_ABI,
            "native_state": metadata["state"],
            "adapter_state": state,
            "nonblocking_attested": metadata["nonblocking_attested"],
            "raw_descriptor_exposed": False,
            "production_available": False,
        }


@runtime_final
class _DarwinTlsEdgeAdapter:
    """Exact TLS-edge interface with adapter-owned operation identifiers."""

    __slots__ = (
        "_publication",
        "_owner",
        "_raw",
        "_operation_ids",
        "_operation_lock",
        "_close_lock",
        "_terminal",
    )

    def __init__(
        self,
        *,
        publication: tls_owner._OpaqueTlsPublication,
        owner: tls_owner._OpaqueTlsOwner,
        raw: _DarwinNumericEdgeAdapter,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TLS_EDGE_AUTHORITY:
            raise TypeError("Darwin TLS adapters require their factory")
        if type(publication) is not tls_owner._OpaqueTlsPublication:
            raise TypeError("publication must be OpaqueTlsPublication")
        if type(owner) is not tls_owner._OpaqueTlsOwner:
            raise TypeError("owner must be OpaqueTlsOwner")
        if type(raw) is not _DarwinNumericEdgeAdapter:
            raise TypeError("raw must be DarwinNumericEdgeAdapter")
        object.__setattr__(self, "_publication", publication)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(
            self,
            "_operation_ids",
            {"handshake": 1, "write": 1, "read": 1},
        )
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_operation_lock", Lock())
        object.__setattr__(self, "_close_lock", Lock())
        object.__setattr__(self, "_terminal", False)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinTlsEdgeAdapter is immutable")

    def _invoke_operation(
        self,
        kind: str,
        action: Callable[[int], object],
    ) -> object:
        if not self._operation_lock.acquire(blocking=False):
            _raise_adapter_error("Darwin TLS operation 正在进行。")
        try:
            operation_id = self._operation_ids[kind]
            interrupted = False
            try:
                selected = action(operation_id)
            except BaseException:
                interrupted = True
                try:
                    selected = action(operation_id)
                except BaseException:
                    _raise_adapter_error()
            self._operation_ids[kind] = operation_id + 1
            if interrupted:
                _raise_adapter_error("Darwin TLS operation 已恢复并停止重放。")
            return selected
        finally:
            self._operation_lock.release()

    def handshake_step(self) -> str:
        selected = self._invoke_operation(
            "handshake",
            lambda operation_id: self._owner.handshake_step(
                operation_id=operation_id
            ),
        )
        if selected not in ("complete", "want_read", "want_write"):
            _raise_adapter_error("TLS 握手结果不确定。")
        return selected

    def wait_ready(self, *, direction: str, max_wait_ns: int) -> bool:
        if not self._operation_lock.acquire(blocking=False):
            _raise_adapter_error("Darwin TLS readiness 正在进行。")
        try:
            return self._owner.wait_ready(
                direction=direction,
                max_wait_ns=max_wait_ns,
            )
        finally:
            self._operation_lock.release()

    def negotiated_values(self) -> tuple[object, object]:
        if not self._operation_lock.acquire(blocking=False):
            _raise_adapter_error("Darwin TLS policy attestation 正在进行。")
        try:
            try:
                evidence = self._owner.attest_policy()
            except BaseException:
                try:
                    evidence = self._owner.attest_policy()
                except BaseException:
                    _raise_adapter_error("TLS 原生策略证据无效。")
            evidence.validate_integrity()
            return "http/1.1", evidence.tls_version
        finally:
            self._operation_lock.release()

    def write_once(self, value: memoryview) -> tuple[str, int]:
        if (
            type(value) is not memoryview
            or value.ndim != 1
            or not value.c_contiguous
            or not value.readonly
            or value.format not in ("B", "b", "c")
            or not 1 <= value.nbytes <= tls_owner.MAX_NATIVE_TLS_WRITE_BYTES
        ):
            raise ValueError("TLS write input is invalid")
        selected = self._invoke_operation(
            "write",
            lambda operation_id: self._owner.write_once(
                value,
                operation_id=operation_id,
            ),
        )
        if (
            type(selected) is not tuple
            or len(selected) != 2
            or selected[0] not in ("written", "want_read", "want_write")
            or type(selected[1]) is not int
        ):
            _raise_adapter_error("TLS 写入结果不确定。")
        return selected

    def read_once(self, maximum: int) -> tuple[str, bytes | None]:
        if (
            type(maximum) is not int
            or not 1 <= maximum <= tls_owner.MAX_NATIVE_TLS_READ_BYTES
        ):
            raise ValueError("TLS read maximum is invalid")
        selected = self._invoke_operation(
            "read",
            lambda operation_id: self._owner.read_once(
                maximum,
                operation_id=operation_id,
            ),
        )
        if (
            type(selected) is not tuple
            or len(selected) != 2
            or selected[0] not in ("data", "want_read", "want_write")
        ):
            _raise_adapter_error("TLS 读取结果不确定。")
        return selected

    def close_once(self) -> None:
        with self._close_lock:
            if self._terminal:
                return
            for attempt in range(2):
                try:
                    self._owner.close_once()
                except BaseException:
                    if self._owner.closed:
                        break
                    if attempt == 0:
                        continue
                    try:
                        self._raw._retire_transfer_tombstone()
                    except BaseException:
                        pass
                    _raise_adapter_error("TLS 原生关闭未终结。")
                else:
                    break
            if not self._owner.closed:
                try:
                    self._raw._retire_transfer_tombstone()
                except BaseException:
                    pass
                _raise_adapter_error("TLS 原生关闭未终结。")
            try:
                self._owner.release()
                self._publication.deinitialize()
            except BaseException:
                _raise_adapter_error("TLS 原生 publication 未终结。")
            self._raw._retire_transfer_tombstone()
            object.__setattr__(self, "_terminal", True)

    @property
    def closed(self) -> bool:
        with self._close_lock:
            return self._terminal

    def safe_metadata(self) -> dict[str, object]:
        metadata = self._owner.safe_metadata()
        return {
            "abi": DARWIN_NATIVE_TRANSFER_ADAPTER_ABI,
            "native_owner": metadata,
            "operation_ids_managed_by_adapter": True,
            "raw_descriptor_exposed": False,
            "production_available": False,
        }


@runtime_final
class _DarwinNativeTransportFactory:
    """One explicit local-test binding for numeric construction and TLS."""

    __slots__ = (
        "_numeric_factory",
        "_tls_bindings",
        "_tls_vtable",
        "_adopt_vtable",
        "_context",
        "_keepalive",
    )

    def __init__(
        self,
        *,
        numeric_factory: numeric_owner._DarwinNumericOwnerFactory,
        tls_bindings: tls_owner._DarwinTlsOwnerBindings,
        tls_vtable: tls_owner._CTlsVtable,
        adopt_vtable: ctypes.c_void_p,
        context: ctypes.c_void_p,
        keepalive: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _FACTORY_AUTHORITY:
            raise TypeError("Darwin transport factories require authority")
        if type(numeric_factory) is not numeric_owner._DarwinNumericOwnerFactory:
            raise TypeError("numeric_factory is invalid")
        if type(tls_bindings) is not tls_owner._DarwinTlsOwnerBindings:
            raise TypeError("tls_bindings is invalid")
        if type(tls_vtable) is not tls_owner._CTlsVtable:
            raise TypeError("tls_vtable is invalid")
        if (
            numeric_owner.DARWIN_OWNER_TRANSFER_CONTRACT_ABI
            != tls_owner.DARWIN_OWNER_TRANSFER_CONTRACT_ABI
            or numeric_owner.DARWIN_OWNER_TRANSFER_CONTRACT_SIZE
            != tls_owner.DARWIN_OWNER_TRANSFER_CONTRACT_SIZE
            or numeric_owner.DARWIN_OWNER_TRANSFER_CONTRACT_VERSION
            != tls_owner.DARWIN_OWNER_TRANSFER_CONTRACT_VERSION
        ):
            _raise_adapter_error("numeric/TLS 原生交接 ABI 不匹配。")
        object.__setattr__(self, "_numeric_factory", numeric_factory)
        object.__setattr__(self, "_tls_bindings", tls_bindings)
        object.__setattr__(
            self,
            "_tls_vtable",
            tls_owner._CTlsVtable.from_buffer_copy(tls_vtable),
        )
        object.__setattr__(self, "_adopt_vtable", adopt_vtable)
        object.__setattr__(self, "_context", context)
        object.__setattr__(self, "_keepalive", keepalive)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinNativeTransportFactory is immutable")

    def publish_numeric_edge(
        self,
        selected: ResolvedAddress,
        family: int,
        socket_type: int,
        protocol: int,
        publish: Callable[[object], None],
        publication_is_exact: Callable[[object], bool],
    ) -> None:
        if type(selected) is not ResolvedAddress:
            raise TypeError("selected must be ResolvedAddress")
        if not callable(publish) or not callable(publication_is_exact):
            raise TypeError("numeric publication callbacks are invalid")
        construction = self._numeric_factory.new_construction()
        adapter: _DarwinNumericEdgeAdapter | None = None
        committed = False
        try:
            try:
                numeric_owner._create_local_darwin_numeric_owner(
                    construction,
                    family=int(family),
                    socket_type=int(socket_type),
                    protocol=int(protocol),
                    _authority=numeric_owner._LOCAL_TEST_AUTHORITY,
                )
            except BaseException:
                if not construction.safe_metadata()["opaque_token_present"]:
                    raise
            adapter = _DarwinNumericEdgeAdapter(
                construction=construction,
                owner=construction.owner(),
                selected=selected,
                _authority=_EDGE_AUTHORITY,
            )
            try:
                publish(adapter)
            except BaseException:
                committed = publication_is_exact(adapter)
                if not committed:
                    raise
            else:
                committed = publication_is_exact(adapter)
                if not committed:
                    raise ValueError("numeric adapter publication changed")
        finally:
            if not committed:
                try:
                    construction.close_once()
                except BaseException:
                    pass
        if not committed or adapter is None:
            _raise_adapter_error()

    def publish_tls_edge(
        self,
        raw: object,
        policy: exact_tls._ExactTlsPolicy,
        hostname: str,
        publish: Callable[[object], None],
        publication_is_exact: Callable[[object], bool],
    ) -> None:
        if type(raw) is not _DarwinNumericEdgeAdapter:
            raise TypeError("raw edge must be DarwinNumericEdgeAdapter")
        if type(policy) is not exact_tls._ExactTlsPolicy:
            raise TypeError("policy must be ExactTlsPolicy")
        if not callable(publish) or not callable(publication_is_exact):
            raise TypeError("TLS publication callbacks are invalid")
        policy.validate_integrity()
        publication = tls_owner._new_publication_for_test(
            self._tls_bindings,
            _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
        )
        transfer = _NativeTlsTransferContext(
            bindings=self._tls_bindings,
            publication=publication,
            tls_vtable=self._tls_vtable,
            adopt_vtable=self._adopt_vtable,
            context=self._context,
            hostname=hostname,
            policy_digest=policy.policy_digest,
            _authority=_TRANSFER_CONTEXT_AUTHORITY,
        )
        transfer_failure = False
        try:
            raw._transfer_to_tls(transfer)
        except BaseException:
            transfer_failure = True
        finally:
            try:
                transfer.deinitialize()
            except BaseException:
                transfer_failure = True
        transfer_state = raw._sync_transfer_state()
        if transfer_state not in ("transferred", "transfer_uncertain"):
            try:
                publication.deinitialize()
            except BaseException:
                pass
            _raise_adapter_error("numeric owner 未交出关闭权。")

        recovery_failed = False
        try:
            publication._recover_transferred(
                hostname=hostname,
                policy_digest=policy.policy_digest,
                keepalive=self._keepalive,
            )
        except BaseException:
            try:
                publication._recover_transferred(
                    hostname=hostname,
                    policy_digest=policy.policy_digest,
                    keepalive=self._keepalive,
                )
            except BaseException:
                recovery_failed = True
        if recovery_failed:
            _raise_adapter_error("TLS 原生交接 publication 无法恢复。")
        edge = _DarwinTlsEdgeAdapter(
            publication=publication,
            owner=publication.owner(),
            raw=raw,
            _authority=_TLS_EDGE_AUTHORITY,
        )
        committed = False
        try:
            try:
                publish(edge)
            except BaseException:
                committed = publication_is_exact(edge)
                if not committed:
                    raise
            else:
                committed = publication_is_exact(edge)
                if not committed:
                    raise ValueError("TLS adapter publication changed")
        finally:
            if not committed:
                try:
                    edge.close_once()
                except BaseException:
                    pass
        if not committed:
            _raise_adapter_error()
        if transfer_failure and transfer_state != "transferred":
            _raise_adapter_error("numeric/TLS 原生交接结果不确定。")


def _new_local_darwin_transport_factory(
    *,
    numeric_library_path: str,
    numeric_syscall_vtable: object,
    tls_library_path: str,
    tls_vtable: tls_owner._CTlsVtable,
    adopt_vtable: object,
    context: object,
    keepalive: object,
    _authority: object | None = None,
) -> _DarwinNativeTransportFactory:
    if _authority is not _LOCAL_TEST_AUTHORITY:
        raise TypeError("local Darwin transport injection requires authority")
    numeric_factory = numeric_owner._new_local_darwin_numeric_owner_factory(
        native_library_path=numeric_library_path,
        syscall_vtable=numeric_syscall_vtable,
        _authority=numeric_owner._LOCAL_TEST_AUTHORITY,
    )
    bindings = tls_owner._load_bindings_for_test(
        tls_library_path,
        _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
    )
    if isinstance(adopt_vtable, ctypes.c_void_p):
        adopt_pointer = adopt_vtable
    elif type(adopt_vtable) is int:
        adopt_pointer = ctypes.c_void_p(adopt_vtable)
    else:
        raise TypeError("adopt_vtable must be an opaque native pointer")
    if isinstance(context, ctypes.c_void_p):
        context_pointer = context
    elif type(context) is int:
        context_pointer = ctypes.c_void_p(context)
    else:
        raise TypeError("context must be an opaque native pointer")
    return _DarwinNativeTransportFactory(
        numeric_factory=numeric_factory,
        tls_bindings=bindings,
        tls_vtable=tls_vtable,
        adopt_vtable=adopt_pointer,
        context=context_pointer,
        keepalive=keepalive,
        _authority=_FACTORY_AUTHORITY,
    )


def _send_exact_with_local_darwin_owners(
    prepared_attempt: PreparedResolverAttempt,
    *,
    factory: _DarwinNativeTransportFactory,
    _authority: object | None = None,
) -> TransportResponse:
    """Private end-to-end seam proving the existing exact-edge contracts."""

    if _authority is not _LOCAL_TEST_AUTHORITY:
        raise TypeError("local Darwin exact transport requires authority")
    if type(prepared_attempt) is not PreparedResolverAttempt:
        raise TypeError("prepared_attempt must be PreparedResolverAttempt")
    if type(factory) is not _DarwinNativeTransportFactory:
        raise TypeError("factory must be DarwinNativeTransportFactory")
    ledger = numeric_connect._new_numeric_connect_ledger_for_test()

    def start_numeric(
        resolution: ResolutionSet,
        max_wait_ns: int,
        construction: numeric_connect._NumericConstructionSlot,
    ) -> None:
        selected = resolution.selected

        def create_edge(
            family: int,
            socket_type: int,
            protocol: int,
            publish: Callable[[object], None],
            publication_is_exact: Callable[[object], bool],
        ) -> None:
            return factory.publish_numeric_edge(
                selected,
                family,
                socket_type,
                protocol,
                publish,
                publication_is_exact,
            )

        return numeric_connect._publish_selected_numeric_with_test_edge(
            resolution,
            max_wait_ns=max_wait_ns,
            ledger=ledger,
            edge_factory=create_edge,
            construction=construction,
            _authority=numeric_connect._TEST_EDGE_AUTHORITY,
        )

    response: TransportResponse | None = None
    failure: tuple[object, ...] | None = None
    try:
        response = exact_transport._run_exact_transport(
            prepared_attempt,
            numeric_start=start_numeric,
            tls_factory=factory.publish_tls_edge,
        )
    except BaseException:
        failure = exact_transport._safe_failure_from(sys.exc_info()[1])
    finally:
        prepared_attempt = None  # type: ignore[assignment]
        factory = None  # type: ignore[assignment]
        start_numeric = None  # type: ignore[assignment]
        ledger = None  # type: ignore[assignment]
    if failure is not None:
        exact_transport._raise_safe_failure(failure)
    if type(response) is not TransportResponse:
        _raise_adapter_error()
    return response
