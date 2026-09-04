"""Unwired numeric single-connect and exact-peer foundation for W09-B2b-S6.

The private edge foundation creates one fresh TCP socket, uses only
``ResolutionSet.selected``, initiates ``connect`` exactly once, and requires
the kernel peer to match the selected resolution exactly.  It does not perform
DNS, retry another candidate, implement Happy Eyeballs, consult a proxy, or
accept caller-owned socket/TLS/context state.

This remains deliberately *unwired*: the temporary bounded wait argument is
not yet an AttemptGate-issued transport wait slice, and the returned pending
capability or socket owner is not yet integrated with TLS, wire commitment, or
terminal cleanup.  A pending capability retains the same fd across slices;
polling it never invokes ``connect`` again.
The real-socket entry points remain fail-closed until an atomic production
socket-ownership factory replaces Python's constructor return/publication gap.
Consequently this module is an independently tested S6 foundation, not the
complete production S6 path.
"""
from __future__ import annotations

import errno
import select
import socket
from threading import Lock
from typing import Callable, NoReturn

from snapquiz.config.profiles import GLM_NETWORK_POLICY_VERSION
from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport.address_policy import (
    INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
    INTERNET_PUBLIC_ADDRESS_POLICY_REF,
    AddressFamily,
    ResolutionSet,
    ResolvedAddress,
    match_exact_peer,
)


__all__ = ()


NUMERIC_CONNECT_POLICY_VERSION = "snapquiz.numeric-single-connect.v1"
NUMERIC_CONNECTION_PROOF_SCHEMA_VERSION = (
    "snapquiz.numeric-connection-proof.v1"
)
MAX_NUMERIC_CONNECT_WAIT_NS = 50_000_000
PRODUCTION_GATE_INTEGRATION_AVAILABLE = False
OPAQUE_NUMERIC_SOCKET_OWNER_AVAILABLE = False

_CONNECT_LEDGER_AUTHORITY = object()
_CONSTRUCTION_SLOT_AUTHORITY = object()
_CONNECTION_PROOF_AUTHORITY = object()
_CONNECTION_OWNER_AUTHORITY = object()
_PENDING_CONNECTION_AUTHORITY = object()
_NUMERIC_TRANSPORT_AUTHORITY = object()
_TEST_EDGE_AUTHORITY = object()
_PRODUCTION_EDGE_AUTHORITY = object()
_PENDING_CONNECT_ERRORS = frozenset(
    {
        errno.EALREADY,
        errno.EINPROGRESS,
        errno.EINTR,
        errno.EWOULDBLOCK,
    }
)


def _numeric_connect_error() -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="numeric_connect",
        retryable=False,
        safe_message="无法建立经过验证的目标连接。",
    )
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_numeric_connect_error() -> NoReturn:
    raise _numeric_connect_error() from None


def _checked_wait_ns(value: object) -> int:
    if (
        type(value) is not int
        or value < 1
        or value > MAX_NUMERIC_CONNECT_WAIT_NS
    ):
        raise ValueError(
            "max_wait_ns must be an exact positive bounded integer"
        )
    return value


def _edge_reports_closed(edge: object) -> bool:
    """Observe resource terminality independently from a close wrapper."""

    try:
        selected = edge.closed  # type: ignore[attr-defined]
    except BaseException:
        return False
    return type(selected) is bool and selected


class _NumericConstructionSlot:
    """Durable raw-to-result owner held before an edge factory runs.

    An edge factory must publish the exact edge from inside the factory and
    return ``None``.  Consequently an exception delivered at the factory's
    Python return event cannot strand a successfully created edge between the
    callee return and the caller's STORE operation.  The slot remains the
    cleanup authority until it atomically replaces the raw edge with the
    Pending/Owner object that owns that same edge.

    This is a Python publication contract for injected/test edges.  It is not
    evidence that ``socket.socket()`` itself constructs and publishes an fd
    atomically; production remains blocked on an opaque native owner.
    """

    __slots__ = ("_state", "_lock", "_close_lock")

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _CONSTRUCTION_SLOT_AUTHORITY:
            raise TypeError("numeric construction slots require their factory")
        self._state: tuple[str, object | None] = ("empty", None)
        self._lock = Lock()
        # Serialize the potentially re-entrant external close action without
        # holding the publication lock across resource callbacks.  A failed or
        # unproven action may be retried after this lock is released; a proven
        # terminal action is committed before a competing caller can proceed.
        self._close_lock = Lock()

    def publish_edge(self, edge: object) -> None:
        required = (
            "set_nonblocking",
            "connect_once",
            "wait_writable",
            "socket_error",
            "peername",
            "close_once",
        )
        if not all(callable(getattr(edge, name, None)) for name in required):
            raise TypeError("numeric construction edge is invalid")
        if _edge_reports_closed(edge):
            raise ValueError("numeric construction edge is already closed")
        with self._lock:
            if self._state != ("empty", None):
                raise ValueError("numeric edge publication replay is forbidden")
            self._state = ("edge", edge)

    def edge_is_exact(self, edge: object) -> bool:
        with self._lock:
            status, current = self._state
            return status == "edge" and current is edge

    def has_edge(self) -> bool:
        with self._lock:
            status, edge = self._state
            return status == "edge" and edge is not None

    def edge(self) -> object:
        with self._lock:
            status, edge = self._state
            if status != "edge" or edge is None:
                raise ValueError("numeric construction edge is unavailable")
            return edge

    @staticmethod
    def _result_owns_edge(result: object, edge: object) -> bool:
        if type(result) is _NumericConnectionOwner:
            with result._close_lock:
                return not result._closed and result._edge is edge
        if type(result) is _PendingNumericConnection:
            with result._lock:
                return result._state == "pending" and result._edge is edge
        return False

    def promote(self, edge: object, result: object) -> None:
        if type(result) not in (
            _PendingNumericConnection,
            _NumericConnectionOwner,
        ):
            raise TypeError("numeric construction result is invalid")
        if not self._result_owns_edge(result, edge):
            raise ValueError("numeric construction result owns another edge")
        with self._lock:
            status, current = self._state
            if status != "edge" or current is not edge:
                raise ValueError("numeric construction owner changed")
            self._state = ("result", result)

    def result_is_exact(self, result: object) -> bool:
        with self._lock:
            status, current = self._state
            return status == "result" and current is result

    def has_result(self) -> bool:
        with self._lock:
            status, result = self._state
            return status == "result" and result is not None

    def result(self) -> object:
        with self._lock:
            status, result = self._state
            if status != "result" or result is None:
                raise ValueError("numeric construction result is unavailable")
            return result

    def is_terminal(self) -> bool:
        with self._lock:
            status, resource = self._state
            if status == "closed":
                return True
            if (
                status in (
                    "edge",
                    "closing_edge",
                    "result",
                    "closing_result",
                )
                and resource is not None
                and _edge_reports_closed(resource)
            ):
                self._state = ("closed", None)
                return True
            return False

    def close_once(self) -> None:
        with self._close_lock:
            with self._lock:
                status, resource = self._state
                if status == "closed":
                    return
                if status == "empty" or resource is None:
                    self._state = ("closed", None)
                    return
                if status in ("edge", "closing_edge"):
                    closing_status = "closing_edge"
                elif status in ("result", "closing_result"):
                    closing_status = "closing_result"
                else:
                    raise ValueError("numeric construction state is invalid")
                self._state = (closing_status, resource)
            failed = False
            try:
                if closing_status == "closing_edge":
                    selected = resource.close_once()  # type: ignore[attr-defined]
                elif type(resource) is _PendingNumericConnection:
                    selected = resource.close()
                elif type(resource) is _NumericConnectionOwner:
                    selected = resource.close()
                else:
                    raise ValueError("numeric construction result changed")
                if selected is not None:
                    failed = True
            except BaseException:
                failed = True
            committed = _edge_reports_closed(resource)
            if committed:
                with self._lock:
                    status, current = self._state
                    if status == closing_status and current is resource:
                        self._state = ("closed", None)
            if failed or not committed:
                _raise_numeric_connect_error()


def _socket_parameters(
    family: AddressFamily,
) -> tuple[int, int, int, str]:
    if family is AddressFamily.IPV4:
        return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "AF_INET"
    if family is AddressFamily.IPV6:
        return socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "AF_INET6"
    raise ValueError("selected address family is invalid")


def _initiate_edge(edge: object, selected: ResolvedAddress) -> int:
    edge.set_nonblocking()  # type: ignore[attr-defined]
    return edge.connect_once(  # type: ignore[attr-defined]
        selected.numeric_sockaddr
    )


def _proof_payload(proof: "_NumericConnectionProof") -> dict[str, object]:
    return {
        "address_policy_digest": proof.address_policy_digest,
        "address_policy_ref": proof.address_policy_ref,
        "attempt_permit_digest": proof.attempt_permit_digest,
        "attempt_permit_id": proof.attempt_permit_id,
        "connect_initiation_count": proof.connect_initiation_count,
        "family": proof.family.value,
        "network_policy_version": proof.network_policy_version,
        "peer_address_digest": proof.peer_address_digest,
        "peer_binding": "family-packed-port-exact",
        "policy_version": proof.policy_version,
        "protocol": "IPPROTO_TCP",
        "resolution_digest": proof.resolution_digest,
        "resolution_id": proof.resolution_id,
        "selected_candidate_digest": proof.selected_candidate_digest,
        "socket_family": proof.socket_family,
        "socket_type": "SOCK_STREAM",
    }


@runtime_final
class _NumericConnectionProof:
    """Factory-only, immutable, content-addressed exact-peer evidence."""

    __slots__ = (
        "resolution_id",
        "resolution_digest",
        "attempt_permit_id",
        "attempt_permit_digest",
        "network_policy_version",
        "address_policy_ref",
        "address_policy_digest",
        "family",
        "socket_family",
        "selected_candidate_digest",
        "peer_address_digest",
        "connect_initiation_count",
        "policy_version",
        "proof_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        resolution: ResolutionSet,
        selected: ResolvedAddress,
        peer: ResolvedAddress,
        socket_family: str,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CONNECTION_PROOF_AUTHORITY:
            raise TypeError("numeric connection proofs require their factory")
        if type(resolution) is not ResolutionSet:
            raise TypeError("resolution must be ResolutionSet")
        if type(selected) is not ResolvedAddress or type(peer) is not ResolvedAddress:
            raise TypeError("selected and peer must be ResolvedAddress")
        if selected is not peer:
            raise ValueError("peer proof is not the selected resolution object")
        expected_socket_family = (
            "AF_INET" if selected.family is AddressFamily.IPV4 else "AF_INET6"
        )
        if socket_family != expected_socket_family:
            raise ValueError("socket family label does not match selected address")
        values = (
            ("resolution_id", resolution.resolution_id),
            ("resolution_digest", resolution.resolution_digest),
            ("attempt_permit_id", resolution.attempt_permit_id),
            ("attempt_permit_digest", resolution.attempt_permit_digest),
            ("network_policy_version", resolution.network_policy_version),
            ("address_policy_ref", resolution.address_policy_ref),
            ("address_policy_digest", resolution.address_policy_digest),
            ("family", selected.family),
            ("socket_family", socket_family),
            ("selected_candidate_digest", selected.address_digest),
            ("peer_address_digest", peer.address_digest),
            ("connect_initiation_count", 1),
            ("policy_version", NUMERIC_CONNECT_POLICY_VERSION),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        selected_digest = digest256(
            "NumericConnectionProof",
            NUMERIC_CONNECTION_PROOF_SCHEMA_VERSION,
            _proof_payload(self),
        )
        object.__setattr__(self, "proof_digest", selected_digest)
        object.__setattr__(self, "_issued_digest", selected_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("NumericConnectionProof is immutable")

    def __copy__(self) -> "_NumericConnectionProof":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_NumericConnectionProof":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("NumericConnectionProof cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("NumericConnectionProof cannot be serialized")

    def __repr__(self) -> str:
        return (
            "NumericConnectionProof("
            f"resolution_id={self.resolution_id!r}, "
            f"family={self.family.value!r})"
        )

    def validate_integrity(self) -> None:
        failed = False
        try:
            require_uuid(self.resolution_id, "resolution_id")
            require_uuid(self.attempt_permit_id, "attempt_permit_id")
            for name in (
                "resolution_digest",
                "attempt_permit_digest",
                "address_policy_digest",
                "selected_candidate_digest",
                "peer_address_digest",
                "proof_digest",
                "_issued_digest",
            ):
                require_digest(getattr(self, name), name)
            require_text(
                self.network_policy_version,
                "network_policy_version",
                max_length=128,
            )
            require_text(
                self.address_policy_ref,
                "address_policy_ref",
                max_length=256,
            )
            require_text(self.socket_family, "socket_family", max_length=16)
            require_text(self.policy_version, "policy_version", max_length=128)
            require_plain_int(
                self.connect_initiation_count,
                "connect_initiation_count",
                minimum=1,
            )
            if type(self.family) is not AddressFamily:
                raise ValueError("connection proof family changed")
            expected_socket_family = (
                "AF_INET"
                if self.family is AddressFamily.IPV4
                else "AF_INET6"
            )
            selected = digest256(
                "NumericConnectionProof",
                NUMERIC_CONNECTION_PROOF_SCHEMA_VERSION,
                _proof_payload(self),
            )
            if (
                self.network_policy_version != GLM_NETWORK_POLICY_VERSION
                or self.address_policy_ref
                != INTERNET_PUBLIC_ADDRESS_POLICY_REF
                or self.address_policy_digest
                != INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST
                or self.socket_family != expected_socket_family
                or self.selected_candidate_digest != self.peer_address_digest
                or self.connect_initiation_count != 1
                or self.policy_version != NUMERIC_CONNECT_POLICY_VERSION
                or self.proof_digest != selected
                or self._issued_digest != selected
            ):
                raise ValueError("numeric connection proof changed")
        except BaseException:
            failed = True
        if failed:
            _raise_numeric_connect_error()

    def validate_binding(self, resolution: ResolutionSet) -> None:
        if type(resolution) is not ResolutionSet:
            raise TypeError("resolution must be ResolutionSet")
        failed = False
        try:
            resolution.validate_integrity()
            selected = resolution.selected
            exact = (
                self.resolution_id == resolution.resolution_id,
                self.resolution_digest == resolution.resolution_digest,
                self.attempt_permit_id == resolution.attempt_permit_id,
                self.attempt_permit_digest == resolution.attempt_permit_digest,
                self.network_policy_version == resolution.network_policy_version,
                self.address_policy_ref == resolution.address_policy_ref,
                self.address_policy_digest == resolution.address_policy_digest,
                self.family is selected.family,
                self.selected_candidate_digest == selected.address_digest,
                self.peer_address_digest == selected.address_digest,
            )
            self.validate_integrity()
            if not all(exact):
                raise ValueError("connection proof binding changed")
        except BaseException:
            failed = True
        if failed:
            _raise_numeric_connect_error()

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "family": self.family.value,
            "policy_version": self.policy_version,
            "proof_digest_prefix": str(self.proof_digest)[:12],
            "connect_initiation_count": self.connect_initiation_count,
            "peer_exactly_matched": True,
        }


@runtime_final
class _NumericConnectionOwner:
    """Exactly-once close owner for a socket with an attested peer."""

    __slots__ = (
        "proof",
        "_edge",
        "_closed",
        "_close_lock",
        "_issued_proof",
    )

    def __init__(
        self,
        *,
        proof: _NumericConnectionProof,
        edge: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CONNECTION_OWNER_AUTHORITY:
            raise TypeError("numeric connection owners require their factory")
        if type(proof) is not _NumericConnectionProof:
            raise TypeError("proof must be NumericConnectionProof")
        proof.validate_integrity()
        object.__setattr__(self, "proof", proof)
        object.__setattr__(self, "_edge", edge)
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_close_lock", Lock())
        object.__setattr__(self, "_issued_proof", proof)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("NumericConnectionOwner is externally immutable")

    def __copy__(self) -> object:
        raise TypeError("NumericConnectionOwner cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("NumericConnectionOwner cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("NumericConnectionOwner cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("NumericConnectionOwner cannot be serialized")

    @property
    def closed(self) -> bool:
        with self._close_lock:
            return self._closed

    def validate_integrity(self) -> None:
        failed = False
        try:
            with self._close_lock:
                if (
                    type(self.proof) is not _NumericConnectionProof
                    or self.proof is not self._issued_proof
                    or type(self._closed) is not bool
                    or self._closed != (self._edge is None)
                ):
                    raise ValueError("numeric connection owner changed")
            self.proof.validate_integrity()
        except BaseException:
            failed = True
        if failed:
            _raise_numeric_connect_error()

    def close(self) -> None:
        failed = False
        committed = False
        with self._close_lock:
            if self._closed:
                return
            edge = self._edge
            if edge is None:
                failed = True
            elif _edge_reports_closed(edge):
                committed = True
            else:
                try:
                    result = edge.close_once()  # type: ignore[attr-defined]
                    if result is not None:
                        failed = True
                except BaseException:
                    failed = True
                committed = _edge_reports_closed(edge)
            if committed:
                object.__setattr__(self, "_edge", None)
                object.__setattr__(self, "_closed", True)
        if failed or not committed:
            _raise_numeric_connect_error()

    def _publish_edge_for_tls(
        self,
        *,
        proof: _NumericConnectionProof,
        publish: Callable[[object], None],
        publication_is_exact: Callable[[object], bool],
        _authority: object | None = None,
    ) -> None:
        """Publish the verified edge before relinquishing its numeric owner.

        The callback/observer pair closes the return-to-``STORE_FAST`` orphan
        window: a BaseException after publication is recoverable by the exact
        Transport ledger, while a pre-publication failure leaves this owner
        responsible for the edge.
        """

        if _authority is not _NUMERIC_TRANSPORT_AUTHORITY:
            raise TypeError("numeric edge transfer requires transport authority")
        if type(proof) is not _NumericConnectionProof:
            raise TypeError("proof must be NumericConnectionProof")
        if not callable(publish) or not callable(publication_is_exact):
            raise TypeError("numeric transfer publication is invalid")
        failed = False
        with self._close_lock:
            if (
                self._closed
                or self._edge is None
                or self.proof is not self._issued_proof
                or proof is not self.proof
            ):
                failed = True
            else:
                try:
                    proof.validate_integrity()
                except BaseException:
                    failed = True
                if not failed:
                    edge = self._edge
                    try:
                        publish(edge)
                    except BaseException:
                        try:
                            committed = publication_is_exact(edge)
                        except BaseException:
                            committed = False
                        if committed:
                            try:
                                object.__setattr__(self, "_edge", None)
                                object.__setattr__(self, "_closed", True)
                            except BaseException:
                                # A committed publication is the live owner;
                                # make best effort to remove the stale alias.
                                try:
                                    object.__setattr__(self, "_edge", None)
                                    object.__setattr__(self, "_closed", True)
                                except BaseException:
                                    pass
                        raise
                    try:
                        committed = publication_is_exact(edge)
                    except BaseException:
                        committed = False
                    if not committed:
                        failed = True
                    else:
                        try:
                            object.__setattr__(self, "_edge", None)
                            object.__setattr__(self, "_closed", True)
                        except BaseException:
                            try:
                                object.__setattr__(self, "_edge", None)
                                object.__setattr__(self, "_closed", True)
                            except BaseException:
                                pass
                            raise
        if failed:
            _raise_numeric_connect_error()

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        metadata = self.proof.safe_metadata()
        metadata["closed"] = self.closed
        return metadata


@runtime_final
class _NumericConnectLedger:
    """Process-local one-shot claim ledger pending AttemptGate integration."""

    __slots__ = ("_lock", "_states")

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _CONNECT_LEDGER_AUTHORITY:
            raise TypeError("numeric connect ledger requires its factory")
        self._lock = Lock()
        self._states: dict[Digest256, tuple[str, int, Digest256]] = {}

    def _claim(
        self,
        resolution: ResolutionSet,
    ) -> tuple[Digest256, ResolvedAddress]:
        resolution.validate_integrity()
        selected = resolution.selected
        key = resolution.resolution_digest
        with self._lock:
            if key in self._states:
                raise ValueError("resolution already consumed by numeric connect")
            self._states[key] = (
                "connecting",
                id(resolution),
                selected.address_digest,
            )
        return key, selected

    def _commit(
        self,
        key: Digest256,
        resolution: ResolutionSet,
        proof: _NumericConnectionProof,
    ) -> None:
        with self._lock:
            if self._states.get(key) != (
                "connecting",
                id(resolution),
                proof.selected_candidate_digest,
            ):
                raise ValueError("numeric connect claim changed")
            self._states[key] = (
                "connected",
                id(resolution),
                proof.selected_candidate_digest,
            )

    def _fail(self, key: Digest256, resolution: ResolutionSet) -> None:
        with self._lock:
            state = self._states.get(key)
            if state is not None and state[1] == id(resolution):
                self._states[key] = ("failed", state[1], state[2])

    def _state_for_test(self, resolution: ResolutionSet) -> str | None:
        with self._lock:
            state = self._states.get(resolution.resolution_digest)
            return None if state is None else state[0]


def _complete_connected_edge(
    *,
    resolution: ResolutionSet,
    selected: ResolvedAddress,
    family_label: str,
    edge: object,
    ledger: _NumericConnectLedger,
    claim_key: Digest256,
) -> _NumericConnectionOwner:
    socket_error = edge.socket_error()  # type: ignore[attr-defined]
    if type(socket_error) is not int or socket_error != 0:
        raise ValueError("numeric connect SO_ERROR is not success")
    peer_sockaddr = edge.peername()  # type: ignore[attr-defined]
    if type(peer_sockaddr) is not tuple:
        raise ValueError("peername returned an invalid shape")
    peer = match_exact_peer(
        resolution,
        family=selected.family,
        sockaddr=peer_sockaddr,
    )
    proof = _NumericConnectionProof(
        resolution=resolution,
        selected=selected,
        peer=peer,
        socket_family=family_label,
        _authority=_CONNECTION_PROOF_AUTHORITY,
    )
    owner = _NumericConnectionOwner(
        proof=proof,
        edge=edge,
        _authority=_CONNECTION_OWNER_AUTHORITY,
    )
    ledger._commit(claim_key, resolution, proof)
    return owner


@runtime_final
class _PendingNumericConnection:
    """Same-fd continuation capability for successive trusted wait slices."""

    __slots__ = (
        "_resolution",
        "_selected",
        "_family_label",
        "_edge",
        "_ledger",
        "_claim_key",
        "_state",
        "_owner",
        "_lock",
    )

    def __init__(
        self,
        *,
        resolution: ResolutionSet,
        selected: ResolvedAddress,
        family_label: str,
        edge: object,
        ledger: _NumericConnectLedger,
        claim_key: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PENDING_CONNECTION_AUTHORITY:
            raise TypeError("pending numeric connections require their factory")
        if (
            type(resolution) is not ResolutionSet
            or type(selected) is not ResolvedAddress
            or type(ledger) is not _NumericConnectLedger
            or type(claim_key) is not Digest256
        ):
            raise TypeError("pending numeric connection binding is invalid")
        expected_family = (
            "AF_INET" if selected.family is AddressFamily.IPV4 else "AF_INET6"
        )
        if family_label != expected_family:
            raise ValueError("pending numeric connection family changed")
        object.__setattr__(self, "_resolution", resolution)
        object.__setattr__(self, "_selected", selected)
        object.__setattr__(self, "_family_label", family_label)
        object.__setattr__(self, "_edge", edge)
        object.__setattr__(self, "_ledger", ledger)
        object.__setattr__(self, "_claim_key", claim_key)
        object.__setattr__(self, "_state", "pending")
        object.__setattr__(self, "_owner", None)
        object.__setattr__(self, "_lock", Lock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("PendingNumericConnection is externally immutable")

    def __copy__(self) -> object:
        raise TypeError("PendingNumericConnection cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("PendingNumericConnection cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("PendingNumericConnection cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("PendingNumericConnection cannot be serialized")

    @property
    def closed(self) -> bool:
        with self._lock:
            if self._state in ("closed", "failed"):
                return True
            if self._state in ("transferred", "failed_owner"):
                if type(self._owner) is not _NumericConnectionOwner:
                    return False
                return self._owner.closed
            if self._state == "failed_edge" and self._edge is not None:
                return _edge_reports_closed(self._edge)
            return False

    def poll(
        self,
        *,
        max_wait_ns: int,
    ) -> "_PendingNumericConnection | _NumericConnectionOwner":
        """Poll this exact fd once; pending never initiates another connect."""

        checked_wait = _checked_wait_ns(max_wait_ns)
        owner: _NumericConnectionOwner | None = None
        still_pending = False
        failed = False
        with self._lock:
            if self._state == "transferred":
                if type(self._owner) is _NumericConnectionOwner:
                    return self._owner
                failed = True
            elif self._state != "pending" or self._edge is None:
                failed = True
            else:
                edge = self._edge
                try:
                    self._resolution.validate_integrity()
                    if self._resolution.selected is not self._selected:
                        raise ValueError("pending selected address changed")
                    writable = edge.wait_writable(  # type: ignore[attr-defined]
                        max_wait_ns=checked_wait
                    )
                    if type(writable) is not bool:
                        raise ValueError("numeric poll returned an invalid result")
                    if not writable:
                        still_pending = True
                    else:
                        owner = _complete_connected_edge(
                            resolution=self._resolution,
                            selected=self._selected,
                            family_label=self._family_label,
                            edge=edge,
                            ledger=self._ledger,
                            claim_key=self._claim_key,
                        )
                        object.__setattr__(self, "_edge", None)
                        object.__setattr__(self, "_owner", owner)
                        object.__setattr__(self, "_state", "transferred")
                except BaseException:
                    failed = True
            if failed and self._state == "pending":
                edge = self._edge
                incomplete_owner = owner
                self._ledger._fail(self._claim_key, self._resolution)
                if type(incomplete_owner) is _NumericConnectionOwner:
                    try:
                        incomplete_owner.close()
                    except BaseException:
                        pass
                    object.__setattr__(self, "_edge", None)
                    if incomplete_owner.closed:
                        object.__setattr__(self, "_owner", None)
                        object.__setattr__(self, "_state", "failed")
                    else:
                        object.__setattr__(self, "_owner", incomplete_owner)
                        object.__setattr__(self, "_state", "failed_owner")
                elif edge is not None:
                    try:
                        edge.close_once()  # type: ignore[attr-defined]
                    except BaseException:
                        pass
                    if _edge_reports_closed(edge):
                        object.__setattr__(self, "_edge", None)
                        object.__setattr__(self, "_owner", None)
                        object.__setattr__(self, "_state", "failed")
                    else:
                        object.__setattr__(self, "_edge", edge)
                        object.__setattr__(self, "_owner", None)
                        object.__setattr__(self, "_state", "failed_edge")
                else:
                    object.__setattr__(self, "_edge", None)
                    object.__setattr__(self, "_owner", None)
                    object.__setattr__(self, "_state", "failed_edge")
        if failed:
            _raise_numeric_connect_error()
        if still_pending:
            return self
        if type(owner) is not _NumericConnectionOwner:
            _raise_numeric_connect_error()
        return owner

    def _transport_snapshot(
        self,
        *,
        _authority: object | None = None,
    ) -> "_PendingNumericConnection | _NumericConnectionOwner":
        """Observe the same-fd root without transferring its close owner."""

        if _authority is not _NUMERIC_TRANSPORT_AUTHORITY:
            raise TypeError("pending snapshot requires transport authority")
        with self._lock:
            if self._state == "pending" and self._edge is not None:
                return self
            if (
                self._state == "transferred"
                and type(self._owner) is _NumericConnectionOwner
            ):
                return self._owner
        _raise_numeric_connect_error()

    def close(self) -> None:
        """Close whichever owner currently holds the one socket, once."""

        failed = False
        committed = False
        with self._lock:
            if self._state in ("closed", "failed"):
                return
            if self._state in ("transferred", "failed_owner"):
                owner = self._owner
                if type(owner) is not _NumericConnectionOwner:
                    failed = True
                else:
                    try:
                        owner.close()
                    except BaseException:
                        failed = True
                    committed = owner.closed
                if committed:
                    object.__setattr__(self, "_owner", None)
                    object.__setattr__(self, "_edge", None)
                    object.__setattr__(self, "_state", "closed")
            elif self._state in ("pending", "failed_edge"):
                edge = self._edge
                self._ledger._fail(self._claim_key, self._resolution)
                if edge is None:
                    failed = True
                elif _edge_reports_closed(edge):
                    committed = True
                else:
                    try:
                        result = edge.close_once()  # type: ignore[attr-defined]
                        if result is not None:
                            failed = True
                    except BaseException:
                        failed = True
                    committed = _edge_reports_closed(edge)
                if committed:
                    object.__setattr__(self, "_edge", None)
                    object.__setattr__(self, "_owner", None)
                    object.__setattr__(self, "_state", "closed")
            else:
                failed = True
        if failed or not committed:
            _raise_numeric_connect_error()

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            state = self._state
        return {
            "policy_version": NUMERIC_CONNECT_POLICY_VERSION,
            "state": state,
            "connect_initiation_count": 1,
            "same_socket_continuation": True,
        }


@runtime_final
class _RealNumericSocketEdge:
    """Private socket edge reserved for a future opaque native owner.

    Python's ``socket.socket()`` return boundary cannot prove atomic
    construction-plus-publication.  Do not put that call back here: the
    production adapter must receive an already owned socket from the attested
    opaque/native capability before this class can become constructible.
    """

    __slots__ = ("_socket", "_closed")

    def __init__(
        self,
        family: int,
        socket_type: int,
        protocol: int,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PRODUCTION_EDGE_AUTHORITY:
            raise TypeError("real numeric socket edge requires production authority")
        if not PRODUCTION_GATE_INTEGRATION_AVAILABLE:
            raise ValueError(
                "real socket construction requires atomic production ownership"
            )
        if not OPAQUE_NUMERIC_SOCKET_OWNER_AVAILABLE:
            raise ValueError("opaque numeric socket owner is unavailable")
        del family, socket_type, protocol
        raise ValueError("opaque numeric socket adapter is unavailable")

    def set_nonblocking(self) -> None:
        if self._closed:
            raise ValueError("socket is closed")
        result = self._socket.setblocking(False)
        if result is not None:
            raise ValueError("setblocking returned an invalid result")

    def connect_once(self, sockaddr: tuple[object, ...]) -> int:
        if self._closed:
            raise ValueError("socket is closed")
        return self._socket.connect_ex(sockaddr)

    def wait_writable(self, *, max_wait_ns: int) -> bool:
        if self._closed:
            raise ValueError("socket is closed")
        checked_wait = _checked_wait_ns(max_wait_ns)
        _, writable, exceptional = select.select(
            (),
            (self._socket,),
            (self._socket,),
            checked_wait / 1_000_000_000,
        )
        return bool(writable or exceptional)

    def socket_error(self) -> int:
        if self._closed:
            raise ValueError("socket is closed")
        return self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)

    def peername(self) -> tuple[object, ...]:
        if self._closed:
            raise ValueError("socket is closed")
        selected = self._socket.getpeername()
        if type(selected) is not tuple:
            raise ValueError("peername returned an invalid shape")
        return selected

    def close_once(self) -> None:
        if self._closed:
            return
        raw_socket = self._socket
        failed = False
        try:
            result = raw_socket.close()
            if result is not None:
                failed = True
        except BaseException:
            failed = True
        try:
            closed = raw_socket.fileno() == -1
        except BaseException:
            closed = False
        if not closed:
            try:
                result = raw_socket.close()
                if result is not None:
                    failed = True
            except BaseException:
                failed = True
            try:
                closed = raw_socket.fileno() == -1
            except BaseException:
                closed = False
        if closed:
            self._closed = True
            self._socket = None  # type: ignore[assignment]
        if failed or not closed:
            raise ValueError("socket close could not be cleanly proven")

    @property
    def closed(self) -> bool:
        if self._closed:
            return True
        try:
            return self._socket.fileno() == -1
        except BaseException:
            return False

    def _use_socket_for_tls(
        self,
        action: Callable[[socket.socket], None],
        *,
        _authority: object | None = None,
    ) -> None:
        """Run TLS publication while this edge retains recovery ownership."""

        if _authority is not _NUMERIC_TRANSPORT_AUTHORITY:
            raise TypeError("raw socket transfer requires transport authority")
        if not callable(action):
            raise TypeError("raw socket transfer action must be callable")
        if self._closed or type(self._socket) is not socket.socket:
            raise ValueError("raw socket is unavailable")
        selected = self._socket
        try:
            action(selected)
        except BaseException:
            try:
                transferred = selected.fileno() == -1
            except BaseException:
                transferred = False
            if transferred:
                self._closed = True
                self._socket = None  # type: ignore[assignment]
            raise
        try:
            transferred = selected.fileno() == -1
        except BaseException:
            transferred = False
        if not transferred:
            raise ValueError("TLS action did not consume the raw socket")
        self._closed = True
        self._socket = None  # type: ignore[assignment]


_PRODUCTION_CONNECT_LEDGER = _NumericConnectLedger(
    _authority=_CONNECT_LEDGER_AUTHORITY,
)


def _new_numeric_connect_ledger_for_test() -> _NumericConnectLedger:
    """Return isolated local state for offline fault/concurrency tests only."""

    return _NumericConnectLedger(_authority=_CONNECT_LEDGER_AUTHORITY)


def _new_numeric_construction_slot_for_transport(
    *,
    _authority: object | None = None,
) -> _NumericConstructionSlot:
    """Preallocate the Transport's durable edge-construction owner."""

    if _authority is not _NUMERIC_TRANSPORT_AUTHORITY:
        raise TypeError("numeric construction slot requires transport authority")
    return _NumericConstructionSlot(_authority=_CONSTRUCTION_SLOT_AUTHORITY)


def _edge_from_callback_factory(
    *,
    family: int,
    socket_type: int,
    protocol: int,
    edge_factory: Callable[
        [
            int,
            int,
            int,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
    construction: _NumericConstructionSlot,
) -> object:
    """Invoke a factory whose only legal result is an in-call publication."""

    returned: object = object()
    try:
        returned = edge_factory(
            family,
            socket_type,
            protocol,
            construction.publish_edge,
            construction.edge_is_exact,
        )
    except BaseException:
        # A Python return-event exception is delivered after the callee has
        # published but before this frame can STORE its return value.  Continue
        # only from the exact durable publication; never invoke the factory
        # again.
        if not construction.has_edge():
            raise
    else:
        if returned is not None:
            raise ValueError("numeric edge factories must not return resources")
    edge = construction.edge()
    if not construction.edge_is_exact(edge):
        raise ValueError("numeric construction publication changed")
    return edge


def _connect_with_edge_factory(
    resolution: ResolutionSet,
    *,
    max_wait_ns: int,
    ledger: _NumericConnectLedger,
    edge_factory: Callable[
        [
            int,
            int,
            int,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
) -> _PendingNumericConnection | _NumericConnectionOwner:
    if type(resolution) is not ResolutionSet:
        raise TypeError("resolution must be ResolutionSet")
    if type(ledger) is not _NumericConnectLedger:
        raise TypeError("ledger must be NumericConnectLedger")
    checked_wait = _checked_wait_ns(max_wait_ns)
    construction = _NumericConstructionSlot(
        _authority=_CONSTRUCTION_SLOT_AUTHORITY
    )
    claim_key: Digest256 | None = None
    selected: ResolvedAddress | None = None
    result: _PendingNumericConnection | _NumericConnectionOwner | None = None
    failed = False
    try:
        claim_key, selected = ledger._claim(resolution)
        family, socket_type, protocol, family_label = _socket_parameters(
            selected.family
        )
        edge = _edge_from_callback_factory(
            family=family,
            socket_type=socket_type,
            protocol=protocol,
            edge_factory=edge_factory,
            construction=construction,
        )
        connect_result = _initiate_edge(edge, selected)
        if type(connect_result) is not int:
            raise ValueError("connect returned an invalid result")
        if connect_result == 0:
            result = _complete_connected_edge(
                resolution=resolution,
                selected=selected,
                family_label=family_label,
                edge=edge,
                ledger=ledger,
                claim_key=claim_key,
            )
        elif connect_result in _PENDING_CONNECT_ERRORS:
            result = _PendingNumericConnection(
                resolution=resolution,
                selected=selected,
                family_label=family_label,
                edge=edge,
                ledger=ledger,
                claim_key=claim_key,
                _authority=_PENDING_CONNECTION_AUTHORITY,
            )
        else:
            raise ValueError("numeric connect failed")
        construction.promote(edge, result)
        if type(result) is _PendingNumericConnection:
            return result.poll(max_wait_ns=checked_wait)
        return result
    except BaseException:
        failed = True
        try:
            construction.close_once()
        except BaseException:
            pass
        if claim_key is not None:
            ledger._fail(claim_key, resolution)
    if failed:
        _raise_numeric_connect_error()
    raise AssertionError("numeric connect reached an impossible state")


def _connect_with_edge_factory_published(
    resolution: ResolutionSet,
    *,
    max_wait_ns: int,
    ledger: _NumericConnectLedger,
    edge_factory: Callable[
        [
            int,
            int,
            int,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
    construction: _NumericConstructionSlot,
) -> None:
    """Initiate once and promote the preheld construction owner.

    Unlike the standalone S6 API, a pending connect is not polled here.  The
    exact Transport consumes a fresh Gate slice before every later poll.  The
    supplied slot already belongs to its cleanup ledger before this function
    or the edge factory runs.
    """

    if type(resolution) is not ResolutionSet:
        raise TypeError("resolution must be ResolutionSet")
    if type(ledger) is not _NumericConnectLedger:
        raise TypeError("ledger must be NumericConnectLedger")
    if not callable(edge_factory):
        raise TypeError("edge_factory must be callable")
    if type(construction) is not _NumericConstructionSlot:
        raise TypeError("numeric construction slot is invalid")
    _checked_wait_ns(max_wait_ns)
    claim_key: Digest256 | None = None
    selected: ResolvedAddress | None = None
    result: _PendingNumericConnection | _NumericConnectionOwner | None = None
    try:
        claim_key, selected = ledger._claim(resolution)
        family, socket_type, protocol, family_label = _socket_parameters(
            selected.family
        )
        edge = _edge_from_callback_factory(
            family=family,
            socket_type=socket_type,
            protocol=protocol,
            edge_factory=edge_factory,
            construction=construction,
        )
        connect_result = _initiate_edge(edge, selected)
        if type(connect_result) is not int:
            raise ValueError("connect returned an invalid result")
        if connect_result == 0:
            result = _complete_connected_edge(
                resolution=resolution,
                selected=selected,
                family_label=family_label,
                edge=edge,
                ledger=ledger,
                claim_key=claim_key,
            )
        elif connect_result in _PENDING_CONNECT_ERRORS:
            result = _PendingNumericConnection(
                resolution=resolution,
                selected=selected,
                family_label=family_label,
                edge=edge,
                ledger=ledger,
                claim_key=claim_key,
                _authority=_PENDING_CONNECTION_AUTHORITY,
            )
        else:
            raise ValueError("numeric connect failed")
        construction.promote(edge, result)
        if not construction.result_is_exact(result):
            raise ValueError("numeric root promotion did not commit")
    except BaseException:
        if construction.has_result():
            # Promotion committed before the exception (including a return
            # trace event).  The Transport resumes from this exact root.
            raise
        if claim_key is not None:
            ledger._fail(claim_key, resolution)
        _raise_numeric_connect_error()


def _connect_selected_numeric_with_test_edge(
    resolution: ResolutionSet,
    *,
    max_wait_ns: int,
    ledger: _NumericConnectLedger,
    edge_factory: Callable[
        [
            int,
            int,
            int,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
    _authority: object | None = None,
) -> _PendingNumericConnection | _NumericConnectionOwner:
    """Private fake edge seam; unavailable to the production-shaped API."""

    if _authority is not _TEST_EDGE_AUTHORITY:
        raise TypeError("test edge injection requires private test authority")
    if not callable(edge_factory):
        raise TypeError("edge_factory must be callable")
    return _connect_with_edge_factory(
        resolution,
        max_wait_ns=max_wait_ns,
        ledger=ledger,
        edge_factory=edge_factory,
    )


def _publish_selected_numeric_with_test_edge(
    resolution: ResolutionSet,
    *,
    max_wait_ns: int,
    ledger: _NumericConnectLedger,
    edge_factory: Callable[
        [
            int,
            int,
            int,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
    construction: _NumericConstructionSlot,
    _authority: object | None = None,
) -> None:
    """Private callback-publication seam for the exact Transport tests."""

    if _authority is not _TEST_EDGE_AUTHORITY:
        raise TypeError("test edge publication requires private authority")
    return _connect_with_edge_factory_published(
        resolution,
        max_wait_ns=max_wait_ns,
        ledger=ledger,
        edge_factory=edge_factory,
        construction=construction,
    )


def _connect_selected_numeric_unwired(
    resolution: ResolutionSet,
    *,
    max_wait_ns: int,
) -> _PendingNumericConnection | _NumericConnectionOwner:
    """Fail closed until real-socket ownership is production-integrated."""

    if not PRODUCTION_GATE_INTEGRATION_AVAILABLE:
        _raise_numeric_connect_error()

    def create_edge(
        family: int,
        socket_type: int,
        protocol: int,
        publish: Callable[[object], None],
        publication_is_exact: Callable[[object], bool],
    ) -> None:
        del family, socket_type, protocol, publish, publication_is_exact
        # A Python ``socket.socket()`` followed by this callback would retain
        # the same constructor-return orphan window.  Only an attested opaque
        # owner may implement this factory, and none is integrated yet.
        _raise_numeric_connect_error()

    return _connect_with_edge_factory(
        resolution,
        max_wait_ns=max_wait_ns,
        ledger=_PRODUCTION_CONNECT_LEDGER,
        edge_factory=create_edge,
    )


def _publish_selected_numeric_unwired(
    resolution: ResolutionSet,
    *,
    max_wait_ns: int,
    construction: _NumericConstructionSlot,
) -> None:
    """Fail closed until callback publication has atomic socket ownership."""

    if not PRODUCTION_GATE_INTEGRATION_AVAILABLE:
        _raise_numeric_connect_error()

    def create_edge(
        family: int,
        socket_type: int,
        protocol: int,
        publish: Callable[[object], None],
        publication_is_exact: Callable[[object], bool],
    ) -> None:
        del family, socket_type, protocol, publish, publication_is_exact
        _raise_numeric_connect_error()

    return _connect_with_edge_factory_published(
        resolution,
        max_wait_ns=max_wait_ns,
        ledger=_PRODUCTION_CONNECT_LEDGER,
        edge_factory=create_edge,
        construction=construction,
    )
