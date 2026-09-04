"""Offline-auditable exact single-request Transport for W09-B3.

This module composes the already-frozen resolver attempt, numeric peer,
system-trust TLS, credential borrow, wire-start transaction, exact HTTP/1.1
codec, and terminal cleanup.  The product entry point remains deliberately
unwired: no application module imports it and production availability is
explicitly false until the resolver and startup composition are complete.

Tests use the private edge seam.  The production-shaped entry point accepts
only one ``PreparedResolverAttempt``; callers cannot provide a socket, proxy,
SSLContext, resolver, clock, deadline, credential, or retry policy.
"""
from __future__ import annotations

import select
import ssl
import sys
from threading import Lock
from typing import Callable, NoReturn
from uuid import UUID, uuid4

from snapquiz.domain.adapter import TransportResponse
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError, OperationError
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.runtime.attempt import (
    AttemptGate,
    AttemptPermit,
    HelperWaitSlice,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.transport import _exact_http1 as exact_http1
from snapquiz.transport import _exact_tls as exact_tls
from snapquiz.transport import _numeric_connect as numeric_connect
from snapquiz.transport.address_policy import ResolutionSet
from snapquiz.transport.credentials import (
    CredentialHandle,
    CredentialResolver,
    _TRANSPORT_CREDENTIAL_AUTHORITY,
)
from snapquiz.transport.http import (
    PreparedResolverAttempt,
    _TRANSPORT_PREPARED_AUTHORITY,
)
from snapquiz.transport.resolver import ResolverResultReceipt


__all__ = ()


EXACT_TRANSPORT_POLICY_VERSION = "snapquiz.exact-transport-h1.v1"
EXACT_WIRE_EVIDENCE_SCHEMA_VERSION = "snapquiz.exact-wire-evidence.v2"
MAX_TLS_READ_CHUNK_BYTES = 16 * 1024
PRODUCTION_APP_INTEGRATION_AVAILABLE = False
OPAQUE_TLS_SOCKET_OWNER_AVAILABLE = False

_TEST_TRANSPORT_AUTHORITY = object()
_REAL_TLS_EDGE_AUTHORITY = object()
_OWNERSHIP_PUBLICATION_AUTHORITY = object()

_TLS_COMPLETE = "complete"
_WANT_READ = "want_read"
_WANT_WRITE = "want_write"
_WRITTEN = "written"
_DATA = "data"

_SafeFailure = tuple[
    str,
    type[BaseException] | None,
    str | None,
    bool | None,
    str | None,
    str | None,
    int | None,
]


def _resource_reports_closed(resource: object) -> bool:
    try:
        selected = resource.closed  # type: ignore[attr-defined]
    except BaseException:
        return False
    return type(selected) is bool and selected


class _NumericRootPublication:
    """Transport-held facade over the raw-to-result construction slot."""

    __slots__ = ("_construction",)

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _OWNERSHIP_PUBLICATION_AUTHORITY:
            raise TypeError("numeric publication requires transport authority")
        self._construction = (
            numeric_connect._new_numeric_construction_slot_for_transport(
                _authority=numeric_connect._NUMERIC_TRANSPORT_AUTHORITY,
            )
        )

    def construction(self) -> numeric_connect._NumericConstructionSlot:
        return self._construction

    def current(self) -> object:
        return self._construction.result()

    def has_live(self) -> bool:
        return self._construction.has_result()

    def is_terminal(self) -> bool:
        return self._construction.is_terminal()

    def close_once(self) -> None:
        self._construction.close_once()


class _TlsOwnershipPublication:
    """Single observable raw/TLS ownership transition and close ledger.

    TLS publication retains both exact identities until terminality has been
    observed independently for each one.  A TLS edge is allowed to close its
    raw edge, but that behavior is never assumed: cleanup falls back to the
    retained raw edge when its terminal state is not observable.
    """

    __slots__ = ("_state", "_lock", "_close_lock")

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _OWNERSHIP_PUBLICATION_AUTHORITY:
            raise TypeError("TLS publication requires transport authority")
        self._state: tuple[str, object | None, object | None] = (
            "empty",
            None,
            None,
        )
        self._lock = Lock()
        # External close callbacks run under this action lock, never under the
        # publication lock.  Competing cleanups therefore cannot invoke the
        # same underlying close action concurrently, while an unproven close
        # remains retryable after the action lock is released.
        self._close_lock = Lock()

    def publish_raw(self, resource: object) -> None:
        with self._lock:
            if self._state != ("empty", None, None):
                raise ValueError("raw edge publication replay is forbidden")
            self._state = ("raw", resource, None)

    def raw_is_exact(self, resource: object) -> bool:
        with self._lock:
            status, raw, tls = self._state
            return status == "raw" and raw is resource and tls is None

    def raw(self) -> object:
        with self._lock:
            status, raw, tls = self._state
            if status != "raw" or raw is None or tls is not None:
                raise ValueError("raw edge publication is unavailable")
            return raw

    def has_raw(self) -> bool:
        with self._lock:
            status, raw, tls = self._state
            return status == "raw" and raw is not None and tls is None

    def publish_tls(self, raw: object, resource: object) -> None:
        required = (
            "handshake_step",
            "wait_ready",
            "negotiated_values",
            "write_once",
            "read_once",
            "close_once",
        )
        if not all(callable(getattr(resource, name, None)) for name in required):
            raise TypeError("TLS edge publication resource is invalid")
        if resource is raw:
            raise ValueError("TLS edge must be distinct from its raw edge")
        with self._lock:
            status, current_raw, current_tls = self._state
            if (
                status != "raw"
                or current_raw is not raw
                or current_tls is not None
            ):
                raise ValueError("TLS edge publication owner changed")
            self._state = ("tls", raw, resource)

    def tls_is_exact(self, resource: object) -> bool:
        with self._lock:
            status, raw, tls = self._state
            return status == "tls" and raw is not None and tls is resource

    def has_tls(self) -> bool:
        with self._lock:
            status, raw, tls = self._state
            return status == "tls" and raw is not None and tls is not None

    def tls(self) -> object:
        with self._lock:
            status, raw, tls = self._state
            if status != "tls" or raw is None or tls is None:
                raise ValueError("TLS edge publication is unavailable")
            return tls

    def is_terminal(self) -> bool:
        with self._lock:
            status, raw, tls = self._state
            if status == "closed":
                return True
            if status in ("raw", "closing_raw"):
                candidate = raw is not None and tls is None
            elif status in ("tls", "closing_tls"):
                candidate = raw is not None and tls is not None
            else:
                return False

        raw_terminal = candidate and _resource_reports_closed(raw)
        tls_terminal = (
            candidate
            and status in ("tls", "closing_tls")
            and _resource_reports_closed(tls)
        )
        committed = raw_terminal and (
            status in ("raw", "closing_raw") or tls_terminal
        )
        if not committed:
            return False
        with self._lock:
            if self._state == (status, raw, tls):
                self._state = ("closed", None, None)
                return True
            return self._state == ("closed", None, None)

    def close_once(self) -> None:
        with self._close_lock:
            with self._lock:
                status, raw, tls = self._state
                if status == "closed":
                    return
                if status == "empty" and raw is None and tls is None:
                    self._state = ("closed", None, None)
                    return
                if (
                    status in ("raw", "closing_raw")
                    and raw is not None
                    and tls is None
                ):
                    closing_status = "closing_raw"
                elif (
                    status in ("tls", "closing_tls")
                    and raw is not None
                    and tls is not None
                ):
                    closing_status = "closing_tls"
                else:
                    raise ValueError("TLS publication state is invalid")
                self._state = (closing_status, raw, tls)

            failed = False
            if closing_status == "closing_tls":
                if not _resource_reports_closed(tls):
                    try:
                        selected = tls.close_once()  # type: ignore[attr-defined]
                        if selected is not None:
                            failed = True
                    except BaseException:
                        failed = True

                tls_terminal = _resource_reports_closed(tls)
                raw_terminal = _resource_reports_closed(raw)
                if not raw_terminal:
                    try:
                        selected = raw.close_once()  # type: ignore[attr-defined]
                        if selected is not None:
                            failed = True
                    except BaseException:
                        failed = True
                    raw_terminal = _resource_reports_closed(raw)
                # Re-observe TLS after the raw fallback: neither edge's state
                # is inferred from the other's close behavior.
                tls_terminal = _resource_reports_closed(tls)
                committed = tls_terminal and raw_terminal
            else:
                if not _resource_reports_closed(raw):
                    try:
                        selected = raw.close_once()  # type: ignore[attr-defined]
                        if selected is not None:
                            failed = True
                    except BaseException:
                        failed = True
                committed = _resource_reports_closed(raw)

            if committed:
                with self._lock:
                    if self._state == (closing_status, raw, tls):
                        self._state = ("closed", None, None)
            if failed or not committed:
                raise _transport_error() from None


class _TransportCleanupOwner:
    """Claim-anchored recovery owner for all numeric/TLS resources."""

    __slots__ = ("_numeric", "_tls", "_lock", "_released")

    def __init__(
        self,
        *,
        numeric: _NumericRootPublication,
        tls: _TlsOwnershipPublication,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _OWNERSHIP_PUBLICATION_AUTHORITY:
            raise TypeError("transport cleanup owner requires transport authority")
        if (
            type(numeric) is not _NumericRootPublication
            or type(tls) is not _TlsOwnershipPublication
        ):
            raise TypeError("transport cleanup publications are invalid")
        self._numeric = numeric
        self._tls = tls
        self._lock = Lock()
        self._released = False

    def cleanup(self) -> None:
        """Release operation use and attempt both resource cleanups once."""

        with self._lock:
            self._released = True
            failures: list[BaseException] = []
            try:
                self._tls.close_once()
            except BaseException as error:
                failures.append(error)
            try:
                self._numeric.close_once()
            except BaseException as error:
                failures.append(error)
            if failures:
                raise failures[0]

    def is_terminal(self) -> bool:
        with self._lock:
            return (
                self._released
                and self._tls.is_terminal()
                and self._numeric.is_terminal()
            )

    def is_released(self) -> bool:
        with self._lock:
            return self._released


def _transport_error() -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="exact_transport",
        retryable=False,
        safe_message="安全传输未能完成。",
    )
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _safe_failure_from(error: object) -> _SafeFailure:
    if isinstance(error, OperationError):
        return (
            "operation",
            type(error),
            error.stage,
            error.retryable,
            error.safe_message,
            error.provider_profile_id,
            error.attempt,
        )
    return ("transport", None, None, None, None, None, None)


def _raise_safe_failure(failure: _SafeFailure) -> NoReturn:
    (
        kind,
        error_type,
        stage,
        retryable,
        safe_message,
        provider_profile_id,
        attempt,
    ) = failure
    if (
        kind == "operation"
        and isinstance(error_type, type)
        and issubclass(error_type, OperationError)
        and type(stage) is str
        and type(retryable) is bool
        and type(safe_message) is str
    ):
        try:
            error = error_type(
                stage=stage,
                retryable=retryable,
                safe_message=safe_message,
                provider_profile_id=provider_profile_id,
                attempt=attempt,
            )
        except BaseException:
            error = _transport_error()
    else:
        error = _transport_error()
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _checkpoint(
    *,
    gate: AttemptGate,
    attempt: AttemptPermit,
    result_receipt: ResolverResultReceipt,
    resolution: ResolutionSet,
    phase: str,
    borrow_id: UUID | None = None,
    wire_commit_id: UUID | None = None,
    wire_evidence_digest: Digest256 | None = None,
) -> HelperWaitSlice:
    selected = gate._checkpoint_transport_io(
        attempt,
        claim_id=resolution.transport_claim_id,
        guard_id=resolution.terminal_guard_id,
        guard_digest=resolution.terminal_guard_digest,
        start_id=resolution.dns_start_id,
        result_receipt_digest=result_receipt.receipt_digest,
        phase=phase,
        borrow_id=borrow_id,
        wire_commit_id=wire_commit_id,
        wire_evidence_digest=wire_evidence_digest,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    if type(selected) is not HelperWaitSlice:
        raise ValueError("transport checkpoint returned an invalid slice")
    selected.validate_integrity()
    return selected


def _wait_tls_edge(
    edge: object,
    *,
    direction: str,
    max_wait_ns: int,
) -> None:
    if direction not in (_WANT_READ, _WANT_WRITE):
        raise ValueError("TLS wait direction is invalid")
    ready = edge.wait_ready(  # type: ignore[attr-defined]
        direction=direction,
        max_wait_ns=max_wait_ns,
    )
    if type(ready) is not bool:
        raise ValueError("TLS wait returned an invalid result")


def _wire_evidence_digest(
    *,
    attempt: AttemptPermit,
    result_receipt: ResolverResultReceipt,
    resolution: ResolutionSet,
    prepared_request_digest: Digest256,
    numeric_proof_digest: Digest256,
    tls_policy_digest: Digest256,
    http1_policy_digest: Digest256,
    hostname: str,
    tls_version: str,
) -> Digest256:
    current_http1_policy_digest = (
        exact_http1._require_exact_http1_policy_digest()
    )
    if (
        type(http1_policy_digest) is not Digest256
        or http1_policy_digest != current_http1_policy_digest
    ):
        raise ValueError("HTTP/1.1 policy binding changed before wire commit")
    return digest256(
        "ExactTransportWireEvidence",
        EXACT_WIRE_EVIDENCE_SCHEMA_VERSION,
        {
            "alpn": "http/1.1",
            "attempt_permit_digest": attempt.attempt_permit_digest,
            "attempt_permit_id": attempt.attempt_permit_id,
            "hostname": hostname,
            "http1_policy_digest": http1_policy_digest,
            "numeric_connection_proof_digest": numeric_proof_digest,
            "request_envelope_digest": prepared_request_digest,
            "resolution_digest": resolution.resolution_digest,
            "result_receipt_digest": result_receipt.receipt_digest,
            "tls_policy_digest": tls_policy_digest,
            "tls_version": tls_version,
            "transport_policy_version": EXACT_TRANSPORT_POLICY_VERSION,
        },
    )


def _commit_wire_or_observe(
    *,
    gate: AttemptGate,
    attempt: AttemptPermit,
    result_receipt: ResolverResultReceipt,
    resolution: ResolutionSet,
    borrow_id: UUID,
    wire_commit_id: UUID,
    wire_evidence_digest: Digest256,
) -> None:
    values = {
        "claim_id": resolution.transport_claim_id,
        "guard_id": resolution.terminal_guard_id,
        "guard_digest": resolution.terminal_guard_digest,
        "start_id": resolution.dns_start_id,
        "result_receipt_digest": result_receipt.receipt_digest,
        "borrow_id": borrow_id,
        "wire_commit_id": wire_commit_id,
        "wire_evidence_digest": wire_evidence_digest,
    }

    def observed() -> bool:
        try:
            selected = gate._wire_start_is_committed(
                attempt,
                **values,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            return False
        return type(selected) is bool and selected

    committed = False
    try:
        gate._commit_wire_start(
            attempt,
            **values,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
    except BaseException:
        committed = observed()
        if not committed:
            raise
    else:
        committed = observed()
    if not committed:
        raise ValueError("wire-start transaction is not committed")


def _write_request_view(
    request: memoryview,
    *,
    tls_edge: object,
    gate: AttemptGate,
    attempt: AttemptPermit,
    result_receipt: ResolverResultReceipt,
    resolution: ResolutionSet,
    borrow_id: UUID,
    wire_commit_id: UUID,
    wire_evidence_digest: Digest256,
) -> None:
    _commit_wire_or_observe(
        gate=gate,
        attempt=attempt,
        result_receipt=result_receipt,
        resolution=resolution,
        borrow_id=borrow_id,
        wire_commit_id=wire_commit_id,
        wire_evidence_digest=wire_evidence_digest,
    )
    offset = 0
    while offset < request.nbytes:
        wait_slice = _checkpoint(
            gate=gate,
            attempt=attempt,
            result_receipt=result_receipt,
            resolution=resolution,
            phase="request-write",
            borrow_id=borrow_id,
            wire_commit_id=wire_commit_id,
            wire_evidence_digest=wire_evidence_digest,
        )
        piece: memoryview | None = request[offset:]
        try:
            outcome = tls_edge.write_once(piece)  # type: ignore[attr-defined]
        finally:
            piece.release()
            piece = None
        if (
            type(outcome) is not tuple
            or len(outcome) != 2
            or type(outcome[0]) is not str
            or type(outcome[1]) is not int
        ):
            raise ValueError("TLS write returned an invalid result")
        status, count = outcome
        if status == _WRITTEN:
            if count < 1 or count > request.nbytes - offset:
                raise ValueError("TLS write byte count is invalid")
            offset += count
            continue
        if status in (_WANT_READ, _WANT_WRITE) and count == 0:
            _wait_tls_edge(
                tls_edge,
                direction=status,
                max_wait_ns=wait_slice.max_wait_ns,
            )
            continue
        raise ValueError("TLS write status is invalid")


def _borrow_encode_and_write(
    *,
    credential_resolver: CredentialResolver,
    credential_handle: CredentialHandle,
    prepared_request: PreparedOutbound,
    tls_edge: object,
    gate: AttemptGate,
    attempt: AttemptPermit,
    result_receipt: ResolverResultReceipt,
    resolution: ResolutionSet,
    wire_commit_id: UUID,
    wire_evidence_digest: Digest256,
) -> tuple[UUID, UUID, Digest256]:
    failure: list[_SafeFailure | None] = [None]
    committed_owner: list[UUID | None] = [None]

    def borrow_action(secret: memoryview, borrow_id: UUID) -> None:
        committed_owner[0] = borrow_id

        def request_action(request: memoryview) -> None:
            try:
                _write_request_view(
                    request,
                    tls_edge=tls_edge,
                    gate=gate,
                    attempt=attempt,
                    result_receipt=result_receipt,
                    resolution=resolution,
                    borrow_id=borrow_id,
                    wire_commit_id=wire_commit_id,
                    wire_evidence_digest=wire_evidence_digest,
                )
            except BaseException:
                failure[0] = _safe_failure_from(sys.exc_info()[1])
            finally:
                request = None  # type: ignore[assignment]

        try:
            exact_http1._encode_exact_http1_request(
                prepared=prepared_request,
                bearer_token=secret,
                action=request_action,
            )
        except BaseException:
            if failure[0] is None:
                failure[0] = _safe_failure_from(sys.exc_info()[1])
        finally:
            secret = None  # type: ignore[assignment]

    credential_resolver._borrow_once_with_owner(
        credential_handle,
        attempt,
        borrow_action,
        _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
    )
    if failure[0] is not None:
        _raise_safe_failure(failure[0])
    borrow_id = committed_owner[0]
    if type(borrow_id) is not UUID:
        raise ValueError("wire-start borrow owner was not published")
    return borrow_id, wire_commit_id, wire_evidence_digest


def _read_exact_response(
    *,
    tls_edge: object,
    gate: AttemptGate,
    attempt: AttemptPermit,
    result_receipt: ResolverResultReceipt,
    resolution: ResolutionSet,
    borrow_id: UUID,
    wire_commit_id: UUID,
    wire_evidence_digest: Digest256,
) -> exact_http1._ExactHttp1Response:
    parser = exact_http1._new_exact_http1_response_parser()
    completed: exact_http1._ExactHttp1Response | None = None
    while True:
        wait_slice = _checkpoint(
            gate=gate,
            attempt=attempt,
            result_receipt=result_receipt,
            resolution=resolution,
            phase="response-read",
            borrow_id=borrow_id,
            wire_commit_id=wire_commit_id,
            wire_evidence_digest=wire_evidence_digest,
        )
        outcome = tls_edge.read_once(  # type: ignore[attr-defined]
            MAX_TLS_READ_CHUNK_BYTES
        )
        if (
            type(outcome) is not tuple
            or len(outcome) != 2
            or type(outcome[0]) is not str
        ):
            raise ValueError("TLS read returned an invalid result")
        status, value = outcome
        if status in (_WANT_READ, _WANT_WRITE) and value is None:
            _wait_tls_edge(
                tls_edge,
                direction=status,
                max_wait_ns=wait_slice.max_wait_ns,
            )
            continue
        if status != _DATA or type(value) is not bytes:
            raise ValueError("TLS read status is invalid")
        if not value:
            final = parser.finish_eof()
            if completed is not None and final is not completed:
                raise ValueError("HTTP response publication changed")
            final.validate_integrity()
            return final
        parsed = parser.feed(value)
        value = b""
        if type(parsed) is exact_http1._ExactHttp1Response:
            parsed.validate_integrity()
            completed = parsed
        elif parsed is not exact_http1._PENDING:
            raise ValueError("HTTP parser returned an invalid state")


class _RealTlsEdge:
    """One nonblocking SSLSocket; select calls allocate no selector owner."""

    __slots__ = ("_state", "_lock")

    def __init__(
        self,
        tls_socket: ssl.SSLSocket,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _REAL_TLS_EDGE_AUTHORITY:
            raise TypeError("real TLS edge requires its factory")
        if type(tls_socket) is not ssl.SSLSocket:
            raise TypeError("tls_socket must be SSLSocket")
        self._state: tuple[str, ssl.SSLSocket | None] = (
            "open",
            tls_socket,
        )
        self._lock = Lock()

    def _active_socket(self) -> ssl.SSLSocket:
        with self._lock:
            status, tls_socket = self._state
            if status != "open" or type(tls_socket) is not ssl.SSLSocket:
                raise ValueError("TLS edge is closed")
            return tls_socket

    @property
    def closed(self) -> bool:
        with self._lock:
            status, tls_socket = self._state
            if status == "closed":
                return True
            if type(tls_socket) is not ssl.SSLSocket:
                return False
            try:
                committed = tls_socket.fileno() == -1
            except BaseException:
                committed = False
            if committed:
                self._state = ("closed", None)
            return committed

    def handshake_step(self) -> str:
        tls_socket = self._active_socket()
        try:
            tls_socket.do_handshake()
        except ssl.SSLWantReadError:
            return _WANT_READ
        except ssl.SSLWantWriteError:
            return _WANT_WRITE
        return _TLS_COMPLETE

    def wait_ready(self, *, direction: str, max_wait_ns: int) -> bool:
        tls_socket = self._active_socket()
        if type(max_wait_ns) is not int or max_wait_ns < 1:
            raise ValueError("TLS wait bound is invalid")
        if direction == _WANT_READ:
            readable, writable = (tls_socket,), ()
        elif direction == _WANT_WRITE:
            readable, writable = (), (tls_socket,)
        else:
            raise ValueError("TLS wait direction is invalid")
        selected_read, selected_write, selected_error = select.select(
            readable,
            writable,
            (tls_socket,),
            max_wait_ns / 1_000_000_000,
        )
        return bool(selected_read or selected_write or selected_error)

    def negotiated_values(self) -> tuple[object, object]:
        tls_socket = self._active_socket()
        return tls_socket.selected_alpn_protocol(), tls_socket.version()

    def write_once(self, value: memoryview) -> tuple[str, int]:
        if type(value) is not memoryview:
            raise ValueError("TLS write input is invalid")
        tls_socket = self._active_socket()
        try:
            count = tls_socket.send(value)
        except ssl.SSLWantReadError:
            return _WANT_READ, 0
        except ssl.SSLWantWriteError:
            return _WANT_WRITE, 0
        return _WRITTEN, count

    def read_once(self, maximum: int) -> tuple[str, bytes | None]:
        if type(maximum) is not int or maximum < 1:
            raise ValueError("TLS read input is invalid")
        tls_socket = self._active_socket()
        try:
            data = tls_socket.recv(maximum)
        except ssl.SSLWantReadError:
            return _WANT_READ, None
        except ssl.SSLWantWriteError:
            return _WANT_WRITE, None
        except ssl.SSLZeroReturnError:
            data = b""
        if type(data) is not bytes:
            raise ValueError("TLS read result is invalid")
        return _DATA, data

    def close_once(self) -> None:
        with self._lock:
            status, tls_socket = self._state
            if status == "closed":
                return
            if (
                status not in ("open", "closing")
                or type(tls_socket) is not ssl.SSLSocket
            ):
                raise ValueError("TLS close owner is invalid")
            self._state = ("closing", tls_socket)
        failed = False
        try:
            result = tls_socket.close()
            if result is not None:
                failed = True
        except BaseException:
            failed = True
        try:
            committed = tls_socket.fileno() == -1
        except BaseException:
            committed = False
        if not committed:
            # Recovery for an interruption before the actual close call.  The
            # state retains the exact socket until closure is observable.
            try:
                result = tls_socket.close()
                if result is not None:
                    failed = True
            except BaseException:
                failed = True
            try:
                committed = tls_socket.fileno() == -1
            except BaseException:
                committed = False
        if committed:
            with self._lock:
                status, current = self._state
                if status == "closing" and current is tls_socket:
                    self._state = ("closed", None)
        if failed or not committed:
            raise ValueError("TLS close could not be cleanly proven")


def _new_real_tls_edge(
    numeric_edge: object,
    policy: exact_tls._ExactTlsPolicy,
    hostname: str,
    publish: Callable[[object], None],
    publication_is_exact: Callable[[object], bool],
) -> None:
    """Reserved adapter for an attested opaque TLS construction owner.

    ``SSLContext.wrap_socket()`` returns an owning Python object before this
    frame can publish it.  A callback immediately after that return does not
    make the transition atomic, so the stdlib constructor is intentionally not
    called here.  Production must supply a native/opaque create-and-publish
    capability before this adapter can be enabled.
    """

    if type(numeric_edge) is not numeric_connect._RealNumericSocketEdge:
        raise TypeError("production TLS requires the real numeric edge")
    if type(policy) is not exact_tls._ExactTlsPolicy:
        raise TypeError("policy must be ExactTlsPolicy")
    if not callable(publish) or not callable(publication_is_exact):
        raise TypeError("TLS publication callbacks are invalid")
    del hostname, publish, publication_is_exact
    if not OPAQUE_TLS_SOCKET_OWNER_AVAILABLE:
        raise _transport_error() from None
    raise _transport_error() from None


def _run_exact_transport(
    prepared_attempt: PreparedResolverAttempt,
    *,
    numeric_start: Callable[
        [
            ResolutionSet,
            int,
            numeric_connect._NumericConstructionSlot,
        ],
        None,
    ],
    tls_factory: Callable[
        [
            object,
            exact_tls._ExactTlsPolicy,
            str,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
) -> TransportResponse:
    claim_committed = False
    numeric_publication = _NumericRootPublication(
        _authority=_OWNERSHIP_PUBLICATION_AUTHORITY
    )
    tls_publication = _TlsOwnershipPublication(
        _authority=_OWNERSHIP_PUBLICATION_AUTHORITY
    )
    transport_owner = _TransportCleanupOwner(
        numeric=numeric_publication,
        tls=tls_publication,
        _authority=_OWNERSHIP_PUBLICATION_AUTHORITY,
    )
    response: TransportResponse | None = None
    primary: _SafeFailure | None = None
    cleanup_failed = False

    try:
        try:
            prepared_attempt._claim_transport(
                transport_owner,
                cleanup_action=transport_owner.cleanup,
                cleanup_terminal=transport_owner.is_terminal,
                cleanup_released=transport_owner.is_released,
                _authority=_TRANSPORT_PREPARED_AUTHORITY,
            )
        except BaseException:
            try:
                claim_committed = prepared_attempt._transport_claim_is_exact(
                    transport_owner,
                    _authority=_TRANSPORT_PREPARED_AUTHORITY,
                )
            except BaseException:
                claim_committed = False
            if not claim_committed:
                raise
        else:
            claim_committed = prepared_attempt._transport_claim_is_exact(
                transport_owner,
                _authority=_TRANSPORT_PREPARED_AUTHORITY,
            )
            if not claim_committed:
                raise ValueError("transport claim was not committed")

        (
            gate,
            credential_resolver,
            credential_handle,
            attempt,
            result_receipt,
            resolution,
            prepared_request,
        ) = prepared_attempt._transport_inputs(
            transport_owner,
            _authority=_TRANSPORT_PREPARED_AUTHORITY,
        )
        http1_policy_digest = (
            exact_http1._require_exact_http1_policy_digest()
        )
        authority, _ = exact_http1._canonical_https_target(prepared_request)
        hostname = authority.decode("ascii")
        if (
            hostname != resolution.canonical_hostname
            or resolution.port != 443
        ):
            raise ValueError("TLS target differs from the resolution binding")

        # System trust construction and forbidden environment checks precede
        # the first socket factory invocation.
        tls_policy = exact_tls._new_exact_tls_policy(hostname=hostname)
        tls_policy.validate_integrity()

        wait_slice = _checkpoint(
            gate=gate,
            attempt=attempt,
            result_receipt=result_receipt,
            resolution=resolution,
            phase="numeric-connect",
        )
        try:
            numeric_start(
                resolution,
                wait_slice.max_wait_ns,
                numeric_publication.construction(),
            )
        except BaseException:
            if not numeric_publication.has_live():
                raise
        numeric_result = numeric_publication.current()
        while type(numeric_result) is numeric_connect._PendingNumericConnection:
            wait_slice = _checkpoint(
                gate=gate,
                attempt=attempt,
                result_receipt=result_receipt,
                resolution=resolution,
                phase="numeric-connect",
            )
            # The publication permanently owns this pending root.  Ignore the
            # return value so an exception at return-to-STORE cannot orphan
            # either the pending edge or its internally published owner.
            numeric_result.poll(max_wait_ns=wait_slice.max_wait_ns)
            numeric_result = numeric_result._transport_snapshot(
                _authority=numeric_connect._NUMERIC_TRANSPORT_AUTHORITY,
            )
        if type(numeric_result) is not numeric_connect._NumericConnectionOwner:
            raise ValueError("numeric connect returned an invalid owner")
        numeric_owner = numeric_result
        numeric_owner.proof.validate_binding(resolution)
        try:
            numeric_owner._publish_edge_for_tls(
                proof=numeric_owner.proof,
                publish=tls_publication.publish_raw,
                publication_is_exact=tls_publication.raw_is_exact,
                _authority=numeric_connect._NUMERIC_TRANSPORT_AUTHORITY,
            )
        except BaseException:
            if not tls_publication.has_raw():
                raise
        raw_edge = tls_publication.raw()

        def publish_tls(candidate: object) -> None:
            tls_publication.publish_tls(raw_edge, candidate)

        try:
            tls_factory_result = tls_factory(
                raw_edge,
                tls_policy,
                hostname,
                publish_tls,
                tls_publication.tls_is_exact,
            )
        except BaseException:
            if not tls_publication.has_tls():
                raise
        else:
            if tls_factory_result is not None:
                raise ValueError("TLS factories must not return resources")
        if not tls_publication.has_tls():
            raise ValueError("TLS factory did not publish an edge")
        tls_edge = tls_publication.tls()

        while True:
            wait_slice = _checkpoint(
                gate=gate,
                attempt=attempt,
                result_receipt=result_receipt,
                resolution=resolution,
                phase="tls-handshake",
            )
            handshake = tls_edge.handshake_step()  # type: ignore[attr-defined]
            if handshake == _TLS_COMPLETE:
                break
            if handshake not in (_WANT_READ, _WANT_WRITE):
                raise ValueError("TLS handshake returned an invalid state")
            _wait_tls_edge(
                tls_edge,
                direction=handshake,
                max_wait_ns=wait_slice.max_wait_ns,
            )

        negotiated = tls_edge.negotiated_values()  # type: ignore[attr-defined]
        if type(negotiated) is not tuple or len(negotiated) != 2:
            raise ValueError("TLS negotiated values are invalid")
        alpn, tls_version = negotiated
        tls_policy._attest_negotiated_values(
            server_hostname=hostname,
            selected_alpn_protocol=alpn,
            negotiated_version=tls_version,
            _authority=exact_tls._POLICY_AUTHORITY,
        )
        if type(tls_version) is not str:
            raise ValueError("TLS version is invalid")

        wire_commit_id = uuid4()
        wire_evidence_digest = _wire_evidence_digest(
            attempt=attempt,
            result_receipt=result_receipt,
            resolution=resolution,
            prepared_request_digest=prepared_request.request_envelope_digest,
            numeric_proof_digest=numeric_owner.proof.proof_digest,
            tls_policy_digest=tls_policy.policy_digest,
            http1_policy_digest=http1_policy_digest,
            hostname=hostname,
            tls_version=tls_version,
        )
        borrow_id, wire_commit_id, wire_evidence_digest = (
            _borrow_encode_and_write(
                credential_resolver=credential_resolver,
                credential_handle=credential_handle,
                prepared_request=prepared_request,
                tls_edge=tls_edge,
                gate=gate,
                attempt=attempt,
                result_receipt=result_receipt,
                resolution=resolution,
                wire_commit_id=wire_commit_id,
                wire_evidence_digest=wire_evidence_digest,
            )
        )
        exact_response = _read_exact_response(
            tls_edge=tls_edge,
            gate=gate,
            attempt=attempt,
            result_receipt=result_receipt,
            resolution=resolution,
            borrow_id=borrow_id,
            wire_commit_id=wire_commit_id,
            wire_evidence_digest=wire_evidence_digest,
        )
        response = TransportResponse(
            plan_id=prepared_request.plan_id,
            stage_id=prepared_request.stage_id,
            operation_id=prepared_request.operation_id,
            request_envelope_digest=prepared_request.request_envelope_digest,
            http_status=exact_response.status,
            provider_request_id=None,
            body=exact_response.body,
        )
        response.validate_integrity()
    except BaseException:
        primary = _safe_failure_from(sys.exc_info()[1])
    finally:
        try:
            transport_owner.cleanup()
        except BaseException:
            cleanup_failed = True
        if not claim_committed:
            try:
                claim_committed = prepared_attempt._transport_claim_is_exact(
                    transport_owner,
                    _authority=_TRANSPORT_PREPARED_AUTHORITY,
                )
            except BaseException:
                claim_committed = False
        if claim_committed:
            try:
                finished = prepared_attempt._finish_transport(
                    transport_owner,
                    _authority=_TRANSPORT_PREPARED_AUTHORITY,
                )
                if finished is not True:
                    cleanup_failed = True
            except BaseException:
                try:
                    finished = prepared_attempt.is_closed
                except BaseException:
                    finished = False
                if not finished:
                    cleanup_failed = True

    if primary is not None:
        _raise_safe_failure(primary)
    if cleanup_failed or response is None:
        _raise_safe_failure(("transport", None, None, None, None, None, None))
    return response


def _send_exact_with_test_edges(
    prepared_attempt: PreparedResolverAttempt,
    *,
    numeric_edge_factory: Callable[
        [
            int,
            int,
            int,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
    tls_edge_factory: Callable[
        [
            object,
            exact_tls._ExactTlsPolicy,
            str,
            Callable[[object], None],
            Callable[[object], bool],
        ],
        None,
    ],
    _authority: object | None = None,
) -> TransportResponse:
    """Private fully offline edge seam; never used by product code."""

    if _authority is not _TEST_TRANSPORT_AUTHORITY:
        raise TypeError("test transport requires private authority")
    if type(prepared_attempt) is not PreparedResolverAttempt:
        raise TypeError("prepared_attempt must be PreparedResolverAttempt")
    if not callable(numeric_edge_factory) or not callable(tls_edge_factory):
        raise TypeError("test edge factories must be callable")
    ledger = numeric_connect._new_numeric_connect_ledger_for_test()
    response: TransportResponse | None = None
    failure: _SafeFailure | None = None

    def start_numeric(
        resolution: ResolutionSet,
        max_wait_ns: int,
        construction: numeric_connect._NumericConstructionSlot,
    ) -> None:
        return numeric_connect._publish_selected_numeric_with_test_edge(
            resolution,
            max_wait_ns=max_wait_ns,
            ledger=ledger,
            edge_factory=numeric_edge_factory,
            construction=construction,
            _authority=numeric_connect._TEST_EDGE_AUTHORITY,
        )

    try:
        response = _run_exact_transport(
            prepared_attempt,
            numeric_start=start_numeric,
            tls_factory=tls_edge_factory,
        )
    except BaseException:
        failure = _safe_failure_from(sys.exc_info()[1])
    finally:
        # Do not let the public exception traceback retain the prepared
        # request/credential owner or a fake edge that copied request bytes.
        prepared_attempt = None  # type: ignore[assignment]
        numeric_edge_factory = None  # type: ignore[assignment]
        tls_edge_factory = None  # type: ignore[assignment]
        start_numeric = None  # type: ignore[assignment]
        ledger = None  # type: ignore[assignment]
    if failure is not None:
        _raise_safe_failure(failure)
    if type(response) is not TransportResponse:
        _raise_safe_failure(("transport", None, None, None, None, None, None))
    return response


def _send_exact_unwired(
    prepared_attempt: PreparedResolverAttempt,
) -> TransportResponse:
    """Production-shaped exact Transport, intentionally not app-wired."""

    if type(prepared_attempt) is not PreparedResolverAttempt:
        raise TypeError("prepared_attempt must be PreparedResolverAttempt")
    if not PRODUCTION_APP_INTEGRATION_AVAILABLE:
        _raise_safe_failure(("transport", None, None, None, None, None, None))

    def start_numeric(
        resolution: ResolutionSet,
        max_wait_ns: int,
        construction: numeric_connect._NumericConstructionSlot,
    ) -> None:
        return numeric_connect._publish_selected_numeric_unwired(
            resolution,
            max_wait_ns=max_wait_ns,
            construction=construction,
        )

    response: TransportResponse | None = None
    failure: _SafeFailure | None = None
    try:
        response = _run_exact_transport(
            prepared_attempt,
            numeric_start=start_numeric,
            tls_factory=_new_real_tls_edge,
        )
    except BaseException:
        failure = _safe_failure_from(sys.exc_info()[1])
    finally:
        prepared_attempt = None  # type: ignore[assignment]
        start_numeric = None  # type: ignore[assignment]
    if failure is not None:
        _raise_safe_failure(failure)
    if type(response) is not TransportResponse:
        _raise_safe_failure(("transport", None, None, None, None, None, None))
    return response
