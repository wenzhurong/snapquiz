"""Offline fault-matrix tests for the W09-B3 exact Transport driver."""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager
import errno
import inspect
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
from threading import Barrier, Event, Lock, Thread
from types import SimpleNamespace
import unittest
from unittest import mock

from snapquiz.domain.adapter import TransportResponse
from snapquiz.domain.errors import (
    CancelledError,
    EndpointPolicyError,
    OperationError,
    TimeoutError,
)
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.runtime.attempt import AttemptGate, HELPER_WAIT_QUANTUM_NS
from snapquiz.runtime.context import CancellationReason
from snapquiz.transport import _exact_http1 as exact_http1
from snapquiz.transport import _exact_tls as exact_tls
from snapquiz.transport import _exact_transport as exact_transport
from snapquiz.transport import _numeric_connect as numeric_connect
from snapquiz.transport.credentials import CredentialHandle, CredentialResolver
from snapquiz.transport.http import (
    PreparedResolverAttempt,
    coordinate_resolver_attempt,
    issue_resolver_cleanup_ticket,
)

from tests.test_w09_resolver_coordinator import (
    DNS_START_ID,
    LIFECYCLE_ID,
    READY_PUBLICATION_ID,
    TRANSPORT_CLAIM_ID,
    VALID_SECRET,
    _components,
    _make_authorized_credential,
    _poison_real_io,
)


_OK_RESPONSE = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"


def _clean_tls_environment():
    return mock.patch.dict(
        os.environ,
        {
            key: os.environ[key]
            for key in os.environ
            if key not in exact_tls.FORBIDDEN_TLS_ENVIRONMENT_KEYS
        },
        clear=True,
    )


@contextmanager
def _poison_network():
    poison = AssertionError("real DNS/network is forbidden in Transport tests")
    with ExitStack() as stack:
        for target in (
            "socket.getaddrinfo",
            "socket.socket",
            "socket.create_connection",
        ):
            stack.enter_context(mock.patch(target, side_effect=poison))
        yield


def _prepared(*, result_address: str = "8.8.8.8") -> SimpleNamespace:
    runtime, gate, credential = _make_authorized_credential()
    launcher, resolver, source, spawner, kernel, events = _components(
        result_address=result_address
    )
    cleanup_ticket = issue_resolver_cleanup_ticket()
    with _poison_real_io(), mock.patch(
        "snapquiz.transport.resolver.uuid4",
        side_effect=(
            READY_PUBLICATION_ID,
            LIFECYCLE_ID,
            TRANSPORT_CLAIM_ID,
            DNS_START_ID,
        ),
    ):
        prepared = coordinate_resolver_attempt(
            launcher=launcher,
            credential_resolver=resolver,
            gate=gate,
            credential_permit=credential,
            cleanup_ticket=cleanup_ticket,
        )
    return SimpleNamespace(
        runtime=runtime,
        gate=gate,
        credential=credential,
        resolver=resolver,
        source=source,
        prepared=prepared,
        cleanup_ticket=cleanup_ticket,
        events=events,
    )


def _assert_closed(case: unittest.TestCase, bundle: SimpleNamespace) -> None:
    case.assertTrue(bundle.prepared.is_closed)
    case.assertTrue(bundle.prepared.credential_handle.is_closed)
    case.assertTrue(bundle.credential._released)


def _assert_safe(case: unittest.TestCase, error: BaseException) -> None:
    case.assertIsInstance(error, OperationError)
    case.assertIsNone(error.__cause__)
    case.assertIsNone(error.__context__)
    rendered = str(error)
    for forbidden in (
        "8.8.8.8",
        "1.1.1.1",
        "synthetic-token",
        "edge-secret",
        "request-secret",
        "cleanup-secret",
    ):
        case.assertNotIn(forbidden, rendered)


class _NumericEdge:
    def __init__(
        self,
        *,
        peer=("8.8.8.8", 443),
        connect_result: int = 0,
        wait_results: tuple[bool, ...] = (),
        socket_error: int = 0,
        on_wait=None,
        fail_at: str | None = None,
        close_fault: BaseException | None = None,
        pre_close_failures: int = 0,
    ) -> None:
        self.peer = peer
        self.connect_result = connect_result
        self.wait_results = list(wait_results)
        self.socket_error_result = socket_error
        self.on_wait = on_wait
        self.fail_at = fail_at
        self.close_fault = close_fault
        self.pre_close_failures = pre_close_failures
        self.events: list[object] = []
        self.connect_calls = 0
        self.wait_limits: list[int] = []
        self.close_calls = 0

    def _step(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise KeyboardInterrupt(f"edge-secret:{name}:8.8.8.8")

    def set_nonblocking(self) -> None:
        self._step("set_nonblocking")

    def connect_once(self, sockaddr) -> int:
        self._step("connect_once")
        self.connect_calls += 1
        self.events.append(("sockaddr", sockaddr))
        return self.connect_result

    def wait_writable(self, *, max_wait_ns: int) -> bool:
        self._step("wait_writable")
        self.wait_limits.append(max_wait_ns)
        if self.on_wait is not None:
            self.on_wait()
        if self.wait_results:
            return self.wait_results.pop(0)
        return True

    def socket_error(self) -> int:
        self._step("socket_error")
        return self.socket_error_result

    def peername(self):
        self._step("peername")
        return self.peer

    def close_once(self) -> None:
        if self.pre_close_failures:
            self.pre_close_failures -= 1
            raise KeyboardInterrupt("cleanup-secret:pre-close-action")
        self.close_calls += 1
        self.events.append("close_once")
        if self.close_calls > 1:
            raise AssertionError("raw edge close replay")
        if self.close_fault is not None:
            raise self.close_fault

    @property
    def closed(self) -> bool:
        return self.close_calls > 0


class _NumericFactory:
    def __init__(
        self,
        edge: _NumericEdge | None,
        *,
        fault: BaseException | None = None,
    ) -> None:
        self.edge = edge
        self.fault = fault
        self.calls: list[tuple[int, int, int]] = []

    def __call__(
        self,
        family: int,
        socket_type: int,
        protocol: int,
        publish,
        publication_is_exact,
    ) -> None:
        self.calls.append((family, socket_type, protocol))
        if self.fault is not None:
            raise self.fault
        if self.edge is None:
            raise AssertionError("test numeric edge is absent")
        publish(self.edge)
        if not publication_is_exact(self.edge):
            raise AssertionError("test numeric publication did not commit")


class _TlsEdge:
    def __init__(
        self,
        raw: _NumericEdge,
        *,
        handshake: tuple[object, ...] = ("complete",),
        negotiated=("http/1.1", "TLSv1.3"),
        writes: tuple[object, ...] = (),
        reads: tuple[object, ...] = (_OK_RESPONSE, b""),
        on_negotiated=None,
        on_write=None,
        close_fault: BaseException | None = None,
        pre_close_failures: int = 0,
        close_raw: bool = True,
    ) -> None:
        self.raw = raw
        self.handshake = list(handshake)
        self.negotiated = negotiated
        self.write_plan = list(writes)
        self.read_plan = list(reads)
        self.on_negotiated = on_negotiated
        self.on_write = on_write
        self.close_fault = close_fault
        self.pre_close_failures = pre_close_failures
        self.close_raw = close_raw
        self.handshake_calls = 0
        self.write_calls = 0
        self.read_calls = 0
        self.wait_calls: list[tuple[str, int]] = []
        self.offered: list[bytes] = []
        self.sent = bytearray()
        self.request_backings: list[type[object]] = []
        self.close_calls = 0

    @staticmethod
    def _select(plan: list[object], default: object) -> object:
        selected = plan.pop(0) if plan else default
        if isinstance(selected, BaseException):
            raise selected
        return selected

    def handshake_step(self) -> str:
        self.handshake_calls += 1
        selected = self._select(self.handshake, "complete")
        if type(selected) is not str:
            raise TypeError("invalid test handshake item")
        return selected

    def wait_ready(self, *, direction: str, max_wait_ns: int) -> bool:
        self.wait_calls.append((direction, max_wait_ns))
        return True

    def negotiated_values(self):
        if self.on_negotiated is not None:
            self.on_negotiated()
        return self.negotiated

    def write_once(self, value: memoryview):
        self.write_calls += 1
        if type(value) is not memoryview:
            raise TypeError("write input must remain a view")
        self.request_backings.append(type(value.obj))
        offered = bytes(value)
        self.offered.append(offered)
        selected = self._select(
            self.write_plan,
            ("written", len(offered)),
        )
        if (
            type(selected) is tuple
            and len(selected) == 2
            and selected[0] == "written"
            and type(selected[1]) is int
            and 0 <= selected[1] <= len(offered)
        ):
            self.sent.extend(offered[: selected[1]])
        if self.on_write is not None:
            self.on_write(self.write_calls, selected)
        return selected

    def read_once(self, maximum: int):
        self.read_calls += 1
        selected = self._select(self.read_plan, b"")
        if type(selected) is bytes:
            return "data", selected
        return selected

    def close_once(self) -> None:
        if self.pre_close_failures:
            self.pre_close_failures -= 1
            raise KeyboardInterrupt("cleanup-secret:tls-pre-close-action")
        self.close_calls += 1
        if self.close_calls > 1:
            raise AssertionError("TLS edge close replay")
        raw_failure: BaseException | None = None
        if self.close_raw and not self.raw.closed:
            try:
                self.raw.close_once()
            except BaseException as error:
                raw_failure = error
        if self.close_fault is not None:
            raise self.close_fault
        if raw_failure is not None:
            raise raw_failure

    @property
    def closed(self) -> bool:
        return self.close_calls > 0


class _BlockingTlsCloseEdge(_TlsEdge):
    """TLS test edge that holds its first close action open for a race."""

    def __init__(self, raw: _NumericEdge) -> None:
        super().__init__(raw)
        self.close_entered = Event()
        self.duplicate_close_entered = Event()
        self.allow_close = Event()
        self._close_state_lock = Lock()
        self._close_committed = False

    def close_once(self) -> None:
        with self._close_state_lock:
            self.close_calls += 1
            if self.close_calls == 1:
                self.close_entered.set()
            else:
                self.duplicate_close_entered.set()
        if not self.allow_close.wait(5):
            raise AssertionError("test TLS close release was not signalled")
        if not self.raw.closed:
            self.raw.close_once()
        with self._close_state_lock:
            self._close_committed = True

    @property
    def closed(self) -> bool:
        with self._close_state_lock:
            return self._close_committed


class _TlsFactory:
    def __init__(
        self,
        *,
        edge_options: dict[str, object] | None = None,
        fault: BaseException | None = None,
        fault_after_publish: BaseException | None = None,
    ) -> None:
        self.edge_options = {} if edge_options is None else edge_options
        self.fault = fault
        self.fault_after_publish = fault_after_publish
        self.calls: list[tuple[object, object, str]] = []
        self.edges: list[_TlsEdge] = []

    def __call__(
        self,
        raw,
        policy,
        hostname: str,
        publish,
        publication_is_exact,
    ) -> None:
        self.calls.append((raw, policy, hostname))
        if self.fault is not None:
            raise self.fault
        edge = _TlsEdge(raw, **self.edge_options)
        self.edges.append(edge)
        publish(edge)
        if not publication_is_exact(edge):
            raise AssertionError("test TLS publication did not commit")
        if self.fault_after_publish is not None:
            raise self.fault_after_publish


def _drive(
    bundle: SimpleNamespace,
    numeric_factory: _NumericFactory,
    tls_factory: _TlsFactory,
) -> TransportResponse:
    with _clean_tls_environment(), _poison_network():
        return exact_transport._send_exact_with_test_edges(
            bundle.prepared,
            numeric_edge_factory=numeric_factory,
            tls_edge_factory=tls_factory,
            _authority=exact_transport._TEST_TRANSPORT_AUTHORITY,
        )


@contextmanager
def _interrupt_return(function):
    target = function.__code__
    previous = sys.gettrace()
    fired = [False]

    def interrupt(frame, event, arg):
        del arg
        if not fired[0] and event == "return" and frame.f_code is target:
            fired[0] = True
            sys.settrace(previous)
            raise KeyboardInterrupt("edge-secret:return-publication")
        return interrupt

    sys.settrace(interrupt)
    try:
        yield fired
    finally:
        sys.settrace(previous)


@contextmanager
def _interrupt_published_numeric_alias(function):
    target = function.__code__
    previous = sys.gettrace()
    fired = [False]

    def interrupt(frame, event, arg):
        del arg
        if not fired[0] and event == "line" and frame.f_code is target:
            result = frame.f_locals.get("result")
            edge = frame.f_locals.get("edge")
            if (
                type(result)
                is exact_transport.numeric_connect._NumericConnectionOwner
                and edge is not None
            ):
                fired[0] = True
                sys.settrace(previous)
                raise KeyboardInterrupt("edge-secret:published-alias")
        return interrupt

    sys.settrace(interrupt)
    try:
        yield fired
    finally:
        sys.settrace(previous)


class ExactTransportSuccessTest(unittest.TestCase):
    def test_http1_policy_digest_is_bound_into_wire_evidence(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()
        evidence_inputs: list[dict[str, object]] = []
        original = exact_transport._wire_evidence_digest

        def capture_evidence(**kwargs):
            evidence_inputs.append(dict(kwargs))
            return original(**kwargs)

        with mock.patch.object(
            exact_transport,
            "_wire_evidence_digest",
            new=capture_evidence,
        ):
            response = _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertEqual(response.http_status, 200)
        self.assertEqual(len(evidence_inputs), 1)
        self.assertEqual(
            evidence_inputs[0]["http1_policy_digest"],
            exact_http1.EXACT_HTTP1_POLICY_DIGEST,
        )
        wrong = dict(evidence_inputs[0])
        wrong["http1_policy_digest"] = type(
            exact_http1.EXACT_HTTP1_POLICY_DIGEST
        )("0" * 64)
        with self.assertRaises(ValueError):
            original(**wrong)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 1)
        _assert_closed(self, bundle)

    def test_all_io_is_sliced_partial_and_bound_to_one_socket(self):
        bundle = _prepared()
        numeric = _NumericEdge(
            connect_result=errno.EINPROGRESS,
            wait_results=(False, False, True),
        )
        numeric_factory = _NumericFactory(numeric)
        split = 17
        tls_factory = _TlsFactory(
            edge_options={
                "handshake": ("want_write", "want_read", "complete"),
                "writes": (("written", 11), ("want_write", 0)),
                "reads": (
                    _OK_RESPONSE[:split],
                    ("want_read", None),
                    _OK_RESPONSE[split:],
                    b"",
                ),
            }
        )
        phases: list[str] = []
        original_checkpoint = AttemptGate._checkpoint_transport_io

        def record_checkpoint(selected, *args, **kwargs):
            phases.append(kwargs["phase"])
            return original_checkpoint(selected, *args, **kwargs)

        with mock.patch.object(
            AttemptGate,
            "_checkpoint_transport_io",
            new=record_checkpoint,
        ):
            response = _drive(bundle, numeric_factory, tls_factory)

        self.assertIs(type(response), TransportResponse)
        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.body, b"ok")
        self.assertEqual(
            response.request_envelope_digest,
            bundle.runtime.prepared.request_envelope_digest,
        )
        self.assertEqual(
            numeric_factory.calls,
            [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)],
        )
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(numeric.wait_limits), 3)
        self.assertEqual(numeric.close_calls, 1)
        self.assertTrue(
            all(0 < value <= HELPER_WAIT_QUANTUM_NS for value in numeric.wait_limits)
        )
        tls = tls_factory.edges[0]
        self.assertEqual(tls_factory.calls[0][2], "open.bigmodel.cn")
        self.assertEqual(tls.handshake_calls, 3)
        self.assertEqual(tls.write_calls, 3)
        self.assertEqual(tls.read_calls, 4)
        self.assertEqual(tls.close_calls, 1)
        self.assertTrue(
            all(0 < value <= HELPER_WAIT_QUANTUM_NS for _, value in tls.wait_calls)
        )
        self.assertTrue(all(item is bytearray for item in tls.request_backings))
        request = bytes(tls.sent)
        self.assertEqual(request.count(b"authorization: Bearer "), 1)
        self.assertEqual(request.count(VALID_SECRET), 1)
        self.assertTrue(request.startswith(b"POST /api/paas/v4/chat/completions HTTP/1.1\r\n"))
        self.assertEqual(phases.count("numeric-connect"), 4)
        self.assertEqual(phases.count("tls-handshake"), 3)
        self.assertEqual(phases.count("request-write"), 3)
        self.assertEqual(phases.count("response-read"), 4)
        _assert_closed(self, bundle)

    def test_302_is_returned_without_redirect_retry_or_second_connect(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory(
            edge_options={
                "reads": (
                    b"HTTP/1.1 302 Found\r\ncontent-length: 0\r\n"
                    b"location: https://other.example/\r\n\r\n",
                    b"",
                )
            }
        )

        response = _drive(bundle, numeric_factory, tls_factory)

        self.assertEqual(response.http_status, 302)
        self.assertEqual(response.body, b"")
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 1)
        _assert_closed(self, bundle)

    def test_committed_wire_survives_commit_then_raise_without_reencode(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory()
        original_commit = AttemptGate._commit_wire_start
        commit_calls = 0

        def commit_then_raise(selected, *args, **kwargs):
            nonlocal commit_calls
            commit_calls += 1
            original_commit(selected, *args, **kwargs)
            raise KeyboardInterrupt("request-secret:postcommit")

        with mock.patch.object(
            AttemptGate,
            "_commit_wire_start",
            new=commit_then_raise,
        ):
            response = _drive(bundle, numeric_factory, tls_factory)

        self.assertEqual(response.http_status, 200)
        self.assertEqual(commit_calls, 1)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 1)
        self.assertEqual(bytes(tls.sent).count(VALID_SECRET), 1)
        self.assertEqual(numeric.connect_calls, 1)
        _assert_closed(self, bundle)

    def test_postpublication_factory_fault_continues_same_tls_edge(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory(
            fault_after_publish=KeyboardInterrupt(
                "edge-secret:tls-published"
            )
        )

        response = _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertEqual(response.http_status, 200)
        self.assertEqual(len(tls_factory.edges), 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 1)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)


class ExactTransportPublicationRecoveryTest(unittest.TestCase):
    def test_concurrent_tls_publication_close_invokes_each_edge_once(self):
        publication = exact_transport._TlsOwnershipPublication(
            _authority=exact_transport._OWNERSHIP_PUBLICATION_AUTHORITY,
        )
        raw = _NumericEdge()
        tls = _BlockingTlsCloseEdge(raw)
        publication.publish_raw(raw)
        publication.publish_tls(raw, tls)
        start = Barrier(3)
        errors: list[BaseException] = []
        errors_lock = Lock()

        def close() -> None:
            start.wait()
            try:
                publication.close_once()
            except BaseException as error:
                with errors_lock:
                    errors.append(error)

        threads = [Thread(target=close) for _ in range(2)]
        for thread in threads:
            thread.start()
        start.wait()
        self.assertTrue(tls.close_entered.wait(5))
        # Both callers crossed the start barrier while the first underlying
        # action is held open; the second must remain above the action edge.
        duplicate_entered = tls.duplicate_close_entered.wait(0.25)
        tls.allow_close.set()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())

        self.assertFalse(duplicate_entered)
        self.assertEqual(errors, [])
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(raw.close_calls, 1)
        self.assertTrue(publication.is_terminal())

    def test_numeric_result_store_interrupt_has_one_cleanup_owner(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()

        with _interrupt_published_numeric_alias(
            exact_transport.numeric_connect._connect_with_edge_factory_published
        ) as fired, self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(raised.exception.stage, "numeric_connect")
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        self.assertEqual(tls_factory.calls, [])
        _assert_closed(self, bundle)

    def test_numeric_start_return_interrupt_recovers_published_owner(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory()

        with _interrupt_return(
            exact_transport.numeric_connect._publish_selected_numeric_with_test_edge
        ) as fired:
            response = _drive(bundle, numeric_factory, tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(response.http_status, 200)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        self.assertEqual(len(tls_factory.edges), 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 1)
        _assert_closed(self, bundle)

    def test_numeric_factory_return_interrupt_uses_preheld_slot_once(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory()

        with _interrupt_return(_NumericFactory.__call__) as fired:
            response = _drive(bundle, numeric_factory, tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(response.http_status, 200)
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(tls_factory.edges), 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 1)
        self.assertEqual(numeric.close_calls, 1)

        second = _NumericFactory(_NumericEdge())
        with self.assertRaises(OperationError) as raised:
            _drive(bundle, second, _TlsFactory())
        _assert_safe(self, raised.exception)
        self.assertEqual(second.calls, [])
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(numeric.connect_calls, 1)
        _assert_closed(self, bundle)

    def test_numeric_factory_return_interrupt_retains_unclosed_raw_ticket(self):
        bundle = _prepared()
        numeric = _NumericEdge(
            fail_at="set_nonblocking",
            pre_close_failures=2,
        )
        numeric_factory = _NumericFactory(numeric)

        with _interrupt_return(_NumericFactory.__call__) as fired, self.assertRaises(
            EndpointPolicyError
        ) as raised:
            _drive(bundle, numeric_factory, _TlsFactory())

        self.assertTrue(fired[0])
        self.assertEqual(raised.exception.stage, "numeric_connect")
        _assert_safe(self, raised.exception)
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(numeric.connect_calls, 0)
        self.assertEqual(numeric.close_calls, 0)
        self.assertFalse(numeric.closed)
        self.assertFalse(bundle.cleanup_ticket.is_terminal)
        self.assertEqual(
            bundle.prepared.safe_metadata()["state"],
            "cleanup_pending",
        )

        self.assertTrue(bundle.cleanup_ticket.retry_cleanup())
        self.assertTrue(bundle.cleanup_ticket.is_terminal)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_pending_poll_return_interrupt_closes_internal_owner(self):
        bundle = _prepared()
        numeric = _NumericEdge(
            connect_result=errno.EINPROGRESS,
            wait_results=(True,),
        )
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory()

        with _interrupt_return(
            exact_transport.numeric_connect._PendingNumericConnection.poll
        ) as fired, self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, numeric_factory, tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(numeric.wait_limits), 1)
        self.assertEqual(numeric.close_calls, 1)
        self.assertEqual(tls_factory.calls, [])
        _assert_closed(self, bundle)

    def test_numeric_to_raw_return_interrupt_observes_committed_handoff(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()

        with _interrupt_return(
            exact_transport.numeric_connect._NumericConnectionOwner
            ._publish_edge_for_tls
        ) as fired:
            response = _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(response.http_status, 200)
        self.assertEqual(numeric.close_calls, 1)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        _assert_closed(self, bundle)

    def test_tls_factory_return_interrupt_observes_committed_handoff(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()

        with _interrupt_return(_TlsFactory.__call__) as fired:
            response = _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(response.http_status, 200)
        self.assertEqual(len(tls_factory.edges), 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 1)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)

        with self.assertRaises(OperationError) as raised:
            _drive(bundle, _NumericFactory(_NumericEdge()), tls_factory)
        _assert_safe(self, raised.exception)
        self.assertEqual(len(tls_factory.calls), 1)
        _assert_closed(self, bundle)

    def test_tls_factory_return_interrupt_retains_unclosed_tls_ticket(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory(
            edge_options={
                "negotiated": ("h2", "TLSv1.3"),
                "pre_close_failures": 2,
            }
        )

        with _interrupt_return(_TlsFactory.__call__) as fired, self.assertRaises(
            EndpointPolicyError
        ) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(raised.exception.stage, "tls_transport")
        _assert_safe(self, raised.exception)
        self.assertEqual(len(tls_factory.calls), 1)
        self.assertEqual(len(tls_factory.edges), 1)
        self.assertEqual(tls_factory.edges[0].close_calls, 0)
        self.assertFalse(tls_factory.edges[0].closed)
        # TLS terminality is still unknown, but cleanup independently closes
        # the retained raw edge instead of assuming the TLS action owns it.
        self.assertEqual(numeric.close_calls, 1)
        self.assertTrue(numeric.closed)
        self.assertFalse(bundle.cleanup_ticket.is_terminal)
        self.assertEqual(
            bundle.prepared.safe_metadata()["state"],
            "cleanup_pending",
        )

        self.assertTrue(bundle.cleanup_ticket.retry_cleanup())
        self.assertTrue(bundle.cleanup_ticket.is_terminal)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_tls_edge_that_detaches_raw_retains_pair_until_fallback_proves_both(self):
        bundle = _prepared()
        numeric = _NumericEdge(pre_close_failures=2)
        tls_factory = _TlsFactory(edge_options={"close_raw": False})

        with self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.close_calls, 1)
        self.assertTrue(tls.closed)
        self.assertEqual(numeric.close_calls, 0)
        self.assertFalse(numeric.closed)
        self.assertFalse(bundle.cleanup_ticket.is_terminal)
        self.assertFalse(bundle.prepared.is_closed)
        self.assertEqual(
            bundle.prepared.safe_metadata()["state"],
            "cleanup_pending",
        )

        self.assertTrue(bundle.cleanup_ticket.retry_cleanup())
        self.assertTrue(bundle.cleanup_ticket.is_terminal)
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        self.assertTrue(numeric.closed)
        _assert_closed(self, bundle)

    def test_tls_factory_cannot_return_the_published_resource(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        edges = []
        calls = []

        def illegal_factory(
            raw,
            policy,
            hostname,
            publish,
            publication_is_exact,
        ):
            calls.append((raw, policy, hostname))
            edge = _TlsEdge(raw)
            edges.append(edge)
            publish(edge)
            self.assertTrue(publication_is_exact(edge))
            return edge

        with self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, _NumericFactory(numeric), illegal_factory)

        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].write_calls, 0)
        self.assertEqual(edges[0].close_calls, 1)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_real_tls_close_return_interrupt_is_observed_and_idempotent(self):
        class FakeSslSocket:
            def __init__(self) -> None:
                self.close_calls = 0
                self.fd = 91

            def close(self) -> None:
                self.close_calls += 1
                self.fd = -1

            def fileno(self) -> int:
                return self.fd

        fake = FakeSslSocket()
        with mock.patch.object(exact_transport.ssl, "SSLSocket", FakeSslSocket):
            edge = exact_transport._RealTlsEdge(
                fake,
                _authority=exact_transport._REAL_TLS_EDGE_AUTHORITY,
            )
            with _interrupt_return(FakeSslSocket.close) as fired, self.assertRaises(
                ValueError
            ):
                edge.close_once()
            self.assertTrue(fired[0])
            self.assertTrue(edge.closed)
            edge.close_once()
        self.assertEqual(fake.close_calls, 1)


class ExactTransportPreWireFailureTest(unittest.TestCase):
    def test_http1_policy_version_and_every_limit_drift_are_zero_wire(self):
        policy_names = (
            "EXACT_HTTP1_POLICY_SCHEMA_VERSION",
            "EXACT_HTTP1_POLICY_VERSION",
            *sorted(
                name
                for name, value in vars(exact_http1).items()
                if name.startswith("MAX_") and type(value) is int
            ),
        )
        for name in policy_names:
            with self.subTest(name=name):
                bundle = _prepared()
                numeric_factory = _NumericFactory(_NumericEdge())
                tls_factory = _TlsFactory()
                original = getattr(exact_http1, name)
                drifted = (
                    original + ".drift"
                    if type(original) is str
                    else original + 1
                )
                with mock.patch.object(
                    exact_http1,
                    name,
                    drifted,
                ), self.assertRaises(EndpointPolicyError) as raised:
                    _drive(bundle, numeric_factory, tls_factory)

                self.assertEqual(raised.exception.stage, "http1_transport")
                _assert_safe(self, raised.exception)
                self.assertEqual(numeric_factory.calls, [])
                self.assertEqual(tls_factory.calls, [])
                _assert_closed(self, bundle)

    def test_http1_policy_is_revalidated_after_tls_before_wire_commit(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        original = exact_http1.MAX_HTTP_CHUNKS

        def drift_after_tls() -> None:
            exact_http1.MAX_HTTP_CHUNKS = original + 1

        tls_factory = _TlsFactory(
            edge_options={"on_negotiated": drift_after_tls}
        )
        try:
            with self.assertRaises(EndpointPolicyError) as raised:
                _drive(bundle, _NumericFactory(numeric), tls_factory)
        finally:
            exact_http1.MAX_HTTP_CHUNKS = original

        self.assertEqual(raised.exception.stage, "http1_transport")
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 0)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        _assert_closed(self, bundle)

    def test_sslkeylogfile_presence_fails_before_context_socket_or_wire(self):
        with tempfile.TemporaryDirectory() as directory:
            keylog_path = Path(directory) / "request-secret.keys"
            for value in ("", str(keylog_path)):
                with self.subTest(value_is_empty=value == ""):
                    bundle = _prepared()
                    numeric_factory = _NumericFactory(_NumericEdge())
                    tls_factory = _TlsFactory()
                    with (
                        mock.patch.dict(
                            os.environ,
                            {"SSLKEYLOGFILE": value},
                            clear=True,
                        ),
                        _poison_network(),
                        mock.patch.object(
                            exact_tls.ssl,
                            "create_default_context",
                            side_effect=AssertionError(
                                "context must not be constructed"
                            ),
                        ) as context_factory,
                        self.assertRaises(EndpointPolicyError) as raised,
                    ):
                        exact_transport._send_exact_with_test_edges(
                            bundle.prepared,
                            numeric_edge_factory=numeric_factory,
                            tls_edge_factory=tls_factory,
                            _authority=exact_transport._TEST_TRANSPORT_AUTHORITY,
                        )

                    self.assertEqual(raised.exception.stage, "tls_transport")
                    _assert_safe(self, raised.exception)
                    context_factory.assert_not_called()
                    self.assertEqual(numeric_factory.calls, [])
                    self.assertEqual(tls_factory.calls, [])
                    self.assertFalse(keylog_path.exists())
                    _assert_closed(self, bundle)

    def test_sslkeylogfile_context_capture_is_rejected_before_socket_or_wire(self):
        with tempfile.TemporaryDirectory() as directory:
            keylog_path = Path(directory) / "captured.keys"
            bundle = _prepared()
            numeric_factory = _NumericFactory(_NumericEdge())
            tls_factory = _TlsFactory()
            original_factory = ssl.create_default_context
            captured_contexts: list[ssl.SSLContext] = []

            def capture_during_factory(purpose):
                with mock.patch.dict(
                    os.environ,
                    {"SSLKEYLOGFILE": str(keylog_path)},
                ):
                    context = original_factory(purpose)
                captured_contexts.append(context)
                return context

            with (
                mock.patch.dict(os.environ, {}, clear=True),
                _poison_network(),
                mock.patch.object(
                    exact_tls.ssl,
                    "create_default_context",
                    side_effect=capture_during_factory,
                ) as context_factory,
            ):
                with self.assertRaises(EndpointPolicyError) as raised:
                    exact_transport._send_exact_with_test_edges(
                        bundle.prepared,
                        numeric_edge_factory=numeric_factory,
                        tls_edge_factory=tls_factory,
                        _authority=exact_transport._TEST_TRANSPORT_AUTHORITY,
                    )
                self.assertNotIn("SSLKEYLOGFILE", os.environ)

            self.assertEqual(raised.exception.stage, "tls_transport")
            _assert_safe(self, raised.exception)
            context_factory.assert_called_once_with(ssl.Purpose.SERVER_AUTH)
            self.assertEqual(len(captured_contexts), 1)
            self.assertIsNotNone(captured_contexts[0].keylog_filename)
            self.assertTrue(keylog_path.exists())
            self.assertEqual(numeric_factory.calls, [])
            self.assertEqual(tls_factory.calls, [])
            _assert_closed(self, bundle)

    def test_peer_rebinding_fails_before_tls_or_wire(self):
        bundle = _prepared()
        numeric = _NumericEdge(peer=("1.1.1.1", 443))
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory()

        with self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, numeric_factory, tls_factory)

        self.assertEqual(raised.exception.stage, "numeric_connect")
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        self.assertEqual(tls_factory.calls, [])
        _assert_closed(self, bundle)

    def test_tls_factory_and_negotiation_failures_are_zero_wire(self):
        cases = (
            ("factory", _TlsFactory(fault=KeyboardInterrupt("edge-secret"))),
            (
                "alpn",
                _TlsFactory(edge_options={"negotiated": ("h2", "TLSv1.3")}),
            ),
            (
                "version",
                _TlsFactory(
                    edge_options={"negotiated": ("http/1.1", "TLSv1.1")}
                ),
            ),
        )
        for name, tls_factory in cases:
            with self.subTest(name=name):
                bundle = _prepared()
                numeric = _NumericEdge()
                numeric_factory = _NumericFactory(numeric)
                with self.assertRaises(OperationError) as raised:
                    _drive(bundle, numeric_factory, tls_factory)
                _assert_safe(self, raised.exception)
                self.assertEqual(numeric.connect_calls, 1)
                self.assertEqual(numeric.close_calls, 1)
                if tls_factory.edges:
                    self.assertEqual(tls_factory.edges[0].write_calls, 0)
                    self.assertEqual(tls_factory.edges[0].close_calls, 1)
                _assert_closed(self, bundle)

    def test_wire_commit_noop_sends_zero_bytes_and_releases_borrow(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()
        with mock.patch.object(
            AttemptGate,
            "_commit_wire_start",
            return_value=None,
        ), self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        _assert_safe(self, raised.exception)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 0)
        self.assertEqual(tls.sent, b"")
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_revocation_after_tls_blocks_credential_borrow_and_wire(self):
        bundle = _prepared()
        numeric = _NumericEdge()

        def revoke() -> None:
            bundle.runtime.cancellation_source.cancel(
                reason=CancellationReason.USER_REQUEST
            )

        tls_factory = _TlsFactory(edge_options={"on_negotiated": revoke})
        with self.assertRaises(CancelledError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        _assert_safe(self, raised.exception)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 0)
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)


class ExactTransportPendingAndWireFailureTest(unittest.TestCase):
    def test_cancel_and_timeout_close_one_pending_fd_without_second_connect(self):
        for mode, expected in (
            ("cancel", CancelledError),
            ("timeout", TimeoutError),
        ):
            with self.subTest(mode=mode):
                bundle = _prepared()
                fired = False

                def stop() -> None:
                    nonlocal fired
                    if fired:
                        return
                    fired = True
                    if mode == "cancel":
                        bundle.runtime.cancellation_source.cancel(
                            reason=CancellationReason.USER_REQUEST
                        )
                    else:
                        bundle.runtime.clock.advance(milliseconds=30_000)

                numeric = _NumericEdge(
                    connect_result=errno.EINPROGRESS,
                    wait_results=(False,),
                    on_wait=stop,
                )
                numeric_factory = _NumericFactory(numeric)
                tls_factory = _TlsFactory()
                with self.assertRaises(expected) as raised:
                    _drive(bundle, numeric_factory, tls_factory)
                _assert_safe(self, raised.exception)
                self.assertEqual(numeric.connect_calls, 1)
                self.assertEqual(len(numeric_factory.calls), 1)
                self.assertEqual(len(numeric.wait_limits), 1)
                self.assertEqual(numeric.close_calls, 1)
                self.assertEqual(tls_factory.calls, [])
                _assert_closed(self, bundle)

    def test_partial_wire_fault_never_reencodes_or_reconnects(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory(
            edge_options={
                "writes": (
                    ("written", 13),
                    KeyboardInterrupt(
                        "request-secret:synthetic-token:8.8.8.8"
                    ),
                )
            }
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, numeric_factory, tls_factory)

        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 2)
        self.assertEqual(len(tls.sent), 13)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(tls.read_calls, 0)
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_write_return_interrupt_never_replays_ambiguous_bytes(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()

        with _interrupt_return(_TlsEdge.write_once) as fired, self.assertRaises(
            EndpointPolicyError
        ) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 1)
        self.assertGreater(len(tls.sent), 0)
        self.assertEqual(tls.read_calls, 0)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_read_return_interrupt_never_retries_ambiguous_response_bytes(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()

        with _interrupt_return(_TlsEdge.read_once) as fired, self.assertRaises(
            EndpointPolicyError
        ) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertTrue(fired[0])
        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 1)
        self.assertEqual(tls.read_calls, 1)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_revocation_after_partial_wire_stops_same_request_without_replay(self):
        bundle = _prepared()
        numeric = _NumericEdge()

        def revoke(write_calls: int, outcome: object) -> None:
            if write_calls == 1 and outcome == ("written", 13):
                bundle.runtime.cancellation_source.cancel(
                    reason=CancellationReason.USER_REQUEST
                )

        tls_factory = _TlsFactory(
            edge_options={
                "writes": (("written", 13),),
                "on_write": revoke,
            }
        )
        numeric_factory = _NumericFactory(numeric)

        with self.assertRaises(CancelledError) as raised:
            _drive(bundle, numeric_factory, tls_factory)

        _assert_safe(self, raised.exception)
        tls = tls_factory.edges[0]
        self.assertEqual(tls.write_calls, 1)
        self.assertEqual(len(tls.sent), 13)
        self.assertEqual(tls.read_calls, 0)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(tls.close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_malformed_or_second_response_is_rejected_without_retry(self):
        cases = (
            b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n"
            b"content-length: 1\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
        )
        for response_bytes in cases:
            with self.subTest(response=response_bytes[:32]):
                bundle = _prepared()
                numeric = _NumericEdge()
                numeric_factory = _NumericFactory(numeric)
                tls_factory = _TlsFactory(
                    edge_options={"reads": (response_bytes, b"")}
                )
                with self.assertRaises(EndpointPolicyError) as raised:
                    _drive(bundle, numeric_factory, tls_factory)
                self.assertEqual(raised.exception.stage, "http1_transport")
                _assert_safe(self, raised.exception)
                self.assertEqual(numeric.connect_calls, 1)
                self.assertEqual(tls_factory.edges[0].write_calls, 1)
                self.assertEqual(tls_factory.edges[0].close_calls, 1)
                self.assertEqual(numeric.close_calls, 1)
                _assert_closed(self, bundle)

    def test_duplicate_transport_claim_never_starts_a_second_socket(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        numeric_factory = _NumericFactory(numeric)
        first_tls = _TlsFactory()
        self.assertEqual(
            _drive(bundle, numeric_factory, first_tls).http_status,
            200,
        )
        second_tls = _TlsFactory()
        with self.assertRaises(OperationError) as raised:
            _drive(bundle, numeric_factory, second_tls)
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(second_tls.calls, [])
        _assert_closed(self, bundle)

    def test_concurrent_transport_claim_has_one_wire_winner(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        numeric_factory = _NumericFactory(numeric)
        tls_factory = _TlsFactory()
        barrier = Barrier(3)
        lock = Lock()
        outcomes: list[object] = []

        def run() -> None:
            barrier.wait()
            try:
                selected: object = exact_transport._send_exact_with_test_edges(
                    bundle.prepared,
                    numeric_edge_factory=numeric_factory,
                    tls_edge_factory=tls_factory,
                    _authority=exact_transport._TEST_TRANSPORT_AUTHORITY,
                )
            except BaseException as error:
                selected = error
            with lock:
                outcomes.append(selected)

        threads = [Thread(target=run), Thread(target=run)]
        with _clean_tls_environment(), _poison_network():
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())

        self.assertEqual(
            sum(type(item) is TransportResponse for item in outcomes),
            1,
        )
        failures = [item for item in outcomes if isinstance(item, BaseException)]
        self.assertEqual(len(failures), 1)
        _assert_safe(self, failures[0])
        self.assertEqual(numeric.connect_calls, 1)
        self.assertEqual(len(numeric_factory.calls), 1)
        self.assertEqual(len(tls_factory.calls), 1)
        self.assertEqual(len(tls_factory.edges), 1)
        self.assertEqual(tls_factory.edges[0].write_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)


class ExactTransportAcquisitionAndCleanupTest(unittest.TestCase):
    def test_numeric_credential_and_parser_acquisition_fail_closed(self):
        cases = ("numeric", "credential", "parser")
        for name in cases:
            with self.subTest(name=name):
                bundle = _prepared()
                numeric = _NumericEdge()
                numeric_factory = _NumericFactory(
                    numeric,
                    fault=(
                        KeyboardInterrupt("edge-secret:factory:8.8.8.8")
                        if name == "numeric"
                        else None
                    ),
                )
                tls_factory = _TlsFactory()
                stack = ExitStack()
                if name == "credential":
                    stack.enter_context(
                        mock.patch.object(
                            CredentialResolver,
                            "_borrow_once_with_owner",
                            side_effect=KeyboardInterrupt(
                                "request-secret:credential"
                            ),
                        )
                    )
                if name == "parser":
                    stack.enter_context(
                        mock.patch.object(
                            exact_transport.exact_http1,
                            "_new_exact_http1_response_parser",
                            side_effect=KeyboardInterrupt(
                                "request-secret:parser"
                            ),
                        )
                    )
                with stack, self.assertRaises(EndpointPolicyError) as raised:
                    _drive(bundle, numeric_factory, tls_factory)
                self.assertEqual(
                    raised.exception.stage,
                    "numeric_connect" if name == "numeric" else "exact_transport",
                )
                _assert_safe(self, raised.exception)
                self.assertEqual(len(numeric_factory.calls), 1)
                if name == "numeric":
                    self.assertEqual(tls_factory.calls, [])
                    self.assertEqual(numeric.close_calls, 0)
                else:
                    tls = tls_factory.edges[0]
                    self.assertEqual(tls.close_calls, 1)
                    self.assertEqual(numeric.close_calls, 1)
                    self.assertEqual(
                        tls.write_calls,
                        1 if name == "parser" else 0,
                    )
                _assert_closed(self, bundle)

    def test_cleanup_fault_never_overrides_primary_or_leaks_its_text(self):
        bundle = _prepared()
        numeric = _NumericEdge()

        def cancel_after_partial(write_calls: int, outcome: object) -> None:
            if write_calls == 1 and outcome == ("written", 13):
                bundle.runtime.cancellation_source.cancel(
                    reason=CancellationReason.USER_REQUEST
                )

        tls_factory = _TlsFactory(
            edge_options={
                "writes": (("written", 13),),
                "on_write": cancel_after_partial,
                "close_fault": KeyboardInterrupt("cleanup-secret:tls"),
            }
        )

        with self.assertRaises(CancelledError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        _assert_safe(self, raised.exception)
        self.assertEqual(len(tls_factory.edges[0].sent), 13)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_success_cleanup_fault_becomes_sanitized_failure(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory(
            edge_options={
                "close_fault": KeyboardInterrupt("cleanup-secret:tls")
            }
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_unproven_socket_close_defers_attempt_and_credential_cleanup(self):
        bundle = _prepared()
        numeric = _NumericEdge(pre_close_failures=2)
        tls_factory = _TlsFactory(
            fault=KeyboardInterrupt("request-secret:tls-factory")
        )

        with self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric.close_calls, 0)
        self.assertFalse(bundle.prepared.is_closed)
        self.assertEqual(
            bundle.prepared.safe_metadata()["state"],
            "cleanup_pending",
        )
        self.assertFalse(bundle.prepared.credential_handle.is_closed)
        self.assertFalse(bundle.credential._released)

        self.assertTrue(bundle.cleanup_ticket.retry_cleanup())
        self.assertTrue(bundle.cleanup_ticket.is_terminal)
        self.assertEqual(numeric.close_calls, 1)
        _assert_closed(self, bundle)

    def test_finish_wrapper_pre_action_fault_is_ticket_recoverable(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()

        with mock.patch.object(
            PreparedResolverAttempt,
            "_finish_transport",
            side_effect=KeyboardInterrupt("cleanup-secret:finish-pre-action"),
        ), self.assertRaises(EndpointPolicyError) as raised:
            _drive(bundle, _NumericFactory(numeric), tls_factory)

        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        self.assertEqual(numeric.close_calls, 1)
        self.assertEqual(tls_factory.edges[0].close_calls, 1)
        self.assertEqual(bundle.prepared.safe_metadata()["state"], "transporting")
        self.assertFalse(bundle.cleanup_ticket.is_terminal)

        self.assertTrue(bundle.cleanup_ticket.retry_cleanup())
        self.assertTrue(bundle.cleanup_ticket.is_terminal)
        _assert_closed(self, bundle)

    def test_tls_numeric_cleanup_precede_finish_transport(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory()
        events: list[str] = []
        original_tls_close = exact_transport._TlsOwnershipPublication.close_once
        original_numeric_close = exact_transport._NumericRootPublication.close_once
        original_finish = PreparedResolverAttempt._finish_transport

        def close_tls(selected):
            events.append("tls-close")
            return original_tls_close(selected)

        def close_numeric(selected):
            events.append("numeric-close")
            return original_numeric_close(selected)

        def finish(selected, *args, **kwargs):
            events.append("finish-transport")
            return original_finish(selected, *args, **kwargs)

        with (
            mock.patch.object(
                exact_transport._TlsOwnershipPublication,
                "close_once",
                new=close_tls,
            ),
            mock.patch.object(
                exact_transport._NumericRootPublication,
                "close_once",
                new=close_numeric,
            ),
            mock.patch.object(
                PreparedResolverAttempt,
                "_finish_transport",
                new=finish,
            ),
        ):
            response = _drive(
                bundle,
                _NumericFactory(numeric),
                tls_factory,
            )

        self.assertEqual(response.http_status, 200)
        self.assertEqual(
            events,
            ["tls-close", "numeric-close", "finish-transport"],
        )
        _assert_closed(self, bundle)

    def test_public_error_traceback_retains_no_request_secret_owner_or_view(self):
        bundle = _prepared()
        numeric = _NumericEdge()
        tls_factory = _TlsFactory(
            edge_options={
                "writes": (
                    KeyboardInterrupt(
                        "request-secret:synthetic-token:8.8.8.8"
                    ),
                )
            }
        )

        error: EndpointPolicyError | None = None
        traceback = None
        try:
            _drive(bundle, _NumericFactory(numeric), tls_factory)
        except EndpointPolicyError:
            selected = sys.exc_info()[1]
            self.assertIs(type(selected), EndpointPolicyError)
            error = selected
            traceback = selected.__traceback__
        self.assertIsNotNone(error)
        assert error is not None
        _assert_safe(self, error)
        checked_frames = 0
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_code.co_filename.endswith(
                "snapquiz/transport/_exact_transport.py"
            ):
                checked_frames += 1
                for value in frame.f_locals.values():
                    self.assertNotIsInstance(
                        value,
                        (
                            PreparedResolverAttempt,
                            PreparedOutbound,
                            CredentialHandle,
                            CredentialResolver,
                            memoryview,
                        ),
                    )
                    if isinstance(value, (bytes, bytearray)):
                        self.assertNotIn(VALID_SECRET, bytes(value))
            traceback = traceback.tb_next
        self.assertGreaterEqual(checked_frames, 1)
        _assert_closed(self, bundle)


class ExactTransportSurfaceTest(unittest.TestCase):
    def test_real_constructor_adapters_wait_for_opaque_native_owners(self):
        self.assertFalse(
            numeric_connect.PRODUCTION_GATE_INTEGRATION_AVAILABLE
        )
        self.assertFalse(
            numeric_connect.OPAQUE_NUMERIC_SOCKET_OWNER_AVAILABLE
        )
        self.assertFalse(
            exact_transport.PRODUCTION_APP_INTEGRATION_AVAILABLE
        )
        self.assertFalse(
            exact_transport.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE
        )

        with mock.patch.object(
            numeric_connect.socket,
            "socket",
            side_effect=AssertionError("stdlib socket constructor must stay dark"),
        ) as socket_factory, self.assertRaises(ValueError):
            numeric_connect._RealNumericSocketEdge(
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                _authority=numeric_connect._PRODUCTION_EDGE_AUTHORITY,
            )
        socket_factory.assert_not_called()

        numeric_edge = object.__new__(numeric_connect._RealNumericSocketEdge)
        tls_policy = object.__new__(exact_transport.exact_tls._ExactTlsPolicy)
        with mock.patch.object(
            exact_transport.exact_tls._ExactTlsPolicy,
            "_context_for_wrap",
            side_effect=AssertionError("stdlib TLS wrapper must stay dark"),
        ) as context_factory, self.assertRaises(EndpointPolicyError) as raised:
            exact_transport._new_real_tls_edge(
                numeric_edge,
                tls_policy,
                "open.bigmodel.cn",
                lambda edge: None,
                lambda edge: False,
            )
        self.assertEqual(raised.exception.stage, "exact_transport")
        _assert_safe(self, raised.exception)
        context_factory.assert_not_called()

    def test_production_surface_is_unwired_and_has_no_injection_parameters(self):
        parameters = inspect.signature(
            exact_transport._send_exact_unwired
        ).parameters
        self.assertEqual(tuple(parameters), ("prepared_attempt",))
        for forbidden in (
            "socket",
            "context",
            "proxy",
            "resolver",
            "deadline",
            "cancellation_token",
            "now",
        ):
            self.assertNotIn(forbidden, parameters)
        self.assertFalse(
            exact_transport.PRODUCTION_APP_INTEGRATION_AVAILABLE
        )
        self.assertEqual(exact_transport.__all__, ())
        with self.assertRaises(TypeError):
            exact_transport._send_exact_with_test_edges(  # type: ignore[call-arg]
                object(),
                numeric_edge_factory=lambda *_: None,
                tls_edge_factory=lambda *_: None,
            )

        bundle = _prepared()
        try:
            with mock.patch.object(
                exact_transport,
                "_run_exact_transport",
                side_effect=AssertionError("unwired production path must stay dark"),
            ) as run_transport, self.assertRaises(EndpointPolicyError) as raised:
                exact_transport._send_exact_unwired(bundle.prepared)
            self.assertEqual(raised.exception.stage, "exact_transport")
            _assert_safe(self, raised.exception)
            run_transport.assert_not_called()
            self.assertFalse(bundle.prepared.is_closed)
        finally:
            if not bundle.prepared.is_closed:
                bundle.prepared.close()

    def test_module_has_no_app_wire_dns_retry_pool_or_client_dependency(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_exact_transport.py"
        )
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imported
            & {
                "requests",
                "httpx",
                "urllib3",
                "aiohttp",
                "snapquiz.app",
            }
        )
        called_names = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertNotIn("getaddrinfo", called_names)
        self.assertNotIn("create_connection", called_names)
        self.assertNotIn("connect", called_names)
        self.assertNotIn("connect_ex", called_names)


if __name__ == "__main__":
    unittest.main()
