"""Offline W09-B2b-S6 numeric single-connect/peer foundation tests."""
from __future__ import annotations

import ast
from contextlib import contextmanager
import copy
import errno
from pathlib import Path
import pickle
import socket
import sys
from threading import Barrier, Event, Lock, Thread
import unittest
from unittest import mock

from snapquiz.domain.digest import digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport.address_policy import build_resolution_set
from snapquiz.transport import _numeric_connect as numeric_connect

from tests.test_w09_address_policy import (
    _close,
    _issue,
    _record4,
    _record6,
)


WAIT_NS = 12_000_000


def _assert_safe(case: unittest.TestCase, error: BaseException) -> None:
    case.assertIs(type(error), EndpointPolicyError)
    case.assertEqual(error.stage, "numeric_connect")
    case.assertFalse(error.retryable)
    case.assertIsNone(error.__cause__)
    case.assertIsNone(error.__context__)
    rendered = str(error)
    case.assertNotIn("8.8.8.8", rendered)
    case.assertNotIn("1.1.1.1", rendered)
    case.assertNotIn("2001:4860", rendered)
    case.assertNotIn("edge-secret", rendered)


def _resolution(*records):
    publication = _issue(*records)
    _, _, attempt, _, _, receipt, _ = publication
    return publication, build_resolution_set(attempt, receipt)


class _FakeEdge:
    def __init__(
        self,
        *,
        peer,
        connect_result=0,
        wait_result=True,
        socket_error=0,
        fail_at: str | None = None,
        invalid_close_result: bool = False,
    ) -> None:
        self.peer = peer
        self.connect_result = connect_result
        self.wait_result = wait_result
        self.socket_error_result = socket_error
        self.fail_at = fail_at
        self.invalid_close_result = invalid_close_result
        self.events: list[object] = []
        self.close_calls = 0
        self.wait_entered: Event | None = None
        self.wait_release: Event | None = None

    def _step(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise KeyboardInterrupt(f"edge-secret:{name}:8.8.8.8")

    def set_nonblocking(self):
        self._step("set_nonblocking")

    def connect_once(self, sockaddr):
        self._step("connect_once")
        self.events.append(("sockaddr", sockaddr))
        return self.connect_result

    def wait_writable(self, *, max_wait_ns: int):
        self._step("wait_writable")
        self.events.append(("max_wait_ns", max_wait_ns))
        if self.wait_entered is not None:
            self.wait_entered.set()
        if self.wait_release is not None and not self.wait_release.wait(5):
            raise AssertionError("test wait release was not signalled")
        return self.wait_result

    def socket_error(self):
        self._step("socket_error")
        return self.socket_error_result

    def peername(self):
        self._step("peername")
        return self.peer

    def close_once(self):
        self.close_calls += 1
        self.events.append("close_once")
        if self.fail_at == "close_once":
            raise KeyboardInterrupt("edge-secret:close:8.8.8.8")
        if self.invalid_close_result:
            return False
        return None

    @property
    def closed(self) -> bool:
        return self.close_calls > 0


class _BlockingCloseEdge(_FakeEdge):
    """Test edge that holds the first close action open for a race."""

    def __init__(self) -> None:
        super().__init__(peer=("8.8.8.8", 443))
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
            raise AssertionError("test close release was not signalled")
        with self._close_state_lock:
            self._close_committed = True

    @property
    def closed(self) -> bool:
        with self._close_state_lock:
            return self._close_committed


@contextmanager
def _interrupt_close_before_action(function):
    target = function.__code__
    previous = sys.gettrace()
    fired = [False]

    def interrupt(frame, event, arg):
        del arg
        if not fired[0] and event == "line" and frame.f_code is target:
            fired[0] = True
            sys.settrace(previous)
            raise KeyboardInterrupt("edge-secret:pre-close-action")
        return interrupt

    sys.settrace(interrupt)
    try:
        yield fired
    finally:
        sys.settrace(previous)


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
            raise KeyboardInterrupt("edge-secret:factory-return")
        return interrupt

    sys.settrace(interrupt)
    try:
        yield fired
    finally:
        sys.settrace(previous)


class _Factory:
    def __init__(self, edge: _FakeEdge) -> None:
        self.edge = edge
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
        publish(self.edge)
        if not publication_is_exact(self.edge):
            raise AssertionError("test numeric edge publication did not commit")


def _connect(resolution, edge: _FakeEdge, *, ledger=None):
    selected_ledger = (
        numeric_connect._new_numeric_connect_ledger_for_test()
        if ledger is None
        else ledger
    )
    factory = _Factory(edge)
    owner = numeric_connect._connect_selected_numeric_with_test_edge(
        resolution,
        max_wait_ns=WAIT_NS,
        ledger=selected_ledger,
        edge_factory=factory,
        _authority=numeric_connect._TEST_EDGE_AUTHORITY,
    )
    return owner, selected_ledger, factory


class NumericConnectSuccessTest(unittest.TestCase):
    def test_ipv4_immediate_success_uses_only_selected_numeric_candidate(self):
        publication, resolution = _resolution(
            _record4("8.8.8.8"),
            _record4("1.1.1.1"),
        )
        edge = _FakeEdge(peer=("1.1.1.1", 443))
        poison = AssertionError("real DNS/network forbidden")
        try:
            with (
                mock.patch("socket.getaddrinfo", side_effect=poison),
                mock.patch("socket.create_connection", side_effect=poison),
                mock.patch("socket.socket", side_effect=poison),
            ):
                owner, ledger, factory = _connect(resolution, edge)
            self.assertEqual(
                factory.calls,
                [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)],
            )
            self.assertEqual(
                edge.events,
                [
                    "set_nonblocking",
                    "connect_once",
                    ("sockaddr", ("1.1.1.1", 443)),
                    "socket_error",
                    "peername",
                ],
            )
            self.assertEqual(ledger._state_for_test(resolution), "connected")
            proof = owner.proof
            proof.validate_binding(resolution)
            self.assertEqual(proof.family.value, "ipv4")
            self.assertEqual(proof.socket_family, "AF_INET")
            self.assertEqual(proof.connect_initiation_count, 1)
            self.assertEqual(
                proof.proof_digest,
                digest256(
                    "NumericConnectionProof",
                    numeric_connect.NUMERIC_CONNECTION_PROOF_SCHEMA_VERSION,
                    numeric_connect._proof_payload(proof),
                ),
            )
            metadata = proof.safe_metadata()
            self.assertTrue(metadata["peer_exactly_matched"])
            self.assertNotIn("address", metadata)
            self.assertNotIn("1.1.1.1", repr(proof))
            owner.close()
            owner.close()
            self.assertTrue(owner.closed)
            self.assertEqual(edge.close_calls, 1)
        finally:
            _close(publication)

    def test_ipv6_pending_success_polls_once_with_exact_bound(self):
        publication, resolution = _resolution(
            _record6("2001:4860:4860::8888")
        )
        edge = _FakeEdge(
            peer=("2001:4860:4860::8888", 443, 0, 0),
            connect_result=errno.EINPROGRESS,
        )
        try:
            owner, ledger, factory = _connect(resolution, edge)
            self.assertEqual(
                factory.calls,
                [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)],
            )
            self.assertEqual(edge.events.count("connect_once"), 1)
            self.assertEqual(edge.events.count("wait_writable"), 1)
            self.assertIn(("max_wait_ns", WAIT_NS), edge.events)
            self.assertEqual(
                edge.events[-2:],
                ["socket_error", "peername"],
            )
            self.assertEqual(ledger._state_for_test(resolution), "connected")
            owner.proof.validate_binding(resolution)
            self.assertEqual(owner.proof.family.value, "ipv6")
            owner.close()
            self.assertEqual(edge.close_calls, 1)
        finally:
            _close(publication)

    def test_owner_pre_action_close_interrupt_retains_recovery_owner(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        edge = _FakeEdge(peer=("8.8.8.8", 443))
        owner = None
        try:
            owner, _, _ = _connect(resolution, edge)
            with _interrupt_close_before_action(
                _FakeEdge.close_once
            ) as fired, self.assertRaises(EndpointPolicyError) as raised:
                owner.close()
            self.assertTrue(fired[0])
            _assert_safe(self, raised.exception)
            self.assertEqual(edge.close_calls, 0)
            self.assertFalse(owner.closed)

            owner.close()
            self.assertTrue(owner.closed)
            self.assertEqual(edge.close_calls, 1)
        finally:
            if owner is not None and not owner.closed:
                owner.close()
            _close(publication)

    def test_pending_pre_action_close_interrupt_retains_same_fd_owner(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        edge = _FakeEdge(
            peer=("8.8.8.8", 443),
            connect_result=errno.EINPROGRESS,
            wait_result=False,
        )
        pending = None
        try:
            pending, _, _ = _connect(resolution, edge)
            self.assertIs(
                type(pending),
                numeric_connect._PendingNumericConnection,
            )
            with _interrupt_close_before_action(
                _FakeEdge.close_once
            ) as fired, self.assertRaises(EndpointPolicyError) as raised:
                pending.close()
            self.assertTrue(fired[0])
            _assert_safe(self, raised.exception)
            self.assertEqual(edge.close_calls, 0)
            self.assertFalse(pending.closed)

            pending.close()
            self.assertTrue(pending.closed)
            self.assertEqual(edge.close_calls, 1)
        finally:
            if pending is not None and not pending.closed:
                pending.close()
            _close(publication)

    def test_all_pending_results_share_the_single_poll_path(self):
        for pending in sorted(numeric_connect._PENDING_CONNECT_ERRORS):
            with self.subTest(pending=pending):
                publication, resolution = _resolution(_record4("8.8.8.8"))
                edge = _FakeEdge(
                    peer=("8.8.8.8", 443),
                    connect_result=pending,
                )
                try:
                    owner, _, _ = _connect(resolution, edge)
                    self.assertEqual(edge.events.count("connect_once"), 1)
                    self.assertEqual(edge.events.count("wait_writable"), 1)
                    owner.close()
                finally:
                    _close(publication)

    def test_pending_capability_continues_same_fd_across_wait_slices(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        edge = _FakeEdge(
            peer=("8.8.8.8", 443),
            connect_result=errno.EINPROGRESS,
            wait_result=False,
        )
        try:
            pending, ledger, _ = _connect(resolution, edge)
            self.assertIs(type(pending), numeric_connect._PendingNumericConnection)
            self.assertEqual(ledger._state_for_test(resolution), "connecting")
            with self.assertRaises(TypeError):
                copy.copy(pending)
            with self.assertRaises(TypeError):
                pickle.dumps(pending)
            with self.assertRaises(AttributeError):
                pending._state = "transferred"
            metadata = pending.safe_metadata()
            self.assertEqual(metadata["state"], "pending")
            self.assertTrue(metadata["same_socket_continuation"])
            self.assertNotIn("8.8.8.8", repr(metadata))
            self.assertIs(
                pending.poll(max_wait_ns=WAIT_NS),
                pending,
            )
            self.assertEqual(edge.events.count("connect_once"), 1)
            self.assertEqual(edge.events.count("wait_writable"), 2)
            self.assertEqual(edge.events.count("socket_error"), 0)
            self.assertEqual(edge.close_calls, 0)

            edge.wait_result = True
            owner = pending.poll(max_wait_ns=WAIT_NS)
            self.assertIs(type(owner), numeric_connect._NumericConnectionOwner)
            self.assertEqual(edge.events.count("connect_once"), 1)
            self.assertEqual(edge.events.count("wait_writable"), 3)
            self.assertEqual(edge.events.count("socket_error"), 1)
            self.assertEqual(edge.events.count("peername"), 1)
            self.assertEqual(ledger._state_for_test(resolution), "connected")
            self.assertIs(pending.poll(max_wait_ns=WAIT_NS), owner)
            self.assertEqual(edge.events.count("wait_writable"), 3)
            owner.close()
            self.assertTrue(pending.closed)
            self.assertEqual(edge.close_calls, 1)
        finally:
            _close(publication)

    def test_proof_is_factory_only_immutable_and_nonserializable(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        edge = _FakeEdge(peer=("8.8.8.8", 443))
        try:
            owner, _, _ = _connect(resolution, edge)
            proof = owner.proof
            self.assertIs(copy.copy(proof), proof)
            self.assertIs(copy.deepcopy(proof), proof)
            with self.assertRaises(AttributeError):
                proof.family = "ipv6"
            with self.assertRaises(TypeError):
                pickle.dumps(proof)
            with self.assertRaises(TypeError):
                numeric_connect._NumericConnectionProof(
                    resolution=resolution,
                    selected=resolution.selected,
                    peer=resolution.selected,
                    socket_family="AF_INET",
                )
            with self.assertRaises(TypeError):
                copy.copy(owner)
            with self.assertRaises(TypeError):
                pickle.dumps(owner)
            with self.assertRaises(AttributeError):
                owner.proof = proof
            original_family = proof.family
            object.__setattr__(proof, "family", "ipv6")
            with self.assertRaises(EndpointPolicyError) as raised:
                proof.validate_integrity()
            _assert_safe(self, raised.exception)
            object.__setattr__(proof, "family", original_family)
            proof.validate_integrity()
            owner.close()
        finally:
            _close(publication)


class NumericConnectFailureTest(unittest.TestCase):
    def rejected(self, resolution, edge: _FakeEdge, *, ledger=None):
        selected_ledger = (
            numeric_connect._new_numeric_connect_ledger_for_test()
            if ledger is None
            else ledger
        )
        factory = _Factory(edge)
        with self.assertRaises(EndpointPolicyError) as raised:
            numeric_connect._connect_selected_numeric_with_test_edge(
                resolution,
                max_wait_ns=WAIT_NS,
                ledger=selected_ledger,
                edge_factory=factory,
                _authority=numeric_connect._TEST_EDGE_AUTHORITY,
            )
        _assert_safe(self, raised.exception)
        return selected_ledger, factory

    def test_partial_acquisition_and_baseexception_matrix_closes_once(self):
        cases = (
            _FakeEdge(peer=("8.8.8.8", 443), fail_at="set_nonblocking"),
            _FakeEdge(peer=("8.8.8.8", 443), fail_at="connect_once"),
            _FakeEdge(
                peer=("8.8.8.8", 443),
                connect_result=errno.EINPROGRESS,
                fail_at="wait_writable",
            ),
            _FakeEdge(peer=("8.8.8.8", 443), fail_at="socket_error"),
            _FakeEdge(peer=("8.8.8.8", 443), fail_at="peername"),
        )
        for edge in cases:
            with self.subTest(fail_at=edge.fail_at):
                publication, resolution = _resolution(_record4("8.8.8.8"))
                try:
                    ledger, _ = self.rejected(resolution, edge)
                    self.assertEqual(edge.events.count("connect_once") <= 1, True)
                    self.assertEqual(edge.close_calls, 1)
                    self.assertEqual(ledger._state_for_test(resolution), "failed")
                finally:
                    _close(publication)

    def test_connect_error_and_so_error_never_retry(self):
        edges = (
            _FakeEdge(peer=("8.8.8.8", 443), connect_result=errno.ECONNREFUSED),
            _FakeEdge(peer=("8.8.8.8", 443), socket_error=errno.ECONNRESET),
            _FakeEdge(peer=("8.8.8.8", 443), connect_result=True),
            _FakeEdge(peer=("8.8.8.8", 443), socket_error=False),
        )
        for edge in edges:
            with self.subTest(edge=edge):
                publication, resolution = _resolution(_record4("8.8.8.8"))
                try:
                    self.rejected(resolution, edge)
                    self.assertEqual(edge.events.count("connect_once"), 1)
                    self.assertLessEqual(edge.events.count("wait_writable"), 1)
                    self.assertEqual(edge.close_calls, 1)
                finally:
                    _close(publication)

    def test_upstream_cancel_or_timeout_closes_pending_socket_once(self):
        for upstream_terminal in ("cancelled", "timed_out"):
            with self.subTest(upstream_terminal=upstream_terminal):
                publication, resolution = _resolution(_record4("8.8.8.8"))
                ledger = numeric_connect._new_numeric_connect_ledger_for_test()
                edge = _FakeEdge(
                    peer=("8.8.8.8", 443),
                    connect_result=errno.EINPROGRESS,
                    wait_result=False,
                )
                try:
                    pending, _, _ = _connect(
                        resolution,
                        edge,
                        ledger=ledger,
                    )
                    self.assertIs(
                        type(pending),
                        numeric_connect._PendingNumericConnection,
                    )
                    pending.close()
                    pending.close()
                    self.assertTrue(pending.closed)
                    self.assertEqual(edge.events.count("connect_once"), 1)
                    self.assertEqual(edge.events.count("wait_writable"), 1)
                    self.assertEqual(edge.close_calls, 1)
                    self.assertEqual(
                        ledger._state_for_test(resolution),
                        "failed",
                    )
                    with self.assertRaises(EndpointPolicyError) as raised:
                        pending.poll(max_wait_ns=WAIT_NS)
                    _assert_safe(self, raised.exception)
                    self.assertEqual(edge.events.count("connect_once"), 1)
                    self.assertEqual(edge.events.count("wait_writable"), 1)
                finally:
                    _close(publication)

    def test_peer_mismatch_is_rebinding_failure_with_no_candidate_fallback(self):
        publication, resolution = _resolution(
            _record4("8.8.8.8"),
            _record4("1.1.1.1"),
        )
        ledger = numeric_connect._new_numeric_connect_ledger_for_test()
        first = _FakeEdge(peer=("8.8.8.8", 443))
        try:
            self.rejected(resolution, first, ledger=ledger)
            self.assertIn(("sockaddr", ("1.1.1.1", 443)), first.events)
            self.assertEqual(first.events.count("connect_once"), 1)
            self.assertEqual(first.close_calls, 1)

            fallback = _FakeEdge(peer=("1.1.1.1", 443))
            _, factory = self.rejected(resolution, fallback, ledger=ledger)
            self.assertEqual(factory.calls, [])
            self.assertEqual(fallback.events, [])
            self.assertEqual(fallback.close_calls, 0)
        finally:
            _close(publication)

    def test_malformed_mapped_and_scoped_peers_are_rejected(self):
        cases = (
            (_record4("8.8.8.8"), ("8.8.8.8", 443, 0, 0)),
            (_record4("8.8.8.8"), ["8.8.8.8", 443]),
            (
                _record6("2001:4860:4860::8888"),
                ("::ffff:8.8.8.8", 443, 0, 0),
            ),
            (
                _record6("2001:4860:4860::8888"),
                ("2001:4860:4860::8888", 443, 0, 1),
            ),
            (
                _record6("2001:4860:4860::8888"),
                ("2001:4860:4860::8888%en0", 443, 0, 0),
            ),
        )
        for record, peer in cases:
            with self.subTest(peer=peer):
                publication, resolution = _resolution(record)
                edge = _FakeEdge(peer=peer)
                try:
                    self.rejected(resolution, edge)
                    self.assertEqual(edge.close_calls, 1)
                finally:
                    _close(publication)

    def test_edge_contract_result_shapes_fail_closed(self):
        cases = (
            _FakeEdge(
                peer=("8.8.8.8", 443),
                connect_result=errno.EINPROGRESS,
                wait_result=1,
            ),
            _FakeEdge(peer="8.8.8.8:443"),
        )
        for edge in cases:
            with self.subTest(edge=edge):
                publication, resolution = _resolution(_record4("8.8.8.8"))
                try:
                    self.rejected(resolution, edge)
                    self.assertEqual(edge.close_calls, 1)
                finally:
                    _close(publication)

    def test_owner_close_failure_is_sanitized_and_not_replayed(self):
        edges = (
            _FakeEdge(peer=("8.8.8.8", 443), fail_at="close_once"),
            _FakeEdge(
                peer=("8.8.8.8", 443),
                invalid_close_result=True,
            ),
        )
        for edge in edges:
            with self.subTest(edge=edge):
                publication, resolution = _resolution(_record4("8.8.8.8"))
                try:
                    owner, _, _ = _connect(resolution, edge)
                    with self.assertRaises(EndpointPolicyError) as raised:
                        owner.close()
                    _assert_safe(self, raised.exception)
                    self.assertTrue(owner.closed)
                    owner.close()
                    self.assertEqual(edge.close_calls, 1)
                finally:
                    _close(publication)


class NumericConnectOneShotTest(unittest.TestCase):
    def test_duplicate_success_is_rejected_before_second_edge_acquisition(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        ledger = numeric_connect._new_numeric_connect_ledger_for_test()
        first = _FakeEdge(peer=("8.8.8.8", 443))
        second = _FakeEdge(peer=("8.8.8.8", 443))
        try:
            owner, _, _ = _connect(resolution, first, ledger=ledger)
            with self.assertRaises(EndpointPolicyError) as raised:
                numeric_connect._connect_selected_numeric_with_test_edge(
                    resolution,
                    max_wait_ns=WAIT_NS,
                    ledger=ledger,
                    edge_factory=_Factory(second),
                    _authority=numeric_connect._TEST_EDGE_AUTHORITY,
                )
            _assert_safe(self, raised.exception)
            self.assertEqual(second.events, [])
            self.assertEqual(second.close_calls, 0)
            self.assertEqual(first.events.count("connect_once"), 1)
            owner.close()
        finally:
            _close(publication)

    def test_concurrent_connect_has_one_winner_and_one_connect_initiation(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        ledger = numeric_connect._new_numeric_connect_ledger_for_test()
        start = Barrier(17)
        result_lock = Lock()
        owners = []
        errors = []
        edges = []

        def run() -> None:
            edge = _FakeEdge(peer=("8.8.8.8", 443))
            start.wait()
            try:
                owner, _, _ = _connect(resolution, edge, ledger=ledger)
            except BaseException as error:
                with result_lock:
                    errors.append(error)
            else:
                with result_lock:
                    owners.append(owner)
            finally:
                with result_lock:
                    edges.append(edge)

        threads = [Thread(target=run) for _ in range(16)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join()
        try:
            self.assertEqual(len(owners), 1)
            self.assertEqual(len(errors), 15)
            for error in errors:
                _assert_safe(self, error)
            self.assertEqual(
                sum(edge.events.count("connect_once") for edge in edges),
                1,
            )
            self.assertEqual(ledger._state_for_test(resolution), "connected")

            close_start = Barrier(17)

            def close() -> None:
                close_start.wait()
                owners[0].close()

            closers = [Thread(target=close) for _ in range(16)]
            for thread in closers:
                thread.start()
            close_start.wait()
            for thread in closers:
                thread.join()
            self.assertEqual(sum(edge.close_calls for edge in edges), 1)
        finally:
            if owners and not owners[0].closed:
                owners[0].close()
            _close(publication)

    def test_concurrent_construction_slot_close_invokes_edge_once(self):
        slot = numeric_connect._new_numeric_construction_slot_for_transport(
            _authority=numeric_connect._NUMERIC_TRANSPORT_AUTHORITY,
        )
        edge = _BlockingCloseEdge()
        slot.publish_edge(edge)
        start = Barrier(3)
        errors: list[BaseException] = []
        errors_lock = Lock()

        def close() -> None:
            start.wait()
            try:
                slot.close_once()
            except BaseException as error:
                with errors_lock:
                    errors.append(error)

        threads = [Thread(target=close) for _ in range(2)]
        for thread in threads:
            thread.start()
        start.wait()
        self.assertTrue(edge.close_entered.wait(5))
        # The first action is deliberately blocked.  A competing cleanup has
        # been released by the same barrier but must not reach the edge.
        duplicate_entered = edge.duplicate_close_entered.wait(0.25)
        edge.allow_close.set()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())

        self.assertFalse(duplicate_entered)
        self.assertEqual(errors, [])
        self.assertEqual(edge.close_calls, 1)
        self.assertTrue(edge.closed)
        self.assertTrue(slot.is_terminal())

    def test_concurrent_pending_polls_share_one_completion_and_never_reconnect(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        edge = _FakeEdge(
            peer=("8.8.8.8", 443),
            connect_result=errno.EINPROGRESS,
            wait_result=False,
        )
        pending = None
        owners = []
        errors = []
        result_lock = Lock()
        try:
            pending, _, _ = _connect(resolution, edge)
            self.assertIs(type(pending), numeric_connect._PendingNumericConnection)
            edge.wait_result = True
            edge.wait_entered = Event()
            edge.wait_release = Event()

            def poll() -> None:
                try:
                    result = pending.poll(max_wait_ns=WAIT_NS)
                except BaseException as error:
                    with result_lock:
                        errors.append(error)
                else:
                    with result_lock:
                        owners.append(result)

            threads = [Thread(target=poll) for _ in range(2)]
            for thread in threads:
                thread.start()
            self.assertTrue(edge.wait_entered.wait(5))
            edge.wait_release.set()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
            self.assertEqual(len(owners), 2)
            self.assertIs(owners[0], owners[1])
            self.assertIs(type(owners[0]), numeric_connect._NumericConnectionOwner)
            self.assertEqual(edge.events.count("connect_once"), 1)
            self.assertEqual(edge.events.count("wait_writable"), 2)
            owners[0].close()
            self.assertEqual(edge.close_calls, 1)
        finally:
            if pending is not None and not pending.closed:
                pending.close()
            _close(publication)

    def test_concurrent_poll_then_close_closes_transferred_owner_once(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        edge = _FakeEdge(
            peer=("8.8.8.8", 443),
            connect_result=errno.EINPROGRESS,
            wait_result=False,
        )
        pending = None
        results = []
        errors = []
        try:
            pending, _, _ = _connect(resolution, edge)
            self.assertIs(type(pending), numeric_connect._PendingNumericConnection)
            edge.wait_result = True
            edge.wait_entered = Event()
            edge.wait_release = Event()

            def poll() -> None:
                try:
                    results.append(pending.poll(max_wait_ns=WAIT_NS))
                except BaseException as error:
                    errors.append(error)

            def close() -> None:
                try:
                    pending.close()
                except BaseException as error:
                    errors.append(error)

            poller = Thread(target=poll)
            closer = Thread(target=close)
            poller.start()
            self.assertTrue(edge.wait_entered.wait(5))
            closer.start()
            edge.wait_release.set()
            poller.join()
            closer.join()
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertIs(type(results[0]), numeric_connect._NumericConnectionOwner)
            self.assertTrue(results[0].closed)
            self.assertTrue(pending.closed)
            self.assertEqual(edge.events.count("connect_once"), 1)
            self.assertEqual(edge.events.count("wait_writable"), 2)
            self.assertEqual(edge.close_calls, 1)
        finally:
            if pending is not None and not pending.closed:
                pending.close()
            _close(publication)


class NumericConnectBoundaryTest(unittest.TestCase):
    def test_wait_and_private_authority_are_checked_before_acquisition(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        try:
            for value in (
                0,
                True,
                numeric_connect.MAX_NUMERIC_CONNECT_WAIT_NS + 1,
            ):
                factory = _Factory(_FakeEdge(peer=("8.8.8.8", 443)))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    numeric_connect._connect_selected_numeric_with_test_edge(
                        resolution,
                        max_wait_ns=value,
                        ledger=numeric_connect._new_numeric_connect_ledger_for_test(),
                        edge_factory=factory,
                        _authority=numeric_connect._TEST_EDGE_AUTHORITY,
                    )
                self.assertEqual(factory.calls, [])
            with self.assertRaises(TypeError):
                numeric_connect._connect_selected_numeric_with_test_edge(
                    resolution,
                    max_wait_ns=WAIT_NS,
                    ledger=numeric_connect._new_numeric_connect_ledger_for_test(),
                    edge_factory=_Factory(_FakeEdge(peer=("8.8.8.8", 443))),
                )
            with self.assertRaises(TypeError):
                numeric_connect._NumericConnectLedger()
        finally:
            _close(publication)

    def test_factory_baseexception_is_sanitized_without_replay(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        ledger = numeric_connect._new_numeric_connect_ledger_for_test()
        calls = []

        def fail(
            family: int,
            socket_type: int,
            protocol: int,
            publish,
            publication_is_exact,
        ) -> None:
            del publish, publication_is_exact
            calls.append((family, socket_type, protocol))
            raise KeyboardInterrupt("edge-secret:8.8.8.8")

        try:
            with self.assertRaises(EndpointPolicyError) as raised:
                numeric_connect._connect_selected_numeric_with_test_edge(
                    resolution,
                    max_wait_ns=WAIT_NS,
                    ledger=ledger,
                    edge_factory=fail,
                    _authority=numeric_connect._TEST_EDGE_AUTHORITY,
                )
            _assert_safe(self, raised.exception)
            self.assertEqual(len(calls), 1)
            self.assertEqual(ledger._state_for_test(resolution), "failed")

            second = _Factory(_FakeEdge(peer=("8.8.8.8", 443)))
            with self.assertRaises(EndpointPolicyError):
                numeric_connect._connect_selected_numeric_with_test_edge(
                    resolution,
                    max_wait_ns=WAIT_NS,
                    ledger=ledger,
                    edge_factory=second,
                    _authority=numeric_connect._TEST_EDGE_AUTHORITY,
                )
            self.assertEqual(second.calls, [])
        finally:
            _close(publication)

    def test_factory_return_interrupt_uses_one_published_edge_without_reconnect(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        ledger = numeric_connect._new_numeric_connect_ledger_for_test()
        edge = _FakeEdge(peer=("8.8.8.8", 443))
        factory = _Factory(edge)
        owner = None
        try:
            with _interrupt_return(_Factory.__call__) as fired:
                owner = numeric_connect._connect_selected_numeric_with_test_edge(
                    resolution,
                    max_wait_ns=WAIT_NS,
                    ledger=ledger,
                    edge_factory=factory,
                    _authority=numeric_connect._TEST_EDGE_AUTHORITY,
                )

            self.assertTrue(fired[0])
            self.assertIs(type(owner), numeric_connect._NumericConnectionOwner)
            self.assertEqual(len(factory.calls), 1)
            self.assertEqual(edge.events.count("connect_once"), 1)

            second = _Factory(_FakeEdge(peer=("8.8.8.8", 443)))
            with self.assertRaises(EndpointPolicyError) as raised:
                numeric_connect._connect_selected_numeric_with_test_edge(
                    resolution,
                    max_wait_ns=WAIT_NS,
                    ledger=ledger,
                    edge_factory=second,
                    _authority=numeric_connect._TEST_EDGE_AUTHORITY,
                )
            _assert_safe(self, raised.exception)
            self.assertEqual(second.calls, [])
            self.assertEqual(edge.events.count("connect_once"), 1)
        finally:
            if owner is not None and not owner.closed:
                owner.close()
            _close(publication)

    def test_factory_cannot_return_the_published_raw_resource(self):
        publication, resolution = _resolution(_record4("8.8.8.8"))
        ledger = numeric_connect._new_numeric_connect_ledger_for_test()
        edge = _FakeEdge(peer=("8.8.8.8", 443))
        calls = []

        def illegal_factory(
            family: int,
            socket_type: int,
            protocol: int,
            publish,
            publication_is_exact,
        ):
            calls.append((family, socket_type, protocol))
            publish(edge)
            self.assertTrue(publication_is_exact(edge))
            return edge

        try:
            with self.assertRaises(EndpointPolicyError) as raised:
                numeric_connect._connect_selected_numeric_with_test_edge(
                    resolution,
                    max_wait_ns=WAIT_NS,
                    ledger=ledger,
                    edge_factory=illegal_factory,
                    _authority=numeric_connect._TEST_EDGE_AUTHORITY,
                )
            _assert_safe(self, raised.exception)
            self.assertEqual(len(calls), 1)
            self.assertEqual(edge.events.count("connect_once"), 0)
            self.assertEqual(edge.close_calls, 1)
            self.assertEqual(ledger._state_for_test(resolution), "failed")
        finally:
            _close(publication)

    def test_production_shape_is_explicitly_unwired_and_accepts_no_injection(self):
        import inspect

        parameters = inspect.signature(
            numeric_connect._connect_selected_numeric_unwired
        ).parameters
        self.assertEqual(tuple(parameters), ("resolution", "max_wait_ns"))
        self.assertFalse(numeric_connect.PRODUCTION_GATE_INTEGRATION_AVAILABLE)
        self.assertFalse(
            numeric_connect.OPAQUE_NUMERIC_SOCKET_OWNER_AVAILABLE
        )
        for forbidden in ("socket", "proxy", "context", "edge", "resolver"):
            self.assertNotIn(forbidden, parameters)

        publication, resolution = _resolution(_record4("8.8.8.8"))
        try:
            with mock.patch.object(
                numeric_connect.socket,
                "socket",
                side_effect=KeyboardInterrupt("edge-secret:8.8.8.8"),
            ) as socket_factory:
                with self.assertRaises(EndpointPolicyError) as raised:
                    numeric_connect._connect_selected_numeric_unwired(
                        resolution,
                        max_wait_ns=WAIT_NS,
                    )
            _assert_safe(self, raised.exception)
            socket_factory.assert_not_called()
        finally:
            _close(publication)

    def test_module_import_has_no_dns_network_or_proxy_action(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_numeric_connect.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden_attributes = {
            "getaddrinfo",
            "create_connection",
            "gethostbyname",
            "gethostbyname_ex",
        }
        self.assertFalse(
            [
                node.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and node.attr in forbidden_attributes
            ]
        )
        attributes = [
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
        ]
        self.assertNotIn("candidates", attributes)
        self.assertEqual(attributes.count("connect_once"), 1)
        top_level_socket_calls = []
        for statement in tree.body:
            for node in ast.walk(statement):
                if isinstance(statement, (ast.FunctionDef, ast.ClassDef)):
                    break
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "socket"
                    and node.func.attr == "socket"
                ):
                    top_level_socket_calls.append(node)
        self.assertEqual(top_level_socket_calls, [])
        self.assertEqual(numeric_connect.__all__, ())


if __name__ == "__main__":
    unittest.main()
