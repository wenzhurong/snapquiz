"""Darwin-local acceptance for the opaque numeric socket owner foundation."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import ctypes
import errno
from pathlib import Path
import pickle
import socket
import subprocess
import sys
import tempfile
from threading import Barrier, Lock, Thread
import unittest
from unittest import mock

from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport.address_policy import build_resolution_set
from snapquiz.transport import _darwin_numeric_owner as native_owner
from snapquiz.transport import _numeric_connect as numeric_connect

from tests.test_w09_address_policy import _close, _issue, _record4, _record6


OWNER_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "snapquiz"
    / "transport"
    / "native"
    / "darwin_numeric_owner.c"
)
FIXTURE_SOURCE = (
    Path(__file__).with_name("fixtures")
    / "darwin_numeric_owner_fixture.c"
)

MODE_IMMEDIATE = 0
MODE_PENDING_THEN_READY = 1
MODE_CONNECT_UNCERTAIN = 2
MODE_CLOSE_UNCERTAIN = 3
MODE_PEER_MISMATCH = 4
MODE_SOCKET_ERROR = 5
MODE_POLL_UNCERTAIN = 6
MODE_CREATE_FAILED = 7
MODE_CREATE_UNCERTAIN = 8
MODE_CLOSE_FAILED = 9
WAIT_NS = 12_345_678


def _assert_safe(test: unittest.TestCase, error: BaseException) -> None:
    test.assertIs(type(error), EndpointPolicyError)
    test.assertEqual(error.stage, "numeric_connect")
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertIsNone(error.__context__)
    test.assertTrue(error.__suppress_context__)
    rendered = str(error)
    test.assertNotIn("8.8.8.8", rendered)
    test.assertNotIn("31337", rendered)
    test.assertNotIn("token", rendered.lower())


@contextmanager
def _resolution(record):
    publication = _issue(record)
    _, _, attempt, _, _, receipt, _ = publication
    try:
        yield build_resolution_set(attempt, receipt)
    finally:
        _close(publication)


@contextmanager
def _selected(record):
    with _resolution(record) as resolution:
        yield resolution.selected


@unittest.skipUnless(sys.platform == "darwin", "Darwin numeric owner")
class DarwinNumericOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not Path("/usr/bin/clang").is_file():
            raise unittest.SkipTest("Apple clang is required")
        cls._build_root = tempfile.TemporaryDirectory(
            prefix="snapquiz-numeric-owner-build-",
            dir="/tmp",
        )
        owner_library = Path(cls._build_root.name) / "numeric-owner.dylib"
        fixture_library = Path(cls._build_root.name) / "numeric-fixture.dylib"
        for source, output in (
            (OWNER_SOURCE, owner_library),
            (FIXTURE_SOURCE, fixture_library),
        ):
            subprocess.run(
                [
                    "/usr/bin/clang",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Os",
                    "-dynamiclib",
                    str(source),
                    "-o",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        cls.owner_library = str(owner_library.resolve())
        cls.fixture = ctypes.CDLL(str(fixture_library.resolve()))
        cls.fixture.sq_numeric_fixture_reset.argtypes = (ctypes.c_int32,)
        cls.fixture.sq_numeric_fixture_reset.restype = None
        cls.fixture.sq_numeric_fixture_vtable.argtypes = ()
        cls.fixture.sq_numeric_fixture_vtable.restype = ctypes.c_void_p
        for name in (
            "create_calls",
            "set_nonblocking_calls",
            "connect_calls",
            "poll_calls",
            "socket_error_calls",
            "peername_calls",
            "close_calls",
        ):
            function = getattr(cls.fixture, f"sq_numeric_fixture_{name}")
            function.argtypes = ()
            function.restype = ctypes.c_uint32
        cls.fixture.sq_numeric_fixture_last_wait_ns.argtypes = ()
        cls.fixture.sq_numeric_fixture_last_wait_ns.restype = ctypes.c_uint64

    @classmethod
    def tearDownClass(cls) -> None:
        cls._build_root.cleanup()

    def _count(self, name: str) -> int:
        return int(getattr(self.fixture, f"sq_numeric_fixture_{name}")())

    def _factory(self, mode: int = MODE_IMMEDIATE):
        self.fixture.sq_numeric_fixture_reset(mode)
        return native_owner._new_local_darwin_numeric_owner_factory(
            native_library_path=self.owner_library,
            syscall_vtable=self.fixture.sq_numeric_fixture_vtable(),
            _authority=native_owner._LOCAL_TEST_AUTHORITY,
        )

    def _create(self, mode: int = MODE_IMMEDIATE, *, family=socket.AF_INET):
        factory = self._factory(mode)
        construction = factory.new_construction()
        result = native_owner._create_local_darwin_numeric_owner(
            construction,
            family=int(family),
            socket_type=int(socket.SOCK_STREAM),
            protocol=int(socket.IPPROTO_TCP),
            _authority=native_owner._LOCAL_TEST_AUTHORITY,
        )
        self.assertIsNone(result)
        return factory, construction, construction.owner()

    def test_foundation_is_injection_only_and_production_remains_closed(self):
        self.assertFalse(numeric_connect.PRODUCTION_GATE_INTEGRATION_AVAILABLE)
        self.assertFalse(numeric_connect.OPAQUE_NUMERIC_SOCKET_OWNER_AVAILABLE)
        self.assertEqual(
            native_owner.DARWIN_NUMERIC_OWNER_SCOPE,
            "darwin_opaque_numeric_owner_local_offline",
        )
        with self.assertRaises(TypeError):
            native_owner._new_local_darwin_numeric_owner_factory(
                native_library_path=self.owner_library,
                syscall_vtable=self.fixture.sq_numeric_fixture_vtable(),
            )

        with _resolution(_record4("8.8.8.8")) as resolution:
            poison = AssertionError("production/native owner must remain unwired")
            with mock.patch.object(ctypes, "CDLL", side_effect=poison):
                with self.assertRaises(EndpointPolicyError) as raised:
                    numeric_connect._connect_selected_numeric_unwired(
                        resolution,
                        max_wait_ns=WAIT_NS,
                    )
            _assert_safe(self, raised.exception)

    def test_ipv4_immediate_success_is_native_verified_and_descriptor_is_hidden(self):
        factory, construction, owner = self._create()
        del factory
        with _selected(_record4("8.8.8.8")) as selected:
            poison = AssertionError("real DNS/AF_INET socket use is forbidden")
            with (
                mock.patch("socket.getaddrinfo", side_effect=poison),
                mock.patch("socket.create_connection", side_effect=poison),
                mock.patch("socket.socket", side_effect=poison),
            ):
                self.assertEqual(owner.connect_once(selected), 0)
                self.assertEqual(owner.socket_error(), 0)
                self.assertEqual(owner.peername(), ("8.8.8.8", 443))
            metadata = owner.safe_metadata()
            self.assertEqual(metadata["state"], "connected")
            self.assertEqual(metadata["connect_initiation_count"], 1)
            self.assertTrue(metadata["peer_exactly_matched"])
            self.assertTrue(metadata["nonblocking_attested"])
            self.assertFalse(metadata["raw_descriptor_exposed"])
            self.assertFalse(metadata["production_available"])
            self.assertEqual(len(owner._token), 32)
            self.assertNotEqual(owner._token, (31337).to_bytes(32, "big"))
            self.assertNotIn("8.8.8.8", repr(owner))
            self.assertNotIn("31337", repr(owner))
            self.assertFalse(any("descriptor" in name for name in owner.__slots__))
            self.assertEqual(self._count("create_calls"), 1)
            self.assertEqual(self._count("set_nonblocking_calls"), 1)
            self.assertEqual(self._count("connect_calls"), 1)
            self.assertEqual(self._count("poll_calls"), 0)
            self.assertEqual(self._count("socket_error_calls"), 1)
            self.assertEqual(self._count("peername_calls"), 1)
            owner.close_once()
            owner.close_once()
            self.assertTrue(owner.closed)
            self.assertTrue(construction.is_terminal())
            self.assertEqual(self._count("close_calls"), 1)

    def test_ipv6_pending_uses_bounded_polls_and_one_connect(self):
        _, _, owner = self._create(
            MODE_PENDING_THEN_READY,
            family=socket.AF_INET6,
        )
        try:
            with _selected(_record6("2001:4860:4860::8888")) as selected:
                self.assertEqual(owner.connect_once(selected), errno.EINPROGRESS)
                self.assertFalse(owner.poll(max_wait_ns=WAIT_NS))
                self.assertTrue(owner.poll(max_wait_ns=WAIT_NS))
                self.assertEqual(
                    owner.peername(),
                    ("2001:4860:4860::8888", 443, 0, 0),
                )
                self.assertEqual(self._count("connect_calls"), 1)
                self.assertEqual(self._count("set_nonblocking_calls"), 1)
                self.assertEqual(self._count("poll_calls"), 2)
                self.assertEqual(
                    int(self.fixture.sq_numeric_fixture_last_wait_ns()),
                    WAIT_NS,
                )
                self.assertEqual(self._count("socket_error_calls"), 1)
                self.assertEqual(self._count("peername_calls"), 1)
        finally:
            owner.close_once()
        self.assertEqual(self._count("close_calls"), 1)

    def test_constructor_return_event_recovers_published_token_without_recreate(self):
        factory = self._factory()
        construction = factory.new_construction()
        target = native_owner._create_local_darwin_numeric_owner.__code__
        previous = sys.gettrace()
        interrupted = False

        def interrupt(frame, event, argument):
            nonlocal interrupted
            if frame.f_code is target and event == "return" and not interrupted:
                interrupted = True
                self.assertIsNone(argument)
                raise KeyboardInterrupt("synthetic create return event")
            return interrupt

        try:
            sys.settrace(interrupt)
            with self.assertRaises(KeyboardInterrupt):
                native_owner._create_local_darwin_numeric_owner(
                    construction,
                    family=int(socket.AF_INET),
                    socket_type=int(socket.SOCK_STREAM),
                    protocol=int(socket.IPPROTO_TCP),
                    _authority=native_owner._LOCAL_TEST_AUTHORITY,
                )
        finally:
            sys.settrace(previous)
        self.assertTrue(interrupted)
        self.assertEqual(self._count("create_calls"), 1)
        self.assertTrue(
            construction.safe_metadata()["native_create_publication_committed"]
        )
        owner = construction.owner()
        construction.close_once()
        self.assertTrue(owner.closed)
        self.assertEqual(self._count("close_calls"), 1)
        with self.assertRaises(ValueError):
            native_owner._create_local_darwin_numeric_owner(
                construction,
                family=int(socket.AF_INET),
                socket_type=int(socket.SOCK_STREAM),
                protocol=int(socket.IPPROTO_TCP),
                _authority=native_owner._LOCAL_TEST_AUTHORITY,
            )
        self.assertEqual(self._count("create_calls"), 1)

    def test_double_connect_never_reaches_injected_syscall_twice(self):
        _, _, owner = self._create()
        try:
            with _selected(_record4("8.8.8.8")) as selected:
                self.assertEqual(owner.connect_once(selected), 0)
                with self.assertRaises(EndpointPolicyError) as raised:
                    owner.connect_once(selected)
                _assert_safe(self, raised.exception)
                self.assertEqual(self._count("connect_calls"), 1)
        finally:
            owner.close_once()

    def test_ambiguous_connect_is_not_replayed_and_can_be_closed_once(self):
        _, _, owner = self._create(MODE_CONNECT_UNCERTAIN)
        with _selected(_record4("8.8.8.8")) as selected:
            with self.assertRaises(EndpointPolicyError) as first:
                owner.connect_once(selected)
            _assert_safe(self, first.exception)
            self.assertEqual(owner.safe_metadata()["state"], "connect_uncertain")
            with self.assertRaises(EndpointPolicyError) as second:
                owner.connect_once(selected)
            _assert_safe(self, second.exception)
            self.assertEqual(self._count("connect_calls"), 1)
        owner.close_once()
        owner.close_once()
        self.assertEqual(self._count("close_calls"), 1)

    def test_ambiguous_and_failed_close_are_each_claimed_once(self):
        for mode in (MODE_CLOSE_UNCERTAIN, MODE_CLOSE_FAILED):
            with self.subTest(mode=mode):
                _, construction, owner = self._create(mode)
                with _selected(_record4("8.8.8.8")) as selected:
                    self.assertEqual(owner.connect_once(selected), 0)
                for _ in range(2):
                    with self.assertRaises(EndpointPolicyError) as raised:
                        owner.close_once()
                    _assert_safe(self, raised.exception)
                self.assertEqual(owner.safe_metadata()["state"], "close_uncertain")
                self.assertEqual(self._count("close_calls"), 1)
                self.assertFalse(owner.closed)
                self.assertFalse(construction.is_terminal())

    def test_tampered_cross_owner_and_stale_tokens_fail_without_os_action(self):
        factory, _, first = self._create()
        first_token = first._token
        second_construction = factory.new_construction()
        native_owner._create_local_darwin_numeric_owner(
            second_construction,
            family=int(socket.AF_INET),
            socket_type=int(socket.SOCK_STREAM),
            protocol=int(socket.IPPROTO_TCP),
            _authority=native_owner._LOCAL_TEST_AUTHORITY,
        )
        second = second_construction.owner()
        second_token = second._token
        self.assertEqual(len(first_token), 32)
        self.assertEqual(len(second_token), 32)
        self.assertNotEqual(first_token, second_token)

        tampered = bytes((first_token[0] ^ 1,)) + first_token[1:]
        for foreign in (tampered, second_token):
            object.__setattr__(first, "_token", foreign)
            with self.assertRaises(EndpointPolicyError) as raised:
                first.safe_metadata()
            _assert_safe(self, raised.exception)
        object.__setattr__(first, "_token", first_token)
        self.assertEqual(self._count("close_calls"), 0)

        first.close_once()
        first._retire_for_test()
        stale = native_owner._DarwinOpaqueNumericSocketOwner(
            bindings=factory._bindings,
            token=first_token,
            family=int(socket.AF_INET),
            _authority=native_owner._OWNER_AUTHORITY,
        )
        with self.assertRaises(EndpointPolicyError) as raised:
            stale.safe_metadata()
        _assert_safe(self, raised.exception)
        self.assertEqual(self._count("close_calls"), 1)
        second.close_once()
        self.assertEqual(self._count("close_calls"), 2)

    def test_peer_or_so_error_failure_remains_owned_for_single_cleanup(self):
        for mode in (MODE_PEER_MISMATCH, MODE_SOCKET_ERROR):
            with self.subTest(mode=mode):
                _, _, owner = self._create(mode)
                with _selected(_record4("8.8.8.8")) as selected:
                    with self.assertRaises(EndpointPolicyError) as raised:
                        owner.connect_once(selected)
                    _assert_safe(self, raised.exception)
                self.assertEqual(owner.safe_metadata()["state"], "failed")
                self.assertEqual(self._count("connect_calls"), 1)
                self.assertEqual(self._count("socket_error_calls"), 1)
                expected_peer_calls = 1 if mode == MODE_PEER_MISMATCH else 0
                self.assertEqual(
                    self._count("peername_calls"),
                    expected_peer_calls,
                )
                owner.close_once()
                owner.close_once()
                self.assertEqual(self._count("close_calls"), 1)

    def test_poll_uncertainty_and_invalid_wait_never_reconnect(self):
        _, _, owner = self._create(MODE_POLL_UNCERTAIN)
        with _selected(_record4("8.8.8.8")) as selected:
            self.assertEqual(owner.connect_once(selected), errno.EINPROGRESS)
            for value in (0, True, native_owner.DARWIN_NUMERIC_OWNER_MAX_WAIT_NS + 1):
                with self.subTest(value=value), self.assertRaises(
                    (TypeError, ValueError)
                ):
                    owner.poll(max_wait_ns=value)
            self.assertEqual(self._count("poll_calls"), 0)
            with self.assertRaises(EndpointPolicyError) as raised:
                owner.poll(max_wait_ns=WAIT_NS)
            _assert_safe(self, raised.exception)
            self.assertEqual(owner.safe_metadata()["state"], "poll_uncertain")
            with self.assertRaises(EndpointPolicyError):
                owner.poll(max_wait_ns=WAIT_NS)
        self.assertEqual(self._count("connect_calls"), 1)
        self.assertEqual(self._count("poll_calls"), 1)
        owner.close_once()
        self.assertEqual(self._count("close_calls"), 1)

    def test_known_and_uncertain_create_outcomes_retain_exact_cleanup_state(self):
        factory = self._factory(MODE_CREATE_FAILED)
        failed = factory.new_construction()
        with self.assertRaises(EndpointPolicyError) as raised:
            native_owner._create_local_darwin_numeric_owner(
                failed,
                family=int(socket.AF_INET),
                socket_type=int(socket.SOCK_STREAM),
                protocol=int(socket.IPPROTO_TCP),
                _authority=native_owner._LOCAL_TEST_AUTHORITY,
            )
        _assert_safe(self, raised.exception)
        self.assertTrue(failed.is_terminal())
        self.assertFalse(failed.safe_metadata()["opaque_token_present"])
        failed.close_once()
        self.assertEqual(self._count("create_calls"), 1)
        self.assertEqual(self._count("close_calls"), 0)

        uncertain_factory = self._factory(MODE_CREATE_UNCERTAIN)
        uncertain = uncertain_factory.new_construction()
        with self.assertRaises(EndpointPolicyError) as raised:
            native_owner._create_local_darwin_numeric_owner(
                uncertain,
                family=int(socket.AF_INET),
                socket_type=int(socket.SOCK_STREAM),
                protocol=int(socket.IPPROTO_TCP),
                _authority=native_owner._LOCAL_TEST_AUTHORITY,
            )
        _assert_safe(self, raised.exception)
        self.assertTrue(uncertain.safe_metadata()["opaque_token_present"])
        owner = uncertain.owner()
        owner.close_once()
        self.assertTrue(owner.closed)
        self.assertEqual(self._count("create_calls"), 1)
        self.assertEqual(self._count("close_calls"), 1)

    def test_concurrent_close_claim_invokes_native_close_once(self):
        _, _, owner = self._create()
        start = Barrier(17)
        errors: list[BaseException] = []
        error_lock = Lock()

        def close() -> None:
            start.wait()
            try:
                owner.close_once()
            except BaseException as error:
                with error_lock:
                    errors.append(error)

        threads = [Thread(target=close) for _ in range(16)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(owner.closed)
        self.assertEqual(self._count("close_calls"), 1)

    def test_owner_is_immutable_nonserializable_and_metadata_is_content_free(self):
        _, _, owner = self._create()
        self.assertEqual(ctypes.sizeof(native_owner._NativeToken), 32)
        with self.assertRaises(TypeError):
            copy.copy(owner)
        with self.assertRaises(TypeError):
            copy.deepcopy(owner)
        with self.assertRaises(TypeError):
            pickle.dumps(owner)
        with self.assertRaises(AttributeError):
            owner._token = b"x" * 32
        metadata = owner.safe_metadata()
        rendered = repr(metadata)
        self.assertNotIn(str(owner._token.hex()), rendered)
        self.assertNotIn("31337", rendered)
        owner.close_once()


if __name__ == "__main__":
    unittest.main()
