"""Offline acceptance for the numeric-owner to TLS-owner atomic adapter."""
from __future__ import annotations

import ast
import ctypes
import errno
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from threading import Thread
import time
import unittest

from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_numeric_owner as numeric_owner
from snapquiz.transport import _darwin_tls_owner as tls_owner
from snapquiz.transport import _darwin_transport_adapter as adapter
from snapquiz.transport import _exact_tls as exact_tls
from snapquiz.transport import _exact_transport as exact_transport
from snapquiz.transport import _numeric_connect as numeric_connect

from tests.test_w09_darwin_numeric_owner import (
    MODE_IMMEDIATE,
    _resolution,
)
from tests.test_w09_address_policy import _record4
from tests.test_w09_exact_transport import (
    _clean_tls_environment,
    _poison_network,
    _prepared,
)


ROOT = Path(__file__).resolve().parents[1]
NUMERIC_SOURCE = (
    ROOT / "snapquiz" / "transport" / "native" / "darwin_numeric_owner.c"
)
TLS_SOURCE = (
    ROOT / "snapquiz" / "transport" / "native" / "darwin_tls_owner.c"
)
TRANSFER_HEADER = (
    ROOT / "snapquiz" / "transport" / "native" / "darwin_owner_transfer.h"
)
NUMERIC_FIXTURE = (
    Path(__file__).with_name("fixtures") / "darwin_numeric_owner_fixture.c"
)
TLS_FIXTURE = (
    Path(__file__).with_name("fixtures")
    / "darwin_transport_adapter_fixture.c"
)

MODE_SUCCESS = 0
MODE_ADOPT_NOT_ISSUED = 1
MODE_ADOPT_AMBIGUOUS_EMPTY = 2
MODE_BLOCK_ADOPT = 3
MODE_WAIT_AMBIGUOUS = 4
MODE_ADOPT_AMBIGUOUS_WITH_TLS = 5
MODE_CLOSE_TLS_NOT_ISSUED_ONCE = 6
MODE_REENTER_NUMERIC_CLOSE = 7
MODE_BLOCK_WRITE = 8


def _assert_safe(test: unittest.TestCase, error: BaseException) -> None:
    test.assertIsInstance(error, EndpointPolicyError)
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertIsNone(error.__context__)
    rendered = str(error)
    test.assertNotIn("31337", rendered)
    test.assertNotIn("8.8.8.8", rendered)
    test.assertNotIn("token", rendered.lower())


@unittest.skipUnless(sys.platform == "darwin", "Darwin transfer adapter")
class DarwinTransportAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not Path("/usr/bin/clang").is_file():
            raise unittest.SkipTest("Apple clang is required")
        cls._build_root = tempfile.TemporaryDirectory(
            prefix="snapquiz-native-transfer-",
            dir="/tmp",
        )
        cls._paths: dict[str, str] = {}
        link_mode = "-dynamiclib" if sys.platform == "darwin" else "-shared"
        for name, source in (
            ("numeric_owner", NUMERIC_SOURCE),
            ("tls_owner", TLS_SOURCE),
            ("numeric_fixture", NUMERIC_FIXTURE),
            ("tls_fixture", TLS_FIXTURE),
        ):
            output = Path(cls._build_root.name) / f"{name}.dylib"
            subprocess.run(
                [
                    "/usr/bin/clang",
                    "-std=c11",
                    "-fPIC",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    link_mode,
                    str(source),
                    "-o",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            cls._paths[name] = str(output.resolve())

        cls.numeric_fixture = ctypes.CDLL(cls._paths["numeric_fixture"])
        cls.numeric_fixture.sq_numeric_fixture_reset.argtypes = (
            ctypes.c_int32,
        )
        cls.numeric_fixture.sq_numeric_fixture_reset.restype = None
        cls.numeric_fixture.sq_numeric_fixture_vtable.argtypes = ()
        cls.numeric_fixture.sq_numeric_fixture_vtable.restype = ctypes.c_void_p
        for name in (
            "create_calls",
            "set_nonblocking_calls",
            "connect_calls",
            "poll_calls",
            "socket_error_calls",
            "peername_calls",
            "close_calls",
        ):
            function = getattr(
                cls.numeric_fixture,
                f"sq_numeric_fixture_{name}",
            )
            function.argtypes = ()
            function.restype = ctypes.c_uint32

        cls.tls_fixture = ctypes.CDLL(cls._paths["tls_fixture"])
        cls.tls_fixture.sq_transport_fixture_reset.argtypes = (
            ctypes.c_int32,
        )
        cls.tls_fixture.sq_transport_fixture_reset.restype = None
        cls.tls_fixture.sq_transport_fixture_tls_vtable.argtypes = ()
        cls.tls_fixture.sq_transport_fixture_tls_vtable.restype = (
            ctypes.POINTER(tls_owner._CTlsVtable)
        )
        cls.tls_fixture.sq_transport_fixture_adopt_vtable.argtypes = ()
        cls.tls_fixture.sq_transport_fixture_adopt_vtable.restype = (
            ctypes.c_void_p
        )
        cls.tls_fixture.sq_transport_fixture_context.argtypes = ()
        cls.tls_fixture.sq_transport_fixture_context.restype = ctypes.c_void_p
        for name in (
            "create_pair_calls",
            "adopt_calls",
            "handshake_calls",
            "wait_calls",
            "write_calls",
            "read_calls",
            "close_tls_calls",
            "close_raw_vtable_calls",
            "adopt_entered",
            "write_entered",
            "write_saw_original",
            "last_wait_direction",
        ):
            function = getattr(
                cls.tls_fixture,
                f"sq_transport_fixture_{name}",
            )
            function.argtypes = ()
            function.restype = ctypes.c_uint32
        cls.tls_fixture.sq_transport_fixture_last_wait_ns.argtypes = ()
        cls.tls_fixture.sq_transport_fixture_last_wait_ns.restype = (
            ctypes.c_uint64
        )
        cls.tls_fixture.sq_transport_fixture_release_adopt.argtypes = ()
        cls.tls_fixture.sq_transport_fixture_release_adopt.restype = None
        cls.tls_fixture.sq_transport_fixture_release_write.argtypes = ()
        cls.tls_fixture.sq_transport_fixture_release_write.restype = None
        cls.tls_fixture.sq_transport_fixture_set_reenter_probe.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        cls.tls_fixture.sq_transport_fixture_set_reenter_probe.restype = None
        cls.tls_fixture.sq_transport_fixture_reenter_result.argtypes = ()
        cls.tls_fixture.sq_transport_fixture_reenter_result.restype = (
            ctypes.c_int32
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._build_root.cleanup()

    def setUp(self) -> None:
        self.numeric_fixture.sq_numeric_fixture_reset(MODE_IMMEDIATE)
        self.tls_fixture.sq_transport_fixture_reset(MODE_SUCCESS)

    def _numeric_count(self, name: str) -> int:
        return int(
            getattr(self.numeric_fixture, f"sq_numeric_fixture_{name}")()
        )

    def _tls_count(self, name: str) -> int:
        return int(
            getattr(self.tls_fixture, f"sq_transport_fixture_{name}")()
        )

    def _factory(self):
        tls_vtable = self.tls_fixture.sq_transport_fixture_tls_vtable().contents
        return adapter._new_local_darwin_transport_factory(
            numeric_library_path=self._paths["numeric_owner"],
            numeric_syscall_vtable=(
                self.numeric_fixture.sq_numeric_fixture_vtable()
            ),
            tls_library_path=self._paths["tls_owner"],
            tls_vtable=tls_vtable,
            adopt_vtable=(
                self.tls_fixture.sq_transport_fixture_adopt_vtable()
            ),
            context=self.tls_fixture.sq_transport_fixture_context(),
            keepalive=(self.numeric_fixture, self.tls_fixture, tls_vtable),
            _authority=adapter._LOCAL_TEST_AUTHORITY,
        )

    def _connected_raw(self):
        selected_context = _resolution(_record4("8.8.8.8"))
        resolution = selected_context.__enter__()
        selected = resolution.selected
        published: list[object] = []
        factory = self._factory()

        def publish(value: object) -> None:
            published.append(value)

        factory.publish_numeric_edge(
            selected,
            int(socket.AF_INET),
            int(socket.SOCK_STREAM),
            int(socket.IPPROTO_TCP),
            publish,
            lambda value: len(published) == 1 and published[0] is value,
        )
        raw = published[0]
        raw.set_nonblocking()
        self.assertEqual(raw.connect_once(selected.numeric_sockaddr), 0)
        self.assertEqual(raw.socket_error(), 0)
        self.assertEqual(raw.peername(), selected.numeric_sockaddr)
        return selected_context, factory, raw

    def _publish_tls(self, factory, raw):
        policy = exact_tls._new_exact_tls_policy(hostname="open.bigmodel.cn")
        published: list[object] = []
        factory.publish_tls_edge(
            raw,
            policy,
            "open.bigmodel.cn",
            published.append,
            lambda value: len(published) == 1 and published[0] is value,
        )
        return published[0]

    def test_import_is_inert_and_all_production_flags_remain_false(self):
        tree = ast.parse(Path(adapter.__file__).read_text(encoding="utf-8"))
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertNotIn("CDLL", calls)
        self.assertTrue(
            adapter.DARWIN_NATIVE_TRANSFER_ADAPTER_FOUNDATION_AVAILABLE
        )
        self.assertFalse(
            adapter.DARWIN_NATIVE_TRANSFER_ADAPTER_PRODUCTION_AVAILABLE
        )
        self.assertFalse(numeric_connect.OPAQUE_NUMERIC_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(tls_owner.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(exact_transport.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(exact_transport.PRODUCTION_APP_INTEGRATION_AVAILABLE)

    def test_shared_transfer_contract_is_versioned_and_size_checked(self):
        header = TRANSFER_HEADER.read_text(encoding="utf-8")
        self.assertIn("#ifndef SNAPQUIZ_DARWIN_OWNER_TRANSFER_H", header)
        self.assertIn("SQ_OWNER_TRANSFER_CONTRACT_ABI", header)
        self.assertIn("SQ_OWNER_TRANSFER_CONTRACT_VERSION 1u", header)
        self.assertIn("_Static_assert", header)
        self.assertIn('#include "darwin_owner_transfer.h"', NUMERIC_SOURCE.read_text())
        self.assertIn('#include "darwin_owner_transfer.h"', TLS_SOURCE.read_text())
        factory = self._factory()
        self.assertEqual(
            factory._numeric_factory._bindings.transfer_contract_size(),
            32,
        )
        self.assertEqual(factory._tls_bindings.transfer_contract_size(), 32)

    def test_atomic_transfer_uses_same_raw_and_only_tls_closes_it(self):
        context, factory, raw = self._connected_raw()
        try:
            self.assertTrue(raw.safe_metadata()["nonblocking_attested"])
            self.assertFalse(raw.safe_metadata()["raw_descriptor_exposed"])
            tls = self._publish_tls(factory, raw)
            self.assertTrue(raw.closed)
            self.assertEqual(raw.safe_metadata()["adapter_state"], "transferred")
            self.assertEqual(self._numeric_count("close_calls"), 0)
            self.assertEqual(self._tls_count("adopt_calls"), 1)
            self.assertEqual(self._tls_count("create_pair_calls"), 0)

            self.assertEqual(tls.handshake_step(), "want_read")
            self.assertTrue(tls.wait_ready(direction="want_read", max_wait_ns=1234))
            self.assertEqual(tls.handshake_step(), "complete")
            self.assertEqual(tls.negotiated_values(), ("http/1.1", "TLSv1.3"))
            request = bytearray(b"synthetic")
            writable = memoryview(request)
            view = writable.toreadonly()
            writable.release()
            try:
                self.assertEqual(tls.write_once(view), ("written", 9))
            finally:
                view.release()
            self.assertEqual(tls.read_once(16 * 1024)[0], "data")
            tls.close_once()
            tls.close_once()
            self.assertTrue(tls.closed)
            self.assertEqual(self._numeric_count("close_calls"), 1)
            self.assertEqual(self._tls_count("close_tls_calls"), 1)
            self.assertEqual(self._tls_count("close_raw_vtable_calls"), 0)
        finally:
            context.__exit__(None, None, None)

    def test_not_issued_adoption_rolls_back_numeric_close_authority(self):
        self.tls_fixture.sq_transport_fixture_reset(MODE_ADOPT_NOT_ISSUED)
        context, factory, raw = self._connected_raw()
        try:
            with self.assertRaises(EndpointPolicyError) as raised:
                self._publish_tls(factory, raw)
            _assert_safe(self, raised.exception)
            self.assertFalse(raw.closed)
            self.assertEqual(raw.safe_metadata()["adapter_state"], "numeric")
            self.assertEqual(self._tls_count("adopt_calls"), 1)
            raw.close_once()
            self.assertTrue(raw.closed)
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            context.__exit__(None, None, None)

    def test_ambiguous_adoption_keeps_destination_recovery_tombstone(self):
        self.tls_fixture.sq_transport_fixture_reset(MODE_ADOPT_AMBIGUOUS_EMPTY)
        context, factory, raw = self._connected_raw()
        published: list[object] = []
        try:
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
            with self.assertRaises(EndpointPolicyError) as raised:
                factory.publish_tls_edge(
                    raw,
                    policy,
                    "open.bigmodel.cn",
                    published.append,
                    lambda value: published == [value],
                )
            _assert_safe(self, raised.exception)
            self.assertEqual(len(published), 1)
            self.assertTrue(raw.closed)
            self.assertEqual(
                raw.safe_metadata()["adapter_state"],
                "transfer_uncertain",
            )
            tls = published[0]
            with self.assertRaises(EndpointPolicyError):
                tls.handshake_step()
            with self.assertRaises(EndpointPolicyError):
                tls.close_once()
            raw.close_once()
            self.assertEqual(self._numeric_count("close_calls"), 1)
            self.assertEqual(self._tls_count("close_raw_vtable_calls"), 0)
        finally:
            context.__exit__(None, None, None)

    def test_ambiguous_adoption_with_tls_closes_each_resource_once(self):
        self.tls_fixture.sq_transport_fixture_reset(
            MODE_ADOPT_AMBIGUOUS_WITH_TLS
        )
        context, factory, raw = self._connected_raw()
        published: list[object] = []
        try:
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
            with self.assertRaises(EndpointPolicyError) as raised:
                factory.publish_tls_edge(
                    raw,
                    policy,
                    "open.bigmodel.cn",
                    published.append,
                    lambda value: published == [value],
                )
            _assert_safe(self, raised.exception)
            self.assertEqual(len(published), 1)
            self.assertTrue(raw.closed)
            edge = published[0]
            for _ in range(2):
                with self.assertRaises(EndpointPolicyError):
                    edge.close_once()
            self.assertEqual(self._tls_count("close_tls_calls"), 1)
            self.assertEqual(self._numeric_count("close_calls"), 1)
            self.assertEqual(self._tls_count("close_raw_vtable_calls"), 0)
        finally:
            context.__exit__(None, None, None)

    def test_close_retries_only_a_definitely_not_issued_tls_action(self):
        self.tls_fixture.sq_transport_fixture_reset(
            MODE_CLOSE_TLS_NOT_ISSUED_ONCE
        )
        context, factory, raw = self._connected_raw()
        try:
            edge = self._publish_tls(factory, raw)
            edge.close_once()
            self.assertTrue(edge.closed)
            self.assertEqual(self._tls_count("close_tls_calls"), 2)
            self.assertEqual(self._numeric_count("close_calls"), 1)
            self.assertEqual(self._tls_count("close_raw_vtable_calls"), 0)
        finally:
            context.__exit__(None, None, None)

    def test_preclosed_numeric_owner_cannot_be_adopted(self):
        context, factory, raw = self._connected_raw()
        try:
            raw.close_once()
            with self.assertRaises(EndpointPolicyError) as raised:
                self._publish_tls(factory, raw)
            _assert_safe(self, raised.exception)
            self.assertEqual(self._tls_count("adopt_calls"), 0)
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            context.__exit__(None, None, None)

    def test_adopt_callback_reentrant_close_is_rejected_as_busy(self):
        self.tls_fixture.sq_transport_fixture_reset(
            MODE_REENTER_NUMERIC_CLOSE
        )
        context, factory, raw = self._connected_raw()
        token = numeric_owner._NativeToken(raw._owner._token)
        outcome = numeric_owner._NativeOutcome()
        close_pointer = ctypes.cast(
            raw._owner._bindings.close,
            ctypes.c_void_p,
        )
        self.tls_fixture.sq_transport_fixture_set_reenter_probe(
            close_pointer,
            ctypes.cast(ctypes.byref(token), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(outcome), ctypes.c_void_p),
        )
        try:
            edge = self._publish_tls(factory, raw)
            self.assertEqual(
                int(self.tls_fixture.sq_transport_fixture_reenter_result()),
                0,
            )
            self.assertEqual(outcome.publication_state, 2)
            self.assertEqual(outcome.status, numeric_owner._STATUS_BUSY)
            self.assertEqual(self._numeric_count("close_calls"), 0)
            edge.close_once()
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            context.__exit__(None, None, None)

    def test_replay_and_tampered_token_never_reach_adopt_twice(self):
        context, factory, raw = self._connected_raw()
        try:
            original = raw._owner._token
            tampered = bytes((original[0] ^ 1,)) + original[1:]
            object.__setattr__(raw._owner, "_token", tampered)
            with self.assertRaises(EndpointPolicyError):
                self._publish_tls(factory, raw)
            self.assertEqual(self._tls_count("adopt_calls"), 0)
            object.__setattr__(raw._owner, "_token", original)

            tls = self._publish_tls(factory, raw)
            self.assertEqual(self._tls_count("adopt_calls"), 1)
            with self.assertRaises(EndpointPolicyError):
                self._publish_tls(factory, raw)
            self.assertEqual(self._tls_count("adopt_calls"), 1)
            tls.close_once()
        finally:
            context.__exit__(None, None, None)

    def test_close_racing_native_transfer_cannot_claim_raw_close(self):
        self.tls_fixture.sq_transport_fixture_reset(MODE_BLOCK_ADOPT)
        context, factory, raw = self._connected_raw()
        published: list[object] = []
        failures: list[BaseException] = []
        policy = exact_tls._new_exact_tls_policy(hostname="open.bigmodel.cn")

        def transfer() -> None:
            try:
                factory.publish_tls_edge(
                    raw,
                    policy,
                    "open.bigmodel.cn",
                    published.append,
                    lambda value: published == [value],
                )
            except BaseException as error:
                failures.append(error)

        thread = Thread(target=transfer)
        thread.start()
        deadline = time.monotonic() + 5
        while (
            not self.tls_fixture.sq_transport_fixture_adopt_entered()
            and time.monotonic() < deadline
        ):
            time.sleep(0.001)
        self.assertEqual(
            self.tls_fixture.sq_transport_fixture_adopt_entered(),
            1,
        )
        token = numeric_owner._NativeToken(raw._owner._token)
        outcome = numeric_owner._NativeOutcome()
        status = raw._owner._bindings.close(
            ctypes.byref(token),
            ctypes.byref(outcome),
        )
        self.assertEqual(status, 0)
        self.assertEqual(outcome.publication_state, 2)
        self.assertEqual(outcome.status, numeric_owner._STATUS_BUSY)
        self.assertEqual(self._numeric_count("close_calls"), 0)

        self.tls_fixture.sq_transport_fixture_release_adopt()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(published), 1)
        published[0].close_once()
        self.assertEqual(self._numeric_count("close_calls"), 1)
        context.__exit__(None, None, None)

    def test_tls_operation_return_gap_replays_same_native_operation_id(self):
        context, factory, raw = self._connected_raw()
        tls = self._publish_tls(factory, raw)
        original = tls._owner._publication._bindings.handshake
        fired = [False]

        def interrupt(*arguments):
            status = original(*arguments)
            if not fired[0]:
                fired[0] = True
                raise KeyboardInterrupt("synthetic return gap")
            return status

        tls._owner._publication._bindings.handshake = interrupt
        try:
            with self.assertRaises(EndpointPolicyError) as raised:
                tls.handshake_step()
            _assert_safe(self, raised.exception)
            self.assertTrue(fired[0])
            self.assertEqual(self._tls_count("handshake_calls"), 1)
        finally:
            tls._owner._publication._bindings.handshake = original
            tls.close_once()
            context.__exit__(None, None, None)

    def test_invalid_io_bounds_do_not_consume_native_operations(self):
        context, factory, raw = self._connected_raw()
        edge = self._publish_tls(factory, raw)
        empty = memoryview(b"")
        stepped = memoryview(b"abcd")[::2]
        writable = memoryview(bytearray(b"abcd"))
        try:
            for value in (empty, stepped, writable):
                with self.assertRaises(ValueError):
                    edge.write_once(value)
            for maximum in (False, 0, tls_owner.MAX_NATIVE_TLS_READ_BYTES + 1):
                with self.assertRaises(ValueError):
                    edge.read_once(maximum)
            metadata = edge.safe_metadata()["native_owner"]
            self.assertEqual(metadata["write_calls"], 0)
            self.assertEqual(metadata["read_calls"], 0)
            self.assertIsNone(metadata["last_write_operation_id"])
            self.assertIsNone(metadata["last_read_operation_id"])
        finally:
            empty.release()
            stepped.release()
            writable.release()
            edge.close_once()
            context.__exit__(None, None, None)

    def test_readonly_write_uses_one_native_snapshot_during_alias_mutation(self):
        self.tls_fixture.sq_transport_fixture_reset(MODE_BLOCK_WRITE)
        context, factory, raw = self._connected_raw()
        edge = self._publish_tls(factory, raw)
        backing = bytearray(b"original")
        writable = memoryview(backing)
        view = writable.toreadonly()
        writable.release()
        results: list[tuple[str, int]] = []
        failures: list[BaseException] = []

        def write() -> None:
            try:
                results.append(edge.write_once(view))
            except BaseException as error:
                failures.append(error)

        thread = Thread(target=write)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while (
                not self.tls_fixture.sq_transport_fixture_write_entered()
                and time.monotonic() < deadline
            ):
                time.sleep(0.001)
            self.assertEqual(
                self.tls_fixture.sq_transport_fixture_write_entered(),
                1,
            )
            backing[:] = b"mutated!"
        finally:
            self.tls_fixture.sq_transport_fixture_release_write()
            thread.join(5)
            view.release()
        try:
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(results, [("written", 8)])
            self.assertEqual(
                self.tls_fixture.sq_transport_fixture_write_saw_original(),
                1,
            )
        finally:
            edge.close_once()
            context.__exit__(None, None, None)

    def test_transfer_return_gap_recovers_committed_native_publication(self):
        context, factory, raw = self._connected_raw()
        original = raw._owner._bindings.transfer
        fired = [False]

        def interrupt(*arguments):
            status = original(*arguments)
            if not fired[0]:
                fired[0] = True
                raise KeyboardInterrupt("synthetic transfer return gap")
            return status

        raw._owner._bindings.transfer = interrupt
        try:
            edge = self._publish_tls(factory, raw)
            self.assertTrue(fired[0])
            self.assertTrue(raw.closed)
            self.assertEqual(raw.safe_metadata()["adapter_state"], "transferred")
            self.assertEqual(self._tls_count("adopt_calls"), 1)
            edge.close_once()
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            raw._owner._bindings.transfer = original
            context.__exit__(None, None, None)

    def test_tls_publication_recovery_return_gap_keeps_the_preheld_owner(self):
        context, factory, raw = self._connected_raw()
        original = tls_owner._OpaqueTlsPublication._recover_transferred
        fired = [False]

        def interrupt(publication, *arguments, **keywords):
            result = original(publication, *arguments, **keywords)
            if not fired[0]:
                fired[0] = True
                raise KeyboardInterrupt("synthetic publication return gap")
            return result

        tls_owner._OpaqueTlsPublication._recover_transferred = interrupt
        try:
            edge = self._publish_tls(factory, raw)
            self.assertTrue(fired[0])
            self.assertEqual(self._tls_count("adopt_calls"), 1)
            edge.close_once()
            self.assertTrue(edge.closed)
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            tls_owner._OpaqueTlsPublication._recover_transferred = original
            context.__exit__(None, None, None)

    def test_numeric_retire_return_gap_is_idempotently_recovered(self):
        context, factory, raw = self._connected_raw()
        edge = self._publish_tls(factory, raw)
        original = raw._owner._bindings.retire
        fired = [False]

        def interrupt(*arguments):
            status = original(*arguments)
            if not fired[0]:
                fired[0] = True
                raise KeyboardInterrupt("synthetic retire return gap")
            return status

        raw._owner._bindings.retire = interrupt
        try:
            edge.close_once()
            self.assertTrue(fired[0])
            self.assertTrue(edge.closed)
            self.assertEqual(raw._transfer_state, "retired")
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            raw._owner._bindings.retire = original
            context.__exit__(None, None, None)

    def test_repeated_retire_failure_never_reports_terminal(self):
        context, factory, raw = self._connected_raw()
        edge = self._publish_tls(factory, raw)
        original = raw._owner._bindings.retire

        def interrupt(*arguments):
            del arguments
            raise KeyboardInterrupt("synthetic retire pre-call interruption")

        raw._owner._bindings.retire = interrupt
        try:
            with self.assertRaises(EndpointPolicyError) as raised:
                edge.close_once()
            _assert_safe(self, raised.exception)
            self.assertFalse(edge.closed)
            self.assertEqual(raw._transfer_state, "transferred")
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            raw._owner._bindings.retire = original
        try:
            edge.close_once()
            self.assertTrue(edge.closed)
            self.assertEqual(raw._transfer_state, "retired")
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            context.__exit__(None, None, None)

    def test_ambiguous_transfer_cleanup_does_not_exhaust_numeric_slots(self):
        self.tls_fixture.sq_transport_fixture_reset(
            MODE_ADOPT_AMBIGUOUS_EMPTY
        )
        context = _resolution(_record4("8.8.8.8"))
        resolution = context.__enter__()
        selected = resolution.selected
        factory = self._factory()
        try:
            for _ in range(70):
                numeric_published: list[object] = []
                factory.publish_numeric_edge(
                    selected,
                    int(socket.AF_INET),
                    int(socket.SOCK_STREAM),
                    int(socket.IPPROTO_TCP),
                    numeric_published.append,
                    lambda value: numeric_published == [value],
                )
                raw = numeric_published[0]
                raw.set_nonblocking()
                self.assertEqual(raw.connect_once(selected.numeric_sockaddr), 0)
                self.assertEqual(raw.socket_error(), 0)
                self.assertEqual(raw.peername(), selected.numeric_sockaddr)
                published: list[object] = []
                policy = exact_tls._new_exact_tls_policy(
                    hostname="open.bigmodel.cn"
                )
                with self.assertRaises(EndpointPolicyError):
                    factory.publish_tls_edge(
                        raw,
                        policy,
                        "open.bigmodel.cn",
                        published.append,
                        lambda value: published == [value],
                    )
                self.assertEqual(len(published), 1)
                with self.assertRaises(EndpointPolicyError):
                    published[0].close_once()
                self.assertEqual(raw._transfer_state, "retired")
        finally:
            context.__exit__(None, None, None)

    def test_transfer_context_deinit_claim_is_atomic_and_busy_in_flight(self):
        source = TLS_SOURCE.read_text(encoding="utf-8")
        deinit = source.split(
            "int32_t sq_tls_numeric_transfer_context_deinit", 1
        )[1].split("int32_t sq_tls_create_publish", 1)[0]
        self.assertIn("atomic_compare_exchange_strong_explicit", deinit)
        self.assertIn("SQ_TRANSFER_CONTEXT_DEINITIALIZING", deinit)
        self.assertNotIn("memset(transfer, 0", deinit)

        self.tls_fixture.sq_transport_fixture_reset(MODE_BLOCK_ADOPT)
        context, factory, raw = self._connected_raw()
        publication = tls_owner._new_publication_for_test(
            factory._tls_bindings,
            _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
        )
        policy = exact_tls._new_exact_tls_policy(hostname="open.bigmodel.cn")
        transfer = adapter._NativeTlsTransferContext(
            bindings=factory._tls_bindings,
            publication=publication,
            tls_vtable=factory._tls_vtable,
            adopt_vtable=factory._adopt_vtable,
            context=factory._context,
            hostname="open.bigmodel.cn",
            policy_digest=policy.policy_digest,
            _authority=adapter._TRANSFER_CONTEXT_AUTHORITY,
        )
        failures: list[BaseException] = []

        def adopt() -> None:
            try:
                raw._transfer_to_tls(transfer)
            except BaseException as error:
                failures.append(error)

        thread = Thread(target=adopt)
        thread.start()
        deadline = time.monotonic() + 5
        while (
            not self.tls_fixture.sq_transport_fixture_adopt_entered()
            and time.monotonic() < deadline
        ):
            time.sleep(0.001)
        try:
            self.assertEqual(
                self.tls_fixture.sq_transport_fixture_adopt_entered(),
                1,
            )
            self.assertEqual(
                transfer._bindings.transfer_context_deinit(transfer.pointer),
                errno.EBUSY,
            )
        finally:
            self.tls_fixture.sq_transport_fixture_release_adopt()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        transfer.deinitialize()
        publication._recover_transferred(
            hostname="open.bigmodel.cn",
            policy_digest=policy.policy_digest,
            keepalive=factory._keepalive,
        )
        owner = publication.owner()
        owner.close_once()
        owner.release()
        publication.deinitialize()
        raw._retire_transfer_tombstone()
        context.__exit__(None, None, None)

    def test_adopt_finalization_has_no_fallible_second_publication_lock(self):
        source = TLS_SOURCE.read_text(encoding="utf-8")
        accept = source.split("int32_t sq_tls_accept_numeric_transfer", 1)[1]
        accept = accept.split(
            "int32_t sq_tls_numeric_transfer_context_deinit", 1
        )[0]
        after_adopt = accept.split(
            "call_result = transfer->adopt_vtable.adopt_raw", 1
        )[1]
        self.assertIn("sq_tls_publish_constructed_owner", after_adopt)
        self.assertNotIn("sq_tls_publication_lock(publication)", after_adopt)

    def test_native_bookkeeping_return_gaps_recover_without_resource_replay(self):
        context, factory, raw = self._connected_raw()
        bindings = factory._tls_bindings
        originals = {
            "transfer_context_deinit": bindings.transfer_context_deinit,
            "snapshot_token": bindings.snapshot_token,
            "release": bindings.release,
            "publication_deinit": bindings.publication_deinit,
        }
        fired = {name: False for name in originals}

        def interrupt_once(name):
            original = originals[name]

            def selected(*arguments):
                status = original(*arguments)
                if not fired[name]:
                    fired[name] = True
                    raise KeyboardInterrupt(f"synthetic {name} return gap")
                return status

            return selected

        for name in originals:
            setattr(bindings, name, interrupt_once(name))
        try:
            edge = self._publish_tls(factory, raw)
            edge.close_once()
            self.assertTrue(edge.closed)
            self.assertTrue(all(fired.values()))
            self.assertEqual(self._tls_count("adopt_calls"), 1)
            self.assertEqual(self._tls_count("close_tls_calls"), 1)
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            for name, original in originals.items():
                setattr(bindings, name, original)
            context.__exit__(None, None, None)

    def test_readiness_is_bounded_and_ambiguous_wait_poisons_owner(self):
        self.tls_fixture.sq_transport_fixture_reset(MODE_WAIT_AMBIGUOUS)
        context, factory, raw = self._connected_raw()
        edge = self._publish_tls(factory, raw)
        try:
            for direction, maximum in (
                ("invalid", 1),
                ("want_read", 0),
                ("want_read", tls_owner.MAX_NATIVE_TLS_WAIT_NS + 1),
            ):
                with self.assertRaises((ValueError, EndpointPolicyError)):
                    edge.wait_ready(
                        direction=direction,
                        max_wait_ns=maximum,
                    )
            self.assertEqual(self._tls_count("wait_calls"), 0)
            with self.assertRaises(EndpointPolicyError) as raised:
                edge.wait_ready(
                    direction="want_write",
                    max_wait_ns=tls_owner.MAX_NATIVE_TLS_WAIT_NS,
                )
            _assert_safe(self, raised.exception)
            metadata = edge.safe_metadata()["native_owner"]
            self.assertEqual(metadata["state"], "poisoned")
            self.assertEqual(metadata["wait_calls"], 1)
            self.assertEqual(metadata["last_wait_direction"], "want_write")
            self.assertEqual(
                metadata["last_max_wait_ns"],
                tls_owner.MAX_NATIVE_TLS_WAIT_NS,
            )
            edge.close_once()
            self.assertEqual(self._numeric_count("close_calls"), 1)
        finally:
            context.__exit__(None, None, None)

    def test_existing_exact_transport_contract_runs_end_to_end_offline(self):
        bundle = _prepared()
        factory = self._factory()
        with _clean_tls_environment(), _poison_network():
            response = adapter._send_exact_with_local_darwin_owners(
                bundle.prepared,
                factory=factory,
                _authority=adapter._LOCAL_TEST_AUTHORITY,
            )
        self.assertEqual(response.http_status, 200)
        self.assertEqual(response.body, b"ok")
        self.assertTrue(bundle.prepared.is_closed)
        self.assertEqual(self._numeric_count("create_calls"), 1)
        self.assertEqual(self._numeric_count("set_nonblocking_calls"), 1)
        self.assertEqual(self._numeric_count("connect_calls"), 1)
        self.assertEqual(self._numeric_count("close_calls"), 1)
        self.assertEqual(self._tls_count("adopt_calls"), 1)
        self.assertEqual(self._tls_count("create_pair_calls"), 0)
        self.assertEqual(self._tls_count("wait_calls"), 1)
        self.assertGreater(self._tls_count("write_calls"), 0)
        self.assertEqual(self._tls_count("close_tls_calls"), 1)
        self.assertEqual(self._tls_count("close_raw_vtable_calls"), 0)
        self.assertGreater(
            int(self.tls_fixture.sq_transport_fixture_last_wait_ns()),
            0,
        )
        self.assertEqual(
            int(self.tls_fixture.sq_transport_fixture_last_wait_direction()),
            1,
        )


if __name__ == "__main__":
    unittest.main()
