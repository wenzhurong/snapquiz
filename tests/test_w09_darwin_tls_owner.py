"""Offline tests for the W09 opaque native TLS-pair owner foundation."""
from __future__ import annotations

import ast
import copy
import ctypes
import errno
import importlib
from pathlib import Path
import pickle
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time
import unittest
from unittest.mock import patch

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_tls_owner as tls_owner
from snapquiz.transport import _exact_transport as exact_transport


HOSTNAME = "open.bigmodel.cn"
POLICY_DIGEST = Digest256("8" * 64)
SOURCE = (
    Path(__file__).resolve().parents[1]
    / "snapquiz"
    / "transport"
    / "native"
    / "darwin_tls_owner.c"
)


def _assert_safe(test: unittest.TestCase, error: EndpointPolicyError) -> None:
    test.assertEqual(error.stage, "darwin_tls_owner")
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertTrue(error.__suppress_context__)


class _FakeTlsVtable:
    """Non-network fake state invoked only through the compiled C vtable."""

    RAW_HANDLE = 0x1201
    TLS_HANDLE = 0x1202

    def __init__(self) -> None:
        self.create_result = tls_owner._CALL_COMMITTED
        self.raw_handle = self.RAW_HANDLE
        self.tls_handle = self.TLS_HANDLE
        self.create_calls = 0
        self.created_hostname = b""
        self.created_alpn = b""
        self.create_reentry = None
        self.handshake_plan: list[tuple[int, int]] = [
            (tls_owner._CALL_COMMITTED, tls_owner._IO_COMPLETE)
        ]
        self.handshake_calls = 0
        self.write_plan: list[tuple[int, int, int]] = []
        self.write_calls = 0
        self.writes: list[bytes] = []
        self.read_plan: list[tuple[int, int, bytes]] = []
        self.read_calls = 0
        self.negotiated_result = tls_owner._CALL_COMMITTED
        self.negotiated_alpn = b"http/1.1"
        self.negotiated_version = b"TLSv1.3"
        self.negotiated_calls = 0
        self.tls_close_plan: list[tuple[int, bool]] = []
        self.raw_close_plan: list[tuple[int, bool]] = []
        self.tls_close_calls = 0
        self.raw_close_calls = 0
        self.tls_closed = False
        self.raw_closed = False
        self.observe_tls_result = tls_owner._CALL_COMMITTED
        self.observe_raw_result = tls_owner._CALL_COMMITTED
        self.tls_close_entered: Event | None = None
        self.tls_close_continue: Event | None = None

        self._create_callback = tls_owner._CreatePairCallback(
            self._create_pair
        )
        self._handshake_callback = tls_owner._HandshakeCallback(
            self._handshake
        )
        self._write_callback = tls_owner._WriteCallback(self._write)
        self._read_callback = tls_owner._ReadCallback(self._read)
        self._negotiated_callback = tls_owner._NegotiatedCallback(
            self._negotiated
        )
        self._close_tls_callback = tls_owner._CloseCallback(self._close_tls)
        self._close_raw_callback = tls_owner._CloseCallback(self._close_raw)
        self._tls_closed_callback = tls_owner._ObserveClosedCallback(
            self._tls_is_closed
        )
        self._raw_closed_callback = tls_owner._ObserveClosedCallback(
            self._raw_is_closed
        )
        self.vtable = tls_owner._CTlsVtable(
            tls_owner._VTABLE_ABI,
            ctypes.sizeof(tls_owner._CTlsVtable),
            tls_owner._VTABLE_VERSION,
            0,
            self._create_callback,
            self._handshake_callback,
            self._write_callback,
            self._read_callback,
            self._negotiated_callback,
            self._close_tls_callback,
            self._close_raw_callback,
            self._tls_closed_callback,
            self._raw_closed_callback,
        )
        self.context = ctypes.c_void_p(0x5154)

    def _create_pair(
        self,
        context,
        hostname,
        hostname_length,
        alpn,
        alpn_length,
        raw_output,
        tls_output,
    ) -> int:
        del context
        self.create_calls += 1
        self.created_hostname = ctypes.string_at(hostname, hostname_length)
        self.created_alpn = ctypes.string_at(alpn, alpn_length)
        if self.create_reentry is not None:
            self.create_reentry()
        raw_output.contents.value = self.raw_handle
        tls_output.contents.value = self.tls_handle
        return self.create_result

    def _handshake(self, context, tls_handle, outcome) -> int:
        del context
        if tls_handle != self.TLS_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        self.handshake_calls += 1
        call_result, selected = (
            self.handshake_plan.pop(0)
            if self.handshake_plan
            else (tls_owner._CALL_COMMITTED, tls_owner._IO_COMPLETE)
        )
        outcome.contents.value = selected
        return call_result

    def _write(
        self, context, tls_handle, value, length, outcome, count
    ) -> int:
        del context
        if tls_handle != self.TLS_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        self.write_calls += 1
        self.writes.append(ctypes.string_at(value, length))
        call_result, selected_outcome, selected = (
            self.write_plan.pop(0)
            if self.write_plan
            else (
                tls_owner._CALL_COMMITTED,
                tls_owner._IO_COMPLETE,
                length,
            )
        )
        outcome.contents.value = selected_outcome
        count.contents.value = selected
        return call_result

    def _read(
        self, context, tls_handle, output, maximum, outcome, count
    ) -> int:
        del context
        if tls_handle != self.TLS_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        self.read_calls += 1
        call_result, selected_outcome, selected = (
            self.read_plan.pop(0)
            if self.read_plan
            else (
                tls_owner._CALL_COMMITTED,
                tls_owner._IO_EOF,
                b"",
            )
        )
        copied = selected[:maximum]
        if copied:
            ctypes.memmove(output, copied, len(copied))
        outcome.contents.value = selected_outcome
        count.contents.value = len(copied)
        return call_result

    def _negotiated(
        self,
        context,
        tls_handle,
        alpn_output,
        alpn_capacity,
        alpn_length,
        version_output,
        version_capacity,
        version_length,
    ) -> int:
        del context
        if tls_handle != self.TLS_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        self.negotiated_calls += 1
        if len(self.negotiated_alpn) <= alpn_capacity:
            ctypes.memmove(
                alpn_output,
                self.negotiated_alpn,
                len(self.negotiated_alpn),
            )
        if len(self.negotiated_version) <= version_capacity:
            ctypes.memmove(
                version_output,
                self.negotiated_version,
                len(self.negotiated_version),
            )
        alpn_length.contents.value = len(self.negotiated_alpn)
        version_length.contents.value = len(self.negotiated_version)
        return self.negotiated_result

    @staticmethod
    def _next_close(
        plan: list[tuple[int, bool]],
    ) -> tuple[int, bool]:
        if plan:
            return plan.pop(0)
        return tls_owner._CALL_COMMITTED, True

    def _close_tls(self, context, tls_handle) -> int:
        del context
        if tls_handle != self.TLS_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        self.tls_close_calls += 1
        if self.tls_close_entered is not None:
            self.tls_close_entered.set()
        if self.tls_close_continue is not None:
            self.tls_close_continue.wait(timeout=5)
        call_result, becomes_closed = self._next_close(self.tls_close_plan)
        if becomes_closed:
            self.tls_closed = True
        return call_result

    def _close_raw(self, context, raw_handle) -> int:
        del context
        if raw_handle != self.RAW_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        self.raw_close_calls += 1
        call_result, becomes_closed = self._next_close(self.raw_close_plan)
        if becomes_closed:
            self.raw_closed = True
        return call_result

    def _tls_is_closed(self, context, tls_handle, closed) -> int:
        del context
        if tls_handle != self.TLS_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        closed.contents.value = int(self.tls_closed)
        return self.observe_tls_result

    def _raw_is_closed(self, context, raw_handle, closed) -> int:
        del context
        if raw_handle != self.RAW_HANDLE:
            return tls_owner._CALL_AMBIGUOUS
        closed.contents.value = int(self.raw_closed)
        return self.observe_raw_result


class DarwinTlsOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        clang = Path("/usr/bin/clang")
        if not clang.is_file():
            raise unittest.SkipTest("clang is required for the native ABI test")
        cls._build_root = tempfile.TemporaryDirectory(
            prefix="snapquiz-tls-owner-"
        )
        suffix = ".dylib" if sys.platform == "darwin" else ".so"
        cls._library_path = str(Path(cls._build_root.name) / f"owner{suffix}")
        link_mode = "-dynamiclib" if sys.platform == "darwin" else "-shared"
        subprocess.run(
            [
                str(clang),
                "-std=c11",
                "-fPIC",
                "-Wall",
                "-Wextra",
                "-Werror",
                link_mode,
                str(SOURCE),
                "-o",
                cls._library_path,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        cls.bindings = tls_owner._load_bindings_for_test(
            cls._library_path,
            _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._build_root.cleanup()

    def _publication(self):
        return tls_owner._new_publication_for_test(
            self.bindings,
            _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
        )

    def _owner(self, fake: _FakeTlsVtable):
        publication = self._publication()
        result = tls_owner._publish_owner_with_test_vtable(
            publication=publication,
            vtable=fake.vtable,
            context=fake.context,
            hostname=HOSTNAME,
            policy_digest=POLICY_DIGEST,
            keepalive=fake,
            _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
        )
        self.assertIsNone(result)
        return publication, publication.owner()

    @staticmethod
    def _finish(publication, owner) -> None:
        if not owner.closed:
            owner.close_once()
        owner.release()
        publication.deinitialize()

    def test_import_is_inert_and_production_flags_stay_false(self):
        source = Path(tls_owner.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertNotIn("socket", imported)
        self.assertNotIn("ssl", imported)
        self.assertEqual(tls_owner.__all__, ())
        self.assertTrue(tls_owner.DARWIN_TLS_OWNER_FOUNDATION_AVAILABLE)
        self.assertFalse(tls_owner.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(exact_transport.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE)
        self.assertFalse(exact_transport.PRODUCTION_APP_INTEGRATION_AVAILABLE)

        script = r'''
import ctypes
def poison(*args, **kwargs):
    raise AssertionError("import loaded a native library")
ctypes.CDLL = poison
import snapquiz.transport._darwin_tls_owner as module
assert module.OPAQUE_TLS_SOCKET_OWNER_AVAILABLE is False
'''
        subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_factory_publishes_only_opaque_binding_and_is_immutable(self):
        fake = _FakeTlsVtable()
        publication, owner = self._owner(fake)
        try:
            self.assertEqual(fake.create_calls, 1)
            self.assertEqual(fake.created_hostname, HOSTNAME.encode("ascii"))
            self.assertEqual(fake.created_alpn, b"http/1.1")
            self.assertIs(copy.copy(owner), owner)
            self.assertIs(copy.deepcopy(owner), owner)
            with self.assertRaises(TypeError):
                pickle.dumps(owner)
            token = owner._token
            self.assertIs(copy.copy(token), token)
            self.assertIs(copy.deepcopy(token), token)
            with self.assertRaises(TypeError):
                pickle.dumps(token)
            metadata = owner.safe_metadata()
            self.assertEqual(metadata["state"], "active")
            self.assertFalse(metadata["production_available"])
            self.assertNotIn("raw_handle", metadata)
            self.assertNotIn("tls_handle", metadata)
            self.assertNotIn("token", metadata)
            self.assertNotIn("socket", tls_owner._OpaqueTlsOwner.__slots__)
            self.assertNotIn("raw_handle", tls_owner._OpaqueTlsOwner.__slots__)
            self.assertNotIn("tls_handle", tls_owner._OpaqueTlsOwner.__slots__)
        finally:
            self._finish(publication, owner)

    def test_constructor_return_gap_retains_published_cleanup_owner(self):
        fake = _FakeTlsVtable()
        publication = self._publication()
        original = tls_owner._native_create_publish

        def interrupt_after_native_commit(*args, **kwargs):
            status = original(*args, **kwargs)
            self.assertEqual(status, 0)
            raise KeyboardInterrupt

        with patch.object(
            tls_owner,
            "_native_create_publish",
            side_effect=interrupt_after_native_commit,
        ), self.assertRaises(KeyboardInterrupt):
            tls_owner._publish_owner_with_test_vtable(
                publication=publication,
                vtable=fake.vtable,
                context=fake.context,
                hostname=HOSTNAME,
                policy_digest=POLICY_DIGEST,
                keepalive=fake,
                _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
            )
        self.assertTrue(publication.has_owner())
        owner = publication.owner()
        self.assertEqual(owner.safe_metadata()["state"], "active")
        self._finish(publication, owner)
        self.assertEqual(fake.tls_close_calls, 1)
        self.assertEqual(fake.raw_close_calls, 1)

    def test_create_callback_can_reenter_publication_without_deadlock(self):
        fake = _FakeTlsVtable()
        publication = self._publication()
        observations: list[object] = []

        def reenter_publication() -> None:
            observations.append(publication.has_owner())
            try:
                publication.deinitialize()
            except ValueError:
                observations.append("creation-active")

        fake.create_reentry = reenter_publication
        tls_owner._publish_owner_with_test_vtable(
            publication=publication,
            vtable=fake.vtable,
            context=fake.context,
            hostname=HOSTNAME,
            policy_digest=POLICY_DIGEST,
            keepalive=fake,
            _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
        )
        owner = publication.owner()
        self.assertEqual(observations, [False, "creation-active"])
        self._finish(publication, owner)

    def test_ambiguous_constructor_is_permanent_uncertain_tombstone(self):
        for raw_handle, tls_handle, expected_tls_closes in (
            (_FakeTlsVtable.RAW_HANDLE, _FakeTlsVtable.TLS_HANDLE, 1),
            (_FakeTlsVtable.RAW_HANDLE, 0, 0),
            (_FakeTlsVtable.RAW_HANDLE, _FakeTlsVtable.RAW_HANDLE, 0),
            (0, 0, 0),
        ):
            with self.subTest(raw=raw_handle, tls=tls_handle):
                fake = _FakeTlsVtable()
                fake.create_result = tls_owner._CALL_AMBIGUOUS
                fake.raw_handle = raw_handle
                fake.tls_handle = tls_handle
                publication, owner = self._owner(fake)
                self.assertEqual(owner.safe_metadata()["state"], "poisoned")
                with self.assertRaises(EndpointPolicyError) as raised:
                    owner.handshake_step(operation_id=1)
                _assert_safe(self, raised.exception)
                for _ in range(2):
                    with self.assertRaises(EndpointPolicyError) as close_error:
                        owner.close_once()
                    _assert_safe(self, close_error.exception)
                self.assertFalse(owner.closed)
                with self.assertRaises(EndpointPolicyError):
                    owner.release()
                with self.assertRaises(ValueError):
                    publication.deinitialize()
                self.assertEqual(fake.raw_close_calls, int(raw_handle != 0))
                self.assertEqual(fake.tls_close_calls, expected_tls_closes)

    def test_definite_unissued_constructor_has_no_publication(self):
        fake = _FakeTlsVtable()
        fake.create_result = tls_owner._CALL_NOT_ISSUED
        fake.raw_handle = 0
        fake.tls_handle = 0
        publication = self._publication()
        with self.assertRaises(EndpointPolicyError) as raised:
            tls_owner._publish_owner_with_test_vtable(
                publication=publication,
                vtable=fake.vtable,
                context=fake.context,
                hostname=HOSTNAME,
                policy_digest=POLICY_DIGEST,
                keepalive=fake,
                _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
            )
        _assert_safe(self, raised.exception)
        self.assertFalse(publication.has_owner())
        publication.deinitialize()

    def test_handshake_outcomes_are_cached_and_never_replayed(self):
        fake = _FakeTlsVtable()
        fake.handshake_plan = [
            (tls_owner._CALL_COMMITTED, tls_owner._IO_WANT_READ),
            (tls_owner._CALL_COMMITTED, tls_owner._IO_COMPLETE),
        ]
        publication, owner = self._owner(fake)
        try:
            self.assertEqual(owner.handshake_step(operation_id=10), "want_read")
            self.assertEqual(owner.handshake_step(operation_id=10), "want_read")
            self.assertEqual(fake.handshake_calls, 1)
            self.assertEqual(owner.handshake_step(operation_id=11), "complete")
            self.assertEqual(fake.handshake_calls, 2)
            with self.assertRaises(EndpointPolicyError):
                owner.handshake_step(operation_id=10)
            self.assertEqual(fake.handshake_calls, 2)
        finally:
            self._finish(publication, owner)

    def test_ambiguous_handshake_is_queryable_but_poisoned(self):
        fake = _FakeTlsVtable()
        fake.handshake_plan = [
            (tls_owner._CALL_AMBIGUOUS, tls_owner._IO_COMPLETE)
        ]
        publication, owner = self._owner(fake)
        self.assertEqual(owner.handshake_step(operation_id=1), "ambiguous")
        self.assertEqual(owner.handshake_step(operation_id=1), "ambiguous")
        self.assertEqual(fake.handshake_calls, 1)
        self.assertEqual(owner.safe_metadata()["state"], "poisoned")
        with self.assertRaises(EndpointPolicyError):
            owner.handshake_step(operation_id=2)
        self.assertEqual(fake.handshake_calls, 1)
        self._finish(publication, owner)

    def test_partial_write_is_cached_and_payload_tamper_fails_closed(self):
        fake = _FakeTlsVtable()
        fake.write_plan = [
            (tls_owner._CALL_COMMITTED, tls_owner._IO_COMPLETE, 3)
        ]
        publication, owner = self._owner(fake)
        try:
            self.assertEqual(
                owner.write_once(b"abcdef", operation_id=20),
                ("written", 3),
            )
            self.assertEqual(
                owner.write_once(b"abcdef", operation_id=20),
                ("written", 3),
            )
            self.assertEqual(fake.write_calls, 1)
            with self.assertRaises(EndpointPolicyError) as raised:
                owner.write_once(b"abcdeg", operation_id=20)
            _assert_safe(self, raised.exception)
            self.assertEqual(fake.write_calls, 1)
        finally:
            self._finish(publication, owner)

    def test_oversized_readonly_view_is_rejected_without_buffer_lease(self):
        fake = _FakeTlsVtable()
        publication, owner = self._owner(fake)
        backing = bytearray(tls_owner.MAX_NATIVE_TLS_WRITE_BYTES + 1)
        view = memoryview(backing).toreadonly()
        try:
            with self.assertRaises(ValueError):
                owner.write_once(view, operation_id=1)
            self.assertEqual(fake.write_calls, 0)
        finally:
            view.release()
        # A leaked Py_buffer export would keep this bytearray non-resizable.
        backing.extend(b"x")
        self._finish(publication, owner)

    def test_write_cache_allocation_failure_preserves_previous_replay(self):
        fake = _FakeTlsVtable()
        publication, owner = self._owner(fake)
        try:
            self.assertEqual(
                owner.write_once(b"first-payload", operation_id=20),
                ("written", len(b"first-payload")),
            )
            owner._fail_next_write_allocation_for_test(
                _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY
            )
            with self.assertRaises(EndpointPolicyError) as raised:
                owner.write_once(b"replacement", operation_id=21)
            _assert_safe(self, raised.exception)
            self.assertEqual(fake.write_calls, 1)
            self.assertEqual(
                owner.write_once(b"first-payload", operation_id=20),
                ("written", len(b"first-payload")),
            )
            self.assertEqual(fake.write_calls, 1)
            self.assertEqual(
                owner.safe_metadata()["last_write_operation_id"], 20
            )
        finally:
            self._finish(publication, owner)

    def test_ambiguous_write_poisoning_prevents_replay(self):
        fake = _FakeTlsVtable()
        fake.write_plan = [
            (tls_owner._CALL_AMBIGUOUS, tls_owner._IO_COMPLETE, 0)
        ]
        publication, owner = self._owner(fake)
        self.assertEqual(
            owner.write_once(b"synthetic", operation_id=1),
            ("ambiguous", 0),
        )
        self.assertEqual(
            owner.write_once(b"synthetic", operation_id=1),
            ("ambiguous", 0),
        )
        with self.assertRaises(EndpointPolicyError):
            owner.write_once(b"synthetic", operation_id=2)
        self.assertEqual(fake.write_calls, 1)
        self._finish(publication, owner)

    def test_write_and_read_want_directions_are_cached(self):
        fake = _FakeTlsVtable()
        fake.write_plan = [
            (tls_owner._CALL_COMMITTED, tls_owner._IO_WANT_WRITE, 0)
        ]
        fake.read_plan = [
            (tls_owner._CALL_COMMITTED, tls_owner._IO_WANT_READ, b"")
        ]
        publication, owner = self._owner(fake)
        try:
            self.assertEqual(
                owner.write_once(b"synthetic", operation_id=1),
                ("want_write", 0),
            )
            self.assertEqual(
                owner.write_once(b"synthetic", operation_id=1),
                ("want_write", 0),
            )
            self.assertEqual(
                owner.read_once(64, operation_id=1),
                ("want_read", None),
            )
            self.assertEqual(
                owner.read_once(64, operation_id=1),
                ("want_read", None),
            )
            self.assertEqual(fake.write_calls, 1)
            self.assertEqual(fake.read_calls, 1)
        finally:
            self._finish(publication, owner)

    def test_read_bytes_are_native_cached_and_bound_to_maximum(self):
        fake = _FakeTlsVtable()
        fake.read_plan = [
            (tls_owner._CALL_COMMITTED, tls_owner._IO_DATA, b"reply")
        ]
        publication, owner = self._owner(fake)
        try:
            self.assertEqual(
                owner.read_once(32, operation_id=30),
                ("data", b"reply"),
            )
            self.assertEqual(
                owner.read_once(32, operation_id=30),
                ("data", b"reply"),
            )
            self.assertEqual(fake.read_calls, 1)
            with self.assertRaises(EndpointPolicyError):
                owner.read_once(16, operation_id=30)
            self.assertEqual(fake.read_calls, 1)
        finally:
            self._finish(publication, owner)

    def test_closed_owner_never_replays_zeroized_read_cache(self):
        fake = _FakeTlsVtable()
        fake.read_plan = [
            (tls_owner._CALL_COMMITTED, tls_owner._IO_DATA, b"secret")
        ]
        publication, owner = self._owner(fake)
        self.assertEqual(
            owner.read_once(32, operation_id=31),
            ("data", b"secret"),
        )
        owner.close_once()
        with self.assertRaises(EndpointPolicyError) as raised:
            owner.read_once(32, operation_id=31)
        _assert_safe(self, raised.exception)
        self.assertEqual(fake.read_calls, 1)
        owner.release()
        publication.deinitialize()

    def test_policy_attestation_is_exact_and_cached(self):
        fake = _FakeTlsVtable()
        publication, owner = self._owner(fake)
        try:
            self.assertEqual(owner.handshake_step(operation_id=1), "complete")
            evidence = owner.attest_policy()
            evidence.validate_integrity()
            self.assertEqual(evidence.hostname, HOSTNAME)
            self.assertEqual(evidence.policy_digest, POLICY_DIGEST)
            self.assertEqual(evidence.tls_version, "TLSv1.3")
            self.assertEqual(evidence.safe_metadata()["alpn"], "http/1.1")
            self.assertIs(copy.copy(evidence), evidence)
            self.assertIs(copy.deepcopy(evidence), evidence)
            with self.assertRaises(TypeError):
                pickle.dumps(evidence)
            self.assertEqual(owner.attest_policy().safe_metadata(), evidence.safe_metadata())
            self.assertEqual(fake.negotiated_calls, 1)
        finally:
            self._finish(publication, owner)

    def test_bad_alpn_or_tls_version_poison_policy_evidence(self):
        for alpn, version in ((b"h2", b"TLSv1.3"), (b"http/1.1", b"TLSv1.1")):
            with self.subTest(alpn=alpn, version=version):
                fake = _FakeTlsVtable()
                fake.negotiated_alpn = alpn
                fake.negotiated_version = version
                publication, owner = self._owner(fake)
                self.assertEqual(owner.handshake_step(operation_id=1), "complete")
                with self.assertRaises(EndpointPolicyError) as raised:
                    owner.attest_policy()
                _assert_safe(self, raised.exception)
                self.assertEqual(owner.safe_metadata()["state"], "poisoned")
                self._finish(publication, owner)

    def test_invalid_hostname_is_rejected_before_native_creation(self):
        for hostname in ("OPEN.bigmodel.cn", "127.0.0.1", "bad..host"):
            with self.subTest(hostname=hostname):
                fake = _FakeTlsVtable()
                publication = self._publication()
                with self.assertRaises(ValueError):
                    tls_owner._publish_owner_with_test_vtable(
                        publication=publication,
                        vtable=fake.vtable,
                        context=fake.context,
                        hostname=hostname,
                        policy_digest=POLICY_DIGEST,
                        keepalive=fake,
                        _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
                    )
                self.assertEqual(fake.create_calls, 0)
                publication.deinitialize()

    def test_token_tamper_and_native_token_mismatch_fail_closed(self):
        fake = _FakeTlsVtable()
        publication, owner = self._owner(fake)
        original = owner._token._value
        tampered = bytes([original[0] ^ 1]) + original[1:]
        object.__setattr__(owner._token, "_value", tampered)
        with self.assertRaises(EndpointPolicyError) as raised:
            owner.safe_metadata()
        _assert_safe(self, raised.exception)
        object.__setattr__(owner._token, "_value", original)

        native_token = owner._token._as_c(
            _authority=tls_owner._OWNER_AUTHORITY
        )
        native_token.bytes[2] ^= 1
        snapshot = tls_owner._CTlsSnapshot()
        self.assertEqual(
            self.bindings.snapshot(
                publication._storage,
                ctypes.byref(native_token),
                ctypes.byref(snapshot),
            ),
            errno.ESTALE,
        )
        self._finish(publication, owner)

    def test_tokens_are_native_random_and_bound_to_one_publication(self):
        source = SOURCE.read_text(encoding="utf-8")
        token_source = source.split("static void sq_tls_make_token", 1)[1].split(
            "static int sq_tls_token_equal", 1
        )[0]
        self.assertIn("arc4random_buf", token_source)
        self.assertNotIn("uintptr_t", token_source)
        self.assertNotIn("generation", token_source)
        self.assertNotIn("hostname", token_source)

        first_publication, first_owner = self._owner(_FakeTlsVtable())
        second_publication, second_owner = self._owner(_FakeTlsVtable())
        try:
            first = first_owner._token._value
            second = second_owner._token._value
            self.assertEqual(len(first), 32)
            self.assertNotEqual(first, bytes(32))
            self.assertNotEqual(first, second)

            cross_token = first_owner._token._as_c(
                _authority=tls_owner._OWNER_AUTHORITY
            )
            snapshot = tls_owner._CTlsSnapshot()
            self.assertEqual(
                self.bindings.snapshot(
                    second_publication._storage,
                    ctypes.byref(cross_token),
                    ctypes.byref(snapshot),
                ),
                errno.ESTALE,
            )
        finally:
            self._finish(first_publication, first_owner)
            self._finish(second_publication, second_owner)

    def test_vtable_abi_size_and_version_are_verified_before_callback(self):
        for field, value in (
            ("abi", 0),
            ("size", ctypes.sizeof(tls_owner._CTlsVtable) - 1),
            ("version", tls_owner._VTABLE_VERSION + 1),
            ("reserved", 1),
        ):
            with self.subTest(field=field):
                fake = _FakeTlsVtable()
                vtable = tls_owner._CTlsVtable.from_buffer_copy(fake.vtable)
                setattr(vtable, field, value)
                publication = self._publication()
                with self.assertRaises(EndpointPolicyError) as raised:
                    tls_owner._publish_owner_with_test_vtable(
                        publication=publication,
                        vtable=vtable,
                        context=fake.context,
                        hostname=HOSTNAME,
                        policy_digest=POLICY_DIGEST,
                        keepalive=fake,
                        _authority=tls_owner._TEST_TLS_OWNER_AUTHORITY,
                    )
                _assert_safe(self, raised.exception)
                self.assertEqual(fake.create_calls, 0)
                self.assertFalse(publication.has_owner())
                publication.deinitialize()

    def test_blocked_callback_is_pinned_and_competing_calls_fail_fast(self):
        fake = _FakeTlsVtable()
        fake.tls_close_entered = Event()
        fake.tls_close_continue = Event()
        publication, owner = self._owner(fake)
        failures: list[BaseException] = []

        def close_in_thread() -> None:
            try:
                owner.close_once()
            except BaseException as error:  # pragma: no cover - diagnostic
                failures.append(error)

        thread = Thread(target=close_in_thread)
        thread.start()
        self.assertTrue(fake.tls_close_entered.wait(timeout=2))
        started = time.monotonic()
        with self.assertRaises(EndpointPolicyError) as raised:
            owner.safe_metadata()
        _assert_safe(self, raised.exception)
        self.assertLess(time.monotonic() - started, 1.0)

        native_token = owner._token._as_c(
            _authority=tls_owner._OWNER_AUTHORITY
        )
        self.assertEqual(
            self.bindings.release(
                publication._storage,
                ctypes.byref(native_token),
            ),
            errno.EBUSY,
        )
        self.assertEqual(
            self.bindings.publication_deinit(publication._storage),
            errno.EBUSY,
        )
        fake.tls_close_continue.set()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(owner.closed)
        owner.release()
        publication.deinitialize()

    def test_close_not_issued_can_retry_but_committed_actions_are_once(self):
        fake = _FakeTlsVtable()
        fake.tls_close_plan = [
            (tls_owner._CALL_NOT_ISSUED, False),
            (tls_owner._CALL_COMMITTED, True),
        ]
        publication, owner = self._owner(fake)
        with self.assertRaises(EndpointPolicyError) as raised:
            owner.close_once()
        _assert_safe(self, raised.exception)
        self.assertFalse(owner.closed)
        self.assertEqual(fake.tls_close_calls, 1)
        self.assertEqual(fake.raw_close_calls, 1)
        owner.close_once()
        self.assertTrue(owner.closed)
        metadata = owner.safe_metadata()
        self.assertEqual(metadata["tls_close_actions"], 2)
        self.assertEqual(metadata["raw_close_actions"], 1)
        owner.close_once()
        self.assertEqual(fake.tls_close_calls, 2)
        self.assertEqual(fake.raw_close_calls, 1)
        owner.release()
        publication.deinitialize()

    def test_ambiguous_close_is_never_replayed_and_observation_can_finish(self):
        fake = _FakeTlsVtable()
        fake.tls_close_plan = [(tls_owner._CALL_AMBIGUOUS, False)]
        publication, owner = self._owner(fake)
        for _ in range(2):
            with self.assertRaises(EndpointPolicyError) as raised:
                owner.close_once()
            _assert_safe(self, raised.exception)
        self.assertEqual(fake.tls_close_calls, 1)
        self.assertEqual(fake.raw_close_calls, 1)
        self.assertFalse(owner.closed)
        fake.tls_closed = True
        owner.close_once()
        self.assertTrue(owner.closed)
        self.assertEqual(fake.tls_close_calls, 1)
        self.assertEqual(fake.raw_close_calls, 1)
        owner.release()
        publication.deinitialize()

    def test_released_token_is_stale_before_publication_deinit(self):
        fake = _FakeTlsVtable()
        publication, owner = self._owner(fake)
        owner.close_once()
        native_token = owner._token._as_c(
            _authority=tls_owner._OWNER_AUTHORITY
        )
        owner.release()
        snapshot = tls_owner._CTlsSnapshot()
        self.assertEqual(
            self.bindings.snapshot(
                publication._storage,
                ctypes.byref(native_token),
                ctypes.byref(snapshot),
            ),
            errno.ESTALE,
        )
        with self.assertRaises(EndpointPolicyError):
            owner.safe_metadata()
        publication.deinitialize()


if __name__ == "__main__":
    unittest.main()
