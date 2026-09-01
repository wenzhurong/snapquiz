"""Deterministic offline tests for the W09-B2a helper lifecycle."""
from __future__ import annotations

import builtins
import copy
import json
import os
import pickle
import socket
import subprocess
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import ConfigError, EndpointPolicyError
from snapquiz.runtime.attempt import _TRANSPORT_ATTEMPT_AUTHORITY
import snapquiz.transport.resolver as resolver_module
from snapquiz.transport.resolver import (
    MAX_READY_FRAME_BYTES,
    MAX_RESULT_FRAME_BYTES,
    MAX_RESULT_TRANSCRIPT_BYTES,
    READY_FRAME,
    RESOLVER_HELPER_PROTOCOL_VERSION,
    RESOLVER_HELPER_START_SCHEMA_VERSION,
    AttemptTerminalGuard,
    PreAttemptResolverGuard,
    ResolverHelperLauncher,
    ResolverResultReceipt,
    start_frame_digest,
)


LIFECYCLE_ID = UUID("70000000-0000-0000-0000-000000000001")
ATTEMPT_ID = UUID("70000000-0000-0000-0000-000000000002")
CLAIM_ID = UUID("70000000-0000-0000-0000-000000000003")
DNS_START_ID = UUID("70000000-0000-0000-0000-000000000004")
ATTEMPT_DIGEST = Digest256("a" * 64)
POLICY_DIGEST = Digest256("b" * 64)
TARGET = "open.bigmodel.cn"
SECRET = "synthetic-secret-must-not-spawn"
EXECUTABLE = "/opt/snapquiz/libexec/resolver-helper"
RESULT = (
    b'{"candidates":[],"schema_version":'
    b'"snapquiz.raw-resolution-transcript.v2"}'
)


class _FakeKernel:
    def __init__(self, chunks, *, faults=None, exit_status: object = 0) -> None:
        self.chunks = list(chunks)
        self.faults = {} if faults is None else dict(faults)
        self.exit_status = exit_status
        self.read_limits: list[int] = []
        self.writes: list[bytes] = []
        self.events: list[str] = []

    def _fault(self, name: str) -> None:
        selected = self.faults.get(name)
        if selected is not None:
            raise selected

    def read_stdout(self, max_bytes: int) -> bytes:
        self.events.append("read")
        self.read_limits.append(max_bytes)
        self._fault("read")
        if not self.chunks:
            return b""
        selected = self.chunks.pop(0)
        if len(selected) <= max_bytes:
            return selected
        self.chunks.insert(0, selected[max_bytes:])
        return selected[:max_bytes]

    def write_stdin(self, frame: bytes) -> None:
        self.events.append("write")
        self.writes.append(frame)
        self._fault("write")

    def terminate(self) -> None:
        self.events.append("terminate")
        self._fault("terminate")

    def reap(self) -> int:
        self.events.append("reap")
        self._fault("reap")
        return self.exit_status  # type: ignore[return-value]

    def close_pipes(self) -> None:
        self.events.append("close_pipes")
        self._fault("close_pipes")


class _FakeSpawner:
    def __init__(self, kernel: _FakeKernel) -> None:
        self.kernel = kernel
        self.requests = []

    def spawn(self, request):
        self.requests.append(request)
        return self.kernel


def _launcher(chunks, *, faults=None, exit_status: object = 0):
    kernel = _FakeKernel(chunks, faults=faults, exit_status=exit_status)
    spawner = _FakeSpawner(kernel)
    return (
        ResolverHelperLauncher(spawner, executable=EXECUTABLE),
        spawner,
        kernel,
    )


def _ready(
    chunks=None,
    *,
    faults=None,
    exit_status: object = 0,
    observer=None,
):
    launcher, spawner, kernel = _launcher(
        [READY_FRAME] if chunks is None else chunks,
        faults=faults,
        exit_status=exit_status,
    )
    guard = launcher.launch_ready(
        lifecycle_id=LIFECYCLE_ID,
        observer=observer,
    )
    return guard, spawner, kernel


def _transfer(guard, *, observer=None):
    return guard.transfer(
        attempt_permit_id=ATTEMPT_ID,
        attempt_permit_digest=ATTEMPT_DIGEST,
        transport_claim_id=CLAIM_ID,
        observer=observer,
    )


def _start(guard, *, observer=None):
    guard.start(
        hostname=TARGET,
        port=443,
        network_policy_ref="snapquiz.internet-public-address-policy.v1",
        network_policy_digest=POLICY_DIGEST,
        dns_start_id=DNS_START_ID,
        observer=observer,
    )


def _cleanup_counts(kernel: _FakeKernel) -> tuple[int, int, int]:
    return (
        kernel.events.count("terminate"),
        kernel.events.count("reap"),
        kernel.events.count("close_pipes"),
    )


class W09ResolverLifecycleTest(unittest.TestCase):
    def test_ready_transfer_single_start_result_and_exact_cleanup(self):
        ready_chunks = [
            READY_FRAME[:5],
            READY_FRAME[5:],
            RESULT[:7],
            RESULT[7:] + b"\n",
        ]
        pre, spawner, kernel = _ready(ready_chunks)

        self.assertEqual(pre.safe_metadata()["state"], "ready")
        attempt = _transfer(pre)
        self.assertEqual(attempt.safe_metadata()["state"], "transferred")
        _start(attempt)
        self.assertEqual(attempt.safe_metadata()["state"], "started")
        receipt = attempt.read_result_receipt()
        self.assertIs(type(receipt), ResolverResultReceipt)
        self.assertEqual(receipt.lifecycle_id, LIFECYCLE_ID)
        self.assertEqual(receipt.attempt_permit_id, ATTEMPT_ID)
        self.assertEqual(receipt.transport_claim_id, CLAIM_ID)
        self.assertEqual(receipt.dns_start_id, DNS_START_ID)
        self.assertEqual(receipt.raw_transcript_byte_size, len(RESULT))
        self.assertEqual(receipt.start_frame_digest, start_frame_digest(kernel.writes[0]))
        self.assertIs(receipt.stdout_eof, True)
        self.assertIs(receipt.child_reaped, True)
        self.assertEqual(receipt.child_exit_status, 0)
        self.assertIs(receipt.helper_pipes_closed, True)
        receipt.validate_integrity()
        self.assertIs(copy.copy(receipt), receipt)
        self.assertIs(copy.deepcopy(receipt), receipt)
        with self.assertRaises(TypeError):
            pickle.dumps(receipt)
        with self.assertRaisesRegex(TypeError, "require terminal guard issuance"):
            ResolverResultReceipt(
                issuer=attempt,
                ledger=attempt._ledger,
                dns_start_id=DNS_START_ID,
                exact_start_frame_digest=receipt.start_frame_digest,
                raw_transcript=RESULT,
            )
        forged = object.__new__(ResolverResultReceipt)
        for name in ResolverResultReceipt.__slots__:
            object.__setattr__(forged, name, getattr(receipt, name))
        with self.assertRaisesRegex(ValueError, "exactly issued"):
            forged._validate_exact_issuance(
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        self.assertEqual(attempt.safe_metadata()["state"], "result_attested")
        self.assertEqual(kernel.events[-3:], ["read", "reap", "close_pipes"])
        self.assertEqual(kernel.read_limits[-1], 1)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertTrue(attempt.cleanup())
        self.assertFalse(attempt.cleanup())

        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(RESOLVER_HELPER_PROTOCOL_VERSION, "snapquiz.resolver-helper.v2")
        self.assertEqual(RESOLVER_HELPER_START_SCHEMA_VERSION, "snapquiz.resolver-start.v2")
        self.assertEqual(READY_FRAME, b"SNAPQUIZ-RESOLVER/2 READY\n")
        self.assertEqual(
            spawner.requests[0].argv[-1],
            "--snapquiz-resolver-helper-v2",
        )
        self.assertEqual(len(kernel.writes), 1)
        frame = json.loads(kernel.writes[0])
        self.assertEqual(frame["kind"], "START")
        self.assertEqual(frame["hostname"], TARGET)
        self.assertEqual(frame["port"], 443)
        self.assertEqual(frame["attempt_permit_id"], str(ATTEMPT_ID))
        self.assertEqual(frame["transport_claim_id"], str(CLAIM_ID))
        self.assertEqual(frame["dns_start_id"], str(DNS_START_ID))
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))

    def test_spawn_and_ready_metadata_never_receive_target_or_secret(self):
        pre, spawner, kernel = _ready()
        rendered = repr(spawner.requests[0]) + repr(
            spawner.requests[0].safe_metadata()
        ) + repr(pre) + repr(pre.safe_metadata())
        self.assertNotIn(TARGET, rendered)
        self.assertNotIn(SECRET, rendered)
        self.assertNotIn("hostname", rendered)
        self.assertNotIn("credential", rendered)
        self.assertEqual(kernel.writes, [])

        attempt = _transfer(pre)
        before_start = rendered + repr(attempt) + repr(attempt.safe_metadata())
        self.assertNotIn(TARGET, before_start)
        self.assertNotIn(SECRET, before_start)
        _start(attempt)
        self.assertIn(TARGET.encode("ascii"), kernel.writes[0])
        self.assertNotIn(SECRET.encode("ascii"), kernel.writes[0])
        attempt.cleanup()

    def test_guards_are_factory_only(self):
        with self.assertRaisesRegex(TypeError, "require launcher"):
            PreAttemptResolverGuard(
                lifecycle_id=LIFECYCLE_ID,
                spawn_request_digest=ATTEMPT_DIGEST,
                ledger=object(),
            )
        with self.assertRaisesRegex(TypeError, "require ownership transfer"):
            AttemptTerminalGuard(
                lifecycle_id=LIFECYCLE_ID,
                attempt_permit_id=ATTEMPT_ID,
                attempt_permit_digest=ATTEMPT_DIGEST,
                transport_claim_id=CLAIM_ID,
                terminal_guard_id=DNS_START_ID,
                terminal_guard_digest=POLICY_DIGEST,
                ledger=object(),
            )

    def test_exact_owner_identity_rejects_forged_guard(self):
        pre, _, kernel = _ready()
        forged = object.__new__(PreAttemptResolverGuard)
        for name in PreAttemptResolverGuard.__slots__:
            object.__setattr__(forged, name, getattr(pre, name))

        with self.assertRaisesRegex(EndpointPolicyError, "owner"):
            forged.cleanup()
        self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        self.assertTrue(pre.cleanup())
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_double_transfer_cannot_steal_new_owner(self):
        pre, _, kernel = _ready()
        attempt = _transfer(pre)
        with self.assertRaisesRegex(EndpointPolicyError, "owner"):
            _transfer(pre)
        self.assertEqual(attempt.safe_metadata()["state"], "transferred")
        self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        self.assertTrue(attempt.cleanup())

    def test_double_start_writes_once_then_fail_closed_cleanup(self):
        pre, _, kernel = _ready()
        attempt = _transfer(pre)
        _start(attempt)
        with self.assertRaisesRegex(EndpointPolicyError, "状态"):
            _start(attempt)
        self.assertEqual(len(kernel.writes), 1)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertFalse(attempt.cleanup())

    def test_truncated_and_oversize_ready_are_cleaned_exactly_once(self):
        cases = (
            ("truncated", [READY_FRAME[:-1]]),
            ("oversize", [b"x" * (MAX_READY_FRAME_BYTES + 1)]),
        )
        for name, chunks in cases:
            with self.subTest(name=name):
                launcher, _, kernel = _launcher(chunks)
                with self.assertRaises(EndpointPolicyError):
                    launcher.launch_ready(lifecycle_id=LIFECYCLE_ID)
                self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
                self.assertEqual(kernel.writes, [])

    def test_partial_ready_frame_is_accepted_without_overread(self):
        pre, _, kernel = _ready(
            [READY_FRAME[:1], READY_FRAME[1:11], READY_FRAME[11:]]
        )
        self.assertEqual(pre.safe_metadata()["state"], "ready")
        self.assertTrue(all(limit <= MAX_READY_FRAME_BYTES for limit in kernel.read_limits))
        pre.cleanup()

    def test_pre_transfer_validation_fault_cleans_pre_owner(self):
        pre, _, kernel = _ready()
        with self.assertRaises(ValueError):
            pre.transfer(
                attempt_permit_id="not-a-uuid",  # type: ignore[arg-type]
                attempt_permit_digest=ATTEMPT_DIGEST,
                transport_claim_id=CLAIM_ID,
            )
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(pre.safe_metadata()["state"], "terminal")

    def test_transfer_observer_sees_commit_then_raise_cleans_new_owner(self):
        pre, _, kernel = _ready()
        observations = []

        def fail_after_commit(event, metadata):
            observations.append((event, metadata["state"]))
            raise RuntimeError("transfer observer fault")

        with self.assertRaisesRegex(RuntimeError, "transfer observer"):
            _transfer(pre, observer=fail_after_commit)
        self.assertEqual(observations, [("ownership_transferred", "transferred")])
        self.assertEqual(pre.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_write_fault_after_transfer_cleans_attempt_owner(self):
        pre, _, kernel = _ready(faults={"write": RuntimeError("write fault")})
        attempt = _transfer(pre)
        with self.assertRaisesRegex(RuntimeError, "write fault"):
            _start(attempt)
        self.assertEqual(len(kernel.writes), 1)
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_start_observer_sees_committed_start_before_fault_cleanup(self):
        pre, _, kernel = _ready()
        attempt = _transfer(pre)
        observations = []

        def fail_after_commit(event, metadata):
            observations.append((event, metadata["state"]))
            raise KeyboardInterrupt("observer fault")

        with self.assertRaisesRegex(KeyboardInterrupt, "observer fault"):
            _start(attempt, observer=fail_after_commit)
        self.assertEqual(observations, [("start_committed", "started")])
        self.assertEqual(len(kernel.writes), 1)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_result_partial_eof_and_oversize_fail_closed(self):
        for name, result_chunks in (
            ("partial", [b'{"candidates":']),
            ("oversize", [b"x" * (MAX_RESULT_FRAME_BYTES + 1)]),
        ):
            with self.subTest(name=name):
                pre, _, kernel = _ready([READY_FRAME, *result_chunks])
                attempt = _transfer(pre)
                _start(attempt)
                with self.assertRaises(EndpointPolicyError):
                    attempt.read_result_receipt()
                self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_result_second_frame_in_next_chunk_fails_closed(self):
        pre, _, kernel = _ready(
            [
                READY_FRAME,
                RESULT + b"\n",
                b'{"kind":"RESULT"}\n',
            ]
        )
        attempt = _transfer(pre)
        _start(attempt)

        with self.assertRaises(EndpointPolicyError):
            attempt.read_result_receipt()

        self.assertIsNone(attempt._ledger._issued_receipt)
        self.assertEqual(kernel.read_limits[-1], 1)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")

    def test_result_second_frame_in_same_chunk_fails_closed(self):
        pre, _, kernel = _ready(
            [READY_FRAME, RESULT + b"\n" + b'{"kind":"RESULT"}\n']
        )
        attempt = _transfer(pre)
        _start(attempt)

        with self.assertRaises(EndpointPolicyError):
            attempt.read_result_receipt()

        self.assertIsNone(attempt._ledger._issued_receipt)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")

    def test_result_eof_probe_rejects_invalid_read_contract(self):
        for name, invalid in (
            ("mutable", bytearray()),
            ("text", ""),
            ("overread", b"xx"),
        ):
            with self.subTest(name=name):
                pre, _, kernel = _ready([READY_FRAME, RESULT + b"\n"])
                attempt = _transfer(pre)
                _start(attempt)
                original_read = kernel.read_stdout
                eof_calls = 0

                def invalid_eof_read(max_bytes):
                    nonlocal eof_calls
                    if max_bytes == 1:
                        eof_calls += 1
                        return invalid
                    return original_read(max_bytes)

                with patch.object(
                    kernel,
                    "read_stdout",
                    side_effect=invalid_eof_read,
                ):
                    with self.assertRaises(EndpointPolicyError):
                        attempt.read_result_receipt()

                self.assertEqual(eof_calls, 1)
                self.assertIsNone(attempt._ledger._issued_receipt)
                self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
                self.assertEqual(attempt.safe_metadata()["state"], "terminal")

    def test_result_eof_probe_base_exception_reads_once(self):
        pre, _, kernel = _ready([READY_FRAME, RESULT + b"\n"])
        attempt = _transfer(pre)
        _start(attempt)
        original_read = kernel.read_stdout
        eof_calls = 0

        def fail_eof_read(max_bytes):
            nonlocal eof_calls
            if max_bytes == 1:
                eof_calls += 1
                raise KeyboardInterrupt("raw EOF read")
            return original_read(max_bytes)

        with patch.object(kernel, "read_stdout", side_effect=fail_eof_read):
            with self.assertRaisesRegex(KeyboardInterrupt, "raw EOF"):
                attempt.read_result_receipt()

        self.assertEqual(eof_calls, 1)
        self.assertIsNone(attempt._ledger._issued_receipt)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")

    def test_result_requires_exact_plain_zero_exit_status(self):
        cases = (
            ("positive", 1),
            ("signal", -9),
            ("bool", True),
            ("none", None),
            ("text", "0"),
            ("float", 0.0),
        )
        for name, exit_status in cases:
            with self.subTest(name=name):
                pre, _, kernel = _ready(
                    [READY_FRAME, RESULT + b"\n"],
                    exit_status=exit_status,
                )
                attempt = _transfer(pre)
                _start(attempt)

                with self.assertRaises(EndpointPolicyError):
                    attempt.read_result_receipt()

                self.assertIsNone(attempt._ledger._issued_receipt)
                self.assertEqual(kernel.events.count("reap"), 1)
                self.assertEqual(kernel.events.count("terminate"), 0)
                self.assertEqual(kernel.events.count("close_pipes"), 1)
                counts = _cleanup_counts(kernel)
                try:
                    attempt.cleanup()
                except EndpointPolicyError:
                    pass
                self.assertEqual(_cleanup_counts(kernel), counts)

    def test_result_reap_and_close_faults_never_repeat_actions(self):
        cases = (
            ("reap", KeyboardInterrupt("raw result reap")),
            ("close_pipes", RuntimeError("raw result close")),
            ("close_pipes", KeyboardInterrupt("raw result close base")),
        )
        for action, error in cases:
            with self.subTest(action=action, error_type=type(error).__name__):
                pre, _, kernel = _ready(
                    [READY_FRAME, RESULT + b"\n"],
                    faults={action: error},
                )
                attempt = _transfer(pre)
                _start(attempt)

                with self.assertRaises(type(error)):
                    attempt.read_result_receipt()

                self.assertIsNone(attempt._ledger._issued_receipt)
                self.assertEqual(kernel.events.count("reap"), 1)
                self.assertEqual(kernel.events.count("terminate"), 0)
                self.assertEqual(kernel.events.count("close_pipes"), 1)
                counts = _cleanup_counts(kernel)
                with self.assertRaises(EndpointPolicyError):
                    attempt.cleanup()
                self.assertEqual(_cleanup_counts(kernel), counts)
                self.assertEqual(
                    attempt.safe_metadata()["state"],
                    "cleanup_failed",
                )

    def test_result_action_commit_then_raise_never_repeats_kernel_actions(self):
        for method_name in ("commit_result_reap", "commit_result_pipe_close"):
            with self.subTest(method_name=method_name):
                pre, _, kernel = _ready([READY_FRAME, RESULT + b"\n"])
                attempt = _transfer(pre)
                _start(attempt)
                ledger_type = type(attempt._ledger)
                original_commit = getattr(ledger_type, method_name)

                def commit_then_raise(instance, *args, **kwargs):
                    original_commit(instance, *args, **kwargs)
                    raise RuntimeError(f"{method_name} postcommit")

                with patch.object(
                    ledger_type,
                    method_name,
                    new=commit_then_raise,
                ):
                    with self.assertRaisesRegex(RuntimeError, "postcommit"):
                        attempt.read_result_receipt()

                self.assertIsNone(attempt._ledger._issued_receipt)
                self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
                self.assertEqual(attempt.safe_metadata()["state"], "terminal")

    def test_result_limit_excludes_lf_and_exact_limit_receives_a_receipt(self):
        transcript = b"x" * MAX_RESULT_TRANSCRIPT_BYTES
        pre, _, kernel = _ready([READY_FRAME, transcript + b"\n"])
        attempt = _transfer(pre)
        _start(attempt)

        receipt = attempt.read_result_receipt()

        self.assertEqual(receipt.raw_transcript_byte_size, 16 * 1024)
        self.assertEqual(MAX_RESULT_FRAME_BYTES, MAX_RESULT_TRANSCRIPT_BYTES + 1)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        attempt.cleanup()
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))

    def test_receipt_recomputed_after_raw_tamper_cannot_replace_ledger_snapshot(self):
        pre, _, kernel = _ready([READY_FRAME, RESULT + b"\n"])
        attempt = _transfer(pre)
        _start(attempt)
        receipt = attempt.read_result_receipt()
        altered = b'{"altered":true}'
        altered_digest = resolver_module.result_transcript_digest(altered)
        object.__setattr__(receipt, "_raw_transcript", altered)
        object.__setattr__(receipt, "raw_transcript_byte_size", len(altered))
        object.__setattr__(receipt, "raw_transcript_digest", altered_digest)
        recomputed = digest256(
            "ResolverResultReceipt",
            resolver_module.RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION,
            resolver_module._result_receipt_payload(receipt),
        )
        object.__setattr__(receipt, "receipt_digest", recomputed)
        object.__setattr__(receipt, "_issued_digest", recomputed)

        receipt.validate_integrity()
        with self.assertRaisesRegex(ValueError, "exactly issued"):
            receipt._validate_exact_issuance(
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

        self.assertTrue(attempt.cleanup())
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))

    def test_result_observer_fault_returns_no_receipt_and_cleans_owner(self):
        pre, _, kernel = _ready([READY_FRAME, RESULT + b"\n"])
        attempt = _transfer(pre)
        _start(attempt)
        returned = []

        def fail_after_commit(event, metadata):
            self.assertEqual(event, "result_attested")
            self.assertEqual(metadata["state"], "result_attested")
            raise RuntimeError("result observer fault")

        with self.assertRaisesRegex(RuntimeError, "result observer fault"):
            returned.append(attempt.read_result_receipt(observer=fail_after_commit))

        self.assertEqual(returned, [])
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        terminal_receipt = attempt._ledger._issued_receipt
        self.assertIs(type(terminal_receipt), ResolverResultReceipt)
        self.assertIs(terminal_receipt.stdout_eof, True)
        self.assertIs(terminal_receipt.child_reaped, True)
        self.assertEqual(terminal_receipt.child_exit_status, 0)
        self.assertIs(terminal_receipt.helper_pipes_closed, True)
        with self.assertRaisesRegex(ValueError, "exactly issued"):
            terminal_receipt._validate_exact_issuance(
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

    def test_cleanup_observer_raises_only_after_commit_and_resources_close(self):
        pre, _, kernel = _ready()
        observations = []

        def fail_after_commit(event, metadata):
            observations.append((event, metadata["state"]))
            raise RuntimeError("cleanup observer fault")

        with self.assertRaisesRegex(RuntimeError, "cleanup observer"):
            pre.cleanup(observer=fail_after_commit)
        self.assertEqual(observations, [("cleanup_committed", "cleaning")])
        self.assertEqual(pre.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertFalse(pre.cleanup())

    def test_cleanup_faults_are_normalized_after_all_actions(self):
        faults = {
            "terminate": RuntimeError("raw terminate"),
            "reap": KeyboardInterrupt("raw reap"),
            "close_pipes": RuntimeError("raw close"),
        }
        pre, _, kernel = _ready(faults=faults)
        with self.assertRaises(EndpointPolicyError) as raised:
            pre.cleanup()
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(pre.safe_metadata()["state"], "cleanup_failed")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        with self.assertRaises(EndpointPolicyError):
            pre.cleanup()

    def test_import_and_construction_have_zero_external_io(self):
        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("external side effect")

        kernel = _FakeKernel([READY_FRAME])
        spawner = _FakeSpawner(kernel)
        with (
            patch.object(builtins, "open", forbidden),
            patch.object(os, "fork", forbidden),
            patch.object(os, "posix_spawn", forbidden),
            patch.object(os, "getenv", forbidden),
            patch.object(socket, "getaddrinfo", forbidden),
            patch.object(socket, "socket", forbidden),
            patch.object(subprocess, "Popen", forbidden),
        ):
            imported = __import__(
                "snapquiz.transport.resolver",
                fromlist=("ResolverHelperLauncher",),
            )
            self.assertIs(imported, resolver_module)
            constructed = resolver_module.ResolverHelperLauncher(
                spawner,
                executable=EXECUTABLE,
            )
            production = resolver_module.ResolverHelperLauncher.production(
                executable=EXECUTABLE,
            )
            self.assertEqual(constructed.safe_metadata()["shell"], False)
            self.assertEqual(production.safe_metadata()["close_fds"], True)
        self.assertEqual(spawner.requests, [])

    def test_production_launcher_fails_closed_without_process_api(self):
        launcher = ResolverHelperLauncher.production(executable=EXECUTABLE)

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("process API")

        with (
            patch.object(os, "fork", forbidden),
            patch.object(os, "posix_spawn", forbidden),
            patch.object(subprocess, "Popen", forbidden),
        ):
            with self.assertRaises(ConfigError):
                launcher.launch_ready(lifecycle_id=LIFECYCLE_ID)


if __name__ == "__main__":
    unittest.main()
