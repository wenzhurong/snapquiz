"""Deterministic offline tests for the W09-B2a helper lifecycle."""
from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import ConfigError, EndpointPolicyError
import snapquiz.transport.resolver as resolver_module
from snapquiz.transport.resolver import (
    MAX_READY_FRAME_BYTES,
    MAX_RESULT_FRAME_BYTES,
    READY_FRAME,
    AttemptTerminalGuard,
    PreAttemptResolverGuard,
    ResolverHelperLauncher,
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
    b'"snapquiz.raw-resolution-transcript.v1"}'
)


class _FakeKernel:
    def __init__(self, chunks, *, faults=None) -> None:
        self.chunks = list(chunks)
        self.faults = {} if faults is None else dict(faults)
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

    def reap(self) -> None:
        self.events.append("reap")
        self._fault("reap")

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


def _launcher(chunks, *, faults=None):
    kernel = _FakeKernel(chunks, faults=faults)
    spawner = _FakeSpawner(kernel)
    return (
        ResolverHelperLauncher(spawner, executable=EXECUTABLE),
        spawner,
        kernel,
    )


def _ready(chunks=None, *, faults=None, observer=None):
    launcher, spawner, kernel = _launcher(
        [READY_FRAME] if chunks is None else chunks,
        faults=faults,
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
        self.assertEqual(attempt.read_result_frame(), RESULT)
        self.assertEqual(attempt.safe_metadata()["state"], "result_read")
        self.assertTrue(attempt.cleanup())
        self.assertFalse(attempt.cleanup())

        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(len(kernel.writes), 1)
        frame = json.loads(kernel.writes[0])
        self.assertEqual(frame["kind"], "START")
        self.assertEqual(frame["hostname"], TARGET)
        self.assertEqual(frame["port"], 443)
        self.assertEqual(frame["attempt_permit_id"], str(ATTEMPT_ID))
        self.assertEqual(frame["transport_claim_id"], str(CLAIM_ID))
        self.assertEqual(frame["dns_start_id"], str(DNS_START_ID))
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

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
                    attempt.read_result_frame()
                self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

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
