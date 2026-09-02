"""Deterministic offline tests for the W09-B2a helper lifecycle."""
from __future__ import annotations

import builtins
import copy
from datetime import timedelta
import gc
import inspect
import json
import os
import pickle
import socket
import subprocess
import unittest
from unittest.mock import patch
from uuid import UUID
import weakref

from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CancelledError, ConfigError, EndpointPolicyError
from snapquiz.privacy.egress import EgressApprovalLedger, EgressGate
from snapquiz.runtime.attempt import AttemptGate, _TRANSPORT_ATTEMPT_AUTHORITY
from snapquiz.runtime.context import CancellationReason
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger
import snapquiz.transport.resolver as resolver_module
from snapquiz.transport.resolver import (
    COMPLETE,
    HELPER_CLEANUP_POLL_QUANTUM_NS,
    HELPER_PHASE_READY,
    HELPER_PHASE_RESULT_CLOSE,
    HELPER_PHASE_RESULT_EOF,
    HELPER_PHASE_RESULT_REAP,
    HELPER_PHASE_SPAWN,
    HELPER_PHASE_START,
    MAX_READY_FRAME_BYTES,
    MAX_HELPER_CLEANUP_POLL_STEPS,
    MAX_RESULT_FRAME_BYTES,
    MAX_RESULT_TRANSCRIPT_BYTES,
    PENDING,
    READY_FRAME,
    RESOLVER_HELPER_PROTOCOL_VERSION,
    RESOLVER_HELPER_START_SCHEMA_VERSION,
    AttemptTerminalGuard,
    PreAttemptResolverGuard,
    ResolverHelperLauncher,
    ResolverResultReceipt,
    _RESOLVER_LIFECYCLE_AUTHORITY,
    start_frame_digest,
)

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime


LIFECYCLE_ID = UUID("70000000-0000-0000-0000-000000000001")
ATTEMPT_ID = UUID("70000000-0000-0000-0000-000000000002")
CLAIM_ID = UUID("70000000-0000-0000-0000-000000000003")
DNS_START_ID = UUID("70000000-0000-0000-0000-000000000004")
READY_PUBLICATION_ID = UUID("70000000-0000-0000-0000-000000000005")
ATTEMPT_DIGEST = Digest256("a" * 64)
POLICY_DIGEST = Digest256("b" * 64)
TARGET = "open.bigmodel.cn"
SECRET = "synthetic-secret-must-not-spawn"
EXECUTABLE = "/opt/snapquiz/libexec/resolver-helper"
RESULT = (
    b'{"candidates":[],"schema_version":'
    b'"snapquiz.raw-resolution-transcript.v2"}'
)


def _make_stop_authority():
    runtime = make_w09_runtime()
    approval_ledger = EgressApprovalLedger()
    approval = EgressGate().approve(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval_ledger=approval_ledger,
        preview_controller=FixedPreviewController(),
    )
    runtime.clock.advance(milliseconds=5_000)
    session_ledger = SendSessionLedger()
    session = SendSessionFactory.create(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval=approval,
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        now=NOW + timedelta(seconds=5),
    )
    gate = AttemptGate()
    credential_permit = gate.authorize_credential_resolution(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        session=session,
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        authority_ledger=runtime.authority_ledger,
        context=runtime.call_context,
        context_ledger=runtime.context_ledger,
    )
    stop_authority = gate._issue_helper_stop_authority(
        credential_permit,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    return runtime, gate, credential_permit, stop_authority


_STOP_RUNTIME, _STOP_GATE, _STOP_PERMIT, _STOP_AUTHORITY = (
    _make_stop_authority()
)


class _FakeKernel:
    def __init__(
        self,
        chunks,
        *,
        faults=None,
        exit_status: object = 0,
        poll_results=None,
        poll_hooks=None,
    ) -> None:
        self.chunks = list(chunks)
        self.faults = {} if faults is None else dict(faults)
        self.poll_results = (
            {} if poll_results is None else {
                name: list(values) for name, values in poll_results.items()
            }
        )
        self.poll_hooks = {} if poll_hooks is None else dict(poll_hooks)
        self.exit_status = exit_status
        self.read_limits: list[int] = []
        self.wait_limits: dict[str, list[int]] = {}
        self.writes: list[bytes] = []
        self.events: list[str] = []

    def _fault(self, name: str) -> None:
        selected = self.faults.get(name)
        if selected is not None:
            raise selected

    def _poll(self, name: str, default: object) -> object:
        hook = self.poll_hooks.get(name)
        if hook is not None:
            hook()
        scripted = self.poll_results.get(name)
        if scripted:
            selected = scripted.pop(0)
            if isinstance(selected, BaseException):
                raise selected
            return selected
        return default

    def _record_wait(self, name: str, max_wait_ns: int) -> None:
        self.wait_limits.setdefault(name, []).append(max_wait_ns)

    def read_stdout(self, max_bytes: int, *, max_wait_ns: int) -> object:
        self.events.append("read")
        self.read_limits.append(max_bytes)
        self._record_wait("read", max_wait_ns)
        hook = self.poll_hooks.get("read")
        if hook is not None:
            hook()
        self._fault("read")
        if not self.chunks:
            return b""
        selected = self.chunks.pop(0)
        if selected is PENDING:
            return PENDING
        if len(selected) <= max_bytes:
            return selected
        self.chunks.insert(0, selected[max_bytes:])
        return selected[:max_bytes]

    def write_stdin(self, frame: bytes, *, max_wait_ns: int) -> object:
        self.events.append("write")
        self._record_wait("write", max_wait_ns)
        if self.faults.get("write") is not None:
            # An exception is intentionally outcome-unknown.
            self.writes.append(frame)
        self._fault("write")
        result = self._poll("write", COMPLETE)
        if result is COMPLETE:
            self.writes.append(frame)
        return result

    def terminate(self, *, max_wait_ns: int) -> object:
        self.events.append("terminate")
        self._record_wait("terminate", max_wait_ns)
        self._fault("terminate")
        return self._poll("terminate", COMPLETE)

    def reap(self, *, max_wait_ns: int) -> object:
        self.events.append("reap")
        self._record_wait("reap", max_wait_ns)
        self._fault("reap")
        return self._poll("reap", self.exit_status)

    def close_pipes(self, *, max_wait_ns: int) -> object:
        self.events.append("close_pipes")
        self._record_wait("close_pipes", max_wait_ns)
        self._fault("close_pipes")
        return self._poll("close_pipes", COMPLETE)


class _FakeSpawner:
    def __init__(
        self,
        kernel: _FakeKernel,
        *,
        spawn_results=None,
        publish_on_pending: bool = False,
    ) -> None:
        self.kernel = kernel
        self.requests = []
        self.wait_limits: list[int] = []
        self.spawn_results = (
            [] if spawn_results is None else list(spawn_results)
        )
        self.publish_on_pending = publish_on_pending
        self._published = False

    def spawn(self, request, *, publication, max_wait_ns):
        self.requests.append(request)
        self.wait_limits.append(max_wait_ns)
        result = self.spawn_results.pop(0) if self.spawn_results else self.kernel
        if isinstance(result, BaseException):
            raise result
        if result is self.kernel or (result is PENDING and self.publish_on_pending):
            if not self._published:
                publication.publish(self.kernel)
                self._published = True
        return result


def _launcher(
    chunks,
    *,
    faults=None,
    exit_status: object = 0,
    poll_results=None,
    poll_hooks=None,
    spawn_results=None,
    publish_on_pending: bool = False,
):
    kernel = _FakeKernel(
        chunks,
        faults=faults,
        exit_status=exit_status,
        poll_results=poll_results,
        poll_hooks=poll_hooks,
    )
    spawner = _FakeSpawner(
        kernel,
        spawn_results=spawn_results,
        publish_on_pending=publish_on_pending,
    )
    return (
        ResolverHelperLauncher(spawner, executable=EXECUTABLE),
        spawner,
        kernel,
    )


def _reserve_lifecycle_capability(
    launcher,
    *,
    stop_authority=_STOP_AUTHORITY,
):
    reservation_owner = object()
    with patch(
        "snapquiz.transport.resolver.uuid4",
        side_effect=[
            READY_PUBLICATION_ID,
            LIFECYCLE_ID,
            CLAIM_ID,
            DNS_START_ID,
        ],
    ):
        return launcher._reserve_lifecycle_capability(
            reservation_owner=reservation_owner,
            stop_authority=stop_authority,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )


def _ready(
    chunks=None,
    *,
    faults=None,
    exit_status: object = 0,
    poll_results=None,
    poll_hooks=None,
    spawn_results=None,
    publish_on_pending: bool = False,
    stop_authority=_STOP_AUTHORITY,
):
    launcher, spawner, kernel = _launcher(
        [READY_FRAME] if chunks is None else chunks,
        faults=faults,
        exit_status=exit_status,
        poll_results=poll_results,
        poll_hooks=poll_hooks,
        spawn_results=spawn_results,
        publish_on_pending=publish_on_pending,
    )
    capability = _reserve_lifecycle_capability(
        launcher,
        stop_authority=stop_authority,
    )
    guard = launcher._launch_ready(
        capability=capability,
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    )
    if not launcher._consume_ready_publication(
        capability,
        guard,
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    ):
        raise AssertionError("READY publication was not consumed")
    return guard, spawner, kernel


def _transfer(guard):
    return guard._transfer(
        attempt_permit_id=ATTEMPT_ID,
        attempt_permit_digest=ATTEMPT_DIGEST,
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    )


def _start(guard):
    guard._start(
        hostname=TARGET,
        port=443,
        network_policy_ref="snapquiz.internet-public-address-policy.v1",
        network_policy_digest=POLICY_DIGEST,
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    )


def _read_result_receipt(guard):
    return guard._read_result_receipt(
        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
    )


def _cleanup_counts(kernel: _FakeKernel) -> tuple[int, int, int]:
    return (
        kernel.events.count("terminate"),
        kernel.events.count("reap"),
        kernel.events.count("close_pipes"),
    )


def _external_counts(spawner: _FakeSpawner, kernel: _FakeKernel):
    return (
        len(spawner.requests),
        kernel.events.count("read"),
        len(kernel.writes),
        kernel.events.count("terminate"),
        kernel.events.count("reap"),
        kernel.events.count("close_pipes"),
    )


class W09ResolverLifecycleTest(unittest.TestCase):
    def test_every_business_poll_has_fixed_pre_and_post_checkpoint_phase(self):
        phases = []
        authority_type = type(_STOP_AUTHORITY)
        original_checkpoint = authority_type._checkpoint

        def record_checkpoint(instance, phase, *, _authority=None):
            phases.append(phase)
            return original_checkpoint(
                instance,
                phase,
                _authority=_authority,
            )

        with patch.object(
            authority_type,
            "_checkpoint",
            new=record_checkpoint,
        ):
            pre, spawner, kernel = _ready([READY_FRAME, RESULT + b"\n"])
            attempt = _transfer(pre)
            _start(attempt)
            _read_result_receipt(attempt)
            self.assertTrue(attempt.cleanup())

        self.assertEqual(
            phases,
            [
                HELPER_PHASE_SPAWN,
                HELPER_PHASE_SPAWN,
                HELPER_PHASE_READY,
                HELPER_PHASE_READY,
                HELPER_PHASE_READY,
                HELPER_PHASE_READY,
                HELPER_PHASE_START,
                HELPER_PHASE_START,
                resolver_module.HELPER_PHASE_RESULT,
                resolver_module.HELPER_PHASE_RESULT,
                HELPER_PHASE_RESULT_EOF,
                HELPER_PHASE_RESULT_EOF,
                HELPER_PHASE_RESULT_REAP,
                HELPER_PHASE_RESULT_REAP,
                HELPER_PHASE_RESULT_CLOSE,
                HELPER_PHASE_RESULT_CLOSE,
            ],
        )
        self.assertEqual(len(spawner.wait_limits), 1)
        self.assertTrue(all(value > 0 for value in spawner.wait_limits))
        self.assertTrue(
            all(
                value > 0
                for values in kernel.wait_limits.values()
                for value in values
            )
        )

    def test_pending_is_distinct_from_eof_and_retries_every_business_poll(self):
        self.assertIsNot(PENDING, COMPLETE)
        self.assertIsNot(PENDING, b"")
        self.assertIs(copy.copy(PENDING), PENDING)
        self.assertIs(copy.deepcopy(PENDING), PENDING)

        for publish_on_pending in (False, True):
            with self.subTest(publish_on_pending=publish_on_pending):
                pre, spawner, kernel = _ready(
                    [
                        PENDING,
                        READY_FRAME,
                        PENDING,
                        RESULT + b"\n",
                        PENDING,
                    ],
                    poll_results={
                        "write": [PENDING, COMPLETE],
                        "reap": [PENDING, 0],
                        "close_pipes": [PENDING, COMPLETE],
                    },
                    spawn_results=[PENDING],
                    publish_on_pending=publish_on_pending,
                )
                attempt = _transfer(pre)
                _start(attempt)
                receipt = _read_result_receipt(attempt)

                self.assertIs(type(receipt), ResolverResultReceipt)
                self.assertEqual(len(spawner.requests), 2)
                self.assertEqual(len(kernel.writes), 1)
                self.assertEqual(kernel.events.count("write"), 2)
                self.assertEqual(kernel.events.count("read"), 6)
                self.assertEqual(_cleanup_counts(kernel), (0, 2, 2))
                self.assertTrue(attempt.cleanup())

    def test_cancel_after_pending_spawn_cleans_only_a_published_kernel(self):
        for publish_on_pending, expected_cleanup in (
            (False, (0, 0, 0)),
            (True, (1, 1, 1)),
        ):
            with self.subTest(publish_on_pending=publish_on_pending):
                runtime, _, _, stop_authority = _make_stop_authority()
                launcher, spawner, kernel = _launcher(
                    [READY_FRAME],
                    spawn_results=[PENDING],
                    publish_on_pending=publish_on_pending,
                )
                capability = _reserve_lifecycle_capability(
                    launcher,
                    stop_authority=stop_authority,
                )
                original_spawn = spawner.spawn

                def cancel_after_poll(*args, **kwargs):
                    result = original_spawn(*args, **kwargs)
                    runtime.cancellation_source.cancel(
                        reason=CancellationReason.USER_REQUEST
                    )
                    return result

                with patch.object(
                    spawner,
                    "spawn",
                    side_effect=cancel_after_poll,
                ):
                    with self.assertRaises(CancelledError):
                        launcher._launch_ready(
                            capability=capability,
                            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                        )

                self.assertEqual(len(spawner.requests), 1)
                self.assertEqual(kernel.events.count("read"), 0)
                self.assertEqual(_cleanup_counts(kernel), expected_cleanup)
                self.assertEqual(launcher._ready_publications, {})
                self.assertEqual(launcher._lifecycle_recovery, {})

    def test_stop_after_success_reap_or_close_pending_continues_in_cleanup(self):
        for action_name, expected_cleanup in (
            ("reap", (0, 2, 1)),
            ("close_pipes", (0, 1, 2)),
        ):
            with self.subTest(action_name=action_name):
                runtime, _, _, stop_authority = _make_stop_authority()
                fired = False

                def cancel_once():
                    nonlocal fired
                    if not fired:
                        fired = True
                        runtime.cancellation_source.cancel(
                            reason=CancellationReason.USER_REQUEST
                        )

                pre, _, kernel = _ready(
                    [READY_FRAME, RESULT + b"\n"],
                    poll_results={action_name: [PENDING]},
                    poll_hooks={action_name: cancel_once},
                    stop_authority=stop_authority,
                )
                attempt = _transfer(pre)
                _start(attempt)

                with self.assertRaises(CancelledError):
                    _read_result_receipt(attempt)

                self.assertEqual(_cleanup_counts(kernel), expected_cleanup)
                self.assertEqual(attempt.safe_metadata()["state"], "terminal")

    def test_pending_then_unknown_reap_or_close_is_never_replayed(self):
        for action_name, expected_cleanup in (
            ("reap", (0, 2, 1)),
            ("close_pipes", (0, 1, 2)),
        ):
            with self.subTest(action_name=action_name):
                pre, _, kernel = _ready(
                    [READY_FRAME, RESULT + b"\n"],
                    poll_results={
                        action_name: [
                            PENDING,
                            RuntimeError("synthetic unknown outcome"),
                        ]
                    },
                )
                attempt = _transfer(pre)
                _start(attempt)

                with self.assertRaisesRegex(RuntimeError, "unknown outcome"):
                    _read_result_receipt(attempt)

                self.assertEqual(_cleanup_counts(kernel), expected_cleanup)
                self.assertEqual(
                    attempt.safe_metadata()["state"],
                    "cleanup_failed",
                )
                counts = _cleanup_counts(kernel)
                with self.assertRaises(EndpointPolicyError):
                    attempt.cleanup()
                self.assertEqual(_cleanup_counts(kernel), counts)

    def test_cleanup_pending_exhaustion_is_bounded_without_business_checkpoint(self):
        pre, _, kernel = _ready(
            poll_results={
                "terminate": [PENDING] * MAX_HELPER_CLEANUP_POLL_STEPS,
            }
        )
        stop_state = _STOP_GATE._helper_stop_authorities[
            _STOP_AUTHORITY.authority_id
        ]
        checkpoint_sequence = stop_state.sequence

        with self.assertRaisesRegex(EndpointPolicyError, "cleanup 失败"):
            pre.cleanup()

        self.assertEqual(stop_state.sequence, checkpoint_sequence)
        self.assertEqual(
            kernel.wait_limits["terminate"],
            [HELPER_CLEANUP_POLL_QUANTUM_NS]
            * MAX_HELPER_CLEANUP_POLL_STEPS,
        )
        self.assertEqual(
            _cleanup_counts(kernel),
            (MAX_HELPER_CLEANUP_POLL_STEPS, 1, 1),
        )
        self.assertEqual(pre.safe_metadata()["state"], "cleanup_failed")

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
        receipt = _read_result_receipt(attempt)
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

    def test_spawn_publish_then_raise_cleans_anchored_kernel_and_registries(self):
        launcher, spawner, kernel = _launcher([READY_FRAME])
        capability = _reserve_lifecycle_capability(launcher)

        def publish_then_raise(request, *, publication, max_wait_ns):
            self.assertGreater(max_wait_ns, 0)
            spawner.requests.append(request)
            publication.publish(kernel)
            raise RuntimeError("synthetic spawn post-publication")

        with patch.object(spawner, "spawn", side_effect=publish_then_raise):
            with self.assertRaisesRegex(
                RuntimeError,
                "spawn post-publication",
            ):
                launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(kernel.events.count("read"), 0)
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})

    def test_spawn_return_without_publication_is_anchored_then_cleaned(self):
        launcher, spawner, kernel = _launcher([READY_FRAME])
        capability = _reserve_lifecycle_capability(launcher)

        def return_without_publication(request, *, publication, max_wait_ns):
            del publication
            self.assertGreater(max_wait_ns, 0)
            spawner.requests.append(request)
            return kernel

        with patch.object(
            spawner,
            "spawn",
            side_effect=return_without_publication,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "kernel 未在 spawn 返回前发布",
            ):
                launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(kernel.events.count("read"), 0)
        self.assertEqual(kernel.writes, [])
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})

    def test_kernel_attach_normal_noop_is_reanchored_then_rejected(self):
        launcher, spawner, kernel = _launcher([READY_FRAME])
        capability = _reserve_lifecycle_capability(launcher)

        with patch.object(
            resolver_module._ResolverLifecycleLedger,
            "attach_kernel",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "kernel publication 未提交",
            ):
                launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(kernel.events.count("read"), 0)
        self.assertEqual(kernel.writes, [])
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})

    def test_ready_ledger_normal_noop_is_rejected_before_publication(self):
        launcher, spawner, kernel = _launcher([READY_FRAME])
        capability = _reserve_lifecycle_capability(launcher)

        with patch.object(
            resolver_module._ResolverLifecycleLedger,
            "mark_ready",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "READY ledger proof 未提交",
            ):
                launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )

        self.assertEqual(len(spawner.requests), 1)
        self.assertEqual(kernel.events.count("read"), 1)
        self.assertEqual(kernel.writes, [])
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})

    def test_live_lifecycle_recovery_anchor_cannot_be_released_early(self):
        pre, _, kernel = _ready()
        launcher = pre._capability._launcher
        publication_id = pre._capability.publication_id

        with self.assertRaisesRegex(
            EndpointPolicyError,
            "只能在 terminal 后释放",
        ):
            launcher._release_lifecycle_recovery(
                publication_id,
                pre._ledger,
            )

        self.assertIn(publication_id, launcher._lifecycle_recovery)
        self.assertEqual(_cleanup_counts(kernel), (0, 0, 0))
        self.assertTrue(pre.cleanup())
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(launcher._lifecycle_recovery, {})

    def test_guards_are_factory_only(self):
        with self.assertRaisesRegex(TypeError, "require launcher"):
            PreAttemptResolverGuard(
                lifecycle_id=LIFECYCLE_ID,
                spawn_request_digest=ATTEMPT_DIGEST,
                ledger=object(),
                capability=object(),
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
                capability=object(),
            )

    def test_public_lifecycle_bypasses_are_absent_and_have_zero_side_effects(self):
        launcher, spawner, kernel = _launcher([READY_FRAME, RESULT + b"\n"])
        before = _external_counts(spawner, kernel)

        with self.assertRaises(AttributeError):
            launcher.launch_ready(lifecycle_id=LIFECYCLE_ID)  # type: ignore[attr-defined]
        self.assertEqual(_external_counts(spawner, kernel), before)

        capability = _reserve_lifecycle_capability(launcher)
        pre = launcher._launch_ready(
            capability=capability,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertTrue(
            launcher._consume_ready_publication(
                capability,
                pre,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        before = _external_counts(spawner, kernel)
        with self.assertRaises(AttributeError):
            pre.transfer(  # type: ignore[attr-defined]
                attempt_permit_id=ATTEMPT_ID,
                attempt_permit_digest=ATTEMPT_DIGEST,
            )
        self.assertEqual(_external_counts(spawner, kernel), before)

        attempt = _transfer(pre)
        before = _external_counts(spawner, kernel)
        with self.assertRaises(AttributeError):
            attempt.start(  # type: ignore[attr-defined]
                hostname=TARGET,
                port=443,
                network_policy_ref="snapquiz.internet-public-address-policy.v1",
                network_policy_digest=POLICY_DIGEST,
            )
        with self.assertRaises(AttributeError):
            attempt.read_result_receipt()  # type: ignore[attr-defined]
        self.assertEqual(_external_counts(spawner, kernel), before)
        self.assertTrue(attempt.cleanup())

    def test_private_lifecycle_entries_require_authority_before_external_io(self):
        launcher, spawner, kernel = _launcher([READY_FRAME, RESULT + b"\n"])
        before = _external_counts(spawner, kernel)
        with self.assertRaisesRegex(TypeError, "requires coordinator"):
            launcher._reserve_lifecycle_capability(
                reservation_owner=object(),
            )
        self.assertEqual(_external_counts(spawner, kernel), before)

        capability = _reserve_lifecycle_capability(launcher)
        before = _external_counts(spawner, kernel)
        with self.assertRaisesRegex(TypeError, "requires coordinator"):
            launcher._launch_ready(capability=capability)
        self.assertEqual(_external_counts(spawner, kernel), before)

        pre = launcher._launch_ready(
            capability=capability,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertTrue(
            launcher._consume_ready_publication(
                capability,
                pre,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        before = _external_counts(spawner, kernel)
        with self.assertRaisesRegex(TypeError, "requires coordinator"):
            pre._transfer(
                attempt_permit_id=ATTEMPT_ID,
                attempt_permit_digest=ATTEMPT_DIGEST,
            )
        self.assertEqual(_external_counts(spawner, kernel), before)

        attempt = _transfer(pre)
        before = _external_counts(spawner, kernel)
        with self.assertRaisesRegex(TypeError, "requires coordinator"):
            attempt._start(
                hostname=TARGET,
                port=443,
                network_policy_ref="snapquiz.internet-public-address-policy.v1",
                network_policy_digest=POLICY_DIGEST,
            )
        self.assertEqual(_external_counts(spawner, kernel), before)

        _start(attempt)
        before = _external_counts(spawner, kernel)
        with self.assertRaisesRegex(TypeError, "requires coordinator"):
            attempt._read_result_receipt()
        self.assertEqual(_external_counts(spawner, kernel), before)
        receipt = _read_result_receipt(attempt)
        self.assertEqual(receipt.lifecycle_id, LIFECYCLE_ID)
        self.assertEqual(receipt.transport_claim_id, CLAIM_ID)
        self.assertEqual(receipt.dns_start_id, DNS_START_ID)

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
                capability = _reserve_lifecycle_capability(launcher)
                with self.assertRaises(EndpointPolicyError):
                    launcher._launch_ready(
                        capability=capability,
                        _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                    )
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
            pre._transfer(
                attempt_permit_id="not-a-uuid",  # type: ignore[arg-type]
                attempt_permit_digest=ATTEMPT_DIGEST,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertEqual(pre.safe_metadata()["state"], "terminal")

    def test_transfer_exposes_no_synchronous_observer_hook(self):
        pre, _, kernel = _ready()
        self.assertNotIn(
            "observer",
            inspect.signature(PreAttemptResolverGuard._transfer).parameters,
        )
        attempt = _transfer(pre)
        self.assertEqual(attempt.safe_metadata()["state"], "transferred")
        self.assertTrue(attempt.cleanup())
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_write_fault_after_transfer_cleans_attempt_owner(self):
        pre, _, kernel = _ready(faults={"write": RuntimeError("write fault")})
        attempt = _transfer(pre)
        with self.assertRaisesRegex(RuntimeError, "write fault"):
            _start(attempt)
        self.assertEqual(len(kernel.writes), 1)
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))

    def test_start_exposes_no_synchronous_observer_hook(self):
        pre, _, kernel = _ready()
        attempt = _transfer(pre)
        self.assertNotIn(
            "observer",
            inspect.signature(AttemptTerminalGuard._start).parameters,
        )
        _start(attempt)
        self.assertEqual(attempt.safe_metadata()["state"], "started")
        self.assertEqual(len(kernel.writes), 1)
        self.assertTrue(attempt.cleanup())
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
                    _read_result_receipt(attempt)
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
            _read_result_receipt(attempt)

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
            _read_result_receipt(attempt)

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

                def invalid_eof_read(max_bytes, *, max_wait_ns):
                    nonlocal eof_calls
                    self.assertGreater(max_wait_ns, 0)
                    if max_bytes == 1:
                        eof_calls += 1
                        return invalid
                    return original_read(
                        max_bytes,
                        max_wait_ns=max_wait_ns,
                    )

                with patch.object(
                    kernel,
                    "read_stdout",
                    side_effect=invalid_eof_read,
                ):
                    with self.assertRaises(EndpointPolicyError):
                        _read_result_receipt(attempt)

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

        def fail_eof_read(max_bytes, *, max_wait_ns):
            nonlocal eof_calls
            self.assertGreater(max_wait_ns, 0)
            if max_bytes == 1:
                eof_calls += 1
                raise KeyboardInterrupt("raw EOF read")
            return original_read(max_bytes, max_wait_ns=max_wait_ns)

        with patch.object(kernel, "read_stdout", side_effect=fail_eof_read):
            with self.assertRaisesRegex(KeyboardInterrupt, "raw EOF"):
                _read_result_receipt(attempt)

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
                    _read_result_receipt(attempt)

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
                    _read_result_receipt(attempt)

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
                        _read_result_receipt(attempt)

                self.assertIsNone(attempt._ledger._issued_receipt)
                self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
                self.assertEqual(attempt.safe_metadata()["state"], "terminal")

    def test_result_limit_excludes_lf_and_exact_limit_receives_a_receipt(self):
        transcript = b"x" * MAX_RESULT_TRANSCRIPT_BYTES
        pre, _, kernel = _ready([READY_FRAME, transcript + b"\n"])
        attempt = _transfer(pre)
        _start(attempt)

        receipt = _read_result_receipt(attempt)

        self.assertEqual(receipt.raw_transcript_byte_size, 16 * 1024)
        self.assertEqual(MAX_RESULT_FRAME_BYTES, MAX_RESULT_TRANSCRIPT_BYTES + 1)
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        attempt.cleanup()
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))

    def test_receipt_recomputed_after_raw_tamper_cannot_replace_ledger_snapshot(self):
        pre, _, kernel = _ready([READY_FRAME, RESULT + b"\n"])
        attempt = _transfer(pre)
        _start(attempt)
        receipt = _read_result_receipt(attempt)
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

    def test_result_exposes_no_synchronous_observer_hook(self):
        pre, _, kernel = _ready([READY_FRAME, RESULT + b"\n"])
        attempt = _transfer(pre)
        _start(attempt)
        self.assertNotIn(
            "observer",
            inspect.signature(
                AttemptTerminalGuard._read_result_receipt
            ).parameters,
        )
        receipt = _read_result_receipt(attempt)
        self.assertEqual(attempt.safe_metadata()["state"], "result_attested")
        self.assertEqual(_cleanup_counts(kernel), (0, 1, 1))
        self.assertTrue(attempt.cleanup())
        self.assertEqual(attempt.safe_metadata()["state"], "terminal")
        with self.assertRaisesRegex(ValueError, "exactly issued"):
            receipt._validate_exact_issuance(
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

    def test_cleanup_exposes_no_synchronous_observer_hook(self):
        pre, _, kernel = _ready()
        for method in (
            ResolverHelperLauncher._launch_ready,
            PreAttemptResolverGuard.cleanup,
            AttemptTerminalGuard.cleanup,
        ):
            self.assertNotIn(
                "observer",
                inspect.signature(method).parameters,
            )
        self.assertTrue(pre.cleanup())
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

    def test_cleanup_postcommit_fault_retains_recovery_anchor_without_retry(self):
        launcher, spawner, kernel = _launcher([READY_FRAME])
        capability = _reserve_lifecycle_capability(launcher)
        launch_owner = object()
        pre = launcher._launch_ready(
            capability=capability,
            launch_owner=launch_owner,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertTrue(
            launcher._consume_ready_publication(
                capability,
                pre,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        ledger = pre._ledger
        ledger_type = type(ledger)
        original_commit = ledger_type.commit_cleanup_action
        committed_actions = []

        def commit_then_raise(instance, owner, action_name, result=None):
            original_commit(instance, owner, action_name, result)
            committed_actions.append(action_name)
            if action_name == "terminate":
                raise RuntimeError("synthetic cleanup action postcommit")

        with patch.object(
            ledger_type,
            "commit_cleanup_action",
            new=commit_then_raise,
        ):
            with self.assertRaises(EndpointPolicyError):
                pre.cleanup()

        self.assertEqual(
            committed_actions,
            ["terminate", "reap", "close_pipes"],
        )
        self.assertEqual(pre.safe_metadata()["state"], "cleanup_failed")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertTrue(ledger._terminated)
        self.assertEqual(launcher._ready_publications, {})
        self.assertIn(capability.publication_id, launcher._lifecycle_recovery)
        recovery = launcher._lifecycle_recovery[capability.publication_id]
        self.assertIs(recovery.ledger, ledger)
        self.assertIs(recovery.ledger._kernel, kernel)

        kernel_reference = weakref.ref(kernel)
        spawner.kernel = None
        del recovery, ledger, pre, kernel
        gc.collect()
        retained_kernel = kernel_reference()
        self.assertIsNotNone(retained_kernel)
        recovery = launcher._lifecycle_recovery[capability.publication_id]
        self.assertIs(recovery.ledger._kernel, retained_kernel)

        counts = _cleanup_counts(retained_kernel)
        self.assertFalse(
            launcher._recover_ready_publication_for_cleanup(
                capability,
                launch_owner=launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        self.assertEqual(_cleanup_counts(retained_kernel), counts)
        self.assertEqual(
            recovery.ledger.safe_metadata()["state"],
            "cleanup_failed",
        )
        self.assertIn(capability.publication_id, launcher._lifecycle_recovery)

    def test_finish_cleanup_normal_noop_is_retried_without_external_actions(self):
        launcher, _, kernel = _launcher([READY_FRAME])
        capability = _reserve_lifecycle_capability(launcher)
        launch_owner = object()
        pre = launcher._launch_ready(
            capability=capability,
            launch_owner=launch_owner,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        self.assertTrue(
            launcher._consume_ready_publication(
                capability,
                pre,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        ledger = pre._ledger

        with patch.object(
            type(ledger),
            "finish_cleanup",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "cleanup 失败",
            ):
                pre.cleanup()

        self.assertEqual(ledger.safe_metadata()["state"], "cleaning")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertIn(capability.publication_id, launcher._lifecycle_recovery)
        cleanup_counts = _cleanup_counts(kernel)

        self.assertTrue(
            launcher._recover_ready_publication_for_cleanup(
                capability,
                launch_owner=launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        self.assertTrue(ledger.is_terminal())
        self.assertEqual(_cleanup_counts(kernel), cleanup_counts)
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(launcher._lifecycle_recovery, {})

    def test_terminal_callback_precommit_fault_is_recovered_without_retry(self):
        launcher, _, kernel = _launcher([READY_FRAME])
        capability = _reserve_lifecycle_capability(launcher)
        launch_owner = object()
        pre = launcher._launch_ready(
            capability=capability,
            launch_owner=launch_owner,
            _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
        )
        ledger = pre._ledger
        original_release = ResolverHelperLauncher._release_lifecycle_recovery
        release_calls = []

        def fail_first_release(instance, publication_id, selected_ledger):
            release_calls.append((instance, publication_id, selected_ledger))
            if len(release_calls) == 1:
                raise RuntimeError("synthetic terminal callback precommit")
            return original_release(instance, publication_id, selected_ledger)

        with patch.object(
            ResolverHelperLauncher,
            "_release_lifecycle_recovery",
            new=fail_first_release,
        ):
            self.assertTrue(pre.cleanup())

        self.assertEqual(len(release_calls), 1)
        self.assertIs(release_calls[0][0], launcher)
        self.assertEqual(release_calls[0][1], capability.publication_id)
        self.assertIs(release_calls[0][2], ledger)
        self.assertTrue(ledger.is_terminal())
        self.assertEqual(pre.safe_metadata()["state"], "terminal")
        self.assertEqual(_cleanup_counts(kernel), (1, 1, 1))
        self.assertIn(capability.publication_id, launcher._lifecycle_recovery)
        self.assertIn(capability.publication_id, launcher._ready_publications)

        cleanup_counts = _cleanup_counts(kernel)
        self.assertTrue(
            launcher._recover_ready_publication_for_cleanup(
                capability,
                launch_owner=launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
        )
        self.assertEqual(launcher._lifecycle_recovery, {})
        self.assertEqual(launcher._ready_publications, {})
        self.assertEqual(_cleanup_counts(kernel), cleanup_counts)

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
        capability = _reserve_lifecycle_capability(launcher)

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("process API")

        with (
            patch.object(os, "fork", forbidden),
            patch.object(os, "posix_spawn", forbidden),
            patch.object(subprocess, "Popen", forbidden),
        ):
            with self.assertRaises(ConfigError):
                launcher._launch_ready(
                    capability=capability,
                    _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
                )


if __name__ == "__main__":
    unittest.main()
