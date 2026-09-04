"""Offline W09-B1 contract for frozen-binding credential resolution."""
from __future__ import annotations

import builtins
import copy
from datetime import timedelta
import os
import pickle
import socket
import sys
from threading import Barrier, Event, Lock, Thread
from types import TracebackType
import unittest
from unittest.mock import patch
from uuid import UUID, uuid5

from snapquiz.config.profiles import GLM_CREDENTIAL_REF
from snapquiz.domain.errors import (
    CancelledError,
    ConfigError,
    EndpointPolicyError,
    TimeoutError as SnapTimeoutError,
)
from snapquiz.privacy.egress import EgressApprovalLedger, EgressGate
from snapquiz.runtime.attempt import (
    AttemptGate,
    _CREDENTIAL_RESOLVER_AUTHORITY,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.runtime.context import CancellationReason
from snapquiz.transport.credentials import (
    CredentialHandle,
    CredentialResolver,
    _CredentialLedger,
    _TRANSPORT_CREDENTIAL_AUTHORITY,
)
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime
from tests.test_w09_attempt import _claim_id, _handle_proof


SESSION_ISSUED_AT = NOW + timedelta(seconds=5)
_VALID_SECRET = b"synthetic-token.ABC_123~+/=="
_TEST_TRANSPORT_CLAIM_NAMESPACE = UUID(
    "1c78dcad-5aa4-58cd-9736-b353f3a0e393"
)


class _ForbiddenEnvironment:
    def _reject(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("environment access")

    __getitem__ = _reject
    __iter__ = _reject
    __len__ = _reject
    __contains__ = _reject
    get = _reject
    keys = _reject
    items = _reject
    values = _reject


class _FakeSource:
    """Exact-locator source that exposes returned buffers only for zero checks."""

    def __init__(self, value=_VALID_SECRET) -> None:
        self.value = value
        self.calls: list[str] = []
        self.returned_buffers: list[bytearray] = []
        self._lock = Lock()

    def read_exact(self, locator: str):
        with self._lock:
            self.calls.append(locator)
        value = self.value
        if isinstance(value, BaseException):
            raise value
        if callable(value):
            value = value()
        if type(value) is bytearray:
            selected = bytearray(value)
            self.returned_buffers.append(selected)
            return selected
        if type(value) is bytes:
            return bytes(value)
        if type(value) is str:
            return value
        return value


class _BlockingSource:
    def __init__(self, value: bytes = _VALID_SECRET) -> None:
        self.entered = Event()
        self.release = Event()
        self.calls: list[str] = []
        self.buffer = bytearray(value)

    def read_exact(self, locator: str) -> bytearray:
        self.calls.append(locator)
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise AssertionError("credential source barrier timed out")
        return self.buffer


class _RaisingSource:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.calls: list[str] = []

    def read_exact(self, locator: str):
        self.calls.append(locator)
        raise self.error


class _FatalValidationError(BaseException):
    pass


def _make_runtime():
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
        now=SESSION_ISSUED_AT,
    )
    runtime.approval = approval
    runtime.approval_ledger = approval_ledger
    runtime.session = session
    runtime.session_ledger = session_ledger
    return runtime


def _authorize(runtime, gate: AttemptGate):
    return gate.authorize_credential_resolution(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        session=runtime.session,
        approval_ledger=runtime.approval_ledger,
        session_ledger=runtime.session_ledger,
        authority_ledger=runtime.authority_ledger,
        context=runtime.call_context,
        context_ledger=runtime.context_ledger,
    )


def _is_closed(handle: CredentialHandle) -> bool:
    selected = handle.is_closed
    return selected() if callable(selected) else selected


def _all_budgets(runtime):
    return (
        *runtime.call_context.operation_budgets,
        runtime.call_context.global_network_budget,
        runtime.call_context.billable_budget,
    )


def _transport_claim_id(attempt):
    return uuid5(
        _TEST_TRANSPORT_CLAIM_NAMESPACE,
        str(attempt.attempt_permit_id),
    )


class W09CredentialResolverTest(unittest.TestCase):
    def assert_zero_budget(self, runtime) -> None:
        for budget in _all_budgets(runtime):
            self.assertEqual(budget.snapshot().consumed, 0)

    def assert_terminal_resolver_failure(self, runtime, permit) -> None:
        self.assert_zero_budget(runtime)
        self.assertTrue(permit._released)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )

    def test_async_interrupts_rollback_credential_claim_and_fail(self):
        for phase in ("status_only", "owner_bound"):
            with self.subTest(operation="claim", phase=phase):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                claim_id = _claim_id(credential)
                primary = KeyboardInterrupt(f"synthetic credential claim {phase}")

                def interrupt_claim(frame, event, arg):
                    del arg
                    if (
                        event == "line"
                        and frame.f_code
                        is AttemptGate._claim_credential_resolution.__code__
                    ):
                        state = gate._credential_permits[credential.permit_id]
                        owner_matches = (
                            state.resolver_claim_id is None
                            if phase == "status_only"
                            else state.resolver_claim_id == claim_id
                        )
                        if state.status == "claiming" and owner_matches:
                            sys.settrace(None)
                            raise primary
                    return interrupt_claim

                sys.settrace(interrupt_claim)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate._claim_credential_resolution(
                            credential,
                            claim_id=claim_id,
                            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._credential_permits[credential.permit_id]
                self.assertEqual(state.status, "authorized")
                self.assertIsNone(state.resolver_claim_id)
                gate._claim_credential_resolution(
                    credential,
                    claim_id=claim_id,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
                self.assertTrue(
                    gate._fail_credential_resolution(
                        credential,
                        claim_id=claim_id,
                        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                    )
                )

        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        claim_id = _claim_id(credential)
        gate._claim_credential_resolution(
            credential,
            claim_id=claim_id,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
        primary = KeyboardInterrupt("synthetic credential fail")

        def interrupt_fail(frame, event, arg):
            del arg
            state = gate._credential_permits[credential.permit_id]
            if (
                event == "line"
                and frame.f_code
                is AttemptGate._fail_credential_resolution.__code__
                and state.status == "failing"
            ):
                sys.settrace(None)
                raise primary
            return interrupt_fail

        sys.settrace(interrupt_fail)
        try:
            with self.assertRaises(KeyboardInterrupt) as raised:
                gate._fail_credential_resolution(
                    credential,
                    claim_id=claim_id,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
        finally:
            sys.settrace(None)
        self.assertIs(raised.exception, primary)
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "resolving")
        self.assertEqual(state.resolver_claim_id, claim_id)
        self.assertTrue(
            gate._fail_credential_resolution(
                credential,
                claim_id=claim_id,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        )

    def test_async_interrupts_rollback_credential_confirmation_partial(self):
        phases = (
            "status_only",
            "binding_bound",
            "handle_bound",
            "claim_released",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                claim_id = _claim_id(credential)
                handle_id, handle_digest = _handle_proof(credential)
                gate._claim_credential_resolution(
                    credential,
                    claim_id=claim_id,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
                primary = KeyboardInterrupt(
                    f"synthetic credential confirmation {phase}"
                )

                def interrupt_confirm(frame, event, arg):
                    del arg
                    if (
                        event == "line"
                        and (
                            frame.f_code
                            is AttemptGate._confirm_credential_resolution.__code__
                            or frame.f_code.co_name == "confirm"
                        )
                    ):
                        state = gate._credential_permits[credential.permit_id]
                        phase_matches = (
                            phase == "status_only"
                            and state.resolved_binding is None
                            or phase == "binding_bound"
                            and state.resolved_binding
                            == credential.credential_binding_digest
                            and state.credential_handle_id is None
                            or phase == "handle_bound"
                            and state.credential_handle_id == handle_id
                            and state.resolved_publication_id is None
                            or phase == "claim_released"
                            and state.resolver_claim_id is None
                        )
                        if state.status == "confirming" and phase_matches:
                            sys.settrace(None)
                            raise primary
                    return interrupt_confirm

                arguments = {
                    "claim_id": claim_id,
                    "resolved_binding_digest": (
                        credential.credential_binding_digest
                    ),
                    "handle_id": handle_id,
                    "handle_digest": handle_digest,
                    "_authority": _CREDENTIAL_RESOLVER_AUTHORITY,
                }
                sys.settrace(interrupt_confirm)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate._confirm_credential_resolution(
                            credential,
                            **arguments,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._credential_permits[credential.permit_id]
                self.assertEqual(state.status, "resolving")
                self.assertEqual(state.resolver_claim_id, claim_id)
                self.assertIsNone(state.resolved_binding)
                self.assertIsNone(state.credential_handle_id)
                self.assertIsNone(state.credential_handle_digest)
                self.assertIsNone(state.resolved_publication_id)
                gate._confirm_credential_resolution(
                    credential,
                    **arguments,
                )
                self.assertTrue(
                    gate._abandon_resolved_credential_resolution(
                        credential,
                        handle_id=handle_id,
                        handle_digest=handle_digest,
                        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                    )
                )

    def test_async_interrupt_rolls_back_invalid_confirmation_failure(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        claim_id = _claim_id(credential)
        handle_id, handle_digest = _handle_proof(credential)
        gate._claim_credential_resolution(
            credential,
            claim_id=claim_id,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
        primary = KeyboardInterrupt("synthetic invalid confirmation")

        def interrupt_failure(frame, event, arg):
            del arg
            state = gate._credential_permits[credential.permit_id]
            if (
                event == "line"
                and frame.f_code
                is AttemptGate._confirm_credential_resolution.__code__
                and state.status == "failing"
            ):
                sys.settrace(None)
                raise primary
            return interrupt_failure

        sys.settrace(interrupt_failure)
        try:
            with self.assertRaises(KeyboardInterrupt) as raised:
                gate._confirm_credential_resolution(
                    credential,
                    claim_id=claim_id,
                    resolved_binding_digest=object(),
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
        finally:
            sys.settrace(None)
        self.assertIs(raised.exception, primary)
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "resolving")
        self.assertEqual(state.resolver_claim_id, claim_id)
        self.assertTrue(
            gate._fail_credential_resolution(
                credential,
                claim_id=claim_id,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        )

    def test_async_interrupts_leave_credential_cleanup_retryable(self):
        for operation in ("resolved", "claimed"):
            with self.subTest(operation=operation):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                claim_id = _claim_id(credential)
                handle_id, handle_digest = _handle_proof(credential)
                gate._claim_credential_resolution(
                    credential,
                    claim_id=claim_id,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
                if operation == "resolved":
                    gate._confirm_credential_resolution(
                        credential,
                        claim_id=claim_id,
                        resolved_binding_digest=(
                            credential.credential_binding_digest
                        ),
                        handle_id=handle_id,
                        handle_digest=handle_digest,
                        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                    )
                    transient = "abandoning"
                    target_code = (
                        AttemptGate._recover_resolved_credential_state_for_cleanup.__code__
                    )
                else:
                    transient = "failing"
                    target_code = (
                        AttemptGate._recover_claimed_credential_state_for_cleanup.__code__
                    )
                primary = KeyboardInterrupt(
                    f"synthetic {operation} credential cleanup"
                )

                def interrupt_cleanup(frame, event, arg):
                    del arg
                    state = gate._credential_permits[credential.permit_id]
                    if (
                        event == "line"
                        and frame.f_code is target_code
                        and state.status == transient
                    ):
                        sys.settrace(None)
                        raise primary
                    return interrupt_cleanup

                sys.settrace(interrupt_cleanup)
                try:
                    if operation == "resolved":
                        self.assertFalse(
                            gate._recover_resolved_credential_for_cleanup(
                                credential,
                                publication_id=claim_id,
                                handle_id=handle_id,
                                handle_digest=handle_digest,
                                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                            )
                        )
                    else:
                        self.assertFalse(
                            gate._recover_claimed_credential_for_cleanup(
                                credential,
                                claim_id=claim_id,
                                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                            )
                        )
                finally:
                    sys.settrace(None)
                state = gate._credential_permits[credential.permit_id]
                self.assertEqual(
                    state.status,
                    "resolved" if operation == "resolved" else "resolving",
                )
                if operation == "resolved":
                    self.assertTrue(
                        gate._recover_resolved_credential_for_cleanup(
                            credential,
                            publication_id=claim_id,
                            handle_id=handle_id,
                            handle_digest=handle_digest,
                            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                        )
                    )
                else:
                    self.assertTrue(
                        gate._recover_claimed_credential_for_cleanup(
                            credential,
                            claim_id=claim_id,
                            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                        )
                    )

    def test_async_interrupt_during_resolved_abandon_is_retryable(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        claim_id = _claim_id(credential)
        handle_id, handle_digest = _handle_proof(credential)
        gate._claim_credential_resolution(
            credential,
            claim_id=claim_id,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
        gate._confirm_credential_resolution(
            credential,
            claim_id=claim_id,
            resolved_binding_digest=credential.credential_binding_digest,
            handle_id=handle_id,
            handle_digest=handle_digest,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
        primary = KeyboardInterrupt("synthetic resolved abandon")

        def interrupt_abandon(frame, event, arg):
            del arg
            state = gate._credential_permits[credential.permit_id]
            if (
                event == "line"
                and frame.f_code
                is AttemptGate._abandon_resolved_credential_resolution.__code__
                and state.status == "abandoning"
            ):
                sys.settrace(None)
                raise primary
            return interrupt_abandon

        sys.settrace(interrupt_abandon)
        try:
            with self.assertRaises(KeyboardInterrupt) as raised:
                gate._abandon_resolved_credential_resolution(
                    credential,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
        finally:
            sys.settrace(None)
        self.assertIs(raised.exception, primary)
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "resolved")
        self.assertTrue(
            gate._abandon_resolved_credential_resolution(
                credential,
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        )

    def test_async_interrupts_rollback_reserve_and_attempt_abandon(self):
        for phase in ("reserving", "attempt_published"):
            with self.subTest(operation="reserve", phase=phase):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                claim_id = _claim_id(credential)
                handle_id, handle_digest = _handle_proof(credential)
                gate._claim_credential_resolution(
                    credential,
                    claim_id=claim_id,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
                gate._confirm_credential_resolution(
                    credential,
                    claim_id=claim_id,
                    resolved_binding_digest=(
                        credential.credential_binding_digest
                    ),
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
                primary = KeyboardInterrupt(f"synthetic reserve {phase}")

                def interrupt_reserve(frame, event, arg):
                    del arg
                    state = gate._credential_permits[credential.permit_id]
                    if event == "line" and state.status == "reserving":
                        phase_matches = (
                            phase == "reserving"
                            and frame.f_code.co_name == "reserve"
                            and not gate._attempt_permits
                            or phase == "attempt_published"
                            and frame.f_code.co_name == "build"
                            and bool(gate._attempt_permits)
                        )
                        if phase_matches:
                            sys.settrace(None)
                            raise primary
                    return interrupt_reserve

                sys.settrace(interrupt_reserve)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate.reserve_attempt(
                            credential_permit=credential,
                            credential_handle_id=handle_id,
                            credential_handle_digest=handle_digest,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._credential_permits[credential.permit_id]
                self.assertEqual(state.status, "resolved")
                self.assertEqual(gate._attempt_permits, {})
                attempt = gate.reserve_attempt(
                    credential_permit=credential,
                    credential_handle_id=handle_id,
                    credential_handle_digest=handle_digest,
                )
                abandon_primary = KeyboardInterrupt(
                    "synthetic attempt abandon"
                )

                def interrupt_abandon(frame, event, arg):
                    del arg
                    attempt_state = gate._attempt_permits[
                        attempt.attempt_permit_id
                    ]
                    if (
                        event == "line"
                        and frame.f_code is AttemptGate.abandon_attempt.__code__
                        and attempt_state.status == "abandoning"
                    ):
                        sys.settrace(None)
                        raise abandon_primary
                    return interrupt_abandon

                sys.settrace(interrupt_abandon)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate.abandon_attempt(
                            attempt,
                            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, abandon_primary)
                attempt_state = gate._attempt_permits[
                    attempt.attempt_permit_id
                ]
                self.assertEqual(attempt_state.status, "active")
                self.assertTrue(
                    gate.abandon_attempt(
                        attempt,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )

    def test_exact_one_read_binds_handle_proof_into_attempt(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)

        handle = resolver.resolve(credential)

        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        handle.validate_integrity()
        self.assertFalse(_is_closed(handle))
        self.assertEqual(handle.credential_permit_id, credential.permit_id)
        self.assertEqual(handle.credential_permit_digest, credential.permit_digest)
        self.assertEqual(handle.context_id, runtime.call_context.context_id)
        self.assertEqual(handle.session_id, runtime.session.session_id)
        self.assertEqual(handle.operation_id, runtime.operation.operation_id)
        self.assertEqual(
            handle.request_envelope_digest,
            runtime.prepared.request_envelope_digest,
        )
        self.assertEqual(
            handle.credential_binding_digest,
            credential.credential_binding_digest,
        )
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.credential_handle_id, handle.handle_id)
        self.assertEqual(state.credential_handle_digest, handle.handle_digest)

        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        self.assertEqual(attempt.credential_handle_id, handle.handle_id)
        self.assertEqual(attempt.credential_handle_digest, handle.handle_digest)
        attempt.validate_integrity()
        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        rendered = (
            repr(handle)
            + repr(handle.safe_metadata())
            + repr(attempt)
            + repr(attempt.safe_metadata())
        )
        self.assertNotIn(_VALID_SECRET.decode("ascii"), rendered)

        self.assertTrue(
            gate.abandon_attempt(
                attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(resolver.close(handle))
        self.assertTrue(_is_closed(handle))
        self.assertFalse(resolver.close(handle))
        handle_state = resolver._ledger._states[handle]
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        for buffer in source.returned_buffers:
            self.assertEqual(buffer, bytearray(len(buffer)))

    def test_concurrent_resolve_has_one_winner_and_one_backend_read(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        barrier = Barrier(3)
        lock = Lock()
        handles: list[CredentialHandle] = []
        errors: list[BaseException] = []

        def worker() -> None:
            barrier.wait()
            try:
                selected = resolver.resolve(credential)
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    handles.append(selected)

        threads = [Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(handles), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        self.assertTrue(resolver.close(handles[0]))
        self.assertFalse(resolver.close(handles[0]))
        self.assert_zero_budget(runtime)

    def test_credential_claim_normal_noop_never_reads_secret(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "credential claim transaction 未提交",
            ):
                resolver.resolve(credential)

        self.assertEqual(source.calls, [])
        self.assertEqual(source.returned_buffers, [])
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "authorized")
        self.assertIsNone(state.resolver_claim_id)
        self.assertTrue(gate.abandon_credential_resolution(credential))
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_credential_claim_wrapper_normal_noop_never_reads_secret(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)

        with patch.object(
            AttemptGate,
            "_claim_credential_resolution",
            return_value=credential,
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver.resolve(credential)

        self.assertEqual(source.calls, [])
        self.assertEqual(source.returned_buffers, [])
        self.assertEqual(resolver._ledger._states, {})
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "authorized")
        self.assertIsNone(state.resolver_claim_id)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 1)
        self.assertTrue(gate.abandon_credential_resolution(credential))
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_claim_commit_then_raise_recovery_noop_uses_state_path(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        original_claim = AttemptGate._claim_credential_resolution

        def claim_then_raise(selected, *args, **kwargs):
            original_claim(selected, *args, **kwargs)
            raise _FatalValidationError("synthetic post-claim failure")

        with (
            patch.object(
                AttemptGate,
                "_claim_credential_resolution",
                new=claim_then_raise,
            ),
            patch.object(
                AttemptGate,
                "_recover_claimed_credential_for_cleanup",
                return_value=True,
            ) as recovery,
        ):
            with self.assertRaisesRegex(
                _FatalValidationError,
                "post-claim",
            ):
                resolver.resolve(credential)

        self.assertEqual(recovery.call_count, 2)
        self.assertEqual(source.calls, [])
        self.assertEqual(source.returned_buffers, [])
        self.assertEqual(resolver._ledger._states, {})
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "abandoned")
        self.assertIsNone(state.resolver_claim_id)
        self.assertIsNone(state.resolved_publication_id)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_attempt_cannot_reserve_before_resolve_publishes_handle_proof(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        entered = Event()
        release = Event()
        errors: list[BaseException] = []
        handles: list[CredentialHandle] = []
        original_confirm = AttemptGate._confirm_credential_resolution

        def confirm_then_pause(selected, *args, **kwargs):
            original_confirm(selected, *args, **kwargs)
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("confirmation barrier timed out")
            raise _FatalValidationError("synthetic post-confirm failure")

        def resolve_worker() -> None:
            try:
                handles.append(resolver.resolve(credential))
            except BaseException as error:
                errors.append(error)

        with patch.object(
            AttemptGate,
            "_confirm_credential_resolution",
            new=confirm_then_pause,
        ):
            thread = Thread(target=resolve_worker)
            thread.start()
            self.assertTrue(entered.wait(timeout=5))
            with self.assertRaises(TypeError):
                gate.reserve_attempt(credential_permit=credential)  # type: ignore[call-arg]
            self.assertEqual(gate.safe_metadata()["attempt_permit_count"], 0)
            self.assert_zero_budget(runtime)
            release.set()
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(handles, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], _FatalValidationError)
        self.assert_terminal_resolver_failure(runtime, credential)
        self.assertEqual(source.returned_buffers[0], bytearray())
        self.assertFalse(
            any(
                handle_state.permit is credential
                for handle_state in resolver._ledger._states.values()
            )
        )

    def test_attempt_reservation_rejects_wrong_typed_handle_proof(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        wrong_id = runtime.call_context.context_id
        wrong_digest = credential.permit_digest
        self.assertNotEqual(wrong_id, handle.handle_id)
        self.assertNotEqual(wrong_digest, handle.handle_digest)

        for handle_id, handle_digest in (
            (wrong_id, handle.handle_digest),
            (handle.handle_id, wrong_digest),
        ):
            with self.subTest(
                wrong_id=handle_id != handle.handle_id,
                wrong_digest=handle_digest != handle.handle_digest,
            ):
                with self.assertRaises(EndpointPolicyError):
                    gate.reserve_attempt(
                        credential_permit=credential,
                        credential_handle_id=handle_id,
                        credential_handle_digest=handle_digest,
                    )
                self.assert_zero_budget(runtime)
                self.assertEqual(
                    gate.safe_metadata()["attempt_permit_count"],
                    0,
                )

        self.assertTrue(resolver.close(handle))

    def test_bearer_accepts_exact_ascii_boundaries_without_normalization(self):
        accepted = (
            b"A",
            b"AZaz09-._~+/",
            b"abc=",
            b"abc====",
            b"A" * 4096,
        )
        for value in accepted:
            with self.subTest(length=len(value), tail=value[-8:]):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                source = _FakeSource(bytearray(value))
                resolver = CredentialResolver(source)
                handle = resolver.resolve(credential)
                self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
                self.assertFalse(_is_closed(handle))
                self.assertTrue(resolver.close(handle))
                self.assertTrue(_is_closed(handle))
                self.assert_zero_budget(runtime)

    def test_bearer_rejects_invalid_bytes_and_zeroizes_temporary_buffer(self):
        rejected = (
            b"",
            b"A" * 4097,
            b" token",
            b"token ",
            b"to ken",
            b"token\r",
            b"token\n",
            b"token\x00",
            b"token\x1f",
            b"token\x7f",
            b"token\x80",
            b"====",
            b"a=b",
            b"token:",
        )
        for value in rejected:
            with self.subTest(length=len(value), value=value[:16]):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                source = _FakeSource(bytearray(value))
                resolver = CredentialResolver(source)
                with self.assertRaises(ConfigError) as raised:
                    resolver.resolve(credential)
                self.assertEqual(raised.exception.stage, "credential_resolver")
                self.assertFalse(raised.exception.retryable)
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)
                self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
                for buffer in source.returned_buffers:
                    self.assertEqual(buffer, bytearray(len(buffer)))
                self.assert_terminal_resolver_failure(runtime, credential)

    def test_source_error_is_sanitized_without_cause_context_or_secret(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        secret_sentinel = "synthetic-token-MUST-NOT-LEAK"
        source = _RaisingSource(RuntimeError(secret_sentinel))
        resolver = CredentialResolver(source)

        with self.assertRaises(ConfigError) as raised:
            resolver.resolve(credential)

        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        self.assertEqual(raised.exception.stage, "credential_resolver")
        self.assertFalse(raised.exception.retryable)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(secret_sentinel, str(raised.exception))
        self.assertNotIn(secret_sentinel, repr(raised.exception))
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_typed_source_error_drops_raw_context_and_traceback(self):
        sentinel = "synthetic-secret-source-context"

        class ContextualSource:
            def read_exact(self, locator: str):
                del locator
                try:
                    raise RuntimeError(sentinel)
                except RuntimeError:
                    raise CancelledError(stage="credential_resolver")

        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)

        with self.assertRaises(CancelledError) as raised:
            CredentialResolver(ContextualSource()).resolve(credential)

        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_typed_source_error_public_frames_do_not_retain_source_traceback(self):
        sentinel = "synthetic-secret-traceback-local"

        class TracebackSource:
            def read_exact(self, locator: str):
                del locator
                secret_local = sentinel
                if secret_local:
                    raise CancelledError(stage="credential_resolver")
                raise AssertionError("unreachable")

        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(TracebackSource())

        try:
            resolver.resolve(credential)
        except CancelledError as error:
            frame_names: list[str] = []
            resolver_frames = []
            traceback = error.__traceback__
            while traceback is not None:
                frame = traceback.tb_frame
                name = frame.f_code.co_name
                frame_names.append(name)
                if name in ("resolve", "_raise_resolver_primary"):
                    resolver_frames.append(frame)
                traceback = traceback.tb_next

            self.assertNotIn("read_exact", frame_names)
            self.assertEqual(
                {frame.f_code.co_name for frame in resolver_frames},
                {"resolve", "_raise_resolver_primary"},
            )
            for frame in resolver_frames:
                leaked_tracebacks = {
                    name: value
                    for name, value in frame.f_locals.items()
                    if isinstance(value, TracebackType)
                }
                self.assertEqual(leaked_tracebacks, {})
                self.assertNotIn(sentinel, repr(frame.f_locals))
        else:
            self.fail("resolver did not preserve typed cancellation")

        self.assert_terminal_resolver_failure(runtime, credential)

    def test_source_requires_a_fresh_mutable_buffer(self):
        invalid_values = (
            _VALID_SECRET,
            _VALID_SECRET.decode("ascii"),
            memoryview(_VALID_SECRET),
            None,
        )
        for value in invalid_values:
            with self.subTest(source_type=type(value).__name__):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                source = _FakeSource(value)
                resolver = CredentialResolver(source)
                with self.assertRaises(ConfigError) as raised:
                    resolver.resolve(credential)
                self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
                self.assertEqual(raised.exception.stage, "credential_resolver")
                self.assertFalse(raised.exception.retryable)
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)
                self.assert_terminal_resolver_failure(runtime, credential)

    def test_handle_is_factory_only_immutable_noncopyable_and_secret_safe(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        handle = resolver.resolve(credential)
        sentinel = _VALID_SECRET.decode("ascii")

        rendered = repr(handle) + repr(handle.safe_metadata())
        self.assertNotIn(sentinel, rendered)
        self.assertNotIn(sentinel, str(handle.handle_id))
        self.assertNotIn(sentinel, str(handle.handle_digest))
        for forbidden in (
            "secret",
            "token",
            "value",
            "header_value",
            "authorization",
        ):
            self.assertFalse(hasattr(handle, forbidden), forbidden)
        with self.assertRaises(AttributeError):
            handle.session_id = runtime.call_context.context_id  # type: ignore[misc]
        with self.assertRaises(TypeError):
            copy.copy(handle)
        with self.assertRaises(TypeError):
            copy.deepcopy(handle)
        with self.assertRaises((TypeError, pickle.PicklingError)):
            pickle.dumps(handle)
        with self.assertRaises(TypeError):
            CredentialHandle()  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            class _DerivedHandle(CredentialHandle):
                pass

        self.assertTrue(resolver.close(handle))

    def test_transport_borrow_is_readonly_one_shot_and_zeroizes(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        gate._claim_attempt(
            attempt,
            claim_id=_transport_claim_id(attempt),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        retained_views: list[memoryview] = []

        def consume(view: memoryview) -> str:
            self.assertTrue(view.readonly)
            self.assertEqual(bytes(view), _VALID_SECRET)
            with self.assertRaises(TypeError):
                view[0] = 0  # type: ignore[index]
            retained_views.append(view)
            return "consumed"

        self.assertEqual(
            resolver._borrow_once(
                handle,
                attempt,
                consume,
                _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
            ),
            "consumed",
        )
        self.assertTrue(_is_closed(handle))
        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertEqual(source.returned_buffers[0], bytearray())
        with self.assertRaises(ValueError):
            retained_views[0].tobytes()
        with self.assertRaises(EndpointPolicyError):
            resolver._borrow_once(
                handle,
                attempt,
                lambda view: bytes(view),
                _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
            )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_transport_borrow_owner_is_exact_and_only_active_in_callback(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        claim_id = _transport_claim_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        observed: list[UUID] = []

        def consume(view: memoryview, borrow_id: UUID) -> str:
            self.assertTrue(view.readonly)
            self.assertEqual(bytes(view), _VALID_SECRET)
            self.assertIs(type(borrow_id), UUID)
            self.assertTrue(
                gate._credential_borrow_is_active(
                    attempt,
                    borrow_id=borrow_id,
                    handle_id=handle.handle_id,
                    handle_digest=handle.handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            observed.append(borrow_id)
            return "consumed"

        self.assertEqual(
            resolver._borrow_once_with_owner(
                handle,
                attempt,
                consume,
                _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
            ),
            "consumed",
        )
        self.assertEqual(len(observed), 1)
        self.assertFalse(
            gate._credential_borrow_is_active(
                attempt,
                borrow_id=observed[0],
                handle_id=handle.handle_id,
                handle_digest=handle.handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(_is_closed(handle))
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_async_interrupt_at_borrow_transition_detaches_and_zeros_secret(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        claim_id = _transport_claim_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        callback_called = False
        primary = KeyboardInterrupt("synthetic borrow transition")

        def consume(view: memoryview, borrow_id: UUID) -> None:
            nonlocal callback_called
            del view, borrow_id
            callback_called = True

        def interrupt_transition(frame, event, arg):
            del arg
            if (
                event == "line"
                and frame.f_code.co_name == "borrow_secret"
            ):
                local_secret = frame.f_locals.get("secret")
                state = resolver._ledger._states[handle]
                if (
                    local_secret is state.secret
                    and type(local_secret) is bytearray
                    and state.status == "active"
                ):
                    sys.settrace(None)
                    raise primary
            return interrupt_transition

        sys.settrace(interrupt_transition)
        try:
            with self.assertRaises(KeyboardInterrupt) as raised:
                resolver._borrow_once_with_owner(
                    handle,
                    attempt,
                    consume,
                    _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
                )
        finally:
            sys.settrace(None)

        self.assertIs(raised.exception, primary)
        self.assertFalse(callback_called)
        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertEqual(source.returned_buffers, [bytearray()])
        attempt_state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertIsNone(attempt_state.credential_borrow_id)
        traceback = raised.exception.__traceback__
        while traceback is not None:
            for value in traceback.tb_frame.f_locals.values():
                if type(value) is bytearray:
                    self.assertFalse(any(value))
                elif type(value) is memoryview:
                    try:
                        retained = value.tobytes()
                    except ValueError:
                        continue
                    self.assertFalse(any(retained))
            traceback = traceback.tb_next
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_consumed_handle_rejects_resolver_close_until_attempt_terminal(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )

        with self.assertRaises(EndpointPolicyError):
            resolver.close(handle)
        self.assertFalse(_is_closed(handle))
        self.assertIsNotNone(resolver._ledger._states[handle].secret)
        with self.assertRaises(TypeError):
            gate.abandon_attempt(attempt)

        self.assertTrue(
            gate.abandon_attempt(
                attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(resolver.close(handle))
        self.assertTrue(_is_closed(handle))
        self.assertFalse(resolver.close(handle))

    def test_concurrent_close_rejects_in_progress_then_allows_retry(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        entered = Event()
        release = Event()
        errors: list[BaseException] = []

        def fail_before_gate_commit(selected, *args, **kwargs):
            del selected, args, kwargs
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("close barrier timed out")
            raise _FatalValidationError("synthetic close precommit failure")

        def close_worker() -> None:
            try:
                resolver.close(handle)
            except BaseException as error:
                errors.append(error)

        with patch.object(
            AttemptGate,
            "_abandon_resolved_credential_resolution",
            new=fail_before_gate_commit,
        ):
            thread = Thread(target=close_worker)
            thread.start()
            self.assertTrue(entered.wait(timeout=5))
            with self.assertRaises(EndpointPolicyError):
                resolver.close(handle)
            release.set()
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], _FatalValidationError)
        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "active")
        self.assertIsNotNone(state.secret)
        self.assertFalse(_is_closed(handle))
        self.assertTrue(resolver.close(handle))
        self.assertTrue(_is_closed(handle))
        self.assertFalse(resolver.close(handle))

    def test_borrow_base_exception_still_closes_view_and_zeroizes(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        gate._claim_attempt(
            attempt,
            claim_id=_transport_claim_id(attempt),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        retained: list[memoryview] = []

        def fail(view: memoryview) -> None:
            retained.append(view)
            raise _FatalValidationError("synthetic callback failure")

        with self.assertRaises(_FatalValidationError):
            resolver._borrow_once(
                handle,
                attempt,
                fail,
                _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
            )
        self.assertTrue(_is_closed(handle))
        self.assertIsNone(resolver._ledger._states[handle].secret)
        with self.assertRaises(ValueError):
            retained[0].tobytes()
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_active_borrow_blocks_attempt_finish_and_second_borrow_owner(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        gate._claim_attempt(
            attempt,
            claim_id=_transport_claim_id(attempt),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        entered = Event()
        release = Event()
        results: list[bytes] = []
        errors: list[BaseException] = []

        def blocked(view: memoryview) -> bytes:
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("borrow barrier timed out")
            return bytes(view)

        def worker() -> None:
            try:
                results.append(
                    resolver._borrow_once(
                        handle,
                        attempt,
                        blocked,
                        _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
                    )
                )
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=worker)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        first_borrow_id = gate._attempt_permits[
            attempt.attempt_permit_id
        ].credential_borrow_id
        self.assertIsNotNone(first_borrow_id)
        with self.assertRaises(EndpointPolicyError):
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        with self.assertRaises(EndpointPolicyError):
            resolver._borrow_once(
                handle,
                attempt,
                lambda view: bytes(view),
                _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
            )
        self.assertEqual(
            gate._attempt_permits[
                attempt.attempt_permit_id
            ].credential_borrow_id,
            first_borrow_id,
        )
        release.set()
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [_VALID_SECRET])
        self.assertIsNone(
            gate._attempt_permits[
                attempt.attempt_permit_id
            ].credential_borrow_id
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_borrow_begin_commit_then_raise_releases_only_its_marker(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        gate._claim_attempt(
            attempt,
            claim_id=_transport_claim_id(attempt),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        original_begin = AttemptGate._begin_credential_borrow

        def begin_then_raise(selected, *args, **kwargs):
            original_begin(selected, *args, **kwargs)
            raise _FatalValidationError("synthetic post-begin failure")

        with patch.object(
            AttemptGate,
            "_begin_credential_borrow",
            new=begin_then_raise,
        ):
            with self.assertRaisesRegex(_FatalValidationError, "post-begin"):
                resolver._borrow_once(
                    handle,
                    attempt,
                    lambda view: bytes(view),
                    _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
                )

        self.assertIsNone(
            gate._attempt_permits[
                attempt.attempt_permit_id
            ].credential_borrow_id
        )
        self.assertEqual(
            resolver._borrow_once(
                handle,
                attempt,
                lambda view: bytes(view),
                _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
            ),
            _VALID_SECRET,
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_borrow_begin_normal_noop_never_exposes_secret(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        gate._claim_attempt(
            attempt,
            claim_id=_transport_claim_id(attempt),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        action_calls = []

        with patch.object(
            AttemptGate,
            "_begin_credential_borrow",
            return_value=None,
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver._borrow_once(
                    handle,
                    attempt,
                    lambda view: action_calls.append(bytes(view)),
                    _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
                )

        self.assertEqual(action_calls, [])
        self.assertFalse(_is_closed(handle))
        self.assertIsNone(
            gate._attempt_permits[
                attempt.attempt_permit_id
            ].credential_borrow_id
        )
        self.assertEqual(
            resolver._borrow_once(
                handle,
                attempt,
                lambda view: bytes(view),
                _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
            ),
            _VALID_SECRET,
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_borrow_finish_normal_noop_uses_force_and_observer(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        gate._claim_attempt(
            attempt,
            claim_id=_transport_claim_id(attempt),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )

        with patch.object(
            AttemptGate,
            "_finish_credential_borrow",
            return_value=None,
        ) as finish:
            self.assertEqual(
                resolver._borrow_once(
                    handle,
                    attempt,
                    lambda view: bytes(view),
                    _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
                ),
                _VALID_SECRET,
            )

        self.assertEqual(finish.call_count, 2)
        self.assertTrue(_is_closed(handle))
        self.assertIsNone(resolver._ledger._states[handle].secret)
        self.assertIsNone(
            gate._attempt_permits[
                attempt.attempt_permit_id
            ].credential_borrow_id
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_borrow_finish_faults_release_marker_after_secret_is_closed(self):
        original_finish = AttemptGate._finish_credential_borrow

        for mode in ("precommit_once", "postcommit_once", "precommit_twice"):
            with self.subTest(mode=mode):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                resolver = CredentialResolver(
                    _FakeSource(bytearray(_VALID_SECRET))
                )
                handle = resolver.resolve(credential)
                attempt = gate.reserve_attempt(
                    credential_permit=credential,
                    credential_handle_id=handle.handle_id,
                    credential_handle_digest=handle.handle_digest,
                )
                gate._claim_attempt(
                    attempt,
                    claim_id=_transport_claim_id(attempt),
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
                finish_calls = 0

                def injected_finish(selected, *args, **kwargs):
                    nonlocal finish_calls
                    finish_calls += 1
                    if mode == "precommit_once" and finish_calls == 1:
                        raise _FatalValidationError("synthetic precommit")
                    if mode == "precommit_twice" and finish_calls <= 2:
                        raise _FatalValidationError("synthetic precommit")
                    result = original_finish(selected, *args, **kwargs)
                    if mode == "postcommit_once" and finish_calls == 1:
                        raise _FatalValidationError("synthetic postcommit")
                    return result

                with patch.object(
                    AttemptGate,
                    "_finish_credential_borrow",
                    new=injected_finish,
                ):
                    self.assertEqual(
                        resolver._borrow_once(
                            handle,
                            attempt,
                            lambda view: bytes(view),
                            _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
                        ),
                        _VALID_SECRET,
                    )

                self.assertEqual(
                    finish_calls,
                    1 if mode == "postcommit_once" else 2,
                )
                self.assertTrue(_is_closed(handle))
                self.assertIsNone(resolver._ledger._states[handle].secret)
                self.assertIsNone(
                    gate._attempt_permits[
                        attempt.attempt_permit_id
                    ].credential_borrow_id
                )
                self.assertTrue(
                    gate.finish_attempt(
                        attempt,
                        claim_id=_transport_claim_id(attempt),
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )

    def test_close_cleanup_faults_do_not_replace_gate_primary(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        primary = _FatalValidationError("synthetic Gate primary")
        cleanup = RuntimeError("synthetic restore cleanup")

        with patch.object(
            AttemptGate,
            "_abandon_resolved_credential_resolution",
            side_effect=primary,
        ), patch.object(
            _CredentialLedger,
            "_restore_active_after_gate_failure",
            side_effect=cleanup,
        ):
            with self.assertRaises(_FatalValidationError) as raised:
                resolver.close(handle)
        self.assertIs(raised.exception, primary)
        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "active")
        self.assertEqual(bytes(state.secret), _VALID_SECRET)
        self.assertTrue(resolver.close(handle))

    def test_async_interrupt_around_close_claim_is_recovered_exactly(self):
        for phase in ("after_claim", "after_gate"):
            with self.subTest(phase=phase):
                runtime = _make_runtime()
                gate = AttemptGate()
                credential = _authorize(runtime, gate)
                source = _FakeSource(bytearray(_VALID_SECRET))
                resolver = CredentialResolver(source)
                handle = resolver.resolve(credential)
                primary = KeyboardInterrupt(f"synthetic close {phase}")

                def interrupt_close(frame, event, arg):
                    del arg
                    state = resolver._ledger._states[handle]
                    gate_state = gate._credential_permits[credential.permit_id]
                    target_matches = (
                        phase == "after_claim"
                        and frame.f_code is _CredentialLedger._release_info.__code__
                        and gate_state.status == "resolved"
                        or phase == "after_gate"
                        and frame.f_code
                        is CredentialResolver._close_claimed.__code__
                        and gate_state.status
                        in ("abandoned", "finished")
                    )
                    if (
                        event == "line"
                        and state.status == "closing"
                        and target_matches
                    ):
                        sys.settrace(None)
                        raise primary
                    return interrupt_close

                sys.settrace(interrupt_close)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        resolver.close(handle)
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = resolver._ledger._states[handle]
                if phase == "after_claim":
                    self.assertEqual(state.status, "active")
                    self.assertEqual(bytes(state.secret), _VALID_SECRET)
                    self.assertTrue(resolver.close(handle))
                else:
                    self.assertEqual(state.status, "closed")
                    self.assertIsNone(state.secret)
                    self.assertEqual(source.returned_buffers, [bytearray()])

    def test_close_force_fault_does_not_replace_postcommit_gate_primary(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        handle = resolver.resolve(credential)
        primary = _FatalValidationError("synthetic Gate postcommit primary")
        cleanup = RuntimeError("synthetic force-close cleanup")
        original = AttemptGate._abandon_resolved_credential_resolution

        def commit_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise primary

        with patch.object(
            AttemptGate,
            "_abandon_resolved_credential_resolution",
            new=commit_then_raise,
        ), patch.object(
            _CredentialLedger,
            "_force_close_after_gate",
            side_effect=cleanup,
        ):
            with self.assertRaises(_FatalValidationError) as raised:
                resolver.close(handle)
        self.assertIs(raised.exception, primary)
        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertEqual(source.returned_buffers, [bytearray()])

    def test_borrow_cleanup_faults_do_not_replace_callback_primary(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        handle = resolver.resolve(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        claim_id = _transport_claim_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        primary = _FatalValidationError("synthetic callback primary")
        cleanup = RuntimeError("synthetic borrow cleanup")

        def fail(_view):
            raise primary

        with patch.object(
            _CredentialLedger,
            "_finish_borrow",
            side_effect=cleanup,
        ), patch.object(
            _CredentialLedger,
            "_force_finish_borrow",
            side_effect=cleanup,
        ), patch.object(
            AttemptGate,
            "_finish_credential_borrow",
            side_effect=cleanup,
        ), patch.object(
            AttemptGate,
            "_force_finish_credential_borrow",
            side_effect=cleanup,
        ):
            with self.assertRaises(_FatalValidationError) as raised:
                resolver._borrow_once(
                    handle,
                    attempt,
                    fail,
                    _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
                )
        self.assertIs(raised.exception, primary)
        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "closed")
        self.assertIsNone(state.secret)
        self.assertEqual(source.returned_buffers, [bytearray()])
        attempt_state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertIsNone(attempt_state.credential_borrow_id)
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_wrong_resolver_and_slot_clone_cannot_close_exact_handle(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))
        handle = resolver.resolve(credential)
        wrong_resolver = CredentialResolver(_FakeSource(bytearray(_VALID_SECRET)))

        with self.assertRaises(EndpointPolicyError):
            wrong_resolver.close(handle)
        clone = object.__new__(CredentialHandle)
        for name in CredentialHandle.__slots__:
            object.__setattr__(clone, name, getattr(handle, name))
        with self.assertRaises(EndpointPolicyError):
            resolver.close(clone)
        self.assertFalse(_is_closed(handle))
        self.assertTrue(resolver.close(handle))

    def test_close_gate_normal_noop_restores_active_handle(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        handle = resolver.resolve(credential)

        with patch.object(
            AttemptGate,
            "_abandon_resolved_credential_resolution",
            return_value=None,
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver.close(handle)

        state = resolver._ledger._states[handle]
        self.assertEqual(state.status, "active")
        self.assertEqual(bytes(state.secret), _VALID_SECRET)
        credential_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(credential_state.status, "resolved")
        self.assertEqual(gate.safe_metadata()["active_session_count"], 1)
        self.assertFalse(_is_closed(handle))

        self.assertTrue(resolver.close(handle))
        self.assertTrue(_is_closed(handle))
        self.assertIsNone(state.secret)
        self.assertEqual(source.returned_buffers, [bytearray()])
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_validation_base_exception_zeroizes_source_and_gate_activity(self):
        class FatalPattern:
            @staticmethod
            def fullmatch(value):
                del value
                raise _FatalValidationError("synthetic validation failure")

        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _BlockingSource()
        source.release.set()
        resolver = CredentialResolver(source)

        with patch(
            "snapquiz.transport.credentials._B64TOKEN_RE",
            FatalPattern(),
        ):
            with self.assertRaises(_FatalValidationError):
                resolver.resolve(credential)

        self.assertEqual(source.buffer, bytearray())
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_resolver_retries_one_precommit_failure_cleanup(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(b"bad token"))
        resolver = CredentialResolver(source)
        original_fail = (
            AttemptGate._recover_claimed_credential_for_cleanup
        )
        fail_calls = 0

        def fail_once(selected, *args, **kwargs):
            nonlocal fail_calls
            fail_calls += 1
            if fail_calls == 1:
                raise _FatalValidationError("synthetic precommit failure")
            return original_fail(selected, *args, **kwargs)

        with patch.object(
            AttemptGate,
            "_recover_claimed_credential_for_cleanup",
            new=fail_once,
        ):
            with self.assertRaises(ConfigError):
                resolver.resolve(credential)

        self.assertEqual(fail_calls, 2)
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "abandoned")
        self.assertIsNone(state.resolver_claim_id)
        self.assert_terminal_resolver_failure(runtime, credential)
        self.assertFalse(
            any(
                handle_state.permit is credential
                for handle_state in resolver._ledger._states.values()
            )
        )

    def test_confirm_commit_then_abandon_retry_discards_unpublished_secret(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        original_confirm = AttemptGate._confirm_credential_resolution
        original_abandon = (
            AttemptGate._recover_resolved_credential_for_cleanup
        )
        abandon_calls = 0

        def confirm_then_raise(selected, *args, **kwargs):
            original_confirm(selected, *args, **kwargs)
            raise _FatalValidationError("synthetic post-confirm failure")

        def abandon_once(selected, *args, **kwargs):
            nonlocal abandon_calls
            abandon_calls += 1
            if abandon_calls == 1:
                raise _FatalValidationError("synthetic pre-abandon failure")
            return original_abandon(selected, *args, **kwargs)

        with (
            patch.object(
                AttemptGate,
                "_confirm_credential_resolution",
                new=confirm_then_raise,
            ),
            patch.object(
                AttemptGate,
                "_recover_resolved_credential_for_cleanup",
                new=abandon_once,
            ),
        ):
            with self.assertRaisesRegex(
                _FatalValidationError,
                "post-confirm",
            ):
                resolver.resolve(credential)

        self.assertEqual(abandon_calls, 2)
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "abandoned")
        self.assertIsNone(state.resolver_claim_id)
        self.assert_terminal_resolver_failure(runtime, credential)
        self.assertFalse(
            any(
                handle_state.permit is credential
                for handle_state in resolver._ledger._states.values()
            )
        )
        for buffer in source.returned_buffers:
            self.assertEqual(buffer, bytearray())

    def test_confirm_noop_fails_closed_and_discards_real_handle_secret(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        original_issue = _CredentialLedger._issue
        issued: list[tuple[CredentialHandle, object, bytearray]] = []

        def capture_issue(selected, *args, **kwargs):
            handle = original_issue(selected, *args, **kwargs)
            state = selected._states[handle]
            issued.append((handle, state, state.secret))
            return handle

        def no_op_confirm(*args, **kwargs):
            del args, kwargs

        with (
            patch.object(_CredentialLedger, "_issue", new=capture_issue),
            patch.object(
                AttemptGate,
                "_confirm_credential_resolution",
                new=no_op_confirm,
            ),
            patch.object(socket, "getaddrinfo") as getaddrinfo,
            patch.object(socket, "socket") as socket_factory,
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver.resolve(credential)

        self.assertEqual(len(issued), 1)
        handle, handle_state, secret = issued[0]
        self.assertNotIn(handle, resolver._ledger._states)
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertIsNone(handle_state.permit)
        self.assertIsNone(handle_state.gate)
        self.assertIsNone(handle_state.publication_id)
        self.assertEqual(secret, bytearray())
        self.assertEqual(source.returned_buffers, [bytearray()])
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "abandoned")
        self.assertIsNone(state.resolver_claim_id)
        self.assertIsNone(state.resolved_publication_id)
        self.assertEqual(gate._attempt_permits, {})
        self.assert_terminal_resolver_failure(runtime, credential)
        getaddrinfo.assert_not_called()
        socket_factory.assert_not_called()

    def test_attestation_failure_recovery_noop_uses_state_path(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        original_issue = _CredentialLedger._issue
        issued: list[tuple[CredentialHandle, object, bytearray]] = []

        def capture_issue(selected, *args, **kwargs):
            handle = original_issue(selected, *args, **kwargs)
            state = selected._states[handle]
            issued.append((handle, state, state.secret))
            return handle

        with (
            patch.object(_CredentialLedger, "_issue", new=capture_issue),
            patch.object(
                CredentialResolver,
                "_published_handle_is_exact_for_transport",
                return_value=False,
            ),
            patch.object(
                AttemptGate,
                "_recover_resolved_credential_for_cleanup",
                return_value=True,
            ) as recovery,
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver.resolve(credential)

        self.assertEqual(recovery.call_count, 2)
        self.assertEqual(len(issued), 1)
        handle, handle_state, secret = issued[0]
        self.assertNotIn(handle, resolver._ledger._states)
        self.assertEqual(handle_state.status, "closed")
        self.assertIsNone(handle_state.secret)
        self.assertIsNone(handle_state.permit)
        self.assertIsNone(handle_state.gate)
        self.assertIsNone(handle_state.publication_id)
        self.assertEqual(secret, bytearray())
        self.assertEqual(source.returned_buffers, [bytearray()])
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "abandoned")
        self.assertIsNone(state.resolver_claim_id)
        self.assertIsNone(state.resolved_publication_id)
        self.assertEqual(gate.safe_metadata()["active_session_count"], 0)
        self.assert_terminal_resolver_failure(runtime, credential)
        with self.assertRaises(EndpointPolicyError):
            gate.reserve_attempt(
                credential_permit=credential,
                credential_handle_id=handle.handle_id,
                credential_handle_digest=handle.handle_digest,
            )

    def test_confirm_transaction_normal_noop_rolls_back_then_cleans(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _FakeSource(bytearray(_VALID_SECRET))
        resolver = CredentialResolver(source)
        original = AttemptGate._run_authority_path

        def no_op_confirmation(selected, **kwargs):
            action = kwargs["final_action"]
            if (
                "_confirm_credential_resolution.<locals>.confirm"
                in action.__qualname__
            ):
                return None
            return original(selected, **kwargs)

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            new=no_op_confirmation,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "confirmation transaction 未提交",
            ):
                resolver.resolve(credential)

        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        self.assertEqual(source.returned_buffers, [bytearray()])
        self.assertEqual(resolver._ledger._states, {})
        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "abandoned")
        self.assertIsNone(state.resolver_claim_id)
        self.assertIsNone(state.resolved_publication_id)
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_blocked_read_cancel_rejects_post_read_and_zeroizes(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _BlockingSource()
        resolver = CredentialResolver(source)
        handles: list[CredentialHandle] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                handles.append(resolver.resolve(credential))
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=worker)
        thread.start()
        self.assertTrue(source.entered.wait(timeout=5))
        runtime.cancellation_source.cancel(reason=CancellationReason.USER_REQUEST)
        source.release.set()
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(handles, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], CancelledError)
        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        self.assertEqual(source.buffer, bytearray(len(source.buffer)))
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_blocked_read_expiry_rejects_post_read_and_zeroizes(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        source = _BlockingSource()
        resolver = CredentialResolver(source)
        handles: list[CredentialHandle] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                handles.append(resolver.resolve(credential))
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=worker)
        thread.start()
        self.assertTrue(source.entered.wait(timeout=5))
        runtime.clock.advance(milliseconds=60_000)
        source.release.set()
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(handles, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], SnapTimeoutError)
        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        self.assertEqual(source.buffer, bytearray(len(source.buffer)))
        self.assert_terminal_resolver_failure(runtime, credential)

    def test_fake_source_path_has_zero_environment_dns_socket_or_file_io(self):
        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("external side effect")

        with (
            patch.object(builtins, "open", forbidden),
            patch.object(os, "getenv", forbidden),
            patch.object(os, "environ", _ForbiddenEnvironment()),
            patch.object(socket, "getaddrinfo", forbidden),
            patch.object(socket, "socket", forbidden),
            patch.object(socket, "create_connection", forbidden),
        ):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)
            source = _FakeSource(bytearray(_VALID_SECRET))
            resolver = CredentialResolver(source)
            handle = resolver.resolve(credential)
            attempt = gate.reserve_attempt(
                credential_permit=credential,
                credential_handle_id=handle.handle_id,
                credential_handle_digest=handle.handle_digest,
            )
            self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
            self.assertTrue(
                gate.abandon_attempt(
                    attempt,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertTrue(resolver.close(handle))


if __name__ == "__main__":
    unittest.main()
