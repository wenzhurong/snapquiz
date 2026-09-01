"""Offline W09-B1 contract for frozen-binding credential resolution."""
from __future__ import annotations

import builtins
import copy
from datetime import timedelta
import os
import pickle
import socket
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
from snapquiz.runtime.attempt import AttemptGate, _TRANSPORT_ATTEMPT_AUTHORITY
from snapquiz.runtime.context import CancellationReason
from snapquiz.transport.credentials import (
    CredentialHandle,
    CredentialResolver,
    _TRANSPORT_CREDENTIAL_AUTHORITY,
)
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime


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
        original_fail = AttemptGate._fail_credential_resolution
        fail_calls = 0

        def fail_once(selected, *args, **kwargs):
            nonlocal fail_calls
            fail_calls += 1
            if fail_calls == 1:
                raise _FatalValidationError("synthetic precommit failure")
            return original_fail(selected, *args, **kwargs)

        with patch.object(
            AttemptGate,
            "_fail_credential_resolution",
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
            AttemptGate._abandon_resolved_credential_resolution
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
                "_abandon_resolved_credential_resolution",
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
