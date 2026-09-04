"""Offline W09 Keychain publication-to-credential-ledger bridge tests."""
from __future__ import annotations

import copy
import pickle
from threading import Barrier, Event, Lock, Thread
from types import TracebackType
import unittest
from unittest.mock import patch
from uuid import uuid4

from snapquiz.config.profiles import GLM_CREDENTIAL_REF
from snapquiz.domain.errors import ConfigError, EndpointPolicyError
from snapquiz.runtime.attempt import _TRANSPORT_ATTEMPT_AUTHORITY
from snapquiz.transport import _darwin_keychain_source as keychain
from snapquiz.transport import credentials
from snapquiz.transport.credentials import (
    CredentialHandle,
    CredentialResolver,
    _CredentialLedger,
    _TRANSPORT_CREDENTIAL_AUTHORITY,
)

from tests.test_w09_credentials import (
    _authorize,
    _make_runtime,
    _transport_claim_id,
)


_KEYCHAIN_LOCATOR = "keychain-generic-password:v1:glm-primary"
_SECRET = b"synthetic-token.ABC_123~+/=="


class _Backend:
    def __init__(
        self,
        value: bytes = _SECRET,
        *,
        before_publish=None,
        error: BaseException | None = None,
    ) -> None:
        self.value = bytearray(value)
        self.before_publish = before_publish
        self.error = error
        self.calls: list[tuple[str, str, str | None]] = []

    def copy_generic_password(
        self,
        *,
        service: str,
        account: str,
        access_group: str | None,
        writer: keychain._KeychainPublicationWriter,
    ) -> None:
        self.calls.append((service, account, access_group))
        if self.before_publish is not None:
            self.before_publish()
        writer.publish(self.value)
        if self.error is not None:
            raise self.error


def _source(permit, backend: object, *, binding_digest=None):
    selected_digest = (
        permit.credential_binding_digest
        if binding_digest is None
        else binding_digest
    )
    binding = keychain._new_darwin_keychain_binding(
        credential_ref=_KEYCHAIN_LOCATOR,
        service="ai.snapquiz.provider",
        account="glm-primary",
        access_group="TEAMID.ai.snapquiz.credentials",
        resolver_credential_ref=GLM_CREDENTIAL_REF,
        resolver_binding_digest=selected_digest,
    )
    return keychain._new_darwin_keychain_source_for_test(
        binding=binding,
        backend=backend,  # type: ignore[arg-type]
        _authority=keychain._TEST_SOURCE_AUTHORITY,
    )


def _capturing_publication_factory(captured):
    original = keychain._new_keychain_buffer_publication_for_credential_resolver

    def factory(*, _authority=None):
        publication = original(_authority=_authority)
        captured.append(publication)
        return publication

    return factory


class W09KeychainCredentialBridgeTest(unittest.TestCase):
    def assert_clean_failure(
        self,
        resolver: CredentialResolver,
        publication,
    ) -> None:
        self.assertEqual(resolver._ledger._states, {})
        self.assertEqual(len(resolver._ledger._staged), 1)
        owner = next(iter(resolver._ledger._staged.values()))
        self.assertEqual(owner.status, "terminal")
        self.assertIsNone(owner.storage)
        self.assertIsNone(owner.source_publication)
        self.assertIsNone(owner.receipt)
        self.assertIsNone(owner.permit)
        self.assertIsNone(owner.gate)
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_preheld_owner_receipt_transfer_and_exact_length_borrow(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        resolver_ref: list[CredentialResolver] = []

        def observe_preheld() -> None:
            resolver = resolver_ref[0]
            self.assertEqual(resolver._ledger._states, {})
            self.assertEqual(len(resolver._ledger._staged), 1)
            owner = next(iter(resolver._ledger._staged.values()))
            self.assertEqual(owner.status, "preheld")
            self.assertEqual(owner.secret_length, 0)
            self.assertEqual(owner.storage, bytearray(4096))
            self.assertIsNotNone(owner.source_publication)

        backend = _Backend(before_publish=observe_preheld)
        resolver = CredentialResolver(_source(permit, backend))
        resolver_ref.append(resolver)

        handle = resolver.resolve(permit)

        self.assertEqual(
            backend.calls,
            [("ai.snapquiz.provider", "glm-primary", "TEAMID.ai.snapquiz.credentials")],
        )
        self.assertEqual(backend.value, bytearray(len(_SECRET)))
        self.assertEqual(resolver._ledger._staged, {})
        state = resolver._ledger._states[handle]
        self.assertEqual(state.secret_length, len(_SECRET))
        self.assertEqual(len(state.secret), 4096)

        attempt = gate.reserve_attempt(
            credential_permit=permit,
            credential_handle_id=handle.handle_id,
            credential_handle_digest=handle.handle_digest,
        )
        claim_id = _transport_claim_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        observed: list[tuple[bool, bytes]] = []
        resolver._borrow_once(
            handle,
            attempt,
            lambda view: observed.append((view.readonly, bytes(view))),
            _authority=_TRANSPORT_CREDENTIAL_AUTHORITY,
        )
        self.assertEqual(observed, [(True, _SECRET)])
        self.assertTrue(handle.is_closed)
        self.assertIsNone(state.secret)
        self.assertEqual(state.secret_length, 0)
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_wrong_registry_mapping_fails_before_backend_and_zeroes_owners(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        backend = _Backend()
        source = _source(
            permit,
            backend,
            binding_digest=permit.permit_digest,
        )
        resolver = CredentialResolver(source)
        captured = []

        with patch.object(
            keychain,
            "_new_keychain_buffer_publication_for_credential_resolver",
            new=_capturing_publication_factory(captured),
        ):
            with self.assertRaises(ConfigError):
                resolver.resolve(permit)

        self.assertEqual(backend.calls, [])
        self.assert_clean_failure(resolver, captured[0])

    def test_invalid_bearer_is_rejected_inside_readonly_callback(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        backend = _Backend(b"not a bearer token")
        resolver = CredentialResolver(_source(permit, backend))
        captured = []

        with patch.object(
            keychain,
            "_new_keychain_buffer_publication_for_credential_resolver",
            new=_capturing_publication_factory(captured),
        ):
            with self.assertRaises(ConfigError):
                resolver.resolve(permit)

        self.assertEqual(backend.value, bytearray(len(b"not a bearer token")))
        self.assert_clean_failure(resolver, captured[0])

    def test_tampered_content_free_source_receipt_fails_closed(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        backend = _Backend()
        source = _source(permit, backend)
        resolver = CredentialResolver(source)
        captured = []
        original = type(source)._read_exact_into_for_credential_resolver

        def tamper(selected, *args, **kwargs):
            receipt = original(selected, *args, **kwargs)
            object.__setattr__(
                receipt,
                "resolver_binding_digest",
                permit.permit_digest,
            )
            return receipt

        with (
            patch.object(
                keychain,
                "_new_keychain_buffer_publication_for_credential_resolver",
                new=_capturing_publication_factory(captured),
            ),
            patch.object(
                type(source),
                "_read_exact_into_for_credential_resolver",
                new=tamper,
            ),
        ):
            with self.assertRaises(ConfigError):
                resolver.resolve(permit)

        self.assertEqual(backend.value, bytearray(len(_SECRET)))
        self.assert_clean_failure(resolver, captured[0])

    def test_source_return_event_primary_is_preserved_and_recovered(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        backend = _Backend()
        source = _source(permit, backend)
        resolver = CredentialResolver(source)
        captured = []
        primary = KeyboardInterrupt("synthetic Keychain return event")
        original = type(source)._read_exact_into_for_credential_resolver

        def return_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise primary

        with (
            patch.object(
                keychain,
                "_new_keychain_buffer_publication_for_credential_resolver",
                new=_capturing_publication_factory(captured),
            ),
            patch.object(
                type(source),
                "_read_exact_into_for_credential_resolver",
                new=return_then_raise,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                resolver.resolve(permit)

        self.assertIs(caught.exception, primary)
        self.assert_clean_failure(resolver, captured[0])

    def test_stage_callback_return_event_is_fail_closed_and_zero(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        backend = _Backend()
        resolver = CredentialResolver(_source(permit, backend))
        captured = []
        primary = KeyboardInterrupt("synthetic stage callback return event")
        original = _CredentialLedger._stage_keychain_view

        def stage_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise primary

        with (
            patch.object(
                keychain,
                "_new_keychain_buffer_publication_for_credential_resolver",
                new=_capturing_publication_factory(captured),
            ),
            patch.object(
                _CredentialLedger,
                "_stage_keychain_view",
                new=stage_then_raise,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                resolver.resolve(permit)

        self.assertIs(caught.exception, primary)
        self.assert_clean_failure(resolver, captured[0])

    def test_reentrant_cleanup_from_stage_callback_does_not_deadlock(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        resolver = CredentialResolver(_source(permit, _Backend()))
        publication_id = uuid4()
        original = _CredentialLedger._stage_keychain_view
        recovered: list[bool] = []

        def stage_then_recover(selected, owner, view):
            original(selected, owner, view)
            publication = owner.source_publication
            self.assertIsNotNone(publication)
            # Avoid turning a future regression into a hanging test: prove the
            # callback already owns a reentrant action lock before recovery.
            acquired = publication._action_lock.acquire(blocking=False)
            self.assertTrue(acquired)
            publication._action_lock.release()
            recovered.append(
                resolver._recover_preheld_keychain_owner_for_cleanup(
                    permit,
                    publication_id=publication_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )

        with patch.object(
            _CredentialLedger,
            "_stage_keychain_view",
            new=stage_then_recover,
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver.resolve(permit, publication_id=publication_id)
        self.assertEqual(recovered, [True])
        self.assertTrue(
            resolver._preheld_keychain_owner_is_closed_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_ledger_transfer_return_event_recovers_unreturned_handle(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        backend = _Backend()
        resolver = CredentialResolver(_source(permit, backend))
        captured = []
        primary = KeyboardInterrupt("synthetic ledger transfer return event")
        original = _CredentialLedger._issue_keychain_staged

        def transfer_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise primary

        with (
            patch.object(
                keychain,
                "_new_keychain_buffer_publication_for_credential_resolver",
                new=_capturing_publication_factory(captured),
            ),
            patch.object(
                _CredentialLedger,
                "_issue_keychain_staged",
                new=transfer_then_raise,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                resolver.resolve(permit)

        self.assertIs(caught.exception, primary)
        self.assertEqual(resolver._ledger._states, {})
        self.assertEqual(resolver._ledger._staged, {})
        self.assertTrue(captured[0].is_terminal())
        self.assertTrue(captured[0]._storage_is_zero_for_test())

    def test_same_publication_id_concurrency_has_one_backend_call(self):
        runtimes = [_make_runtime(), _make_runtime()]
        gates = [credentials.AttemptGate(), credentials.AttemptGate()]
        permits = [
            _authorize(runtime, gate)
            for runtime, gate in zip(runtimes, gates, strict=True)
        ]
        entered = Event()
        release = Event()

        def block() -> None:
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("Keychain bridge barrier timed out")

        backend = _Backend(before_publish=block)
        resolver = CredentialResolver(_source(permits[0], backend))
        publication_id = uuid4()
        barrier = Barrier(3)
        lock = Lock()
        handles: list[CredentialHandle] = []
        errors: list[BaseException] = []

        def worker(permit) -> None:
            barrier.wait()
            try:
                handle = resolver.resolve(
                    permit,
                    publication_id=publication_id,
                )
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    handles.append(handle)

        threads = [Thread(target=worker, args=(permit,)) for permit in permits]
        for thread in threads:
            thread.start()
        barrier.wait()
        self.assertTrue(entered.wait(timeout=5))
        release.set()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(handles), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        self.assertEqual(len(backend.calls), 1)
        self.assertTrue(resolver.close(handles[0]))

    def test_stage_receipt_is_exact_noncopyable_and_cannot_replay(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        resolver = CredentialResolver(_source(permit, _Backend()))
        captured: list[tuple[object, object]] = []
        original = _CredentialLedger._stage_keychain_view

        def capture_stage(selected, owner, view):
            original(selected, owner, view)
            captured.append((owner, owner.receipt))

        with patch.object(
            _CredentialLedger,
            "_stage_keychain_view",
            new=capture_stage,
        ):
            handle = resolver.resolve(permit)

        owner, receipt = captured[0]
        self.assertEqual(repr(receipt), "_CredentialStageReceipt(<content-free>)")
        self.assertEqual(repr(owner), "_CredentialStagingOwner(<private>)")
        with self.assertRaises(TypeError):
            copy.copy(receipt)
        with self.assertRaises(TypeError):
            pickle.dumps(receipt)
        with self.assertRaises(TypeError):
            copy.copy(owner)
        with self.assertRaises(TypeError):
            pickle.dumps(owner)
        with self.assertRaises(EndpointPolicyError):
            resolver._ledger._issue_keychain_staged(
                owner=owner,
                receipt=receipt,
                permit=permit,
                operation_id=runtime.operation.operation_id,
                credential_injection_slot=(
                    handle.credential_injection_slot
                ),
                credential_value_scheme=handle.credential_value_scheme,
            )
        self.assertFalse(handle.is_closed)
        self.assertTrue(resolver.close(handle))

    def test_staging_owner_tamper_fails_closed_but_remains_recoverable(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        resolver_ref: list[CredentialResolver] = []

        def tamper_owner() -> None:
            owner = next(iter(resolver_ref[0]._ledger._staged.values()))
            owner.credential_binding_digest = permit.permit_digest

        backend = _Backend(before_publish=tamper_owner)
        resolver = CredentialResolver(_source(permit, backend))
        resolver_ref.append(resolver)
        captured = []
        with patch.object(
            keychain,
            "_new_keychain_buffer_publication_for_credential_resolver",
            new=_capturing_publication_factory(captured),
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver.resolve(permit)
        self.assert_clean_failure(resolver, captured[0])

    def test_stage_receipt_post_validation_length_tamper_fails_closed(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        resolver = CredentialResolver(_source(permit, _Backend()))
        original = credentials._CredentialStageReceipt._validated_snapshot
        tampered = False

        def snapshot_then_tamper(receipt):
            nonlocal tampered
            snapshot = original(receipt)
            if not tampered:
                tampered = True
                owner = next(iter(resolver._ledger._staged.values()))
                object.__setattr__(receipt, "secret_length", 1)
                owner.secret_length = 1
            return snapshot

        with patch.object(
            credentials._CredentialStageReceipt,
            "_validated_snapshot",
            new=snapshot_then_tamper,
        ):
            with self.assertRaises(EndpointPolicyError):
                resolver.resolve(permit)
        self.assertTrue(tampered)
        owner = next(iter(resolver._ledger._staged.values()))
        self.assertEqual(owner.status, "terminal")
        self.assertIsNone(owner.storage)
        self.assertIsNone(owner.receipt)

    def test_concurrent_cleanup_wins_before_late_backend_publish(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        entered = Event()
        release = Event()

        def block() -> None:
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("Keychain close race barrier timed out")

        resolver = CredentialResolver(_source(permit, _Backend(before_publish=block)))
        publication_id = uuid4()
        errors: list[BaseException] = []

        def resolve_worker() -> None:
            try:
                resolver.resolve(permit, publication_id=publication_id)
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=resolve_worker)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        self.assertTrue(
            resolver._recover_preheld_keychain_owner_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            resolver._preheld_keychain_owner_is_closed_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ConfigError)

    def test_persistent_source_cleanup_fault_retains_exact_retry_owner(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        source = _source(permit, _Backend())
        resolver = CredentialResolver(source)
        publication_id = uuid4()
        primary = KeyboardInterrupt("synthetic post-source return")
        original_read = type(source)._read_exact_into_for_credential_resolver

        def return_then_raise(selected, *args, **kwargs):
            original_read(selected, *args, **kwargs)
            raise primary

        with (
            patch.object(
                type(source),
                "_read_exact_into_for_credential_resolver",
                new=return_then_raise,
            ),
            patch.object(
                keychain._KeychainBufferPublication,
                "close",
                side_effect=KeyboardInterrupt("synthetic cleanup interruption"),
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                resolver.resolve(permit, publication_id=publication_id)
        self.assertIs(caught.exception, primary)
        owner = resolver._ledger._staged[publication_id]
        self.assertEqual(owner.status, "cleanup_required")
        self.assertIsNotNone(owner.source_publication)
        self.assertFalse(
            resolver._preheld_keychain_owner_is_closed_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            resolver._recover_preheld_keychain_owner_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            resolver._preheld_keychain_owner_is_closed_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_persistent_ledger_zero_fault_retains_exact_retry_owner(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        resolver = CredentialResolver(_source(permit, _Backend()))
        publication_id = uuid4()
        primary = KeyboardInterrupt("synthetic post-stage return")
        original_stage = _CredentialLedger._stage_keychain_view

        def stage_then_raise(selected, *args, **kwargs):
            original_stage(selected, *args, **kwargs)
            raise primary

        with (
            patch.object(
                _CredentialLedger,
                "_stage_keychain_view",
                new=stage_then_raise,
            ),
            patch.object(
                credentials,
                "_best_effort_zero",
                new=lambda buffer: None,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                resolver.resolve(permit, publication_id=publication_id)
        self.assertIs(caught.exception, primary)
        owner = resolver._ledger._staged[publication_id]
        self.assertEqual(owner.status, "cleanup_required")
        self.assertIsNotNone(owner.storage)
        self.assertEqual(bytes(owner.storage[: len(_SECRET)]), _SECRET)
        self.assertTrue(
            resolver._recover_preheld_keychain_owner_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            resolver._preheld_keychain_owner_is_closed_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_prehold_return_event_is_recovered_before_any_backend_call(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        backend = _Backend()
        resolver = CredentialResolver(_source(permit, backend))
        publication_id = uuid4()
        primary = KeyboardInterrupt("synthetic prehold return event")
        original = _CredentialLedger._prehold_keychain_owner

        def prehold_then_raise(selected, *args, **kwargs):
            original(selected, *args, **kwargs)
            raise primary

        with patch.object(
            _CredentialLedger,
            "_prehold_keychain_owner",
            new=prehold_then_raise,
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                resolver.resolve(permit, publication_id=publication_id)
        self.assertIs(caught.exception, primary)
        self.assertEqual(backend.calls, [])
        self.assertTrue(
            resolver._preheld_keychain_owner_is_closed_for_cleanup(
                permit,
                publication_id=publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_backend_traceback_and_secret_do_not_escape(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)
        sentinel = "synthetic-secret-in-Keychain-backend-frame"

        class RaisingBackend:
            def copy_generic_password(self, **kwargs):
                del kwargs
                secret_local = sentinel
                if secret_local:
                    raise RuntimeError(secret_local)

        resolver = CredentialResolver(_source(permit, RaisingBackend()))
        try:
            resolver.resolve(permit)
        except ConfigError as error:
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            traceback = error.__traceback__
            while traceback is not None:
                frame = traceback.tb_frame
                self.assertNotEqual(frame.f_code.co_name, "copy_generic_password")
                if frame.f_code.co_name != (
                    "test_backend_traceback_and_secret_do_not_escape"
                ):
                    self.assertNotIn(sentinel, repr(frame.f_locals))
                    self.assertFalse(
                        any(
                            isinstance(value, TracebackType)
                            for value in frame.f_locals.values()
                        )
                    )
                traceback = traceback.tb_next
        else:
            self.fail("Keychain backend failure did not fail closed")

    def test_legacy_fake_source_path_remains_selected(self):
        runtime = _make_runtime()
        gate = credentials.AttemptGate()
        permit = _authorize(runtime, gate)

        class LegacySource:
            def __init__(self) -> None:
                self.calls = []
                self.buffer = bytearray(_SECRET)

            def read_exact(self, locator: str) -> bytearray:
                self.calls.append(locator)
                return self.buffer

        source = LegacySource()
        resolver = CredentialResolver(source)
        with patch.object(
            _CredentialLedger,
            "_prehold_keychain_owner",
            side_effect=AssertionError("legacy source used Keychain bridge"),
        ):
            handle = resolver.resolve(permit)
        self.assertEqual(source.calls, [GLM_CREDENTIAL_REF])
        self.assertEqual(source.buffer, bytearray())
        self.assertTrue(resolver.close(handle))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
