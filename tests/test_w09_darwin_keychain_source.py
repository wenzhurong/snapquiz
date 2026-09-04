from __future__ import annotations

import copy
import pickle
from threading import Event, Lock, Thread
from types import TracebackType
import sys
import unittest
from unittest import mock

from snapquiz.domain.errors import CancelledError, ConfigError, TimeoutError
from snapquiz.transport import _darwin_keychain_source as keychain
from snapquiz.transport import credentials


_LOCATOR = "keychain-generic-password:v1:glm-primary"
_SECRET = b"synthetic-token.ABC_123"


class _Backend:
    def __init__(
        self,
        value: bytes = _SECRET,
        *,
        result: object | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.value = bytearray(value)
        self.result = result
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
        writer.publish(self.value)
        if self.error is not None:
            raise self.error
        return self.result  # type: ignore[return-value]


def _binding() -> keychain._DarwinKeychainBinding:
    return keychain._new_darwin_keychain_binding(
        credential_ref=_LOCATOR,
        service="ai.snapquiz.provider",
        account="glm-primary",
        access_group="TEAMID.ai.snapquiz.credentials",
    )


def _source(backend: object) -> keychain._DarwinKeychainCredentialSource:
    return keychain._new_darwin_keychain_source_for_test(
        binding=_binding(),
        backend=backend,  # type: ignore[arg-type]
        _authority=keychain._TEST_SOURCE_AUTHORITY,
    )


def _publication() -> keychain._KeychainBufferPublication:
    return keychain._new_keychain_buffer_publication_for_test(
        _authority=keychain._TEST_PUBLICATION_AUTHORITY,
    )


def _read(
    source: keychain._DarwinKeychainCredentialSource,
    publication: keychain._KeychainBufferPublication,
) -> keychain._KeychainReadReceipt:
    receipt = source.read_exact_into(
        _LOCATOR,
        publication,
        _authority=keychain._TEST_SOURCE_AUTHORITY,
    )
    source = None  # type: ignore[assignment]
    publication = None  # type: ignore[assignment]
    receipt.raise_for_failure()
    return receipt


def _traceback_frames(error: BaseException) -> list[TracebackType]:
    frames: list[TracebackType] = []
    traceback = error.__traceback__
    while traceback is not None:
        frames.append(traceback)
        traceback = traceback.tb_next
    return frames


class W09DarwinKeychainSourceTest(unittest.TestCase):
    def test_zero_fallback_drops_first_interruption_traceback(self):
        first = RuntimeError("synthetic secret-bearing first interruption")
        second = KeyboardInterrupt("synthetic fallback interruption")

        class TwiceInterruptedBuffer:
            def __len__(self) -> int:
                return 4

            def __setitem__(self, key: object, value: object) -> None:
                del value
                if isinstance(key, slice):
                    raise first
                raise second

        with self.assertRaises(KeyboardInterrupt) as caught:
            keychain._best_effort_zero(TwiceInterruptedBuffer())  # type: ignore[arg-type]
        self.assertIs(caught.exception, second)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(first.__traceback__)

    def test_caller_preheld_publication_owns_value_and_consumes_once(self):
        backend = _Backend()
        source = _source(backend)
        publication = _publication()
        self.assertEqual(backend.calls, [])
        self.assertFalse(hasattr(source, "read_exact"))

        _read(source, publication)

        self.assertEqual(
            backend.calls,
            [
                (
                    "ai.snapquiz.provider",
                    "glm-primary",
                    "TEAMID.ai.snapquiz.credentials",
                )
            ],
        )
        self.assertEqual(backend.value, bytearray(len(_SECRET)))
        self.assertTrue(publication.has_value())
        observed: list[bytes] = []

        def consume(view: memoryview) -> None:
            self.assertTrue(view.readonly)
            observed.append(view.tobytes())

        publication.consume_once(consume)
        self.assertEqual(observed, [_SECRET])
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())
        with self.assertRaises(ValueError):
            publication.consume_once(consume)

    def test_wrong_locator_and_wrong_authority_fail_before_backend(self):
        backend = _Backend()
        source = _source(backend)
        for locator, authority in (
            ("keychain-generic-password:v1:other", keychain._TEST_SOURCE_AUTHORITY),
            (_LOCATOR, object()),
        ):
            with self.subTest(
                locator=locator,
                correct=authority is keychain._TEST_SOURCE_AUTHORITY,
            ):
                publication = _publication()
                receipt = source.read_exact_into(
                    locator,
                    publication,
                    _authority=authority,
                )
                with self.assertRaises(ConfigError) as caught:
                    receipt.raise_for_failure()
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertTrue(publication.close())
        self.assertEqual(backend.calls, [])

    def test_publish_then_backend_exception_is_sanitized_and_zeroized(self):
        sentinel = "synthetic-secret-must-not-escape"
        backend = _Backend(error=RuntimeError(sentinel))
        publication = _publication()
        with self.assertRaises(ConfigError) as caught:
            _read(_source(backend), publication)

        self.assertNotIn(sentinel, str(caught.exception))
        self.assertNotIn(sentinel, repr(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(backend.value, bytearray(len(_SECRET)))
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_source_return_event_keeps_value_in_caller_preheld_publication(self):
        publication = _publication()
        source = _source(_Backend())
        target = source.read_exact_into.__func__.__code__
        previous = sys.gettrace()
        interrupted = False

        def interrupt(frame, event, argument):
            nonlocal interrupted
            if frame.f_code is target and event == "return" and not interrupted:
                interrupted = True
                self.assertIsInstance(argument, keychain._KeychainReadReceipt)
                raise KeyboardInterrupt("synthetic source return event")
            return interrupt

        sys.settrace(interrupt)
        try:
            with self.assertRaises(KeyboardInterrupt):
                _read(source, publication)
        finally:
            sys.settrace(previous)
        self.assertTrue(interrupted)
        self.assertTrue(publication.has_value())
        recovered = publication.recover_read_receipt(
            _authority=keychain._TEST_SOURCE_AUTHORITY,
        )
        self.assertTrue(recovered.succeeded)
        observed: list[bytes] = []
        publication.consume_once(lambda view: observed.append(view.tobytes()))
        self.assertEqual(observed, [_SECRET])
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_typed_backend_errors_are_fresh_fixed_and_drop_backend_traceback(self):
        sentinel = "synthetic-secret-source-context"
        originals = (
            CancelledError(
                stage="wrong-stage",
                retryable=True,
                safe_message=sentinel,
            ),
            TimeoutError(
                stage="wrong-stage",
                retryable=False,
                safe_message=sentinel,
            ),
        )
        for original in originals:
            with self.subTest(error=type(original).__name__):
                publication = _publication()
                with self.assertRaises(type(original)) as caught:
                    _read(_source(_Backend(error=original)), publication)
                selected = caught.exception
                self.assertIsNot(selected, original)
                self.assertEqual(selected.stage, "credential_source")
                self.assertEqual(
                    selected.retryable,
                    isinstance(selected, TimeoutError),
                )
                self.assertNotIn(sentinel, str(selected))
                self.assertIsNone(selected.__cause__)
                self.assertIsNone(selected.__context__)
                frame_names = {
                    item.tb_frame.f_code.co_name
                    for item in _traceback_frames(selected)
                }
                self.assertNotIn("copy_generic_password", frame_names)
                self.assertNotIn("_perform_read_into", frame_names)
                for item in _traceback_frames(selected):
                    if item.tb_frame.f_code.co_name == "_read":
                        self.assertIsNone(item.tb_frame.f_locals["source"])
                        self.assertIsNone(
                            item.tb_frame.f_locals["publication"]
                        )
                self.assertTrue(publication.is_terminal())
                self.assertTrue(publication._storage_is_zero_for_test())

    def test_nonconforming_backend_return_does_not_enter_public_traceback(self):
        sentinel = b"synthetic-secret-invalid-return"

        class InvalidBackend:
            def copy_generic_password(self, **kwargs: object) -> bytes:
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)
                writer.publish(bytearray(_SECRET))
                return sentinel

        publication = _publication()
        with self.assertRaises(ConfigError) as caught:
            _read(_source(InvalidBackend()), publication)
        for item in _traceback_frames(caught.exception):
            rendered = repr(item.tb_frame.f_locals)
            self.assertNotIn(sentinel.decode("ascii"), rendered)
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_backend_base_exception_after_publish_becomes_safe_config_error(self):
        publication = _publication()
        backend = _Backend(error=KeyboardInterrupt("synthetic-secret-interrupt"))
        with self.assertRaises(ConfigError) as caught:
            _read(_source(backend), publication)
        self.assertNotIn("synthetic-secret", repr(caught.exception))
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())
        self.assertEqual(backend.value, bytearray(len(_SECRET)))

    def test_callback_base_exception_releases_view_and_zeroizes(self):
        publication = _publication()
        backend = _Backend()
        _read(_source(backend), publication)
        retained: list[memoryview] = []
        primary = KeyboardInterrupt("synthetic callback failure")

        def fail(view: memoryview) -> None:
            retained.append(view)
            raise primary

        with self.assertRaises(KeyboardInterrupt) as caught:
            publication.consume_once(fail)
        self.assertIs(caught.exception, primary)
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())
        with self.assertRaises(ValueError):
            retained[0].tobytes()

    def test_close_during_blocked_backend_rejects_and_zeros_late_publish(self):
        entered = Event()
        release = Event()

        class BlockingBackend:
            def __init__(self) -> None:
                self.value = bytearray(_SECRET)

            def copy_generic_password(self, **kwargs: object) -> None:
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("Keychain test barrier timed out")
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)
                writer.publish(self.value)

        backend = BlockingBackend()
        publication = _publication()
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                _read(_source(backend), publication)
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=worker)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        self.assertTrue(publication.close())
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ConfigError)
        self.assertEqual(backend.value, bytearray(len(_SECRET)))
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_close_after_claim_before_backend_skips_keychain_access(self):
        backend = _Backend()
        publication = _publication()
        original_claim = keychain._KeychainBufferPublication._claim_read

        def claim_then_close(selected, binding_digest):
            writer = original_claim(selected, binding_digest)
            selected.close()
            return writer

        with mock.patch.object(
            keychain._KeychainBufferPublication,
            "_claim_read",
            new=claim_then_close,
        ):
            receipt = _source(backend).read_exact_into(
                _LOCATOR,
                publication,
                _authority=keychain._TEST_SOURCE_AUTHORITY,
            )
        self.assertEqual(receipt.kind, "source")
        self.assertEqual(backend.calls, [])
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_close_after_publish_before_backend_return_forces_failure_receipt(self):
        entered = Event()
        release = Event()

        class PublishedThenBlockedBackend:
            def __init__(self) -> None:
                self.value = bytearray(_SECRET)

            def copy_generic_password(self, **kwargs: object) -> None:
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)
                writer.publish(self.value)
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("Keychain post-publish barrier timed out")

        backend = PublishedThenBlockedBackend()
        publication = _publication()
        receipts: list[keychain._KeychainReadReceipt] = []

        def worker() -> None:
            receipts.append(
                _source(backend).read_exact_into(
                    _LOCATOR,
                    publication,
                    _authority=keychain._TEST_SOURCE_AUTHORITY,
                )
            )

        thread = Thread(target=worker)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        self.assertTrue(publication.close())
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([item.kind for item in receipts], ["source"])
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_staged_value_is_not_consumable_before_backend_validation(self):
        entered = Event()
        release = Event()

        class PublishedThenFailedBackend:
            def copy_generic_password(self, **kwargs: object) -> None:
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)
                writer.publish(bytearray(_SECRET))
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("staged-value barrier timed out")
                raise RuntimeError("synthetic backend failure after publish")

        publication = _publication()
        receipts: list[keychain._KeychainReadReceipt] = []
        thread = Thread(
            target=lambda: receipts.append(
                _source(PublishedThenFailedBackend()).read_exact_into(
                    _LOCATOR,
                    publication,
                    _authority=keychain._TEST_SOURCE_AUTHORITY,
                )
            )
        )
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        self.assertFalse(publication.has_value())
        self.assertFalse(
            publication.recover_read_receipt(
                _authority=keychain._TEST_SOURCE_AUTHORITY,
            ).succeeded
        )
        with self.assertRaises(ValueError):
            publication.consume_once(lambda view: None)
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([item.kind for item in receipts], ["source"])
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_detached_late_publish_after_backend_return_is_rejected_and_zeroed(self):
        release = Event()
        finished = Event()
        late_value = bytearray(_SECRET)
        late_errors: list[BaseException] = []
        late_threads: list[Thread] = []

        class DetachedBackend:
            def copy_generic_password(self, **kwargs: object) -> object:
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)

                def publish_late() -> None:
                    release.wait(timeout=5)
                    try:
                        writer.publish(late_value)
                    except BaseException as error:
                        late_errors.append(error)
                    finally:
                        finished.set()

                thread = Thread(target=publish_late)
                late_threads.append(thread)
                thread.start()
                return object()

        publication = _publication()
        receipt = _source(DetachedBackend()).read_exact_into(
            _LOCATOR,
            publication,
            _authority=keychain._TEST_SOURCE_AUTHORITY,
        )
        self.assertEqual(receipt.kind, "source")
        self.assertTrue(publication.is_terminal())
        release.set()
        self.assertTrue(finished.wait(timeout=5))
        late_threads[0].join(timeout=5)
        self.assertEqual(len(late_errors), 1)
        self.assertIsInstance(late_errors[0], ValueError)
        self.assertEqual(late_value, bytearray(len(_SECRET)))
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_writer_cannot_be_transferred_to_a_detached_thread(self):
        finished = Event()
        detached_value = bytearray(_SECRET)
        detached_errors: list[BaseException] = []
        detached_threads: list[Thread] = []

        class DetachedBackend:
            def copy_generic_password(self, **kwargs: object) -> None:
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)

                def publish_detached() -> None:
                    try:
                        writer.publish(detached_value)
                    except BaseException as error:
                        detached_errors.append(error)
                    finally:
                        finished.set()

                thread = Thread(target=publish_detached)
                detached_threads.append(thread)
                thread.start()
                if not finished.wait(timeout=5):
                    raise AssertionError("detached writer barrier timed out")

        publication = _publication()
        receipt = _source(DetachedBackend()).read_exact_into(
            _LOCATOR,
            publication,
            _authority=keychain._TEST_SOURCE_AUTHORITY,
        )
        detached_threads[0].join(timeout=5)
        self.assertEqual(receipt.kind, "source")
        self.assertEqual(len(detached_errors), 1)
        self.assertIsInstance(detached_errors[0], ValueError)
        self.assertEqual(detached_value, bytearray(len(_SECRET)))
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_read_claim_allows_only_one_backend_and_loser_cannot_close_winner(self):
        entered = Event()
        release = Event()
        call_lock = Lock()
        call_count = 0

        class BlockingBackend:
            def copy_generic_password(self, **kwargs: object) -> None:
                nonlocal call_count
                with call_lock:
                    call_count += 1
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("Keychain claim barrier timed out")
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)
                writer.publish(bytearray(_SECRET))

        publication = _publication()
        receipts: list[keychain._KeychainReadReceipt] = []

        def worker() -> None:
            receipts.append(
                _source(BlockingBackend()).read_exact_into(
                    _LOCATOR,
                    publication,
                    _authority=keychain._TEST_SOURCE_AUTHORITY,
                )
            )

        first = Thread(target=worker)
        second = Thread(target=worker)
        first.start()
        self.assertTrue(entered.wait(timeout=5))
        second.start()
        second.join(timeout=5)
        self.assertFalse(second.is_alive())
        self.assertEqual(call_count, 1)
        release.set()
        first.join(timeout=5)
        self.assertFalse(first.is_alive())
        self.assertEqual(sorted(item.kind for item in receipts), ["published", "source"])
        self.assertTrue(publication.has_value())
        observed: list[bytes] = []
        publication.consume_once(lambda view: observed.append(view.tobytes()))
        self.assertEqual(observed, [_SECRET])

    def test_only_exact_writer_can_publish_and_it_is_one_shot(self):
        entered = Event()
        release = Event()
        captured: list[keychain._KeychainPublicationWriter] = []

        class CapturingBackend:
            def copy_generic_password(self, **kwargs: object) -> None:
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)
                captured.append(writer)
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("writer capability barrier timed out")
                writer.publish(bytearray(_SECRET))

        publication = _publication()
        receipts: list[keychain._KeychainReadReceipt] = []
        thread = Thread(
            target=lambda: receipts.append(
                _source(CapturingBackend()).read_exact_into(
                    _LOCATOR,
                    publication,
                    _authority=keychain._TEST_SOURCE_AUTHORITY,
                )
            )
        )
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        self.assertFalse(hasattr(publication, "publish"))
        exact_writer = captured[0]
        rogue = keychain._KeychainPublicationWriter(
            publication,
            object(),
            _authority=keychain._WRITER_AUTHORITY,
        )
        injected = bytearray(b"attacker-controlled")
        with self.assertRaises(ValueError):
            rogue.publish(injected)
        self.assertEqual(injected, bytearray(len(injected)))
        forged = keychain._KeychainPublicationWriter(
            publication,
            exact_writer._nonce,
            _authority=keychain._WRITER_AUTHORITY,
        )
        forged_value = bytearray(b"forged-with-copied-nonce")
        with self.assertRaises(ValueError):
            forged.publish(forged_value)
        self.assertEqual(forged_value, bytearray(len(forged_value)))
        with self.assertRaises((TypeError, AttributeError)):
            copy.copy(exact_writer)
        with self.assertRaises((TypeError, AttributeError)):
            copy.deepcopy(exact_writer)
        with self.assertRaises((TypeError, AttributeError, pickle.PickleError)):
            pickle.dumps(exact_writer)
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([item.kind for item in receipts], ["published"])
        replay = bytearray(b"replayed-secret")
        with self.assertRaises(ValueError):
            captured[0].publish(replay)
        self.assertEqual(replay, bytearray(len(replay)))
        publication.close()

    def test_query_snapshot_recheck_rejects_source_tamper_during_read(self):
        entered = Event()
        release = Event()

        class BlockingBackend(_Backend):
            def copy_generic_password(self, **kwargs: object) -> None:
                self.calls.append(
                    (
                        kwargs["service"],
                        kwargs["account"],
                        kwargs["access_group"],
                    )
                )
                writer = kwargs["writer"]
                assert isinstance(writer, keychain._KeychainPublicationWriter)
                writer.publish(self.value)
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("query snapshot barrier timed out")

        backend = BlockingBackend()
        source = _source(backend)
        publication = _publication()
        receipts: list[keychain._KeychainReadReceipt] = []
        thread = Thread(
            target=lambda: receipts.append(
                source.read_exact_into(
                    _LOCATOR,
                    publication,
                    _authority=keychain._TEST_SOURCE_AUTHORITY,
                )
            )
        )
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        object.__setattr__(source, "_account", "tampered-after-query")
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([item.kind for item in receipts], ["source"])
        self.assertEqual(backend.calls[0][1], "glm-primary")
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_query_snapshot_has_no_validation_to_use_reread_gap(self):
        backend = _Backend()
        source = _source(backend)
        publication = _publication()
        original_digest = keychain.digest256
        snapshot_calls = 0

        def mutate_after_digest(*args: object, **kwargs: object):
            nonlocal snapshot_calls
            selected = original_digest(*args, **kwargs)
            if args and args[0] == "DarwinKeychainQuerySnapshot":
                snapshot_calls += 1
                if snapshot_calls == 1:
                    object.__setattr__(source, "_account", "attacker-account")
            return selected

        with mock.patch.object(
            keychain,
            "digest256",
            side_effect=mutate_after_digest,
        ):
            receipt = source.read_exact_into(
                _LOCATOR,
                publication,
                _authority=keychain._TEST_SOURCE_AUTHORITY,
            )
        self.assertEqual(receipt.kind, "source")
        self.assertEqual(
            backend.calls,
            [
                (
                    "ai.snapquiz.provider",
                    "glm-primary",
                    "TEAMID.ai.snapquiz.credentials",
                )
            ],
        )
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_original_binding_mutation_cannot_change_frozen_source_query(self):
        binding = _binding()
        backend = _Backend()
        source = keychain._new_darwin_keychain_source_for_test(
            binding=binding,
            backend=backend,
            _authority=keychain._TEST_SOURCE_AUTHORITY,
        )
        object.__setattr__(binding, "account", "tampered-live-binding")
        publication = _publication()
        _read(source, publication)
        self.assertEqual(backend.calls[0][1], "glm-primary")
        publication.close()

    def test_integrity_failure_returns_safe_receipt_without_source_traceback(self):
        backend = _Backend()
        source = _source(backend)
        object.__setattr__(source, "_account", "tampered")
        publication = _publication()
        receipt = source.read_exact_into(
            _LOCATOR,
            publication,
            _authority=keychain._TEST_SOURCE_AUTHORITY,
        )
        self.assertEqual(receipt.kind, "source")
        with self.assertRaises(ConfigError) as caught:
            receipt.raise_for_failure()
        frame_names = {
            item.tb_frame.f_code.co_name
            for item in _traceback_frames(caught.exception)
        }
        self.assertNotIn("read_exact_into", frame_names)
        self.assertNotIn("validate_integrity", frame_names)
        self.assertEqual(backend.calls, [])
        self.assertTrue(publication._is_empty())
        self.assertTrue(publication.close())

    def test_cleanup_interrupt_is_recoverable_by_caller_preheld_owner(self):
        publication = _publication()
        _read(_source(_Backend()), publication)
        original_zero = keychain._best_effort_zero
        interrupted = False

        def interrupt_once(buffer: bytearray) -> None:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt("synthetic cleanup interrupt")
            original_zero(buffer)

        with mock.patch.object(
            keychain,
            "_best_effort_zero",
            side_effect=interrupt_once,
        ):
            with self.assertRaises(KeyboardInterrupt):
                publication.consume_once(lambda view: None)
            self.assertFalse(publication.is_terminal())
            self.assertFalse(publication._storage_is_zero_for_test())
            self.assertTrue(publication.close())
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_claim_and_failure_cleanup_interrupts_recover_through_close(self):
        publication = _publication()

        def partial_claim(selected, binding_digest):
            with selected._lock:
                object.__setattr__(selected, "_claim_digest", binding_digest)
                object.__setattr__(selected, "_state", "reading")
            raise KeyboardInterrupt("synthetic claim return gap")

        with mock.patch.object(
            keychain._KeychainBufferPublication,
            "_claim_read",
            new=partial_claim,
        ):
            receipt = _source(_Backend()).read_exact_into(
                _LOCATOR,
                publication,
                _authority=keychain._TEST_SOURCE_AUTHORITY,
            )
        self.assertEqual(receipt.kind, "source")
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_claim_cleanup_interruption_does_not_chain_claim_traceback(self):
        publication = _publication()
        claim_error = RuntimeError("synthetic secret-bearing claim failure")
        cleanup_error = KeyboardInterrupt("synthetic cleanup interruption")

        with mock.patch.object(
            keychain._KeychainBufferPublication,
            "_claim_read",
            side_effect=claim_error,
        ), mock.patch.object(
            keychain._KeychainBufferPublication,
            "close",
            side_effect=cleanup_error,
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                _source(_Backend()).read_exact_into(
                    _LOCATOR,
                    publication,
                    _authority=keychain._TEST_SOURCE_AUTHORITY,
                )
        self.assertIs(caught.exception, cleanup_error)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(claim_error.__traceback__)

    def test_close_cleanup_interruption_is_retryable(self):
        publication = _publication()
        _read(_source(_Backend()), publication)
        original_zero = keychain._best_effort_zero
        interrupted = False

        def interrupt_once(buffer: bytearray) -> None:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt("synthetic close cleanup interruption")
            original_zero(buffer)

        with mock.patch.object(
            keychain,
            "_best_effort_zero",
            side_effect=interrupt_once,
        ):
            with self.assertRaises(KeyboardInterrupt):
                publication.close()
            self.assertFalse(publication.is_terminal())
            self.assertTrue(publication.close())
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

        publication = _publication()
        original_zero = keychain._best_effort_zero
        interrupted = False

        def interrupt_once(buffer: bytearray) -> None:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt("synthetic failure cleanup gap")
            original_zero(buffer)

        with mock.patch.object(
            keychain,
            "_best_effort_zero",
            side_effect=interrupt_once,
        ):
            class RaisingBackend:
                def copy_generic_password(self, **kwargs: object) -> None:
                    del kwargs
                    raise RuntimeError("safe synthetic backend failure")

            with self.assertRaises(KeyboardInterrupt):
                _source(RaisingBackend()).read_exact_into(
                    _LOCATOR,
                    publication,
                    _authority=keychain._TEST_SOURCE_AUTHORITY,
                )
            self.assertTrue(publication.close())
        self.assertTrue(publication.is_terminal())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_owned_backend_and_consumer_aliases_observe_zero_after_handoff(self):
        aliases: list[memoryview] = []

        class AliasingBackend(_Backend):
            def copy_generic_password(self, **kwargs: object) -> None:
                aliases.append(memoryview(self.value))
                super().copy_generic_password(**kwargs)

        publication = _publication()
        _read(_source(AliasingBackend()), publication)
        self.assertEqual(aliases[0].tobytes(), bytes(len(_SECRET)))
        retained: list[object] = []

        def consume(view: memoryview) -> None:
            retained.extend((view[1:], view.obj))

        publication.consume_once(consume)
        self.assertEqual(retained[0].tobytes(), bytes(len(_SECRET) - 1))
        self.assertEqual(retained[1], bytearray(keychain._MAX_CREDENTIAL_BYTES))
        aliases[0].release()
        retained[0].release()

    def test_current_credential_source_protocol_fails_before_keychain_backend(self):
        backend = _Backend()
        source = _source(backend)
        with self.assertRaises(ConfigError):
            credentials._read_validated_secret(source, _LOCATOR)  # type: ignore[arg-type]
        self.assertEqual(backend.calls, [])

    def test_publication_is_factory_only_immutable_and_not_serializable(self):
        with self.assertRaises(TypeError):
            keychain._KeychainBufferPublication()
        publication = _publication()
        with self.assertRaises(AttributeError):
            publication._state = "published"
        with self.assertRaises((TypeError, AttributeError, pickle.PickleError)):
            pickle.dumps(publication)
        with self.assertRaises((TypeError, AttributeError)):
            copy.copy(publication)
        self.assertEqual(
            repr(publication),
            "_KeychainBufferPublication(<private>)",
        )
        self.assertTrue(publication.close())
        self.assertFalse(publication.close())

    def test_publication_replay_and_invalid_buffers_fail_closed(self):
        publication = _publication()
        writer = publication._claim_read(_binding().binding_digest)
        self.assertIsInstance(writer, keychain._KeychainPublicationWriter)
        assert writer is not None
        empty = bytearray()
        with self.assertRaises(ValueError):
            writer.publish(empty)
        self.assertEqual(empty, bytearray())
        first = bytearray(_SECRET)
        writer.publish(first)
        self.assertEqual(first, bytearray(len(_SECRET)))
        replay = bytearray(b"another-synthetic-token")
        replay_size = len(replay)
        with self.assertRaises(ValueError):
            writer.publish(replay)
        self.assertEqual(replay, bytearray(replay_size))
        self.assertTrue(publication.close())
        self.assertTrue(publication._storage_is_zero_for_test())

    def test_binding_is_factory_only_immutable_and_not_serializable(self):
        binding = _binding()
        binding.validate_integrity()
        with self.assertRaises(TypeError):
            keychain._DarwinKeychainBinding(
                credential_ref="keychain-generic-password:v1:x",
                service="s",
                account="a",
                access_group=None,
            )
        with self.assertRaises(AttributeError):
            binding.account = "other"
        with self.assertRaises((TypeError, AttributeError, pickle.PickleError)):
            pickle.dumps(binding)
        with self.assertRaises((TypeError, AttributeError)):
            copy.copy(binding)

    def test_binding_metadata_uses_one_validated_snapshot(self):
        binding = _binding()
        expected_digest = str(binding.binding_digest)
        original_snapshot = binding._validated_snapshot

        def mutate_after_snapshot():
            snapshot = original_snapshot()
            object.__setattr__(binding, "binding_digest", "sensitive-label")
            return snapshot

        with mock.patch.object(
            keychain._DarwinKeychainBinding,
            "_validated_snapshot",
            side_effect=mutate_after_snapshot,
        ):
            metadata = binding.safe_metadata()
        self.assertEqual(metadata["binding_digest"], expected_digest)
        self.assertNotIn("sensitive-label", repr(metadata))

    def test_safe_metadata_omits_locator_and_query_labels(self):
        metadata = _source(_Backend()).safe_metadata()
        rendered = repr(metadata)
        self.assertEqual(
            metadata["schema_version"],
            keychain.DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
        )
        self.assertTrue(metadata["local_foundation_available"])
        self.assertFalse(metadata["production_available"])
        self.assertTrue(metadata["binding_integrity_valid"])
        self.assertEqual(
            metadata["publication_contract"],
            "caller_preheld_fixed_capacity_once",
        )
        self.assertNotIn("glm-primary", rendered)
        self.assertNotIn("ai.snapquiz", rendered)
        self.assertNotIn("TEAMID", rendered)

        source = _source(_Backend())
        object.__setattr__(source, "_account", "tampered")
        tampered = source.safe_metadata()
        self.assertFalse(tampered["binding_integrity_valid"])
        self.assertFalse(tampered["local_foundation_available"])

    def test_production_factory_fails_before_backend_or_keychain_access(self):
        self.assertFalse(keychain.PRODUCTION_DARWIN_KEYCHAIN_SOURCE_AVAILABLE)
        with self.assertRaises(ConfigError):
            keychain._new_production_darwin_keychain_source(binding=_binding())

    def test_labels_reject_controls_wrong_scheme_and_oversize(self):
        base = {
            "credential_ref": "keychain-generic-password:v1:x",
            "service": "service",
            "account": "account",
            "access_group": None,
        }
        cases = (
            {**base, "credential_ref": "env:GLM_API_KEY"},
            {**base, "service": "bad\nservice"},
            {**base, "account": "x" * 513},
            {**base, "access_group": "bad\x7fgroup"},
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    keychain._new_darwin_keychain_binding(**values)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
