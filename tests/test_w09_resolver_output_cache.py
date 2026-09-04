"""W09-B2b-S4d pure/local durable output cache contract tests."""
from __future__ import annotations

import ast
import copy
import inspect
import pickle
from pathlib import Path
import sys
import unittest
from uuid import UUID

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_output_cache as output


EPOCH_ID = UUID("8d000000-0000-0000-0000-000000000001")
OPERATION_ID = UUID("8d000000-0000-0000-0000-000000000002")
PROXY_ID = UUID("8d000000-0000-0000-0000-000000000003")
BINDING_DIGEST = Digest256("a" * 64)
RESULT = b'{"kind":"RESULT"}\n'


def _cache(*, operation_id=OPERATION_ID):
    return output._new_resolver_output_cache(
        epoch_id=EPOCH_ID,
        operation_id=operation_id,
        proxy_id=PROXY_ID,
        operation_binding_digest=BINDING_DIGEST,
    )


def _publish(cache, sequence, kind, payload):
    publication = cache.new_publication(sequence=sequence, kind=kind)
    return publication, publication.publish(payload)


def _call_with_line_interrupt(function, needle, call, *, occurrence=1):
    lines, first_line = inspect.getsourcelines(function)
    matches = [
        first_line + index
        for index, line in enumerate(lines)
        if needle in line
    ]
    target_line = matches[occurrence - 1]
    previous = sys.gettrace()
    fired = False

    def interrupt(frame, event, arg):
        nonlocal fired
        del arg
        if (
            not fired
            and event == "line"
            and frame.f_code is function.__code__
            and frame.f_lineno == target_line
        ):
            fired = True
            raise KeyboardInterrupt("synthetic output-cache interruption")
        return interrupt

    sys.settrace(interrupt)
    try:
        return call()
    finally:
        sys.settrace(previous)


class ResolverOutputCacheTest(unittest.TestCase):
    def test_local_only_contract_has_no_io_or_production_authority(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_resolver_output_cache.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertFalse(
            imported
            & {
                "ctypes",
                "os",
                "select",
                "socket",
                "ssl",
                "subprocess",
            }
        )
        self.assertTrue(output.LOCAL_DURABLE_OUTPUT_CONTRACT_AVAILABLE)
        self.assertFalse(output.PRODUCTION_DURABLE_OUTPUT_CONTRACT_AVAILABLE)

    def test_ready_result_eof_are_one_slot_and_fixed_sequence(self):
        cache = _cache()
        observations = []
        for sequence, kind, payload in (
            (0, output._ResolverOutputKind.READY, output.READY_OUTPUT_PAYLOAD),
            (1, output._ResolverOutputKind.RESULT, RESULT),
            (2, output._ResolverOutputKind.EOF, b""),
        ):
            publication, observation = _publish(
                cache,
                sequence,
                kind,
                payload,
            )
            observations.append(observation)
            metadata = cache.safe_metadata()
            self.assertTrue(metadata["slot_present"])
            self.assertEqual(metadata["slot_payload_size"], len(payload))
            self.assertIs(cache.current(publication), observation)
            cache.acknowledge(observation)
            metadata = cache.safe_metadata()
            self.assertFalse(metadata["slot_present"])
            self.assertEqual(metadata["acked_count"], sequence + 1)
        self.assertEqual(
            [item.kind.value for item in observations],
            ["READY", "RESULT", "EOF"],
        )
        self.assertEqual(len({item.delivery_id for item in observations}), 3)

    def test_publish_retry_returns_exact_cached_observation_before_ack(self):
        cache = _cache()
        publication = cache.new_publication(
            sequence=0,
            kind=output._ResolverOutputKind.READY,
        )
        first = publication.publish(output.READY_OUTPUT_PAYLOAD)
        second = publication.publish(output.READY_OUTPUT_PAYLOAD)
        self.assertIs(second, first)
        self.assertIs(cache.current(publication), first)
        self.assertEqual(cache.safe_metadata()["acked_count"], 0)

    def test_ack_is_idempotent_and_payload_free_tombstone_survives_slot_clear(self):
        cache = _cache()
        _, observation = _publish(
            cache,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        first = cache.acknowledge(observation)
        second = cache.acknowledge(observation)
        self.assertIs(second, first)
        self.assertFalse(hasattr(first, "payload"))
        self.assertFalse(cache.safe_metadata()["slot_present"])
        self.assertEqual(cache.safe_metadata()["tombstone_count"], 1)

    def test_tombstone_before_slot_clear_window_is_recovered(self):
        cache = _cache()
        _, observation = _publish(
            cache,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        tombstone = output._ResolverOutputTombstone(
            observation,
            _authority=output._TOMBSTONE_AUTHORITY,
        )
        cache._tombstones[0] = tombstone
        self.assertIs(cache.acknowledge(observation), tombstone)
        self.assertFalse(cache.safe_metadata()["slot_present"])

    def test_atomic_tombstone_store_interrupt_recovers_slot_and_ack(self):
        cache = _cache()
        _, observation = _publish(
            cache,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                output._ResolverOutputCache.acknowledge,
                'object.__setattr__(self, "_slot", None)',
                lambda: cache.acknowledge(observation),
                occurrence=2,
            )
        self.assertTrue(cache.safe_metadata()["slot_present"])
        self.assertEqual(cache.safe_metadata()["tombstone_count"], 1)
        cache.acknowledge(observation)
        self.assertFalse(cache.safe_metadata()["slot_present"])

    def test_ack_commit_return_interrupt_replays_payload_free_tombstone(self):
        cache = _cache()
        _, observation = _publish(
            cache,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                output._ResolverOutputCache.acknowledge,
                "return retained",
                lambda: cache.acknowledge(observation),
            )
        self.assertFalse(cache.safe_metadata()["slot_present"])
        self.assertIsNotNone(cache.acknowledged(observation))
        cache.acknowledge(observation)

    def test_tombstone_field_and_digest_tamper_poison_idempotent_ack(self):
        fields = {
            "delivery_id": UUID("8d000000-0000-0000-0000-000000000077"),
            "payload_size": 99,
            "payload_digest": Digest256("b" * 64),
            "observation_digest": Digest256("c" * 64),
            "tombstone_digest": Digest256("d" * 64),
            "_issued_digest": Digest256("e" * 64),
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                cache = _cache()
                _, observation = _publish(
                    cache,
                    0,
                    output._ResolverOutputKind.READY,
                    output.READY_OUTPUT_PAYLOAD,
                )
                tombstone = cache.acknowledge(observation)
                object.__setattr__(tombstone, field, value)
                with self.assertRaises(EndpointPolicyError):
                    cache.acknowledge(observation)
                self.assertTrue(cache.safe_metadata()["poisoned"])

    def test_changed_payload_for_same_delivery_poison_fails_closed(self):
        cache = _cache()
        publication, _ = _publish(
            cache,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        with self.assertRaises(EndpointPolicyError):
            publication.publish(b"not-ready\n")
        self.assertTrue(cache.safe_metadata()["poisoned"])

    def test_cross_operation_ack_poison_fails_closed(self):
        first = _cache()
        second = _cache(
            operation_id=UUID("8d000000-0000-0000-0000-000000000099")
        )
        _, observation = _publish(
            first,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        with self.assertRaisesRegex(EndpointPolicyError, "binding"):
            second.acknowledge(observation)
        self.assertTrue(second.safe_metadata()["poisoned"])

    def test_cross_operation_tombstone_transplant_poison_fails_closed(self):
        first = _cache()
        second = _cache(
            operation_id=UUID("8d000000-0000-0000-0000-000000000099")
        )
        _, observation = _publish(
            first,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        tombstone = first.acknowledge(observation)
        second._tombstones[0] = tombstone

        with self.assertRaisesRegex(EndpointPolicyError, "ledger|损坏"):
            second.safe_metadata()
        self.assertTrue(second.safe_metadata()["poisoned"])

    def test_tampered_id_payload_and_digest_poison_on_ack(self):
        fields = {
            "delivery_id": UUID("8d000000-0000-0000-0000-000000000088"),
            "payload": b"changed\n",
            "payload_digest": Digest256("b" * 64),
            "observation_digest": Digest256("c" * 64),
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                cache = _cache()
                _, observation = _publish(
                    cache,
                    0,
                    output._ResolverOutputKind.READY,
                    output.READY_OUTPUT_PAYLOAD,
                )
                object.__setattr__(observation, field, value)
                with self.assertRaises(EndpointPolicyError):
                    cache.acknowledge(observation)
                self.assertTrue(cache.safe_metadata()["poisoned"])

    def test_factory_only_immutable_observation_cannot_be_serialized(self):
        cache = _cache()
        _, observation = _publish(
            cache,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        with self.assertRaises(TypeError):
            output._ResolverOutputObservation(
                epoch_id=EPOCH_ID,
                operation_id=OPERATION_ID,
                proxy_id=PROXY_ID,
                operation_binding_digest=BINDING_DIGEST,
                sequence=0,
                kind=output._ResolverOutputKind.READY,
                payload=output.READY_OUTPUT_PAYLOAD,
            )
        with self.assertRaises(AttributeError):
            observation.sequence = 2
        self.assertIs(copy.copy(observation), observation)
        self.assertIs(copy.deepcopy(observation), observation)
        with self.assertRaises(TypeError):
            pickle.dumps(observation)

    def test_payload_bound_and_order_are_strict(self):
        cache = _cache()
        with self.assertRaises(EndpointPolicyError):
            cache.new_publication(
                sequence=1,
                kind=output._ResolverOutputKind.RESULT,
            )
        self.assertTrue(cache.safe_metadata()["poisoned"])

        oversized = _cache()
        publication = oversized.new_publication(
            sequence=0,
            kind=output._ResolverOutputKind.READY,
        )
        with self.assertRaises(EndpointPolicyError):
            publication.publish(b"x" * (output.MAX_RESOLVER_OUTPUT_PAYLOAD_BYTES + 1))

        invalid_result = _cache()
        ready_publication, ready = _publish(
            invalid_result,
            0,
            output._ResolverOutputKind.READY,
            output.READY_OUTPUT_PAYLOAD,
        )
        del ready_publication
        invalid_result.acknowledge(ready)
        result_publication = invalid_result.new_publication(
            sequence=1,
            kind=output._ResolverOutputKind.RESULT,
        )
        with self.assertRaises(EndpointPolicyError):
            result_publication.publish(b"missing-lf")


if __name__ == "__main__":
    unittest.main()
