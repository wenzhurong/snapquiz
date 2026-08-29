import unittest
from datetime import datetime, timedelta, timezone

from snapquiz.domain.digest import (
    CanonicalizationError,
    Digest256,
    canonical_json_bytes,
    digest256,
)


class DigestContractTest(unittest.TestCase):
    def test_golden_vector(self):
        payload = {"z": -0.0, "a": [1.0, "题目", {"enabled": True}]}
        self.assertEqual(
            canonical_json_bytes(payload),
            '{"a":[1,"题目",{"enabled":true}],"z":0}'.encode("utf-8"),
        )
        self.assertEqual(
            digest256("GoldenExample", "snapquiz.golden.v1", payload),
            "b1f18b850742c7dec6fe727d03e1a6283f1ad9f0563c92258d813e3c8fcf7f4b",
        )

    def test_mapping_order_does_not_change_digest(self):
        left = {"answer": "B", "count": 2, "nested": {"b": 2, "a": 1}}
        right = {"nested": {"a": 1, "b": 2}, "count": 2.0, "answer": "B"}
        self.assertEqual(digest256("Result", "v1", left), digest256("Result", "v1", right))

    def test_type_and_schema_labels_are_domain_separated(self):
        payload = {"value": 1}
        self.assertNotEqual(digest256("Plan", "v1", payload), digest256("Scope", "v1", payload))
        self.assertNotEqual(digest256("Plan", "v1", payload), digest256("Plan", "v2", payload))

    def test_serializer_version_is_domain_separated(self):
        payload = {"value": 1}
        self.assertNotEqual(
            digest256("Plan", "v1", payload),
            digest256(
                "Plan",
                "v1",
                payload,
                canonical_serializer_version="snapquiz.canonical-json.v2-test",
            ),
        )

    def test_nested_digest256_is_serialized_as_canonical_text(self):
        nested = Digest256("0" * 64)
        self.assertEqual(
            canonical_json_bytes({"policy_digest": nested}),
            canonical_json_bytes({"policy_digest": str(nested)}),
        )

    def test_length_delimiting_avoids_prefix_ambiguity(self):
        payload = {"value": "same"}
        self.assertNotEqual(digest256("ab", "c", payload), digest256("a", "bc", payload))

    def test_datetime_is_normalized_to_utc(self):
        utc_value = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
        offset_value = datetime(
            2026, 8, 28, 8, 0, tzinfo=timezone(timedelta(hours=-4))
        )
        self.assertEqual(canonical_json_bytes(utc_value), canonical_json_bytes(offset_value))

    def test_rejects_non_finite_and_unsupported_values(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(CanonicalizationError):
                canonical_json_bytes(value)
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({1: "non-string key"})
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes(b"not-json")
        with self.assertRaises(CanonicalizationError) as surrogate_error:
            canonical_json_bytes("\ud800")
        self.assertIsNone(surrogate_error.exception.__context__)
        recursive = []
        recursive.append(recursive)
        with self.assertRaises(CanonicalizationError) as cycle_error:
            canonical_json_bytes(recursive)
        self.assertIsNone(cycle_error.exception.__context__)

    def test_digest256_rejects_non_canonical_text(self):
        with self.assertRaises(ValueError):
            Digest256("A" * 64)
        with self.assertRaises(ValueError):
            Digest256("0" * 63)


if __name__ == "__main__":
    unittest.main()
