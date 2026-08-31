from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import inspect
import unittest
from unittest.mock import patch

from snapquiz.domain.digest import Digest256, digest256
from snapquiz.runtime import clock as clock_module
from snapquiz.runtime.clock import (
    CLOCK_SAMPLE_SCHEMA_VERSION,
    MONOTONIC_DEADLINE_SCHEMA_VERSION,
    ClockSample,
    MonotonicDeadline,
    RuntimeClock,
    SystemRuntimeClock,
    _DEADLINE_AUTHORITY,
)


WALL_TIME = datetime(2026, 8, 31, 12, 34, 56, 789000, tzinfo=timezone.utc)
MONO_BEFORE_NS = 7_000_000_000
MONO_AFTER_NS = 7_000_125_000


class ManualRuntimeClock(RuntimeClock):
    """Offline-only clock using RuntimeClock's protected sample capability."""

    __slots__ = ("_wall_time", "_before_ns", "_after_ns")

    def __init__(
        self,
        *,
        wall_time: datetime = WALL_TIME,
        before_ns: int = MONO_BEFORE_NS,
        after_ns: int = MONO_AFTER_NS,
    ) -> None:
        self._wall_time = wall_time
        self._before_ns = before_ns
        self._after_ns = after_ns

    def sample(self) -> ClockSample:
        return self._make_sample(
            wall_time=self._wall_time,
            monotonic_before_ns=self._before_ns,
            monotonic_after_ns=self._after_ns,
        )


def _sample(
    *,
    wall_time: datetime = WALL_TIME,
    before_ns: int = MONO_BEFORE_NS,
    after_ns: int = MONO_AFTER_NS,
) -> ClockSample:
    return ManualRuntimeClock(
        wall_time=wall_time,
        before_ns=before_ns,
        after_ns=after_ns,
    ).sample()


def _deadline(
    *,
    sample: ClockSample | None = None,
    timeout_budget_ms: int = 4_000,
    wall_valid_until: datetime | None = None,
) -> MonotonicDeadline:
    return MonotonicDeadline.from_sample(
        sample=_sample() if sample is None else sample,
        timeout_budget_ms=timeout_budget_ms,
        wall_valid_until=wall_valid_until,
        _authority=_DEADLINE_AUTHORITY,
    )


class W09ClockSampleTest(unittest.TestCase):
    def test_system_clock_samples_mono_wall_mono_in_exact_order(self):
        events: list[str] = []
        monotonic_values = iter((MONO_BEFORE_NS, MONO_AFTER_NS))

        def monotonic_ns() -> int:
            events.append("mono")
            return next(monotonic_values)

        class OrderedDateTime:
            @classmethod
            def now(cls, selected_timezone):
                self.assertIs(selected_timezone, timezone.utc)
                events.append("wall")
                return WALL_TIME

        with (
            patch.object(clock_module.time, "monotonic_ns", monotonic_ns),
            patch.object(clock_module, "datetime", OrderedDateTime),
        ):
            result = SystemRuntimeClock().sample()

        self.assertEqual(events, ["mono", "wall", "mono"])
        self.assertIs(type(result), ClockSample)
        self.assertEqual(result.wall_time, WALL_TIME)
        self.assertEqual(result.monotonic_before_ns, MONO_BEFORE_NS)
        self.assertEqual(result.monotonic_after_ns, MONO_AFTER_NS)
        self.assertEqual(result.monotonic_ns, MONO_BEFORE_NS)
        self.assertEqual(result.sampling_interval_ns, 125_000)
        result.validate_integrity()

    def test_sample_is_factory_only_final_immutable_and_utc_normalized(self):
        offset_time = WALL_TIME.astimezone(timezone(timedelta(hours=8)))
        with self.assertRaises(TypeError):
            ClockSample(
                wall_time=WALL_TIME,
                monotonic_before_ns=MONO_BEFORE_NS,
                monotonic_after_ns=MONO_AFTER_NS,
            )
        sample = _sample(wall_time=offset_time)
        self.assertEqual(sample.wall_time, WALL_TIME)
        self.assertIs(sample.wall_time.tzinfo, timezone.utc)
        with self.assertRaises(AttributeError):
            sample.wall_time = WALL_TIME + timedelta(seconds=1)  # type: ignore[misc]
        with self.assertRaises(TypeError):
            class DerivedClockSample(ClockSample):
                pass
        self.assertIs(copy.copy(sample), sample)
        self.assertIs(copy.deepcopy(sample), sample)
        with self.assertRaises(TypeError):
            vars(sample)

    def test_manual_clock_factory_rejects_wrong_types_and_clock_rollback(self):
        invalid_cases = (
            {"wall_time": "2026-08-31", "before_ns": 1, "after_ns": 2},
            {
                "wall_time": WALL_TIME.replace(tzinfo=None),
                "before_ns": 1,
                "after_ns": 2,
            },
            {"wall_time": WALL_TIME, "before_ns": True, "after_ns": 2},
            {"wall_time": WALL_TIME, "before_ns": 1, "after_ns": False},
            {"wall_time": WALL_TIME, "before_ns": -1, "after_ns": 2},
            {"wall_time": WALL_TIME, "before_ns": 2, "after_ns": 1},
        )
        for values in invalid_cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                _sample(**values)  # type: ignore[arg-type]

    def test_sample_integrity_rechecks_every_field_and_digest(self):
        mutations = (
            ("wall_time", WALL_TIME.replace(tzinfo=None)),
            ("monotonic_before_ns", True),
            ("monotonic_after_ns", "7000125000"),
            ("sample_digest", str(_sample().sample_digest)),
        )
        for name, value in mutations:
            sample = _sample()
            object.__setattr__(sample, name, value)
            with self.subTest(field=name), self.assertRaises(ValueError):
                sample.validate_integrity()

        sample = _sample()
        object.__setattr__(sample, "monotonic_after_ns", MONO_BEFORE_NS - 1)
        with self.assertRaises(ValueError):
            sample.validate_integrity()

        sample = _sample()
        object.__setattr__(
            sample,
            "sample_digest",
            digest256("tampered", "v1", {}),
        )
        with self.assertRaises(ValueError):
            sample.validate_integrity()

    def test_sample_contract_and_golden_digest(self):
        sample = _sample()
        self.assertEqual(CLOCK_SAMPLE_SCHEMA_VERSION, "snapquiz.clock-sample.v1")
        self.assertIs(type(sample.sample_digest), Digest256)
        self.assertEqual(
            str(sample.sample_digest),
            "ce705c988374712c1ae0203abf27bc3adf46acca0d0859b55ba2bf7d2dabf009",
        )

    def test_system_clock_is_exact_final_and_has_no_time_parameters(self):
        self.assertIs(type(SystemRuntimeClock()), SystemRuntimeClock)
        self.assertEqual(tuple(inspect.signature(SystemRuntimeClock.sample).parameters), ("self",))
        with self.assertRaises(TypeError):
            class DerivedSystemClock(SystemRuntimeClock):
                pass


class W09MonotonicDeadlineTest(unittest.TestCase):
    def test_factory_only_deadline_uses_before_for_both_bounds(self):
        sample = _sample()
        wall_expiry = sample.wall_time + timedelta(seconds=2)
        deadline = _deadline(
            sample=sample,
            timeout_budget_ms=4_000,
            wall_valid_until=wall_expiry,
        )

        self.assertEqual(deadline.started_wall_at, sample.wall_time)
        self.assertEqual(deadline.started_monotonic_ns, sample.monotonic_before_ns)
        self.assertEqual(
            deadline.sampled_monotonic_after_ns,
            sample.monotonic_after_ns,
        )
        self.assertEqual(
            deadline.deadline_monotonic_ns,
            sample.monotonic_before_ns + 2_000_000_000,
        )
        self.assertNotEqual(
            deadline.deadline_monotonic_ns,
            sample.monotonic_after_ns + 2_000_000_000,
        )
        self.assertEqual(deadline.wall_valid_until, wall_expiry)
        self.assertEqual(deadline.source_sample_digest, sample.sample_digest)
        deadline.validate_integrity()

    def test_duration_budget_is_also_anchored_to_before(self):
        sample = _sample()
        deadline = _deadline(
            sample=sample,
            timeout_budget_ms=500,
            wall_valid_until=sample.wall_time + timedelta(seconds=2),
        )
        self.assertEqual(
            deadline.deadline_monotonic_ns,
            sample.monotonic_before_ns + 500_000_000,
        )

    def test_deadline_has_half_open_semantics(self):
        deadline = _deadline(timeout_budget_ms=1_000)
        boundary = deadline.deadline_monotonic_ns

        self.assertFalse(deadline.is_expired_at(deadline.started_monotonic_ns))
        self.assertEqual(
            deadline.remaining_ns_at(deadline.started_monotonic_ns),
            1_000_000_000,
        )
        self.assertFalse(deadline.is_expired_at(boundary - 1))
        self.assertEqual(deadline.remaining_ns_at(boundary - 1), 1)
        self.assertTrue(deadline.is_expired_at(boundary))
        self.assertEqual(deadline.remaining_ns_at(boundary), 0)
        self.assertTrue(deadline.is_expired_at(boundary + 1))
        self.assertEqual(deadline.remaining_ns_at(boundary + 1), 0)

        for invalid in (True, -1, "0"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                deadline.is_expired_at(invalid)  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                deadline.remaining_ns_at(invalid)  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            deadline.is_expired_at(deadline.started_monotonic_ns - 1)
        with self.assertRaises(ValueError):
            deadline.remaining_ns_at(deadline.started_monotonic_ns - 1)

    def test_expired_wall_bound_and_expiry_during_sample_fail_closed(self):
        sample = _sample()
        for wall_expiry in (
            sample.wall_time,
            sample.wall_time - timedelta(microseconds=1),
        ):
            with self.subTest(wall_expiry=wall_expiry), self.assertRaises(ValueError):
                _deadline(sample=sample, wall_valid_until=wall_expiry)

        slow_sample = _sample(before_ns=1_000, after_ns=1_001_000)
        with self.assertRaises(ValueError):
            _deadline(sample=slow_sample, timeout_budget_ms=1)

        wall_limited_sample = _sample(before_ns=1_000, after_ns=1_001_000)
        with self.assertRaises(ValueError):
            _deadline(
                sample=wall_limited_sample,
                timeout_budget_ms=10,
                wall_valid_until=WALL_TIME + timedelta(milliseconds=1),
            )

    def test_deadline_factories_reject_untrusted_construction_and_types(self):
        sample = _sample()
        with self.assertRaises(TypeError):
            MonotonicDeadline.from_sample(
                sample=sample,
                timeout_budget_ms=1_000,
            )
        with self.assertRaises(TypeError):
            MonotonicDeadline(
                started_wall_at=sample.wall_time,
                started_monotonic_ns=sample.monotonic_before_ns,
                sampled_monotonic_after_ns=sample.monotonic_after_ns,
                deadline_monotonic_ns=sample.monotonic_before_ns + 1_000_000_000,
                timeout_budget_ms=1_000,
                wall_valid_until=None,
                source_sample_digest=sample.sample_digest,
            )
        with self.assertRaises(ValueError):
            _deadline(timeout_budget_ms=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _deadline(
                wall_valid_until=(WALL_TIME + timedelta(seconds=1)).replace(
                    tzinfo=None
                )
            )
        with self.assertRaises(ValueError):
            MonotonicDeadline.from_sample(
                sample=object(),  # type: ignore[arg-type]
                timeout_budget_ms=1_000,
                _authority=_DEADLINE_AUTHORITY,
            )
        with self.assertRaises(TypeError):
            class DerivedDeadline(MonotonicDeadline):
                pass

    def test_deadline_is_immutable_and_normalizes_wall_expiry(self):
        offset_expiry = (WALL_TIME + timedelta(seconds=2)).astimezone(
            timezone(timedelta(hours=-4))
        )
        deadline = _deadline(wall_valid_until=offset_expiry)
        self.assertEqual(deadline.wall_valid_until, WALL_TIME + timedelta(seconds=2))
        self.assertIs(deadline.wall_valid_until.tzinfo, timezone.utc)
        with self.assertRaises(AttributeError):
            deadline.timeout_budget_ms = 5_000  # type: ignore[misc]
        self.assertIs(copy.copy(deadline), deadline)
        self.assertIs(copy.deepcopy(deadline), deadline)
        with self.assertRaises(TypeError):
            vars(deadline)

    def test_deadline_integrity_rechecks_every_field_and_mapping(self):
        wall_expiry = WALL_TIME + timedelta(seconds=2)
        mutations = (
            ("started_wall_at", WALL_TIME.replace(tzinfo=None)),
            ("started_monotonic_ns", True),
            ("sampled_monotonic_after_ns", "7000125000"),
            ("deadline_monotonic_ns", False),
            ("timeout_budget_ms", "4000"),
            ("wall_valid_until", wall_expiry.replace(tzinfo=None)),
            ("source_sample_digest", str(_sample().sample_digest)),
            ("deadline_digest", str(_deadline().deadline_digest)),
        )
        for name, value in mutations:
            deadline = _deadline(wall_valid_until=wall_expiry)
            object.__setattr__(deadline, name, value)
            with self.subTest(field=name), self.assertRaises(ValueError):
                deadline.validate_integrity()

        relational_mutations = (
            ("sampled_monotonic_after_ns", MONO_BEFORE_NS - 1),
            ("sampled_monotonic_after_ns", MONO_BEFORE_NS + 2_000_000_000),
            ("deadline_monotonic_ns", MONO_BEFORE_NS),
            ("deadline_monotonic_ns", MONO_BEFORE_NS + 1_999_999_999),
        )
        for name, value in relational_mutations:
            deadline = _deadline(wall_valid_until=wall_expiry)
            object.__setattr__(deadline, name, value)
            with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                deadline.validate_integrity()

        deadline = _deadline(wall_valid_until=wall_expiry)
        object.__setattr__(
            deadline,
            "source_sample_digest",
            digest256("tampered-sample", "v1", {}),
        )
        with self.assertRaises(ValueError):
            deadline.validate_integrity()

        deadline = _deadline(wall_valid_until=wall_expiry)
        object.__setattr__(
            deadline,
            "deadline_digest",
            digest256("tampered-deadline", "v1", {}),
        )
        with self.assertRaises(ValueError):
            deadline.validate_integrity()

    def test_deadline_contract_and_golden_digest(self):
        deadline = _deadline(
            timeout_budget_ms=4_000,
            wall_valid_until=WALL_TIME + timedelta(seconds=2),
        )
        self.assertEqual(
            MONOTONIC_DEADLINE_SCHEMA_VERSION,
            "snapquiz.monotonic-deadline.v1",
        )
        self.assertIs(type(deadline.deadline_digest), Digest256)
        self.assertEqual(
            str(deadline.deadline_digest),
            "e6853041814b3414de4bc80d7803f7b7c85ffa6899aa94ff002801c9b7050df6",
        )


if __name__ == "__main__":
    unittest.main()
