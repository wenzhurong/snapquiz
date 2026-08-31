"""Trusted wall/monotonic clock contracts for the W09 runtime.

Wall time is sampled between two monotonic reads. Runtime deadlines are
anchored to the first read so scheduler delay during sampling can only shorten,
never extend, the authority window.
"""
from __future__ import annotations

from datetime import datetime, timezone
import time

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_plain_int,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256


CLOCK_SAMPLE_SCHEMA_VERSION = "snapquiz.clock-sample.v1"
MONOTONIC_DEADLINE_SCHEMA_VERSION = "snapquiz.monotonic-deadline.v1"

_CLOCK_SAMPLE_AUTHORITY = object()
_DEADLINE_AUTHORITY = object()
_DEADLINE_CONSTRUCTION_AUTHORITY = object()


def _utc_datetime(value: object, name: str) -> datetime:
    checked = require_aware_datetime(value, name)
    return checked.astimezone(timezone.utc)


def _datetime_delta_ns(later: datetime, earlier: datetime) -> int:
    delta = later - earlier
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _clock_sample_digest(
    *,
    wall_time: datetime,
    monotonic_before_ns: int,
    monotonic_after_ns: int,
) -> Digest256:
    return digest256(
        "ClockSample",
        CLOCK_SAMPLE_SCHEMA_VERSION,
        {
            "wall_time": wall_time,
            "monotonic_before_ns": monotonic_before_ns,
            "monotonic_after_ns": monotonic_after_ns,
        },
    )


@runtime_final
class ClockSample:
    """Immutable proof that one wall reading occurred inside a mono interval."""

    __slots__ = (
        "wall_time",
        "monotonic_before_ns",
        "monotonic_after_ns",
        "sample_digest",
    )

    def __init__(
        self,
        *,
        wall_time: datetime,
        monotonic_before_ns: int,
        monotonic_after_ns: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CLOCK_SAMPLE_AUTHORITY:
            raise TypeError("ClockSample requires a RuntimeClock capability")
        normalized_wall_time = _utc_datetime(wall_time, "wall_time")
        require_plain_int(
            monotonic_before_ns,
            "monotonic_before_ns",
            minimum=0,
        )
        require_plain_int(
            monotonic_after_ns,
            "monotonic_after_ns",
            minimum=0,
        )
        if monotonic_after_ns < monotonic_before_ns:
            raise ValueError("monotonic clock moved backwards during sampling")
        for name, value in (
            ("wall_time", normalized_wall_time),
            ("monotonic_before_ns", monotonic_before_ns),
            ("monotonic_after_ns", monotonic_after_ns),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "sample_digest",
            _clock_sample_digest(
                wall_time=normalized_wall_time,
                monotonic_before_ns=monotonic_before_ns,
                monotonic_after_ns=monotonic_after_ns,
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ClockSample is immutable")

    def __copy__(self) -> "ClockSample":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "ClockSample":
        del memo
        return self

    @property
    def monotonic_ns(self) -> int:
        """Conservative compatibility alias: always the pre-wall reading."""

        return self.monotonic_before_ns

    @property
    def sampling_interval_ns(self) -> int:
        return self.monotonic_after_ns - self.monotonic_before_ns

    def __repr__(self) -> str:
        return (
            "ClockSample("
            f"monotonic_before_ns={self.monotonic_before_ns!r}, "
            f"monotonic_after_ns={self.monotonic_after_ns!r})"
        )

    def validate_integrity(self) -> None:
        wall_time = _utc_datetime(self.wall_time, "wall_time")
        if wall_time != self.wall_time or self.wall_time.tzinfo is not timezone.utc:
            raise ValueError("wall_time must remain normalized UTC")
        require_plain_int(
            self.monotonic_before_ns,
            "monotonic_before_ns",
            minimum=0,
        )
        require_plain_int(
            self.monotonic_after_ns,
            "monotonic_after_ns",
            minimum=0,
        )
        if self.monotonic_after_ns < self.monotonic_before_ns:
            raise ValueError("monotonic sample ordering changed")
        require_digest(self.sample_digest, "sample_digest")
        expected = _clock_sample_digest(
            wall_time=self.wall_time,
            monotonic_before_ns=self.monotonic_before_ns,
            monotonic_after_ns=self.monotonic_after_ns,
        )
        if self.sample_digest != expected:
            raise ValueError("clock sample integrity mismatch")


class RuntimeClock:
    """TCB clock capability; request factories must not accept caller clocks."""

    __slots__ = ()

    @staticmethod
    def _make_sample(
        *,
        wall_time: datetime,
        monotonic_before_ns: int,
        monotonic_after_ns: int,
    ) -> ClockSample:
        """Protected factory for production and deterministic offline clocks."""

        return ClockSample(
            wall_time=wall_time,
            monotonic_before_ns=monotonic_before_ns,
            monotonic_after_ns=monotonic_after_ns,
            _authority=_CLOCK_SAMPLE_AUTHORITY,
        )

    def sample(self) -> ClockSample:
        raise NotImplementedError


@runtime_final
class SystemRuntimeClock(RuntimeClock):
    """Exact production clock: mono-before, UTC wall, mono-after."""

    __slots__ = ()

    def sample(self) -> ClockSample:
        monotonic_before_ns = time.monotonic_ns()
        wall_time = datetime.now(timezone.utc)
        monotonic_after_ns = time.monotonic_ns()
        return self._make_sample(
            wall_time=wall_time,
            monotonic_before_ns=monotonic_before_ns,
            monotonic_after_ns=monotonic_after_ns,
        )


def _deadline_digest_payload(
    *,
    started_wall_at: datetime,
    started_monotonic_ns: int,
    sampled_monotonic_after_ns: int,
    deadline_monotonic_ns: int,
    timeout_budget_ms: int,
    wall_valid_until: datetime | None,
    source_sample_digest: Digest256,
) -> dict[str, object]:
    return {
        "started_wall_at": started_wall_at,
        "started_monotonic_ns": started_monotonic_ns,
        "sampled_monotonic_after_ns": sampled_monotonic_after_ns,
        "deadline_monotonic_ns": deadline_monotonic_ns,
        "timeout_budget_ms": timeout_budget_ms,
        "wall_valid_until": wall_valid_until,
        "source_sample_digest": source_sample_digest,
    }


@runtime_final
class MonotonicDeadline:
    """Immutable half-open ``[start, deadline)`` runtime authority window."""

    __slots__ = (
        "started_wall_at",
        "started_monotonic_ns",
        "sampled_monotonic_after_ns",
        "deadline_monotonic_ns",
        "timeout_budget_ms",
        "wall_valid_until",
        "source_sample_digest",
        "deadline_digest",
    )

    def __init__(
        self,
        *,
        started_wall_at: datetime,
        started_monotonic_ns: int,
        sampled_monotonic_after_ns: int,
        deadline_monotonic_ns: int,
        timeout_budget_ms: int,
        wall_valid_until: datetime | None,
        source_sample_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _DEADLINE_CONSTRUCTION_AUTHORITY:
            raise TypeError("MonotonicDeadline requires from_sample")
        normalized_started_wall_at = _utc_datetime(
            started_wall_at,
            "started_wall_at",
        )
        normalized_wall_valid_until = (
            None
            if wall_valid_until is None
            else _utc_datetime(wall_valid_until, "wall_valid_until")
        )
        require_plain_int(
            started_monotonic_ns,
            "started_monotonic_ns",
            minimum=0,
        )
        require_plain_int(
            sampled_monotonic_after_ns,
            "sampled_monotonic_after_ns",
            minimum=0,
        )
        require_plain_int(
            deadline_monotonic_ns,
            "deadline_monotonic_ns",
            minimum=1,
        )
        require_plain_int(timeout_budget_ms, "timeout_budget_ms", minimum=1)
        require_digest(source_sample_digest, "source_sample_digest")
        if sampled_monotonic_after_ns < started_monotonic_ns:
            raise ValueError("source sample ordering is invalid")
        if deadline_monotonic_ns <= started_monotonic_ns:
            raise ValueError("deadline must be later than its start")
        if sampled_monotonic_after_ns >= deadline_monotonic_ns:
            raise ValueError("deadline was already expired when sampling completed")
        for name, value in (
            ("started_wall_at", normalized_started_wall_at),
            ("started_monotonic_ns", started_monotonic_ns),
            ("sampled_monotonic_after_ns", sampled_monotonic_after_ns),
            ("deadline_monotonic_ns", deadline_monotonic_ns),
            ("timeout_budget_ms", timeout_budget_ms),
            ("wall_valid_until", normalized_wall_valid_until),
            ("source_sample_digest", source_sample_digest),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "deadline_digest",
            digest256(
                "MonotonicDeadline",
                MONOTONIC_DEADLINE_SCHEMA_VERSION,
                _deadline_digest_payload(
                    started_wall_at=normalized_started_wall_at,
                    started_monotonic_ns=started_monotonic_ns,
                    sampled_monotonic_after_ns=sampled_monotonic_after_ns,
                    deadline_monotonic_ns=deadline_monotonic_ns,
                    timeout_budget_ms=timeout_budget_ms,
                    wall_valid_until=normalized_wall_valid_until,
                    source_sample_digest=source_sample_digest,
                ),
            ),
        )
        self.validate_integrity()

    @classmethod
    def from_sample(
        cls,
        *,
        sample: ClockSample,
        timeout_budget_ms: int,
        wall_valid_until: datetime | None = None,
        _authority: object | None = None,
    ) -> "MonotonicDeadline":
        """Map duration/wall bounds from the conservative pre-wall reading."""

        if _authority is not _DEADLINE_AUTHORITY:
            raise TypeError("MonotonicDeadline requires RuntimeCallFactory")
        if type(sample) is not ClockSample:
            raise ValueError("sample must be ClockSample")
        sample.validate_integrity()
        require_plain_int(timeout_budget_ms, "timeout_budget_ms", minimum=1)
        normalized_wall_valid_until = (
            None
            if wall_valid_until is None
            else _utc_datetime(wall_valid_until, "wall_valid_until")
        )
        budget_deadline_ns = (
            sample.monotonic_before_ns + timeout_budget_ms * 1_000_000
        )
        deadline_monotonic_ns = budget_deadline_ns
        if normalized_wall_valid_until is not None:
            wall_remaining_ns = _datetime_delta_ns(
                normalized_wall_valid_until,
                sample.wall_time,
            )
            if wall_remaining_ns <= 0:
                raise ValueError("wall authority is already expired")
            deadline_monotonic_ns = min(
                deadline_monotonic_ns,
                sample.monotonic_before_ns + wall_remaining_ns,
            )
        return cls(
            started_wall_at=sample.wall_time,
            started_monotonic_ns=sample.monotonic_before_ns,
            sampled_monotonic_after_ns=sample.monotonic_after_ns,
            deadline_monotonic_ns=deadline_monotonic_ns,
            timeout_budget_ms=timeout_budget_ms,
            wall_valid_until=normalized_wall_valid_until,
            source_sample_digest=sample.sample_digest,
            _authority=_DEADLINE_CONSTRUCTION_AUTHORITY,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("MonotonicDeadline is immutable")

    def __copy__(self) -> "MonotonicDeadline":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "MonotonicDeadline":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "MonotonicDeadline("
            f"started_monotonic_ns={self.started_monotonic_ns!r}, "
            f"deadline_monotonic_ns={self.deadline_monotonic_ns!r}, "
            f"timeout_budget_ms={self.timeout_budget_ms!r})"
        )

    def is_expired_at(self, monotonic_ns: int) -> bool:
        """Return true at and after the half-open deadline boundary."""

        require_plain_int(monotonic_ns, "monotonic_ns", minimum=0)
        self.validate_integrity()
        if monotonic_ns < self.started_monotonic_ns:
            raise ValueError("monotonic clock moved backwards from deadline start")
        return monotonic_ns >= self.deadline_monotonic_ns

    def remaining_ns_at(self, monotonic_ns: int) -> int:
        """Return a non-negative remainder; equality has no authority left."""

        require_plain_int(monotonic_ns, "monotonic_ns", minimum=0)
        self.validate_integrity()
        if monotonic_ns < self.started_monotonic_ns:
            raise ValueError("monotonic clock moved backwards from deadline start")
        return max(0, self.deadline_monotonic_ns - monotonic_ns)

    def validate_integrity(self) -> None:
        started_wall_at = _utc_datetime(self.started_wall_at, "started_wall_at")
        if (
            started_wall_at != self.started_wall_at
            or self.started_wall_at.tzinfo is not timezone.utc
        ):
            raise ValueError("started_wall_at must remain normalized UTC")
        require_plain_int(
            self.started_monotonic_ns,
            "started_monotonic_ns",
            minimum=0,
        )
        require_plain_int(
            self.sampled_monotonic_after_ns,
            "sampled_monotonic_after_ns",
            minimum=0,
        )
        require_plain_int(
            self.deadline_monotonic_ns,
            "deadline_monotonic_ns",
            minimum=1,
        )
        require_plain_int(
            self.timeout_budget_ms,
            "timeout_budget_ms",
            minimum=1,
        )
        require_digest(self.source_sample_digest, "source_sample_digest")
        require_digest(self.deadline_digest, "deadline_digest")
        if self.wall_valid_until is not None:
            wall_valid_until = _utc_datetime(
                self.wall_valid_until,
                "wall_valid_until",
            )
            if (
                wall_valid_until != self.wall_valid_until
                or self.wall_valid_until.tzinfo is not timezone.utc
            ):
                raise ValueError("wall_valid_until must remain normalized UTC")
        if self.sampled_monotonic_after_ns < self.started_monotonic_ns:
            raise ValueError("source sample ordering changed")
        if self.deadline_monotonic_ns <= self.started_monotonic_ns:
            raise ValueError("deadline ordering changed")
        if self.sampled_monotonic_after_ns >= self.deadline_monotonic_ns:
            raise ValueError("deadline expired inside its source sample")

        expected_sample_digest = _clock_sample_digest(
            wall_time=self.started_wall_at,
            monotonic_before_ns=self.started_monotonic_ns,
            monotonic_after_ns=self.sampled_monotonic_after_ns,
        )
        if self.source_sample_digest != expected_sample_digest:
            raise ValueError("source sample integrity mismatch")

        budget_deadline_ns = (
            self.started_monotonic_ns + self.timeout_budget_ms * 1_000_000
        )
        expected_deadline_ns = budget_deadline_ns
        if self.wall_valid_until is not None:
            wall_remaining_ns = _datetime_delta_ns(
                self.wall_valid_until,
                self.started_wall_at,
            )
            if wall_remaining_ns <= 0:
                raise ValueError("wall authority is expired at deadline start")
            expected_deadline_ns = min(
                expected_deadline_ns,
                self.started_monotonic_ns + wall_remaining_ns,
            )
        if self.deadline_monotonic_ns != expected_deadline_ns:
            raise ValueError("deadline mapping changed")

        expected_digest = digest256(
            "MonotonicDeadline",
            MONOTONIC_DEADLINE_SCHEMA_VERSION,
            _deadline_digest_payload(
                started_wall_at=self.started_wall_at,
                started_monotonic_ns=self.started_monotonic_ns,
                sampled_monotonic_after_ns=self.sampled_monotonic_after_ns,
                deadline_monotonic_ns=self.deadline_monotonic_ns,
                timeout_budget_ms=self.timeout_budget_ms,
                wall_valid_until=self.wall_valid_until,
                source_sample_digest=self.source_sample_digest,
            ),
        )
        if self.deadline_digest != expected_digest:
            raise ValueError("deadline integrity mismatch")


__all__ = [
    "CLOCK_SAMPLE_SCHEMA_VERSION",
    "MONOTONIC_DEADLINE_SCHEMA_VERSION",
    "ClockSample",
    "MonotonicDeadline",
    "RuntimeClock",
    "SystemRuntimeClock",
]
