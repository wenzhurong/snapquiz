"""Fail-closed screen-recording permission contracts.

The macOS framework is deliberately imported only by an explicit
``MacOSScreenPermissionProbe.observe`` call. Importing this module is pure and
works on platforms where Quartz is unavailable.

The two legacy boolean helpers remain as patchable migration seams for M0, but
they are permanently disabled. New code must use ``PermissionObservation`` and
``PermissionGate`` so an unavailable probe cannot be mistaken for a grant.
"""
from __future__ import annotations

import sys
from datetime import datetime
from enum import Enum

from snapquiz.domain._validation import require_aware_datetime, runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import PermissionDeniedError

PERMISSION_OBSERVATION_SCHEMA_VERSION = "snapquiz.permission-observation.v1"
PERMISSION_OBSERVATION_SOURCE = "macos_quartz_current_process"

_PERMISSION_OBSERVATION_AUTHORITY = object()


class ScreenPermissionState(str, Enum):
    """The complete result space for a screen-recording permission probe."""

    GRANTED = "granted"
    DENIED = "denied"
    UNKNOWN = "unknown"


class PermissionObservationReason(str, Enum):
    """Why a screen-permission probe produced its tri-state result."""

    GRANTED = "granted"
    DENIED = "denied"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    API_UNAVAILABLE = "api_unavailable"
    API_ERROR = "api_error"
    INVALID_RESULT = "invalid_result"


_VALID_REASONS_BY_STATE = {
    ScreenPermissionState.GRANTED: frozenset(
        {PermissionObservationReason.GRANTED}
    ),
    ScreenPermissionState.DENIED: frozenset(
        {PermissionObservationReason.DENIED}
    ),
    ScreenPermissionState.UNKNOWN: frozenset(
        {
            PermissionObservationReason.UNSUPPORTED_PLATFORM,
            PermissionObservationReason.API_UNAVAILABLE,
            PermissionObservationReason.API_ERROR,
            PermissionObservationReason.INVALID_RESULT,
        }
    ),
}


def _validate_state_reason(
    state: ScreenPermissionState,
    reason: PermissionObservationReason,
) -> None:
    if type(state) is not ScreenPermissionState:
        raise ValueError("state must be ScreenPermissionState")
    if type(reason) is not PermissionObservationReason:
        raise ValueError("reason must be PermissionObservationReason")
    if reason not in _VALID_REASONS_BY_STATE[state]:
        raise ValueError("reason is inconsistent with permission state")


@runtime_final
class PermissionObservation:
    """Immutable, integrity-checkable result of one explicit permission probe."""

    __slots__ = (
        "state",
        "reason",
        "source",
        "observed_at",
        "observation_digest",
    )

    state: ScreenPermissionState
    reason: PermissionObservationReason
    observed_at: datetime
    observation_digest: Digest256

    def __init__(
        self,
        *,
        state: ScreenPermissionState,
        reason: PermissionObservationReason,
        observed_at: datetime,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMISSION_OBSERVATION_AUTHORITY:
            raise TypeError(
                "PermissionObservation can only be created by its platform probe"
            )
        _validate_state_reason(state, reason)
        require_aware_datetime(observed_at, "observed_at")
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "source", PERMISSION_OBSERVATION_SOURCE)
        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(
            self,
            "observation_digest",
            self.recompute_digest(),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("PermissionObservation is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "PermissionObservation":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "PermissionObservation("
            f"state={self.state.value!r}, reason={self.reason.value!r}, "
            f"source={self.source!r}, "
            f"observed_at={self.observed_at!r}, "
            f"observation_digest_prefix={str(self.observation_digest)[:12]!r})"
        )

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "reason": self.reason.value,
            "source": self.source,
            "observed_at": self.observed_at,
        }

    def recompute_digest(self) -> Digest256:
        return digest256(
            "PermissionObservation",
            PERMISSION_OBSERVATION_SCHEMA_VERSION,
            self.as_digest_payload(),
        )

    def validate_integrity(self) -> None:
        _validate_state_reason(self.state, self.reason)
        if self.source != PERMISSION_OBSERVATION_SOURCE:
            raise ValueError("permission observation source changed")
        require_aware_datetime(self.observed_at, "observed_at")
        if type(self.observation_digest) is not Digest256:
            raise ValueError("observation_digest must be Digest256")
        if self.recompute_digest() != self.observation_digest:
            raise ValueError("permission observation digest changed")


@runtime_final
class MacOSScreenPermissionProbe:
    """Observe macOS screen-capture permission without a fail-open branch."""

    __slots__ = ()

    def observe(self, *, now: datetime) -> PermissionObservation:
        require_aware_datetime(now, "now")
        state = ScreenPermissionState.UNKNOWN
        reason = PermissionObservationReason.UNSUPPORTED_PLATFORM
        if sys.platform == "darwin":
            try:
                # Lazy by design: module import and object construction are pure.
                from Quartz import CGPreflightScreenCaptureAccess
            except ImportError:
                reason = PermissionObservationReason.API_UNAVAILABLE
            except Exception:
                reason = PermissionObservationReason.API_ERROR
            else:
                try:
                    raw_state = CGPreflightScreenCaptureAccess()
                except Exception:
                    reason = PermissionObservationReason.API_ERROR
                else:
                    if type(raw_state) is bool:
                        if raw_state:
                            state = ScreenPermissionState.GRANTED
                            reason = PermissionObservationReason.GRANTED
                        else:
                            state = ScreenPermissionState.DENIED
                            reason = PermissionObservationReason.DENIED
                    else:
                        # ``bool(value)`` is intentionally forbidden here:
                        # integers, mocks and foreign scalar wrappers are not
                        # permission grants.
                        reason = PermissionObservationReason.INVALID_RESULT
        return PermissionObservation(
            state=state,
            reason=reason,
            observed_at=now,
            _authority=_PERMISSION_OBSERVATION_AUTHORITY,
        )


@runtime_final
class PermissionGate:
    """Require a valid, same-snapshot grant before capture can proceed."""

    __slots__ = ()

    @staticmethod
    def require_granted(
        *, observation: PermissionObservation, now: datetime
    ) -> None:
        try:
            require_aware_datetime(now, "now")
        except ValueError:
            raise PermissionDeniedError(stage="permission_gate") from None
        if type(observation) is not PermissionObservation:
            raise PermissionDeniedError(stage="permission_gate")
        try:
            observation.validate_integrity()
        except (TypeError, ValueError):
            raise PermissionDeniedError(stage="permission_gate") from None
        if (
            observation.observed_at != now
            or observation.state is not ScreenPermissionState.GRANTED
        ):
            raise PermissionDeniedError(stage="permission_gate")


def has_screen_recording() -> bool:
    """Legacy-disabled boolean seam; never use it as an authorization signal."""

    return False


def request_screen_recording() -> bool:
    """Legacy-disabled request seam; it never prompts or grants permission."""

    return False
