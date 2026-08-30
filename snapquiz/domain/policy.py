"""Immutable policy snapshots and explicit contract markers."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from snapquiz.domain._validation import (
    require_aware_datetime,
    require_digest,
    require_text,
    runtime_final,
)
from snapquiz.domain.digest import Digest256


class ContractMarker(str, Enum):
    """Explicit non-value states; callers must not conflate the two."""

    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


@runtime_final
@dataclass(frozen=True, slots=True, kw_only=True)
class PolicySnapshot:
    ref: str
    content_digest: Digest256 = field(repr=False)
    verified_at: datetime
    expires_at: datetime | None

    def __post_init__(self) -> None:
        require_text(self.ref, "ref", max_length=512)
        require_digest(self.content_digest, "content_digest")
        require_aware_datetime(self.verified_at, "verified_at")
        if self.expires_at is not None:
            require_aware_datetime(self.expires_at, "expires_at")
            if self.expires_at <= self.verified_at:
                raise ValueError("expires_at must be later than verified_at")

    def as_digest_payload(self) -> dict[str, object]:
        return {
            "ref": self.ref,
            "content_digest": self.content_digest,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
        }


PolicyValue = PolicySnapshot | ContractMarker


def require_policy_value(value: object, name: str) -> PolicyValue:
    if (
        type(value) is PolicySnapshot
        or value is ContractMarker.NOT_APPLICABLE
        or value is ContractMarker.UNKNOWN
    ):
        return value  # type: ignore[return-value]
    raise ValueError(
        f"{name} must be PolicySnapshot, not_applicable, or unknown"
    )


def policy_value_payload(value: PolicyValue) -> object:
    require_policy_value(value, "policy value")
    if type(value) is PolicySnapshot:
        return PolicySnapshot.as_digest_payload(value)
    return value.value


def validate_policy_value_at(
    value: PolicyValue,
    now: datetime,
    *,
    name: str = "policy value",
) -> None:
    """Fail closed when a verified policy is not valid at ``now``.

    Contract markers have no temporal evidence to validate.  Their disclosure
    and acknowledgement requirements belong to the privacy-consent boundary.
    """

    require_policy_value(value, name)
    require_aware_datetime(now, "now")
    if type(value) is not PolicySnapshot:
        return
    if now < value.verified_at:
        raise ValueError(f"{name} is not valid yet")
    if value.expires_at is not None and now >= value.expires_at:
        raise ValueError(f"{name} has expired")
