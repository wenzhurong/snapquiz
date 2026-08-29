"""Pre-capture user intent for v3 planning."""
from __future__ import annotations

import re
from enum import Enum
from uuid import UUID

from snapquiz.domain._validation import (
    require_optional_text,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.capture import CaptureScopeKind
from snapquiz.domain.solve import SOLVE_RESULT_SCHEMA_VERSION

SOLVE_INTENT_SCHEMA_VERSION = "snapquiz.solve-intent.v1"
MAX_USER_HINT_CHARS = 4_000
_BCP47_RE = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")


class OutputTokenLimit(str, Enum):
    PROFILE_DEFAULT = "profile_default"


@runtime_final
class SolveIntent:
    """Immutable intent that cannot be traversed by dataclasses.asdict()."""

    schema_version: str
    request_id: UUID
    pipeline_profile_id: str
    capture_scope_preference: CaptureScopeKind
    locale: str
    timeout_budget_ms: int
    max_output_tokens: int | OutputTokenLimit
    requested_result_schema_version: str
    user_hint: str | None

    __slots__ = (
        "schema_version",
        "request_id",
        "pipeline_profile_id",
        "capture_scope_preference",
        "locale",
        "timeout_budget_ms",
        "max_output_tokens",
        "requested_result_schema_version",
        "user_hint",
    )

    def __init__(
        self,
        *,
        schema_version: str,
        request_id: UUID,
        pipeline_profile_id: str,
        capture_scope_preference: CaptureScopeKind,
        locale: str,
        timeout_budget_ms: int,
        max_output_tokens: int | OutputTokenLimit,
        requested_result_schema_version: str,
        user_hint: str | None = None,
    ) -> None:
        if schema_version != SOLVE_INTENT_SCHEMA_VERSION:
            raise ValueError("unsupported SolveIntent schema_version")
        require_uuid(request_id, "request_id")
        require_text(pipeline_profile_id, "pipeline_profile_id")
        if not isinstance(capture_scope_preference, CaptureScopeKind):
            raise ValueError("capture_scope_preference must be CaptureScopeKind")
        require_text(locale, "locale", max_length=63)
        if _BCP47_RE.fullmatch(locale) is None:
            raise ValueError("locale must use a conservative BCP-47 syntax")
        require_plain_int(timeout_budget_ms, "timeout_budget_ms", minimum=1)
        if max_output_tokens is not OutputTokenLimit.PROFILE_DEFAULT:
            require_plain_int(max_output_tokens, "max_output_tokens", minimum=1)
        if requested_result_schema_version != SOLVE_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported requested_result_schema_version")
        require_optional_text(
            user_hint,
            "user_hint",
            max_length=MAX_USER_HINT_CHARS,
            allow_multiline=True,
        )
        for name, value in (
            ("schema_version", schema_version),
            ("request_id", request_id),
            ("pipeline_profile_id", pipeline_profile_id),
            ("capture_scope_preference", capture_scope_preference),
            ("locale", locale),
            ("timeout_budget_ms", timeout_budget_ms),
            ("max_output_tokens", max_output_tokens),
            ("requested_result_schema_version", requested_result_schema_version),
            ("user_hint", user_hint),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SolveIntent is immutable")

    def __repr__(self) -> str:
        return (
            "SolveIntent("
            f"schema_version={self.schema_version!r}, request_id={self.request_id!r}, "
            f"pipeline_profile_id={self.pipeline_profile_id!r}, "
            f"capture_scope_preference={self.capture_scope_preference!r}, "
            f"locale={self.locale!r}, timeout_budget_ms={self.timeout_budget_ms!r}, "
            f"max_output_tokens={self.max_output_tokens!r}, "
            "requested_result_schema_version="
            f"{self.requested_result_schema_version!r})"
        )

    def __deepcopy__(self, memo: dict[int, object]) -> "SolveIntent":
        return self
