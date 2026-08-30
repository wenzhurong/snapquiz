"""Pure migration mapping for the frozen MVP-0 GLM selection.

The mapper intentionally has no API-key parameter and never reads a Mapping or
the process environment.  It converts only exact legacy non-secret metadata to
references in the controlled Registry.
"""
from __future__ import annotations

from snapquiz.domain._validation import runtime_final
from snapquiz.config.profiles import (
    GLM_LEGACY_BASE_URL,
    GLM_MODEL_ID,
    GLM_PIPELINE_PROFILE_ID,
)


class LegacyGlmMappingError(ValueError):
    """Legacy non-secret metadata does not match the one frozen profile."""


@runtime_final
class LegacyGlmProfileReference:
    __slots__ = (
        "pipeline_profile_id",
        "deprecation_code",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "pipeline_profile_id", GLM_PIPELINE_PROFILE_ID)
        object.__setattr__(
            self,
            "deprecation_code",
            "legacy_glm_environment_names_deprecated",
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("LegacyGlmProfileReference is immutable")

    def __deepcopy__(
        self, memo: dict[int, object]
    ) -> "LegacyGlmProfileReference":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "LegacyGlmProfileReference("
            f"pipeline_profile_id={self.pipeline_profile_id!r}, "
            f"deprecation_code={self.deprecation_code!r})"
        )

    def safe_metadata(self) -> dict[str, str]:
        return {
            "pipeline_profile_id": self.pipeline_profile_id,
            "deprecation_code": self.deprecation_code,
        }


def map_legacy_glm_profile(
    *, base_url: str | None, model: str | None
) -> LegacyGlmProfileReference:
    """Map explicitly supplied legacy metadata; never accept or inspect a secret."""

    selected_base_url = GLM_LEGACY_BASE_URL if base_url is None else base_url
    selected_model = GLM_MODEL_ID if model is None else model
    if type(selected_base_url) is not str or selected_base_url != GLM_LEGACY_BASE_URL:
        raise LegacyGlmMappingError("legacy GLM endpoint is not the frozen official profile")
    if type(selected_model) is not str or selected_model != GLM_MODEL_ID:
        raise LegacyGlmMappingError("legacy GLM model is not the frozen exact binding")
    return LegacyGlmProfileReference()


__all__ = [
    "LegacyGlmMappingError",
    "LegacyGlmProfileReference",
    "map_legacy_glm_profile",
]
