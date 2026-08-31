"""Pure contracts shared by future v3 pipeline executors."""

from snapquiz.pipelines.contracts import (
    SOLVE_REQUEST_SCHEMA_VERSION,
    STAGE_INVOCATION_SCHEMA_VERSION,
    SolveRequest,
    SolveRequestFactory,
    StageInvocation,
    StageInvocationFactory,
)

__all__ = [
    "SOLVE_REQUEST_SCHEMA_VERSION",
    "STAGE_INVOCATION_SCHEMA_VERSION",
    "SolveRequest",
    "SolveRequestFactory",
    "StageInvocation",
    "StageInvocationFactory",
]
