"""Provider-neutral domain contracts for the v3 pipeline.

This package must stay importable with only the Python standard library.  It is
deliberately not wired into the MVP-0 runtime until the v3 safety gates exist.
"""

from snapquiz.domain.capture import (
    CaptureArtifact,
    CaptureConstraints,
    CaptureRect,
    CaptureScope,
    CaptureScopeKind,
    CoordinateSpace,
    validate_capture_artifact,
)
from snapquiz.domain.digest import (
    CANONICAL_SERIALIZER_VERSION,
    Digest256,
    canonical_json_bytes,
    digest256,
)
from snapquiz.domain.intent import (
    MAX_USER_HINT_CHARS,
    SOLVE_INTENT_SCHEMA_VERSION,
    OutputTokenLimit,
    SolveIntent,
)
from snapquiz.domain.outbound import (
    NON_SECRET_HEADERS_SCHEMA_VERSION,
    PREPARED_BODY_SCHEMA_VERSION,
    REQUEST_ENVELOPE_SCHEMA_VERSION,
    NonSecretHeader,
    PreparedOutbound,
    validate_prepared_outbound_against_plan,
)
from snapquiz.domain.plan import (
    EXECUTION_PLAN_SCHEMA_VERSION,
    CanonicalQueryPolicy,
    ComputeLocation,
    CredentialInjectionSlot,
    ExecutionPlan,
    ExecutionPlanNetworkOperation,
    ExecutionPlanStage,
    NetworkOperationPurpose,
    NetworkScope,
    OutboundDataKind,
    QueryPolicyKind,
    RequiredConsentScope,
    validate_phase1_remote_direct_plan,
)
from snapquiz.domain.policy import ContractMarker, PolicySnapshot, PolicyValue
from snapquiz.domain.solve import (
    ConfidenceKind,
    PipelineKind,
    SolveProvenance,
    SolveResult,
    SolveStatus,
    StageRole,
    StageProvenance,
    UsageSummary,
)

__all__ = [
    "CANONICAL_SERIALIZER_VERSION",
    "CaptureArtifact",
    "CaptureConstraints",
    "CaptureRect",
    "CaptureScope",
    "CaptureScopeKind",
    "ConfidenceKind",
    "CoordinateSpace",
    "CanonicalQueryPolicy",
    "ComputeLocation",
    "ContractMarker",
    "CredentialInjectionSlot",
    "Digest256",
    "EXECUTION_PLAN_SCHEMA_VERSION",
    "ExecutionPlan",
    "ExecutionPlanNetworkOperation",
    "ExecutionPlanStage",
    "MAX_USER_HINT_CHARS",
    "NON_SECRET_HEADERS_SCHEMA_VERSION",
    "NetworkOperationPurpose",
    "NetworkScope",
    "NonSecretHeader",
    "OutboundDataKind",
    "OutputTokenLimit",
    "PipelineKind",
    "PREPARED_BODY_SCHEMA_VERSION",
    "PolicySnapshot",
    "PolicyValue",
    "PreparedOutbound",
    "QueryPolicyKind",
    "REQUEST_ENVELOPE_SCHEMA_VERSION",
    "RequiredConsentScope",
    "SOLVE_INTENT_SCHEMA_VERSION",
    "SolveIntent",
    "SolveProvenance",
    "SolveResult",
    "SolveStatus",
    "StageRole",
    "StageProvenance",
    "UsageSummary",
    "canonical_json_bytes",
    "digest256",
    "validate_capture_artifact",
    "validate_phase1_remote_direct_plan",
    "validate_prepared_outbound_against_plan",
]
