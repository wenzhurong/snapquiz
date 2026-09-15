"""Provider-neutral domain contracts.

This package stays importable with only the Python standard library: no
screen, credential, SDK, or network dependency.  It is the surviving core of
the v3 work; the Registry/Plan/routing layers that used to sit on top of it
were removed in the 2026-09 rebuild and live on tag ``v3-transport-research``.
"""

from snapquiz.domain.adapter import (
    ANSWER_CANDIDATE_SCHEMA_VERSION,
    MAX_PROVIDER_RESPONSE_BYTES,
    TRANSPORT_RESPONSE_SCHEMA_VERSION,
    AnswerCandidateResult,
    NormalizedRefusal,
    TransportResponse,
)
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
    SOLVE_INTENT_DIGEST_SCHEMA_VERSION,
    SOLVE_INTENT_SCHEMA_VERSION,
    OutputTokenLimit,
    SolveIntent,
)
from snapquiz.domain.outbound import (
    NON_SECRET_HEADERS_SCHEMA_VERSION,
    PREPARED_BODY_SCHEMA_VERSION,
    REQUEST_ENVELOPE_SCHEMA_VERSION,
    CredentialInjectionSlot,
    NonSecretHeader,
    OutboundDataKind,
    OutboundRequest,
    QueryPolicyKind,
)
from snapquiz.domain.policy import (
    ContractMarker,
    PolicySnapshot,
    PolicyValue,
    validate_policy_value_at,
)
from snapquiz.domain.solve import (
    ConfidenceKind,
    PipelineKind,
    SolveProvenance,
    SolveResult,
    SolveStatus,
    StageProvenance,
    StageRole,
    UsageSummary,
)

__all__ = [
    "ANSWER_CANDIDATE_SCHEMA_VERSION",
    "CANONICAL_SERIALIZER_VERSION",
    "MAX_PROVIDER_RESPONSE_BYTES",
    "MAX_USER_HINT_CHARS",
    "NON_SECRET_HEADERS_SCHEMA_VERSION",
    "PREPARED_BODY_SCHEMA_VERSION",
    "REQUEST_ENVELOPE_SCHEMA_VERSION",
    "SOLVE_INTENT_DIGEST_SCHEMA_VERSION",
    "SOLVE_INTENT_SCHEMA_VERSION",
    "TRANSPORT_RESPONSE_SCHEMA_VERSION",
    "AnswerCandidateResult",
    "CaptureArtifact",
    "CaptureConstraints",
    "CaptureRect",
    "CaptureScope",
    "CaptureScopeKind",
    "ConfidenceKind",
    "ContractMarker",
    "CoordinateSpace",
    "CredentialInjectionSlot",
    "Digest256",
    "NonSecretHeader",
    "NormalizedRefusal",
    "OutboundDataKind",
    "OutputTokenLimit",
    "PipelineKind",
    "PolicySnapshot",
    "PolicyValue",
    "OutboundRequest",
    "QueryPolicyKind",
    "SolveIntent",
    "SolveProvenance",
    "SolveResult",
    "SolveStatus",
    "StageProvenance",
    "StageRole",
    "TransportResponse",
    "UsageSummary",
    "canonical_json_bytes",
    "digest256",
    "validate_capture_artifact",
    "validate_policy_value_at",
]
