"""Privacy authorization contracts for the v3 pipeline."""

from importlib import import_module

from snapquiz.privacy.consent import (
    AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
    CONSENT_GRANT_SCHEMA_VERSION,
    CONSENT_NETWORK_OPERATION_SCHEMA_VERSION,
    CONSENT_POLICY_VERSION,
    AuthorizationContext,
    ConsentGrant,
    ConsentLedger,
    ConsentNetworkOperation,
    PrivacyGate,
    UnknownPolicyDimension,
)

__all__ = [
    "AUTHORIZATION_CONTEXT_SCHEMA_VERSION",
    "CONSENT_GRANT_SCHEMA_VERSION",
    "CONSENT_NETWORK_OPERATION_SCHEMA_VERSION",
    "CONSENT_POLICY_VERSION",
    "AuthorizationContext",
    "ConsentGrant",
    "ConsentLedger",
    "ConsentNetworkOperation",
    "PrivacyGate",
    "UnknownPolicyDimension",
    "EGRESS_APPROVAL_LIFETIME",
    "EGRESS_APPROVAL_SCHEMA_VERSION",
    "EGRESS_POLICY_VERSION",
    "EGRESS_PREVIEW_DECISION_SCHEMA_VERSION",
    "EGRESS_PREVIEW_SCHEMA_VERSION",
    "EgressApproval",
    "EgressApprovalLedger",
    "EgressGate",
    "EgressPreview",
    "EgressPreviewController",
    "EgressPreviewDecision",
]

_EGRESS_EXPORTS = frozenset(__all__[10:])


def __getattr__(name: str):
    """Load W08 contracts lazily to avoid the capture/privacy import cycle."""

    if name in _EGRESS_EXPORTS:
        module = import_module("snapquiz.privacy.egress")
        return getattr(module, name)
    raise AttributeError(name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(__all__))
