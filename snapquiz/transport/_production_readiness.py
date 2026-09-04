"""Pure/local W09 production-readiness evidence contract.

This module records the production facts that the local W09 foundations do
not provide.  Importing it and constructing a manifest perform no filesystem,
Security.framework, ``codesign``, DNS, socket, or process action.  Any adapter
that gathers those facts must be supplied explicitly to
``_assess_production_readiness`` through the narrow probe methods below.

An assessment is deliberately negative evidence only.  Even a fully verified
probe leaves ``production_authority_unavailable`` as a blocker and can never
mint a process, credential, DNS, socket, TLS, HTTP, or application authority.
The production integration flag must stay false until a separately reviewed
native owner and application wiring replace this inventory contract.
"""
from __future__ import annotations

from enum import Enum
import re
from typing import NamedTuple, NoReturn

from snapquiz.domain._validation import require_digest, runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.transport import _darwin_keychain_source as darwin_keychain
from snapquiz.transport import _exact_http1 as exact_http1
from snapquiz.transport import _exact_tls as exact_tls
from snapquiz.transport import _exact_transport as exact_transport


__all__ = ()


PRODUCTION_READINESS_MANIFEST_SCHEMA_VERSION = (
    "snapquiz.production-readiness-manifest.v5"
)
PRODUCTION_READINESS_ASSESSMENT_SCHEMA_VERSION = (
    "snapquiz.production-readiness-assessment.v1"
)

# This module is an inventory and fail-closed diagnostic boundary only.
PRODUCTION_READINESS_AUTHORITY_AVAILABLE = False
PRODUCTION_TRANSPORT_INTEGRATION_AVAILABLE = False

_MANIFEST_AUTHORITY = object()
_ASSESSMENT_AUTHORITY = object()
_CUTOVER_REQUIREMENT_AUTHORITY = object()

_BUNDLE_IDENTIFIER_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){2,}"
)
_TEAM_ID_RE = re.compile(r"[A-Z0-9]{10}")
_EXECUTABLE_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?")

REQUIRED_EXACT_TLS_POLICY_SCHEMA_VERSION = "snapquiz.tls-policy-proof.v1"
REQUIRED_EXACT_TLS_POLICY_REF = "snapquiz.tls.system-default-h1.v1"
REQUIRED_DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION = (
    "snapquiz.darwin-keychain-source.v1"
)
REQUIRED_PRODUCTION_CREDENTIAL_SOURCE_BINDING_VERSION = (
    "snapquiz.production-credential-source-binding.v1"
)
APPLICATION_KEYCHAIN_ENTITLEMENTS_SCHEMA_VERSION = (
    "snapquiz.application-keychain-entitlements.v1"
)
EXACT_TRANSPORT_BINDING_SCHEMA_VERSION = (
    "snapquiz.exact-transport-binding.v1"
)
REQUIRED_EXACT_TRANSPORT_POLICY_VERSION = "snapquiz.exact-transport-h1.v1"
REQUIRED_EXACT_WIRE_EVIDENCE_SCHEMA_VERSION = (
    "snapquiz.exact-wire-evidence.v2"
)
PRODUCTION_READINESS_MANIFEST_CONTENT_SCHEMA_VERSION = (
    "snapquiz.production-readiness-manifest-content.v1"
)
APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION = (
    "snapquiz.application-transport-cutover.v2"
)
APPLICATION_TRANSPORT_CUTOVER_PROBE_BINDING_SCHEMA_VERSION = (
    "snapquiz.application-transport-cutover-probe-binding.v1"
)
MACOS_APPLICATION_IDENTIFIER_ENTITLEMENT_KEY = (
    "com.apple.application-identifier"
)


class _ProbeState(str, Enum):
    VERIFIED = "verified"
    MISSING = "missing"
    UNKNOWN = "unknown"
    TAMPERED = "tampered"


class _ArtifactRole(str, Enum):
    SUPERVISOR = "supervisor"
    HELPER = "helper"


class _AttestationKind(str, Enum):
    SUSPENDED_PROCESS_IDENTITY = "suspended_process_identity"
    PRE_SECRET_STARTUP_COMPOSITION = "pre_secret_startup_composition"
    DURABLE_RESOLVER_OUTPUT = "durable_resolver_output"
    RESOLVER_START_PROTOCOL = "resolver_start_protocol"
    RAW_DNS_TRANSCRIPT = "raw_dns_transcript"
    NUMERIC_CONNECTION_PROOF = "numeric_connection_proof"
    EXACT_HTTP1_POLICY = "exact_http1_policy"
    EXACT_TLS_POLICY = "exact_tls_policy"
    EXACT_WIRE_EVIDENCE = "exact_wire_evidence"
    PRODUCTION_CREDENTIAL_SOURCE_BINDING = (
        "production_credential_source_binding"
    )
    APPLICATION_TRANSPORT_CUTOVER = "application_transport_cutover"


class _NativeCapability(str, Enum):
    FIXED_BUNDLE_STARTUP_OWNER = "fixed_bundle_startup_owner"
    NATIVE_ATOMIC_PROCESS_OUTCOME_OWNER = "native_atomic_process_outcome_owner"
    NATIVE_SOLE_REAPER = "native_sole_reaper"
    NATIVE_DURABLE_OUTPUT_ACK_OWNER = "native_durable_output_ack_owner"
    NATIVE_CONTROL_LIVENESS_OWNER = "native_control_liveness_owner"
    OPAQUE_NUMERIC_SOCKET_OWNER = "opaque_numeric_socket_owner"
    OPAQUE_TLS_SOCKET_OWNER = "opaque_tls_socket_owner"
    NATIVE_NUMERIC_TLS_TRANSFER_OWNER = "native_numeric_tls_transfer_owner"
    NATIVE_KEYCHAIN_BUFFER_OWNER = "native_keychain_buffer_owner"


class _ReadinessBlocker(str, Enum):
    PRODUCTION_AUTHORITY_UNAVAILABLE = "production_authority_unavailable"
    MANIFEST_TAMPERED = "manifest_tampered"
    PROBE_FAILED = "probe_failed"
    PROBE_CONTRACT_INVALID = "probe_contract_invalid"

    APP_BUNDLE_MISSING = "app_bundle_missing"
    APP_BUNDLE_UNKNOWN = "app_bundle_unknown"
    APP_BUNDLE_TAMPERED = "app_bundle_tampered"
    APP_BUNDLE_LAYOUT_INVALID = "app_bundle_layout_invalid"
    APP_BUNDLE_IDENTIFIER_MISMATCH = "app_bundle_identifier_mismatch"
    APP_BUNDLE_TEAM_MISMATCH = "app_bundle_team_mismatch"
    APP_BUNDLE_APPLICATION_IDENTIFIER_ENTITLEMENT_MISMATCH = (
        "app_bundle_application_identifier_entitlement_mismatch"
    )
    APP_BUNDLE_TEAM_IDENTIFIER_ENTITLEMENT_MISMATCH = (
        "app_bundle_team_identifier_entitlement_mismatch"
    )
    APP_BUNDLE_KEYCHAIN_ACCESS_GROUPS_ENTITLEMENT_MISMATCH = (
        "app_bundle_keychain_access_groups_entitlement_mismatch"
    )
    APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_VERSION_MISMATCH = (
        "app_bundle_keychain_entitlements_version_mismatch"
    )
    APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_DIGEST_MISMATCH = (
        "app_bundle_keychain_entitlements_digest_mismatch"
    )
    SIGNING_IDENTITY_UNAVAILABLE = "signing_identity_unavailable"
    APP_BUNDLE_CODESIGN_INVALID = "app_bundle_codesign_invalid"
    APP_BUNDLE_SECURITY_ASSESSMENT_INVALID = (
        "app_bundle_security_assessment_invalid"
    )

    SUPERVISOR_ARTIFACT_MISSING = "supervisor_artifact_missing"
    SUPERVISOR_ARTIFACT_UNKNOWN = "supervisor_artifact_unknown"
    SUPERVISOR_ARTIFACT_TAMPERED = "supervisor_artifact_tampered"
    SUPERVISOR_ARTIFACT_INVALID = "supervisor_artifact_invalid"
    HELPER_ARTIFACT_MISSING = "helper_artifact_missing"
    HELPER_ARTIFACT_UNKNOWN = "helper_artifact_unknown"
    HELPER_ARTIFACT_TAMPERED = "helper_artifact_tampered"
    HELPER_ARTIFACT_INVALID = "helper_artifact_invalid"

    ATTESTATION_MISSING = "attestation_missing"
    ATTESTATION_UNKNOWN = "attestation_unknown"
    ATTESTATION_TAMPERED = "attestation_tampered"
    ATTESTATION_VERSION_MISMATCH = "attestation_version_mismatch"
    ATTESTATION_DIGEST_MISMATCH = "attestation_digest_mismatch"

    EXACT_TLS_POLICY_MISSING = "exact_tls_policy_missing"
    EXACT_TLS_POLICY_UNKNOWN = "exact_tls_policy_unknown"
    EXACT_TLS_POLICY_TAMPERED = "exact_tls_policy_tampered"
    EXACT_TLS_POLICY_MISMATCH = "exact_tls_policy_mismatch"

    PRODUCTION_CREDENTIAL_SOURCE_BINDING_MISSING = (
        "production_credential_source_binding_missing"
    )
    PRODUCTION_CREDENTIAL_SOURCE_BINDING_UNKNOWN = (
        "production_credential_source_binding_unknown"
    )
    PRODUCTION_CREDENTIAL_SOURCE_BINDING_TAMPERED = (
        "production_credential_source_binding_tampered"
    )
    PRODUCTION_CREDENTIAL_SOURCE_BINDING_MISMATCH = (
        "production_credential_source_binding_mismatch"
    )
    APPLICATION_TRANSPORT_CUTOVER_MISSING = (
        "application_transport_cutover_missing"
    )
    APPLICATION_TRANSPORT_CUTOVER_UNKNOWN = (
        "application_transport_cutover_unknown"
    )
    APPLICATION_TRANSPORT_CUTOVER_TAMPERED = (
        "application_transport_cutover_tampered"
    )
    APPLICATION_TRANSPORT_CUTOVER_STALE_OR_REPLAYED = (
        "application_transport_cutover_stale_or_replayed"
    )
    APPLICATION_TRANSPORT_CUTOVER_MISMATCH = (
        "application_transport_cutover_mismatch"
    )
    NATIVE_CAPABILITY_MISSING = "native_capability_missing"
    NATIVE_CAPABILITY_UNKNOWN = "native_capability_unknown"
    NATIVE_CAPABILITY_TAMPERED = "native_capability_tampered"
    NATIVE_CAPABILITY_VERSION_MISMATCH = (
        "native_capability_version_mismatch"
    )

    DNS_EVIDENCE_MISSING = "dns_evidence_missing"
    DNS_EVIDENCE_UNKNOWN = "dns_evidence_unknown"
    DNS_EVIDENCE_TAMPERED = "dns_evidence_tampered"
    DNS_POLICY_MISMATCH = "dns_policy_mismatch"


class _AttestationRequirement(NamedTuple):
    kind: _AttestationKind
    version: str
    content_digest: Digest256 | None = None


class _NativeCapabilityRequirement(NamedTuple):
    capability: _NativeCapability
    interface_version: str


class _ExactTlsPolicyRequirement(NamedTuple):
    version: str
    hostname: str
    policy_ref: str
    policy_digest: Digest256


class _ApplicationKeychainEntitlementRequirement(NamedTuple):
    version: str
    application_identifier: str
    team_identifier: str
    keychain_access_groups: tuple[str, ...]
    content_digest: Digest256


class _ProductionCredentialSourceBindingRequirement(NamedTuple):
    version: str
    keychain_source_schema_version: str
    credential_ref: str
    service: str
    account: str
    access_group: str
    keychain_binding_digest: Digest256
    resolver_credential_ref: str
    resolver_binding_digest: Digest256
    resolver_mapping_digest: Digest256
    application_entitlements_digest: Digest256
    content_digest: Digest256


class _ExactTransportBindingRequirement(NamedTuple):
    version: str
    transport_policy_version: str
    wire_evidence_schema_version: str
    http1_policy_version: str
    http1_policy_digest: Digest256
    tls_policy_version: str
    tls_policy_ref: str
    tls_hostname: str
    tls_policy_digest: Digest256
    credential_source_binding_version: str
    credential_source_binding_digest: Digest256
    network_policy_version: str
    public_address_policy_digest: Digest256
    content_digest: Digest256


REQUIRED_EXACT_HTTP1_POLICY_DIGEST = Digest256(
    "16a5bc342f274e1d893a26de9417e75ead96b5cd2f06969faf09c6aba8a4d13c"
)


REQUIRED_ATTESTATION_VERSIONS = (
    _AttestationRequirement(
        _AttestationKind.SUSPENDED_PROCESS_IDENTITY,
        "snapquiz.darwin-suspended-identity-proof.v1",
    ),
    _AttestationRequirement(
        _AttestationKind.PRE_SECRET_STARTUP_COMPOSITION,
        "snapquiz.resolver-startup-composition-proof.v1",
    ),
    _AttestationRequirement(
        _AttestationKind.DURABLE_RESOLVER_OUTPUT,
        "snapquiz.resolver-output-observation.v1",
    ),
    _AttestationRequirement(
        _AttestationKind.RESOLVER_START_PROTOCOL,
        "snapquiz.resolver-start.v2",
    ),
    _AttestationRequirement(
        _AttestationKind.RAW_DNS_TRANSCRIPT,
        "snapquiz.raw-resolution-transcript.v2",
    ),
    _AttestationRequirement(
        _AttestationKind.NUMERIC_CONNECTION_PROOF,
        "snapquiz.numeric-connection-proof.v1",
    ),
    _AttestationRequirement(
        _AttestationKind.EXACT_HTTP1_POLICY,
        exact_http1.EXACT_HTTP1_POLICY_SCHEMA_VERSION,
        REQUIRED_EXACT_HTTP1_POLICY_DIGEST,
    ),
    _AttestationRequirement(
        _AttestationKind.EXACT_TLS_POLICY,
        REQUIRED_EXACT_TLS_POLICY_SCHEMA_VERSION,
    ),
    _AttestationRequirement(
        _AttestationKind.EXACT_WIRE_EVIDENCE,
        REQUIRED_EXACT_WIRE_EVIDENCE_SCHEMA_VERSION,
    ),
    _AttestationRequirement(
        _AttestationKind.PRODUCTION_CREDENTIAL_SOURCE_BINDING,
        REQUIRED_PRODUCTION_CREDENTIAL_SOURCE_BINDING_VERSION,
    ),
)

# These are required interfaces, not implementations or attestations that they
# currently exist.  In particular, a Python object that happens to wrap an FD
# is not evidence for any of these native/opaque ownership capabilities.
REQUIRED_NATIVE_CAPABILITIES = (
    _NativeCapabilityRequirement(
        _NativeCapability.FIXED_BUNDLE_STARTUP_OWNER,
        "snapquiz.fixed-bundle-startup-owner.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.NATIVE_ATOMIC_PROCESS_OUTCOME_OWNER,
        "snapquiz.native-atomic-process-outcome-owner.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.NATIVE_SOLE_REAPER,
        "snapquiz.native-sole-reaper.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.NATIVE_DURABLE_OUTPUT_ACK_OWNER,
        "snapquiz.native-durable-output-ack-owner.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.NATIVE_CONTROL_LIVENESS_OWNER,
        "snapquiz.native-control-liveness-owner.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.OPAQUE_NUMERIC_SOCKET_OWNER,
        "snapquiz.opaque-numeric-socket-owner.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.OPAQUE_TLS_SOCKET_OWNER,
        "snapquiz.opaque-tls-socket-owner.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.NATIVE_NUMERIC_TLS_TRANSFER_OWNER,
        "snapquiz.native-numeric-tls-transfer-owner.v1",
    ),
    _NativeCapabilityRequirement(
        _NativeCapability.NATIVE_KEYCHAIN_BUFFER_OWNER,
        "snapquiz.native-keychain-buffer-owner.v1",
    ),
)

REQUIRED_NETWORK_POLICY_VERSION = "remote-https.v1"
REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST = Digest256(
    "721939766c8857b23b1c079b1010e092b223835e490255466c7c47083d0b67a4"
)


class _BundleProbeRequest(NamedTuple):
    manifest_digest: Digest256
    app_bundle_identifier: str
    team_id: str
    keychain_entitlements_version: str
    application_identifier_entitlement: str
    team_identifier_entitlement: str
    keychain_access_groups_entitlement: tuple[str, ...]
    keychain_entitlements_digest: Digest256


class _ArtifactProbeRequest(NamedTuple):
    manifest_digest: Digest256
    role: _ArtifactRole
    bundle_relative_path: str
    sha256: Digest256
    signing_identifier: str
    team_id: str


class _AttestationProbeRequest(NamedTuple):
    manifest_digest: Digest256
    requirements: tuple[_AttestationRequirement, ...]


class _ExactTlsPolicyProbeRequest(NamedTuple):
    manifest_digest: Digest256
    requirement: _ExactTlsPolicyRequirement


class _ProductionCredentialSourceBindingProbeRequest(NamedTuple):
    manifest_digest: Digest256
    requirement: _ProductionCredentialSourceBindingRequirement


@runtime_final
class _AssessmentFreshnessChallenge:
    """Unpersistable identity token scoped to one local assessment call."""

    __slots__ = ()

    def __reduce__(self) -> NoReturn:
        raise TypeError("assessment freshness challenges are process-local")


class _ApplicationTransportCutoverProbeRequest(NamedTuple):
    manifest_digest: Digest256
    request_digest: Digest256
    freshness_challenge: object
    version: str
    manifest_content_digest: Digest256
    app_bundle_identifier: str
    team_id: str
    application_entrypoint_relative_path: str
    application_entrypoint_sha256: Digest256
    exact_transport_binding_version: str
    exact_transport_policy_version: str
    exact_wire_evidence_schema_version: str
    exact_http1_policy_version: str
    exact_http1_policy_digest: Digest256
    exact_tls_policy_version: str
    exact_tls_policy_ref: str
    exact_tls_hostname: str
    exact_tls_policy_digest: Digest256
    credential_source_binding_version: str
    credential_source_binding_digest: Digest256
    network_policy_version: str
    public_address_policy_digest: Digest256
    exact_transport_binding_digest: Digest256
    content_digest: Digest256


class _NativeCapabilityProbeRequest(NamedTuple):
    manifest_digest: Digest256
    requirements: tuple[_NativeCapabilityRequirement, ...]


class _DnsProbeRequest(NamedTuple):
    manifest_digest: Digest256
    network_policy_version: str
    public_address_policy_digest: Digest256


class _BundleProbeFact(NamedTuple):
    state: _ProbeState
    is_macos_app_bundle: bool | None
    bundle_identifier: str | None
    team_id: str | None
    usable_signing_identity_count: int | None
    codesign_valid: bool | None
    security_assessment_valid: bool | None
    keychain_entitlements_version: str | None = None
    application_identifier_entitlement: str | None = None
    team_identifier_entitlement: str | None = None
    keychain_access_groups_entitlement: tuple[str, ...] | None = None
    keychain_entitlements_digest: Digest256 | None = None


class _ArtifactProbeFact(NamedTuple):
    state: _ProbeState
    role: _ArtifactRole
    bundle_relative_path: str | None
    sha256: Digest256 | None
    is_macho: bool | None
    is_bundle_member: bool | None
    signing_identifier: str | None
    team_id: str | None
    codesign_valid: bool | None
    security_assessment_valid: bool | None


class _AttestationProbeFact(NamedTuple):
    kind: _AttestationKind
    state: _ProbeState
    version: str | None
    content_digest: Digest256 | None = None


class _ExactTlsPolicyProbeFact(NamedTuple):
    state: _ProbeState
    version: str | None
    hostname: str | None
    policy_ref: str | None
    policy_digest: Digest256 | None


class _ProductionCredentialSourceBindingProbeFact(NamedTuple):
    state: _ProbeState
    version: str | None
    keychain_source_schema_version: str | None
    credential_ref: str | None
    service: str | None
    account: str | None
    access_group: str | None
    keychain_binding_digest: Digest256 | None
    resolver_credential_ref: str | None
    resolver_binding_digest: Digest256 | None
    resolver_mapping_digest: Digest256 | None
    application_entitlements_digest: Digest256 | None
    content_digest: Digest256 | None


class _ApplicationTransportCutoverProbeFact(NamedTuple):
    state: _ProbeState
    manifest_digest: Digest256 | None
    request_digest: Digest256 | None
    freshness_challenge: object | None
    version: str | None
    manifest_content_digest: Digest256 | None
    app_bundle_identifier: str | None
    team_id: str | None
    application_entrypoint_relative_path: str | None
    application_entrypoint_sha256: Digest256 | None
    exact_transport_binding_version: str | None
    exact_transport_policy_version: str | None
    exact_wire_evidence_schema_version: str | None
    exact_http1_policy_version: str | None
    exact_http1_policy_digest: Digest256 | None
    exact_tls_policy_version: str | None
    exact_tls_policy_ref: str | None
    exact_tls_hostname: str | None
    exact_tls_policy_digest: Digest256 | None
    credential_source_binding_version: str | None
    credential_source_binding_digest: Digest256 | None
    network_policy_version: str | None
    public_address_policy_digest: Digest256 | None
    exact_transport_binding_digest: Digest256 | None
    content_digest: Digest256 | None


class _NativeCapabilityProbeFact(NamedTuple):
    capability: _NativeCapability
    state: _ProbeState
    interface_version: str | None


class _DnsProbeFact(NamedTuple):
    state: _ProbeState
    network_policy_version: str | None
    public_address_policy_digest: Digest256 | None
    public_candidate_set_attested: bool | None
    numeric_peer_match_attested: bool | None
    performed_without_http: bool | None


def _require_identifier(value: object, name: str) -> str:
    if (
        type(value) is not str
        or len(value) > 255
        or _BUNDLE_IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise ValueError(f"{name} must be a canonical reverse-DNS identifier")
    return value


def _require_team_id(value: object) -> str:
    if type(value) is not str or _TEAM_ID_RE.fullmatch(value) is None:
        raise ValueError("team_id must be an exact 10-character signing Team ID")
    return value


def _require_bundle_executable_path(
    value: object,
    *,
    role: _ArtifactRole,
) -> str:
    if type(value) is not str or len(value) > 255 or "\\" in value:
        raise ValueError("artifact path must be a safe bundle-relative path")
    parts = value.split("/")
    expected_prefix = (
        ("Contents", "Library", "LaunchServices")
        if role is _ArtifactRole.SUPERVISOR
        else ("Contents", "Helpers")
    )
    if (
        value.startswith("/")
        or len(parts) != len(expected_prefix) + 1
        or tuple(parts[:-1]) != expected_prefix
        or any(part in ("", ".", "..") for part in parts)
        or _EXECUTABLE_NAME_RE.fullmatch(parts[-1]) is None
    ):
        raise ValueError("artifact path is outside its fixed app-bundle directory")
    return value


def _require_application_entrypoint_path(value: object) -> str:
    if type(value) is not str or len(value) > 255 or "\\" in value:
        raise ValueError("application entrypoint must be a safe bundle-relative path")
    parts = value.split("/")
    if (
        value.startswith("/")
        or len(parts) != 3
        or tuple(parts[:2]) != ("Contents", "MacOS")
        or any(part in ("", ".", "..") for part in parts)
        or _EXECUTABLE_NAME_RE.fullmatch(parts[-1]) is None
    ):
        raise ValueError("application entrypoint is outside Contents/MacOS")
    return value


def _require_exact_tls_policy_binding(
    *,
    hostname: object,
    expected_digest: object,
) -> _ExactTlsPolicyRequirement:
    """Freeze one exact TLS policy without constructing an ``SSLContext``."""

    try:
        checked_hostname = exact_tls._require_canonical_hostname(hostname)
        checked_digest = require_digest(
            expected_digest,
            "exact_tls_policy_digest",
        )
        if (
            exact_tls.EXACT_TLS_POLICY_SCHEMA_VERSION
            != REQUIRED_EXACT_TLS_POLICY_SCHEMA_VERSION
            or exact_tls.EXACT_TLS_POLICY_REF != REQUIRED_EXACT_TLS_POLICY_REF
        ):
            raise ValueError("exact TLS policy identity changed")
        selected = digest256(
            "ExactTlsPolicy",
            REQUIRED_EXACT_TLS_POLICY_SCHEMA_VERSION,
            exact_tls._exact_tls_policy_payload(hostname=checked_hostname),
        )
    except BaseException:
        raise ValueError("exact TLS policy binding is unavailable") from None
    if selected != checked_digest:
        raise ValueError("exact TLS policy binding changed")
    return _ExactTlsPolicyRequirement(
        version=REQUIRED_EXACT_TLS_POLICY_SCHEMA_VERSION,
        hostname=checked_hostname,
        policy_ref=REQUIRED_EXACT_TLS_POLICY_REF,
        policy_digest=checked_digest,
    )


def _require_keychain_access_groups(
    value: object,
    *,
    team_id: str,
    selected_access_group: str,
) -> tuple[str, ...]:
    if type(value) is not tuple or not value or len(value) > 32:
        raise ValueError("app_keychain_access_groups must be a non-empty tuple")
    checked: list[str] = []
    for item in value:
        try:
            group = darwin_keychain._require_label(
                item,
                "app keychain access group",
            )
        except BaseException:
            raise ValueError("app keychain access group is invalid") from None
        if type(group) is not str or not group.startswith(team_id + "."):
            raise ValueError("app keychain access group uses another Team ID")
        checked.append(group)
    selected = tuple(checked)
    if (
        selected != tuple(sorted(selected))
        or len(set(selected)) != len(selected)
        or selected_access_group not in selected
    ):
        raise ValueError(
            "app keychain access groups must canonically include the source group"
        )
    return selected


def _application_keychain_entitlement_requirement(
    *,
    app_bundle_identifier: str,
    team_id: str,
    keychain_access_groups: tuple[str, ...],
) -> _ApplicationKeychainEntitlementRequirement:
    application_identifier = f"{team_id}.{app_bundle_identifier}"
    selected = digest256(
        "ApplicationKeychainEntitlements",
        APPLICATION_KEYCHAIN_ENTITLEMENTS_SCHEMA_VERSION,
        {
            MACOS_APPLICATION_IDENTIFIER_ENTITLEMENT_KEY: (
                application_identifier
            ),
            "com.apple.developer.team-identifier": team_id,
            "keychain-access-groups": keychain_access_groups,
        },
    )
    return _ApplicationKeychainEntitlementRequirement(
        version=APPLICATION_KEYCHAIN_ENTITLEMENTS_SCHEMA_VERSION,
        application_identifier=application_identifier,
        team_identifier=team_id,
        keychain_access_groups=keychain_access_groups,
        content_digest=selected,
    )


def _require_production_credential_source_binding(
    *,
    binding: object,
    app_bundle_identifier: str,
    team_id: str,
    app_keychain_access_groups: object,
) -> tuple[
    _ProductionCredentialSourceBindingRequirement,
    _ApplicationKeychainEntitlementRequirement,
]:
    """Freeze the existing Keychain binding and its resolver mapping."""

    try:
        if (
            type(binding) is not darwin_keychain._DarwinKeychainBinding
            or darwin_keychain.DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION
            != REQUIRED_DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION
            or darwin_keychain.PRODUCTION_CREDENTIAL_SOURCE_BINDING_ATTESTATION_VERSION
            != REQUIRED_PRODUCTION_CREDENTIAL_SOURCE_BINDING_VERSION
        ):
            raise ValueError("unsupported Keychain binding contract")
        keychain_snapshot = binding._validated_snapshot()
        resolver_snapshot = binding._validated_resolver_mapping_snapshot(
            keychain_snapshot
        )
    except BaseException:
        raise ValueError("production credential source binding is invalid") from None
    try:
        if type(keychain_snapshot) is not tuple or len(keychain_snapshot) != 5:
            raise ValueError("invalid Keychain snapshot")
        if type(resolver_snapshot) is not tuple or len(resolver_snapshot) != 3:
            raise ValueError("invalid resolver mapping snapshot")
        (
            credential_ref,
            service,
            account,
            access_group,
            keychain_binding_digest,
        ) = keychain_snapshot
        (
            resolver_credential_ref,
            resolver_binding_digest,
            resolver_mapping_digest,
        ) = resolver_snapshot
        exact_text = (
            credential_ref,
            service,
            account,
            access_group,
            resolver_credential_ref,
        )
        exact_digests = (
            keychain_binding_digest,
            resolver_binding_digest,
            resolver_mapping_digest,
        )
        if (
            any(type(value) is not str for value in exact_text)
            or any(type(value) is not Digest256 for value in exact_digests)
            or not access_group.startswith(team_id + ".")
        ):
            raise ValueError("incomplete Keychain binding")
        expected_keychain_digest = digest256(
            "DarwinKeychainBinding",
            REQUIRED_DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "credential_ref": credential_ref,
                "service": service,
                "account": account,
                "access_group": access_group,
            },
        )
        expected_mapping_digest = digest256(
            "DarwinKeychainResolverMapping",
            REQUIRED_DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "keychain_binding_digest": expected_keychain_digest,
                "resolver_credential_ref": resolver_credential_ref,
                "resolver_binding_digest": resolver_binding_digest,
            },
        )
        if (
            keychain_binding_digest != expected_keychain_digest
            or resolver_mapping_digest != expected_mapping_digest
        ):
            raise ValueError("Keychain content binding changed")
    except BaseException:
        raise ValueError(
            "production credential source requires an exact Team Keychain mapping"
        ) from None
    access_groups = _require_keychain_access_groups(
        app_keychain_access_groups,
        team_id=team_id,
        selected_access_group=access_group,
    )
    entitlements = _application_keychain_entitlement_requirement(
        app_bundle_identifier=app_bundle_identifier,
        team_id=team_id,
        keychain_access_groups=access_groups,
    )
    selected = digest256(
        "ProductionCredentialSourceBinding",
        REQUIRED_PRODUCTION_CREDENTIAL_SOURCE_BINDING_VERSION,
        {
            "account": account,
            "access_group": access_group,
            "application_entitlements_digest": entitlements.content_digest,
            "credential_ref": credential_ref,
            "keychain_binding_digest": keychain_binding_digest,
            "keychain_source_schema_version": (
                REQUIRED_DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION
            ),
            "resolver_binding_digest": resolver_binding_digest,
            "resolver_credential_ref": resolver_credential_ref,
            "resolver_mapping_digest": resolver_mapping_digest,
            "service": service,
        },
    )
    requirement = _ProductionCredentialSourceBindingRequirement(
        version=REQUIRED_PRODUCTION_CREDENTIAL_SOURCE_BINDING_VERSION,
        keychain_source_schema_version=(
            REQUIRED_DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION
        ),
        credential_ref=credential_ref,
        service=service,
        account=account,
        access_group=access_group,
        keychain_binding_digest=keychain_binding_digest,
        resolver_credential_ref=resolver_credential_ref,
        resolver_binding_digest=resolver_binding_digest,
        resolver_mapping_digest=resolver_mapping_digest,
        application_entitlements_digest=entitlements.content_digest,
        content_digest=selected,
    )
    return requirement, entitlements


def _bound_attestation_requirements(
    *,
    exact_tls_policy_digest: Digest256,
    credential_source_binding_digest: Digest256,
    application_transport_cutover_digest: Digest256 | None = None,
) -> tuple[_AttestationRequirement, ...]:
    selected = tuple(
        _AttestationRequirement(
            item.kind,
            item.version,
            (
                exact_tls_policy_digest
                if item.kind is _AttestationKind.EXACT_TLS_POLICY
                else credential_source_binding_digest
                if item.kind
                is _AttestationKind.PRODUCTION_CREDENTIAL_SOURCE_BINDING
                else item.content_digest
            ),
        )
        for item in REQUIRED_ATTESTATION_VERSIONS
    )
    if application_transport_cutover_digest is None:
        return selected
    return selected + (
        _AttestationRequirement(
            _AttestationKind.APPLICATION_TRANSPORT_CUTOVER,
            APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION,
            require_digest(
                application_transport_cutover_digest,
                "application_transport_cutover_digest",
            ),
        ),
    )


def _require_exact_http1_policy_binding() -> Digest256:
    try:
        selected = exact_http1._require_exact_http1_policy_digest()
    except BaseException:
        raise ValueError(
            "exact HTTP/1.1 policy binding is unavailable"
        ) from None
    if (
        type(REQUIRED_EXACT_HTTP1_POLICY_DIGEST) is not Digest256
        or selected != REQUIRED_EXACT_HTTP1_POLICY_DIGEST
    ):
        raise ValueError("exact HTTP/1.1 policy binding changed")
    return selected


def _exact_transport_binding_requirement(
    *,
    exact_http1_policy_digest: Digest256,
    exact_tls_policy_requirement: _ExactTlsPolicyRequirement,
    credential_source_binding_requirement: (
        _ProductionCredentialSourceBindingRequirement
    ),
) -> _ExactTransportBindingRequirement:
    try:
        http1_digest = require_digest(
            exact_http1_policy_digest,
            "exact_http1_policy_digest",
        )
        tls = exact_tls_policy_requirement
        credential = credential_source_binding_requirement
        if (
            type(tls) is not _ExactTlsPolicyRequirement
            or type(credential)
            is not _ProductionCredentialSourceBindingRequirement
            or exact_transport.EXACT_TRANSPORT_POLICY_VERSION
            != REQUIRED_EXACT_TRANSPORT_POLICY_VERSION
            or exact_transport.EXACT_WIRE_EVIDENCE_SCHEMA_VERSION
            != REQUIRED_EXACT_WIRE_EVIDENCE_SCHEMA_VERSION
        ):
            raise ValueError("exact transport contract changed")
        selected = digest256(
            "ExactTransportBinding",
            EXACT_TRANSPORT_BINDING_SCHEMA_VERSION,
            {
                "credential_source_binding_digest": credential.content_digest,
                "credential_source_binding_version": credential.version,
                "http1_policy_digest": http1_digest,
                "http1_policy_version": (
                    exact_http1.EXACT_HTTP1_POLICY_SCHEMA_VERSION
                ),
                "network_policy_version": REQUIRED_NETWORK_POLICY_VERSION,
                "public_address_policy_digest": (
                    REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST
                ),
                "tls_hostname": tls.hostname,
                "tls_policy_digest": tls.policy_digest,
                "tls_policy_ref": tls.policy_ref,
                "tls_policy_version": tls.version,
                "transport_policy_version": (
                    REQUIRED_EXACT_TRANSPORT_POLICY_VERSION
                ),
                "wire_evidence_schema_version": (
                    REQUIRED_EXACT_WIRE_EVIDENCE_SCHEMA_VERSION
                ),
            },
        )
    except BaseException:
        raise ValueError("exact transport binding is unavailable") from None
    return _ExactTransportBindingRequirement(
        version=EXACT_TRANSPORT_BINDING_SCHEMA_VERSION,
        transport_policy_version=REQUIRED_EXACT_TRANSPORT_POLICY_VERSION,
        wire_evidence_schema_version=(
            REQUIRED_EXACT_WIRE_EVIDENCE_SCHEMA_VERSION
        ),
        http1_policy_version=exact_http1.EXACT_HTTP1_POLICY_SCHEMA_VERSION,
        http1_policy_digest=http1_digest,
        tls_policy_version=tls.version,
        tls_policy_ref=tls.policy_ref,
        tls_hostname=tls.hostname,
        tls_policy_digest=tls.policy_digest,
        credential_source_binding_version=credential.version,
        credential_source_binding_digest=credential.content_digest,
        network_policy_version=REQUIRED_NETWORK_POLICY_VERSION,
        public_address_policy_digest=REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST,
        content_digest=selected,
    )


def _validate_exact_transport_binding_requirement(
    value: object,
) -> _ExactTransportBindingRequirement:
    try:
        if type(value) is not _ExactTransportBindingRequirement:
            raise ValueError("exact transport binding type changed")
        exact_text = (
            value.version,
            value.transport_policy_version,
            value.wire_evidence_schema_version,
            value.http1_policy_version,
            value.tls_policy_version,
            value.tls_policy_ref,
            value.tls_hostname,
            value.credential_source_binding_version,
            value.network_policy_version,
        )
        exact_digests = (
            value.http1_policy_digest,
            value.tls_policy_digest,
            value.credential_source_binding_digest,
            value.public_address_policy_digest,
            value.content_digest,
        )
        selected = digest256(
            "ExactTransportBinding",
            EXACT_TRANSPORT_BINDING_SCHEMA_VERSION,
            {
                "credential_source_binding_digest": (
                    value.credential_source_binding_digest
                ),
                "credential_source_binding_version": (
                    value.credential_source_binding_version
                ),
                "http1_policy_digest": value.http1_policy_digest,
                "http1_policy_version": value.http1_policy_version,
                "network_policy_version": value.network_policy_version,
                "public_address_policy_digest": (
                    value.public_address_policy_digest
                ),
                "tls_hostname": value.tls_hostname,
                "tls_policy_digest": value.tls_policy_digest,
                "tls_policy_ref": value.tls_policy_ref,
                "tls_policy_version": value.tls_policy_version,
                "transport_policy_version": value.transport_policy_version,
                "wire_evidence_schema_version": (
                    value.wire_evidence_schema_version
                ),
            },
        )
    except BaseException:
        raise ValueError("exact transport binding integrity failed") from None
    if (
        any(type(item) is not str for item in exact_text)
        or any(type(item) is not Digest256 for item in exact_digests)
        or value.version != EXACT_TRANSPORT_BINDING_SCHEMA_VERSION
        or value.transport_policy_version
        != REQUIRED_EXACT_TRANSPORT_POLICY_VERSION
        or value.wire_evidence_schema_version
        != REQUIRED_EXACT_WIRE_EVIDENCE_SCHEMA_VERSION
        or value.http1_policy_version
        != exact_http1.EXACT_HTTP1_POLICY_SCHEMA_VERSION
        or value.tls_policy_version != REQUIRED_EXACT_TLS_POLICY_SCHEMA_VERSION
        or value.tls_policy_ref != REQUIRED_EXACT_TLS_POLICY_REF
        or value.credential_source_binding_version
        != REQUIRED_PRODUCTION_CREDENTIAL_SOURCE_BINDING_VERSION
        or value.network_policy_version != REQUIRED_NETWORK_POLICY_VERSION
        or value.public_address_policy_digest
        != REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST
        or selected != value.content_digest
    ):
        raise ValueError("exact transport binding integrity failed")
    return value


def _application_transport_cutover_payload(
    *,
    manifest_content_digest: Digest256,
    app_bundle_identifier: str,
    team_id: str,
    application_entrypoint_relative_path: str,
    application_entrypoint_sha256: Digest256,
    exact_transport_binding_requirement: _ExactTransportBindingRequirement,
) -> dict[str, object]:
    return {
        "app_bundle_identifier": app_bundle_identifier,
        "application_entrypoint_relative_path": (
            application_entrypoint_relative_path
        ),
        "application_entrypoint_sha256": application_entrypoint_sha256,
        "exact_transport_binding_requirement": tuple(
            exact_transport_binding_requirement
        ),
        "manifest_content_digest": manifest_content_digest,
        "team_id": team_id,
    }


@runtime_final
class _ApplicationTransportCutoverRequirement:
    """Factory-only exact application-to-transport cutover subject."""

    __slots__ = (
        "version",
        "manifest_content_digest",
        "app_bundle_identifier",
        "team_id",
        "application_entrypoint_relative_path",
        "application_entrypoint_sha256",
        "exact_transport_binding_requirement",
        "content_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        manifest_content_digest: Digest256,
        app_bundle_identifier: str,
        team_id: str,
        application_entrypoint_relative_path: str,
        application_entrypoint_sha256: Digest256,
        exact_transport_binding_requirement: _ExactTransportBindingRequirement,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CUTOVER_REQUIREMENT_AUTHORITY:
            raise TypeError("application cutover requirements require their factory")
        manifest_content = require_digest(
            manifest_content_digest,
            "manifest_content_digest",
        )
        bundle_id = _require_identifier(
            app_bundle_identifier,
            "app_bundle_identifier",
        )
        checked_team_id = _require_team_id(team_id)
        entrypoint_path = _require_application_entrypoint_path(
            application_entrypoint_relative_path
        )
        entrypoint_digest = require_digest(
            application_entrypoint_sha256,
            "application_entrypoint_sha256",
        )
        transport = _validate_exact_transport_binding_requirement(
            exact_transport_binding_requirement
        )
        selected = digest256(
            "ApplicationTransportCutover",
            APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION,
            _application_transport_cutover_payload(
                manifest_content_digest=manifest_content,
                app_bundle_identifier=bundle_id,
                team_id=checked_team_id,
                application_entrypoint_relative_path=entrypoint_path,
                application_entrypoint_sha256=entrypoint_digest,
                exact_transport_binding_requirement=transport,
            ),
        )
        values = (
            ("version", APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION),
            ("manifest_content_digest", manifest_content),
            ("app_bundle_identifier", bundle_id),
            ("team_id", checked_team_id),
            ("application_entrypoint_relative_path", entrypoint_path),
            ("application_entrypoint_sha256", entrypoint_digest),
            ("exact_transport_binding_requirement", transport),
            ("content_digest", selected),
            ("_issued_digest", selected),
        )
        for name, value in values:
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del name, value
        raise AttributeError("ApplicationTransportCutoverRequirement is immutable")

    def __copy__(self) -> "_ApplicationTransportCutoverRequirement":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_ApplicationTransportCutoverRequirement":
        del memo
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("ApplicationTransportCutoverRequirement is process-local")

    def _validated_snapshot(self) -> tuple[object, ...]:
        try:
            selected = digest256(
                "ApplicationTransportCutover",
                APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION,
                _application_transport_cutover_payload(
                    manifest_content_digest=require_digest(
                        self.manifest_content_digest,
                        "manifest_content_digest",
                    ),
                    app_bundle_identifier=_require_identifier(
                        self.app_bundle_identifier,
                        "app_bundle_identifier",
                    ),
                    team_id=_require_team_id(self.team_id),
                    application_entrypoint_relative_path=(
                        _require_application_entrypoint_path(
                            self.application_entrypoint_relative_path
                        )
                    ),
                    application_entrypoint_sha256=require_digest(
                        self.application_entrypoint_sha256,
                        "application_entrypoint_sha256",
                    ),
                    exact_transport_binding_requirement=(
                        _validate_exact_transport_binding_requirement(
                            self.exact_transport_binding_requirement
                        )
                    ),
                ),
            )
        except BaseException:
            raise ValueError(
                "application transport cutover requirement integrity failed"
            ) from None
        snapshot = (
            self.version,
            self.manifest_content_digest,
            self.app_bundle_identifier,
            self.team_id,
            self.application_entrypoint_relative_path,
            self.application_entrypoint_sha256,
            tuple(self.exact_transport_binding_requirement),
            self.content_digest,
        )
        if (
            self.version != APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION
            or type(self.exact_transport_binding_requirement)
            is not _ExactTransportBindingRequirement
            or selected != self.content_digest
            or selected != self._issued_digest
        ):
            raise ValueError(
                "application transport cutover requirement integrity failed"
            )
        return snapshot

    def validate_integrity(self) -> None:
        self._validated_snapshot()


def _new_application_transport_cutover_requirement(
    *,
    manifest_content_digest: Digest256,
    app_bundle_identifier: str,
    team_id: str,
    application_entrypoint_relative_path: str,
    application_entrypoint_sha256: Digest256,
    exact_transport_binding_requirement: _ExactTransportBindingRequirement,
) -> _ApplicationTransportCutoverRequirement:
    return _ApplicationTransportCutoverRequirement(
        manifest_content_digest=manifest_content_digest,
        app_bundle_identifier=app_bundle_identifier,
        team_id=team_id,
        application_entrypoint_relative_path=application_entrypoint_relative_path,
        application_entrypoint_sha256=application_entrypoint_sha256,
        exact_transport_binding_requirement=exact_transport_binding_requirement,
        _authority=_CUTOVER_REQUIREMENT_AUTHORITY,
    )


def _manifest_content_payload(
    *,
    app_bundle_identifier: str,
    team_id: str,
    application_entrypoint_relative_path: str,
    application_entrypoint_sha256: Digest256,
    supervisor_relative_path: str,
    supervisor_sha256: Digest256,
    supervisor_signing_identifier: str,
    helper_relative_path: str,
    helper_sha256: Digest256,
    helper_signing_identifier: str,
    attestation_requirements: tuple[_AttestationRequirement, ...],
    exact_http1_policy_digest: Digest256,
    exact_tls_policy_requirement: _ExactTlsPolicyRequirement,
    application_keychain_entitlement_requirement: (
        _ApplicationKeychainEntitlementRequirement
    ),
    credential_source_binding_requirement: (
        _ProductionCredentialSourceBindingRequirement
    ),
    exact_transport_binding_requirement: _ExactTransportBindingRequirement,
) -> dict[str, object]:
    return {
        "app_bundle_identifier": app_bundle_identifier,
        "application_entrypoint_relative_path": (
            application_entrypoint_relative_path
        ),
        "application_entrypoint_sha256": application_entrypoint_sha256,
        "attestation_requirements": tuple(
            (item.kind.value, item.version, item.content_digest)
            for item in attestation_requirements
        ),
        "application_keychain_entitlement_requirement": tuple(
            application_keychain_entitlement_requirement
        ),
        "credential_source_binding_requirement": tuple(
            credential_source_binding_requirement
        ),
        "exact_http1_policy_digest": exact_http1_policy_digest,
        "exact_tls_policy_requirement": tuple(exact_tls_policy_requirement),
        "exact_transport_binding_requirement": tuple(
            exact_transport_binding_requirement
        ),
        "helper_relative_path": helper_relative_path,
        "helper_sha256": helper_sha256,
        "helper_signing_identifier": helper_signing_identifier,
        "native_capability_requirements": tuple(
            (item.capability.value, item.interface_version)
            for item in REQUIRED_NATIVE_CAPABILITIES
        ),
        "network_policy_version": REQUIRED_NETWORK_POLICY_VERSION,
        "public_address_policy_digest": REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST,
        "supervisor_relative_path": supervisor_relative_path,
        "supervisor_sha256": supervisor_sha256,
        "supervisor_signing_identifier": supervisor_signing_identifier,
        "team_id": team_id,
    }


def _manifest_payload(
    *,
    manifest_content_digest: Digest256,
    application_transport_cutover_requirement: (
        _ApplicationTransportCutoverRequirement
    ),
    **content: object,
) -> dict[str, object]:
    payload = _manifest_content_payload(**content)  # type: ignore[arg-type]
    payload.update(
        {
            "application_transport_cutover_requirement": (
                application_transport_cutover_requirement._validated_snapshot()
            ),
            "manifest_content_digest": manifest_content_digest,
        }
    )
    return payload


@runtime_final
class _ProductionReadinessManifest:
    """Factory-only immutable expectations for one production app bundle."""

    __slots__ = (
        "app_bundle_identifier",
        "team_id",
        "application_entrypoint_relative_path",
        "application_entrypoint_sha256",
        "supervisor_relative_path",
        "supervisor_sha256",
        "supervisor_signing_identifier",
        "helper_relative_path",
        "helper_sha256",
        "helper_signing_identifier",
        "attestation_requirements",
        "exact_http1_policy_digest",
        "exact_tls_policy_requirement",
        "application_keychain_entitlement_requirement",
        "credential_source_binding_requirement",
        "exact_transport_binding_requirement",
        "manifest_content_digest",
        "application_transport_cutover_requirement",
        "native_capability_requirements",
        "network_policy_version",
        "public_address_policy_digest",
        "manifest_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        app_bundle_identifier: str,
        team_id: str,
        application_entrypoint_relative_path: str,
        application_entrypoint_sha256: Digest256,
        supervisor_relative_path: str,
        supervisor_sha256: Digest256,
        supervisor_signing_identifier: str,
        helper_relative_path: str,
        helper_sha256: Digest256,
        helper_signing_identifier: str,
        exact_tls_hostname: str,
        exact_tls_policy_digest: Digest256,
        credential_source_binding: darwin_keychain._DarwinKeychainBinding,
        app_keychain_access_groups: tuple[str, ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _MANIFEST_AUTHORITY:
            raise TypeError("production readiness manifests require their factory")
        bundle_id = _require_identifier(
            app_bundle_identifier,
            "app_bundle_identifier",
        )
        checked_team_id = _require_team_id(team_id)
        entrypoint_path = _require_application_entrypoint_path(
            application_entrypoint_relative_path
        )
        entrypoint_digest = require_digest(
            application_entrypoint_sha256,
            "application_entrypoint_sha256",
        )
        supervisor_path = _require_bundle_executable_path(
            supervisor_relative_path,
            role=_ArtifactRole.SUPERVISOR,
        )
        helper_path = _require_bundle_executable_path(
            helper_relative_path,
            role=_ArtifactRole.HELPER,
        )
        supervisor_digest = require_digest(
            supervisor_sha256,
            "supervisor_sha256",
        )
        helper_digest = require_digest(helper_sha256, "helper_sha256")
        if supervisor_digest == helper_digest:
            raise ValueError("supervisor and helper artifact digests must differ")
        supervisor_identifier = _require_identifier(
            supervisor_signing_identifier,
            "supervisor_signing_identifier",
        )
        helper_identifier = _require_identifier(
            helper_signing_identifier,
            "helper_signing_identifier",
        )
        expected_prefix = bundle_id + "."
        if (
            not supervisor_identifier.startswith(expected_prefix)
            or not helper_identifier.startswith(expected_prefix)
            or supervisor_identifier == helper_identifier
        ):
            raise ValueError(
                "artifact signing identifiers must be distinct children of the app"
            )
        http1_policy_digest = _require_exact_http1_policy_binding()
        tls_policy_requirement = _require_exact_tls_policy_binding(
            hostname=exact_tls_hostname,
            expected_digest=exact_tls_policy_digest,
        )
        (
            credential_requirement,
            application_entitlement_requirement,
        ) = _require_production_credential_source_binding(
            binding=credential_source_binding,
            app_bundle_identifier=bundle_id,
            team_id=checked_team_id,
            app_keychain_access_groups=app_keychain_access_groups,
        )
        transport_binding_requirement = _exact_transport_binding_requirement(
            exact_http1_policy_digest=http1_policy_digest,
            exact_tls_policy_requirement=tls_policy_requirement,
            credential_source_binding_requirement=credential_requirement,
        )
        non_cutover_attestations = _bound_attestation_requirements(
            exact_tls_policy_digest=tls_policy_requirement.policy_digest,
            credential_source_binding_digest=credential_requirement.content_digest,
        )
        content_payload = _manifest_content_payload(
            app_bundle_identifier=bundle_id,
            team_id=checked_team_id,
            application_entrypoint_relative_path=entrypoint_path,
            application_entrypoint_sha256=entrypoint_digest,
            supervisor_relative_path=supervisor_path,
            supervisor_sha256=supervisor_digest,
            supervisor_signing_identifier=supervisor_identifier,
            helper_relative_path=helper_path,
            helper_sha256=helper_digest,
            helper_signing_identifier=helper_identifier,
            attestation_requirements=non_cutover_attestations,
            exact_http1_policy_digest=http1_policy_digest,
            exact_tls_policy_requirement=tls_policy_requirement,
            application_keychain_entitlement_requirement=(
                application_entitlement_requirement
            ),
            credential_source_binding_requirement=credential_requirement,
            exact_transport_binding_requirement=transport_binding_requirement,
        )
        manifest_content_digest = digest256(
            "ProductionReadinessManifestContent",
            PRODUCTION_READINESS_MANIFEST_CONTENT_SCHEMA_VERSION,
            content_payload,
        )
        cutover_requirement = _new_application_transport_cutover_requirement(
            manifest_content_digest=manifest_content_digest,
            app_bundle_identifier=bundle_id,
            team_id=checked_team_id,
            application_entrypoint_relative_path=entrypoint_path,
            application_entrypoint_sha256=entrypoint_digest,
            exact_transport_binding_requirement=transport_binding_requirement,
        )
        attestation_requirements = _bound_attestation_requirements(
            exact_tls_policy_digest=tls_policy_requirement.policy_digest,
            credential_source_binding_digest=credential_requirement.content_digest,
            application_transport_cutover_digest=(
                cutover_requirement.content_digest
            ),
        )
        payload = _manifest_payload(
            manifest_content_digest=manifest_content_digest,
            application_transport_cutover_requirement=cutover_requirement,
            app_bundle_identifier=bundle_id,
            team_id=checked_team_id,
            application_entrypoint_relative_path=entrypoint_path,
            application_entrypoint_sha256=entrypoint_digest,
            supervisor_relative_path=supervisor_path,
            supervisor_sha256=supervisor_digest,
            supervisor_signing_identifier=supervisor_identifier,
            helper_relative_path=helper_path,
            helper_sha256=helper_digest,
            helper_signing_identifier=helper_identifier,
            attestation_requirements=attestation_requirements,
            exact_http1_policy_digest=http1_policy_digest,
            exact_tls_policy_requirement=tls_policy_requirement,
            application_keychain_entitlement_requirement=(
                application_entitlement_requirement
            ),
            credential_source_binding_requirement=credential_requirement,
            exact_transport_binding_requirement=transport_binding_requirement,
        )
        selected = digest256(
            "ProductionReadinessManifest",
            PRODUCTION_READINESS_MANIFEST_SCHEMA_VERSION,
            payload,
        )
        values = (
            ("app_bundle_identifier", bundle_id),
            ("team_id", checked_team_id),
            ("application_entrypoint_relative_path", entrypoint_path),
            ("application_entrypoint_sha256", entrypoint_digest),
            ("supervisor_relative_path", supervisor_path),
            ("supervisor_sha256", supervisor_digest),
            ("supervisor_signing_identifier", supervisor_identifier),
            ("helper_relative_path", helper_path),
            ("helper_sha256", helper_digest),
            ("helper_signing_identifier", helper_identifier),
            ("attestation_requirements", attestation_requirements),
            ("exact_http1_policy_digest", http1_policy_digest),
            ("exact_tls_policy_requirement", tls_policy_requirement),
            (
                "application_keychain_entitlement_requirement",
                application_entitlement_requirement,
            ),
            (
                "credential_source_binding_requirement",
                credential_requirement,
            ),
            ("exact_transport_binding_requirement", transport_binding_requirement),
            ("manifest_content_digest", manifest_content_digest),
            ("application_transport_cutover_requirement", cutover_requirement),
            ("native_capability_requirements", REQUIRED_NATIVE_CAPABILITIES),
            ("network_policy_version", REQUIRED_NETWORK_POLICY_VERSION),
            ("public_address_policy_digest", REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST),
            ("manifest_digest", selected),
            ("_issued_digest", selected),
        )
        for name, value in values:
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del name, value
        raise AttributeError("ProductionReadinessManifest is immutable")

    def __copy__(self) -> "_ProductionReadinessManifest":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_ProductionReadinessManifest":
        del memo
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProductionReadinessManifest is process-local")

    def validate_integrity(self) -> None:
        try:
            http1_policy_digest = _require_exact_http1_policy_binding()
            entrypoint_path = _require_application_entrypoint_path(
                self.application_entrypoint_relative_path
            )
            entrypoint_digest = require_digest(
                self.application_entrypoint_sha256,
                "application_entrypoint_sha256",
            )
            tls_requirement = self.exact_tls_policy_requirement
            entitlement_requirement = (
                self.application_keychain_entitlement_requirement
            )
            credential_requirement = self.credential_source_binding_requirement
            transport_requirement = self.exact_transport_binding_requirement
            cutover_requirement = (
                self.application_transport_cutover_requirement
            )
            if (
                type(tls_requirement) is not _ExactTlsPolicyRequirement
                or type(entitlement_requirement)
                is not _ApplicationKeychainEntitlementRequirement
                or type(credential_requirement)
                is not _ProductionCredentialSourceBindingRequirement
                or type(transport_requirement)
                is not _ExactTransportBindingRequirement
                or type(cutover_requirement)
                is not _ApplicationTransportCutoverRequirement
            ):
                raise ValueError("manifest requirement type changed")
            rebuilt_tls_requirement = _require_exact_tls_policy_binding(
                hostname=tls_requirement.hostname,
                expected_digest=tls_requirement.policy_digest,
            )
            rebuilt_binding = darwin_keychain._new_darwin_keychain_binding(
                credential_ref=credential_requirement.credential_ref,
                service=credential_requirement.service,
                account=credential_requirement.account,
                access_group=credential_requirement.access_group,
                resolver_credential_ref=(
                    credential_requirement.resolver_credential_ref
                ),
                resolver_binding_digest=(
                    credential_requirement.resolver_binding_digest
                ),
            )
            (
                rebuilt_credential_requirement,
                rebuilt_entitlement_requirement,
            ) = _require_production_credential_source_binding(
                binding=rebuilt_binding,
                app_bundle_identifier=self.app_bundle_identifier,
                team_id=self.team_id,
                app_keychain_access_groups=(
                    entitlement_requirement.keychain_access_groups
                ),
            )
            rebuilt_transport_requirement = (
                _exact_transport_binding_requirement(
                    exact_http1_policy_digest=http1_policy_digest,
                    exact_tls_policy_requirement=rebuilt_tls_requirement,
                    credential_source_binding_requirement=(
                        rebuilt_credential_requirement
                    ),
                )
            )
            non_cutover_attestations = _bound_attestation_requirements(
                exact_tls_policy_digest=rebuilt_tls_requirement.policy_digest,
                credential_source_binding_digest=(
                    rebuilt_credential_requirement.content_digest
                ),
            )
            rebuilt_manifest_content_digest = digest256(
                "ProductionReadinessManifestContent",
                PRODUCTION_READINESS_MANIFEST_CONTENT_SCHEMA_VERSION,
                _manifest_content_payload(
                    app_bundle_identifier=self.app_bundle_identifier,
                    team_id=self.team_id,
                    application_entrypoint_relative_path=entrypoint_path,
                    application_entrypoint_sha256=entrypoint_digest,
                    supervisor_relative_path=self.supervisor_relative_path,
                    supervisor_sha256=self.supervisor_sha256,
                    supervisor_signing_identifier=(
                        self.supervisor_signing_identifier
                    ),
                    helper_relative_path=self.helper_relative_path,
                    helper_sha256=self.helper_sha256,
                    helper_signing_identifier=self.helper_signing_identifier,
                    attestation_requirements=non_cutover_attestations,
                    exact_http1_policy_digest=http1_policy_digest,
                    exact_tls_policy_requirement=rebuilt_tls_requirement,
                    application_keychain_entitlement_requirement=(
                        rebuilt_entitlement_requirement
                    ),
                    credential_source_binding_requirement=(
                        rebuilt_credential_requirement
                    ),
                    exact_transport_binding_requirement=(
                        rebuilt_transport_requirement
                    ),
                ),
            )
            rebuilt_cutover_requirement = (
                _new_application_transport_cutover_requirement(
                    manifest_content_digest=rebuilt_manifest_content_digest,
                    app_bundle_identifier=self.app_bundle_identifier,
                    team_id=self.team_id,
                    application_entrypoint_relative_path=entrypoint_path,
                    application_entrypoint_sha256=entrypoint_digest,
                    exact_transport_binding_requirement=(
                        rebuilt_transport_requirement
                    ),
                )
            )
            expected_attestations = _bound_attestation_requirements(
                exact_tls_policy_digest=rebuilt_tls_requirement.policy_digest,
                credential_source_binding_digest=(
                    rebuilt_credential_requirement.content_digest
                ),
                application_transport_cutover_digest=(
                    rebuilt_cutover_requirement.content_digest
                ),
            )
            selected = digest256(
                "ProductionReadinessManifest",
                PRODUCTION_READINESS_MANIFEST_SCHEMA_VERSION,
                _manifest_payload(
                    manifest_content_digest=rebuilt_manifest_content_digest,
                    application_transport_cutover_requirement=(
                        rebuilt_cutover_requirement
                    ),
                    app_bundle_identifier=self.app_bundle_identifier,
                    team_id=self.team_id,
                    application_entrypoint_relative_path=entrypoint_path,
                    application_entrypoint_sha256=entrypoint_digest,
                    supervisor_relative_path=self.supervisor_relative_path,
                    supervisor_sha256=self.supervisor_sha256,
                    supervisor_signing_identifier=(
                        self.supervisor_signing_identifier
                    ),
                    helper_relative_path=self.helper_relative_path,
                    helper_sha256=self.helper_sha256,
                    helper_signing_identifier=self.helper_signing_identifier,
                    attestation_requirements=expected_attestations,
                    exact_http1_policy_digest=http1_policy_digest,
                    exact_tls_policy_requirement=rebuilt_tls_requirement,
                    application_keychain_entitlement_requirement=(
                        rebuilt_entitlement_requirement
                    ),
                    credential_source_binding_requirement=(
                        rebuilt_credential_requirement
                    ),
                    exact_transport_binding_requirement=(
                        rebuilt_transport_requirement
                    ),
                ),
            )
        except BaseException:
            raise ValueError("production readiness manifest integrity failed") from None
        if (
            self.attestation_requirements != expected_attestations
            or rebuilt_tls_requirement != tls_requirement
            or rebuilt_entitlement_requirement != entitlement_requirement
            or rebuilt_credential_requirement != credential_requirement
            or rebuilt_transport_requirement != transport_requirement
            or cutover_requirement._validated_snapshot()
            != rebuilt_cutover_requirement._validated_snapshot()
            or self.manifest_content_digest
            != rebuilt_manifest_content_digest
            or self.exact_http1_policy_digest != http1_policy_digest
            or self.native_capability_requirements
            is not REQUIRED_NATIVE_CAPABILITIES
            or self.network_policy_version != REQUIRED_NETWORK_POLICY_VERSION
            or self.public_address_policy_digest
            != REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST
            or selected != self.manifest_digest
            or selected != self._issued_digest
        ):
            raise ValueError("production readiness manifest integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "manifest_digest": self.manifest_digest,
            "exact_http1_policy_digest": self.exact_http1_policy_digest,
            "exact_tls_policy_digest": (
                self.exact_tls_policy_requirement.policy_digest
            ),
            "keychain_binding_digest": (
                self.credential_source_binding_requirement.keychain_binding_digest
            ),
            "resolver_mapping_digest": (
                self.credential_source_binding_requirement.resolver_mapping_digest
            ),
            "application_keychain_entitlements_digest": (
                self.application_keychain_entitlement_requirement.content_digest
            ),
            "application_entrypoint_sha256": (
                self.application_entrypoint_sha256
            ),
            "exact_transport_binding_digest": (
                self.exact_transport_binding_requirement.content_digest
            ),
            "manifest_content_digest": self.manifest_content_digest,
            "application_transport_cutover_digest": (
                self.application_transport_cutover_requirement.content_digest
            ),
            "attestation_requirement_count": len(self.attestation_requirements),
            "native_capability_requirement_count": len(
                self.native_capability_requirements
            ),
            "production_authority_available": False,
        }


def _new_production_readiness_manifest(
    *,
    app_bundle_identifier: str,
    team_id: str,
    application_entrypoint_relative_path: str,
    application_entrypoint_sha256: Digest256,
    supervisor_relative_path: str,
    supervisor_sha256: Digest256,
    supervisor_signing_identifier: str,
    helper_relative_path: str,
    helper_sha256: Digest256,
    helper_signing_identifier: str,
    exact_tls_hostname: str,
    exact_tls_policy_digest: Digest256,
    credential_source_binding: darwin_keychain._DarwinKeychainBinding,
    app_keychain_access_groups: tuple[str, ...],
) -> _ProductionReadinessManifest:
    return _ProductionReadinessManifest(
        app_bundle_identifier=app_bundle_identifier,
        team_id=team_id,
        application_entrypoint_relative_path=application_entrypoint_relative_path,
        application_entrypoint_sha256=application_entrypoint_sha256,
        supervisor_relative_path=supervisor_relative_path,
        supervisor_sha256=supervisor_sha256,
        supervisor_signing_identifier=supervisor_signing_identifier,
        helper_relative_path=helper_relative_path,
        helper_sha256=helper_sha256,
        helper_signing_identifier=helper_signing_identifier,
        exact_tls_hostname=exact_tls_hostname,
        exact_tls_policy_digest=exact_tls_policy_digest,
        credential_source_binding=credential_source_binding,
        app_keychain_access_groups=app_keychain_access_groups,
        _authority=_MANIFEST_AUTHORITY,
    )


def _seal_manifest_snapshot(
    manifest: _ProductionReadinessManifest,
) -> _ProductionReadinessManifest:
    """Return an independently validated snapshot for all probe requests.

    A probe is external code.  It must never be able to change the source
    manifest between calls and thereby redirect a later filesystem/signing
    inspection to a different path or identity.  The fresh factory value owns
    only immutable primitives and the frozen module requirements; it is never
    shared with the probe itself.
    """

    manifest.validate_integrity()
    snapshot = _ProductionReadinessManifest(
        app_bundle_identifier=manifest.app_bundle_identifier,
        team_id=manifest.team_id,
        application_entrypoint_relative_path=(
            manifest.application_entrypoint_relative_path
        ),
        application_entrypoint_sha256=manifest.application_entrypoint_sha256,
        supervisor_relative_path=manifest.supervisor_relative_path,
        supervisor_sha256=manifest.supervisor_sha256,
        supervisor_signing_identifier=manifest.supervisor_signing_identifier,
        helper_relative_path=manifest.helper_relative_path,
        helper_sha256=manifest.helper_sha256,
        helper_signing_identifier=manifest.helper_signing_identifier,
        exact_tls_hostname=manifest.exact_tls_policy_requirement.hostname,
        exact_tls_policy_digest=(
            manifest.exact_tls_policy_requirement.policy_digest
        ),
        credential_source_binding=darwin_keychain._new_darwin_keychain_binding(
            credential_ref=(
                manifest.credential_source_binding_requirement.credential_ref
            ),
            service=manifest.credential_source_binding_requirement.service,
            account=manifest.credential_source_binding_requirement.account,
            access_group=(
                manifest.credential_source_binding_requirement.access_group
            ),
            resolver_credential_ref=(
                manifest.credential_source_binding_requirement.resolver_credential_ref
            ),
            resolver_binding_digest=(
                manifest.credential_source_binding_requirement.resolver_binding_digest
            ),
        ),
        app_keychain_access_groups=(
            manifest.application_keychain_entitlement_requirement.keychain_access_groups
        ),
        _authority=_MANIFEST_AUTHORITY,
    )
    if (
        snapshot.manifest_digest != manifest.manifest_digest
        or snapshot.manifest_digest != manifest._issued_digest
    ):
        raise ValueError("production readiness manifest snapshot failed")
    return snapshot


def _status_blocker(
    state: _ProbeState,
    *,
    missing: _ReadinessBlocker,
    unknown: _ReadinessBlocker,
    tampered: _ReadinessBlocker,
) -> _ReadinessBlocker | None:
    if state is _ProbeState.MISSING:
        return missing
    if state is _ProbeState.UNKNOWN:
        return unknown
    if state is _ProbeState.TAMPERED:
        return tampered
    return None


def _assess_bundle(
    manifest: _ProductionReadinessManifest,
    fact: object,
) -> set[_ReadinessBlocker]:
    if type(fact) is not _BundleProbeFact or type(fact.state) is not _ProbeState:
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    status = _status_blocker(
        fact.state,
        missing=_ReadinessBlocker.APP_BUNDLE_MISSING,
        unknown=_ReadinessBlocker.APP_BUNDLE_UNKNOWN,
        tampered=_ReadinessBlocker.APP_BUNDLE_TAMPERED,
    )
    if status is not None:
        return {status}
    blockers: set[_ReadinessBlocker] = set()
    if type(fact.is_macos_app_bundle) is not bool or not fact.is_macos_app_bundle:
        blockers.add(_ReadinessBlocker.APP_BUNDLE_LAYOUT_INVALID)
    if (
        type(fact.bundle_identifier) is not str
        or fact.bundle_identifier != manifest.app_bundle_identifier
    ):
        blockers.add(_ReadinessBlocker.APP_BUNDLE_IDENTIFIER_MISMATCH)
    if type(fact.team_id) is not str or fact.team_id != manifest.team_id:
        blockers.add(_ReadinessBlocker.APP_BUNDLE_TEAM_MISMATCH)
    entitlement_requirement = (
        manifest.application_keychain_entitlement_requirement
    )
    if (
        type(fact.keychain_entitlements_version) is not str
        or fact.keychain_entitlements_version != entitlement_requirement.version
    ):
        blockers.add(
            _ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_VERSION_MISMATCH
        )
    if (
        type(fact.application_identifier_entitlement) is not str
        or fact.application_identifier_entitlement
        != entitlement_requirement.application_identifier
    ):
        blockers.add(
            _ReadinessBlocker.APP_BUNDLE_APPLICATION_IDENTIFIER_ENTITLEMENT_MISMATCH
        )
    if (
        type(fact.team_identifier_entitlement) is not str
        or fact.team_identifier_entitlement
        != entitlement_requirement.team_identifier
    ):
        blockers.add(
            _ReadinessBlocker.APP_BUNDLE_TEAM_IDENTIFIER_ENTITLEMENT_MISMATCH
        )
    if (
        type(fact.keychain_access_groups_entitlement) is not tuple
        or any(
            type(item) is not str
            for item in fact.keychain_access_groups_entitlement
        )
        or fact.keychain_access_groups_entitlement
        != entitlement_requirement.keychain_access_groups
    ):
        blockers.add(
            _ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ACCESS_GROUPS_ENTITLEMENT_MISMATCH
        )
    if (
        type(fact.keychain_entitlements_digest) is not Digest256
        or fact.keychain_entitlements_digest
        != entitlement_requirement.content_digest
    ):
        blockers.add(
            _ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_DIGEST_MISMATCH
        )
    if (
        type(fact.usable_signing_identity_count) is not int
        or fact.usable_signing_identity_count < 1
    ):
        blockers.add(_ReadinessBlocker.SIGNING_IDENTITY_UNAVAILABLE)
    if type(fact.codesign_valid) is not bool or not fact.codesign_valid:
        blockers.add(_ReadinessBlocker.APP_BUNDLE_CODESIGN_INVALID)
    if (
        type(fact.security_assessment_valid) is not bool
        or not fact.security_assessment_valid
    ):
        blockers.add(
            _ReadinessBlocker.APP_BUNDLE_SECURITY_ASSESSMENT_INVALID
        )
    return blockers


def _artifact_status_blocker(
    role: _ArtifactRole,
    state: _ProbeState,
) -> _ReadinessBlocker | None:
    if role is _ArtifactRole.SUPERVISOR:
        return _status_blocker(
            state,
            missing=_ReadinessBlocker.SUPERVISOR_ARTIFACT_MISSING,
            unknown=_ReadinessBlocker.SUPERVISOR_ARTIFACT_UNKNOWN,
            tampered=_ReadinessBlocker.SUPERVISOR_ARTIFACT_TAMPERED,
        )
    return _status_blocker(
        state,
        missing=_ReadinessBlocker.HELPER_ARTIFACT_MISSING,
        unknown=_ReadinessBlocker.HELPER_ARTIFACT_UNKNOWN,
        tampered=_ReadinessBlocker.HELPER_ARTIFACT_TAMPERED,
    )


def _assess_artifact(
    manifest: _ProductionReadinessManifest,
    *,
    role: _ArtifactRole,
    fact: object,
) -> set[_ReadinessBlocker]:
    if (
        type(fact) is not _ArtifactProbeFact
        or type(fact.state) is not _ProbeState
        or type(fact.role) is not _ArtifactRole
        or fact.role is not role
    ):
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    status = _artifact_status_blocker(role, fact.state)
    if status is not None:
        return {status}
    if role is _ArtifactRole.SUPERVISOR:
        expected = (
            manifest.supervisor_relative_path,
            manifest.supervisor_sha256,
            manifest.supervisor_signing_identifier,
        )
        invalid = _ReadinessBlocker.SUPERVISOR_ARTIFACT_INVALID
    else:
        expected = (
            manifest.helper_relative_path,
            manifest.helper_sha256,
            manifest.helper_signing_identifier,
        )
        invalid = _ReadinessBlocker.HELPER_ARTIFACT_INVALID
    exact_bools = (
        fact.is_macho,
        fact.is_bundle_member,
        fact.codesign_valid,
        fact.security_assessment_valid,
    )
    if (
        type(fact.bundle_relative_path) is not str
        or type(fact.sha256) is not Digest256
        or type(fact.signing_identifier) is not str
        or type(fact.team_id) is not str
        or (
            fact.bundle_relative_path,
            fact.sha256,
            fact.signing_identifier,
        )
        != expected
        or fact.team_id != manifest.team_id
        or any(type(value) is not bool or not value for value in exact_bools)
    ):
        return {invalid}
    return set()


def _assess_attestations(
    requirements: tuple[_AttestationRequirement, ...],
    facts: object,
) -> set[_ReadinessBlocker]:
    if type(facts) is not tuple or any(
        type(fact) is not _AttestationProbeFact
        or type(fact.kind) is not _AttestationKind
        or type(fact.state) is not _ProbeState
        for fact in facts
    ):
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    by_kind: dict[_AttestationKind, _AttestationProbeFact] = {}
    for fact in facts:
        if fact.kind in by_kind:
            return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
        by_kind[fact.kind] = fact
    blockers: set[_ReadinessBlocker] = set()
    for requirement in requirements:
        fact = by_kind.get(requirement.kind)
        if fact is None:
            blockers.add(_ReadinessBlocker.ATTESTATION_MISSING)
            continue
        status = _status_blocker(
            fact.state,
            missing=_ReadinessBlocker.ATTESTATION_MISSING,
            unknown=_ReadinessBlocker.ATTESTATION_UNKNOWN,
            tampered=_ReadinessBlocker.ATTESTATION_TAMPERED,
        )
        if status is not None:
            blockers.add(status)
        elif type(fact.version) is not str or fact.version != requirement.version:
            blockers.add(_ReadinessBlocker.ATTESTATION_VERSION_MISMATCH)
        elif requirement.content_digest is None:
            if fact.content_digest is not None:
                blockers.add(_ReadinessBlocker.PROBE_CONTRACT_INVALID)
        elif (
            type(fact.content_digest) is not Digest256
            or fact.content_digest != requirement.content_digest
        ):
            blockers.add(_ReadinessBlocker.ATTESTATION_DIGEST_MISMATCH)
    if set(by_kind) != {item.kind for item in requirements}:
        blockers.add(_ReadinessBlocker.PROBE_CONTRACT_INVALID)
    return blockers


def _assess_exact_tls_policy(
    requirement: _ExactTlsPolicyRequirement,
    fact: object,
) -> set[_ReadinessBlocker]:
    if (
        type(fact) is not _ExactTlsPolicyProbeFact
        or type(fact.state) is not _ProbeState
    ):
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    status = _status_blocker(
        fact.state,
        missing=_ReadinessBlocker.EXACT_TLS_POLICY_MISSING,
        unknown=_ReadinessBlocker.EXACT_TLS_POLICY_UNKNOWN,
        tampered=_ReadinessBlocker.EXACT_TLS_POLICY_TAMPERED,
    )
    if status is not None:
        return {status}
    if (
        type(fact.version) is not str
        or type(fact.hostname) is not str
        or type(fact.policy_ref) is not str
        or type(fact.policy_digest) is not Digest256
        or (
            fact.version,
            fact.hostname,
            fact.policy_ref,
            fact.policy_digest,
        )
        != tuple(requirement)
    ):
        return {_ReadinessBlocker.EXACT_TLS_POLICY_MISMATCH}
    return set()


def _assess_production_credential_source_binding(
    requirement: _ProductionCredentialSourceBindingRequirement,
    fact: object,
) -> set[_ReadinessBlocker]:
    if (
        type(fact) is not _ProductionCredentialSourceBindingProbeFact
        or type(fact.state) is not _ProbeState
    ):
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    status = _status_blocker(
        fact.state,
        missing=(
            _ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_MISSING
        ),
        unknown=(
            _ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_UNKNOWN
        ),
        tampered=(
            _ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_TAMPERED
        ),
    )
    if status is not None:
        return {status}
    exact_text = (
        fact.version,
        fact.keychain_source_schema_version,
        fact.credential_ref,
        fact.service,
        fact.account,
        fact.access_group,
        fact.resolver_credential_ref,
    )
    exact_digests = (
        fact.keychain_binding_digest,
        fact.resolver_binding_digest,
        fact.resolver_mapping_digest,
        fact.application_entitlements_digest,
        fact.content_digest,
    )
    if (
        any(type(value) is not str for value in exact_text)
        or any(type(value) is not Digest256 for value in exact_digests)
        or (
            fact.version,
            fact.keychain_source_schema_version,
            fact.credential_ref,
            fact.service,
            fact.account,
            fact.access_group,
            fact.keychain_binding_digest,
            fact.resolver_credential_ref,
            fact.resolver_binding_digest,
            fact.resolver_mapping_digest,
            fact.application_entitlements_digest,
            fact.content_digest,
        )
        != tuple(requirement)
    ):
        return {
            _ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_MISMATCH
        }
    return set()


def _assess_application_transport_cutover(
    request: _ApplicationTransportCutoverProbeRequest,
    fact: object,
) -> set[_ReadinessBlocker]:
    if (
        type(fact) is not _ApplicationTransportCutoverProbeFact
        or type(fact.state) is not _ProbeState
    ):
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    status = _status_blocker(
        fact.state,
        missing=_ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_MISSING,
        unknown=_ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_UNKNOWN,
        tampered=_ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_TAMPERED,
    )
    if status is not None:
        return {status}
    if (
        type(fact.manifest_digest) is not Digest256
        or type(fact.request_digest) is not Digest256
        or fact.manifest_digest != request.manifest_digest
        or fact.request_digest != request.request_digest
        or fact.freshness_challenge is not request.freshness_challenge
    ):
        return {
            _ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_STALE_OR_REPLAYED
        }
    exact_text = (
        fact.version,
        fact.app_bundle_identifier,
        fact.team_id,
        fact.application_entrypoint_relative_path,
        fact.exact_transport_binding_version,
        fact.exact_transport_policy_version,
        fact.exact_wire_evidence_schema_version,
        fact.exact_http1_policy_version,
        fact.exact_tls_policy_version,
        fact.exact_tls_policy_ref,
        fact.exact_tls_hostname,
        fact.credential_source_binding_version,
        fact.network_policy_version,
    )
    exact_digests = (
        fact.manifest_content_digest,
        fact.application_entrypoint_sha256,
        fact.exact_http1_policy_digest,
        fact.exact_tls_policy_digest,
        fact.credential_source_binding_digest,
        fact.public_address_policy_digest,
        fact.exact_transport_binding_digest,
        fact.content_digest,
    )
    if (
        any(type(value) is not str for value in exact_text)
        or any(type(value) is not Digest256 for value in exact_digests)
        or fact[4:] != request[3:]
    ):
        return {_ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_MISMATCH}
    return set()


def _assess_native_capabilities(facts: object) -> set[_ReadinessBlocker]:
    if type(facts) is not tuple or any(
        type(fact) is not _NativeCapabilityProbeFact
        or type(fact.capability) is not _NativeCapability
        or type(fact.state) is not _ProbeState
        for fact in facts
    ):
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    by_capability: dict[_NativeCapability, _NativeCapabilityProbeFact] = {}
    for fact in facts:
        if fact.capability in by_capability:
            return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
        by_capability[fact.capability] = fact
    blockers: set[_ReadinessBlocker] = set()
    for requirement in REQUIRED_NATIVE_CAPABILITIES:
        fact = by_capability.get(requirement.capability)
        if fact is None:
            blockers.add(_ReadinessBlocker.NATIVE_CAPABILITY_MISSING)
            continue
        status = _status_blocker(
            fact.state,
            missing=_ReadinessBlocker.NATIVE_CAPABILITY_MISSING,
            unknown=_ReadinessBlocker.NATIVE_CAPABILITY_UNKNOWN,
            tampered=_ReadinessBlocker.NATIVE_CAPABILITY_TAMPERED,
        )
        if status is not None:
            blockers.add(status)
        elif (
            type(fact.interface_version) is not str
            or fact.interface_version != requirement.interface_version
        ):
            blockers.add(
                _ReadinessBlocker.NATIVE_CAPABILITY_VERSION_MISMATCH
            )
    if set(by_capability) != {
        item.capability for item in REQUIRED_NATIVE_CAPABILITIES
    }:
        blockers.add(_ReadinessBlocker.PROBE_CONTRACT_INVALID)
    return blockers


def _assess_dns(fact: object) -> set[_ReadinessBlocker]:
    if type(fact) is not _DnsProbeFact or type(fact.state) is not _ProbeState:
        return {_ReadinessBlocker.PROBE_CONTRACT_INVALID}
    status = _status_blocker(
        fact.state,
        missing=_ReadinessBlocker.DNS_EVIDENCE_MISSING,
        unknown=_ReadinessBlocker.DNS_EVIDENCE_UNKNOWN,
        tampered=_ReadinessBlocker.DNS_EVIDENCE_TAMPERED,
    )
    if status is not None:
        return {status}
    exact_bools = (
        fact.public_candidate_set_attested,
        fact.numeric_peer_match_attested,
        fact.performed_without_http,
    )
    if (
        type(fact.network_policy_version) is not str
        or type(fact.public_address_policy_digest) is not Digest256
        or fact.network_policy_version != REQUIRED_NETWORK_POLICY_VERSION
        or fact.public_address_policy_digest
        != REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST
        or any(type(value) is not bool or not value for value in exact_bools)
    ):
        return {_ReadinessBlocker.DNS_POLICY_MISMATCH}
    return set()


def _assessment_payload(
    *,
    manifest_digest: Digest256,
    blockers: tuple[_ReadinessBlocker, ...],
) -> dict[str, object]:
    return {
        "blockers": tuple(blocker.value for blocker in blockers),
        "manifest_digest": manifest_digest,
        "production_authority_available": False,
        "production_transport_integration_available": False,
    }


@runtime_final
class _ProductionReadinessAssessment:
    """Factory-only immutable blocker report; never an authority token."""

    __slots__ = (
        "manifest_digest",
        "blockers",
        "assessment_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        manifest_digest: Digest256,
        blockers: tuple[_ReadinessBlocker, ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ASSESSMENT_AUTHORITY:
            raise TypeError("production readiness assessments require their factory")
        checked_manifest = require_digest(manifest_digest, "manifest_digest")
        if (
            type(blockers) is not tuple
            or not blockers
            or any(type(item) is not _ReadinessBlocker for item in blockers)
            or len(set(blockers)) != len(blockers)
            or tuple(sorted(blockers, key=lambda item: item.value)) != blockers
            or _ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE not in blockers
        ):
            raise ValueError("assessment must contain canonical fail-closed blockers")
        selected = digest256(
            "ProductionReadinessAssessment",
            PRODUCTION_READINESS_ASSESSMENT_SCHEMA_VERSION,
            _assessment_payload(
                manifest_digest=checked_manifest,
                blockers=blockers,
            ),
        )
        object.__setattr__(self, "manifest_digest", checked_manifest)
        object.__setattr__(self, "blockers", blockers)
        object.__setattr__(self, "assessment_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del name, value
        raise AttributeError("ProductionReadinessAssessment is immutable")

    def __copy__(self) -> "_ProductionReadinessAssessment":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_ProductionReadinessAssessment":
        del memo
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProductionReadinessAssessment is process-local")

    @property
    def is_ready(self) -> bool:
        return False

    @property
    def production_authority_available(self) -> bool:
        return False

    def validate_integrity(self) -> None:
        canonical_blockers = (
            type(self.blockers) is tuple
            and bool(self.blockers)
            and all(type(item) is _ReadinessBlocker for item in self.blockers)
            and len(set(self.blockers)) == len(self.blockers)
            and tuple(sorted(self.blockers, key=lambda item: item.value))
            == self.blockers
            and _ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE
            in self.blockers
        )
        if not canonical_blockers:
            raise ValueError("production readiness assessment integrity failed")
        selected = digest256(
            "ProductionReadinessAssessment",
            PRODUCTION_READINESS_ASSESSMENT_SCHEMA_VERSION,
            _assessment_payload(
                manifest_digest=self.manifest_digest,
                blockers=self.blockers,
            ),
        )
        if (
            selected != self.assessment_digest
            or selected != self._issued_digest
        ):
            raise ValueError("production readiness assessment integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "assessment_digest": self.assessment_digest,
            "manifest_digest": self.manifest_digest,
            "blocker_count": len(self.blockers),
            "blockers": tuple(item.value for item in self.blockers),
            "is_ready": False,
            "production_authority_available": False,
            "production_transport_integration_available": False,
        }


def _new_assessment(
    manifest_digest: Digest256,
    blockers: set[_ReadinessBlocker],
) -> _ProductionReadinessAssessment:
    blockers.add(_ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE)
    canonical = tuple(sorted(blockers, key=lambda item: item.value))
    return _ProductionReadinessAssessment(
        manifest_digest=manifest_digest,
        blockers=canonical,
        _authority=_ASSESSMENT_AUTHORITY,
    )


def _assess_production_readiness(
    *,
    manifest: _ProductionReadinessManifest,
    probe: object,
) -> _ProductionReadinessAssessment:
    """Collect explicitly injected facts and return blockers only.

    The probe may perform external reads, but this function supplies only
    immutable expected values and never supplies credentials, request data, or
    a production authority.  Probe exceptions are reduced to one content-free
    blocker; exception text is never retained.
    """

    if type(manifest) is not _ProductionReadinessManifest:
        raise TypeError("manifest must be a ProductionReadinessManifest")
    source_manifest = manifest
    try:
        manifest = _seal_manifest_snapshot(source_manifest)
    except BaseException:
        issued = getattr(source_manifest, "_issued_digest", None)
        if type(issued) is not Digest256:
            issued = Digest256("0" * 64)
        return _new_assessment(
            issued,
            {_ReadinessBlocker.MANIFEST_TAMPERED},
        )

    blockers: set[_ReadinessBlocker] = set()

    entitlement_requirement = (
        manifest.application_keychain_entitlement_requirement
    )
    bundle_request = _BundleProbeRequest(
        manifest_digest=manifest.manifest_digest,
        app_bundle_identifier=manifest.app_bundle_identifier,
        team_id=manifest.team_id,
        keychain_entitlements_version=entitlement_requirement.version,
        application_identifier_entitlement=(
            entitlement_requirement.application_identifier
        ),
        team_identifier_entitlement=entitlement_requirement.team_identifier,
        keychain_access_groups_entitlement=(
            entitlement_requirement.keychain_access_groups
        ),
        keychain_entitlements_digest=entitlement_requirement.content_digest,
    )
    try:
        bundle_fact = probe.inspect_app_bundle(bundle_request)
    except BaseException:
        blockers.add(_ReadinessBlocker.PROBE_FAILED)
    else:
        blockers.update(_assess_bundle(manifest, bundle_fact))

    artifact_requests = (
        _ArtifactProbeRequest(
            manifest.manifest_digest,
            _ArtifactRole.SUPERVISOR,
            manifest.supervisor_relative_path,
            manifest.supervisor_sha256,
            manifest.supervisor_signing_identifier,
            manifest.team_id,
        ),
        _ArtifactProbeRequest(
            manifest.manifest_digest,
            _ArtifactRole.HELPER,
            manifest.helper_relative_path,
            manifest.helper_sha256,
            manifest.helper_signing_identifier,
            manifest.team_id,
        ),
    )
    for request in artifact_requests:
        try:
            artifact_fact = probe.inspect_artifact(request)
        except BaseException:
            blockers.add(_ReadinessBlocker.PROBE_FAILED)
        else:
            blockers.update(
                _assess_artifact(
                    manifest,
                    role=request.role,
                    fact=artifact_fact,
                )
            )

    try:
        attestation_facts = probe.inspect_attestations(
            _AttestationProbeRequest(
                manifest.manifest_digest,
                manifest.attestation_requirements,
            )
        )
    except BaseException:
        blockers.add(_ReadinessBlocker.PROBE_FAILED)
    else:
        blockers.update(
            _assess_attestations(
                manifest.attestation_requirements,
                attestation_facts,
            )
        )

    try:
        tls_policy_fact = probe.inspect_exact_tls_policy(
            _ExactTlsPolicyProbeRequest(
                manifest.manifest_digest,
                manifest.exact_tls_policy_requirement,
            )
        )
    except BaseException:
        blockers.add(_ReadinessBlocker.PROBE_FAILED)
    else:
        blockers.update(
            _assess_exact_tls_policy(
                manifest.exact_tls_policy_requirement,
                tls_policy_fact,
            )
        )

    try:
        credential_source_fact = (
            probe.inspect_production_credential_source_binding(
                _ProductionCredentialSourceBindingProbeRequest(
                    manifest.manifest_digest,
                    manifest.credential_source_binding_requirement,
                )
            )
        )
    except BaseException:
        blockers.add(_ReadinessBlocker.PROBE_FAILED)
    else:
        blockers.update(
            _assess_production_credential_source_binding(
                manifest.credential_source_binding_requirement,
                credential_source_fact,
            )
        )

    cutover = manifest.application_transport_cutover_requirement
    transport = manifest.exact_transport_binding_requirement
    cutover_request = _ApplicationTransportCutoverProbeRequest(
        manifest_digest=manifest.manifest_digest,
        request_digest=digest256(
            "ApplicationTransportCutoverProbeBinding",
            APPLICATION_TRANSPORT_CUTOVER_PROBE_BINDING_SCHEMA_VERSION,
            {
                "cutover_subject_digest": cutover.content_digest,
                "manifest_digest": manifest.manifest_digest,
            },
        ),
        freshness_challenge=_AssessmentFreshnessChallenge(),
        version=cutover.version,
        manifest_content_digest=cutover.manifest_content_digest,
        app_bundle_identifier=cutover.app_bundle_identifier,
        team_id=cutover.team_id,
        application_entrypoint_relative_path=(
            cutover.application_entrypoint_relative_path
        ),
        application_entrypoint_sha256=cutover.application_entrypoint_sha256,
        exact_transport_binding_version=transport.version,
        exact_transport_policy_version=transport.transport_policy_version,
        exact_wire_evidence_schema_version=(
            transport.wire_evidence_schema_version
        ),
        exact_http1_policy_version=transport.http1_policy_version,
        exact_http1_policy_digest=transport.http1_policy_digest,
        exact_tls_policy_version=transport.tls_policy_version,
        exact_tls_policy_ref=transport.tls_policy_ref,
        exact_tls_hostname=transport.tls_hostname,
        exact_tls_policy_digest=transport.tls_policy_digest,
        credential_source_binding_version=(
            transport.credential_source_binding_version
        ),
        credential_source_binding_digest=(
            transport.credential_source_binding_digest
        ),
        network_policy_version=transport.network_policy_version,
        public_address_policy_digest=transport.public_address_policy_digest,
        exact_transport_binding_digest=transport.content_digest,
        content_digest=cutover.content_digest,
    )
    try:
        cutover_fact = probe.inspect_application_transport_cutover(
            cutover_request
        )
    except BaseException:
        blockers.add(_ReadinessBlocker.PROBE_FAILED)
    else:
        blockers.update(
            _assess_application_transport_cutover(
                cutover_request,
                cutover_fact,
            )
        )

    try:
        capability_facts = probe.inspect_native_capabilities(
            _NativeCapabilityProbeRequest(
                manifest.manifest_digest,
                manifest.native_capability_requirements,
            )
        )
    except BaseException:
        blockers.add(_ReadinessBlocker.PROBE_FAILED)
    else:
        blockers.update(_assess_native_capabilities(capability_facts))

    try:
        dns_fact = probe.inspect_dns_policy(
            _DnsProbeRequest(
                manifest.manifest_digest,
                manifest.network_policy_version,
                manifest.public_address_policy_digest,
            )
        )
    except BaseException:
        blockers.add(_ReadinessBlocker.PROBE_FAILED)
    else:
        blockers.update(_assess_dns(dns_fact))

    # The source is not used after the snapshot is sealed, but detect any
    # concurrent/probe-side tamper so this diagnostic cannot silently report
    # the old manifest as current.
    try:
        source_manifest.validate_integrity()
        if source_manifest.manifest_digest != manifest.manifest_digest:
            raise ValueError("production readiness manifest changed")
    except BaseException:
        blockers.add(_ReadinessBlocker.MANIFEST_TAMPERED)

    return _new_assessment(manifest.manifest_digest, blockers)
