"""Offline acceptance for the W09 production-readiness blocker inventory."""
from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import copy
import os
from pathlib import Path
import pickle
import re
import socket
import subprocess
import sys
import unittest
from unittest import mock

from snapquiz.domain.digest import Digest256, digest256
from snapquiz.config.profiles import GLM_NETWORK_POLICY_VERSION
from snapquiz.transport import _darwin_keychain_source as darwin_keychain
from snapquiz.transport import _darwin_suspended_identity as suspended_identity
from snapquiz.transport import _exact_http1 as exact_http1
from snapquiz.transport import _exact_tls as exact_tls
from snapquiz.transport import _exact_transport as exact_transport
from snapquiz.transport import _numeric_connect as numeric_connect
from snapquiz.transport import _production_readiness as readiness
from snapquiz.transport import _resolver_helper_dns as resolver_helper_dns
from snapquiz.transport import _resolver_output_cache as resolver_output_cache
from snapquiz.transport import (
    _resolver_startup_composition as startup_composition,
)
from snapquiz.transport.address_policy import (
    INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
)


_SUPERVISOR_DIGEST = Digest256("1" * 64)
_HELPER_DIGEST = Digest256("2" * 64)
_RESOLVER_BINDING_DIGEST = Digest256("3" * 64)
_APPLICATION_ENTRYPOINT_DIGEST = Digest256("4" * 64)
_TLS_HOSTNAME = "open.bigmodel.cn"
_TLS_POLICY_DIGEST = Digest256(
    "c43f3cff9fd6179f2df0f9f0a6d755027360d3dfcdf6d8532bc33945629fef04"
)
_KEYCHAIN_BINDING_DIGEST = Digest256(
    "c353b8358801ef62f691be8d4e0962dacceee9bc35c158269ac0d15ca677c83f"
)
_RESOLVER_MAPPING_DIGEST = Digest256(
    "d2debf65092ce97e3fe13694f4ae75c71ec8329fa36691c9ba03e20ff9b264cc"
)
_APP_KEYCHAIN_ENTITLEMENTS_DIGEST = Digest256(
    "d00baacdbba40e0513f7139ba3d141009258ef82e77e9cf17500c1d478f9804b"
)
_CREDENTIAL_SOURCE_BINDING_DIGEST = Digest256(
    "9bb9912b7d0ada59138228b824c315828eeebf688038728e82bf01ca6e50843e"
)
_EXACT_TRANSPORT_BINDING_DIGEST = Digest256(
    "97c238f01e67211c2bc370b6ad12edf79cdde2d0425143c130e472dcad89e5ac"
)
_MANIFEST_CONTENT_DIGEST = Digest256(
    "9c83e161f90a5b5f6c2ab9df71142ab82edc073370a99fc51ee099a5056cb162"
)
_APPLICATION_TRANSPORT_CUTOVER_DIGEST = Digest256(
    "7a5dc9691357e0fd1f3c9f086f33086a80d399a17939f7748df6ce05cd7d74d1"
)
_MANIFEST_DIGEST = Digest256(
    "0637dc29cdfcfdc9f63c26752afd2ae4bacaea9e6e06556be0a3feefb3817e9c"
)
_KEYCHAIN_CREDENTIAL_REF = "keychain-generic-password:v1:glm-primary"
_KEYCHAIN_SERVICE = "ai.snapquiz.provider"
_KEYCHAIN_ACCOUNT = "glm-primary"
_KEYCHAIN_ACCESS_GROUP = "A1B2C3D4E5.ai.snapquiz.credentials"
_RESOLVER_CREDENTIAL_REF = "env:GLM_API_KEY"


def _tls_policy_digest(hostname: str) -> Digest256:
    return digest256(
        "ExactTlsPolicy",
        exact_tls.EXACT_TLS_POLICY_SCHEMA_VERSION,
        exact_tls._exact_tls_policy_payload(hostname=hostname),
    )


def _credential_source_binding(
    *,
    credential_ref: str = _KEYCHAIN_CREDENTIAL_REF,
    service: str = _KEYCHAIN_SERVICE,
    account: str = _KEYCHAIN_ACCOUNT,
    access_group: str | None = _KEYCHAIN_ACCESS_GROUP,
    resolver_credential_ref: str | None = _RESOLVER_CREDENTIAL_REF,
    resolver_binding_digest: Digest256 | None = _RESOLVER_BINDING_DIGEST,
):
    return darwin_keychain._new_darwin_keychain_binding(
        credential_ref=credential_ref,
        service=service,
        account=account,
        access_group=access_group,
        resolver_credential_ref=resolver_credential_ref,
        resolver_binding_digest=resolver_binding_digest,
    )


def _manifest(**overrides):
    values = {
        "app_bundle_identifier": "ai.snapquiz.desktop",
        "team_id": "A1B2C3D4E5",
        "application_entrypoint_relative_path": "Contents/MacOS/SnapQuiz",
        "application_entrypoint_sha256": _APPLICATION_ENTRYPOINT_DIGEST,
        "supervisor_relative_path": (
            "Contents/Library/LaunchServices/SnapQuizResolverSupervisor"
        ),
        "supervisor_sha256": _SUPERVISOR_DIGEST,
        "supervisor_signing_identifier": (
            "ai.snapquiz.desktop.resolver-supervisor"
        ),
        "helper_relative_path": "Contents/Helpers/SnapQuizResolverHelper",
        "helper_sha256": _HELPER_DIGEST,
        "helper_signing_identifier": "ai.snapquiz.desktop.resolver-helper",
        "exact_tls_hostname": _TLS_HOSTNAME,
        "exact_tls_policy_digest": _TLS_POLICY_DIGEST,
        "credential_source_binding": _credential_source_binding(),
        "app_keychain_access_groups": (_KEYCHAIN_ACCESS_GROUP,),
    }
    values.update(overrides)
    return readiness._new_production_readiness_manifest(**values)


class _VerifiedProbe:
    def __init__(self) -> None:
        self.requests: list[object] = []
        self.bundle_fact: object | None = None
        self.artifact_facts: dict[readiness._ArtifactRole, object] = {}
        self.attestation_facts: object | None = None
        self.tls_policy_fact: object | None = None
        self.credential_source_fact: object | None = None
        self.cutover_fact: object | None = None
        self.capability_facts: object | None = None
        self.dns_fact: object | None = None

    def inspect_app_bundle(self, request):
        self.requests.append(request)
        if self.bundle_fact is not None:
            return self.bundle_fact
        return readiness._BundleProbeFact(
            state=readiness._ProbeState.VERIFIED,
            is_macos_app_bundle=True,
            bundle_identifier=request.app_bundle_identifier,
            team_id=request.team_id,
            usable_signing_identity_count=1,
            codesign_valid=True,
            security_assessment_valid=True,
            keychain_entitlements_version=(
                request.keychain_entitlements_version
            ),
            application_identifier_entitlement=(
                request.application_identifier_entitlement
            ),
            team_identifier_entitlement=request.team_identifier_entitlement,
            keychain_access_groups_entitlement=(
                request.keychain_access_groups_entitlement
            ),
            keychain_entitlements_digest=request.keychain_entitlements_digest,
        )

    def inspect_artifact(self, request):
        self.requests.append(request)
        selected = self.artifact_facts.get(request.role)
        if selected is not None:
            return selected
        return readiness._ArtifactProbeFact(
            state=readiness._ProbeState.VERIFIED,
            role=request.role,
            bundle_relative_path=request.bundle_relative_path,
            sha256=request.sha256,
            is_macho=True,
            is_bundle_member=True,
            signing_identifier=request.signing_identifier,
            team_id=request.team_id,
            codesign_valid=True,
            security_assessment_valid=True,
        )

    def inspect_attestations(self, request):
        self.requests.append(request)
        if self.attestation_facts is not None:
            return self.attestation_facts
        return tuple(
            readiness._AttestationProbeFact(
                kind=item.kind,
                state=readiness._ProbeState.VERIFIED,
                version=item.version,
                content_digest=item.content_digest,
            )
            for item in request.requirements
        )

    def inspect_exact_tls_policy(self, request):
        self.requests.append(request)
        if self.tls_policy_fact is not None:
            return self.tls_policy_fact
        requirement = request.requirement
        return readiness._ExactTlsPolicyProbeFact(
            state=readiness._ProbeState.VERIFIED,
            version=requirement.version,
            hostname=requirement.hostname,
            policy_ref=requirement.policy_ref,
            policy_digest=requirement.policy_digest,
        )

    def inspect_production_credential_source_binding(self, request):
        self.requests.append(request)
        if self.credential_source_fact is not None:
            return self.credential_source_fact
        requirement = request.requirement
        return readiness._ProductionCredentialSourceBindingProbeFact(
            state=readiness._ProbeState.VERIFIED,
            version=requirement.version,
            keychain_source_schema_version=(
                requirement.keychain_source_schema_version
            ),
            credential_ref=requirement.credential_ref,
            service=requirement.service,
            account=requirement.account,
            access_group=requirement.access_group,
            keychain_binding_digest=requirement.keychain_binding_digest,
            resolver_credential_ref=requirement.resolver_credential_ref,
            resolver_binding_digest=requirement.resolver_binding_digest,
            resolver_mapping_digest=requirement.resolver_mapping_digest,
            application_entitlements_digest=(
                requirement.application_entitlements_digest
            ),
            content_digest=requirement.content_digest,
        )

    def inspect_application_transport_cutover(self, request):
        self.requests.append(request)
        if self.cutover_fact is not None:
            return self.cutover_fact
        return readiness._ApplicationTransportCutoverProbeFact(
            state=readiness._ProbeState.VERIFIED,
            manifest_digest=request.manifest_digest,
            request_digest=request.request_digest,
            freshness_challenge=request.freshness_challenge,
            version=request.version,
            manifest_content_digest=request.manifest_content_digest,
            app_bundle_identifier=request.app_bundle_identifier,
            team_id=request.team_id,
            application_entrypoint_relative_path=(
                request.application_entrypoint_relative_path
            ),
            application_entrypoint_sha256=(
                request.application_entrypoint_sha256
            ),
            exact_transport_binding_version=(
                request.exact_transport_binding_version
            ),
            exact_transport_policy_version=(
                request.exact_transport_policy_version
            ),
            exact_wire_evidence_schema_version=(
                request.exact_wire_evidence_schema_version
            ),
            exact_http1_policy_version=request.exact_http1_policy_version,
            exact_http1_policy_digest=request.exact_http1_policy_digest,
            exact_tls_policy_version=request.exact_tls_policy_version,
            exact_tls_policy_ref=request.exact_tls_policy_ref,
            exact_tls_hostname=request.exact_tls_hostname,
            exact_tls_policy_digest=request.exact_tls_policy_digest,
            credential_source_binding_version=(
                request.credential_source_binding_version
            ),
            credential_source_binding_digest=(
                request.credential_source_binding_digest
            ),
            network_policy_version=request.network_policy_version,
            public_address_policy_digest=(
                request.public_address_policy_digest
            ),
            exact_transport_binding_digest=(
                request.exact_transport_binding_digest
            ),
            content_digest=request.content_digest,
        )

    def inspect_native_capabilities(self, request):
        self.requests.append(request)
        if self.capability_facts is not None:
            return self.capability_facts
        return tuple(
            readiness._NativeCapabilityProbeFact(
                capability=item.capability,
                state=readiness._ProbeState.VERIFIED,
                interface_version=item.interface_version,
            )
            for item in request.requirements
        )

    def inspect_dns_policy(self, request):
        self.requests.append(request)
        if self.dns_fact is not None:
            return self.dns_fact
        return readiness._DnsProbeFact(
            state=readiness._ProbeState.VERIFIED,
            network_policy_version=request.network_policy_version,
            public_address_policy_digest=request.public_address_policy_digest,
            public_candidate_set_attested=True,
            numeric_peer_match_attested=True,
            performed_without_http=True,
        )


def _assessment(probe: object | None = None):
    return readiness._assess_production_readiness(
        manifest=_manifest(),
        probe=_VerifiedProbe() if probe is None else probe,
    )


def _blockers(assessment) -> set[readiness._ReadinessBlocker]:
    return set(assessment.blockers)


class ProductionReadinessManifestTest(unittest.TestCase):
    def test_manifest_is_factory_only_immutable_and_content_addressed(self):
        manifest = _manifest()
        manifest.validate_integrity()
        self.assertIs(copy.copy(manifest), manifest)
        self.assertIs(copy.deepcopy(manifest), manifest)
        with self.assertRaises(TypeError):
            readiness._ProductionReadinessManifest(
                app_bundle_identifier=manifest.app_bundle_identifier,
                team_id=manifest.team_id,
                application_entrypoint_relative_path=(
                    manifest.application_entrypoint_relative_path
                ),
                application_entrypoint_sha256=(
                    manifest.application_entrypoint_sha256
                ),
                supervisor_relative_path=manifest.supervisor_relative_path,
                supervisor_sha256=manifest.supervisor_sha256,
                supervisor_signing_identifier=(
                    manifest.supervisor_signing_identifier
                ),
                helper_relative_path=manifest.helper_relative_path,
                helper_sha256=manifest.helper_sha256,
                helper_signing_identifier=manifest.helper_signing_identifier,
                exact_tls_hostname=(
                    manifest.exact_tls_policy_requirement.hostname
                ),
                exact_tls_policy_digest=(
                    manifest.exact_tls_policy_requirement.policy_digest
                ),
                credential_source_binding=_credential_source_binding(),
                app_keychain_access_groups=(_KEYCHAIN_ACCESS_GROUP,),
            )
        with self.assertRaises(AttributeError):
            manifest.team_id = "Z9Y8X7W6V5"
        with self.assertRaises(TypeError):
            pickle.dumps(manifest)
        with self.assertRaises(TypeError):
            class _ManifestSubclass(readiness._ProductionReadinessManifest):
                pass

    def test_cutover_requirement_is_factory_only_immutable_and_bound(self):
        manifest = _manifest()
        requirement = manifest.application_transport_cutover_requirement
        requirement.validate_integrity()
        self.assertIs(copy.copy(requirement), requirement)
        self.assertIs(copy.deepcopy(requirement), requirement)
        self.assertEqual(
            requirement.manifest_content_digest,
            manifest.manifest_content_digest,
        )
        self.assertEqual(
            requirement.app_bundle_identifier,
            manifest.app_bundle_identifier,
        )
        self.assertEqual(requirement.team_id, manifest.team_id)
        self.assertEqual(
            requirement.application_entrypoint_relative_path,
            manifest.application_entrypoint_relative_path,
        )
        self.assertEqual(
            requirement.application_entrypoint_sha256,
            manifest.application_entrypoint_sha256,
        )
        self.assertEqual(
            requirement.exact_transport_binding_requirement,
            manifest.exact_transport_binding_requirement,
        )
        with self.assertRaises(TypeError):
            readiness._ApplicationTransportCutoverRequirement(
                manifest_content_digest=requirement.manifest_content_digest,
                app_bundle_identifier=requirement.app_bundle_identifier,
                team_id=requirement.team_id,
                application_entrypoint_relative_path=(
                    requirement.application_entrypoint_relative_path
                ),
                application_entrypoint_sha256=(
                    requirement.application_entrypoint_sha256
                ),
                exact_transport_binding_requirement=(
                    requirement.exact_transport_binding_requirement
                ),
            )
        with self.assertRaises(AttributeError):
            requirement.team_id = "Z9Y8X7W6V5"
        with self.assertRaises(TypeError):
            pickle.dumps(requirement)
        with self.assertRaises(TypeError):
            class _CutoverSubclass(
                readiness._ApplicationTransportCutoverRequirement
            ):
                pass

    def test_security_bindings_have_stable_content_addresses(self):
        first = _manifest()
        second = _manifest()
        self.assertEqual(_tls_policy_digest(_TLS_HOSTNAME), _TLS_POLICY_DIGEST)
        self.assertEqual(first.manifest_digest, _MANIFEST_DIGEST)
        self.assertEqual(second.manifest_digest, _MANIFEST_DIGEST)
        credential = first.credential_source_binding_requirement
        entitlement = first.application_keychain_entitlement_requirement
        self.assertEqual(
            credential.keychain_binding_digest,
            _KEYCHAIN_BINDING_DIGEST,
        )
        self.assertEqual(
            credential.resolver_mapping_digest,
            _RESOLVER_MAPPING_DIGEST,
        )
        self.assertEqual(
            credential.application_entitlements_digest,
            _APP_KEYCHAIN_ENTITLEMENTS_DIGEST,
        )
        self.assertEqual(
            entitlement.content_digest,
            _APP_KEYCHAIN_ENTITLEMENTS_DIGEST,
        )
        self.assertEqual(
            credential.content_digest,
            _CREDENTIAL_SOURCE_BINDING_DIGEST,
        )
        self.assertEqual(
            first.exact_transport_binding_requirement.content_digest,
            _EXACT_TRANSPORT_BINDING_DIGEST,
        )
        self.assertEqual(
            first.manifest_content_digest,
            _MANIFEST_CONTENT_DIGEST,
        )
        self.assertEqual(
            first.application_transport_cutover_requirement.content_digest,
            _APPLICATION_TRANSPORT_CUTOVER_DIGEST,
        )
        cutover_attestation = next(
            item
            for item in first.attestation_requirements
            if item.kind
            is readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER
        )
        self.assertEqual(
            cutover_attestation.content_digest,
            _APPLICATION_TRANSPORT_CUTOVER_DIGEST,
        )

    def test_each_security_expectation_readdresses_the_manifest(self):
        base = _manifest()
        extra_group = "A1B2C3D4E5.ai.snapquiz.extra"
        other_group = "A1B2C3D4E5.ai.snapquiz.other-credentials"
        variants = (
            {
                "application_entrypoint_relative_path": (
                    "Contents/MacOS/SnapQuizProduction"
                ),
            },
            {
                "application_entrypoint_sha256": Digest256("5" * 64),
            },
            {
                "exact_tls_hostname": "api.example.com",
                "exact_tls_policy_digest": _tls_policy_digest(
                    "api.example.com"
                ),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    credential_ref=(
                        "keychain-generic-password:v1:glm-production"
                    )
                ),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    service="ai.snapquiz.production-provider"
                ),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    account="glm-production"
                ),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    access_group=other_group
                ),
                "app_keychain_access_groups": (other_group,),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    resolver_credential_ref="env:GLM_PRODUCTION_API_KEY"
                ),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    resolver_binding_digest=Digest256("4" * 64)
                ),
            },
            {
                "app_keychain_access_groups": (
                    _KEYCHAIN_ACCESS_GROUP,
                    extra_group,
                ),
            },
        )
        digests: set[Digest256] = set()
        content_digests: set[Digest256] = set()
        cutover_digests: set[Digest256] = set()
        for values in variants:
            with self.subTest(values=tuple(values)):
                first = _manifest(**values)
                second = _manifest(**values)
                self.assertEqual(first.manifest_digest, second.manifest_digest)
                self.assertNotEqual(first.manifest_digest, base.manifest_digest)
                self.assertNotEqual(
                    first.manifest_content_digest,
                    base.manifest_content_digest,
                )
                self.assertNotEqual(
                    first.application_transport_cutover_requirement.content_digest,
                    base.application_transport_cutover_requirement.content_digest,
                )
                digests.add(first.manifest_digest)
                content_digests.add(first.manifest_content_digest)
                cutover_digests.add(
                    first.application_transport_cutover_requirement.content_digest
                )
        self.assertEqual(len(digests), len(variants))
        self.assertEqual(len(content_digests), len(variants))
        self.assertEqual(len(cutover_digests), len(variants))

    def test_manifest_rejects_unbound_tls_keychain_and_entitlement_facts(self):
        cases = (
            {
                "exact_tls_policy_digest": Digest256("f" * 64),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    access_group=None
                ),
            },
            {
                "credential_source_binding": _credential_source_binding(
                    resolver_credential_ref=None,
                    resolver_binding_digest=None,
                ),
            },
            {
                "app_keychain_access_groups": (
                    "A1B2C3D4E5.ai.snapquiz.unrelated",
                ),
            },
            {
                "app_keychain_access_groups": (
                    "Z9Y8X7W6V5.ai.snapquiz.credentials",
                    _KEYCHAIN_ACCESS_GROUP,
                ),
            },
            {
                "app_keychain_access_groups": (
                    "A1B2C3D4E5.ai.snapquiz.z",
                    _KEYCHAIN_ACCESS_GROUP,
                ),
            },
        )
        for values in cases:
            with self.subTest(values=tuple(values)):
                with self.assertRaises(ValueError):
                    _manifest(**values)

        binding = _credential_source_binding()
        object.__setattr__(binding, "service", "tampered-service")
        with self.assertRaises(ValueError):
            _manifest(credential_source_binding=binding)

    def test_manifest_rejects_non_bundle_paths_and_ambiguous_identity(self):
        valid = {
            "app_bundle_identifier": "ai.snapquiz.desktop",
            "team_id": "A1B2C3D4E5",
            "application_entrypoint_relative_path": "Contents/MacOS/SnapQuiz",
            "application_entrypoint_sha256": _APPLICATION_ENTRYPOINT_DIGEST,
            "supervisor_relative_path": (
                "Contents/Library/LaunchServices/SnapQuizResolverSupervisor"
            ),
            "supervisor_sha256": _SUPERVISOR_DIGEST,
            "supervisor_signing_identifier": (
                "ai.snapquiz.desktop.resolver-supervisor"
            ),
            "helper_relative_path": "Contents/Helpers/SnapQuizResolverHelper",
            "helper_sha256": _HELPER_DIGEST,
            "helper_signing_identifier": (
                "ai.snapquiz.desktop.resolver-helper"
            ),
            "exact_tls_hostname": _TLS_HOSTNAME,
            "exact_tls_policy_digest": _TLS_POLICY_DIGEST,
            "credential_source_binding": _credential_source_binding(),
            "app_keychain_access_groups": (_KEYCHAIN_ACCESS_GROUP,),
        }
        cases = (
            ("app_bundle_identifier", "SnapQuiz"),
            ("team_id", ""),
            ("team_id", "A1B2C3D4E0/"),
            ("application_entrypoint_relative_path", "/tmp/SnapQuiz"),
            (
                "application_entrypoint_relative_path",
                "Contents/Helpers/SnapQuiz",
            ),
            (
                "application_entrypoint_relative_path",
                "Contents/MacOS/../SnapQuiz",
            ),
            ("supervisor_relative_path", "/tmp/Supervisor"),
            (
                "supervisor_relative_path",
                "Contents/Library/LaunchServices/../Supervisor",
            ),
            ("supervisor_relative_path", "Contents/Helpers/Supervisor"),
            ("helper_relative_path", "Contents/MacOS/Helper"),
            ("helper_relative_path", "Contents/Helpers/subdir/Helper"),
            ("helper_signing_identifier", "other.vendor.helper"),
            (
                "helper_signing_identifier",
                "ai.snapquiz.desktop.resolver-supervisor",
            ),
            ("helper_sha256", _SUPERVISOR_DIGEST),
        )
        for name, value in cases:
            with self.subTest(name=name, value=value):
                selected = dict(valid)
                selected[name] = value
                with self.assertRaises(ValueError):
                    readiness._new_production_readiness_manifest(**selected)

    def test_manifest_construction_has_no_external_side_effect(self):
        with ExitStack() as stack:
            calls = (
                stack.enter_context(
                    mock.patch("builtins.open", side_effect=AssertionError("open"))
                ),
                stack.enter_context(
                    mock.patch.object(
                        os,
                        "stat",
                        side_effect=AssertionError("stat"),
                    )
                ),
                stack.enter_context(
                    mock.patch.object(
                        subprocess,
                        "run",
                        side_effect=AssertionError("subprocess"),
                    )
                ),
                stack.enter_context(
                    mock.patch.object(
                        socket,
                        "getaddrinfo",
                        side_effect=AssertionError("dns"),
                    )
                ),
            )
            manifest = _manifest()
        self.assertTrue(all(item.call_count == 0 for item in calls))
        manifest.validate_integrity()

    def test_required_versions_and_native_interfaces_are_exactly_frozen(self):
        manifest = _manifest()
        self.assertEqual(
            tuple(
                (item.kind, item.version)
                for item in manifest.attestation_requirements
            ),
            tuple(
                (item.kind, item.version)
                for item in readiness.REQUIRED_ATTESTATION_VERSIONS
            )
            + (
                (
                    readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER,
                    readiness.APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION,
                ),
            ),
        )
        self.assertIs(
            manifest.native_capability_requirements,
            readiness.REQUIRED_NATIVE_CAPABILITIES,
        )
        capabilities = {
            item.capability for item in manifest.native_capability_requirements
        }
        self.assertIn(readiness._NativeCapability.NATIVE_SOLE_REAPER, capabilities)
        self.assertIn(
            readiness._NativeCapability.OPAQUE_NUMERIC_SOCKET_OWNER,
            capabilities,
        )
        self.assertIn(
            readiness._NativeCapability.OPAQUE_TLS_SOCKET_OWNER,
            capabilities,
        )
        self.assertIn(
            readiness._NativeCapability.NATIVE_CONTROL_LIVENESS_OWNER,
            capabilities,
        )
        self.assertIn(
            readiness._NativeCapability.NATIVE_NUMERIC_TLS_TRANSFER_OWNER,
            capabilities,
        )
        self.assertIn(
            readiness._NativeCapability.NATIVE_KEYCHAIN_BUFFER_OWNER,
            capabilities,
        )
        attestation_kinds = {
            item.kind for item in manifest.attestation_requirements
        }
        self.assertIn(
            readiness._AttestationKind.EXACT_HTTP1_POLICY,
            attestation_kinds,
        )
        self.assertIn(
            readiness._AttestationKind.PRODUCTION_CREDENTIAL_SOURCE_BINDING,
            attestation_kinds,
        )
        self.assertIn(
            readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER,
            attestation_kinds,
        )
        self.assertEqual(
            manifest.exact_http1_policy_digest,
            exact_http1.EXACT_HTTP1_POLICY_DIGEST,
        )
        self.assertEqual(
            manifest.exact_tls_policy_requirement,
            readiness._ExactTlsPolicyRequirement(
                version=exact_tls.EXACT_TLS_POLICY_SCHEMA_VERSION,
                hostname=_TLS_HOSTNAME,
                policy_ref=exact_tls.EXACT_TLS_POLICY_REF,
                policy_digest=_TLS_POLICY_DIGEST,
            ),
        )
        credential = manifest.credential_source_binding_requirement
        source_binding = _credential_source_binding()
        self.assertEqual(credential.credential_ref, _KEYCHAIN_CREDENTIAL_REF)
        self.assertEqual(credential.service, _KEYCHAIN_SERVICE)
        self.assertEqual(credential.account, _KEYCHAIN_ACCOUNT)
        self.assertEqual(credential.access_group, _KEYCHAIN_ACCESS_GROUP)
        self.assertEqual(
            credential.keychain_binding_digest,
            source_binding.binding_digest,
        )
        self.assertEqual(
            credential.resolver_mapping_digest,
            source_binding.resolver_mapping_digest,
        )
        entitlement = manifest.application_keychain_entitlement_requirement
        self.assertEqual(
            entitlement.application_identifier,
            "A1B2C3D4E5.ai.snapquiz.desktop",
        )
        self.assertEqual(entitlement.team_identifier, "A1B2C3D4E5")
        self.assertEqual(
            entitlement.keychain_access_groups,
            (_KEYCHAIN_ACCESS_GROUP,),
        )
        self.assertFalse(readiness.PRODUCTION_READINESS_AUTHORITY_AVAILABLE)
        self.assertFalse(readiness.PRODUCTION_TRANSPORT_INTEGRATION_AVAILABLE)

    def test_attestation_versions_match_their_local_contract_sources(self):
        versions = {
            item.kind: item.version
            for item in readiness.REQUIRED_ATTESTATION_VERSIONS
        }
        self.assertEqual(
            versions[
                readiness._AttestationKind.SUSPENDED_PROCESS_IDENTITY
            ],
            suspended_identity.DARWIN_SUSPENDED_IDENTITY_PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[
                readiness._AttestationKind.PRE_SECRET_STARTUP_COMPOSITION
            ],
            startup_composition.STARTUP_COMPOSITION_PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[readiness._AttestationKind.DURABLE_RESOLVER_OUTPUT],
            resolver_output_cache.RESOLVER_OUTPUT_OBSERVATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[readiness._AttestationKind.RESOLVER_START_PROTOCOL],
            resolver_helper_dns.RESOLVER_HELPER_START_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[readiness._AttestationKind.RAW_DNS_TRANSCRIPT],
            resolver_helper_dns.RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[readiness._AttestationKind.NUMERIC_CONNECTION_PROOF],
            numeric_connect.NUMERIC_CONNECTION_PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[readiness._AttestationKind.EXACT_HTTP1_POLICY],
            exact_http1.EXACT_HTTP1_POLICY_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[readiness._AttestationKind.EXACT_TLS_POLICY],
            exact_tls.EXACT_TLS_POLICY_SCHEMA_VERSION,
        )
        self.assertEqual(
            readiness.REQUIRED_EXACT_TLS_POLICY_REF,
            exact_tls.EXACT_TLS_POLICY_REF,
        )
        self.assertEqual(
            versions[readiness._AttestationKind.EXACT_WIRE_EVIDENCE],
            exact_transport.EXACT_WIRE_EVIDENCE_SCHEMA_VERSION,
        )
        self.assertEqual(
            readiness.REQUIRED_EXACT_TRANSPORT_POLICY_VERSION,
            exact_transport.EXACT_TRANSPORT_POLICY_VERSION,
        )
        self.assertEqual(
            readiness.REQUIRED_EXACT_WIRE_EVIDENCE_SCHEMA_VERSION,
            exact_transport.EXACT_WIRE_EVIDENCE_SCHEMA_VERSION,
        )
        self.assertEqual(
            versions[
                readiness._AttestationKind.PRODUCTION_CREDENTIAL_SOURCE_BINDING
            ],
            darwin_keychain.PRODUCTION_CREDENTIAL_SOURCE_BINDING_ATTESTATION_VERSION,
        )
        self.assertEqual(
            readiness.REQUIRED_DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            darwin_keychain.DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
        )
        self.assertEqual(
            readiness.MACOS_APPLICATION_IDENTIFIER_ENTITLEMENT_KEY,
            "com.apple.application-identifier",
        )
        self.assertNotIn(
            readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER,
            versions,
        )
        self.assertEqual(
            readiness.REQUIRED_NETWORK_POLICY_VERSION,
            GLM_NETWORK_POLICY_VERSION,
        )
        self.assertEqual(
            readiness.REQUIRED_PUBLIC_ADDRESS_POLICY_DIGEST,
            INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
        )
        http1_requirement = next(
            item
            for item in readiness.REQUIRED_ATTESTATION_VERSIONS
            if item.kind is readiness._AttestationKind.EXACT_HTTP1_POLICY
        )
        self.assertEqual(
            http1_requirement.content_digest,
            exact_http1.EXACT_HTTP1_POLICY_DIGEST,
        )
        self.assertEqual(
            readiness.REQUIRED_EXACT_HTTP1_POLICY_DIGEST,
            exact_http1.EXACT_HTTP1_POLICY_DIGEST,
        )
        self.assertEqual(
            str(readiness.REQUIRED_EXACT_HTTP1_POLICY_DIGEST),
            "16a5bc342f274e1d893a26de9417e75ead96b5cd2f06969faf09c6aba8a4d13c",
        )
        manifest = _manifest()
        requirements = {
            item.kind: item for item in manifest.attestation_requirements
        }
        self.assertEqual(
            requirements[
                readiness._AttestationKind.EXACT_TLS_POLICY
            ].content_digest,
            _TLS_POLICY_DIGEST,
        )
        self.assertEqual(
            requirements[
                readiness._AttestationKind.PRODUCTION_CREDENTIAL_SOURCE_BINDING
            ].content_digest,
            manifest.credential_source_binding_requirement.content_digest,
        )
        self.assertEqual(
            requirements[
                readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER
            ].content_digest,
            manifest.application_transport_cutover_requirement.content_digest,
        )

    def test_manifest_safe_metadata_discloses_no_identity_or_path(self):
        manifest = _manifest()
        rendered = repr(manifest.safe_metadata())
        for sensitive in (
            manifest.app_bundle_identifier,
            manifest.team_id,
            manifest.application_entrypoint_relative_path,
            manifest.supervisor_relative_path,
            manifest.helper_relative_path,
            manifest.supervisor_signing_identifier,
            manifest.helper_signing_identifier,
            manifest.exact_tls_policy_requirement.hostname,
            manifest.credential_source_binding_requirement.credential_ref,
            manifest.credential_source_binding_requirement.service,
            manifest.credential_source_binding_requirement.account,
            manifest.credential_source_binding_requirement.access_group,
            manifest.credential_source_binding_requirement.resolver_credential_ref,
            manifest.application_keychain_entitlement_requirement.application_identifier,
        ):
            self.assertNotIn(sensitive, rendered)

    def test_http1_policy_regex_or_limit_drift_invalidates_manifest(self):
        class _NoCall:
            def __getattribute__(self, name):
                raise AssertionError("probe called after HTTP policy drift: " + name)

        cases = (
            (
                "MAX_HTTP_RESPONSE_BODY_BYTES",
                exact_http1.MAX_HTTP_RESPONSE_BODY_BYTES + 1,
            ),
            (
                "_STATUS_LINE_RE",
                re.compile(
                    rb"HTTP/2\.0 ([0-9]{3})(?: ([\x20-\x7e]*))?\Z"
                ),
            ),
        )
        for name, replacement in cases:
            with self.subTest(name=name):
                manifest = _manifest()
                with mock.patch.object(exact_http1, name, replacement):
                    assessment = readiness._assess_production_readiness(
                        manifest=manifest,
                        probe=_NoCall(),
                    )
                    with self.assertRaises(ValueError):
                        _manifest()

                self.assertEqual(
                    _blockers(assessment),
                    {
                        readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                        readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
                    },
                )

    def test_tls_policy_or_keychain_schema_drift_invalidates_manifest(self):
        class _NoCall:
            def __getattribute__(self, name):
                raise AssertionError("probe called after binding drift: " + name)

        tls_manifest = _manifest()
        original_payload = exact_tls._exact_tls_policy_payload

        def drifted_payload(*, hostname):
            payload = original_payload(hostname=hostname)
            payload["minimum_version"] = "TLSv1.3"
            return payload

        with mock.patch.object(
            exact_tls,
            "_exact_tls_policy_payload",
            drifted_payload,
        ):
            assessment = readiness._assess_production_readiness(
                manifest=tls_manifest,
                probe=_NoCall(),
            )
            with self.assertRaises(ValueError):
                _manifest()
        self.assertEqual(
            _blockers(assessment),
            {
                readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
            },
        )

        keychain_manifest = _manifest()
        with mock.patch.object(
            darwin_keychain,
            "DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION",
            "snapquiz.darwin-keychain-source.wrong",
        ):
            assessment = readiness._assess_production_readiness(
                manifest=keychain_manifest,
                probe=_NoCall(),
            )
            with self.assertRaises(ValueError):
                _manifest()
        self.assertEqual(
            _blockers(assessment),
            {
                readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
            },
        )

    def test_exact_transport_contract_drift_invalidates_manifest(self):
        class _NoCall:
            def __getattribute__(self, name):
                raise AssertionError("probe called after transport drift: " + name)

        for field in (
            "EXACT_TRANSPORT_POLICY_VERSION",
            "EXACT_WIRE_EVIDENCE_SCHEMA_VERSION",
        ):
            with self.subTest(field=field):
                manifest = _manifest()
                with mock.patch.object(
                    exact_transport,
                    field,
                    "snapquiz.exact-transport.wrong",
                ):
                    assessment = readiness._assess_production_readiness(
                        manifest=manifest,
                        probe=_NoCall(),
                    )
                    with self.assertRaises(ValueError):
                        _manifest()
                self.assertEqual(
                    _blockers(assessment),
                    {
                        readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                        readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
                    },
                )


class ProductionReadinessAssessmentTest(unittest.TestCase):
    def test_verified_fake_evidence_still_has_no_production_authority(self):
        assessment = _assessment()
        self.assertEqual(
            assessment.blockers,
            (readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,),
        )
        self.assertFalse(assessment.is_ready)
        self.assertFalse(assessment.production_authority_available)
        metadata = assessment.safe_metadata()
        self.assertFalse(metadata["is_ready"])
        self.assertFalse(metadata["production_authority_available"])
        self.assertFalse(metadata["production_transport_integration_available"])

    def test_probe_receives_only_bound_expected_values_once(self):
        manifest = _manifest()
        probe = _VerifiedProbe()
        assessment = readiness._assess_production_readiness(
            manifest=manifest,
            probe=probe,
        )
        self.assertEqual(len(probe.requests), 9)
        self.assertTrue(
            all(request.manifest_digest == manifest.manifest_digest for request in probe.requests)
        )
        artifact_requests = tuple(
            request
            for request in probe.requests
            if type(request) is readiness._ArtifactProbeRequest
        )
        self.assertEqual(
            tuple(request.role for request in artifact_requests),
            (
                readiness._ArtifactRole.SUPERVISOR,
                readiness._ArtifactRole.HELPER,
            ),
        )
        tls_request = next(
            request
            for request in probe.requests
            if type(request) is readiness._ExactTlsPolicyProbeRequest
        )
        credential_request = next(
            request
            for request in probe.requests
            if type(request)
            is readiness._ProductionCredentialSourceBindingProbeRequest
        )
        cutover_request = next(
            request
            for request in probe.requests
            if type(request)
            is readiness._ApplicationTransportCutoverProbeRequest
        )
        self.assertEqual(
            tls_request.requirement,
            manifest.exact_tls_policy_requirement,
        )
        self.assertEqual(
            credential_request.requirement,
            manifest.credential_source_binding_requirement,
        )
        cutover = manifest.application_transport_cutover_requirement
        transport = manifest.exact_transport_binding_requirement
        self.assertEqual(cutover_request.version, cutover.version)
        self.assertEqual(
            cutover_request.manifest_content_digest,
            manifest.manifest_content_digest,
        )
        self.assertEqual(
            cutover_request.application_entrypoint_sha256,
            manifest.application_entrypoint_sha256,
        )
        self.assertEqual(
            cutover_request.exact_transport_binding_digest,
            transport.content_digest,
        )
        self.assertEqual(cutover_request.content_digest, cutover.content_digest)
        self.assertEqual(
            cutover_request.request_digest,
            digest256(
                "ApplicationTransportCutoverProbeBinding",
                readiness.APPLICATION_TRANSPORT_CUTOVER_PROBE_BINDING_SCHEMA_VERSION,
                {
                    "cutover_subject_digest": cutover.content_digest,
                    "manifest_digest": manifest.manifest_digest,
                },
            ),
        )
        with self.assertRaises(TypeError):
            pickle.dumps(cutover_request)
        with self.assertRaises(TypeError):
            pickle.dumps(
                readiness._ApplicationTransportCutoverProbeFact(
                    readiness._ProbeState.VERIFIED,
                    *cutover_request,
                )
            )
        self.assertNotIn("freshness", repr(manifest.safe_metadata()))
        self.assertNotIn("freshness", repr(assessment.safe_metadata()))
        self.assertEqual(
            assessment.blockers,
            (readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,),
        )

    def test_missing_unknown_tampered_bundle_facts_fail_closed(self):
        expected = {
            readiness._ProbeState.MISSING: (
                readiness._ReadinessBlocker.APP_BUNDLE_MISSING
            ),
            readiness._ProbeState.UNKNOWN: (
                readiness._ReadinessBlocker.APP_BUNDLE_UNKNOWN
            ),
            readiness._ProbeState.TAMPERED: (
                readiness._ReadinessBlocker.APP_BUNDLE_TAMPERED
            ),
        }
        for state, blocker in expected.items():
            with self.subTest(state=state):
                probe = _VerifiedProbe()
                probe.bundle_fact = readiness._BundleProbeFact(
                    state=state,
                    is_macos_app_bundle=None,
                    bundle_identifier=None,
                    team_id=None,
                    usable_signing_identity_count=None,
                    codesign_valid=None,
                    security_assessment_valid=None,
                )
                self.assertIn(blocker, _blockers(_assessment(probe)))

    def test_identity_zero_non_bundle_and_identity_mismatch_fail_closed(self):
        probe = _VerifiedProbe()
        probe.bundle_fact = readiness._BundleProbeFact(
            state=readiness._ProbeState.VERIFIED,
            is_macos_app_bundle=False,
            bundle_identifier="other.vendor.desktop",
            team_id="Z9Y8X7W6V5",
            usable_signing_identity_count=0,
            codesign_valid=False,
            security_assessment_valid=False,
        )
        blockers = _blockers(_assessment(probe))
        self.assertTrue(
            {
                readiness._ReadinessBlocker.APP_BUNDLE_LAYOUT_INVALID,
                readiness._ReadinessBlocker.APP_BUNDLE_IDENTIFIER_MISMATCH,
                readiness._ReadinessBlocker.APP_BUNDLE_TEAM_MISMATCH,
                readiness._ReadinessBlocker.SIGNING_IDENTITY_UNAVAILABLE,
                readiness._ReadinessBlocker.APP_BUNDLE_CODESIGN_INVALID,
                readiness._ReadinessBlocker.APP_BUNDLE_SECURITY_ASSESSMENT_INVALID,
            }.issubset(blockers)
        )

    def test_app_keychain_entitlements_are_proved_field_by_field(self):
        manifest = _manifest()
        requirement = manifest.application_keychain_entitlement_requirement
        base = readiness._BundleProbeFact(
            state=readiness._ProbeState.VERIFIED,
            is_macos_app_bundle=True,
            bundle_identifier=manifest.app_bundle_identifier,
            team_id=manifest.team_id,
            usable_signing_identity_count=1,
            codesign_valid=True,
            security_assessment_valid=True,
            keychain_entitlements_version=requirement.version,
            application_identifier_entitlement=(
                requirement.application_identifier
            ),
            team_identifier_entitlement=requirement.team_identifier,
            keychain_access_groups_entitlement=(
                requirement.keychain_access_groups
            ),
            keychain_entitlements_digest=requirement.content_digest,
        )
        cases = (
            (
                "keychain_entitlements_version",
                "snapquiz.application-keychain-entitlements.wrong",
                readiness._ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_VERSION_MISMATCH,
            ),
            (
                "application_identifier_entitlement",
                "A1B2C3D4E5.other.vendor.desktop",
                readiness._ReadinessBlocker.APP_BUNDLE_APPLICATION_IDENTIFIER_ENTITLEMENT_MISMATCH,
            ),
            (
                "team_identifier_entitlement",
                "Z9Y8X7W6V5",
                readiness._ReadinessBlocker.APP_BUNDLE_TEAM_IDENTIFIER_ENTITLEMENT_MISMATCH,
            ),
            (
                "keychain_access_groups_entitlement",
                ("A1B2C3D4E5.ai.snapquiz.unrelated",),
                readiness._ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ACCESS_GROUPS_ENTITLEMENT_MISMATCH,
            ),
            (
                "keychain_entitlements_digest",
                Digest256("e" * 64),
                readiness._ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_DIGEST_MISMATCH,
            ),
        )
        for field, value, blocker in cases:
            with self.subTest(field=field):
                probe = _VerifiedProbe()
                probe.bundle_fact = base._replace(**{field: value})
                blockers = _blockers(
                    readiness._assess_production_readiness(
                        manifest=manifest,
                        probe=probe,
                    )
                )
                self.assertIn(blocker, blockers)

        legacy = _VerifiedProbe()
        legacy.bundle_fact = readiness._BundleProbeFact(
            readiness._ProbeState.VERIFIED,
            True,
            manifest.app_bundle_identifier,
            manifest.team_id,
            1,
            True,
            True,
        )
        self.assertTrue(
            {
                readiness._ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_VERSION_MISMATCH,
                readiness._ReadinessBlocker.APP_BUNDLE_APPLICATION_IDENTIFIER_ENTITLEMENT_MISMATCH,
                readiness._ReadinessBlocker.APP_BUNDLE_TEAM_IDENTIFIER_ENTITLEMENT_MISMATCH,
                readiness._ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ACCESS_GROUPS_ENTITLEMENT_MISMATCH,
                readiness._ReadinessBlocker.APP_BUNDLE_KEYCHAIN_ENTITLEMENTS_DIGEST_MISMATCH,
            }.issubset(_blockers(_assessment(legacy)))
        )

    def test_artifact_non_macho_path_digest_and_signing_mismatch_fail_closed(self):
        manifest = _manifest()
        probe = _VerifiedProbe()
        probe.artifact_facts[readiness._ArtifactRole.SUPERVISOR] = (
            readiness._ArtifactProbeFact(
                state=readiness._ProbeState.VERIFIED,
                role=readiness._ArtifactRole.SUPERVISOR,
                bundle_relative_path="Contents/Library/LaunchServices/Wrong",
                sha256=Digest256("3" * 64),
                is_macho=False,
                is_bundle_member=False,
                signing_identifier="other.vendor.supervisor",
                team_id="Z9Y8X7W6V5",
                codesign_valid=False,
                security_assessment_valid=False,
            )
        )
        blockers = _blockers(
            readiness._assess_production_readiness(
                manifest=manifest,
                probe=probe,
            )
        )
        self.assertIn(
            readiness._ReadinessBlocker.SUPERVISOR_ARTIFACT_INVALID,
            blockers,
        )
        self.assertNotIn(
            readiness._ReadinessBlocker.HELPER_ARTIFACT_INVALID,
            blockers,
        )

    def test_artifact_statuses_are_role_specific(self):
        cases = (
            (
                readiness._ArtifactRole.SUPERVISOR,
                readiness._ProbeState.MISSING,
                readiness._ReadinessBlocker.SUPERVISOR_ARTIFACT_MISSING,
            ),
            (
                readiness._ArtifactRole.SUPERVISOR,
                readiness._ProbeState.UNKNOWN,
                readiness._ReadinessBlocker.SUPERVISOR_ARTIFACT_UNKNOWN,
            ),
            (
                readiness._ArtifactRole.HELPER,
                readiness._ProbeState.TAMPERED,
                readiness._ReadinessBlocker.HELPER_ARTIFACT_TAMPERED,
            ),
        )
        for role, state, expected in cases:
            with self.subTest(role=role, state=state):
                probe = _VerifiedProbe()
                probe.artifact_facts[role] = readiness._ArtifactProbeFact(
                    state=state,
                    role=role,
                    bundle_relative_path=None,
                    sha256=None,
                    is_macho=None,
                    is_bundle_member=None,
                    signing_identifier=None,
                    team_id=None,
                    codesign_valid=None,
                    security_assessment_valid=None,
                )
                self.assertIn(expected, _blockers(_assessment(probe)))

    def test_attestation_missing_unknown_tamper_and_version_drift_fail_closed(self):
        requirements = readiness.REQUIRED_ATTESTATION_VERSIONS
        probe = _VerifiedProbe()
        probe.attestation_facts = (
            readiness._AttestationProbeFact(
                requirements[0].kind,
                readiness._ProbeState.UNKNOWN,
                None,
            ),
            readiness._AttestationProbeFact(
                requirements[1].kind,
                readiness._ProbeState.TAMPERED,
                requirements[1].version,
            ),
            readiness._AttestationProbeFact(
                requirements[2].kind,
                readiness._ProbeState.VERIFIED,
                "snapquiz.wrong.v1",
            ),
        ) + tuple(
            readiness._AttestationProbeFact(
                item.kind,
                readiness._ProbeState.VERIFIED,
                item.version,
                item.content_digest,
            )
            for item in requirements[3:-1]
        )
        blockers = _blockers(_assessment(probe))
        self.assertTrue(
            {
                readiness._ReadinessBlocker.ATTESTATION_UNKNOWN,
                readiness._ReadinessBlocker.ATTESTATION_TAMPERED,
                readiness._ReadinessBlocker.ATTESTATION_VERSION_MISMATCH,
                readiness._ReadinessBlocker.ATTESTATION_MISSING,
                readiness._ReadinessBlocker.PROBE_CONTRACT_INVALID,
            }.issubset(blockers)
        )

    def test_http1_attestation_digest_drift_fails_closed(self):
        requirement = next(
            item
            for item in readiness.REQUIRED_ATTESTATION_VERSIONS
            if item.kind is readiness._AttestationKind.EXACT_HTTP1_POLICY
        )
        probe = _VerifiedProbe()
        probe.attestation_facts = tuple(
            readiness._AttestationProbeFact(
                kind=item.kind,
                state=readiness._ProbeState.VERIFIED,
                version=item.version,
                content_digest=(
                    Digest256("f" * 64)
                    if item is requirement
                    else item.content_digest
                ),
            )
            for item in readiness.REQUIRED_ATTESTATION_VERSIONS
        )

        blockers = _blockers(_assessment(probe))

        self.assertIn(
            readiness._ReadinessBlocker.ATTESTATION_DIGEST_MISMATCH,
            blockers,
        )
        self.assertNotIn(
            readiness._ReadinessBlocker.ATTESTATION_VERSION_MISMATCH,
            blockers,
        )

    def test_security_and_cutover_attestations_require_content_digests(self):
        for kind in (
            readiness._AttestationKind.EXACT_TLS_POLICY,
            readiness._AttestationKind.PRODUCTION_CREDENTIAL_SOURCE_BINDING,
            readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER,
        ):
            with self.subTest(kind=kind):
                manifest = _manifest()
                probe = _VerifiedProbe()
                probe.attestation_facts = tuple(
                    readiness._AttestationProbeFact(
                        item.kind,
                        readiness._ProbeState.VERIFIED,
                        item.version,
                        (
                            None
                            if item.kind is kind
                            else item.content_digest
                        ),
                    )
                    for item in manifest.attestation_requirements
                )
                self.assertIn(
                    readiness._ReadinessBlocker.ATTESTATION_DIGEST_MISMATCH,
                    _blockers(
                        readiness._assess_production_readiness(
                            manifest=manifest,
                            probe=probe,
                        )
                    ),
                )

    def test_tls_probe_status_and_each_exact_field_fail_closed(self):
        manifest = _manifest()
        requirement = manifest.exact_tls_policy_requirement
        base = readiness._ExactTlsPolicyProbeFact(
            readiness._ProbeState.VERIFIED,
            requirement.version,
            requirement.hostname,
            requirement.policy_ref,
            requirement.policy_digest,
        )
        status_cases = (
            (
                readiness._ProbeState.MISSING,
                readiness._ReadinessBlocker.EXACT_TLS_POLICY_MISSING,
            ),
            (
                readiness._ProbeState.UNKNOWN,
                readiness._ReadinessBlocker.EXACT_TLS_POLICY_UNKNOWN,
            ),
            (
                readiness._ProbeState.TAMPERED,
                readiness._ReadinessBlocker.EXACT_TLS_POLICY_TAMPERED,
            ),
        )
        for state, blocker in status_cases:
            with self.subTest(state=state):
                probe = _VerifiedProbe()
                probe.tls_policy_fact = readiness._ExactTlsPolicyProbeFact(
                    state,
                    None,
                    None,
                    None,
                    None,
                )
                self.assertIn(blocker, _blockers(_assessment(probe)))

        mismatch_cases = (
            ("version", "snapquiz.tls-policy-proof.wrong"),
            ("hostname", "api.example.com"),
            ("policy_ref", "snapquiz.tls.other.v1"),
            ("policy_digest", Digest256("d" * 64)),
            ("policy_digest", str(requirement.policy_digest)),
        )
        for field, value in mismatch_cases:
            with self.subTest(field=field, value_type=type(value).__name__):
                probe = _VerifiedProbe()
                probe.tls_policy_fact = base._replace(**{field: value})
                self.assertIn(
                    readiness._ReadinessBlocker.EXACT_TLS_POLICY_MISMATCH,
                    _blockers(_assessment(probe)),
                )

    def test_credential_probe_status_and_each_exact_field_fail_closed(self):
        manifest = _manifest()
        requirement = manifest.credential_source_binding_requirement
        base = readiness._ProductionCredentialSourceBindingProbeFact(
            readiness._ProbeState.VERIFIED,
            *tuple(requirement),
        )
        status_cases = (
            (
                readiness._ProbeState.MISSING,
                readiness._ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_MISSING,
            ),
            (
                readiness._ProbeState.UNKNOWN,
                readiness._ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_UNKNOWN,
            ),
            (
                readiness._ProbeState.TAMPERED,
                readiness._ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_TAMPERED,
            ),
        )
        for state, blocker in status_cases:
            with self.subTest(state=state):
                probe = _VerifiedProbe()
                probe.credential_source_fact = (
                    readiness._ProductionCredentialSourceBindingProbeFact(
                        state,
                        *(None for _ in requirement),
                    )
                )
                self.assertIn(blocker, _blockers(_assessment(probe)))

        replacement_digest = Digest256("d" * 64)
        mismatch_cases = (
            ("version", "snapquiz.production-credential-source-binding.wrong"),
            ("keychain_source_schema_version", "snapquiz.keychain.wrong"),
            ("credential_ref", "keychain-generic-password:v1:other"),
            ("service", "ai.snapquiz.other"),
            ("account", "other"),
            ("access_group", "A1B2C3D4E5.ai.snapquiz.other"),
            ("keychain_binding_digest", replacement_digest),
            ("resolver_credential_ref", "env:OTHER_API_KEY"),
            ("resolver_binding_digest", replacement_digest),
            ("resolver_mapping_digest", replacement_digest),
            ("application_entitlements_digest", replacement_digest),
            ("content_digest", replacement_digest),
            ("content_digest", str(requirement.content_digest)),
        )
        for field, value in mismatch_cases:
            with self.subTest(field=field, value_type=type(value).__name__):
                probe = _VerifiedProbe()
                probe.credential_source_fact = base._replace(**{field: value})
                self.assertIn(
                    readiness._ReadinessBlocker.PRODUCTION_CREDENTIAL_SOURCE_BINDING_MISMATCH,
                    _blockers(_assessment(probe)),
                )

    def test_cutover_probe_status_and_each_exact_field_fail_closed(self):
        status_cases = (
            (
                readiness._ProbeState.MISSING,
                readiness._ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_MISSING,
            ),
            (
                readiness._ProbeState.UNKNOWN,
                readiness._ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_UNKNOWN,
            ),
            (
                readiness._ProbeState.TAMPERED,
                readiness._ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_TAMPERED,
            ),
        )
        for state, blocker in status_cases:
            with self.subTest(state=state):
                probe = _VerifiedProbe()

                def status_fact(request, selected=state):
                    return readiness._ApplicationTransportCutoverProbeFact(
                        selected,
                        *(None for _ in request),
                    )

                probe.inspect_application_transport_cutover = status_fact
                self.assertIn(blocker, _blockers(_assessment(probe)))

        replacement_digest = Digest256("d" * 64)
        mismatch_cases = (
            ("version", "snapquiz.application-transport-cutover.v1"),
            ("manifest_content_digest", replacement_digest),
            ("app_bundle_identifier", "other.vendor.desktop"),
            ("team_id", "Z9Y8X7W6V5"),
            (
                "application_entrypoint_relative_path",
                "Contents/MacOS/Other",
            ),
            ("application_entrypoint_sha256", replacement_digest),
            ("exact_transport_binding_version", "snapquiz.binding.wrong"),
            ("exact_transport_policy_version", "snapquiz.transport.wrong"),
            ("exact_wire_evidence_schema_version", "snapquiz.wire.wrong"),
            ("exact_http1_policy_version", "snapquiz.http.wrong"),
            ("exact_http1_policy_digest", replacement_digest),
            ("exact_tls_policy_version", "snapquiz.tls.wrong"),
            ("exact_tls_policy_ref", "snapquiz.tls.other"),
            ("exact_tls_hostname", "api.example.com"),
            ("exact_tls_policy_digest", replacement_digest),
            (
                "credential_source_binding_version",
                "snapquiz.credential.wrong",
            ),
            ("credential_source_binding_digest", replacement_digest),
            ("network_policy_version", "remote-https.wrong"),
            ("public_address_policy_digest", replacement_digest),
            ("exact_transport_binding_digest", replacement_digest),
            ("content_digest", replacement_digest),
            ("content_digest", str(replacement_digest)),
        )
        for field, value in mismatch_cases:
            with self.subTest(field=field, value_type=type(value).__name__):
                probe = _VerifiedProbe()

                def mismatch_fact(request, name=field, replacement=value):
                    fact = readiness._ApplicationTransportCutoverProbeFact(
                        readiness._ProbeState.VERIFIED,
                        *request,
                    )
                    return fact._replace(**{name: replacement})

                probe.inspect_application_transport_cutover = mismatch_fact
                self.assertIn(
                    readiness._ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_MISMATCH,
                    _blockers(_assessment(probe)),
                )

    def test_cutover_stale_generic_and_replayed_facts_fail_closed(self):
        manifest = _manifest()
        old_generic_probe = _VerifiedProbe()
        old_generic_probe.attestation_facts = tuple(
            readiness._AttestationProbeFact(
                item.kind,
                readiness._ProbeState.VERIFIED,
                (
                    "snapquiz.application-transport-cutover.v1"
                    if item.kind
                    is readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER
                    else item.version
                ),
                (
                    None
                    if item.kind
                    is readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER
                    else item.content_digest
                ),
            )
            for item in manifest.attestation_requirements
        )
        self.assertIn(
            readiness._ReadinessBlocker.ATTESTATION_VERSION_MISMATCH,
            _blockers(
                readiness._assess_production_readiness(
                    manifest=manifest,
                    probe=old_generic_probe,
                )
            ),
        )

        stale_cases = (
            ("manifest_digest", Digest256("a" * 64)),
            ("request_digest", Digest256("b" * 64)),
            ("freshness_challenge", object()),
        )
        for field, value in stale_cases:
            with self.subTest(field=field):
                probe = _VerifiedProbe()

                def stale_fact(request, name=field, replacement=value):
                    fact = readiness._ApplicationTransportCutoverProbeFact(
                        readiness._ProbeState.VERIFIED,
                        *request,
                    )
                    return fact._replace(**{name: replacement})

                probe.inspect_application_transport_cutover = stale_fact
                self.assertIn(
                    readiness._ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_STALE_OR_REPLAYED,
                    _blockers(_assessment(probe)),
                )

        source_manifest = _manifest()
        source_probe = _VerifiedProbe()
        readiness._assess_production_readiness(
            manifest=source_manifest,
            probe=source_probe,
        )
        source_request = next(
            request
            for request in source_probe.requests
            if type(request)
            is readiness._ApplicationTransportCutoverProbeRequest
        )
        replayed = readiness._ApplicationTransportCutoverProbeFact(
            readiness._ProbeState.VERIFIED,
            *source_request,
        )

        same_manifest_probe = _VerifiedProbe()
        same_manifest_probe.cutover_fact = replayed
        self.assertIn(
            readiness._ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_STALE_OR_REPLAYED,
            _blockers(
                readiness._assess_production_readiness(
                    manifest=source_manifest,
                    probe=same_manifest_probe,
                )
            ),
        )

        changed_manifest = _manifest(
            application_entrypoint_sha256=Digest256("5" * 64)
        )
        changed_manifest_probe = _VerifiedProbe()
        changed_manifest_probe.cutover_fact = replayed
        self.assertIn(
            readiness._ReadinessBlocker.APPLICATION_TRANSPORT_CUTOVER_STALE_OR_REPLAYED,
            _blockers(
                readiness._assess_production_readiness(
                    manifest=changed_manifest,
                    probe=changed_manifest_probe,
                )
            ),
        )

        generic_probe = _VerifiedProbe()
        generic_probe.cutover_fact = readiness._AttestationProbeFact(
            readiness._AttestationKind.APPLICATION_TRANSPORT_CUTOVER,
            readiness._ProbeState.VERIFIED,
            readiness.APPLICATION_TRANSPORT_CUTOVER_ATTESTATION_VERSION,
            _APPLICATION_TRANSPORT_CUTOVER_DIGEST,
        )
        self.assertIn(
            readiness._ReadinessBlocker.PROBE_CONTRACT_INVALID,
            _blockers(_assessment(generic_probe)),
        )

    def test_legacy_probe_without_exact_security_methods_fails_closed(self):
        class _LegacyProbe(_VerifiedProbe):
            inspect_exact_tls_policy = None
            inspect_production_credential_source_binding = None
            inspect_application_transport_cutover = None

        assessment = _assessment(_LegacyProbe())
        self.assertIn(readiness._ReadinessBlocker.PROBE_FAILED, assessment.blockers)

    def test_native_owner_capability_missing_and_version_drift_fail_closed(self):
        requirements = readiness.REQUIRED_NATIVE_CAPABILITIES
        probe = _VerifiedProbe()
        probe.capability_facts = (
            readiness._NativeCapabilityProbeFact(
                requirements[0].capability,
                readiness._ProbeState.MISSING,
                None,
            ),
            readiness._NativeCapabilityProbeFact(
                requirements[1].capability,
                readiness._ProbeState.VERIFIED,
                "snapquiz.wrong-owner.v1",
            ),
        ) + tuple(
            readiness._NativeCapabilityProbeFact(
                item.capability,
                readiness._ProbeState.VERIFIED,
                item.interface_version,
            )
            for item in requirements[2:-1]
        )
        blockers = _blockers(_assessment(probe))
        self.assertTrue(
            {
                readiness._ReadinessBlocker.NATIVE_CAPABILITY_MISSING,
                readiness._ReadinessBlocker.NATIVE_CAPABILITY_VERSION_MISMATCH,
                readiness._ReadinessBlocker.PROBE_CONTRACT_INVALID,
            }.issubset(blockers)
        )

    def test_dns_unknown_tamper_and_policy_mismatch_fail_closed(self):
        expected = {
            readiness._ProbeState.MISSING: (
                readiness._ReadinessBlocker.DNS_EVIDENCE_MISSING
            ),
            readiness._ProbeState.UNKNOWN: (
                readiness._ReadinessBlocker.DNS_EVIDENCE_UNKNOWN
            ),
            readiness._ProbeState.TAMPERED: (
                readiness._ReadinessBlocker.DNS_EVIDENCE_TAMPERED
            ),
        }
        for state, blocker in expected.items():
            with self.subTest(state=state):
                probe = _VerifiedProbe()
                probe.dns_fact = readiness._DnsProbeFact(
                    state,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                self.assertIn(blocker, _blockers(_assessment(probe)))

        probe = _VerifiedProbe()
        probe.dns_fact = readiness._DnsProbeFact(
            readiness._ProbeState.VERIFIED,
            "wrong-policy.v1",
            Digest256("4" * 64),
            True,
            False,
            True,
        )
        self.assertIn(
            readiness._ReadinessBlocker.DNS_POLICY_MISMATCH,
            _blockers(_assessment(probe)),
        )

    def test_invalid_or_faulting_probe_is_content_free_and_fail_closed(self):
        class _FaultingProbe(_VerifiedProbe):
            def inspect_app_bundle(self, request):
                del request
                raise RuntimeError("/private/secret/path API_TOKEN=do-not-leak")

            def inspect_artifact(self, request):
                del request
                return object()

        assessment = _assessment(_FaultingProbe())
        blockers = _blockers(assessment)
        self.assertIn(readiness._ReadinessBlocker.PROBE_FAILED, blockers)
        self.assertIn(
            readiness._ReadinessBlocker.PROBE_CONTRACT_INVALID,
            blockers,
        )
        rendered = repr(assessment.safe_metadata())
        self.assertNotIn("secret", rendered)
        self.assertNotIn("API_TOKEN", rendered)

    def test_probe_baseexceptions_and_return_interrupts_are_content_free(self):
        method_names = (
            "inspect_app_bundle",
            "inspect_artifact",
            "inspect_attestations",
            "inspect_exact_tls_policy",
            "inspect_production_credential_source_binding",
            "inspect_application_transport_cutover",
            "inspect_native_capabilities",
            "inspect_dns_policy",
        )
        exception_types = (KeyboardInterrupt, SystemExit)
        for method_name in method_names:
            for exception_type in exception_types:
                with self.subTest(
                    method_name=method_name,
                    exception_type=exception_type.__name__,
                ):
                    probe = _VerifiedProbe()
                    setattr(
                        probe,
                        method_name,
                        mock.Mock(
                            side_effect=exception_type(
                                "private-path:/tmp/secret API_TOKEN=do-not-leak"
                            )
                        ),
                    )
                    assessment = _assessment(probe)
                    self.assertIn(
                        readiness._ReadinessBlocker.PROBE_FAILED,
                        assessment.blockers,
                    )
                    rendered = repr(assessment.safe_metadata())
                    self.assertNotIn("private-path", rendered)
                    self.assertNotIn("API_TOKEN", rendered)

        # A trace interruption on the probe's return event models the narrow
        # CPython CALL-return -> caller-STORE gap.  The diagnostic owns no
        # resource from that call, so it must reduce the event to one blocker.
        probe = _VerifiedProbe()
        original = probe.inspect_app_bundle

        def return_value(request):
            return original(request)

        probe.inspect_app_bundle = return_value  # type: ignore[method-assign]
        previous = sys.gettrace()
        fired = False

        def interrupt(frame, event, arg):
            nonlocal fired
            del arg
            if (
                not fired
                and event == "return"
                and frame.f_code is return_value.__code__
            ):
                fired = True
                sys.settrace(previous)
                raise KeyboardInterrupt(
                    "private-path:/tmp/secret API_TOKEN=return-gap"
                )
            return interrupt

        sys.settrace(interrupt)
        try:
            assessment = _assessment(probe)
        finally:
            sys.settrace(previous)
        self.assertTrue(fired)
        self.assertIn(
            readiness._ReadinessBlocker.PROBE_FAILED,
            assessment.blockers,
        )
        rendered = repr(assessment.safe_metadata())
        self.assertNotIn("private-path", rendered)
        self.assertNotIn("API_TOKEN", rendered)

    def test_probe_cannot_redirect_later_requests_by_tampering_source_manifest(self):
        manifest = _manifest()
        expected_path = manifest.supervisor_relative_path

        class _TamperingProbe(_VerifiedProbe):
            def inspect_app_bundle(self, request):
                fact = super().inspect_app_bundle(request)
                object.__setattr__(
                    manifest,
                    "supervisor_relative_path",
                    "Contents/Library/LaunchServices/RedirectedSupervisor",
                )
                return fact

        probe = _TamperingProbe()
        assessment = readiness._assess_production_readiness(
            manifest=manifest,
            probe=probe,
        )
        supervisor_requests = tuple(
            request
            for request in probe.requests
            if type(request) is readiness._ArtifactProbeRequest
            and request.role is readiness._ArtifactRole.SUPERVISOR
        )
        self.assertEqual(len(supervisor_requests), 1)
        self.assertEqual(
            supervisor_requests[0].bundle_relative_path,
            expected_path,
        )
        self.assertIn(
            readiness._ReadinessBlocker.MANIFEST_TAMPERED,
            assessment.blockers,
        )

    def test_manifest_validation_baseexception_skips_probe_and_is_content_free(self):
        manifest = _manifest()

        class _NoCall:
            def __getattribute__(self, name):
                raise AssertionError("probe action after validation fault: " + name)

        with mock.patch.object(
            readiness._ProductionReadinessManifest,
            "validate_integrity",
            side_effect=SystemExit(
                "private-path:/tmp/secret API_TOKEN=do-not-leak"
            ),
        ):
            assessment = readiness._assess_production_readiness(
                manifest=manifest,
                probe=_NoCall(),
            )
        self.assertEqual(
            _blockers(assessment),
            {
                readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
            },
        )
        rendered = repr(assessment.safe_metadata())
        self.assertNotIn("private-path", rendered)
        self.assertNotIn("API_TOKEN", rendered)

    def test_manifest_tamper_skips_all_probe_actions(self):
        manifest = _manifest()
        object.__setattr__(manifest, "team_id", "Z9Y8X7W6V5")

        class _NoCall:
            def __getattribute__(self, name):
                raise AssertionError("probe action after manifest tamper: " + name)

        assessment = readiness._assess_production_readiness(
            manifest=manifest,
            probe=_NoCall(),
        )
        self.assertEqual(
            _blockers(assessment),
            {
                readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
            },
        )

    def test_nested_security_requirement_tamper_skips_probe_actions(self):
        class _NoCall:
            def __getattribute__(self, name):
                raise AssertionError(
                    "probe action after security requirement tamper: " + name
                )

        mutations = (
            (
                "exact_tls_policy_requirement",
                lambda manifest: manifest.exact_tls_policy_requirement._replace(
                    hostname="api.example.com"
                ),
            ),
            (
                "credential_source_binding_requirement",
                lambda manifest: (
                    manifest.credential_source_binding_requirement._replace(
                        service="ai.snapquiz.other"
                    )
                ),
            ),
            (
                "application_keychain_entitlement_requirement",
                lambda manifest: (
                    manifest.application_keychain_entitlement_requirement._replace(
                        keychain_access_groups=(
                            "A1B2C3D4E5.ai.snapquiz.other",
                        )
                    )
                ),
            ),
            (
                "exact_transport_binding_requirement",
                lambda manifest: (
                    manifest.exact_transport_binding_requirement._replace(
                        content_digest=Digest256("e" * 64)
                    )
                ),
            ),
        )
        for field, mutation in mutations:
            with self.subTest(field=field):
                manifest = _manifest()
                object.__setattr__(manifest, field, mutation(manifest))
                assessment = readiness._assess_production_readiness(
                    manifest=manifest,
                    probe=_NoCall(),
                )
                self.assertEqual(
                    _blockers(assessment),
                    {
                        readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                        readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
                    },
                )

        manifest = _manifest()
        object.__setattr__(
            manifest.application_transport_cutover_requirement,
            "application_entrypoint_sha256",
            Digest256("e" * 64),
        )
        assessment = readiness._assess_production_readiness(
            manifest=manifest,
            probe=_NoCall(),
        )
        self.assertEqual(
            _blockers(assessment),
            {
                readiness._ReadinessBlocker.MANIFEST_TAMPERED,
                readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
            },
        )

    def test_assessment_is_factory_only_immutable_and_tamper_evident(self):
        assessment = _assessment()
        assessment.validate_integrity()
        self.assertIs(copy.copy(assessment), assessment)
        self.assertIs(copy.deepcopy(assessment), assessment)
        with self.assertRaises(TypeError):
            readiness._ProductionReadinessAssessment(
                manifest_digest=assessment.manifest_digest,
                blockers=assessment.blockers,
            )
        with self.assertRaises(AttributeError):
            assessment.blockers = ()
        with self.assertRaises(TypeError):
            pickle.dumps(assessment)
        with self.assertRaises(TypeError):
            class _AssessmentSubclass(
                readiness._ProductionReadinessAssessment
            ):
                pass
        object.__setattr__(assessment, "blockers", ())
        with self.assertRaises(Exception):
            assessment.validate_integrity()

    def test_concurrent_assessments_are_deterministic_and_share_no_state(self):
        manifest = _manifest()

        def assess(_):
            return readiness._assess_production_readiness(
                manifest=manifest,
                probe=_VerifiedProbe(),
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            assessments = tuple(pool.map(assess, range(32)))
        self.assertEqual(
            {item.assessment_digest for item in assessments},
            {assessments[0].assessment_digest},
        )
        self.assertEqual(
            {item.blockers for item in assessments},
            {
                (
                    readiness._ReadinessBlocker.PRODUCTION_AUTHORITY_UNAVAILABLE,
                )
            },
        )


class ProductionReadinessStaticContractTest(unittest.TestCase):
    def test_http1_policy_anchor_is_an_independent_digest_literal(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_production_readiness.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        assignments = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "REQUIRED_EXACT_HTTP1_POLICY_DIGEST"
                for target in node.targets
            )
        ]
        self.assertEqual(len(assignments), 1)
        value = assignments[0].value
        self.assertIs(type(value), ast.Call)
        assert isinstance(value, ast.Call)
        self.assertIs(type(value.func), ast.Name)
        assert isinstance(value.func, ast.Name)
        self.assertEqual(value.func.id, "Digest256")
        self.assertEqual(len(value.args), 1)
        self.assertIs(type(value.args[0]), ast.Constant)
        assert isinstance(value.args[0], ast.Constant)
        self.assertEqual(
            value.args[0].value,
            "16a5bc342f274e1d893a26de9417e75ead96b5cd2f06969faf09c6aba8a4d13c",
        )

    def test_runtime_module_has_no_external_probe_or_authority_implementation(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_production_readiness.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertTrue(
            imports.isdisjoint(
                {
                    "ctypes",
                    "os",
                    "pathlib",
                    "selectors",
                    "socket",
                    "ssl",
                    "subprocess",
                }
            )
        )
        forbidden_calls = {
            "connect",
            "getaddrinfo",
            "open",
            "posix_spawn",
            "run",
            "socket",
            "stat",
            "wrap_socket",
        }
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(forbidden_calls.isdisjoint(called_names | called_attributes))
        self.assertEqual(readiness.__all__, ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
