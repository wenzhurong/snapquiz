"""Offline W09-B2 address-policy and ResolutionSet contract."""
from __future__ import annotations

import copy
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network
import json
import pickle
import unittest
from unittest.mock import patch
from uuid import UUID, uuid5

from snapquiz.domain.digest import Digest256, canonical_json_bytes, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.privacy.egress import EgressApprovalLedger, EgressGate
from snapquiz.runtime.attempt import (
    AttemptGate,
    _CREDENTIAL_RESOLVER_AUTHORITY,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.transport.address_policy import (
    INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
    INTERNET_PUBLIC_ADDRESS_POLICY_REF,
    MAX_RAW_RESOLUTION_BYTES,
    MAX_RAW_RESOLUTION_CANDIDATES,
    RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
    AddressFamily,
    ResolvedAddress,
    ResolutionSet,
    build_resolution_set,
    match_exact_peer,
)
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime


SESSION_ISSUED_AT = NOW + timedelta(seconds=5)
_TEST_HANDLE_NAMESPACE = UUID("d9343864-e58b-5ff7-aef4-b242641ebbd3")
_TEST_CLAIM_NAMESPACE = UUID("ef50b726-448a-5101-a45f-852d4316454d")


def _record4(address: str, *, port: object = 443) -> dict[str, object]:
    return {
        "address": address,
        "family": "AF_INET",
        "port": port,
        "protocol": "IPPROTO_TCP",
        "socket_type": "SOCK_STREAM",
    }


def _record6(
    address: str,
    *,
    port: object = 443,
    flowinfo: object = 0,
    scope_id: object = 0,
) -> dict[str, object]:
    return {
        "address": address,
        "family": "AF_INET6",
        "flowinfo": flowinfo,
        "port": port,
        "protocol": "IPPROTO_TCP",
        "scope_id": scope_id,
        "socket_type": "SOCK_STREAM",
    }


def _transcript(*records: dict[str, object]) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
            "candidates": list(records),
        }
    )


def _make_runtime():
    runtime = make_w09_runtime()
    approval_ledger = EgressApprovalLedger()
    approval = EgressGate().approve(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval_ledger=approval_ledger,
        preview_controller=FixedPreviewController(),
    )
    runtime.clock.advance(milliseconds=5_000)
    session_ledger = SendSessionLedger()
    session = SendSessionFactory.create(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval=approval,
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        now=SESSION_ISSUED_AT,
    )
    runtime.approval = approval
    runtime.approval_ledger = approval_ledger
    runtime.session = session
    runtime.session_ledger = session_ledger
    return runtime


def _make_attempt():
    runtime = _make_runtime()
    gate = AttemptGate()
    credential = gate.authorize_credential_resolution(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        session=runtime.session,
        approval_ledger=runtime.approval_ledger,
        session_ledger=runtime.session_ledger,
        authority_ledger=runtime.authority_ledger,
        context=runtime.call_context,
        context_ledger=runtime.context_ledger,
    )
    claim_id = uuid5(_TEST_CLAIM_NAMESPACE, str(credential.permit_id))
    gate._claim_credential_resolution(
        credential,
        claim_id=claim_id,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )
    handle_id = uuid5(_TEST_HANDLE_NAMESPACE, str(credential.permit_id))
    handle_digest = digest256(
        "TestAddressPolicyCredentialHandle",
        "snapquiz.test-address-policy-handle.v1",
        {
            "handle_id": handle_id,
            "credential_permit_id": credential.permit_id,
            "credential_permit_digest": credential.permit_digest,
        },
    )
    gate._confirm_credential_resolution(
        credential,
        claim_id=claim_id,
        resolved_binding_digest=credential.credential_binding_digest,
        handle_id=handle_id,
        handle_digest=handle_digest,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )
    attempt = gate.reserve_attempt(
        credential_permit=credential,
        credential_handle_id=handle_id,
        credential_handle_digest=handle_digest,
    )
    return runtime, gate, attempt


class W09AddressPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime, self.gate, self.attempt = _make_attempt()
        self.io_patches = (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS access")),
            patch("socket.socket", side_effect=AssertionError("socket access")),
            patch(
                "socket.create_connection",
                side_effect=AssertionError("connect access"),
            ),
            patch("os.getenv", side_effect=AssertionError("environment access")),
            patch("builtins.open", side_effect=AssertionError("file access")),
        )
        for selected in self.io_patches:
            selected.start()

    def tearDown(self) -> None:
        for selected in reversed(self.io_patches):
            selected.stop()
        self.gate.abandon_attempt(
            self.attempt,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )

    def assert_rejected(self, transcript: bytes) -> None:
        with self.assertRaises(EndpointPolicyError) as raised:
            build_resolution_set(self.attempt, transcript)
        self.assertEqual(raised.exception.stage, "address_policy")
        self.assertFalse(raised.exception.retryable)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_policy_digest_is_frozen_and_content_addressed(self):
        self.assertEqual(
            INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            "snapquiz.internet-public-address-policy.iana-2025-10-09.v1",
        )
        self.assertEqual(
            INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
            Digest256(
                "721939766c8857b23b1c079b1010e092"
                "b223835e490255466c7c47083d0b67a4"
            ),
        )

    def test_resolution_binds_attempt_and_normalizes_deduplicates_and_sorts(self):
        raw = _transcript(
            _record6("2001:4860:4860::8888"),
            _record4("8.8.8.8"),
            _record4("1.1.1.1"),
            _record4("8.8.8.8"),
        )
        resolution = build_resolution_set(self.attempt, raw)

        resolution.validate_integrity()
        resolution.validate_binding(self.attempt)
        self.assertEqual(resolution.canonical_hostname, "open.bigmodel.cn")
        self.assertEqual(resolution.port, 443)
        self.assertEqual(resolution.raw_candidate_count, 4)
        self.assertEqual(resolution.raw_transcript_byte_size, len(raw))
        self.assertEqual(
            tuple(item.canonical_text for item in resolution.candidates),
            ("1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"),
        )
        self.assertEqual(resolution.selected.canonical_text, "1.1.1.1")
        self.assertEqual(
            resolution.selected_candidate_digest,
            resolution.selected.address_digest,
        )
        self.assertEqual(resolution.attempt_permit_id, self.attempt.attempt_permit_id)
        self.assertEqual(
            resolution.attempt_permit_digest,
            self.attempt.attempt_permit_digest,
        )
        rendered = repr(resolution) + repr(resolution.safe_metadata())
        self.assertNotIn("1.1.1.1", rendered)
        self.assertNotIn("8.8.8.8", rendered)

    def test_raw_candidate_limit_is_applied_before_deduplication(self):
        records = tuple(_record4("8.8.8.8") for _ in range(32))
        resolution = build_resolution_set(self.attempt, _transcript(*records))
        self.assertEqual(resolution.raw_candidate_count, 32)
        self.assertEqual(len(resolution.candidates), 1)

        self.assert_rejected(_transcript())
        self.assert_rejected(_transcript(*(records + (_record4("8.8.4.4"),))))
        self.assertEqual(MAX_RAW_RESOLUTION_CANDIDATES, 32)

    def test_raw_transcript_is_bounded_strict_canonical_json(self):
        valid = _transcript(_record4("8.8.8.8"))
        build_resolution_set(self.attempt, valid)
        variants = (
            b"\xef\xbb\xbf" + valid,
            valid + b"\n",
            json.dumps(
                {
                    "schema_version": RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
                    "candidates": [_record4("8.8.8.8")],
                }
            ).encode("utf-8"),
            b'{"candidates":[],"candidates":[],"schema_version":"x"}',
            b"{" + b"x" * (MAX_RAW_RESOLUTION_BYTES - 1),
            b"x" * (MAX_RAW_RESOLUTION_BYTES + 1),
        )
        for variant in variants:
            with self.subTest(size=len(variant), prefix=variant[:12]):
                self.assert_rejected(variant)
        self.assertEqual(MAX_RAW_RESOLUTION_BYTES, 16 * 1024)

    def test_candidate_transport_metadata_and_keys_are_exact(self):
        invalid: list[dict[str, object]] = []
        for name, value in (
            ("family", "AF_UNIX"),
            ("socket_type", "SOCK_DGRAM"),
            ("protocol", "IPPROTO_UDP"),
            ("port", 444),
            ("port", True),
        ):
            record = _record4("8.8.8.8")
            record[name] = value
            invalid.append(record)
        with_extra = _record4("8.8.8.8")
        with_extra["canonname"] = "open.bigmodel.cn"
        invalid.append(with_extra)
        without_protocol = _record4("8.8.8.8")
        del without_protocol["protocol"]
        invalid.append(without_protocol)
        invalid.extend(
            (
                _record6("2001:4860:4860::8888", flowinfo=1),
                _record6("2001:4860:4860::8888", scope_id=1),
                _record6("2001:4860:4860::8888", flowinfo=True),
                _record6("2001:4860:4860::8888", scope_id=True),
            )
        )
        for record in invalid:
            with self.subTest(record=record):
                self.assert_rejected(_transcript(record))

    def test_noncanonical_numeric_forms_mapped_and_zones_are_rejected(self):
        invalid_v4 = (
            "008.008.008.008",
            "8.8.8",
            "0x08080808",
            "8.8.8.8 ",
            "+8.8.8.8",
        )
        invalid_v6 = (
            "2001:4860:4860:0:0:0:0:8888",
            "2001:4860:4860::08888",
            "2001:4860:4860::ABCD",
            "2001:4860:4860::8888%en0",
            "[2001:4860:4860::8888]",
            "::ffff:c000:201",
            "::ffff:192.0.2.1",
        )
        for address in invalid_v4:
            with self.subTest(family="ipv4", address=address):
                self.assert_rejected(_transcript(_record4(address)))
        for address in invalid_v6:
            with self.subTest(family="ipv6", address=address):
                self.assert_rejected(_transcript(_record6(address)))

    def test_every_frozen_ipv4_reject_range_rejects_first_and_last(self):
        cidrs = (
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.31.196.0/24",
            "192.52.193.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "192.175.48.0/24",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        )
        for cidr in cidrs:
            network = IPv4Network(cidr)
            for address in (network.network_address, network.broadcast_address):
                with self.subTest(cidr=cidr, address=str(address)):
                    self.assert_rejected(
                        _transcript(_record4(str(address)))
                    )
        for address in ("1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0"):
            with self.subTest(allowed=address):
                build_resolution_set(self.attempt, _transcript(_record4(address)))

    def test_ipv6_base_and_frozen_exclusions_are_exact(self):
        for cidr in (
            "2001::/23",
            "2001:db8::/32",
            "2002::/16",
            "2620:4f:8000::/48",
            "3fff::/20",
        ):
            network = IPv6Network(cidr)
            for address in (network.network_address, network.broadcast_address):
                with self.subTest(cidr=cidr, address=str(address)):
                    self.assert_rejected(
                        _transcript(_record6(str(address)))
                    )
        for address in (
            "2000::",
            "2001:200::",
            "2001:db9::",
            "2003::",
            "2fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff:1000::",
        ):
            with self.subTest(allowed=address):
                build_resolution_set(self.attempt, _transcript(_record6(address)))
        for address in ("::", "::1", "fc00::1", "fe80::1", "ff00::1", "4000::"):
            with self.subTest(outside_base=address):
                self.assert_rejected(_transcript(_record6(address)))

    def test_mixed_allowed_and_forbidden_results_reject_the_entire_set(self):
        allowed = _record4("8.8.8.8")
        forbidden = _record4("127.0.0.1")
        for records in (
            (forbidden, allowed, allowed),
            (allowed, forbidden, allowed),
            (allowed, allowed, forbidden),
        ):
            with self.subTest(position=records.index(forbidden)):
                self.assert_rejected(_transcript(*records))

    def test_transcript_proof_changes_but_normalized_set_is_stable(self):
        first = build_resolution_set(
            self.attempt,
            _transcript(_record4("8.8.8.8"), _record4("1.1.1.1")),
        )
        second = build_resolution_set(
            self.attempt,
            _transcript(_record4("1.1.1.1"), _record4("8.8.8.8")),
        )
        self.assertEqual(
            tuple(item.address_digest for item in first.candidates),
            tuple(item.address_digest for item in second.candidates),
        )
        self.assertNotEqual(first.raw_transcript_digest, second.raw_transcript_digest)
        self.assertNotEqual(first.resolution_id, second.resolution_id)
        self.assertNotEqual(first.resolution_digest, second.resolution_digest)

    def test_factory_only_final_immutable_nonserializable_and_tamper_evident(self):
        resolution = build_resolution_set(
            self.attempt, _transcript(_record4("8.8.8.8"))
        )
        candidate = resolution.selected
        with self.assertRaises(TypeError):
            ResolvedAddress(
                family=AddressFamily.IPV4,
                packed_hex="08080808",
                canonical_text="8.8.8.8",
                port=443,
            )
        with self.assertRaises(TypeError):
            class InvalidResolvedAddress(ResolvedAddress):
                pass
        with self.assertRaises(TypeError):
            class InvalidResolutionSet(ResolutionSet):
                pass
        with self.assertRaises(AttributeError):
            resolution.port = 444  # type: ignore[misc]
        self.assertIs(copy.copy(candidate), candidate)
        self.assertIs(copy.deepcopy(resolution), resolution)
        with self.assertRaises(TypeError):
            pickle.dumps(candidate)
        with self.assertRaises(TypeError):
            pickle.dumps(resolution)

        object.__setattr__(resolution, "raw_candidate_count", 2)
        with self.assertRaises(ValueError):
            resolution.validate_integrity()

    def test_binding_rejects_another_attempt(self):
        resolution = build_resolution_set(
            self.attempt, _transcript(_record4("8.8.8.8"))
        )
        other_runtime, other_gate, other_attempt = _make_attempt()
        del other_runtime
        try:
            with self.assertRaises(ValueError):
                resolution.validate_binding(other_attempt)
        finally:
            other_gate.abandon_attempt(
                other_attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

    def test_peer_match_normalizes_os_text_and_requires_exact_selected_tuple(self):
        ipv4 = build_resolution_set(
            self.attempt, _transcript(_record4("8.8.8.8"))
        )
        self.assertIs(
            match_exact_peer(
                ipv4,
                family=AddressFamily.IPV4,
                sockaddr=("8.8.8.8", 443),
            ),
            ipv4.selected,
        )

        ipv6 = build_resolution_set(
            self.attempt,
            _transcript(_record6("2001:4860:4860::8888")),
        )
        self.assertIs(
            match_exact_peer(
                ipv6,
                family=AddressFamily.IPV6,
                sockaddr=("2001:4860:4860:0:0:0:0:8888", 443, 0, 0),
            ),
            ipv6.selected,
        )

        bad_peers = (
            (ipv4, AddressFamily.IPV4, ("8.8.4.4", 443)),
            (ipv4, AddressFamily.IPV4, ("8.8.8.8", 444)),
            (ipv4, AddressFamily.IPV4, ("8.8.8.8", True)),
            (ipv4, AddressFamily.IPV6, ("2001:4860:4860::8888", 443, 0, 0)),
            (ipv6, AddressFamily.IPV6, ("2001:4860:4860::8888", 443, 1, 0)),
            (ipv6, AddressFamily.IPV6, ("2001:4860:4860::8888", 443, 0, 1)),
            (ipv6, AddressFamily.IPV6, ("2001:4860:4860::8888%en0", 443, 0, 0)),
            (ipv6, AddressFamily.IPV6, ("::ffff:8.8.8.8", 443, 0, 0)),
        )
        for resolution, family, sockaddr in bad_peers:
            with self.subTest(family=family, sockaddr=sockaddr):
                with self.assertRaises(EndpointPolicyError) as raised:
                    match_exact_peer(
                        resolution,
                        family=family,
                        sockaddr=sockaddr,
                    )
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)


if __name__ == "__main__":
    unittest.main()
