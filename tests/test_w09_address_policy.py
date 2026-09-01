"""Offline W09-B2 RESULT normalization and receipt-only publication tests."""
from __future__ import annotations

import copy
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network
import json
import pickle
import unittest
from unittest.mock import patch
from uuid import UUID, uuid5

from snapquiz.config.profiles import GLM_NETWORK_POLICY_VERSION
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
    NORMALIZED_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
    RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
    RESOLUTION_SET_SCHEMA_VERSION,
    AddressFamily,
    NormalizedResolutionTranscript,
    ResolvedAddress,
    ResolutionSet,
    build_resolution_set,
    match_exact_peer,
    normalize_resolution_transcript,
)
from snapquiz.transport.resolver import (
    READY_FRAME,
    ResolverHelperLauncher,
    ResolverResultReceipt,
    start_frame_digest,
)
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime
import snapquiz.transport.address_policy as address_policy_module
import snapquiz.transport.resolver as resolver_module


SESSION_ISSUED_AT = NOW + timedelta(seconds=5)
EXECUTABLE = "/opt/snapquiz/libexec/resolver-helper"
LIFECYCLE_ID = UUID("72000000-0000-0000-0000-000000000001")
ATTEMPT_ID = UUID("72000000-0000-0000-0000-000000000002")
CLAIM_ID = UUID("72000000-0000-0000-0000-000000000003")
GUARD_ID = UUID("72000000-0000-0000-0000-000000000004")
START_ID = UUID("72000000-0000-0000-0000-000000000005")
ATTEMPT_DIGEST = Digest256("a" * 64)
GUARD_DIGEST = Digest256("b" * 64)
START_DIGEST = Digest256("c" * 64)
_HANDLE_NAMESPACE = UUID("d9343864-e58b-5ff7-aef4-b242641ebbd3")
_CREDENTIAL_CLAIM_NAMESPACE = UUID("ef50b726-448a-5101-a45f-852d4316454d")
_TRANSPORT_CLAIM_NAMESPACE = UUID("96e965e3-57ba-55cb-8a9e-52a2ff69421c")


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


def _transcript(
    *records: dict[str, object],
    overrides: dict[str, object] | None = None,
    remove: tuple[str, ...] = (),
) -> bytes:
    payload: dict[str, object] = {
        "address_policy_digest": str(INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST),
        "address_policy_ref": INTERNET_PUBLIC_ADDRESS_POLICY_REF,
        "attempt_permit_digest": str(ATTEMPT_DIGEST),
        "attempt_permit_id": str(ATTEMPT_ID),
        "candidates": list(records),
        "canonical_hostname": "open.bigmodel.cn",
        "dns_start_id": str(START_ID),
        "kind": "RESULT",
        "network_policy_version": GLM_NETWORK_POLICY_VERSION,
        "port": 443,
        "schema_version": RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
        "start_frame_digest": str(START_DIGEST),
        "status": "ok",
        "terminal_guard_digest": str(GUARD_DIGEST),
        "terminal_guard_id": str(GUARD_ID),
        "transport_claim_id": str(CLAIM_ID),
    }
    if overrides is not None:
        payload.update(overrides)
    for name in remove:
        del payload[name]
    return canonical_json_bytes(payload)


def _make_attempt():
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
    gate = AttemptGate()
    credential = gate.authorize_credential_resolution(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        session=session,
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        authority_ledger=runtime.authority_ledger,
        context=runtime.call_context,
        context_ledger=runtime.context_ledger,
    )
    credential_claim = uuid5(_CREDENTIAL_CLAIM_NAMESPACE, str(credential.permit_id))
    gate._claim_credential_resolution(
        credential,
        claim_id=credential_claim,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )
    handle_id = uuid5(_HANDLE_NAMESPACE, str(credential.permit_id))
    handle_digest = digest256(
        "TestAddressPolicyCredentialHandle",
        "snapquiz.test-address-policy-handle.v1",
        {"handle_id": handle_id, "credential_permit_id": credential.permit_id},
    )
    gate._confirm_credential_resolution(
        credential,
        claim_id=credential_claim,
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
    claim_id = uuid5(_TRANSPORT_CLAIM_NAMESPACE, str(attempt.attempt_permit_id))
    return runtime, gate, attempt, claim_id


def _result_from_start(
    frame: bytes,
    records: tuple[dict[str, object], ...],
    overrides: dict[str, object] | None,
) -> bytes:
    start = json.loads(frame)
    payload: dict[str, object] = {
        "address_policy_digest": start["network_policy_digest"],
        "address_policy_ref": start["network_policy_ref"],
        "attempt_permit_digest": start["attempt_permit_digest"],
        "attempt_permit_id": start["attempt_permit_id"],
        "candidates": list(records),
        "canonical_hostname": start["hostname"],
        "dns_start_id": start["dns_start_id"],
        "kind": "RESULT",
        "network_policy_version": GLM_NETWORK_POLICY_VERSION,
        "port": start["port"],
        "schema_version": RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
        "start_frame_digest": str(start_frame_digest(frame)),
        "status": "ok",
        "terminal_guard_digest": start["terminal_guard_digest"],
        "terminal_guard_id": start["terminal_guard_id"],
        "transport_claim_id": start["transport_claim_id"],
    }
    if overrides is not None:
        payload.update(overrides)
    return canonical_json_bytes(payload)


class _Kernel:
    def __init__(self, records, overrides) -> None:
        self.chunks = [READY_FRAME]
        self.records = records
        self.overrides = overrides
        self.writes: list[bytes] = []
        self.events: list[str] = []

    def read_stdout(self, maximum: int) -> bytes:
        self.events.append("read")
        if not self.chunks:
            return b""
        selected = self.chunks.pop(0)
        if len(selected) <= maximum:
            return selected
        self.chunks.insert(0, selected[maximum:])
        return selected[:maximum]

    def write_stdin(self, frame: bytes) -> None:
        self.events.append("write")
        self.writes.append(frame)
        self.chunks.append(_result_from_start(frame, self.records, self.overrides) + b"\n")

    def terminate(self) -> None:
        self.events.append("terminate")

    def reap(self) -> None:
        self.events.append("reap")

    def close_pipes(self) -> None:
        self.events.append("close_pipes")


class _Spawner:
    def __init__(self, kernel: _Kernel) -> None:
        self.kernel = kernel

    def spawn(self, request):
        del request
        return self.kernel


def _issue(*records, overrides=None, read_result: bool = True):
    runtime, gate, attempt, claim_id = _make_attempt()
    kernel = _Kernel(tuple(records), overrides)
    launcher = ResolverHelperLauncher(_Spawner(kernel), executable=EXECUTABLE)
    pre = launcher.launch_ready(lifecycle_id=LIFECYCLE_ID)
    gate._claim_attempt(
        attempt,
        claim_id=claim_id,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    guard = pre.transfer(
        attempt_permit_id=attempt.attempt_permit_id,
        attempt_permit_digest=attempt.attempt_permit_digest,
        transport_claim_id=claim_id,
    )
    gate._bind_terminal_guard(
        attempt,
        claim_id=claim_id,
        guard_id=guard.terminal_guard_id,
        guard_digest=guard.terminal_guard_digest,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    start_id = uuid5(LIFECYCLE_ID, str(attempt.attempt_permit_id))
    gate._commit_dns_start(
        attempt,
        claim_id=claim_id,
        guard_id=guard.terminal_guard_id,
        guard_digest=guard.terminal_guard_digest,
        start_id=start_id,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    guard.start(
        hostname="open.bigmodel.cn",
        port=443,
        network_policy_ref=INTERNET_PUBLIC_ADDRESS_POLICY_REF,
        network_policy_digest=INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
        dns_start_id=start_id,
    )
    receipt = guard.read_result_receipt() if read_result else None
    return runtime, gate, attempt, claim_id, guard, receipt, kernel


def _close(publication) -> None:
    _, gate, attempt, claim_id, guard, _, _ = publication
    guard.cleanup()
    gate.finish_attempt(
        attempt,
        claim_id=claim_id,
        guard_id=guard.terminal_guard_id,
        guard_digest=guard.terminal_guard_digest,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )


class W09AddressNormalizationTest(unittest.TestCase):
    def normalize(self, *records, overrides=None, remove=()):
        return normalize_resolution_transcript(
            _transcript(*records, overrides=overrides, remove=remove),
            expected_port=443,
        )

    def rejected(self, transcript: bytes) -> None:
        with self.assertRaises(EndpointPolicyError) as raised:
            normalize_resolution_transcript(transcript, expected_port=443)
        self.assertEqual(raised.exception.stage, "address_policy")
        self.assertIsNone(raised.exception.__cause__)

    def test_frozen_versions_and_policy_digest(self):
        self.assertEqual(RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION, "snapquiz.raw-resolution-transcript.v2")
        self.assertEqual(NORMALIZED_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION, "snapquiz.normalized-resolution-transcript.v1")
        self.assertEqual(RESOLUTION_SET_SCHEMA_VERSION, "snapquiz.resolution-set.v2")
        self.assertEqual(INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST, Digest256("721939766c8857b23b1c079b1010e092b223835e490255466c7c47083d0b67a4"))

    def test_pure_normalization_is_factory_only_sorted_and_nonpublishing(self):
        raw = _transcript(
            _record6("2001:4860:4860::8888"),
            _record4("8.8.8.8"),
            _record4("1.1.1.1"),
            _record4("8.8.8.8"),
        )
        normalized = normalize_resolution_transcript(raw, expected_port=443)
        normalized.validate_integrity()
        self.assertEqual(normalized.raw_candidate_count, 4)
        self.assertEqual(tuple(item.canonical_text for item in normalized.candidates), ("1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"))
        self.assertNotIsInstance(normalized, ResolutionSet)
        with self.assertRaises(TypeError):
            NormalizedResolutionTranscript(parsed={}, raw_transcript_digest=Digest256("0" * 64), raw_transcript_byte_size=1, raw_candidate_count=1, candidates=())

    def test_normalized_values_are_immutable_nonserializable_and_tamper_evident(self):
        normalized = self.normalize(_record4("8.8.8.8"))
        with self.assertRaises(TypeError):
            ResolvedAddress(family=AddressFamily.IPV4, packed_hex="08080808", canonical_text="8.8.8.8", port=443)
        with self.assertRaises(AttributeError):
            normalized.port = 444  # type: ignore[misc]
        self.assertIs(copy.deepcopy(normalized), normalized)
        with self.assertRaises(TypeError):
            pickle.dumps(normalized)
        object.__setattr__(normalized, "raw_candidate_count", 2)
        with self.assertRaises(ValueError):
            normalized.validate_integrity()

    def test_raw_limits_strict_canonical_json_and_exact_proof_shape(self):
        records = tuple(_record4("8.8.8.8") for _ in range(32))
        self.assertEqual(self.normalize(*records).raw_candidate_count, 32)
        self.rejected(_transcript())
        self.rejected(_transcript(*(records + (_record4("8.8.4.4"),))))
        valid = _transcript(_record4("8.8.8.8"))
        variants = (
            valid + b"\n",
            json.dumps(json.loads(valid)).encode(),
            b'{"candidates":[],"candidates":[]}',
            b"x" * (MAX_RAW_RESOLUTION_BYTES + 1),
            _transcript(_record4("8.8.8.8"), overrides={"unexpected": True}),
            _transcript(_record4("8.8.8.8"), remove=("dns_start_id",)),
            _transcript(_record4("8.8.8.8"), overrides={"attempt_permit_id": "x"}),
            _transcript(_record4("8.8.8.8"), overrides={"start_frame_digest": "0" * 63}),
            _transcript(_record4("8.8.8.8"), overrides={"port": True}),
        )
        for variant in variants:
            self.rejected(variant)
        self.assertEqual(MAX_RAW_RESOLUTION_CANDIDATES, 32)

    def test_candidate_transport_numeric_and_scope_forms_are_strict(self):
        invalid = (
            {**_record4("8.8.8.8"), "family": "AF_UNIX"},
            {**_record4("8.8.8.8"), "socket_type": "SOCK_DGRAM"},
            {**_record4("8.8.8.8"), "protocol": "IPPROTO_UDP"},
            _record4("8.8.8.8", port=True),
            _record6("2001:4860:4860::8888", flowinfo=1),
            _record6("2001:4860:4860::8888", scope_id=1),
        )
        for record in invalid:
            self.rejected(_transcript(record))
        for value, family in (
            ("008.008.008.008", "v4"),
            ("8.8.8", "v4"),
            ("2001:4860:4860:0:0:0:0:8888", "v6"),
            ("2001:4860:4860::8888%en0", "v6"),
            ("::ffff:192.0.2.1", "v6"),
        ):
            self.rejected(_transcript(_record4(value) if family == "v4" else _record6(value)))

    def test_frozen_ipv4_and_ipv6_ranges_reject_entire_set(self):
        v4 = (
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
            "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
            "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24",
            "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
            "224.0.0.0/4", "240.0.0.0/4",
        )
        for cidr in v4:
            network = IPv4Network(cidr)
            for address in (network.network_address, network.broadcast_address):
                self.rejected(_transcript(_record4("8.8.8.8"), _record4(str(address))))
        for cidr in ("2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20"):
            network = IPv6Network(cidr)
            for address in (network.network_address, network.broadcast_address):
                self.rejected(_transcript(_record6(str(address))))
        self.normalize(_record4("1.1.1.1"), _record6("2001:4860:4860::8888"))


class W09ResolutionPublicationTest(unittest.TestCase):
    def test_gate_only_start_without_result_read_has_no_publication_receipt(self):
        publication = _issue(_record4("8.8.8.8"), read_result=False)
        _, _, attempt, _, guard, receipt, _ = publication
        try:
            self.assertIsNone(receipt)
            self.assertEqual(guard.safe_metadata()["state"], "started")
            self.assertFalse(guard.safe_metadata()["result_receipt_issued"])
            with self.assertRaises(TypeError):
                build_resolution_set(attempt, b"{}")  # type: ignore[arg-type]
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(
                    attempt,
                    object.__new__(ResolverResultReceipt),
                )
        finally:
            _close(publication)

    def test_exact_receipt_publishes_and_resolution_retains_receipt_binding(self):
        publication = _issue(_record4("8.8.8.8"), _record4("1.1.1.1"))
        _, _, attempt, _, _, receipt, kernel = publication
        try:
            resolution = build_resolution_set(attempt, receipt)
            resolution.validate_binding(attempt, receipt)
            self.assertEqual(resolution.receipt_digest, receipt.receipt_digest)
            self.assertEqual(resolution.raw_transcript_digest, receipt.raw_transcript_digest)
            self.assertEqual(tuple(item.canonical_text for item in resolution.candidates), ("1.1.1.1", "8.8.8.8"))
            self.assertEqual(receipt.start_frame_digest, start_frame_digest(kernel.writes[0]))
        finally:
            _close(publication)

    def test_naked_bytes_unissued_and_forged_receipts_cannot_publish(self):
        publication = _issue(_record4("8.8.8.8"))
        _, _, attempt, _, _, receipt, _ = publication
        try:
            with self.assertRaises(TypeError):
                build_resolution_set(attempt, b"{}")  # type: ignore[arg-type]
            forged = object.__new__(ResolverResultReceipt)
            for name in ResolverResultReceipt.__slots__:
                object.__setattr__(forged, name, getattr(receipt, name))
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(attempt, forged)
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(attempt, object.__new__(ResolverResultReceipt))
        finally:
            _close(publication)

    def test_result_echo_start_proof_and_receipt_integrity_tamper_fail_closed(self):
        for override in (
            {"start_frame_digest": "0" * 64},
            {"dns_start_id": str(START_ID)},
            {"transport_claim_id": str(CLAIM_ID)},
            {"attempt_permit_digest": "0" * 64},
            {"canonical_hostname": "example.com"},
            {"port": 444},
        ):
            publication = _issue(_record4("8.8.8.8"), overrides=override)
            _, _, attempt, _, _, receipt, _ = publication
            try:
                with self.assertRaises(EndpointPolicyError):
                    build_resolution_set(attempt, receipt)
            finally:
                _close(publication)
        publication = _issue(_record4("8.8.8.8"))
        _, _, attempt, _, _, receipt, _ = publication
        try:
            object.__setattr__(receipt, "start_frame_digest", Digest256("0" * 64))
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(attempt, receipt)
        finally:
            _close(publication)

    def test_recomputed_receipt_cannot_replace_ledger_owned_transcript_snapshot(self):
        publication = _issue(_record4("8.8.8.8"))
        _, _, attempt, _, _, receipt, kernel = publication
        try:
            altered = _result_from_start(
                kernel.writes[0],
                (_record4("1.1.1.1"),),
                None,
            )
            altered_digest = resolver_module.result_transcript_digest(altered)
            object.__setattr__(receipt, "_raw_transcript", altered)
            object.__setattr__(receipt, "raw_transcript_byte_size", len(altered))
            object.__setattr__(receipt, "raw_transcript_digest", altered_digest)
            recomputed = digest256(
                "ResolverResultReceipt",
                resolver_module.RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION,
                resolver_module._result_receipt_payload(receipt),
            )
            object.__setattr__(receipt, "receipt_digest", recomputed)
            object.__setattr__(receipt, "_issued_digest", recomputed)

            receipt.validate_integrity()
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(attempt, receipt)
        finally:
            _close(publication)

    def test_observer_fault_terminal_receipt_cannot_publish(self):
        publication = _issue(_record4("8.8.8.8"), read_result=False)
        _, _, attempt, _, guard, _, _ = publication

        def fail_after_issue(event, metadata):
            self.assertEqual(event, "result_read")
            self.assertEqual(metadata["state"], "result_read")
            raise RuntimeError("observer after RESULT issue")

        try:
            with self.assertRaisesRegex(RuntimeError, "after RESULT"):
                guard.read_result_receipt(observer=fail_after_issue)
            terminal_receipt = guard._ledger._issued_receipt
            self.assertIs(type(terminal_receipt), ResolverResultReceipt)
            self.assertEqual(guard.safe_metadata()["state"], "terminal")
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(attempt, terminal_receipt)
        finally:
            _close(publication)

    def test_cross_attempt_receipt_replay_and_binding_are_rejected(self):
        first = _issue(_record4("8.8.8.8"))
        second = _issue(_record4("1.1.1.1"))
        _, _, attempt1, _, _, receipt1, _ = first
        _, _, attempt2, _, _, receipt2, _ = second
        try:
            resolution = build_resolution_set(attempt1, receipt1)
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(attempt2, receipt1)
            with self.assertRaises(ValueError):
                resolution.validate_binding(attempt2, receipt2)
        finally:
            _close(first)
            _close(second)

    def test_receipt_allows_exactly_one_resolution_publication(self):
        publication = _issue(_record4("8.8.8.8"))
        _, _, attempt, _, _, receipt, _ = publication
        try:
            first = build_resolution_set(attempt, receipt)
            first.validate_binding(attempt, receipt)
            with self.assertRaises(EndpointPolicyError):
                build_resolution_set(attempt, receipt)
        finally:
            _close(publication)

    def test_recomputed_loopback_candidate_cannot_replace_published_snapshot(self):
        publication = _issue(_record4("8.8.8.8"))
        _, _, attempt, _, _, receipt, _ = publication
        try:
            resolution = build_resolution_set(attempt, receipt)
            candidate = resolution.selected
            object.__setattr__(candidate, "packed_hex", "7f000001")
            object.__setattr__(candidate, "canonical_text", "127.0.0.1")
            recomputed_address = digest256(
                "ResolvedAddress",
                address_policy_module.RESOLVED_ADDRESS_SCHEMA_VERSION,
                address_policy_module._address_payload(candidate),
            )
            object.__setattr__(candidate, "address_digest", recomputed_address)
            object.__setattr__(candidate, "_issued_digest", recomputed_address)
            object.__setattr__(
                resolution,
                "selected_candidate_digest",
                recomputed_address,
            )
            recomputed_resolution = digest256(
                "ResolutionSet",
                RESOLUTION_SET_SCHEMA_VERSION,
                address_policy_module._resolution_payload(resolution),
            )
            object.__setattr__(
                resolution,
                "resolution_digest",
                recomputed_resolution,
            )
            object.__setattr__(
                resolution,
                "_issued_digest",
                recomputed_resolution,
            )

            candidate.validate_integrity()
            resolution._validate_intrinsic_integrity()
            with self.assertRaisesRegex(ValueError, "exactly published"):
                resolution.validate_integrity()
            with self.assertRaisesRegex(ValueError, "exactly published"):
                _ = resolution.selected
            with self.assertRaises(EndpointPolicyError):
                match_exact_peer(
                    resolution,
                    family=AddressFamily.IPV4,
                    sockaddr=("127.0.0.1", 443),
                )
        finally:
            _close(publication)

    def test_resolution_is_immutable_peer_exact_and_publication_zero_real_io(self):
        poison = AssertionError("real I/O forbidden")
        with (
            patch("socket.getaddrinfo", side_effect=poison),
            patch("socket.socket", side_effect=poison),
            patch("socket.create_connection", side_effect=poison),
            patch("os.getenv", side_effect=poison),
            patch("builtins.open", side_effect=poison),
        ):
            publication = _issue(_record4("8.8.8.8"))
            try:
                _, _, attempt, _, _, receipt, _ = publication
                resolution = build_resolution_set(attempt, receipt)
                with self.assertRaises(AttributeError):
                    resolution.port = 444  # type: ignore[misc]
                with self.assertRaises(TypeError):
                    pickle.dumps(resolution)
                self.assertIs(match_exact_peer(resolution, family=AddressFamily.IPV4, sockaddr=("8.8.8.8", 443)), resolution.selected)
                with self.assertRaises(EndpointPolicyError):
                    match_exact_peer(resolution, family=AddressFamily.IPV4, sockaddr=("8.8.4.4", 443))
            finally:
                _close(publication)


if __name__ == "__main__":
    unittest.main()
