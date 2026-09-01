"""Pure W09-B2 address-policy and resolution-set contracts.

The module deliberately contains no resolver, process, DNS, or socket code.
It accepts one bounded, canonical transcript produced by the future isolated
resolver helper, validates every raw candidate, and binds the normalized set
to one exact :class:`~snapquiz.runtime.attempt.AttemptPermit`.
"""
from __future__ import annotations

from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import json
import re
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from snapquiz.config.profiles import (
    GLM_CHAT_COMPLETIONS_ENDPOINT,
    GLM_NETWORK_POLICY_VERSION,
)
from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import (
    Digest256,
    canonical_json_bytes,
    digest256,
)
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.domain.plan import NetworkScope
from snapquiz.runtime.attempt import (
    AttemptPermit,
    CredentialResolutionPermit,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.transport.credentials import _frozen_glm_binding
from snapquiz.transport.resolver import (
    ResolverResultReceipt,
    encode_start_frame,
    result_transcript_digest,
    start_frame_digest,
)


INTERNET_PUBLIC_ADDRESS_POLICY_SCHEMA_VERSION = (
    "snapquiz.internet-public-address-policy.v1"
)
INTERNET_PUBLIC_ADDRESS_POLICY_REF = (
    "snapquiz.internet-public-address-policy.iana-2025-10-09.v1"
)
RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION = (
    "snapquiz.raw-resolution-transcript.v2"
)
RESOLVED_ADDRESS_SCHEMA_VERSION = "snapquiz.resolved-address.v1"
NORMALIZED_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION = (
    "snapquiz.normalized-resolution-transcript.v1"
)
RESOLUTION_SET_SCHEMA_VERSION = "snapquiz.resolution-set.v2"

MAX_RAW_RESOLUTION_BYTES = 16 * 1024
MAX_RAW_RESOLUTION_CANDIDATES = 32

_RESOLUTION_UUID_NAMESPACE = UUID("5f7eb2d6-f155-55dc-a6bb-59e573788524")
_ADDRESS_FACTORY_AUTHORITY = object()
_NORMALIZED_TRANSCRIPT_FACTORY_AUTHORITY = object()
_RESOLUTION_FACTORY_AUTHORITY = object()
_LOWER_HEX_RE = re.compile(r"^[0-9a-f]+$")
_CANONICAL_DNS_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)

_IPV4_REJECT_CIDRS = (
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
_IPV6_ACCEPT_CIDRS = ("2000::/3",)
_IPV6_REJECT_CIDRS = (
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "2620:4f:8000::/48",
    "3fff::/20",
)

_IPV4_REJECT_NETWORKS = tuple(
    IPv4Network(value, strict=True) for value in _IPV4_REJECT_CIDRS
)
_IPV6_ACCEPT_NETWORKS = tuple(
    IPv6Network(value, strict=True) for value in _IPV6_ACCEPT_CIDRS
)
_IPV6_REJECT_NETWORKS = tuple(
    IPv6Network(value, strict=True) for value in _IPV6_REJECT_CIDRS
)


def _address_policy_payload() -> dict[str, object]:
    return {
        "policy_ref": INTERNET_PUBLIC_ADDRESS_POLICY_REF,
        "scope": NetworkScope.INTERNET.value,
        "family_order": ("ipv4", "ipv6"),
        "ipv4_reject_cidrs": _IPV4_REJECT_CIDRS,
        "ipv6_accept_cidrs": _IPV6_ACCEPT_CIDRS,
        "ipv6_reject_cidrs": _IPV6_REJECT_CIDRS,
        "reject_ipv4_mapped_ipv6": True,
        "reject_zone_identifiers": True,
        "require_canonical_raw_numeric_text": True,
        "required_socket_type": "SOCK_STREAM",
        "required_protocol": "IPPROTO_TCP",
        "require_exact_planned_port": True,
        "require_zero_ipv6_flowinfo_and_scope_id": True,
        "raw_candidate_limit": MAX_RAW_RESOLUTION_CANDIDATES,
        "raw_transcript_byte_limit": MAX_RAW_RESOLUTION_BYTES,
        "candidate_failure_mode": "reject-entire-set",
        "deduplication_key": "family-packed-port",
        "sort_key": "ipv4-before-ipv6-packed-port",
        "selection": "first-only",
        "peer_binding": "family-packed-port-exact",
    }


INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST = digest256(
    "InternetPublicAddressPolicy",
    INTERNET_PUBLIC_ADDRESS_POLICY_SCHEMA_VERSION,
    _address_policy_payload(),
)


class AddressFamily(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


def _address_error() -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="address_policy",
        retryable=False,
        safe_message="解析结果未通过地址安全策略。",
    )


def _raise_address_error() -> None:
    error = _address_error()
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _address_payload(address: "ResolvedAddress") -> dict[str, object]:
    return {
        "family": address.family.value,
        "packed_hex": address.packed_hex,
        "canonical_text": address.canonical_text,
        "port": address.port,
    }


@runtime_final
class ResolvedAddress:
    """Factory-only normalized TCP address; platform AF integers stay out."""

    __slots__ = (
        "family",
        "packed_hex",
        "canonical_text",
        "port",
        "address_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        family: AddressFamily,
        packed_hex: str,
        canonical_text: str,
        port: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ADDRESS_FACTORY_AUTHORITY:
            raise TypeError("resolved addresses require the address-policy factory")
        if type(family) is not AddressFamily:
            raise TypeError("family must be AddressFamily")
        if type(packed_hex) is not str or _LOWER_HEX_RE.fullmatch(packed_hex) is None:
            raise ValueError("packed_hex must be lowercase hexadecimal")
        expected_hex_length = 8 if family is AddressFamily.IPV4 else 32
        if len(packed_hex) != expected_hex_length:
            raise ValueError("packed_hex length does not match family")
        require_text(canonical_text, "canonical_text", max_length=39)
        require_plain_int(port, "port", minimum=1)
        if port > 65_535:
            raise ValueError("port exceeds TCP range")
        parsed = (
            IPv4Address(bytes.fromhex(packed_hex))
            if family is AddressFamily.IPV4
            else IPv6Address(bytes.fromhex(packed_hex))
        )
        if canonical_text != str(parsed):
            raise ValueError("canonical text does not match packed address")
        for name, value in (
            ("family", family),
            ("packed_hex", packed_hex),
            ("canonical_text", canonical_text),
            ("port", port),
        ):
            object.__setattr__(self, name, value)
        address_digest = digest256(
            "ResolvedAddress",
            RESOLVED_ADDRESS_SCHEMA_VERSION,
            _address_payload(self),
        )
        object.__setattr__(self, "address_digest", address_digest)
        object.__setattr__(self, "_issued_digest", address_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolvedAddress is immutable")

    def __copy__(self) -> "ResolvedAddress":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "ResolvedAddress":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("ResolvedAddress cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("ResolvedAddress cannot be serialized")

    def __repr__(self) -> str:
        return (
            "ResolvedAddress("
            f"family={self.family.value!r}, canonical_text={self.canonical_text!r}, "
            f"port={self.port!r})"
        )

    @property
    def packed(self) -> bytes:
        return bytes.fromhex(self.packed_hex)

    @property
    def numeric_sockaddr(self) -> tuple[object, ...]:
        if self.family is AddressFamily.IPV4:
            return (self.canonical_text, self.port)
        return (self.canonical_text, self.port, 0, 0)

    def validate_integrity(self) -> None:
        if type(self.family) is not AddressFamily:
            raise ValueError("resolved address family changed")
        if (
            type(self.packed_hex) is not str
            or _LOWER_HEX_RE.fullmatch(self.packed_hex) is None
        ):
            raise ValueError("resolved address packed value changed")
        expected_hex_length = 8 if self.family is AddressFamily.IPV4 else 32
        if len(self.packed_hex) != expected_hex_length:
            raise ValueError("resolved address packed length changed")
        require_plain_int(self.port, "port", minimum=1)
        if self.port > 65_535:
            raise ValueError("resolved address port changed")
        try:
            parsed = (
                IPv4Address(bytes.fromhex(self.packed_hex))
                if self.family is AddressFamily.IPV4
                else IPv6Address(bytes.fromhex(self.packed_hex))
            )
        except ValueError as error:
            raise ValueError("resolved address packed value changed") from error
        if self.canonical_text != str(parsed):
            raise ValueError("resolved address text changed")
        require_digest(self.address_digest, "address_digest")
        require_digest(self._issued_digest, "_issued_digest")
        recomputed = digest256(
            "ResolvedAddress",
            RESOLVED_ADDRESS_SCHEMA_VERSION,
            _address_payload(self),
        )
        if recomputed != self.address_digest or recomputed != self._issued_digest:
            raise ValueError("resolved address integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "family": self.family.value,
            "port": self.port,
            "address_digest_prefix": str(self.address_digest)[:12],
        }


def _resolution_payload(resolution: "ResolutionSet") -> dict[str, object]:
    return {
        "resolution_id": resolution.resolution_id,
        "attempt_permit_id": resolution.attempt_permit_id,
        "attempt_permit_digest": resolution.attempt_permit_digest,
        "transport_claim_id": resolution.transport_claim_id,
        "terminal_guard_id": resolution.terminal_guard_id,
        "terminal_guard_digest": resolution.terminal_guard_digest,
        "dns_start_id": resolution.dns_start_id,
        "context_id": resolution.context_id,
        "context_digest": resolution.context_digest,
        "session_id": resolution.session_id,
        "session_terms_digest": resolution.session_terms_digest,
        "operation_id": resolution.operation_id,
        "request_envelope_digest": resolution.request_envelope_digest,
        "canonical_hostname": resolution.canonical_hostname,
        "port": resolution.port,
        "network_scope": resolution.network_scope.value,
        "network_policy_version": resolution.network_policy_version,
        "address_policy_ref": resolution.address_policy_ref,
        "address_policy_digest": resolution.address_policy_digest,
        "receipt_digest": resolution.receipt_digest,
        "raw_transcript_digest": resolution.raw_transcript_digest,
        "raw_transcript_byte_size": resolution.raw_transcript_byte_size,
        "raw_candidate_count": resolution.raw_candidate_count,
        "candidates": tuple(_address_payload(item) for item in resolution.candidates),
        "selected_candidate_digest": resolution.selected_candidate_digest,
    }


def _resolution_canonical_payload(resolution: "ResolutionSet") -> bytes:
    return canonical_json_bytes(_resolution_payload(resolution))


def _resolution_candidate_publication_snapshots(
    resolution: "ResolutionSet",
) -> tuple[tuple[object, Digest256, bytes], ...]:
    return tuple(
        (
            candidate,
            candidate.address_digest,
            canonical_json_bytes(_address_payload(candidate)),
        )
        for candidate in resolution.candidates
    )


def _resolution_identifier(
    *,
    attempt_permit_id: UUID,
    attempt_permit_digest: Digest256,
    transport_claim_id: UUID,
    terminal_guard_id: UUID,
    terminal_guard_digest: Digest256,
    dns_start_id: UUID,
    receipt_digest: Digest256,
    raw_transcript_digest: Digest256,
) -> UUID:
    seed = digest256(
        "ResolutionSetIdentifier",
        RESOLUTION_SET_SCHEMA_VERSION,
        {
            "attempt_permit_id": attempt_permit_id,
            "attempt_permit_digest": attempt_permit_digest,
            "transport_claim_id": transport_claim_id,
            "terminal_guard_id": terminal_guard_id,
            "terminal_guard_digest": terminal_guard_digest,
            "dns_start_id": dns_start_id,
            "receipt_digest": receipt_digest,
            "raw_transcript_digest": raw_transcript_digest,
            "address_policy_ref": INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            "address_policy_digest": INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
        },
    )
    return uuid5(_RESOLUTION_UUID_NAMESPACE, str(seed))


@runtime_final
class ResolutionSet:
    """Factory-only, all-result-normalized address set for one attempt."""

    __slots__ = (
        "resolution_id",
        "attempt_permit_id",
        "attempt_permit_digest",
        "transport_claim_id",
        "terminal_guard_id",
        "terminal_guard_digest",
        "dns_start_id",
        "context_id",
        "context_digest",
        "session_id",
        "session_terms_digest",
        "operation_id",
        "request_envelope_digest",
        "canonical_hostname",
        "port",
        "network_scope",
        "network_policy_version",
        "address_policy_ref",
        "address_policy_digest",
        "receipt_digest",
        "raw_transcript_digest",
        "raw_transcript_byte_size",
        "raw_candidate_count",
        "candidates",
        "selected_candidate_digest",
        "resolution_digest",
        "_issued_digest",
        "_result_receipt",
    )

    def __init__(
        self,
        *,
        attempt_permit: AttemptPermit,
        transport_claim_id: UUID,
        terminal_guard_id: UUID,
        terminal_guard_digest: Digest256,
        dns_start_id: UUID,
        result_receipt: ResolverResultReceipt,
        canonical_hostname: str,
        port: int,
        network_policy_version: str,
        raw_transcript_digest: Digest256,
        raw_transcript_byte_size: int,
        raw_candidate_count: int,
        candidates: tuple[ResolvedAddress, ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RESOLUTION_FACTORY_AUTHORITY:
            raise TypeError("resolution sets require the address-policy factory")
        if type(result_receipt) is not ResolverResultReceipt:
            raise TypeError("result_receipt must be ResolverResultReceipt")
        resolution_id = _resolution_identifier(
            attempt_permit_id=attempt_permit.attempt_permit_id,
            attempt_permit_digest=attempt_permit.attempt_permit_digest,
            transport_claim_id=transport_claim_id,
            terminal_guard_id=terminal_guard_id,
            terminal_guard_digest=terminal_guard_digest,
            dns_start_id=dns_start_id,
            receipt_digest=result_receipt.receipt_digest,
            raw_transcript_digest=raw_transcript_digest,
        )
        values = (
            ("resolution_id", resolution_id),
            ("attempt_permit_id", attempt_permit.attempt_permit_id),
            ("attempt_permit_digest", attempt_permit.attempt_permit_digest),
            ("transport_claim_id", transport_claim_id),
            ("terminal_guard_id", terminal_guard_id),
            ("terminal_guard_digest", terminal_guard_digest),
            ("dns_start_id", dns_start_id),
            ("context_id", attempt_permit.context_id),
            ("context_digest", attempt_permit.context_digest),
            ("session_id", attempt_permit.session_id),
            ("session_terms_digest", attempt_permit.session_terms_digest),
            ("operation_id", attempt_permit.operation_id),
            (
                "request_envelope_digest",
                attempt_permit.request_envelope_digest,
            ),
            ("canonical_hostname", canonical_hostname),
            ("port", port),
            ("network_scope", NetworkScope.INTERNET),
            ("network_policy_version", network_policy_version),
            ("address_policy_ref", INTERNET_PUBLIC_ADDRESS_POLICY_REF),
            ("address_policy_digest", INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST),
            ("receipt_digest", result_receipt.receipt_digest),
            ("raw_transcript_digest", raw_transcript_digest),
            ("raw_transcript_byte_size", raw_transcript_byte_size),
            ("raw_candidate_count", raw_candidate_count),
            ("candidates", candidates),
            ("selected_candidate_digest", candidates[0].address_digest),
            ("_result_receipt", result_receipt),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        resolution_digest = digest256(
            "ResolutionSet",
            RESOLUTION_SET_SCHEMA_VERSION,
            _resolution_payload(self),
        )
        object.__setattr__(self, "resolution_digest", resolution_digest)
        object.__setattr__(self, "_issued_digest", resolution_digest)
        self._validate_intrinsic_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolutionSet is immutable")

    def __copy__(self) -> "ResolutionSet":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "ResolutionSet":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("ResolutionSet cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("ResolutionSet cannot be serialized")

    def __repr__(self) -> str:
        return (
            "ResolutionSet("
            f"resolution_id={self.resolution_id!r}, "
            f"attempt_permit_id={self.attempt_permit_id!r}, "
            f"candidate_count={len(self.candidates)!r})"
        )

    @property
    def selected(self) -> ResolvedAddress:
        self.validate_integrity()
        return self.candidates[0]

    def validate_integrity(self) -> None:
        self._validate_intrinsic_integrity()
        self._result_receipt._validate_resolution_publication(
            self,
            resolution_digest=self.resolution_digest,
            canonical_payload=_resolution_canonical_payload(self),
            candidates=_resolution_candidate_publication_snapshots(self),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )

    def _validate_intrinsic_integrity(self) -> None:
        for name in (
            "resolution_id",
            "attempt_permit_id",
            "transport_claim_id",
            "terminal_guard_id",
            "dns_start_id",
            "context_id",
            "session_id",
            "operation_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "attempt_permit_digest",
            "terminal_guard_digest",
            "context_digest",
            "session_terms_digest",
            "request_envelope_digest",
            "address_policy_digest",
            "receipt_digest",
            "raw_transcript_digest",
            "selected_candidate_digest",
            "resolution_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        require_text(self.canonical_hostname, "canonical_hostname", max_length=253)
        require_plain_int(self.port, "port", minimum=1)
        if self.port > 65_535:
            raise ValueError("resolution port changed")
        if self.network_scope is not NetworkScope.INTERNET:
            raise ValueError("resolution network scope changed")
        if self.network_policy_version != GLM_NETWORK_POLICY_VERSION:
            raise ValueError("resolution network policy changed")
        if (
            self.address_policy_ref != INTERNET_PUBLIC_ADDRESS_POLICY_REF
            or self.address_policy_digest
            != INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST
        ):
            raise ValueError("resolution address policy changed")
        if (
            type(self._result_receipt) is not ResolverResultReceipt
            or self.receipt_digest != self._result_receipt.receipt_digest
        ):
            raise ValueError("resolution receipt binding changed")
        require_plain_int(
            self.raw_transcript_byte_size,
            "raw_transcript_byte_size",
            minimum=1,
        )
        if self.raw_transcript_byte_size > MAX_RAW_RESOLUTION_BYTES:
            raise ValueError("resolution transcript size changed")
        require_plain_int(
            self.raw_candidate_count,
            "raw_candidate_count",
            minimum=1,
        )
        if self.raw_candidate_count > MAX_RAW_RESOLUTION_CANDIDATES:
            raise ValueError("resolution raw candidate count changed")
        if (
            type(self.candidates) is not tuple
            or not self.candidates
            or not all(type(item) is ResolvedAddress for item in self.candidates)
        ):
            raise ValueError("resolution candidates changed")
        if len(self.candidates) > self.raw_candidate_count:
            raise ValueError("resolution contains more normalized than raw candidates")
        for candidate in self.candidates:
            candidate.validate_integrity()
            if candidate.port != self.port:
                raise ValueError("resolution candidate port changed")
        keys = tuple(_candidate_sort_key(item) for item in self.candidates)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("resolution candidates are not canonical")
        if self.selected_candidate_digest != self.candidates[0].address_digest:
            raise ValueError("resolution selection changed")
        expected_id = _resolution_identifier(
            attempt_permit_id=self.attempt_permit_id,
            attempt_permit_digest=self.attempt_permit_digest,
            transport_claim_id=self.transport_claim_id,
            terminal_guard_id=self.terminal_guard_id,
            terminal_guard_digest=self.terminal_guard_digest,
            dns_start_id=self.dns_start_id,
            receipt_digest=self.receipt_digest,
            raw_transcript_digest=self.raw_transcript_digest,
        )
        if self.resolution_id != expected_id:
            raise ValueError("resolution identifier changed")
        recomputed = digest256(
            "ResolutionSet",
            RESOLUTION_SET_SCHEMA_VERSION,
            _resolution_payload(self),
        )
        if recomputed != self.resolution_digest or recomputed != self._issued_digest:
            raise ValueError("resolution set integrity mismatch")

    def validate_binding(
        self,
        attempt_permit: AttemptPermit,
        result_receipt: ResolverResultReceipt,
    ) -> None:
        if type(result_receipt) is not ResolverResultReceipt:
            raise TypeError("result_receipt must be ResolverResultReceipt")
        result_receipt._validate_exact_issuance(
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        hostname, port, network_policy_version = _frozen_attempt_network_binding(
            attempt_permit
        )
        exact = (
            self._result_receipt is result_receipt,
            self.attempt_permit_id == attempt_permit.attempt_permit_id,
            self.attempt_permit_digest == attempt_permit.attempt_permit_digest,
            self.attempt_permit_id == result_receipt.attempt_permit_id,
            self.attempt_permit_digest == result_receipt.attempt_permit_digest,
            self.transport_claim_id == result_receipt.transport_claim_id,
            self.terminal_guard_id == result_receipt.terminal_guard_id,
            self.terminal_guard_digest == result_receipt.terminal_guard_digest,
            self.dns_start_id == result_receipt.dns_start_id,
            self.receipt_digest == result_receipt.receipt_digest,
            self.raw_transcript_digest == result_receipt.raw_transcript_digest,
            self.raw_transcript_byte_size
            == result_receipt.raw_transcript_byte_size,
            self.context_id == attempt_permit.context_id,
            self.context_digest == attempt_permit.context_digest,
            self.session_id == attempt_permit.session_id,
            self.session_terms_digest == attempt_permit.session_terms_digest,
            self.operation_id == attempt_permit.operation_id,
            self.request_envelope_digest
            == attempt_permit.request_envelope_digest,
            self.canonical_hostname == hostname,
            self.port == port,
            self.network_policy_version == network_policy_version,
        )
        self.validate_integrity()
        if not all(exact) or not attempt_permit._attempt_gate._dns_start_is_committed(
            attempt_permit,
            claim_id=result_receipt.transport_claim_id,
            guard_id=result_receipt.terminal_guard_id,
            guard_digest=result_receipt.terminal_guard_digest,
            start_id=result_receipt.dns_start_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise ValueError("resolution set is bound to another attempt")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "resolution_id": str(self.resolution_id),
            "attempt_permit_id": str(self.attempt_permit_id),
            "transport_claim_id": str(self.transport_claim_id),
            "terminal_guard_id": str(self.terminal_guard_id),
            "terminal_guard_digest_prefix": str(self.terminal_guard_digest)[:12],
            "dns_start_id": str(self.dns_start_id),
            "receipt_digest_prefix": str(self.receipt_digest)[:12],
            "candidate_count": len(self.candidates),
            "raw_candidate_count": self.raw_candidate_count,
            "address_policy_ref": self.address_policy_ref,
            "resolution_digest_prefix": str(self.resolution_digest)[:12],
        }


class _TranscriptRejected(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _TranscriptRejected("duplicate object key")
        result[key] = value
    return result


def _reject_json_number(value: str) -> object:
    del value
    raise _TranscriptRejected("unsupported JSON number")


def _parse_transcript(
    transcript: bytes,
) -> tuple[dict[str, object], tuple[dict[str, object], ...], Digest256]:
    if type(transcript) is not bytes:
        raise _TranscriptRejected("transcript must be immutable bytes")
    if not transcript or len(transcript) > MAX_RAW_RESOLUTION_BYTES:
        raise _TranscriptRejected("transcript byte limit")
    try:
        text = transcript.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
        if canonical_json_bytes(parsed) != transcript:
            raise _TranscriptRejected("transcript is not canonical JSON")
    except Exception as error:
        raise _TranscriptRejected("invalid transcript") from error
    fixed = {
        "address_policy_digest": str(INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST),
        "address_policy_ref": INTERNET_PUBLIC_ADDRESS_POLICY_REF,
        "kind": "RESULT",
        "network_policy_version": GLM_NETWORK_POLICY_VERSION,
        "schema_version": RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
        "status": "ok",
    }
    proof_names = {
        "attempt_permit_digest",
        "attempt_permit_id",
        "canonical_hostname",
        "dns_start_id",
        "port",
        "start_frame_digest",
        "terminal_guard_digest",
        "terminal_guard_id",
        "transport_claim_id",
    }
    if (
        type(parsed) is not dict
        or set(parsed) != set(fixed) | proof_names | {"candidates"}
    ):
        raise _TranscriptRejected("invalid transcript object")
    if any(parsed[name] != value for name, value in fixed.items()):
        raise _TranscriptRejected("transcript policy fields are invalid")
    try:
        for name in (
            "attempt_permit_id",
            "transport_claim_id",
            "terminal_guard_id",
            "dns_start_id",
        ):
            value = parsed[name]
            if type(value) is not str or str(UUID(value)) != value:
                raise ValueError("invalid UUID proof")
        for name in (
            "attempt_permit_digest",
            "terminal_guard_digest",
            "start_frame_digest",
        ):
            Digest256(parsed[name])
        hostname = parsed["canonical_hostname"]
        if (
            type(hostname) is not str
            or hostname != hostname.lower()
            or _CANONICAL_DNS_RE.fullmatch(hostname) is None
        ):
            raise ValueError("invalid hostname proof")
        port = parsed["port"]
        if type(port) is not int or not 1 <= port <= 65_535:
            raise ValueError("invalid port proof")
    except (TypeError, ValueError) as error:
        raise _TranscriptRejected("invalid transcript proof shape") from error
    candidates = parsed["candidates"]
    if type(candidates) is not list or not (
        1 <= len(candidates) <= MAX_RAW_RESOLUTION_CANDIDATES
    ):
        raise _TranscriptRejected("invalid candidate count")
    if not all(type(candidate) is dict for candidate in candidates):
        raise _TranscriptRejected("invalid candidate object")
    return parsed, tuple(candidates), result_transcript_digest(transcript)


def _is_ipv4_allowed(address: IPv4Address) -> bool:
    return not any(address in network for network in _IPV4_REJECT_NETWORKS)


def _is_ipv4_mapped(address: IPv6Address) -> bool:
    packed = address.packed
    return packed[:12] == (b"\x00" * 10 + b"\xff\xff")


def _is_ipv6_allowed(address: IPv6Address) -> bool:
    return (
        not _is_ipv4_mapped(address)
        and any(address in network for network in _IPV6_ACCEPT_NETWORKS)
        and not any(address in network for network in _IPV6_REJECT_NETWORKS)
    )


def _normalized_raw_address(
    record: dict[str, object],
    *,
    expected_port: int,
) -> ResolvedAddress:
    family_value = record.get("family")
    if family_value == "AF_INET":
        expected_keys = {
            "address",
            "family",
            "port",
            "protocol",
            "socket_type",
        }
        family = AddressFamily.IPV4
    elif family_value == "AF_INET6":
        expected_keys = {
            "address",
            "family",
            "flowinfo",
            "port",
            "protocol",
            "scope_id",
            "socket_type",
        }
        family = AddressFamily.IPV6
    else:
        raise _TranscriptRejected("unsupported address family")
    if set(record) != expected_keys:
        raise _TranscriptRejected("candidate keys are not exact")
    if (
        record["socket_type"] != "SOCK_STREAM"
        or record["protocol"] != "IPPROTO_TCP"
        or type(record["port"]) is not int
        or record["port"] != expected_port
    ):
        raise _TranscriptRejected("candidate transport metadata changed")
    raw_address = record["address"]
    if type(raw_address) is not str or not raw_address or "%" in raw_address:
        raise _TranscriptRejected("candidate address is malformed")
    if family is AddressFamily.IPV4:
        try:
            parsed: IPv4Address | IPv6Address = IPv4Address(raw_address)
        except ValueError as error:
            raise _TranscriptRejected("candidate address is malformed") from error
        if raw_address != str(parsed) or not _is_ipv4_allowed(parsed):
            raise _TranscriptRejected("candidate address is forbidden")
    else:
        if (
            type(record["flowinfo"]) is not int
            or record["flowinfo"] != 0
            or type(record["scope_id"]) is not int
            or record["scope_id"] != 0
        ):
            raise _TranscriptRejected("IPv6 scope metadata is forbidden")
        try:
            parsed = IPv6Address(raw_address)
        except ValueError as error:
            raise _TranscriptRejected("candidate address is malformed") from error
        if raw_address != str(parsed) or not _is_ipv6_allowed(parsed):
            raise _TranscriptRejected("candidate address is forbidden")
    return ResolvedAddress(
        family=family,
        packed_hex=parsed.packed.hex(),
        canonical_text=str(parsed),
        port=expected_port,
        _authority=_ADDRESS_FACTORY_AUTHORITY,
    )


def _candidate_sort_key(address: ResolvedAddress) -> tuple[int, bytes, int]:
    family_rank = 0 if address.family is AddressFamily.IPV4 else 1
    return family_rank, address.packed, address.port


def _normalized_transcript_payload(
    normalized: "NormalizedResolutionTranscript",
) -> dict[str, object]:
    return {
        "attempt_permit_id": normalized.attempt_permit_id,
        "attempt_permit_digest": normalized.attempt_permit_digest,
        "transport_claim_id": normalized.transport_claim_id,
        "terminal_guard_id": normalized.terminal_guard_id,
        "terminal_guard_digest": normalized.terminal_guard_digest,
        "dns_start_id": normalized.dns_start_id,
        "start_frame_digest": normalized.start_frame_digest,
        "canonical_hostname": normalized.canonical_hostname,
        "port": normalized.port,
        "network_policy_version": normalized.network_policy_version,
        "address_policy_ref": normalized.address_policy_ref,
        "address_policy_digest": normalized.address_policy_digest,
        "raw_transcript_digest": normalized.raw_transcript_digest,
        "raw_transcript_byte_size": normalized.raw_transcript_byte_size,
        "raw_candidate_count": normalized.raw_candidate_count,
        "candidates": tuple(_address_payload(item) for item in normalized.candidates),
    }


@runtime_final
class NormalizedResolutionTranscript:
    """Pure, factory-only normalized RESULT data with no publish authority."""

    __slots__ = (
        "attempt_permit_id",
        "attempt_permit_digest",
        "transport_claim_id",
        "terminal_guard_id",
        "terminal_guard_digest",
        "dns_start_id",
        "start_frame_digest",
        "canonical_hostname",
        "port",
        "network_policy_version",
        "address_policy_ref",
        "address_policy_digest",
        "raw_transcript_digest",
        "raw_transcript_byte_size",
        "raw_candidate_count",
        "candidates",
        "normalization_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        parsed: dict[str, object],
        raw_transcript_digest: Digest256,
        raw_transcript_byte_size: int,
        raw_candidate_count: int,
        candidates: tuple[ResolvedAddress, ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _NORMALIZED_TRANSCRIPT_FACTORY_AUTHORITY:
            raise TypeError("normalized transcripts require the policy factory")
        values = (
            ("attempt_permit_id", UUID(parsed["attempt_permit_id"])),
            (
                "attempt_permit_digest",
                Digest256(parsed["attempt_permit_digest"]),
            ),
            ("transport_claim_id", UUID(parsed["transport_claim_id"])),
            ("terminal_guard_id", UUID(parsed["terminal_guard_id"])),
            (
                "terminal_guard_digest",
                Digest256(parsed["terminal_guard_digest"]),
            ),
            ("dns_start_id", UUID(parsed["dns_start_id"])),
            ("start_frame_digest", Digest256(parsed["start_frame_digest"])),
            ("canonical_hostname", parsed["canonical_hostname"]),
            ("port", parsed["port"]),
            ("network_policy_version", parsed["network_policy_version"]),
            ("address_policy_ref", parsed["address_policy_ref"]),
            ("address_policy_digest", Digest256(parsed["address_policy_digest"])),
            ("raw_transcript_digest", raw_transcript_digest),
            ("raw_transcript_byte_size", raw_transcript_byte_size),
            ("raw_candidate_count", raw_candidate_count),
            ("candidates", candidates),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        normalization_digest = digest256(
            "NormalizedResolutionTranscript",
            NORMALIZED_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
            _normalized_transcript_payload(self),
        )
        object.__setattr__(self, "normalization_digest", normalization_digest)
        object.__setattr__(self, "_issued_digest", normalization_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("NormalizedResolutionTranscript is immutable")

    def __copy__(self) -> "NormalizedResolutionTranscript":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "NormalizedResolutionTranscript":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("NormalizedResolutionTranscript cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("NormalizedResolutionTranscript cannot be serialized")

    def __repr__(self) -> str:
        return (
            "NormalizedResolutionTranscript("
            f"raw_candidate_count={self.raw_candidate_count!r}, "
            f"candidate_count={len(self.candidates)!r}, port={self.port!r})"
        )

    def validate_integrity(self) -> None:
        for name in (
            "attempt_permit_id",
            "transport_claim_id",
            "terminal_guard_id",
            "dns_start_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "attempt_permit_digest",
            "terminal_guard_digest",
            "start_frame_digest",
            "address_policy_digest",
            "raw_transcript_digest",
            "normalization_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        if (
            type(self.canonical_hostname) is not str
            or self.canonical_hostname != self.canonical_hostname.lower()
            or _CANONICAL_DNS_RE.fullmatch(self.canonical_hostname) is None
        ):
            raise ValueError("normalized hostname changed")
        require_plain_int(self.port, "port", minimum=1)
        if self.port > 65_535:
            raise ValueError("normalized port changed")
        if self.network_policy_version != GLM_NETWORK_POLICY_VERSION:
            raise ValueError("normalized network policy changed")
        if (
            self.address_policy_ref != INTERNET_PUBLIC_ADDRESS_POLICY_REF
            or self.address_policy_digest != INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST
        ):
            raise ValueError("normalized address policy changed")
        require_plain_int(
            self.raw_transcript_byte_size,
            "raw_transcript_byte_size",
            minimum=1,
        )
        if self.raw_transcript_byte_size > MAX_RAW_RESOLUTION_BYTES:
            raise ValueError("normalized transcript size changed")
        require_plain_int(
            self.raw_candidate_count,
            "raw_candidate_count",
            minimum=1,
        )
        if self.raw_candidate_count > MAX_RAW_RESOLUTION_CANDIDATES:
            raise ValueError("normalized candidate count changed")
        if (
            type(self.candidates) is not tuple
            or not self.candidates
            or not all(type(item) is ResolvedAddress for item in self.candidates)
            or len(self.candidates) > self.raw_candidate_count
        ):
            raise ValueError("normalized candidates changed")
        for candidate in self.candidates:
            candidate.validate_integrity()
            if candidate.port != self.port:
                raise ValueError("normalized candidate port changed")
        keys = tuple(_candidate_sort_key(item) for item in self.candidates)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("normalized candidates are not canonical")
        recomputed = digest256(
            "NormalizedResolutionTranscript",
            NORMALIZED_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
            _normalized_transcript_payload(self),
        )
        if (
            recomputed != self.normalization_digest
            or recomputed != self._issued_digest
        ):
            raise ValueError("normalized transcript integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "schema_version": NORMALIZED_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
            "port": self.port,
            "raw_candidate_count": self.raw_candidate_count,
            "candidate_count": len(self.candidates),
            "raw_transcript_digest_prefix": str(self.raw_transcript_digest)[:12],
            "normalization_digest_prefix": str(self.normalization_digest)[:12],
        }


def normalize_resolution_transcript(
    transcript: bytes,
    *,
    expected_port: int,
) -> NormalizedResolutionTranscript:
    """Purely parse and normalize RESULT; this cannot publish a ResolutionSet."""

    result: NormalizedResolutionTranscript | None = None
    try:
        checked_port = require_plain_int(expected_port, "expected_port", minimum=1)
        if checked_port > 65_535:
            raise _TranscriptRejected("expected port is out of range")
        parsed, raw_candidates, transcript_digest = _parse_transcript(transcript)
        if parsed["port"] != checked_port:
            raise _TranscriptRejected("transcript port changed")
        normalized = tuple(
            _normalized_raw_address(record, expected_port=checked_port)
            for record in raw_candidates
        )
        unique_by_key = {
            _candidate_sort_key(candidate): candidate for candidate in normalized
        }
        candidates = tuple(unique_by_key[key] for key in sorted(unique_by_key))
        if not candidates:
            raise _TranscriptRejected("resolution set is empty")
        result = NormalizedResolutionTranscript(
            parsed=parsed,
            raw_transcript_digest=transcript_digest,
            raw_transcript_byte_size=len(transcript),
            raw_candidate_count=len(raw_candidates),
            candidates=candidates,
            _authority=_NORMALIZED_TRANSCRIPT_FACTORY_AUTHORITY,
        )
    except Exception:
        _raise_address_error()
    if result is None:
        _raise_address_error()
    return result


def _frozen_attempt_network_binding(
    attempt_permit: AttemptPermit,
) -> tuple[str, int, str]:
    if type(attempt_permit) is not AttemptPermit:
        raise TypeError("attempt_permit must be AttemptPermit")
    attempt_permit.validate_integrity()
    credential_permit = attempt_permit._credential_permit
    if type(credential_permit) is not CredentialResolutionPermit:
        raise ValueError("attempt no longer retains its credential authority")
    _, operation = _frozen_glm_binding(credential_permit)
    planned = credential_permit._planned
    invocation = credential_permit._invocation
    prepared = credential_permit._prepared
    if planned is None or invocation is None or prepared is None:
        raise ValueError("attempt frozen binding is unavailable")
    stages = tuple(
        stage
        for stage in planned.plan.stages
        if stage.stage_id == invocation.stage_id
    )
    if len(stages) != 1:
        raise ValueError("attempt stage binding is ambiguous")
    stage = stages[0]
    if (
        stage.network_scope is not NetworkScope.INTERNET
        or stage.network_policy_version != GLM_NETWORK_POLICY_VERSION
        or operation.canonical_endpoint != GLM_CHAT_COMPLETIONS_ENDPOINT
        or prepared.canonical_url != operation.canonical_endpoint
        or attempt_permit.operation_id != operation.operation_id
        or attempt_permit.request_envelope_digest
        != prepared.request_envelope_digest
        or attempt_permit.context_id != credential_permit.context_id
        or attempt_permit.session_id != credential_permit.session_id
    ):
        raise ValueError("attempt network binding changed")
    parsed = urlsplit(prepared.canonical_url)
    if parsed.hostname is None or parsed.port is None:
        raise ValueError("attempt URL lacks an exact host and port")
    return parsed.hostname, parsed.port, stage.network_policy_version


def build_resolution_set(
    attempt_permit: AttemptPermit,
    result_receipt: ResolverResultReceipt,
) -> ResolutionSet:
    """Publish only from one exact, ledger-issued helper RESULT receipt."""

    if type(attempt_permit) is not AttemptPermit:
        raise TypeError("attempt_permit must be AttemptPermit")
    if type(result_receipt) is not ResolverResultReceipt:
        raise TypeError("result_receipt must be ResolverResultReceipt")
    failed = False
    result: ResolutionSet | None = None
    try:
        transcript = result_receipt._publication_transcript(
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        hostname, port, network_policy_version = _frozen_attempt_network_binding(
            attempt_permit
        )
        exact_start_frame = encode_start_frame(
            hostname=hostname,
            port=port,
            network_policy_ref=INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            network_policy_digest=INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
            attempt_permit_id=result_receipt.attempt_permit_id,
            attempt_permit_digest=result_receipt.attempt_permit_digest,
            transport_claim_id=result_receipt.transport_claim_id,
            terminal_guard_id=result_receipt.terminal_guard_id,
            terminal_guard_digest=result_receipt.terminal_guard_digest,
            dns_start_id=result_receipt.dns_start_id,
        )
        if start_frame_digest(exact_start_frame) != result_receipt.start_frame_digest:
            raise _TranscriptRejected("receipt START frame digest changed")
        gate = attempt_permit._attempt_gate
        if not gate._dns_start_is_committed(
            attempt_permit,
            claim_id=result_receipt.transport_claim_id,
            guard_id=result_receipt.terminal_guard_id,
            guard_digest=result_receipt.terminal_guard_digest,
            start_id=result_receipt.dns_start_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        ):
            raise _TranscriptRejected("DNS START proof is not committed")
        normalized = normalize_resolution_transcript(
            transcript,
            expected_port=port,
        )
        exact_echo = (
            normalized.attempt_permit_id == attempt_permit.attempt_permit_id,
            normalized.attempt_permit_digest
            == attempt_permit.attempt_permit_digest,
            normalized.attempt_permit_id == result_receipt.attempt_permit_id,
            normalized.attempt_permit_digest
            == result_receipt.attempt_permit_digest,
            normalized.transport_claim_id == result_receipt.transport_claim_id,
            normalized.terminal_guard_id == result_receipt.terminal_guard_id,
            normalized.terminal_guard_digest
            == result_receipt.terminal_guard_digest,
            normalized.dns_start_id == result_receipt.dns_start_id,
            normalized.start_frame_digest == result_receipt.start_frame_digest,
            normalized.canonical_hostname == hostname,
            normalized.port == port,
            normalized.network_policy_version == network_policy_version,
            normalized.address_policy_ref == INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            normalized.address_policy_digest
            == INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
            normalized.raw_transcript_digest
            == result_receipt.raw_transcript_digest,
            normalized.raw_transcript_byte_size
            == result_receipt.raw_transcript_byte_size,
        )
        if not all(exact_echo):
            raise _TranscriptRejected("RESULT proof does not match receipt")
        result = ResolutionSet(
            attempt_permit=attempt_permit,
            transport_claim_id=result_receipt.transport_claim_id,
            terminal_guard_id=result_receipt.terminal_guard_id,
            terminal_guard_digest=result_receipt.terminal_guard_digest,
            dns_start_id=result_receipt.dns_start_id,
            result_receipt=result_receipt,
            canonical_hostname=hostname,
            port=port,
            network_policy_version=network_policy_version,
            raw_transcript_digest=normalized.raw_transcript_digest,
            raw_transcript_byte_size=normalized.raw_transcript_byte_size,
            raw_candidate_count=normalized.raw_candidate_count,
            candidates=normalized.candidates,
            _authority=_RESOLUTION_FACTORY_AUTHORITY,
        )
        result_receipt._publish_resolution(
            result,
            resolution_digest=result.resolution_digest,
            canonical_payload=_resolution_canonical_payload(result),
            candidates=_resolution_candidate_publication_snapshots(result),
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        result.validate_binding(attempt_permit, result_receipt)
    except Exception:
        failed = True
    if failed or result is None:
        _raise_address_error()
    return result


def match_exact_peer(
    resolution: ResolutionSet,
    *,
    family: AddressFamily,
    sockaddr: tuple[object, ...],
) -> ResolvedAddress:
    """Normalize an OS peer tuple and require the selected address exactly."""

    if type(resolution) is not ResolutionSet:
        raise TypeError("resolution must be ResolutionSet")
    failed = False
    selected: ResolvedAddress | None = None
    try:
        resolution.validate_integrity()
        if type(family) is not AddressFamily or type(sockaddr) is not tuple:
            raise ValueError("peer shape is invalid")
        if family is AddressFamily.IPV4:
            if len(sockaddr) != 2:
                raise ValueError("IPv4 peer shape is invalid")
            raw_address, port = sockaddr
        else:
            if len(sockaddr) != 4:
                raise ValueError("IPv6 peer shape is invalid")
            raw_address, port, flowinfo, scope_id = sockaddr
            if (
                type(flowinfo) is not int
                or flowinfo != 0
                or type(scope_id) is not int
                or scope_id != 0
            ):
                raise ValueError("IPv6 peer scope is invalid")
        if (
            type(raw_address) is not str
            or not raw_address
            or "%" in raw_address
            or type(port) is not int
            or not 1 <= port <= 65_535
        ):
            raise ValueError("peer address is invalid")
        parsed = (
            IPv4Address(raw_address)
            if family is AddressFamily.IPV4
            else IPv6Address(raw_address)
        )
        if family is AddressFamily.IPV6 and _is_ipv4_mapped(parsed):
            raise ValueError("mapped peer is forbidden")
        selected = resolution.selected
        if (
            selected.family is not family
            or selected.packed != parsed.packed
            or selected.port != port
        ):
            raise ValueError("peer does not match the selected resolution")
    except Exception:
        failed = True
    if failed or selected is None:
        _raise_address_error()
    return selected


__all__ = [
    "INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST",
    "INTERNET_PUBLIC_ADDRESS_POLICY_REF",
    "INTERNET_PUBLIC_ADDRESS_POLICY_SCHEMA_VERSION",
    "MAX_RAW_RESOLUTION_BYTES",
    "MAX_RAW_RESOLUTION_CANDIDATES",
    "NORMALIZED_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION",
    "RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION",
    "RESOLVED_ADDRESS_SCHEMA_VERSION",
    "RESOLUTION_SET_SCHEMA_VERSION",
    "AddressFamily",
    "NormalizedResolutionTranscript",
    "ResolvedAddress",
    "ResolutionSet",
    "build_resolution_set",
    "match_exact_peer",
    "normalize_resolution_transcript",
]
