"""System-trust, hostname-verifying, HTTP/1.1-only TLS policy for W09-B3.

Construction is explicit and network-free.  No caller context, CA material, or
OpenSSL configuration is accepted.  Environment variables capable of changing
trust/configuration or exporting TLS secrets make the policy unavailable even
when their values are empty; their values are never read or retained.
"""
from __future__ import annotations

import ipaddress
import os
import re
import ssl
from typing import NoReturn

from snapquiz.domain._validation import runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError


__all__ = ()


EXACT_TLS_POLICY_REF = "snapquiz.tls.system-default-h1.v1"
EXACT_TLS_POLICY_SCHEMA_VERSION = "snapquiz.tls-policy-proof.v1"
FORBIDDEN_TLS_ENVIRONMENT_KEYS = (
    "OPENSSL_CONF",
    "OPENSSL_CONF_INCLUDE",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSLKEYLOGFILE",
)


_HOST_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\Z"
)
_POLICY_AUTHORITY = object()


def _tls_error(
    safe_message: str = "TLS 配置未通过安全策略。",
) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="tls_transport",
        retryable=False,
        safe_message=safe_message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_tls_error(
    safe_message: str = "TLS 配置未通过安全策略。",
) -> NoReturn:
    raise _tls_error(safe_message) from None


def _require_canonical_hostname(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 253
        or value != value.lower()
        or value.endswith(".")
        or _HOST_RE.fullmatch(value) is None
    ):
        raise ValueError("hostname must be a canonical lowercase DNS name")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("hostname must be ASCII") from None
    if len(encoded) > 253:
        raise ValueError("hostname exceeds the DNS limit")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("hostname must not be an IP literal")
    return value


def _forbidden_environment_keys_present() -> tuple[str, ...]:
    # Membership checks deliberately avoid reading or retaining any value.
    return tuple(
        key for key in FORBIDDEN_TLS_ENVIRONMENT_KEYS if key in os.environ
    )


def _require_clean_tls_environment() -> None:
    if _forbidden_environment_keys_present():
        _raise_tls_error()


def _exact_tls_policy_payload(*, hostname: str) -> dict[str, object]:
    return {
        "alpn_protocols": ("http/1.1",),
        "cert_required": True,
        "forbidden_environment_keys": tuple(
            sorted(FORBIDDEN_TLS_ENVIRONMENT_KEYS)
        ),
        "hostname": hostname,
        "hostname_check": True,
        "key_logging": False,
        "maximum_version": "system_supported",
        "minimum_version": "TLSv1.2",
        "policy_ref": EXACT_TLS_POLICY_REF,
        "system_default_trust": True,
    }


def _context_matches_policy(context: object) -> bool:
    try:
        return (
            type(context) is ssl.SSLContext
            and context.protocol == ssl.PROTOCOL_TLS_CLIENT
            and context.check_hostname is True
            and context.verify_mode == ssl.CERT_REQUIRED
            and context.minimum_version == ssl.TLSVersion.TLSv1_2
            and context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
            and getattr(context, "keylog_filename", None) is None
            and bool(context.options & ssl.OP_NO_COMPRESSION)
        )
    except (AttributeError, TypeError, ValueError):
        return False


@runtime_final
class _ExactTlsPolicy:
    """One private SSLContext plus immutable policy evidence."""

    __slots__ = (
        "hostname",
        "policy_ref",
        "policy_digest",
        "_context",
        "_context_snapshot",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        hostname: str,
        context: ssl.SSLContext,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _POLICY_AUTHORITY:
            raise TypeError("exact TLS policy requires its factory")
        checked_hostname = _require_canonical_hostname(hostname)
        if not _context_matches_policy(context):
            raise ValueError("SSLContext does not match the exact TLS policy")
        object.__setattr__(self, "hostname", checked_hostname)
        object.__setattr__(self, "policy_ref", EXACT_TLS_POLICY_REF)
        object.__setattr__(self, "_context", context)
        object.__setattr__(self, "_context_snapshot", context)
        selected = digest256(
            "ExactTlsPolicy",
            EXACT_TLS_POLICY_SCHEMA_VERSION,
            _exact_tls_policy_payload(hostname=checked_hostname),
        )
        object.__setattr__(self, "policy_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ExactTlsPolicy is immutable")

    def __copy__(self) -> "_ExactTlsPolicy":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_ExactTlsPolicy":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("ExactTlsPolicy cannot be serialized")

    def validate_integrity(self) -> None:
        _require_clean_tls_environment()
        checked_hostname = _require_canonical_hostname(self.hostname)
        selected = digest256(
            "ExactTlsPolicy",
            EXACT_TLS_POLICY_SCHEMA_VERSION,
            _exact_tls_policy_payload(hostname=checked_hostname),
        )
        if (
            self.policy_ref != EXACT_TLS_POLICY_REF
            or self._context is not self._context_snapshot
            or not _context_matches_policy(self._context)
            or type(self.policy_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.policy_digest != selected
            or self._issued_digest != selected
        ):
            _raise_tls_error()

    def _context_for_wrap(
        self,
        *,
        server_hostname: str,
        _authority: object,
    ) -> ssl.SSLContext:
        if _authority is not _POLICY_AUTHORITY:
            raise TypeError("TLS context access requires transport authority")
        if _require_canonical_hostname(server_hostname) != self.hostname:
            _raise_tls_error("TLS SNI 与冻结目标不匹配。")
        self.validate_integrity()
        return self._context

    def _attest_negotiated_values(
        self,
        *,
        server_hostname: str,
        selected_alpn_protocol: object,
        negotiated_version: object,
        _authority: object,
    ) -> None:
        """Validate facts read from the exact SSLSocket after its handshake."""

        if _authority is not _POLICY_AUTHORITY:
            raise TypeError("TLS negotiation attestation requires transport")
        if _require_canonical_hostname(server_hostname) != self.hostname:
            _raise_tls_error("TLS SNI 与冻结目标不匹配。")
        self.validate_integrity()
        if (
            type(selected_alpn_protocol) is not str
            or selected_alpn_protocol != "http/1.1"
            or type(negotiated_version) is not str
            or negotiated_version not in ("TLSv1.2", "TLSv1.3")
        ):
            _raise_tls_error("TLS 协商结果未通过安全策略。")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "alpn": "http/1.1",
            "hostname_check": True,
            "minimum_version": "TLSv1.2",
            "policy_digest_prefix": str(self.policy_digest)[:12],
            "policy_ref": self.policy_ref,
            "system_default_trust": True,
        }


def _new_exact_tls_policy(*, hostname: str) -> _ExactTlsPolicy:
    checked_hostname = _require_canonical_hostname(hostname)
    _require_clean_tls_environment()
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if type(context) is not ssl.SSLContext:
            raise ValueError("default SSLContext type is invalid")
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_alpn_protocols(["http/1.1"])
    except BaseException:
        _raise_tls_error()
    # Detect ordinary environment mutation across default-trust construction.
    _require_clean_tls_environment()
    try:
        return _ExactTlsPolicy(
            hostname=checked_hostname,
            context=context,
            _authority=_POLICY_AUTHORITY,
        )
    except (TypeError, ValueError):
        _raise_tls_error()
