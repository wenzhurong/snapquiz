"""Darwin-local dynamic code identity foundation for a connected peer.

This private W09-B2b-S2b-I1 module is deliberately development-only and is
not imported by the production resolver or application entry point.  It
attests the process that performed an ``AF_UNIX/SOCK_STREAM`` connect by using
Darwin's kernel-supplied ``LOCAL_PEERTOKEN`` rather than any child payload.
The opaque audit token is then bound to one PID generation, one executable
path, and one dynamically validated Security.framework code object.

The proof is intentionally named *connection peer* identity.  A connected
descriptor can survive a later fork or exec, so this slice does not claim
continuous running-image identity, process ownership, bundle provenance, or
production startup ordering.  Those claims require suspended spawn plus a
lifelong process-event watcher and a fixed signed application manifest.

Import and policy construction perform no file, process, socket, environment,
or framework operation.  The explicit attestation call is Darwin-only and
contains no target, credential, DNS, or network authority.
"""
from __future__ import annotations

import ctypes
import os
import re
import signal
import socket
import sys
from typing import NamedTuple, NoReturn

from snapquiz.domain._validation import require_plain_int, runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError


__all__ = ()


DARWIN_PROCESS_IDENTITY_POLICY_SCHEMA_VERSION = (
    "snapquiz.darwin-process-identity-policy.v1"
)
DARWIN_PROCESS_IDENTITY_ATTESTATION_SCHEMA_VERSION = (
    "snapquiz.darwin-process-identity-attestation.v1"
)
DARWIN_PROCESS_IDENTITY_SCOPE = (
    "darwin_connection_peer_dynamic_code_development"
)

_AUDIT_TOKEN_BYTES = 32
_CODE_DIRECTORY_HASH_BYTES = 20
_PROC_PIDPATHINFO_MAXSIZE = 4_096
_MAX_EXECUTABLE_PATH_BYTES = _PROC_PIDPATHINFO_MAXSIZE - 1
_MAX_CODE_IDENTITY_TEXT_BYTES = 1_024
_LOCAL_PEERPID = 0x002
_LOCAL_PEERTOKEN = 0x006
_SOL_LOCAL = 0
_K_CF_STRING_ENCODING_UTF8 = 0x08000100
_K_CF_NUMBER_SINT64_TYPE = 4
_K_CF_URL_POSIX_PATH_STYLE = 0
_K_SEC_CS_SIGNING_INFORMATION = 1 << 1
_K_SEC_CS_DYNAMIC_INFORMATION = 1 << 3
_K_SEC_CS_STRICT_VALIDATE = 1 << 4
_CS_VALID = 0x00000001
_CS_ADHOC = 0x00000002
_UINT32_MAX = (1 << 32) - 1
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,254})$")
_TEAM_IDENTIFIER_RE = re.compile(r"^[A-Z0-9]{10}$")
_CDHASH_RE = re.compile(r"^[0-9a-f]{40}$")
_POLICY_AUTHORITY = object()
_ATTESTATION_AUTHORITY = object()

_CORE_FOUNDATION_PATH = (
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
)
_SECURITY_PATH = "/System/Library/Frameworks/Security.framework/Security"
_LIBBSM_PATH = "/usr/lib/libbsm.dylib"
_LIBPROC_PATH = "/usr/lib/libproc.dylib"


class _IdentityBoundaryFailure(Exception):
    """Content-free internal marker; never crosses the adapter boundary."""


class _AuditToken(ctypes.Structure):
    _fields_ = (("value", ctypes.c_uint32 * 8),)


class _ObservedIdentity(NamedTuple):
    process_id: int
    process_version: int
    effective_user_id: int
    executable: str
    code_identifier: str
    team_identifier: str | None
    code_directory_hash: str
    static_code_flags: int
    dynamic_code_status: int
    audit_token_digest: Digest256


class _ObservedRunningCode(NamedTuple):
    process_id: int
    executable: str
    code_identifier: str
    team_identifier: str | None
    code_directory_hash: str
    static_code_flags: int
    dynamic_code_status: int


def _identity_error(
    safe_message: str = "resolver supervisor 进程身份不可用。",
) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_supervisor_identity",
        retryable=False,
        safe_message=safe_message,
    )


def _raise_identity_error(
    safe_message: str = "resolver supervisor 进程身份不可用。",
) -> NoReturn:
    error = _identity_error(safe_message)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _require_executable_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or len(os.fsencode(value)) > _MAX_EXECUTABLE_PATH_BYTES
    ):
        raise ValueError("expected_executable must be a normalized absolute path")
    return value


def _require_code_identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError("expected_code_identifier is invalid")
    return value


def _require_team_identifier(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _TEAM_IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError("expected_team_identifier is invalid")
    return value


def _require_cdhash(value: object) -> str:
    if type(value) is not str or _CDHASH_RE.fullmatch(value) is None:
        raise ValueError("expected_code_directory_hash is invalid")
    return value


def _require_uint32(value: object, name: str) -> int:
    checked = require_plain_int(value, name)
    if checked > _UINT32_MAX:
        raise ValueError(f"{name} must fit uint32")
    return checked


@runtime_final
class _LocalDarwinProcessIdentityPolicy:
    """Pure expected identity for one Darwin-local development peer."""

    __slots__ = (
        "expected_executable",
        "expected_code_identifier",
        "expected_team_identifier",
        "expected_code_directory_hash",
        "expected_effective_user_id",
        "required_static_code_flags",
        "forbidden_static_code_flags",
        "required_dynamic_code_status",
        "forbidden_dynamic_code_status",
        "expected_adhoc",
        "policy_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        expected_executable: str,
        expected_code_identifier: str,
        expected_team_identifier: str | None,
        expected_code_directory_hash: str,
        expected_effective_user_id: int,
        required_static_code_flags: int,
        forbidden_static_code_flags: int,
        required_dynamic_code_status: int,
        forbidden_dynamic_code_status: int,
        expected_adhoc: bool,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _POLICY_AUTHORITY:
            raise TypeError("local Darwin identity policy requires its factory")
        executable = _require_executable_path(expected_executable)
        identifier = _require_code_identifier(expected_code_identifier)
        team = _require_team_identifier(expected_team_identifier)
        cdhash = _require_cdhash(expected_code_directory_hash)
        user_id = _require_uint32(
            expected_effective_user_id,
            "expected_effective_user_id",
        )
        required_flags = _require_uint32(
            required_static_code_flags,
            "required_static_code_flags",
        )
        forbidden_flags = _require_uint32(
            forbidden_static_code_flags,
            "forbidden_static_code_flags",
        )
        required_dynamic = _require_uint32(
            required_dynamic_code_status,
            "required_dynamic_code_status",
        )
        forbidden_dynamic = _require_uint32(
            forbidden_dynamic_code_status,
            "forbidden_dynamic_code_status",
        )
        if required_flags & forbidden_flags:
            raise ValueError("required and forbidden code flags overlap")
        if required_dynamic & forbidden_dynamic:
            raise ValueError("required and forbidden dynamic status overlap")
        if not required_dynamic & _CS_VALID:
            raise ValueError("dynamic status must require CS_VALID")
        if type(expected_adhoc) is not bool:
            raise ValueError("expected_adhoc must be bool")
        if bool(required_flags & _CS_ADHOC) is not expected_adhoc:
            raise ValueError("expected_adhoc must match required code flags")
        if bool(forbidden_flags & _CS_ADHOC) is expected_adhoc:
            raise ValueError("expected_adhoc must match forbidden code flags")
        if expected_adhoc and team is not None:
            raise ValueError("ad-hoc development identity cannot claim a Team ID")

        payload = {
            "expected_adhoc": expected_adhoc,
            "expected_code_directory_hash": cdhash,
            "expected_code_identifier": identifier,
            "expected_effective_user_id": user_id,
            "expected_executable": executable,
            "expected_team_identifier": team,
            "forbidden_static_code_flags": forbidden_flags,
            "forbidden_dynamic_code_status": forbidden_dynamic,
            "identity_scope": DARWIN_PROCESS_IDENTITY_SCOPE,
            "production_eligible": False,
            "required_dynamic_code_status": required_dynamic,
            "required_static_code_flags": required_flags,
        }
        selected = digest256(
            "LocalDarwinProcessIdentityPolicy",
            DARWIN_PROCESS_IDENTITY_POLICY_SCHEMA_VERSION,
            payload,
        )
        object.__setattr__(self, "expected_executable", executable)
        object.__setattr__(self, "expected_code_identifier", identifier)
        object.__setattr__(self, "expected_team_identifier", team)
        object.__setattr__(self, "expected_code_directory_hash", cdhash)
        object.__setattr__(self, "expected_effective_user_id", user_id)
        object.__setattr__(self, "required_static_code_flags", required_flags)
        object.__setattr__(self, "forbidden_static_code_flags", forbidden_flags)
        object.__setattr__(self, "required_dynamic_code_status", required_dynamic)
        object.__setattr__(
            self,
            "forbidden_dynamic_code_status",
            forbidden_dynamic,
        )
        object.__setattr__(self, "expected_adhoc", expected_adhoc)
        object.__setattr__(self, "policy_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("LocalDarwinProcessIdentityPolicy is immutable")

    def __copy__(self) -> "_LocalDarwinProcessIdentityPolicy":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_LocalDarwinProcessIdentityPolicy":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("LocalDarwinProcessIdentityPolicy cannot be serialized")

    def _digest_payload(self) -> dict[str, object]:
        return {
            "expected_adhoc": self.expected_adhoc,
            "expected_code_directory_hash": self.expected_code_directory_hash,
            "expected_code_identifier": self.expected_code_identifier,
            "expected_effective_user_id": self.expected_effective_user_id,
            "expected_executable": self.expected_executable,
            "expected_team_identifier": self.expected_team_identifier,
            "forbidden_static_code_flags": self.forbidden_static_code_flags,
            "forbidden_dynamic_code_status": self.forbidden_dynamic_code_status,
            "identity_scope": DARWIN_PROCESS_IDENTITY_SCOPE,
            "production_eligible": False,
            "required_dynamic_code_status": self.required_dynamic_code_status,
            "required_static_code_flags": self.required_static_code_flags,
        }

    def validate_integrity(self) -> None:
        _require_executable_path(self.expected_executable)
        _require_code_identifier(self.expected_code_identifier)
        _require_team_identifier(self.expected_team_identifier)
        _require_cdhash(self.expected_code_directory_hash)
        _require_uint32(
            self.expected_effective_user_id,
            "expected_effective_user_id",
        )
        required_flags = _require_uint32(
            self.required_static_code_flags,
            "required_static_code_flags",
        )
        forbidden_flags = _require_uint32(
            self.forbidden_static_code_flags,
            "forbidden_static_code_flags",
        )
        required_dynamic = _require_uint32(
            self.required_dynamic_code_status,
            "required_dynamic_code_status",
        )
        forbidden_dynamic = _require_uint32(
            self.forbidden_dynamic_code_status,
            "forbidden_dynamic_code_status",
        )
        if required_flags & forbidden_flags:
            raise ValueError("required and forbidden code flags overlap")
        if required_dynamic & forbidden_dynamic:
            raise ValueError("required and forbidden dynamic status overlap")
        if not required_dynamic & _CS_VALID:
            raise ValueError("dynamic status must require CS_VALID")
        if type(self.expected_adhoc) is not bool:
            raise ValueError("expected_adhoc must be bool")
        if bool(required_flags & _CS_ADHOC) is not self.expected_adhoc:
            raise ValueError("expected_adhoc must match required code flags")
        if bool(forbidden_flags & _CS_ADHOC) is self.expected_adhoc:
            raise ValueError("expected_adhoc must match forbidden code flags")
        if self.expected_adhoc and self.expected_team_identifier is not None:
            raise ValueError("ad-hoc development identity cannot claim a Team ID")
        selected = digest256(
            "LocalDarwinProcessIdentityPolicy",
            DARWIN_PROCESS_IDENTITY_POLICY_SCHEMA_VERSION,
            self._digest_payload(),
        )
        if (
            type(self.policy_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.policy_digest != selected
            or self._issued_digest != selected
        ):
            raise ValueError("local Darwin identity policy integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "expected_adhoc": self.expected_adhoc,
            "identity_scope": DARWIN_PROCESS_IDENTITY_SCOPE,
            "policy_digest": str(self.policy_digest),
            "production_eligible": False,
        }


def _new_local_darwin_process_identity_policy(
    *,
    expected_executable: str,
    expected_code_identifier: str,
    expected_team_identifier: str | None,
    expected_code_directory_hash: str,
    expected_effective_user_id: int,
    required_static_code_flags: int,
    forbidden_static_code_flags: int,
    required_dynamic_code_status: int,
    forbidden_dynamic_code_status: int,
    expected_adhoc: bool,
) -> _LocalDarwinProcessIdentityPolicy:
    return _LocalDarwinProcessIdentityPolicy(
        expected_executable=expected_executable,
        expected_code_identifier=expected_code_identifier,
        expected_team_identifier=expected_team_identifier,
        expected_code_directory_hash=expected_code_directory_hash,
        expected_effective_user_id=expected_effective_user_id,
        required_static_code_flags=required_static_code_flags,
        forbidden_static_code_flags=forbidden_static_code_flags,
        required_dynamic_code_status=required_dynamic_code_status,
        forbidden_dynamic_code_status=forbidden_dynamic_code_status,
        expected_adhoc=expected_adhoc,
        _authority=_POLICY_AUTHORITY,
    )


@runtime_final
class _DarwinConnectionPeerIdentityAttestation:
    """Factory-only proof of one audit-token-bound connection peer."""

    __slots__ = (
        "process_id",
        "process_version",
        "effective_user_id",
        "executable",
        "code_identifier",
        "team_identifier",
        "code_directory_hash",
        "static_code_flags",
        "dynamic_code_status",
        "audit_token_digest",
        "policy_digest",
        "attestation_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        observed: _ObservedIdentity,
        policy: _LocalDarwinProcessIdentityPolicy,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ATTESTATION_AUTHORITY:
            raise TypeError("Darwin peer attestation requires its factory")
        if type(observed) is not _ObservedIdentity:
            raise TypeError("observed identity is invalid")
        if type(policy) is not _LocalDarwinProcessIdentityPolicy:
            raise TypeError("identity policy is invalid")
        policy.validate_integrity()
        values = {
            "process_id": observed.process_id,
            "process_version": observed.process_version,
            "effective_user_id": observed.effective_user_id,
            "executable": observed.executable,
            "code_identifier": observed.code_identifier,
            "team_identifier": observed.team_identifier,
            "code_directory_hash": observed.code_directory_hash,
            "static_code_flags": observed.static_code_flags,
            "dynamic_code_status": observed.dynamic_code_status,
            "audit_token_digest": observed.audit_token_digest,
            "policy_digest": policy.policy_digest,
        }
        selected = digest256(
            "DarwinConnectionPeerIdentityAttestation",
            DARWIN_PROCESS_IDENTITY_ATTESTATION_SCHEMA_VERSION,
            {
                **values,
                "connection_peer_identity_attested": True,
                "continuous_running_identity_attested": False,
                "identity_scope": DARWIN_PROCESS_IDENTITY_SCOPE,
                "production_bundle_attested": False,
            },
        )
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "attestation_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError(
            "DarwinConnectionPeerIdentityAttestation is immutable"
        )

    def __copy__(self) -> "_DarwinConnectionPeerIdentityAttestation":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_DarwinConnectionPeerIdentityAttestation":
        del memo
        return self

    def __reduce__(self):
        raise TypeError(
            "DarwinConnectionPeerIdentityAttestation cannot be serialized"
        )

    def _digest_payload(self) -> dict[str, object]:
        return {
            "attestation_digest": self.attestation_digest,
            "audit_token_digest": self.audit_token_digest,
            "code_directory_hash": self.code_directory_hash,
            "code_identifier": self.code_identifier,
            "connection_peer_identity_attested": True,
            "continuous_running_identity_attested": False,
            "dynamic_code_status": self.dynamic_code_status,
            "effective_user_id": self.effective_user_id,
            "executable": self.executable,
            "identity_scope": DARWIN_PROCESS_IDENTITY_SCOPE,
            "policy_digest": self.policy_digest,
            "process_id": self.process_id,
            "process_version": self.process_version,
            "production_bundle_attested": False,
            "static_code_flags": self.static_code_flags,
            "team_identifier": self.team_identifier,
        }

    def validate_integrity(self) -> None:
        require_plain_int(self.process_id, "process_id", minimum=1)
        require_plain_int(self.process_version, "process_version", minimum=1)
        _require_uint32(self.effective_user_id, "effective_user_id")
        _require_executable_path(self.executable)
        _require_code_identifier(self.code_identifier)
        _require_team_identifier(self.team_identifier)
        _require_cdhash(self.code_directory_hash)
        _require_uint32(self.static_code_flags, "static_code_flags")
        dynamic_status = _require_uint32(
            self.dynamic_code_status,
            "dynamic_code_status",
        )
        if not dynamic_status & _CS_VALID:
            raise ValueError("dynamic code is not valid")
        if (
            type(self.audit_token_digest) is not Digest256
            or type(self.policy_digest) is not Digest256
            or type(self.attestation_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
        ):
            raise ValueError("Darwin peer attestation digest type failed")
        payload = self._digest_payload()
        claimed = payload.pop("attestation_digest")
        selected = digest256(
            "DarwinConnectionPeerIdentityAttestation",
            DARWIN_PROCESS_IDENTITY_ATTESTATION_SCHEMA_VERSION,
            payload,
        )
        if (
            type(claimed) is not Digest256
            or type(self._issued_digest) is not Digest256
            or claimed != selected
            or self._issued_digest != selected
        ):
            raise ValueError("Darwin peer attestation integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "attestation_digest": str(self.attestation_digest),
            "connection_peer_identity_attested": True,
            "continuous_running_identity_attested": False,
            "identity_scope": DARWIN_PROCESS_IDENTITY_SCOPE,
            "process_id": self.process_id,
            "process_version": self.process_version,
            "production_bundle_attested": False,
            "startup_order_attested": False,
            "transport_available": False,
        }


class _DarwinFrameworks:
    """Per-call typed ctypes handles; construction is explicit I/O."""

    __slots__ = ("cf", "security", "bsm", "proc")

    def __init__(self) -> None:
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise _IdentityBoundaryFailure
        self.cf = ctypes.CDLL(_CORE_FOUNDATION_PATH, use_errno=True)
        self.security = ctypes.CDLL(_SECURITY_PATH, use_errno=True)
        self.bsm = ctypes.CDLL(_LIBBSM_PATH, use_errno=True)
        self.proc = ctypes.CDLL(_LIBPROC_PATH, use_errno=True)
        self._configure()

    def _configure(self) -> None:
        pointer = ctypes.c_void_p
        cf = self.cf
        security = self.security

        cf.CFDataCreate.argtypes = (
            pointer,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_long,
        )
        cf.CFDataCreate.restype = pointer
        cf.CFDataGetLength.argtypes = (pointer,)
        cf.CFDataGetLength.restype = ctypes.c_long
        cf.CFDataGetBytePtr.argtypes = (pointer,)
        cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
        cf.CFDictionaryCreateMutable.argtypes = (
            pointer,
            ctypes.c_long,
            pointer,
            pointer,
        )
        cf.CFDictionaryCreateMutable.restype = pointer
        cf.CFDictionarySetValue.argtypes = (pointer, pointer, pointer)
        cf.CFDictionarySetValue.restype = None
        cf.CFDictionaryGetValue.argtypes = (pointer, pointer)
        cf.CFDictionaryGetValue.restype = pointer
        cf.CFStringCreateWithCString.argtypes = (
            pointer,
            ctypes.c_char_p,
            ctypes.c_uint32,
        )
        cf.CFStringCreateWithCString.restype = pointer
        cf.CFStringGetCString.argtypes = (
            pointer,
            ctypes.c_char_p,
            ctypes.c_long,
            ctypes.c_uint32,
        )
        cf.CFStringGetCString.restype = ctypes.c_ubyte
        cf.CFURLCopyFileSystemPath.argtypes = (pointer, ctypes.c_long)
        cf.CFURLCopyFileSystemPath.restype = pointer
        cf.CFNumberGetValue.argtypes = (pointer, ctypes.c_long, pointer)
        cf.CFNumberGetValue.restype = ctypes.c_ubyte
        cf.CFNumberCreate.argtypes = (pointer, ctypes.c_long, pointer)
        cf.CFNumberCreate.restype = pointer
        cf.CFGetTypeID.argtypes = (pointer,)
        cf.CFGetTypeID.restype = ctypes.c_ulong
        for name in (
            "CFDataGetTypeID",
            "CFDictionaryGetTypeID",
            "CFNumberGetTypeID",
            "CFStringGetTypeID",
            "CFURLGetTypeID",
        ):
            function = getattr(cf, name)
            function.argtypes = ()
            function.restype = ctypes.c_ulong
        cf.CFRelease.argtypes = (pointer,)
        cf.CFRelease.restype = None

        security.SecCodeCopyGuestWithAttributes.argtypes = (
            pointer,
            pointer,
            ctypes.c_uint32,
            ctypes.POINTER(pointer),
        )
        security.SecCodeCopyGuestWithAttributes.restype = ctypes.c_int32
        security.SecRequirementCreateWithString.argtypes = (
            pointer,
            ctypes.c_uint32,
            ctypes.POINTER(pointer),
        )
        security.SecRequirementCreateWithString.restype = ctypes.c_int32
        security.SecCodeCheckValidityWithErrors.argtypes = (
            pointer,
            ctypes.c_uint32,
            pointer,
            ctypes.POINTER(pointer),
        )
        security.SecCodeCheckValidityWithErrors.restype = ctypes.c_int32
        security.SecCodeCopySigningInformation.argtypes = (
            pointer,
            ctypes.c_uint32,
            ctypes.POINTER(pointer),
        )
        security.SecCodeCopySigningInformation.restype = ctypes.c_int32

        self.bsm.audit_token_to_pid.argtypes = (_AuditToken,)
        self.bsm.audit_token_to_pid.restype = ctypes.c_int
        self.bsm.audit_token_to_pidversion.argtypes = (_AuditToken,)
        self.bsm.audit_token_to_pidversion.restype = ctypes.c_int
        self.bsm.audit_token_to_euid.argtypes = (_AuditToken,)
        self.bsm.audit_token_to_euid.restype = ctypes.c_uint32
        self.proc.proc_pidpath_audittoken.argtypes = (
            ctypes.POINTER(_AuditToken),
            pointer,
            ctypes.c_uint32,
        )
        self.proc.proc_pidpath_audittoken.restype = ctypes.c_int
        self.proc.proc_pidpath.argtypes = (
            ctypes.c_int,
            pointer,
            ctypes.c_uint32,
        )
        self.proc.proc_pidpath.restype = ctypes.c_int

    def symbol(self, name: str) -> int:
        value = ctypes.c_void_p.in_dll(self.security, name).value
        if type(value) is not int or value <= 0:
            raise _IdentityBoundaryFailure
        return value

    def callback_address(self, name: str) -> int:
        value = (ctypes.c_ubyte * 1).in_dll(self.cf, name)
        address = ctypes.addressof(value)
        if address <= 0:
            raise _IdentityBoundaryFailure
        return address

    def require_type(self, value: int | None, expected_type: int) -> int:
        if type(value) is not int or value <= 0:
            raise _IdentityBoundaryFailure
        if self.cf.CFGetTypeID(value) != expected_type:
            raise _IdentityBoundaryFailure
        return value

    def read_string(
        self,
        value: int | None,
        *,
        buffer_bytes: int = _MAX_CODE_IDENTITY_TEXT_BYTES,
    ) -> str:
        selected = self.require_type(value, self.cf.CFStringGetTypeID())
        if type(buffer_bytes) is not int or buffer_bytes < 2:
            raise _IdentityBoundaryFailure
        buffer = ctypes.create_string_buffer(buffer_bytes)
        if not self.cf.CFStringGetCString(
            selected,
            buffer,
            len(buffer),
            _K_CF_STRING_ENCODING_UTF8,
        ):
            raise _IdentityBoundaryFailure
        try:
            return buffer.value.decode("utf-8")
        except UnicodeDecodeError:
            raise _IdentityBoundaryFailure from None

    def read_optional_string(self, value: int | None) -> str | None:
        if value is None:
            return None
        return self.read_string(value)

    def read_data(self, value: int | None) -> bytes:
        selected = self.require_type(value, self.cf.CFDataGetTypeID())
        length = self.cf.CFDataGetLength(selected)
        if length < 0 or length > _MAX_CODE_IDENTITY_TEXT_BYTES:
            raise _IdentityBoundaryFailure
        pointer = self.cf.CFDataGetBytePtr(selected)
        if length and not pointer:
            raise _IdentityBoundaryFailure
        return bytes(pointer[:length])

    def read_number(self, value: int | None) -> int:
        selected = self.require_type(value, self.cf.CFNumberGetTypeID())
        result = ctypes.c_longlong()
        if not self.cf.CFNumberGetValue(
            selected,
            _K_CF_NUMBER_SINT64_TYPE,
            ctypes.byref(result),
        ):
            raise _IdentityBoundaryFailure
        if result.value < 0 or result.value > _UINT32_MAX:
            raise _IdentityBoundaryFailure
        return result.value

    def read_url_path(self, value: int | None) -> str:
        selected = self.require_type(value, self.cf.CFURLGetTypeID())
        path = self.cf.CFURLCopyFileSystemPath(
            selected,
            _K_CF_URL_POSIX_PATH_STYLE,
        )
        if not path:
            raise _IdentityBoundaryFailure
        try:
            return self.read_string(
                path,
                buffer_bytes=_PROC_PIDPATHINFO_MAXSIZE,
            )
        finally:
            self.cf.CFRelease(path)


def _copy_dynamic_code_identity_from_attributes(
    *,
    bindings: _DarwinFrameworks,
    attributes: int,
    policy: _LocalDarwinProcessIdentityPolicy,
) -> tuple[str, str | None, str, int, int, str]:
    cf = bindings.cf
    security = bindings.security
    requirement_text: int | None = None
    requirement: int | None = None
    code: int | None = None
    validity_error: int | None = None
    information: int | None = None
    try:
        code_out = ctypes.c_void_p()
        if security.SecCodeCopyGuestWithAttributes(
            None,
            attributes,
            0,
            ctypes.byref(code_out),
        ) != 0 or not code_out.value:
            raise _IdentityBoundaryFailure
        code = code_out.value

        requirement_source = (
            f'identifier "{policy.expected_code_identifier}" and '
            f'cdhash H"{policy.expected_code_directory_hash}"'
        ).encode("ascii")
        requirement_text = cf.CFStringCreateWithCString(
            None,
            requirement_source,
            _K_CF_STRING_ENCODING_UTF8,
        )
        if not requirement_text:
            raise _IdentityBoundaryFailure
        requirement_out = ctypes.c_void_p()
        if security.SecRequirementCreateWithString(
            requirement_text,
            0,
            ctypes.byref(requirement_out),
        ) != 0 or not requirement_out.value:
            raise _IdentityBoundaryFailure
        requirement = requirement_out.value
        validity_error_out = ctypes.c_void_p()
        if security.SecCodeCheckValidityWithErrors(
            code,
            _K_SEC_CS_STRICT_VALIDATE,
            requirement,
            ctypes.byref(validity_error_out),
        ) != 0:
            validity_error = validity_error_out.value
            raise _IdentityBoundaryFailure
        if validity_error_out.value:
            validity_error = validity_error_out.value
            raise _IdentityBoundaryFailure

        information_out = ctypes.c_void_p()
        if security.SecCodeCopySigningInformation(
            code,
            _K_SEC_CS_SIGNING_INFORMATION | _K_SEC_CS_DYNAMIC_INFORMATION,
            ctypes.byref(information_out),
        ) != 0 or not information_out.value:
            raise _IdentityBoundaryFailure
        information = information_out.value
        information = bindings.require_type(
            information,
            cf.CFDictionaryGetTypeID(),
        )

        def item(name: str) -> int | None:
            return cf.CFDictionaryGetValue(information, bindings.symbol(name))

        identifier = bindings.read_string(item("kSecCodeInfoIdentifier"))
        team_identifier = bindings.read_optional_string(
            item("kSecCodeInfoTeamIdentifier")
        )
        cdhash_bytes = bindings.read_data(item("kSecCodeInfoUnique"))
        if len(cdhash_bytes) != _CODE_DIRECTORY_HASH_BYTES:
            raise _IdentityBoundaryFailure
        code_directory_hash = cdhash_bytes.hex()
        static_flags = bindings.read_number(item("kSecCodeInfoFlags"))
        dynamic_status = bindings.read_number(item("kSecCodeInfoStatus"))
        main_executable = bindings.read_url_path(
            item("kSecCodeInfoMainExecutable")
        )
        return (
            identifier,
            team_identifier,
            code_directory_hash,
            static_flags,
            dynamic_status,
            main_executable,
        )
    finally:
        for value in (
            information,
            validity_error,
            requirement,
            requirement_text,
            code,
        ):
            if value:
                try:
                    cf.CFRelease(value)
                except BaseException:
                    pass


def _read_dynamic_code_identity(
    *,
    bindings: _DarwinFrameworks,
    raw_audit_token: bytes,
    policy: _LocalDarwinProcessIdentityPolicy,
) -> tuple[str, str | None, str, int, int, str]:
    cf = bindings.cf
    audit_data: int | None = None
    attributes: int | None = None
    try:
        audit_array = (ctypes.c_ubyte * len(raw_audit_token)).from_buffer_copy(
            raw_audit_token
        )
        audit_data = cf.CFDataCreate(None, audit_array, len(raw_audit_token))
        if not audit_data:
            raise _IdentityBoundaryFailure
        attributes = cf.CFDictionaryCreateMutable(
            None,
            0,
            bindings.callback_address("kCFTypeDictionaryKeyCallBacks"),
            bindings.callback_address("kCFTypeDictionaryValueCallBacks"),
        )
        if not attributes:
            raise _IdentityBoundaryFailure
        cf.CFDictionarySetValue(
            attributes,
            bindings.symbol("kSecGuestAttributeAudit"),
            audit_data,
        )
        return _copy_dynamic_code_identity_from_attributes(
            bindings=bindings,
            attributes=attributes,
            policy=policy,
        )
    finally:
        for value in (attributes, audit_data):
            if value:
                try:
                    cf.CFRelease(value)
                except BaseException:
                    pass


def _read_dynamic_code_identity_for_pid(
    *,
    bindings: _DarwinFrameworks,
    process_id: int,
    policy: _LocalDarwinProcessIdentityPolicy,
) -> tuple[str, str | None, str, int, int, str]:
    cf = bindings.cf
    pid_number: int | None = None
    attributes: int | None = None
    try:
        pid_value = ctypes.c_longlong(process_id)
        pid_number = cf.CFNumberCreate(
            None,
            _K_CF_NUMBER_SINT64_TYPE,
            ctypes.byref(pid_value),
        )
        if not pid_number:
            raise _IdentityBoundaryFailure
        attributes = cf.CFDictionaryCreateMutable(
            None,
            0,
            bindings.callback_address("kCFTypeDictionaryKeyCallBacks"),
            bindings.callback_address("kCFTypeDictionaryValueCallBacks"),
        )
        if not attributes:
            raise _IdentityBoundaryFailure
        cf.CFDictionarySetValue(
            attributes,
            bindings.symbol("kSecGuestAttributePid"),
            pid_number,
        )
        return _copy_dynamic_code_identity_from_attributes(
            bindings=bindings,
            attributes=attributes,
            policy=policy,
        )
    finally:
        for value in (attributes, pid_number):
            if value:
                try:
                    cf.CFRelease(value)
                except BaseException:
                    pass


def _observe_running_code_by_pid(
    *,
    expected_process_id: int,
    policy: _LocalDarwinProcessIdentityPolicy,
) -> _ObservedRunningCode:
    """Observe a live PID before audit-token generation binding.

    The caller must own a suspended spawn and later bind this PID to a kernel
    audit token.  This preliminary check alone is never a reusable identity
    authority.
    """

    if sys.platform != "darwin":
        raise _IdentityBoundaryFailure
    process_id = require_plain_int(
        expected_process_id,
        "expected_process_id",
        minimum=1,
    )
    policy.validate_integrity()
    bindings = _DarwinFrameworks()
    executable_buffer = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
    executable_length = bindings.proc.proc_pidpath(
        process_id,
        executable_buffer,
        len(executable_buffer),
    )
    if executable_length <= 0 or executable_length > _MAX_EXECUTABLE_PATH_BYTES:
        raise _IdentityBoundaryFailure
    raw_executable = bytes(executable_buffer.raw[:executable_length])
    if not raw_executable or b"\x00" in raw_executable:
        raise _IdentityBoundaryFailure
    try:
        executable = os.fsdecode(raw_executable)
    except UnicodeError:
        raise _IdentityBoundaryFailure from None
    (
        identifier,
        team_identifier,
        code_directory_hash,
        static_flags,
        dynamic_status,
        security_executable,
    ) = _read_dynamic_code_identity_for_pid(
        bindings=bindings,
        process_id=process_id,
        policy=policy,
    )
    if (
        executable != policy.expected_executable
        or security_executable != executable
        or identifier != policy.expected_code_identifier
        or team_identifier != policy.expected_team_identifier
        or code_directory_hash != policy.expected_code_directory_hash
        or bool(static_flags & _CS_ADHOC) is not policy.expected_adhoc
        or static_flags & policy.required_static_code_flags
        != policy.required_static_code_flags
        or static_flags & policy.forbidden_static_code_flags
        or dynamic_status & policy.required_dynamic_code_status
        != policy.required_dynamic_code_status
        or dynamic_status & policy.forbidden_dynamic_code_status
    ):
        raise _IdentityBoundaryFailure
    return _ObservedRunningCode(
        process_id=process_id,
        executable=executable,
        code_identifier=identifier,
        team_identifier=team_identifier,
        code_directory_hash=code_directory_hash,
        static_code_flags=static_flags,
        dynamic_code_status=dynamic_status,
    )


def _copy_process_audit_token(*, expected_process_id: int) -> bytes:
    """Copy the kernel audit token for one exact live process.

    The temporary task-name right is always deallocated before return.  The
    returned token remains opaque; callers may compare exact bytes and pass it
    back to kernel APIs, but must not infer its private field layout.
    """

    if sys.platform != "darwin":
        raise _IdentityBoundaryFailure
    process_id = require_plain_int(
        expected_process_id,
        "expected_process_id",
        minimum=1,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mach_task_self.argtypes = ()
    libc.mach_task_self.restype = ctypes.c_uint32
    libc.task_name_for_pid.argtypes = (
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
    )
    libc.task_name_for_pid.restype = ctypes.c_int
    libc.task_info.argtypes = (
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    )
    libc.task_info.restype = ctypes.c_int
    libc.mach_port_deallocate.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
    libc.mach_port_deallocate.restype = ctypes.c_int

    self_task = libc.mach_task_self()
    task_name = ctypes.c_uint32(0)
    if (
        type(self_task) is not int
        or self_task <= 0
        or libc.task_name_for_pid(
            self_task,
            process_id,
            ctypes.byref(task_name),
        )
        != 0
        or task_name.value == 0
    ):
        raise _IdentityBoundaryFailure
    try:
        token_words = (ctypes.c_uint32 * 8)()
        token_word_count = ctypes.c_uint32(len(token_words))
        if (
            libc.task_info(
                task_name.value,
                15,  # TASK_AUDIT_TOKEN
                token_words,
                ctypes.byref(token_word_count),
            )
            != 0
            or token_word_count.value != len(token_words)
        ):
            raise _IdentityBoundaryFailure
        raw_token = bytes(token_words)
        bindings = _DarwinFrameworks()
        token = _AuditToken.from_buffer_copy(raw_token)
        if (
            bindings.bsm.audit_token_to_pid(token) != process_id
            or bindings.bsm.audit_token_to_pidversion(token) <= 0
        ):
            raise _IdentityBoundaryFailure
        return raw_token
    finally:
        if libc.mach_port_deallocate(self_task, task_name.value) != 0:
            raise _IdentityBoundaryFailure


def _signal_process_with_audit_token(
    *,
    raw_audit_token: bytes,
    signal_number: int,
) -> None:
    """Send one generation-bound lifecycle signal through libproc."""

    if sys.platform != "darwin":
        raise _IdentityBoundaryFailure
    if type(raw_audit_token) is not bytes or len(raw_audit_token) != 32:
        raise _IdentityBoundaryFailure
    if signal_number not in (signal.SIGCONT, signal.SIGKILL):
        raise _IdentityBoundaryFailure
    bindings = _DarwinFrameworks()
    token = _AuditToken.from_buffer_copy(raw_audit_token)
    bindings.proc.proc_signal_with_audittoken.argtypes = (
        ctypes.POINTER(_AuditToken),
        ctypes.c_int,
    )
    bindings.proc.proc_signal_with_audittoken.restype = ctypes.c_int
    if (
        bindings.proc.proc_signal_with_audittoken(
            ctypes.byref(token),
            signal_number,
        )
        != 0
    ):
        raise _IdentityBoundaryFailure


def _observe_connected_process(
    *,
    peer_socket: socket.socket,
    expected_process_id: int,
    policy: _LocalDarwinProcessIdentityPolicy,
) -> _ObservedIdentity:
    if sys.platform != "darwin":
        raise _IdentityBoundaryFailure
    if type(peer_socket) is not socket.socket:
        raise _IdentityBoundaryFailure
    if (
        peer_socket.family != socket.AF_UNIX
        or peer_socket.type != socket.SOCK_STREAM
        or peer_socket.fileno() < 0
    ):
        raise _IdentityBoundaryFailure
    process_id = require_plain_int(
        expected_process_id,
        "expected_process_id",
        minimum=1,
    )
    policy.validate_integrity()

    kernel_peer_pid = peer_socket.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID)
    raw_token = peer_socket.getsockopt(
        _SOL_LOCAL,
        _LOCAL_PEERTOKEN,
        _AUDIT_TOKEN_BYTES,
    )
    if (
        type(kernel_peer_pid) is not int
        or kernel_peer_pid != process_id
        or type(raw_token) is not bytes
        or len(raw_token) != _AUDIT_TOKEN_BYTES
    ):
        raise _IdentityBoundaryFailure

    bindings = _DarwinFrameworks()
    token = _AuditToken.from_buffer_copy(raw_token)
    audit_process_id = bindings.bsm.audit_token_to_pid(token)
    process_version = bindings.bsm.audit_token_to_pidversion(token)
    effective_user_id = bindings.bsm.audit_token_to_euid(token)
    if (
        audit_process_id != process_id
        or type(process_version) is not int
        or process_version <= 0
        or effective_user_id != policy.expected_effective_user_id
    ):
        raise _IdentityBoundaryFailure

    executable_buffer = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
    executable_length = bindings.proc.proc_pidpath_audittoken(
        ctypes.byref(token),
        executable_buffer,
        len(executable_buffer),
    )
    if executable_length <= 0 or executable_length > _MAX_EXECUTABLE_PATH_BYTES:
        raise _IdentityBoundaryFailure
    raw_executable = bytes(executable_buffer.raw[:executable_length])
    if not raw_executable or b"\x00" in raw_executable:
        raise _IdentityBoundaryFailure
    try:
        executable = os.fsdecode(raw_executable)
    except UnicodeError:
        raise _IdentityBoundaryFailure from None
    if executable != policy.expected_executable:
        raise _IdentityBoundaryFailure

    (
        identifier,
        team_identifier,
        code_directory_hash,
        static_flags,
        dynamic_status,
        security_executable,
    ) = _read_dynamic_code_identity(
        bindings=bindings,
        raw_audit_token=raw_token,
        policy=policy,
    )
    if (
        security_executable != executable
        or identifier != policy.expected_code_identifier
        or team_identifier != policy.expected_team_identifier
        or code_directory_hash != policy.expected_code_directory_hash
        or bool(static_flags & _CS_ADHOC) is not policy.expected_adhoc
        or static_flags & policy.required_static_code_flags
        != policy.required_static_code_flags
        or static_flags & policy.forbidden_static_code_flags
        or dynamic_status & policy.required_dynamic_code_status
        != policy.required_dynamic_code_status
        or dynamic_status & policy.forbidden_dynamic_code_status
    ):
        raise _IdentityBoundaryFailure

    return _ObservedIdentity(
        process_id=process_id,
        process_version=process_version,
        effective_user_id=effective_user_id,
        executable=executable,
        code_identifier=identifier,
        team_identifier=team_identifier,
        code_directory_hash=code_directory_hash,
        static_code_flags=static_flags,
        dynamic_code_status=dynamic_status,
        audit_token_digest=digest256(
            "DarwinAuditToken",
            DARWIN_PROCESS_IDENTITY_ATTESTATION_SCHEMA_VERSION,
            {"opaque_token_hex": raw_token.hex()},
        ),
    )


def _attest_darwin_connection_peer(
    *,
    peer_socket: socket.socket,
    expected_process_id: int,
    policy: _LocalDarwinProcessIdentityPolicy,
) -> _DarwinConnectionPeerIdentityAttestation:
    """Attest the process generation that connected ``peer_socket``.

    The caller retains ownership of the accepted socket.  All framework
    objects are released before this function returns or raises.
    """

    if type(policy) is not _LocalDarwinProcessIdentityPolicy:
        raise TypeError("policy must be LocalDarwinProcessIdentityPolicy")
    try:
        observed = _observe_connected_process(
            peer_socket=peer_socket,
            expected_process_id=expected_process_id,
            policy=policy,
        )
        return _DarwinConnectionPeerIdentityAttestation(
            observed=observed,
            policy=policy,
            _authority=_ATTESTATION_AUTHORITY,
        )
    except BaseException:
        _raise_identity_error()
