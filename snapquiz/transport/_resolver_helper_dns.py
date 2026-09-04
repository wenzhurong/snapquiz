"""Strict local W09-B2b-S5 resolver-helper/DNS foundation.

This private module is intentionally self-contained and production-unwired.
It models the code that belongs in the eventual signed resolver executable:
one fixed READY, one ``AF_UNIX/SOCK_DGRAM`` START record received by one
``recvmsg`` call, one ``getaddrinfo`` call, and one bounded canonical RESULT.

The implementation is useful local evidence, but it is still Python code.  It
does not attest a bundled Team-signed Mach-O, native atomic process ownership,
or durable RESULT delivery acknowledgement.  In particular, the current S4
stream reader can lose bytes if an asynchronous exception lands after a
destructive child read and before the caller stores the return value.  The
production availability gate below therefore remains hard false.

Only Python's standard library is imported so starting this helper cannot
pull credential, request-body, provider, HTTP, or application modules into
the isolated process.
"""
from __future__ import annotations

import hashlib
from ipaddress import AddressValueError, IPv4Address, IPv6Address
import json
import os
import re
import select
import socket
import sys
from threading import Event, Thread
from typing import Callable, NamedTuple, NoReturn
from uuid import UUID


__all__ = ()


RESOLVER_HELPER_DNS_FOUNDATION_SCHEMA_VERSION = (
    "snapquiz.resolver-helper-dns-foundation.v1"
)
RESOLVER_HELPER_PROTOCOL_FLAG = "--snapquiz-resolver-helper-v2"
RESOLVER_HELPER_START_SCHEMA_VERSION = "snapquiz.resolver-start.v2"
RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION = (
    "snapquiz.raw-resolution-transcript.v2"
)
READY_FRAME = b"SNAPQUIZ-RESOLVER/2 READY\n"
MAX_START_FRAME_BYTES = 4_096
MAX_RESULT_TRANSCRIPT_BYTES = 16_384
MAX_RESULT_CANDIDATES = 32
MAX_SAFE_STDERR_BYTES = 4_096

# These values deliberately duplicate the frozen cross-process protocol.  A
# parity test against the application contracts makes any drift fail closed.
INTERNET_PUBLIC_ADDRESS_POLICY_REF = (
    "snapquiz.internet-public-address-policy.iana-2025-10-09.v1"
)
INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST = (
    "721939766c8857b23b1c079b1010e092b223835e490255466c7c47083d0b67a4"
)
NETWORK_POLICY_VERSION = "remote-https.v1"

_CANONICAL_SERIALIZER_VERSION = "snapquiz.canonical-json.v1"
_START_DIGEST_TYPE_TAG = "ResolverStartFrame"
_DIGEST_PROTOCOL_TAG = b"snapquiz.digest.v1"
_SAFE_ERROR_FRAME = b"SNAPQUIZ-RESOLVER/2 ERROR\n"
_HELPER_FAILURE_STATUS = 70
_HELPER_LIVENESS_STATUS = 71
_ANCILLARY_BUFFER_BYTES = 256
_LOWER_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_DNS_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_START_KEYS = frozenset(
    {
        "attempt_permit_digest",
        "attempt_permit_id",
        "dns_start_id",
        "hostname",
        "kind",
        "network_policy_digest",
        "network_policy_ref",
        "port",
        "schema_version",
        "terminal_guard_digest",
        "terminal_guard_id",
        "transport_claim_id",
    }
)
_GETADDRINFO_FLAGS = 0

# A local protocol implementation is not a production authorization fact.
_NATIVE_HELPER_IDENTITY_ATTESTED = False
_DURABLE_RESULT_DELIVERY_ACK_ATTESTED = False
_NATIVE_LIVENESS_OWNER_ATTESTED = False
_PRODUCTION_AVAILABLE = False


class _ResolverHelperDnsFailure(Exception):
    """Content-free helper failure marker."""

    __slots__ = ()


class _ParsedStart(NamedTuple):
    attempt_permit_digest: str
    attempt_permit_id: str
    dns_start_id: str
    hostname: str
    port: int
    terminal_guard_digest: str
    terminal_guard_id: str
    transport_claim_id: str
    start_frame_digest: str


def _raise_helper_failure() -> NoReturn:
    error = _ResolverHelperDnsFailure()
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    selected: dict[str, object] = {}
    for key, value in pairs:
        if key in selected:
            _raise_helper_failure()
        selected[key] = value
    return selected


def _reject_json_number(value: str) -> object:
    del value
    _raise_helper_failure()


def _parse_json_int(value: str) -> int:
    if len(value) > 5:
        _raise_helper_failure()
    try:
        return int(value)
    except (TypeError, ValueError):
        _raise_helper_failure()


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _raise_helper_failure()


def _exact_start_frame_digest(frame: bytes) -> str:
    """Mirror ``resolver.start_frame_digest`` without importing the app."""

    exact_payload = _canonical_json_bytes(
        {
            "byte_size": len(frame),
            "sha256": hashlib.sha256(frame).hexdigest(),
        }
    )
    parts = (
        _DIGEST_PROTOCOL_TAG,
        _START_DIGEST_TYPE_TAG.encode("ascii"),
        RESOLVER_HELPER_START_SCHEMA_VERSION.encode("ascii"),
        _CANONICAL_SERIALIZER_VERSION.encode("ascii"),
        exact_payload,
    )
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, byteorder="big", signed=False))
        digest.update(part)
    return digest.hexdigest()


def _canonical_uuid(value: object) -> str:
    if type(value) is not str:
        _raise_helper_failure()
    try:
        selected = str(UUID(value))
    except (AttributeError, TypeError, ValueError):
        _raise_helper_failure()
    if selected != value:
        _raise_helper_failure()
    return value


def _lower_digest(value: object) -> str:
    if type(value) is not str or _LOWER_DIGEST_RE.fullmatch(value) is None:
        _raise_helper_failure()
    return value


def _parse_start_frame(frame: bytes) -> _ParsedStart:
    if (
        type(frame) is not bytes
        or not frame
        or len(frame) > MAX_START_FRAME_BYTES
        or not frame.endswith(b"\n")
        or b"\n" in frame[:-1]
        or b"\r" in frame
    ):
        _raise_helper_failure()
    transcript = frame[:-1]
    if not transcript:
        _raise_helper_failure()
    try:
        parsed = json.loads(
            transcript.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_int=_parse_json_int,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except _ResolverHelperDnsFailure:
        raise
    except BaseException:
        _raise_helper_failure()
    if (
        type(parsed) is not dict
        or set(parsed) != _START_KEYS
        or _canonical_json_bytes(parsed) + b"\n" != frame
        or parsed["kind"] != "START"
        or parsed["schema_version"]
        != RESOLVER_HELPER_START_SCHEMA_VERSION
        or parsed["network_policy_ref"]
        != INTERNET_PUBLIC_ADDRESS_POLICY_REF
        or parsed["network_policy_digest"]
        != INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST
    ):
        _raise_helper_failure()
    hostname = parsed["hostname"]
    port = parsed["port"]
    if (
        type(hostname) is not str
        or hostname != hostname.lower()
        or _DNS_HOST_RE.fullmatch(hostname) is None
        or type(port) is not int
        or not 1 <= port <= 65_535
    ):
        _raise_helper_failure()
    return _ParsedStart(
        attempt_permit_digest=_lower_digest(parsed["attempt_permit_digest"]),
        attempt_permit_id=_canonical_uuid(parsed["attempt_permit_id"]),
        dns_start_id=_canonical_uuid(parsed["dns_start_id"]),
        hostname=hostname,
        port=port,
        terminal_guard_digest=_lower_digest(parsed["terminal_guard_digest"]),
        terminal_guard_id=_canonical_uuid(parsed["terminal_guard_id"]),
        transport_claim_id=_canonical_uuid(parsed["transport_claim_id"]),
        start_frame_digest=_exact_start_frame_digest(frame),
    )


def _socket_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _raw_candidate(
    value: object,
    *,
    expected_port: int,
) -> dict[str, object]:
    if type(value) is not tuple or len(value) != 5:
        _raise_helper_failure()
    family, socket_type, protocol, canonical_name, sockaddr = value
    if (
        not _socket_integer(family)
        or family not in (socket.AF_INET, socket.AF_INET6)
        or not _socket_integer(socket_type)
        or socket_type != socket.SOCK_STREAM
        or not _socket_integer(protocol)
        or protocol != socket.IPPROTO_TCP
        or canonical_name != ""
        or type(canonical_name) is not str
        or type(sockaddr) is not tuple
    ):
        _raise_helper_failure()
    if family == socket.AF_INET:
        if len(sockaddr) != 2:
            _raise_helper_failure()
        address, port = sockaddr
        if type(address) is not str or "%" in address:
            _raise_helper_failure()
        try:
            parsed_address: IPv4Address | IPv6Address = IPv4Address(address)
        except (AddressValueError, ValueError):
            _raise_helper_failure()
        if str(parsed_address) != address:
            _raise_helper_failure()
        candidate = {
            "address": address,
            "family": "AF_INET",
            "port": port,
            "protocol": "IPPROTO_TCP",
            "socket_type": "SOCK_STREAM",
        }
    else:
        if len(sockaddr) != 4:
            _raise_helper_failure()
        address, port, flowinfo, scope_id = sockaddr
        if (
            type(address) is not str
            or "%" in address
            or type(flowinfo) is not int
            or flowinfo != 0
            or type(scope_id) is not int
            or scope_id != 0
        ):
            _raise_helper_failure()
        try:
            parsed_address = IPv6Address(address)
        except (AddressValueError, ValueError):
            _raise_helper_failure()
        if str(parsed_address) != address:
            _raise_helper_failure()
        candidate = {
            "address": address,
            "family": "AF_INET6",
            "flowinfo": flowinfo,
            "port": port,
            "protocol": "IPPROTO_TCP",
            "scope_id": scope_id,
            "socket_type": "SOCK_STREAM",
        }
    if type(port) is not int or port != expected_port:
        _raise_helper_failure()
    return candidate


def _resolve_start_frame(
    frame: bytes,
    *,
    getaddrinfo_call: Callable[..., object],
) -> bytes:
    """Resolve once and return canonical RESULT bytes without their LF."""

    if not callable(getaddrinfo_call):
        raise TypeError("getaddrinfo_call must be callable")
    start = _parse_start_frame(frame)
    try:
        raw_results = getaddrinfo_call(
            start.hostname,
            start.port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            _GETADDRINFO_FLAGS,
        )
    except BaseException:
        _raise_helper_failure()
    if (
        type(raw_results) is not list
        or not 1 <= len(raw_results) <= MAX_RESULT_CANDIDATES
    ):
        _raise_helper_failure()
    candidates = [
        _raw_candidate(value, expected_port=start.port)
        for value in raw_results
    ]
    transcript = _canonical_json_bytes(
        {
            "address_policy_digest": INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
            "address_policy_ref": INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            "attempt_permit_digest": start.attempt_permit_digest,
            "attempt_permit_id": start.attempt_permit_id,
            "candidates": candidates,
            "canonical_hostname": start.hostname,
            "dns_start_id": start.dns_start_id,
            "kind": "RESULT",
            "network_policy_version": NETWORK_POLICY_VERSION,
            "port": start.port,
            "schema_version": RAW_RESOLUTION_TRANSCRIPT_SCHEMA_VERSION,
            "start_frame_digest": start.start_frame_digest,
            "status": "ok",
            "terminal_guard_digest": start.terminal_guard_digest,
            "terminal_guard_id": start.terminal_guard_id,
            "transport_claim_id": start.transport_claim_id,
        }
    )
    if (
        not transcript
        or len(transcript) > MAX_RESULT_TRANSCRIPT_BYTES
        or b"\n" in transcript
        or b"\r" in transcript
    ):
        _raise_helper_failure()
    return transcript


def _receive_start_frame_once(channel: object) -> bytes:
    recvmsg = getattr(channel, "recvmsg", None)
    if not callable(recvmsg):
        _raise_helper_failure()
    try:
        selected = recvmsg(
            MAX_START_FRAME_BYTES + 1,
            _ANCILLARY_BUFFER_BYTES,
        )
    except BaseException:
        _raise_helper_failure()
    if type(selected) is not tuple or len(selected) != 4:
        _raise_helper_failure()
    frame, ancillary, message_flags, peer = selected
    del peer
    truncation_flags = socket.MSG_TRUNC | socket.MSG_CTRUNC
    if (
        type(frame) is not bytes
        or not frame
        or len(frame) > MAX_START_FRAME_BYTES
        or type(ancillary) is not list
        or ancillary
        or not _socket_integer(message_flags)
        or message_flags & truncation_flags
    ):
        _raise_helper_failure()
    return frame


def _validate_control_channel(channel: socket.socket) -> None:
    try:
        if (
            type(channel) is not socket.socket
            or channel.fileno() != 0
            or channel.family != socket.AF_UNIX
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            != socket.SOCK_DGRAM
        ):
            _raise_helper_failure()
        channel.getpeername()
    except _ResolverHelperDnsFailure:
        raise
    except BaseException:
        _raise_helper_failure()


def _start_control_liveness_watch(channel: socket.socket) -> Thread:
    """Exit if the supervisor endpoint dies or sends a second record."""

    started = Event()

    def watch() -> None:
        try:
            poller = select.poll()
            poller.register(
                channel.fileno(),
                select.POLLIN
                | select.POLLHUP
                | select.POLLERR
                | select.POLLNVAL,
            )
            started.set()
            while True:
                try:
                    events = poller.poll()
                except InterruptedError:
                    continue
                if events:
                    os._exit(_HELPER_LIVENESS_STATUS)
        except BaseException:
            os._exit(_HELPER_LIVENESS_STATUS)

    thread = Thread(
        target=watch,
        daemon=True,
        name="snapquiz-resolver-control-liveness",
    )
    try:
        thread.start()
        if not started.wait(1.0):
            _raise_helper_failure()
    except _ResolverHelperDnsFailure:
        raise
    except BaseException:
        _raise_helper_failure()
    return thread


def _write_all(fd: int, payload: bytes) -> None:
    if type(fd) is not int or fd < 0 or type(payload) is not bytes:
        _raise_helper_failure()
    view = memoryview(payload)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        except BaseException:
            _raise_helper_failure()
        if type(written) is not int or written <= 0 or written > len(view):
            _raise_helper_failure()
        view = view[written:]


def _write_safe_error(stderr_fd: int) -> None:
    if len(_SAFE_ERROR_FRAME) > MAX_SAFE_STDERR_BYTES:
        return
    try:
        _write_all(stderr_fd, _SAFE_ERROR_FRAME)
    except BaseException:
        pass


def _run_helper(
    *,
    argv: tuple[str, ...],
    getaddrinfo_call: Callable[..., object] = socket.getaddrinfo,
    stdout_fd: int = 1,
    stderr_fd: int = 2,
) -> int:
    """Run one local helper lifecycle and return a content-free status."""

    channel: socket.socket | None = None
    try:
        if argv != (RESOLVER_HELPER_PROTOCOL_FLAG,):
            _raise_helper_failure()
        channel = socket.socket(fileno=0)
        _validate_control_channel(channel)
        _write_all(stdout_fd, READY_FRAME)
        frame = _receive_start_frame_once(channel)
        _start_control_liveness_watch(channel)
        transcript = _resolve_start_frame(
            frame,
            getaddrinfo_call=getaddrinfo_call,
        )
        _write_all(stdout_fd, transcript + b"\n")
        try:
            os.close(stdout_fd)
        except BaseException:
            _raise_helper_failure()
        return 0
    except BaseException:
        _write_safe_error(stderr_fd)
        return _HELPER_FAILURE_STATUS
    finally:
        if channel is not None:
            try:
                channel.detach()
            except BaseException:
                pass


def _production_availability() -> dict[str, bool | str]:
    """Expose only explicit, non-authoritative local foundation facts."""

    return {
        "durable_result_delivery_ack_attested": (
            _DURABLE_RESULT_DELIVERY_ACK_ATTESTED
        ),
        "local_dns_contract_available": True,
        "native_helper_identity_attested": _NATIVE_HELPER_IDENTITY_ATTESTED,
        "native_liveness_owner_attested": _NATIVE_LIVENESS_OWNER_ATTESTED,
        "network_connect_available": False,
        "production_available": _PRODUCTION_AVAILABLE,
        "schema_version": RESOLVER_HELPER_DNS_FOUNDATION_SCHEMA_VERSION,
    }


def _main() -> NoReturn:
    status = _run_helper(argv=tuple(sys.argv[1:]))
    os._exit(status)


if __name__ == "__main__":
    _main()
