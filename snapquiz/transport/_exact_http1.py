"""Exact, network-free HTTP/1.1 codec for the W09-B3 transport.

The module deliberately owns no socket and performs no DNS, TLS, credential
lookup, or environment read.  It turns one already-authorized
``PreparedOutbound`` plus a borrowed bearer-token view into deterministic
HTTP/1.1 bytes, and incrementally validates exactly one bounded response.

Connection establishment, TLS policy, AttemptGate wire commitment, deadline
polling, and cleanup remain separate owners.  In particular, EOF never
delimits a response body here: a response must carry one exact Content-Length
or the narrowly frozen chunked framing.
"""
from __future__ import annotations

from enum import Enum
import hashlib
import re
from typing import Callable, NoReturn, TypeVar
from urllib.parse import urlsplit

from snapquiz.domain._validation import runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.domain.outbound import NonSecretHeader, PreparedOutbound


__all__ = ()


EXACT_HTTP1_POLICY_VERSION = "snapquiz.http1.exact-single-request.v1"
EXACT_HTTP1_POLICY_SCHEMA_VERSION = "snapquiz.http1.exact-policy.v1"
EXACT_HTTP1_RESPONSE_SCHEMA_VERSION = "snapquiz.http1.exact-response.v1"
MAX_HTTP_REQUEST_BODY_BYTES = 8 * 1024 * 1024
MAX_HTTP_RESPONSE_BODY_BYTES = 2 * 1024 * 1024
MAX_HTTP_HEADER_BYTES = 64 * 1024
MAX_HTTP_HEADER_FIELDS = 128
MAX_HTTP_LINE_BYTES = 8 * 1024
MAX_HTTP_CHUNKS = 4_096
MAX_HTTP_CHUNK_METADATA_BYTES = 64 * 1024
MAX_BEARER_TOKEN_BYTES = 4_096


_TOKEN_RE = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_STATUS_LINE_RE = re.compile(rb"HTTP/1\.1 ([0-9]{3})(?: ([\x20-\x7e]*))?\Z")
_CHUNK_SIZE_RE = re.compile(rb"[0-9A-Fa-f]+\Z")
_HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\Z")
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "accept-encoding",
        "authorization",
        "connection",
        "content-encoding",
        "content-length",
        "content-type",
        "expect",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_PENDING = object()
_FAILED = object()
_RESPONSE_AUTHORITY = object()
_ResultT = TypeVar("_ResultT")
_BEARER_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/-"
)


def _compiled_regex_payload(value: object) -> dict[str, object]:
    if type(value) is not re.Pattern:
        raise ValueError("exact HTTP/1.1 regex must be a compiled pattern")
    pattern = value.pattern
    flags = value.flags
    if type(pattern) is bytes:
        pattern_kind = "bytes"
        exact_pattern = pattern.hex()
    elif type(pattern) is str:
        pattern_kind = "text"
        exact_pattern = pattern
    else:
        raise ValueError("exact HTTP/1.1 regex pattern type is invalid")
    if type(flags) is not int or flags < 0:
        raise ValueError("exact HTTP/1.1 regex flags are invalid")
    return {
        "flags": flags,
        "pattern": exact_pattern,
        "pattern_kind": pattern_kind,
    }


def _exact_http1_policy_payload() -> dict[str, object]:
    limits = {
        "MAX_BEARER_TOKEN_BYTES": MAX_BEARER_TOKEN_BYTES,
        "MAX_HTTP_CHUNK_METADATA_BYTES": MAX_HTTP_CHUNK_METADATA_BYTES,
        "MAX_HTTP_CHUNKS": MAX_HTTP_CHUNKS,
        "MAX_HTTP_HEADER_BYTES": MAX_HTTP_HEADER_BYTES,
        "MAX_HTTP_HEADER_FIELDS": MAX_HTTP_HEADER_FIELDS,
        "MAX_HTTP_LINE_BYTES": MAX_HTTP_LINE_BYTES,
        "MAX_HTTP_REQUEST_BODY_BYTES": MAX_HTTP_REQUEST_BODY_BYTES,
        "MAX_HTTP_RESPONSE_BODY_BYTES": MAX_HTTP_RESPONSE_BODY_BYTES,
    }
    if (
        type(EXACT_HTTP1_POLICY_VERSION) is not str
        or not EXACT_HTTP1_POLICY_VERSION
        or any(type(value) is not int or value < 1 for value in limits.values())
    ):
        raise ValueError("exact HTTP/1.1 policy constants are invalid")
    return {
        "limits": limits,
        "policy_version": EXACT_HTTP1_POLICY_VERSION,
        "regex_contracts": {
            "_CHUNK_SIZE_RE": _compiled_regex_payload(_CHUNK_SIZE_RE),
            "_HOST_RE": _compiled_regex_payload(_HOST_RE),
            "_STATUS_LINE_RE": _compiled_regex_payload(_STATUS_LINE_RE),
            "_TOKEN_RE": _compiled_regex_payload(_TOKEN_RE),
        },
        "request_policy": {
            "accept_encoding": "identity",
            "authorization_scheme": "Bearer",
            "bearer_alphabet": "".join(
                chr(value) for value in sorted(_BEARER_BYTES)
            ),
            "canonical_target": "https-origin-form-port-443",
            "connection": "close",
            "forbidden_headers": tuple(sorted(_FORBIDDEN_REQUEST_HEADERS)),
            "method": "POST",
            "single_request": True,
        },
        "response_policy": {
            "accepted_protocol": "HTTP/1.1",
            "body_framing": ("content-length", "chunked"),
            "chunk_extensions": False,
            "close_delimited_body": False,
            "content_encoding": False,
            "interim_responses": False,
            "redirect_following": False,
            "single_response": True,
            "trailers": False,
        },
    }


EXACT_HTTP1_POLICY_DIGEST = digest256(
    "ExactHttp1Policy",
    EXACT_HTTP1_POLICY_SCHEMA_VERSION,
    _exact_http1_policy_payload(),
)
_ISSUED_EXACT_HTTP1_POLICY_DIGEST = EXACT_HTTP1_POLICY_DIGEST


class _ParserState(str, Enum):
    HEADERS = "headers"
    CONTENT_LENGTH = "content_length"
    CHUNK_SIZE = "chunk_size"
    CHUNK_DATA = "chunk_data"
    CHUNK_TERMINATOR = "chunk_terminator"
    FINAL_CHUNK = "final_chunk"
    COMPLETE = "complete"
    FAILED = "failed"


def _http_error(
    safe_message: str = "HTTP/1.1 响应未通过安全策略。",
) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="http1_transport",
        retryable=False,
        safe_message=safe_message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_http_error(
    safe_message: str = "HTTP/1.1 响应未通过安全策略。",
) -> NoReturn:
    raise _http_error(safe_message) from None


def _require_exact_http1_policy_digest() -> Digest256:
    """Return the frozen content binding or fail closed on module drift."""

    selected: Digest256 | None = None
    try:
        selected = digest256(
            "ExactHttp1Policy",
            EXACT_HTTP1_POLICY_SCHEMA_VERSION,
            _exact_http1_policy_payload(),
        )
    except BaseException:
        pass
    if (
        type(selected) is not Digest256
        or type(EXACT_HTTP1_POLICY_DIGEST) is not Digest256
        or type(_ISSUED_EXACT_HTTP1_POLICY_DIGEST) is not Digest256
        or selected != EXACT_HTTP1_POLICY_DIGEST
        or selected != _ISSUED_EXACT_HTTP1_POLICY_DIGEST
    ):
        _raise_http_error("HTTP/1.1 策略绑定无效。")
    return selected


def _ascii_bytes(value: object, name: str, *, maximum: int) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise ValueError(f"{name} must be bounded non-empty text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be ASCII") from None
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise ValueError(f"{name} contains an invalid byte")
    return encoded


def _canonical_https_target(prepared: PreparedOutbound) -> tuple[bytes, bytes]:
    try:
        prepared.validate_integrity()
        split = urlsplit(prepared.canonical_url)
        hostname = split.hostname
        port = split.port
    except (AttributeError, TypeError, ValueError):
        raise ValueError("prepared outbound URL is invalid") from None
    if (
        split.scheme != "https"
        or type(hostname) is not str
        or not hostname
        or hostname != hostname.lower()
        or _HOST_RE.fullmatch(hostname) is None
        or split.username is not None
        or split.password is not None
        or split.fragment
        or split.query
        or port not in (None, 443)
        or split.netloc not in (hostname, f"{hostname}:443")
        or not split.path.startswith("/")
        or "//" in split.path[:2]
    ):
        raise ValueError("prepared outbound must use one canonical HTTPS origin")
    authority = _ascii_bytes(hostname, "hostname", maximum=253)
    target = _ascii_bytes(split.path, "origin target", maximum=MAX_HTTP_LINE_BYTES)
    if b" " in target or b"#" in target or b"?" in target:
        raise ValueError("origin target is not canonical")
    return authority, target


def _validate_borrowed_bearer(value: object) -> int:
    if type(value) is not memoryview:
        raise TypeError("bearer_token must be an exact memoryview")
    if (
        value.ndim != 1
        or value.itemsize != 1
        or value.format != "B"
        or not value.c_contiguous
        or not value.readonly
        or type(value.obj) is not bytearray
    ):
        raise ValueError("bearer_token must be a readonly mutable-backed byte view")
    size = value.nbytes
    if (
        not 1 <= size <= MAX_BEARER_TOKEN_BYTES
        or len(value) != size
    ):
        raise ValueError("bearer_token is invalid")
    saw_payload = False
    saw_padding = False
    try:
        for index in range(size):
            byte = value[index]
            if byte == 0x3D:
                if not saw_payload:
                    raise ValueError("bearer_token is invalid")
                saw_padding = True
            elif byte not in _BEARER_BYTES or saw_padding:
                raise ValueError("bearer_token is invalid")
            else:
                saw_payload = True
    except ValueError:
        raise
    except BaseException:
        raise ValueError("bearer_token view is invalid") from None
    return size


def _best_effort_zero_request(buffer: object | None) -> None:
    if type(buffer) is not bytearray:
        return
    try:
        for index in range(len(buffer)):
            buffer[index] = 0
    except BaseException:
        pass
    try:
        buffer.clear()
    except BaseException:
        pass


def _normalized_non_secret_headers(
    prepared: PreparedOutbound,
) -> tuple[tuple[bytes, bytes], ...]:
    headers = prepared.non_secret_headers
    if type(headers) is not tuple:
        raise ValueError("non-secret headers are invalid")
    selected: list[tuple[bytes, bytes]] = []
    previous: str | None = None
    for header in headers:
        if type(header) is not NonSecretHeader:
            raise ValueError("non-secret header type is invalid")
        name = header.lowercase_name
        if (
            previous is not None
            and name <= previous
        ) or name in _FORBIDDEN_REQUEST_HEADERS:
            raise ValueError("non-secret header name is forbidden or unsorted")
        name_bytes = _ascii_bytes(name, "header name", maximum=256)
        value_bytes = _ascii_bytes(
            header.normalized_value,
            "header value",
            maximum=4_096,
        )
        if name_bytes.lower() != name_bytes or _TOKEN_RE.fullmatch(name_bytes) is None:
            raise ValueError("non-secret header name is invalid")
        previous = name
        selected.append((name_bytes, value_bytes))
    return tuple(selected)


def _encode_exact_http1_request(
    *,
    prepared: PreparedOutbound,
    bearer_token: memoryview,
    action: Callable[[memoryview], _ResultT],
) -> _ResultT:
    """Use the only Phase-1 request shape inside one erasable callback.

    The callback receives a readonly view backed by a temporary mutable buffer.
    The view is released and the buffer is overwritten before this function
    returns or propagates an exception.  A trusted Transport callback must
    consume the bytes synchronously and must not copy or retain the secret.
    """

    _require_exact_http1_policy_digest()
    if type(prepared) is not PreparedOutbound:
        raise TypeError("prepared must be PreparedOutbound")
    if prepared.http_method != "POST":
        raise ValueError("Phase-1 exact HTTP requires POST")
    if type(prepared.body) is not bytes or not prepared.body:
        raise ValueError("prepared body must be non-empty bytes")
    if len(prepared.body) > MAX_HTTP_REQUEST_BODY_BYTES:
        raise ValueError("prepared body exceeds the exact HTTP limit")
    authority, target = _canonical_https_target(prepared)
    content_type = _ascii_bytes(
        prepared.content_type,
        "content type",
        maximum=256,
    )
    extra = _normalized_non_secret_headers(prepared)
    if not callable(action):
        raise TypeError("action must be callable")
    static_lines = [
        b"POST " + target + b" HTTP/1.1",
        b"host: " + authority,
        b"content-type: " + content_type,
        b"accept-encoding: identity",
        b"connection: close",
        b"content-length: " + str(len(prepared.body)).encode("ascii"),
    ]
    static_lines.extend(name + b": " + value for name, value in extra)
    if len(static_lines) > MAX_HTTP_HEADER_FIELDS:
        raise ValueError("request header field limit exceeded")
    if any(len(line) > MAX_HTTP_LINE_BYTES for line in static_lines):
        raise ValueError("request line limit exceeded")
    authorization_prefix = b"authorization: Bearer "
    line_count = len(static_lines) + 1
    static_head_size = (
        sum(len(line) for line in static_lines)
        + len(authorization_prefix)
        + 1
        + (2 * line_count)
        + 2
    )
    if static_head_size > MAX_HTTP_HEADER_BYTES:
        raise ValueError("request header byte limit exceeded")
    token_size = _validate_borrowed_bearer(bearer_token)
    if len(authorization_prefix) + token_size > MAX_HTTP_LINE_BYTES:
        raise ValueError("request line limit exceeded")
    head_size = (
        sum(len(line) for line in static_lines)
        + len(authorization_prefix)
        + token_size
        + (2 * line_count)
        + 2
    )
    if head_size > MAX_HTTP_HEADER_BYTES:
        raise ValueError("request header byte limit exceeded")

    request_buffer: bytearray | None = bytearray()
    writable_view: memoryview | None = None
    readonly_view: memoryview | None = None
    try:
        for line in static_lines[:3]:
            request_buffer.extend(line)
            request_buffer.extend(b"\r\n")
        request_buffer.extend(authorization_prefix)
        request_buffer.extend(bearer_token)
        request_buffer.extend(b"\r\n")
        for line in static_lines[3:]:
            request_buffer.extend(line)
            request_buffer.extend(b"\r\n")
        request_buffer.extend(b"\r\n")
        request_buffer.extend(prepared.body)

        # Do not let a callback traceback retain the borrowed source view.
        bearer_token = None  # type: ignore[assignment]
        writable_view = memoryview(request_buffer)
        readonly_view = writable_view.toreadonly()
        writable_view.release()
        writable_view = None
        action_result = action(readonly_view)
        if isinstance(action_result, (bytes, bytearray, memoryview)):
            action_result = None  # type: ignore[assignment]
            raise TypeError("request action must not return byte-bearing values")
        return action_result
    finally:
        bearer_token = None  # type: ignore[assignment]
        if readonly_view is not None:
            try:
                readonly_view.release()
            except BaseException:
                pass
            readonly_view = None
        if writable_view is not None:
            try:
                writable_view.release()
            except BaseException:
                pass
            writable_view = None
        _best_effort_zero_request(request_buffer)


@runtime_final
class _ExactHttp1Response:
    """Immutable, private result of one fully framed HTTP response."""

    __slots__ = (
        "status",
        "headers",
        "body",
        "response_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        status: int,
        headers: tuple[tuple[bytes, bytes], ...],
        body: bytes,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RESPONSE_AUTHORITY:
            raise TypeError("exact HTTP response requires its parser")
        _require_exact_http1_policy_digest()
        if type(status) is not int or not 200 <= status <= 599:
            raise ValueError("HTTP response status is invalid")
        if type(headers) is not tuple or not all(
            type(item) is tuple
            and len(item) == 2
            and type(item[0]) is bytes
            and type(item[1]) is bytes
            for item in headers
        ):
            raise ValueError("HTTP response headers are invalid")
        if type(body) is not bytes or len(body) > MAX_HTTP_RESPONSE_BODY_BYTES:
            raise ValueError("HTTP response body is invalid")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "headers", headers)
        object.__setattr__(self, "body", body)
        selected = self._recompute_digest()
        object.__setattr__(self, "response_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ExactHttp1Response is immutable")

    def __copy__(self) -> "_ExactHttp1Response":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_ExactHttp1Response":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("ExactHttp1Response cannot be serialized")

    def _recompute_digest(self) -> Digest256:
        return digest256(
            "ExactHttp1Response",
            EXACT_HTTP1_RESPONSE_SCHEMA_VERSION,
            {
                "status": self.status,
                "headers": tuple(
                    (name.decode("ascii"), value.decode("ascii"))
                    for name, value in self.headers
                ),
                "body_byte_size": len(self.body),
                "body_sha256": hashlib.sha256(self.body).hexdigest(),
            },
        )

    def validate_integrity(self) -> None:
        _require_exact_http1_policy_digest()
        if (
            type(self.status) is not int
            or not 200 <= self.status <= 599
            or type(self.headers) is not tuple
            or type(self.body) is not bytes
            or len(self.body) > MAX_HTTP_RESPONSE_BODY_BYTES
        ):
            raise ValueError("exact HTTP response integrity failed")
        try:
            selected = self._recompute_digest()
        except (AttributeError, UnicodeDecodeError, TypeError, ValueError):
            raise ValueError("exact HTTP response integrity failed") from None
        if (
            type(self.response_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or selected != self.response_digest
            or selected != self._issued_digest
        ):
            raise ValueError("exact HTTP response integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "body_byte_size": len(self.body),
            "header_field_count": len(self.headers),
            "response_digest_prefix": str(self.response_digest)[:12],
            "status": self.status,
        }


class _ExactHttp1ResponseParser:
    """Incremental parser for exactly one bounded response record."""

    __slots__ = (
        "_state",
        "_buffer",
        "_headers",
        "_status",
        "_body",
        "_expected_body_bytes",
        "_chunk_bytes_remaining",
        "_chunk_count",
        "_chunk_metadata_bytes",
        "_header_scan_offset",
        "_header_line_start",
        "_chunk_scan_offset",
        "_result",
    )

    def __init__(self) -> None:
        _require_exact_http1_policy_digest()
        self._state = _ParserState.HEADERS
        self._buffer = bytearray()
        self._headers: tuple[tuple[bytes, bytes], ...] = ()
        self._status: int | None = None
        self._body = bytearray()
        self._expected_body_bytes: int | None = None
        self._chunk_bytes_remaining = 0
        self._chunk_count = 0
        self._chunk_metadata_bytes = 0
        self._header_scan_offset = 0
        self._header_line_start = 0
        self._chunk_scan_offset = 0
        self._result: _ExactHttp1Response | None = None

    def __copy__(self):
        raise TypeError("ExactHttp1ResponseParser cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]):
        del memo
        raise TypeError("ExactHttp1ResponseParser cannot be copied")

    def __reduce__(self):
        raise TypeError("ExactHttp1ResponseParser cannot be serialized")

    @property
    def is_complete(self) -> bool:
        return self._state is _ParserState.COMPLETE

    def _mark_failed(self) -> object:
        self._state = _ParserState.FAILED
        self._buffer.clear()
        self._body.clear()
        self._headers = ()
        self._status = None
        self._expected_body_bytes = None
        self._chunk_bytes_remaining = 0
        self._chunk_count = 0
        self._chunk_metadata_bytes = 0
        self._header_scan_offset = 0
        self._header_line_start = 0
        self._chunk_scan_offset = 0
        self._result = None
        return _FAILED

    def _parse_headers(self, block: bytes) -> bool:
        lines = block.split(b"\r\n")
        if not lines or any(len(line) > MAX_HTTP_LINE_BYTES for line in lines):
            return False
        status_match = _STATUS_LINE_RE.fullmatch(lines[0])
        if status_match is None:
            return False
        status = int(status_match.group(1))
        if not 200 <= status <= 599:
            return False
        if len(lines) - 1 > MAX_HTTP_HEADER_FIELDS:
            return False
        selected: list[tuple[bytes, bytes]] = []
        content_lengths: list[bytes] = []
        transfer_encodings: list[bytes] = []
        for line in lines[1:]:
            if not line or line[:1] in (b" ", b"\t") or line.count(b":") < 1:
                return False
            name, value = line.split(b":", 1)
            if (
                not name
                or name != name.strip()
                or _TOKEN_RE.fullmatch(name) is None
                or any(byte < 0x20 and byte != 0x09 for byte in value)
                or any(byte > 0x7E for byte in value)
            ):
                return False
            normalized_name = name.lower()
            normalized_value = value.strip(b" \t")
            selected.append((normalized_name, normalized_value))
            if normalized_name == b"content-length":
                content_lengths.append(normalized_value)
            elif normalized_name == b"transfer-encoding":
                transfer_encodings.append(normalized_value)
            elif normalized_name in (b"content-encoding", b"trailer"):
                return False
        if len(content_lengths) > 1 or len(transfer_encodings) > 1:
            return False
        if content_lengths and transfer_encodings:
            return False
        next_state: _ParserState
        expected_body_bytes: int | None = None
        if transfer_encodings:
            if transfer_encodings[0] != b"chunked":
                return False
            next_state = _ParserState.CHUNK_SIZE
        elif content_lengths:
            value = content_lengths[0]
            if not value or not value.isdigit():
                return False
            maximum = str(MAX_HTTP_RESPONSE_BODY_BYTES).encode("ascii")
            if len(value) > len(maximum) or (
                len(value) == len(maximum) and value > maximum
            ):
                return False
            expected_body_bytes = int(value)
            next_state = _ParserState.CONTENT_LENGTH
        else:
            return False
        self._status = status
        self._headers = tuple(selected)
        self._expected_body_bytes = expected_body_bytes
        self._state = next_state
        return True

    def _finish(self) -> object:
        if self._buffer:
            return self._mark_failed()
        if self._status is None:
            return self._mark_failed()
        result = _ExactHttp1Response(
            status=self._status,
            headers=self._headers,
            body=bytes(self._body),
            _authority=_RESPONSE_AUTHORITY,
        )
        self._body.clear()
        self._state = _ParserState.COMPLETE
        self._result = result
        return result

    def _consume(self) -> object:
        while True:
            if self._state is _ParserState.HEADERS:
                index = self._header_scan_offset
                line_start = self._header_line_start
                while index < len(self._buffer):
                    byte = self._buffer[index]
                    if byte == 0x0D:
                        if index + 1 == len(self._buffer):
                            break
                        if self._buffer[index + 1] != 0x0A:
                            return self._mark_failed()
                        line_size = index - line_start
                        if line_size > MAX_HTTP_LINE_BYTES:
                            return self._mark_failed()
                        index += 2
                        if line_size == 0:
                            if line_start == 0:
                                return self._mark_failed()
                            header_size = index
                            if header_size > MAX_HTTP_HEADER_BYTES:
                                return self._mark_failed()
                            block = bytes(self._buffer[: header_size - 4])
                            del self._buffer[:header_size]
                            self._header_scan_offset = 0
                            self._header_line_start = 0
                            if not self._parse_headers(block):
                                return self._mark_failed()
                            break
                        line_start = index
                        continue
                    if byte == 0x0A:
                        return self._mark_failed()
                    if index - line_start + 1 > MAX_HTTP_LINE_BYTES:
                        return self._mark_failed()
                    index += 1
                else:
                    self._header_scan_offset = index
                    self._header_line_start = line_start
                    if len(self._buffer) >= MAX_HTTP_HEADER_BYTES:
                        return self._mark_failed()
                    return _PENDING
                if self._state is _ParserState.HEADERS:
                    self._header_scan_offset = index
                    self._header_line_start = line_start
                    if len(self._buffer) >= MAX_HTTP_HEADER_BYTES:
                        return self._mark_failed()
                    return _PENDING
                continue

            if self._state is _ParserState.CONTENT_LENGTH:
                expected = self._expected_body_bytes
                if expected is None:
                    return self._mark_failed()
                remaining = expected - len(self._body)
                if remaining < 0:
                    return self._mark_failed()
                take = min(remaining, len(self._buffer))
                if take:
                    self._body.extend(self._buffer[:take])
                    del self._buffer[:take]
                if len(self._body) > MAX_HTTP_RESPONSE_BODY_BYTES:
                    return self._mark_failed()
                if len(self._body) == expected:
                    return self._finish()
                return _PENDING

            if self._state is _ParserState.CHUNK_SIZE:
                index = self._chunk_scan_offset
                while index < len(self._buffer):
                    byte = self._buffer[index]
                    if byte == 0x0D:
                        if index + 1 == len(self._buffer):
                            self._chunk_scan_offset = index
                            return _PENDING
                        if self._buffer[index + 1] != 0x0A:
                            return self._mark_failed()
                        break
                    if byte == 0x0A or index + 1 > MAX_HTTP_LINE_BYTES:
                        return self._mark_failed()
                    index += 1
                else:
                    self._chunk_scan_offset = index
                    return _PENDING
                line = bytes(self._buffer[:index])
                del self._buffer[: index + 2]
                self._chunk_scan_offset = 0
                self._chunk_metadata_bytes += index + 2
                if (
                    not line
                    or len(line) > MAX_HTTP_LINE_BYTES
                    or self._chunk_metadata_bytes
                    > MAX_HTTP_CHUNK_METADATA_BYTES
                    or _CHUNK_SIZE_RE.fullmatch(line) is None
                ):
                    return self._mark_failed()
                size = int(line, 16)
                if size > MAX_HTTP_RESPONSE_BODY_BYTES - len(self._body):
                    return self._mark_failed()
                if size == 0:
                    self._state = _ParserState.FINAL_CHUNK
                else:
                    self._chunk_count += 1
                    if self._chunk_count > MAX_HTTP_CHUNKS:
                        return self._mark_failed()
                    self._chunk_bytes_remaining = size
                    self._state = _ParserState.CHUNK_DATA
                continue

            if self._state is _ParserState.CHUNK_DATA:
                take = min(self._chunk_bytes_remaining, len(self._buffer))
                if take:
                    self._body.extend(self._buffer[:take])
                    del self._buffer[:take]
                    self._chunk_bytes_remaining -= take
                if len(self._body) > MAX_HTTP_RESPONSE_BODY_BYTES:
                    return self._mark_failed()
                if self._chunk_bytes_remaining:
                    return _PENDING
                self._state = _ParserState.CHUNK_TERMINATOR
                continue

            if self._state is _ParserState.CHUNK_TERMINATOR:
                if len(self._buffer) < 2:
                    return _PENDING
                if self._buffer[:2] != b"\r\n":
                    return self._mark_failed()
                del self._buffer[:2]
                self._chunk_metadata_bytes += 2
                if self._chunk_metadata_bytes > MAX_HTTP_CHUNK_METADATA_BYTES:
                    return self._mark_failed()
                self._state = _ParserState.CHUNK_SIZE
                continue

            if self._state is _ParserState.FINAL_CHUNK:
                if len(self._buffer) < 2:
                    return _PENDING
                if self._buffer[:2] != b"\r\n":
                    return self._mark_failed()
                del self._buffer[:2]
                self._chunk_metadata_bytes += 2
                if self._chunk_metadata_bytes > MAX_HTTP_CHUNK_METADATA_BYTES:
                    return self._mark_failed()
                return self._finish()

            if self._state is _ParserState.COMPLETE:
                if self._buffer:
                    return self._mark_failed()
                assert self._result is not None
                return self._result
            return self._mark_failed()

    def _input_capacity(self) -> int:
        if self._state is _ParserState.HEADERS:
            return MAX_HTTP_HEADER_BYTES - len(self._buffer)
        if self._state is _ParserState.CONTENT_LENGTH:
            if self._expected_body_bytes is None:
                return 0
            return (
                self._expected_body_bytes
                - len(self._body)
                - len(self._buffer)
            )
        if self._state is _ParserState.CHUNK_SIZE:
            return MAX_HTTP_LINE_BYTES + 2 - len(self._buffer)
        if self._state is _ParserState.CHUNK_DATA:
            return self._chunk_bytes_remaining - len(self._buffer)
        if self._state in (
            _ParserState.CHUNK_TERMINATOR,
            _ParserState.FINAL_CHUNK,
        ):
            return 2 - len(self._buffer)
        return 0

    def feed(self, data: bytes) -> object:
        try:
            _require_exact_http1_policy_digest()
        except BaseException:
            self._mark_failed()
            raise
        if type(data) is not bytes:
            data = b""
            raise TypeError("HTTP response input must be exact bytes")
        if self._state is _ParserState.FAILED:
            data = b""
            _raise_http_error()
        if self._state is _ParserState.COMPLETE:
            if data:
                self._mark_failed()
                data = b""
                _raise_http_error()
            assert self._result is not None
            return self._result

        incoming: memoryview | None = memoryview(data)
        data = b""
        piece: memoryview | None = None
        outcome: object = _PENDING
        offset = 0
        try:
            total = incoming.nbytes
            if total == 0:
                outcome = self._consume()
            while offset < total:
                if self._state in (_ParserState.FAILED, _ParserState.COMPLETE):
                    outcome = self._mark_failed()
                    break
                capacity = self._input_capacity()
                if capacity <= 0:
                    outcome = self._consume()
                    if outcome is _PENDING:
                        outcome = self._mark_failed()
                    elif outcome is not _FAILED and offset < total:
                        outcome = self._mark_failed()
                    break
                take = min(capacity, total - offset)
                piece = incoming[offset : offset + take]
                try:
                    self._buffer.extend(piece)
                finally:
                    piece.release()
                    piece = None
                offset += take
                outcome = self._consume()
                if outcome is _FAILED:
                    break
                if outcome is not _PENDING:
                    if offset < total:
                        outcome = self._mark_failed()
                    break
        finally:
            if piece is not None:
                try:
                    piece.release()
                except BaseException:
                    pass
                piece = None
            if incoming is not None:
                try:
                    incoming.release()
                except BaseException:
                    pass
                incoming = None
            data = b""
        if outcome is _FAILED:
            _raise_http_error()
        return outcome

    def finish_eof(self) -> _ExactHttp1Response:
        try:
            _require_exact_http1_policy_digest()
        except BaseException:
            self._mark_failed()
            raise
        if self._state is _ParserState.COMPLETE and self._result is not None:
            return self._result
        self._mark_failed()
        _raise_http_error()


def _new_exact_http1_response_parser() -> _ExactHttp1ResponseParser:
    return _ExactHttp1ResponseParser()
