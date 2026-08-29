"""Small validation helpers shared by standard-library domain contracts."""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from ipaddress import ip_address
from typing import TypeVar
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit
from uuid import UUID

from snapquiz.domain.digest import Digest256

HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PATH_ASCII_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/"
)
_UNRESERVED_ASCII = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_UPPER_HEX = frozenset("0123456789ABCDEF")
_ClassT = TypeVar("_ClassT", bound=type)
_FORBIDDEN_NON_SECRET_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "content-type",
        "cookie",
        "host",
        "proxy-authorization",
        "set-cookie",
        "transfer-encoding",
        "x-api-key",
        "x-auth-token",
    }
)


def runtime_final(cls: _ClassT) -> _ClassT:
    """Make a security value object non-subclassable at runtime."""

    def _reject_subclass(subclass: type, **kwargs: object) -> None:
        del subclass, kwargs
        raise TypeError(f"{cls.__name__} is final")

    cls.__init_subclass__ = classmethod(_reject_subclass)  # type: ignore[attr-defined]
    return cls


def contains_unsafe_codepoint(value: str, *, allow_multiline: bool = False) -> bool:
    allowed_controls = "\t\n\r" if allow_multiline else ""
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            return True
        if (codepoint < 0x20 and char not in allowed_controls) or 0x7F <= codepoint <= 0x9F:
            return True
    return False


def require_text(
    value: object,
    name: str,
    *,
    max_length: int = 256,
    allow_multiline: bool = False,
) -> str:
    if type(value) is not str or len(value) > max_length:
        raise ValueError(f"{name} must be a safe non-empty string <= {max_length} chars")
    if not value.strip() or contains_unsafe_codepoint(
        value, allow_multiline=allow_multiline
    ):
        raise ValueError(f"{name} must be a safe non-empty string <= {max_length} chars")
    return value


def require_optional_text(
    value: object,
    name: str,
    *,
    max_length: int,
    allow_multiline: bool = False,
) -> str | None:
    if value is None:
        return None
    return require_text(
        value,
        name,
        max_length=max_length,
        allow_multiline=allow_multiline,
    )


def require_plain_int(value: object, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def require_uuid(value: object, name: str) -> UUID:
    if type(value) is not UUID:
        raise ValueError(f"{name} must be a UUID")
    return value


def require_digest(value: object, name: str) -> Digest256:
    if type(value) is not Digest256:
        raise ValueError(f"{name} must be Digest256")
    return value


def require_aware_datetime(value: object, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def require_non_secret_header_name(value: object, name: str = "header name") -> str:
    header_name = require_text(value, name, max_length=256)
    if header_name != header_name.lower() or HTTP_TOKEN_RE.fullmatch(header_name) is None:
        raise ValueError(f"{name} must be a lowercase HTTP token")
    dashed_name = header_name.replace("_", "-")
    compact_name = header_name.replace("_", "")
    name_parts = frozenset(re.split(r"[-_]", header_name))
    if (
        header_name in _FORBIDDEN_NON_SECRET_HEADERS
        or "api-key" in dashed_name
        or "apikey" in compact_name
        or "auth-token" in dashed_name
        or "secret" in header_name
        or name_parts.intersection({"auth", "credential", "key", "token"})
    ):
        raise ValueError("credential-bearing headers cannot be non-secret headers")
    return header_name


def require_non_secret_query_key(value: object, name: str = "query key") -> str:
    """Accept a normalized metadata key while rejecting credential-shaped names."""

    key = require_text(value, name, max_length=256)
    if key != key.lower():
        raise ValueError(f"{name} must be normalized lowercase text")
    dashed_name = key.replace("_", "-")
    compact_name = key.replace("_", "").replace("-", "")
    name_parts = frozenset(re.split(r"[-_.]", key))
    if (
        "api-key" in dashed_name
        or "apikey" in compact_name
        or "auth-token" in dashed_name
        or "secret" in key
        or name_parts.intersection(
            {
                "auth",
                "authorization",
                "code",
                "credential",
                "key",
                "password",
                "passwd",
                "sas",
                "signature",
                "token",
            }
        )
    ):
        raise ValueError("credential-bearing query keys are forbidden")
    return key


def canonical_query_string(items: tuple[tuple[str, str], ...]) -> str:
    """Render already ordered, non-secret query pairs with one strict encoding."""

    if type(items) is not tuple or not items:
        raise ValueError("canonical query items must be a non-empty tuple")
    checked: list[tuple[str, str]] = []
    for item in items:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError("canonical query items must be (key, value) tuples")
        key = require_non_secret_query_key(item[0])
        value = require_text(item[1], "query value", max_length=1_024)
        checked.append((key, value))
    checked_tuple = tuple(checked)
    if checked_tuple != tuple(sorted(checked_tuple)):
        raise ValueError("canonical query items must be in sorted order")
    if len({key for key, _ in checked_tuple}) != len(checked_tuple):
        raise ValueError("canonical query keys must be unique")
    return "&".join(
        f"{quote(key, safe='-._~')}={quote(value, safe='-._~')}"
        for key, value in checked_tuple
    )


def _canonical_host(hostname: str) -> str:
    if "%" in hostname:
        raise ValueError("URL host cannot contain a zone identifier")
    try:
        parsed_ip = ip_address(hostname)
    except ValueError:
        try:
            ascii_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("URL host is not valid IDNA") from error
        if (
            not ascii_host
            or len(ascii_host) > 253
            or ascii_host.endswith(".")
            or all(char.isdigit() or char == "." for char in ascii_host)
            or any(_DNS_LABEL_RE.fullmatch(label) is None for label in ascii_host.split("."))
        ):
            raise ValueError("URL host is not a canonical DNS name")
        return ascii_host
    return str(parsed_ip)


def _require_canonical_path(path: str) -> str:
    if not path.startswith("/") or any(ord(char) > 0x7F for char in path):
        raise ValueError("URL path must be absolute and ASCII encoded")
    index = 0
    decoded_bytes = bytearray()
    while index < len(path):
        char = path[index]
        if char == "%":
            if (
                index + 2 >= len(path)
                or path[index + 1] not in _UPPER_HEX
                or path[index + 2] not in _UPPER_HEX
            ):
                raise ValueError("URL percent encoding must use uppercase hex")
            decoded_byte = int(path[index + 1 : index + 3], 16)
            decoded = chr(decoded_byte)
            if decoded in _UNRESERVED_ASCII or decoded in ("%", "/", "\\"):
                raise ValueError("URL path contains ambiguous percent encoding")
            decoded_bytes.append(decoded_byte)
            index += 3
            continue
        if char not in _PATH_ASCII_CHARS or char == "\\":
            raise ValueError("URL path contains a non-canonical character")
        decoded_bytes.extend(char.encode("ascii"))
        index += 1
    try:
        decoded_path = bytes(decoded_bytes).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("URL path must contain valid UTF-8") from error
    if (
        contains_unsafe_codepoint(decoded_path)
        or "\\" in decoded_path
        or unicodedata.normalize("NFC", decoded_path) != decoded_path
    ):
        raise ValueError("URL path decodes to unsafe or non-normalized text")
    if any(segment in (".", "..") for segment in decoded_path.split("/")):
        raise ValueError("URL path cannot contain dot segments")
    return path


def _require_canonical_query(query: str) -> str:
    if not query:
        return ""
    try:
        parsed_items = tuple(
            parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                encoding="utf-8",
                errors="strict",
                separator="&",
            )
        )
        rendered = canonical_query_string(parsed_items)
    except (UnicodeError, ValueError) as error:
        raise ValueError("URL query is not canonical") from error
    if rendered != query:
        raise ValueError("URL query is not canonical")
    return rendered


def require_canonical_http_url(
    value: object,
    name: str,
    *,
    allow_query: bool,
) -> str:
    """Require exact scheme/IDNA host/port/path/query canonical spelling."""

    url = require_text(value, name, max_length=2_048)
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{name} is malformed") from error
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or parsed.fragment
        or any(char.isspace() for char in url)
    ):
        raise ValueError(f"{name} must be an explicit HTTP URL")
    canonical_host = _canonical_host(parsed.hostname)
    rendered_host = (
        f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    )
    canonical_path = _require_canonical_path(parsed.path)
    if parsed.query and not allow_query:
        raise ValueError(f"{name} cannot contain a query")
    canonical_query = _require_canonical_query(parsed.query) if allow_query else ""
    canonical = urlunsplit(
        (parsed.scheme, f"{rendered_host}:{port}", canonical_path, canonical_query, "")
    )
    if canonical != url:
        raise ValueError(f"{name} is not in canonical form")
    return url


def canonical_http_url_host(value: str) -> str:
    """Return the host from a URL that has already passed canonical validation."""

    hostname = urlsplit(value).hostname
    if hostname is None:
        raise ValueError("canonical URL has no host")
    return hostname
