"""Versioned canonical digests used by immutable v3 contracts.

UUIDs, datetimes, enums and tuples normalize to their declared JSON-schema
representations.  Callers must therefore use this serializer only with a fixed
type tag, schema version and field schema; it is not a dynamically typed object
fingerprinter.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID

CANONICAL_SERIALIZER_VERSION = "snapquiz.canonical-json.v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_CANONICAL_DEPTH = 100
_MAX_INTEGER_BITS = 4_096


class CanonicalizationError(ValueError):
    """A value cannot be represented by the canonical serializer."""


class Digest256(str):
    """A validated lowercase SHA-256 hexadecimal digest."""

    def __new__(cls, value: str) -> "Digest256":
        if type(value) is not str or not _DIGEST_RE.fullmatch(value):
            raise ValueError("Digest256 must be 64 lowercase hexadecimal characters")
        return str.__new__(cls, value)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("Digest256 is final")


def _validate_unicode_text(value: str) -> str:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise CanonicalizationError("unpaired Unicode surrogates are not canonicalizable")
    return value


def _canonicalize(
    value: Any, *, _active_containers: set[int] | None = None, _depth: int = 0
) -> Any:
    if _depth > _MAX_CANONICAL_DEPTH:
        raise CanonicalizationError("canonical value exceeds maximum nesting depth")
    if _active_containers is None:
        _active_containers = set()
    if type(value) is Digest256:
        return str(value)
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        return _validate_unicode_text(value)
    if type(value) is int:
        if value.bit_length() > _MAX_INTEGER_BITS:
            raise CanonicalizationError("integer exceeds canonical size limit")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite numbers are not canonicalizable")
        if value == 0:
            return 0
        if value.is_integer():
            normalized_integer = int(value)
            if normalized_integer.bit_length() > _MAX_INTEGER_BITS:
                raise CanonicalizationError("number exceeds canonical size limit")
            return normalized_integer
        return value
    if isinstance(value, Enum):
        return _canonicalize(
            value.value,
            _active_containers=_active_containers,
            _depth=_depth + 1,
        )
    if type(value) is UUID:
        return str(value)
    if type(value) is datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise CanonicalizationError("datetime values must include a timezone")
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if type(value) is dict:
        marker = id(value)
        if marker in _active_containers:
            raise CanonicalizationError("cyclic values are not canonicalizable")
        _active_containers.add(marker)
        try:
            normalized: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise CanonicalizationError("canonical object keys must be strings")
                normalized[_validate_unicode_text(key)] = _canonicalize(
                    item,
                    _active_containers=_active_containers,
                    _depth=_depth + 1,
                )
            return normalized
        finally:
            _active_containers.remove(marker)
    if type(value) in (list, tuple):
        marker = id(value)
        if marker in _active_containers:
            raise CanonicalizationError("cyclic values are not canonicalizable")
        _active_containers.add(marker)
        try:
            return [
                _canonicalize(
                    item,
                    _active_containers=_active_containers,
                    _depth=_depth + 1,
                )
                for item in value
            ]
        finally:
            _active_containers.remove(marker)
    raise CanonicalizationError(f"unsupported canonical value type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a supported value deterministically as UTF-8 JSON.

    Serializer v1 sorts object keys, emits Unicode directly, uses compact
    separators, normalizes negative zero to zero and integral floats to ints,
    and rejects non-finite numbers and non-string object keys.
    """

    normalized = _canonicalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest256(
    type_tag: str,
    schema_version: str,
    payload: Any,
    *,
    canonical_serializer_version: str = CANONICAL_SERIALIZER_VERSION,
) -> Digest256:
    """Return a domain-separated, length-delimited SHA-256 digest."""

    labels = (type_tag, schema_version, canonical_serializer_version)
    if any(type(label) is not str or not label.strip() for label in labels):
        raise ValueError("digest type and version labels must be non-empty strings")

    parts = (
        b"snapquiz.digest.v1",
        _validate_unicode_text(type_tag).encode("utf-8"),
        _validate_unicode_text(schema_version).encode("utf-8"),
        _validate_unicode_text(canonical_serializer_version).encode("utf-8"),
        canonical_json_bytes(payload),
    )
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(len(part).to_bytes(8, byteorder="big", signed=False))
        hasher.update(part)
    return Digest256(hasher.hexdigest())
