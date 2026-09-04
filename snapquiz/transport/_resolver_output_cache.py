"""Pure/local durable output observation contract for W09-B2b-S4d.

This module owns no process, pipe, DNS, socket, credential, or production
authority.  It freezes the smallest single-slot cache used between an injected
child/native output owner and the async supervisor.  The output owner publishes
into the supplied sink *before* returning; callers then acknowledge the exact
factory-issued observation.  A lost return can therefore be retried without
reading a destructive stream again.

The production adapter remains unavailable until a native, signed child owner
implements this publication/ACK contract across the real pipe boundary.
"""
from __future__ import annotations

from enum import Enum
import hashlib
from threading import RLock
from typing import NoReturn
from uuid import UUID, uuid5

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError


__all__ = ()


RESOLVER_OUTPUT_CACHE_SCHEMA_VERSION = "snapquiz.resolver-output-cache.v1"
RESOLVER_OUTPUT_OBSERVATION_SCHEMA_VERSION = (
    "snapquiz.resolver-output-observation.v1"
)
RESOLVER_OUTPUT_TOMBSTONE_SCHEMA_VERSION = (
    "snapquiz.resolver-output-tombstone.v1"
)
MAX_RESOLVER_OUTPUT_PAYLOAD_BYTES = 16_385
READY_OUTPUT_PAYLOAD = b"SNAPQUIZ-RESOLVER/2 READY\n"

# This slice is an executable local contract, never production authority.
LOCAL_DURABLE_OUTPUT_CONTRACT_AVAILABLE = True
PRODUCTION_DURABLE_OUTPUT_CONTRACT_AVAILABLE = False

_CACHE_AUTHORITY = object()
_OBSERVATION_AUTHORITY = object()
_PUBLICATION_AUTHORITY = object()
_TOMBSTONE_AUTHORITY = object()
_DELIVERY_NAMESPACE = UUID("7fc86004-f087-5c6a-bd45-bfbf71cab654")


class _ResolverOutputKind(str, Enum):
    READY = "READY"
    RESULT = "RESULT"
    EOF = "EOF"


_OUTPUT_SEQUENCE = {
    _ResolverOutputKind.READY: 0,
    _ResolverOutputKind.RESULT: 1,
    _ResolverOutputKind.EOF: 2,
}
_SEQUENCE_OUTPUT = {sequence: kind for kind, sequence in _OUTPUT_SEQUENCE.items()}


def _cache_error(message: str) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="resolver_output_cache",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_cache_error(message: str) -> NoReturn:
    raise _cache_error(message) from None


def _payload_digest(
    *,
    sequence: int,
    kind: _ResolverOutputKind,
    payload: bytes,
) -> Digest256:
    return digest256(
        "ResolverOutputPayload",
        RESOLVER_OUTPUT_OBSERVATION_SCHEMA_VERSION,
        {
            "byte_size": len(payload),
            "kind": kind,
            "sequence": sequence,
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
    )


def _delivery_id(
    *,
    epoch_id: UUID,
    operation_id: UUID,
    proxy_id: UUID,
    operation_binding_digest: Digest256,
    sequence: int,
    kind: _ResolverOutputKind,
) -> UUID:
    selected = digest256(
        "ResolverOutputDeliveryIdentifier",
        RESOLVER_OUTPUT_OBSERVATION_SCHEMA_VERSION,
        {
            "epoch_id": epoch_id,
            "kind": kind,
            "operation_binding_digest": operation_binding_digest,
            "operation_id": operation_id,
            "proxy_id": proxy_id,
            "sequence": sequence,
        },
    )
    return uuid5(_DELIVERY_NAMESPACE, str(selected))


def _observation_digest(
    *,
    epoch_id: UUID,
    operation_id: UUID,
    proxy_id: UUID,
    operation_binding_digest: Digest256,
    delivery_id: UUID,
    sequence: int,
    kind: _ResolverOutputKind,
    payload_digest: Digest256,
    payload_size: int,
) -> Digest256:
    return digest256(
        "ResolverOutputObservation",
        RESOLVER_OUTPUT_OBSERVATION_SCHEMA_VERSION,
        {
            "delivery_id": delivery_id,
            "epoch_id": epoch_id,
            "kind": kind,
            "operation_binding_digest": operation_binding_digest,
            "operation_id": operation_id,
            "payload_digest": payload_digest,
            "payload_size": payload_size,
            "proxy_id": proxy_id,
            "sequence": sequence,
        },
    )


def _validate_payload(
    sequence: object,
    kind: object,
    payload: object,
) -> tuple[int, _ResolverOutputKind, bytes]:
    checked_sequence = require_plain_int(sequence, "sequence", minimum=0)
    if type(kind) is not _ResolverOutputKind:
        raise ValueError("kind must be ResolverOutputKind")
    if _SEQUENCE_OUTPUT.get(checked_sequence) is not kind:
        raise ValueError("resolver output sequence is invalid")
    if type(payload) is not bytes:
        raise TypeError("payload must be immutable bytes")
    if len(payload) > MAX_RESOLVER_OUTPUT_PAYLOAD_BYTES:
        raise ValueError("resolver output payload exceeds its byte limit")
    if kind is _ResolverOutputKind.READY:
        if payload != READY_OUTPUT_PAYLOAD:
            raise ValueError("READY output payload is invalid")
    elif kind is _ResolverOutputKind.RESULT:
        if not payload or payload == READY_OUTPUT_PAYLOAD or not payload.endswith(b"\n"):
            raise ValueError("RESULT output payload is invalid")
    elif payload:
        raise ValueError("EOF output payload must be empty")
    return checked_sequence, kind, payload


@runtime_final
class _ResolverOutputObservation:
    """Factory-only immutable payload observation for one exact delivery."""

    __slots__ = (
        "epoch_id",
        "operation_id",
        "proxy_id",
        "operation_binding_digest",
        "delivery_id",
        "sequence",
        "kind",
        "payload",
        "payload_digest",
        "observation_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        epoch_id: UUID,
        operation_id: UUID,
        proxy_id: UUID,
        operation_binding_digest: Digest256,
        sequence: int,
        kind: _ResolverOutputKind,
        payload: bytes,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _OBSERVATION_AUTHORITY:
            raise TypeError("resolver output observations require their cache")
        checked_sequence, checked_kind, checked_payload = _validate_payload(
            sequence,
            kind,
            payload,
        )
        values = (
            ("epoch_id", require_uuid(epoch_id, "epoch_id")),
            ("operation_id", require_uuid(operation_id, "operation_id")),
            ("proxy_id", require_uuid(proxy_id, "proxy_id")),
            (
                "operation_binding_digest",
                require_digest(
                    operation_binding_digest,
                    "operation_binding_digest",
                ),
            ),
            ("sequence", checked_sequence),
            ("kind", checked_kind),
            ("payload", checked_payload),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        selected_delivery = _delivery_id(
            epoch_id=self.epoch_id,
            operation_id=self.operation_id,
            proxy_id=self.proxy_id,
            operation_binding_digest=self.operation_binding_digest,
            sequence=self.sequence,
            kind=self.kind,
        )
        selected_payload_digest = _payload_digest(
            sequence=self.sequence,
            kind=self.kind,
            payload=self.payload,
        )
        selected_digest = _observation_digest(
            epoch_id=self.epoch_id,
            operation_id=self.operation_id,
            proxy_id=self.proxy_id,
            operation_binding_digest=self.operation_binding_digest,
            delivery_id=selected_delivery,
            sequence=self.sequence,
            kind=self.kind,
            payload_digest=selected_payload_digest,
            payload_size=len(self.payload),
        )
        object.__setattr__(self, "delivery_id", selected_delivery)
        object.__setattr__(self, "payload_digest", selected_payload_digest)
        object.__setattr__(self, "observation_digest", selected_digest)
        object.__setattr__(self, "_issued_digest", selected_digest)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverOutputObservation is immutable")

    def __copy__(self) -> "_ResolverOutputObservation":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_ResolverOutputObservation":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("ResolverOutputObservation is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("ResolverOutputObservation is not serializable")

    def __getstate__(self) -> object:
        raise TypeError("ResolverOutputObservation is not serializable")

    def validate_integrity(self) -> None:
        sequence, kind, payload = _validate_payload(
            self.sequence,
            self.kind,
            self.payload,
        )
        epoch_id = require_uuid(self.epoch_id, "epoch_id")
        operation_id = require_uuid(self.operation_id, "operation_id")
        proxy_id = require_uuid(self.proxy_id, "proxy_id")
        binding_digest = require_digest(
            self.operation_binding_digest,
            "operation_binding_digest",
        )
        expected_delivery = _delivery_id(
            epoch_id=epoch_id,
            operation_id=operation_id,
            proxy_id=proxy_id,
            operation_binding_digest=binding_digest,
            sequence=sequence,
            kind=kind,
        )
        expected_payload_digest = _payload_digest(
            sequence=sequence,
            kind=kind,
            payload=payload,
        )
        expected_digest = _observation_digest(
            epoch_id=epoch_id,
            operation_id=operation_id,
            proxy_id=proxy_id,
            operation_binding_digest=binding_digest,
            delivery_id=expected_delivery,
            sequence=sequence,
            kind=kind,
            payload_digest=expected_payload_digest,
            payload_size=len(payload),
        )
        if (
            self.delivery_id != expected_delivery
            or self.payload_digest != expected_payload_digest
            or self.observation_digest != expected_digest
            or self._issued_digest != expected_digest
        ):
            raise ValueError("resolver output observation integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "delivery_id": str(self.delivery_id),
            "kind": self.kind.value,
            "observation_digest_prefix": str(self.observation_digest)[:12],
            "operation_id": str(self.operation_id),
            "payload_size": len(self.payload),
            "sequence": self.sequence,
        }


@runtime_final
class _ResolverOutputTombstone:
    """Payload-free durable acknowledgement of one exact observation."""

    __slots__ = (
        "epoch_id",
        "operation_id",
        "proxy_id",
        "operation_binding_digest",
        "delivery_id",
        "sequence",
        "kind",
        "payload_digest",
        "payload_size",
        "observation_digest",
        "tombstone_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        observation: _ResolverOutputObservation,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TOMBSTONE_AUTHORITY:
            raise TypeError("resolver output tombstones require their cache")
        observation.validate_integrity()
        for name, value in (
            ("epoch_id", observation.epoch_id),
            ("operation_id", observation.operation_id),
            ("proxy_id", observation.proxy_id),
            (
                "operation_binding_digest",
                observation.operation_binding_digest,
            ),
            ("delivery_id", observation.delivery_id),
            ("sequence", observation.sequence),
            ("kind", observation.kind),
            ("payload_digest", observation.payload_digest),
            ("payload_size", len(observation.payload)),
            ("observation_digest", observation.observation_digest),
        ):
            object.__setattr__(self, name, value)
        selected = digest256(
            "ResolverOutputTombstone",
            RESOLVER_OUTPUT_TOMBSTONE_SCHEMA_VERSION,
            {
                "delivery_id": self.delivery_id,
                "epoch_id": self.epoch_id,
                "kind": self.kind,
                "observation_digest": self.observation_digest,
                "operation_binding_digest": self.operation_binding_digest,
                "operation_id": self.operation_id,
                "payload_digest": self.payload_digest,
                "payload_size": self.payload_size,
                "proxy_id": self.proxy_id,
                "sequence": self.sequence,
            },
        )
        object.__setattr__(self, "tombstone_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverOutputTombstone is immutable")

    def validate_integrity(self) -> None:
        epoch_id = require_uuid(self.epoch_id, "epoch_id")
        operation_id = require_uuid(self.operation_id, "operation_id")
        proxy_id = require_uuid(self.proxy_id, "proxy_id")
        operation_binding_digest = require_digest(
            self.operation_binding_digest,
            "operation_binding_digest",
        )
        delivery_id = require_uuid(self.delivery_id, "delivery_id")
        sequence = require_plain_int(self.sequence, "sequence", minimum=0)
        if type(self.kind) is not _ResolverOutputKind:
            raise ValueError("resolver output tombstone kind is invalid")
        if _SEQUENCE_OUTPUT.get(sequence) is not self.kind:
            raise ValueError("resolver output tombstone sequence is invalid")
        payload_digest = require_digest(
            self.payload_digest,
            "payload_digest",
        )
        payload_size = require_plain_int(
            self.payload_size,
            "payload_size",
            minimum=0,
        )
        if payload_size > MAX_RESOLVER_OUTPUT_PAYLOAD_BYTES:
            raise ValueError("resolver output tombstone payload size is invalid")
        observation_digest = require_digest(
            self.observation_digest,
            "observation_digest",
        )
        expected = digest256(
            "ResolverOutputTombstone",
            RESOLVER_OUTPUT_TOMBSTONE_SCHEMA_VERSION,
            {
                "delivery_id": delivery_id,
                "epoch_id": epoch_id,
                "kind": self.kind,
                "observation_digest": observation_digest,
                "operation_binding_digest": operation_binding_digest,
                "operation_id": operation_id,
                "payload_digest": payload_digest,
                "payload_size": payload_size,
                "proxy_id": proxy_id,
                "sequence": sequence,
            },
        )
        if self.tombstone_digest != expected or self._issued_digest != expected:
            raise ValueError("resolver output tombstone integrity failed")

    def matches(self, observation: _ResolverOutputObservation) -> bool:
        try:
            self.validate_integrity()
            observation.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            return False
        return (
            observation.epoch_id == self.epoch_id
            and observation.operation_id == self.operation_id
            and observation.proxy_id == self.proxy_id
            and observation.operation_binding_digest
            == self.operation_binding_digest
            and observation.delivery_id == self.delivery_id
            and observation.sequence == self.sequence
            and observation.kind is self.kind
            and observation.payload_digest == self.payload_digest
            and len(observation.payload) == self.payload_size
            and observation.observation_digest == self.observation_digest
        )


@runtime_final
class _ResolverOutputPublication:
    """One child-facing sink; publication stores the slot before returning."""

    __slots__ = ("_cache", "sequence", "kind")

    def __init__(
        self,
        *,
        cache: "_ResolverOutputCache",
        sequence: int,
        kind: _ResolverOutputKind,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PUBLICATION_AUTHORITY:
            raise TypeError("resolver output publications require their cache")
        object.__setattr__(self, "_cache", cache)
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "kind", kind)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverOutputPublication is immutable")

    def publish(self, payload: bytes) -> _ResolverOutputObservation:
        return self._cache._publish(self, payload)


@runtime_final
class _ResolverOutputCache:
    """Three-delivery, one-payload-slot cache for one bound operation."""

    __slots__ = (
        "epoch_id",
        "operation_id",
        "proxy_id",
        "operation_binding_digest",
        "_lock",
        "_publication",
        "_slot",
        "_tombstones",
        "_poisoned",
    )

    def __init__(
        self,
        *,
        epoch_id: UUID,
        operation_id: UUID,
        proxy_id: UUID,
        operation_binding_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CACHE_AUTHORITY:
            raise TypeError("resolver output caches require their factory")
        object.__setattr__(self, "epoch_id", require_uuid(epoch_id, "epoch_id"))
        object.__setattr__(
            self,
            "operation_id",
            require_uuid(operation_id, "operation_id"),
        )
        object.__setattr__(self, "proxy_id", require_uuid(proxy_id, "proxy_id"))
        object.__setattr__(
            self,
            "operation_binding_digest",
            require_digest(
                operation_binding_digest,
                "operation_binding_digest",
            ),
        )
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_publication", None)
        object.__setattr__(self, "_slot", None)
        object.__setattr__(self, "_tombstones", {})
        object.__setattr__(self, "_poisoned", False)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverOutputCache identity is immutable")

    def _fail(self, message: str) -> NoReturn:
        object.__setattr__(self, "_poisoned", True)
        _raise_cache_error(message)

    def _require_live(self) -> None:
        if self._poisoned:
            _raise_cache_error("resolver output cache 已隔离。")

    def _validate_tombstones_locked(self) -> None:
        if (
            len(self._tombstones) > len(_SEQUENCE_OUTPUT)
            or set(self._tombstones) != set(range(len(self._tombstones)))
        ):
            self._fail("resolver output tombstone ledger 已损坏。")
        for sequence, tombstone in self._tombstones.items():
            try:
                exact = (
                    type(tombstone) is _ResolverOutputTombstone
                    and tombstone.sequence == sequence
                    and tombstone.epoch_id == self.epoch_id
                    and tombstone.operation_id == self.operation_id
                    and tombstone.proxy_id == self.proxy_id
                    and tombstone.operation_binding_digest
                    == self.operation_binding_digest
                )
                tombstone.validate_integrity()
            except (AttributeError, TypeError, ValueError):
                exact = False
            if not exact:
                self._fail("resolver output tombstone ledger 已损坏。")

    def new_publication(
        self,
        *,
        sequence: int,
        kind: _ResolverOutputKind,
    ) -> _ResolverOutputPublication:
        checked_sequence = require_plain_int(sequence, "sequence", minimum=0)
        if type(kind) is not _ResolverOutputKind:
            raise TypeError("kind must be ResolverOutputKind")
        with self._lock:
            self._require_live()
            self._validate_tombstones_locked()
            expected = len(self._tombstones)
            if checked_sequence != expected or _SEQUENCE_OUTPUT.get(expected) is not kind:
                self._fail("resolver output publication 顺序已变化。")
            publication = self._publication
            if publication is None:
                publication = _ResolverOutputPublication(
                    cache=self,
                    sequence=checked_sequence,
                    kind=kind,
                    _authority=_PUBLICATION_AUTHORITY,
                )
                object.__setattr__(self, "_publication", publication)
            elif (
                publication.sequence != checked_sequence
                or publication.kind is not kind
            ):
                self._fail("resolver output publication binding 已变化。")
            return publication

    def _publish(
        self,
        publication: _ResolverOutputPublication,
        payload: bytes,
    ) -> _ResolverOutputObservation:
        with self._lock:
            self._require_live()
            self._validate_tombstones_locked()
            if publication is not self._publication or publication._cache is not self:
                self._fail("resolver output publication owner 无效。")
            try:
                sequence, kind, checked_payload = _validate_payload(
                    publication.sequence,
                    publication.kind,
                    payload,
                )
            except (TypeError, ValueError):
                self._fail("resolver output payload 无效。")
            selected = _ResolverOutputObservation(
                epoch_id=self.epoch_id,
                operation_id=self.operation_id,
                proxy_id=self.proxy_id,
                operation_binding_digest=self.operation_binding_digest,
                sequence=sequence,
                kind=kind,
                payload=checked_payload,
                _authority=_OBSERVATION_AUTHORITY,
            )
            existing = self._slot
            if existing is None:
                object.__setattr__(self, "_slot", selected)
                return selected
            try:
                existing.validate_integrity()
            except (AttributeError, TypeError, ValueError):
                self._fail("resolver output cache slot 已损坏。")
            if (
                existing.delivery_id != selected.delivery_id
                or existing.observation_digest != selected.observation_digest
                or existing.payload != selected.payload
            ):
                self._fail("resolver output delivery 已变化。")
            return existing

    def current(
        self,
        publication: _ResolverOutputPublication,
    ) -> _ResolverOutputObservation | None:
        with self._lock:
            self._require_live()
            self._validate_tombstones_locked()
            if publication is not self._publication or publication._cache is not self:
                self._fail("resolver output publication owner 无效。")
            selected = self._slot
            if selected is not None:
                try:
                    selected.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    self._fail("resolver output cache slot 已损坏。")
            return selected

    def acknowledge(
        self,
        observation: _ResolverOutputObservation,
    ) -> _ResolverOutputTombstone:
        with self._lock:
            self._require_live()
            self._validate_tombstones_locked()
            try:
                observation.validate_integrity()
            except (AttributeError, TypeError, ValueError):
                self._fail("resolver output ACK observation 无效。")
            if (
                observation.epoch_id != self.epoch_id
                or observation.operation_id != self.operation_id
                or observation.proxy_id != self.proxy_id
                or observation.operation_binding_digest
                != self.operation_binding_digest
            ):
                self._fail("resolver output ACK operation binding 无效。")
            existing_tombstone = self._tombstones.get(observation.sequence)
            if existing_tombstone is not None:
                try:
                    existing_tombstone.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    self._fail("resolver output ACK tombstone 已损坏。")
                if not existing_tombstone.matches(observation):
                    self._fail("resolver output ACK tombstone 已变化。")
                slot = self._slot
                if slot is observation:
                    object.__setattr__(self, "_slot", None)
                    object.__setattr__(self, "_publication", None)
                return existing_tombstone
            slot = self._slot
            if slot is not observation:
                self._fail("resolver output ACK exact observation 缺失。")
            tombstone = _ResolverOutputTombstone(
                observation,
                _authority=_TOMBSTONE_AUTHORITY,
            )
            retained = self._tombstones.setdefault(
                observation.sequence,
                tombstone,
            )
            if retained is not tombstone and not retained.matches(observation):
                self._fail("resolver output ACK publication 冲突。")
            # The payload-free tombstone is durable before the sole slot is
            # released.  An interruption between these stores is recovered by
            # the idempotent branch above.
            object.__setattr__(self, "_slot", None)
            object.__setattr__(self, "_publication", None)
            return retained

    def acknowledged(
        self,
        observation: _ResolverOutputObservation,
    ) -> _ResolverOutputTombstone | None:
        """Observe an exact prior ACK without creating a new tombstone."""

        with self._lock:
            self._require_live()
            self._validate_tombstones_locked()
            try:
                observation.validate_integrity()
            except (AttributeError, TypeError, ValueError):
                self._fail("resolver output ACK observation 无效。")
            if (
                observation.epoch_id != self.epoch_id
                or observation.operation_id != self.operation_id
                or observation.proxy_id != self.proxy_id
                or observation.operation_binding_digest
                != self.operation_binding_digest
            ):
                self._fail("resolver output ACK operation binding 无效。")
            tombstone = self._tombstones.get(observation.sequence)
            if tombstone is not None:
                try:
                    tombstone.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    self._fail("resolver output ACK tombstone 已损坏。")
                if not tombstone.matches(observation):
                    self._fail("resolver output ACK tombstone 已变化。")
            return tombstone

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            if self._poisoned:
                return {
                    "acked_count": 0,
                    "next_sequence": 0,
                    "poisoned": True,
                    "slot_kind": None,
                    "slot_payload_size": 0,
                    "slot_present": False,
                    "tombstone_count": 0,
                }
            self._validate_tombstones_locked()
            slot = self._slot
            if slot is not None:
                try:
                    slot.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    self._fail("resolver output cache slot 已损坏。")
            return {
                "acked_count": len(self._tombstones),
                "next_sequence": len(self._tombstones),
                "poisoned": self._poisoned,
                "slot_kind": None if slot is None else slot.kind.value,
                "slot_payload_size": 0 if slot is None else len(slot.payload),
                "slot_present": slot is not None,
                "tombstone_count": len(self._tombstones),
            }


def _new_resolver_output_cache(
    *,
    epoch_id: UUID,
    operation_id: UUID,
    proxy_id: UUID,
    operation_binding_digest: Digest256,
) -> _ResolverOutputCache:
    return _ResolverOutputCache(
        epoch_id=epoch_id,
        operation_id=operation_id,
        proxy_id=proxy_id,
        operation_binding_digest=operation_binding_digest,
        _authority=_CACHE_AUTHORITY,
    )
