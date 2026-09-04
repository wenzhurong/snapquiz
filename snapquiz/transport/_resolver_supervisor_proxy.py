"""Injected W09-B2b-S3 resolver-supervisor proxy integration.

The objects in this module adapt ``resolver.HelperSpawner``/``HelperKernel``
to the durable operation model frozen by ``_resolver_supervisor_contract``.
They deliberately do not bootstrap, spawn, resolve, or open a network socket.
The only concrete channel is an in-memory, wire-validating test seam; a later
slice must replace it with the already-attested production supervisor session.

One call to ``spawn(..., max_wait_ns=...)`` performs at most one channel
exchange.  The first successful RESERVE still owns zero children.  The exact
operation, command frames, proxy and resolver publication are retained across
``PENDING`` re-entry.  A kernel is returned only after the exact ARM fact is
attested by either its ACK or a bound STATE query.
"""
from __future__ import annotations

from enum import Enum
from threading import Lock
from typing import Callable, NoReturn
from uuid import UUID, uuid5

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_supervisor_contract as contract
from snapquiz.transport import _resolver_supervisor_wire as wire
from snapquiz.transport import resolver


__all__ = ()


MAX_SUPERVISOR_PROXY_WAIT_NS = 50_000_000
SUPERVISOR_PROXY_SCHEMA_VERSION = "snapquiz.resolver-supervisor-proxy.v1"
SUPERVISOR_ACTIVE_OPERATION_LIMIT = 64
SUPERVISOR_REPLAY_LIMIT_PER_OPERATION = 64
# Keep enough of the 64-frame ledger for one CANCEL, the eight authoritative
# cleanup observations required by the parent contract, and terminal/release
# recovery.  Ordinary business queries cannot consume this tail.
SUPERVISOR_TERMINAL_REPLAY_RESERVE = (
    contract.SUPERVISOR_CLEANUP_PENDING_LIMIT + 4
)
_SUPERVISOR_TERMINAL_ONLY_REPLAY_RESERVE = 3
SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT = 256
SUPERVISOR_RECEIVED_HISTORY_LIMIT = 256

_ROLE_NAMESPACE = UUID("c789581b-a84d-54fa-a32f-adf5c1f3e140")
_CHANNEL_RESPONSE_AUTHORITY = object()
_IN_MEMORY_CHANNEL_AUTHORITY = object()
_SPAWNER_AUTHORITY = object()
_KERNEL_AUTHORITY = object()


class _DefiniteSupervisorCapacityError(EndpointPolicyError):
    """A pre-mutation capacity refusal that must not degrade to PENDING."""


class _DefiniteSupervisorProtocolError(EndpointPolicyError):
    """A committed terminal conflict that must not degrade to PENDING."""


def _capacity_error(message: str) -> _DefiniteSupervisorCapacityError:
    error = _DefiniteSupervisorCapacityError(
        stage="resolver_supervisor_capacity",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _protocol_error(message: str) -> _DefiniteSupervisorProtocolError:
    error = _DefiniteSupervisorProtocolError(
        stage="resolver_supervisor_protocol",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _proxy_error(message: str) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="resolver_supervisor_proxy",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_proxy_error(message: str) -> NoReturn:
    raise _proxy_error(message) from None


def _wait_limit(value: object) -> int:
    selected = require_plain_int(value, "max_wait_ns", minimum=1)
    if selected > MAX_SUPERVISOR_PROXY_WAIT_NS:
        raise ValueError(
            f"max_wait_ns must be <= {MAX_SUPERVISOR_PROXY_WAIT_NS}"
        )
    return selected


def _try_acquire(lock: object) -> bool:
    acquire = getattr(lock, "acquire", None)
    release = getattr(lock, "release", None)
    if not callable(acquire) or not callable(release):
        return False
    try:
        return acquire(blocking=False) is True
    except (TypeError, ValueError):
        return False


def _same_binding(
    first: contract._SupervisorOperationBinding,
    second: contract._SupervisorOperationBinding,
) -> bool:
    return contract._same_binding(first, second)


def _operation_role_uuid(
    *,
    epoch_id: UUID,
    lifecycle_id: UUID,
    publication_id: UUID,
    spawn_request_digest: Digest256,
    role: str,
) -> UUID:
    selected = digest256(
        "ResolverSupervisorProxyRole",
        SUPERVISOR_PROXY_SCHEMA_VERSION,
        {
            "epoch_id": require_uuid(epoch_id, "epoch_id"),
            "lifecycle_id": require_uuid(lifecycle_id, "lifecycle_id"),
            "publication_id": require_uuid(publication_id, "publication_id"),
            "role": role,
            "spawn_request_digest": require_digest(
                spawn_request_digest,
                "spawn_request_digest",
            ),
        },
    )
    return uuid5(_ROLE_NAMESPACE, str(selected))


def _bound_role_uuid(
    binding: contract._SupervisorOperationBinding,
    role: str,
    sequence: int = 0,
) -> UUID:
    binding.validate_integrity()
    require_plain_int(sequence, "sequence", minimum=0)
    selected = digest256(
        "ResolverSupervisorProxyBoundRole",
        SUPERVISOR_PROXY_SCHEMA_VERSION,
        {
            "binding_digest": binding.binding_digest,
            "role": role,
            "sequence": sequence,
        },
    )
    return uuid5(_ROLE_NAMESPACE, str(selected))


def _wire_state_payload(
    attestation: contract._SupervisorOperationAttestation,
    *,
    proxy_id: UUID,
    query_id: UUID,
) -> dict[str, object]:
    attestation.validate_integrity()
    return {
        "arm_command_id": attestation.arm_command_id,
        "attachment_command_id": attestation.attachment_command_id,
        "attachment_proof_digest": attestation.attachment_proof_digest,
        "attestation_digest": attestation.attestation_digest,
        "cancel_command_id": attestation.cancel_command_id,
        "cancel_latched": attestation.cancel_latched,
        "cancel_payload_digest": attestation.cancel_payload_digest,
        "child_ever_owned": attestation.child_ever_owned,
        "cleanup_phase": wire._SupervisorWireCleanupPhase(
            attestation.cleanup_phase.value
        ),
        "close_action_id": attestation.close_action_id,
        "poison_reason": (
            None
            if attestation.poison_reason is None
            else wire._SupervisorWirePoisonReason(
                attestation.poison_reason.value
            )
        ),
        "proxy_id": require_uuid(proxy_id, "proxy_id"),
        "query_id": require_uuid(query_id, "query_id"),
        "ready_event_id": attestation.ready_event_id,
        "reap_action_id": attestation.reap_action_id,
        "release_tombstone_id": attestation.release_tombstone_id,
        "result_digest": attestation.result_digest,
        "result_event_id": attestation.result_event_id,
        "success_cleanup_event_id": attestation.success_cleanup_event_id,
        "durable_eof_ack_digest": attestation.durable_eof_ack_digest,
        "revision": attestation.revision,
        "spawn_created": attestation.spawn_created,
        "spawn_event_id": attestation.spawn_event_id,
        "start_command_id": attestation.start_command_id,
        "start_committed": attestation.start_committed,
        "start_payload_digest": attestation.start_payload_digest,
        "state": wire._SupervisorWireState(attestation.state.value),
        "terminal_attestation_id": attestation.terminal_attestation_id,
        "terminal_kind": (
            None
            if attestation.terminal_kind is None
            else wire._SupervisorWireTerminalKind(
                attestation.terminal_kind.value
            )
        ),
        "terminal_status": attestation.terminal_status,
        "terminate_action_id": attestation.terminate_action_id,
    }


def _require_wire_attestation(
    frame: wire._SupervisorWireFrame,
    attestation: contract._SupervisorOperationAttestation,
    *,
    binding: contract._SupervisorOperationBinding,
    proxy_id: UUID,
    query_id: UUID | None,
) -> None:
    try:
        frame.validate_integrity()
        attestation.validate_integrity()
        frame.require_binding(
            epoch_id=binding.epoch_id,
            operation_id=binding.operation_id,
            control_channel_id=frame.control_channel_id,
            operation_binding_digest=binding.binding_digest,
        )
        if not _same_binding(binding, attestation.binding):
            raise ValueError("attestation binding changed")
        if frame.kind is wire._SupervisorWireKind.ACK:
            if (
                frame.payload["attestation_digest"]
                != attestation.attestation_digest
                or frame.payload["revision"] != attestation.revision
            ):
                raise ValueError("ACK attestation changed")
        elif frame.kind is wire._SupervisorWireKind.STATE:
            if query_id is None:
                raise ValueError("STATE query is absent")
            expected = _wire_state_payload(
                attestation,
                proxy_id=proxy_id,
                query_id=query_id,
            )
            if dict(frame.payload) != expected:
                raise ValueError("STATE attestation changed")
        else:
            raise ValueError("unexpected supervisor reply kind")
    except (AttributeError, TypeError, ValueError):
        _raise_proxy_error("resolver supervisor response attestation 无效。")


@runtime_final
class _SupervisorChannelResponse:
    """Wire reply plus its local-only S1 object-capability observation."""

    __slots__ = ("wire_bytes", "attestation", "_frame")

    def __init__(
        self,
        *,
        frame: wire._SupervisorWireFrame,
        attestation: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CHANNEL_RESPONSE_AUTHORITY:
            raise TypeError("channel response requires its channel")
        if type(frame) is not wire._SupervisorWireFrame:
            raise TypeError("frame must be SupervisorWireFrame")
        if type(attestation) not in (
            contract._SupervisorOperationAttestation,
            _PrimitiveAttestationReplay,
        ):
            raise TypeError("attestation must be SupervisorOperationAttestation")
        frame.validate_integrity()
        attestation.validate_integrity()
        object.__setattr__(self, "_frame", frame)
        object.__setattr__(
            self,
            "wire_bytes",
            wire._encode_supervisor_wire_frame(frame),
        )
        object.__setattr__(self, "attestation", attestation)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorChannelResponse is immutable")


class _ChannelReplay:
    __slots__ = (
        "frame_bytes",
        "frame_digest",
        "local_proof",
        "response",
    )

    def __init__(
        self,
        *,
        frame_bytes: bytes,
        frame_digest: Digest256,
        local_proof: object,
        response: _SupervisorChannelResponse,
    ) -> None:
        if type(frame_bytes) is not bytes:
            raise TypeError("frame_bytes must be immutable bytes")
        self.frame_bytes = frame_bytes
        self.frame_digest = frame_digest
        self.local_proof = local_proof
        self.response = response


_ATTESTATION_REPLAY_FIELDS = (
    "revision",
    "state",
    "attachment_command_id",
    "attachment_proof_digest",
    "arm_command_id",
    "cancel_command_id",
    "cancel_payload_digest",
    "cancel_latched",
    "spawn_event_id",
    "spawn_created",
    "child_ever_owned",
    "ready_event_id",
    "start_command_id",
    "start_payload_digest",
    "start_committed",
    "result_event_id",
    "result_digest",
    "success_cleanup_event_id",
    "durable_eof_ack_digest",
    "cleanup_phase",
    "terminate_action_id",
    "reap_action_id",
    "close_action_id",
    "terminal_attestation_id",
    "terminal_kind",
    "terminal_status",
    "release_tombstone_id",
    "poison_reason",
    "attestation_digest",
)


class _PrimitiveAttestationReplay:
    """Capability-free copy sufficient to validate one exact wire replay."""

    __slots__ = ("binding",) + _ATTESTATION_REPLAY_FIELDS + ("_issued_digest",)

    def __init__(
        self,
        attestation: contract._SupervisorOperationAttestation,
    ) -> None:
        if type(attestation) is not contract._SupervisorOperationAttestation:
            raise TypeError("attestation must be SupervisorOperationAttestation")
        attestation.validate_integrity()
        object.__setattr__(self, "binding", attestation.binding)
        for name in _ATTESTATION_REPLAY_FIELDS:
            object.__setattr__(self, name, getattr(attestation, name))
        object.__setattr__(self, "_issued_digest", self.attestation_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("PrimitiveAttestationReplay is immutable")

    def validate_integrity(self) -> None:
        if type(self.binding) is not contract._SupervisorOperationBinding:
            raise ValueError("primitive attestation binding is invalid")
        self.binding.validate_integrity()
        contract._validate_attestation_facts(self)
        expected = digest256(
            "ResolverSupervisorOperationAttestation",
            contract.SUPERVISOR_ATTESTATION_SCHEMA_VERSION,
            contract._attestation_payload(self),
        )
        if (
            type(self.attestation_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.attestation_digest != expected
            or self._issued_digest != expected
        ):
            raise ValueError("primitive attestation digest is invalid")


def _local_proof_snapshot(value: object) -> tuple[object, ...] | None:
    if value is None:
        return None
    if type(value) is not contract._SupervisorPublicationProof:
        raise TypeError("local publication proof is invalid")
    value.validate_integrity()
    return (
        value.publication_id,
        value.binding_digest,
        value.proxy_id,
        value.reservation_attestation_digest,
        value.proof_id,
        value.proof_digest,
    )


class _PrimitiveChannelReplay:
    """Bounded replay data with no proxy, publication, ledger, or child refs."""

    __slots__ = (
        "frame_bytes",
        "frame_digest",
        "frame_id",
        "local_proof_snapshot",
        "response_wire_bytes",
        "response_attestation",
    )

    def __init__(self, replay: _ChannelReplay) -> None:
        if type(replay) is not _ChannelReplay:
            raise TypeError("replay must be ChannelReplay")
        command = wire._decode_supervisor_wire_frame(replay.frame_bytes)
        response = replay.response
        if type(response) is not _SupervisorChannelResponse:
            raise TypeError("replay response is invalid")
        object.__setattr__(self, "frame_bytes", replay.frame_bytes)
        object.__setattr__(self, "frame_digest", replay.frame_digest)
        object.__setattr__(self, "frame_id", command.frame_id)
        object.__setattr__(
            self,
            "local_proof_snapshot",
            _local_proof_snapshot(replay.local_proof),
        )
        object.__setattr__(self, "response_wire_bytes", response.wire_bytes)
        object.__setattr__(
            self,
            "response_attestation",
            _PrimitiveAttestationReplay(response.attestation),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("PrimitiveChannelReplay is immutable")

    def matches(
        self,
        *,
        frame_bytes: bytes,
        command: wire._SupervisorWireFrame,
        local_publication_proof: object,
    ) -> bool:
        try:
            return (
                self.frame_bytes == frame_bytes
                and self.frame_digest == command.frame_digest
                and self.frame_id == command.frame_id
                and self.local_proof_snapshot
                == _local_proof_snapshot(local_publication_proof)
            )
        except (AttributeError, TypeError, ValueError):
            return False

    def response(self) -> _SupervisorChannelResponse:
        frame = wire._decode_supervisor_wire_frame(self.response_wire_bytes)
        return _SupervisorChannelResponse(
            frame=frame,
            attestation=self.response_attestation,
            _authority=_CHANNEL_RESPONSE_AUTHORITY,
        )


class _ReleasedChannelTombstone:
    """Channel-owned, bounded and capability-free terminal replay anchor."""

    __slots__ = (
        "binding",
        "proxy_id",
        "release_tombstone_id",
        "release_attestation_digest",
        "release_attestation",
        "replays",
    )

    def __init__(
        self,
        *,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        release_attestation: contract._SupervisorOperationAttestation,
        replays: tuple[_ChannelReplay, ...],
    ) -> None:
        binding.validate_integrity()
        release_attestation.validate_integrity()
        if (
            not _same_binding(binding, release_attestation.binding)
            or release_attestation.state
            is not contract._BrokerOperationState.RELEASED
            or release_attestation.release_tombstone_id is None
            or release_attestation.terminal_attestation_id is None
        ):
            raise ValueError("released channel attestation is invalid")
        if len(replays) > SUPERVISOR_REPLAY_LIMIT_PER_OPERATION:
            raise ValueError("released channel replay limit exceeded")
        selected_replays = tuple(
            _PrimitiveChannelReplay(replay) for replay in replays
        )
        if len({replay.frame_id for replay in selected_replays}) != len(
            selected_replays
        ):
            raise ValueError("released channel replay identifiers conflict")
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "proxy_id", require_uuid(proxy_id, "proxy_id"))
        object.__setattr__(
            self,
            "release_tombstone_id",
            release_attestation.release_tombstone_id,
        )
        object.__setattr__(
            self,
            "release_attestation_digest",
            release_attestation.attestation_digest,
        )
        object.__setattr__(
            self,
            "release_attestation",
            _PrimitiveAttestationReplay(release_attestation),
        )
        object.__setattr__(self, "replays", selected_replays)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ReleasedChannelTombstone is immutable")

    def validate_binding(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
    ) -> None:
        if (
            not _same_binding(self.binding, binding)
            or self.proxy_id != require_uuid(proxy_id, "proxy_id")
        ):
            _raise_proxy_error("resolver supervisor released binding 已变化。")

    def replay_for(self, frame_id: UUID) -> _PrimitiveChannelReplay | None:
        checked = require_uuid(frame_id, "frame_id")
        matches = tuple(
            replay for replay in self.replays if replay.frame_id == checked
        )
        if len(matches) > 1:
            _raise_proxy_error("resolver supervisor terminal replay 已损坏。")
        return None if not matches else matches[0]


@runtime_final
class _InMemorySupervisorChannel:
    """Wire-validating injected channel; it performs no process or network I/O."""

    __slots__ = (
        "epoch_id",
        "control_channel_id",
        "ports",
        "_lock",
        "_replays",
        "_terminal_tombstones",
        "_received",
        "_initial_stdout_results",
        "_initial_stdin_results",
        "_stdout_by_operation",
        "_stdin_by_operation",
        "_closed_operations",
        "_operation_pipe_close_total",
        "_session_closed",
        "_spawner_owner",
    )

    def __init__(
        self,
        *,
        epoch_id: UUID,
        control_channel_id: UUID,
        stdout_results: tuple[object, ...] = (),
        stdin_results: tuple[object, ...] = (),
        _authority: object | None = None,
    ) -> None:
        if _authority is not _IN_MEMORY_CHANNEL_AUTHORITY:
            raise TypeError("in-memory supervisor channel requires its factory")
        object.__setattr__(self, "epoch_id", require_uuid(epoch_id, "epoch_id"))
        object.__setattr__(
            self,
            "control_channel_id",
            require_uuid(control_channel_id, "control_channel_id"),
        )
        object.__setattr__(
            self,
            "ports",
            contract._new_supervisor_broker(epoch_id=self.epoch_id),
        )
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_replays", {})
        object.__setattr__(self, "_terminal_tombstones", {})
        object.__setattr__(self, "_received", [])
        object.__setattr__(self, "_initial_stdout_results", tuple(stdout_results))
        object.__setattr__(self, "_initial_stdin_results", tuple(stdin_results))
        object.__setattr__(self, "_stdout_by_operation", {})
        object.__setattr__(self, "_stdin_by_operation", {})
        object.__setattr__(self, "_closed_operations", set())
        object.__setattr__(self, "_operation_pipe_close_total", 0)
        object.__setattr__(self, "_session_closed", False)
        object.__setattr__(self, "_spawner_owner", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("InMemorySupervisorChannel identity is immutable")

    @property
    def received_kinds(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._received)

    @property
    def session_closed(self) -> bool:
        with self._lock:
            return self._session_closed

    def _append_received_locked(self, kind: str) -> None:
        if len(self._received) >= SUPERVISOR_RECEIVED_HISTORY_LIMIT:
            self._received.pop(0)
        self._received.append(kind)

    def _active_replay_count_locked(self, operation_id: UUID) -> int:
        return sum(
            replay.response.attestation.binding.operation_id == operation_id
            for replay in self._replays.values()
        )

    def _reject_terminal_conflict_locked(
        self,
        *,
        reason: contract._PoisonReason,
        message: str,
    ) -> NoReturn:
        try:
            self.ports.ledger._reject_locked(reason, message)
        except EndpointPolicyError:
            raise _protocol_error(message) from None

    def _require_terminal_frame_locked(
        self,
        command: wire._SupervisorWireFrame,
        tombstone: _ReleasedChannelTombstone,
    ) -> None:
        try:
            command.require_binding(
                epoch_id=tombstone.binding.epoch_id,
                operation_id=tombstone.binding.operation_id,
                control_channel_id=self.control_channel_id,
                operation_binding_digest=tombstone.binding.binding_digest,
            )
            if command.kind is wire._SupervisorWireKind.RESERVE:
                supplied = self._binding_for_reserve_frame(command)
                if not _same_binding(supplied, tombstone.binding):
                    raise ValueError("released RESERVE binding changed")
            elif command.payload["proxy_id"] != tombstone.proxy_id:
                raise ValueError("released proxy binding changed")
        except (AttributeError, KeyError, TypeError, ValueError):
            self._reject_terminal_conflict_locked(
                reason=contract._PoisonReason.BINDING_MISMATCH,
                message="supervisor released wire binding 已变化。",
            )

    @staticmethod
    def _binding_for_reserve_frame(
        frame: wire._SupervisorWireFrame,
    ) -> contract._SupervisorOperationBinding:
        return contract._new_supervisor_operation_binding(
            epoch_id=frame.epoch_id,
            operation_id=frame.operation_id,
            lifecycle_id=frame.payload["lifecycle_id"],
            publication_id=frame.payload["publication_id"],
            spawn_request_digest=frame.payload["spawn_request_digest"],
        )

    def preflight_admission(self) -> object:
        """Refuse new work before any operation-owned object is installed."""

        if not _try_acquire(self._lock):
            return resolver.PENDING
        broker_lock = self.ports.ledger._lock
        if not _try_acquire(broker_lock):
            self._lock.release()
            return resolver.PENDING
        try:
            active = len(self.ports.ledger._operations)
            terminal = len(self._terminal_tombstones)
            if active >= SUPERVISOR_ACTIVE_OPERATION_LIMIT:
                raise _capacity_error(
                    "resolver supervisor active operation capacity 已满。"
                )
            if active + terminal >= SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT:
                raise _capacity_error(
                    "resolver supervisor epoch terminal capacity 已满。"
                )
            return resolver.COMPLETE
        finally:
            broker_lock.release()
            self._lock.release()

    def terminal_tombstone(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
    ) -> _ReleasedChannelTombstone | None:
        """Return the immutable terminal anchor without exposing live state."""

        binding.validate_integrity()
        checked_proxy = require_uuid(proxy_id, "proxy_id")
        if _try_acquire(self._lock):
            try:
                tombstone = self._terminal_tombstones.get(
                    binding.operation_id
                )
            finally:
                self._lock.release()
        else:
            # Values are immutable and publication uses one atomic
            # ``setdefault``; a lock owner can only add, never replace/evict.
            tombstone = self._terminal_tombstones.get(binding.operation_id)
        if tombstone is None:
            return None
        tombstone.validate_binding(binding, checked_proxy)
        return tombstone

    def _spawner_operations_empty_locked(self) -> bool:
        owner = self._spawner_owner
        if owner is None:
            return True
        owner_lock = getattr(owner, "_lock", None)
        if not _try_acquire(owner_lock):
            return False
        try:
            operations = getattr(owner, "_operations", None)
            return type(operations) is dict and not operations
        finally:
            owner_lock.release()

    def epoch_rotation_ready(self) -> bool:
        """Report the only safe rotation boundary; rotation is not automatic."""

        with self._lock, self.ports.ledger._lock:
            return (
                not self.ports.ledger._operations
                and len(self._terminal_tombstones)
                >= SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT
                and self._spawner_operations_empty_locked()
            )

    def _binding_for_frame(
        self,
        frame: wire._SupervisorWireFrame,
    ) -> contract._SupervisorOperationBinding:
        if frame.kind is wire._SupervisorWireKind.RESERVE:
            return self._binding_for_reserve_frame(frame)
        record = self.ports.ledger._operations.get(frame.operation_id)
        if record is None:
            _raise_proxy_error("resolver supervisor operation 不存在。")
        binding = record.binding
        frame.require_binding(
            epoch_id=binding.epoch_id,
            operation_id=binding.operation_id,
            control_channel_id=self.control_channel_id,
            operation_binding_digest=binding.binding_digest,
        )
        expected_proxy_id = _bound_role_uuid(binding, "proxy")
        if frame.payload["proxy_id"] != expected_proxy_id:
            _raise_proxy_error("resolver supervisor command proxy binding 无效。")
        return binding

    def bind_spawner(self, spawner: object) -> None:
        """Bind one exact parent spawner to this injected session."""

        if spawner is None:
            raise TypeError("spawner must be an identity object")
        with self._lock:
            if self._spawner_owner is None:
                object.__setattr__(self, "_spawner_owner", spawner)
                return
            if self._spawner_owner is not spawner:
                _raise_proxy_error("resolver supervisor session spawner 已绑定。")

    def _reply_frame(
        self,
        *,
        command: wire._SupervisorWireFrame,
        attestation: contract._SupervisorOperationAttestation,
    ) -> wire._SupervisorWireFrame:
        response_id = _bound_role_uuid(
            attestation.binding,
            f"reply:{command.kind.value}:{command.frame_id}",
        )
        if command.kind is wire._SupervisorWireKind.QUERY:
            payload = _wire_state_payload(
                attestation,
                proxy_id=command.payload["proxy_id"],
                query_id=command.payload["query_id"],
            )
            kind = wire._SupervisorWireKind.STATE
        else:
            payload = {
                "acked_frame_digest": command.frame_digest,
                "acked_frame_id": command.frame_id,
                "acked_kind": command.kind,
                "attestation_digest": attestation.attestation_digest,
                "proxy_id": (
                    None
                    if command.kind is wire._SupervisorWireKind.RESERVE
                    else command.payload["proxy_id"]
                ),
                "revision": attestation.revision,
            }
            kind = wire._SupervisorWireKind.ACK
        return wire._new_supervisor_wire_frame(
            kind=kind,
            epoch_id=attestation.binding.epoch_id,
            operation_id=attestation.binding.operation_id,
            control_channel_id=self.control_channel_id,
            operation_binding_digest=attestation.binding.binding_digest,
            frame_id=response_id,
            payload=payload,
        )

    def exchange(
        self,
        frame_bytes: bytes,
        *,
        max_wait_ns: int,
        local_publication_proof: object = None,
    ) -> object:
        _wait_limit(max_wait_ns)
        try:
            command = wire._decode_supervisor_wire_frame(frame_bytes)
            if (
                command.epoch_id != self.epoch_id
                or command.control_channel_id != self.control_channel_id
            ):
                raise ValueError("channel binding changed")
        except (AttributeError, TypeError, ValueError):
            _raise_proxy_error("resolver supervisor command wire 无效。")

        if not _try_acquire(self._lock):
            return resolver.PENDING
        broker_lock = self.ports.ledger._lock
        if not _try_acquire(broker_lock):
            self._lock.release()
            return resolver.PENDING
        try:
            released = self._terminal_tombstones.get(command.operation_id)
            if released is not None:
                self._require_terminal_frame_locked(command, released)
                retained = released.replay_for(command.frame_id)
                if retained is None:
                    raise _protocol_error(
                        "resolver supervisor released operation 拒绝新 frame。"
                    )
                if not retained.matches(
                    frame_bytes=frame_bytes,
                    command=command,
                    local_publication_proof=local_publication_proof,
                ):
                    self._reject_terminal_conflict_locked(
                        reason=contract._PoisonReason.EVENT_EQUIVOCATION,
                        message="supervisor released frame replay 冲突。",
                    )
                return retained.response()

            existing = self._replays.get(command.frame_id)
            if existing is not None:
                if (
                    existing.frame_bytes != frame_bytes
                    or existing.frame_digest != command.frame_digest
                    or existing.local_proof is not local_publication_proof
                ):
                    _raise_proxy_error("resolver supervisor frame replay 冲突。")
                return existing.response

            if command.kind is wire._SupervisorWireKind.RESERVE:
                active = len(self.ports.ledger._operations)
                if active >= SUPERVISOR_ACTIVE_OPERATION_LIMIT:
                    raise _capacity_error(
                        "resolver supervisor active operation capacity 已满。"
                    )
                if (
                    active + len(self._terminal_tombstones)
                    >= SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT
                ):
                    raise _capacity_error(
                        "resolver supervisor epoch terminal capacity 已满。"
                    )
            replay_count = self._active_replay_count_locked(
                command.operation_id
            )
            if replay_count >= SUPERVISOR_REPLAY_LIMIT_PER_OPERATION:
                raise _capacity_error(
                    "resolver supervisor operation replay capacity 已满。"
                )
            if replay_count >= (
                SUPERVISOR_REPLAY_LIMIT_PER_OPERATION
                - SUPERVISOR_TERMINAL_REPLAY_RESERVE
            ):
                record = self.ports.ledger._operations.get(
                    command.operation_id
                )
                cleanup_query = (
                    command.kind is wire._SupervisorWireKind.QUERY
                    and record is not None
                    and record.terminal_attestation_id is None
                    and (
                        record.cancel_command_id is not None
                        or record.success_cleanup_event_id is not None
                        or record.state
                        is contract._BrokerOperationState.POISONED
                    )
                    and replay_count
                    < (
                        SUPERVISOR_REPLAY_LIMIT_PER_OPERATION
                        - _SUPERVISOR_TERMINAL_ONLY_REPLAY_RESERVE
                    )
                )
                terminal_query = (
                    command.kind is wire._SupervisorWireKind.QUERY
                    and record is not None
                    and record.terminal_attestation_id is not None
                )
                terminal_command = command.kind in (
                    wire._SupervisorWireKind.CANCEL,
                    wire._SupervisorWireKind.RELEASE,
                )
                if not (
                    cleanup_query or terminal_query or terminal_command
                ):
                    raise _capacity_error(
                        "resolver supervisor terminal replay reserve 已启用。"
                    )

            self._append_received_locked(command.kind.value)
            binding = self._binding_for_frame(command)
            if command.kind is wire._SupervisorWireKind.RESERVE:
                if local_publication_proof is not None:
                    _raise_proxy_error("RESERVE 不接受 publication proof。")
                attestation = self.ports.control.reserve(binding)
            elif command.kind is wire._SupervisorWireKind.ATTACH:
                proof = local_publication_proof
                if (
                    type(proof) is not contract._SupervisorPublicationProof
                    or proof.proof_digest
                    != command.payload["publication_proof_digest"]
                    or proof.reservation_attestation_digest
                    != command.payload["reservation_attestation_digest"]
                    or proof.proxy_id != command.payload["proxy_id"]
                    or proof.publication_id != command.payload["publication_id"]
                ):
                    _raise_proxy_error("ATTACH publication proof 无效。")
                attestation = self.ports.control.attach(
                    binding,
                    proof=proof,
                    command_id=command.payload["command_id"],
                )
            elif command.kind is wire._SupervisorWireKind.ARM:
                if local_publication_proof is not None:
                    _raise_proxy_error("ARM 不接受 publication proof。")
                attestation = self.ports.control.arm(
                    binding,
                    command_id=command.payload["command_id"],
                )
            elif command.kind is wire._SupervisorWireKind.CANCEL:
                if local_publication_proof is not None:
                    _raise_proxy_error("CANCEL 不接受 publication proof。")
                attestation = self.ports.control.cancel(
                    binding,
                    command_id=command.payload["command_id"],
                    payload_digest=command.payload["cancel_payload_digest"],
                )
            elif command.kind is wire._SupervisorWireKind.QUERY:
                if local_publication_proof is not None:
                    _raise_proxy_error("QUERY 不接受 publication proof。")
                attestation = self.ports.control.query_reply(
                    binding,
                    query_id=command.payload["query_id"],
                ).attestation
            elif command.kind is wire._SupervisorWireKind.RELEASE:
                if local_publication_proof is not None:
                    _raise_proxy_error("RELEASE 不接受 publication proof。")
                current = self.ports.control.query(binding)
                if (
                    current.attestation_digest
                    != command.payload["terminal_attestation_digest"]
                ):
                    _raise_proxy_error("RELEASE terminal proof 已变化。")
                attestation = self.ports.control.release(
                    binding,
                    tombstone_id=command.payload["tombstone_id"],
                )
            else:
                _raise_proxy_error("resolver supervisor command kind 无效。")
            reply_frame = self._reply_frame(
                command=command,
                attestation=attestation,
            )
            response = _SupervisorChannelResponse(
                frame=reply_frame,
                attestation=attestation,
                _authority=_CHANNEL_RESPONSE_AUTHORITY,
            )
            self._replays[command.frame_id] = _ChannelReplay(
                frame_bytes=frame_bytes,
                frame_digest=command.frame_digest,
                local_proof=local_publication_proof,
                response=response,
            )
            return response
        finally:
            broker_lock.release()
            self._lock.release()

    def prepare_proxy(
        self,
        *,
        reservation: contract._SupervisorOperationAttestation,
        proxy_id: UUID,
        proof_id: UUID,
        max_wait_ns: int,
    ) -> object:
        """Bridge the local S1 capability during injected-only integration."""

        _wait_limit(max_wait_ns)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        broker_lock = self.ports.ledger._lock
        session_lock = self.ports.parent_session._lock
        if not _try_acquire(broker_lock):
            self._lock.release()
            return resolver.PENDING
        if not _try_acquire(session_lock):
            broker_lock.release()
            self._lock.release()
            return resolver.PENDING
        try:
            selected = self.ports.parent_session.prepare_proxy(
                reservation=reservation,
                proxy_id=proxy_id,
                proof_id=proof_id,
            )
            key = (reservation.binding.operation_id, proxy_id)
            if key not in self._stdout_by_operation:
                self._stdout_by_operation[key] = list(
                    self._initial_stdout_results
                )
                self._stdin_by_operation[key] = list(
                    self._initial_stdin_results
                )
                object.__setattr__(self, "_initial_stdout_results", ())
                object.__setattr__(self, "_initial_stdin_results", ())
        finally:
            session_lock.release()
            broker_lock.release()
            self._lock.release()
        return selected

    def script_operation_io(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        *,
        stdout_results: tuple[object, ...] = (),
        stdin_results: tuple[object, ...] = (),
    ) -> None:
        """Set data polls for one exact injected operation only."""

        key = (binding.operation_id, require_uuid(proxy_id, "proxy_id"))
        with self._lock:
            self._require_operation_proxy(binding, proxy_id)
            self._stdout_by_operation[key] = list(stdout_results)
            self._stdin_by_operation[key] = list(stdin_results)

    def _require_operation_proxy(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
    ) -> None:
        binding.validate_integrity()
        checked_proxy = require_uuid(proxy_id, "proxy_id")
        existing = self.ports.parent_session._operations.get(
            binding.operation_id
        )
        if (
            existing is None
            or existing[0].proxy_id != checked_proxy
            or not _same_binding(existing[0].binding, binding)
        ):
            _raise_proxy_error("resolver supervisor operation proxy 无效。")

    def read_stdout(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        max_bytes: int,
        *,
        max_wait_ns: int,
    ) -> object:
        _wait_limit(max_wait_ns)
        require_plain_int(max_bytes, "max_bytes", minimum=1)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            self._require_operation_proxy(binding, proxy_id)
            key = (binding.operation_id, proxy_id)
            if key in self._closed_operations:
                _raise_proxy_error("resolver supervisor operation pipes 已关闭。")
            results = self._stdout_by_operation.get(key)
            if results is None:
                _raise_proxy_error("resolver supervisor stdout owner 缺失。")
            selected = (
                results.pop(0)
                if results
                else resolver.PENDING
            )
        finally:
            self._lock.release()
        if selected is resolver.PENDING:
            return selected
        if type(selected) is not bytes or len(selected) > max_bytes:
            _raise_proxy_error("resolver supervisor stdout poll 无效。")
        return selected

    def write_stdin(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        frame: bytes,
        *,
        max_wait_ns: int,
    ) -> object:
        _wait_limit(max_wait_ns)
        if type(frame) is not bytes or not frame:
            raise TypeError("frame must be non-empty bytes")
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            self._require_operation_proxy(binding, proxy_id)
            key = (binding.operation_id, proxy_id)
            if key in self._closed_operations:
                _raise_proxy_error("resolver supervisor operation pipes 已关闭。")
            results = self._stdin_by_operation.get(key)
            if results is None:
                _raise_proxy_error("resolver supervisor stdin owner 缺失。")
            selected = (
                results.pop(0)
                if results
                else resolver.PENDING
            )
        finally:
            self._lock.release()
        if selected not in (resolver.PENDING, resolver.COMPLETE):
            _raise_proxy_error("resolver supervisor stdin poll 无效。")
        return selected

    def close_operation_pipes(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        *,
        max_wait_ns: int,
    ) -> object:
        _wait_limit(max_wait_ns)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            checked_proxy = require_uuid(proxy_id, "proxy_id")
            retained = self._terminal_tombstones.get(binding.operation_id)
            if retained is None:
                self._require_operation_proxy(binding, checked_proxy)
                released = self.ports.control.query(binding)
                if (
                    released.state is not contract._BrokerOperationState.RELEASED
                    or released.release_tombstone_id is None
                    or released.terminal_attestation_id is None
                ):
                    _raise_proxy_error(
                        "resolver supervisor operation 尚未 exact release。"
                    )
                if (
                    len(self._terminal_tombstones)
                    >= SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT
                ):
                    raise _capacity_error(
                        "resolver supervisor terminal tombstone capacity 已满。"
                    )
                operation_replays = tuple(
                    replay
                    for replay in self._replays.values()
                    if replay.response.attestation.binding.operation_id
                    == binding.operation_id
                )
                candidate = _ReleasedChannelTombstone(
                    binding=binding,
                    proxy_id=checked_proxy,
                    release_attestation=released,
                    replays=operation_replays,
                )
                retained = self._terminal_tombstones.setdefault(
                    binding.operation_id,
                    candidate,
                )
                if retained is candidate:
                    self._closed_operations.add(
                        (binding.operation_id, checked_proxy)
                    )
                    object.__setattr__(
                        self,
                        "_operation_pipe_close_total",
                        self._operation_pipe_close_total + 1,
                    )
            retained.validate_binding(binding, checked_proxy)
            compacted = self.ports.cleanup.compact_released(
                binding,
                retained.release_tombstone_id,
                retained.release_attestation_digest,
            )
            if not compacted.matches(
                binding,
                retained.release_tombstone_id,
                retained.release_attestation_digest,
            ):
                _raise_proxy_error(
                    "resolver supervisor contract tombstone 已变化。"
                )
            for frame_id, replay in tuple(self._replays.items()):
                if (
                    replay.response.attestation.binding.operation_id
                    == binding.operation_id
                ):
                    self._replays.pop(frame_id, None)
            key = (binding.operation_id, checked_proxy)
            self._stdout_by_operation.pop(key, None)
            self._stdin_by_operation.pop(key, None)
            self._closed_operations.discard(key)
        finally:
            self._lock.release()
        return resolver.COMPLETE

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "control_channel_id": str(self.control_channel_id),
                "epoch_id": str(self.epoch_id),
                "active_operation_count": len(self.ports.ledger._operations),
                "active_replay_count": len(self._replays),
                "epoch_rotation_ready": (
                    not self.ports.ledger._operations
                    and len(self._terminal_tombstones)
                    >= SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT
                    and self._spawner_operations_empty_locked()
                ),
                "operation_pipe_close_count": self._operation_pipe_close_total,
                "received_frame_count": len(self._received),
                "received_frame_limit": SUPERVISOR_RECEIVED_HISTORY_LIMIT,
                "session_closed": self._session_closed,
                "terminal_tombstone_count": len(self._terminal_tombstones),
                "terminal_tombstone_limit": (
                    SUPERVISOR_TERMINAL_TOMBSTONE_LIMIT
                ),
                "transport_available": False,
            }


def _new_in_memory_supervisor_channel(
    *,
    epoch_id: UUID,
    control_channel_id: UUID,
    stdout_results: tuple[object, ...] = (),
    stdin_results: tuple[object, ...] = (),
) -> _InMemorySupervisorChannel:
    return _InMemorySupervisorChannel(
        epoch_id=epoch_id,
        control_channel_id=control_channel_id,
        stdout_results=stdout_results,
        stdin_results=stdin_results,
        _authority=_IN_MEMORY_CHANNEL_AUTHORITY,
    )


class _HandshakePhase(str, Enum):
    RESERVE_SEND = "reserve_send"
    RESERVE_QUERY = "reserve_query"
    PREPARE_PROXY = "prepare_proxy"
    PUBLICATION = "publication"
    PUBLICATION_CLEANUP_CANCEL = "publication_cleanup_cancel"
    PUBLICATION_CLEANUP_RELEASE = "publication_cleanup_release"
    PUBLICATION_CLEANUP_CLOSE = "publication_cleanup_close"
    ATTACH_SEND = "attach_send"
    ATTACH_QUERY = "attach_query"
    ARM_SEND = "arm_send"
    ARM_QUERY = "arm_query"
    ACTIVE = "active"
    RETIRED = "retired"
    POISONED = "poisoned"


class _HandshakeOperation:
    __slots__ = (
        "binding",
        "publication",
        "proxy_id",
        "proof_id",
        "reservation",
        "proxy",
        "proxy_publication",
        "kernel",
        "publication_attempted",
        "publication_failure",
        "publication_proof",
        "attach_command_id",
        "arm_command_id",
        "commands",
        "queries",
        "phase",
    )

    def __init__(
        self,
        *,
        binding: contract._SupervisorOperationBinding,
        publication: resolver._KernelPublication,
        proxy_id: UUID,
        proof_id: UUID,
    ) -> None:
        self.binding = binding
        self.publication = publication
        self.proxy_id = proxy_id
        self.proof_id = proof_id
        self.reservation: contract._SupervisorOperationAttestation | None = None
        self.proxy: contract._SupervisorParentProxy | None = None
        self.proxy_publication: contract._SupervisorPublicationLedger | None = None
        self.kernel: _SupervisorHelperKernel | None = None
        self.publication_attempted = False
        self.publication_failure: BaseException | None = None
        self.publication_proof: contract._SupervisorPublicationProof | None = None
        self.attach_command_id = _bound_role_uuid(binding, "attach-command")
        self.arm_command_id = _bound_role_uuid(binding, "arm-command")
        self.commands: dict[
            wire._SupervisorWireKind, wire._SupervisorWireFrame
        ] = {}
        self.queries: dict[_HandshakePhase, wire._SupervisorWireFrame] = {}
        self.phase = _HandshakePhase.RESERVE_SEND


def _publication_context(
    request: resolver.ResolverHelperSpawnRequest,
    publication: object,
) -> tuple[UUID, UUID, Digest256]:
    if type(request) is not resolver.ResolverHelperSpawnRequest:
        raise TypeError("request must be ResolverHelperSpawnRequest")
    if type(publication) is not resolver._KernelPublication:
        raise TypeError("publication must be _KernelPublication")
    try:
        ledger = publication._ledger
        snapshot = ledger._capability_snapshot
        lifecycle_id = require_uuid(snapshot.lifecycle_id, "lifecycle_id")
        publication_id = require_uuid(snapshot.publication_id, "publication_id")
        spawn_digest = require_digest(
            snapshot.spawn_request_digest,
            "spawn_request_digest",
        )
        if (
            ledger.lifecycle_id != lifecycle_id
            or request.request_digest != spawn_digest
            or publication._owner is not ledger._owner
            or ledger._pre_owner is not publication._owner
            or ledger._state not in ("created", "spawned")
        ):
            raise ValueError("publication lifecycle changed")
    except (AttributeError, TypeError, ValueError):
        _raise_proxy_error("resolver supervisor publication context 无效。")
    return lifecycle_id, publication_id, spawn_digest


def _intrinsic_publication_observer(
    publication: resolver._KernelPublication,
    kernel: object,
) -> bool | None:
    publication_lock = getattr(publication, "_lock", None)
    if not _try_acquire(publication_lock):
        return None
    ledger_lock = getattr(
        getattr(publication, "_ledger", None),
        "_lock",
        None,
    )
    if not _try_acquire(ledger_lock):
        publication_lock.release()
        return None
    try:
        return (
            publication._kernel is kernel
            and publication._ledger.is_exact_kernel_attached(
                publication._owner,
                kernel,
            )
        )
    except (AttributeError, TypeError, ValueError):
        return False
    finally:
        ledger_lock.release()
        publication_lock.release()


def _require_channel(channel: object) -> None:
    required = (
        "bind_spawner",
        "exchange",
        "prepare_proxy",
        "read_stdout",
        "write_stdin",
        "close_operation_pipes",
    )
    if channel is None or any(
        not callable(getattr(channel, name, None)) for name in required
    ):
        raise TypeError("channel must implement the supervisor channel contract")
    require_uuid(getattr(channel, "epoch_id", None), "epoch_id")
    require_uuid(
        getattr(channel, "control_channel_id", None),
        "control_channel_id",
    )


def _new_command_frame(
    operation: _HandshakeOperation,
    *,
    kind: wire._SupervisorWireKind,
    channel_id: UUID,
    payload: dict[str, object],
) -> wire._SupervisorWireFrame:
    existing = operation.commands.get(kind)
    if existing is not None:
        return existing
    selected = wire._new_supervisor_wire_frame(
        kind=kind,
        epoch_id=operation.binding.epoch_id,
        operation_id=operation.binding.operation_id,
        control_channel_id=channel_id,
        operation_binding_digest=operation.binding.binding_digest,
        frame_id=_bound_role_uuid(operation.binding, f"frame:{kind.value}"),
        payload=payload,
    )
    operation.commands[kind] = selected
    return selected


def _new_query_frame(
    operation: _HandshakeOperation,
    *,
    phase: _HandshakePhase,
    channel_id: UUID,
) -> wire._SupervisorWireFrame:
    existing = operation.queries.get(phase)
    if existing is not None:
        return existing
    query_id = _bound_role_uuid(operation.binding, f"query:{phase.value}")
    selected = wire._new_supervisor_wire_frame(
        kind=wire._SupervisorWireKind.QUERY,
        epoch_id=operation.binding.epoch_id,
        operation_id=operation.binding.operation_id,
        control_channel_id=channel_id,
        operation_binding_digest=operation.binding.binding_digest,
        frame_id=_bound_role_uuid(
            operation.binding,
            f"query-frame:{phase.value}",
        ),
        payload={"proxy_id": operation.proxy_id, "query_id": query_id},
    )
    operation.queries[phase] = selected
    return selected


def _decode_response(
    result: object,
) -> tuple[wire._SupervisorWireFrame, contract._SupervisorOperationAttestation]:
    if type(result) is not _SupervisorChannelResponse:
        _raise_proxy_error("resolver supervisor channel response 类型无效。")
    try:
        frame = wire._decode_supervisor_wire_frame(result.wire_bytes)
        if frame.frame_digest != result._frame.frame_digest:
            raise ValueError("response object changed")
    except (AttributeError, TypeError, ValueError):
        _raise_proxy_error("resolver supervisor channel response wire 无效。")
    return frame, result.attestation


@runtime_final
class _SupervisorHelperSpawner:
    """Durable, exact-reentry ``resolver.HelperSpawner`` adapter."""

    __slots__ = (
        "__weakref__",
        "_channel",
        "_lock",
        "_operations",
        "_publication_observer",
    )

    def __init__(
        self,
        *,
        channel: object,
        publication_observer: Callable[[object, object], object],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _SPAWNER_AUTHORITY:
            raise TypeError("supervisor helper spawner requires its factory")
        _require_channel(channel)
        if not callable(publication_observer):
            raise TypeError("publication_observer must be callable")
        object.__setattr__(self, "_channel", channel)
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_operations", {})
        object.__setattr__(self, "_publication_observer", publication_observer)
        channel.bind_spawner(self)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorHelperSpawner identity is immutable")

    def _operation(
        self,
        request: resolver.ResolverHelperSpawnRequest,
        publication: resolver._KernelPublication,
    ) -> object:
        lifecycle_id, publication_id, spawn_digest = _publication_context(
            request,
            publication,
        )
        existing = self._operations.get(publication_id)
        if existing is not None:
            if (
                existing.publication is not publication
                or existing.binding.lifecycle_id != lifecycle_id
                or existing.binding.spawn_request_digest != spawn_digest
            ):
                _raise_proxy_error("resolver supervisor operation reentry 已变化。")
            return existing
        if len(self._operations) >= SUPERVISOR_ACTIVE_OPERATION_LIMIT:
            raise _capacity_error(
                "resolver supervisor spawner operation capacity 已满。"
            )
        preflight = getattr(self._channel, "preflight_admission", None)
        if callable(preflight):
            admitted = preflight()
            if admitted is resolver.PENDING:
                return admitted
            if admitted is not resolver.COMPLETE:
                _raise_proxy_error(
                    "resolver supervisor admission result 无效。"
                )
        operation_id = _operation_role_uuid(
            epoch_id=self._channel.epoch_id,
            lifecycle_id=lifecycle_id,
            publication_id=publication_id,
            spawn_request_digest=spawn_digest,
            role="operation",
        )
        binding = contract._new_supervisor_operation_binding(
            epoch_id=self._channel.epoch_id,
            operation_id=operation_id,
            lifecycle_id=lifecycle_id,
            publication_id=publication_id,
            spawn_request_digest=spawn_digest,
        )
        proxy_id = _bound_role_uuid(binding, "proxy")
        proof_id = _bound_role_uuid(binding, "publication-proof")
        terminal_observer = getattr(
            self._channel,
            "terminal_tombstone",
            None,
        )
        if (
            callable(terminal_observer)
            and terminal_observer(binding, proxy_id) is not None
        ):
            _raise_proxy_error(
                "resolver supervisor released operation 不可重新 admission。"
            )
        selected = _HandshakeOperation(
            binding=binding,
            publication=publication,
            proxy_id=proxy_id,
            proof_id=proof_id,
        )
        self._operations[publication_id] = selected
        return selected

    def _exchange(
        self,
        operation: _HandshakeOperation,
        command: wire._SupervisorWireFrame,
        *,
        max_wait_ns: int,
        local_publication_proof: object = None,
    ) -> object:
        try:
            result = self._channel.exchange(
                wire._encode_supervisor_wire_frame(command),
                max_wait_ns=max_wait_ns,
                local_publication_proof=local_publication_proof,
            )
        except _DefiniteSupervisorCapacityError:
            if operation.phase is _HandshakePhase.RESERVE_SEND:
                retained = self._operations.get(
                    operation.binding.publication_id
                )
                if retained is operation:
                    self._operations.pop(
                        operation.binding.publication_id,
                        None,
                    )
            raise
        except _DefiniteSupervisorProtocolError:
            raise
        except Exception:
            return resolver.PENDING
        if result is resolver.PENDING:
            return result
        frame, attestation = _decode_response(result)
        try:
            frame.require_binding(
                epoch_id=operation.binding.epoch_id,
                operation_id=operation.binding.operation_id,
                control_channel_id=self._channel.control_channel_id,
                operation_binding_digest=operation.binding.binding_digest,
            )
        except (TypeError, ValueError):
            _raise_proxy_error("resolver supervisor response binding 无效。")
        return frame, attestation

    def _send_or_query(
        self,
        operation: _HandshakeOperation,
        *,
        command: wire._SupervisorWireFrame,
        unknown_phase: _HandshakePhase,
        max_wait_ns: int,
        local_publication_proof: object = None,
    ) -> object:
        # PENDING is deliberately ambiguous: it may precede inbox/base
        # publication, follow durable queueing, or follow the broker mutation
        # with its ACK lost.  Until the channel exposes a separate durable-send
        # receipt, retry the exact cached command in all three cases.  Every
        # layer deduplicates by the same frame/command binding.
        result = self._exchange(
            operation,
            command,
            max_wait_ns=max_wait_ns,
            local_publication_proof=local_publication_proof,
        )
        if result is resolver.PENDING:
            operation.phase = unknown_phase
            return result
        frame, attestation = result
        if frame.kind is not wire._SupervisorWireKind.ACK:
            _raise_proxy_error("resolver supervisor command ACK 无效。")
        try:
            frame.require_acknowledges(command)
        except (TypeError, ValueError):
            _raise_proxy_error("resolver supervisor command ACK binding 无效。")
        _require_wire_attestation(
            frame,
            attestation,
            binding=operation.binding,
            proxy_id=operation.proxy_id,
            query_id=None,
        )
        return frame, attestation

    def _publish_proxy(self, operation: _HandshakeOperation) -> object:
        if operation.proxy is None:
            _raise_proxy_error("resolver supervisor proxy 尚未准备。")
        if operation.kernel is None:
            operation.kernel = _SupervisorHelperKernel(
                channel=self._channel,
                proxy=operation.proxy,
                retirement_owner=self,
                _authority=_KERNEL_AUTHORITY,
            )
        kernel = operation.kernel
        publication_lock = operation.publication._lock
        ledger_lock = operation.publication._ledger._lock
        if not _try_acquire(publication_lock):
            return resolver.PENDING
        if not _try_acquire(ledger_lock):
            publication_lock.release()
            return resolver.PENDING
        try:
            publish_error: BaseException | None = None
            if not operation.publication_attempted:
                operation.publication_attempted = True
                try:
                    operation.publication.publish(kernel)
                except BaseException as error:
                    publish_error = error
            observer_failure: BaseException | None = None
            try:
                observed = self._publication_observer(
                    operation.publication,
                    kernel,
                )
            except Exception:
                return resolver.PENDING
            except BaseException as error:
                observer_failure = error
                observed = False
            intrinsic = _intrinsic_publication_observer(
                operation.publication,
                kernel,
            )
            exact = (
                publish_error is None
                and observer_failure is None
                and observed is True
                and intrinsic is True
            )
            if not exact:
                # The kernel cannot be returned for business, but it remains a
                # valid cleanup-only handle.  Anchor it in the resolver ledger
                # when possible, then durably drive the still-zero-child
                # supervisor operation through CANCEL/RELEASE before exposing
                # the publication failure.
                try:
                    operation.publication._ledger \
                        .recover_kernel_publication_for_cleanup(
                            operation.publication._owner,
                            kernel,
                        )
                except BaseException:
                    pass
                operation.publication_failure = (
                    publish_error
                    if publish_error is not None
                    else (
                        observer_failure
                        if observer_failure is not None
                        else _proxy_error(
                            "resolver supervisor proxy publication 未提交。"
                        )
                    )
                )
                operation.phase = (
                    _HandshakePhase.PUBLICATION_CLEANUP_CANCEL
                )
                return resolver.PENDING
        finally:
            ledger_lock.release()
            publication_lock.release()

        publication = operation.proxy_publication
        if publication is None:
            _raise_proxy_error("resolver supervisor publication ledger 缺失。")
        if not _try_acquire(publication._lock):
            return resolver.PENDING
        commit_error: Exception | None = None
        try:
            try:
                publication.commit(operation.proxy)
            except Exception as error:
                commit_error = error
            try:
                committed = publication.safe_metadata()["committed"] is True
            except (AttributeError, TypeError, ValueError):
                committed = False
            if not committed:
                if commit_error is not None:
                    return resolver.PENDING
                operation.phase = _HandshakePhase.POISONED
                _raise_proxy_error(
                    "resolver supervisor publication proof 未提交。"
                )
            try:
                proof = publication.observe(operation.proxy)
            except Exception:
                return resolver.PENDING
        finally:
            publication._lock.release()
        operation.publication_proof = proof
        operation.phase = _HandshakePhase.ATTACH_SEND
        return resolver.PENDING

    def _advance_publication_failure_cleanup(
        self,
        operation: _HandshakeOperation,
        *,
        max_wait_ns: int,
    ) -> object:
        """Retire a failed pre-business publication without orphaning RESERVE."""

        if operation.phase is _HandshakePhase.RETIRED:
            return self._finish_publication_failure_retirement(operation)
        proxy = operation.proxy
        kernel = operation.kernel
        if proxy is None or kernel is None:
            operation.phase = _HandshakePhase.POISONED
            _raise_proxy_error(
                "resolver supervisor publication cleanup handle 缺失。"
            )
        if not _try_acquire(proxy._lock):
            return resolver.PENDING
        try:
            if operation.phase is _HandshakePhase.PUBLICATION_CLEANUP_CANCEL:
                cancel_id = _bound_role_uuid(
                    operation.binding,
                    "cancel-command",
                )
                cancel_digest = digest256(
                    "ResolverSupervisorCancel",
                    SUPERVISOR_PROXY_SCHEMA_VERSION,
                    {
                        "binding_digest": operation.binding.binding_digest,
                        "command_id": cancel_id,
                    },
                )
                should_send = proxy.begin_cancel(
                    command_id=cancel_id,
                    payload_digest=cancel_digest,
                )
                if should_send:
                    command = _new_command_frame(
                        operation,
                        kind=wire._SupervisorWireKind.CANCEL,
                        channel_id=self._channel.control_channel_id,
                        payload={
                            "cancel_payload_digest": cancel_digest,
                            "command_id": cancel_id,
                            "proxy_id": operation.proxy_id,
                        },
                    )
                    result = self._exchange(
                        operation,
                        command,
                        max_wait_ns=max_wait_ns,
                    )
                    if result is resolver.PENDING:
                        return result
                    frame, attestation = result
                    if frame.kind is not wire._SupervisorWireKind.ACK:
                        _raise_proxy_error(
                            "resolver supervisor publication CANCEL ACK 无效。"
                        )
                    try:
                        frame.require_acknowledges(command)
                    except (TypeError, ValueError):
                        _raise_proxy_error(
                            "resolver supervisor publication CANCEL binding 无效。"
                        )
                    _require_wire_attestation(
                        frame,
                        attestation,
                        binding=operation.binding,
                        proxy_id=operation.proxy_id,
                        query_id=None,
                    )
                    proxy.observe_cancel_ack(attestation)
                try:
                    _, terminal_kind, _ = proxy.terminal_attestation()
                except EndpointPolicyError:
                    return resolver.PENDING
                if terminal_kind is not contract._TerminalKind.ZERO_CHILD_CANCEL:
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error(
                        "resolver supervisor publication cleanup 非 zero-child。"
                    )
                operation.phase = (
                    _HandshakePhase.PUBLICATION_CLEANUP_RELEASE
                )
                return resolver.PENDING

            if operation.phase is _HandshakePhase.PUBLICATION_CLEANUP_RELEASE:
                try:
                    terminal_id, terminal_kind, _ = (
                        proxy.terminal_attestation()
                    )
                except EndpointPolicyError:
                    return resolver.PENDING
                if terminal_kind is not contract._TerminalKind.ZERO_CHILD_CANCEL:
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error(
                        "resolver supervisor publication terminal 已变化。"
                    )
                observed = proxy._observed
                if (
                    observed is None
                    or observed.terminal_attestation_id != terminal_id
                ):
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error(
                        "resolver supervisor publication terminal proof 缺失。"
                    )
                tombstone_id = _bound_role_uuid(
                    operation.binding,
                    "release-tombstone",
                )
                should_send = proxy.begin_release(
                    tombstone_id=tombstone_id
                )
                if should_send:
                    command = _new_command_frame(
                        operation,
                        kind=wire._SupervisorWireKind.RELEASE,
                        channel_id=self._channel.control_channel_id,
                        payload={
                            "proxy_id": operation.proxy_id,
                            "terminal_attestation_digest": (
                                observed.attestation_digest
                            ),
                            "tombstone_id": tombstone_id,
                        },
                    )
                    result = self._exchange(
                        operation,
                        command,
                        max_wait_ns=max_wait_ns,
                    )
                    if result is resolver.PENDING:
                        return result
                    frame, attestation = result
                    if frame.kind is not wire._SupervisorWireKind.ACK:
                        _raise_proxy_error(
                            "resolver supervisor publication RELEASE ACK 无效。"
                        )
                    try:
                        frame.require_acknowledges(command)
                    except (TypeError, ValueError):
                        _raise_proxy_error(
                            "resolver supervisor publication RELEASE binding 无效。"
                        )
                    _require_wire_attestation(
                        frame,
                        attestation,
                        binding=operation.binding,
                        proxy_id=operation.proxy_id,
                        query_id=None,
                    )
                    proxy.observe_release_ack(attestation)
                if not proxy.can_release_operation_refs():
                    return resolver.PENDING
                operation.phase = _HandshakePhase.PUBLICATION_CLEANUP_CLOSE
                return resolver.PENDING
        finally:
            proxy._lock.release()

        if operation.phase is not _HandshakePhase.PUBLICATION_CLEANUP_CLOSE:
            operation.phase = _HandshakePhase.POISONED
            _raise_proxy_error(
                "resolver supervisor publication cleanup state 无效。"
            )
        result = self._channel.close_operation_pipes(
            operation.binding,
            operation.proxy_id,
            max_wait_ns=max_wait_ns,
        )
        if result is resolver.PENDING:
            return result
        if result is not resolver.COMPLETE:
            _raise_proxy_error(
                "resolver supervisor publication pipe close 无效。"
            )
        object.__setattr__(kernel, "_operation_pipes_closed", True)

        publication = operation.publication
        if publication is not None:
            publication_lock = getattr(publication, "_lock", None)
            if not _try_acquire(publication_lock):
                return resolver.PENDING
            try:
                current = getattr(publication, "_kernel", None)
                if current not in (None, kernel):
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error(
                        "resolver supervisor failed publication 已变化。"
                    )
                if current is kernel:
                    object.__setattr__(publication, "_kernel", None)
            finally:
                publication_lock.release()

        failure = operation.publication_failure
        operation.phase = _HandshakePhase.RETIRED
        return self._finish_publication_failure_retirement(
            operation,
            failure=failure,
        )

    def _finish_publication_failure_retirement(
        self,
        operation: _HandshakeOperation,
        *,
        failure: BaseException | None = None,
    ) -> object:
        """Finish local heavy-ref retirement after the channel tombstone."""

        if operation.phase is not _HandshakePhase.RETIRED:
            _raise_proxy_error(
                "resolver supervisor publication retirement state 无效。"
            )
        if failure is None:
            failure = operation.publication_failure
        publication_id = operation.binding.publication_id
        retained = self._operations.get(publication_id)
        if retained is not operation:
            _raise_proxy_error(
                "resolver supervisor publication retirement owner 已变化。"
            )
        # Removing the sole spawner registry entry is the local commit point.
        # If an interruption follows, stack unwinding releases the now
        # unreachable operation and all remaining fields without resurrection.
        self._operations.pop(publication_id, None)
        operation.publication = None
        operation.reservation = None
        operation.proxy = None
        operation.proxy_publication = None
        operation.kernel = None
        operation.publication_proof = None
        operation.publication_failure = None
        operation.commands.clear()
        operation.queries.clear()
        if failure is None:
            _raise_proxy_error(
                "resolver supervisor publication failure 证明缺失。"
            )
        raise failure

    def _retire_kernel(self, kernel: object) -> object:
        """Drop all spawner/publication strong refs after channel commit."""

        if type(kernel) is not _SupervisorHelperKernel:
            raise TypeError("kernel must be SupervisorHelperKernel")
        if not _try_acquire(self._lock):
            return resolver.PENDING
        publication_lock = None
        publication_lock_acquired = False
        try:
            publication_id = kernel._binding.publication_id
            operation = self._operations.get(publication_id)
            if operation is None:
                return resolver.COMPLETE
            if operation.phase is not _HandshakePhase.RETIRED:
                if (
                    operation.kernel is not kernel
                    or operation.proxy is not kernel._proxy
                    or operation.proxy_id != kernel._proxy_id
                    or not _same_binding(operation.binding, kernel._binding)
                    or not kernel._operation_pipes_closed
                ):
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error(
                        "resolver supervisor kernel retirement binding 无效。"
                    )
                # The primitive terminal phase is published before any heavy
                # ref is cleared, so every following store/pop gap is retryable.
                operation.phase = _HandshakePhase.RETIRED

            publication = operation.publication
            if publication is not None:
                publication_lock = getattr(publication, "_lock", None)
                if not _try_acquire(publication_lock):
                    return resolver.PENDING
                publication_lock_acquired = True
                current_kernel = getattr(publication, "_kernel", None)
                if current_kernel not in (None, kernel):
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error(
                        "resolver supervisor kernel publication 已变化。"
                    )
                if current_kernel is kernel:
                    object.__setattr__(publication, "_kernel", None)

            operation.publication = None
            operation.reservation = None
            operation.proxy = None
            operation.proxy_publication = None
            operation.kernel = None
            operation.publication_proof = None
            operation.commands.clear()
            operation.queries.clear()
            self._operations.pop(publication_id, None)
            return resolver.COMPLETE
        finally:
            if publication_lock_acquired:
                publication_lock.release()
            self._lock.release()

    def _prepare_proxy(
        self,
        operation: _HandshakeOperation,
        *,
        max_wait_ns: int,
    ) -> object:
        reservation = operation.reservation
        if reservation is None:
            operation.phase = _HandshakePhase.POISONED
            _raise_proxy_error("RESERVE attestation 缺失。")
        try:
            selected = self._channel.prepare_proxy(
                reservation=reservation,
                proxy_id=operation.proxy_id,
                proof_id=operation.proof_id,
                max_wait_ns=max_wait_ns,
            )
        except (
            _DefiniteSupervisorCapacityError,
            _DefiniteSupervisorProtocolError,
        ):
            raise
        except Exception:
            return resolver.PENDING
        if selected is resolver.PENDING:
            return selected
        if type(selected) is not tuple or len(selected) != 2:
            operation.phase = _HandshakePhase.POISONED
            _raise_proxy_error("resolver supervisor prepared proxy 无效。")
        proxy, proxy_publication = selected
        if (
            type(proxy) is not contract._SupervisorParentProxy
            or type(proxy_publication)
            is not contract._SupervisorPublicationLedger
            or proxy.proxy_id != operation.proxy_id
            or proxy_publication.proof_id != operation.proof_id
            or proxy.reservation_attestation_digest
            != reservation.attestation_digest
            or not _same_binding(proxy.binding, operation.binding)
            or proxy_publication._prepared_proxy is not proxy
        ):
            operation.phase = _HandshakePhase.POISONED
            _raise_proxy_error("resolver supervisor prepared proxy binding 无效。")
        operation.proxy = proxy
        operation.proxy_publication = proxy_publication
        operation.phase = _HandshakePhase.PUBLICATION
        return self._publish_proxy(operation)

    def spawn(
        self,
        request: resolver.ResolverHelperSpawnRequest,
        *,
        publication: resolver._KernelPublication,
        max_wait_ns: int,
    ) -> object:
        selected_wait = _wait_limit(max_wait_ns)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            operation = self._operation(request, publication)
            if operation is resolver.PENDING:
                return operation
            if type(operation) is not _HandshakeOperation:
                _raise_proxy_error(
                    "resolver supervisor operation owner 无效。"
                )
            if operation.phase is _HandshakePhase.POISONED:
                _raise_proxy_error("resolver supervisor operation 已隔离。")
            if operation.phase in (
                _HandshakePhase.RESERVE_SEND,
                _HandshakePhase.RESERVE_QUERY,
            ):
                command = _new_command_frame(
                    operation,
                    kind=wire._SupervisorWireKind.RESERVE,
                    channel_id=self._channel.control_channel_id,
                    payload={
                        "lifecycle_id": operation.binding.lifecycle_id,
                        "publication_id": operation.binding.publication_id,
                        "spawn_request_digest": (
                            operation.binding.spawn_request_digest
                        ),
                    },
                )
                result = self._send_or_query(
                    operation,
                    command=command,
                    unknown_phase=_HandshakePhase.RESERVE_QUERY,
                    max_wait_ns=selected_wait,
                )
                if result is resolver.PENDING:
                    return result
                _, reservation = result
                if (
                    reservation.state
                    is not contract._BrokerOperationState.RESERVED
                    or reservation.revision != 0
                    or reservation.child_ever_owned
                ):
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error("RESERVE zero-child attestation 无效。")
                operation.reservation = reservation
                operation.phase = _HandshakePhase.PREPARE_PROXY
                return self._prepare_proxy(
                    operation,
                    max_wait_ns=selected_wait,
                )

            if operation.phase is _HandshakePhase.PREPARE_PROXY:
                return self._prepare_proxy(
                    operation,
                    max_wait_ns=selected_wait,
                )

            if operation.phase is _HandshakePhase.PUBLICATION:
                return self._publish_proxy(operation)

            if operation.phase in (
                _HandshakePhase.PUBLICATION_CLEANUP_CANCEL,
                _HandshakePhase.PUBLICATION_CLEANUP_RELEASE,
                _HandshakePhase.PUBLICATION_CLEANUP_CLOSE,
            ) or (
                operation.phase is _HandshakePhase.RETIRED
                and operation.publication_failure is not None
            ):
                return self._advance_publication_failure_cleanup(
                    operation,
                    max_wait_ns=selected_wait,
                )

            if operation.phase in (
                _HandshakePhase.ATTACH_SEND,
                _HandshakePhase.ATTACH_QUERY,
            ):
                proxy = operation.proxy
                proof = operation.publication_proof
                if proxy is None or proof is None:
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error("ATTACH publication binding 缺失。")
                if not _try_acquire(proxy._lock):
                    return resolver.PENDING
                try:
                    kernel = operation.kernel
                    if (
                        kernel is not None
                        and kernel._cancel_frame is not None
                    ):
                        # Publication transfers the cleanup handle before
                        # ATTACH.  Once that exact kernel has begun CANCEL,
                        # handshake progress must not overtake it or reinterpret
                        # its valid successor as an ATTACH protocol conflict.
                        operation.phase = _HandshakePhase.ACTIVE
                    else:
                        try:
                            proxy.terminal_attestation()
                        except EndpointPolicyError:
                            terminal_successor = False
                        else:
                            terminal_successor = True
                        if terminal_successor:
                            operation.phase = _HandshakePhase.ACTIVE
                        else:
                            if operation.phase is _HandshakePhase.ATTACH_SEND:
                                proxy.begin_attach(
                                    proof=proof,
                                    command_id=operation.attach_command_id,
                                )
                            command = _new_command_frame(
                                operation,
                                kind=wire._SupervisorWireKind.ATTACH,
                                channel_id=self._channel.control_channel_id,
                                payload={
                                    "command_id": operation.attach_command_id,
                                    "proxy_id": operation.proxy_id,
                                    "publication_id": (
                                        operation.binding.publication_id
                                    ),
                                    "publication_proof_digest": (
                                        proof.proof_digest
                                    ),
                                    "reservation_attestation_digest": (
                                        proof.reservation_attestation_digest
                                    ),
                                },
                            )
                            was_query = (
                                operation.phase
                                is _HandshakePhase.ATTACH_QUERY
                            )
                            result = self._send_or_query(
                                operation,
                                command=command,
                                unknown_phase=_HandshakePhase.ATTACH_QUERY,
                                max_wait_ns=selected_wait,
                                local_publication_proof=proof,
                            )
                            if result is resolver.PENDING:
                                return result
                            _, attestation = result
                            if was_query:
                                proxy.observe_status(attestation)
                            else:
                                proxy.observe_attach_ack(attestation)
                            if (
                                attestation.attachment_command_id
                                != operation.attach_command_id
                                or attestation.attachment_proof_digest
                                != proof.proof_digest
                                or attestation.state
                                is not contract._BrokerOperationState.ATTACHED
                            ):
                                operation.phase = _HandshakePhase.POISONED
                                _raise_proxy_error(
                                    "ATTACH attestation 无效。"
                                )
                            operation.phase = _HandshakePhase.ARM_SEND
                            return resolver.PENDING
                finally:
                    proxy._lock.release()

            if operation.phase in (
                _HandshakePhase.ARM_SEND,
                _HandshakePhase.ARM_QUERY,
            ):
                proxy = operation.proxy
                if proxy is None:
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error("ARM proxy binding 缺失。")
                if not _try_acquire(proxy._lock):
                    return resolver.PENDING
                try:
                    kernel = operation.kernel
                    if (
                        kernel is not None
                        and kernel._cancel_frame is not None
                    ):
                        operation.phase = _HandshakePhase.ACTIVE
                    else:
                        try:
                            proxy.terminal_attestation()
                        except EndpointPolicyError:
                            terminal_successor = False
                        else:
                            terminal_successor = True
                        if terminal_successor:
                            operation.phase = _HandshakePhase.ACTIVE
                        else:
                            if operation.phase is _HandshakePhase.ARM_SEND:
                                proxy.begin_arm(
                                    command_id=operation.arm_command_id
                                )
                            command = _new_command_frame(
                                operation,
                                kind=wire._SupervisorWireKind.ARM,
                                channel_id=self._channel.control_channel_id,
                                payload={
                                    "command_id": operation.arm_command_id,
                                    "proxy_id": operation.proxy_id,
                                },
                            )
                            was_query = (
                                operation.phase is _HandshakePhase.ARM_QUERY
                            )
                            result = self._send_or_query(
                                operation,
                                command=command,
                                unknown_phase=_HandshakePhase.ARM_QUERY,
                                max_wait_ns=selected_wait,
                            )
                            if result is resolver.PENDING:
                                return result
                            _, attestation = result
                            if was_query:
                                proxy.observe_status(attestation)
                            else:
                                proxy.observe_arm_ack(attestation)
                            if (
                                attestation.arm_command_id
                                != operation.arm_command_id
                                or attestation.state
                                not in (
                                    contract._BrokerOperationState.SPAWN_INFLIGHT,
                                    contract._BrokerOperationState.CHILD_OWNED,
                                    contract._BrokerOperationState.READY,
                                    contract._BrokerOperationState.STARTED,
                                    contract._BrokerOperationState.RESULT_PENDING_TERMINAL,
                                    contract._BrokerOperationState.TERMINAL_ATTESTED,
                                )
                            ):
                                operation.phase = _HandshakePhase.POISONED
                                _raise_proxy_error(
                                    "ARM attestation 无效。"
                                )
                            operation.phase = _HandshakePhase.ACTIVE
                finally:
                    proxy._lock.release()

            if operation.phase is _HandshakePhase.ACTIVE:
                proxy = operation.proxy
                kernel = operation.kernel
                if proxy is None or kernel is None:
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error("resolver supervisor active proxy 缺失。")
                if not _try_acquire(proxy._lock):
                    return resolver.PENDING
                try:
                    try:
                        proxy.require_business_allowed()
                    except EndpointPolicyError:
                        if kernel._cancel_frame is None:
                            # An exact zero-child terminal successor may
                            # overtake a lost handshake ACK.  The published
                            # kernel remains its only reap/release handle.
                            proxy.terminal_attestation()
                finally:
                    proxy._lock.release()
                exact_publication = _intrinsic_publication_observer(
                    publication,
                    kernel,
                )
                if exact_publication is None:
                    return resolver.PENDING
                if not exact_publication:
                    operation.phase = _HandshakePhase.POISONED
                    _raise_proxy_error(
                        "resolver supervisor active publication 失效。"
                    )
                return kernel

            _raise_proxy_error("resolver supervisor handshake state 无效。")
        finally:
            self._lock.release()

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "control_channel_id": str(self._channel.control_channel_id),
                "epoch_id": str(self._channel.epoch_id),
                "operation_count": len(self._operations),
                "production_wired": False,
                "transport_available": False,
            }


def _new_supervisor_helper_spawner(
    *,
    channel: object,
    publication_observer: Callable[[object, object], object] = (
        _intrinsic_publication_observer
    ),
) -> _SupervisorHelperSpawner:
    return _SupervisorHelperSpawner(
        channel=channel,
        publication_observer=publication_observer,
        _authority=_SPAWNER_AUTHORITY,
    )


@runtime_final
class _SupervisorHelperKernel:
    """Parent-side HelperKernel facade; it never contains a resolver PID."""

    __slots__ = (
        "__weakref__",
        "_channel",
        "_proxy",
        "_retirement_owner",
        "_binding",
        "_proxy_id",
        "_lock",
        "_cancel_frame",
        "_cancel_query_sequence",
        "_release_frame",
        "_release_query_sequence",
        "_operation_pipes_closed",
    )

    def __init__(
        self,
        *,
        channel: object,
        proxy: contract._SupervisorParentProxy,
        retirement_owner: _SupervisorHelperSpawner,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _KERNEL_AUTHORITY:
            raise TypeError("supervisor helper kernel requires its spawner")
        _require_channel(channel)
        if type(proxy) is not contract._SupervisorParentProxy:
            raise TypeError("proxy must be SupervisorParentProxy")
        if type(retirement_owner) is not _SupervisorHelperSpawner:
            raise TypeError("retirement_owner must be SupervisorHelperSpawner")
        object.__setattr__(self, "_channel", channel)
        object.__setattr__(self, "_proxy", proxy)
        object.__setattr__(self, "_retirement_owner", retirement_owner)
        object.__setattr__(self, "_binding", proxy.binding)
        object.__setattr__(self, "_proxy_id", proxy.proxy_id)
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_cancel_frame", None)
        object.__setattr__(self, "_cancel_query_sequence", 0)
        object.__setattr__(self, "_release_frame", None)
        object.__setattr__(self, "_release_query_sequence", 0)
        object.__setattr__(self, "_operation_pipes_closed", False)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorHelperKernel identity is immutable")

    def _try_acquire_operation(self) -> bool:
        if not _try_acquire(self._lock):
            return False
        if not _try_acquire(self._proxy._lock):
            self._lock.release()
            return False
        return True

    def _release_operation(self) -> None:
        self._proxy._lock.release()
        self._lock.release()

    def _exchange(
        self,
        command: wire._SupervisorWireFrame,
        *,
        max_wait_ns: int,
    ) -> object:
        try:
            result = self._channel.exchange(
                wire._encode_supervisor_wire_frame(command),
                max_wait_ns=max_wait_ns,
                local_publication_proof=None,
            )
        except (
            _DefiniteSupervisorCapacityError,
            _DefiniteSupervisorProtocolError,
        ):
            raise
        except Exception:
            return resolver.PENDING
        if result is resolver.PENDING:
            return result
        frame, attestation = _decode_response(result)
        try:
            frame.require_binding(
                epoch_id=self._binding.epoch_id,
                operation_id=self._binding.operation_id,
                control_channel_id=self._channel.control_channel_id,
                operation_binding_digest=self._binding.binding_digest,
            )
        except (TypeError, ValueError):
            _raise_proxy_error("resolver supervisor kernel reply binding 无效。")
        return frame, attestation

    def _query(self, *, role: str, sequence: int, max_wait_ns: int) -> object:
        query_id = _bound_role_uuid(self._binding, role, sequence)
        command = wire._new_supervisor_wire_frame(
            kind=wire._SupervisorWireKind.QUERY,
            epoch_id=self._binding.epoch_id,
            operation_id=self._binding.operation_id,
            control_channel_id=self._channel.control_channel_id,
            operation_binding_digest=self._binding.binding_digest,
            frame_id=_bound_role_uuid(self._binding, f"{role}-frame", sequence),
            payload={"proxy_id": self._proxy_id, "query_id": query_id},
        )
        result = self._exchange(command, max_wait_ns=max_wait_ns)
        if result is resolver.PENDING:
            return result
        frame, attestation = result
        if frame.kind is not wire._SupervisorWireKind.STATE:
            _raise_proxy_error("resolver supervisor kernel query 无效。")
        _require_wire_attestation(
            frame,
            attestation,
            binding=self._binding,
            proxy_id=self._proxy_id,
            query_id=query_id,
        )
        self._proxy.observe_status(attestation)
        if attestation.terminal_attestation_id is None:
            cleanup_observer = getattr(
                self._channel,
                "observe_cleanup_pending",
                None,
            )
            if callable(cleanup_observer):
                observed = cleanup_observer(
                    proxy=self._proxy,
                    query_id=query_id,
                    max_wait_ns=max_wait_ns,
                )
                if observed not in (True, False, resolver.PENDING):
                    _raise_proxy_error(
                        "resolver supervisor cleanup observation 无效。"
                    )
        return attestation

    def read_stdout(self, max_bytes: int, *, max_wait_ns: int) -> object:
        selected_wait = _wait_limit(max_wait_ns)
        require_plain_int(max_bytes, "max_bytes", minimum=1)
        if not self._try_acquire_operation():
            return resolver.PENDING
        try:
            if self._cancel_frame is not None:
                _raise_proxy_error(
                    "resolver supervisor cleanup 已开始。"
                )
            self._proxy.require_business_allowed()
            return self._channel.read_stdout(
                self._binding,
                self._proxy_id,
                max_bytes,
                max_wait_ns=selected_wait,
            )
        finally:
            self._release_operation()

    def durable_output_available(self) -> bool:
        return all(
            callable(getattr(self._channel, name, None))
            for name in (
                "observe_stdout_durable",
                "acknowledge_stdout_durable",
            )
        )

    def observe_stdout_durable(
        self,
        max_bytes: int,
        *,
        publication: object = None,
        max_wait_ns: int,
    ) -> object:
        """Observe one supervisor-cached output without stream replay."""

        selected_wait = _wait_limit(max_wait_ns)
        require_plain_int(max_bytes, "max_bytes", minimum=1)
        if not self._try_acquire_operation():
            return resolver.PENDING
        try:
            if (
                publication is not None
                and type(publication) is not resolver._DurableOutputPublication
            ):
                _raise_proxy_error(
                    "resolver durable output local publication 无效。"
                )
            if publication is not None:
                try:
                    publication.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    _raise_proxy_error(
                        "resolver durable output local publication proof 无效。"
                    )
            if self._cancel_frame is not None:
                _raise_proxy_error("resolver supervisor cleanup 已开始。")
            self._proxy.require_business_allowed()
            observer = getattr(self._channel, "observe_stdout_durable", None)
            if not callable(observer):
                _raise_proxy_error(
                    "resolver supervisor durable output channel 未接线。"
                )
            selected = observer(
                self._binding,
                self._proxy_id,
                max_bytes,
                max_wait_ns=selected_wait,
                local_publication=publication,
            )
            if selected is resolver.PENDING:
                return selected
            validator = getattr(selected, "validate_integrity", None)
            if not callable(validator):
                _raise_proxy_error("resolver supervisor output observation 无效。")
            try:
                validator()
                exact = (
                    selected.epoch_id == self._binding.epoch_id
                    and selected.operation_id == self._binding.operation_id
                    and selected.proxy_id == self._proxy_id
                    and selected.operation_binding_digest
                    == self._binding.binding_digest
                    and type(selected.payload) is bytes
                    and len(selected.payload) <= max_bytes
                )
            except (AttributeError, TypeError, ValueError):
                exact = False
            if not exact:
                _raise_proxy_error(
                    "resolver supervisor output observation binding 无效。"
                )
            return selected
        finally:
            self._release_operation()

    def acknowledge_stdout_durable(
        self,
        observation: object,
        *,
        publication: object = None,
        max_wait_ns: int,
    ) -> object:
        """ACK an exact cached observation, including after cancellation."""

        selected_wait = _wait_limit(max_wait_ns)
        if not self._try_acquire_operation():
            return resolver.PENDING
        try:
            if (
                publication is not None
                and type(publication) is not resolver._DurableOutputPublication
            ):
                _raise_proxy_error(
                    "resolver durable output ACK publication 无效。"
                )
            if publication is not None:
                try:
                    publication.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    _raise_proxy_error(
                        "resolver durable output ACK publication proof 无效。"
                    )
            acknowledger = getattr(
                self._channel,
                "acknowledge_stdout_durable",
                None,
            )
            if not callable(acknowledger):
                _raise_proxy_error(
                    "resolver supervisor durable output ACK channel 未接线。"
                )
            try:
                observation.validate_integrity()
                exact = (
                    observation.epoch_id == self._binding.epoch_id
                    and observation.operation_id == self._binding.operation_id
                    and observation.proxy_id == self._proxy_id
                    and observation.operation_binding_digest
                    == self._binding.binding_digest
                )
            except (AttributeError, TypeError, ValueError):
                exact = False
            if not exact:
                _raise_proxy_error(
                    "resolver supervisor output ACK binding 无效。"
                )
            selected = acknowledger(
                self._binding,
                self._proxy_id,
                observation,
                max_wait_ns=selected_wait,
                local_publication=publication,
            )
            if selected not in (resolver.PENDING, resolver.COMPLETE):
                _raise_proxy_error("resolver supervisor output ACK result 无效。")
            return selected
        finally:
            self._release_operation()

    def write_stdin(self, frame: bytes, *, max_wait_ns: int) -> object:
        selected_wait = _wait_limit(max_wait_ns)
        if type(frame) is not bytes or not frame:
            raise TypeError("frame must be non-empty bytes")
        if not self._try_acquire_operation():
            return resolver.PENDING
        try:
            if self._cancel_frame is not None:
                _raise_proxy_error(
                    "resolver supervisor cleanup 已开始。"
                )
            self._proxy.require_business_allowed()
            start_writer = getattr(self._channel, "write_start_once", None)
            if callable(start_writer):
                result = start_writer(
                    self._binding,
                    self._proxy_id,
                    frame,
                    max_wait_ns=selected_wait,
                )
                if result not in (resolver.PENDING, resolver.COMPLETE):
                    _raise_proxy_error(
                        "resolver supervisor START write result 无效。"
                    )
                return result
            # The S3-only channel has no event owner.  Delegating an
            # untracked write there could report a false START success.
            _raise_proxy_error(
                "resolver supervisor START event owner 尚未接线。"
            )
        finally:
            self._release_operation()

    def terminate(self, *, max_wait_ns: int) -> object:
        selected_wait = _wait_limit(max_wait_ns)
        if not self._try_acquire_operation():
            return resolver.PENDING
        try:
            if self._operation_pipes_closed:
                return resolver.COMPLETE
            if self._cancel_frame is None:
                cancel_id = _bound_role_uuid(self._binding, "cancel-command")
                cancel_digest = digest256(
                    "ResolverSupervisorCancel",
                    SUPERVISOR_PROXY_SCHEMA_VERSION,
                    {
                        "binding_digest": self._binding.binding_digest,
                        "command_id": cancel_id,
                    },
                )
                should_send = self._proxy.begin_cancel(
                    command_id=cancel_id,
                    payload_digest=cancel_digest,
                )
                if not should_send:
                    return resolver.COMPLETE
                object.__setattr__(
                    self,
                    "_cancel_frame",
                    wire._new_supervisor_wire_frame(
                        kind=wire._SupervisorWireKind.CANCEL,
                        epoch_id=self._binding.epoch_id,
                        operation_id=self._binding.operation_id,
                        control_channel_id=self._channel.control_channel_id,
                        operation_binding_digest=self._binding.binding_digest,
                        frame_id=_bound_role_uuid(self._binding, "cancel-frame"),
                        payload={
                            "cancel_payload_digest": cancel_digest,
                            "command_id": cancel_id,
                            "proxy_id": self._proxy_id,
                        },
                    ),
                )
                result = self._exchange(
                    self._cancel_frame,
                    max_wait_ns=selected_wait,
                )
                if result is resolver.PENDING:
                    return result
                frame, attestation = result
                if frame.kind is not wire._SupervisorWireKind.ACK:
                    _raise_proxy_error("resolver supervisor CANCEL ACK 无效。")
                try:
                    frame.require_acknowledges(self._cancel_frame)
                except (TypeError, ValueError):
                    _raise_proxy_error("resolver supervisor CANCEL binding 无效。")
                _require_wire_attestation(
                    frame,
                    attestation,
                    binding=self._binding,
                    proxy_id=self._proxy_id,
                    query_id=None,
                )
                if (
                    attestation.success_cleanup_event_id is not None
                    and not attestation.cancel_latched
                ):
                    self._proxy.observe_status(attestation)
                    return resolver.COMPLETE
                self._proxy.observe_cancel_ack(attestation)
            else:
                try:
                    self._proxy.terminal_attestation()
                except EndpointPolicyError:
                    pass
                else:
                    return resolver.COMPLETE
                # Frame construction is not a send receipt.  Re-deliver this
                # exact frame so interruption before exchange and channel-lock
                # contention cannot strand CANCEL in a query-only state.
                result = self._exchange(
                    self._cancel_frame,
                    max_wait_ns=selected_wait,
                )
                if result is resolver.PENDING:
                    return result
                frame, attestation = result
                if frame.kind is not wire._SupervisorWireKind.ACK:
                    _raise_proxy_error("resolver supervisor CANCEL ACK 无效。")
                try:
                    frame.require_acknowledges(self._cancel_frame)
                except (TypeError, ValueError):
                    _raise_proxy_error(
                        "resolver supervisor CANCEL binding 无效。"
                    )
                _require_wire_attestation(
                    frame,
                    attestation,
                    binding=self._binding,
                    proxy_id=self._proxy_id,
                    query_id=None,
                )
                if (
                    attestation.success_cleanup_event_id is not None
                    and not attestation.cancel_latched
                ):
                    self._proxy.observe_status(attestation)
                    return resolver.COMPLETE
                self._proxy.observe_cancel_ack(attestation)
            cancel_confirmer = getattr(
                self._channel,
                "confirm_cancel_delegated",
                None,
            )
            if callable(cancel_confirmer) and cancel_confirmer(
                binding=self._binding,
                proxy_id=self._proxy_id,
                attestation=attestation,
            ) is True:
                return resolver.COMPLETE
            try:
                self._proxy.terminal_attestation()
            except EndpointPolicyError:
                return resolver.PENDING
            return resolver.COMPLETE
        finally:
            self._release_operation()

    def reap(self, *, max_wait_ns: int) -> object:
        selected_wait = _wait_limit(max_wait_ns)
        if not self._try_acquire_operation():
            return resolver.PENDING
        try:
            try:
                _, terminal_kind, status = self._proxy.terminal_attestation()
            except EndpointPolicyError:
                sequence = self._cancel_query_sequence
                object.__setattr__(
                    self,
                    "_cancel_query_sequence",
                    sequence + 1,
                )
                result = self._query(
                    role="terminal-query",
                    sequence=sequence,
                    max_wait_ns=selected_wait,
                )
                if result is resolver.PENDING:
                    return result
                try:
                    _, terminal_kind, status = (
                        self._proxy.terminal_attestation()
                    )
                except EndpointPolicyError:
                    return resolver.PENDING
            if terminal_kind is contract._TerminalKind.ZERO_CHILD_CANCEL:
                return 0
            if status is None:
                _raise_proxy_error("resolver supervisor terminal status 缺失。")
            return status
        finally:
            self._release_operation()

    def _close_pipes_locked(self, *, max_wait_ns: int) -> object:
        if self._operation_pipes_closed:
            return resolver.COMPLETE
        try:
            terminal_id, _, _ = self._proxy.terminal_attestation()
        except EndpointPolicyError:
            return resolver.PENDING
        observed = self._proxy._observed
        if observed is None or observed.terminal_attestation_id != terminal_id:
            _raise_proxy_error("resolver supervisor terminal observation 缺失。")
        if self._release_frame is None:
            tombstone_id = _bound_role_uuid(
                self._binding,
                "release-tombstone",
            )
            if not self._proxy.begin_release(tombstone_id=tombstone_id):
                _raise_proxy_error("resolver supervisor RELEASE state 无效。")
            object.__setattr__(
                self,
                "_release_frame",
                wire._new_supervisor_wire_frame(
                    kind=wire._SupervisorWireKind.RELEASE,
                    epoch_id=self._binding.epoch_id,
                    operation_id=self._binding.operation_id,
                    control_channel_id=self._channel.control_channel_id,
                    operation_binding_digest=self._binding.binding_digest,
                    frame_id=_bound_role_uuid(self._binding, "release-frame"),
                    payload={
                        "proxy_id": self._proxy_id,
                        "terminal_attestation_digest": (
                            observed.attestation_digest
                        ),
                        "tombstone_id": tombstone_id,
                    },
                ),
            )
            result = self._exchange(
                self._release_frame,
                max_wait_ns=max_wait_ns,
            )
            if result is resolver.PENDING:
                return result
            frame, attestation = result
            if frame.kind is not wire._SupervisorWireKind.ACK:
                _raise_proxy_error("resolver supervisor RELEASE ACK 无效。")
            try:
                frame.require_acknowledges(self._release_frame)
            except (TypeError, ValueError):
                _raise_proxy_error("resolver supervisor RELEASE binding 无效。")
            _require_wire_attestation(
                frame,
                attestation,
                binding=self._binding,
                proxy_id=self._proxy_id,
                query_id=None,
            )
            self._proxy.observe_release_ack(attestation)
        elif not self._proxy.can_release_operation_refs():
            # As with CANCEL, assigning the cached frame does not prove it was
            # durably published.  Exact re-delivery covers pre-send
            # interruption, channel contention, and post-commit ACK loss.
            result = self._exchange(
                self._release_frame,
                max_wait_ns=max_wait_ns,
            )
            if result is resolver.PENDING:
                return result
            frame, attestation = result
            if frame.kind is not wire._SupervisorWireKind.ACK:
                _raise_proxy_error("resolver supervisor RELEASE ACK 无效。")
            try:
                frame.require_acknowledges(self._release_frame)
            except (TypeError, ValueError):
                _raise_proxy_error("resolver supervisor RELEASE binding 无效。")
            _require_wire_attestation(
                frame,
                attestation,
                binding=self._binding,
                proxy_id=self._proxy_id,
                query_id=None,
            )
            self._proxy.observe_release_ack(attestation)
        if not self._proxy.can_release_operation_refs():
            return resolver.PENDING
        result = self._channel.close_operation_pipes(
            self._binding,
            self._proxy_id,
            max_wait_ns=max_wait_ns,
        )
        if result is resolver.COMPLETE:
            object.__setattr__(self, "_operation_pipes_closed", True)
        elif result is not resolver.PENDING:
            _raise_proxy_error("resolver supervisor operation pipe close 无效。")
        return result

    def close_pipes(self, *, max_wait_ns: int) -> object:
        selected_wait = _wait_limit(max_wait_ns)
        if not self._try_acquire_operation():
            return resolver.PENDING
        try:
            result = self._close_pipes_locked(max_wait_ns=selected_wait)
        finally:
            self._release_operation()
        if result is resolver.COMPLETE:
            retired = self._retirement_owner._retire_kernel(self)
            if retired not in (resolver.PENDING, resolver.COMPLETE):
                _raise_proxy_error(
                    "resolver supervisor kernel retirement result 无效。"
                )
            return retired
        return result

    def _cleanup_waiting_supervisor(self) -> bool:
        """Expose only the S1-attested retryable cleanup wait to resolver."""

        if not self._try_acquire_operation():
            return False
        try:
            return (
                self._proxy.safe_metadata()["cleanup_state"]
                == contract._SupervisorCleanupState.WAITING_SUPERVISOR.value
            )
        finally:
            self._release_operation()

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "binding_digest": str(self._binding.binding_digest),
                "operation_id": str(self._binding.operation_id),
                "operation_pipes_closed": self._operation_pipes_closed,
                "owns_pid": False,
                "proxy_id": str(self._proxy_id),
                "session_channel_owned": False,
            }
