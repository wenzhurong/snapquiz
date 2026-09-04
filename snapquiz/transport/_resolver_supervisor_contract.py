"""Pure W09-B2b supervisor state and attestation contracts.

This private module performs no process, file, environment, clock, credential,
DNS, socket, or network operation.  It freezes the broker-authoritative and
parent-observation state machines that later supervisor slices must implement.
It is deliberately not imported by ``ResolverHelperLauncher.production``.
"""
from __future__ import annotations

from enum import Enum
from threading import RLock
from typing import NoReturn
from uuid import UUID

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError


__all__ = ()


SUPERVISOR_OPERATION_BINDING_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-operation-binding.v1"
)
SUPERVISOR_PUBLICATION_PROOF_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-publication-proof.v1"
)
SUPERVISOR_ATTESTATION_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-attestation.v1"
)
SUPERVISOR_QUERY_REPLY_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-query-reply.v1"
)
SUPERVISOR_RELEASED_TOMBSTONE_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-released-tombstone.v1"
)
SUPERVISOR_CLEANUP_PENDING_LIMIT = 8
SUPERVISOR_ACTIVE_OPERATION_LIMIT = 64
SUPERVISOR_QUERY_REPLY_LIMIT_PER_OPERATION = 64
SUPERVISOR_RELEASED_TOMBSTONE_LIMIT = 256

_BINDING_AUTHORITY = object()
_PUBLICATION_PROOF_AUTHORITY = object()
_ATTESTATION_AUTHORITY = object()
_QUERY_REPLY_AUTHORITY = object()
_RELEASED_TOMBSTONE_AUTHORITY = object()
_PARENT_SESSION_AUTHORITY = object()
_BROKER_PORT_AUTHORITY = object()
_BROKER_LEDGER_AUTHORITY = object()
_SPAWN_FAILED_STATUS = 70


class _BrokerOperationState(str, Enum):
    RESERVED = "reserved"
    ATTACHED = "attached"
    SPAWN_INFLIGHT = "spawn_inflight"
    CANCEL_WAIT_SPAWN = "cancel_wait_spawn"
    CHILD_OWNED = "child_owned"
    READY = "ready"
    STARTED = "started"
    RESULT_PENDING_TERMINAL = "result_pending_terminal"
    TERMINAL_ATTESTED = "terminal_attested"
    RELEASED = "released"
    POISONED = "poisoned"


class _ParentProxyState(str, Enum):
    ATTACH_UNKNOWN = "attach_unknown"
    ATTACHED_UNARMED = "attached_unarmed"
    ARM_UNKNOWN = "arm_unknown"
    ACTIVE = "active"
    CANCEL_NOT_ATTESTED = "cancel_not_attested"
    CANCEL_LATCHED_WAIT_TERMINAL = "cancel_latched_wait_terminal"
    TERMINAL_ATTESTED = "terminal_attested"
    RELEASE_NOT_ATTESTED = "release_not_attested"
    RELEASED = "released"
    POISONED = "poisoned"


class _SupervisorCleanupState(str, Enum):
    IDLE = "idle"
    POLLING = "polling"
    WAITING_SUPERVISOR = "cleanup_waiting_supervisor"
    TERMINAL = "terminal"


class _BrokerCleanupPhase(str, Enum):
    NONE = "none"
    TERMINATE_REQUIRED = "terminate_required"
    TERMINATE_CLAIMED = "terminate_claimed"
    REAP_REQUIRED = "reap_required"
    REAP_CLAIMED = "reap_claimed"
    CLOSE_REQUIRED = "close_required"
    CLOSE_CLAIMED = "close_claimed"
    COMPLETE = "complete"


class _TerminalKind(str, Enum):
    ZERO_CHILD_CANCEL = "zero_child_cancel"
    SPAWN_FAILED = "spawn_failed"
    CHILD_EXITED = "child_exited"


class _PoisonReason(str, Enum):
    BINDING_MISMATCH = "binding_mismatch"
    EPOCH_LOST = "epoch_lost"
    EVENT_EQUIVOCATION = "event_equivocation"
    INVALID_TRANSITION = "invalid_transition"
    LIVENESS_LOST = "liveness_lost"
    OS_ACTION_UNCERTAIN = "os_action_uncertain"
    SNAPSHOT_EQUIVOCATION = "snapshot_equivocation"


_CLEANUP_PHASE_RANK = {
    _BrokerCleanupPhase.NONE: 0,
    _BrokerCleanupPhase.TERMINATE_REQUIRED: 1,
    _BrokerCleanupPhase.TERMINATE_CLAIMED: 2,
    _BrokerCleanupPhase.REAP_REQUIRED: 3,
    _BrokerCleanupPhase.REAP_CLAIMED: 4,
    _BrokerCleanupPhase.CLOSE_REQUIRED: 5,
    _BrokerCleanupPhase.CLOSE_CLAIMED: 6,
    _BrokerCleanupPhase.COMPLETE: 7,
}

_BROKER_STATE_REACHABLE = {
    _BrokerOperationState.RESERVED: frozenset(_BrokerOperationState),
    _BrokerOperationState.ATTACHED: frozenset(
        {
            _BrokerOperationState.ATTACHED,
            _BrokerOperationState.SPAWN_INFLIGHT,
            _BrokerOperationState.CANCEL_WAIT_SPAWN,
            _BrokerOperationState.CHILD_OWNED,
            _BrokerOperationState.READY,
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.SPAWN_INFLIGHT: frozenset(
        {
            _BrokerOperationState.SPAWN_INFLIGHT,
            _BrokerOperationState.CANCEL_WAIT_SPAWN,
            _BrokerOperationState.CHILD_OWNED,
            _BrokerOperationState.READY,
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.CANCEL_WAIT_SPAWN: frozenset(
        {
            _BrokerOperationState.CANCEL_WAIT_SPAWN,
            _BrokerOperationState.CHILD_OWNED,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.CHILD_OWNED: frozenset(
        {
            _BrokerOperationState.CHILD_OWNED,
            _BrokerOperationState.READY,
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.READY: frozenset(
        {
            _BrokerOperationState.READY,
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.STARTED: frozenset(
        {
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.RESULT_PENDING_TERMINAL: frozenset(
        {
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.TERMINAL_ATTESTED: frozenset(
        {
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        }
    ),
    _BrokerOperationState.RELEASED: frozenset({_BrokerOperationState.RELEASED}),
    _BrokerOperationState.POISONED: frozenset({_BrokerOperationState.POISONED}),
}


def _supervisor_error(message: str) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="resolver_supervisor",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_supervisor_error(message: str) -> NoReturn:
    raise _supervisor_error(message) from None


def _require_optional_uuid(value: object, name: str) -> UUID | None:
    if value is None:
        return None
    return require_uuid(value, name)


def _require_optional_digest(value: object, name: str) -> Digest256 | None:
    if value is None:
        return None
    return require_digest(value, name)


@runtime_final
class _SupervisorOperationBinding:
    """Immutable, content-addressed identity for one broker operation."""

    __slots__ = (
        "epoch_id",
        "operation_id",
        "lifecycle_id",
        "publication_id",
        "spawn_request_digest",
        "binding_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        epoch_id: UUID,
        operation_id: UUID,
        lifecycle_id: UUID,
        publication_id: UUID,
        spawn_request_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BINDING_AUTHORITY:
            raise TypeError("supervisor operation binding requires its factory")
        values = (
            ("epoch_id", require_uuid(epoch_id, "epoch_id")),
            ("operation_id", require_uuid(operation_id, "operation_id")),
            ("lifecycle_id", require_uuid(lifecycle_id, "lifecycle_id")),
            ("publication_id", require_uuid(publication_id, "publication_id")),
            (
                "spawn_request_digest",
                require_digest(spawn_request_digest, "spawn_request_digest"),
            ),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        selected_digest = digest256(
            "ResolverSupervisorOperationBinding",
            SUPERVISOR_OPERATION_BINDING_SCHEMA_VERSION,
            self._digest_payload(),
        )
        object.__setattr__(self, "binding_digest", selected_digest)
        object.__setattr__(self, "_issued_digest", selected_digest)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorOperationBinding is immutable")

    def __copy__(self) -> "_SupervisorOperationBinding":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_SupervisorOperationBinding":
        del memo
        return self

    def _digest_payload(self) -> dict[str, object]:
        return {
            "epoch_id": self.epoch_id,
            "lifecycle_id": self.lifecycle_id,
            "operation_id": self.operation_id,
            "publication_id": self.publication_id,
            "spawn_request_digest": self.spawn_request_digest,
        }

    def validate_integrity(self) -> None:
        require_uuid(self.epoch_id, "epoch_id")
        require_uuid(self.operation_id, "operation_id")
        require_uuid(self.lifecycle_id, "lifecycle_id")
        require_uuid(self.publication_id, "publication_id")
        require_digest(self.spawn_request_digest, "spawn_request_digest")
        current = digest256(
            "ResolverSupervisorOperationBinding",
            SUPERVISOR_OPERATION_BINDING_SCHEMA_VERSION,
            self._digest_payload(),
        )
        if (
            type(self.binding_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or current != self.binding_digest
            or current != self._issued_digest
        ):
            raise ValueError("supervisor operation binding integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "binding_digest": str(self.binding_digest),
            "epoch_id": str(self.epoch_id),
            "lifecycle_id": str(self.lifecycle_id),
            "operation_id": str(self.operation_id),
            "publication_id": str(self.publication_id),
            "spawn_request_digest": str(self.spawn_request_digest),
        }


def _new_supervisor_operation_binding(
    *,
    epoch_id: UUID,
    operation_id: UUID,
    lifecycle_id: UUID,
    publication_id: UUID,
    spawn_request_digest: Digest256,
) -> _SupervisorOperationBinding:
    return _SupervisorOperationBinding(
        epoch_id=epoch_id,
        operation_id=operation_id,
        lifecycle_id=lifecycle_id,
        publication_id=publication_id,
        spawn_request_digest=spawn_request_digest,
        _authority=_BINDING_AUTHORITY,
    )


def _same_binding(
    first: _SupervisorOperationBinding,
    second: _SupervisorOperationBinding,
) -> bool:
    try:
        first.validate_integrity()
        second.validate_integrity()
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        first.epoch_id == second.epoch_id
        and first.operation_id == second.operation_id
        and first.lifecycle_id == second.lifecycle_id
        and first.publication_id == second.publication_id
        and first.spawn_request_digest == second.spawn_request_digest
        and first.binding_digest == second.binding_digest
    )


@runtime_final
class _SupervisorReleasedOperationTombstone:
    """Bounded primitive proof that one operation can never be reserved again."""

    __slots__ = (
        "epoch_id",
        "operation_id",
        "lifecycle_id",
        "publication_id",
        "spawn_request_digest",
        "binding_digest",
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
        "release_attestation_digest",
        "poison_reason",
        "tombstone_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        binding: _SupervisorOperationBinding,
        release_tombstone_id: UUID,
        release_attestation_digest: Digest256,
        released_attestation: "_SupervisorOperationAttestation",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RELEASED_TOMBSTONE_AUTHORITY:
            raise TypeError("released tombstone requires its broker")
        if type(binding) is not _SupervisorOperationBinding:
            raise TypeError("binding must be SupervisorOperationBinding")
        binding.validate_integrity()
        if type(released_attestation) is not _SupervisorOperationAttestation:
            raise TypeError(
                "released_attestation must be SupervisorOperationAttestation"
            )
        released_attestation.validate_integrity()
        if (
            not _same_binding(binding, released_attestation.binding)
            or released_attestation.state is not _BrokerOperationState.RELEASED
            or released_attestation.release_tombstone_id
            != release_tombstone_id
            or released_attestation.attestation_digest
            != release_attestation_digest
        ):
            raise ValueError("released attestation is inconsistent")
        values = (
            ("epoch_id", binding.epoch_id),
            ("operation_id", binding.operation_id),
            ("lifecycle_id", binding.lifecycle_id),
            ("publication_id", binding.publication_id),
            ("spawn_request_digest", binding.spawn_request_digest),
            ("binding_digest", binding.binding_digest),
            ("revision", released_attestation.revision),
            ("state", released_attestation.state),
            (
                "attachment_command_id",
                released_attestation.attachment_command_id,
            ),
            (
                "attachment_proof_digest",
                released_attestation.attachment_proof_digest,
            ),
            ("arm_command_id", released_attestation.arm_command_id),
            ("cancel_command_id", released_attestation.cancel_command_id),
            (
                "cancel_payload_digest",
                released_attestation.cancel_payload_digest,
            ),
            ("cancel_latched", released_attestation.cancel_latched),
            ("spawn_event_id", released_attestation.spawn_event_id),
            ("spawn_created", released_attestation.spawn_created),
            ("child_ever_owned", released_attestation.child_ever_owned),
            ("ready_event_id", released_attestation.ready_event_id),
            ("start_command_id", released_attestation.start_command_id),
            (
                "start_payload_digest",
                released_attestation.start_payload_digest,
            ),
            ("start_committed", released_attestation.start_committed),
            ("result_event_id", released_attestation.result_event_id),
            ("result_digest", released_attestation.result_digest),
            (
                "success_cleanup_event_id",
                released_attestation.success_cleanup_event_id,
            ),
            (
                "durable_eof_ack_digest",
                released_attestation.durable_eof_ack_digest,
            ),
            ("cleanup_phase", released_attestation.cleanup_phase),
            (
                "terminate_action_id",
                released_attestation.terminate_action_id,
            ),
            ("reap_action_id", released_attestation.reap_action_id),
            ("close_action_id", released_attestation.close_action_id),
            (
                "terminal_attestation_id",
                released_attestation.terminal_attestation_id,
            ),
            ("terminal_kind", released_attestation.terminal_kind),
            ("terminal_status", released_attestation.terminal_status),
            (
                "release_tombstone_id",
                require_uuid(release_tombstone_id, "release_tombstone_id"),
            ),
            (
                "release_attestation_digest",
                require_digest(
                    release_attestation_digest,
                    "release_attestation_digest",
                ),
            ),
            ("poison_reason", released_attestation.poison_reason),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        selected = digest256(
            "ResolverSupervisorReleasedOperationTombstone",
            SUPERVISOR_RELEASED_TOMBSTONE_SCHEMA_VERSION,
            self._digest_payload(),
        )
        object.__setattr__(self, "tombstone_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorReleasedOperationTombstone is immutable")

    def __copy__(self) -> "_SupervisorReleasedOperationTombstone":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_SupervisorReleasedOperationTombstone":
        del memo
        return self

    def _digest_payload(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding_digest,
            "epoch_id": self.epoch_id,
            "lifecycle_id": self.lifecycle_id,
            "operation_id": self.operation_id,
            "publication_id": self.publication_id,
            "release_attestation_digest": self.release_attestation_digest,
            "release_tombstone_id": self.release_tombstone_id,
            "spawn_request_digest": self.spawn_request_digest,
        }

    def validate_integrity(self) -> None:
        require_uuid(self.epoch_id, "epoch_id")
        require_uuid(self.operation_id, "operation_id")
        require_uuid(self.lifecycle_id, "lifecycle_id")
        require_uuid(self.publication_id, "publication_id")
        require_digest(self.spawn_request_digest, "spawn_request_digest")
        require_digest(self.binding_digest, "binding_digest")
        require_uuid(self.release_tombstone_id, "release_tombstone_id")
        require_digest(
            self.release_attestation_digest,
            "release_attestation_digest",
        )
        require_plain_int(self.revision, "revision", minimum=0)
        if self.state is not _BrokerOperationState.RELEASED:
            raise ValueError("released tombstone state is invalid")
        for name in (
            "attachment_command_id",
            "arm_command_id",
            "cancel_command_id",
            "spawn_event_id",
            "ready_event_id",
            "start_command_id",
            "result_event_id",
            "success_cleanup_event_id",
            "terminate_action_id",
            "reap_action_id",
            "close_action_id",
            "terminal_attestation_id",
        ):
            _require_optional_uuid(getattr(self, name), name)
        for name in (
            "attachment_proof_digest",
            "cancel_payload_digest",
            "result_digest",
            "start_payload_digest",
            "durable_eof_ack_digest",
        ):
            _require_optional_digest(getattr(self, name), name)
        if type(self.cancel_latched) is not bool:
            raise ValueError("cancel_latched must be bool")
        if type(self.child_ever_owned) is not bool:
            raise ValueError("child_ever_owned must be bool")
        if type(self.start_committed) is not bool:
            raise ValueError("start_committed must be bool")
        if (
            self.spawn_created is not None
            and type(self.spawn_created) is not bool
        ):
            raise ValueError("spawn_created must be bool when present")
        if type(self.cleanup_phase) is not _BrokerCleanupPhase:
            raise ValueError("cleanup_phase is invalid")
        if (
            self.terminal_kind is not None
            and type(self.terminal_kind) is not _TerminalKind
        ):
            raise ValueError("terminal_kind is invalid")
        if self.terminal_status is not None:
            require_plain_int(self.terminal_status, "terminal_status", minimum=0)
        if self.poison_reason is not None:
            raise ValueError("released tombstone contains poison reason")
        _validate_attestation_facts(self)
        expected_binding_digest = digest256(
            "ResolverSupervisorOperationBinding",
            SUPERVISOR_OPERATION_BINDING_SCHEMA_VERSION,
            {
                "epoch_id": self.epoch_id,
                "lifecycle_id": self.lifecycle_id,
                "operation_id": self.operation_id,
                "publication_id": self.publication_id,
                "spawn_request_digest": self.spawn_request_digest,
            },
        )
        expected_attestation_digest = digest256(
            "ResolverSupervisorOperationAttestation",
            SUPERVISOR_ATTESTATION_SCHEMA_VERSION,
            _attestation_payload_for_binding_digest(
                self,
                self.binding_digest,
            ),
        )
        selected = digest256(
            "ResolverSupervisorReleasedOperationTombstone",
            SUPERVISOR_RELEASED_TOMBSTONE_SCHEMA_VERSION,
            self._digest_payload(),
        )
        if (
            type(self.tombstone_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.binding_digest != expected_binding_digest
            or self.release_attestation_digest != expected_attestation_digest
            or selected != self.tombstone_digest
            or selected != self._issued_digest
        ):
            raise ValueError("released tombstone integrity failed")

    def matches(
        self,
        binding: _SupervisorOperationBinding,
        release_tombstone_id: UUID,
        release_attestation_digest: Digest256,
    ) -> bool:
        try:
            self.validate_integrity()
            binding.validate_integrity()
            checked_tombstone = require_uuid(
                release_tombstone_id,
                "release_tombstone_id",
            )
            checked_attestation = require_digest(
                release_attestation_digest,
                "release_attestation_digest",
            )
        except (AttributeError, TypeError, ValueError):
            return False
        return (
            self.epoch_id == binding.epoch_id
            and self.operation_id == binding.operation_id
            and self.lifecycle_id == binding.lifecycle_id
            and self.publication_id == binding.publication_id
            and self.spawn_request_digest == binding.spawn_request_digest
            and self.binding_digest == binding.binding_digest
            and self.release_tombstone_id == checked_tombstone
            and self.release_attestation_digest == checked_attestation
        )

    def matches_binding(self, binding: _SupervisorOperationBinding) -> bool:
        try:
            self.validate_integrity()
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            return False
        return (
            self.epoch_id == binding.epoch_id
            and self.operation_id == binding.operation_id
            and self.lifecycle_id == binding.lifecycle_id
            and self.publication_id == binding.publication_id
            and self.spawn_request_digest == binding.spawn_request_digest
            and self.binding_digest == binding.binding_digest
        )

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "binding_digest": str(self.binding_digest),
            "operation_id": str(self.operation_id),
            "release_attestation_digest": str(self.release_attestation_digest),
            "release_tombstone_id": str(self.release_tombstone_id),
            "tombstone_digest": str(self.tombstone_digest),
        }


@runtime_final
class _SupervisorPublicationProof:
    """Exact local publication observation accepted by broker ATTACH."""

    __slots__ = (
        "publication_id",
        "binding_digest",
        "proxy_id",
        "reservation_attestation_digest",
        "proof_id",
        "proof_digest",
        "_proxy",
        "_publication_ledger",
        "_issued_digest",
        "_issued_proxy",
        "_issued_publication_ledger",
    )

    def __init__(
        self,
        *,
        publication_id: UUID,
        binding_digest: Digest256,
        proxy_id: UUID,
        reservation_attestation_digest: Digest256,
        proof_id: UUID,
        proxy: "_SupervisorParentProxy",
        publication_ledger: "_SupervisorPublicationLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PUBLICATION_PROOF_AUTHORITY:
            raise TypeError("supervisor publication proof requires its ledger")
        if type(proxy) is not _SupervisorParentProxy:
            raise TypeError("proxy must be SupervisorParentProxy")
        if type(publication_ledger) is not _SupervisorPublicationLedger:
            raise TypeError(
                "publication_ledger must be SupervisorPublicationLedger"
            )
        if (
            publication_ledger._prepared_proxy is not proxy
            or publication_ledger._proxy is not proxy
        ):
            raise ValueError("supervisor publication proxy is not committed")
        object.__setattr__(
            self,
            "publication_id",
            require_uuid(publication_id, "publication_id"),
        )
        object.__setattr__(
            self,
            "binding_digest",
            require_digest(binding_digest, "binding_digest"),
        )
        object.__setattr__(self, "proxy_id", require_uuid(proxy_id, "proxy_id"))
        object.__setattr__(
            self,
            "reservation_attestation_digest",
            require_digest(
                reservation_attestation_digest,
                "reservation_attestation_digest",
            ),
        )
        object.__setattr__(self, "proof_id", require_uuid(proof_id, "proof_id"))
        object.__setattr__(self, "_proxy", proxy)
        object.__setattr__(self, "_publication_ledger", publication_ledger)
        selected_digest = digest256(
            "ResolverSupervisorPublicationProof",
            SUPERVISOR_PUBLICATION_PROOF_SCHEMA_VERSION,
            self._digest_payload(),
        )
        object.__setattr__(self, "proof_digest", selected_digest)
        object.__setattr__(self, "_issued_digest", selected_digest)
        object.__setattr__(self, "_issued_proxy", proxy)
        object.__setattr__(
            self,
            "_issued_publication_ledger",
            publication_ledger,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorPublicationProof is immutable")

    def __copy__(self) -> "_SupervisorPublicationProof":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_SupervisorPublicationProof":
        del memo
        return self

    def _digest_payload(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding_digest,
            "proof_id": self.proof_id,
            "proxy_id": self.proxy_id,
            "publication_id": self.publication_id,
            "reservation_attestation_digest": (
                self.reservation_attestation_digest
            ),
        }

    def validate_integrity(self) -> None:
        require_uuid(self.publication_id, "publication_id")
        require_uuid(self.proof_id, "proof_id")
        require_uuid(self.proxy_id, "proxy_id")
        require_digest(self.binding_digest, "binding_digest")
        require_digest(
            self.reservation_attestation_digest,
            "reservation_attestation_digest",
        )
        current = digest256(
            "ResolverSupervisorPublicationProof",
            SUPERVISOR_PUBLICATION_PROOF_SCHEMA_VERSION,
            self._digest_payload(),
        )
        if (
            type(self.proof_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or current != self.proof_digest
            or current != self._issued_digest
        ):
            raise ValueError("supervisor publication proof integrity failed")
        if (
            type(self._proxy) is not _SupervisorParentProxy
            or self._proxy is not self._issued_proxy
            or type(self._publication_ledger) is not _SupervisorPublicationLedger
            or self._publication_ledger is not self._issued_publication_ledger
            or self._publication_ledger._prepared_proxy is not self._proxy
            or self._publication_ledger._proxy is not self._proxy
            or self._publication_ledger._proof is not self
            or self._proxy.proxy_id != self.proxy_id
            or self._proxy.reservation_attestation_digest
            != self.reservation_attestation_digest
            or self._proxy.binding.publication_id != self.publication_id
            or self._proxy.binding.binding_digest != self.binding_digest
            or not _same_binding(
                self._publication_ledger.binding,
                self._proxy.binding,
            )
        ):
            raise ValueError("supervisor publication capability integrity failed")


def _attestation_payload_for_binding_digest(
    value: object,
    binding_digest: Digest256,
) -> dict[str, object]:
    return {
        "arm_command_id": value.arm_command_id,
        "attachment_command_id": value.attachment_command_id,
        "attachment_proof_digest": value.attachment_proof_digest,
        "binding_digest": binding_digest,
        "cancel_command_id": value.cancel_command_id,
        "cancel_latched": value.cancel_latched,
        "cancel_payload_digest": value.cancel_payload_digest,
        "child_ever_owned": value.child_ever_owned,
        "cleanup_phase": value.cleanup_phase,
        "close_action_id": value.close_action_id,
        "poison_reason": value.poison_reason,
        "ready_event_id": value.ready_event_id,
        "reap_action_id": value.reap_action_id,
        "release_tombstone_id": value.release_tombstone_id,
        "result_digest": value.result_digest,
        "result_event_id": value.result_event_id,
        "success_cleanup_event_id": value.success_cleanup_event_id,
        "durable_eof_ack_digest": value.durable_eof_ack_digest,
        "revision": value.revision,
        "spawn_created": value.spawn_created,
        "spawn_event_id": value.spawn_event_id,
        "start_command_id": value.start_command_id,
        "start_payload_digest": value.start_payload_digest,
        "start_committed": value.start_committed,
        "state": value.state,
        "terminal_attestation_id": value.terminal_attestation_id,
        "terminal_kind": value.terminal_kind,
        "terminal_status": value.terminal_status,
        "terminate_action_id": value.terminate_action_id,
    }


def _attestation_payload(value: "_SupervisorOperationAttestation") -> dict[str, object]:
    return _attestation_payload_for_binding_digest(
        value,
        value.binding.binding_digest,
    )


def _validate_attestation_facts(
    value: "_SupervisorOperationAttestation",
) -> None:
    paired_fields = (
        (value.attachment_command_id, value.attachment_proof_digest, "ATTACH"),
        (value.cancel_command_id, value.cancel_payload_digest, "CANCEL"),
        (value.spawn_event_id, value.spawn_created, "SPAWN_DONE"),
        (value.start_command_id, value.start_payload_digest, "START"),
        (value.result_event_id, value.result_digest, "RESULT"),
        (
            value.success_cleanup_event_id,
            value.durable_eof_ack_digest,
            "success cleanup",
        ),
        (value.terminal_attestation_id, value.terminal_kind, "terminal"),
    )
    for first, second, name in paired_fields:
        if (first is None) != (second is None):
            raise ValueError(f"{name} attestation is inconsistent")

    if value.cancel_latched != (value.cancel_command_id is not None):
        raise ValueError("cancel attestation is inconsistent")
    if value.start_committed and value.start_command_id is None:
        raise ValueError("START commit lacks a claim")
    if value.child_ever_owned != (value.spawn_created is True):
        raise ValueError("child ownership attestation is inconsistent")
    if value.ready_event_id is not None and not value.child_ever_owned:
        raise ValueError("READY lacks child ownership")
    if value.result_event_id is not None and not value.start_committed:
        raise ValueError("RESULT lacks committed START")
    success_cleanup = value.success_cleanup_event_id is not None
    if success_cleanup and (
        value.result_event_id is None
        or value.cancel_latched
        or not value.child_ever_owned
        or value.terminate_action_id is not None
        or value.cleanup_phase
        in (
            _BrokerCleanupPhase.NONE,
            _BrokerCleanupPhase.TERMINATE_REQUIRED,
            _BrokerCleanupPhase.TERMINATE_CLAIMED,
        )
        or value.state
        not in (
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        )
    ):
        raise ValueError("success cleanup proof is inconsistent")

    if value.state is _BrokerOperationState.POISONED:
        if value.poison_reason is None:
            raise ValueError("poisoned operation lacks reason")
    elif value.poison_reason is not None:
        raise ValueError("non-poisoned operation contains poison reason")

    terminal_state = value.state in (
        _BrokerOperationState.TERMINAL_ATTESTED,
        _BrokerOperationState.RELEASED,
    )
    if terminal_state:
        if value.terminal_attestation_id is None:
            raise ValueError("terminal operation lacks terminal attestation")
        if value.cleanup_phase is not _BrokerCleanupPhase.COMPLETE:
            raise ValueError("terminal operation lacks cleanup completion")
    elif (
        value.state is not _BrokerOperationState.POISONED
        and value.terminal_attestation_id is not None
    ):
        raise ValueError("nonterminal operation contains terminal attestation")

    if value.state is _BrokerOperationState.RELEASED:
        if value.release_tombstone_id is None:
            raise ValueError("released operation lacks tombstone")
    elif value.release_tombstone_id is not None:
        raise ValueError("unreleased operation contains tombstone")

    if value.terminal_kind is _TerminalKind.ZERO_CHILD_CANCEL:
        if (
            value.child_ever_owned
            or not value.cancel_latched
            or value.arm_command_id is not None
            or value.spawn_event_id is not None
            or value.terminal_attestation_id != value.cancel_command_id
            or value.terminal_status is not None
        ):
            raise ValueError("zero-child cancellation proof is inconsistent")
    elif value.terminal_kind is _TerminalKind.SPAWN_FAILED:
        if (
            value.child_ever_owned
            or value.spawn_created is not False
            or value.attachment_command_id is None
            or value.arm_command_id is None
            or value.terminal_attestation_id != value.spawn_event_id
            or value.terminal_status != _SPAWN_FAILED_STATUS
        ):
            raise ValueError("spawn-failure proof is inconsistent")
    elif value.terminal_kind is _TerminalKind.CHILD_EXITED:
        if (
            not value.child_ever_owned
            or value.attachment_command_id is None
            or value.arm_command_id is None
            or value.terminal_status is None
        ):
            raise ValueError("child-exit proof is inconsistent")
    elif value.terminal_status is not None:
        raise ValueError("terminal status lacks a terminal kind")

    if value.cleanup_phase is _BrokerCleanupPhase.NONE:
        if success_cleanup or any(
            action is not None
            for action in (
                value.terminate_action_id,
                value.reap_action_id,
                value.close_action_id,
            )
        ):
            raise ValueError("cleanup NONE contains action facts")
    elif value.cleanup_phase is _BrokerCleanupPhase.TERMINATE_REQUIRED:
        if any(
            action is not None
            for action in (
                value.terminate_action_id,
                value.reap_action_id,
                value.close_action_id,
            )
        ):
            raise ValueError("terminate-required contains action facts")
    elif value.cleanup_phase is _BrokerCleanupPhase.TERMINATE_CLAIMED:
        if (
            value.terminate_action_id is None
            or value.reap_action_id is not None
            or value.close_action_id is not None
        ):
            raise ValueError("terminate claim is inconsistent")
    elif value.cleanup_phase is _BrokerCleanupPhase.REAP_REQUIRED:
        if (
            value.reap_action_id is not None
            or value.close_action_id is not None
            or (value.terminate_action_id is None and not success_cleanup)
        ):
            raise ValueError("reap-required facts are inconsistent")
    elif value.cleanup_phase is _BrokerCleanupPhase.REAP_CLAIMED:
        if (
            value.reap_action_id is None
            or value.close_action_id is not None
            or (value.terminate_action_id is None and not success_cleanup)
        ):
            raise ValueError("reap claim is inconsistent")
    elif value.cleanup_phase is _BrokerCleanupPhase.CLOSE_REQUIRED:
        if (
            value.reap_action_id is None
            or value.close_action_id is not None
            or (value.terminate_action_id is None and not success_cleanup)
        ):
            raise ValueError("close-required facts are inconsistent")
    elif value.cleanup_phase is _BrokerCleanupPhase.CLOSE_CLAIMED:
        if (
            value.reap_action_id is None
            or value.close_action_id is None
            or (value.terminate_action_id is None and not success_cleanup)
        ):
            raise ValueError("close claim is inconsistent")
    elif value.cleanup_phase is _BrokerCleanupPhase.COMPLETE:
        action_ids = (
            value.terminate_action_id,
            value.reap_action_id,
            value.close_action_id,
        )
        if success_cleanup:
            if (
                value.terminate_action_id is not None
                or value.reap_action_id is None
                or value.close_action_id is None
            ):
                raise ValueError("success cleanup completion is inconsistent")
        elif any(action is not None for action in action_ids) and any(
            action is None for action in action_ids
        ):
            raise ValueError("cleanup completion is only partially attested")
        if value.child_ever_owned and value.cancel_latched and any(
            action is None for action in action_ids
        ):
            raise ValueError("cancelled child cleanup lacks action attestations")

    if value.cleanup_phase not in (
        _BrokerCleanupPhase.NONE,
        _BrokerCleanupPhase.COMPLETE,
    ) and value.state is not _BrokerOperationState.POISONED:
        cancelled_cleanup = value.child_ever_owned and value.cancel_latched
        if not cancelled_cleanup and not success_cleanup:
            raise ValueError("active cleanup lacks exact ownership")

    if value.state is _BrokerOperationState.RESERVED:
        if any(
            fact is not None
            for fact in (
                value.attachment_command_id,
                value.arm_command_id,
                value.cancel_command_id,
                value.spawn_event_id,
                value.ready_event_id,
                value.start_command_id,
                value.result_event_id,
                value.terminal_attestation_id,
            )
        ) or value.cleanup_phase is not _BrokerCleanupPhase.NONE:
            raise ValueError("reserved operation contains later facts")
    elif value.state is _BrokerOperationState.ATTACHED:
        if (
            value.attachment_command_id is None
            or value.arm_command_id is not None
            or value.cancel_latched
            or value.spawn_event_id is not None
            or value.ready_event_id is not None
            or value.start_command_id is not None
            or value.result_event_id is not None
            or value.cleanup_phase is not _BrokerCleanupPhase.NONE
        ):
            raise ValueError("attached operation facts are inconsistent")
    elif value.state is _BrokerOperationState.SPAWN_INFLIGHT:
        if (
            value.attachment_command_id is None
            or value.arm_command_id is None
            or value.spawn_event_id is not None
            or value.cancel_latched
            or value.ready_event_id is not None
            or value.start_command_id is not None
            or value.result_event_id is not None
            or value.cleanup_phase is not _BrokerCleanupPhase.NONE
        ):
            raise ValueError("spawn-inflight facts are inconsistent")
    elif value.state is _BrokerOperationState.CANCEL_WAIT_SPAWN:
        if (
            value.attachment_command_id is None
            or value.arm_command_id is None
            or value.spawn_event_id is not None
            or not value.cancel_latched
            or value.ready_event_id is not None
            or value.start_command_id is not None
            or value.result_event_id is not None
            or value.cleanup_phase is not _BrokerCleanupPhase.NONE
        ):
            raise ValueError("cancel-wait-spawn facts are inconsistent")
    elif value.state in (
        _BrokerOperationState.CHILD_OWNED,
        _BrokerOperationState.READY,
        _BrokerOperationState.STARTED,
        _BrokerOperationState.RESULT_PENDING_TERMINAL,
    ):
        if (
            value.attachment_command_id is None
            or value.arm_command_id is None
            or not value.child_ever_owned
        ):
            raise ValueError("child operation lacks ownership facts")
        if (
            value.state is _BrokerOperationState.CHILD_OWNED
            and (
                value.ready_event_id is not None
                or value.start_command_id is not None
                or value.result_event_id is not None
            )
        ):
            raise ValueError("child-owned operation contains later facts")
        if (
            value.state is _BrokerOperationState.READY
            and (value.start_committed or value.result_event_id is not None)
        ):
            raise ValueError("READY operation contains committed business facts")
        if (
            value.state is _BrokerOperationState.STARTED
            and value.result_event_id is not None
        ):
            raise ValueError("STARTED operation contains RESULT facts")
        if (
            value.state is not _BrokerOperationState.CHILD_OWNED
            and value.ready_event_id is None
        ):
            raise ValueError("post-READY operation lacks READY proof")
        if value.state in (
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
        ) and not value.start_committed:
            raise ValueError("started operation lacks START proof")
        if (
            value.state is _BrokerOperationState.RESULT_PENDING_TERMINAL
            and value.result_event_id is None
        ):
            raise ValueError("result-pending operation lacks RESULT proof")


@runtime_final
class _SupervisorOperationAttestation:
    """Immutable authoritative snapshot; queries never mutate its revision."""

    __slots__ = (
        "binding",
        "revision",
        "state",
        "attachment_command_id",
        "attachment_proof_digest",
        "_attachment_proof",
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
        "_broker_ledger",
        "_issued_digest",
        "_issued_attachment_proof",
        "_issued_broker_ledger",
        "_compacted_release",
    )

    def __init__(
        self,
        *,
        record: "_BrokerOperationRecord",
        broker_ledger: "_SupervisorBrokerLedger",
        _authority: object,
    ) -> None:
        if _authority is not _ATTESTATION_AUTHORITY:
            raise TypeError("supervisor attestation requires its broker")
        if type(broker_ledger) is not _SupervisorBrokerLedger:
            raise TypeError("broker_ledger must be SupervisorBrokerLedger")
        if (
            broker_ledger._operations.get(record.binding.operation_id)
            is not record
        ):
            raise ValueError("supervisor attestation record owner changed")
        values = (
            ("binding", record.binding),
            ("revision", record.revision),
            ("state", record.state),
            ("attachment_command_id", record.attachment_command_id),
            ("attachment_proof_digest", record.attachment_proof_digest),
            ("_attachment_proof", record.attachment_proof),
            ("arm_command_id", record.arm_command_id),
            ("cancel_command_id", record.cancel_command_id),
            ("cancel_payload_digest", record.cancel_payload_digest),
            ("cancel_latched", record.cancel_command_id is not None),
            ("spawn_event_id", record.spawn_event_id),
            ("spawn_created", record.spawn_created),
            ("child_ever_owned", record.child_ever_owned),
            ("ready_event_id", record.ready_event_id),
            ("start_command_id", record.start_command_id),
            ("start_payload_digest", record.start_payload_digest),
            ("start_committed", record.start_committed),
            ("result_event_id", record.result_event_id),
            ("result_digest", record.result_digest),
            ("success_cleanup_event_id", record.success_cleanup_event_id),
            ("durable_eof_ack_digest", record.durable_eof_ack_digest),
            ("cleanup_phase", record.cleanup_phase),
            ("terminate_action_id", record.terminate_action_id),
            ("reap_action_id", record.reap_action_id),
            ("close_action_id", record.close_action_id),
            ("terminal_attestation_id", record.terminal_attestation_id),
            ("terminal_kind", record.terminal_kind),
            ("terminal_status", record.terminal_status),
            ("release_tombstone_id", record.release_tombstone_id),
            ("poison_reason", record.poison_reason),
        )
        for name, selected in values:
            object.__setattr__(self, name, selected)
        object.__setattr__(self, "_broker_ledger", broker_ledger)
        selected_digest = digest256(
            "ResolverSupervisorOperationAttestation",
            SUPERVISOR_ATTESTATION_SCHEMA_VERSION,
            _attestation_payload(self),
        )
        object.__setattr__(self, "attestation_digest", selected_digest)
        object.__setattr__(self, "_issued_digest", selected_digest)
        object.__setattr__(
            self,
            "_issued_attachment_proof",
            self._attachment_proof,
        )
        object.__setattr__(
            self,
            "_issued_broker_ledger",
            broker_ledger,
        )
        object.__setattr__(self, "_compacted_release", False)
        self.validate_integrity()

    @classmethod
    def _from_released_tombstone(
        cls,
        *,
        tombstone: _SupervisorReleasedOperationTombstone,
        broker_ledger: "_SupervisorBrokerLedger",
        _authority: object,
    ) -> "_SupervisorOperationAttestation":
        if _authority is not _ATTESTATION_AUTHORITY:
            raise TypeError("supervisor attestation requires its broker")
        if type(tombstone) is not _SupervisorReleasedOperationTombstone:
            raise TypeError("tombstone must be SupervisorReleasedOperationTombstone")
        if type(broker_ledger) is not _SupervisorBrokerLedger:
            raise TypeError("broker_ledger must be SupervisorBrokerLedger")
        tombstone.validate_integrity()
        if (
            broker_ledger._released_tombstones.get(tombstone.operation_id)
            is not tombstone
            or broker_ledger.epoch_id != tombstone.epoch_id
        ):
            raise ValueError("released tombstone owner changed")
        selected = object.__new__(cls)
        binding = _new_supervisor_operation_binding(
            epoch_id=tombstone.epoch_id,
            operation_id=tombstone.operation_id,
            lifecycle_id=tombstone.lifecycle_id,
            publication_id=tombstone.publication_id,
            spawn_request_digest=tombstone.spawn_request_digest,
        )
        values = (
            ("binding", binding),
            ("revision", tombstone.revision),
            ("state", tombstone.state),
            ("attachment_command_id", tombstone.attachment_command_id),
            ("attachment_proof_digest", tombstone.attachment_proof_digest),
            ("_attachment_proof", None),
            ("arm_command_id", tombstone.arm_command_id),
            ("cancel_command_id", tombstone.cancel_command_id),
            ("cancel_payload_digest", tombstone.cancel_payload_digest),
            ("cancel_latched", tombstone.cancel_latched),
            ("spawn_event_id", tombstone.spawn_event_id),
            ("spawn_created", tombstone.spawn_created),
            ("child_ever_owned", tombstone.child_ever_owned),
            ("ready_event_id", tombstone.ready_event_id),
            ("start_command_id", tombstone.start_command_id),
            ("start_payload_digest", tombstone.start_payload_digest),
            ("start_committed", tombstone.start_committed),
            ("result_event_id", tombstone.result_event_id),
            ("result_digest", tombstone.result_digest),
            (
                "success_cleanup_event_id",
                tombstone.success_cleanup_event_id,
            ),
            ("durable_eof_ack_digest", tombstone.durable_eof_ack_digest),
            ("cleanup_phase", tombstone.cleanup_phase),
            ("terminate_action_id", tombstone.terminate_action_id),
            ("reap_action_id", tombstone.reap_action_id),
            ("close_action_id", tombstone.close_action_id),
            ("terminal_attestation_id", tombstone.terminal_attestation_id),
            ("terminal_kind", tombstone.terminal_kind),
            ("terminal_status", tombstone.terminal_status),
            ("release_tombstone_id", tombstone.release_tombstone_id),
            ("poison_reason", tombstone.poison_reason),
            ("attestation_digest", tombstone.release_attestation_digest),
            ("_broker_ledger", broker_ledger),
            ("_issued_digest", tombstone.release_attestation_digest),
            ("_issued_attachment_proof", None),
            ("_issued_broker_ledger", broker_ledger),
            ("_compacted_release", True),
        )
        for name, value in values:
            object.__setattr__(selected, name, value)
        selected.validate_integrity()
        return selected

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorOperationAttestation is immutable")

    def __copy__(self) -> "_SupervisorOperationAttestation":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_SupervisorOperationAttestation":
        del memo
        return self

    def validate_integrity(self) -> None:
        if type(self.binding) is not _SupervisorOperationBinding:
            raise ValueError("attestation binding is invalid")
        self.binding.validate_integrity()
        if (
            type(self._broker_ledger) is not _SupervisorBrokerLedger
            or self._broker_ledger is not self._issued_broker_ledger
            or self._broker_ledger.epoch_id != self.binding.epoch_id
        ):
            raise ValueError("attestation broker owner is invalid")
        if type(self._compacted_release) is not bool:
            raise ValueError("attestation compaction marker is invalid")
        require_plain_int(self.revision, "revision", minimum=0)
        if type(self.state) is not _BrokerOperationState:
            raise ValueError("attestation state is invalid")
        for name in (
            "attachment_command_id",
            "arm_command_id",
            "cancel_command_id",
            "spawn_event_id",
            "ready_event_id",
            "start_command_id",
            "result_event_id",
            "success_cleanup_event_id",
            "terminate_action_id",
            "reap_action_id",
            "close_action_id",
            "terminal_attestation_id",
            "release_tombstone_id",
        ):
            _require_optional_uuid(getattr(self, name), name)
        for name in (
            "attachment_proof_digest",
            "cancel_payload_digest",
            "result_digest",
            "start_payload_digest",
            "durable_eof_ack_digest",
        ):
            _require_optional_digest(getattr(self, name), name)
        if type(self.cancel_latched) is not bool:
            raise ValueError("cancel_latched must be bool")
        if type(self.child_ever_owned) is not bool:
            raise ValueError("child_ever_owned must be bool")
        if type(self.start_committed) is not bool:
            raise ValueError("start_committed must be bool")
        if self.spawn_created is not None and type(self.spawn_created) is not bool:
            raise ValueError("spawn_created must be bool when present")
        if type(self.cleanup_phase) is not _BrokerCleanupPhase:
            raise ValueError("cleanup_phase is invalid")
        if self.terminal_kind is not None and type(self.terminal_kind) is not _TerminalKind:
            raise ValueError("terminal_kind is invalid")
        if self.terminal_status is not None:
            require_plain_int(self.terminal_status, "terminal_status", minimum=0)
        if self.poison_reason is not None and type(self.poison_reason) is not _PoisonReason:
            raise ValueError("poison_reason is invalid")
        if self.cancel_latched != (self.cancel_command_id is not None):
            raise ValueError("cancel attestation is inconsistent")
        if self._compacted_release:
            if (
                self.state is not _BrokerOperationState.RELEASED
                or self._attachment_proof is not None
                or self._issued_attachment_proof is not None
            ):
                raise ValueError("compacted release capability is invalid")
            tombstone = self._broker_ledger._released_tombstones.get(
                self.binding.operation_id
            )
            if (
                type(tombstone) is not _SupervisorReleasedOperationTombstone
                or not tombstone.matches(
                    self.binding,
                    self.release_tombstone_id,
                    self.attestation_digest,
                )
                or _attestation_payload_for_binding_digest(
                    tombstone,
                    tombstone.binding_digest,
                )
                != _attestation_payload(self)
            ):
                raise ValueError("compacted release tombstone is invalid")
        elif (self.attachment_command_id is None) != (
            self._attachment_proof is None
        ):
            raise ValueError("ATTACH capability is inconsistent")
        elif self._attachment_proof is not self._issued_attachment_proof:
            raise ValueError("ATTACH capability identity changed")
        elif self._attachment_proof is not None:
            if type(self._attachment_proof) is not _SupervisorPublicationProof:
                raise ValueError("ATTACH capability is invalid")
            self._attachment_proof.validate_integrity()
            if (
                self._attachment_proof.proof_digest
                != self.attachment_proof_digest
                or self._attachment_proof.binding_digest
                != self.binding.binding_digest
                or self._attachment_proof.publication_id
                != self.binding.publication_id
            ):
                raise ValueError("ATTACH capability binding changed")
        if (self.start_command_id is None) != (self.start_payload_digest is None):
            raise ValueError("START claim is inconsistent")
        if self.start_committed and self.start_command_id is None:
            raise ValueError("START commit lacks a claim")
        if self.state is _BrokerOperationState.ATTACHED and self.attachment_command_id is None:
            raise ValueError("attached operation lacks attachment attestation")
        if self.state in (
            _BrokerOperationState.SPAWN_INFLIGHT,
            _BrokerOperationState.CANCEL_WAIT_SPAWN,
            _BrokerOperationState.CHILD_OWNED,
            _BrokerOperationState.READY,
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
        ) and self.arm_command_id is None:
            raise ValueError("armed operation lacks ARM attestation")
        if self.state in (
            _BrokerOperationState.CHILD_OWNED,
            _BrokerOperationState.READY,
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
        ) and not self.child_ever_owned:
            raise ValueError("child state lacks ownership attestation")
        if self.state in (
            _BrokerOperationState.STARTED,
            _BrokerOperationState.RESULT_PENDING_TERMINAL,
        ) and not self.start_committed:
            raise ValueError("started operation lacks START attestation")
        if self.state in (
            _BrokerOperationState.TERMINAL_ATTESTED,
            _BrokerOperationState.RELEASED,
        ) and (
            self.terminal_attestation_id is None or self.terminal_kind is None
        ):
            raise ValueError("terminal operation lacks terminal attestation")
        if self.state is _BrokerOperationState.RELEASED and self.release_tombstone_id is None:
            raise ValueError("released operation lacks tombstone")
        if self.state is _BrokerOperationState.POISONED and self.poison_reason is None:
            raise ValueError("poisoned operation lacks reason")
        _validate_attestation_facts(self)
        current = digest256(
            "ResolverSupervisorOperationAttestation",
            SUPERVISOR_ATTESTATION_SCHEMA_VERSION,
            _attestation_payload(self),
        )
        if (
            type(self.attestation_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or current != self.attestation_digest
            or current != self._issued_digest
        ):
            raise ValueError("supervisor attestation integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "attestation_digest": str(self.attestation_digest),
            "binding_digest": str(self.binding.binding_digest),
            "cancel_latched": self.cancel_latched,
            "child_ever_owned": self.child_ever_owned,
            "cleanup_phase": self.cleanup_phase.value,
            "released": self.release_tombstone_id is not None,
            "revision": self.revision,
            "start_committed": self.start_committed,
            "state": self.state.value,
            "terminal_attested": self.terminal_attestation_id is not None,
        }


@runtime_final
class _SupervisorQueryReply:
    """One exact status-query response, separate from operation revision."""

    __slots__ = (
        "query_id",
        "attestation",
        "reply_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        query_id: UUID,
        attestation: _SupervisorOperationAttestation,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _QUERY_REPLY_AUTHORITY:
            raise TypeError("supervisor query reply requires its broker")
        if type(attestation) is not _SupervisorOperationAttestation:
            raise TypeError("attestation must be SupervisorOperationAttestation")
        attestation.validate_integrity()
        object.__setattr__(self, "query_id", require_uuid(query_id, "query_id"))
        object.__setattr__(self, "attestation", attestation)
        selected = digest256(
            "ResolverSupervisorQueryReply",
            SUPERVISOR_QUERY_REPLY_SCHEMA_VERSION,
            {
                "attestation_digest": attestation.attestation_digest,
                "query_id": self.query_id,
            },
        )
        object.__setattr__(self, "reply_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorQueryReply is immutable")

    def validate_integrity(self) -> None:
        require_uuid(self.query_id, "query_id")
        if type(self.attestation) is not _SupervisorOperationAttestation:
            raise ValueError("query reply attestation is invalid")
        self.attestation.validate_integrity()
        selected = digest256(
            "ResolverSupervisorQueryReply",
            SUPERVISOR_QUERY_REPLY_SCHEMA_VERSION,
            {
                "attestation_digest": self.attestation.attestation_digest,
                "query_id": self.query_id,
            },
        )
        if (
            type(self.reply_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or selected != self.reply_digest
            or selected != self._issued_digest
        ):
            raise ValueError("supervisor query reply integrity failed")


class _BrokerOperationRecord:
    __slots__ = (
        "binding",
        "revision",
        "state",
        "attachment_command_id",
        "attachment_proof_digest",
        "attachment_proof",
        "arm_command_id",
        "cancel_command_id",
        "cancel_payload_digest",
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
        "uncertain_cleanup_action_id",
        "terminal_attestation_id",
        "terminal_kind",
        "terminal_status",
        "release_tombstone_id",
        "poison_reason",
    )

    def __init__(self, binding: _SupervisorOperationBinding) -> None:
        self.binding = binding
        self.revision = 0
        self.state = _BrokerOperationState.RESERVED
        self.attachment_command_id: UUID | None = None
        self.attachment_proof_digest: Digest256 | None = None
        self.attachment_proof: _SupervisorPublicationProof | None = None
        self.arm_command_id: UUID | None = None
        self.cancel_command_id: UUID | None = None
        self.cancel_payload_digest: Digest256 | None = None
        self.spawn_event_id: UUID | None = None
        self.spawn_created: bool | None = None
        self.child_ever_owned = False
        self.ready_event_id: UUID | None = None
        self.start_command_id: UUID | None = None
        self.start_payload_digest: Digest256 | None = None
        self.start_committed = False
        self.result_event_id: UUID | None = None
        self.result_digest: Digest256 | None = None
        self.success_cleanup_event_id: UUID | None = None
        self.durable_eof_ack_digest: Digest256 | None = None
        self.cleanup_phase = _BrokerCleanupPhase.NONE
        self.terminate_action_id: UUID | None = None
        self.reap_action_id: UUID | None = None
        self.close_action_id: UUID | None = None
        self.uncertain_cleanup_action_id: UUID | None = None
        self.terminal_attestation_id: UUID | None = None
        self.terminal_kind: _TerminalKind | None = None
        self.terminal_status: int | None = None
        self.release_tombstone_id: UUID | None = None
        self.poison_reason: _PoisonReason | None = None


@runtime_final
class _SupervisorBrokerLedger:
    """Single-event-owner, pure authoritative operation registry."""

    __slots__ = (
        "epoch_id",
        "_lock",
        "_operations",
        "_query_replies",
        "_released_tombstones",
        "_poisoned",
        "_global_poison_reason",
        "_parent_session",
        "_control_port",
        "_event_port",
        "_cleanup_port",
    )

    def __init__(
        self,
        *,
        epoch_id: UUID,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BROKER_LEDGER_AUTHORITY:
            raise TypeError("supervisor broker ledger requires its factory")
        object.__setattr__(self, "epoch_id", require_uuid(epoch_id, "epoch_id"))
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_operations", {})
        object.__setattr__(self, "_query_replies", {})
        object.__setattr__(self, "_released_tombstones", {})
        object.__setattr__(self, "_poisoned", False)
        object.__setattr__(self, "_global_poison_reason", None)
        object.__setattr__(self, "_parent_session", None)
        object.__setattr__(
            self,
            "_control_port",
            _SupervisorBrokerControlPort(
                ledger=self,
                _authority=_BROKER_PORT_AUTHORITY,
            ),
        )
        object.__setattr__(
            self,
            "_event_port",
            _SupervisorBrokerEventPort(
                ledger=self,
                _authority=_BROKER_PORT_AUTHORITY,
            ),
        )
        object.__setattr__(
            self,
            "_cleanup_port",
            _SupervisorBrokerCleanupPort(
                ledger=self,
                _authority=_BROKER_PORT_AUTHORITY,
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorBrokerLedger identity is immutable")

    def _require_role(self, authority: object, expected: type[object]) -> None:
        if type(authority) is not expected or authority._ledger is not self:
            raise TypeError("supervisor broker role authority is invalid")

    def _snapshot(
        self,
        record: _BrokerOperationRecord,
    ) -> _SupervisorOperationAttestation:
        return _SupervisorOperationAttestation(
            record=record,
            broker_ledger=self,
            _authority=_ATTESTATION_AUTHORITY,
        )

    def _released_snapshot(
        self,
        tombstone: _SupervisorReleasedOperationTombstone,
    ) -> _SupervisorOperationAttestation:
        return _SupervisorOperationAttestation._from_released_tombstone(
            tombstone=tombstone,
            broker_ledger=self,
            _authority=_ATTESTATION_AUTHORITY,
        )

    def _poison_all_locked(self, reason: _PoisonReason) -> None:
        if (
            reason is not _PoisonReason.OS_ACTION_UNCERTAIN
            and any(
                (
                    record.start_command_id is not None
                    and not record.start_committed
                    and record.state
                    not in (
                        _BrokerOperationState.RELEASED,
                        _BrokerOperationState.POISONED,
                    )
                )
                or self._claimed_cleanup_action_id(record) is not None
                for record in self._operations.values()
            )
        ):
            reason = _PoisonReason.OS_ACTION_UNCERTAIN
        object.__setattr__(self, "_poisoned", True)
        if (
            self._global_poison_reason is None
            or reason is _PoisonReason.OS_ACTION_UNCERTAIN
        ):
            object.__setattr__(self, "_global_poison_reason", reason)
        for record in self._operations.values():
            uncertainty_marker_added = False
            if (
                reason is _PoisonReason.OS_ACTION_UNCERTAIN
                and record.uncertain_cleanup_action_id is None
            ):
                claimed_action_id = self._claimed_cleanup_action_id(record)
                if claimed_action_id is not None:
                    record.uncertain_cleanup_action_id = claimed_action_id
                    uncertainty_marker_added = True
            if record.state in (
                _BrokerOperationState.RELEASED,
            ):
                continue
            if record.state is _BrokerOperationState.POISONED:
                poison_reason_changed = False
                if (
                    reason is _PoisonReason.OS_ACTION_UNCERTAIN
                    and record.poison_reason is not reason
                ):
                    record.poison_reason = reason
                    poison_reason_changed = True
                if uncertainty_marker_added or poison_reason_changed:
                    record.revision += 1
                continue
            self._poison_record_locked(record, reason)

    @staticmethod
    def _claimed_cleanup_action_id(
        record: _BrokerOperationRecord,
    ) -> UUID | None:
        if record.cleanup_phase is _BrokerCleanupPhase.TERMINATE_CLAIMED:
            return record.terminate_action_id
        if record.cleanup_phase is _BrokerCleanupPhase.REAP_CLAIMED:
            return record.reap_action_id
        if record.cleanup_phase is _BrokerCleanupPhase.CLOSE_CLAIMED:
            return record.close_action_id
        return None

    @staticmethod
    def _poison_record_locked(
        record: _BrokerOperationRecord,
        reason: _PoisonReason,
    ) -> None:
        if record.state in (
            _BrokerOperationState.RELEASED,
            _BrokerOperationState.POISONED,
        ):
            return
        if (
            record.child_ever_owned
            and record.cleanup_phase is _BrokerCleanupPhase.NONE
        ):
            record.cleanup_phase = _BrokerCleanupPhase.TERMINATE_REQUIRED
        record.state = _BrokerOperationState.POISONED
        record.poison_reason = reason
        record.revision += 1

    def _reject_locked(self, reason: _PoisonReason, message: str) -> NoReturn:
        self._poison_all_locked(reason)
        _raise_supervisor_error(message)

    def _reject_operation_locked(
        self,
        record: _BrokerOperationRecord,
        reason: _PoisonReason,
        message: str,
    ) -> NoReturn:
        if record.start_command_id is not None and not record.start_committed:
            self._reject_locked(
                _PoisonReason.OS_ACTION_UNCERTAIN,
                "supervisor START send outcome 不确定。",
            )
        if (
            reason is _PoisonReason.OS_ACTION_UNCERTAIN
            and record.uncertain_cleanup_action_id is None
        ):
            record.uncertain_cleanup_action_id = (
                self._claimed_cleanup_action_id(record)
            )
        self._poison_record_locked(record, reason)
        _raise_supervisor_error(message)

    def _released_tombstone_locked(
        self,
        binding: _SupervisorOperationBinding,
    ) -> _SupervisorReleasedOperationTombstone | None:
        tombstone = self._released_tombstones.get(binding.operation_id)
        if tombstone is None:
            return None
        if type(tombstone) is not _SupervisorReleasedOperationTombstone:
            self._reject_locked(
                _PoisonReason.SNAPSHOT_EQUIVOCATION,
                "supervisor released tombstone 无效。",
            )
        try:
            tombstone.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            self._reject_locked(
                _PoisonReason.SNAPSHOT_EQUIVOCATION,
                "supervisor released tombstone 无效。",
            )
        if not tombstone.matches_binding(binding):
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor released operation identity 已变化。",
            )
        return tombstone

    def _record_locked(
        self,
        binding: _SupervisorOperationBinding,
    ) -> _BrokerOperationRecord:
        if type(binding) is not _SupervisorOperationBinding:
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor operation binding 无效。",
            )
        try:
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor operation binding 无效。",
            )
        if binding.epoch_id != self.epoch_id:
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor epoch 已变化。",
            )
        record = self._operations.get(binding.operation_id)
        if record is None:
            tombstone = self._released_tombstone_locked(binding)
            if tombstone is not None:
                _raise_supervisor_error("supervisor operation 已 compact release。")
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor operation identity 已变化。",
            )
        if not _same_binding(record.binding, binding):
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor operation identity 已变化。",
            )
        return record

    def _query_snapshot_locked(
        self,
        binding: _SupervisorOperationBinding,
    ) -> _SupervisorOperationAttestation:
        if type(binding) is not _SupervisorOperationBinding:
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor operation binding 无效。",
            )
        try:
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor operation binding 无效。",
            )
        if binding.epoch_id != self.epoch_id:
            self._reject_locked(
                _PoisonReason.BINDING_MISMATCH,
                "supervisor epoch 已变化。",
            )
        record = self._operations.get(binding.operation_id)
        if record is not None:
            if not _same_binding(record.binding, binding):
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor operation identity 已变化。",
                )
            return self._snapshot(record)
        tombstone = self._released_tombstone_locked(binding)
        if tombstone is not None:
            return self._released_snapshot(tombstone)
        self._reject_locked(
            _PoisonReason.BINDING_MISMATCH,
            "supervisor operation identity 已变化。",
        )

    def _mutable_record_locked(
        self,
        binding: _SupervisorOperationBinding,
        *,
        pending_start_command_id: UUID | None = None,
    ) -> _BrokerOperationRecord:
        record = self._record_locked(binding)
        self._require_external_action_slot_locked(
            record=record,
            action_kind="start",
            action_id=pending_start_command_id,
        )
        if self._poisoned or record.state is _BrokerOperationState.POISONED:
            _raise_supervisor_error("supervisor epoch 已隔离。")
        return record

    def _cleanup_record_locked(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_kind: _BrokerCleanupPhase,
        action_id: UUID,
    ) -> _BrokerOperationRecord:
        record = self._record_locked(binding)
        self._require_external_action_slot_locked(
            record=record,
            action_kind=action_kind.value,
            action_id=action_id,
        )
        if record.state is not _BrokerOperationState.POISONED:
            return record
        if record.uncertain_cleanup_action_id is not None:
            _raise_supervisor_error("supervisor cleanup outcome 不可恢复。")
        return record

    def _pending_external_action_locked(
        self,
    ) -> tuple[str, _BrokerOperationRecord, UUID] | None:
        for record in self._operations.values():
            if (
                record.start_command_id is not None
                and not record.start_committed
                and record.state
                not in (
                    _BrokerOperationState.RELEASED,
                    _BrokerOperationState.POISONED,
                )
            ):
                return "start", record, record.start_command_id
            cleanup_action_id = self._claimed_cleanup_action_id(record)
            if cleanup_action_id is not None:
                return record.cleanup_phase.value, record, cleanup_action_id
        return None

    def _require_external_action_slot_locked(
        self,
        *,
        record: _BrokerOperationRecord | None = None,
        action_kind: str | None = None,
        action_id: UUID | None = None,
        action_digest: Digest256 | None = None,
        require_action_digest: bool = False,
    ) -> None:
        pending = self._pending_external_action_locked()
        if pending is None:
            return
        pending_kind, pending_record, pending_action_id = pending
        if (
            pending_record is record
            and pending_kind == action_kind
            and pending_action_id == action_id
            and (
                not require_action_digest
                or (
                    action_digest is not None
                    and pending_record.start_payload_digest == action_digest
                )
            )
        ):
            return
        self._reject_locked(
            _PoisonReason.OS_ACTION_UNCERTAIN,
            "supervisor external action outcome 不确定。",
        )

    def _preflight_mutation(
        self,
        binding: object,
        *,
        action_kind: str | None = None,
        action_id: object = None,
        action_digest: object = None,
        require_action_digest: bool = False,
    ) -> None:
        with self._lock:
            record = None
            if type(binding) is _SupervisorOperationBinding:
                operation_id = binding.operation_id
                if type(operation_id) is UUID:
                    record = self._operations.get(operation_id)
            checked_action_id = action_id if type(action_id) is UUID else None
            checked_action_digest = (
                action_digest
                if type(action_digest) is Digest256
                else None
            )
            self._require_external_action_slot_locked(
                record=record,
                action_kind=action_kind,
                action_id=checked_action_id,
                action_digest=checked_action_digest,
                require_action_digest=require_action_digest,
            )

    def reserve(
        self,
        binding: _SupervisorOperationBinding,
        *,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerControlPort)
        self._preflight_mutation(binding)
        if type(binding) is not _SupervisorOperationBinding:
            raise TypeError("binding must be SupervisorOperationBinding")
        try:
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            _raise_supervisor_error("supervisor operation binding 无效。")
        with self._lock:
            self._require_external_action_slot_locked()
            if self._poisoned:
                _raise_supervisor_error("supervisor epoch 已隔离。")
            if binding.epoch_id != self.epoch_id:
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor epoch 已变化。",
                )
            existing = self._operations.get(binding.operation_id)
            if existing is not None:
                if _same_binding(existing.binding, binding):
                    return self._snapshot(existing)
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor operation identity 已变化。",
                )
            tombstone = self._released_tombstone_locked(binding)
            if tombstone is not None:
                _raise_supervisor_error("supervisor operation 已 release。")
            if len(self._operations) >= SUPERVISOR_ACTIVE_OPERATION_LIMIT:
                _raise_supervisor_error("supervisor active operation ledger 已满。")
            if (
                len(self._operations) + len(self._released_tombstones)
                >= SUPERVISOR_RELEASED_TOMBSTONE_LIMIT
            ):
                _raise_supervisor_error("supervisor epoch terminal capacity 已满。")
            record = _BrokerOperationRecord(binding)
            self._operations[binding.operation_id] = record
            return self._snapshot(record)

    def query(
        self,
        binding: _SupervisorOperationBinding,
        *,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerControlPort)
        with self._lock:
            return self._query_snapshot_locked(binding)

    def query_reply(
        self,
        binding: _SupervisorOperationBinding,
        *,
        query_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorQueryReply:
        self._require_role(_authority, _SupervisorBrokerControlPort)
        checked_query = require_uuid(query_id, "query_id")
        with self._lock:
            attestation = self._query_snapshot_locked(binding)
            # A compacted operation is reconstructed from its immutable
            # released tombstone.  Returning the deterministic reply directly
            # avoids resurrecting the capability-bearing active reply cache.
            if binding.operation_id not in self._operations:
                return _SupervisorQueryReply(
                    query_id=checked_query,
                    attestation=attestation,
                    _authority=_QUERY_REPLY_AUTHORITY,
                )
            key = (binding.operation_id, checked_query)
            existing = self._query_replies.get(key)
            if existing is not None and (
                attestation.state is not _BrokerOperationState.POISONED
                or existing.attestation.state is _BrokerOperationState.POISONED
            ):
                return existing
            if existing is None and sum(
                operation_id == binding.operation_id
                for operation_id, _ in self._query_replies
            ) >= SUPERVISOR_QUERY_REPLY_LIMIT_PER_OPERATION:
                _raise_supervisor_error(
                    "supervisor operation query reply ledger 已满。"
                )
            reply = _SupervisorQueryReply(
                query_id=checked_query,
                attestation=attestation,
                _authority=_QUERY_REPLY_AUTHORITY,
            )
            self._query_replies[key] = reply
            return reply

    def attach(
        self,
        binding: _SupervisorOperationBinding,
        *,
        proof: _SupervisorPublicationProof,
        command_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerControlPort)
        self._preflight_mutation(binding)
        checked_command = require_uuid(command_id, "command_id")
        if type(proof) is not _SupervisorPublicationProof:
            raise TypeError("proof must be SupervisorPublicationProof")
        try:
            proof.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            _raise_supervisor_error("supervisor publication proof 无效。")
        with self._lock:
            record = self._mutable_record_locked(binding)
            if (
                proof.publication_id != binding.publication_id
                or proof.binding_digest != binding.binding_digest
                or proof._proxy._broker_ledger is not self
            ):
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor publication proof 已变化。",
                )
            if record.attachment_command_id is not None:
                if (
                    record.attachment_command_id == checked_command
                    and record.attachment_proof_digest == proof.proof_digest
                    and record.attachment_proof is proof
                ):
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor ATTACH command 已变化。",
                )
            if (
                record.cancel_command_id is not None
                and record.state
                in (
                    _BrokerOperationState.TERMINAL_ATTESTED,
                    _BrokerOperationState.RELEASED,
                )
            ):
                return self._snapshot(record)
            if record.state is not _BrokerOperationState.RESERVED:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor ATTACH 顺序无效。",
                )
            if (
                proof.reservation_attestation_digest
                != self._snapshot(record).attestation_digest
            ):
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor RESERVED attestation 已变化。",
                )
            record.attachment_command_id = checked_command
            record.attachment_proof_digest = proof.proof_digest
            record.attachment_proof = proof
            record.state = _BrokerOperationState.ATTACHED
            record.revision += 1
            return self._snapshot(record)

    def arm(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerControlPort)
        self._preflight_mutation(binding)
        checked_command = require_uuid(command_id, "command_id")
        with self._lock:
            record = self._mutable_record_locked(binding)
            if record.arm_command_id is not None:
                if record.arm_command_id == checked_command:
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor ARM command 已变化。",
                )
            if (
                record.cancel_command_id is not None
                and record.state
                in (
                    _BrokerOperationState.TERMINAL_ATTESTED,
                    _BrokerOperationState.RELEASED,
                )
            ):
                return self._snapshot(record)
            if record.state is not _BrokerOperationState.ATTACHED:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor ARM 缺少 publication attestation。",
                )
            record.arm_command_id = checked_command
            record.state = _BrokerOperationState.SPAWN_INFLIGHT
            record.revision += 1
            return self._snapshot(record)

    def cancel(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
        payload_digest: Digest256,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerControlPort)
        self._preflight_mutation(binding)
        checked_command = require_uuid(command_id, "command_id")
        checked_payload = require_digest(payload_digest, "payload_digest")
        with self._lock:
            record = self._mutable_record_locked(binding)
            if record.cancel_command_id is not None:
                if (
                    record.cancel_command_id == checked_command
                    and record.cancel_payload_digest == checked_payload
                ):
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor CANCEL command 已变化。",
                )
            if record.state in (
                _BrokerOperationState.TERMINAL_ATTESTED,
                _BrokerOperationState.RELEASED,
            ):
                return self._snapshot(record)
            if record.start_command_id is not None and not record.start_committed:
                self._reject_locked(
                    _PoisonReason.OS_ACTION_UNCERTAIN,
                    "supervisor START send outcome 不确定。",
                )
            if record.success_cleanup_event_id is not None:
                # Natural EOF cleanup won the single-owner ordering race.
                # A later CANCEL is acknowledged as a no-op snapshot; it may
                # neither introduce terminate authority nor poison the winner.
                return self._snapshot(record)
            record.cancel_command_id = checked_command
            record.cancel_payload_digest = checked_payload
            if record.state in (
                _BrokerOperationState.RESERVED,
                _BrokerOperationState.ATTACHED,
            ):
                record.state = _BrokerOperationState.TERMINAL_ATTESTED
                record.terminal_attestation_id = checked_command
                record.terminal_kind = _TerminalKind.ZERO_CHILD_CANCEL
                record.cleanup_phase = _BrokerCleanupPhase.COMPLETE
            elif record.state is _BrokerOperationState.SPAWN_INFLIGHT:
                record.state = _BrokerOperationState.CANCEL_WAIT_SPAWN
            elif record.state in (
                _BrokerOperationState.CHILD_OWNED,
                _BrokerOperationState.READY,
                _BrokerOperationState.STARTED,
                _BrokerOperationState.RESULT_PENDING_TERMINAL,
            ):
                record.cleanup_phase = _BrokerCleanupPhase.TERMINATE_REQUIRED
            else:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor CANCEL 顺序无效。",
                )
            record.revision += 1
            return self._snapshot(record)

    def complete_spawn(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
        child_created: bool,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerEventPort)
        self._preflight_mutation(binding)
        checked_event = require_uuid(event_id, "event_id")
        if type(child_created) is not bool:
            raise TypeError("child_created must be bool")
        with self._lock:
            record = self._record_locked(binding)
            self._require_external_action_slot_locked()
            if record.spawn_event_id is not None:
                if (
                    record.spawn_event_id == checked_event
                    and record.spawn_created is child_created
                ):
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor SPAWN_DONE event 已变化。",
                )
            if record.state is _BrokerOperationState.POISONED:
                if (
                    record.arm_command_id is None
                    or record.terminal_attestation_id is not None
                ):
                    _raise_supervisor_error(
                        "supervisor poisoned operation 不接受 SPAWN_DONE。"
                    )
                record.spawn_event_id = checked_event
                record.spawn_created = child_created
                if child_created:
                    record.child_ever_owned = True
                    if record.cleanup_phase is _BrokerCleanupPhase.NONE:
                        record.cleanup_phase = (
                            _BrokerCleanupPhase.TERMINATE_REQUIRED
                        )
                else:
                    record.cleanup_phase = _BrokerCleanupPhase.COMPLETE
                record.revision += 1
                return self._snapshot(record)
            if self._poisoned:
                _raise_supervisor_error("supervisor epoch 已隔离。")
            if record.state not in (
                _BrokerOperationState.SPAWN_INFLIGHT,
                _BrokerOperationState.CANCEL_WAIT_SPAWN,
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor SPAWN_DONE 顺序无效。",
                )
            record.spawn_event_id = checked_event
            record.spawn_created = child_created
            if child_created:
                record.child_ever_owned = True
                record.state = _BrokerOperationState.CHILD_OWNED
                if record.cancel_command_id is not None:
                    record.cleanup_phase = _BrokerCleanupPhase.TERMINATE_REQUIRED
            else:
                record.state = _BrokerOperationState.TERMINAL_ATTESTED
                record.terminal_attestation_id = checked_event
                record.terminal_kind = _TerminalKind.SPAWN_FAILED
                record.terminal_status = _SPAWN_FAILED_STATUS
                record.cleanup_phase = _BrokerCleanupPhase.COMPLETE
            record.revision += 1
            return self._snapshot(record)

    def mark_ready(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerEventPort)
        self._preflight_mutation(binding)
        checked_event = require_uuid(event_id, "event_id")
        with self._lock:
            record = self._mutable_record_locked(binding)
            if record.ready_event_id is not None:
                if record.ready_event_id == checked_event:
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor READY event 已变化。",
                )
            if record.cancel_command_id is not None or record.state in (
                _BrokerOperationState.TERMINAL_ATTESTED,
                _BrokerOperationState.RELEASED,
            ):
                return self._snapshot(record)
            if (
                record.state is not _BrokerOperationState.CHILD_OWNED
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor READY 顺序无效。",
                )
            record.ready_event_id = checked_event
            record.state = _BrokerOperationState.READY
            record.revision += 1
            return self._snapshot(record)

    def claim_start(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
        payload_digest: Digest256,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerEventPort)
        self._preflight_mutation(
            binding,
            action_kind="start",
            action_id=command_id,
            action_digest=payload_digest,
            require_action_digest=True,
        )
        checked_command = require_uuid(command_id, "command_id")
        checked_payload = require_digest(payload_digest, "payload_digest")
        with self._lock:
            record = self._mutable_record_locked(
                binding,
                pending_start_command_id=checked_command,
            )
            if record.start_command_id is not None:
                if (
                    record.start_command_id == checked_command
                    and record.start_payload_digest == checked_payload
                ):
                    return self._snapshot(record)
                if not record.start_committed:
                    self._reject_locked(
                        _PoisonReason.OS_ACTION_UNCERTAIN,
                        "supervisor START send outcome 不确定。",
                    )
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor START claim 已变化。",
                )
            if record.cancel_command_id is not None or record.state in (
                _BrokerOperationState.TERMINAL_ATTESTED,
                _BrokerOperationState.RELEASED,
            ):
                return self._snapshot(record)
            if (
                record.state is not _BrokerOperationState.READY
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor START claim 顺序无效。",
                )
            record.start_command_id = checked_command
            record.start_payload_digest = checked_payload
            record.revision += 1
            return self._snapshot(record)

    def commit_start(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerEventPort)
        self._preflight_mutation(
            binding,
            action_kind="start",
            action_id=command_id,
        )
        checked_command = require_uuid(command_id, "command_id")
        with self._lock:
            record = self._mutable_record_locked(
                binding,
                pending_start_command_id=checked_command,
            )
            if record.start_committed:
                if record.start_command_id == checked_command:
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor START commit 已变化。",
                )
            if (
                record.start_command_id is not None
                and record.start_command_id != checked_command
            ):
                self._reject_locked(
                    _PoisonReason.OS_ACTION_UNCERTAIN,
                    "supervisor START send outcome 不确定。",
                )
            if record.cancel_command_id is not None or record.state in (
                _BrokerOperationState.TERMINAL_ATTESTED,
                _BrokerOperationState.RELEASED,
            ):
                return self._snapshot(record)
            if (
                record.state is not _BrokerOperationState.READY
                or record.start_command_id != checked_command
                or record.start_payload_digest is None
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor START commit 顺序无效。",
                )
            record.start_committed = True
            record.state = _BrokerOperationState.STARTED
            record.revision += 1
            return self._snapshot(record)

    def mark_result(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
        result_digest: Digest256,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerEventPort)
        self._preflight_mutation(binding)
        checked_event = require_uuid(event_id, "event_id")
        checked_digest = require_digest(result_digest, "result_digest")
        with self._lock:
            record = self._mutable_record_locked(binding)
            if record.result_event_id is not None:
                if (
                    record.result_event_id == checked_event
                    and record.result_digest == checked_digest
                ):
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor RESULT event 已变化。",
                )
            if record.start_command_id is not None and not record.start_committed:
                self._reject_locked(
                    _PoisonReason.OS_ACTION_UNCERTAIN,
                    "supervisor START send outcome 不确定。",
                )
            if record.cancel_command_id is not None or record.state in (
                _BrokerOperationState.TERMINAL_ATTESTED,
                _BrokerOperationState.RELEASED,
            ):
                return self._snapshot(record)
            if (
                record.state is not _BrokerOperationState.STARTED
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor RESULT 顺序无效。",
                )
            record.result_event_id = checked_event
            record.result_digest = checked_digest
            record.state = _BrokerOperationState.RESULT_PENDING_TERMINAL
            record.revision += 1
            return self._snapshot(record)

    def mark_success_cleanup_ready(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
        durable_eof_ack_digest: Digest256,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        """Commit the exact durable EOF ACK before any success-path reap."""

        self._require_role(_authority, _SupervisorBrokerEventPort)
        self._preflight_mutation(binding)
        checked_event = require_uuid(event_id, "event_id")
        checked_digest = require_digest(
            durable_eof_ack_digest,
            "durable_eof_ack_digest",
        )
        with self._lock:
            record = self._mutable_record_locked(binding)
            if record.success_cleanup_event_id is not None:
                if (
                    record.success_cleanup_event_id == checked_event
                    and record.durable_eof_ack_digest == checked_digest
                ):
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor success cleanup event 已变化。",
                )
            if record.cancel_command_id is not None:
                # CANCEL won the event-owner race.  The durable EOF ACK remains
                # valid delivery bookkeeping, but it cannot authorize the
                # natural-exit cleanup path and must not poison cancellation.
                return self._snapshot(record)
            if (
                record.state is not _BrokerOperationState.RESULT_PENDING_TERMINAL
                or record.result_event_id is None
                or record.result_digest is None
                or not record.start_committed
                or not record.child_ever_owned
                or record.cleanup_phase is not _BrokerCleanupPhase.NONE
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor success cleanup 缺少 exact RESULT/EOF ACK。",
                )
            record.success_cleanup_event_id = checked_event
            record.durable_eof_ack_digest = checked_digest
            record.cleanup_phase = _BrokerCleanupPhase.REAP_REQUIRED
            record.revision += 1
            return self._snapshot(record)

    def claim_terminate(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        return self._claim_cleanup_action(
            binding,
            action_id=action_id,
            expected=_BrokerCleanupPhase.TERMINATE_REQUIRED,
            claimed=_BrokerCleanupPhase.TERMINATE_CLAIMED,
            attribute="terminate_action_id",
        )

    def complete_terminate(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        return self._complete_cleanup_action(
            binding,
            action_id=action_id,
            claimed=_BrokerCleanupPhase.TERMINATE_CLAIMED,
            completed=_BrokerCleanupPhase.REAP_REQUIRED,
            attribute="terminate_action_id",
        )

    def claim_reap(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        return self._claim_cleanup_action(
            binding,
            action_id=action_id,
            expected=_BrokerCleanupPhase.REAP_REQUIRED,
            claimed=_BrokerCleanupPhase.REAP_CLAIMED,
            attribute="reap_action_id",
        )

    def complete_reap(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        return self._complete_cleanup_action(
            binding,
            action_id=action_id,
            claimed=_BrokerCleanupPhase.REAP_CLAIMED,
            completed=_BrokerCleanupPhase.CLOSE_REQUIRED,
            attribute="reap_action_id",
        )

    def claim_close(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        return self._claim_cleanup_action(
            binding,
            action_id=action_id,
            expected=_BrokerCleanupPhase.CLOSE_REQUIRED,
            claimed=_BrokerCleanupPhase.CLOSE_CLAIMED,
            attribute="close_action_id",
        )

    def complete_close(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        return self._complete_cleanup_action(
            binding,
            action_id=action_id,
            claimed=_BrokerCleanupPhase.CLOSE_CLAIMED,
            completed=_BrokerCleanupPhase.COMPLETE,
            attribute="close_action_id",
        )

    def _claim_cleanup_action(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        expected: _BrokerCleanupPhase,
        claimed: _BrokerCleanupPhase,
        attribute: str,
    ) -> _SupervisorOperationAttestation:
        self._preflight_mutation(
            binding,
            action_kind=claimed.value,
            action_id=action_id,
        )
        checked_action = require_uuid(action_id, "action_id")
        with self._lock:
            record = self._cleanup_record_locked(
                binding,
                action_kind=claimed,
                action_id=checked_action,
            )
            existing = getattr(record, attribute)
            if existing is not None:
                if existing == checked_action:
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor cleanup action 已变化。",
                )
            if record.cleanup_phase is not expected:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor cleanup 顺序无效。",
                )
            setattr(record, attribute, checked_action)
            record.cleanup_phase = claimed
            record.revision += 1
            return self._snapshot(record)

    def _complete_cleanup_action(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
        claimed: _BrokerCleanupPhase,
        completed: _BrokerCleanupPhase,
        attribute: str,
    ) -> _SupervisorOperationAttestation:
        self._preflight_mutation(
            binding,
            action_kind=claimed.value,
            action_id=action_id,
        )
        checked_action = require_uuid(action_id, "action_id")
        with self._lock:
            record = self._cleanup_record_locked(
                binding,
                action_kind=claimed,
                action_id=checked_action,
            )
            existing = getattr(record, attribute)
            if existing != checked_action:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor cleanup completion 未绑定 exact claim。",
                )
            if _CLEANUP_PHASE_RANK[record.cleanup_phase] > _CLEANUP_PHASE_RANK[
                claimed
            ]:
                return self._snapshot(record)
            if record.cleanup_phase is not claimed:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor cleanup completion 顺序无效。",
                )
            record.cleanup_phase = completed
            record.revision += 1
            return self._snapshot(record)

    def attest_terminal(
        self,
        binding: _SupervisorOperationBinding,
        *,
        attestation_id: UUID,
        status: int,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        self._preflight_mutation(binding)
        checked_attestation = require_uuid(attestation_id, "attestation_id")
        checked_status = require_plain_int(status, "status", minimum=0)
        with self._lock:
            record = self._mutable_record_locked(binding)
            if record.terminal_attestation_id is not None:
                if (
                    record.terminal_attestation_id == checked_attestation
                    and record.terminal_kind is _TerminalKind.CHILD_EXITED
                    and record.terminal_status == checked_status
                ):
                    return self._snapshot(record)
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor terminal attestation 已变化。",
                )
            if record.start_command_id is not None and not record.start_committed:
                self._reject_locked(
                    _PoisonReason.OS_ACTION_UNCERTAIN,
                    "supervisor START send outcome 不确定。",
                )
            if not record.child_ever_owned or record.state not in (
                _BrokerOperationState.CHILD_OWNED,
                _BrokerOperationState.READY,
                _BrokerOperationState.STARTED,
                _BrokerOperationState.RESULT_PENDING_TERMINAL,
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor terminal attestation 顺序无效。",
                )
            if (
                record.cancel_command_id is not None
                and record.cleanup_phase is not _BrokerCleanupPhase.COMPLETE
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor cleanup 尚未证明 terminal。",
                )
            if (
                record.state is _BrokerOperationState.RESULT_PENDING_TERMINAL
                and record.cancel_command_id is None
                and (
                    record.success_cleanup_event_id is None
                    or record.durable_eof_ack_digest is None
                    or record.cleanup_phase is not _BrokerCleanupPhase.COMPLETE
                )
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor success cleanup 尚未证明 terminal。",
                )
            record.terminal_attestation_id = checked_attestation
            record.terminal_kind = _TerminalKind.CHILD_EXITED
            record.terminal_status = checked_status
            record.state = _BrokerOperationState.TERMINAL_ATTESTED
            if record.cleanup_phase is _BrokerCleanupPhase.NONE:
                record.cleanup_phase = _BrokerCleanupPhase.COMPLETE
            record.revision += 1
            return self._snapshot(record)

    def release(
        self,
        binding: _SupervisorOperationBinding,
        *,
        tombstone_id: UUID,
        _authority: object | None = None,
    ) -> _SupervisorOperationAttestation:
        self._require_role(_authority, _SupervisorBrokerControlPort)
        self._preflight_mutation(binding)
        checked_tombstone = require_uuid(tombstone_id, "tombstone_id")
        with self._lock:
            current = self._query_snapshot_locked(binding)
            if current.release_tombstone_id is not None:
                if current.release_tombstone_id == checked_tombstone:
                    return current
                record = self._operations.get(binding.operation_id)
                if record is None:
                    self._reject_locked(
                        _PoisonReason.EVENT_EQUIVOCATION,
                        "supervisor compacted release tombstone 已变化。",
                    )
                self._reject_operation_locked(
                    record,
                    _PoisonReason.EVENT_EQUIVOCATION,
                    "supervisor release tombstone 已变化。",
                )
            record = self._mutable_record_locked(binding)
            if record.state is not _BrokerOperationState.TERMINAL_ATTESTED:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor release 缺少 terminal attestation。",
                )
            record.release_tombstone_id = checked_tombstone
            record.state = _BrokerOperationState.RELEASED
            record.revision += 1
            return self._snapshot(record)

    def _require_parent_released_for_compaction(
        self,
        binding: _SupervisorOperationBinding,
        expected_release_tombstone_id: UUID,
    ) -> None:
        parent_session = self._parent_session
        if type(parent_session) is not _SupervisorParentSessionLedger:
            with self._lock:
                self._reject_locked(
                    _PoisonReason.SNAPSHOT_EQUIVOCATION,
                    "supervisor parent session 无效。",
                )
        invalid_reason = None
        release_pending = False
        # Snapshot under the parent lock, then validate the exact proxy after
        # releasing it.  Parent entries are install-once/remove-once, so this
        # forbids the parent->proxy half of an X(proxy)->P(parent) compaction
        # deadlock without weakening identity validation.
        with parent_session._lock:
            existing = parent_session._operations.get(binding.operation_id)
        if existing is None:
            return
        if type(existing) is not tuple or len(existing) != 2:
            invalid_reason = (
                _PoisonReason.SNAPSHOT_EQUIVOCATION,
                "supervisor parent operation 无效。",
            )
        else:
            proxy, publication = existing
            if (
                type(proxy) is not _SupervisorParentProxy
                or type(publication) is not _SupervisorPublicationLedger
                or publication._prepared_proxy is not proxy
                or not _same_binding(proxy.binding, binding)
                or not _same_binding(publication.binding, binding)
            ):
                invalid_reason = (
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor parent operation identity 已变化。",
                )
            else:
                with proxy._lock:
                    release_pending = (
                        proxy._state is not _ParentProxyState.RELEASED
                        or proxy._cleanup_state
                        is not _SupervisorCleanupState.TERMINAL
                        or proxy._release_tombstone_id
                        != expected_release_tombstone_id
                    )
        if invalid_reason is not None:
            reason, message = invalid_reason
            with self._lock:
                self._reject_locked(reason, message)
        if release_pending:
            _raise_supervisor_error(
                "supervisor parent RELEASE 尚未 exact attested。"
            )

    def _drop_released_operation_refs_locked(
        self,
        tombstone: _SupervisorReleasedOperationTombstone,
    ) -> None:
        tombstone.validate_integrity()
        operation_id = tombstone.operation_id
        record = self._operations.get(operation_id)
        if record is not None:
            if (
                not tombstone.matches(
                    record.binding,
                    tombstone.release_tombstone_id,
                    tombstone.release_attestation_digest,
                )
                or record.state is not _BrokerOperationState.RELEASED
                or record.release_tombstone_id != tombstone.release_tombstone_id
                or self._snapshot(record).attestation_digest
                != tombstone.release_attestation_digest
            ):
                self._reject_locked(
                    _PoisonReason.SNAPSHOT_EQUIVOCATION,
                    "supervisor released operation 已变化。",
                )

        for key in tuple(self._query_replies):
            if key[0] == operation_id:
                self._query_replies.pop(key, None)
        parent_session = self._parent_session
        with parent_session._lock:
            parent_session._operations.pop(operation_id, None)
        self._operations.pop(operation_id, None)

    def compact_released(
        self,
        binding: _SupervisorOperationBinding,
        expected_release_tombstone_id: UUID,
        expected_attestation_digest: Digest256,
        *,
        _authority: object | None = None,
    ) -> _SupervisorReleasedOperationTombstone:
        """Publish a replay tombstone, then drop every contract-owned ref."""

        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        if type(binding) is not _SupervisorOperationBinding:
            raise TypeError("binding must be SupervisorOperationBinding")
        try:
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            _raise_supervisor_error("supervisor operation binding 无效。")
        checked_tombstone = require_uuid(
            expected_release_tombstone_id,
            "expected_release_tombstone_id",
        )
        checked_attestation = require_digest(
            expected_attestation_digest,
            "expected_attestation_digest",
        )
        self._require_parent_released_for_compaction(
            binding,
            checked_tombstone,
        )
        with self._lock:
            if binding.epoch_id != self.epoch_id:
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor epoch 已变化。",
                )
            retained = self._released_tombstone_locked(binding)
            if retained is not None:
                if not retained.matches(
                    binding,
                    checked_tombstone,
                    checked_attestation,
                ):
                    self._reject_locked(
                        _PoisonReason.SNAPSHOT_EQUIVOCATION,
                        "supervisor released tombstone 已变化。",
                    )
                self._drop_released_operation_refs_locked(retained)
                return retained

            record = self._operations.get(binding.operation_id)
            if record is None or not _same_binding(record.binding, binding):
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor operation identity 已变化。",
                )
            if (
                record.state is not _BrokerOperationState.RELEASED
                or record.release_tombstone_id != checked_tombstone
            ):
                self._reject_operation_locked(
                    record,
                    _PoisonReason.INVALID_TRANSITION,
                    "supervisor operation 尚未 exact release。",
                )
            released = self._snapshot(record)
            if released.attestation_digest != checked_attestation:
                self._reject_operation_locked(
                    record,
                    _PoisonReason.SNAPSHOT_EQUIVOCATION,
                    "supervisor RELEASE attestation 已变化。",
                )
            if (
                len(self._released_tombstones)
                >= SUPERVISOR_RELEASED_TOMBSTONE_LIMIT
            ):
                _raise_supervisor_error(
                    "supervisor released tombstone ledger 已满。"
                )
            candidate = _SupervisorReleasedOperationTombstone(
                binding=binding,
                release_tombstone_id=checked_tombstone,
                release_attestation_digest=checked_attestation,
                released_attestation=released,
                _authority=_RELEASED_TOMBSTONE_AUTHORITY,
            )
            retained = self._released_tombstones.setdefault(
                binding.operation_id,
                candidate,
            )
            if (
                type(retained) is not _SupervisorReleasedOperationTombstone
                or not retained.matches(
                    binding,
                    checked_tombstone,
                    checked_attestation,
                )
            ):
                self._reject_locked(
                    _PoisonReason.SNAPSHOT_EQUIVOCATION,
                    "supervisor released tombstone 冲突。",
                )
            self._drop_released_operation_refs_locked(retained)
            return retained

    def released_tombstone(
        self,
        binding: _SupervisorOperationBinding,
        *,
        _authority: object | None = None,
    ) -> _SupervisorReleasedOperationTombstone | None:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        if type(binding) is not _SupervisorOperationBinding:
            raise TypeError("binding must be SupervisorOperationBinding")
        try:
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            _raise_supervisor_error("supervisor operation binding 无效。")
        with self._lock:
            if binding.epoch_id != self.epoch_id:
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor epoch 已变化。",
                )
            tombstone = self._released_tombstone_locked(binding)
            if tombstone is not None:
                return tombstone
            record = self._operations.get(binding.operation_id)
            if record is not None and not _same_binding(record.binding, binding):
                self._reject_locked(
                    _PoisonReason.BINDING_MISMATCH,
                    "supervisor operation identity 已变化。",
                )
            return None

    def poison_epoch(
        self,
        *,
        reason: _PoisonReason,
        _authority: object | None = None,
    ) -> None:
        self._require_role(_authority, _SupervisorBrokerCleanupPort)
        if type(reason) is not _PoisonReason or reason not in (
            _PoisonReason.EPOCH_LOST,
            _PoisonReason.LIVENESS_LOST,
            _PoisonReason.OS_ACTION_UNCERTAIN,
        ):
            raise ValueError("reason must be an epoch poison reason")
        with self._lock:
            self._poison_all_locked(reason)

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            for operation_id, tombstone in self._released_tombstones.items():
                if (
                    type(operation_id) is not UUID
                    or type(tombstone)
                    is not _SupervisorReleasedOperationTombstone
                    or tombstone.operation_id != operation_id
                ):
                    self._reject_locked(
                        _PoisonReason.SNAPSHOT_EQUIVOCATION,
                        "supervisor released tombstone ledger 无效。",
                    )
                try:
                    tombstone.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    self._reject_locked(
                        _PoisonReason.SNAPSHOT_EQUIVOCATION,
                        "supervisor released tombstone ledger 无效。",
                    )
            return {
                "active_operation_limit": SUPERVISOR_ACTIVE_OPERATION_LIMIT,
                "epoch_id": str(self.epoch_id),
                "global_poison_reason": (
                    None
                    if self._global_poison_reason is None
                    else self._global_poison_reason.value
                ),
                "operation_count": len(self._operations),
                "poisoned": self._poisoned,
                "query_reply_count": len(self._query_replies),
                "query_reply_limit_per_operation": (
                    SUPERVISOR_QUERY_REPLY_LIMIT_PER_OPERATION
                ),
                "released_count": sum(
                    record.state is _BrokerOperationState.RELEASED
                    for record in self._operations.values()
                ),
                "released_tombstone_count": len(self._released_tombstones),
                "released_tombstone_limit": (
                    SUPERVISOR_RELEASED_TOMBSTONE_LIMIT
                ),
            }


class _SupervisorBrokerPort:
    __slots__ = ("_ledger",)

    def __init__(
        self,
        *,
        ledger: _SupervisorBrokerLedger,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BROKER_PORT_AUTHORITY:
            raise TypeError("supervisor broker port requires its ledger")
        object.__setattr__(self, "_ledger", ledger)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorBrokerPort identity is immutable")


@runtime_final
class _SupervisorBrokerControlPort(_SupervisorBrokerPort):
    def reserve(
        self,
        binding: _SupervisorOperationBinding,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.reserve(binding, _authority=self)

    def query(
        self,
        binding: _SupervisorOperationBinding,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.query(binding, _authority=self)

    def query_reply(
        self,
        binding: _SupervisorOperationBinding,
        *,
        query_id: UUID,
    ) -> _SupervisorQueryReply:
        return self._ledger.query_reply(
            binding,
            query_id=query_id,
            _authority=self,
        )

    def attach(
        self,
        binding: _SupervisorOperationBinding,
        *,
        proof: _SupervisorPublicationProof,
        command_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.attach(
            binding,
            proof=proof,
            command_id=command_id,
            _authority=self,
        )

    def arm(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.arm(
            binding,
            command_id=command_id,
            _authority=self,
        )

    def cancel(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
        payload_digest: Digest256,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.cancel(
            binding,
            command_id=command_id,
            payload_digest=payload_digest,
            _authority=self,
        )

    def release(
        self,
        binding: _SupervisorOperationBinding,
        *,
        tombstone_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.release(
            binding,
            tombstone_id=tombstone_id,
            _authority=self,
        )


@runtime_final
class _SupervisorBrokerEventPort(_SupervisorBrokerPort):
    def complete_spawn(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
        child_created: bool,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.complete_spawn(
            binding,
            event_id=event_id,
            child_created=child_created,
            _authority=self,
        )

    def mark_ready(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.mark_ready(
            binding,
            event_id=event_id,
            _authority=self,
        )

    def claim_start(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
        payload_digest: Digest256,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.claim_start(
            binding,
            command_id=command_id,
            payload_digest=payload_digest,
            _authority=self,
        )

    def commit_start(
        self,
        binding: _SupervisorOperationBinding,
        *,
        command_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.commit_start(
            binding,
            command_id=command_id,
            _authority=self,
        )

    def mark_result(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
        result_digest: Digest256,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.mark_result(
            binding,
            event_id=event_id,
            result_digest=result_digest,
            _authority=self,
        )

    def mark_success_cleanup_ready(
        self,
        binding: _SupervisorOperationBinding,
        *,
        event_id: UUID,
        durable_eof_ack_digest: Digest256,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.mark_success_cleanup_ready(
            binding,
            event_id=event_id,
            durable_eof_ack_digest=durable_eof_ack_digest,
            _authority=self,
        )


@runtime_final
class _SupervisorBrokerCleanupPort(_SupervisorBrokerPort):
    def compact_released(
        self,
        binding: _SupervisorOperationBinding,
        expected_release_tombstone_id: UUID,
        expected_attestation_digest: Digest256,
    ) -> _SupervisorReleasedOperationTombstone:
        return self._ledger.compact_released(
            binding,
            expected_release_tombstone_id,
            expected_attestation_digest,
            _authority=self,
        )

    def released_tombstone(
        self,
        binding: _SupervisorOperationBinding,
    ) -> _SupervisorReleasedOperationTombstone | None:
        return self._ledger.released_tombstone(
            binding,
            _authority=self,
        )

    def claim_terminate(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.claim_terminate(
            binding,
            action_id=action_id,
            _authority=self,
        )

    def complete_terminate(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.complete_terminate(
            binding,
            action_id=action_id,
            _authority=self,
        )

    def claim_reap(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.claim_reap(
            binding,
            action_id=action_id,
            _authority=self,
        )

    def complete_reap(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.complete_reap(
            binding,
            action_id=action_id,
            _authority=self,
        )

    def claim_close(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.claim_close(
            binding,
            action_id=action_id,
            _authority=self,
        )

    def complete_close(
        self,
        binding: _SupervisorOperationBinding,
        *,
        action_id: UUID,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.complete_close(
            binding,
            action_id=action_id,
            _authority=self,
        )

    def attest_terminal(
        self,
        binding: _SupervisorOperationBinding,
        *,
        attestation_id: UUID,
        status: int,
    ) -> _SupervisorOperationAttestation:
        return self._ledger.attest_terminal(
            binding,
            attestation_id=attestation_id,
            status=status,
            _authority=self,
        )

    def poison_epoch(self, *, reason: _PoisonReason) -> None:
        self._ledger.poison_epoch(reason=reason, _authority=self)


@runtime_final
class _SupervisorBrokerPorts:
    __slots__ = (
        "ledger",
        "control",
        "events",
        "cleanup",
        "parent_session",
    )

    def __init__(
        self,
        *,
        ledger: _SupervisorBrokerLedger,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BROKER_LEDGER_AUTHORITY:
            raise TypeError("supervisor broker ports require their factory")
        object.__setattr__(self, "ledger", ledger)
        object.__setattr__(self, "control", ledger._control_port)
        object.__setattr__(self, "events", ledger._event_port)
        object.__setattr__(self, "cleanup", ledger._cleanup_port)
        parent_session = ledger._parent_session
        if type(parent_session) is not _SupervisorParentSessionLedger:
            raise ValueError("supervisor broker lacks its parent session")
        object.__setattr__(self, "parent_session", parent_session)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorBrokerPorts identity is immutable")


def _new_supervisor_broker(*, epoch_id: UUID) -> _SupervisorBrokerPorts:
    ledger = _SupervisorBrokerLedger(
        epoch_id=epoch_id,
        _authority=_BROKER_LEDGER_AUTHORITY,
    )
    parent_session = _SupervisorParentSessionLedger(
        epoch_id=ledger.epoch_id,
        broker_ledger=ledger,
        _authority=_BROKER_LEDGER_AUTHORITY,
    )
    object.__setattr__(ledger, "_parent_session", parent_session)
    return _SupervisorBrokerPorts(
        ledger=ledger,
        _authority=_BROKER_LEDGER_AUTHORITY,
    )


_MONOTONIC_ATTESTATION_FIELDS = (
    "attachment_command_id",
    "attachment_proof_digest",
    "arm_command_id",
    "cancel_command_id",
    "cancel_payload_digest",
    "spawn_event_id",
    "spawn_created",
    "ready_event_id",
    "start_command_id",
    "start_payload_digest",
    "result_event_id",
    "result_digest",
    "success_cleanup_event_id",
    "durable_eof_ack_digest",
    "terminate_action_id",
    "reap_action_id",
    "close_action_id",
    "terminal_attestation_id",
    "terminal_kind",
    "terminal_status",
    "release_tombstone_id",
)


@runtime_final
class _SupervisorParentProxy:
    """Pure parent observation ledger; it never contains a PID or OS action."""

    __slots__ = (
        "binding",
        "proxy_id",
        "reservation_attestation_digest",
        "_broker_ledger",
        "_lock",
        "_state",
        "_cleanup_state",
        "_cleanup_pending_count",
        "_cleanup_query_proofs",
        "_business_open",
        "_attachment_proof",
        "_attachment_proof_digest",
        "_attachment_command_id",
        "_arm_command_id",
        "_cancel_command_id",
        "_cancel_payload_digest",
        "_release_tombstone_id",
        "_observed",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        reservation: _SupervisorOperationAttestation,
        proxy_id: UUID,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PARENT_SESSION_AUTHORITY:
            raise TypeError("supervisor parent proxy requires its session")
        if type(reservation) is not _SupervisorOperationAttestation:
            raise TypeError("reservation must be SupervisorOperationAttestation")
        reservation.validate_integrity()
        if (
            reservation.state is not _BrokerOperationState.RESERVED
            or reservation.revision != 0
            or reservation.child_ever_owned
        ):
            raise ValueError("parent proxy requires an exact RESERVED attestation")
        object.__setattr__(self, "binding", reservation.binding)
        object.__setattr__(self, "proxy_id", require_uuid(proxy_id, "proxy_id"))
        object.__setattr__(
            self,
            "reservation_attestation_digest",
            reservation.attestation_digest,
        )
        object.__setattr__(self, "_broker_ledger", reservation._broker_ledger)
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_state", _ParentProxyState.ATTACH_UNKNOWN)
        object.__setattr__(self, "_cleanup_state", _SupervisorCleanupState.IDLE)
        object.__setattr__(self, "_cleanup_pending_count", 0)
        object.__setattr__(self, "_cleanup_query_proofs", ())
        object.__setattr__(self, "_business_open", False)
        object.__setattr__(self, "_attachment_proof", None)
        object.__setattr__(self, "_attachment_proof_digest", None)
        object.__setattr__(self, "_attachment_command_id", None)
        object.__setattr__(self, "_arm_command_id", None)
        object.__setattr__(self, "_cancel_command_id", None)
        object.__setattr__(self, "_cancel_payload_digest", None)
        object.__setattr__(self, "_release_tombstone_id", None)
        object.__setattr__(self, "_observed", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorParentProxy identity is immutable")

    def _poison_locked(self, message: str) -> NoReturn:
        object.__setattr__(self, "_state", _ParentProxyState.POISONED)
        object.__setattr__(self, "_business_open", False)
        _raise_supervisor_error(message)

    def _observe_liveness_lost(self, *, _authority: object) -> None:
        if _authority is not _PARENT_SESSION_AUTHORITY:
            raise TypeError("liveness observation requires parent session")
        with self._lock:
            if self._state is not _ParentProxyState.RELEASED:
                object.__setattr__(self, "_state", _ParentProxyState.POISONED)
                object.__setattr__(self, "_business_open", False)

    def _accept_locked(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> bool:
        if type(attestation) is not _SupervisorOperationAttestation:
            self._poison_locked("supervisor attestation 类型无效。")
        try:
            attestation.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            self._poison_locked("supervisor attestation proof 无效。")
        if not _same_binding(self.binding, attestation.binding):
            self._poison_locked("supervisor attestation binding 已变化。")
        if attestation._broker_ledger is not self._broker_ledger:
            self._poison_locked("supervisor broker owner 已变化。")
        if (
            attestation._attachment_proof is not None
            and attestation._attachment_proof is not self._attachment_proof
        ):
            self._poison_locked("supervisor ATTACH capability 已变化。")
        previous = self._observed
        if previous is not None:
            if attestation.revision < previous.revision:
                return False
            if attestation.revision == previous.revision:
                if attestation.attestation_digest == previous.attestation_digest:
                    if attestation.state is _BrokerOperationState.POISONED:
                        self._poison_locked(
                            "supervisor authoritative operation 已隔离。"
                        )
                    return True
                self._poison_locked("supervisor 同 revision attestation 冲突。")
            if attestation.state not in _BROKER_STATE_REACHABLE[previous.state]:
                self._poison_locked("supervisor authoritative state 回退。")
            if (
                _CLEANUP_PHASE_RANK[attestation.cleanup_phase]
                < _CLEANUP_PHASE_RANK[previous.cleanup_phase]
            ):
                self._poison_locked("supervisor cleanup phase 回退。")
            for name in _MONOTONIC_ATTESTATION_FIELDS:
                before = getattr(previous, name)
                after = getattr(attestation, name)
                if before is not None and after != before:
                    self._poison_locked("supervisor attestation facts 回退。")
            if previous.child_ever_owned and not attestation.child_ever_owned:
                self._poison_locked("supervisor child ownership 回退。")
            if previous.cancel_latched and not attestation.cancel_latched:
                self._poison_locked("supervisor cancel latch 回退。")
            if previous.start_committed and not attestation.start_committed:
                self._poison_locked("supervisor START fact 回退。")
        object.__setattr__(self, "_observed", attestation)
        if attestation.state is _BrokerOperationState.POISONED:
            self._poison_locked("supervisor authoritative operation 已隔离。")
        return True

    def begin_attach(
        self,
        *,
        proof: _SupervisorPublicationProof,
        command_id: UUID,
    ) -> None:
        checked_command = require_uuid(command_id, "command_id")
        if type(proof) is not _SupervisorPublicationProof:
            raise TypeError("proof must be SupervisorPublicationProof")
        try:
            proof.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            _raise_supervisor_error("supervisor publication proof 无效。")
        with self._lock:
            if (
                proof._proxy is not self
                or proof._publication_ledger._prepared_proxy is not self
                or proof._publication_ledger._proxy is not self
                or proof._publication_ledger._proof is not proof
                or proof.publication_id != self.binding.publication_id
                or proof.binding_digest != self.binding.binding_digest
                or proof.proxy_id != self.proxy_id
                or proof.reservation_attestation_digest
                != self.reservation_attestation_digest
            ):
                self._poison_locked("supervisor publication proof 已变化。")
            if self._attachment_command_id is not None:
                if (
                    self._attachment_command_id == checked_command
                    and self._attachment_proof_digest == proof.proof_digest
                ):
                    return
                self._poison_locked("supervisor ATTACH command 已变化。")
            if self._state is not _ParentProxyState.ATTACH_UNKNOWN:
                self._poison_locked("supervisor ATTACH observation 顺序无效。")
            object.__setattr__(self, "_attachment_command_id", checked_command)
            object.__setattr__(self, "_attachment_proof", proof)
            object.__setattr__(
                self,
                "_attachment_proof_digest",
                proof.proof_digest,
            )

    def observe_attach_ack(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        with self._lock:
            if self._attachment_command_id is None:
                self._poison_locked("supervisor ATTACH 尚未提交。")
            if not self._accept_locked(attestation):
                return
            if self._accept_cancel_won_command_ack_locked(attestation):
                return
            if (
                attestation.attachment_command_id
                != self._attachment_command_id
                or attestation.attachment_proof_digest
                != self._attachment_proof_digest
                or attestation._attachment_proof is not self._attachment_proof
            ):
                self._poison_locked("supervisor ATTACH ack 无效。")
            self._validate_command_bindings_locked(attestation)
            if self._accept_requested_release_successor_locked(attestation):
                return
            if (
                self._state is _ParentProxyState.RELEASE_NOT_ATTESTED
                and attestation.state
                is _BrokerOperationState.TERMINAL_ATTESTED
            ):
                return
            if attestation.terminal_attestation_id is not None:
                self._set_terminal_locked(attestation)
                return
            if self._state is _ParentProxyState.ATTACH_UNKNOWN:
                if attestation.state is not _BrokerOperationState.ATTACHED:
                    self._poison_locked("supervisor ATTACH ack 顺序无效。")
                object.__setattr__(
                    self,
                    "_state",
                    _ParentProxyState.ATTACHED_UNARMED,
                )
                return
            if self._state in (
                _ParentProxyState.ATTACHED_UNARMED,
                _ParentProxyState.ARM_UNKNOWN,
                _ParentProxyState.ACTIVE,
                _ParentProxyState.CANCEL_NOT_ATTESTED,
                _ParentProxyState.CANCEL_LATCHED_WAIT_TERMINAL,
            ):
                if attestation.cancel_latched:
                    self._apply_cancel_observation_locked(attestation)
                elif (
                    attestation.state
                    is _BrokerOperationState.RESULT_PENDING_TERMINAL
                ):
                    object.__setattr__(self, "_business_open", False)
                return
            self._poison_locked("supervisor ATTACH ack 顺序无效。")

    def begin_arm(self, *, command_id: UUID) -> None:
        checked_command = require_uuid(command_id, "command_id")
        with self._lock:
            if self._state is not _ParentProxyState.ATTACHED_UNARMED:
                self._poison_locked("supervisor ARM observation 顺序无效。")
            if self._arm_command_id is not None:
                self._poison_locked("supervisor ARM 不得重发。")
            object.__setattr__(self, "_arm_command_id", checked_command)
            object.__setattr__(self, "_state", _ParentProxyState.ARM_UNKNOWN)

    def observe_arm_ack(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        with self._lock:
            if not self._accept_locked(attestation):
                return
            if self._arm_command_id is None:
                self._poison_locked("supervisor ARM 尚未提交。")
            if self._accept_cancel_won_command_ack_locked(attestation):
                return
            if attestation.arm_command_id != self._arm_command_id:
                self._poison_locked("supervisor ARM ack 无效。")
            self._validate_command_bindings_locked(attestation)
            if self._accept_requested_release_successor_locked(attestation):
                return
            if (
                self._state is _ParentProxyState.RELEASE_NOT_ATTESTED
                and attestation.state
                is _BrokerOperationState.TERMINAL_ATTESTED
            ):
                return
            if attestation.terminal_attestation_id is not None:
                self._set_terminal_locked(attestation)
                return
            if (
                attestation.state not in (
                    _BrokerOperationState.SPAWN_INFLIGHT,
                    _BrokerOperationState.CHILD_OWNED,
                    _BrokerOperationState.READY,
                    _BrokerOperationState.STARTED,
                    _BrokerOperationState.RESULT_PENDING_TERMINAL,
                )
            ):
                self._poison_locked("supervisor ARM ack 无效。")
            if self._state is _ParentProxyState.ARM_UNKNOWN:
                if attestation.cancel_latched:
                    self._poison_locked("supervisor ARM ack 含未请求 CANCEL。")
                object.__setattr__(self, "_state", _ParentProxyState.ACTIVE)
                object.__setattr__(
                    self,
                    "_business_open",
                    attestation.state
                    is not _BrokerOperationState.RESULT_PENDING_TERMINAL,
                )
                return
            if self._state in (
                _ParentProxyState.ACTIVE,
                _ParentProxyState.CANCEL_NOT_ATTESTED,
                _ParentProxyState.CANCEL_LATCHED_WAIT_TERMINAL,
            ):
                if attestation.cancel_latched:
                    self._apply_cancel_observation_locked(attestation)
                elif self._state is _ParentProxyState.ACTIVE:
                    object.__setattr__(
                        self,
                        "_business_open",
                        attestation.state
                        is not _BrokerOperationState.RESULT_PENDING_TERMINAL,
                    )
                return
            self._poison_locked("supervisor ARM ack 顺序无效。")

    def begin_cancel(
        self,
        *,
        command_id: UUID,
        payload_digest: Digest256,
    ) -> bool:
        checked_command = require_uuid(command_id, "command_id")
        checked_payload = require_digest(payload_digest, "payload_digest")
        with self._lock:
            if (
                self._cancel_command_id is None
                and self._state
                in (
                    _ParentProxyState.TERMINAL_ATTESTED,
                    _ParentProxyState.RELEASE_NOT_ATTESTED,
                    _ParentProxyState.RELEASED,
                )
            ):
                return False
            if self._cancel_command_id is not None:
                if (
                    self._cancel_command_id == checked_command
                    and self._cancel_payload_digest == checked_payload
                ):
                    if self._state is _ParentProxyState.CANCEL_NOT_ATTESTED:
                        return True
                    if self._state in (
                        _ParentProxyState.CANCEL_LATCHED_WAIT_TERMINAL,
                        _ParentProxyState.TERMINAL_ATTESTED,
                        _ParentProxyState.RELEASE_NOT_ATTESTED,
                        _ParentProxyState.RELEASED,
                    ):
                        return False
                self._poison_locked("supervisor CANCEL command 已变化。")
            if self._state not in (
                _ParentProxyState.ATTACH_UNKNOWN,
                _ParentProxyState.ATTACHED_UNARMED,
                _ParentProxyState.ARM_UNKNOWN,
                _ParentProxyState.ACTIVE,
            ):
                self._poison_locked("supervisor CANCEL observation 顺序无效。")
            object.__setattr__(self, "_cancel_command_id", checked_command)
            object.__setattr__(self, "_cancel_payload_digest", checked_payload)
            object.__setattr__(self, "_business_open", False)
            object.__setattr__(
                self,
                "_state",
                _ParentProxyState.CANCEL_NOT_ATTESTED,
            )
            return True

    def observe_cancel_ack(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        with self._lock:
            if not self._accept_locked(attestation):
                return
            if self._cancel_command_id is None:
                self._poison_locked("supervisor CANCEL 尚未提交。")
            self._validate_command_bindings_locked(attestation)
            if self._accept_requested_release_successor_locked(attestation):
                return
            if (
                self._state is _ParentProxyState.RELEASE_NOT_ATTESTED
                and attestation.state
                is _BrokerOperationState.TERMINAL_ATTESTED
            ):
                return
            if self._state not in (
                _ParentProxyState.CANCEL_NOT_ATTESTED,
                _ParentProxyState.CANCEL_LATCHED_WAIT_TERMINAL,
                _ParentProxyState.TERMINAL_ATTESTED,
            ):
                self._poison_locked("supervisor CANCEL ack 顺序无效。")
            if attestation.terminal_attestation_id is not None:
                if attestation.state is not _BrokerOperationState.TERMINAL_ATTESTED:
                    self._poison_locked("supervisor CANCEL ack 含未请求 RELEASE。")
                if attestation.cancel_latched and (
                    attestation.cancel_command_id != self._cancel_command_id
                    or attestation.cancel_payload_digest
                    != self._cancel_payload_digest
                ):
                    self._poison_locked("supervisor CANCEL terminal 已变化。")
                self._set_terminal_locked(attestation)
                return
            self._apply_cancel_observation_locked(attestation)

    def _apply_cancel_observation_locked(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        if (
            attestation.cancel_command_id != self._cancel_command_id
            or attestation.cancel_payload_digest != self._cancel_payload_digest
            or not attestation.cancel_latched
        ):
            self._poison_locked("supervisor CANCEL attestation 无效。")
        if attestation.terminal_attestation_id is not None:
            self._set_terminal_locked(attestation)
            return
        object.__setattr__(
            self,
            "_state",
            _ParentProxyState.CANCEL_LATCHED_WAIT_TERMINAL,
        )

    def _validate_command_bindings_locked(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        if attestation.attachment_command_id is not None and (
            self._attachment_command_id is None
            or attestation.attachment_command_id != self._attachment_command_id
            or attestation.attachment_proof_digest
            != self._attachment_proof_digest
            or attestation._attachment_proof is not self._attachment_proof
        ):
            self._poison_locked("supervisor ATTACH binding 已变化。")
        if (
            attestation.arm_command_id is not None
            and attestation.arm_command_id != self._arm_command_id
        ):
            self._poison_locked("supervisor ARM binding 已变化。")
        if attestation.cancel_latched and (
            self._cancel_command_id is None
            or attestation.cancel_command_id != self._cancel_command_id
            or attestation.cancel_payload_digest != self._cancel_payload_digest
        ):
            self._poison_locked("supervisor CANCEL binding 已变化。")

    def _accept_cancel_won_command_ack_locked(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> bool:
        if (
            not attestation.cancel_latched
            or attestation.state
            not in (
                _BrokerOperationState.TERMINAL_ATTESTED,
                _BrokerOperationState.RELEASED,
            )
        ):
            return False
        if (
            self._cancel_command_id is None
            or attestation.cancel_command_id != self._cancel_command_id
            or attestation.cancel_payload_digest != self._cancel_payload_digest
        ):
            self._poison_locked("supervisor command ACK 含未请求 CANCEL。")
        self._validate_command_bindings_locked(attestation)
        if (
            self._state is _ParentProxyState.RELEASE_NOT_ATTESTED
            and attestation.state is _BrokerOperationState.TERMINAL_ATTESTED
        ):
            return True
        if self._accept_requested_release_successor_locked(attestation):
            return True
        self._set_terminal_locked(attestation)
        return True

    def _accept_requested_release_successor_locked(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> bool:
        if attestation.state is not _BrokerOperationState.RELEASED:
            return False
        if (
            self._state
            in (
                _ParentProxyState.RELEASE_NOT_ATTESTED,
                _ParentProxyState.RELEASED,
            )
            and self._release_tombstone_id is not None
            and attestation.release_tombstone_id
            == self._release_tombstone_id
        ):
            self._set_released_locked()
            return True
        self._poison_locked("supervisor ack 含未请求 RELEASE。")

    def observe_status(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        with self._lock:
            if not self._accept_locked(attestation):
                return
            state = self._state
            if state is _ParentProxyState.RELEASE_NOT_ATTESTED:
                if (
                    attestation.state is _BrokerOperationState.RELEASED
                    and attestation.release_tombstone_id
                    == self._release_tombstone_id
                ):
                    self._set_released_locked()
                    return
                if attestation.state is _BrokerOperationState.TERMINAL_ATTESTED:
                    return
                self._poison_locked("supervisor release query 无效。")
            if state is _ParentProxyState.RELEASED:
                if attestation.state is _BrokerOperationState.RELEASED:
                    return
                self._poison_locked("supervisor released fact 回退。")
            if attestation.terminal_attestation_id is not None:
                self._validate_command_bindings_locked(attestation)
                self._set_terminal_locked(attestation)
                return
            if state is _ParentProxyState.ATTACH_UNKNOWN:
                if (
                    self._attachment_command_id is not None
                    and attestation.state is _BrokerOperationState.ATTACHED
                    and attestation.attachment_command_id
                    == self._attachment_command_id
                    and attestation.attachment_proof_digest
                    == self._attachment_proof_digest
                ):
                    object.__setattr__(
                        self,
                        "_state",
                        _ParentProxyState.ATTACHED_UNARMED,
                    )
                    return
                if attestation.state is _BrokerOperationState.RESERVED:
                    return
                self._poison_locked("supervisor ATTACH query 无效。")
            if state is _ParentProxyState.ATTACHED_UNARMED:
                if attestation.state is _BrokerOperationState.ATTACHED:
                    return
                self._poison_locked("supervisor unarmed query 无效。")
            if state is _ParentProxyState.ARM_UNKNOWN:
                if attestation.cancel_latched:
                    self._apply_cancel_observation_locked(attestation)
                    return
                if attestation.state is _BrokerOperationState.ATTACHED:
                    return
                if (
                    attestation.arm_command_id == self._arm_command_id
                    and attestation.state
                    in (
                        _BrokerOperationState.SPAWN_INFLIGHT,
                        _BrokerOperationState.CHILD_OWNED,
                        _BrokerOperationState.READY,
                        _BrokerOperationState.STARTED,
                        _BrokerOperationState.RESULT_PENDING_TERMINAL,
                    )
                ):
                    object.__setattr__(self, "_state", _ParentProxyState.ACTIVE)
                    object.__setattr__(
                        self,
                        "_business_open",
                        attestation.state
                        is not _BrokerOperationState.RESULT_PENDING_TERMINAL,
                    )
                    return
                self._poison_locked("supervisor ARM query 无效。")
            if state is _ParentProxyState.ACTIVE:
                if attestation.arm_command_id != self._arm_command_id:
                    self._poison_locked("supervisor active ARM binding 已变化。")
                if attestation.cancel_latched:
                    self._apply_cancel_observation_locked(attestation)
                    return
                if attestation.state not in (
                    _BrokerOperationState.SPAWN_INFLIGHT,
                    _BrokerOperationState.CHILD_OWNED,
                    _BrokerOperationState.READY,
                    _BrokerOperationState.STARTED,
                    _BrokerOperationState.RESULT_PENDING_TERMINAL,
                ):
                    self._poison_locked("supervisor active query 无效。")
                object.__setattr__(
                    self,
                    "_business_open",
                    attestation.state
                    is not _BrokerOperationState.RESULT_PENDING_TERMINAL,
                )
                return
            if state is _ParentProxyState.CANCEL_NOT_ATTESTED:
                if attestation.cancel_latched:
                    self._apply_cancel_observation_locked(attestation)
                elif (
                    attestation.arm_command_id is not None
                    and attestation.arm_command_id != self._arm_command_id
                ):
                    self._poison_locked("supervisor pending CANCEL ARM 已变化。")
                return
            if state is _ParentProxyState.CANCEL_LATCHED_WAIT_TERMINAL:
                if not attestation.cancel_latched:
                    self._poison_locked("supervisor cancel latch 回退。")
                return
            if state is _ParentProxyState.TERMINAL_ATTESTED:
                if attestation.state is _BrokerOperationState.TERMINAL_ATTESTED:
                    return
                self._poison_locked("supervisor release 未由 parent 提交。")
            self._poison_locked("supervisor proxy 已隔离。")

    def _set_terminal_locked(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        if attestation.state is not _BrokerOperationState.TERMINAL_ATTESTED:
            self._poison_locked("supervisor terminal attestation 无效。")
        object.__setattr__(self, "_state", _ParentProxyState.TERMINAL_ATTESTED)
        object.__setattr__(self, "_business_open", False)

    def begin_release(self, *, tombstone_id: UUID) -> bool:
        checked_tombstone = require_uuid(tombstone_id, "tombstone_id")
        with self._lock:
            if self._release_tombstone_id is not None:
                if (
                    self._release_tombstone_id == checked_tombstone
                    and self._state is _ParentProxyState.RELEASE_NOT_ATTESTED
                ):
                    return True
                if (
                    self._release_tombstone_id == checked_tombstone
                    and self._state is _ParentProxyState.RELEASED
                ):
                    return False
                self._poison_locked("supervisor RELEASE command 已变化。")
            if self._state is not _ParentProxyState.TERMINAL_ATTESTED:
                self._poison_locked("supervisor RELEASE 缺少 terminal attestation。")
            object.__setattr__(self, "_release_tombstone_id", checked_tombstone)
            object.__setattr__(
                self,
                "_state",
                _ParentProxyState.RELEASE_NOT_ATTESTED,
            )
            return True

    def observe_release_ack(
        self,
        attestation: _SupervisorOperationAttestation,
    ) -> None:
        with self._lock:
            if not self._accept_locked(attestation):
                return
            if self._state not in (
                _ParentProxyState.RELEASE_NOT_ATTESTED,
                _ParentProxyState.RELEASED,
            ):
                self._poison_locked("supervisor RELEASE ack 顺序无效。")
            if (
                attestation.state is not _BrokerOperationState.RELEASED
                or attestation.release_tombstone_id
                != self._release_tombstone_id
            ):
                self._poison_locked("supervisor RELEASE ack 无效。")
            if self._state is _ParentProxyState.RELEASED:
                return
            self._set_released_locked()

    def _set_released_locked(self) -> None:
        object.__setattr__(self, "_state", _ParentProxyState.RELEASED)
        object.__setattr__(self, "_business_open", False)
        object.__setattr__(self, "_cleanup_state", _SupervisorCleanupState.TERMINAL)

    def _observe_cleanup_pending(
        self,
        reply: _SupervisorQueryReply,
        *,
        _authority: object,
    ) -> bool:
        if _authority is not _PARENT_SESSION_AUTHORITY:
            raise TypeError("cleanup observation requires parent session")
        if type(reply) is not _SupervisorQueryReply:
            raise TypeError("reply must be SupervisorQueryReply")
        try:
            reply.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            with self._lock:
                self._poison_locked("supervisor cleanup query proof 无效。")
        with self._lock:
            if not _same_binding(self.binding, reply.attestation.binding):
                self._poison_locked("supervisor cleanup query binding 已变化。")
            for query_id, reply_digest in self._cleanup_query_proofs:
                if query_id == reply.query_id:
                    if reply_digest == reply.reply_digest:
                        return False
                    self._poison_locked("supervisor cleanup query id 冲突。")
            if (
                self._observed is not None
                and reply.attestation.revision < self._observed.revision
            ):
                return False
            accepted = self._accept_locked(reply.attestation)
            if not accepted and self._state in (
                _ParentProxyState.RELEASE_NOT_ATTESTED,
                _ParentProxyState.RELEASED,
            ):
                return False
            self._validate_command_bindings_locked(reply.attestation)
            if self._accept_requested_release_successor_locked(
                reply.attestation
            ):
                return False
            if reply.attestation.terminal_attestation_id is not None:
                if self._state is _ParentProxyState.RELEASE_NOT_ATTESTED:
                    return False
                self._set_terminal_locked(reply.attestation)
                return False
            success_wait = (
                self._state is _ParentProxyState.ACTIVE
                and reply.attestation.state
                is _BrokerOperationState.RESULT_PENDING_TERMINAL
                and not reply.attestation.cancel_latched
                and reply.attestation.child_ever_owned
                and reply.attestation.start_committed
                and reply.attestation.result_event_id is not None
                and reply.attestation.success_cleanup_event_id is not None
                and reply.attestation.durable_eof_ack_digest is not None
                and reply.attestation.cleanup_phase
                in (
                    _BrokerCleanupPhase.REAP_REQUIRED,
                    _BrokerCleanupPhase.REAP_CLAIMED,
                    _BrokerCleanupPhase.CLOSE_REQUIRED,
                    _BrokerCleanupPhase.CLOSE_CLAIMED,
                    _BrokerCleanupPhase.COMPLETE,
                )
            )
            if not success_wait and self._state not in (
                _ParentProxyState.CANCEL_NOT_ATTESTED,
                _ParentProxyState.CANCEL_LATCHED_WAIT_TERMINAL,
            ):
                self._poison_locked("supervisor cleanup PENDING 顺序无效。")
            if success_wait:
                object.__setattr__(self, "_business_open", False)
            object.__setattr__(
                self,
                "_cleanup_query_proofs",
                self._cleanup_query_proofs
                + ((reply.query_id, reply.reply_digest),),
            )
            selected_count = self._cleanup_pending_count + 1
            object.__setattr__(self, "_cleanup_pending_count", selected_count)
            selected_state = (
                _SupervisorCleanupState.WAITING_SUPERVISOR
                if selected_count >= SUPERVISOR_CLEANUP_PENDING_LIMIT
                else _SupervisorCleanupState.POLLING
            )
            object.__setattr__(self, "_cleanup_state", selected_state)
            return True

    def require_business_allowed(self) -> None:
        with self._lock:
            if (
                self._state is not _ParentProxyState.ACTIVE
                or not self._business_open
                or self._cleanup_state is not _SupervisorCleanupState.IDLE
            ):
                _raise_supervisor_error("supervisor proxy 不允许 business。")

    def terminal_attestation(
        self,
    ) -> tuple[UUID, _TerminalKind, int | None]:
        with self._lock:
            if self._state not in (
                _ParentProxyState.TERMINAL_ATTESTED,
                _ParentProxyState.RELEASE_NOT_ATTESTED,
                _ParentProxyState.RELEASED,
            ) or self._observed is None:
                _raise_supervisor_error("supervisor terminal 尚未证明。")
            attestation_id = self._observed.terminal_attestation_id
            terminal_kind = self._observed.terminal_kind
            if attestation_id is None or terminal_kind is None:
                self._poison_locked("supervisor terminal proof 无效。")
            return (
                attestation_id,
                terminal_kind,
                self._observed.terminal_status,
            )

    def can_release_operation_refs(self) -> bool:
        with self._lock:
            return (
                self._state is _ParentProxyState.RELEASED
                and self._cleanup_state is _SupervisorCleanupState.TERMINAL
            )

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "binding_digest": str(self.binding.binding_digest),
                "business_allowed": (
                    self._state is _ParentProxyState.ACTIVE
                    and self._business_open
                    and self._cleanup_state is _SupervisorCleanupState.IDLE
                ),
                "cleanup_pending_count": self._cleanup_pending_count,
                "cleanup_state": self._cleanup_state.value,
                "observed_revision": (
                    None if self._observed is None else self._observed.revision
                ),
                "operation_recovery_refs_held": (
                    not self.can_release_operation_refs()
                ),
                "state": self._state.value,
            }


@runtime_final
class _SupervisorPublicationLedger:
    """Pure local observer that proves an exact proxy publication."""

    __slots__ = (
        "binding",
        "proxy_id",
        "reservation_attestation_digest",
        "proof_id",
        "_lock",
        "_prepared_proxy",
        "_proxy",
        "_proof",
    )

    def __init__(
        self,
        *,
        proxy: _SupervisorParentProxy,
        proof_id: UUID,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PARENT_SESSION_AUTHORITY:
            raise TypeError("supervisor publication ledger requires its session")
        if type(proxy) is not _SupervisorParentProxy:
            raise TypeError("proxy must be SupervisorParentProxy")
        proxy.binding.validate_integrity()
        object.__setattr__(self, "binding", proxy.binding)
        object.__setattr__(self, "proxy_id", proxy.proxy_id)
        object.__setattr__(
            self,
            "reservation_attestation_digest",
            proxy.reservation_attestation_digest,
        )
        object.__setattr__(self, "proof_id", require_uuid(proof_id, "proof_id"))
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_prepared_proxy", proxy)
        object.__setattr__(self, "_proxy", None)
        object.__setattr__(self, "_proof", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorPublicationLedger identity is immutable")

    def commit(self, proxy: _SupervisorParentProxy) -> None:
        if type(proxy) is not _SupervisorParentProxy:
            raise TypeError("proxy must be SupervisorParentProxy")
        with self._lock:
            if (
                proxy is not self._prepared_proxy
                or not _same_binding(self.binding, proxy.binding)
                or proxy.proxy_id != self.proxy_id
                or proxy.reservation_attestation_digest
                != self.reservation_attestation_digest
            ):
                _raise_supervisor_error("supervisor proxy binding 已变化。")
            if self._proxy is not None:
                if self._proxy is proxy:
                    return
                _raise_supervisor_error("supervisor publication 已变化。")
            object.__setattr__(self, "_proxy", proxy)

    def observe(
        self,
        proxy: _SupervisorParentProxy,
    ) -> _SupervisorPublicationProof:
        if type(proxy) is not _SupervisorParentProxy:
            raise TypeError("proxy must be SupervisorParentProxy")
        with self._lock:
            if self._prepared_proxy is not proxy or self._proxy is not proxy:
                _raise_supervisor_error("supervisor publication 尚未证明。")
            proof = self._proof
            if proof is None:
                proof = _SupervisorPublicationProof(
                    publication_id=self.binding.publication_id,
                    binding_digest=self.binding.binding_digest,
                    proxy_id=self.proxy_id,
                    reservation_attestation_digest=(
                        self.reservation_attestation_digest
                    ),
                    proof_id=self.proof_id,
                    proxy=proxy,
                    publication_ledger=self,
                    _authority=_PUBLICATION_PROOF_AUTHORITY,
                )
                object.__setattr__(self, "_proof", proof)
            return proof

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "committed": self._proxy is not None,
                "proof_issued": self._proof is not None,
                "proxy_id": str(self.proxy_id),
                "publication_id": str(self.binding.publication_id),
            }


@runtime_final
class _SupervisorParentSessionLedger:
    """Pure epoch/liveness owner for every parent-side operation proxy."""

    __slots__ = (
        "epoch_id",
        "_broker_ledger",
        "_lock",
        "_operations",
        "_poisoned",
    )

    def __init__(
        self,
        *,
        epoch_id: UUID,
        broker_ledger: _SupervisorBrokerLedger,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BROKER_LEDGER_AUTHORITY:
            raise TypeError("parent session requires its broker factory")
        if type(broker_ledger) is not _SupervisorBrokerLedger:
            raise TypeError("broker_ledger must be SupervisorBrokerLedger")
        object.__setattr__(self, "epoch_id", require_uuid(epoch_id, "epoch_id"))
        if broker_ledger.epoch_id != self.epoch_id:
            raise ValueError("parent session broker epoch changed")
        object.__setattr__(self, "_broker_ledger", broker_ledger)
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_operations", {})
        object.__setattr__(self, "_poisoned", False)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorParentSessionLedger identity is immutable")

    def prepare_proxy(
        self,
        *,
        reservation: _SupervisorOperationAttestation,
        proxy_id: UUID,
        proof_id: UUID,
    ) -> tuple[_SupervisorParentProxy, _SupervisorPublicationLedger]:
        checked_proxy = require_uuid(proxy_id, "proxy_id")
        checked_proof = require_uuid(proof_id, "proof_id")
        if type(reservation) is not _SupervisorOperationAttestation:
            raise TypeError("reservation must be SupervisorOperationAttestation")
        reservation.validate_integrity()
        if (
            self._broker_ledger._parent_session is not self
            or reservation._broker_ledger is not self._broker_ledger
            or reservation.binding.epoch_id != self.epoch_id
            or reservation.state is not _BrokerOperationState.RESERVED
            or reservation.revision != 0
        ):
            _raise_supervisor_error("parent session RESERVED proof 无效。")
        broker = self._broker_ledger
        poisoned_proxies = None
        with broker._lock:
            with self._lock:
                if self._poisoned:
                    _raise_supervisor_error("parent supervisor session 已隔离。")
                operation_id = reservation.binding.operation_id
                existing = self._operations.get(operation_id)
                if existing is not None:
                    proxy, publication = existing
                    if (
                        proxy.proxy_id == checked_proxy
                        and publication.proof_id == checked_proof
                        and proxy._broker_ledger is reservation._broker_ledger
                        and proxy.reservation_attestation_digest
                        == reservation.attestation_digest
                    ):
                        return proxy, publication
                    poisoned_proxies = self._poison_all_locked()
                else:
                    if broker._poisoned:
                        _raise_supervisor_error(
                            "parent supervisor broker 已隔离。"
                        )
                    broker._require_external_action_slot_locked()
                    record = broker._operations.get(operation_id)
                    if (
                        record is None
                        or not _same_binding(record.binding, reservation.binding)
                        or record.state is not _BrokerOperationState.RESERVED
                        or record.revision != 0
                        or broker._snapshot(record).attestation_digest
                        != reservation.attestation_digest
                    ):
                        _raise_supervisor_error(
                            "parent session RESERVED proof 已过期。"
                        )
                    proxy = _SupervisorParentProxy(
                        reservation=reservation,
                        proxy_id=checked_proxy,
                        _authority=_PARENT_SESSION_AUTHORITY,
                    )
                    publication = _SupervisorPublicationLedger(
                        proxy=proxy,
                        proof_id=checked_proof,
                        _authority=_PARENT_SESSION_AUTHORITY,
                    )
                    self._operations[operation_id] = (proxy, publication)
                    return proxy, publication
        self._fanout_liveness_lost(poisoned_proxies)
        _raise_supervisor_error("parent supervisor operation 已变化。")

    def _poison_all_locked(self) -> tuple[_SupervisorParentProxy, ...]:
        object.__setattr__(self, "_poisoned", True)
        return tuple(proxy for proxy, _ in self._operations.values())

    @staticmethod
    def _fanout_liveness_lost(
        proxies: tuple[_SupervisorParentProxy, ...] | None,
    ) -> None:
        for proxy in () if proxies is None else proxies:
            proxy._observe_liveness_lost(_authority=_PARENT_SESSION_AUTHORITY)

    def observe_liveness_lost(self, *, epoch_id: UUID) -> None:
        checked_epoch = require_uuid(epoch_id, "epoch_id")
        with self._lock:
            proxies = self._poison_all_locked()
            epoch_changed = checked_epoch != self.epoch_id
        self._fanout_liveness_lost(proxies)
        if epoch_changed:
            _raise_supervisor_error("parent supervisor epoch 已变化。")

    def observe_cleanup_pending(
        self,
        *,
        proxy: _SupervisorParentProxy,
        reply: _SupervisorQueryReply,
    ) -> bool:
        if type(proxy) is not _SupervisorParentProxy:
            raise TypeError("proxy must be SupervisorParentProxy")
        if type(reply) is not _SupervisorQueryReply:
            raise TypeError("reply must be SupervisorQueryReply")
        proxies = None
        with self._lock:
            if self._poisoned:
                _raise_supervisor_error("parent supervisor session 已隔离。")
            existing = self._operations.get(proxy.binding.operation_id)
            if existing is None or existing[0] is not proxy:
                proxies = self._poison_all_locked()
        if proxies is not None:
            self._fanout_liveness_lost(proxies)
            _raise_supervisor_error("parent supervisor proxy 未注册。")
        return proxy._observe_cleanup_pending(
            reply,
            _authority=_PARENT_SESSION_AUTHORITY,
        )

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "epoch_id": str(self.epoch_id),
                "broker_bound": (
                    self._broker_ledger._parent_session is self
                ),
                "operation_count": len(self._operations),
                "poisoned": self._poisoned,
            }
