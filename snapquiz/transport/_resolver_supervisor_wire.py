"""Pure canonical wire values for the resolver supervisor control channel.

This W09-B2b-S3-0 module deliberately performs no I/O and has no dependency on
the in-process supervisor state contract.  It only freezes one bounded JSON
record format that a later channel owner may transport and adapt.
"""
from __future__ import annotations

from enum import Enum
import json
from types import MappingProxyType
from uuid import UUID

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, canonical_json_bytes, digest256


__all__ = ()


SUPERVISOR_WIRE_PROTOCOL_VERSION = "snapquiz.resolver-supervisor-wire.v1"
SUPERVISOR_WIRE_FRAME_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-wire-frame.v1"
)
SUPERVISOR_OPERATION_BINDING_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-operation-binding.v1"
)
SUPERVISOR_ATTESTATION_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-attestation.v1"
)
MAX_SUPERVISOR_WIRE_FRAME_BYTES = 4_096
MAX_SUPERVISOR_WIRE_COUNTER = (1 << 63) - 1

_FRAME_AUTHORITY = object()
_FRAME_TYPE_TAG = "ResolverSupervisorWireFrame"
_OPERATION_BINDING_TYPE_TAG = "ResolverSupervisorOperationBinding"
_ATTESTATION_TYPE_TAG = "ResolverSupervisorOperationAttestation"
_INVALID_FRAME_MESSAGE = "resolver supervisor wire frame is invalid"
_SPAWN_FAILED_STATUS = 70


class _SupervisorWireKind(str, Enum):
    RESERVE = "RESERVE"
    ATTACH = "ATTACH"
    ARM = "ARM"
    CANCEL = "CANCEL"
    QUERY = "QUERY"
    RELEASE = "RELEASE"
    ACK = "ACK"
    STATE = "STATE"


class _SupervisorWireState(str, Enum):
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


class _SupervisorWireCleanupPhase(str, Enum):
    NONE = "none"
    TERMINATE_REQUIRED = "terminate_required"
    TERMINATE_CLAIMED = "terminate_claimed"
    REAP_REQUIRED = "reap_required"
    REAP_CLAIMED = "reap_claimed"
    CLOSE_REQUIRED = "close_required"
    CLOSE_CLAIMED = "close_claimed"
    COMPLETE = "complete"


class _SupervisorWireTerminalKind(str, Enum):
    ZERO_CHILD_CANCEL = "zero_child_cancel"
    SPAWN_FAILED = "spawn_failed"
    CHILD_EXITED = "child_exited"


class _SupervisorWirePoisonReason(str, Enum):
    BINDING_MISMATCH = "binding_mismatch"
    EPOCH_LOST = "epoch_lost"
    EVENT_EQUIVOCATION = "event_equivocation"
    INVALID_TRANSITION = "invalid_transition"
    LIVENESS_LOST = "liveness_lost"
    OS_ACTION_UNCERTAIN = "os_action_uncertain"
    SNAPSHOT_EQUIVOCATION = "snapshot_equivocation"


_ACKNOWLEDGEABLE_KINDS = frozenset(
    {
        _SupervisorWireKind.RESERVE,
        _SupervisorWireKind.ATTACH,
        _SupervisorWireKind.ARM,
        _SupervisorWireKind.CANCEL,
        _SupervisorWireKind.RELEASE,
    }
)

_RESERVE_FIELDS = frozenset(
    {"lifecycle_id", "publication_id", "spawn_request_digest"}
)
_ATTACH_FIELDS = frozenset(
    {
        "command_id",
        "proxy_id",
        "publication_id",
        "publication_proof_digest",
        "reservation_attestation_digest",
    }
)
_ARM_FIELDS = frozenset({"command_id", "proxy_id"})
_CANCEL_FIELDS = frozenset(
    {"cancel_payload_digest", "command_id", "proxy_id"}
)
_QUERY_FIELDS = frozenset({"proxy_id", "query_id"})
_RELEASE_FIELDS = frozenset(
    {"proxy_id", "terminal_attestation_digest", "tombstone_id"}
)
_ACK_FIELDS = frozenset(
    {
        "acked_frame_digest",
        "acked_frame_id",
        "acked_kind",
        "attestation_digest",
        "proxy_id",
        "revision",
    }
)
_STATE_FIELDS = frozenset(
    {
        "arm_command_id",
        "attachment_command_id",
        "attachment_proof_digest",
        "attestation_digest",
        "cancel_command_id",
        "cancel_latched",
        "cancel_payload_digest",
        "child_ever_owned",
        "cleanup_phase",
        "close_action_id",
        "poison_reason",
        "proxy_id",
        "query_id",
        "ready_event_id",
        "reap_action_id",
        "release_tombstone_id",
        "result_digest",
        "result_event_id",
        "success_cleanup_event_id",
        "durable_eof_ack_digest",
        "revision",
        "spawn_created",
        "spawn_event_id",
        "start_command_id",
        "start_committed",
        "start_payload_digest",
        "state",
        "terminal_attestation_id",
        "terminal_kind",
        "terminal_status",
        "terminate_action_id",
    }
)
_PAYLOAD_FIELDS = {
    _SupervisorWireKind.RESERVE: _RESERVE_FIELDS,
    _SupervisorWireKind.ATTACH: _ATTACH_FIELDS,
    _SupervisorWireKind.ARM: _ARM_FIELDS,
    _SupervisorWireKind.CANCEL: _CANCEL_FIELDS,
    _SupervisorWireKind.QUERY: _QUERY_FIELDS,
    _SupervisorWireKind.RELEASE: _RELEASE_FIELDS,
    _SupervisorWireKind.ACK: _ACK_FIELDS,
    _SupervisorWireKind.STATE: _STATE_FIELDS,
}
_TOP_LEVEL_FIELDS = frozenset(
    {
        "control_channel_id",
        "epoch_id",
        "frame_id",
        "kind",
        "operation_binding_digest",
        "operation_id",
        "payload",
        "protocol_version",
        "schema_version",
    }
)


def _require_counter(value: object, name: str) -> int:
    selected = require_plain_int(value, name, minimum=0)
    if selected > MAX_SUPERVISOR_WIRE_COUNTER:
        raise ValueError(f"{name} exceeds the supervisor wire limit")
    return selected


def _require_optional_uuid(value: object, name: str) -> UUID | None:
    if value is None:
        return None
    return require_uuid(value, name)


def _require_optional_digest(value: object, name: str) -> Digest256 | None:
    if value is None:
        return None
    return require_digest(value, name)


def _require_optional_bool(value: object, name: str) -> bool | None:
    if value is not None and type(value) is not bool:
        raise ValueError(f"{name} must be bool or None")
    return value


def _require_exact_enum(value: object, enum_type: type[Enum], name: str) -> Enum:
    if type(value) is not enum_type:
        raise ValueError(f"{name} has an invalid enum type")
    return value


def _require_exact_fields(
    payload: object,
    expected: frozenset[str],
) -> dict[str, object]:
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("supervisor wire payload fields are invalid")
    return payload


def _validate_reserve_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        "lifecycle_id": require_uuid(payload["lifecycle_id"], "lifecycle_id"),
        "publication_id": require_uuid(
            payload["publication_id"], "publication_id"
        ),
        "spawn_request_digest": require_digest(
            payload["spawn_request_digest"], "spawn_request_digest"
        ),
    }


def _validate_attach_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        "command_id": require_uuid(payload["command_id"], "command_id"),
        "proxy_id": require_uuid(payload["proxy_id"], "proxy_id"),
        "publication_id": require_uuid(
            payload["publication_id"], "publication_id"
        ),
        "publication_proof_digest": require_digest(
            payload["publication_proof_digest"],
            "publication_proof_digest",
        ),
        "reservation_attestation_digest": require_digest(
            payload["reservation_attestation_digest"],
            "reservation_attestation_digest",
        ),
    }


def _validate_arm_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        "command_id": require_uuid(payload["command_id"], "command_id"),
        "proxy_id": require_uuid(payload["proxy_id"], "proxy_id"),
    }


def _validate_cancel_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        "cancel_payload_digest": require_digest(
            payload["cancel_payload_digest"], "cancel_payload_digest"
        ),
        "command_id": require_uuid(payload["command_id"], "command_id"),
        "proxy_id": require_uuid(payload["proxy_id"], "proxy_id"),
    }


def _validate_query_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        "proxy_id": require_uuid(payload["proxy_id"], "proxy_id"),
        "query_id": require_uuid(payload["query_id"], "query_id"),
    }


def _validate_release_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        "proxy_id": require_uuid(payload["proxy_id"], "proxy_id"),
        "terminal_attestation_digest": require_digest(
            payload["terminal_attestation_digest"],
            "terminal_attestation_digest",
        ),
        "tombstone_id": require_uuid(payload["tombstone_id"], "tombstone_id"),
    }


def _validate_ack_payload(payload: dict[str, object]) -> dict[str, object]:
    acked_kind = _require_exact_enum(
        payload["acked_kind"], _SupervisorWireKind, "acked_kind"
    )
    if acked_kind not in _ACKNOWLEDGEABLE_KINDS:
        raise ValueError("acked_kind cannot be acknowledged")
    proxy_id = _require_optional_uuid(payload["proxy_id"], "proxy_id")
    if (acked_kind is _SupervisorWireKind.RESERVE) != (proxy_id is None):
        raise ValueError("ACK proxy binding is invalid")
    return {
        "acked_frame_digest": require_digest(
            payload["acked_frame_digest"], "acked_frame_digest"
        ),
        "acked_frame_id": require_uuid(
            payload["acked_frame_id"], "acked_frame_id"
        ),
        "acked_kind": acked_kind,
        "attestation_digest": require_digest(
            payload["attestation_digest"], "attestation_digest"
        ),
        "proxy_id": proxy_id,
        "revision": _require_counter(payload["revision"], "revision"),
    }


def _validate_cleanup_facts(payload: dict[str, object]) -> None:
    phase = payload["cleanup_phase"]
    terminate = payload["terminate_action_id"]
    reap = payload["reap_action_id"]
    close = payload["close_action_id"]
    success = payload["success_cleanup_event_id"] is not None
    if phase is _SupervisorWireCleanupPhase.NONE:
        valid = not success and terminate is None and reap is None and close is None
    elif phase is _SupervisorWireCleanupPhase.TERMINATE_REQUIRED:
        valid = not success and terminate is None and reap is None and close is None
    elif phase is _SupervisorWireCleanupPhase.TERMINATE_CLAIMED:
        valid = not success and terminate is not None and reap is None and close is None
    elif phase is _SupervisorWireCleanupPhase.REAP_REQUIRED:
        valid = (
            reap is None
            and close is None
            and ((success and terminate is None) or (not success and terminate is not None))
        )
    elif phase in (
        _SupervisorWireCleanupPhase.REAP_CLAIMED,
        _SupervisorWireCleanupPhase.CLOSE_REQUIRED,
    ):
        valid = (
            reap is not None
            and close is None
            and ((success and terminate is None) or (not success and terminate is not None))
        )
    elif phase is _SupervisorWireCleanupPhase.CLOSE_CLAIMED:
        valid = (
            reap is not None
            and close is not None
            and ((success and terminate is None) or (not success and terminate is not None))
        )
    else:
        valid = (
            success
            and terminate is None
            and reap is not None
            and close is not None
        ) or (
            not success
            and (
                all(item is None for item in (terminate, reap, close))
                or all(item is not None for item in (terminate, reap, close))
            )
        )
    if not valid:
        raise ValueError("STATE cleanup facts are inconsistent")


def _validate_state_facts(payload: dict[str, object]) -> None:
    paired = (
        (payload["attachment_command_id"], payload["attachment_proof_digest"]),
        (payload["cancel_command_id"], payload["cancel_payload_digest"]),
        (payload["spawn_event_id"], payload["spawn_created"]),
        (payload["start_command_id"], payload["start_payload_digest"]),
        (payload["result_event_id"], payload["result_digest"]),
        (
            payload["success_cleanup_event_id"],
            payload["durable_eof_ack_digest"],
        ),
        (payload["terminal_attestation_id"], payload["terminal_kind"]),
    )
    if any((first is None) != (second is None) for first, second in paired):
        raise ValueError("STATE paired facts are inconsistent")
    if payload["cancel_latched"] != (payload["cancel_command_id"] is not None):
        raise ValueError("STATE cancel facts are inconsistent")
    if payload["child_ever_owned"] != (payload["spawn_created"] is True):
        raise ValueError("STATE child ownership facts are inconsistent")
    if payload["start_committed"] and payload["start_command_id"] is None:
        raise ValueError("STATE START commit lacks a command")
    if payload["ready_event_id"] is not None and not payload["child_ever_owned"]:
        raise ValueError("STATE READY lacks child ownership")
    if payload["result_event_id"] is not None and not payload["start_committed"]:
        raise ValueError("STATE RESULT lacks committed START")

    success_cleanup = payload["success_cleanup_event_id"] is not None
    if success_cleanup and (
        payload["result_event_id"] is None
        or payload["cancel_latched"]
        or not payload["child_ever_owned"]
        or payload["terminate_action_id"] is not None
        or payload["cleanup_phase"]
        in (
            _SupervisorWireCleanupPhase.NONE,
            _SupervisorWireCleanupPhase.TERMINATE_REQUIRED,
            _SupervisorWireCleanupPhase.TERMINATE_CLAIMED,
        )
        or payload["state"]
        not in (
            _SupervisorWireState.RESULT_PENDING_TERMINAL,
            _SupervisorWireState.TERMINAL_ATTESTED,
            _SupervisorWireState.RELEASED,
            _SupervisorWireState.POISONED,
        )
    ):
        raise ValueError("STATE success cleanup proof is inconsistent")

    state = payload["state"]
    poison_reason = payload["poison_reason"]
    if (state is _SupervisorWireState.POISONED) != (poison_reason is not None):
        raise ValueError("STATE poison facts are inconsistent")
    tombstone = payload["release_tombstone_id"]
    if (state is _SupervisorWireState.RELEASED) != (tombstone is not None):
        raise ValueError("STATE release facts are inconsistent")
    terminal = state in (
        _SupervisorWireState.TERMINAL_ATTESTED,
        _SupervisorWireState.RELEASED,
    )
    terminal_present = payload["terminal_attestation_id"] is not None
    if terminal and not terminal_present:
        raise ValueError("STATE terminal facts are inconsistent")
    if terminal and (
        payload["cleanup_phase"] is not _SupervisorWireCleanupPhase.COMPLETE
    ):
        raise ValueError("STATE terminal lacks cleanup completion")
    if state is not _SupervisorWireState.POISONED and (
        not terminal and terminal_present
    ):
        raise ValueError("STATE terminal facts are inconsistent")

    terminal_kind = payload["terminal_kind"]
    terminal_status = payload["terminal_status"]
    if terminal_kind is _SupervisorWireTerminalKind.ZERO_CHILD_CANCEL:
        if (
            payload["child_ever_owned"]
            or not payload["cancel_latched"]
            or payload["arm_command_id"] is not None
            or payload["spawn_event_id"] is not None
            or payload["terminal_attestation_id"]
            != payload["cancel_command_id"]
            or terminal_status is not None
        ):
            raise ValueError("STATE zero-child terminal facts are invalid")
    elif terminal_kind is _SupervisorWireTerminalKind.SPAWN_FAILED:
        if (
            payload["child_ever_owned"]
            or payload["spawn_created"] is not False
            or payload["attachment_command_id"] is None
            or payload["arm_command_id"] is None
            or payload["terminal_attestation_id"]
            != payload["spawn_event_id"]
            or terminal_status != _SPAWN_FAILED_STATUS
        ):
            raise ValueError("STATE spawn-failed terminal facts are invalid")
    elif terminal_kind is _SupervisorWireTerminalKind.CHILD_EXITED:
        if (
            not payload["child_ever_owned"]
            or payload["attachment_command_id"] is None
            or payload["arm_command_id"] is None
            or terminal_status is None
        ):
            raise ValueError("STATE child-exited terminal facts are invalid")
    elif terminal_status is not None:
        raise ValueError("terminal status lacks a terminal kind")
    _validate_cleanup_facts(payload)
    if (
        payload["cleanup_phase"] is _SupervisorWireCleanupPhase.COMPLETE
        and payload["child_ever_owned"]
        and payload["cancel_latched"]
        and any(
            payload[name] is None
            for name in (
                "terminate_action_id",
                "reap_action_id",
                "close_action_id",
            )
        )
    ):
        raise ValueError("STATE cancelled-child cleanup lacks action proofs")

    if payload["cleanup_phase"] not in (
        _SupervisorWireCleanupPhase.NONE,
        _SupervisorWireCleanupPhase.COMPLETE,
    ) and state is not _SupervisorWireState.POISONED and (
        not (
            payload["child_ever_owned"] and payload["cancel_latched"]
        )
        and not success_cleanup
    ):
        raise ValueError("STATE active cleanup lacks cancelled child ownership")

    if state is _SupervisorWireState.RESERVED:
        if any(
            payload[name] is not None
            for name in (
                "attachment_command_id",
                "arm_command_id",
                "cancel_command_id",
                "spawn_event_id",
                "ready_event_id",
                "start_command_id",
                "result_event_id",
                "terminal_attestation_id",
            )
        ) or payload["cleanup_phase"] is not _SupervisorWireCleanupPhase.NONE:
            raise ValueError("STATE reserved facts are inconsistent")
    elif state is _SupervisorWireState.ATTACHED:
        if (
            payload["attachment_command_id"] is None
            or payload["arm_command_id"] is not None
            or payload["cancel_latched"]
            or payload["spawn_event_id"] is not None
            or payload["ready_event_id"] is not None
            or payload["start_command_id"] is not None
            or payload["result_event_id"] is not None
            or payload["cleanup_phase"] is not _SupervisorWireCleanupPhase.NONE
        ):
            raise ValueError("STATE attached facts are inconsistent")
    elif state is _SupervisorWireState.SPAWN_INFLIGHT:
        if (
            payload["attachment_command_id"] is None
            or payload["arm_command_id"] is None
            or payload["spawn_event_id"] is not None
            or payload["cancel_latched"]
            or payload["ready_event_id"] is not None
            or payload["start_command_id"] is not None
            or payload["result_event_id"] is not None
            or payload["cleanup_phase"] is not _SupervisorWireCleanupPhase.NONE
        ):
            raise ValueError("STATE spawn-inflight facts are inconsistent")
    elif state is _SupervisorWireState.CANCEL_WAIT_SPAWN:
        if (
            payload["attachment_command_id"] is None
            or payload["arm_command_id"] is None
            or payload["spawn_event_id"] is not None
            or not payload["cancel_latched"]
            or payload["ready_event_id"] is not None
            or payload["start_command_id"] is not None
            or payload["result_event_id"] is not None
            or payload["cleanup_phase"] is not _SupervisorWireCleanupPhase.NONE
        ):
            raise ValueError("STATE cancel-wait-spawn facts are inconsistent")
    elif state in (
        _SupervisorWireState.CHILD_OWNED,
        _SupervisorWireState.READY,
        _SupervisorWireState.STARTED,
        _SupervisorWireState.RESULT_PENDING_TERMINAL,
    ):
        if (
            payload["attachment_command_id"] is None
            or payload["arm_command_id"] is None
            or not payload["child_ever_owned"]
        ):
            raise ValueError("STATE child operation lacks ownership facts")
        if state is _SupervisorWireState.CHILD_OWNED and any(
            payload[name] is not None
            for name in (
                "ready_event_id",
                "start_command_id",
                "result_event_id",
            )
        ):
            raise ValueError("STATE child-owned contains later facts")
        if state is _SupervisorWireState.READY and (
            payload["start_committed"]
            or payload["result_event_id"] is not None
        ):
            raise ValueError("STATE READY contains committed business facts")
        if state is _SupervisorWireState.STARTED and (
            payload["result_event_id"] is not None
        ):
            raise ValueError("STATE STARTED contains RESULT facts")
        if state is not _SupervisorWireState.CHILD_OWNED and (
            payload["ready_event_id"] is None
        ):
            raise ValueError("STATE post-READY lacks READY proof")
        if state in (
            _SupervisorWireState.STARTED,
            _SupervisorWireState.RESULT_PENDING_TERMINAL,
        ) and not payload["start_committed"]:
            raise ValueError("STATE started operation lacks START proof")
        if state is _SupervisorWireState.RESULT_PENDING_TERMINAL and (
            payload["result_event_id"] is None
        ):
            raise ValueError("STATE result-pending lacks RESULT proof")


def _validate_state_payload(payload: dict[str, object]) -> dict[str, object]:
    selected: dict[str, object] = {
        "arm_command_id": _require_optional_uuid(
            payload["arm_command_id"], "arm_command_id"
        ),
        "attachment_command_id": _require_optional_uuid(
            payload["attachment_command_id"], "attachment_command_id"
        ),
        "attachment_proof_digest": _require_optional_digest(
            payload["attachment_proof_digest"], "attachment_proof_digest"
        ),
        "attestation_digest": require_digest(
            payload["attestation_digest"], "attestation_digest"
        ),
        "cancel_command_id": _require_optional_uuid(
            payload["cancel_command_id"], "cancel_command_id"
        ),
        "cancel_latched": payload["cancel_latched"],
        "cancel_payload_digest": _require_optional_digest(
            payload["cancel_payload_digest"], "cancel_payload_digest"
        ),
        "child_ever_owned": payload["child_ever_owned"],
        "cleanup_phase": _require_exact_enum(
            payload["cleanup_phase"],
            _SupervisorWireCleanupPhase,
            "cleanup_phase",
        ),
        "close_action_id": _require_optional_uuid(
            payload["close_action_id"], "close_action_id"
        ),
        "poison_reason": payload["poison_reason"],
        "proxy_id": require_uuid(payload["proxy_id"], "proxy_id"),
        "query_id": require_uuid(payload["query_id"], "query_id"),
        "ready_event_id": _require_optional_uuid(
            payload["ready_event_id"], "ready_event_id"
        ),
        "reap_action_id": _require_optional_uuid(
            payload["reap_action_id"], "reap_action_id"
        ),
        "release_tombstone_id": _require_optional_uuid(
            payload["release_tombstone_id"], "release_tombstone_id"
        ),
        "result_digest": _require_optional_digest(
            payload["result_digest"], "result_digest"
        ),
        "result_event_id": _require_optional_uuid(
            payload["result_event_id"], "result_event_id"
        ),
        "success_cleanup_event_id": _require_optional_uuid(
            payload["success_cleanup_event_id"], "success_cleanup_event_id"
        ),
        "durable_eof_ack_digest": _require_optional_digest(
            payload["durable_eof_ack_digest"], "durable_eof_ack_digest"
        ),
        "revision": _require_counter(payload["revision"], "revision"),
        "spawn_created": _require_optional_bool(
            payload["spawn_created"], "spawn_created"
        ),
        "spawn_event_id": _require_optional_uuid(
            payload["spawn_event_id"], "spawn_event_id"
        ),
        "start_command_id": _require_optional_uuid(
            payload["start_command_id"], "start_command_id"
        ),
        "start_committed": payload["start_committed"],
        "start_payload_digest": _require_optional_digest(
            payload["start_payload_digest"], "start_payload_digest"
        ),
        "state": _require_exact_enum(
            payload["state"], _SupervisorWireState, "state"
        ),
        "terminal_attestation_id": _require_optional_uuid(
            payload["terminal_attestation_id"], "terminal_attestation_id"
        ),
        "terminal_kind": payload["terminal_kind"],
        "terminal_status": payload["terminal_status"],
        "terminate_action_id": _require_optional_uuid(
            payload["terminate_action_id"], "terminate_action_id"
        ),
    }
    for name in ("cancel_latched", "child_ever_owned", "start_committed"):
        if type(selected[name]) is not bool:
            raise ValueError(f"{name} must be bool")
    poison_reason = selected["poison_reason"]
    if poison_reason is not None:
        selected["poison_reason"] = _require_exact_enum(
            poison_reason,
            _SupervisorWirePoisonReason,
            "poison_reason",
        )
    terminal_kind = selected["terminal_kind"]
    if terminal_kind is not None:
        selected["terminal_kind"] = _require_exact_enum(
            terminal_kind,
            _SupervisorWireTerminalKind,
            "terminal_kind",
        )
    terminal_status = selected["terminal_status"]
    if terminal_status is not None:
        selected["terminal_status"] = _require_counter(
            terminal_status, "terminal_status"
        )
    _validate_state_facts(selected)
    return selected


_PAYLOAD_VALIDATORS = {
    _SupervisorWireKind.RESERVE: _validate_reserve_payload,
    _SupervisorWireKind.ATTACH: _validate_attach_payload,
    _SupervisorWireKind.ARM: _validate_arm_payload,
    _SupervisorWireKind.CANCEL: _validate_cancel_payload,
    _SupervisorWireKind.QUERY: _validate_query_payload,
    _SupervisorWireKind.RELEASE: _validate_release_payload,
    _SupervisorWireKind.ACK: _validate_ack_payload,
    _SupervisorWireKind.STATE: _validate_state_payload,
}


def _validate_payload(
    kind: _SupervisorWireKind,
    payload: object,
) -> dict[str, object]:
    checked = _require_exact_fields(payload, _PAYLOAD_FIELDS[kind])
    return _PAYLOAD_VALIDATORS[kind](checked)


def _reserve_operation_binding_digest(
    *,
    epoch_id: UUID,
    operation_id: UUID,
    payload: dict[str, object],
) -> Digest256:
    return digest256(
        _OPERATION_BINDING_TYPE_TAG,
        SUPERVISOR_OPERATION_BINDING_SCHEMA_VERSION,
        {
            "epoch_id": epoch_id,
            "lifecycle_id": payload["lifecycle_id"],
            "operation_id": operation_id,
            "publication_id": payload["publication_id"],
            "spawn_request_digest": payload["spawn_request_digest"],
        },
    )


def _validate_reserve_binding(
    *,
    kind: _SupervisorWireKind,
    epoch_id: UUID,
    operation_id: UUID,
    operation_binding_digest: Digest256,
    payload: dict[str, object],
) -> None:
    if kind is _SupervisorWireKind.RESERVE and operation_binding_digest != (
        _reserve_operation_binding_digest(
            epoch_id=epoch_id,
            operation_id=operation_id,
            payload=payload,
        )
    ):
        raise ValueError("RESERVE operation binding digest is invalid")


def _state_attestation_digest(
    *,
    operation_binding_digest: Digest256,
    payload: dict[str, object],
) -> Digest256:
    return digest256(
        _ATTESTATION_TYPE_TAG,
        SUPERVISOR_ATTESTATION_SCHEMA_VERSION,
        {
            "arm_command_id": payload["arm_command_id"],
            "attachment_command_id": payload["attachment_command_id"],
            "attachment_proof_digest": payload["attachment_proof_digest"],
            "binding_digest": operation_binding_digest,
            "cancel_command_id": payload["cancel_command_id"],
            "cancel_latched": payload["cancel_latched"],
            "cancel_payload_digest": payload["cancel_payload_digest"],
            "child_ever_owned": payload["child_ever_owned"],
            "cleanup_phase": payload["cleanup_phase"],
            "close_action_id": payload["close_action_id"],
            "poison_reason": payload["poison_reason"],
            "ready_event_id": payload["ready_event_id"],
            "reap_action_id": payload["reap_action_id"],
            "release_tombstone_id": payload["release_tombstone_id"],
            "result_digest": payload["result_digest"],
            "result_event_id": payload["result_event_id"],
            "success_cleanup_event_id": payload["success_cleanup_event_id"],
            "durable_eof_ack_digest": payload["durable_eof_ack_digest"],
            "revision": payload["revision"],
            "spawn_created": payload["spawn_created"],
            "spawn_event_id": payload["spawn_event_id"],
            "start_command_id": payload["start_command_id"],
            "start_committed": payload["start_committed"],
            "start_payload_digest": payload["start_payload_digest"],
            "state": payload["state"],
            "terminal_attestation_id": payload["terminal_attestation_id"],
            "terminal_kind": payload["terminal_kind"],
            "terminal_status": payload["terminal_status"],
            "terminate_action_id": payload["terminate_action_id"],
        },
    )


def _validate_state_attestation_digest(
    *,
    kind: _SupervisorWireKind,
    operation_binding_digest: Digest256,
    payload: dict[str, object],
) -> None:
    if kind is _SupervisorWireKind.STATE and payload["attestation_digest"] != (
        _state_attestation_digest(
            operation_binding_digest=operation_binding_digest,
            payload=payload,
        )
    ):
        raise ValueError("STATE attestation digest is invalid")


def _wire_scalar(value: object) -> object:
    if type(value) is UUID:
        return str(value)
    if type(value) is Digest256:
        return str(value)
    if type(value) in (
        _SupervisorWireKind,
        _SupervisorWireState,
        _SupervisorWireCleanupPhase,
        _SupervisorWireTerminalKind,
        _SupervisorWirePoisonReason,
    ):
        return value.value
    if value is None or type(value) in (bool, int):
        return value
    raise ValueError("supervisor wire value has no canonical representation")


def _frame_payload(frame: "_SupervisorWireFrame") -> dict[str, object]:
    return {
        "control_channel_id": str(frame.control_channel_id),
        "epoch_id": str(frame.epoch_id),
        "frame_id": str(frame.frame_id),
        "kind": frame.kind.value,
        "operation_binding_digest": str(frame.operation_binding_digest),
        "operation_id": str(frame.operation_id),
        "payload": {
            name: _wire_scalar(value) for name, value in frame.payload.items()
        },
        "protocol_version": SUPERVISOR_WIRE_PROTOCOL_VERSION,
        "schema_version": SUPERVISOR_WIRE_FRAME_SCHEMA_VERSION,
    }


@runtime_final
class _SupervisorWireFrame:
    """Factory-issued, immutable and content-addressed wire frame."""

    __slots__ = (
        "kind",
        "epoch_id",
        "operation_id",
        "control_channel_id",
        "operation_binding_digest",
        "frame_id",
        "payload",
        "frame_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        kind: _SupervisorWireKind,
        epoch_id: UUID,
        operation_id: UUID,
        control_channel_id: UUID,
        operation_binding_digest: Digest256,
        frame_id: UUID,
        payload: dict[str, object],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _FRAME_AUTHORITY:
            raise TypeError("supervisor wire frame requires its factory")
        if type(kind) is not _SupervisorWireKind:
            raise ValueError("kind must be SupervisorWireKind")
        selected_payload = _validate_payload(kind, payload)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "epoch_id", require_uuid(epoch_id, "epoch_id"))
        object.__setattr__(
            self,
            "operation_id",
            require_uuid(operation_id, "operation_id"),
        )
        object.__setattr__(
            self,
            "control_channel_id",
            require_uuid(control_channel_id, "control_channel_id"),
        )
        object.__setattr__(
            self,
            "operation_binding_digest",
            require_digest(
                operation_binding_digest,
                "operation_binding_digest",
            ),
        )
        object.__setattr__(self, "frame_id", require_uuid(frame_id, "frame_id"))
        object.__setattr__(
            self,
            "payload",
            MappingProxyType(selected_payload),
        )
        _validate_reserve_binding(
            kind=self.kind,
            epoch_id=self.epoch_id,
            operation_id=self.operation_id,
            operation_binding_digest=self.operation_binding_digest,
            payload=selected_payload,
        )
        _validate_state_attestation_digest(
            kind=self.kind,
            operation_binding_digest=self.operation_binding_digest,
            payload=selected_payload,
        )
        selected_digest = digest256(
            _FRAME_TYPE_TAG,
            SUPERVISOR_WIRE_FRAME_SCHEMA_VERSION,
            _frame_payload(self),
        )
        object.__setattr__(self, "frame_digest", selected_digest)
        object.__setattr__(self, "_issued_digest", selected_digest)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorWireFrame is immutable")

    def __copy__(self) -> "_SupervisorWireFrame":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_SupervisorWireFrame":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("SupervisorWireFrame is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("SupervisorWireFrame is not serializable")

    def __getstate__(self) -> object:
        raise TypeError("SupervisorWireFrame is not serializable")

    def validate_integrity(self) -> None:
        if type(self.kind) is not _SupervisorWireKind:
            raise ValueError("supervisor wire frame kind changed")
        require_uuid(self.epoch_id, "epoch_id")
        require_uuid(self.operation_id, "operation_id")
        require_uuid(self.control_channel_id, "control_channel_id")
        require_uuid(self.frame_id, "frame_id")
        require_digest(
            self.operation_binding_digest,
            "operation_binding_digest",
        )
        if type(self.payload) is not MappingProxyType:
            raise ValueError("supervisor wire frame payload changed")
        selected = _validate_payload(self.kind, dict(self.payload))
        if selected != dict(self.payload):
            raise ValueError("supervisor wire frame payload changed")
        _validate_reserve_binding(
            kind=self.kind,
            epoch_id=self.epoch_id,
            operation_id=self.operation_id,
            operation_binding_digest=self.operation_binding_digest,
            payload=selected,
        )
        _validate_state_attestation_digest(
            kind=self.kind,
            operation_binding_digest=self.operation_binding_digest,
            payload=selected,
        )
        current = digest256(
            _FRAME_TYPE_TAG,
            SUPERVISOR_WIRE_FRAME_SCHEMA_VERSION,
            _frame_payload(self),
        )
        if (
            type(self.frame_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or current != self.frame_digest
            or current != self._issued_digest
        ):
            raise ValueError("supervisor wire frame integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "control_channel_id": str(self.control_channel_id),
            "epoch_id": str(self.epoch_id),
            "frame_digest_prefix": str(self.frame_digest)[:12],
            "frame_id": str(self.frame_id),
            "kind": self.kind.value,
            "operation_binding_digest_prefix": str(
                self.operation_binding_digest
            )[:12],
            "operation_id": str(self.operation_id),
        }

    def require_binding(
        self,
        *,
        epoch_id: UUID,
        operation_id: UUID,
        control_channel_id: UUID,
        operation_binding_digest: Digest256,
    ) -> None:
        """Reject a valid frame replayed into a different trusted context."""

        self.validate_integrity()
        expected = (
            require_uuid(epoch_id, "epoch_id"),
            require_uuid(operation_id, "operation_id"),
            require_uuid(control_channel_id, "control_channel_id"),
            require_digest(
                operation_binding_digest,
                "operation_binding_digest",
            ),
        )
        observed = (
            self.epoch_id,
            self.operation_id,
            self.control_channel_id,
            self.operation_binding_digest,
        )
        if observed != expected:
            raise ValueError("resolver supervisor wire binding mismatch")

    def require_acknowledges(self, command: "_SupervisorWireFrame") -> None:
        """Prove that this ACK names one exact command frame on this channel."""

        self.validate_integrity()
        if type(command) is not _SupervisorWireFrame:
            raise TypeError("command must be SupervisorWireFrame")
        command.validate_integrity()
        if (
            self.kind is not _SupervisorWireKind.ACK
            or command.kind not in _ACKNOWLEDGEABLE_KINDS
        ):
            raise ValueError("resolver supervisor ACK kind is invalid")
        expected_proxy = (
            None
            if command.kind is _SupervisorWireKind.RESERVE
            else command.payload["proxy_id"]
        )
        exact = (
            self.epoch_id == command.epoch_id,
            self.operation_id == command.operation_id,
            self.control_channel_id == command.control_channel_id,
            self.operation_binding_digest
            == command.operation_binding_digest,
            self.payload["acked_frame_id"] == command.frame_id,
            self.payload["acked_frame_digest"] == command.frame_digest,
            self.payload["acked_kind"] is command.kind,
            self.payload["proxy_id"] == expected_proxy,
        )
        if not all(exact):
            raise ValueError("resolver supervisor ACK binding mismatch")


def _new_supervisor_wire_frame(
    *,
    kind: _SupervisorWireKind,
    epoch_id: UUID,
    operation_id: UUID,
    control_channel_id: UUID,
    operation_binding_digest: Digest256,
    frame_id: UUID,
    payload: dict[str, object],
) -> _SupervisorWireFrame:
    return _SupervisorWireFrame(
        kind=kind,
        epoch_id=epoch_id,
        operation_id=operation_id,
        control_channel_id=control_channel_id,
        operation_binding_digest=operation_binding_digest,
        frame_id=frame_id,
        payload=payload,
        _authority=_FRAME_AUTHORITY,
    )


def _encode_supervisor_wire_frame(frame: _SupervisorWireFrame) -> bytes:
    if type(frame) is not _SupervisorWireFrame:
        raise TypeError("frame must be SupervisorWireFrame")
    frame.validate_integrity()
    encoded = canonical_json_bytes(_frame_payload(frame)) + b"\n"
    if len(encoded) > MAX_SUPERVISOR_WIRE_FRAME_BYTES:
        raise ValueError("resolver supervisor wire frame exceeds its byte limit")
    return encoded


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    selected: dict[str, object] = {}
    for key, value in pairs:
        if key in selected:
            raise ValueError("duplicate supervisor wire object key")
        selected[key] = value
    return selected


def _parse_json_int(value: str) -> int:
    if len(value) > 19:
        raise ValueError("supervisor wire integer is too large")
    return int(value)


def _reject_json_number(value: str) -> object:
    del value
    raise ValueError("unsupported supervisor wire JSON number")


def _decode_uuid(value: object, name: str) -> UUID:
    if type(value) is not str:
        raise ValueError(f"{name} must be a canonical UUID string")
    selected = UUID(value)
    if str(selected) != value:
        raise ValueError(f"{name} must be a canonical UUID string")
    return selected


def _decode_optional_uuid(value: object, name: str) -> UUID | None:
    if value is None:
        return None
    return _decode_uuid(value, name)


def _decode_digest(value: object, name: str) -> Digest256:
    if type(value) is not str:
        raise ValueError(f"{name} must be a canonical Digest256 string")
    return Digest256(value)


def _decode_optional_digest(value: object, name: str) -> Digest256 | None:
    if value is None:
        return None
    return _decode_digest(value, name)


def _decode_enum(value: object, enum_type: type[Enum], name: str) -> Enum:
    if type(value) is not str:
        raise ValueError(f"{name} must be a wire enum string")
    return enum_type(value)


def _decode_payload(
    kind: _SupervisorWireKind,
    payload: object,
) -> dict[str, object]:
    selected = _require_exact_fields(payload, _PAYLOAD_FIELDS[kind])
    decoded = dict(selected)
    uuid_fields = {
        _SupervisorWireKind.RESERVE: (
            "lifecycle_id",
            "publication_id",
        ),
        _SupervisorWireKind.ATTACH: (
            "command_id",
            "proxy_id",
            "publication_id",
        ),
        _SupervisorWireKind.ARM: ("command_id", "proxy_id"),
        _SupervisorWireKind.CANCEL: ("command_id", "proxy_id"),
        _SupervisorWireKind.QUERY: ("proxy_id", "query_id"),
        _SupervisorWireKind.RELEASE: ("proxy_id", "tombstone_id"),
        _SupervisorWireKind.ACK: ("acked_frame_id",),
        _SupervisorWireKind.STATE: ("proxy_id", "query_id"),
    }[kind]
    digest_fields = {
        _SupervisorWireKind.RESERVE: ("spawn_request_digest",),
        _SupervisorWireKind.ATTACH: (
            "publication_proof_digest",
            "reservation_attestation_digest",
        ),
        _SupervisorWireKind.ARM: (),
        _SupervisorWireKind.CANCEL: ("cancel_payload_digest",),
        _SupervisorWireKind.QUERY: (),
        _SupervisorWireKind.RELEASE: ("terminal_attestation_digest",),
        _SupervisorWireKind.ACK: (
            "acked_frame_digest",
            "attestation_digest",
        ),
        _SupervisorWireKind.STATE: ("attestation_digest",),
    }[kind]
    for name in uuid_fields:
        decoded[name] = _decode_uuid(decoded[name], name)
    for name in digest_fields:
        decoded[name] = _decode_digest(decoded[name], name)

    if kind is _SupervisorWireKind.ACK:
        decoded["acked_kind"] = _decode_enum(
            decoded["acked_kind"], _SupervisorWireKind, "acked_kind"
        )
        decoded["proxy_id"] = _decode_optional_uuid(
            decoded["proxy_id"], "proxy_id"
        )
    elif kind is _SupervisorWireKind.STATE:
        optional_uuids = (
            "arm_command_id",
            "attachment_command_id",
            "cancel_command_id",
            "close_action_id",
            "ready_event_id",
            "reap_action_id",
            "release_tombstone_id",
            "result_event_id",
            "success_cleanup_event_id",
            "spawn_event_id",
            "start_command_id",
            "terminal_attestation_id",
            "terminate_action_id",
        )
        optional_digests = (
            "attachment_proof_digest",
            "cancel_payload_digest",
            "result_digest",
            "durable_eof_ack_digest",
            "start_payload_digest",
        )
        for name in optional_uuids:
            decoded[name] = _decode_optional_uuid(decoded[name], name)
        for name in optional_digests:
            decoded[name] = _decode_optional_digest(decoded[name], name)
        decoded["cleanup_phase"] = _decode_enum(
            decoded["cleanup_phase"],
            _SupervisorWireCleanupPhase,
            "cleanup_phase",
        )
        if decoded["poison_reason"] is not None:
            decoded["poison_reason"] = _decode_enum(
                decoded["poison_reason"],
                _SupervisorWirePoisonReason,
                "poison_reason",
            )
        decoded["state"] = _decode_enum(
            decoded["state"], _SupervisorWireState, "state"
        )
        if decoded["terminal_kind"] is not None:
            decoded["terminal_kind"] = _decode_enum(
                decoded["terminal_kind"],
                _SupervisorWireTerminalKind,
                "terminal_kind",
            )
    return _validate_payload(kind, decoded)


def _decode_supervisor_wire_frame(frame: bytes) -> _SupervisorWireFrame:
    selected: _SupervisorWireFrame | None = None
    try:
        if type(frame) is not bytes:
            raise ValueError("supervisor wire input must be bytes")
        if not frame or len(frame) > MAX_SUPERVISOR_WIRE_FRAME_BYTES:
            raise ValueError("supervisor wire frame byte limit")
        if not frame.endswith(b"\n") or b"\n" in frame[:-1]:
            raise ValueError("supervisor wire frame delimiter is invalid")
        body = frame[:-1]
        if not body or body.startswith(b"\xef\xbb\xbf"):
            raise ValueError("supervisor wire frame body is invalid")
        parsed = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_int=_parse_json_int,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
        if canonical_json_bytes(parsed) != body:
            raise ValueError("supervisor wire frame is not canonical JSON")
        if type(parsed) is not dict or set(parsed) != _TOP_LEVEL_FIELDS:
            raise ValueError("supervisor wire envelope fields are invalid")
        if (
            parsed["protocol_version"] != SUPERVISOR_WIRE_PROTOCOL_VERSION
            or parsed["schema_version"]
            != SUPERVISOR_WIRE_FRAME_SCHEMA_VERSION
        ):
            raise ValueError("supervisor wire version is invalid")
        kind = _decode_enum(parsed["kind"], _SupervisorWireKind, "kind")
        if type(kind) is not _SupervisorWireKind:
            raise ValueError("supervisor wire kind is invalid")
        selected = _new_supervisor_wire_frame(
            kind=kind,
            epoch_id=_decode_uuid(parsed["epoch_id"], "epoch_id"),
            operation_id=_decode_uuid(
                parsed["operation_id"], "operation_id"
            ),
            control_channel_id=_decode_uuid(
                parsed["control_channel_id"], "control_channel_id"
            ),
            operation_binding_digest=_decode_digest(
                parsed["operation_binding_digest"],
                "operation_binding_digest",
            ),
            frame_id=_decode_uuid(parsed["frame_id"], "frame_id"),
            payload=_decode_payload(kind, parsed["payload"]),
        )
        if _encode_supervisor_wire_frame(selected) != frame:
            raise ValueError("supervisor wire frame did not round-trip")
    except Exception:
        selected = None
    if selected is None:
        raise ValueError(_INVALID_FRAME_MESSAGE) from None
    return selected
