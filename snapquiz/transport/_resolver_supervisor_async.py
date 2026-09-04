"""Injected W09-B2b-S4 async supervisor event-owner integration.

This module is deliberately private and is not production wiring.  It wraps
the S3 wire-validating in-memory channel with one event owner.  The owner is
the sole linearization point for ARM, CANCEL, worker SPAWN_DONE delivery and
the actual START datagram claim/write/commit critical section.

The spawn worker and child are injected structural contracts.  No process,
DNS, socket, credential or network primitive is imported here.  A synchronous
worker runs on a daemon thread, but its return value is only an untrusted
mailbox item until the event owner freezes the exact child object and PID.
"""
from __future__ import annotations

from threading import Lock, Thread
from typing import Callable, NoReturn
from uuid import UUID

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_output_cache as output_cache
from snapquiz.transport import _resolver_supervisor_contract as contract
from snapquiz.transport import _resolver_supervisor_proxy as proxy_module
from snapquiz.transport import _resolver_supervisor_wire as wire
from snapquiz.transport import resolver


__all__ = ()


ASYNC_SUPERVISOR_SCHEMA_VERSION = "snapquiz.resolver-supervisor-async.v1"

# S4d is an injected local contract.  No signed/native pipe owner is wired.
LOCAL_DURABLE_OUTPUT_INTEGRATION_AVAILABLE = True
PRODUCTION_DURABLE_OUTPUT_INTEGRATION_AVAILABLE = False

_ASYNC_CHANNEL_AUTHORITY = object()
_EVENT_OWNER_AUTHORITY = object()
_READY_READ_UNKNOWN = object()
_MAX_PENDING_CONTROL_EVENTS = 64
_MAX_ACTIVE_OPERATIONS = 64
_MAX_RELEASED_OPERATION_TOMBSTONES = 256
_CONTROL_INBOX_BUSY = object()
_CONTROL_INBOX_QUEUED = object()
_CONTROL_INBOX_REPLAY = object()
_SPAWN_PUBLICATION_BEGUN = object()
_SPAWN_PUBLICATION_FAILED_BEFORE_CREATE = object()
_SPAWN_RECOVERY_ANCHOR_OWNED = object()
_SPAWN_RECOVERY_ANCHOR_FAILED_BEFORE_CREATE = object()
_SPAWN_RECOVERY_ANCHOR_UNRESOLVED = object()
_SPAWN_OUTCOME_CONSUMED = object()
_SPAWN_OUTCOME_DELIVERY_RECEIPT = object()


def _async_error(message: str) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="resolver_supervisor_async",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_async_error(message: str) -> NoReturn:
    raise _async_error(message) from None


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


def _require_child(child: object) -> int:
    if child is None:
        raise TypeError("child must be an identity object")
    pid = require_plain_int(getattr(child, "pid", None), "pid", minimum=1)
    required = (
        "write_start_datagram",
        "terminate_exact",
        "reap_exact",
        "close_exact",
    )
    legacy_output = callable(getattr(child, "read_stdout", None))
    durable_output = all(
        callable(getattr(child, name, None))
        for name in ("observe_stdout_durable", "ack_stdout_durable")
    )
    if (
        any(not callable(getattr(child, name, None)) for name in required)
        or not (legacy_output or durable_output)
    ):
        raise TypeError("child must implement the injected child contract")
    return pid


class _SpawnOutcome:
    __slots__ = (
        "operation_id",
        "child",
        "failed",
        "uncertain",
        "source_unresolved",
        "source_retire_ready",
        "child_pid",
        "terminate_state",
        "reap_state",
        "close_state",
        "exit_status",
    )

    def __init__(
        self,
        *,
        operation_id: UUID,
        child: object,
        failed: bool,
        uncertain: bool = False,
        source_unresolved: bool = False,
        source_retire_ready: bool = True,
    ) -> None:
        self.operation_id = require_uuid(operation_id, "operation_id")
        self.child = child
        self.failed = failed
        self.uncertain = uncertain
        self.source_unresolved = source_unresolved
        self.source_retire_ready = source_retire_ready
        self.child_pid = None
        self.terminate_state = "idle"
        self.reap_state = "idle"
        self.close_state = "idle"
        self.exit_status = None


class _QueuedControl:
    __slots__ = ("frame_bytes", "command", "local_publication_proof")

    def __init__(
        self,
        *,
        frame_bytes: bytes,
        command: wire._SupervisorWireFrame,
        local_publication_proof: object,
    ) -> None:
        if type(frame_bytes) is not bytes:
            raise TypeError("frame_bytes must be bytes")
        command.validate_integrity()
        self.frame_bytes = frame_bytes
        self.command = command
        self.local_publication_proof = local_publication_proof


class _EventInbox:
    """CPython-atomic, insertion-ordered event publication ledger.

    A plain deque cannot deduplicate a control frame before appending it, so
    repeated delivery while the event owner is busy can grow without bound.
    ``dict.setdefault`` gives this injected CPython layer one atomic
    publication point: an async exception after the call still leaves the
    exact event discoverable, while exact retries reuse the existing entry.
    The dict's insertion order is also the control/worker linearization order.
    """

    __slots__ = ("_ordered", "_outcome_operation_ids")

    def __init__(self) -> None:
        self._ordered: dict[tuple[object, ...], object] = {}
        self._outcome_operation_ids: set[UUID] = set()

    def __bool__(self) -> bool:
        return bool(self._ordered)

    def __len__(self) -> int:
        snapshot = self._ordered.copy()
        return sum(
            event is not _SPAWN_OUTCOME_DELIVERY_RECEIPT
            for event in snapshot.values()
        )

    def __getitem__(self, index: int) -> object:
        snapshot = self._ordered.copy()
        if index != 0:
            raise IndexError(index)
        for event in snapshot.values():
            if event is not _SPAWN_OUTCOME_DELIVERY_RECEIPT:
                return event
        raise IndexError(index)

    def publish_outcome(self, outcome: _SpawnOutcome) -> object:
        key = (
            "spawn",
            outcome.operation_id,
            id(outcome.child),
            outcome.failed,
            outcome.uncertain,
            outcome.source_unresolved,
            outcome.source_retire_ready,
        )
        # Publish the conservative operation fence before the event.  A worker
        # paused between these two atomic operations remains visible through
        # both its source and this index; an event can never be consumed first
        # and make a live worker disappear from epoch readiness.
        self._outcome_operation_ids.add(outcome.operation_id)
        retained = self._ordered.setdefault(key, outcome)
        return retained

    def pending_outcome_operation_ids(self) -> set[UUID]:
        # ``set.copy`` is one bounded CPython operation; worker publishers only
        # add here, while retirement is serialized by the event-owner lock.
        return self._outcome_operation_ids.copy()

    def outcome_receipt_operation_ids(self) -> set[UUID]:
        snapshot = self._ordered.copy()
        return {
            key[1]
            for key, event in snapshot.items()
            if (
                type(key) is tuple
                and len(key) == 7
                and key[0] == "spawn"
                and type(key[1]) is UUID
                and event is _SPAWN_OUTCOME_DELIVERY_RECEIPT
            )
        }

    def has_pending_outcome(self, operation_id: UUID) -> bool:
        checked = require_uuid(operation_id, "operation_id")
        # dict.copy is one bounded CPython operation and cannot interleave with
        # the worker's C-level setdefault publication.  Iterating the live
        # values view here would otherwise raise when a worker publishes.
        snapshot = self._ordered.copy()
        return any(
            type(event) is _SpawnOutcome
            and event.operation_id == checked
            for event in snapshot.values()
        )

    def has_outcome_index(self, operation_id: UUID) -> bool:
        return (
            require_uuid(operation_id, "operation_id")
            in self._outcome_operation_ids.copy()
        )

    def release_outcome_operation(self, operation_id: UUID) -> None:
        """Release the conservative index only after source quiescence."""

        checked = require_uuid(operation_id, "operation_id")
        snapshot = self._ordered.copy()
        for key, event in snapshot.items():
            if (
                type(key) is tuple
                and len(key) == 7
                and key[0] == "spawn"
                and key[1] == checked
                and event is _SPAWN_OUTCOME_DELIVERY_RECEIPT
            ):
                self._ordered.pop(key, None)
        self._outcome_operation_ids.discard(checked)

    def publish_control(
        self,
        control: _QueuedControl,
    ) -> tuple[object, bool, bool]:
        key = ("control", control.command.frame_id)
        present = self._ordered.get(key)
        if present is not None:
            return present, False, False
        if self.pending_control_count() >= _MAX_PENDING_CONTROL_EVENTS:
            return control, False, True
        existing = self._ordered.setdefault(key, control)
        inserted = existing is control
        overflow = inserted and self.pending_control_count() > (
            _MAX_PENDING_CONTROL_EVENTS
        )
        return existing, inserted, overflow

    def control_for(self, frame_id: UUID) -> object:
        return self._ordered.get(("control", frame_id))

    def popleft(self) -> object:
        snapshot = self._ordered.copy()
        for key, event in snapshot.items():
            if event is _SPAWN_OUTCOME_DELIVERY_RECEIPT:
                continue
            if type(event) is _SpawnOutcome:
                # Do not create a remove/reinsert gap for a worker that lost
                # the return from its already committed setdefault.  This
                # primitive receipt occupies the exact semantic event key
                # until the pre-held worker source is observably stopped.
                self._ordered[key] = _SPAWN_OUTCOME_DELIVERY_RECEIPT
            else:
                self._ordered.pop(key)
            return event
        raise IndexError("pop from an empty event inbox")

    def pending_control_count(self) -> int:
        # Worker outcomes are published without the control-inbox lock, so
        # count from the same atomic CPython snapshot used above.
        snapshot = self._ordered.copy()
        return sum(key[0] == "control" for key in snapshot)

    def discard_operation(
        self,
        operation_id: UUID,
    ) -> tuple[_SpawnOutcome, ...]:
        checked = require_uuid(operation_id, "operation_id")
        late = []
        snapshot = self._ordered.copy()
        for key, event in snapshot.items():
            if type(event) is _SpawnOutcome and event.operation_id == checked:
                if event.child is not None:
                    late.append(event)
                else:
                    self._ordered[key] = (
                        _SPAWN_OUTCOME_DELIVERY_RECEIPT
                    )
            elif (
                type(event) is _QueuedControl
                and event.command.operation_id == checked
            ):
                self._ordered.pop(key, None)
        return tuple(late)

    def discard_exact(self, event: object) -> bool:
        snapshot = self._ordered.copy()
        for key, retained in snapshot.items():
            if retained is event:
                if type(event) is _SpawnOutcome:
                    self._ordered[key] = (
                        _SPAWN_OUTCOME_DELIVERY_RECEIPT
                    )
                else:
                    self._ordered.pop(key, None)
                return True
        return False


class _FrozenChild:
    __slots__ = ("child", "pid")

    def __init__(self, child: object) -> None:
        self.pid = _require_child(child)
        self.child = child


class _SpawnConstructionPublication:
    """Pre-held worker-to-event-owner child construction ledger.

    The event owner creates and retains this slot before ``Thread.start``.
    A conforming injected worker calls ``begin`` before any resource
    acquisition and publishes the exact child immediately after creation.
    The plain dict operations are deliberate CPython publication points: if a
    return-event interruption loses the callee result, the exact child remains
    recoverable from this independently held object.
    """

    __slots__ = ("operation_id", "binding_digest", "_state")

    def __init__(
        self,
        *,
        operation_id: UUID,
        binding_digest: Digest256,
    ) -> None:
        object.__setattr__(
            self,
            "operation_id",
            require_uuid(operation_id, "operation_id"),
        )
        object.__setattr__(
            self,
            "binding_digest",
            require_digest(binding_digest, "binding_digest"),
        )
        object.__setattr__(
            self,
            "_state",
            {
                "issued_operation_id": self.operation_id,
                "issued_binding_digest": self.binding_digest,
            },
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SpawnConstructionPublication identity is immutable")

    def _validate_identity(self) -> None:
        state = self._state.copy()
        if (
            state.get("issued_operation_id") != self.operation_id
            or state.get("issued_binding_digest") != self.binding_digest
        ):
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction publication identity 已变化。")

    def matches(
        self,
        operation_id: UUID,
        binding_digest: Digest256,
    ) -> bool:
        state = self._state.copy()
        return (
            type(operation_id) is UUID
            and type(binding_digest) is Digest256
            and state.get("issued_operation_id") == operation_id
            and state.get("issued_binding_digest") == binding_digest
            and self.operation_id == operation_id
            and self.binding_digest == binding_digest
        )

    def mark_conflict(self) -> None:
        self._state.setdefault("conflict", True)

    def attach_thread(self, thread: Thread) -> None:
        self._validate_identity()
        if not callable(getattr(thread, "is_alive", None)):
            raise TypeError("thread must expose is_alive")
        retained = self._state.setdefault("thread", thread)
        if retained is not thread:
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction worker thread 已变化。")

    def attach_recovery_anchor(self, child: object) -> object:
        """Retain a pre-created child facade before native acquisition.

        The facade is not treated as an owned child until its recovery method
        proves an exact native publication.  Retaining it first closes the
        successful native-return/Python-publication gap without inventing a
        zero-resource success.
        """

        self._validate_identity()
        retained = self._state.setdefault("recovery_anchor", child)
        if retained is not child:
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction recovery anchor 已变化。")
        try:
            _require_child(child)
        except BaseException:
            self._state.setdefault("conflict", True)
            raise
        if self._state.get("begun") is not _SPAWN_PUBLICATION_BEGUN:
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction recovery anchor 顺序无效。")
        return self

    def worker_thread(self) -> object:
        return self._state.copy().get("thread")

    def begin(self) -> object:
        self._validate_identity()
        retained = self._state.setdefault(
            "begun",
            _SPAWN_PUBLICATION_BEGUN,
        )
        if retained is not _SPAWN_PUBLICATION_BEGUN:
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction publication begin 冲突。")
        return self

    def publish(self, child: object) -> _FrozenChild:
        self._validate_identity()
        # Retain the raw identity before validation so an interruption after
        # this atomic publication can be recovered and validation retried.
        retained_child = self._state.setdefault("child", child)
        if retained_child is not child:
            # ``begin`` grants exactly one construction/publication permit.
            # Ownership of any additional object never transfers into this
            # bounded slot and remains with the injected worker/caller.
            self._state.setdefault("conflict", True)
            _raise_async_error(
                "spawn construction one-child publication 已被占用。"
            )
        candidate = _FrozenChild(retained_child)
        retained = self._state.setdefault("frozen", candidate)
        if (
            type(retained) is not _FrozenChild
            or retained.child is not retained_child
            or retained.pid != candidate.pid
        ):
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction frozen child 已变化。")
        if (
            self._state.get("begun") is not _SPAWN_PUBLICATION_BEGUN
            or self._state.get("failure")
            is _SPAWN_PUBLICATION_FAILED_BEFORE_CREATE
        ):
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction publication ordering 无效。")
        return retained

    def fail_before_create(self) -> object:
        self._validate_identity()
        if (
            self._state.get("begun") is not _SPAWN_PUBLICATION_BEGUN
            or "child" in self._state
        ):
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction zero-child proof 无效。")
        retained = self._state.setdefault(
            "failure",
            _SPAWN_PUBLICATION_FAILED_BEFORE_CREATE,
        )
        if retained is not _SPAWN_PUBLICATION_FAILED_BEFORE_CREATE:
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction zero-child proof 冲突。")
        return resolver.COMPLETE

    def snapshot(
        self,
    ) -> tuple[bool, bool, _FrozenChild | None, object, bool]:
        """Return construction facts; the fourth compatibility field is None."""

        state = self._state.copy()
        identity_conflicted = (
            state.get("issued_operation_id") != self.operation_id
            or state.get("issued_binding_digest") != self.binding_digest
        )
        if identity_conflicted:
            # Identity poison must not hide an already published child.  The
            # issued state remains a cleanup-only recovery authority even
            # though it can no longer authorize business progress.
            self._state.setdefault("conflict", True)
        anchor = state.get("recovery_anchor")
        raw_child = state.get("child")
        if anchor is not None and raw_child is None:
            recover = getattr(anchor, "recover_construction_exact", None)
            try:
                recovered = recover() if callable(recover) else None
            except BaseException:
                recovered = None
            if recovered is _SPAWN_RECOVERY_ANCHOR_OWNED:
                retained_child = self._state.setdefault("child", anchor)
                if retained_child is not anchor:
                    self._state.setdefault("conflict", True)
            elif recovered is _SPAWN_RECOVERY_ANCHOR_FAILED_BEFORE_CREATE:
                retained_failure = self._state.setdefault(
                    "failure",
                    _SPAWN_PUBLICATION_FAILED_BEFORE_CREATE,
                )
                if retained_failure is not _SPAWN_PUBLICATION_FAILED_BEFORE_CREATE:
                    self._state.setdefault("conflict", True)
            elif recovered is not _SPAWN_RECOVERY_ANCHOR_UNRESOLVED:
                self._state.setdefault("conflict", True)
            else:
                self._state.setdefault("conflict", True)
            state = self._state.copy()
        frozen = state.get("frozen")
        raw_child = state.get("child")
        if anchor is not None and raw_child is not None and raw_child is not anchor:
            self._state.setdefault("conflict", True)
        if raw_child is not None and frozen is None:
            # A prior interruption may have landed after raw identity
            # publication but before validation/freeze.  Complete that exact
            # publication here; never call the worker again.
            try:
                candidate = _FrozenChild(raw_child)
            except Exception:
                self._state.setdefault("conflict", True)
                self._state.setdefault("conflict_child", raw_child)
            else:
                frozen = self._state.setdefault("frozen", candidate)
                if (
                    type(frozen) is not _FrozenChild
                    or frozen.child is not raw_child
                    or frozen.pid != candidate.pid
                ):
                    self._state.setdefault("conflict", True)
        elif frozen is not None and (
            type(frozen) is not _FrozenChild
            or frozen.child is not raw_child
        ):
            self._state.setdefault("conflict", True)
        state = self._state.copy()
        selected = state.get("frozen")
        if type(selected) is not _FrozenChild:
            selected = None
        return (
            state.get("begun") is _SPAWN_PUBLICATION_BEGUN,
            state.get("failure")
            is _SPAWN_PUBLICATION_FAILED_BEFORE_CREATE,
            selected,
            None,
            state.get("conflict") is True or identity_conflicted,
        )

    def release_child(self) -> None:
        # Owner-only heavy-reference release.  Each pop is independently
        # idempotent across callback/return interruption gaps.
        state = self._state.copy()
        if (
            state.get("issued_operation_id") != self.operation_id
            or state.get("issued_binding_digest") != self.binding_digest
        ):
            # Identity mismatch remains poisoned, but after exact outcome
            # cleanup it must not pin a now-closed child forever.
            self._state.setdefault("conflict", True)
        self._state.pop("frozen", None)
        self._state.pop("child", None)
        self._state.pop("recovery_anchor", None)
        self._state.pop("thread", None)

    def has_child_reference(self) -> bool:
        state = self._state.copy()
        return any(
            state.get(name) is not None
            for name in ("frozen", "child", "recovery_anchor")
        )

    def mark_outcome_consumed(self, outcome: _SpawnOutcome) -> None:
        state = self._state.copy()
        if state.get("issued_operation_id") != outcome.operation_id:
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction outcome identity 已变化。")
        if outcome.source_unresolved:
            self._state.setdefault("source_unresolved", True)
            return
        if not outcome.source_retire_ready:
            return
        retained = self._state.setdefault(
            "outcome_consumed",
            _SPAWN_OUTCOME_CONSUMED,
        )
        if retained is not _SPAWN_OUTCOME_CONSUMED:
            self._state.setdefault("conflict", True)
            _raise_async_error("spawn construction outcome receipt 冲突。")

    def source_retirement_ready(self) -> bool:
        state = self._state.copy()
        return (
            state.get("outcome_consumed") is _SPAWN_OUTCOME_CONSUMED
            and state.get("source_unresolved") is not True
        )


class _StartRecord:
    __slots__ = ("frame", "payload_digest")

    def __init__(self, frame: bytes) -> None:
        if type(frame) is not bytes or not frame:
            raise TypeError("frame must be non-empty bytes")
        self.frame = frame
        self.payload_digest = require_digest(
            resolver.start_frame_digest(frame),
            "payload_digest",
        )


class _AsyncOperation:
    __slots__ = (
        "binding",
        "proxy_id",
        "worker_state",
        "worker_thread",
        "worker_publication",
        "outcome_consumed",
        "construction_uncertain",
        "frozen_child",
        "spawn_event_id",
        "ready_event_id",
        "ready_observation",
        "result_event_id",
        "output_cache",
        "output_publication",
        "output_mode",
        "success_cleanup_event_id",
        "terminal_attestation_id",
        "terminate_action_id",
        "reap_action_id",
        "close_action_id",
        "terminate_state",
        "reap_state",
        "close_state",
        "exit_status",
        "start_command_id",
        "start_record",
        "start_state",
        "emergency_cleaned",
    )

    def __init__(
        self,
        *,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
    ) -> None:
        binding.validate_integrity()
        self.binding = binding
        self.proxy_id = require_uuid(proxy_id, "proxy_id")
        self.worker_state = "idle"
        self.worker_thread: Thread | None = None
        self.worker_publication: _SpawnConstructionPublication | None = None
        self.outcome_consumed = False
        self.construction_uncertain = False
        self.frozen_child: _FrozenChild | None = None
        self.spawn_event_id = proxy_module._bound_role_uuid(
            binding,
            "s4-spawn-done",
        )
        self.ready_event_id = proxy_module._bound_role_uuid(
            binding,
            "s4-ready",
        )
        self.ready_observation: object = None
        self.result_event_id = proxy_module._bound_role_uuid(
            binding,
            "s4-result",
        )
        self.output_cache = output_cache._new_resolver_output_cache(
            epoch_id=binding.epoch_id,
            operation_id=binding.operation_id,
            proxy_id=self.proxy_id,
            operation_binding_digest=binding.binding_digest,
        )
        self.output_publication: object = None
        self.output_mode: str | None = None
        self.success_cleanup_event_id = proxy_module._bound_role_uuid(
            binding,
            "s4-success-cleanup-ready",
        )
        self.terminal_attestation_id = proxy_module._bound_role_uuid(
            binding,
            "s4-terminal",
        )
        self.terminate_action_id = proxy_module._bound_role_uuid(
            binding,
            "s4-terminate",
        )
        self.reap_action_id = proxy_module._bound_role_uuid(
            binding,
            "s4-reap",
        )
        self.close_action_id = proxy_module._bound_role_uuid(
            binding,
            "s4-close",
        )
        self.terminate_state = "idle"
        self.reap_state = "idle"
        self.close_state = "idle"
        self.exit_status: int | None = None
        self.start_command_id = proxy_module._bound_role_uuid(
            binding,
            "s4-start",
        )
        self.start_record: _StartRecord | None = None
        self.start_state = "idle"
        self.emergency_cleaned = False

    @property
    def child(self) -> object:
        frozen = self.frozen_child
        return None if frozen is None else frozen.child

    @property
    def child_pid(self) -> int | None:
        frozen = self.frozen_child
        return None if frozen is None else frozen.pid


@runtime_final
class _AsyncSupervisorEventOwner:
    """The only owner allowed to order control, worker and OS-like actions."""

    __slots__ = (
        "_base",
        "_worker",
        "_lock",
        "_control_inbox_lock",
        "_events",
        "_operations",
        "_proxies",
        "_released_operations",
        "_late_child_tombstones",
        "_worker_sources",
        "_worker_publications",
        "_crash_reason",
    )

    def __init__(
        self,
        *,
        base: proxy_module._InMemorySupervisorChannel,
        worker: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _EVENT_OWNER_AUTHORITY:
            raise TypeError("async event owner requires its channel")
        spawn = getattr(worker, "spawn", None)
        if not callable(spawn):
            raise TypeError("worker must implement synchronous spawn")
        object.__setattr__(self, "_base", base)
        object.__setattr__(self, "_worker", worker)
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_control_inbox_lock", Lock())
        object.__setattr__(self, "_events", _EventInbox())
        object.__setattr__(self, "_operations", {})
        object.__setattr__(self, "_proxies", {})
        object.__setattr__(self, "_released_operations", {})
        object.__setattr__(self, "_late_child_tombstones", {})
        object.__setattr__(self, "_worker_sources", set())
        object.__setattr__(self, "_worker_publications", {})
        object.__setattr__(self, "_crash_reason", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AsyncSupervisorEventOwner identity is immutable")

    def preflight_admission(self) -> object:
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            self._recover_stopped_worker_publications()
            self._release_quiescent_outcome_indexes()
            self._validate_released_tombstones()
            active_ids = (
                set(self._proxies)
                | set(self._operations)
                | set(self._worker_sources)
                | set(self._worker_publications)
                | self._events.pending_outcome_operation_ids()
            )
            if len(active_ids) >= _MAX_ACTIVE_OPERATIONS:
                raise proxy_module._capacity_error(
                    "async supervisor active operation capacity 已满。"
                )
            if (
                len(active_ids | set(self._released_operations))
                >= _MAX_RELEASED_OPERATION_TOMBSTONES
            ):
                raise proxy_module._capacity_error(
                    "async supervisor epoch terminal capacity 已满。"
                )
            return resolver.COMPLETE
        finally:
            self._lock.release()

    def epoch_rotation_ready(self) -> bool:
        if not _try_acquire(self._lock):
            # Native/fixture callbacks run below the event-owner critical
            # section.  A same-thread diagnostic/reentrancy probe must fail
            # closed instead of blocking forever on this non-reentrant lock.
            return False
        try:
            self._recover_stopped_worker_publications()
            self._release_quiescent_outcome_indexes()
            if not _try_acquire(self._control_inbox_lock):
                # A control publisher may be between validation and its atomic
                # inbox publication.  Rotation cannot overtake that boundary.
                return False
            try:
                return (
                    not self._operations
                    and not self._proxies
                    # The source remains present until the exact Thread has
                    # stopped and its consumed-outcome receipt is durable.
                    and not self._worker_sources
                    and not self._worker_publications
                    and not self._events
                    and not self._events.pending_outcome_operation_ids()
                    and len(self._released_operations)
                    >= _MAX_RELEASED_OPERATION_TOMBSTONES
                )
            finally:
                self._control_inbox_lock.release()
        finally:
            self._lock.release()

    def register_proxy(self, proxy: contract._SupervisorParentProxy) -> object:
        if type(proxy) is not contract._SupervisorParentProxy:
            raise TypeError("proxy must be SupervisorParentProxy")
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            self._recover_stopped_worker_publications()
            self._release_quiescent_outcome_indexes()
            self._validate_released_tombstones()
            operation_id = proxy.binding.operation_id
            if operation_id in self._released_operations:
                _raise_async_error("async supervisor released proxy 不得重放。")
            existing = self._proxies.get(operation_id)
            if existing is not None and existing is not proxy:
                _raise_async_error("async supervisor proxy identity 已变化。")
            active_ids = (
                set(self._proxies)
                | set(self._operations)
                | set(self._worker_sources)
                | set(self._worker_publications)
                | self._events.pending_outcome_operation_ids()
            )
            if existing is None and (
                len(active_ids) >= _MAX_ACTIVE_OPERATIONS
                or len(active_ids | set(self._released_operations))
                >= _MAX_RELEASED_OPERATION_TOMBSTONES
            ):
                raise proxy_module._capacity_error(
                    "async supervisor operation capacity 已满。"
                )
            self._proxies[operation_id] = proxy
            return resolver.COMPLETE
        finally:
            self._lock.release()

    def _operation(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
    ) -> _AsyncOperation:
        binding.validate_integrity()
        checked_proxy = require_uuid(proxy_id, "proxy_id")
        released = self._released_operations.get(binding.operation_id)
        if released is not None:
            if released != self._released_snapshot(binding, checked_proxy):
                self._poison_unknown_os_action()
                _raise_async_error(
                    "async supervisor released operation binding 已变化。"
                )
            _raise_async_error("async supervisor released operation 已终结。")
        parent_proxy = self._proxies.get(binding.operation_id)
        if (
            parent_proxy is None
            or parent_proxy.proxy_id != checked_proxy
            or not _same_binding(parent_proxy.binding, binding)
        ):
            _raise_async_error("async supervisor proxy binding 无效。")
        selected = self._operations.get(binding.operation_id)
        if selected is None:
            if len(self._operations) >= _MAX_ACTIVE_OPERATIONS:
                object.__setattr__(
                    self,
                    "_crash_reason",
                    contract._PoisonReason.LIVENESS_LOST,
                )
                self._ensure_global_poison()
                _raise_async_error("async supervisor active operation 已满。")
            selected = _AsyncOperation(binding=binding, proxy_id=checked_proxy)
            self._operations[binding.operation_id] = selected
        elif (
            selected.proxy_id != checked_proxy
            or not _same_binding(selected.binding, binding)
        ):
            _raise_async_error("async supervisor operation reentry 已变化。")
        return selected
    def _publish_worker_outcome(self, outcome: _SpawnOutcome) -> None:
        # Worker completion is only an inbox event.  The worker never mutates
        # broker state and never acquires child ownership itself.
        while True:
            try:
                self._events.publish_outcome(outcome)
                return
            except BaseException:
                # If interruption followed the atomic setdefault, the exact
                # outcome remains discoverable and the retry reuses it.
                continue

    def _run_worker(
        self,
        operation_id: UUID,
        binding: contract._SupervisorOperationBinding,
        publication: _SpawnConstructionPublication,
    ) -> None:
        returned = _READY_READ_UNKNOWN
        binding_matches = False
        try:
            try:
                binding_matches = publication.matches(
                    operation_id,
                    binding.binding_digest,
                )
            except BaseException:
                # Pure identity inspection cannot justify starting the worker;
                # preserve the slot/source as an unresolved recovery anchor.
                binding_matches = False
            if not binding_matches:
                try:
                    publication.mark_conflict()
                except BaseException:
                    pass
            else:
                try:
                    returned = self._worker.spawn(
                        binding,
                        publication=publication,
                    )
                except BaseException:
                    # The independently held construction publication, rather
                    # than this caller local, is the recovery authority for a
                    # true callee return-event interruption.
                    pass
        finally:
            # The worker invocation occurs at most once.  Every later step is
            # reconstructible from the pre-held slot and is retried without
            # reacquiring a resource.  Event-owner stopped-thread sweeping is
            # the independent fallback if an exception lands inside this
            # finally itself.
            while True:
                try:
                    self._publish_construction_outcomes(
                        operation_id=operation_id,
                        binding_digest=binding.binding_digest,
                        publication=publication,
                        returned=returned,
                        binding_matches=binding_matches,
                    )
                    break
                except BaseException:
                    continue

    def _publish_construction_outcomes(
        self,
        *,
        operation_id: UUID,
        binding_digest: Digest256,
        publication: _SpawnConstructionPublication,
        returned: object = _READY_READ_UNKNOWN,
        binding_matches: bool | None = None,
    ) -> bool:
        if binding_matches is None:
            try:
                binding_matches = publication.matches(
                    operation_id,
                    binding_digest,
                )
            except BaseException:
                binding_matches = False
        snapshot = publication.snapshot()
        (
            begun,
            explicit_failure,
            frozen,
            conflict_child,
            conflicted,
        ) = snapshot

        child = None if frozen is None else frozen.child
        uncertain = conflicted or not binding_matches
        del conflict_child
        if returned is not _READY_READ_UNKNOWN and returned is not None:
            # The worker does not transfer authority through its return
            # value.  Success is publish(child) then return None.  Ownership
            # of any naked return remains with the injected worker/caller.
            uncertain = True

        if child is None:
            if (
                begun
                and explicit_failure
                and not conflicted
                and binding_matches
            ):
                failed = True
            else:
                # Only an explicit pre-create failure is a zero-child fact.
                # Begun-but-empty *and* pristine exceptions may hide a child
                # created by a nonconforming/nested factory.
                failed = True
                uncertain = True
        else:
            failed = False
            if explicit_failure:
                uncertain = True

        source_unresolved = uncertain and child is None
        outcomes = [(child, failed, uncertain, source_unresolved, True)]

        for (
            selected_child,
            selected_failed,
            selected_uncertain,
            selected_source_unresolved,
            selected_source_retire_ready,
        ) in outcomes:
            outcome = _SpawnOutcome(
                operation_id=operation_id,
                child=selected_child,
                failed=selected_failed,
                uncertain=selected_uncertain,
                source_unresolved=selected_source_unresolved,
                source_retire_ready=selected_source_retire_ready,
            )
            self._publish_worker_outcome(outcome)
        return source_unresolved

    def _retire_worker_source(self, operation_id: UUID) -> None:
        checked = require_uuid(operation_id, "operation_id")
        while True:
            try:
                if checked not in self._worker_sources:
                    return
                self._worker_sources.discard(checked)
            except BaseException:
                continue

    def _begin_worker(self, operation: _AsyncOperation) -> None:
        if operation.worker_state == "started":
            return
        publication = operation.worker_publication
        if publication is None:
            publication = _SpawnConstructionPublication(
                operation_id=operation.binding.operation_id,
                binding_digest=operation.binding.binding_digest,
            )
            operation.worker_publication = publication
        retained_publication = self._worker_publications.setdefault(
            operation.binding.operation_id,
            publication,
        )
        if (
            retained_publication is not publication
            or not publication.matches(
                operation.binding.operation_id,
                operation.binding.binding_digest,
            )
        ):
            self._poison_unknown_os_action()
            _raise_async_error("async supervisor worker publication 已变化。")
        thread = operation.worker_thread
        if thread is None:
            thread = Thread(
                target=self._run_worker,
                args=(
                    operation.binding.operation_id,
                    operation.binding,
                    publication,
                ),
                daemon=True,
                name=f"snapquiz-resolver-{operation.binding.operation_id}",
            )
            operation.worker_thread = thread
        publication.attach_thread(thread)
        if operation.worker_state == "start_unknown":
            # ``Thread.ident`` is retained after termination.  A non-None
            # identity proves that the exact stored Thread started; otherwise
            # do not risk starting the same request twice and publish a
            # zero-child failure instead.
            if thread.ident is None:
                object.__setattr__(
                    self,
                    "_crash_reason",
                    contract._PoisonReason.OS_ACTION_UNCERTAIN,
                )
                self._ensure_global_poison()
                return
            operation.worker_state = "started"
            return
        try:
            self._worker_sources.add(operation.binding.operation_id)
            operation.worker_state = "start_unknown"
            thread.start()
            operation.worker_state = "started"
        except BaseException:
            if thread.ident is None:
                object.__setattr__(
                    self,
                    "_crash_reason",
                    contract._PoisonReason.OS_ACTION_UNCERTAIN,
                )
                self._ensure_global_poison()
                return
            operation.worker_state = "started"

    def _queue_control(
        self,
        *,
        frame_bytes: bytes,
        command: wire._SupervisorWireFrame,
        local_publication_proof: object,
        max_wait_ns: int,
    ) -> object:
        del max_wait_ns
        selected = _QueuedControl(
            frame_bytes=frame_bytes,
            command=command,
            local_publication_proof=local_publication_proof,
        )
        if not _try_acquire(self._control_inbox_lock):
            return _CONTROL_INBOX_BUSY
        try:
            existing = self._events.control_for(command.frame_id)
            if existing is None:
                replay = self._base._replays.get(command.frame_id)
                if replay is not None:
                    if (
                        replay.frame_bytes != frame_bytes
                        or replay.frame_digest != command.frame_digest
                        or replay.local_proof is not local_publication_proof
                    ):
                        object.__setattr__(
                            self,
                            "_crash_reason",
                            contract._PoisonReason.LIVENESS_LOST,
                        )
                        self._ensure_global_poison()
                        _raise_async_error(
                            "async supervisor control replay 冲突。"
                        )
                    return _CONTROL_INBOX_REPLAY
                existing, _, overflow = self._events.publish_control(
                    selected
                )
            else:
                overflow = False
            if type(existing) is not _QueuedControl or (
                existing.frame_bytes != frame_bytes
                or existing.command.epoch_id != command.epoch_id
                or existing.command.operation_id != command.operation_id
                or existing.command.control_channel_id
                != command.control_channel_id
                or existing.command.operation_binding_digest
                != command.operation_binding_digest
                or existing.command.frame_digest != command.frame_digest
                or existing.local_publication_proof
                is not local_publication_proof
            ):
                object.__setattr__(
                    self,
                    "_crash_reason",
                    contract._PoisonReason.LIVENESS_LOST,
                )
                self._ensure_global_poison()
                _raise_async_error("async supervisor control inbox 冲突。")
            if overflow:
                object.__setattr__(
                    self,
                    "_crash_reason",
                    contract._PoisonReason.LIVENESS_LOST,
                )
                self._ensure_global_poison()
                _raise_async_error(
                    "async supervisor control inbox 超过上限。"
                )
            return _CONTROL_INBOX_QUEUED
        finally:
            self._control_inbox_lock.release()

    def _guard_unqueued_control(
        self,
        *,
        frame_bytes: bytes,
        command: wire._SupervisorWireFrame,
        local_publication_proof: object,
    ) -> bool:
        """Reject a QUERY that aliases any pending or completed frame ID."""

        if not _try_acquire(self._control_inbox_lock):
            return False
        try:
            pending = self._events.control_for(command.frame_id)
            replay = self._base._replays.get(command.frame_id)
            conflict = pending is not None and (
                type(pending) is not _QueuedControl
                or pending.frame_bytes != frame_bytes
                or pending.command.epoch_id != command.epoch_id
                or pending.command.operation_id != command.operation_id
                or pending.command.control_channel_id
                != command.control_channel_id
                or pending.command.operation_binding_digest
                != command.operation_binding_digest
                or pending.command.frame_digest != command.frame_digest
                or pending.local_publication_proof
                is not local_publication_proof
            )
            conflict = conflict or (
                replay is not None
                and (
                    replay.frame_bytes != frame_bytes
                    or replay.frame_digest != command.frame_digest
                    or replay.local_proof is not local_publication_proof
                )
            )
            if conflict:
                object.__setattr__(
                    self,
                    "_crash_reason",
                    contract._PoisonReason.LIVENESS_LOST,
                )
                self._ensure_global_poison()
                _raise_async_error("async supervisor control frame ID 冲突。")
            return True
        finally:
            self._control_inbox_lock.release()

    def _take_event(self) -> object:
        if not self._events:
            return None
        # Peek only.  The event remains durable across every exception until
        # all broker/local postconditions are independently proven.
        try:
            return self._events[0]
        except IndexError:
            # A delivery receipt is intentionally retained while its worker
            # publisher may still be unwinding.  It is a replay fence, not a
            # deliverable event.
            return None

    def _retire_event(
        self,
        event: object,
        *,
        max_wait_ns: int,
    ) -> bool:
        del max_wait_ns
        if type(event) is _QueuedControl:
            if not _try_acquire(self._control_inbox_lock):
                return False
            try:
                if self._events and self._events[0] is event:
                    self._events.popleft()
                    return True
                return False
            finally:
                self._control_inbox_lock.release()
        if self._events and self._events[0] is event:
            self._events.popleft()
            return True
        return False

    def _query(
        self,
        operation: _AsyncOperation,
    ) -> contract._SupervisorOperationAttestation:
        return self._base.ports.control.query(operation.binding)

    def _complete_spawn(self, operation: _AsyncOperation) -> bool:
        child_created = operation.child is not None
        try:
            attestation = self._base.ports.events.complete_spawn(
                operation.binding,
                event_id=operation.spawn_event_id,
                child_created=child_created,
            )
        except BaseException:
            attestation = self._query(operation)
        if (
            attestation.spawn_event_id != operation.spawn_event_id
            or attestation.spawn_created is not child_created
        ):
            return False
        if child_created and not attestation.child_ever_owned:
            _raise_async_error("async supervisor child takeover 未提交。")
        return True

    def _accept_outcome(
        self,
        outcome: _SpawnOutcome,
        *,
        max_wait_ns: int,
    ) -> bool:
        operation = self._operations.get(outcome.operation_id)
        if operation is not None and outcome.uncertain:
            operation.construction_uncertain = True
        if outcome.uncertain and self._crash_reason is None:
            # Begun-but-empty construction, identity conflict, or a worker
            # that bypassed the durable slot is never a zero-child fact.
            self._poison_unknown_os_action()
        if operation is None:
            if outcome.child is not None:
                return self._advance_unbound_outcome_cleanup(
                    outcome,
                    max_wait_ns=max_wait_ns,
                )
            return True
        if operation.outcome_consumed:
            if outcome.child is operation.child:
                return True
            if outcome.child is not None:
                return self._advance_unbound_outcome_cleanup(
                    outcome,
                    max_wait_ns=max_wait_ns,
                )
            return True
        if not outcome.failed:
            # Freeze the exact object and PID before publishing SPAWN_DONE.
            frozen = operation.frozen_child
            if frozen is None:
                candidate = _FrozenChild(outcome.child)
                for existing in self._operations.values():
                    if existing is operation or existing.frozen_child is None:
                        continue
                    if (
                        existing.child is candidate.child
                        or existing.child_pid == candidate.pid
                    ):
                        object.__setattr__(
                            self,
                            "_crash_reason",
                            contract._PoisonReason.LIVENESS_LOST,
                        )
                        try:
                            self._ensure_global_poison()
                        finally:
                            for selected in tuple(self._operations.values()):
                                self._emergency_cleanup_child(selected)
                        _raise_async_error(
                            "async supervisor child ownership 已重复。"
                        )
                operation.frozen_child = candidate
            elif frozen.child is not outcome.child:
                if not self._advance_unbound_outcome_cleanup(
                    outcome,
                    max_wait_ns=max_wait_ns,
                ):
                    return False
                self._poison_unknown_os_action()
                return True
        elif outcome.child is not None or operation.frozen_child is not None:
            _raise_async_error("async supervisor SPAWN_DONE failure 已变化。")
        if operation.child is not None and self._crash_reason is None:
            checkpoint = getattr(
                self._exact_child(operation),
                "checkpoint_liveness_exact",
                None,
            )
            if callable(checkpoint):
                try:
                    live = checkpoint(max_wait_ns=max_wait_ns)
                except BaseException:
                    live = False
                if live is resolver.PENDING:
                    # Keep the exact child-bearing outcome at the inbox head;
                    # a bounded liveness poll may be retried without spawning.
                    return False
                if live is not True:
                    object.__setattr__(
                        self,
                        "_crash_reason",
                        contract._PoisonReason.LIVENESS_LOST,
                    )
                    self._ensure_global_poison()
        if self._crash_reason is not None:
            if operation.child is None:
                operation.outcome_consumed = True
                return True
            self._emergency_cleanup_child(operation)
            if not operation.emergency_cleaned:
                # Keep the exact child-bearing outcome at the inbox head while
                # any emergency OS action remains PENDING or uncertain.
                return False
            operation.outcome_consumed = True
            return True
        if not self._complete_spawn(operation):
            return False
        operation.outcome_consumed = True
        return True

    def _after_control(
        self,
        command: wire._SupervisorWireFrame,
        result: object,
    ) -> None:
        attestation = result.attestation
        if command.kind is not wire._SupervisorWireKind.ARM:
            return
        if command.operation_id in self._released_operations:
            return
        operation = self._operation(
            attestation.binding,
            command.payload["proxy_id"],
        )
        if (
            attestation.arm_command_id == command.payload["command_id"]
            and attestation.state
            in (
                contract._BrokerOperationState.SPAWN_INFLIGHT,
                contract._BrokerOperationState.CHILD_OWNED,
                contract._BrokerOperationState.READY,
                contract._BrokerOperationState.STARTED,
                contract._BrokerOperationState.RESULT_PENDING_TERMINAL,
            )
        ):
            self._begin_worker(operation)

    def _process_one_event(
        self,
        *,
        max_wait_ns: int,
    ) -> tuple[object, object] | None:
        """Process one prior event, preserving its retry position exactly."""

        self._recover_stopped_worker_publications()
        self._release_quiescent_outcome_indexes()
        if self._crash_reason is not None:
            self._ensure_global_poison()
        else:
            start_result = self._advance_pending_start_once(
                max_wait_ns=max_wait_ns,
            )
            if start_result is not None:
                return None, start_result
        event = self._take_event()
        if event is None:
            return None
        if type(event) is _SpawnOutcome:
            try:
                accepted = self._accept_outcome(
                    event,
                    max_wait_ns=max_wait_ns,
                )
            except BaseException:
                # Peek-before-process keeps the exact outcome at queue head.
                raise
            if not accepted:
                return event, resolver.PENDING
            publication = self._worker_publications.get(event.operation_id)
            if publication is not None:
                # This cleanup-only receipt is committed before event retire.
                # Source retirement additionally requires the exact Thread to
                # be observably stopped and the operation index to exist.
                publication.mark_outcome_consumed(event)
            retired = self._retire_event(event, max_wait_ns=max_wait_ns)
            if retired:
                self._recover_stopped_worker_publications()
                self._release_quiescent_outcome_indexes()
            return event, resolver.COMPLETE
        if type(event) is not _QueuedControl:
            self._poison_unknown_os_action()
            _raise_async_error("async supervisor event inbox 已损坏。")
        if self._crash_reason is not None:
            self._retire_event(event, max_wait_ns=max_wait_ns)
            return event, resolver.PENDING
        try:
            result = self._base.exchange(
                event.frame_bytes,
                max_wait_ns=max_wait_ns,
                local_publication_proof=(
                    event.local_publication_proof
                ),
            )
        except (
            proxy_module._DefiniteSupervisorCapacityError,
            proxy_module._DefiniteSupervisorProtocolError,
        ):
            self._retire_event(event, max_wait_ns=max_wait_ns)
            raise
        except BaseException:
            return event, resolver.PENDING
        if result is resolver.PENDING:
            return event, result
        try:
            self._after_control(event.command, result)
        except BaseException:
            return event, resolver.PENDING
        self._retire_event(event, max_wait_ns=max_wait_ns)
        return event, result

    def _release_quiescent_outcome_indexes(self) -> None:
        """Forget handoff ledgers only after producer/inbox quiescence."""

        for operation_id in self._events.pending_outcome_operation_ids():
            # Only the event owner retires a source, after the exact Thread is
            # stopped and a consumed-outcome receipt is durable.  Its absence
            # therefore proves that no publisher can reinsert this outcome.
            if operation_id in self._worker_sources:
                continue
            if self._events.has_pending_outcome(operation_id):
                continue
            self._events.release_outcome_operation(operation_id)

        publications = self._worker_publications.copy()
        for operation_id, publication in publications.items():
            if operation_id in self._worker_sources:
                continue
            if self._events.has_pending_outcome(operation_id):
                continue
            operation = self._operations.get(operation_id)
            if operation is not None and not operation.outcome_consumed:
                continue
            if (
                operation is None
                and operation_id not in self._released_operations
            ):
                continue
            try:
                publication.release_child()
            except BaseException:
                # A later owner entry retries the same exact slot.  Do not
                # remove its recovery root on an interrupted heavy-ref clear.
                continue
            retained = self._worker_publications.get(operation_id)
            if retained is not publication:
                self._poison_unknown_os_action()
                _raise_async_error(
                    "async supervisor worker publication ledger 已变化。"
                )
            if (
                operation is not None
                and operation.worker_publication is publication
            ):
                operation.worker_publication = None
            self._worker_publications.pop(operation_id, None)

    def _recover_stopped_worker_publications(self) -> None:
        """Synthesize a lost worker outcome from its pre-held slot.

        This is independent of the worker's own ``finally``.  It closes the
        otherwise unavoidable Python async-exception window inside that
        finally by waiting until the exact pre-held Thread is observably
        stopped, then publishing from the slot without another spawn call.
        """

        for operation_id, publication in (
            self._worker_publications.copy().items()
        ):
            if operation_id not in self._worker_sources:
                continue
            if self._events.has_pending_outcome(operation_id):
                continue
            try:
                thread = publication.worker_thread()
                if thread is None:
                    continue
                if thread.ident is None or thread.is_alive():
                    continue
            except BaseException:
                continue
            operation = self._operations.get(operation_id)
            if publication.source_retirement_ready():
                if self._events.has_outcome_index(operation_id):
                    self._retire_worker_source(operation_id)
                else:
                    # A consumed receipt without its earlier publication fence
                    # is structural corruption.  Keep source/slot visible.
                    self._poison_unknown_os_action()
                continue
            if operation is not None:
                binding_digest = operation.binding.binding_digest
            else:
                released = self._released_operations.get(operation_id)
                if released is None:
                    self._poison_unknown_os_action()
                    continue
                binding_digest = released[5]
            try:
                self._publish_construction_outcomes(
                    operation_id=operation_id,
                    binding_digest=binding_digest,
                    publication=publication,
                )
            except BaseException:
                # Slot and source remain the durable retry anchors.
                continue

    @staticmethod
    def _exact_child(operation: _AsyncOperation) -> object:
        child = operation.child
        if child is None or _require_child(child) != operation.child_pid:
            _raise_async_error("async supervisor frozen child identity 已变化。")
        return child

    @staticmethod
    def _legacy_stdout_reader(operation: _AsyncOperation) -> object:
        child = _AsyncSupervisorEventOwner._exact_child(operation)
        reader = getattr(child, "read_stdout", None)
        if not callable(reader):
            _raise_async_error(
                "async supervisor durable-only child 拒绝 legacy stdout。"
            )
        return reader

    def _poison_unknown_os_action(self) -> None:
        object.__setattr__(
            self,
            "_crash_reason",
            contract._PoisonReason.OS_ACTION_UNCERTAIN,
        )
        self._ensure_global_poison()

    def _ensure_global_poison(self) -> None:
        reason = self._crash_reason
        if reason is None:
            return
        try:
            self._base.ports.cleanup.poison_epoch(
                reason=reason
            )
        finally:
            self._base.ports.parent_session.observe_liveness_lost(
                epoch_id=self._base.epoch_id
            )

    @staticmethod
    def _ready_is_attested(
        operation: _AsyncOperation,
        attestation: contract._SupervisorOperationAttestation,
    ) -> bool:
        return (
            attestation.ready_event_id == operation.ready_event_id
            and not attestation.cancel_latched
            and attestation.state
            in (
                contract._BrokerOperationState.READY,
                contract._BrokerOperationState.STARTED,
                contract._BrokerOperationState.RESULT_PENDING_TERMINAL,
            )
        )

    def _poison_ready_read(self, operation: _AsyncOperation) -> NoReturn:
        try:
            self._poison_unknown_os_action()
        finally:
            self._emergency_cleanup_child(operation)
        _raise_async_error("async supervisor READY read outcome 不确定。")

    def _attest_cached_ready(self, operation: _AsyncOperation) -> object:
        try:
            ready = self._base.ports.events.mark_ready(
                operation.binding,
                event_id=operation.ready_event_id,
            )
        except BaseException:
            ready = self._query(operation)
        if self._ready_is_attested(operation, ready):
            operation.ready_observation = resolver.READY_FRAME
            return resolver.READY_FRAME
        if (
            ready.ready_event_id is None
            and not ready.cancel_latched
            and ready.poison_reason is None
            and ready.state is contract._BrokerOperationState.CHILD_OWNED
        ):
            # READY is cached locally; retry only the idempotent broker event.
            return resolver.PENDING
        self._poison_ready_read(operation)

    def _recover_ready_read(self, operation: _AsyncOperation) -> object:
        observation = operation.ready_observation
        if observation == resolver.READY_FRAME:
            return self._attest_cached_ready(operation)
        if observation is None:
            # Either the read was not invoked or the child explicitly returned
            # PENDING, whose contract proves zero bytes consumed.
            return resolver.PENDING
        attestation = self._query(operation)
        if self._ready_is_attested(operation, attestation):
            operation.ready_observation = resolver.READY_FRAME
            return resolver.READY_FRAME
        # The stream call may have consumed READY even though no Python local
        # survived.  Re-reading would risk consuming RESULT as READY.
        self._poison_ready_read(operation)

    def _read_ready_once(
        self,
        operation: _AsyncOperation,
        *,
        max_bytes: int,
        max_wait_ns: int,
    ) -> object:
        if operation.ready_observation is not None:
            return self._recover_ready_read(operation)
        # Resolve the legacy capability before marking a destructive read as
        # in-flight.  A durable-only child has consumed no bytes and must fail
        # closed without being mislabeled as an uncertain stream outcome.
        reader = self._legacy_stdout_reader(operation)
        try:
            operation.ready_observation = _READY_READ_UNKNOWN
            selected = reader(
                max_bytes,
                max_wait_ns=max_wait_ns,
            )
            if selected is resolver.PENDING:
                operation.ready_observation = None
                return selected
            if (
                type(selected) is not bytes
                or len(selected) > max_bytes
                or selected != resolver.READY_FRAME
            ):
                self._poison_ready_read(operation)
            operation.ready_observation = resolver.READY_FRAME
            return self._attest_cached_ready(operation)
        except BaseException:
            if self._crash_reason is not None:
                self._ensure_global_poison()
                _raise_async_error("async supervisor READY read 已隔离。")
            if "selected" in locals():
                if selected is resolver.PENDING:
                    operation.ready_observation = None
                elif (
                    type(selected) is bytes
                    and len(selected) <= max_bytes
                    and selected == resolver.READY_FRAME
                ):
                    operation.ready_observation = resolver.READY_FRAME
            return self._recover_ready_read(operation)

    def _poison_output(
        self,
        operation: _AsyncOperation,
        message: str,
    ) -> NoReturn:
        try:
            self._poison_unknown_os_action()
        finally:
            self._emergency_cleanup_child(operation)
        _raise_async_error(message)

    @staticmethod
    def _expected_output_kind(
        sequence: int,
    ) -> output_cache._ResolverOutputKind:
        selected = {
            0: output_cache._ResolverOutputKind.READY,
            1: output_cache._ResolverOutputKind.RESULT,
            2: output_cache._ResolverOutputKind.EOF,
        }.get(sequence)
        if selected is None:
            _raise_async_error("async supervisor output sequence 已终结。")
        return selected

    def _output_state_allows(
        self,
        operation: _AsyncOperation,
        kind: output_cache._ResolverOutputKind,
    ) -> bool:
        attestation = self._query(operation)
        if attestation.cancel_latched or attestation.poison_reason is not None:
            return False
        if kind is output_cache._ResolverOutputKind.READY:
            return attestation.state in (
                contract._BrokerOperationState.CHILD_OWNED,
                contract._BrokerOperationState.READY,
            )
        if kind is output_cache._ResolverOutputKind.RESULT:
            return (
                attestation.start_committed
                and attestation.state
                in (
                    contract._BrokerOperationState.STARTED,
                    contract._BrokerOperationState.RESULT_PENDING_TERMINAL,
                )
            )
        return (
            attestation.result_event_id == operation.result_event_id
            and attestation.state
            is contract._BrokerOperationState.RESULT_PENDING_TERMINAL
        )

    def _attest_cached_result(
        self,
        operation: _AsyncOperation,
        observation: output_cache._ResolverOutputObservation,
    ) -> object:
        transcript_digest = resolver.result_transcript_digest(
            observation.payload[:-1]
        )
        try:
            attestation = self._base.ports.events.mark_result(
                operation.binding,
                event_id=operation.result_event_id,
                result_digest=transcript_digest,
            )
        except BaseException:
            attestation = self._query(operation)
        if (
            attestation.result_event_id == operation.result_event_id
            and attestation.result_digest == transcript_digest
            and attestation.state
            is contract._BrokerOperationState.RESULT_PENDING_TERMINAL
        ):
            return observation
        if (
            attestation.result_event_id is None
            and attestation.poison_reason is None
            and attestation.state is contract._BrokerOperationState.STARTED
        ):
            # The exact bytes already live in the cache.  Retrying only this
            # idempotent broker fact cannot read the child stream again.
            return resolver.PENDING
        self._poison_output(
            operation,
            "async supervisor RESULT attestation 已变化。",
        )

    def _attest_output(
        self,
        operation: _AsyncOperation,
        observation: output_cache._ResolverOutputObservation,
    ) -> object:
        if observation.kind is output_cache._ResolverOutputKind.READY:
            selected = self._attest_cached_ready(operation)
            return observation if selected == resolver.READY_FRAME else selected
        if observation.kind is output_cache._ResolverOutputKind.RESULT:
            return self._attest_cached_result(operation, observation)
        attestation = self._query(operation)
        if (
            attestation.result_event_id == operation.result_event_id
            and attestation.state
            is contract._BrokerOperationState.RESULT_PENDING_TERMINAL
        ):
            return observation
        self._poison_output(
            operation,
            "async supervisor EOF 缺少 RESULT attestation。",
        )

    def observe_stdout_durable(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        max_bytes: int,
        *,
        max_wait_ns: int,
        local_publication: object = None,
    ) -> object:
        """Return one cached observation without destructive replay.

        The injected child must publish through the supplied sink before its
        method returns.  This makes the supervisor slot observable even when
        the child-method return cannot be stored in the caller frame.
        """

        selected_wait = proxy_module._wait_limit(max_wait_ns)
        checked_max = require_plain_int(max_bytes, "max_bytes", minimum=1)
        if checked_max > output_cache.MAX_RESOLVER_OUTPUT_PAYLOAD_BYTES:
            raise ValueError("max_bytes exceeds resolver output cache limit")
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            if self._process_one_event(max_wait_ns=selected_wait) is not None:
                return resolver.PENDING
            if self._crash_reason is not None:
                self._ensure_global_poison()
                _raise_async_error("async supervisor event owner 已隔离。")
            operation = self._operation(binding, proxy_id)
            if operation.output_mode not in (None, "durable"):
                self._poison_output(
                    operation,
                    "async supervisor stdout owner mode 已变化。",
                )
            operation.output_mode = "durable"
            metadata = operation.output_cache.safe_metadata()
            sequence = metadata["next_sequence"]
            kind = self._expected_output_kind(sequence)
            if not self._output_state_allows(operation, kind):
                return resolver.PENDING
            try:
                publication = operation.output_cache.new_publication(
                    sequence=sequence,
                    kind=kind,
                )
                operation.output_publication = publication
                observation = operation.output_cache.current(publication)
            except EndpointPolicyError:
                self._poison_output(
                    operation,
                    "async supervisor output cache 已损坏。",
                )
            if observation is None:
                child = self._exact_child(operation)
                observer = getattr(child, "observe_stdout_durable", None)
                if not callable(observer):
                    _raise_async_error(
                        "async supervisor child durable output owner 缺失。"
                    )
                try:
                    observed = observer(
                        checked_max,
                        publication=publication,
                        max_wait_ns=selected_wait,
                    )
                except BaseException:
                    # A publication that happened before the interruption is
                    # retained in the cache.  No second stream read occurs.
                    raise
                try:
                    observation = operation.output_cache.current(publication)
                except EndpointPolicyError:
                    self._poison_output(
                        operation,
                        "async supervisor output publication 已损坏。",
                    )
                if observed is resolver.PENDING:
                    if observation is not None:
                        self._poison_output(
                            operation,
                            "async supervisor child output result 已变化。",
                        )
                    return observed
                if observed is not resolver.COMPLETE or observation is None:
                    self._poison_output(
                        operation,
                        "async supervisor child output publication 未提交。",
                    )
            if len(observation.payload) > checked_max:
                self._poison_output(
                    operation,
                    "async supervisor cached output 超过调用上限。",
                )
            selected = self._attest_output(operation, observation)
            if selected is resolver.PENDING:
                return selected
            if local_publication is not None:
                if type(local_publication) is not resolver._DurableOutputPublication:
                    _raise_async_error(
                        "async supervisor local output publication 无效。"
                    )
                try:
                    local_publication.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    _raise_async_error(
                        "async supervisor local output publication proof 无效。"
                    )
                published = local_publication.publish(observation)
                if published is not observation:
                    _raise_async_error(
                        "async supervisor local output publication 未提交。"
                    )
            return observation
        finally:
            self._lock.release()

    def acknowledge_stdout_durable(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        observation: object,
        *,
        max_wait_ns: int,
        local_publication: object = None,
    ) -> object:
        """ACK one exact observation; retry resolves through its tombstone."""

        selected_wait = proxy_module._wait_limit(max_wait_ns)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            if self._process_one_event(max_wait_ns=selected_wait) is not None:
                # Control/worker inbox insertion is the event-owner ordering
                # point.  In particular, a queued CANCEL must linearize before
                # a later EOF ACK can publish natural-success cleanup.
                return resolver.PENDING
            operation = self._operation(binding, proxy_id)
            if operation.output_mode != "durable":
                self._poison_output(
                    operation,
                    "async supervisor output ACK owner mode 无效。",
                )
            try:
                tombstone = operation.output_cache.acknowledged(observation)
            except EndpointPolicyError:
                self._poison_output(
                    operation,
                    "async supervisor output ACK binding 无效。",
                )
            if tombstone is not None:
                # The cache ACK may have committed before interruption left a
                # stale operation-level publication reference.  Clear it on
                # every tombstone replay before reporting completion.
                if local_publication is not None:
                    if type(local_publication) is not resolver._DurableOutputPublication:
                        _raise_async_error(
                            "async supervisor local output ACK publication 无效。"
                        )
                    try:
                        local_publication.validate_integrity()
                    except (AttributeError, TypeError, ValueError):
                        _raise_async_error(
                            "async supervisor local output ACK proof 无效。"
                        )
                    local_publication.acknowledge(observation)
                operation.output_publication = None
                if not self._commit_eof_cleanup_ready(
                    operation,
                    tombstone,
                ):
                    return resolver.PENDING
                return resolver.COMPLETE
            publication = operation.output_publication
            if publication is None:
                self._poison_output(
                    operation,
                    "async supervisor output ACK publication 缺失。",
                )
            try:
                current = operation.output_cache.current(publication)
            except EndpointPolicyError:
                self._poison_output(
                    operation,
                    "async supervisor output ACK cache 已损坏。",
                )
            if current is not observation:
                self._poison_output(
                    operation,
                    "async supervisor output ACK exact observation 缺失。",
                )
            child = self._exact_child(operation)
            acknowledger = getattr(child, "ack_stdout_durable", None)
            if not callable(acknowledger):
                _raise_async_error(
                    "async supervisor child output ACK owner 缺失。"
                )
            acked = acknowledger(
                observation,
                max_wait_ns=selected_wait,
            )
            if acked is resolver.PENDING:
                return acked
            if acked is not resolver.COMPLETE:
                self._poison_output(
                    operation,
                    "async supervisor child output ACK result 无效。",
                )
            try:
                operation.output_cache.acknowledge(observation)
            except EndpointPolicyError:
                self._poison_output(
                    operation,
                    "async supervisor output ACK commit 已损坏。",
                )
            if local_publication is not None:
                if type(local_publication) is not resolver._DurableOutputPublication:
                    _raise_async_error(
                        "async supervisor local output ACK publication 无效。"
                    )
                try:
                    local_publication.validate_integrity()
                except (AttributeError, TypeError, ValueError):
                    _raise_async_error(
                        "async supervisor local output ACK proof 无效。"
                    )
                local_publication.acknowledge(observation)
            operation.output_publication = None
            tombstone = operation.output_cache.acknowledged(observation)
            if tombstone is None:
                self._poison_output(
                    operation,
                    "async supervisor output ACK tombstone 缺失。",
                )
            if not self._commit_eof_cleanup_ready(operation, tombstone):
                return resolver.PENDING
            return resolver.COMPLETE
        finally:
            self._lock.release()

    def _commit_eof_cleanup_ready(
        self,
        operation: _AsyncOperation,
        tombstone: output_cache._ResolverOutputTombstone,
    ) -> bool:
        try:
            tombstone.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            self._poison_output(
                operation,
                "async supervisor output ACK tombstone 已损坏。",
            )
        if tombstone.kind is not output_cache._ResolverOutputKind.EOF:
            return True
        current = self._query(operation)
        if current.cancel_latched:
            # Delivery ACK and cancellation are independent durable facts.
            # Once CANCEL wins ordering, EOF must not switch cleanup to the
            # natural-exit path or introduce a false protocol conflict.
            return True
        try:
            attestation = self._base.ports.events.mark_success_cleanup_ready(
                operation.binding,
                event_id=operation.success_cleanup_event_id,
                durable_eof_ack_digest=tombstone.tombstone_digest,
            )
        except BaseException:
            attestation = self._query(operation)
        if (
            attestation.success_cleanup_event_id
            == operation.success_cleanup_event_id
            and attestation.durable_eof_ack_digest
            == tombstone.tombstone_digest
            and not attestation.cancel_latched
            and attestation.poison_reason is None
        ):
            # This marks a natural-exit path; emergency cleanup must never
            # introduce a terminate action before/after its exact reap claim.
            operation.terminate_state = "complete"
            return True
        if attestation.cancel_latched:
            return True
        if (
            attestation.state
            is contract._BrokerOperationState.RESULT_PENDING_TERMINAL
            and attestation.cleanup_phase is contract._BrokerCleanupPhase.NONE
            and attestation.success_cleanup_event_id is None
            and attestation.durable_eof_ack_digest is None
        ):
            return False
        self._poison_output(
            operation,
            "async supervisor successful cleanup fact 已变化。",
        )

    @staticmethod
    def _start_observation(
        operation: _AsyncOperation,
        record: _StartRecord,
        attestation: contract._SupervisorOperationAttestation,
    ) -> str:
        if (
            attestation.start_command_id is None
            and attestation.start_payload_digest is None
            and not attestation.start_committed
        ):
            return "unclaimed"
        if (
            attestation.start_command_id == operation.start_command_id
            and attestation.start_payload_digest == record.payload_digest
        ):
            if attestation.start_committed:
                return "committed"
            return "claimed"
        return "conflict"

    def _poison_start(self, operation: _AsyncOperation, message: str) -> NoReturn:
        operation.start_state = "poisoned"
        try:
            self._poison_unknown_os_action()
        finally:
            self._emergency_cleanup_child(operation)
        _raise_async_error(message)

    def _observe_start(
        self,
        operation: _AsyncOperation,
        record: _StartRecord,
    ) -> str:
        attestation = self._query(operation)
        observed = self._start_observation(operation, record, attestation)
        if observed == "committed":
            if attestation.state not in (
                contract._BrokerOperationState.STARTED,
                contract._BrokerOperationState.RESULT_PENDING_TERMINAL,
                contract._BrokerOperationState.TERMINAL_ATTESTED,
            ):
                self._poison_start(
                    operation,
                    "async supervisor START commit attestation 无效。",
                )
            operation.start_state = "committed"
        elif observed == "conflict" or attestation.poison_reason is not None:
            self._poison_start(
                operation,
                "async supervisor START attestation 已变化。",
            )
        return observed

    def _commit_written_start(
        self,
        operation: _AsyncOperation,
        record: _StartRecord,
    ) -> object:
        try:
            committed = self._base.ports.events.commit_start(
                operation.binding,
                command_id=operation.start_command_id,
            )
        except BaseException:
            committed = self._query(operation)
        observed = self._start_observation(operation, record, committed)
        if observed == "committed":
            operation.start_state = "committed"
            return resolver.COMPLETE
        if observed == "claimed" and committed.poison_reason is None:
            # The write is locally proven complete.  Retrying only the broker
            # commit is safe; the datagram is never written again.
            operation.start_state = "write_complete"
            return resolver.PENDING
        self._poison_start(
            operation,
            "async supervisor START commit outcome 不确定。",
        )

    def _advance_start_action(
        self,
        operation: _AsyncOperation,
        *,
        max_wait_ns: int,
    ) -> object:
        record = operation.start_record
        if record is None:
            self._poison_start(operation, "async supervisor START record 缺失。")
        if operation.start_state == "poisoned":
            try:
                self._ensure_global_poison()
            finally:
                self._emergency_cleanup_child(operation)
            _raise_async_error("async supervisor START outcome 不确定。")
        if operation.start_state == "write_unknown":
            observed = self._observe_start(operation, record)
            if observed == "committed":
                return resolver.COMPLETE
            # Once the external call might have run, an uncommitted broker
            # claim cannot authorize a second datagram write.
            self._poison_start(
                operation,
                "async supervisor START send outcome 不确定。",
            )
        if operation.start_state == "write_complete":
            return self._commit_written_start(operation, record)
        if operation.start_state == "claim_unknown":
            observed = self._observe_start(operation, record)
            if observed == "committed":
                return resolver.COMPLETE
            if observed == "unclaimed":
                operation.start_state = "idle"
                return resolver.PENDING
            operation.start_state = "claimed"
            return resolver.PENDING
        if operation.start_state != "claimed":
            _raise_async_error("async supervisor START local state 无效。")

        child = self._exact_child(operation)
        try:
            # The unknown state is inside the same catch region as the sole
            # write.  Any interruption after this transition is recovered by
            # broker query and otherwise globally poisoned without replay.
            operation.start_state = "write_unknown"
            written = child.write_start_datagram(
                record.frame,
                max_wait_ns=max_wait_ns,
            )
            if written is not resolver.COMPLETE:
                self._poison_start(
                    operation,
                    "async supervisor START send outcome 不确定。",
                )
            operation.start_state = "write_complete"
            return self._commit_written_start(operation, record)
        except BaseException:
            if operation.start_state == "poisoned":
                try:
                    self._ensure_global_poison()
                finally:
                    self._emergency_cleanup_child(operation)
                _raise_async_error("async supervisor START outcome 不确定。")
            if (
                operation.start_state == "write_unknown"
                and "written" in locals()
                and written is resolver.COMPLETE
            ):
                operation.start_state = "write_complete"
            if operation.start_state == "write_complete":
                return self._commit_written_start(operation, record)
            observed = self._observe_start(operation, record)
            if observed == "committed":
                return resolver.COMPLETE
            self._poison_start(
                operation,
                "async supervisor START send outcome 不确定。",
            )

    def _advance_pending_start_once(self, *, max_wait_ns: int) -> object:
        for operation in tuple(self._operations.values()):
            if operation.start_state in (
                "claim_unknown",
                "claimed",
                "write_unknown",
                "write_complete",
                "poisoned",
            ):
                return self._advance_start_action(
                    operation,
                    max_wait_ns=max_wait_ns,
                )
        return None

    def _cleanup_child(
        self,
        operation: _AsyncOperation,
        *,
        max_wait_ns: int,
    ) -> None:
        child = self._exact_child(operation)
        attestation = self._query(operation)
        if attestation.terminal_attestation_id is not None:
            return
        if attestation.cleanup_phase is contract._BrokerCleanupPhase.NONE:
            return

        if (
            attestation.cleanup_phase
            is contract._BrokerCleanupPhase.TERMINATE_REQUIRED
        ):
            attestation = self._recover_cleanup_mutation(
                operation,
                lambda: self._base.ports.cleanup.claim_terminate(
                    operation.binding,
                    action_id=operation.terminate_action_id,
                ),
            )
            if (
                attestation.cleanup_phase
                is contract._BrokerCleanupPhase.TERMINATE_REQUIRED
            ):
                return
        if (
            attestation.cleanup_phase
            is contract._BrokerCleanupPhase.TERMINATE_CLAIMED
        ):
            if operation.terminate_state == "unknown":
                self._poison_unknown_os_action()
                self._emergency_cleanup_child(operation)
                return
            if operation.terminate_state == "idle":
                result = None
                try:
                    operation.terminate_state = "unknown"
                    result = child.terminate_exact(
                        operation.child_pid,
                        max_wait_ns=max_wait_ns,
                    )
                    if result is resolver.PENDING:
                        operation.terminate_state = "idle"
                        return
                    if result is not resolver.COMPLETE:
                        self._poison_unknown_os_action()
                        self._emergency_cleanup_child(operation)
                        return
                    operation.terminate_state = "complete"
                except BaseException:
                    if result is resolver.PENDING:
                        operation.terminate_state = "idle"
                        return
                    if result is resolver.COMPLETE:
                        operation.terminate_state = "complete"
                    else:
                        self._poison_unknown_os_action()
                        self._emergency_cleanup_child(operation)
                        return
            self._recover_cleanup_mutation(
                operation,
                lambda: self._base.ports.cleanup.complete_terminate(
                    operation.binding,
                    action_id=operation.terminate_action_id,
                ),
            )
            return

        if (
            attestation.cleanup_phase
            is contract._BrokerCleanupPhase.REAP_REQUIRED
        ):
            attestation = self._recover_cleanup_mutation(
                operation,
                lambda: self._base.ports.cleanup.claim_reap(
                    operation.binding,
                    action_id=operation.reap_action_id,
                ),
            )
            if (
                attestation.cleanup_phase
                is contract._BrokerCleanupPhase.REAP_REQUIRED
            ):
                return
        if (
            attestation.cleanup_phase
            is contract._BrokerCleanupPhase.REAP_CLAIMED
        ):
            if operation.reap_state == "unknown":
                self._poison_unknown_os_action()
                self._emergency_cleanup_child(operation)
                return
            if operation.reap_state == "idle":
                status = None
                try:
                    operation.reap_state = "unknown"
                    status = child.reap_exact(
                        operation.child_pid,
                        max_wait_ns=max_wait_ns,
                    )
                    if status is resolver.PENDING:
                        operation.reap_state = "idle"
                        return
                    if type(status) is not int:
                        self._poison_unknown_os_action()
                        self._emergency_cleanup_child(operation)
                        return
                    operation.exit_status = status
                    operation.reap_state = "complete"
                except BaseException:
                    if status is resolver.PENDING:
                        operation.reap_state = "idle"
                        return
                    if type(status) is int:
                        operation.exit_status = status
                        operation.reap_state = "complete"
                    else:
                        self._poison_unknown_os_action()
                        self._emergency_cleanup_child(operation)
                        return
            self._recover_cleanup_mutation(
                operation,
                lambda: self._base.ports.cleanup.complete_reap(
                    operation.binding,
                    action_id=operation.reap_action_id,
                ),
            )
            return

        if (
            attestation.cleanup_phase
            is contract._BrokerCleanupPhase.CLOSE_REQUIRED
        ):
            attestation = self._recover_cleanup_mutation(
                operation,
                lambda: self._base.ports.cleanup.claim_close(
                    operation.binding,
                    action_id=operation.close_action_id,
                ),
            )
            if (
                attestation.cleanup_phase
                is contract._BrokerCleanupPhase.CLOSE_REQUIRED
            ):
                return
        if (
            attestation.cleanup_phase
            is contract._BrokerCleanupPhase.CLOSE_CLAIMED
        ):
            if operation.close_state == "unknown":
                self._poison_unknown_os_action()
                self._emergency_cleanup_child(operation)
                return
            if operation.close_state == "idle":
                result = None
                try:
                    operation.close_state = "unknown"
                    result = child.close_exact(max_wait_ns=max_wait_ns)
                    if result is resolver.PENDING:
                        operation.close_state = "idle"
                        return
                    if result is not resolver.COMPLETE:
                        self._poison_unknown_os_action()
                        self._emergency_cleanup_child(operation)
                        return
                    operation.close_state = "complete"
                except BaseException:
                    if result is resolver.PENDING:
                        operation.close_state = "idle"
                        return
                    if result is resolver.COMPLETE:
                        operation.close_state = "complete"
                    else:
                        self._poison_unknown_os_action()
                        self._emergency_cleanup_child(operation)
                        return
            attestation = self._recover_cleanup_mutation(
                operation,
                lambda: self._base.ports.cleanup.complete_close(
                    operation.binding,
                    action_id=operation.close_action_id,
                ),
            )

        if attestation.cleanup_phase is contract._BrokerCleanupPhase.COMPLETE:
            status = operation.exit_status
            if status is None:
                _raise_async_error("async supervisor exit status 缺失。")
            self._recover_cleanup_mutation(
                operation,
                lambda: self._base.ports.cleanup.attest_terminal(
                    operation.binding,
                    attestation_id=operation.terminal_attestation_id,
                    status=status,
                ),
            )

    def _recover_cleanup_mutation(
        self,
        operation: _AsyncOperation,
        mutation: Callable[[], object],
    ) -> contract._SupervisorOperationAttestation:
        """Recover broker-only callback return gaps from authority state."""

        try:
            attestation = mutation()
            attestation.validate_integrity()
        except BaseException:
            attestation = self._query(operation)
        if (
            type(attestation)
            is not contract._SupervisorOperationAttestation
            or not _same_binding(attestation.binding, operation.binding)
        ):
            _raise_async_error(
                "async supervisor cleanup mutation attestation 无效。"
            )
        return attestation

    def _advance_cleanup_once(
        self,
        *,
        max_wait_ns: int,
        operation_id: UUID | None = None,
    ) -> None:
        """Run at most one bounded terminal child action."""

        if operation_id is None:
            selected_operations = tuple(self._operations.values())
        else:
            selected = self._operations.get(operation_id)
            selected_operations = () if selected is None else (selected,)
        for operation in selected_operations:
            if operation.child is None:
                continue
            attestation = self._query(operation)
            if (
                attestation.terminal_attestation_id is None
                and (
                    attestation.cancel_latched
                    or attestation.success_cleanup_event_id is not None
                    or attestation.state is contract._BrokerOperationState.POISONED
                )
            ):
                self._cleanup_child(
                    operation,
                    max_wait_ns=max_wait_ns,
                )
                return

    def _cleanup_query_waits_for_terminal(self, operation_id: UUID) -> bool:
        operation = self._operations.get(operation_id)
        if operation is None:
            return False
        attestation = self._query(operation)
        parent_proxy = self._proxies.get(operation_id)
        if (
            parent_proxy is None
            or parent_proxy._cleanup_pending_count
            < contract.SUPERVISOR_CLEANUP_PENDING_LIMIT
        ):
            # Allow the finite parent-observation proof budget to establish
            # WAITING_SUPERVISOR first.  Only subsequent unchanged polls are
            # suppressed rather than consuming durable wire replay slots.
            return False
        return (
            attestation.terminal_attestation_id is None
            and (
                attestation.cancel_latched
                or (
                    attestation.cleanup_phase
                    is not contract._BrokerCleanupPhase.NONE
                    and (
                        attestation.success_cleanup_event_id is not None
                        or attestation.state
                        is contract._BrokerOperationState.POISONED
                    )
                )
            )
        )

    def _advance_unbound_outcome_cleanup(
        self,
        outcome: _SpawnOutcome,
        *,
        max_wait_ns: int,
    ) -> bool:
        """Advance one normal late action; salvage independent uncertain lanes."""

        if type(outcome) is not _SpawnOutcome or outcome.child is None:
            return True
        child = outcome.child
        try:
            pid = _require_child(child)
        except BaseException:
            self._poison_unknown_os_action()
            return False
        completed_pid = self._late_child_tombstones.get(outcome.operation_id)
        if completed_pid is not None:
            if completed_pid != pid:
                self._poison_unknown_os_action()
                return False
            outcome.child = None
            outcome.child_pid = pid
            outcome.terminate_state = "complete"
            outcome.reap_state = "complete"
            outcome.close_state = "complete"
            return True
        if outcome.child_pid is None:
            outcome.child_pid = pid
        elif outcome.child_pid != pid:
            self._poison_unknown_os_action()
            return False

        cleanup_uncertain = outcome.terminate_state == "unknown"
        if cleanup_uncertain:
            self._poison_unknown_os_action()
        if outcome.terminate_state == "idle":
            outcome.terminate_state = "unknown"
            try:
                selected = child.terminate_exact(pid, max_wait_ns=max_wait_ns)
            except BaseException:
                self._poison_unknown_os_action()
                cleanup_uncertain = True
                selected = None
            if selected is resolver.PENDING:
                outcome.terminate_state = "idle"
                return False
            if selected is resolver.COMPLETE:
                outcome.terminate_state = "complete"
                return False
            if selected is not None:
                self._poison_unknown_os_action()
                cleanup_uncertain = True

        if outcome.reap_state == "unknown":
            self._poison_unknown_os_action()
            cleanup_uncertain = True
        if outcome.reap_state == "idle":
            outcome.reap_state = "unknown"
            try:
                selected = child.reap_exact(pid, max_wait_ns=max_wait_ns)
            except BaseException:
                self._poison_unknown_os_action()
                cleanup_uncertain = True
                selected = None
            if selected is resolver.PENDING:
                outcome.reap_state = "idle"
                if not cleanup_uncertain:
                    return False
            elif type(selected) is int and selected >= 0:
                outcome.exit_status = selected
                outcome.reap_state = "complete"
                if not cleanup_uncertain:
                    return False
            elif selected is not None:
                self._poison_unknown_os_action()
                cleanup_uncertain = True

        if outcome.close_state == "unknown":
            self._poison_unknown_os_action()
            return False
        if outcome.close_state == "idle":
            outcome.close_state = "unknown"
            try:
                selected = child.close_exact(max_wait_ns=max_wait_ns)
            except BaseException:
                self._poison_unknown_os_action()
                return False
            if selected is resolver.PENDING:
                outcome.close_state = "idle"
                return False
            if selected is not resolver.COMPLETE:
                self._poison_unknown_os_action()
                return False
            outcome.close_state = "complete"

        # Unknown signal/wait lanes are never replayed, but they also cannot
        # strand an independent close lane.  Only an exact reap plus exact
        # descriptor closure is sufficient to retire the cleanup authority.
        if (
            outcome.reap_state != "complete"
            or outcome.close_state != "complete"
        ):
            return False

        if len(self._late_child_tombstones) >= (
            _MAX_RELEASED_OPERATION_TOMBSTONES
        ):
            self._poison_unknown_os_action()
            return False
        retained = self._late_child_tombstones.setdefault(
            outcome.operation_id,
            pid,
        )
        if retained != pid:
            self._poison_unknown_os_action()
            return False
        # Publish the primitive tombstone before releasing the sole event-owned
        # strong reference.  An exact duplicate can never repeat an OS action.
        outcome.child = None
        return True

    def _emergency_cleanup_child(self, operation: _AsyncOperation) -> None:
        if operation.emergency_cleaned or operation.child is None:
            return
        child = operation.child
        try:
            pid = _require_child(child)
        except BaseException:
            return
        if pid != operation.child_pid:
            return
        if (
            operation.terminate_state == "idle"
            and not operation.construction_uncertain
        ):
            try:
                authority = self._query(operation)
            except BaseException:
                return
            if authority.success_cleanup_event_id is not None:
                if (
                    authority.success_cleanup_event_id
                    != operation.success_cleanup_event_id
                    or authority.durable_eof_ack_digest is None
                    or authority.cancel_latched
                ):
                    return
                # The broker marker is the durable race winner.  It may have
                # committed immediately before interruption prevented the
                # equivalent local assignment; emergency cleanup must recover
                # that fact and never introduce SIGTERM on natural success.
                operation.terminate_state = "complete"
        # Each OS action has its own exact-once ledger.  An unknown signal
        # result must never be replayed, but it must not strand the independent
        # wait/descriptor-close lanes either.
        if operation.terminate_state == "idle":
            result = None
            try:
                operation.terminate_state = "unknown"
                result = child.terminate_exact(
                    pid,
                    max_wait_ns=proxy_module.MAX_SUPERVISOR_PROXY_WAIT_NS,
                )
            except BaseException:
                result = None
            if result is resolver.PENDING:
                operation.terminate_state = "idle"
            elif result is resolver.COMPLETE:
                operation.terminate_state = "complete"
        if operation.reap_state == "idle":
            status = None
            try:
                operation.reap_state = "unknown"
                status = child.reap_exact(
                    pid,
                    max_wait_ns=proxy_module.MAX_SUPERVISOR_PROXY_WAIT_NS,
                )
            except BaseException:
                status = None
            if status is resolver.PENDING:
                operation.reap_state = "idle"
            elif type(status) is int and status >= 0:
                operation.exit_status = status
                operation.reap_state = "complete"
        if operation.close_state == "idle":
            result = None
            try:
                operation.close_state = "unknown"
                result = child.close_exact(
                    max_wait_ns=proxy_module.MAX_SUPERVISOR_PROXY_WAIT_NS
                )
            except BaseException:
                result = None
            if result is resolver.PENDING:
                operation.close_state = "idle"
            elif result is resolver.COMPLETE:
                operation.close_state = "complete"
        operation.emergency_cleaned = (
            operation.terminate_state == "complete"
            and operation.reap_state == "complete"
            and operation.close_state == "complete"
        )

    def control_exchange(
        self,
        frame_bytes: bytes,
        *,
        max_wait_ns: int,
        local_publication_proof: object = None,
    ) -> object:
        selected_wait = proxy_module._wait_limit(max_wait_ns)
        try:
            command = wire._decode_supervisor_wire_frame(frame_bytes)
            if (
                command.epoch_id != self._base.epoch_id
                or command.control_channel_id
                != self._base.control_channel_id
            ):
                raise ValueError("channel binding changed")
        except (AttributeError, TypeError, ValueError):
            _raise_async_error("async supervisor command wire 无效。")
        queued = command.kind is not wire._SupervisorWireKind.QUERY
        queue_state = None
        if queued:
            queue_state = self._queue_control(
                frame_bytes=frame_bytes,
                command=command,
                local_publication_proof=local_publication_proof,
                max_wait_ns=selected_wait,
            )
            if queue_state is _CONTROL_INBOX_BUSY:
                return resolver.PENDING
        elif not self._guard_unqueued_control(
            frame_bytes=frame_bytes,
            command=command,
            local_publication_proof=local_publication_proof,
        ):
            return resolver.PENDING
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            processed = self._process_one_event(max_wait_ns=selected_wait)
            if processed is not None:
                event, result = processed
                if (
                    queue_state is _CONTROL_INBOX_QUEUED
                    and type(event) is _QueuedControl
                    and event.command.frame_id == command.frame_id
                ):
                    return result
                return resolver.PENDING
            if self._crash_reason is not None:
                return resolver.PENDING
            if queue_state is _CONTROL_INBOX_QUEUED:
                # The exact queued mutation must have been selected above.
                # Reaching here means event queue ownership was unavailable.
                return resolver.PENDING
            self._advance_cleanup_once(
                max_wait_ns=selected_wait,
                operation_id=(
                    command.operation_id
                    if command.kind is wire._SupervisorWireKind.QUERY
                    else None
                ),
            )
            if (
                command.kind is wire._SupervisorWireKind.QUERY
                and self._cleanup_query_waits_for_terminal(
                    command.operation_id
                )
            ):
                # A PENDING child action has no wire reply to replay.  Do not
                # consume one of the finite exact-replay slots until a fresh
                # terminal fact actually exists.
                return resolver.PENDING
            return self._base.exchange(
                frame_bytes,
                max_wait_ns=selected_wait,
                local_publication_proof=local_publication_proof,
            )
        finally:
            self._lock.release()

    def read_stdout(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        max_bytes: int,
        *,
        max_wait_ns: int,
    ) -> object:
        proxy_module._wait_limit(max_wait_ns)
        require_plain_int(max_bytes, "max_bytes", minimum=1)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            if self._process_one_event(max_wait_ns=max_wait_ns) is not None:
                return resolver.PENDING
            if self._crash_reason is not None:
                self._ensure_global_poison()
                _raise_async_error("async supervisor event owner 已隔离。")
            self._advance_cleanup_once(max_wait_ns=max_wait_ns)
            operation = self._operation(binding, proxy_id)
            if operation.output_mode not in (None, "legacy"):
                self._poison_output(
                    operation,
                    "async supervisor stdout owner mode 已变化。",
                )
            operation.output_mode = "legacy"
            attestation = self._query(operation)
            if attestation.cancel_latched:
                return resolver.PENDING
            if operation.child is None:
                return resolver.PENDING
            if attestation.state not in (
                contract._BrokerOperationState.CHILD_OWNED,
                contract._BrokerOperationState.READY,
                contract._BrokerOperationState.STARTED,
                contract._BrokerOperationState.RESULT_PENDING_TERMINAL,
            ):
                _raise_async_error("async supervisor stdout state 无效。")
            if (
                attestation.state is contract._BrokerOperationState.CHILD_OWNED
                or (
                    operation.ready_observation is not None
                    and not attestation.start_committed
                )
            ):
                return self._read_ready_once(
                    operation,
                    max_bytes=max_bytes,
                    max_wait_ns=max_wait_ns,
                )
            selected = self._legacy_stdout_reader(operation)(
                max_bytes,
                max_wait_ns=max_wait_ns,
            )
            if selected is resolver.PENDING:
                return selected
            if type(selected) is not bytes or len(selected) > max_bytes:
                _raise_async_error("async supervisor stdout poll 无效。")
            if selected == resolver.READY_FRAME:
                _raise_async_error("async supervisor READY replay 无效。")
            return selected
        finally:
            self._lock.release()

    def write_start_once(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        frame: bytes,
        *,
        max_wait_ns: int,
    ) -> object:
        proxy_module._wait_limit(max_wait_ns)
        if type(frame) is not bytes or not frame:
            raise TypeError("frame must be non-empty bytes")
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            if self._process_one_event(max_wait_ns=max_wait_ns) is not None:
                return resolver.PENDING
            if self._crash_reason is not None:
                self._ensure_global_poison()
                _raise_async_error("async supervisor epoch 已隔离。")
            operation = self._operation(binding, proxy_id)
            record = operation.start_record
            if record is None:
                record = _StartRecord(frame)
                operation.start_record = record
            elif record.frame != frame:
                _raise_async_error("async supervisor START replay 已变化。")
            observed = self._observe_start(operation, record)
            if observed == "committed":
                return resolver.COMPLETE
            if operation.start_state == "poisoned":
                return self._advance_start_action(
                    operation,
                    max_wait_ns=max_wait_ns,
                )
            if observed == "claimed":
                if operation.start_state == "idle":
                    self._poison_start(
                        operation,
                        "async supervisor START local claim proof 缺失。",
                    )
                return self._advance_start_action(
                    operation,
                    max_wait_ns=max_wait_ns,
                )
            attestation = self._query(operation)
            if attestation.cancel_latched:
                _raise_async_error("async supervisor CANCEL 已先提交。")
            if attestation.state is not contract._BrokerOperationState.READY:
                _raise_async_error("async supervisor START 缺少 READY。")
            try:
                operation.start_state = "claim_unknown"
                claimed = self._base.ports.events.claim_start(
                    operation.binding,
                    command_id=operation.start_command_id,
                    payload_digest=record.payload_digest,
                )
            except BaseException:
                claimed = self._query(operation)
            claimed_state = self._start_observation(
                operation,
                record,
                claimed,
            )
            if claimed_state == "committed":
                operation.start_state = "committed"
                return resolver.COMPLETE
            if (
                claimed_state != "claimed"
                or claimed.poison_reason is not None
            ):
                if claimed_state == "unclaimed":
                    operation.start_state = "idle"
                    return resolver.PENDING
                self._poison_start(
                    operation,
                    "async supervisor START claim 未提交。",
                )
            operation.start_state = "claimed"
            return self._advance_start_action(
                operation,
                max_wait_ns=max_wait_ns,
            )
        finally:
            self._lock.release()

    def confirm_cancel_delegated(
        self,
        *,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        attestation: contract._SupervisorOperationAttestation,
    ) -> bool:
        if not _try_acquire(self._lock):
            return False
        try:
            if type(attestation) is not contract._SupervisorOperationAttestation:
                return False
            parent_proxy = self._proxies.get(binding.operation_id)
            return (
                parent_proxy is not None
                and parent_proxy.proxy_id == proxy_id
                and _same_binding(parent_proxy.binding, binding)
                and _same_binding(attestation.binding, binding)
                and attestation.cancel_latched
            )
        finally:
            self._lock.release()

    def observe_cleanup_pending(
        self,
        *,
        proxy: contract._SupervisorParentProxy,
        query_id: UUID,
        max_wait_ns: int,
    ) -> object:
        proxy_module._wait_limit(max_wait_ns)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            reply = self._base.ports.control.query_reply(
                proxy.binding,
                query_id=require_uuid(query_id, "query_id"),
            )
            return self._base.ports.parent_session.observe_cleanup_pending(
                proxy=proxy,
                reply=reply,
            )
        finally:
            self._lock.release()

    def pump(self, *, max_wait_ns: int) -> object:
        selected_wait = proxy_module._wait_limit(max_wait_ns)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            processed = self._process_one_event(max_wait_ns=selected_wait)
            if processed is not None:
                _, result = processed
                return (
                    resolver.PENDING
                    if result is resolver.PENDING
                    else resolver.COMPLETE
                )
            self._advance_cleanup_once(max_wait_ns=selected_wait)
            return resolver.PENDING
        finally:
            self._lock.release()

    def observe_broker_crash(self) -> object:
        """Test-seam liveness loss: retain and clean every frozen child."""

        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            if self._crash_reason is None:
                object.__setattr__(
                    self,
                    "_crash_reason",
                    contract._PoisonReason.LIVENESS_LOST,
                )
            try:
                self._ensure_global_poison()
            finally:
                for operation in tuple(self._operations.values()):
                    self._emergency_cleanup_child(operation)
            # One crash observation owns one bounded inbox step.  A late
            # child's PENDING result must remain durable for a later pump; an
            # eager drain here would busy-loop forever under backpressure.
            self._process_one_event(
                max_wait_ns=proxy_module.MAX_SUPERVISOR_PROXY_WAIT_NS,
            )
            return resolver.COMPLETE
        finally:
            self._lock.release()

    @staticmethod
    def _released_snapshot(
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
    ) -> tuple[object, ...]:
        binding.validate_integrity()
        return (
            binding.epoch_id,
            binding.operation_id,
            binding.lifecycle_id,
            binding.publication_id,
            binding.spawn_request_digest,
            binding.binding_digest,
            require_uuid(proxy_id, "proxy_id"),
        )

    def _validate_released_tombstones(self) -> None:
        valid = len(self._released_operations) <= (
            _MAX_RELEASED_OPERATION_TOMBSTONES
        )
        if valid:
            for operation_id, snapshot in self._released_operations.items():
                valid = (
                    type(operation_id) is UUID
                    and type(snapshot) is tuple
                    and len(snapshot) == 7
                    and type(snapshot[0]) is UUID
                    and snapshot[1] == operation_id
                    and all(
                        type(snapshot[index]) is UUID
                        for index in (1, 2, 3, 6)
                    )
                    and all(
                        type(snapshot[index]) is Digest256
                        for index in (4, 5)
                    )
                )
                if not valid:
                    break
        if valid:
            outcome_operation_ids = (
                self._events.pending_outcome_operation_ids()
            )
            outcome_receipt_ids = (
                self._events.outcome_receipt_operation_ids()
            )
            valid = (
                len(self._late_child_tombstones)
                <= _MAX_RELEASED_OPERATION_TOMBSTONES
                and len(self._worker_sources) <= _MAX_ACTIVE_OPERATIONS
                and len(self._worker_publications)
                <= _MAX_ACTIVE_OPERATIONS
                and len(outcome_operation_ids) <= _MAX_ACTIVE_OPERATIONS
                and len(outcome_receipt_ids) <= _MAX_ACTIVE_OPERATIONS
                and all(
                    type(operation_id) is UUID
                    and type(pid) is int
                    and pid > 0
                    and (
                        operation_id in self._operations
                        or operation_id in self._released_operations
                    )
                    for operation_id, pid
                    in self._late_child_tombstones.items()
                )
                and all(
                    type(operation_id) is UUID
                    and (
                        operation_id in self._operations
                        or operation_id in self._released_operations
                    )
                    for operation_id in self._worker_sources
                )
                and all(
                    type(operation_id) is UUID
                    and type(publication)
                    is _SpawnConstructionPublication
                    and publication.operation_id == operation_id
                    and (
                        operation_id in self._operations
                        or operation_id in self._released_operations
                    )
                    and publication.binding_digest
                    == (
                        self._operations[
                            operation_id
                        ].binding.binding_digest
                        if operation_id in self._operations
                        else self._released_operations[operation_id][5]
                    )
                    and publication.matches(
                        operation_id,
                        (
                            self._operations[
                                operation_id
                            ].binding.binding_digest
                            if operation_id in self._operations
                            else self._released_operations[
                                operation_id
                            ][5]
                        ),
                    )
                    and (
                        operation_id not in self._operations
                        or self._operations[
                            operation_id
                        ].worker_publication is publication
                    )
                    for operation_id, publication
                    in self._worker_publications.copy().items()
                )
                and all(
                    operation_id in self._worker_publications
                    for operation_id in self._worker_sources.copy()
                )
                and all(
                    type(operation_id) is UUID
                    and (
                        operation_id in self._operations
                        or operation_id in self._released_operations
                    )
                    for operation_id in outcome_operation_ids
                )
                and outcome_receipt_ids <= outcome_operation_ids
            )
        if not valid:
            object.__setattr__(
                self,
                "_crash_reason",
                contract._PoisonReason.LIVENESS_LOST,
            )
            self._ensure_global_poison()
            _raise_async_error(
                "async supervisor released tombstone ledger 已损坏。"
            )

    def _compact_released_operation(
        self,
        operation_id: UUID,
    ) -> bool:
        if not _try_acquire(self._control_inbox_lock):
            return False
        try:
            late_outcomes = self._events.discard_operation(operation_id)
        finally:
            self._control_inbox_lock.release()
        operation = self._operations.get(operation_id)
        if operation is not None:
            # No live/output object survives exact terminal pipe close.  Only
            # the primitive, bounded replay tombstone remains.
            operation.frozen_child = None
            operation.worker_thread = None
            operation.worker_publication = None
            operation.ready_observation = None
            operation.start_record = None
            operation.output_publication = None
            operation.output_cache = None
            self._operations.pop(operation_id, None)
        self._proxies.pop(operation_id, None)
        pending = operation_id in self._worker_sources
        for outcome in late_outcomes:
            if not self._advance_unbound_outcome_cleanup(
                outcome,
                max_wait_ns=proxy_module.MAX_SUPERVISOR_PROXY_WAIT_NS,
            ):
                pending = True
                continue
            if not _try_acquire(self._control_inbox_lock):
                pending = True
                continue
            try:
                self._events.discard_exact(outcome)
            finally:
                self._control_inbox_lock.release()
        if self._events.has_pending_outcome(operation_id):
            pending = True
        if not pending:
            # The source is quiescent and every exact late outcome has either
            # been tombstoned or retired.  Only now may admission forget this
            # operation's conservative active-slot index.
            self._events.release_outcome_operation(operation_id)
        self._release_quiescent_outcome_indexes()
        if operation_id in self._worker_publications:
            pending = True
        return not pending

    def close_operation_pipes(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
        *,
        max_wait_ns: int,
    ) -> object:
        """Close exact terminal pipes, then release all strong S4 references."""

        selected_wait = proxy_module._wait_limit(max_wait_ns)
        snapshot = self._released_snapshot(binding, proxy_id)
        if not _try_acquire(self._lock):
            return resolver.PENDING
        try:
            self._recover_stopped_worker_publications()
            self._validate_released_tombstones()
            existing = self._released_operations.get(binding.operation_id)
            if existing is not None:
                if existing != snapshot:
                    self._poison_unknown_os_action()
                    _raise_async_error(
                        "async supervisor released operation 已变化。"
                    )
                return (
                    resolver.COMPLETE
                    if self._compact_released_operation(binding.operation_id)
                    else resolver.PENDING
                )

            base_tombstone = self._base.terminal_tombstone(
                binding,
                proxy_id,
            )
            if base_tombstone is not None:
                base_result = self._base.close_operation_pipes(
                    binding,
                    proxy_id,
                    max_wait_ns=selected_wait,
                )
                if base_result is not resolver.COMPLETE:
                    if base_result is resolver.PENDING:
                        return base_result
                    _raise_async_error(
                        "async supervisor base compaction result 无效。"
                    )
                if (
                    len(self._released_operations)
                    >= _MAX_RELEASED_OPERATION_TOMBSTONES
                ):
                    raise proxy_module._capacity_error(
                        "async supervisor released tombstone capacity 已满。"
                    )
                retained = self._released_operations.setdefault(
                    binding.operation_id,
                    snapshot,
                )
                if retained != snapshot:
                    self._poison_unknown_os_action()
                    _raise_async_error(
                        "async supervisor released tombstone 冲突。"
                    )
                return (
                    resolver.COMPLETE
                    if self._compact_released_operation(binding.operation_id)
                    else resolver.PENDING
                )

            operation = self._operation(binding, proxy_id)
            attestation = self._query(operation)
            if (
                attestation.state is not contract._BrokerOperationState.RELEASED
                or attestation.terminal_attestation_id is None
                or attestation.release_tombstone_id is None
            ):
                _raise_async_error(
                    "async supervisor operation 尚未 exact release。"
                )
            result = self._base.close_operation_pipes(
                binding,
                proxy_id,
                max_wait_ns=selected_wait,
            )
            if result is not resolver.COMPLETE:
                if result is resolver.PENDING:
                    return result
                _raise_async_error(
                    "async supervisor operation pipe close result 无效。"
                )
            if (
                len(self._released_operations)
                >= _MAX_RELEASED_OPERATION_TOMBSTONES
            ):
                raise proxy_module._capacity_error(
                    "async supervisor released tombstone capacity 已满。"
                )
            retained = self._released_operations.setdefault(
                binding.operation_id,
                snapshot,
            )
            if retained != snapshot:
                self._poison_unknown_os_action()
                _raise_async_error(
                    "async supervisor released tombstone 冲突。"
                )
            return (
                resolver.COMPLETE
                if self._compact_released_operation(binding.operation_id)
                else resolver.PENDING
            )
        finally:
            self._lock.release()

    def safe_metadata(self) -> dict[str, object]:
        if not _try_acquire(self._lock):
            # Metadata is diagnostic, never an ownership authority.  Expose a
            # bounded busy fact instead of blocking a callback that reenters
            # while the event owner is performing the exact native action.
            return {"snapshot_busy": True}
        try:
            self._recover_stopped_worker_publications()
            self._release_quiescent_outcome_indexes()
            self._validate_released_tombstones()
            return {
                "snapshot_busy": False,
                "crashed": self._crash_reason is not None,
                "frozen_child_count": sum(
                    operation.child is not None
                    for operation in self._operations.values()
                ),
                "operation_count": len(self._operations),
                "active_operation_limit": _MAX_ACTIVE_OPERATIONS,
                "released_operation_tombstone_count": len(
                    self._released_operations
                ),
                "released_operation_tombstone_limit": (
                    _MAX_RELEASED_OPERATION_TOMBSTONES
                ),
                "late_child_tombstone_count": len(
                    self._late_child_tombstones
                ),
                "worker_source_count": len(self._worker_sources),
                "worker_construction_publication_count": len(
                    self._worker_publications
                ),
                "worker_construction_child_count": sum(
                    publication.has_child_reference()
                    for publication in self._worker_publications.copy().values()
                ),
                "worker_started_count": sum(
                    operation.worker_state == "started"
                    for operation in self._operations.values()
                ),
                "pending_event_count": len(self._events),
                "pending_outcome_operation_count": len(
                    self._events.pending_outcome_operation_ids()
                ),
                "outcome_delivery_receipt_count": len(
                    self._events.outcome_receipt_operation_ids()
                ),
                "pending_control_event_count": (
                    self._events.pending_control_count()
                ),
                "pending_control_event_limit": _MAX_PENDING_CONTROL_EVENTS,
                "durable_output_slot_count": sum(
                    operation.output_cache.safe_metadata()["slot_present"]
                    for operation in self._operations.values()
                    if operation.output_cache is not None
                ),
                "durable_output_tombstone_count": sum(
                    operation.output_cache.safe_metadata()["tombstone_count"]
                    for operation in self._operations.values()
                    if operation.output_cache is not None
                ),
            }
        finally:
            self._lock.release()


@runtime_final
class _AsyncSupervisorChannel:
    """Bounded parent channel whose control/data calls enter one event owner."""

    __slots__ = (
        "epoch_id",
        "control_channel_id",
        "ports",
        "event_owner",
        "_base",
    )

    def __init__(
        self,
        *,
        base: proxy_module._InMemorySupervisorChannel,
        worker: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ASYNC_CHANNEL_AUTHORITY:
            raise TypeError("async supervisor channel requires its factory")
        object.__setattr__(self, "epoch_id", base.epoch_id)
        object.__setattr__(self, "control_channel_id", base.control_channel_id)
        object.__setattr__(self, "ports", base.ports)
        object.__setattr__(self, "_base", base)
        object.__setattr__(
            self,
            "event_owner",
            _AsyncSupervisorEventOwner(
                base=base,
                worker=worker,
                _authority=_EVENT_OWNER_AUTHORITY,
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AsyncSupervisorChannel identity is immutable")

    def bind_spawner(self, spawner: object) -> None:
        self._base.bind_spawner(spawner)

    def preflight_admission(self) -> object:
        return self.event_owner.preflight_admission()

    def terminal_tombstone(
        self,
        binding: contract._SupervisorOperationBinding,
        proxy_id: UUID,
    ) -> object:
        return self._base.terminal_tombstone(binding, proxy_id)

    def epoch_rotation_ready(self) -> bool:
        return (
            self._base.epoch_rotation_ready()
            and self.event_owner.epoch_rotation_ready()
        )

    def exchange(
        self,
        frame_bytes: bytes,
        *,
        max_wait_ns: int,
        local_publication_proof: object = None,
    ) -> object:
        return self.event_owner.control_exchange(
            frame_bytes,
            max_wait_ns=max_wait_ns,
            local_publication_proof=local_publication_proof,
        )

    def prepare_proxy(self, **kwargs: object) -> object:
        selected = self._base.prepare_proxy(**kwargs)
        if selected is resolver.PENDING:
            return selected
        proxy, _ = selected
        registered = self.event_owner.register_proxy(proxy)
        if registered is resolver.PENDING:
            return registered
        return selected

    def read_stdout(self, *args: object, **kwargs: object) -> object:
        return self.event_owner.read_stdout(*args, **kwargs)

    def observe_stdout_durable(
        self,
        *args: object,
        **kwargs: object,
    ) -> object:
        return self.event_owner.observe_stdout_durable(*args, **kwargs)

    def acknowledge_stdout_durable(
        self,
        *args: object,
        **kwargs: object,
    ) -> object:
        return self.event_owner.acknowledge_stdout_durable(*args, **kwargs)

    def write_stdin(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        _raise_async_error("unlinearized async START write 已拒绝。")

    def write_start_once(self, *args: object, **kwargs: object) -> object:
        return self.event_owner.write_start_once(*args, **kwargs)

    def confirm_cancel_delegated(self, **kwargs: object) -> bool:
        return self.event_owner.confirm_cancel_delegated(**kwargs)

    def observe_cleanup_pending(self, **kwargs: object) -> object:
        return self.event_owner.observe_cleanup_pending(**kwargs)

    def close_operation_pipes(self, *args: object, **kwargs: object) -> object:
        return self.event_owner.close_operation_pipes(*args, **kwargs)

    @property
    def received_kinds(self) -> tuple[str, ...]:
        return self._base.received_kinds

    @property
    def session_closed(self) -> bool:
        return self._base.session_closed

    def safe_metadata(self) -> dict[str, object]:
        selected = self._base.safe_metadata()
        selected.update(self.event_owner.safe_metadata())
        selected["async_event_owner"] = True
        return selected


def _new_async_supervisor_channel(
    *,
    epoch_id: UUID,
    control_channel_id: UUID,
    spawn_worker: object,
) -> _AsyncSupervisorChannel:
    base = proxy_module._new_in_memory_supervisor_channel(
        epoch_id=epoch_id,
        control_channel_id=control_channel_id,
    )
    return _AsyncSupervisorChannel(
        base=base,
        worker=spawn_worker,
        _authority=_ASYNC_CHANNEL_AUTHORITY,
    )
