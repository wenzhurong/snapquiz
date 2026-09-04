"""Darwin-only local supervisor bootstrap foundation.

This private module is the W09-B2b-S2a development harness.  Its controlled
repository fixture is exercised without targets, secrets, network access, or
operation children.  The harness validates one exact READY record, owns two
independent liveness pipes, and binds the resulting epoch to the S1 in-process
broker contract.  A generic executable admitted by the local probe policy is
not sandboxed.  This module deliberately exposes no operation API and is not
imported by the production resolver.

The executable check in this slice is intentionally named a local probe
policy.  ``lstat/open/fstat/hash`` plus pre/post path snapshots detect ordinary
replacement, symlink, owner, and mode failures, but a path-based
``posix_spawn`` cannot prove the image that actually executed across an ABA
replacement race.  A bundled/signed Mach-O identity check against the running
process (or an OS-owned XPC/launchd service) remains an S2b exit gate.

This development harness assumes one non-forking interpreter and one reaper.
Its APIs are not signal-handler-safe.  Native atomic ownership, fork/PID
generation handling, and the application startup composition are also S2b or
later production gates.
"""
from __future__ import annotations

import ctypes
import errno
from enum import Enum
import hashlib
import json
import os
import select
import signal
import stat
import sys
from threading import Lock, RLock
from typing import NamedTuple, NoReturn
from uuid import UUID

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport._resolver_supervisor_contract import (
    _PoisonReason,
    _SupervisorBrokerPorts,
    _new_supervisor_broker,
)


__all__ = ()


SUPERVISOR_BOOTSTRAP_PROTOCOL_VERSION = (
    "snapquiz.resolver-supervisor-bootstrap.v1"
)
SUPERVISOR_PROBE_POLICY_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-probe-policy.v1"
)
SUPERVISOR_BOOTSTRAP_BINDING_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-bootstrap-binding.v1"
)
SUPERVISOR_READY_SCHEMA_VERSION = "snapquiz.resolver-supervisor-ready.v1"
SUPERVISOR_READY_PROOF_SCHEMA_VERSION = (
    "snapquiz.resolver-supervisor-ready-proof.v1"
)
MAX_SUPERVISOR_READY_FRAME_BYTES = 2_048
MAX_SUPERVISOR_STDERR_BYTES = 4_096
MAX_LOCAL_PROBE_EXECUTABLE_BYTES = 8 * 1024 * 1024
MAX_BOOTSTRAP_READY_WAIT_NS = 5_000_000_000


_POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
_POSIX_SPAWN_SETSIGDEF = 0x0004
_POSIX_SPAWN_SETSIGMASK = 0x0008
_POSIX_SPAWN_FLAGS = (
    _POSIX_SPAWN_CLOEXEC_DEFAULT
    | _POSIX_SPAWN_SETSIGDEF
    | _POSIX_SPAWN_SETSIGMASK
)
_SUPERVISOR_ARG = "--snapquiz-resolver-supervisor-bootstrap-v1"
_SUPERVISOR_ENVIRONMENT = (("LANG", "C"), ("LC_ALL", "C"))
_POLICY_AUTHORITY = object()
_BINDING_AUTHORITY = object()
_READY_PROOF_AUTHORITY = object()
_SESSION_AUTHORITY = object()
_BOOTSTRAP_AUTHORITY = object()
_ACQUISITION_AUTHORITY = object()
_STATE_AUTHORITY = object()


class _BootstrapState(str, Enum):
    NEW = "new"
    PREPARED = "prepared"
    SPAWN_CLAIMED = "spawn_claimed"
    READY_PENDING = "ready_pending"
    READY_ATTESTED = "ready_attested"
    SHUTDOWN_LATCHED = "shutdown_latched"
    TERMINAL_ATTESTED = "terminal_attested"
    FAILED_CLEAN = "failed_clean"
    GLOBAL_POISONED = "global_poisoned"


class _SpawnState(str, Enum):
    NOT_CALLED = "not_called"
    IN_FLIGHT = "in_flight"
    FAILED = "failed"
    SUCCEEDED = "succeeded"
    UNCERTAIN = "uncertain"


class _WaitState(str, Enum):
    NOT_CALLED = "not_called"
    IN_FLIGHT = "in_flight"
    COMPLETED = "completed"
    UNCERTAIN = "uncertain"


class _BootstrapLedgerRecord(NamedTuple):
    state: _BootstrapState
    global_poison_reason: _PoisonReason | None


@runtime_final
class _BootstrapStateLedger:
    """Single observable state source shared by bootstrap and session."""

    __slots__ = ("_lock", "_record")

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _STATE_AUTHORITY:
            raise TypeError("bootstrap state ledger requires its factory")
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(
            self,
            "_record",
            _BootstrapLedgerRecord(
                state=_BootstrapState.NEW,
                global_poison_reason=None,
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("BootstrapStateLedger identity is immutable")

    def transition(
        self,
        state: _BootstrapState,
        *,
        _authority: object,
    ) -> None:
        if _authority is not _STATE_AUTHORITY or type(state) is not _BootstrapState:
            raise TypeError("invalid bootstrap state transition authority")
        allowed = {
            _BootstrapState.NEW: frozenset({_BootstrapState.PREPARED}),
            _BootstrapState.PREPARED: frozenset(
                {
                    _BootstrapState.SPAWN_CLAIMED,
                    _BootstrapState.FAILED_CLEAN,
                    _BootstrapState.GLOBAL_POISONED,
                }
            ),
            _BootstrapState.SPAWN_CLAIMED: frozenset(
                {
                    _BootstrapState.READY_PENDING,
                    _BootstrapState.FAILED_CLEAN,
                    _BootstrapState.GLOBAL_POISONED,
                }
            ),
            _BootstrapState.READY_PENDING: frozenset(
                {
                    _BootstrapState.READY_ATTESTED,
                    _BootstrapState.GLOBAL_POISONED,
                }
            ),
            _BootstrapState.READY_ATTESTED: frozenset(
                {
                    _BootstrapState.SHUTDOWN_LATCHED,
                    _BootstrapState.GLOBAL_POISONED,
                }
            ),
            _BootstrapState.SHUTDOWN_LATCHED: frozenset(
                {
                    _BootstrapState.TERMINAL_ATTESTED,
                    _BootstrapState.GLOBAL_POISONED,
                }
            ),
            _BootstrapState.FAILED_CLEAN: frozenset(),
            _BootstrapState.GLOBAL_POISONED: frozenset(),
            _BootstrapState.TERMINAL_ATTESTED: frozenset(),
        }
        with self._lock:
            current = self._record
            if state is current.state:
                return
            if state not in allowed[current.state]:
                raise _BootstrapBoundaryFailure
            object.__setattr__(
                self,
                "_record",
                _BootstrapLedgerRecord(
                    state=state,
                    global_poison_reason=current.global_poison_reason,
                ),
            )

    def poison(
        self,
        reason: _PoisonReason,
        *,
        _authority: object,
    ) -> None:
        if _authority is not _STATE_AUTHORITY or type(reason) is not _PoisonReason:
            raise TypeError("invalid bootstrap poison authority")
        with self._lock:
            current = self._record
            if current.state is _BootstrapState.TERMINAL_ATTESTED:
                return
            if current.state is _BootstrapState.GLOBAL_POISONED:
                if current.global_poison_reason is None:
                    object.__setattr__(
                        self,
                        "_record",
                        _BootstrapLedgerRecord(
                            state=_BootstrapState.GLOBAL_POISONED,
                            global_poison_reason=reason,
                        ),
                    )
                return
            object.__setattr__(
                self,
                "_record",
                _BootstrapLedgerRecord(
                    state=_BootstrapState.GLOBAL_POISONED,
                    global_poison_reason=reason,
                ),
            )

    def state(self) -> _BootstrapState:
        with self._lock:
            return self._record.state

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            current = self._record
            return {
                "global_poison_reason": (
                    None
                    if current.global_poison_reason is None
                    else current.global_poison_reason.value
                ),
                "state": current.state.value,
            }


def _bootstrap_error(
    safe_message: str = "resolver supervisor bootstrap 不可用。",
) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_supervisor_bootstrap",
        retryable=False,
        safe_message=safe_message,
    )


def _raise_bootstrap_error(
    safe_message: str = "resolver supervisor bootstrap 不可用。",
) -> NoReturn:
    error = _bootstrap_error(safe_message)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _require_bootstrap_wait_ns(
    value: object,
    name: str,
    *,
    minimum: int,
) -> int:
    selected = require_plain_int(value, name, minimum=minimum)
    if selected > MAX_BOOTSTRAP_READY_WAIT_NS:
        raise ValueError(
            f"{name} must be <= {MAX_BOOTSTRAP_READY_WAIT_NS}"
        )
    return selected


class _BootstrapBoundaryFailure(Exception):
    """Content-free internal boundary failure."""


class _BootstrapLivenessLost(_BootstrapBoundaryFailure):
    """Exact child liveness ended or became ambiguous."""


def _require_local_probe_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
    ):
        raise ValueError("executable must be a normalized absolute path")
    return value


@runtime_final
class _LocalSupervisorProbePolicy:
    """Pure expected identity for a development-only supervisor probe."""

    __slots__ = (
        "executable",
        "executable_sha256",
        "policy_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        executable: str,
        executable_sha256: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _POLICY_AUTHORITY:
            raise TypeError("local supervisor probe policy requires its factory")
        checked_path = _require_local_probe_path(executable)
        checked_digest = require_digest(
            executable_sha256,
            "executable_sha256",
        )
        selected = digest256(
            "LocalSupervisorProbePolicy",
            SUPERVISOR_PROBE_POLICY_SCHEMA_VERSION,
            {
                "executable": checked_path,
                "executable_sha256": checked_digest,
                "identity_scope": "local_path_pre_post_only",
                "protocol_version": SUPERVISOR_BOOTSTRAP_PROTOCOL_VERSION,
            },
        )
        object.__setattr__(self, "executable", checked_path)
        object.__setattr__(self, "executable_sha256", checked_digest)
        object.__setattr__(self, "policy_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("LocalSupervisorProbePolicy is immutable")

    def validate_integrity(self) -> None:
        checked_path = _require_local_probe_path(self.executable)
        checked_digest = require_digest(
            self.executable_sha256,
            "executable_sha256",
        )
        selected = digest256(
            "LocalSupervisorProbePolicy",
            SUPERVISOR_PROBE_POLICY_SCHEMA_VERSION,
            {
                "executable": checked_path,
                "executable_sha256": checked_digest,
                "identity_scope": "local_path_pre_post_only",
                "protocol_version": SUPERVISOR_BOOTSTRAP_PROTOCOL_VERSION,
            },
        )
        if (
            self.policy_digest != selected
            or self._issued_digest != selected
        ):
            raise ValueError("local supervisor probe policy integrity failed")


def _new_local_supervisor_probe_policy(
    *,
    executable: str,
    executable_sha256: Digest256,
) -> _LocalSupervisorProbePolicy:
    return _LocalSupervisorProbePolicy(
        executable=executable,
        executable_sha256=executable_sha256,
        _authority=_POLICY_AUTHORITY,
    )


@runtime_final
class _SupervisorBootstrapBinding:
    """Immutable identity for one process-wide bootstrap attempt."""

    __slots__ = (
        "bootstrap_id",
        "epoch_id",
        "challenge_id",
        "control_channel_id",
        "parent_liveness_id",
        "supervisor_liveness_id",
        "local_probe_policy_digest",
        "executable_sha256",
        "binding_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        bootstrap_id: UUID,
        epoch_id: UUID,
        challenge_id: UUID,
        control_channel_id: UUID,
        parent_liveness_id: UUID,
        supervisor_liveness_id: UUID,
        local_probe_policy_digest: Digest256,
        executable_sha256: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BINDING_AUTHORITY:
            raise TypeError("supervisor bootstrap binding requires its factory")
        identifiers = (
            require_uuid(bootstrap_id, "bootstrap_id"),
            require_uuid(epoch_id, "epoch_id"),
            require_uuid(challenge_id, "challenge_id"),
            require_uuid(control_channel_id, "control_channel_id"),
            require_uuid(parent_liveness_id, "parent_liveness_id"),
            require_uuid(supervisor_liveness_id, "supervisor_liveness_id"),
        )
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("supervisor bootstrap identifiers must be distinct")
        policy_digest = require_digest(
            local_probe_policy_digest,
            "local_probe_policy_digest",
        )
        executable_digest = require_digest(
            executable_sha256,
            "executable_sha256",
        )
        payload = {
            "bootstrap_id": str(identifiers[0]),
            "challenge_id": str(identifiers[2]),
            "control_channel_id": str(identifiers[3]),
            "epoch_id": str(identifiers[1]),
            "executable_sha256": executable_digest,
            "local_probe_policy_digest": policy_digest,
            "parent_liveness_id": str(identifiers[4]),
            "protocol_version": SUPERVISOR_BOOTSTRAP_PROTOCOL_VERSION,
            "supervisor_liveness_id": str(identifiers[5]),
        }
        selected = digest256(
            "ResolverSupervisorBootstrapBinding",
            SUPERVISOR_BOOTSTRAP_BINDING_SCHEMA_VERSION,
            payload,
        )
        for name, value in zip(
            (
                "bootstrap_id",
                "epoch_id",
                "challenge_id",
                "control_channel_id",
                "parent_liveness_id",
                "supervisor_liveness_id",
            ),
            identifiers,
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "local_probe_policy_digest",
            policy_digest,
        )
        object.__setattr__(
            self,
            "executable_sha256",
            executable_digest,
        )
        object.__setattr__(self, "binding_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorBootstrapBinding is immutable")

    def validate_integrity(self) -> None:
        identifiers = (
            require_uuid(self.bootstrap_id, "bootstrap_id"),
            require_uuid(self.epoch_id, "epoch_id"),
            require_uuid(self.challenge_id, "challenge_id"),
            require_uuid(self.control_channel_id, "control_channel_id"),
            require_uuid(self.parent_liveness_id, "parent_liveness_id"),
            require_uuid(
                self.supervisor_liveness_id,
                "supervisor_liveness_id",
            ),
        )
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("supervisor bootstrap identifiers changed")
        policy_digest = require_digest(
            self.local_probe_policy_digest,
            "local_probe_policy_digest",
        )
        executable_digest = require_digest(
            self.executable_sha256,
            "executable_sha256",
        )
        selected = digest256(
            "ResolverSupervisorBootstrapBinding",
            SUPERVISOR_BOOTSTRAP_BINDING_SCHEMA_VERSION,
            {
                "bootstrap_id": str(self.bootstrap_id),
                "challenge_id": str(self.challenge_id),
                "control_channel_id": str(self.control_channel_id),
                "epoch_id": str(self.epoch_id),
                "executable_sha256": executable_digest,
                "local_probe_policy_digest": policy_digest,
                "parent_liveness_id": str(self.parent_liveness_id),
                "protocol_version": SUPERVISOR_BOOTSTRAP_PROTOCOL_VERSION,
                "supervisor_liveness_id": str(
                    self.supervisor_liveness_id
                ),
            },
        )
        if (
            self.binding_digest != selected
            or self._issued_digest != selected
        ):
            raise ValueError("supervisor bootstrap binding integrity failed")


def _new_supervisor_bootstrap_binding(
    *,
    bootstrap_id: UUID,
    epoch_id: UUID,
    challenge_id: UUID,
    control_channel_id: UUID,
    parent_liveness_id: UUID,
    supervisor_liveness_id: UUID,
    local_probe_policy_digest: Digest256,
    executable_sha256: Digest256,
) -> _SupervisorBootstrapBinding:
    return _SupervisorBootstrapBinding(
        bootstrap_id=bootstrap_id,
        epoch_id=epoch_id,
        challenge_id=challenge_id,
        control_channel_id=control_channel_id,
        parent_liveness_id=parent_liveness_id,
        supervisor_liveness_id=supervisor_liveness_id,
        local_probe_policy_digest=local_probe_policy_digest,
        executable_sha256=executable_sha256,
        _authority=_BINDING_AUTHORITY,
    )


class _ExecutableFingerprint(NamedTuple):
    device: int
    inode: int
    mode: int
    link_count: int
    owner: int
    group: int
    size: int
    modified_ns: int
    changed_ns: int


class _ExecutableLease(NamedTuple):
    fd: int
    fingerprint: _ExecutableFingerprint
    executable_sha256: Digest256


class _NativeHandleLease(NamedTuple):
    storage: ctypes.c_void_p
    destroy: object


def _fingerprint(value: os.stat_result) -> _ExecutableFingerprint:
    return _ExecutableFingerprint(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        link_count=value.st_nlink,
        owner=value.st_uid,
        group=value.st_gid,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _validate_probe_stat(value: os.stat_result) -> None:
    mode = value.st_mode
    forbidden_mode = (
        stat.S_IWGRP
        | stat.S_IWOTH
        | stat.S_ISUID
        | stat.S_ISGID
        | stat.S_ISVTX
    )
    if (
        not stat.S_ISREG(mode)
        or value.st_nlink != 1
        or value.st_uid != os.getuid()
        or not mode & stat.S_IXUSR
        or mode & forbidden_mode
        or value.st_size <= 0
        or value.st_size > MAX_LOCAL_PROBE_EXECUTABLE_BYTES
    ):
        raise _BootstrapBoundaryFailure


def _attest_local_probe(
    policy: _LocalSupervisorProbePolicy,
    acquisition: "_BootstrapAcquisitionOwner",
) -> _ExecutableLease:
    fd: int | None = None
    try:
        policy.validate_integrity()
        if os.path.realpath(policy.executable) != policy.executable:
            raise _BootstrapBoundaryFailure
        before = os.lstat(policy.executable)
        _validate_probe_stat(before)
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        acquisition.begin_raw_acquisition(
            _authority=_ACQUISITION_AUTHORITY
        )
        try:
            fd = os.open(policy.executable, flags)
        except BaseException:
            # The in-flight marker remains set because pure Python cannot
            # distinguish syscall failure from return-before-STORE_FAST.
            raise
        acquisition.claim_raw_fds(
            (fd,),
            _authority=_ACQUISITION_AUTHORITY,
        )
        opened = os.fstat(fd)
        _validate_probe_stat(opened)
        if _fingerprint(before) != _fingerprint(opened):
            raise _BootstrapBoundaryFailure

        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LOCAL_PROBE_EXECUTABLE_BYTES:
                raise _BootstrapBoundaryFailure
            hasher.update(chunk)
        after = os.fstat(fd)
        if (
            total != opened.st_size
            or _fingerprint(opened) != _fingerprint(after)
        ):
            raise _BootstrapBoundaryFailure
        selected = Digest256(hasher.hexdigest())
        if selected != policy.executable_sha256:
            raise _BootstrapBoundaryFailure
        current = os.lstat(policy.executable)
        if _fingerprint(current) != _fingerprint(opened):
            raise _BootstrapBoundaryFailure
        lease = _ExecutableLease(
            fd=fd,
            fingerprint=_fingerprint(opened),
            executable_sha256=selected,
        )
        acquisition.claim_executable_lease(
            lease,
            _authority=_ACQUISITION_AUTHORITY,
        )
        fd = None
        return lease
    except BaseException:
        if (
            fd is not None
            and not acquisition.owns_executable_fd(fd)
            and not acquisition.owns_raw_fd(fd)
        ):
            try:
                os.close(fd)
            except BaseException:
                acquisition.mark_raw_acquisition_uncertain(
                    _authority=_ACQUISITION_AUTHORITY
                )
        raise _BootstrapBoundaryFailure from None


def _probe_path_matches(
    policy: _LocalSupervisorProbePolicy,
    lease: _ExecutableLease,
) -> bool:
    try:
        return (
            _fingerprint(os.lstat(policy.executable)) == lease.fingerprint
            and _fingerprint(os.fstat(lease.fd)) == lease.fingerprint
        )
    except BaseException:
        return False


class _BootstrapChannels(NamedTuple):
    parent_control: int
    child_control: int
    parent_liveness_write: int
    child_parent_liveness_read: int
    parent_supervisor_liveness_read: int
    child_supervisor_liveness_write: int
    parent_stderr: int
    child_stderr: int

    def all_fds(self) -> tuple[int, ...]:
        return tuple(self)

    def child_fds(self) -> tuple[int, ...]:
        return (
            self.child_control,
            self.child_parent_liveness_read,
            self.child_supervisor_liveness_write,
            self.child_stderr,
        )

    def parent_fds(self) -> tuple[int, ...]:
        return (
            self.parent_control,
            self.parent_liveness_write,
            self.parent_supervisor_liveness_read,
            self.parent_stderr,
        )


@runtime_final
class _BootstrapAcquisitionOwner:
    """Recovery anchor installed before the first bootstrap acquisition."""

    __slots__ = (
        "_lock",
        "_executable_lease",
        "_raw_fds",
        "_raw_acquisitions_inflight",
        "_native_handles",
        "_native_initializations_inflight",
        "_native_destroy_uncertain",
        "_channels",
        "_process_owner",
        "_lease_close_uncertain",
        "_channel_close_uncertain",
        "_raw_close_uncertain",
    )

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("bootstrap acquisition owner requires its factory")
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_executable_lease", None)
        object.__setattr__(self, "_raw_fds", [])
        object.__setattr__(self, "_raw_acquisitions_inflight", 0)
        object.__setattr__(self, "_native_handles", {})
        object.__setattr__(self, "_native_initializations_inflight", set())
        object.__setattr__(self, "_native_destroy_uncertain", set())
        object.__setattr__(self, "_channels", None)
        object.__setattr__(self, "_process_owner", None)
        object.__setattr__(self, "_lease_close_uncertain", False)
        object.__setattr__(self, "_channel_close_uncertain", False)
        object.__setattr__(self, "_raw_close_uncertain", False)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("BootstrapAcquisitionOwner identity is immutable")

    def claim_executable_lease(
        self,
        lease: _ExecutableLease,
        *,
        _authority: object,
    ) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid executable lease authority")
        if type(lease) is not _ExecutableLease:
            raise TypeError("lease must be ExecutableLease")
        with self._lock:
            if (
                self._executable_lease is not None
                or self._lease_close_uncertain
                or lease.fd not in self._raw_fds
            ):
                raise _BootstrapBoundaryFailure
            object.__setattr__(self, "_executable_lease", lease)

    def executable_lease(self) -> _ExecutableLease:
        with self._lock:
            selected = self._executable_lease
            if type(selected) is not _ExecutableLease:
                raise _BootstrapBoundaryFailure
            return selected

    def owns_executable_fd(self, fd: int) -> bool:
        with self._lock:
            lease = self._executable_lease
            return type(lease) is _ExecutableLease and lease.fd == fd

    def claim_raw_fds(
        self,
        fds: tuple[int, ...],
        *,
        _authority: object,
    ) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid raw descriptor authority")
        if (
            not fds
            or any(type(fd) is not int or fd < 0 for fd in fds)
            or len(set(fds)) != len(fds)
        ):
            raise _BootstrapBoundaryFailure
        with self._lock:
            if (
                self._raw_acquisitions_inflight <= 0
                or any(fd in self._raw_fds for fd in fds)
            ):
                raise _BootstrapBoundaryFailure
            self._raw_fds.extend(fds)
            object.__setattr__(
                self,
                "_raw_acquisitions_inflight",
                self._raw_acquisitions_inflight - 1,
            )

    def begin_raw_acquisition(self, *, _authority: object) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid raw acquisition authority")
        with self._lock:
            object.__setattr__(
                self,
                "_raw_acquisitions_inflight",
                self._raw_acquisitions_inflight + 1,
            )

    def owns_raw_fd(self, fd: int) -> bool:
        with self._lock:
            return fd in self._raw_fds

    def mark_raw_acquisition_uncertain(self, *, _authority: object) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid raw acquisition authority")
        with self._lock:
            object.__setattr__(self, "_raw_close_uncertain", True)

    def begin_native_handle_initialization(
        self,
        kind: str,
        *,
        _authority: object,
    ) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid native handle authority")
        if kind not in ("file_actions", "spawn_attributes"):
            raise _BootstrapBoundaryFailure
        with self._lock:
            if (
                kind in self._native_initializations_inflight
                or kind in self._native_handles
                or kind in self._native_destroy_uncertain
            ):
                raise _BootstrapBoundaryFailure
            self._native_initializations_inflight.add(kind)

    def record_native_handle_initialization_failure(
        self,
        kind: str,
        *,
        _authority: object,
    ) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid native handle authority")
        with self._lock:
            if kind not in self._native_initializations_inflight:
                raise _BootstrapBoundaryFailure
            self._native_initializations_inflight.remove(kind)

    def claim_native_handle(
        self,
        kind: str,
        *,
        storage: ctypes.c_void_p,
        destroy: object,
        _authority: object,
    ) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid native handle authority")
        if type(storage) is not ctypes.c_void_p or not callable(destroy):
            raise _BootstrapBoundaryFailure
        with self._lock:
            if (
                kind not in self._native_initializations_inflight
                or kind in self._native_handles
                or kind in self._native_destroy_uncertain
            ):
                raise _BootstrapBoundaryFailure
            # Publish the handle before retiring the in-flight marker.  An
            # interruption between these mutations remains conservatively
            # poisoned, but cleanup can still destroy the exact known handle.
            self._native_handles[kind] = _NativeHandleLease(
                storage=storage,
                destroy=destroy,
            )
            self._native_initializations_inflight.remove(kind)

    def destroy_native_handle_once(self, kind: str) -> None:
        with self._lock:
            if kind in self._native_destroy_uncertain:
                raise _BootstrapBoundaryFailure
            lease = self._native_handles.get(kind)
            if lease is None:
                return
            # Claim destruction before invoking libc.  A return-before-local-
            # commit interruption must never replay an opaque native handle.
            self._native_destroy_uncertain.add(kind)
            del self._native_handles[kind]
            try:
                result = lease.destroy(ctypes.byref(lease.storage))
            except BaseException:
                raise _BootstrapBoundaryFailure from None
            if result != 0:
                raise _BootstrapBoundaryFailure
            self._native_destroy_uncertain.remove(kind)

    def destroy_native_handles(self) -> bool:
        clean = True
        for kind in ("spawn_attributes", "file_actions"):
            try:
                self.destroy_native_handle_once(kind)
            except BaseException:
                clean = False
        with self._lock:
            return (
                clean
                and not self._native_handles
                and not self._native_initializations_inflight
                and not self._native_destroy_uncertain
            )

    def claim_channels(
        self,
        channels: _BootstrapChannels,
        *,
        _authority: object,
    ) -> None:
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid bootstrap channel authority")
        if type(channels) is not _BootstrapChannels:
            raise TypeError("channels must be BootstrapChannels")
        with self._lock:
            if (
                self._channels is not None
                or self._process_owner is not None
                or self._channel_close_uncertain
                or any(fd not in self._raw_fds for fd in channels.all_fds())
            ):
                raise _BootstrapBoundaryFailure
            object.__setattr__(self, "_channels", channels)

    def channels(self) -> _BootstrapChannels:
        with self._lock:
            selected = self._channels
            if type(selected) is not _BootstrapChannels:
                raise _BootstrapBoundaryFailure
            return selected

    def owns_channels(self, channels: _BootstrapChannels) -> bool:
        with self._lock:
            return self._channels is channels

    def build_process_owner(
        self,
        *,
        binding: _SupervisorBootstrapBinding,
        _authority: object,
    ) -> "_BootstrapProcessOwner":
        if _authority is not _ACQUISITION_AUTHORITY:
            raise TypeError("invalid process owner authority")
        with self._lock:
            channels = self._channels
            if (
                type(channels) is not _BootstrapChannels
                or self._process_owner is not None
            ):
                raise _BootstrapBoundaryFailure
            selected = _BootstrapProcessOwner(
                binding=binding,
                channels=channels,
            )
            # Publish the new owner before retiring the acquisition copy.  An
            # interruption between these assignments therefore converges on
            # process-owner cleanup and never raw-closes the same FD numbers.
            object.__setattr__(self, "_process_owner", selected)
            channel_fds = frozenset(channels.all_fds())
            self._raw_fds[:] = [
                fd for fd in self._raw_fds if fd not in channel_fds
            ]
            object.__setattr__(self, "_channels", None)
            return selected

    def process_owner(self) -> "_BootstrapProcessOwner | None":
        with self._lock:
            return self._process_owner

    def close_executable_lease_once(self) -> None:
        with self._lock:
            if self._lease_close_uncertain:
                raise _BootstrapBoundaryFailure
            lease = self._executable_lease
            if lease is None:
                return
            # Retire the numeric descriptor before calling close.  A
            # close-then-interrupt fault can never replay this number after an
            # unrelated descriptor has reused it.
            try:
                self._raw_fds.remove(lease.fd)
                object.__setattr__(self, "_executable_lease", None)
                os.close(lease.fd)
            except BaseException:
                object.__setattr__(self, "_lease_close_uncertain", True)
                raise _BootstrapBoundaryFailure from None

    def _close_claimed_raw_fds_once_locked(
        self,
        fds: tuple[int, ...],
        *,
        channels: bool,
    ) -> None:
        for fd in fds:
            if fd not in self._raw_fds:
                continue
            try:
                self._raw_fds.remove(fd)
                os.close(fd)
            except BaseException:
                object.__setattr__(self, "_raw_close_uncertain", True)
                if channels:
                    object.__setattr__(
                        self,
                        "_channel_close_uncertain",
                        True,
                    )

    def _close_untransferred_channels_once_locked(self) -> None:
        channels = self._channels
        if channels is None:
            return
        object.__setattr__(self, "_channels", None)
        self._close_claimed_raw_fds_once_locked(
            channels.all_fds(),
            channels=True,
        )

    def cleanup(self, *, max_wait_ns: int) -> bool:
        cleanup_uncertain = False
        with self._lock:
            if not self.destroy_native_handles():
                cleanup_uncertain = True
            owner = self._process_owner
            if owner is not None:
                # The process owner is the sole FD owner after publication,
                # even if an interruption prevented the redundant channel
                # reference from being retired.
                channels = self._channels
                if channels is not None:
                    channel_fds = frozenset(channels.all_fds())
                    self._raw_fds[:] = [
                        fd for fd in self._raw_fds if fd not in channel_fds
                    ]
                object.__setattr__(self, "_channels", None)
            else:
                self._close_untransferred_channels_once_locked()
            try:
                self.close_executable_lease_once()
            except BaseException:
                cleanup_uncertain = True
            self._close_claimed_raw_fds_once_locked(
                tuple(self._raw_fds),
                channels=False,
            )
        if owner is not None:
            try:
                terminal = owner.shutdown(max_wait_ns=max_wait_ns)
            except BaseException:
                terminal = False
                cleanup_uncertain = True
        else:
            terminal = True
        with self._lock:
            return (
                terminal
                and not cleanup_uncertain
                and not self._lease_close_uncertain
                and not self._channel_close_uncertain
                and not self._raw_close_uncertain
                and not self._native_handles
                and not self._native_initializations_inflight
                and not self._native_destroy_uncertain
                and self._raw_acquisitions_inflight == 0
                and self._executable_lease is None
                and not self._raw_fds
                and self._channels is None
            )

    def recovery_refs_held(self) -> bool:
        with self._lock:
            owner = self._process_owner
            return (
                self._executable_lease is not None
                or bool(self._raw_fds)
                or self._raw_acquisitions_inflight != 0
                or bool(self._native_handles)
                or bool(self._native_initializations_inflight)
                or bool(self._native_destroy_uncertain)
                or self._channels is not None
                or self._lease_close_uncertain
                or self._channel_close_uncertain
                or self._raw_close_uncertain
                or (owner is not None and not owner.locally_terminal())
            )

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "channel_close_uncertain": self._channel_close_uncertain,
                "channels_claimed": self._channels is not None,
                "executable_lease_claimed": (
                    self._executable_lease is not None
                ),
                "lease_close_uncertain": self._lease_close_uncertain,
                "process_owner_present": self._process_owner is not None,
                "raw_close_uncertain": self._raw_close_uncertain,
                "raw_acquisitions_inflight": (
                    self._raw_acquisitions_inflight
                ),
                "raw_descriptor_count": len(self._raw_fds),
                "native_handle_count": len(self._native_handles),
                "native_initialization_inflight_count": len(
                    self._native_initializations_inflight
                ),
                "native_destroy_uncertain_count": len(
                    self._native_destroy_uncertain
                ),
                "recovery_refs_held": self.recovery_refs_held(),
            }


def _close_raw_fds(fds: tuple[int, ...]) -> bool:
    clean = True
    for fd in fds:
        try:
            os.close(fd)
        except BaseException:
            clean = False
    return clean


def _create_bootstrap_channels(
    acquisition: _BootstrapAcquisitionOwner,
) -> _BootstrapChannels:
    opened: list[int] = []
    channels: _BootstrapChannels | None = None

    def open_pipe_claimed() -> tuple[int, int]:
        acquisition.begin_raw_acquisition(
            _authority=_ACQUISITION_AUTHORITY
        )
        try:
            selected = os.pipe()
        except BaseException:
            raise
        acquisition.claim_raw_fds(
            selected,
            _authority=_ACQUISITION_AUTHORITY,
        )
        opened.extend(selected)
        return selected

    try:
        parent_control, child_control = open_pipe_claimed()
        child_parent_read, parent_write = open_pipe_claimed()
        parent_supervisor_read, child_supervisor_write = open_pipe_claimed()
        parent_stderr, child_stderr = open_pipe_claimed()
        all_fds = tuple(opened)
        if len(set(all_fds)) != 8 or any(fd < 3 for fd in all_fds):
            raise _BootstrapBoundaryFailure
        for fd in opened:
            os.set_inheritable(fd, False)
            if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                raise _BootstrapBoundaryFailure
        os.set_blocking(parent_control, False)
        os.set_blocking(parent_supervisor_read, False)
        os.set_blocking(parent_stderr, False)

        channels = _BootstrapChannels(
            parent_control=parent_control,
            child_control=child_control,
            parent_liveness_write=parent_write,
            child_parent_liveness_read=child_parent_read,
            parent_supervisor_liveness_read=parent_supervisor_read,
            child_supervisor_liveness_write=child_supervisor_write,
            parent_stderr=parent_stderr,
            child_stderr=child_stderr,
        )
        acquisition.claim_channels(
            channels,
            _authority=_ACQUISITION_AUTHORITY,
        )
        opened.clear()
        return channels
    except BaseException:
        claimed = (
            channels is not None and acquisition.owns_channels(channels)
        )
        if not claimed:
            unowned = tuple(
                fd for fd in opened if not acquisition.owns_raw_fd(fd)
            )
            if not _close_raw_fds(unowned):
                acquisition.mark_raw_acquisition_uncertain(
                    _authority=_ACQUISITION_AUTHORITY
                )
        raise _BootstrapBoundaryFailure from None


def _configure_spawn_functions(libc: object) -> tuple[object, ...]:
    try:
        actions_init = libc.posix_spawn_file_actions_init
        actions_destroy = libc.posix_spawn_file_actions_destroy
        actions_adddup2 = libc.posix_spawn_file_actions_adddup2
        actions_addclose = libc.posix_spawn_file_actions_addclose
        actions_addinherit = libc.posix_spawn_file_actions_addinherit_np
        attr_init = libc.posix_spawnattr_init
        attr_destroy = libc.posix_spawnattr_destroy
        attr_setflags = libc.posix_spawnattr_setflags
        attr_setsigdefault = libc.posix_spawnattr_setsigdefault
        attr_setsigmask = libc.posix_spawnattr_setsigmask
        sigemptyset = libc.sigemptyset
        sigfillset = libc.sigfillset
        sigdelset = libc.sigdelset
        spawn = libc.posix_spawn

        opaque_pointer_pointer = ctypes.POINTER(ctypes.c_void_p)
        char_pointer_pointer = ctypes.POINTER(ctypes.c_char_p)
        signal_set_pointer = ctypes.POINTER(ctypes.c_uint32)
        actions_init.argtypes = [opaque_pointer_pointer]
        actions_destroy.argtypes = [opaque_pointer_pointer]
        actions_adddup2.argtypes = [
            opaque_pointer_pointer,
            ctypes.c_int,
            ctypes.c_int,
        ]
        actions_addclose.argtypes = [opaque_pointer_pointer, ctypes.c_int]
        actions_addinherit.argtypes = [opaque_pointer_pointer, ctypes.c_int]
        attr_init.argtypes = [opaque_pointer_pointer]
        attr_destroy.argtypes = [opaque_pointer_pointer]
        attr_setflags.argtypes = [opaque_pointer_pointer, ctypes.c_short]
        attr_setsigdefault.argtypes = [
            opaque_pointer_pointer,
            signal_set_pointer,
        ]
        attr_setsigmask.argtypes = [
            opaque_pointer_pointer,
            signal_set_pointer,
        ]
        sigemptyset.argtypes = [signal_set_pointer]
        sigfillset.argtypes = [signal_set_pointer]
        sigdelset.argtypes = [signal_set_pointer, ctypes.c_int]
        spawn.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
            opaque_pointer_pointer,
            opaque_pointer_pointer,
            char_pointer_pointer,
            char_pointer_pointer,
        ]
        for function in (
            actions_init,
            actions_destroy,
            actions_adddup2,
            actions_addclose,
            actions_addinherit,
            attr_init,
            attr_destroy,
            attr_setflags,
            attr_setsigdefault,
            attr_setsigmask,
            sigemptyset,
            sigfillset,
            sigdelset,
            spawn,
        ):
            function.restype = ctypes.c_int
        return (
            actions_init,
            actions_destroy,
            actions_adddup2,
            actions_addclose,
            actions_addinherit,
            attr_init,
            attr_destroy,
            attr_setflags,
            attr_setsigdefault,
            attr_setsigmask,
            sigemptyset,
            sigfillset,
            sigdelset,
            spawn,
        )
    except BaseException:
        raise _BootstrapBoundaryFailure from None


def _ready_payload(
    binding: _SupervisorBootstrapBinding,
    *,
    process_id: int,
    parent_process_id: int,
) -> dict[str, object]:
    return {
        "binding_digest": binding.binding_digest,
        "bootstrap_id": str(binding.bootstrap_id),
        "challenge_id": str(binding.challenge_id),
        "control_channel_id": str(binding.control_channel_id),
        "environment_allowlist_only": True,
        "epoch_id": str(binding.epoch_id),
        "executable_sha256": binding.executable_sha256,
        "kind": "READY",
        "local_probe_policy_digest": binding.local_probe_policy_digest,
        "operation_children_created": 0,
        "parent_environment_canary_absent": True,
        "parent_liveness_id": str(binding.parent_liveness_id),
        "parent_process_id": parent_process_id,
        "process_id": process_id,
        "protocol_version": SUPERVISOR_BOOTSTRAP_PROTOCOL_VERSION,
        "schema_version": SUPERVISOR_READY_SCHEMA_VERSION,
        "supervisor_liveness_id": str(binding.supervisor_liveness_id),
        "unexpected_fd_count": 0,
    }


def _encode_ready_frame(
    binding: _SupervisorBootstrapBinding,
    *,
    process_id: int,
    parent_process_id: int,
) -> bytes:
    return (
        json.dumps(
            _ready_payload(
                binding,
                process_id=process_id,
                parent_process_id=parent_process_id,
            ),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


@runtime_final
class _BootstrapProcessOwner:
    """Exact PID/FD owner for one local supervisor bootstrap attempt."""

    __slots__ = (
        "binding",
        "_lock",
        "_channels",
        "_spawn_pid_cell",
        "_spawn_state",
        "_pid",
        "_wait_state",
        "_wait_status",
        "_kill_sent",
        "_kill_uncertain",
        "_parent_liveness_closed",
        "_control_buffer",
        "_ready_frame_digest",
        "_stderr_size",
        "_close_uncertain",
    )

    def __init__(
        self,
        *,
        binding: _SupervisorBootstrapBinding,
        channels: _BootstrapChannels,
    ) -> None:
        binding.validate_integrity()
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_channels", list(channels))
        object.__setattr__(self, "_spawn_pid_cell", ctypes.c_int(0))
        object.__setattr__(self, "_spawn_state", _SpawnState.NOT_CALLED)
        object.__setattr__(self, "_pid", None)
        object.__setattr__(self, "_wait_state", _WaitState.NOT_CALLED)
        object.__setattr__(self, "_wait_status", None)
        object.__setattr__(self, "_kill_sent", False)
        object.__setattr__(self, "_kill_uncertain", False)
        object.__setattr__(self, "_parent_liveness_closed", False)
        object.__setattr__(self, "_control_buffer", b"")
        object.__setattr__(self, "_ready_frame_digest", None)
        object.__setattr__(self, "_stderr_size", 0)
        object.__setattr__(self, "_close_uncertain", False)

    def _fd(self, index: int) -> int | None:
        selected = self._channels[index]
        return selected if type(selected) is int else None

    def _take_fd(self, index: int) -> int | None:
        selected = self._fd(index)
        self._channels[index] = None
        return selected

    def _begin_spawn(self) -> None:
        with self._lock:
            if self._spawn_state is not _SpawnState.NOT_CALLED:
                raise _BootstrapBoundaryFailure
            self._spawn_state = _SpawnState.IN_FLIGHT

    def _record_spawn_failure(self) -> None:
        with self._lock:
            if self._spawn_state is not _SpawnState.IN_FLIGHT:
                raise _BootstrapBoundaryFailure
            self._spawn_state = _SpawnState.FAILED
            self._spawn_pid_cell.value = 0

    def _record_spawn_success(self) -> None:
        with self._lock:
            if (
                self._spawn_state is not _SpawnState.IN_FLIGHT
                or type(self._spawn_pid_cell.value) is not int
                or self._spawn_pid_cell.value <= 0
            ):
                self._spawn_state = _SpawnState.UNCERTAIN
                raise _BootstrapBoundaryFailure
            self._spawn_state = _SpawnState.SUCCEEDED

    def _bind_spawned_pid(self) -> None:
        with self._lock:
            if self._pid is not None:
                raise _BootstrapBoundaryFailure
            self._ensure_pid_bound_locked()

    def _ensure_pid_bound_locked(self) -> int:
        pid = self._pid
        if pid is None:
            cell_pid = self._spawn_pid_cell.value
            if (
                self._spawn_state is _SpawnState.SUCCEEDED
                and type(cell_pid) is int
                and cell_pid > 0
            ):
                # Recovery may arrive after libc returned exact success and the
                # success state was published, but before the normal cache bind.
                self._pid = cell_pid
                pid = cell_pid
        if type(pid) is not int or pid <= 0:
            raise _BootstrapBoundaryFailure
        return pid

    def _mark_spawn_uncertain_if_inflight(self) -> None:
        with self._lock:
            if self._spawn_state is _SpawnState.IN_FLIGHT:
                self._spawn_state = _SpawnState.UNCERTAIN

    def _close_fd_once_locked(self, index: int) -> None:
        try:
            fd = self._take_fd(index)
            if fd is None:
                return
            os.close(fd)
        except BaseException:
            self._close_uncertain = True
            raise _BootstrapBoundaryFailure from None

    def close_child_fds_after_spawn(self) -> None:
        with self._lock:
            self._close_indices_locked((1, 3, 5, 7))

    def close_all_without_child(self) -> None:
        with self._lock:
            if self._spawn_state not in (
                _SpawnState.NOT_CALLED,
                _SpawnState.FAILED,
            ):
                raise _BootstrapBoundaryFailure
            self._close_indices_locked(tuple(range(len(self._channels))))

    def _close_indices_locked(self, indices: tuple[int, ...]) -> None:
        close_uncertain = False
        for index in indices:
            try:
                self._close_fd_once_locked(index)
            except BaseException:
                self._close_uncertain = True
                close_uncertain = True
        if close_uncertain:
            raise _BootstrapBoundaryFailure

    def _drain_stderr_locked(self) -> None:
        fd = self._fd(6)
        if fd is None:
            return
        while True:
            try:
                chunk = os.read(fd, 1_024)
            except BlockingIOError:
                return
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    return
                raise _BootstrapBoundaryFailure from None
            except BaseException:
                raise _BootstrapBoundaryFailure from None
            if not chunk:
                self._close_fd_once_locked(6)
                return
            self._stderr_size += len(chunk)
            if self._stderr_size > MAX_SUPERVISOR_STDERR_BYTES:
                raise _BootstrapBoundaryFailure
            # Any supervisor bootstrap stderr makes READY ineligible; bytes are
            # counted only and are never copied into an error or metadata.
            raise _BootstrapBoundaryFailure

    def _record_wait_result_locked(
        self,
        result: tuple[int, int],
    ) -> int | None:
        waited_pid, status = result
        if waited_pid == 0:
            self._wait_state = _WaitState.NOT_CALLED
            return None
        if (
            self._pid is None
            or waited_pid != self._pid
            or type(status) is not int
            or status < 0
        ):
            self._wait_state = _WaitState.UNCERTAIN
            raise _BootstrapBoundaryFailure
        self._wait_status = status
        return self._finish_wait_bookkeeping_locked()

    def _finish_wait_bookkeeping_locked(self) -> int:
        status = self._wait_status
        if type(status) is not int or status < 0:
            self._wait_state = _WaitState.UNCERTAIN
            raise _BootstrapBoundaryFailure
        # Once the exact wait result is retained, this tail is idempotent local
        # bookkeeping.  Publish COMPLETED last so every partial assignment can
        # safely converge without a second waitpid call.
        self._pid = None
        self._spawn_pid_cell.value = 0
        self._kill_uncertain = False
        self._wait_state = _WaitState.COMPLETED
        return status

    def _wait_nohang_locked(self) -> int | None:
        if self._wait_status is not None:
            return self._finish_wait_bookkeeping_locked()
        if self._wait_state is _WaitState.COMPLETED:
            raise _BootstrapBoundaryFailure
        if self._wait_state in (
            _WaitState.IN_FLIGHT,
            _WaitState.UNCERTAIN,
        ):
            self._wait_state = _WaitState.UNCERTAIN
            raise _BootstrapBoundaryFailure
        if self._spawn_state is not _SpawnState.SUCCEEDED:
            raise _BootstrapBoundaryFailure
        exact_pid = self._ensure_pid_bound_locked()
        self._wait_state = _WaitState.IN_FLIGHT
        try:
            result = os.waitpid(exact_pid, os.WNOHANG)
        except OSError as error:
            if error.errno == errno.EINTR:
                self._wait_state = _WaitState.NOT_CALLED
                return None
            self._wait_state = _WaitState.UNCERTAIN
            raise _BootstrapBoundaryFailure from None
        except BaseException:
            self._wait_state = _WaitState.UNCERTAIN
            raise _BootstrapBoundaryFailure from None
        try:
            return self._record_wait_result_locked(result)
        except BaseException:
            if self._wait_state is _WaitState.IN_FLIGHT:
                self._wait_state = _WaitState.UNCERTAIN
            raise

    def _poll_events_locked(
        self,
        *,
        max_wait_ns: int,
    ) -> dict[int, int]:
        interests = tuple(
            fd
            for fd in (self._fd(0), self._fd(4), self._fd(6))
            if fd is not None
        )
        try:
            poller = select.poll()
            for fd in interests:
                poller.register(fd, select.POLLIN | select.POLLHUP)
            events = poller.poll(max_wait_ns // 1_000_000)
        except OSError as error:
            if error.errno == errno.EINTR:
                return {}
            raise _BootstrapBoundaryFailure from None
        except BaseException:
            raise _BootstrapBoundaryFailure from None
        result: dict[int, int] = {}
        for fd, mask in events:
            if mask & (select.POLLERR | select.POLLNVAL):
                raise _BootstrapBoundaryFailure
            result[fd] = result.get(fd, 0) | mask
        return result

    def _consume_liveness_event_locked(self, events: dict[int, int]) -> None:
        fd = self._fd(4)
        if fd is None or fd not in events:
            return
        try:
            observed = os.read(fd, 1)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                return
            raise _BootstrapLivenessLost from None
        except BaseException:
            raise _BootstrapLivenessLost from None
        # The child never sends data on this pipe.  A byte and EOF are both a
        # protocol/liveness failure, and loss wins over a simultaneous READY.
        del observed
        raise _BootstrapLivenessLost

    def _consume_control_locked(self) -> bytes:
        fd = self._fd(0)
        if fd is None:
            raise _BootstrapBoundaryFailure
        try:
            chunk = os.read(fd, MAX_SUPERVISOR_READY_FRAME_BYTES + 1)
        except BlockingIOError:
            raise _BootstrapBoundaryFailure from None
        except BaseException:
            raise _BootstrapBoundaryFailure from None
        if not chunk:
            raise _BootstrapLivenessLost
        frame = self._control_buffer + chunk
        if len(frame) > MAX_SUPERVISOR_READY_FRAME_BYTES:
            raise _BootstrapBoundaryFailure
        self._control_buffer = frame
        return frame

    def await_ready(
        self,
        *,
        expected_frame: bytes,
        max_wait_ns: int,
    ) -> Digest256:
        deadline = _monotonic_ns() + max_wait_ns
        with self._lock:
            while True:
                self._drain_stderr_locked()
                if self._wait_nohang_locked() is not None:
                    raise _BootstrapLivenessLost
                remaining = deadline - _monotonic_ns()
                if remaining <= 0:
                    raise _BootstrapBoundaryFailure
                events = self._poll_events_locked(max_wait_ns=remaining)
                self._consume_liveness_event_locked(events)
                stderr_fd = self._fd(6)
                if stderr_fd is not None and stderr_fd in events:
                    self._drain_stderr_locked()
                control_fd = self._fd(0)
                if control_fd is None or control_fd not in events:
                    continue
                frame = self._consume_control_locked()
                if not expected_frame.startswith(frame):
                    raise _BootstrapBoundaryFailure
                if len(frame) < len(expected_frame):
                    continue
                selected = digest256(
                    "ResolverSupervisorReadyFrame",
                    SUPERVISOR_READY_SCHEMA_VERSION,
                    {
                        "frame_sha256": Digest256(
                            hashlib.sha256(frame).hexdigest()
                        ),
                        "frame_size": len(frame),
                    },
                )
                self._ready_frame_digest = selected
                # READY publication requires a final zero-wait liveness and
                # unsolicited-control check.  A later record is still caught by
                # every session liveness probe.
                self._drain_stderr_locked()
                if self._wait_nohang_locked() is not None:
                    raise _BootstrapLivenessLost
                final_events = self._poll_events_locked(max_wait_ns=0)
                self._consume_liveness_event_locked(final_events)
                if control_fd in final_events:
                    raise _BootstrapBoundaryFailure
                return selected

    def require_live(self, *, max_wait_ns: int) -> None:
        with self._lock:
            if self._ready_frame_digest is None:
                raise _BootstrapBoundaryFailure
            self._drain_stderr_locked()
            if self._wait_nohang_locked() is not None:
                raise _BootstrapLivenessLost
            events = self._poll_events_locked(max_wait_ns=max_wait_ns)
            self._consume_liveness_event_locked(events)
            stderr_fd = self._fd(6)
            if stderr_fd is not None and stderr_fd in events:
                self._drain_stderr_locked()
            control_fd = self._fd(0)
            if control_fd is not None and control_fd in events:
                # A second READY or any unsolicited S2a control record is an
                # equivocation.  S3 will introduce its own exact message types.
                self._consume_control_locked()
                raise _BootstrapBoundaryFailure
            if self._wait_nohang_locked() is not None:
                raise _BootstrapLivenessLost

    def _close_parent_liveness_locked(self) -> None:
        if self._parent_liveness_closed:
            return
        self._close_fd_once_locked(2)
        # The channel slot retirement above is the one-shot close claim.  If
        # publication is interrupted, a retry observes a None slot and cannot
        # replay a reused descriptor number.
        self._parent_liveness_closed = True

    def _kill_once_locked(self) -> None:
        if self._kill_sent:
            return
        if self._kill_uncertain or self._pid is None:
            raise _BootstrapBoundaryFailure
        if self._wait_nohang_locked() is not None:
            return
        exact_pid = self._pid
        # Claim the destructive action before entering the syscall.  If an
        # asynchronous exception lands after the kernel acted but before the
        # success assignment, uncertainty blocks every replay; exact waitpid
        # may still prove resource terminal later.
        self._kill_uncertain = True
        try:
            os.kill(exact_pid, signal.SIGKILL)
        except OSError as error:
            if error.errno == errno.ESRCH:
                # ESRCH is not terminal proof.  It only proves this kill call
                # need not be replayed; exact waitpid remains mandatory.
                self._kill_sent = True
                self._kill_uncertain = False
                return
            raise _BootstrapBoundaryFailure from None
        except BaseException:
            raise _BootstrapBoundaryFailure from None
        self._kill_sent = True
        self._kill_uncertain = False

    def shutdown(self, *, max_wait_ns: int) -> bool:
        started = _monotonic_ns()
        deadline = started + max_wait_ns
        grace_deadline = started + (max_wait_ns // 2)
        with self._lock:
            try:
                if self._wait_state is _WaitState.COMPLETED:
                    return self._finish_terminal_locked()
                if self._spawn_state in (
                    _SpawnState.NOT_CALLED,
                    _SpawnState.FAILED,
                ):
                    self.close_all_without_child()
                    return True
                if self._spawn_state is not _SpawnState.SUCCEEDED:
                    # The raw PID cell is not authoritative and must never be
                    # killed or waited.  All exact local FD capabilities can
                    # still be retired by the failure handler below.
                    raise _BootstrapBoundaryFailure
                self._ensure_pid_bound_locked()
                self._close_parent_liveness_locked()
                while _monotonic_ns() < grace_deadline:
                    if self._wait_nohang_locked() is not None:
                        return self._finish_terminal_locked()
                    remaining = grace_deadline - _monotonic_ns()
                    if remaining <= 0:
                        break
                    self._poll_events_locked(
                        max_wait_ns=min(remaining, 25_000_000)
                    )
                self._kill_once_locked()
                while True:
                    if self._wait_nohang_locked() is not None:
                        return self._finish_terminal_locked()
                    remaining = deadline - _monotonic_ns()
                    if remaining <= 0:
                        break
                    self._poll_events_locked(
                        max_wait_ns=min(remaining, 25_000_000)
                    )
                raise _BootstrapBoundaryFailure
            except BaseException:
                # PID/wait/kill uncertainty must remain permanent, but none of
                # those unknowns require retaining a known local FD.  Retire
                # every endpoint once so cleanup cannot leak capabilities.
                try:
                    self._close_indices_locked(
                        tuple(range(len(self._channels)))
                    )
                except BaseException:
                    pass
                raise

    def _finish_terminal_locked(self) -> bool:
        if self._wait_state is not _WaitState.COMPLETED:
            return False
        self._close_indices_locked((0, 2, 4, 6, 1, 3, 5, 7))
        return self._locally_terminal_locked()

    def _clean_exit_locked(self) -> bool:
        status = self._wait_status
        return (
            type(status) is int
            and os.WIFEXITED(status)
            and os.WEXITSTATUS(status) == 0
        )

    def clean_exit(self) -> bool:
        with self._lock:
            return self._locally_terminal_locked() and self._clean_exit_locked()

    def _locally_terminal_locked(self) -> bool:
        return (
            self._wait_state is _WaitState.COMPLETED
            and self._pid is None
            and self._spawn_pid_cell.value == 0
            and all(item is None for item in self._channels)
            and not self._kill_uncertain
            and not self._close_uncertain
        )

    def locally_terminal(self) -> bool:
        with self._lock:
            if self._spawn_state in (
                _SpawnState.NOT_CALLED,
                _SpawnState.FAILED,
            ):
                return (
                    all(item is None for item in self._channels)
                    and not self._close_uncertain
                )
            return self._locally_terminal_locked()

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "child_endpoint_count": sum(
                    self._fd(index) is not None for index in (1, 3, 5, 7)
                ),
                "clean_exit": self.clean_exit(),
                "kill_sent": self._kill_sent,
                "locally_terminal": self.locally_terminal(),
                "parent_endpoint_count": sum(
                    self._fd(index) is not None for index in (0, 2, 4, 6)
                ),
                "pid_bound": self._pid is not None,
                "ready_observed": self._ready_frame_digest is not None,
                "spawn_state": self._spawn_state.value,
                "wait_state": self._wait_state.value,
            }


def _monotonic_ns() -> int:
    try:
        selected = __import__("time").monotonic_ns()
    except BaseException:
        raise _BootstrapBoundaryFailure from None
    if type(selected) is not int or selected < 0:
        raise _BootstrapBoundaryFailure
    return selected


def _spawn_local_probe(
    *,
    policy: _LocalSupervisorProbePolicy,
    binding: _SupervisorBootstrapBinding,
    channels: _BootstrapChannels,
    owner: _BootstrapProcessOwner,
    acquisition: _BootstrapAcquisitionOwner,
) -> None:
    actions = ctypes.c_void_p()
    attributes = ctypes.c_void_p()
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        (
            actions_init,
            actions_destroy,
            actions_adddup2,
            actions_addclose,
            actions_addinherit,
            attr_init,
            attr_destroy,
            attr_setflags,
            attr_setsigdefault,
            attr_setsigmask,
            sigemptyset,
            sigfillset,
            sigdelset,
            posix_spawn,
        ) = _configure_spawn_functions(libc)
        acquisition.begin_native_handle_initialization(
            "file_actions",
            _authority=_ACQUISITION_AUTHORITY,
        )
        actions_result = actions_init(ctypes.byref(actions))
        if actions_result != 0:
            acquisition.record_native_handle_initialization_failure(
                "file_actions",
                _authority=_ACQUISITION_AUTHORITY,
            )
            raise _BootstrapBoundaryFailure
        acquisition.claim_native_handle(
            "file_actions",
            storage=actions,
            destroy=actions_destroy,
            _authority=_ACQUISITION_AUTHORITY,
        )
        acquisition.begin_native_handle_initialization(
            "spawn_attributes",
            _authority=_ACQUISITION_AUTHORITY,
        )
        attributes_result = attr_init(ctypes.byref(attributes))
        if attributes_result != 0:
            acquisition.record_native_handle_initialization_failure(
                "spawn_attributes",
                _authority=_ACQUISITION_AUTHORITY,
            )
            raise _BootstrapBoundaryFailure
        acquisition.claim_native_handle(
            "spawn_attributes",
            storage=attributes,
            destroy=attr_destroy,
            _authority=_ACQUISITION_AUTHORITY,
        )
        if (
            attr_setflags(
                ctypes.byref(attributes),
                ctypes.c_short(_POSIX_SPAWN_FLAGS),
            )
            != 0
        ):
            raise _BootstrapBoundaryFailure
        empty_signal_mask = ctypes.c_uint32(0)
        default_signal_set = ctypes.c_uint32(0)
        if sigemptyset(ctypes.byref(empty_signal_mask)) != 0:
            raise _BootstrapBoundaryFailure
        if sigfillset(ctypes.byref(default_signal_set)) != 0:
            raise _BootstrapBoundaryFailure
        if sigdelset(ctypes.byref(default_signal_set), signal.SIGKILL) != 0:
            raise _BootstrapBoundaryFailure
        if sigdelset(ctypes.byref(default_signal_set), signal.SIGSTOP) != 0:
            raise _BootstrapBoundaryFailure
        if (
            attr_setsigmask(
                ctypes.byref(attributes),
                ctypes.byref(empty_signal_mask),
            )
            != 0
            or attr_setsigdefault(
                ctypes.byref(attributes),
                ctypes.byref(default_signal_set),
            )
            != 0
        ):
            raise _BootstrapBoundaryFailure

        for source_fd, target_fd in (
            (channels.child_control, 1),
            (channels.child_stderr, 2),
        ):
            if (
                actions_adddup2(
                    ctypes.byref(actions),
                    source_fd,
                    target_fd,
                )
                != 0
            ):
                raise _BootstrapBoundaryFailure
        if actions_addclose(ctypes.byref(actions), 0) != 0:
            raise _BootstrapBoundaryFailure
        for fd in (
            channels.child_parent_liveness_read,
            channels.child_supervisor_liveness_write,
        ):
            if actions_addinherit(ctypes.byref(actions), fd) != 0:
                raise _BootstrapBoundaryFailure
        for fd in (
            channels.parent_control,
            channels.child_control,
            channels.parent_liveness_write,
            channels.parent_supervisor_liveness_read,
            channels.parent_stderr,
            channels.child_stderr,
        ):
            if actions_addclose(ctypes.byref(actions), fd) != 0:
                raise _BootstrapBoundaryFailure

        argv_text = (
            policy.executable,
            _SUPERVISOR_ARG,
            str(binding.bootstrap_id),
            str(binding.epoch_id),
            str(binding.challenge_id),
            str(binding.control_channel_id),
            str(binding.parent_liveness_id),
            str(binding.supervisor_liveness_id),
            str(binding.local_probe_policy_digest),
            str(binding.executable_sha256),
            str(binding.binding_digest),
            str(channels.child_parent_liveness_read),
            str(channels.child_supervisor_liveness_write),
        )
        argv_bytes = tuple(os.fsencode(item) for item in argv_text)
        environment_bytes = tuple(
            f"{name}={value}".encode("ascii")
            for name, value in _SUPERVISOR_ENVIRONMENT
        )
        if any(not item or b"\x00" in item for item in argv_bytes):
            raise _BootstrapBoundaryFailure
        executable_bytes = os.fsencode(policy.executable)
        argv_type = ctypes.c_char_p * (len(argv_bytes) + 1)
        environment_type = ctypes.c_char_p * (len(environment_bytes) + 1)
        argv = argv_type(*argv_bytes, None)
        environment = environment_type(*environment_bytes, None)

        owner._begin_spawn()
        result = posix_spawn(
            ctypes.byref(owner._spawn_pid_cell),
            executable_bytes,
            ctypes.byref(actions),
            ctypes.byref(attributes),
            argv,
            environment,
        )
        if result != 0:
            owner._record_spawn_failure()
            raise _BootstrapBoundaryFailure
        owner._record_spawn_success()
        owner._bind_spawned_pid()
    except _BootstrapBoundaryFailure:
        owner._mark_spawn_uncertain_if_inflight()
        raise
    except BaseException:
        owner._mark_spawn_uncertain_if_inflight()
        raise _BootstrapBoundaryFailure from None
    finally:
        if not acquisition.destroy_native_handles():
            raise _BootstrapBoundaryFailure


@runtime_final
class _SupervisorReadyProof:
    """Factory-owned proof for one exact READY record and process owner."""

    __slots__ = (
        "binding",
        "ready_frame_digest",
        "proof_digest",
        "_owner",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        binding: _SupervisorBootstrapBinding,
        ready_frame_digest: Digest256,
        owner: _BootstrapProcessOwner,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _READY_PROOF_AUTHORITY:
            raise TypeError("supervisor READY proof requires its bootstrap")
        binding.validate_integrity()
        checked_frame = require_digest(
            ready_frame_digest,
            "ready_frame_digest",
        )
        if (
            type(owner) is not _BootstrapProcessOwner
            or owner.binding is not binding
            or owner._ready_frame_digest != checked_frame
        ):
            raise ValueError("supervisor READY owner changed")
        selected = digest256(
            "ResolverSupervisorReadyProof",
            SUPERVISOR_READY_PROOF_SCHEMA_VERSION,
            {
                "binding_digest": binding.binding_digest,
                "ready_frame_digest": checked_frame,
            },
        )
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "ready_frame_digest", checked_frame)
        object.__setattr__(self, "proof_digest", selected)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorReadyProof is immutable")

    def validate_integrity(self) -> None:
        self.binding.validate_integrity()
        if (
            type(self._owner) is not _BootstrapProcessOwner
            or self._owner.binding is not self.binding
            or self._owner._ready_frame_digest != self.ready_frame_digest
        ):
            raise ValueError("supervisor READY owner changed")
        selected = digest256(
            "ResolverSupervisorReadyProof",
            SUPERVISOR_READY_PROOF_SCHEMA_VERSION,
            {
                "binding_digest": self.binding.binding_digest,
                "ready_frame_digest": require_digest(
                    self.ready_frame_digest,
                    "ready_frame_digest",
                ),
            },
        )
        if self.proof_digest != selected or self._issued_digest != selected:
            raise ValueError("supervisor READY proof integrity failed")


@runtime_final
class _SupervisorBootstrapSession:
    """READY-bound session; intentionally exposes no operation capability."""

    __slots__ = (
        "binding",
        "ready_proof",
        "_owner",
        "_broker_ports",
        "_state_ledger",
        "_lock",
        "_broker_poison_observed",
        "_parent_poison_observed",
        "_pending_epoch_end_reason",
    )

    def __init__(
        self,
        *,
        binding: _SupervisorBootstrapBinding,
        ready_proof: _SupervisorReadyProof,
        owner: _BootstrapProcessOwner,
        broker_ports: _SupervisorBrokerPorts,
        state_ledger: _BootstrapStateLedger,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _SESSION_AUTHORITY:
            raise TypeError("supervisor bootstrap session requires its factory")
        binding.validate_integrity()
        ready_proof.validate_integrity()
        if (
            ready_proof.binding is not binding
            or ready_proof._owner is not owner
            or type(state_ledger) is not _BootstrapStateLedger
            or state_ledger.state() is not _BootstrapState.READY_PENDING
            or broker_ports.ledger.epoch_id != binding.epoch_id
            or broker_ports.parent_session is not broker_ports.ledger._parent_session
        ):
            raise ValueError("supervisor bootstrap session owner changed")
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "ready_proof", ready_proof)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_broker_ports", broker_ports)
        object.__setattr__(self, "_state_ledger", state_ledger)
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_broker_poison_observed", False)
        object.__setattr__(self, "_parent_poison_observed", False)
        object.__setattr__(self, "_pending_epoch_end_reason", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SupervisorBootstrapSession identity is immutable")

    def _fanout_epoch_end_locked(self, reason: _PoisonReason) -> None:
        fanout_uncertain = False
        if not self._broker_poison_observed:
            try:
                self._broker_ports.cleanup.poison_epoch(reason=reason)
            except BaseException:
                fanout_uncertain = True
            finally:
                try:
                    observed = self._broker_ports.ledger.safe_metadata()[
                        "global_poison_reason"
                    ] is not None
                except BaseException:
                    observed = False
                    fanout_uncertain = True
                if observed:
                    object.__setattr__(
                        self,
                        "_broker_poison_observed",
                        True,
                    )
        if not self._parent_poison_observed:
            try:
                self._broker_ports.parent_session.observe_liveness_lost(
                    epoch_id=self.binding.epoch_id
                )
            except BaseException:
                fanout_uncertain = True
            finally:
                try:
                    observed = self._broker_ports.parent_session.safe_metadata()[
                        "poisoned"
                    ]
                except BaseException:
                    observed = False
                    fanout_uncertain = True
                if observed:
                    object.__setattr__(
                        self,
                        "_parent_poison_observed",
                        True,
                    )
        if (
            fanout_uncertain
            or not self._broker_poison_observed
            or not self._parent_poison_observed
        ):
            raise _BootstrapBoundaryFailure

    def _fanout_poison_locked(self, reason: _PoisonReason) -> None:
        pending = self._pending_epoch_end_reason
        if pending is None:
            object.__setattr__(self, "_pending_epoch_end_reason", reason)
        elif type(pending) is not _PoisonReason:
            raise _BootstrapBoundaryFailure
        self._state_ledger.poison(reason, _authority=_STATE_AUTHORITY)
        self._fanout_epoch_end_locked(
            self._pending_epoch_end_reason
        )

    def _converge_pending_poison_locked(self) -> None:
        reason = self._pending_epoch_end_reason
        if type(reason) is not _PoisonReason:
            reason = _PoisonReason.OS_ACTION_UNCERTAIN
            object.__setattr__(self, "_pending_epoch_end_reason", reason)
        self._state_ledger.poison(reason, _authority=_STATE_AUTHORITY)
        self._fanout_epoch_end_locked(reason)

    def require_live(self, *, max_wait_ns: int) -> None:
        checked_wait = _require_bootstrap_wait_ns(
            max_wait_ns,
            "max_wait_ns",
            minimum=0,
        )
        with self._lock:
            if self._pending_epoch_end_reason is not None:
                try:
                    self._converge_pending_poison_locked()
                except BaseException:
                    pass
                _raise_bootstrap_error("resolver supervisor session 已不可用。")
            if self._state_ledger.state() is not _BootstrapState.READY_ATTESTED:
                _raise_bootstrap_error("resolver supervisor session 已不可用。")
            try:
                self._owner.require_live(max_wait_ns=checked_wait)
            except BaseException:
                try:
                    self._fanout_poison_locked(_PoisonReason.LIVENESS_LOST)
                except BaseException:
                    pass
                _raise_bootstrap_error("resolver supervisor liveness 已丢失。")

    def shutdown(self, *, max_wait_ns: int) -> bool:
        checked_wait = _require_bootstrap_wait_ns(
            max_wait_ns,
            "max_wait_ns",
            minimum=1,
        )
        with self._lock:
            state = self._state_ledger.state()
            if state is _BootstrapState.TERMINAL_ATTESTED:
                return True
            if state is _BootstrapState.GLOBAL_POISONED:
                fanout_complete = True
                try:
                    self._converge_pending_poison_locked()
                except BaseException:
                    fanout_complete = False
                try:
                    terminal = self._owner.shutdown(max_wait_ns=checked_wait)
                except BaseException:
                    return False
                return terminal and fanout_complete
            if state not in (
                _BootstrapState.READY_ATTESTED,
                _BootstrapState.SHUTDOWN_LATCHED,
            ):
                _raise_bootstrap_error("resolver supervisor shutdown 顺序无效。")
            self._state_ledger.transition(
                _BootstrapState.SHUTDOWN_LATCHED,
                _authority=_STATE_AUTHORITY,
            )
            try:
                terminal = self._owner.shutdown(max_wait_ns=checked_wait)
            except BaseException:
                try:
                    self._fanout_poison_locked(
                        _PoisonReason.OS_ACTION_UNCERTAIN
                    )
                except BaseException:
                    pass
                return False
            if terminal:
                if not self._owner.clean_exit():
                    fanout_complete = True
                    try:
                        self._fanout_poison_locked(
                            _PoisonReason.OS_ACTION_UNCERTAIN
                        )
                    except BaseException:
                        fanout_complete = False
                    # Cleanup is proven complete even though the supervisor's
                    # exit was not the graceful zero status required for a
                    # clean session terminal state.
                    return fanout_complete
                try:
                    # A clean shutdown still closes the S1 epoch.  No broker
                    # capability may remain usable after its process owner is
                    # terminal, even though no S2a operation API was exposed.
                    self._fanout_epoch_end_locked(_PoisonReason.EPOCH_LOST)
                except BaseException:
                    try:
                        self._fanout_poison_locked(
                            _PoisonReason.OS_ACTION_UNCERTAIN
                        )
                    except BaseException:
                        pass
                    return False
                self._state_ledger.transition(
                    _BootstrapState.TERMINAL_ATTESTED,
                    _authority=_STATE_AUTHORITY,
                )
                return True
            try:
                self._fanout_poison_locked(_PoisonReason.OS_ACTION_UNCERTAIN)
            except BaseException:
                pass
            return False

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            broker = self._broker_ports.ledger.safe_metadata()
            state = self._state_ledger.safe_metadata()
            return {
                "actual_process_identity_attested": False,
                "bootstrap_id": str(self.binding.bootstrap_id),
                "broker_global_poison_reason": broker[
                    "global_poison_reason"
                ],
                "broker_operation_count": broker["operation_count"],
                "epoch_id": str(self.binding.epoch_id),
                "identity_scope": "local_path_pre_post_only",
                "operation_api_available": False,
                "poison_fanout_complete": (
                    self._broker_poison_observed
                    and self._parent_poison_observed
                ),
                "ready_proof_digest": str(self.ready_proof.proof_digest),
                "recovery_refs_held": not self._owner.locally_terminal(),
                "state": state["state"],
                "transport_available": False,
            }

@runtime_final
class _DarwinResolverSupervisorBootstrap:
    """One-shot local bootstrap owner; deliberately not production-wired."""

    __slots__ = (
        "_lock",
        "_state_ledger",
        "_attempt",
        "_acquisition_owner",
        "_owner",
        "_broker_ports",
        "_session",
    )

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _BOOTSTRAP_AUTHORITY:
            raise TypeError("supervisor bootstrap requires its factory")
        # start/cleanup are mutation entries, not recursively composable
        # helpers.  A plain lock makes same-thread signal/trace reentry fail
        # closed at their existing non-blocking acquisition boundary.
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(
            self,
            "_state_ledger",
            _BootstrapStateLedger(_authority=_STATE_AUTHORITY),
        )
        object.__setattr__(
            self,
            "_attempt",
            (False, None, None),
        )
        object.__setattr__(self, "_acquisition_owner", None)
        object.__setattr__(self, "_owner", None)
        object.__setattr__(self, "_broker_ports", None)
        object.__setattr__(self, "_session", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinResolverSupervisorBootstrap is immutable")

    def _same_request(
        self,
        policy: _LocalSupervisorProbePolicy,
        binding: _SupervisorBootstrapBinding,
    ) -> bool:
        attempted, stored_binding, stored_policy_digest = self._attempt
        return (
            attempted
            and stored_binding is binding
            and stored_policy_digest == policy.policy_digest
        )

    def _commit_ready(
        self,
        *,
        broker_ports: _SupervisorBrokerPorts,
        session: _SupervisorBootstrapSession,
    ) -> None:
        # Publish the session first: it is the complete recovery anchor and
        # already strongly owns broker_ports.  The second field is only a
        # redundant inspection reference.
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_broker_ports", broker_ports)
        self._state_ledger.transition(
            _BootstrapState.READY_ATTESTED,
            _authority=_STATE_AUTHORITY,
        )

    def start(
        self,
        *,
        policy: _LocalSupervisorProbePolicy,
        binding: _SupervisorBootstrapBinding,
        max_ready_wait_ns: int,
    ) -> _SupervisorBootstrapSession:
        if type(policy) is not _LocalSupervisorProbePolicy:
            raise TypeError("policy must be LocalSupervisorProbePolicy")
        if type(binding) is not _SupervisorBootstrapBinding:
            raise TypeError("binding must be SupervisorBootstrapBinding")
        checked_wait = _require_bootstrap_wait_ns(
            max_ready_wait_ns,
            "max_ready_wait_ns",
            minimum=1,
        )
        try:
            policy.validate_integrity()
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            _raise_bootstrap_error("resolver supervisor bootstrap identity 无效。")
        if (
            binding.local_probe_policy_digest != policy.policy_digest
            or binding.executable_sha256 != policy.executable_sha256
        ):
            _raise_bootstrap_error("resolver supervisor bootstrap identity 无效。")
        if sys.platform != "darwin":
            _raise_bootstrap_error("resolver supervisor Darwin bootstrap 不可用。")
        if not self._lock.acquire(blocking=False):
            _raise_bootstrap_error("resolver supervisor bootstrap 正在进行。")

        acquisition: _BootstrapAcquisitionOwner | None = None
        owner: _BootstrapProcessOwner | None = None
        session: _SupervisorBootstrapSession | None = None
        try:
            if self._session is not None:
                if not self._same_request(policy, binding):
                    poison_reason = _PoisonReason.EPOCH_LOST
                    with self._session._lock:
                        try:
                            self._session._fanout_poison_locked(poison_reason)
                        except BaseException:
                            poison_reason = _PoisonReason.OS_ACTION_UNCERTAIN
                            self._state_ledger.poison(
                                poison_reason,
                                _authority=_STATE_AUTHORITY,
                            )
                    self._state_ledger.poison(
                        poison_reason,
                        _authority=_STATE_AUTHORITY,
                    )
                    _raise_bootstrap_error(
                        "resolver supervisor bootstrap identity 已变化。"
                    )
                self._session.require_live(max_wait_ns=0)
                return self._session
            if self._attempt[0]:
                _raise_bootstrap_error(
                    "resolver supervisor bootstrap 不允许自动重试。"
                )

            self._state_ledger.transition(
                _BootstrapState.PREPARED,
                _authority=_STATE_AUTHORITY,
            )
            object.__setattr__(
                self,
                "_attempt",
                (True, binding, policy.policy_digest),
            )
            acquisition = _BootstrapAcquisitionOwner(
                _authority=_ACQUISITION_AUTHORITY
            )
            object.__setattr__(self, "_acquisition_owner", acquisition)
            _attest_local_probe(policy, acquisition)
            lease = acquisition.executable_lease()
            _create_bootstrap_channels(acquisition)
            channels = acquisition.channels()
            owner = acquisition.build_process_owner(
                binding=binding,
                _authority=_ACQUISITION_AUTHORITY,
            )
            object.__setattr__(self, "_owner", owner)
            self._state_ledger.transition(
                _BootstrapState.SPAWN_CLAIMED,
                _authority=_STATE_AUTHORITY,
            )
            _spawn_local_probe(
                policy=policy,
                binding=binding,
                channels=channels,
                owner=owner,
                acquisition=acquisition,
            )
            owner.close_child_fds_after_spawn()
            if not _probe_path_matches(policy, lease):
                raise _BootstrapBoundaryFailure
            acquisition.close_executable_lease_once()
            self._state_ledger.transition(
                _BootstrapState.READY_PENDING,
                _authority=_STATE_AUTHORITY,
            )
            pid = owner._pid
            if type(pid) is not int or pid <= 0:
                raise _BootstrapBoundaryFailure
            expected = _encode_ready_frame(
                binding,
                process_id=pid,
                parent_process_id=os.getpid(),
            )
            frame_digest = owner.await_ready(
                expected_frame=expected,
                max_wait_ns=checked_wait,
            )
            ready_proof = _SupervisorReadyProof(
                binding=binding,
                ready_frame_digest=frame_digest,
                owner=owner,
                _authority=_READY_PROOF_AUTHORITY,
            )
            broker_ports = _new_supervisor_broker(epoch_id=binding.epoch_id)
            session = _SupervisorBootstrapSession(
                binding=binding,
                ready_proof=ready_proof,
                owner=owner,
                broker_ports=broker_ports,
                state_ledger=self._state_ledger,
                _authority=_SESSION_AUTHORITY,
            )
            owner.require_live(max_wait_ns=0)
            self._commit_ready(
                broker_ports=broker_ports,
                session=session,
            )
            return session
        except BaseException:
            if not self._attempt[0]:
                # The PREPARED transition and this immutable tuple are two
                # Python publications.  If interruption lands between them,
                # recovery completes the bookkeeping before choosing a final
                # failure state; no second attempt can enter.
                object.__setattr__(
                    self,
                    "_attempt",
                    (True, binding, policy.policy_digest),
                )
            committed_session = self._session
            committed_ready_anchor = (
                self._state_ledger.state()
                is _BootstrapState.READY_ATTESTED
                and committed_session is not None
                and session is committed_session
                and acquisition is self._acquisition_owner
                and owner is committed_session._owner
            )
            if committed_ready_anchor:
                # READY/session publication may have committed before an outer
                # interruption.  Exact reentry recovers the same session.
                _raise_bootstrap_error(
                    "resolver supervisor READY 返回未被调用方确认。"
                )
            acquisition = (
                self._acquisition_owner
                if self._acquisition_owner is not None
                else acquisition
            )
            acquired_owner = (
                None if acquisition is None else acquisition.process_owner()
            )
            owner = (
                self._owner
                if self._owner is not None
                else owner if owner is not None else acquired_owner
            )
            spawn_state = (
                None if owner is None else owner._spawn_state
            )
            global_poison = spawn_state in (
                _SpawnState.IN_FLIGHT,
                _SpawnState.SUCCEEDED,
                _SpawnState.UNCERTAIN,
            )
            if acquisition is not None:
                try:
                    if not acquisition.cleanup(max_wait_ns=checked_wait):
                        global_poison = True
                except BaseException:
                    global_poison = True
            elif owner is not None:
                try:
                    owner.shutdown(max_wait_ns=checked_wait)
                except BaseException:
                    global_poison = True
            if global_poison:
                candidate_session = (
                    self._session
                    if self._session is not None
                    else session
                )
                if candidate_session is not None:
                    try:
                        with candidate_session._lock:
                            candidate_session._fanout_poison_locked(
                                _PoisonReason.OS_ACTION_UNCERTAIN
                            )
                    except BaseException:
                        pass
                self._state_ledger.poison(
                    _PoisonReason.OS_ACTION_UNCERTAIN,
                    _authority=_STATE_AUTHORITY,
                )
            else:
                if self._state_ledger.state() is _BootstrapState.NEW:
                    self._state_ledger.transition(
                        _BootstrapState.PREPARED,
                        _authority=_STATE_AUTHORITY,
                    )
                self._state_ledger.transition(
                    _BootstrapState.FAILED_CLEAN,
                    _authority=_STATE_AUTHORITY,
                )
            _raise_bootstrap_error()
        finally:
            self._lock.release()

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            owner = self._owner
            acquisition = self._acquisition_owner
            state = self._state_ledger.safe_metadata()
            return {
                "actual_process_identity_attested": False,
                "attempted": self._attempt[0],
                "global_poison_reason": state["global_poison_reason"],
                "identity_scope": "local_path_pre_post_only",
                "operation_api_available": False,
                "owner_present": owner is not None,
                "recovery_refs_held": (
                    acquisition.recovery_refs_held()
                    if acquisition is not None
                    else owner is not None and not owner.locally_terminal()
                ),
                "session_committed": self._session is not None,
                "state": state["state"],
                "transport_available": False,
            }

    def cleanup(self, *, max_wait_ns: int) -> bool:
        """Continue cleanup only; never retries bootstrap or creates a child."""

        checked_wait = _require_bootstrap_wait_ns(
            max_wait_ns,
            "max_wait_ns",
            minimum=1,
        )
        if not self._lock.acquire(blocking=False):
            return False
        try:
            session = self._session
            if session is not None:
                try:
                    terminal = session.shutdown(max_wait_ns=checked_wait)
                except BaseException:
                    terminal = False
                metadata = session.safe_metadata()
                acquisition = self._acquisition_owner
                return (
                    terminal
                    and not metadata["recovery_refs_held"]
                    and metadata["poison_fanout_complete"]
                    and (
                        acquisition is None
                        or not acquisition.recovery_refs_held()
                    )
                )
            acquisition = self._acquisition_owner
            if acquisition is None:
                return False
            try:
                acquisition.cleanup(max_wait_ns=checked_wait)
            except BaseException:
                pass
            return not acquisition.recovery_refs_held()
        finally:
            self._lock.release()


_PROCESS_BOOTSTRAP_LOCK = Lock()
_PROCESS_BOOTSTRAP: _DarwinResolverSupervisorBootstrap | None = None


def _new_darwin_resolver_supervisor_bootstrap(
) -> _DarwinResolverSupervisorBootstrap:
    global _PROCESS_BOOTSTRAP
    if not _PROCESS_BOOTSTRAP_LOCK.acquire(blocking=False):
        raise _BootstrapBoundaryFailure
    try:
        if _PROCESS_BOOTSTRAP is None:
            _PROCESS_BOOTSTRAP = _DarwinResolverSupervisorBootstrap(
                _authority=_BOOTSTRAP_AUTHORITY
            )
        return _PROCESS_BOOTSTRAP
    finally:
        _PROCESS_BOOTSTRAP_LOCK.release()
