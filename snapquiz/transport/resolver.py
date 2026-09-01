"""Offline contracts for the W09-B2 resolver-helper lifecycle.

This module deliberately contains no process implementation.  A helper can
only be reached through injected ``HelperSpawner``/``HelperKernel`` objects;
that injection point is a trusted test seam, not a production authorization
boundary.  The offline coordinator proves the matching AttemptGate claim and
DNS-start commit before calling ``transfer``/``start``; factory capability
sealing remains pending.  The production placeholder fails closed until an
independently executable, ``posix_spawn`` based adapter is implemented and
validated.
Importing and constructing the contracts performs no process, DNS, file,
environment, or socket I/O.
"""
from __future__ import annotations

import hashlib
import re
from threading import RLock
from typing import Callable, NamedTuple, Protocol
from uuid import UUID, uuid5

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, canonical_json_bytes, digest256
from snapquiz.domain.errors import ConfigError, EndpointPolicyError
from snapquiz.runtime.attempt import _TRANSPORT_ATTEMPT_AUTHORITY


RESOLVER_HELPER_PROTOCOL_VERSION = "snapquiz.resolver-helper.v2"
RESOLVER_HELPER_START_SCHEMA_VERSION = "snapquiz.resolver-start.v2"
RESOLVER_TERMINAL_GUARD_SCHEMA_VERSION = "snapquiz.resolver-terminal-guard.v1"
RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION = "snapquiz.resolver-result-receipt.v2"
READY_FRAME = b"SNAPQUIZ-RESOLVER/2 READY\n"
MAX_READY_FRAME_BYTES = 64
MAX_START_FRAME_BYTES = 4_096
MAX_RESULT_TRANSCRIPT_BYTES = 16_384
# The protocol frame includes its terminating LF; the transcript limit does not.
MAX_RESULT_FRAME_BYTES = MAX_RESULT_TRANSCRIPT_BYTES + 1
MAX_RESULT_CANDIDATES = 32
MAX_HELPER_STDERR_BYTES = 4_096

_PRE_GUARD_FACTORY_AUTHORITY = object()
_ATTEMPT_GUARD_FACTORY_AUTHORITY = object()
_RESULT_RECEIPT_FACTORY_AUTHORITY = object()
_READY_PUBLICATION_TICKET_AUTHORITY = object()
_TERMINAL_GUARD_UUID_NAMESPACE = UUID(
    "4c82487b-3247-52f0-9fb9-7696da7f7471"
)
_DNS_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)

LifecycleObserver = Callable[[str, dict[str, object]], None]


def _exact_bytes_digest(
    type_tag: str,
    schema_version: str,
    value: bytes,
) -> Digest256:
    if type(value) is not bytes:
        raise TypeError("value must be immutable bytes")
    return digest256(
        type_tag,
        schema_version,
        {
            "byte_size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        },
    )


def start_frame_digest(frame: bytes) -> Digest256:
    """Return the domain-separated digest of one exact encoded START frame."""

    return _exact_bytes_digest(
        "ResolverStartFrame",
        RESOLVER_HELPER_START_SCHEMA_VERSION,
        frame,
    )


def result_transcript_digest(transcript: bytes) -> Digest256:
    """Return the domain-separated digest of RESULT bytes without their LF."""

    return _exact_bytes_digest(
        "ResolverResultTranscript",
        RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION,
        transcript,
    )


class HelperKernel(Protocol):
    """The smallest injectable owner of one already-created helper."""

    def read_stdout(self, max_bytes: int) -> bytes:
        """Read at most ``max_bytes`` bytes from the helper stdout pipe."""

    def write_stdin(self, frame: bytes) -> None:
        """Write one complete, already-bounded protocol frame."""

    def terminate(self) -> None:
        """Best-effort stop of the helper, whether it is alive or exited."""

    def reap(self) -> int:
        """Reap the helper exactly once and return its plain exit status."""

    def close_pipes(self) -> None:
        """Close every helper-owned parent-side pipe exactly once."""


class HelperSpawner(Protocol):
    """Injectable process boundary used only by ``launch_ready``."""

    def spawn(self, request: "ResolverHelperSpawnRequest") -> HelperKernel:
        """Create one helper without receiving target or credential data."""


class _ResultReceiptIssuanceSnapshot(NamedTuple):
    """Ledger-owned copy of every exact RESULT receipt proof field."""

    schema_version: str
    issuer: object
    ledger: object
    lifecycle_id: UUID
    attempt_permit_id: UUID
    attempt_permit_digest: Digest256
    transport_claim_id: UUID
    terminal_guard_id: UUID
    terminal_guard_digest: Digest256
    dns_start_id: UUID
    start_frame_digest: Digest256
    raw_transcript_byte_size: int
    raw_transcript_digest: Digest256
    raw_transcript: bytes
    stdout_eof: bool
    child_reaped: bool
    child_exit_status: int
    helper_pipes_closed: bool
    receipt_digest: Digest256
    issued_digest: Digest256


class _ResolutionCandidatePublicationSnapshot(NamedTuple):
    """Independent snapshot of one candidate published by a ResolutionSet."""

    candidate: object
    address_digest: Digest256
    canonical_payload: bytes


class _ResolutionPublicationSnapshot(NamedTuple):
    """Single ResolutionSet publication anchored to one active receipt."""

    receipt: object
    resolution: object
    resolution_digest: Digest256
    canonical_payload: bytes
    candidates: tuple[_ResolutionCandidatePublicationSnapshot, ...]


class _CleanupPlan(NamedTuple):
    """Ledger-claimed external actions for one terminal cleanup pass."""

    kernel: HelperKernel | None
    claimed: bool
    terminate: bool
    reap: bool
    close_pipes: bool
    inherited_failure: bool


def _lifecycle_error(message: str) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_helper",
        retryable=False,
        safe_message=message,
    )


def _production_unavailable() -> ConfigError:
    return ConfigError(
        stage="resolver_helper",
        retryable=False,
        safe_message="生产 resolver helper 尚未启用。",
    )


def _require_executable(value: object) -> str:
    executable = require_text(value, "executable", max_length=1_024)
    if (
        not executable.startswith("/")
        or "\x00" in executable
        or "\n" in executable
        or "\r" in executable
        or any(part in ("", ".", "..") for part in executable.split("/")[1:])
    ):
        raise ValueError("executable must be a normalized absolute path")
    return executable


def _require_hostname(value: object) -> str:
    hostname = require_text(value, "hostname", max_length=253)
    if hostname != hostname.lower() or _DNS_HOST_RE.fullmatch(hostname) is None:
        raise ValueError("hostname must be a canonical lowercase DNS name")
    return hostname


def _notify(
    observer: LifecycleObserver | None,
    event: str,
    metadata: dict[str, object],
) -> None:
    if observer is not None:
        observer(event, dict(metadata))


def _read_bounded_frame(
    kernel: HelperKernel,
    *,
    maximum: int,
    label: str,
) -> bytes:
    """Read exactly one newline-terminated frame without over-read."""

    require_plain_int(maximum, "maximum", minimum=1)
    buffer = bytearray()
    while True:
        allowance = maximum - len(buffer)
        if allowance <= 0:
            raise _lifecycle_error(f"{label} frame 超过上限。")
        chunk = kernel.read_stdout(allowance)
        if type(chunk) is not bytes or len(chunk) > allowance:
            raise _lifecycle_error(f"{label} frame 读取合同无效。")
        if not chunk:
            raise _lifecycle_error(f"{label} frame 不完整。")
        newline = chunk.find(b"\n")
        if newline >= 0 and newline != len(chunk) - 1:
            raise _lifecycle_error(f"{label} frame 含有尾随数据。")
        buffer.extend(chunk)
        if newline >= 0:
            return bytes(buffer)


@runtime_final
class ResolverHelperSpawnRequest:
    """Fixed, non-secret spawn metadata; it has no target-shaped field."""

    __slots__ = (
        "protocol_version",
        "executable",
        "argv",
        "environment",
        "shell",
        "close_fds",
        "max_ready_frame_bytes",
        "max_start_frame_bytes",
        "max_result_frame_bytes",
        "max_stderr_bytes",
        "request_digest",
    )

    def __init__(self, *, executable: str) -> None:
        checked = _require_executable(executable)
        values = (
            ("protocol_version", RESOLVER_HELPER_PROTOCOL_VERSION),
            ("executable", checked),
            ("argv", (checked, "--snapquiz-resolver-helper-v2")),
            ("environment", (("LANG", "C"), ("LC_ALL", "C"))),
            ("shell", False),
            ("close_fds", True),
            ("max_ready_frame_bytes", MAX_READY_FRAME_BYTES),
            ("max_start_frame_bytes", MAX_START_FRAME_BYTES),
            ("max_result_frame_bytes", MAX_RESULT_FRAME_BYTES),
            ("max_stderr_bytes", MAX_HELPER_STDERR_BYTES),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "request_digest",
            digest256(
                "ResolverHelperSpawnRequest",
                RESOLVER_HELPER_PROTOCOL_VERSION,
                self.safe_metadata(),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverHelperSpawnRequest is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "ResolverHelperSpawnRequest":
        del memo
        return self

    def safe_metadata(self) -> dict[str, object]:
        return {
            "protocol_version": self.protocol_version,
            "executable": self.executable,
            "argv": self.argv,
            "environment": self.environment,
            "shell": self.shell,
            "close_fds": self.close_fds,
            "max_ready_frame_bytes": self.max_ready_frame_bytes,
            "max_start_frame_bytes": self.max_start_frame_bytes,
            "max_result_frame_bytes": self.max_result_frame_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
        }

    def __repr__(self) -> str:
        return (
            "ResolverHelperSpawnRequest("
            f"executable={self.executable!r}, "
            f"protocol_version={self.protocol_version!r})"
        )


@runtime_final
class FailClosedProductionHelperSpawner:
    """Production placeholder: deliberately performs no process operation."""

    __slots__ = ()

    def spawn(self, request: ResolverHelperSpawnRequest) -> HelperKernel:
        if type(request) is not ResolverHelperSpawnRequest:
            raise TypeError("request must be ResolverHelperSpawnRequest")
        raise _production_unavailable() from None


class _ResolverLifecycleLedger:
    """One ledger whose owner identity is the guard object itself."""

    __slots__ = (
        "lifecycle_id",
        "_lock",
        "_pre_owner",
        "_owner",
        "_kernel",
        "_state",
        "_cleanup_claimed",
        "_terminate_claimed",
        "_terminated",
        "_eof_probe_claimed",
        "_stdout_eof",
        "_reap_claimed",
        "_child_reaped",
        "_child_exit_status",
        "_pipes_close_claimed",
        "_helper_pipes_closed",
        "_dns_start_id",
        "_start_frame_digest",
        "_issued_receipt",
        "_issued_receipt_snapshot",
        "_issued_resolution_snapshot",
    )

    def __init__(self, lifecycle_id: UUID) -> None:
        self.lifecycle_id = require_uuid(lifecycle_id, "lifecycle_id")
        self._lock = RLock()
        self._pre_owner: object | None = None
        self._owner: object | None = None
        self._kernel: HelperKernel | None = None
        self._state = "created"
        self._cleanup_claimed = False
        self._terminate_claimed = False
        self._terminated = False
        self._eof_probe_claimed = False
        self._stdout_eof = False
        self._reap_claimed = False
        self._child_reaped = False
        self._child_exit_status: int | None = None
        self._pipes_close_claimed = False
        self._helper_pipes_closed = False
        self._dns_start_id: UUID | None = None
        self._start_frame_digest: Digest256 | None = None
        self._issued_receipt: ResolverResultReceipt | None = None
        self._issued_receipt_snapshot: _ResultReceiptIssuanceSnapshot | None = None
        self._issued_resolution_snapshot: _ResolutionPublicationSnapshot | None = None

    def bind_pre_owner(self, owner: object) -> None:
        with self._lock:
            if self._owner is not None or self._state != "created":
                raise _lifecycle_error("resolver helper owner 已绑定。")
            self._pre_owner = owner
            self._owner = owner

    def attach_kernel(self, owner: object, kernel: HelperKernel) -> None:
        with self._lock:
            if self._owner is not owner or self._state != "created":
                raise _lifecycle_error("resolver helper spawn owner 已变化。")
            self._kernel = kernel
            self._state = "spawned"

    def mark_ready(self, owner: object) -> None:
        self._cas(owner, expected="spawned", replacement=owner, target="ready")

    def transfer(self, owner: object, replacement: object) -> None:
        self._cas(
            owner,
            expected="ready",
            replacement=replacement,
            target="transferred",
        )

    def recover_transferred_guard(
        self,
        pre_owner: object,
        *,
        attempt_permit_id: UUID,
        attempt_permit_digest: Digest256,
        transport_claim_id: UUID,
    ) -> "AttemptTerminalGuard | None":
        """Recover the exact post-transfer owner without reviving cleanup."""

        expected_guard_id = uuid5(
            _TERMINAL_GUARD_UUID_NAMESPACE,
            str(
                digest256(
                    "ResolverTerminalGuardIdentifier",
                    RESOLVER_TERMINAL_GUARD_SCHEMA_VERSION,
                    {
                        "lifecycle_id": self.lifecycle_id,
                        "attempt_permit_id": attempt_permit_id,
                        "attempt_permit_digest": attempt_permit_digest,
                        "transport_claim_id": transport_claim_id,
                    },
                )
            ),
        )
        expected_guard_digest = _terminal_guard_digest(
            lifecycle_id=self.lifecycle_id,
            attempt_permit_id=attempt_permit_id,
            attempt_permit_digest=attempt_permit_digest,
            transport_claim_id=transport_claim_id,
            terminal_guard_id=expected_guard_id,
        )
        with self._lock:
            guard = self._owner
            if (
                self._pre_owner is not pre_owner
                or self._state != "transferred"
                or self._cleanup_claimed
                or type(guard) is not AttemptTerminalGuard
                or guard._ledger is not self
                or guard.lifecycle_id != self.lifecycle_id
                or guard.attempt_permit_id != attempt_permit_id
                or guard.attempt_permit_digest != attempt_permit_digest
                or guard.transport_claim_id != transport_claim_id
                or guard.terminal_guard_id != expected_guard_id
                or guard.terminal_guard_digest != expected_guard_digest
            ):
                return None
            return guard

    def commit_start(
        self,
        owner: object,
        *,
        dns_start_id: UUID,
        exact_start_frame_digest: Digest256,
    ) -> None:
        checked_start_id = require_uuid(dns_start_id, "dns_start_id")
        checked_digest = require_digest(
            exact_start_frame_digest,
            "exact_start_frame_digest",
        )
        with self._lock:
            if self._owner is not owner or self._state != "transferred":
                raise _lifecycle_error("resolver helper owner 或状态已经变化。")
            if self._dns_start_id is not None or self._start_frame_digest is not None:
                raise _lifecycle_error("resolver helper START proof 已存在。")
            self._dns_start_id = checked_start_id
            self._start_frame_digest = checked_digest
            self._state = "start_committed"

    def mark_started(self, owner: object) -> None:
        self._cas(
            owner,
            expected="start_committed",
            replacement=owner,
            target="started",
        )

    def commit_result_read(self, owner: object) -> None:
        self._cas(
            owner,
            expected="started",
            replacement=owner,
            target="result_reading",
        )

    def claim_stdout_eof_probe(self, owner: object) -> HelperKernel:
        """Claim the sole read after RESULT before touching helper stdout."""

        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_reading"
                or self._eof_probe_claimed
                or self._stdout_eof
                or self._kernel is None
            ):
                raise _lifecycle_error("resolver RESULT EOF probe 状态无效。")
            self._eof_probe_claimed = True
            self._state = "result_eof_probing"
            return self._kernel

    def commit_stdout_eof(self, owner: object) -> None:
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_eof_probing"
                or not self._eof_probe_claimed
                or self._stdout_eof
            ):
                raise _lifecycle_error("resolver RESULT EOF proof 状态无效。")
            self._stdout_eof = True
            self._state = "result_eof"

    def claim_result_reap(self, owner: object) -> HelperKernel:
        """Claim the only success-path reap before calling the kernel."""

        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_eof"
                or not self._stdout_eof
                or self._reap_claimed
                or self._child_reaped
                or self._kernel is None
            ):
                raise _lifecycle_error("resolver child reap 状态无效。")
            self._reap_claimed = True
            self._state = "result_reaping"
            return self._kernel

    def commit_result_reap(self, owner: object, exit_status: object) -> None:
        """Commit one exact plain exit status; only zero may publish RESULT."""

        try:
            checked_status = require_plain_int(
                exit_status,
                "child_exit_status",
            )
        except (TypeError, ValueError):
            raise _lifecycle_error("resolver child 退出状态合同无效。") from None
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_reaping"
                or not self._reap_claimed
                or self._child_reaped
            ):
                raise _lifecycle_error("resolver child reap proof 状态无效。")
            self._child_reaped = True
            self._child_exit_status = checked_status
            self._state = (
                "result_reaped" if checked_status == 0 else "result_exit_rejected"
            )
        if checked_status != 0:
            raise _lifecycle_error("resolver child 退出状态不是 0。")

    def claim_result_pipe_close(self, owner: object) -> HelperKernel:
        """Claim parent-side pipe closure after an exact successful reap."""

        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_reaped"
                or not self._stdout_eof
                or not self._child_reaped
                or self._child_exit_status != 0
                or self._pipes_close_claimed
                or self._helper_pipes_closed
                or self._kernel is None
            ):
                raise _lifecycle_error("resolver helper pipe close 状态无效。")
            self._pipes_close_claimed = True
            self._state = "result_pipes_closing"
            return self._kernel

    def commit_result_pipe_close(self, owner: object) -> None:
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_pipes_closing"
                or not self._pipes_close_claimed
                or self._helper_pipes_closed
            ):
                raise _lifecycle_error("resolver helper pipe proof 状态无效。")
            self._helper_pipes_closed = True
            self._state = "result_resources_closed"

    def result_attestation_for(
        self,
        owner: object,
    ) -> tuple[bool, bool, int, bool]:
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_resources_closed"
                or not self._stdout_eof
                or not self._child_reaped
                or self._child_exit_status != 0
                or not self._helper_pipes_closed
            ):
                raise _lifecycle_error("resolver RESULT completion proof 不完整。")
            return (
                self._stdout_eof,
                self._child_reaped,
                self._child_exit_status,
                self._helper_pipes_closed,
            )

    def issue_result_receipt(
        self,
        owner: object,
        receipt: "ResolverResultReceipt",
    ) -> None:
        snapshot = _capture_result_receipt_snapshot(receipt)
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_resources_closed"
                or type(owner) is not AttemptTerminalGuard
                or type(receipt) is not ResolverResultReceipt
                or receipt._ledger is not self
                or receipt._issuer is not owner
                or self._issued_receipt is not None
                or self._issued_receipt_snapshot is not None
                or self._dns_start_id != receipt.dns_start_id
                or self._start_frame_digest != receipt.start_frame_digest
                or receipt.stdout_eof is not self._stdout_eof
                or receipt.child_reaped is not self._child_reaped
                or receipt.child_exit_status != self._child_exit_status
                or receipt.helper_pipes_closed is not self._helper_pipes_closed
            ):
                raise _lifecycle_error("resolver RESULT receipt 发行状态无效。")
            self._issued_receipt = receipt
            self._issued_receipt_snapshot = snapshot
            self._state = "result_attested"

    def is_exact_receipt_issued(
        self,
        owner: object,
        receipt: "ResolverResultReceipt",
    ) -> bool:
        with self._lock:
            return self._is_exact_receipt_issued_locked(owner, receipt)

    def publication_transcript_for(
        self,
        owner: object,
        receipt: "ResolverResultReceipt",
    ) -> bytes:
        """Return the ledger-owned transcript, never receipt-owned mutable state."""

        with self._lock:
            if not self._is_exact_receipt_issued_locked(owner, receipt):
                raise ValueError("resolver result receipt was not exactly issued")
            snapshot = self._issued_receipt_snapshot
            if snapshot is None:
                raise ValueError("resolver result receipt snapshot is unavailable")
            return snapshot.raw_transcript

    def _is_exact_receipt_issued_locked(
        self,
        owner: object,
        receipt: "ResolverResultReceipt",
    ) -> bool:
        snapshot = self._issued_receipt_snapshot
        return (
            self._state == "result_attested"
            and self._owner is owner
            and type(owner) is AttemptTerminalGuard
            and type(receipt) is ResolverResultReceipt
            and receipt._ledger is self
            and receipt._issuer is owner
            and self._issued_receipt is receipt
            and snapshot is not None
            and _matches_result_receipt_snapshot(receipt, snapshot)
            and self._dns_start_id == snapshot.dns_start_id
            and self._start_frame_digest == snapshot.start_frame_digest
            and self._stdout_eof is snapshot.stdout_eof
            and self._child_reaped is snapshot.child_reaped
            and self._child_exit_status == snapshot.child_exit_status
            and self._helper_pipes_closed is snapshot.helper_pipes_closed
        )

    def issue_resolution(
        self,
        owner: object,
        receipt: "ResolverResultReceipt",
        resolution: object,
        *,
        resolution_digest: Digest256,
        canonical_payload: bytes,
        candidates: tuple[tuple[object, Digest256, bytes], ...],
    ) -> None:
        """Record the only ResolutionSet publication for an active receipt."""

        snapshot = _capture_resolution_publication_snapshot(
            receipt=receipt,
            resolution=resolution,
            resolution_digest=resolution_digest,
            canonical_payload=canonical_payload,
            candidates=candidates,
        )
        with self._lock:
            if (
                not self._is_exact_receipt_issued_locked(owner, receipt)
                or self._issued_resolution_snapshot is not None
            ):
                raise _lifecycle_error("resolver ResolutionSet 发行状态无效。")
            self._issued_resolution_snapshot = snapshot

    def is_exact_resolution_issued(
        self,
        owner: object,
        receipt: "ResolverResultReceipt",
        resolution: object,
        *,
        resolution_digest: Digest256,
        canonical_payload: bytes,
        candidates: tuple[tuple[object, Digest256, bytes], ...],
    ) -> bool:
        current = _capture_resolution_publication_snapshot(
            receipt=receipt,
            resolution=resolution,
            resolution_digest=resolution_digest,
            canonical_payload=canonical_payload,
            candidates=candidates,
        )
        with self._lock:
            issued = self._issued_resolution_snapshot
            return (
                self._is_exact_receipt_issued_locked(owner, receipt)
                and issued is not None
                and _matches_resolution_publication_snapshot(current, issued)
            )

    def _cas(
        self,
        owner: object,
        *,
        expected: str,
        replacement: object,
        target: str,
    ) -> None:
        with self._lock:
            if self._owner is not owner or self._state != expected:
                raise _lifecycle_error("resolver helper owner 或状态已经变化。")
            self._owner = replacement
            self._state = target

    def claim_cleanup(self, owner: object) -> _CleanupPlan:
        with self._lock:
            if self._state == "terminal":
                return _CleanupPlan(None, False, False, False, False, False)
            if self._owner is not owner:
                raise _lifecycle_error("resolver helper cleanup owner 不匹配。")
            if self._state == "cleanup_failed":
                raise _lifecycle_error("resolver helper cleanup 尚未证明完成。")
            if self._cleanup_claimed:
                return _CleanupPlan(None, False, False, False, False, False)

            kernel = self._kernel
            inherited_failure = (
                (self._reap_claimed and not self._child_reaped)
                or (
                    self._pipes_close_claimed
                    and not self._helper_pipes_closed
                )
                or (self._terminate_claimed and not self._terminated)
            )
            terminate = (
                kernel is not None
                and not self._child_reaped
                and not self._reap_claimed
                and not self._terminate_claimed
            )
            reap = (
                kernel is not None
                and not self._child_reaped
                and not self._reap_claimed
            )
            close_pipes = (
                kernel is not None
                and not self._helper_pipes_closed
                and not self._pipes_close_claimed
            )

            # Claim each selected external action before exposing the plan.
            # A return-then-raise fault must never permit a second reap/close.
            if terminate:
                self._terminate_claimed = True
            if reap:
                self._reap_claimed = True
            if close_pipes:
                self._pipes_close_claimed = True
            self._cleanup_claimed = True
            self._state = "cleaning"
            return _CleanupPlan(
                kernel,
                True,
                terminate,
                reap,
                close_pipes,
                inherited_failure,
            )

    def commit_cleanup_action(
        self,
        owner: object,
        action_name: str,
        result: object = None,
    ) -> None:
        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            if action_name == "terminate":
                if not self._terminate_claimed or self._terminated:
                    raise _lifecycle_error("resolver helper terminate proof 无效。")
                self._terminated = True
                return
            if action_name == "reap":
                if not self._reap_claimed or self._child_reaped:
                    raise _lifecycle_error("resolver helper reap proof 无效。")
                checked_status = require_plain_int(
                    result,
                    "child_exit_status",
                )
                self._child_reaped = True
                self._child_exit_status = checked_status
                return
            if action_name == "close_pipes":
                if not self._pipes_close_claimed or self._helper_pipes_closed:
                    raise _lifecycle_error("resolver helper pipe proof 无效。")
                self._helper_pipes_closed = True
                return
            raise ValueError("unknown resolver helper cleanup action")

    def finish_cleanup(self, owner: object) -> None:
        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            if self._kernel is not None and (
                not self._child_reaped or not self._helper_pipes_closed
            ):
                raise _lifecycle_error("resolver helper 资源终结证明不完整。")
            self._kernel = None
            self._pre_owner = None
            self._owner = None
            self._state = "terminal"

    def mark_cleanup_failed(self, owner: object) -> None:
        """Retain the kernel and owner when resource release is unproven."""

        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            self._state = "cleanup_failed"

    def kernel_for(self, owner: object, *, states: tuple[str, ...]) -> HelperKernel:
        with self._lock:
            if self._owner is not owner or self._state not in states:
                raise _lifecycle_error("resolver helper owner 或状态已经变化。")
            if self._kernel is None:
                raise _lifecycle_error("resolver helper kernel 不存在。")
            return self._kernel

    def start_proof_for(
        self,
        owner: object,
        *,
        states: tuple[str, ...],
    ) -> tuple[UUID, Digest256]:
        with self._lock:
            if self._owner is not owner or self._state not in states:
                raise _lifecycle_error("resolver helper START proof owner 无效。")
            if self._dns_start_id is None or self._start_frame_digest is None:
                raise _lifecycle_error("resolver helper START proof 不完整。")
            return self._dns_start_id, self._start_frame_digest

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "protocol_version": RESOLVER_HELPER_PROTOCOL_VERSION,
                "lifecycle_id": str(self.lifecycle_id),
                "state": self._state,
                "cleanup_claimed": self._cleanup_claimed,
                "dns_start_committed": self._dns_start_id is not None,
                "result_receipt_issued": self._issued_receipt is not None,
                "stdout_eof": self._stdout_eof,
                "child_reaped": self._child_reaped,
                "child_exit_status": self._child_exit_status,
                "helper_pipes_closed": self._helper_pipes_closed,
            }


def _cleanup_guard(
    guard: object,
    ledger: _ResolverLifecycleLedger,
    *,
    observer: LifecycleObserver | None,
    suppress_errors: bool,
) -> bool:
    try:
        plan = ledger.claim_cleanup(guard)
    except BaseException:
        if suppress_errors:
            return False
        raise
    if not plan.claimed:
        return False

    observer_error: BaseException | None = None
    try:
        _notify(observer, "cleanup_committed", ledger.safe_metadata())
    except BaseException as error:
        observer_error = error

    cleanup_failed = plan.inherited_failure
    if plan.kernel is not None:
        actions = (
            ("terminate", plan.terminate),
            ("reap", plan.reap),
            ("close_pipes", plan.close_pipes),
        )
        for action_name, selected in actions:
            if not selected:
                continue
            try:
                action = getattr(plan.kernel, action_name)
                result = action()
                ledger.commit_cleanup_action(guard, action_name, result)
            except BaseException:
                cleanup_failed = True
    if cleanup_failed:
        try:
            ledger.mark_cleanup_failed(guard)
        except BaseException:
            pass
    else:
        try:
            ledger.finish_cleanup(guard)
        except BaseException:
            cleanup_failed = True
            try:
                ledger.mark_cleanup_failed(guard)
            except BaseException:
                pass

    if observer_error is not None and not suppress_errors:
        raise observer_error
    if cleanup_failed and not suppress_errors:
        error = _lifecycle_error("resolver helper cleanup 失败。")
        error.__cause__ = None
        error.__context__ = None
        error.__suppress_context__ = True
        raise error from None
    return True


def _terminal_guard_digest(
    *,
    lifecycle_id: UUID,
    attempt_permit_id: UUID,
    attempt_permit_digest: Digest256,
    transport_claim_id: UUID,
    terminal_guard_id: UUID,
) -> Digest256:
    return digest256(
        "ResolverTerminalGuard",
        RESOLVER_TERMINAL_GUARD_SCHEMA_VERSION,
        {
            "lifecycle_id": lifecycle_id,
            "attempt_permit_id": attempt_permit_id,
            "attempt_permit_digest": attempt_permit_digest,
            "transport_claim_id": transport_claim_id,
            "terminal_guard_id": terminal_guard_id,
        },
    )


def _result_receipt_payload(receipt: "ResolverResultReceipt") -> dict[str, object]:
    return {
        "lifecycle_id": receipt.lifecycle_id,
        "attempt_permit_id": receipt.attempt_permit_id,
        "attempt_permit_digest": receipt.attempt_permit_digest,
        "transport_claim_id": receipt.transport_claim_id,
        "terminal_guard_id": receipt.terminal_guard_id,
        "terminal_guard_digest": receipt.terminal_guard_digest,
        "dns_start_id": receipt.dns_start_id,
        "start_frame_digest": receipt.start_frame_digest,
        "raw_transcript_byte_size": receipt.raw_transcript_byte_size,
        "raw_transcript_digest": receipt.raw_transcript_digest,
        "stdout_eof": receipt.stdout_eof,
        "child_reaped": receipt.child_reaped,
        "child_exit_status": receipt.child_exit_status,
        "helper_pipes_closed": receipt.helper_pipes_closed,
    }


def _capture_result_receipt_snapshot(
    receipt: "ResolverResultReceipt",
) -> _ResultReceiptIssuanceSnapshot:
    if type(receipt) is not ResolverResultReceipt:
        raise TypeError("receipt must be ResolverResultReceipt")
    return _ResultReceiptIssuanceSnapshot(
        schema_version=RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION,
        issuer=receipt._issuer,
        ledger=receipt._ledger,
        lifecycle_id=receipt.lifecycle_id,
        attempt_permit_id=receipt.attempt_permit_id,
        attempt_permit_digest=receipt.attempt_permit_digest,
        transport_claim_id=receipt.transport_claim_id,
        terminal_guard_id=receipt.terminal_guard_id,
        terminal_guard_digest=receipt.terminal_guard_digest,
        dns_start_id=receipt.dns_start_id,
        start_frame_digest=receipt.start_frame_digest,
        raw_transcript_byte_size=receipt.raw_transcript_byte_size,
        raw_transcript_digest=receipt.raw_transcript_digest,
        raw_transcript=receipt._raw_transcript,
        stdout_eof=receipt.stdout_eof,
        child_reaped=receipt.child_reaped,
        child_exit_status=receipt.child_exit_status,
        helper_pipes_closed=receipt.helper_pipes_closed,
        receipt_digest=receipt.receipt_digest,
        issued_digest=receipt._issued_digest,
    )


def _matches_result_receipt_snapshot(
    receipt: "ResolverResultReceipt",
    snapshot: _ResultReceiptIssuanceSnapshot,
) -> bool:
    try:
        current = _capture_result_receipt_snapshot(receipt)
    except Exception:
        return False
    return (
        current.schema_version == snapshot.schema_version
        and current.issuer is snapshot.issuer
        and current.ledger is snapshot.ledger
        and current.lifecycle_id == snapshot.lifecycle_id
        and current.attempt_permit_id == snapshot.attempt_permit_id
        and current.attempt_permit_digest == snapshot.attempt_permit_digest
        and current.transport_claim_id == snapshot.transport_claim_id
        and current.terminal_guard_id == snapshot.terminal_guard_id
        and current.terminal_guard_digest == snapshot.terminal_guard_digest
        and current.dns_start_id == snapshot.dns_start_id
        and current.start_frame_digest == snapshot.start_frame_digest
        and current.raw_transcript_byte_size
        == snapshot.raw_transcript_byte_size
        and current.raw_transcript_digest == snapshot.raw_transcript_digest
        and current.raw_transcript == snapshot.raw_transcript
        and current.stdout_eof is snapshot.stdout_eof
        and current.child_reaped is snapshot.child_reaped
        and current.child_exit_status == snapshot.child_exit_status
        and current.helper_pipes_closed is snapshot.helper_pipes_closed
        and current.receipt_digest == snapshot.receipt_digest
        and current.issued_digest == snapshot.issued_digest
    )


def _capture_resolution_publication_snapshot(
    *,
    receipt: object,
    resolution: object,
    resolution_digest: Digest256,
    canonical_payload: bytes,
    candidates: tuple[tuple[object, Digest256, bytes], ...],
) -> _ResolutionPublicationSnapshot:
    checked_digest = require_digest(resolution_digest, "resolution_digest")
    if type(canonical_payload) is not bytes:
        raise TypeError("canonical_payload must be immutable bytes")
    if type(candidates) is not tuple or not candidates:
        raise TypeError("candidates must be a non-empty tuple")
    checked_candidates: list[_ResolutionCandidatePublicationSnapshot] = []
    for item in candidates:
        if type(item) is not tuple or len(item) != 3:
            raise TypeError("candidate publication snapshot is invalid")
        candidate, address_digest, candidate_payload = item
        checked_address_digest = require_digest(
            address_digest,
            "candidate address_digest",
        )
        if type(candidate_payload) is not bytes:
            raise TypeError("candidate payload must be immutable bytes")
        checked_candidates.append(
            _ResolutionCandidatePublicationSnapshot(
                candidate=candidate,
                address_digest=checked_address_digest,
                canonical_payload=candidate_payload,
            )
        )
    return _ResolutionPublicationSnapshot(
        receipt=receipt,
        resolution=resolution,
        resolution_digest=checked_digest,
        canonical_payload=canonical_payload,
        candidates=tuple(checked_candidates),
    )


def _matches_resolution_publication_snapshot(
    current: _ResolutionPublicationSnapshot,
    issued: _ResolutionPublicationSnapshot,
) -> bool:
    if (
        current.receipt is not issued.receipt
        or current.resolution is not issued.resolution
        or current.resolution_digest != issued.resolution_digest
        or current.canonical_payload != issued.canonical_payload
        or len(current.candidates) != len(issued.candidates)
    ):
        return False
    return all(
        current_candidate.candidate is issued_candidate.candidate
        and current_candidate.address_digest == issued_candidate.address_digest
        and current_candidate.canonical_payload
        == issued_candidate.canonical_payload
        for current_candidate, issued_candidate in zip(
            current.candidates,
            issued.candidates,
        )
    )


@runtime_final
class ResolverResultReceipt:
    """Factory-only proof of exact RESULT completion and helper release.

    The raw transcript is retained privately for the address-policy factory;
    callers receive neither naked helper bytes nor a forgeable proof bag.  A
    receipt exists only after stdout EOF, exit status zero, one successful
    reap, and parent-side pipe closure are all ledger-attested.
    """

    __slots__ = (
        "lifecycle_id",
        "attempt_permit_id",
        "attempt_permit_digest",
        "transport_claim_id",
        "terminal_guard_id",
        "terminal_guard_digest",
        "dns_start_id",
        "start_frame_digest",
        "raw_transcript_byte_size",
        "raw_transcript_digest",
        "stdout_eof",
        "child_reaped",
        "child_exit_status",
        "helper_pipes_closed",
        "receipt_digest",
        "_issued_digest",
        "_raw_transcript",
        "_issuer",
        "_ledger",
    )

    def __init__(
        self,
        *,
        issuer: "AttemptTerminalGuard",
        ledger: _ResolverLifecycleLedger,
        dns_start_id: UUID,
        exact_start_frame_digest: Digest256,
        raw_transcript: bytes,
        stdout_eof: bool = False,
        child_reaped: bool = False,
        child_exit_status: int = -1,
        helper_pipes_closed: bool = False,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _RESULT_RECEIPT_FACTORY_AUTHORITY:
            raise TypeError("resolver result receipts require terminal guard issuance")
        if type(issuer) is not AttemptTerminalGuard:
            raise TypeError("issuer must be AttemptTerminalGuard")
        if type(ledger) is not _ResolverLifecycleLedger or issuer._ledger is not ledger:
            raise TypeError("receipt ledger must be the issuer ledger")
        checked_transcript = raw_transcript
        if (
            type(checked_transcript) is not bytes
            or not checked_transcript
            or len(checked_transcript) > MAX_RESULT_TRANSCRIPT_BYTES
            or b"\n" in checked_transcript
            or b"\r" in checked_transcript
        ):
            raise _lifecycle_error("RESULT transcript 边界无效。")
        if (
            stdout_eof is not True
            or child_reaped is not True
            or helper_pipes_closed is not True
        ):
            raise _lifecycle_error("RESULT completion attestation 无效。")
        checked_exit_status = require_plain_int(
            child_exit_status,
            "child_exit_status",
        )
        if checked_exit_status != 0:
            raise _lifecycle_error("RESULT child exit status 无效。")
        values = (
            ("lifecycle_id", issuer.lifecycle_id),
            ("attempt_permit_id", issuer.attempt_permit_id),
            ("attempt_permit_digest", issuer.attempt_permit_digest),
            ("transport_claim_id", issuer.transport_claim_id),
            ("terminal_guard_id", issuer.terminal_guard_id),
            ("terminal_guard_digest", issuer.terminal_guard_digest),
            ("dns_start_id", require_uuid(dns_start_id, "dns_start_id")),
            (
                "start_frame_digest",
                require_digest(
                    exact_start_frame_digest,
                    "exact_start_frame_digest",
                ),
            ),
            ("raw_transcript_byte_size", len(checked_transcript)),
            (
                "raw_transcript_digest",
                result_transcript_digest(checked_transcript),
            ),
            ("stdout_eof", True),
            ("child_reaped", True),
            ("child_exit_status", checked_exit_status),
            ("helper_pipes_closed", True),
            ("_raw_transcript", checked_transcript),
            ("_issuer", issuer),
            ("_ledger", ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        receipt_digest = digest256(
            "ResolverResultReceipt",
            RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION,
            _result_receipt_payload(self),
        )
        object.__setattr__(self, "receipt_digest", receipt_digest)
        object.__setattr__(self, "_issued_digest", receipt_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverResultReceipt is immutable")

    def __copy__(self) -> "ResolverResultReceipt":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "ResolverResultReceipt":
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("ResolverResultReceipt cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("ResolverResultReceipt cannot be serialized")

    def __repr__(self) -> str:
        return (
            "ResolverResultReceipt("
            f"lifecycle_id={self.lifecycle_id!r}, "
            f"attempt_permit_id={self.attempt_permit_id!r}, "
            f"raw_transcript_byte_size={self.raw_transcript_byte_size!r}, "
            f"child_exit_status={self.child_exit_status!r})"
        )

    def validate_integrity(self) -> None:
        for name in (
            "lifecycle_id",
            "attempt_permit_id",
            "transport_claim_id",
            "terminal_guard_id",
            "dns_start_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "attempt_permit_digest",
            "terminal_guard_digest",
            "start_frame_digest",
            "raw_transcript_digest",
            "receipt_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        require_plain_int(
            self.raw_transcript_byte_size,
            "raw_transcript_byte_size",
            minimum=1,
        )
        require_plain_int(
            self.child_exit_status,
            "child_exit_status",
        )
        if (
            self.raw_transcript_byte_size > MAX_RESULT_TRANSCRIPT_BYTES
            or type(self._raw_transcript) is not bytes
            or len(self._raw_transcript) != self.raw_transcript_byte_size
            or b"\n" in self._raw_transcript
            or b"\r" in self._raw_transcript
            or result_transcript_digest(self._raw_transcript)
            != self.raw_transcript_digest
            or self.stdout_eof is not True
            or self.child_reaped is not True
            or self.child_exit_status != 0
            or self.helper_pipes_closed is not True
        ):
            raise ValueError("resolver result transcript integrity mismatch")
        if (
            type(self._issuer) is not AttemptTerminalGuard
            or type(self._ledger) is not _ResolverLifecycleLedger
            or self._issuer._ledger is not self._ledger
            or self.lifecycle_id != self._issuer.lifecycle_id
            or self.attempt_permit_id != self._issuer.attempt_permit_id
            or self.attempt_permit_digest != self._issuer.attempt_permit_digest
            or self.transport_claim_id != self._issuer.transport_claim_id
            or self.terminal_guard_id != self._issuer.terminal_guard_id
            or self.terminal_guard_digest != self._issuer.terminal_guard_digest
        ):
            raise ValueError("resolver result receipt issuer changed")
        recomputed = digest256(
            "ResolverResultReceipt",
            RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION,
            _result_receipt_payload(self),
        )
        if recomputed != self.receipt_digest or recomputed != self._issued_digest:
            raise ValueError("resolver result receipt integrity mismatch")

    def _validate_exact_issuance(
        self,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("resolver result receipt verification requires transport")
        self.validate_integrity()
        if not self._ledger.is_exact_receipt_issued(self._issuer, self):
            raise ValueError("resolver result receipt was not exactly issued")

    def _publication_transcript(
        self,
        *,
        _authority: object | None = None,
    ) -> bytes:
        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("resolver result receipt verification requires transport")
        self.validate_integrity()
        return self._ledger.publication_transcript_for(self._issuer, self)

    def _publish_resolution(
        self,
        resolution: object,
        *,
        resolution_digest: Digest256,
        canonical_payload: bytes,
        candidates: tuple[tuple[object, Digest256, bytes], ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("resolution publication requires transport")
        self._ledger.issue_resolution(
            self._issuer,
            self,
            resolution,
            resolution_digest=resolution_digest,
            canonical_payload=canonical_payload,
            candidates=candidates,
        )

    def _validate_resolution_publication(
        self,
        resolution: object,
        *,
        resolution_digest: Digest256,
        canonical_payload: bytes,
        candidates: tuple[tuple[object, Digest256, bytes], ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("resolution verification requires transport")
        if not self._ledger.is_exact_resolution_issued(
            self._issuer,
            self,
            resolution,
            resolution_digest=resolution_digest,
            canonical_payload=canonical_payload,
            candidates=candidates,
        ):
            raise ValueError("resolution was not exactly published")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "schema_version": RESOLVER_RESULT_RECEIPT_SCHEMA_VERSION,
            "lifecycle_id": str(self.lifecycle_id),
            "attempt_permit_id": str(self.attempt_permit_id),
            "transport_claim_id": str(self.transport_claim_id),
            "terminal_guard_id": str(self.terminal_guard_id),
            "dns_start_id": str(self.dns_start_id),
            "start_frame_digest_prefix": str(self.start_frame_digest)[:12],
            "raw_transcript_byte_size": self.raw_transcript_byte_size,
            "raw_transcript_digest_prefix": str(self.raw_transcript_digest)[:12],
            "stdout_eof": self.stdout_eof,
            "child_reaped": self.child_reaped,
            "child_exit_status": self.child_exit_status,
            "helper_pipes_closed": self.helper_pipes_closed,
            "receipt_digest_prefix": str(self.receipt_digest)[:12],
        }


@runtime_final
class PreAttemptResolverGuard:
    """Factory-only owner from process creation through verified READY."""

    __slots__ = ("lifecycle_id", "spawn_request_digest", "_ledger")

    def __init__(
        self,
        *,
        lifecycle_id: UUID,
        spawn_request_digest: Digest256,
        ledger: _ResolverLifecycleLedger,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PRE_GUARD_FACTORY_AUTHORITY:
            raise TypeError("pre-attempt resolver guards require launcher")
        self.lifecycle_id = require_uuid(lifecycle_id, "lifecycle_id")
        self.spawn_request_digest = require_digest(
            spawn_request_digest, "spawn_request_digest"
        )
        self._ledger = ledger

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("PreAttemptResolverGuard is immutable")
        object.__setattr__(self, name, value)

    def __deepcopy__(self, memo: dict[int, object]) -> "PreAttemptResolverGuard":
        del memo
        return self

    def __repr__(self) -> str:
        return f"PreAttemptResolverGuard(lifecycle_id={self.lifecycle_id!r})"

    def safe_metadata(self) -> dict[str, object]:
        return self._ledger.safe_metadata()

    def transfer(
        self,
        *,
        attempt_permit_id: UUID,
        attempt_permit_digest: Digest256,
        transport_claim_id: UUID,
        observer: LifecycleObserver | None = None,
    ) -> "AttemptTerminalGuard":
        """Record proof values after a trusted coordinator proves ``io_claimed``.

        This ledger validates identity and one-shot ownership only.  It cannot
        itself consult AttemptGate; direct callers therefore do not gain DNS
        authority merely by supplying UUID/digest-shaped values.
        """

        replacement: AttemptTerminalGuard | None = None
        try:
            require_uuid(attempt_permit_id, "attempt_permit_id")
            require_digest(attempt_permit_digest, "attempt_permit_digest")
            require_uuid(transport_claim_id, "transport_claim_id")
            guard_id = uuid5(
                _TERMINAL_GUARD_UUID_NAMESPACE,
                str(
                    digest256(
                        "ResolverTerminalGuardIdentifier",
                        RESOLVER_TERMINAL_GUARD_SCHEMA_VERSION,
                        {
                            "lifecycle_id": self.lifecycle_id,
                            "attempt_permit_id": attempt_permit_id,
                            "attempt_permit_digest": attempt_permit_digest,
                            "transport_claim_id": transport_claim_id,
                        },
                    )
                ),
            )
            guard_digest = _terminal_guard_digest(
                lifecycle_id=self.lifecycle_id,
                attempt_permit_id=attempt_permit_id,
                attempt_permit_digest=attempt_permit_digest,
                transport_claim_id=transport_claim_id,
                terminal_guard_id=guard_id,
            )
            replacement = AttemptTerminalGuard(
                lifecycle_id=self.lifecycle_id,
                attempt_permit_id=attempt_permit_id,
                attempt_permit_digest=attempt_permit_digest,
                transport_claim_id=transport_claim_id,
                terminal_guard_id=guard_id,
                terminal_guard_digest=guard_digest,
                ledger=self._ledger,
                _authority=_ATTEMPT_GUARD_FACTORY_AUTHORITY,
            )
            self._ledger.transfer(self, replacement)
            _notify(observer, "ownership_transferred", replacement.safe_metadata())
        except BaseException:
            if replacement is not None:
                _cleanup_guard(
                    replacement,
                    self._ledger,
                    observer=None,
                    suppress_errors=True,
                )
            _cleanup_guard(
                self,
                self._ledger,
                observer=None,
                suppress_errors=True,
            )
            raise
        return replacement

    def _recover_transferred_guard(
        self,
        *,
        attempt_permit_id: UUID,
        attempt_permit_digest: Digest256,
        transport_claim_id: UUID,
        _authority: object | None = None,
    ) -> "AttemptTerminalGuard | None":
        """Recover one exact owner lost after ``transfer`` returned."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("resolver publication recovery requires transport")
        if (
            type(attempt_permit_id) is not UUID
            or type(attempt_permit_digest) is not Digest256
            or type(transport_claim_id) is not UUID
        ):
            return None
        return self._ledger.recover_transferred_guard(
            self,
            attempt_permit_id=attempt_permit_id,
            attempt_permit_digest=attempt_permit_digest,
            transport_claim_id=transport_claim_id,
        )

    def cleanup(self, *, observer: LifecycleObserver | None = None) -> bool:
        return _cleanup_guard(
            self,
            self._ledger,
            observer=observer,
            suppress_errors=False,
        )


@runtime_final
class AttemptTerminalGuard:
    """Factory-only exact owner from handoff through terminal cleanup."""

    __slots__ = (
        "lifecycle_id",
        "attempt_permit_id",
        "attempt_permit_digest",
        "transport_claim_id",
        "terminal_guard_id",
        "terminal_guard_digest",
        "_ledger",
    )

    def __init__(
        self,
        *,
        lifecycle_id: UUID,
        attempt_permit_id: UUID,
        attempt_permit_digest: Digest256,
        transport_claim_id: UUID,
        terminal_guard_id: UUID,
        terminal_guard_digest: Digest256,
        ledger: _ResolverLifecycleLedger,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ATTEMPT_GUARD_FACTORY_AUTHORITY:
            raise TypeError("attempt terminal guards require ownership transfer")
        values = (
            ("lifecycle_id", require_uuid(lifecycle_id, "lifecycle_id")),
            (
                "attempt_permit_id",
                require_uuid(attempt_permit_id, "attempt_permit_id"),
            ),
            (
                "attempt_permit_digest",
                require_digest(attempt_permit_digest, "attempt_permit_digest"),
            ),
            (
                "transport_claim_id",
                require_uuid(transport_claim_id, "transport_claim_id"),
            ),
            (
                "terminal_guard_id",
                require_uuid(terminal_guard_id, "terminal_guard_id"),
            ),
            (
                "terminal_guard_digest",
                require_digest(terminal_guard_digest, "terminal_guard_digest"),
            ),
            ("_ledger", ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AttemptTerminalGuard is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "AttemptTerminalGuard":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "AttemptTerminalGuard("
            f"terminal_guard_id={self.terminal_guard_id!r}, "
            f"attempt_permit_id={self.attempt_permit_id!r})"
        )

    def safe_metadata(self) -> dict[str, object]:
        metadata = self._ledger.safe_metadata()
        metadata.update(
            {
                "attempt_permit_id": str(self.attempt_permit_id),
                "transport_claim_id": str(self.transport_claim_id),
                "terminal_guard_id": str(self.terminal_guard_id),
                "terminal_guard_digest": str(self.terminal_guard_digest),
            }
        )
        return metadata

    def start(
        self,
        *,
        hostname: str,
        port: int,
        network_policy_ref: str,
        network_policy_digest: Digest256,
        dns_start_id: UUID,
        observer: LifecycleObserver | None = None,
    ) -> None:
        """Write the sole START after the coordinator commits DNS authority.

        The guard enforces one-shot lifecycle ownership, but the trusted
        coordinator remains responsible for calling AttemptGate's exact
        ``_commit_dns_start`` first and for checking commit-then-raise state.
        """

        try:
            frame = encode_start_frame(
                hostname=hostname,
                port=port,
                network_policy_ref=network_policy_ref,
                network_policy_digest=network_policy_digest,
                attempt_permit_id=self.attempt_permit_id,
                attempt_permit_digest=self.attempt_permit_digest,
                transport_claim_id=self.transport_claim_id,
                terminal_guard_id=self.terminal_guard_id,
                terminal_guard_digest=self.terminal_guard_digest,
                dns_start_id=dns_start_id,
            )
            exact_start_digest = start_frame_digest(frame)
            self._ledger.commit_start(
                self,
                dns_start_id=dns_start_id,
                exact_start_frame_digest=exact_start_digest,
            )
            kernel = self._ledger.kernel_for(self, states=("start_committed",))
            kernel.write_stdin(frame)
            self._ledger.mark_started(self)
            _notify(observer, "start_committed", self.safe_metadata())
        except BaseException:
            _cleanup_guard(
                self,
                self._ledger,
                observer=None,
                suppress_errors=True,
            )
            raise

    def read_result_receipt(
        self,
        *,
        observer: LifecycleObserver | None = None,
    ) -> ResolverResultReceipt:
        """Attest one RESULT, EOF, exit-zero, reap, and closed pipes."""

        try:
            self._ledger.commit_result_read(self)
            kernel = self._ledger.kernel_for(self, states=("result_reading",))
            frame = _read_bounded_frame(
                kernel,
                maximum=MAX_RESULT_FRAME_BYTES,
                label="RESULT",
            )
            transcript = frame[:-1]
            if not transcript or len(transcript) > MAX_RESULT_TRANSCRIPT_BYTES:
                raise _lifecycle_error("RESULT transcript 超过上限。")

            eof_kernel = self._ledger.claim_stdout_eof_probe(self)
            trailing = eof_kernel.read_stdout(1)
            if type(trailing) is not bytes or len(trailing) > 1:
                raise _lifecycle_error("RESULT EOF probe 读取合同无效。")
            if trailing:
                raise _lifecycle_error("RESULT 后存在第二帧或尾随输出。")
            self._ledger.commit_stdout_eof(self)

            reap_kernel = self._ledger.claim_result_reap(self)
            exit_status = reap_kernel.reap()
            self._ledger.commit_result_reap(self, exit_status)

            close_kernel = self._ledger.claim_result_pipe_close(self)
            close_kernel.close_pipes()
            self._ledger.commit_result_pipe_close(self)

            dns_start_id, exact_start_digest = self._ledger.start_proof_for(
                self,
                states=("result_resources_closed",),
            )
            (
                stdout_eof,
                child_reaped,
                child_exit_status,
                helper_pipes_closed,
            ) = self._ledger.result_attestation_for(self)
            receipt = ResolverResultReceipt(
                issuer=self,
                ledger=self._ledger,
                dns_start_id=dns_start_id,
                exact_start_frame_digest=exact_start_digest,
                raw_transcript=transcript,
                stdout_eof=stdout_eof,
                child_reaped=child_reaped,
                child_exit_status=child_exit_status,
                helper_pipes_closed=helper_pipes_closed,
                _authority=_RESULT_RECEIPT_FACTORY_AUTHORITY,
            )
            self._ledger.issue_result_receipt(self, receipt)
            _notify(observer, "result_attested", self.safe_metadata())
            return receipt
        except BaseException:
            _cleanup_guard(
                self,
                self._ledger,
                observer=None,
                suppress_errors=True,
            )
            raise

    def cleanup(self, *, observer: LifecycleObserver | None = None) -> bool:
        return _cleanup_guard(
            self,
            self._ledger,
            observer=observer,
            suppress_errors=False,
        )


@runtime_final
class _ReadyPublicationTicket:
    """Launcher-issued identity for one caller-generated publication ID."""

    __slots__ = (
        "publication_id",
        "lifecycle_id",
        "spawn_request_digest",
        "_launcher",
        "_reservation_owner",
    )

    def __init__(
        self,
        *,
        publication_id: UUID,
        lifecycle_id: UUID,
        spawn_request_digest: Digest256,
        launcher: object,
        reservation_owner: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _READY_PUBLICATION_TICKET_AUTHORITY:
            raise TypeError("READY publication tickets require launcher")
        if reservation_owner is None:
            raise TypeError("reservation_owner must be an identity object")
        object.__setattr__(
            self,
            "publication_id",
            require_uuid(publication_id, "publication_id"),
        )
        object.__setattr__(
            self,
            "lifecycle_id",
            require_uuid(lifecycle_id, "lifecycle_id"),
        )
        object.__setattr__(
            self,
            "spawn_request_digest",
            require_digest(spawn_request_digest, "spawn_request_digest"),
        )
        object.__setattr__(self, "_launcher", launcher)
        object.__setattr__(self, "_reservation_owner", reservation_owner)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("READY publication ticket is immutable")


class _ReadyPublicationState:
    __slots__ = ("ticket", "guard", "status")

    def __init__(self, ticket: _ReadyPublicationTicket) -> None:
        self.ticket = ticket
        self.guard: PreAttemptResolverGuard | None = None
        self.status = "reserved"


@runtime_final
class ResolverHelperLauncher:
    """Construct-only configuration plus one explicit spawn/READY method."""

    __slots__ = (
        "_spawner",
        "_request",
        "_publication_lock",
        "_ready_publications",
    )

    def __init__(self, spawner: HelperSpawner, *, executable: str) -> None:
        if spawner is None or not callable(getattr(spawner, "spawn", None)):
            raise TypeError("spawner must implement HelperSpawner")
        object.__setattr__(self, "_spawner", spawner)
        object.__setattr__(
            self,
            "_request",
            ResolverHelperSpawnRequest(executable=executable),
        )
        object.__setattr__(self, "_publication_lock", RLock())
        object.__setattr__(self, "_ready_publications", {})

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverHelperLauncher is immutable")

    @classmethod
    def production(cls, *, executable: str) -> "ResolverHelperLauncher":
        """Return the explicit fail-closed production placeholder."""

        return cls(FailClosedProductionHelperSpawner(), executable=executable)

    def safe_metadata(self) -> dict[str, object]:
        return self._request.safe_metadata()

    def _reserve_ready_publication(
        self,
        *,
        publication_id: UUID,
        lifecycle_id: UUID,
        reservation_owner: object,
        _authority: object | None = None,
    ) -> _ReadyPublicationTicket:
        """Atomically reserve an exact ticket before any helper can spawn."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("READY publication reservation requires transport")
        checked_publication_id = require_uuid(
            publication_id,
            "publication_id",
        )
        checked_lifecycle_id = require_uuid(lifecycle_id, "lifecycle_id")
        if reservation_owner is None:
            raise TypeError("reservation_owner must be an identity object")
        ticket = _ReadyPublicationTicket(
            publication_id=checked_publication_id,
            lifecycle_id=checked_lifecycle_id,
            spawn_request_digest=self._request.request_digest,
            launcher=self,
            reservation_owner=reservation_owner,
            _authority=_READY_PUBLICATION_TICKET_AUTHORITY,
        )
        state = _ReadyPublicationState(ticket)
        with self._publication_lock:
            if checked_publication_id in self._ready_publications:
                raise _lifecycle_error("resolver READY publication id 已使用。")
            self._ready_publications[checked_publication_id] = state
        return ticket

    def _recover_ready_reservation(
        self,
        *,
        publication_id: UUID,
        lifecycle_id: UUID,
        reservation_owner: object,
        _authority: object | None = None,
    ) -> bool:
        """Remove only this caller-owned reservation after a lost return."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("READY reservation recovery requires transport")
        if (
            type(publication_id) is not UUID
            or type(lifecycle_id) is not UUID
            or reservation_owner is None
        ):
            return False
        with self._publication_lock:
            state = self._ready_publications.get(publication_id)
            ticket = None if state is None else state.ticket
            if (
                state is None
                or type(ticket) is not _ReadyPublicationTicket
                or ticket._launcher is not self
                or ticket._reservation_owner is not reservation_owner
                or ticket.lifecycle_id != lifecycle_id
                or ticket.spawn_request_digest != self._request.request_digest
                or state.status != "reserved"
                or state.guard is not None
            ):
                return False
            del self._ready_publications[publication_id]
            return True

    def _cancel_ready_reservation(
        self,
        ticket: _ReadyPublicationTicket,
    ) -> None:
        """Drop only this still-reserved ticket after an internal failure."""

        with self._publication_lock:
            state = self._ready_publications.get(ticket.publication_id)
            if (
                state is not None
                and state.ticket is ticket
                and state.status == "reserved"
                and state.guard is None
            ):
                del self._ready_publications[ticket.publication_id]

    def _publish_ready_guard(
        self,
        ticket: _ReadyPublicationTicket,
        guard: PreAttemptResolverGuard,
    ) -> None:
        """Publish the exact READY owner as the final pre-return action."""

        if (
            type(ticket) is not _ReadyPublicationTicket
            or ticket._launcher is not self
            or type(guard) is not PreAttemptResolverGuard
            or guard.lifecycle_id != ticket.lifecycle_id
            or guard.spawn_request_digest != ticket.spawn_request_digest
        ):
            raise _lifecycle_error("resolver READY publication proof 无效。")
        with self._publication_lock:
            state = self._ready_publications.get(ticket.publication_id)
            if (
                state is None
                or state.ticket is not ticket
                or state.status != "reserved"
                or state.guard is not None
            ):
                raise _lifecycle_error("resolver READY publication reservation 已变化。")
            state.guard = guard
            state.status = "published"

    def _consume_ready_publication(
        self,
        ticket: _ReadyPublicationTicket,
        guard: PreAttemptResolverGuard,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Consume only the normally assigned exact guard identity."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("READY publication consumption requires transport")
        if (
            type(ticket) is not _ReadyPublicationTicket
            or ticket._launcher is not self
            or type(guard) is not PreAttemptResolverGuard
        ):
            return False
        with self._publication_lock:
            state = self._ready_publications.get(ticket.publication_id)
            if (
                state is None
                or state.ticket is not ticket
                or state.status != "published"
                or state.guard is not guard
            ):
                return False
            state.guard = None
            state.status = "consumed"
            del self._ready_publications[ticket.publication_id]
            return True

    def _recover_ready_publication(
        self,
        ticket: _ReadyPublicationTicket,
        *,
        _authority: object | None = None,
    ) -> PreAttemptResolverGuard | None:
        """Consume a reserved/published ticket after an outer exception."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("READY publication recovery requires transport")
        if (
            type(ticket) is not _ReadyPublicationTicket
            or ticket._launcher is not self
        ):
            return None
        with self._publication_lock:
            state = self._ready_publications.get(ticket.publication_id)
            if state is None or state.ticket is not ticket:
                return None
            if state.status == "reserved" and state.guard is None:
                state.status = "consumed"
                del self._ready_publications[ticket.publication_id]
                return None
            guard = state.guard
            if (
                state.status != "published"
                or type(guard) is not PreAttemptResolverGuard
                or guard.lifecycle_id != ticket.lifecycle_id
                or guard.spawn_request_digest != ticket.spawn_request_digest
            ):
                return None
            state.guard = None
            state.status = "consumed"
            del self._ready_publications[ticket.publication_id]
            return guard

    def launch_ready(
        self,
        *,
        lifecycle_id: UUID,
        observer: LifecycleObserver | None = None,
        publication_ticket: _ReadyPublicationTicket | None = None,
    ) -> PreAttemptResolverGuard:
        """Spawn with fixed metadata, then accept only the fixed READY frame."""

        checked_lifecycle_id = require_uuid(lifecycle_id, "lifecycle_id")
        if publication_ticket is not None:
            if (
                type(publication_ticket) is not _ReadyPublicationTicket
                or publication_ticket._launcher is not self
                or publication_ticket.lifecycle_id != checked_lifecycle_id
                or publication_ticket.spawn_request_digest
                != self._request.request_digest
            ):
                raise _lifecycle_error("resolver READY publication ticket 无效。")
            with self._publication_lock:
                publication_state = self._ready_publications.get(
                    publication_ticket.publication_id
                )
                if (
                    publication_state is None
                    or publication_state.ticket is not publication_ticket
                    or publication_state.status != "reserved"
                    or publication_state.guard is not None
                ):
                    raise _lifecycle_error(
                        "resolver READY publication reservation 不可用。"
                    )
        ledger = _ResolverLifecycleLedger(lifecycle_id)
        guard = PreAttemptResolverGuard(
            lifecycle_id=lifecycle_id,
            spawn_request_digest=self._request.request_digest,
            ledger=ledger,
            _authority=_PRE_GUARD_FACTORY_AUTHORITY,
        )
        ledger.bind_pre_owner(guard)
        try:
            kernel = self._spawner.spawn(self._request)
            ledger.attach_kernel(guard, kernel)
            frame = _read_bounded_frame(
                kernel,
                maximum=MAX_READY_FRAME_BYTES,
                label="READY",
            )
            if frame != READY_FRAME:
                raise _lifecycle_error("resolver helper READY frame 无效。")
            ledger.mark_ready(guard)
            _notify(observer, "ready_committed", guard.safe_metadata())
            if publication_ticket is not None:
                self._publish_ready_guard(publication_ticket, guard)
            return guard
        except BaseException:
            if publication_ticket is not None:
                self._cancel_ready_reservation(publication_ticket)
            _cleanup_guard(
                guard,
                ledger,
                observer=None,
                suppress_errors=True,
            )
            raise


def encode_start_frame(
    *,
    hostname: str,
    port: int,
    network_policy_ref: str,
    network_policy_digest: Digest256,
    attempt_permit_id: UUID,
    attempt_permit_digest: Digest256,
    transport_claim_id: UUID,
    terminal_guard_id: UUID,
    terminal_guard_digest: Digest256,
    dns_start_id: UUID,
) -> bytes:
    """Encode the only target-bearing frame in canonical bounded JSON."""

    checked_hostname = _require_hostname(hostname)
    checked_port = require_plain_int(port, "port", minimum=1)
    if checked_port > 65_535:
        raise ValueError("port must be <= 65535")
    checked_ref = require_text(
        network_policy_ref, "network_policy_ref", max_length=256
    )
    if any(ord(char) > 0x7F for char in checked_ref):
        raise ValueError("network_policy_ref must be ASCII")
    payload = {
        "attempt_permit_digest": require_digest(
            attempt_permit_digest, "attempt_permit_digest"
        ),
        "attempt_permit_id": require_uuid(
            attempt_permit_id, "attempt_permit_id"
        ),
        "dns_start_id": require_uuid(dns_start_id, "dns_start_id"),
        "hostname": checked_hostname,
        "kind": "START",
        "network_policy_digest": require_digest(
            network_policy_digest, "network_policy_digest"
        ),
        "network_policy_ref": checked_ref,
        "port": checked_port,
        "schema_version": RESOLVER_HELPER_START_SCHEMA_VERSION,
        "terminal_guard_digest": require_digest(
            terminal_guard_digest, "terminal_guard_digest"
        ),
        "terminal_guard_id": require_uuid(
            terminal_guard_id, "terminal_guard_id"
        ),
        "transport_claim_id": require_uuid(
            transport_claim_id, "transport_claim_id"
        ),
    }
    frame = canonical_json_bytes(payload) + b"\n"
    if len(frame) > MAX_START_FRAME_BYTES:
        raise _lifecycle_error("START frame 超过上限。")
    return frame
