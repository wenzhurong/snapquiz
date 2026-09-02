"""Offline contracts for the W09-B2 resolver-helper lifecycle.

This module deliberately contains no process implementation.  A helper can
only be reached through injected ``HelperSpawner``/``HelperKernel`` objects;
that injection point is a trusted test seam, not a production authorization
boundary.  The offline coordinator holds a launcher-issued lifecycle
capability and proves the matching AttemptGate claim and DNS-start commit
before invoking the private lifecycle transitions.  The production placeholder
fails closed until an independently executable, ``posix_spawn`` based adapter
is implemented and validated.
Importing and constructing the contracts performs no process, DNS, file,
environment, or socket I/O.
"""
from __future__ import annotations

import hashlib
import re
from threading import RLock
from typing import Callable, NamedTuple, Protocol
from uuid import UUID, uuid4, uuid5

import snapquiz.runtime.attempt as attempt_module

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
RESOLVER_LIFECYCLE_CAPABILITY_SCHEMA_VERSION = (
    "snapquiz.resolver-lifecycle-capability.v1"
)
READY_FRAME = b"SNAPQUIZ-RESOLVER/2 READY\n"
MAX_READY_FRAME_BYTES = 64
MAX_START_FRAME_BYTES = 4_096
MAX_RESULT_TRANSCRIPT_BYTES = 16_384
# The protocol frame includes its terminating LF; the transcript limit does not.
MAX_RESULT_FRAME_BYTES = MAX_RESULT_TRANSCRIPT_BYTES + 1
MAX_RESULT_CANDIDATES = 32
MAX_HELPER_STDERR_BYTES = 4_096
HELPER_CLEANUP_POLL_QUANTUM_NS = 50_000_000
MAX_HELPER_CLEANUP_POLL_STEPS = 8

HELPER_PHASE_SPAWN = "resolver_helper.spawn"
HELPER_PHASE_READY = "resolver_helper.ready"
HELPER_PHASE_START = "resolver_helper.start"
HELPER_PHASE_RESULT = "resolver_helper.result"
HELPER_PHASE_RESULT_EOF = "resolver_helper.result_eof"
HELPER_PHASE_RESULT_REAP = "resolver_helper.result_reap"
HELPER_PHASE_RESULT_CLOSE = "resolver_helper.result_close"

_PRE_GUARD_FACTORY_AUTHORITY = object()
_ATTEMPT_GUARD_FACTORY_AUTHORITY = object()
_RESULT_RECEIPT_FACTORY_AUTHORITY = object()
_READY_PUBLICATION_TICKET_AUTHORITY = object()
_RESOLVER_LIFECYCLE_AUTHORITY = object()
_KERNEL_PUBLICATION_AUTHORITY = object()
_TERMINAL_GUARD_UUID_NAMESPACE = UUID(
    "4c82487b-3247-52f0-9fb9-7696da7f7471"
)
_DNS_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)

@runtime_final
class _HelperPollSentinel:
    """Immutable identity result for one bounded helper poll."""

    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        object.__setattr__(self, "_name", name)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("helper poll sentinels are immutable")

    def __copy__(self) -> "_HelperPollSentinel":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_HelperPollSentinel":
        del memo
        return self

    def __repr__(self) -> str:
        return self._name


# ``b""`` is exclusively stdout EOF.  These identity values are therefore
# deliberately not bytes and cannot be confused with either data or EOF.
PENDING = _HelperPollSentinel("PENDING")
COMPLETE = _HelperPollSentinel("COMPLETE")


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

    def read_stdout(self, max_bytes: int, *, max_wait_ns: int) -> object:
        """Return non-empty bytes, exact EOF ``b""``, or ``PENDING``."""

    def write_stdin(self, frame: bytes, *, max_wait_ns: int) -> object:
        """Atomically return ``COMPLETE`` or ``PENDING`` for one frame."""

    def terminate(self, *, max_wait_ns: int) -> object:
        """Return ``COMPLETE`` or ``PENDING`` without exceeding the slice."""

    def reap(self, *, max_wait_ns: int) -> object:
        """Return a plain exit status or ``PENDING`` within the slice."""

    def close_pipes(self, *, max_wait_ns: int) -> object:
        """Return ``COMPLETE`` or ``PENDING`` without exceeding the slice."""


class HelperSpawner(Protocol):
    """Injectable process boundary used only by the private READY transition."""

    def spawn(
        self,
        request: "ResolverHelperSpawnRequest",
        *,
        publication: "_KernelPublication",
        max_wait_ns: int,
    ) -> object:
        """Return the published kernel or ``PENDING`` within the slice."""


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


class _LifecycleCapabilitySnapshot(NamedTuple):
    """Ledger-owned copy of one launcher-issued lifecycle capability."""

    publication_id: UUID
    lifecycle_id: UUID
    transport_claim_id: UUID
    dns_start_id: UUID
    spawn_request_digest: Digest256
    stop_authority_id: UUID
    stop_authority_digest: Digest256
    capability_digest: Digest256
    launcher: object
    reservation_owner: object


class _TerminalGuardSnapshot(NamedTuple):
    """Ledger-owned copy of one READY-to-attempt ownership transfer."""

    attempt_permit_id: UUID
    attempt_permit_digest: Digest256
    transport_claim_id: UUID
    terminal_guard_id: UUID
    terminal_guard_digest: Digest256


class _SpawnRequestSnapshot(NamedTuple):
    """Launcher-owned immutable view of its exact spawn configuration."""

    request: object
    spawner: object
    canonical_metadata: bytes
    request_digest: Digest256


def _lifecycle_capability_digest(
    *,
    publication_id: UUID,
    lifecycle_id: UUID,
    transport_claim_id: UUID,
    dns_start_id: UUID,
    spawn_request_digest: Digest256,
    stop_authority_id: UUID,
    stop_authority_digest: Digest256,
) -> Digest256:
    """Bind every generated role ID to the exact helper spawn contract."""

    return digest256(
        "ResolverLifecycleCapability",
        RESOLVER_LIFECYCLE_CAPABILITY_SCHEMA_VERSION,
        {
            "publication_id": require_uuid(publication_id, "publication_id"),
            "lifecycle_id": require_uuid(lifecycle_id, "lifecycle_id"),
            "transport_claim_id": require_uuid(
                transport_claim_id,
                "transport_claim_id",
            ),
            "dns_start_id": require_uuid(dns_start_id, "dns_start_id"),
            "spawn_request_digest": require_digest(
                spawn_request_digest,
                "spawn_request_digest",
            ),
            "stop_authority_id": require_uuid(
                stop_authority_id,
                "stop_authority_id",
            ),
            "stop_authority_digest": require_digest(
                stop_authority_digest,
                "stop_authority_digest",
            ),
        },
    )


def _validated_stop_authority(stop_authority: object) -> tuple[UUID, Digest256]:
    """Validate the exact AttemptGate-issued helper stop authority."""

    authority_type = getattr(attempt_module, "HelperStopAuthority", None)
    if authority_type is None or type(stop_authority) is not authority_type:
        raise _lifecycle_error("resolver helper stop authority 类型无效。")
    try:
        stop_authority.validate_integrity()
        authority_id = require_uuid(
            stop_authority.authority_id,
            "stop_authority_id",
        )
        authority_digest = require_digest(
            stop_authority.authority_digest,
            "stop_authority_digest",
        )
    except (AttributeError, TypeError, ValueError):
        raise _lifecycle_error("resolver helper stop authority proof 无效。") from None
    return authority_id, authority_digest


def _validated_lifecycle_capability_snapshot(
    capability: object,
    *,
    launcher: object | None = None,
) -> _LifecycleCapabilitySnapshot:
    """Validate one exact immutable capability and return an independent copy."""

    if type(capability) is not _ReadyPublicationTicket:
        raise _lifecycle_error("resolver lifecycle capability 类型无效。")
    bound_launcher = capability._launcher
    reservation_owner = capability._reservation_owner
    if bound_launcher is None or reservation_owner is None:
        raise _lifecycle_error("resolver lifecycle capability owner 无效。")
    if launcher is not None and bound_launcher is not launcher:
        raise _lifecycle_error("resolver lifecycle capability launcher 无效。")
    publication_id = require_uuid(capability.publication_id, "publication_id")
    lifecycle_id = require_uuid(capability.lifecycle_id, "lifecycle_id")
    transport_claim_id = require_uuid(
        capability.transport_claim_id,
        "transport_claim_id",
    )
    dns_start_id = require_uuid(capability.dns_start_id, "dns_start_id")
    if len(
        {
            publication_id,
            lifecycle_id,
            transport_claim_id,
            dns_start_id,
        }
    ) != 4:
        raise _lifecycle_error("resolver lifecycle capability role id 冲突。")
    spawn_request_digest = require_digest(
        capability.spawn_request_digest,
        "spawn_request_digest",
    )
    stop_authority = capability._stop_authority
    if stop_authority is not capability._issued_stop_authority:
        raise _lifecycle_error("resolver helper stop authority owner 无效。")
    stop_authority_id, stop_authority_digest = _validated_stop_authority(
        stop_authority
    )
    if (
        require_uuid(capability.stop_authority_id, "stop_authority_id")
        != stop_authority_id
        or require_digest(
            capability.stop_authority_digest,
            "stop_authority_digest",
        )
        != stop_authority_digest
    ):
        raise _lifecycle_error("resolver helper stop authority binding 无效。")
    capability_digest = require_digest(
        capability.capability_digest,
        "capability_digest",
    )
    expected_digest = _lifecycle_capability_digest(
        publication_id=publication_id,
        lifecycle_id=lifecycle_id,
        transport_claim_id=transport_claim_id,
        dns_start_id=dns_start_id,
        spawn_request_digest=spawn_request_digest,
        stop_authority_id=stop_authority_id,
        stop_authority_digest=stop_authority_digest,
    )
    if capability_digest != expected_digest:
        raise _lifecycle_error("resolver lifecycle capability digest 无效。")
    return _LifecycleCapabilitySnapshot(
        publication_id=publication_id,
        lifecycle_id=lifecycle_id,
        transport_claim_id=transport_claim_id,
        dns_start_id=dns_start_id,
        spawn_request_digest=spawn_request_digest,
        stop_authority_id=stop_authority_id,
        stop_authority_digest=stop_authority_digest,
        capability_digest=capability_digest,
        launcher=bound_launcher,
        reservation_owner=reservation_owner,
    )


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


def _read_bounded_frame(
    kernel: HelperKernel,
    *,
    ledger: "_ResolverLifecycleLedger",
    owner: object,
    phase: str,
    maximum: int,
    label: str,
) -> bytes:
    """Poll exactly one newline-terminated frame without blocking or over-read."""

    require_plain_int(maximum, "maximum", minimum=1)
    checked_phase = require_text(phase, "phase", max_length=64)
    buffer = bytearray()
    while True:
        allowance = maximum - len(buffer)
        if allowance <= 0:
            raise _lifecycle_error(f"{label} frame 超过上限。")
        wait_slice = ledger.business_wait_slice(owner, checked_phase)
        chunk = kernel.read_stdout(
            allowance,
            max_wait_ns=wait_slice.max_wait_ns,
        )
        if chunk is PENDING:
            ledger.business_wait_slice(owner, checked_phase)
            continue
        if type(chunk) is not bytes or len(chunk) > allowance:
            raise _lifecycle_error(f"{label} frame 读取合同无效。")
        ledger.business_wait_slice(owner, checked_phase)
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


def _capture_spawn_request_snapshot(
    request: object,
    spawner: object,
) -> _SpawnRequestSnapshot:
    """Validate and freeze the exact request bytes and spawner identity."""

    if type(request) is not ResolverHelperSpawnRequest:
        raise _lifecycle_error("resolver helper spawn request 类型无效。")
    if spawner is None or not callable(getattr(spawner, "spawn", None)):
        raise _lifecycle_error("resolver helper spawner 无效。")
    try:
        metadata = request.safe_metadata()
        canonical_metadata = canonical_json_bytes(metadata)
        request_digest = digest256(
            "ResolverHelperSpawnRequest",
            RESOLVER_HELPER_PROTOCOL_VERSION,
            metadata,
        )
        current_digest = require_digest(
            request.request_digest,
            "request_digest",
        )
    except (AttributeError, TypeError, ValueError):
        raise _lifecycle_error("resolver helper spawn request proof 无效。") from None
    if request_digest != current_digest:
        raise _lifecycle_error("resolver helper spawn request 已变化。")
    return _SpawnRequestSnapshot(
        request=request,
        spawner=spawner,
        canonical_metadata=canonical_metadata,
        request_digest=request_digest,
    )


@runtime_final
class FailClosedProductionHelperSpawner:
    """Production placeholder: deliberately performs no process operation."""

    __slots__ = ()

    def spawn(
        self,
        request: ResolverHelperSpawnRequest,
        *,
        publication: "_KernelPublication",
        max_wait_ns: int,
    ) -> object:
        if type(request) is not ResolverHelperSpawnRequest:
            raise TypeError("request must be ResolverHelperSpawnRequest")
        if type(publication) is not _KernelPublication:
            raise TypeError("publication must be _KernelPublication")
        require_plain_int(max_wait_ns, "max_wait_ns", minimum=1)
        raise _production_unavailable() from None


class _ResolverLifecycleLedger:
    """One ledger whose owner identity is the guard object itself."""

    __slots__ = (
        "lifecycle_id",
        "_capability",
        "_capability_snapshot",
        "_terminal_guard_snapshot",
        "_lock",
        "_pre_owner",
        "_owner",
        "_kernel",
        "_state",
        "_cleanup_claimed",
        "_terminate_claimed",
        "_terminate_pending",
        "_terminated",
        "_eof_probe_claimed",
        "_stdout_eof",
        "_reap_claimed",
        "_reap_pending",
        "_child_reaped",
        "_child_exit_status",
        "_pipes_close_claimed",
        "_pipes_close_pending",
        "_helper_pipes_closed",
        "_dns_start_id",
        "_start_frame_digest",
        "_issued_receipt",
        "_issued_receipt_snapshot",
        "_issued_resolution_snapshot",
        "_launch_owner_snapshot",
        "_stop_authority",
        "_on_terminal",
    )

    def __init__(
        self,
        capability: object,
        *,
        on_terminal: Callable[["_ResolverLifecycleLedger"], None] | None = None,
    ) -> None:
        snapshot = _validated_lifecycle_capability_snapshot(capability)
        if on_terminal is not None and not callable(on_terminal):
            raise TypeError("on_terminal must be callable")
        self.lifecycle_id = snapshot.lifecycle_id
        self._capability = capability
        self._capability_snapshot = snapshot
        self._terminal_guard_snapshot: _TerminalGuardSnapshot | None = None
        self._lock = RLock()
        self._pre_owner: object | None = None
        self._owner: object | None = None
        self._kernel: HelperKernel | None = None
        self._state = "created"
        self._cleanup_claimed = False
        self._terminate_claimed = False
        self._terminate_pending = False
        self._terminated = False
        self._eof_probe_claimed = False
        self._stdout_eof = False
        self._reap_claimed = False
        self._reap_pending = False
        self._child_reaped = False
        self._child_exit_status: int | None = None
        self._pipes_close_claimed = False
        self._pipes_close_pending = False
        self._helper_pipes_closed = False
        self._dns_start_id: UUID | None = None
        self._start_frame_digest: Digest256 | None = None
        self._issued_receipt: ResolverResultReceipt | None = None
        self._issued_receipt_snapshot: _ResultReceiptIssuanceSnapshot | None = None
        self._issued_resolution_snapshot: _ResolutionPublicationSnapshot | None = None
        self._launch_owner_snapshot: object | None = None
        self._stop_authority: object | None = capability._stop_authority
        self._on_terminal = on_terminal

    def bind_launch_owner(
        self,
        capability: object,
        launch_owner: object,
    ) -> None:
        """Freeze the exact launch identity before helper creation is possible."""

        if launch_owner is None:
            raise TypeError("launch_owner must be an identity object")
        with self._lock:
            if (
                capability is not self._capability
                or self._launch_owner_snapshot is not None
                or _validated_lifecycle_capability_snapshot(capability)
                != self._capability_snapshot
            ):
                raise _lifecycle_error("resolver helper launch owner 已变化。")
            self._launch_owner_snapshot = launch_owner

    def require_exact_capability(
        self,
        owner: object,
        capability: object,
    ) -> _LifecycleCapabilitySnapshot:
        """Reject aliases or mutated capability objects before state changes."""

        with self._lock:
            if (
                capability is not self._capability
                or getattr(owner, "_capability", None) is not capability
            ):
                raise _lifecycle_error("resolver lifecycle capability owner 无效。")
            snapshot = _validated_lifecycle_capability_snapshot(capability)
            if snapshot != self._capability_snapshot:
                raise _lifecycle_error("resolver lifecycle capability 已变化。")
            return snapshot

    def business_wait_slice(self, owner: object, phase: str) -> object:
        """Issue one exact bounded wait slice before or after a business poll."""

        checked_phase = require_text(phase, "phase", max_length=64)
        with self._lock:
            snapshot = self._capability_snapshot
            stop_authority = self._stop_authority
            if (
                self._owner is not owner
                or self._state in ("cleaning", "cleanup_failed", "terminal")
                or stop_authority is None
                or self._capability is None
                or stop_authority is not self._capability._stop_authority
                or _validated_lifecycle_capability_snapshot(self._capability)
                != snapshot
            ):
                raise _lifecycle_error("resolver helper stop authority owner 无效。")
        authority_id, authority_digest = _validated_stop_authority(stop_authority)
        if (
            authority_id != snapshot.stop_authority_id
            or authority_digest != snapshot.stop_authority_digest
        ):
            raise _lifecycle_error("resolver helper stop authority 已变化。")

        wait_slice = stop_authority._checkpoint(
            checked_phase,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        wait_slice_type = getattr(attempt_module, "HelperWaitSlice", None)
        if wait_slice_type is None or type(wait_slice) is not wait_slice_type:
            raise _lifecycle_error("resolver helper wait slice 类型无效。")
        try:
            wait_slice.validate_integrity()
            wait_authority_id = require_uuid(
                wait_slice.authority_id,
                "wait_authority_id",
            )
            wait_authority_digest = require_digest(
                wait_slice.authority_digest,
                "wait_authority_digest",
            )
            max_wait_ns = require_plain_int(
                wait_slice.max_wait_ns,
                "max_wait_ns",
                minimum=1,
            )
            observed_ns = require_plain_int(
                wait_slice.observed_monotonic_ns,
                "observed_monotonic_ns",
            )
            deadline_ns = require_plain_int(
                wait_slice.effective_deadline_ns,
                "effective_deadline_ns",
            )
            wait_phase = require_text(
                wait_slice.phase,
                "phase",
                max_length=64,
            )
        except (AttributeError, TypeError, ValueError):
            raise _lifecycle_error("resolver helper wait slice proof 无效。") from None
        if (
            wait_phase != checked_phase
            or wait_authority_id != snapshot.stop_authority_id
            or wait_authority_digest != snapshot.stop_authority_digest
            or deadline_ns != stop_authority.effective_deadline_ns
            or observed_ns >= deadline_ns
            or max_wait_ns > deadline_ns - observed_ns
        ):
            raise _lifecycle_error("resolver helper wait slice binding 无效。")

        # Recheck identity after the authority call so a tampered or aliased
        # capability cannot supply a slice and then win the poll boundary.
        with self._lock:
            if (
                self._owner is not owner
                or self._stop_authority is not stop_authority
                or self._capability_snapshot != snapshot
            ):
                raise _lifecycle_error("resolver helper stop authority 已变化。")
        return wait_slice

    def bind_pre_owner(self, owner: object) -> None:
        with self._lock:
            if (
                self._owner is not None
                or self._state != "created"
                or getattr(owner, "_capability", None) is not self._capability
                or _validated_lifecycle_capability_snapshot(self._capability)
                != self._capability_snapshot
            ):
                raise _lifecycle_error("resolver helper owner 已绑定。")
            self._pre_owner = owner
            self._owner = owner

    def attach_kernel(self, owner: object, kernel: HelperKernel) -> None:
        with self._lock:
            if self._owner is not owner or self._state != "created":
                raise _lifecycle_error("resolver helper spawn owner 已变化。")
            self._kernel = kernel
            self._state = "spawned"

    def is_exact_kernel_attached(
        self,
        owner: object,
        kernel: HelperKernel,
    ) -> bool:
        """Observe the exact pre-return kernel anchor."""

        with self._lock:
            return (
                self._owner is owner
                and self._pre_owner is owner
                and self._kernel is kernel
                and self._state == "spawned"
            )

    def recover_kernel_publication_for_cleanup(
        self,
        owner: object,
        kernel: HelperKernel,
    ) -> bool:
        """Anchor a normal-return no-op publication for cleanup only."""

        with self._lock:
            if (
                self._owner is not owner
                or self._pre_owner is not owner
                or self._state != "created"
                or self._kernel is not None
            ):
                return self._kernel is kernel and self._state == "spawned"
            self._kernel = kernel
            self._state = "spawned"
            return True

    def mark_ready(self, owner: object) -> None:
        self._cas(owner, expected="spawned", replacement=owner, target="ready")

    def require_exact_ready_guard(
        self,
        owner: object,
        capability: object,
    ) -> _LifecycleCapabilitySnapshot:
        """Return the snapshot only after READY is durably ledger-owned."""

        with self._lock:
            snapshot = self.require_exact_capability(owner, capability)
            if (
                type(owner) is not PreAttemptResolverGuard
                or getattr(owner, "_ledger", None) is not self
                or self._owner is not owner
                or self._pre_owner is not owner
                or self._state != "ready"
                or self._kernel is None
                or owner.lifecycle_id != snapshot.lifecycle_id
                or owner.spawn_request_digest != snapshot.spawn_request_digest
            ):
                raise _lifecycle_error("resolver READY ledger proof 未提交。")
            return snapshot

    def transfer(self, owner: object, replacement: object) -> None:
        with self._lock:
            capability_snapshot = _validated_lifecycle_capability_snapshot(
                self._capability
            )
            if (
                getattr(owner, "_capability", None) is not self._capability
                or type(replacement) is not AttemptTerminalGuard
                or getattr(replacement, "_capability", None)
                is not self._capability
                or replacement._ledger is not self
                or capability_snapshot != self._capability_snapshot
                or replacement.lifecycle_id != capability_snapshot.lifecycle_id
                or replacement.transport_claim_id
                != capability_snapshot.transport_claim_id
                or self._owner is not owner
                or self._state != "ready"
                or self._terminal_guard_snapshot is not None
            ):
                raise _lifecycle_error("resolver helper owner 或状态已经变化。")
            expected_guard_id = uuid5(
                _TERMINAL_GUARD_UUID_NAMESPACE,
                str(
                    digest256(
                        "ResolverTerminalGuardIdentifier",
                        RESOLVER_TERMINAL_GUARD_SCHEMA_VERSION,
                        {
                            "lifecycle_id": capability_snapshot.lifecycle_id,
                            "attempt_permit_id": replacement.attempt_permit_id,
                            "attempt_permit_digest": (
                                replacement.attempt_permit_digest
                            ),
                            "transport_claim_id": (
                                capability_snapshot.transport_claim_id
                            ),
                        },
                    )
                ),
            )
            expected_guard_digest = _terminal_guard_digest(
                lifecycle_id=capability_snapshot.lifecycle_id,
                attempt_permit_id=replacement.attempt_permit_id,
                attempt_permit_digest=replacement.attempt_permit_digest,
                transport_claim_id=capability_snapshot.transport_claim_id,
                terminal_guard_id=expected_guard_id,
            )
            if (
                replacement.terminal_guard_id != expected_guard_id
                or replacement.terminal_guard_digest != expected_guard_digest
            ):
                raise _lifecycle_error("resolver terminal guard proof 无效。")
            self._terminal_guard_snapshot = _TerminalGuardSnapshot(
                attempt_permit_id=replacement.attempt_permit_id,
                attempt_permit_digest=replacement.attempt_permit_digest,
                transport_claim_id=capability_snapshot.transport_claim_id,
                terminal_guard_id=expected_guard_id,
                terminal_guard_digest=expected_guard_digest,
            )
            self._owner = replacement
            self._state = "transferred"

    def recover_transferred_guard_for_cleanup(
        self,
        pre_owner: object,
        *,
        attempt_permit_id: UUID,
        attempt_permit_digest: Digest256,
    ) -> bool:
        """Clean the ledger-owned post-transfer owner without returning it."""

        transport_claim_id = self._capability_snapshot.transport_claim_id
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
            expected_snapshot = _TerminalGuardSnapshot(
                attempt_permit_id=attempt_permit_id,
                attempt_permit_digest=attempt_permit_digest,
                transport_claim_id=transport_claim_id,
                terminal_guard_id=expected_guard_id,
                terminal_guard_digest=expected_guard_digest,
            )
            if (
                self._pre_owner is not pre_owner
                or self._state != "transferred"
                or self._cleanup_claimed
                or type(guard) is not AttemptTerminalGuard
                or self._terminal_guard_snapshot != expected_snapshot
            ):
                return self._state == "terminal"
        _cleanup_guard(
            guard,
            self,
            suppress_errors=True,
        )
        return self.is_terminal()

    def require_exact_terminal_guard(
        self,
        owner: object,
        capability: object,
    ) -> tuple[_LifecycleCapabilitySnapshot, _TerminalGuardSnapshot]:
        """Return only ledger snapshots after exact terminal-owner validation."""

        with self._lock:
            capability_snapshot = _validated_lifecycle_capability_snapshot(
                capability
            )
            guard_snapshot = self._terminal_guard_snapshot
            if (
                capability is not self._capability
                or capability_snapshot != self._capability_snapshot
                or self._owner is not owner
                or type(owner) is not AttemptTerminalGuard
                or getattr(owner, "_ledger", None) is not self
                or getattr(owner, "_capability", None) is not self._capability
                or guard_snapshot is None
                or owner.lifecycle_id != capability_snapshot.lifecycle_id
                or owner.attempt_permit_id != guard_snapshot.attempt_permit_id
                or owner.attempt_permit_digest
                != guard_snapshot.attempt_permit_digest
                or owner.transport_claim_id != guard_snapshot.transport_claim_id
                or owner.terminal_guard_id != guard_snapshot.terminal_guard_id
                or owner.terminal_guard_digest
                != guard_snapshot.terminal_guard_digest
            ):
                raise _lifecycle_error("resolver terminal guard proof 已变化。")
            return capability_snapshot, guard_snapshot

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
        self.require_exact_terminal_guard(owner, self._capability)
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "transferred"
                or getattr(owner, "_capability", None)
                is not self._capability
                or _validated_lifecycle_capability_snapshot(self._capability)
                != self._capability_snapshot
                or checked_start_id != self._capability_snapshot.dns_start_id
            ):
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
        self.require_exact_terminal_guard(owner, self._capability)
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
            self._reap_pending = False
            self._state = "result_reaping"
            return self._kernel

    def begin_result_reap_poll(self, owner: object) -> None:
        """Forget a prior explicit PENDING immediately before the next poll."""

        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_reaping"
                or not self._reap_claimed
                or self._child_reaped
            ):
                raise _lifecycle_error("resolver child reap poll 状态无效。")
            self._reap_pending = False

    def mark_result_reap_pending(self, owner: object) -> None:
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_reaping"
                or not self._reap_claimed
                or self._child_reaped
            ):
                raise _lifecycle_error("resolver child reap pending 状态无效。")
            self._reap_pending = True

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
            self._reap_pending = False
            self._state = (
                "result_reaped" if checked_status == 0 else "result_exit_rejected"
            )

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
            self._pipes_close_pending = False
            self._state = "result_pipes_closing"
            return self._kernel

    def begin_result_pipe_close_poll(self, owner: object) -> None:
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_pipes_closing"
                or not self._pipes_close_claimed
                or self._helper_pipes_closed
            ):
                raise _lifecycle_error("resolver helper pipe close poll 状态无效。")
            self._pipes_close_pending = False

    def mark_result_pipe_close_pending(self, owner: object) -> None:
        with self._lock:
            if (
                self._owner is not owner
                or self._state != "result_pipes_closing"
                or not self._pipes_close_claimed
                or self._helper_pipes_closed
            ):
                raise _lifecycle_error("resolver helper pipe close pending 状态无效。")
            self._pipes_close_pending = True

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
            self._pipes_close_pending = False
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
            guard_snapshot = self._terminal_guard_snapshot
            if (
                self._owner is not owner
                or self._state != "result_resources_closed"
                or type(owner) is not AttemptTerminalGuard
                or guard_snapshot is None
                or type(receipt) is not ResolverResultReceipt
                or receipt._ledger is not self
                or receipt._issuer is not owner
                or self._issued_receipt is not None
                or self._issued_receipt_snapshot is not None
                or snapshot.lifecycle_id != self._capability_snapshot.lifecycle_id
                or snapshot.attempt_permit_id
                != guard_snapshot.attempt_permit_id
                or snapshot.attempt_permit_digest
                != guard_snapshot.attempt_permit_digest
                or snapshot.transport_claim_id
                != guard_snapshot.transport_claim_id
                or snapshot.terminal_guard_id
                != guard_snapshot.terminal_guard_id
                or snapshot.terminal_guard_digest
                != guard_snapshot.terminal_guard_digest
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
                (
                    self._reap_claimed
                    and not self._child_reaped
                    and not self._reap_pending
                )
                or (
                    self._pipes_close_claimed
                    and not self._helper_pipes_closed
                    and not self._pipes_close_pending
                )
                or (
                    self._terminate_claimed
                    and not self._terminated
                    and not self._terminate_pending
                )
            )
            terminate = (
                kernel is not None
                and not self._child_reaped
                and not self._reap_claimed
                and (not self._terminate_claimed or self._terminate_pending)
            )
            reap = (
                kernel is not None
                and not self._child_reaped
                and (not self._reap_claimed or self._reap_pending)
            )
            close_pipes = (
                kernel is not None
                and not self._helper_pipes_closed
                and (
                    not self._pipes_close_claimed
                    or self._pipes_close_pending
                )
            )

            # Claim each selected external action before exposing the plan.
            # A return-then-raise fault must never permit a second reap/close.
            if terminate:
                self._terminate_claimed = True
                self._terminate_pending = False
            if reap:
                self._reap_claimed = True
                # Preserve explicit PENDING until the cleanup poll begins.
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

    def begin_cleanup_action_poll(
        self,
        owner: object,
        action_name: str,
    ) -> None:
        """Turn an explicit retry-safe PENDING into an in-flight poll."""

        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            if action_name == "terminate":
                if not self._terminate_claimed or self._terminated:
                    raise _lifecycle_error("resolver helper terminate poll 无效。")
                self._terminate_pending = False
                return
            if action_name == "reap":
                if not self._reap_claimed or self._child_reaped:
                    raise _lifecycle_error("resolver helper reap poll 无效。")
                self._reap_pending = False
                return
            if action_name == "close_pipes":
                if not self._pipes_close_claimed or self._helper_pipes_closed:
                    raise _lifecycle_error("resolver helper pipe poll 无效。")
                self._pipes_close_pending = False
                return
            raise ValueError("unknown resolver helper cleanup action")

    def mark_cleanup_action_pending(
        self,
        owner: object,
        action_name: str,
    ) -> None:
        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            if action_name == "terminate":
                if not self._terminate_claimed or self._terminated:
                    raise _lifecycle_error("resolver helper terminate pending 无效。")
                self._terminate_pending = True
                return
            if action_name == "reap":
                if not self._reap_claimed or self._child_reaped:
                    raise _lifecycle_error("resolver helper reap pending 无效。")
                self._reap_pending = True
                return
            if action_name == "close_pipes":
                if not self._pipes_close_claimed or self._helper_pipes_closed:
                    raise _lifecycle_error("resolver helper pipe pending 无效。")
                self._pipes_close_pending = True
                return
            raise ValueError("unknown resolver helper cleanup action")

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
                self._terminate_pending = False
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
                self._reap_pending = False
                return
            if action_name == "close_pipes":
                if not self._pipes_close_claimed or self._helper_pipes_closed:
                    raise _lifecycle_error("resolver helper pipe proof 无效。")
                self._helper_pipes_closed = True
                self._pipes_close_pending = False
                return
            raise ValueError("unknown resolver helper cleanup action")

    def finish_cleanup(self, owner: object) -> None:
        callback: Callable[["_ResolverLifecycleLedger"], None] | None
        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            if self._kernel is not None and (
                not self._child_reaped or not self._helper_pipes_closed
            ):
                raise _lifecycle_error("resolver helper 资源终结证明不完整。")
            self._kernel = None
            self._stop_authority = None
            self._pre_owner = None
            self._owner = None
            self._state = "terminal"
            callback = self._on_terminal
        if callback is not None:
            try:
                callback(self)
            except BaseException:
                # Terminal resource proof is stronger than registry bookkeeping.
                pass

    def mark_cleanup_failed(self, owner: object) -> None:
        """Retain the kernel and owner when resource release is unproven."""

        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            self._state = "cleanup_failed"

    def cleanup_is_ready_to_finish(self, owner: object) -> bool:
        """Observe bookkeeping-only cleanup remaining after all resources."""

        with self._lock:
            return (
                self._owner is owner
                and self._state == "cleaning"
                and self._cleanup_claimed
                and (
                    self._kernel is None
                    or (self._child_reaped and self._helper_pipes_closed)
                )
            )

    def retry_finish_cleanup(self, owner: object) -> bool:
        """Retry only terminal bookkeeping; never repeat external actions."""

        if self.is_terminal():
            return True
        if not self.cleanup_is_ready_to_finish(owner):
            return False
        try:
            self.finish_cleanup(owner)
        except BaseException:
            return False
        return self.is_terminal()

    def is_terminal(self) -> bool:
        with self._lock:
            return self._state == "terminal"

    def recover_current_owner_for_cleanup(self) -> bool:
        """Clean the ledger-held owner without exposing a live capability."""

        with self._lock:
            if self._state == "terminal":
                return True
            owner = self._owner
            if owner is None:
                return False
        _cleanup_guard(
            owner,
            self,
            suppress_errors=True,
        )
        return self.is_terminal()

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


@runtime_final
class _KernelPublication:
    """Single-use sink that anchors a created helper before spawn returns."""

    __slots__ = ("_ledger", "_owner", "_lock", "_kernel")

    def __init__(
        self,
        *,
        ledger: _ResolverLifecycleLedger,
        owner: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _KERNEL_PUBLICATION_AUTHORITY:
            raise TypeError("kernel publication requires launcher")
        if type(ledger) is not _ResolverLifecycleLedger:
            raise TypeError("ledger must be _ResolverLifecycleLedger")
        object.__setattr__(self, "_ledger", ledger)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_kernel", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("_KernelPublication is immutable")

    def publish(self, kernel: HelperKernel) -> None:
        """Attach the exact live helper before control can leave ``spawn``."""

        if kernel is None or any(
            not callable(getattr(kernel, method_name, None))
            for method_name in (
                "read_stdout",
                "write_stdin",
                "terminate",
                "reap",
                "close_pipes",
            )
        ):
            raise _lifecycle_error("resolver helper kernel 合同无效。")
        with self._lock:
            if self._kernel is not None:
                raise _lifecycle_error("resolver helper kernel 已发布。")
            self._ledger.attach_kernel(self._owner, kernel)
            if not self._ledger.is_exact_kernel_attached(
                self._owner,
                kernel,
            ):
                self._ledger.recover_kernel_publication_for_cleanup(
                    self._owner,
                    kernel,
                )
                raise _lifecycle_error(
                    "resolver helper kernel publication 未提交。"
                )
            object.__setattr__(self, "_kernel", kernel)

    def confirm_returned(self, kernel: HelperKernel) -> None:
        """Require spawn to return the exact already-published kernel."""

        with self._lock:
            if self._kernel is None:
                # A contract-violating spawner may create and return the real
                # helper without first using the sink.  Adopt that exact
                # normal-return value for cleanup only, then still reject the
                # launch so READY/secret/START can never continue.
                if kernel is None or any(
                    not callable(getattr(kernel, method_name, None))
                    for method_name in (
                        "read_stdout",
                        "write_stdin",
                        "terminate",
                        "reap",
                        "close_pipes",
                    )
                ):
                    raise _lifecycle_error(
                        "resolver helper kernel publication 无效。"
                    )
                self._ledger.attach_kernel(self._owner, kernel)
                if not self._ledger.is_exact_kernel_attached(
                    self._owner,
                    kernel,
                ):
                    self._ledger.recover_kernel_publication_for_cleanup(
                        self._owner,
                        kernel,
                    )
                    raise _lifecycle_error(
                        "resolver helper kernel publication 未提交。"
                    )
                object.__setattr__(self, "_kernel", kernel)
                raise _lifecycle_error(
                    "resolver helper kernel 未在 spawn 返回前发布。"
                )
            if self._kernel is not kernel:
                raise _lifecycle_error("resolver helper kernel publication 无效。")


def _cleanup_guard(
    guard: object,
    ledger: _ResolverLifecycleLedger,
    *,
    suppress_errors: bool,
) -> bool:
    try:
        plan = ledger.claim_cleanup(guard)
    except BaseException:
        if suppress_errors:
            return False
        raise
    if not plan.claimed:
        if ledger.is_terminal():
            return False
        return ledger.retry_finish_cleanup(guard)

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
            completed = False
            for _ in range(MAX_HELPER_CLEANUP_POLL_STEPS):
                try:
                    ledger.begin_cleanup_action_poll(guard, action_name)
                    action = getattr(plan.kernel, action_name)
                    result = action(
                        max_wait_ns=HELPER_CLEANUP_POLL_QUANTUM_NS,
                    )
                    if result is PENDING:
                        ledger.mark_cleanup_action_pending(
                            guard,
                            action_name,
                        )
                        continue
                    if action_name in ("terminate", "close_pipes"):
                        if result is not COMPLETE:
                            raise _lifecycle_error(
                                "resolver helper cleanup poll 合同无效。"
                            )
                        result = None
                    elif type(result) is not int:
                        raise _lifecycle_error(
                            "resolver helper cleanup reap 合同无效。"
                        )
                    ledger.commit_cleanup_action(
                        guard,
                        action_name,
                        result,
                    )
                    completed = True
                    break
                except BaseException:
                    break
            if not completed:
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
            pass
        if not ledger.is_terminal():
            ledger.retry_finish_cleanup(guard)
        if not ledger.is_terminal():
            cleanup_failed = True
            if not ledger.cleanup_is_ready_to_finish(guard):
                try:
                    ledger.mark_cleanup_failed(guard)
                except BaseException:
                    pass

    if cleanup_failed and not suppress_errors:
        error = _lifecycle_error("resolver helper cleanup 失败。")
        error.__cause__ = None
        error.__context__ = None
        error.__suppress_context__ = True
        raise error from None
    return ledger.is_terminal()


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
        capability_snapshot, guard_snapshot = ledger.require_exact_terminal_guard(
            issuer,
            issuer._capability,
        )
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
            ("lifecycle_id", capability_snapshot.lifecycle_id),
            ("attempt_permit_id", guard_snapshot.attempt_permit_id),
            ("attempt_permit_digest", guard_snapshot.attempt_permit_digest),
            ("transport_claim_id", guard_snapshot.transport_claim_id),
            ("terminal_guard_id", guard_snapshot.terminal_guard_id),
            ("terminal_guard_digest", guard_snapshot.terminal_guard_digest),
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

    __slots__ = (
        "lifecycle_id",
        "spawn_request_digest",
        "_ledger",
        "_capability",
    )

    def __init__(
        self,
        *,
        lifecycle_id: UUID,
        spawn_request_digest: Digest256,
        ledger: _ResolverLifecycleLedger,
        capability: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PRE_GUARD_FACTORY_AUTHORITY:
            raise TypeError("pre-attempt resolver guards require launcher")
        if type(ledger) is not _ResolverLifecycleLedger:
            raise TypeError("ledger must be _ResolverLifecycleLedger")
        snapshot = _validated_lifecycle_capability_snapshot(capability)
        if (
            ledger._capability is not capability
            or snapshot != ledger._capability_snapshot
            or lifecycle_id != snapshot.lifecycle_id
            or spawn_request_digest != snapshot.spawn_request_digest
        ):
            raise _lifecycle_error("resolver lifecycle capability binding 无效。")
        self.lifecycle_id = require_uuid(lifecycle_id, "lifecycle_id")
        self.spawn_request_digest = require_digest(
            spawn_request_digest, "spawn_request_digest"
        )
        self._ledger = ledger
        self._capability = capability

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

    def _transfer(
        self,
        *,
        attempt_permit_id: UUID,
        attempt_permit_digest: Digest256,
        _authority: object | None = None,
    ) -> "AttemptTerminalGuard":
        """Transfer READY ownership after the coordinator proves ``io_claimed``."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver ownership transfer requires coordinator")
        capability = self._ledger.require_exact_capability(
            self,
            self._capability,
        )
        transport_claim_id = capability.transport_claim_id

        replacement: AttemptTerminalGuard | None = None
        try:
            require_uuid(attempt_permit_id, "attempt_permit_id")
            require_digest(attempt_permit_digest, "attempt_permit_digest")
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
                capability=self._capability,
                _authority=_ATTEMPT_GUARD_FACTORY_AUTHORITY,
            )
            self._ledger.transfer(self, replacement)
        except BaseException:
            if replacement is not None:
                _cleanup_guard(
                    replacement,
                    self._ledger,
                    suppress_errors=True,
                )
            _cleanup_guard(
                self,
                self._ledger,
                suppress_errors=True,
            )
            raise
        return replacement

    def _recover_transferred_guard_for_cleanup(
        self,
        *,
        attempt_permit_id: UUID,
        attempt_permit_digest: Digest256,
        _authority: object | None = None,
    ) -> bool:
        """Clean one lost post-transfer owner without returning capability."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver publication recovery requires coordinator")
        if (
            type(attempt_permit_id) is not UUID
            or type(attempt_permit_digest) is not Digest256
        ):
            return False
        return self._ledger.recover_transferred_guard_for_cleanup(
            self,
            attempt_permit_id=attempt_permit_id,
            attempt_permit_digest=attempt_permit_digest,
        )

    def cleanup(self) -> bool:
        return _cleanup_guard(
            self,
            self._ledger,
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
        "_capability",
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
        capability: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ATTEMPT_GUARD_FACTORY_AUTHORITY:
            raise TypeError("attempt terminal guards require ownership transfer")
        if type(ledger) is not _ResolverLifecycleLedger:
            raise TypeError("ledger must be _ResolverLifecycleLedger")
        snapshot = _validated_lifecycle_capability_snapshot(capability)
        if (
            ledger._capability is not capability
            or snapshot != ledger._capability_snapshot
            or lifecycle_id != snapshot.lifecycle_id
            or transport_claim_id != snapshot.transport_claim_id
        ):
            raise _lifecycle_error("resolver terminal capability binding 无效。")
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
            ("_capability", capability),
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

    def _proof_snapshot(
        self,
        *,
        _authority: object | None = None,
    ) -> _TerminalGuardSnapshot:
        """Return the ledger-owned proof only to the trusted coordinator."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver terminal proof requires coordinator")
        _, guard_snapshot = self._ledger.require_exact_terminal_guard(
            self,
            self._capability,
        )
        return guard_snapshot

    def _start(
        self,
        *,
        hostname: str,
        port: int,
        network_policy_ref: str,
        network_policy_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        """Write the sole START after the coordinator commits DNS authority."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver START requires coordinator")
        capability, guard_snapshot = self._ledger.require_exact_terminal_guard(
            self,
            self._capability,
        )
        dns_start_id = capability.dns_start_id

        try:
            frame = encode_start_frame(
                hostname=hostname,
                port=port,
                network_policy_ref=network_policy_ref,
                network_policy_digest=network_policy_digest,
                attempt_permit_id=guard_snapshot.attempt_permit_id,
                attempt_permit_digest=guard_snapshot.attempt_permit_digest,
                transport_claim_id=guard_snapshot.transport_claim_id,
                terminal_guard_id=guard_snapshot.terminal_guard_id,
                terminal_guard_digest=guard_snapshot.terminal_guard_digest,
                dns_start_id=dns_start_id,
            )
            exact_start_digest = start_frame_digest(frame)
            self._ledger.commit_start(
                self,
                dns_start_id=dns_start_id,
                exact_start_frame_digest=exact_start_digest,
            )
            kernel = self._ledger.kernel_for(self, states=("start_committed",))
            while True:
                wait_slice = self._ledger.business_wait_slice(
                    self,
                    HELPER_PHASE_START,
                )
                write_result = kernel.write_stdin(
                    frame,
                    max_wait_ns=wait_slice.max_wait_ns,
                )
                if write_result is COMPLETE:
                    self._ledger.mark_started(self)
                elif write_result is not PENDING:
                    raise _lifecycle_error(
                        "resolver helper START write 合同无效。"
                    )
                self._ledger.business_wait_slice(self, HELPER_PHASE_START)
                if write_result is COMPLETE:
                    break
        except BaseException:
            _cleanup_guard(
                self,
                self._ledger,
                suppress_errors=True,
            )
            raise

    def _read_result_receipt(
        self,
        *,
        _authority: object | None = None,
    ) -> ResolverResultReceipt:
        """Attest one RESULT, EOF, exit-zero, reap, and closed pipes."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver RESULT read requires coordinator")
        self._ledger.require_exact_terminal_guard(self, self._capability)

        try:
            self._ledger.commit_result_read(self)
            kernel = self._ledger.kernel_for(self, states=("result_reading",))
            frame = _read_bounded_frame(
                kernel,
                ledger=self._ledger,
                owner=self,
                phase=HELPER_PHASE_RESULT,
                maximum=MAX_RESULT_FRAME_BYTES,
                label="RESULT",
            )
            transcript = frame[:-1]
            if not transcript or len(transcript) > MAX_RESULT_TRANSCRIPT_BYTES:
                raise _lifecycle_error("RESULT transcript 超过上限。")

            eof_kernel = self._ledger.claim_stdout_eof_probe(self)
            while True:
                wait_slice = self._ledger.business_wait_slice(
                    self,
                    HELPER_PHASE_RESULT_EOF,
                )
                trailing = eof_kernel.read_stdout(
                    1,
                    max_wait_ns=wait_slice.max_wait_ns,
                )
                if trailing is PENDING:
                    self._ledger.business_wait_slice(
                        self,
                        HELPER_PHASE_RESULT_EOF,
                    )
                    continue
                if type(trailing) is not bytes or len(trailing) > 1:
                    raise _lifecycle_error("RESULT EOF probe 读取合同无效。")
                if not trailing:
                    self._ledger.commit_stdout_eof(self)
                self._ledger.business_wait_slice(
                    self,
                    HELPER_PHASE_RESULT_EOF,
                )
                if trailing:
                    raise _lifecycle_error("RESULT 后存在第二帧或尾随输出。")
                break

            reap_kernel = self._ledger.claim_result_reap(self)
            while True:
                wait_slice = self._ledger.business_wait_slice(
                    self,
                    HELPER_PHASE_RESULT_REAP,
                )
                self._ledger.begin_result_reap_poll(self)
                exit_status = reap_kernel.reap(
                    max_wait_ns=wait_slice.max_wait_ns,
                )
                if exit_status is PENDING:
                    self._ledger.mark_result_reap_pending(self)
                elif type(exit_status) is int:
                    self._ledger.commit_result_reap(self, exit_status)
                else:
                    raise _lifecycle_error("resolver child reap 合同无效。")
                self._ledger.business_wait_slice(
                    self,
                    HELPER_PHASE_RESULT_REAP,
                )
                if exit_status is PENDING:
                    continue
                if exit_status != 0:
                    raise _lifecycle_error("resolver child 退出状态不是 0。")
                break

            close_kernel = self._ledger.claim_result_pipe_close(self)
            while True:
                wait_slice = self._ledger.business_wait_slice(
                    self,
                    HELPER_PHASE_RESULT_CLOSE,
                )
                self._ledger.begin_result_pipe_close_poll(self)
                close_result = close_kernel.close_pipes(
                    max_wait_ns=wait_slice.max_wait_ns,
                )
                if close_result is PENDING:
                    self._ledger.mark_result_pipe_close_pending(self)
                elif close_result is COMPLETE:
                    self._ledger.commit_result_pipe_close(self)
                else:
                    raise _lifecycle_error(
                        "resolver helper pipe close 合同无效。"
                    )
                self._ledger.business_wait_slice(
                    self,
                    HELPER_PHASE_RESULT_CLOSE,
                )
                if close_result is COMPLETE:
                    break

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
            return receipt
        except BaseException:
            _cleanup_guard(
                self,
                self._ledger,
                suppress_errors=True,
            )
            raise

    def cleanup(self) -> bool:
        return _cleanup_guard(
            self,
            self._ledger,
            suppress_errors=False,
        )


@runtime_final
class _ReadyPublicationTicket:
    """Launcher-issued identity for one complete resolver lifecycle."""

    __slots__ = (
        "publication_id",
        "lifecycle_id",
        "transport_claim_id",
        "dns_start_id",
        "spawn_request_digest",
        "stop_authority_id",
        "stop_authority_digest",
        "capability_digest",
        "_stop_authority",
        "_issued_stop_authority",
        "_launcher",
        "_reservation_owner",
        "_launch_owner_snapshot",
        "_ledger_snapshot",
    )

    def __init__(
        self,
        *,
        publication_id: UUID,
        lifecycle_id: UUID,
        transport_claim_id: UUID,
        dns_start_id: UUID,
        spawn_request_digest: Digest256,
        stop_authority: object,
        stop_authority_id: UUID,
        stop_authority_digest: Digest256,
        capability_digest: Digest256,
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
            "transport_claim_id",
            require_uuid(transport_claim_id, "transport_claim_id"),
        )
        object.__setattr__(
            self,
            "dns_start_id",
            require_uuid(dns_start_id, "dns_start_id"),
        )
        object.__setattr__(
            self,
            "spawn_request_digest",
            require_digest(spawn_request_digest, "spawn_request_digest"),
        )
        checked_authority_id, checked_authority_digest = (
            _validated_stop_authority(stop_authority)
        )
        if (
            require_uuid(stop_authority_id, "stop_authority_id")
            != checked_authority_id
            or require_digest(
                stop_authority_digest,
                "stop_authority_digest",
            )
            != checked_authority_digest
        ):
            raise _lifecycle_error("resolver helper stop authority binding 无效。")
        object.__setattr__(self, "stop_authority_id", checked_authority_id)
        object.__setattr__(
            self,
            "stop_authority_digest",
            checked_authority_digest,
        )
        object.__setattr__(
            self,
            "capability_digest",
            require_digest(capability_digest, "capability_digest"),
        )
        object.__setattr__(self, "_stop_authority", stop_authority)
        object.__setattr__(self, "_issued_stop_authority", stop_authority)
        object.__setattr__(self, "_launcher", launcher)
        object.__setattr__(self, "_reservation_owner", reservation_owner)
        object.__setattr__(self, "_launch_owner_snapshot", None)
        object.__setattr__(self, "_ledger_snapshot", None)
        _validated_lifecycle_capability_snapshot(self, launcher=launcher)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("READY publication ticket is immutable")


class _ReadyPublicationState:
    __slots__ = (
        "ticket",
        "capability_snapshot",
        "guard",
        "ledger",
        "launch_owner",
        "status",
    )

    def __init__(self, ticket: _ReadyPublicationTicket) -> None:
        self.ticket = ticket
        self.capability_snapshot = _validated_lifecycle_capability_snapshot(
            ticket
        )
        self.guard: PreAttemptResolverGuard | None = None
        self.ledger: _ResolverLifecycleLedger | None = None
        self.launch_owner: object | None = None
        self.status = "reserved"


class _LifecycleRecoveryState(NamedTuple):
    """Strong recovery anchor retained until ledger terminal proof."""

    ticket: _ReadyPublicationTicket
    capability_snapshot: _LifecycleCapabilitySnapshot
    launch_owner: object
    ledger: _ResolverLifecycleLedger


@runtime_final
class ResolverHelperLauncher:
    """Construct-only configuration plus one capability-gated READY path."""

    __slots__ = (
        "_spawner",
        "_spawner_snapshot",
        "_request",
        "_request_snapshot",
        "_publication_lock",
        "_ready_publications",
        "_lifecycle_recovery",
    )

    def __init__(self, spawner: HelperSpawner, *, executable: str) -> None:
        if spawner is None or not callable(getattr(spawner, "spawn", None)):
            raise TypeError("spawner must implement HelperSpawner")
        request = ResolverHelperSpawnRequest(executable=executable)
        snapshot = _capture_spawn_request_snapshot(request, spawner)
        object.__setattr__(self, "_spawner", spawner)
        object.__setattr__(self, "_spawner_snapshot", spawner)
        object.__setattr__(self, "_request", request)
        object.__setattr__(self, "_request_snapshot", snapshot)
        object.__setattr__(self, "_publication_lock", RLock())
        object.__setattr__(self, "_ready_publications", {})
        object.__setattr__(self, "_lifecycle_recovery", {})

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverHelperLauncher is immutable")

    @classmethod
    def production(cls, *, executable: str) -> "ResolverHelperLauncher":
        """Return the explicit fail-closed production placeholder."""

        return cls(FailClosedProductionHelperSpawner(), executable=executable)

    def safe_metadata(self) -> dict[str, object]:
        return self._request.safe_metadata()

    def _validated_spawn_configuration(self) -> _SpawnRequestSnapshot:
        """Reject current launcher aliases that differ from construction."""

        expected = self._request_snapshot
        current = _capture_spawn_request_snapshot(
            self._request,
            self._spawner,
        )
        if (
            type(expected) is not _SpawnRequestSnapshot
            or self._spawner_snapshot is not expected.spawner
            or current.request is not expected.request
            or current.spawner is not expected.spawner
            or current.canonical_metadata != expected.canonical_metadata
            or current.request_digest != expected.request_digest
        ):
            raise _lifecycle_error("resolver helper spawn configuration 已变化。")
        return expected

    def _reserve_lifecycle_capability(
        self,
        *,
        reservation_owner: object,
        stop_authority: object | None = None,
        _authority: object | None = None,
    ) -> _ReadyPublicationTicket:
        """Generate and reserve every role ID before any helper can spawn."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver capability reservation requires coordinator")
        if reservation_owner is None:
            raise TypeError("reservation_owner must be an identity object")
        stop_authority_id, stop_authority_digest = _validated_stop_authority(
            stop_authority
        )
        spawn_snapshot = self._validated_spawn_configuration()
        publication_id = require_uuid(uuid4(), "publication_id")
        lifecycle_id = require_uuid(uuid4(), "lifecycle_id")
        transport_claim_id = require_uuid(uuid4(), "transport_claim_id")
        dns_start_id = require_uuid(uuid4(), "dns_start_id")
        if len(
            {
                publication_id,
                lifecycle_id,
                transport_claim_id,
                dns_start_id,
            }
        ) != 4:
            raise _lifecycle_error("resolver lifecycle capability role id 冲突。")
        capability_digest = _lifecycle_capability_digest(
            publication_id=publication_id,
            lifecycle_id=lifecycle_id,
            transport_claim_id=transport_claim_id,
            dns_start_id=dns_start_id,
            spawn_request_digest=spawn_snapshot.request_digest,
            stop_authority_id=stop_authority_id,
            stop_authority_digest=stop_authority_digest,
        )
        ticket = _ReadyPublicationTicket(
            publication_id=publication_id,
            lifecycle_id=lifecycle_id,
            transport_claim_id=transport_claim_id,
            dns_start_id=dns_start_id,
            spawn_request_digest=spawn_snapshot.request_digest,
            stop_authority=stop_authority,
            stop_authority_id=stop_authority_id,
            stop_authority_digest=stop_authority_digest,
            capability_digest=capability_digest,
            launcher=self,
            reservation_owner=reservation_owner,
            _authority=_READY_PUBLICATION_TICKET_AUTHORITY,
        )
        state = _ReadyPublicationState(ticket)
        with self._publication_lock:
            if publication_id in self._ready_publications:
                raise _lifecycle_error("resolver READY publication id 已使用。")
            self._ready_publications[publication_id] = state
        return ticket

    def _recover_lifecycle_reservation(
        self,
        *,
        reservation_owner: object,
        _authority: object | None = None,
    ) -> bool:
        """Remove only this caller-owned reservation after a lost return."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver capability recovery requires coordinator")
        if reservation_owner is None:
            return False
        with self._publication_lock:
            matches = [
                (publication_id, state)
                for publication_id, state in self._ready_publications.items()
                if type(state.ticket) is _ReadyPublicationTicket
                and state.capability_snapshot.launcher is self
                and state.capability_snapshot.reservation_owner
                is reservation_owner
            ]
            if len(matches) != 1:
                return False
            publication_id, state = matches[0]
            if (
                state.status != "reserved"
                or state.guard is not None
                or state.launch_owner is not None
            ):
                return False
            state.status = "consumed"
            del self._ready_publications[publication_id]
            return True

    def _lifecycle_reservation_is_absent_for_cleanup(
        self,
        *,
        reservation_owner: object,
        _authority: object | None = None,
    ) -> bool:
        """Observe a lost-return reservation as absent without trusting recovery.

        This path is for a coordinator that has not received a READY ticket.
        Every registry entry is validated before absence is accepted because a
        malformed entry could otherwise conceal the exact reservation owner.
        No helper or cleanup action is invoked.
        """

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver capability observation requires coordinator")
        if reservation_owner is None:
            return False
        with self._publication_lock:
            try:
                for publication_id, state in self._ready_publications.items():
                    if (
                        type(publication_id) is not UUID
                        or type(state) is not _ReadyPublicationState
                        or type(state.ticket) is not _ReadyPublicationTicket
                    ):
                        return False
                    snapshot = _validated_lifecycle_capability_snapshot(
                        state.ticket,
                        launcher=self,
                    )
                    if (
                        publication_id != snapshot.publication_id
                        or state.capability_snapshot != snapshot
                        or state.ticket._reservation_owner
                        is not snapshot.reservation_owner
                    ):
                        return False
                    if snapshot.reservation_owner is reservation_owner:
                        return False

                for publication_id, recovery in self._lifecycle_recovery.items():
                    if (
                        type(publication_id) is not UUID
                        or type(recovery) is not _LifecycleRecoveryState
                        or type(recovery.ticket) is not _ReadyPublicationTicket
                        or type(recovery.ledger) is not _ResolverLifecycleLedger
                    ):
                        return False
                    snapshot = _validated_lifecycle_capability_snapshot(
                        recovery.ticket,
                        launcher=self,
                    )
                    if (
                        publication_id != snapshot.publication_id
                        or recovery.capability_snapshot != snapshot
                        or recovery.ticket._reservation_owner
                        is not snapshot.reservation_owner
                        or recovery.ledger._capability is not recovery.ticket
                        or recovery.ledger._capability_snapshot != snapshot
                    ):
                        return False
                    if snapshot.reservation_owner is reservation_owner:
                        return False
            except BaseException:
                return False
            return True

    def _reserved_lifecycle_snapshot_for_owner(
        self,
        ticket: _ReadyPublicationTicket,
        *,
        reservation_owner: object,
        _authority: object | None = None,
    ) -> _LifecycleCapabilitySnapshot:
        """Attest one normal-return ticket against its reserving owner."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver reservation attestation requires coordinator")
        if reservation_owner is None:
            raise TypeError("reservation_owner must be an identity object")
        snapshot = _validated_lifecycle_capability_snapshot(
            ticket,
            launcher=self,
        )
        with self._publication_lock:
            state = self._ready_publications.get(snapshot.publication_id)
            if (
                state is None
                or state.ticket is not ticket
                or state.capability_snapshot != snapshot
                or state.capability_snapshot.reservation_owner
                is not reservation_owner
                or state.status != "reserved"
                or state.guard is not None
                or state.ledger is not None
                or state.launch_owner is not None
            ):
                raise _lifecycle_error(
                    "resolver lifecycle reservation owner 不匹配。"
                )
            return state.capability_snapshot

    def _claim_ready_launch(
        self,
        ticket: _ReadyPublicationTicket,
        *,
        launch_owner: object,
        _authority: object | None = None,
    ) -> _LifecycleCapabilitySnapshot:
        """Atomically claim the only spawn allowed by one capability."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver launch claim requires coordinator")
        if launch_owner is None:
            raise TypeError("launch_owner must be an identity object")
        snapshot = _validated_lifecycle_capability_snapshot(
            ticket,
            launcher=self,
        )
        spawn_snapshot = self._validated_spawn_configuration()
        if snapshot.spawn_request_digest != spawn_snapshot.request_digest:
            raise _lifecycle_error("resolver lifecycle capability request 无效。")
        with self._publication_lock:
            state = self._ready_publications.get(snapshot.publication_id)
            if (
                state is None
                or state.ticket is not ticket
                or state.capability_snapshot != snapshot
                or state.status != "reserved"
                or state.guard is not None
                or state.launch_owner is not None
                or ticket._launch_owner_snapshot is not None
                or ticket._ledger_snapshot is not None
            ):
                raise _lifecycle_error("resolver lifecycle capability 不可启动。")
            object.__setattr__(ticket, "_launch_owner_snapshot", launch_owner)
            state.launch_owner = launch_owner
            state.status = "launching"
        return snapshot

    def _cancel_ready_launch(
        self,
        ticket: _ReadyPublicationTicket,
        *,
        launch_owner: object,
    ) -> None:
        """Consume only this exact in-progress launch after internal failure."""

        with self._publication_lock:
            for publication_id, state in tuple(
                self._ready_publications.items()
            ):
                if (
                    state.ticket is ticket
                    and state.status == "launching"
                    and state.guard is None
                    and state.launch_owner is launch_owner
                ):
                    state.launch_owner = None
                    state.status = "consumed"
                    del self._ready_publications[publication_id]
                    return

    def _register_lifecycle_recovery(
        self,
        ticket: _ReadyPublicationTicket,
        ledger: _ResolverLifecycleLedger,
        *,
        launch_owner: object,
    ) -> None:
        """Anchor the ledger before the first operation that may create a child."""

        snapshot = _validated_lifecycle_capability_snapshot(
            ticket,
            launcher=self,
        )
        with self._publication_lock:
            state = self._ready_publications.get(snapshot.publication_id)
            if (
                state is None
                or state.ticket is not ticket
                or state.capability_snapshot != snapshot
                or state.status != "launching"
                or state.launch_owner is not launch_owner
                or state.guard is not None
                or state.ledger is not None
                or ticket._launch_owner_snapshot is not launch_owner
                or ticket._ledger_snapshot is not None
                or snapshot.publication_id in self._lifecycle_recovery
            ):
                raise _lifecycle_error("resolver lifecycle recovery anchor 无效。")
            ledger.bind_launch_owner(ticket, launch_owner)
            object.__setattr__(ticket, "_ledger_snapshot", ledger)
            state.ledger = ledger
            self._lifecycle_recovery[snapshot.publication_id] = (
                _LifecycleRecoveryState(
                    ticket=ticket,
                    capability_snapshot=snapshot,
                    launch_owner=launch_owner,
                    ledger=ledger,
                )
            )

    def _release_lifecycle_recovery(
        self,
        publication_id: UUID,
        ledger: _ResolverLifecycleLedger,
    ) -> None:
        """Forget an anchor only after its ledger proves terminal cleanup."""

        if (
            type(publication_id) is not UUID
            or type(ledger) is not _ResolverLifecycleLedger
            or not ledger.is_terminal()
        ):
            raise _lifecycle_error(
                "resolver lifecycle recovery 只能在 terminal 后释放。"
            )
        with self._publication_lock:
            recovery = self._lifecycle_recovery.get(publication_id)
            if recovery is not None and recovery.ledger is ledger:
                del self._lifecycle_recovery[publication_id]
            state = self._ready_publications.get(publication_id)
            if state is not None and state.ledger is ledger:
                state.guard = None
                state.ledger = None
                state.launch_owner = None
                state.status = "consumed"
                del self._ready_publications[publication_id]

    def _recover_ready_launch_claim(
        self,
        ticket: _ReadyPublicationTicket,
        *,
        launch_owner: object,
    ) -> bool:
        """Best-effort exact-owner fallback if launch cancellation faults."""

        with self._publication_lock:
            for publication_id, state in tuple(
                self._ready_publications.items()
            ):
                if (
                    state.ticket is ticket
                    and state.capability_snapshot.launcher is self
                    and state.status == "launching"
                    and state.guard is None
                    and state.launch_owner is launch_owner
                ):
                    state.launch_owner = None
                    state.status = "consumed"
                    del self._ready_publications[publication_id]
                    return True
        return False

    def _publish_ready_guard(
        self,
        ticket: _ReadyPublicationTicket,
        guard: PreAttemptResolverGuard,
        *,
        launch_owner: object,
        _authority: object | None = None,
    ) -> None:
        """Publish the exact READY owner as the final pre-return action."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver READY publication requires coordinator")
        snapshot = _validated_lifecycle_capability_snapshot(
            ticket,
            launcher=self,
        )
        spawn_snapshot = self._validated_spawn_configuration()
        if (
            snapshot.spawn_request_digest != spawn_snapshot.request_digest
            or type(guard) is not PreAttemptResolverGuard
            or guard._capability is not ticket
            or guard._ledger._capability is not ticket
            or guard._ledger._capability_snapshot != snapshot
            or guard.lifecycle_id != snapshot.lifecycle_id
            or guard.spawn_request_digest != snapshot.spawn_request_digest
        ):
            raise _lifecycle_error("resolver READY publication proof 无效。")
        guard._ledger.require_exact_ready_guard(guard, ticket)
        with self._publication_lock:
            state = self._ready_publications.get(snapshot.publication_id)
            if (
                state is None
                or state.ticket is not ticket
                or state.capability_snapshot != snapshot
                or state.status != "launching"
                or state.guard is not None
                or state.ledger is not guard._ledger
                or state.launch_owner is not launch_owner
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

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("READY publication consumption requires coordinator")
        if (
            type(ticket) is not _ReadyPublicationTicket
            or ticket._launcher is not self
            or type(guard) is not PreAttemptResolverGuard
            or guard._capability is not ticket
        ):
            return False
        try:
            snapshot = _validated_lifecycle_capability_snapshot(
                ticket,
                launcher=self,
            )
        except (TypeError, ValueError, EndpointPolicyError):
            return False
        with self._publication_lock:
            state = self._ready_publications.get(snapshot.publication_id)
            if (
                state is None
                or state.ticket is not ticket
                or state.capability_snapshot != snapshot
                or state.status != "published"
                or state.guard is not guard
                or state.launch_owner is None
            ):
                return False
            state.guard = None
            state.launch_owner = None
            state.status = "consumed"
            del self._ready_publications[snapshot.publication_id]
            return True

    def _recover_ready_publication_for_cleanup(
        self,
        ticket: _ReadyPublicationTicket,
        *,
        launch_owner: object,
        _authority: object | None = None,
    ) -> bool:
        """Clean an exact launch owner in-place without returning capability."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("READY publication recovery requires coordinator")
        if type(ticket) is not _ReadyPublicationTicket or launch_owner is None:
            return False
        with self._publication_lock:
            matches = [
                recovery
                for recovery in self._lifecycle_recovery.values()
                if recovery.ticket is ticket
                and recovery.capability_snapshot.launcher is self
                and recovery.launch_owner is launch_owner
            ]
            if len(matches) != 1:
                return False
            recovery = matches[0]
            publication_id = recovery.capability_snapshot.publication_id
            ledger = recovery.ledger
        ledger.recover_current_owner_for_cleanup()
        if not ledger.is_terminal():
            return False
        # ``finish_cleanup`` deliberately treats terminal resource proof as
        # stronger than bookkeeping callback success.  Retry that idempotent
        # bookkeeping here so a callback fault cannot retain the strong
        # lifecycle recovery anchor forever.
        self._release_lifecycle_recovery(publication_id, ledger)
        with self._publication_lock:
            recovery_is_gone = publication_id not in self._lifecycle_recovery
            ready_state = self._ready_publications.get(publication_id)
            ready_state_is_gone = (
                ready_state is None or ready_state.ledger is not ledger
            )
        return recovery_is_gone and ready_state_is_gone

    def _ready_publication_is_terminal_for_cleanup(
        self,
        ticket: _ReadyPublicationTicket,
        *,
        reservation_owner: object,
        launch_owner: object,
        ledger: _ResolverLifecycleLedger | None = None,
        capability_snapshot: _LifecycleCapabilitySnapshot | None = None,
        _authority: object | None = None,
    ) -> bool:
        """Observe exact helper terminal state independently from recovery.

        The READY and strong-recovery registries are checked together.  A
        terminal ledger may have survived only because its best-effort
        ``on_terminal`` callback failed; in that case this method may release
        the exact bookkeeping anchors, but it never invokes helper actions.
        Wrong owners, aliases, duplicate identities, or malformed registry
        state all fail closed.
        """

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("READY terminal observation requires coordinator")
        if (
            type(ticket) is not _ReadyPublicationTicket
            or reservation_owner is None
            or launch_owner is None
            or (ledger is not None and type(ledger) is not _ResolverLifecycleLedger)
            or (
                capability_snapshot is not None
                and type(capability_snapshot) is not _LifecycleCapabilitySnapshot
            )
        ):
            return False
        if capability_snapshot is None:
            try:
                snapshot = _validated_lifecycle_capability_snapshot(
                    ticket,
                    launcher=self,
                )
            except BaseException:
                return False
        else:
            snapshot = capability_snapshot
        if (
            snapshot.launcher is not self
            or snapshot.reservation_owner is not reservation_owner
            or ticket._reservation_owner is not reservation_owner
            or ticket._launcher is not self
            or ticket._launch_owner_snapshot not in (None, launch_owner)
        ):
            return False

        ticket_ledger = ticket._ledger_snapshot
        if ticket_ledger is not None and type(ticket_ledger) is not _ResolverLifecycleLedger:
            return False
        if ledger is not None and ticket_ledger is not ledger:
            return False

        if ticket_ledger is not None:
            try:
                with ticket_ledger._lock:
                    if (
                        ticket_ledger._capability is not ticket
                        or ticket_ledger._capability_snapshot != snapshot
                        or ticket_ledger.lifecycle_id != snapshot.lifecycle_id
                        or ticket_ledger._launch_owner_snapshot is not launch_owner
                    ):
                        return False
            except BaseException:
                return False

        selected_ledger: _ResolverLifecycleLedger | None = ticket_ledger
        with self._publication_lock:
            try:
                ready_matches = [
                    (publication_id, state)
                    for publication_id, state in self._ready_publications.items()
                    if publication_id == snapshot.publication_id
                    or getattr(state, "ticket", None) is ticket
                ]
                recovery_matches = [
                    (publication_id, recovery)
                    for publication_id, recovery in self._lifecycle_recovery.items()
                    if publication_id == snapshot.publication_id
                    or getattr(recovery, "ticket", None) is ticket
                ]
            except BaseException:
                return False
            if len(ready_matches) > 1 or len(recovery_matches) > 1:
                return False

            ready_state: _ReadyPublicationState | None = None
            if ready_matches:
                publication_id, candidate = ready_matches[0]
                if (
                    publication_id != snapshot.publication_id
                    or type(candidate) is not _ReadyPublicationState
                    or candidate.ticket is not ticket
                    or candidate.capability_snapshot != snapshot
                    or candidate.capability_snapshot.reservation_owner
                    is not reservation_owner
                ):
                    return False
                ready_state = candidate

            recovery_state: _LifecycleRecoveryState | None = None
            if recovery_matches:
                publication_id, candidate = recovery_matches[0]
                if (
                    publication_id != snapshot.publication_id
                    or type(candidate) is not _LifecycleRecoveryState
                    or candidate.ticket is not ticket
                    or candidate.capability_snapshot != snapshot
                    or candidate.launch_owner is not launch_owner
                    or type(candidate.ledger) is not _ResolverLifecycleLedger
                    or ticket._ledger_snapshot is not candidate.ledger
                    or candidate.ledger._capability is not ticket
                    or candidate.ledger._capability_snapshot != snapshot
                    or candidate.ledger._launch_owner_snapshot is not launch_owner
                ):
                    return False
                recovery_state = candidate
                selected_ledger = candidate.ledger

            if ready_state is not None:
                if ready_state.status == "reserved":
                    if (
                        ready_state.guard is not None
                        or ready_state.ledger is not None
                        or ready_state.launch_owner is not None
                        or ticket._launch_owner_snapshot is not None
                        or ticket._ledger_snapshot is not None
                    ):
                        return False
                    return False
                if ready_state.status not in ("launching", "published"):
                    return False
                if ready_state.launch_owner is not launch_owner:
                    return False
                if ready_state.ledger is None:
                    if recovery_state is not None:
                        return False
                    return False
                if (
                    type(ready_state.ledger) is not _ResolverLifecycleLedger
                    or ticket._ledger_snapshot is not ready_state.ledger
                    or recovery_state is None
                    or recovery_state.ledger is not ready_state.ledger
                ):
                    return False
                selected_ledger = ready_state.ledger
                if ready_state.status == "launching":
                    if ready_state.guard is not None:
                        return False
                elif (
                    type(ready_state.guard) is not PreAttemptResolverGuard
                    or ready_state.guard._ledger is not selected_ledger
                    or ready_state.guard._capability is not ticket
                ):
                    return False

            if ledger is not None:
                if selected_ledger is None:
                    selected_ledger = ledger
                elif selected_ledger is not ledger:
                    return False

        if selected_ledger is None:
            # A validated exact ticket with neither a READY entry nor a strong
            # recovery anchor represents a consumed no-helper or terminal
            # lifecycle.  Wrong-owner tickets were rejected above.
            return True
        try:
            if not selected_ledger.is_terminal():
                return False
            self._release_lifecycle_recovery(
                snapshot.publication_id,
                selected_ledger,
            )
        except BaseException:
            return False

        # Prove the exact anchors are now absent.  Do not trust the release
        # helper's successful return as the terminal observation.
        with self._publication_lock:
            try:
                ready_matches = [
                    state
                    for publication_id, state in self._ready_publications.items()
                    if publication_id == snapshot.publication_id
                    or getattr(state, "ticket", None) is ticket
                ]
                recovery_matches = [
                    recovery
                    for publication_id, recovery in self._lifecycle_recovery.items()
                    if publication_id == snapshot.publication_id
                    or getattr(recovery, "ticket", None) is ticket
                ]
            except BaseException:
                return False
            return not ready_matches and not recovery_matches

    def _accepted_ready_guard_ledger(
        self,
        ticket: _ReadyPublicationTicket,
        guard: PreAttemptResolverGuard,
        *,
        launch_owner: object,
        _authority: object | None = None,
    ) -> _ResolverLifecycleLedger:
        """Attest consumed READY ownership without returning a new guard."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("READY guard attestation requires coordinator")
        if (
            type(ticket) is not _ReadyPublicationTicket
            or type(guard) is not PreAttemptResolverGuard
            or launch_owner is None
        ):
            raise _lifecycle_error("resolver READY guard 类型无效。")
        snapshot = _validated_lifecycle_capability_snapshot(
            ticket,
            launcher=self,
        )
        with self._publication_lock:
            recovery = self._lifecycle_recovery.get(snapshot.publication_id)
            if (
                snapshot.publication_id in self._ready_publications
                or recovery is None
                or recovery.ticket is not ticket
                or recovery.capability_snapshot != snapshot
                or recovery.launch_owner is not launch_owner
            ):
                raise _lifecycle_error(
                    "resolver READY publication 未提交消费。"
                )
            ledger = recovery.ledger
        ledger.require_exact_ready_guard(guard, ticket)
        return ledger

    def _launch_ready(
        self,
        *,
        capability: _ReadyPublicationTicket,
        launch_owner: object | None = None,
        _authority: object | None = None,
    ) -> PreAttemptResolverGuard:
        """Spawn with fixed metadata, then accept only the fixed READY frame."""

        if _authority is not _RESOLVER_LIFECYCLE_AUTHORITY:
            raise TypeError("resolver launch requires coordinator")
        if launch_owner is None:
            launch_owner = object()
        guard: PreAttemptResolverGuard | None = None
        try:
            snapshot = self._claim_ready_launch(
                capability,
                launch_owner=launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            publication_id = snapshot.publication_id
            ledger = _ResolverLifecycleLedger(
                capability,
                on_terminal=lambda selected: self._release_lifecycle_recovery(
                    publication_id,
                    selected,
                ),
            )
            guard = PreAttemptResolverGuard(
                lifecycle_id=snapshot.lifecycle_id,
                spawn_request_digest=snapshot.spawn_request_digest,
                ledger=ledger,
                capability=capability,
                _authority=_PRE_GUARD_FACTORY_AUTHORITY,
            )
            ledger.bind_pre_owner(guard)
            self._register_lifecycle_recovery(
                capability,
                ledger,
                launch_owner=launch_owner,
            )
            spawn_snapshot = self._validated_spawn_configuration()
            publication = _KernelPublication(
                ledger=ledger,
                owner=guard,
                _authority=_KERNEL_PUBLICATION_AUTHORITY,
            )
            while True:
                wait_slice = ledger.business_wait_slice(
                    guard,
                    HELPER_PHASE_SPAWN,
                )
                kernel = spawn_snapshot.spawner.spawn(
                    spawn_snapshot.request,
                    publication=publication,
                    max_wait_ns=wait_slice.max_wait_ns,
                )
                if kernel is not PENDING:
                    publication.confirm_returned(kernel)
                ledger.business_wait_slice(guard, HELPER_PHASE_SPAWN)
                if kernel is not PENDING:
                    break
            frame = _read_bounded_frame(
                kernel,
                ledger=ledger,
                owner=guard,
                phase=HELPER_PHASE_READY,
                maximum=MAX_READY_FRAME_BYTES,
                label="READY",
            )
            if frame != READY_FRAME:
                raise _lifecycle_error("resolver helper READY frame 无效。")
            ledger.mark_ready(guard)
            ledger.business_wait_slice(guard, HELPER_PHASE_READY)
            self._publish_ready_guard(
                capability,
                guard,
                launch_owner=launch_owner,
                _authority=_RESOLVER_LIFECYCLE_AUTHORITY,
            )
            ledger.business_wait_slice(guard, HELPER_PHASE_READY)
            return guard
        except BaseException:
            try:
                self._cancel_ready_launch(
                    capability,
                    launch_owner=launch_owner,
                )
            except BaseException:
                try:
                    self._recover_ready_launch_claim(
                        capability,
                        launch_owner=launch_owner,
                    )
                except BaseException:
                    pass
            if guard is not None:
                _cleanup_guard(
                    guard,
                    guard._ledger,
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
