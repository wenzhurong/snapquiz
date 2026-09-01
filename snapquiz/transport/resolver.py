"""Offline contracts for the W09-B2 resolver-helper lifecycle.

This module deliberately contains no process implementation.  A helper can
only be reached through injected ``HelperSpawner``/``HelperKernel`` objects;
that injection point is a trusted test seam, not a production authorization
boundary.  A future coordinator must prove the matching AttemptGate claim and
DNS-start commit before calling ``transfer``/``start``.  The production
placeholder fails closed until that coordinator and an independently
executable, ``posix_spawn`` based adapter are implemented and validated.
Importing and constructing the contracts performs no process, DNS, file,
environment, or socket I/O.
"""
from __future__ import annotations

import re
from threading import RLock
from typing import Callable, Protocol
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


RESOLVER_HELPER_PROTOCOL_VERSION = "snapquiz.resolver-helper.v1"
RESOLVER_HELPER_START_SCHEMA_VERSION = "snapquiz.resolver-start.v1"
RESOLVER_TERMINAL_GUARD_SCHEMA_VERSION = "snapquiz.resolver-terminal-guard.v1"
READY_FRAME = b"SNAPQUIZ-RESOLVER/1 READY\n"
MAX_READY_FRAME_BYTES = 64
MAX_START_FRAME_BYTES = 4_096
MAX_RESULT_FRAME_BYTES = 16_384
MAX_RESULT_CANDIDATES = 32
MAX_HELPER_STDERR_BYTES = 4_096

_PRE_GUARD_FACTORY_AUTHORITY = object()
_ATTEMPT_GUARD_FACTORY_AUTHORITY = object()
_TERMINAL_GUARD_UUID_NAMESPACE = UUID(
    "4c82487b-3247-52f0-9fb9-7696da7f7471"
)
_DNS_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)

LifecycleObserver = Callable[[str, dict[str, object]], None]


class HelperKernel(Protocol):
    """The smallest injectable owner of one already-created helper."""

    def read_stdout(self, max_bytes: int) -> bytes:
        """Read at most ``max_bytes`` bytes from the helper stdout pipe."""

    def write_stdin(self, frame: bytes) -> None:
        """Write one complete, already-bounded protocol frame."""

    def terminate(self) -> None:
        """Best-effort stop of the helper, whether it is alive or exited."""

    def reap(self) -> None:
        """Reap the helper exactly once."""

    def close_pipes(self) -> None:
        """Close every helper-owned parent-side pipe exactly once."""


class HelperSpawner(Protocol):
    """Injectable process boundary used only by ``launch_ready``."""

    def spawn(self, request: "ResolverHelperSpawnRequest") -> HelperKernel:
        """Create one helper without receiving target or credential data."""


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
            ("argv", (checked, "--snapquiz-resolver-helper-v1")),
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
        "_owner",
        "_kernel",
        "_state",
        "_cleanup_claimed",
    )

    def __init__(self, lifecycle_id: UUID) -> None:
        self.lifecycle_id = require_uuid(lifecycle_id, "lifecycle_id")
        self._lock = RLock()
        self._owner: object | None = None
        self._kernel: HelperKernel | None = None
        self._state = "created"
        self._cleanup_claimed = False

    def bind_pre_owner(self, owner: object) -> None:
        with self._lock:
            if self._owner is not None or self._state != "created":
                raise _lifecycle_error("resolver helper owner 已绑定。")
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

    def commit_start(self, owner: object) -> None:
        self._cas(
            owner,
            expected="transferred",
            replacement=owner,
            target="start_committed",
        )

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

    def mark_result_read(self, owner: object) -> None:
        self._cas(
            owner,
            expected="result_reading",
            replacement=owner,
            target="result_read",
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

    def claim_cleanup(self, owner: object) -> tuple[HelperKernel | None, bool]:
        with self._lock:
            if self._state == "terminal":
                return None, False
            if self._owner is not owner:
                raise _lifecycle_error("resolver helper cleanup owner 不匹配。")
            if self._state == "cleanup_failed":
                raise _lifecycle_error("resolver helper cleanup 尚未证明完成。")
            if self._cleanup_claimed:
                return None, False
            self._cleanup_claimed = True
            self._state = "cleaning"
            return self._kernel, True

    def finish_cleanup(self, owner: object) -> None:
        with self._lock:
            if self._owner is not owner or self._state != "cleaning":
                raise _lifecycle_error("resolver helper cleanup 状态已经变化。")
            self._kernel = None
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

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "protocol_version": RESOLVER_HELPER_PROTOCOL_VERSION,
                "lifecycle_id": str(self.lifecycle_id),
                "state": self._state,
                "cleanup_claimed": self._cleanup_claimed,
            }


def _cleanup_guard(
    guard: object,
    ledger: _ResolverLifecycleLedger,
    *,
    observer: LifecycleObserver | None,
    suppress_errors: bool,
) -> bool:
    try:
        kernel, claimed = ledger.claim_cleanup(guard)
    except BaseException:
        if suppress_errors:
            return False
        raise
    if not claimed:
        return False

    observer_error: BaseException | None = None
    try:
        _notify(observer, "cleanup_committed", ledger.safe_metadata())
    except BaseException as error:
        observer_error = error

    cleanup_failed = False
    if kernel is not None:
        for action_name in ("terminate", "reap", "close_pipes"):
            try:
                action = getattr(kernel, action_name)
                action()
            except BaseException:
                cleanup_failed = True
    try:
        if cleanup_failed:
            ledger.mark_cleanup_failed(guard)
        else:
            ledger.finish_cleanup(guard)
    except BaseException:
        cleanup_failed = True

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
            self._ledger.commit_start(self)
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

    def read_result_frame(
        self,
        *,
        observer: LifecycleObserver | None = None,
    ) -> bytes:
        """Read the helper's one bounded result frame, excluding newline."""

        try:
            self._ledger.commit_result_read(self)
            kernel = self._ledger.kernel_for(self, states=("result_reading",))
            frame = _read_bounded_frame(
                kernel,
                maximum=MAX_RESULT_FRAME_BYTES,
                label="RESULT",
            )
            self._ledger.mark_result_read(self)
            _notify(observer, "result_read", self.safe_metadata())
            return frame[:-1]
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
class ResolverHelperLauncher:
    """Construct-only configuration plus one explicit spawn/READY method."""

    __slots__ = ("_spawner", "_request")

    def __init__(self, spawner: HelperSpawner, *, executable: str) -> None:
        if spawner is None or not callable(getattr(spawner, "spawn", None)):
            raise TypeError("spawner must implement HelperSpawner")
        object.__setattr__(self, "_spawner", spawner)
        object.__setattr__(
            self,
            "_request",
            ResolverHelperSpawnRequest(executable=executable),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverHelperLauncher is immutable")

    @classmethod
    def production(cls, *, executable: str) -> "ResolverHelperLauncher":
        """Return the explicit fail-closed production placeholder."""

        return cls(FailClosedProductionHelperSpawner(), executable=executable)

    def safe_metadata(self) -> dict[str, object]:
        return self._request.safe_metadata()

    def launch_ready(
        self,
        *,
        lifecycle_id: UUID,
        observer: LifecycleObserver | None = None,
    ) -> PreAttemptResolverGuard:
        """Spawn with fixed metadata, then accept only the fixed READY frame."""

        require_uuid(lifecycle_id, "lifecycle_id")
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
            return guard
        except BaseException:
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
