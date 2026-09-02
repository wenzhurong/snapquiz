"""One-shot credential handles and frozen-binding resolution for W09-B1.

This module is intentionally the only dependency direction between the two
layers: credentials depend on :mod:`snapquiz.runtime.attempt`; the AttemptGate
stores only primitive handle proof and never imports this module.  Importing or
constructing any object here performs no credential read and no I/O.
"""
from __future__ import annotations

import re
from threading import RLock
from typing import Callable, Protocol, TypeVar
from uuid import UUID, uuid4, uuid5

from snapquiz.config.profiles import (
    BUILTIN_REGISTRY_REVISION,
    GLM_BINDING_ID,
    GLM_CHAT_COMPLETIONS_ENDPOINT,
    GLM_CREDENTIAL_BINDING_REF,
    GLM_CREDENTIAL_REF,
    GLM_ENDPOINT_POLICY_VERSION,
    GLM_NETWORK_POLICY_VERSION,
    GLM_PROVIDER_ID,
    GLM_PROVIDER_PROFILE_ID,
    GLM_TLS_POLICY_REF,
    builtin_registry_digest,
)
from snapquiz.domain._validation import (
    require_digest,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.capabilities import (
    CredentialBindingMetadata,
    CredentialValueScheme,
    ProviderProfileSnapshot,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import (
    CancelledError,
    ConfigError,
    EndpointPolicyError,
    TimeoutError,
)
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.domain.plan import (
    CredentialInjectionSlot,
    ExecutionPlanNetworkOperation,
    ExecutionPlanStage,
)
from snapquiz.pipelines.contracts import StageInvocation
from snapquiz.routing.planner import PlannedExecution
from snapquiz.runtime.attempt import (
    AttemptGate,
    AttemptPermit,
    CredentialResolutionPermit,
    _CREDENTIAL_RESOLVER_AUTHORITY,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.transport.session import AuthorizedSendSession


CREDENTIAL_HANDLE_SCHEMA_VERSION = "snapquiz.credential-handle.v1"
CREDENTIAL_RESOLVER_POLICY_VERSION = "snapquiz.credential-resolver.glm-bearer.v1"
MAX_CREDENTIAL_BYTES = 4_096

_HANDLE_FACTORY_AUTHORITY = object()
_TRANSPORT_CREDENTIAL_AUTHORITY = object()
_HANDLE_UUID_NAMESPACE = UUID("fa0f299f-b9b2-5c38-81dc-d7bc12c735bb")
_B64TOKEN_RE = re.compile(rb"[A-Za-z0-9\-._~+/]+={0,}\Z")
_ResultT = TypeVar("_ResultT")


class CredentialSource(Protocol):
    """An exact-locator backend.

    Production implementations are deliberately outside W09-B1.  Tests use a
    fake that returns a fresh mutable buffer so this boundary can relinquish
    and best-effort zero its source copy immediately.
    """

    def read_exact(self, credential_ref: str) -> bytearray:
        """Read exactly ``credential_ref`` once and return a mutable buffer."""


def _credential_error() -> ConfigError:
    return ConfigError(
        stage="credential_resolver",
        retryable=False,
        safe_message="凭据配置无效。",
    )


def _credential_policy_error() -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="credential_resolver",
        retryable=False,
        safe_message="冻结的凭据绑定未通过安全策略。",
    )


def _raise_credential_error() -> None:
    """Raise outside a source exception handler with no retained raw chain."""

    error = _credential_error()
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _raise_credential_policy_error() -> None:
    error = _credential_policy_error()
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _raise_resolver_primary(
    primary: BaseException,
    primary_traceback: object | None,
) -> None:
    if isinstance(
        primary,
        (CancelledError, ConfigError, EndpointPolicyError, TimeoutError),
    ):
        # The new public traceback contains this helper and its caller.  Do not
        # let either frame retain the source traceback through a local variable.
        primary_traceback = None
        primary.__traceback__ = None
        primary.__cause__ = None
        primary.__context__ = None
        primary.__suppress_context__ = True
        raise primary from None
    raise primary.with_traceback(primary_traceback)  # type: ignore[arg-type]


def _best_effort_zero(buffer: object | None) -> None:
    """Overwrite without resizing first, then release storage when possible."""

    if not isinstance(buffer, bytearray):
        return
    try:
        for index in range(len(buffer)):
            buffer[index] = 0
    except BaseException:
        pass
    try:
        buffer.clear()
    except BaseException:
        # A retained memoryview can prevent resizing.  The bytes above are
        # still zero, and the ledger drops its reference below.
        pass


def _handle_identifier(
    *,
    slot_id: UUID,
    credential_permit_id: UUID,
    credential_permit_digest: Digest256,
) -> UUID:
    return uuid5(
        _HANDLE_UUID_NAMESPACE,
        str(
            digest256(
                "CredentialHandleIdentifier",
                CREDENTIAL_HANDLE_SCHEMA_VERSION,
                {
                    "slot_id": slot_id,
                    "credential_permit_id": credential_permit_id,
                    "credential_permit_digest": credential_permit_digest,
                },
            )
        ),
    )


def _handle_payload(handle: "CredentialHandle") -> dict[str, object]:
    return {
        "handle_id": handle.handle_id,
        "credential_permit_id": handle.credential_permit_id,
        "credential_permit_digest": handle.credential_permit_digest,
        "context_id": handle.context_id,
        "context_digest": handle.context_digest,
        "session_id": handle.session_id,
        "session_terms_digest": handle.session_terms_digest,
        "operation_id": handle.operation_id,
        "request_envelope_digest": handle.request_envelope_digest,
        "credential_binding_digest": handle.credential_binding_digest,
        "credential_injection_slot": handle.credential_injection_slot.value,
        "credential_value_scheme": handle.credential_value_scheme.value,
    }


@runtime_final
class CredentialHandle:
    """Factory-only public proof for one private, mutable credential buffer."""

    __slots__ = (
        "handle_id",
        "handle_digest",
        "credential_permit_id",
        "credential_permit_digest",
        "context_id",
        "context_digest",
        "session_id",
        "session_terms_digest",
        "operation_id",
        "request_envelope_digest",
        "credential_binding_digest",
        "credential_injection_slot",
        "credential_value_scheme",
        "_slot_id",
        "_issued_digest",
        "_ledger",
    )

    def __init__(
        self,
        *,
        slot_id: UUID,
        permit: CredentialResolutionPermit,
        operation_id: UUID,
        credential_injection_slot: CredentialInjectionSlot,
        credential_value_scheme: CredentialValueScheme,
        ledger: "_CredentialLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _HANDLE_FACTORY_AUTHORITY:
            raise TypeError("credential handles require CredentialResolver")
        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
        if type(ledger) is not _CredentialLedger:
            raise TypeError("ledger must be the private credential ledger")
        require_uuid(slot_id, "slot_id")
        require_uuid(operation_id, "operation_id")
        if type(credential_injection_slot) is not CredentialInjectionSlot:
            raise ValueError("invalid credential injection slot")
        if type(credential_value_scheme) is not CredentialValueScheme:
            raise ValueError("invalid credential value scheme")

        handle_id = _handle_identifier(
            slot_id=slot_id,
            credential_permit_id=permit.permit_id,
            credential_permit_digest=permit.permit_digest,
        )
        values = (
            ("handle_id", handle_id),
            ("credential_permit_id", permit.permit_id),
            ("credential_permit_digest", permit.permit_digest),
            ("context_id", permit.context_id),
            ("context_digest", permit.context_digest),
            ("session_id", permit.session_id),
            ("session_terms_digest", permit.session_terms_digest),
            ("operation_id", operation_id),
            ("request_envelope_digest", permit.request_envelope_digest),
            ("credential_binding_digest", permit.credential_binding_digest),
            ("credential_injection_slot", credential_injection_slot),
            ("credential_value_scheme", credential_value_scheme),
            ("_slot_id", slot_id),
            ("_ledger", ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        handle_digest = digest256(
            "CredentialHandle",
            CREDENTIAL_HANDLE_SCHEMA_VERSION,
            _handle_payload(self),
        )
        object.__setattr__(self, "handle_digest", handle_digest)
        object.__setattr__(self, "_issued_digest", handle_digest)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CredentialHandle is immutable")

    def __copy__(self) -> "CredentialHandle":
        raise TypeError("CredentialHandle cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> "CredentialHandle":
        del memo
        raise TypeError("CredentialHandle cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("CredentialHandle cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("CredentialHandle cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("CredentialHandle cannot be serialized")

    def __repr__(self) -> str:
        return (
            "CredentialHandle("
            f"handle_id={self.handle_id!r}, "
            f"credential_permit_id={self.credential_permit_id!r}, "
            f"context_id={self.context_id!r}, session_id={self.session_id!r}, "
            f"operation_id={self.operation_id!r}, closed={self.is_closed!r})"
        )

    @property
    def is_closed(self) -> bool:
        ledger = self._ledger
        if type(ledger) is not _CredentialLedger:
            return True
        return ledger._is_closed(self)

    def recompute_digest(self) -> Digest256:
        return digest256(
            "CredentialHandle",
            CREDENTIAL_HANDLE_SCHEMA_VERSION,
            _handle_payload(self),
        )

    def validate_integrity(self) -> None:
        for name in (
            "handle_id",
            "credential_permit_id",
            "context_id",
            "session_id",
            "operation_id",
            "_slot_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "handle_digest",
            "credential_permit_digest",
            "context_digest",
            "session_terms_digest",
            "request_envelope_digest",
            "credential_binding_digest",
            "_issued_digest",
        ):
            require_digest(getattr(self, name), name)
        if type(self.credential_injection_slot) is not CredentialInjectionSlot:
            raise ValueError("credential handle slot changed")
        if type(self.credential_value_scheme) is not CredentialValueScheme:
            raise ValueError("credential handle scheme changed")
        if type(self._ledger) is not _CredentialLedger:
            raise ValueError("credential handle ledger changed")
        if self.handle_id != _handle_identifier(
            slot_id=self._slot_id,
            credential_permit_id=self.credential_permit_id,
            credential_permit_digest=self.credential_permit_digest,
        ):
            raise ValueError("credential handle identifier changed")
        recomputed = self.recompute_digest()
        if recomputed != self.handle_digest or recomputed != self._issued_digest:
            raise ValueError("credential handle integrity mismatch")

    def safe_metadata(self) -> dict[str, object]:
        return {
            "handle_id": str(self.handle_id),
            "handle_digest_prefix": str(self.handle_digest)[:12],
            "credential_permit_id": str(self.credential_permit_id),
            "context_id": str(self.context_id),
            "session_id": str(self.session_id),
            "operation_id": str(self.operation_id),
            "credential_binding_digest_prefix": str(
                self.credential_binding_digest
            )[:12],
            "credential_injection_slot": self.credential_injection_slot.value,
            "credential_value_scheme": self.credential_value_scheme.value,
            "closed": self.is_closed,
        }


class _HandleState:
    __slots__ = (
        "handle",
        "handle_id",
        "handle_digest",
        "publication_id",
        "publication_id_snapshot",
        "permit",
        "permit_id_snapshot",
        "permit_digest_snapshot",
        "gate",
        "gate_id_snapshot",
        "secret",
        "status",
    )

    def __init__(
        self,
        *,
        handle: CredentialHandle,
        publication_id: UUID,
        permit: CredentialResolutionPermit,
        gate: AttemptGate,
        secret: bytearray,
    ) -> None:
        self.handle = handle
        self.handle_id = handle.handle_id
        self.handle_digest = handle.handle_digest
        self.publication_id = require_uuid(
            publication_id,
            "publication_id",
        )
        self.publication_id_snapshot = self.publication_id
        self.permit: CredentialResolutionPermit | None = permit
        self.permit_id_snapshot = permit.permit_id
        self.permit_digest_snapshot = permit.permit_digest
        self.gate: AttemptGate | None = gate
        self.gate_id_snapshot = permit.gate_id
        self.secret: bytearray | None = secret
        # This state is caller-unobservable until AttemptGate confirmation
        # returns and resolve() returns the handle.  Confirmation is the sole
        # publication linearization point, so no fallible ledger activation is
        # allowed after it.
        self.status = "active"


class _CredentialLedger:
    __slots__ = ("_states", "_lock")

    def __init__(self) -> None:
        self._states: dict[CredentialHandle, _HandleState] = {}
        self._lock = RLock()

    def _issue(
        self,
        *,
        publication_id: UUID,
        permit: CredentialResolutionPermit,
        operation_id: UUID,
        credential_injection_slot: CredentialInjectionSlot,
        credential_value_scheme: CredentialValueScheme,
        secret: bytearray,
    ) -> CredentialHandle:
        if type(secret) is not bytearray:
            raise TypeError("secret must be a private bytearray")
        handle: CredentialHandle | None = None
        try:
            slot_id = uuid4()
            handle = CredentialHandle(
                slot_id=slot_id,
                permit=permit,
                operation_id=operation_id,
                credential_injection_slot=credential_injection_slot,
                credential_value_scheme=credential_value_scheme,
                ledger=self,
                _authority=_HANDLE_FACTORY_AUTHORITY,
            )
            state = _HandleState(
                handle=handle,
                publication_id=publication_id,
                permit=permit,
                gate=permit._attempt_gate,
                secret=secret,
            )
            with self._lock:
                if handle in self._states:
                    raise RuntimeError("credential handle collision")
                self._states[handle] = state
            return handle
        except BaseException:
            if handle is not None:
                with self._lock:
                    self._states.pop(handle, None)
            _best_effort_zero(secret)
            raise

    def _lookup_exact_locked(
        self,
        handle: CredentialHandle,
    ) -> _HandleState:
        if type(handle) is not CredentialHandle:
            raise TypeError("handle must be CredentialHandle")
        state = self._states.get(handle)
        if state is None:
            raise _credential_policy_error()
        return state

    @staticmethod
    def _integrity_is_valid(
        handle: CredentialHandle,
        state: _HandleState,
    ) -> bool:
        try:
            handle.validate_integrity()
            return (
                state.handle is handle
                and handle.handle_id == state.handle_id
                and handle.handle_digest == state.handle_digest
            )
        except (TypeError, ValueError, AttributeError):
            return False

    def _is_closed(self, handle: CredentialHandle) -> bool:
        with self._lock:
            state = self._states.get(handle)
            if state is None:
                return True
            if not self._integrity_is_valid(handle, state):
                return True
            return state.status == "closed"

    def _recover_active_for_permit(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
    ) -> CredentialHandle | None:
        """Return one unique handle for an exact permit/publication pair."""

        if type(publication_id) is not UUID:
            return None

        with self._lock:
            matches: list[CredentialHandle] = []
            for state in self._states.values():
                handle = state.handle
                if (
                    state.status != "active"
                    or state.publication_id != publication_id
                    or state.permit is not permit
                    or state.gate is not permit._attempt_gate
                    or type(state.secret) is not bytearray
                    or type(handle) is not CredentialHandle
                    or handle.credential_permit_id != permit.permit_id
                    or handle.credential_permit_digest != permit.permit_digest
                    or not self._integrity_is_valid(handle, state)
                ):
                    continue
                matches.append(handle)
                if len(matches) > 1:
                    return None
            return matches[0] if len(matches) == 1 else None

    def _recover_active_state_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        gate: AttemptGate | None = None,
    ) -> tuple[CredentialHandle, _HandleState] | None:
        """Find one active publication using only ledger-owned handle proof.

        Cleanup must remain possible when the returned handle's public slots
        were changed after publication.  The state snapshots the proof that
        was confirmed by AttemptGate, so this lookup deliberately does not
        consult or validate any public handle field.
        """

        if type(publication_id) is not UUID or (
            gate is not None and type(gate) is not AttemptGate
        ):
            return None

        with self._lock:
            matches: list[tuple[CredentialHandle, _HandleState]] = []
            for handle, state in self._states.items():
                if (
                    state.status != "active"
                    or state.handle is not handle
                    or state.publication_id != publication_id
                    or state.permit is not permit
                    or type(state.gate) is not AttemptGate
                    or (gate is not None and state.gate is not gate)
                    or type(state.handle_id) is not UUID
                    or type(state.handle_digest) is not Digest256
                    or type(state.secret) is not bytearray
                    or type(handle) is not CredentialHandle
                ):
                    continue
                matches.append((handle, state))
                if len(matches) > 1:
                    return None
            return matches[0] if len(matches) == 1 else None

    def _cleanup_state_is_closed(
        self,
        handle: CredentialHandle,
        state: _HandleState,
    ) -> bool:
        """Confirm cleanup without trusting a possibly changed handle."""

        with self._lock:
            current = self._states.get(handle)
            return (
                current is state
                and current.handle is handle
                and current.status == "closed"
                and current.secret is None
                and current.permit is None
                and current.gate is None
                and current.publication_id is None
            )

    def _publication_is_closed_for_cleanup(
        self,
        publication_id: UUID,
    ) -> bool:
        """Observe one exact terminal publication from immutable state."""

        if type(publication_id) is not UUID:
            return False
        with self._lock:
            matches = [
                (handle, state)
                for handle, state in self._states.items()
                if state.publication_id_snapshot == publication_id
                and state.handle is handle
            ]
            if len(matches) != 1:
                return False
            handle, state = matches[0]
            return (
                state.status == "closed"
                and state.secret is None
                and state.permit is None
                and state.gate is None
                and state.publication_id is None
                and state.handle is handle
            )

    def _publication_terminal_state_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
    ) -> str:
        """Classify one exact publication without trusting live handle slots.

        ``absent`` is reserved for a publication ID that was never anchored in
        this resolver ledger.  ``closed`` requires one and only one ledger
        entry whose frozen primitive permit/Gate proof matches and whose live
        secret and ownership references have all been cleared.  Every active,
        duplicate, malformed, or wrong-owner state is deliberately collapsed
        to ``ambiguous`` so a cleanup caller must fail closed.
        """

        if (
            type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
        ):
            return "ambiguous"
        try:
            permit.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            return "ambiguous"

        with self._lock:
            matches = [
                (handle, state)
                for handle, state in self._states.items()
                if getattr(state, "publication_id_snapshot", None)
                == publication_id
            ]
            if not matches:
                return "absent"
            if len(matches) != 1:
                return "ambiguous"
            handle, state = matches[0]
            if (
                type(state) is not _HandleState
                or type(handle) is not CredentialHandle
                or state.handle is not handle
                or state.permit_id_snapshot != permit.permit_id
                or state.permit_digest_snapshot != permit.permit_digest
                or state.gate_id_snapshot != permit.gate_id
                or type(state.handle_id) is not UUID
                or type(state.handle_digest) is not Digest256
            ):
                return "ambiguous"
            if (
                state.status == "closed"
                and state.secret is None
                and state.permit is None
                and state.gate is None
                and state.publication_id is None
            ):
                return "closed"
            return "ambiguous"

    def _release_info(
        self,
        handle: CredentialHandle,
    ) -> tuple[
        _HandleState,
        CredentialResolutionPermit | None,
        AttemptGate | None,
        bool,
    ]:
        with self._lock:
            state = self._lookup_exact_locked(handle)
            integrity_is_valid = self._integrity_is_valid(handle, state)
            if getattr(state, "status", None) == "borrowing":
                raise _credential_policy_error()
            if getattr(state, "status", None) == "closed":
                return state, None, None, integrity_is_valid
            if getattr(state, "status", None) == "closing":
                raise _credential_policy_error()
            if (
                type(getattr(state, "permit", None))
                is not CredentialResolutionPermit
                or type(getattr(state, "gate", None)) is not AttemptGate
            ):
                raise _credential_policy_error()
            state.status = "closing"
            return state, state.permit, state.gate, integrity_is_valid

    def _restore_active_after_gate_failure(
        self,
        handle: CredentialHandle,
        state: _HandleState,
    ) -> None:
        with self._lock:
            current = self._states.get(handle)
            if current is state and current.status == "closing":
                current.status = "active"

    def _close_after_gate(
        self,
        handle: CredentialHandle,
        state: _HandleState,
    ) -> bool:
        secret: bytearray | None = None
        with self._lock:
            current = self._states.get(handle)
            if current is not state:
                return False
            if current.status == "closed":
                return False
            if current.status == "borrowing":
                raise _credential_policy_error()
            secret = current.secret
            current.secret = None
            current.permit = None
            current.gate = None
            current.publication_id = None
            current.status = "closed"
        _best_effort_zero(secret)
        return True

    def _force_close_after_gate(
        self,
        handle: CredentialHandle,
        state: _HandleState,
    ) -> bool:
        """Non-throwing fallback after Gate terminalization is irreversible."""

        secret: object | None = None
        changed = False
        try:
            with self._lock:
                current = self._states.get(handle)
                if current is state:
                    changed = getattr(current, "status", None) != "closed"
                    secret = getattr(current, "secret", None)
                    current.secret = None
                    current.permit = None
                    current.gate = None
                    current.publication_id = None
                    current.status = "closed"
        except BaseException:
            # The Gate can no longer reserve or send.  Even if an injected
            # ledger fault prevents the normal locked transition, detach and
            # zero the exact state's buffer without allowing Gate revival.
            try:
                secret = getattr(state, "secret", secret)
            except BaseException:
                pass
            for name, value in (
                ("secret", None),
                ("permit", None),
                ("gate", None),
                ("publication_id", None),
                ("status", "closed"),
            ):
                try:
                    setattr(state, name, value)
                except BaseException:
                    pass
        try:
            _best_effort_zero(secret)
        except BaseException:
            pass
        return changed

    def _discard_unpublished(self, handle: CredentialHandle) -> None:
        secret: bytearray | None = None
        with self._lock:
            state = self._states.pop(handle, None)
            if state is not None:
                secret = state.secret
                state.secret = None
                state.permit = None
                state.gate = None
                state.publication_id = None
                state.status = "closed"
        _best_effort_zero(secret)

    def _force_discard_unpublished(
        self,
        handle: CredentialHandle,
        known_state: _HandleState | None,
    ) -> None:
        """Non-throwing fallback after failed resolution is Gate-terminal."""

        state = known_state
        secret: object | None = None
        try:
            with self._lock:
                current = self._states.pop(handle, None)
                if state is None:
                    state = current
                if current is not None and current is not state:
                    # No valid flow replaces an exact unpublished handle.  If
                    # an injected fault did, detach both private buffers.
                    _best_effort_zero(getattr(current, "secret", None))
                    current.secret = None
                    current.permit = None
                    current.gate = None
                    current.publication_id = None
                    current.status = "closed"
                if state is not None:
                    secret = getattr(state, "secret", None)
                    state.secret = None
                    state.permit = None
                    state.gate = None
                    state.publication_id = None
                    state.status = "closed"
        except BaseException:
            if state is not None:
                try:
                    secret = getattr(state, "secret", secret)
                except BaseException:
                    pass
                for name, value in (
                    ("secret", None),
                    ("permit", None),
                    ("gate", None),
                    ("publication_id", None),
                    ("status", "closed"),
                ):
                    try:
                        setattr(state, name, value)
                    except BaseException:
                        pass
        try:
            _best_effort_zero(secret)
        except BaseException:
            pass

    def _force_discard_for_permit(
        self,
        permit: CredentialResolutionPermit,
    ) -> None:
        """Recover an issued-before-raise handle by exact permit identity."""

        secrets: list[object] = []
        states: list[_HandleState] = []
        try:
            with self._lock:
                for handle, state in tuple(self._states.items()):
                    if getattr(state, "permit", None) is permit:
                        self._states.pop(handle, None)
                        states.append(state)
                for state in states:
                    secrets.append(getattr(state, "secret", None))
                    state.secret = None
                    state.permit = None
                    state.gate = None
                    state.publication_id = None
                    state.status = "closed"
        except BaseException:
            for state in states:
                try:
                    secrets.append(getattr(state, "secret", None))
                except BaseException:
                    pass
                for name, value in (
                    ("secret", None),
                    ("permit", None),
                    ("gate", None),
                    ("publication_id", None),
                    ("status", "closed"),
                ):
                    try:
                        setattr(state, name, value)
                    except BaseException:
                        pass
        for secret in secrets:
            try:
                _best_effort_zero(secret)
            except BaseException:
                pass

    def _finish_borrow(
        self,
        handle: CredentialHandle,
        secret: bytearray,
    ) -> None:
        with self._lock:
            state = self._states.get(handle)
            if state is not None:
                if state.secret is secret:
                    state.secret = None
                state.permit = None
                state.gate = None
                state.publication_id = None
                state.status = "closed"
        _best_effort_zero(secret)

    def _force_finish_borrow(
        self,
        handle: CredentialHandle,
        secret: bytearray,
    ) -> None:
        """Non-throwing detach/zero before the Gate borrow marker is released."""

        state: _HandleState | None = None
        try:
            with self._lock:
                state = self._states.get(handle)
                if state is not None:
                    state.secret = None
                    state.permit = None
                    state.gate = None
                    state.publication_id = None
                    state.status = "closed"
        except BaseException:
            if state is not None:
                for name, value in (
                    ("secret", None),
                    ("permit", None),
                    ("gate", None),
                    ("publication_id", None),
                    ("status", "closed"),
                ):
                    try:
                        setattr(state, name, value)
                    except BaseException:
                        pass
        try:
            _best_effort_zero(secret)
        except BaseException:
            pass

    def _close_all(self) -> None:
        secrets: list[bytearray] = []
        with self._lock:
            for state in self._states.values():
                if type(state.secret) is bytearray:
                    secrets.append(state.secret)
                state.secret = None
                state.permit = None
                state.gate = None
                state.publication_id = None
                state.status = "closed"
        for secret in secrets:
            _best_effort_zero(secret)

    def __del__(self) -> None:
        try:
            self._close_all()
        except BaseException:
            pass


def _frozen_glm_binding(
    permit: CredentialResolutionPermit,
) -> tuple[
    CredentialBindingMetadata,
    ExecutionPlanNetworkOperation,
]:
    valid = True
    binding: CredentialBindingMetadata | None = None
    operation: ExecutionPlanNetworkOperation | None = None
    try:
        planned = permit._planned
        invocation = permit._invocation
        prepared = permit._prepared
        session = permit._session
        if (
            type(planned) is not PlannedExecution
            or type(invocation) is not StageInvocation
            or type(prepared) is not PreparedOutbound
            or type(session) is not AuthorizedSendSession
        ):
            valid = False
        else:
            planned.validate_integrity()
            invocation.validate_integrity()
            prepared.validate_integrity()
            session.validate_integrity()

            stage_indexes = tuple(
                index
                for index, stage in enumerate(planned.plan.stages)
                if stage.stage_id == invocation.stage_id
            )
            if len(stage_indexes) != 1:
                valid = False
            else:
                stage_index = stage_indexes[0]
                stage = planned.plan.stages[stage_index]
                resolved = planned.resolved_pipeline.stages[stage_index]
                provider = resolved.provider_profile
                operations = tuple(
                    item
                    for item in stage.network_operations
                    if item.operation_id == prepared.operation_id
                )
                if len(operations) == 1:
                    operation = operations[0]
                else:
                    valid = False
                if type(provider) is ProviderProfileSnapshot:
                    candidate_binding = provider.credential_binding
                    if type(candidate_binding) is CredentialBindingMetadata:
                        binding = candidate_binding
                    else:
                        valid = False
                else:
                    valid = False

                if binding is not None and operation is not None:
                    endpoint = provider.endpoint_policy
                    exact = (
                        planned.resolved_pipeline.registry_revision
                        == BUILTIN_REGISTRY_REVISION,
                        planned.resolved_pipeline.registry_digest
                        == builtin_registry_digest(),
                        stage.binding_id == GLM_BINDING_ID,
                        resolved.stage_binding.binding_id == GLM_BINDING_ID,
                        stage.provider_profile_id == GLM_PROVIDER_PROFILE_ID,
                        provider.provider_profile_id == GLM_PROVIDER_PROFILE_ID,
                        stage.provider_id == GLM_PROVIDER_ID,
                        provider.provider_id == GLM_PROVIDER_ID,
                        binding.provider_id == GLM_PROVIDER_ID,
                        stage.credential_binding_ref
                        == GLM_CREDENTIAL_BINDING_REF,
                        binding.credential_binding_ref
                        == GLM_CREDENTIAL_BINDING_REF,
                        binding.credential_ref == GLM_CREDENTIAL_REF,
                        stage.endpoint_policy_version
                        == GLM_ENDPOINT_POLICY_VERSION,
                        endpoint.endpoint_policy_version
                        == GLM_ENDPOINT_POLICY_VERSION,
                        binding.endpoint_policy_version
                        == GLM_ENDPOINT_POLICY_VERSION,
                        stage.network_policy_version
                        == GLM_NETWORK_POLICY_VERSION,
                        endpoint.network_policy_version
                        == GLM_NETWORK_POLICY_VERSION,
                        binding.network_policy_version
                        == GLM_NETWORK_POLICY_VERSION,
                        stage.tls_policy_ref == GLM_TLS_POLICY_REF,
                        endpoint.tls_policy_ref == GLM_TLS_POLICY_REF,
                        binding.tls_policy_ref == GLM_TLS_POLICY_REF,
                        operation.canonical_endpoint
                        == GLM_CHAT_COMPLETIONS_ENDPOINT,
                        operation.credential_injection_slot
                        is CredentialInjectionSlot.AUTHORIZATION_HEADER,
                        binding.credential_injection_slot
                        is CredentialInjectionSlot.AUTHORIZATION_HEADER,
                        binding.credential_value_scheme
                        is CredentialValueScheme.BEARER,
                        provider.credential_binding is binding,
                        binding.endpoint_policy_digest
                        == endpoint.endpoint_policy_digest,
                        stage.provider_profile_digest
                        == provider.provider_profile_digest,
                        stage.credential_binding_digest
                        == binding.credential_binding_digest,
                        prepared.credential_binding_digest
                        == binding.credential_binding_digest,
                        session.credential_binding_digest
                        == binding.credential_binding_digest,
                        permit.credential_binding_digest
                        == binding.credential_binding_digest,
                        prepared.operation_id == operation.operation_id,
                        session.operation_id == operation.operation_id,
                        session.stage_id == stage.stage_id,
                        session.request_envelope_digest
                        == permit.request_envelope_digest,
                    )
                    valid = valid and all(exact)
    except (TypeError, ValueError, AttributeError, LookupError):
        valid = False

    if not valid or binding is None or operation is None:
        _raise_credential_policy_error()
    return binding, operation


def _read_validated_secret(
    source: CredentialSource,
    credential_ref: str,
) -> bytearray:
    raw: object | None = None
    passthrough: CancelledError | TimeoutError | None = None
    source_failed = False
    try:
        raw = source.read_exact(credential_ref)
    except (CancelledError, TimeoutError) as error:
        passthrough = error
    except Exception:
        source_failed = True

    if passthrough is not None:
        raise passthrough
    if source_failed:
        _raise_credential_error()

    if type(raw) is not bytearray:
        _best_effort_zero(raw)
        _raise_credential_error()

    secret: bytearray | None = None
    value_is_valid = False
    try:
        try:
            value_is_valid = (
                1 <= len(raw) <= MAX_CREDENTIAL_BYTES
                and _B64TOKEN_RE.fullmatch(raw) is not None
            )
            if value_is_valid:
                secret = bytearray(raw)
        except (CancelledError, TimeoutError):
            raise
        except Exception:
            value_is_valid = False
    finally:
        # This also runs for async cancellation, KeyboardInterrupt and other
        # BaseException paths that must not strand the source-owned buffer.
        _best_effort_zero(raw)

    if not value_is_valid or type(secret) is not bytearray:
        _best_effort_zero(secret)
        _raise_credential_error()
    return secret


def _credential_gate_is_terminal_for_cleanup(
    gate: AttemptGate,
    permit: CredentialResolutionPermit,
) -> bool:
    """Observe cleanup from Gate-owned state, never transition returns."""

    try:
        return gate._credential_resolution_is_terminal_for_cleanup(
            permit,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
    except BaseException:
        return False


def _recover_claimed_gate_for_cleanup(
    gate: AttemptGate,
    permit: CredentialResolutionPermit,
    *,
    claim_id: UUID,
) -> bool:
    """Retry a claimed Gate through wrapper and independent state paths."""

    recoveries = (
        gate._recover_claimed_credential_for_cleanup,
        gate._recover_claimed_credential_state_for_cleanup,
    )
    for recovery in recoveries:
        for _ in range(2):
            try:
                recovery(
                    permit,
                    claim_id=claim_id,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
            except BaseException:
                pass
            if _credential_gate_is_terminal_for_cleanup(gate, permit):
                return True
    return _credential_gate_is_terminal_for_cleanup(gate, permit)


def _recover_resolved_gate_for_cleanup(
    gate: AttemptGate,
    permit: CredentialResolutionPermit,
    *,
    publication_id: UUID,
    handle_id: UUID,
    handle_digest: Digest256,
) -> bool:
    """Retry a resolved Gate through wrapper and independent state paths."""

    recoveries = (
        gate._recover_resolved_credential_for_cleanup,
        gate._recover_resolved_credential_state_for_cleanup,
    )
    for recovery in recoveries:
        for _ in range(2):
            try:
                recovery(
                    permit,
                    publication_id=publication_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
            except BaseException:
                pass
            if _credential_gate_is_terminal_for_cleanup(gate, permit):
                return True
    return _credential_gate_is_terminal_for_cleanup(gate, permit)


@runtime_final
class CredentialResolver:
    """Resolve one frozen built-in GLM binding into a one-shot handle."""

    __slots__ = ("_source", "_ledger")

    def __init__(self, source: CredentialSource) -> None:
        # Do not inspect the source or its method here.  Construction must be
        # zero-read; the exact method lookup belongs to the claimed read stage.
        object.__setattr__(self, "_source", source)
        object.__setattr__(self, "_ledger", _CredentialLedger())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CredentialResolver is immutable")

    def __copy__(self) -> "CredentialResolver":
        raise TypeError("CredentialResolver cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> "CredentialResolver":
        del memo
        raise TypeError("CredentialResolver cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("CredentialResolver cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("CredentialResolver cannot be serialized")

    def __repr__(self) -> str:
        return "CredentialResolver()"

    def resolve(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID | None = None,
    ) -> CredentialHandle:
        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
        exact_publication_id = (
            uuid4()
            if publication_id is None
            else require_uuid(publication_id, "publication_id")
        )
        gate = permit._attempt_gate
        if type(gate) is not AttemptGate:
            _raise_credential_policy_error()

        claim_id = uuid4()
        try:
            gate._claim_credential_resolution(
                permit,
                claim_id=claim_id,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
            if not gate._credential_claim_is_owned(
                permit,
                claim_id=claim_id,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            ):
                _raise_credential_policy_error()
        except BaseException as primary:
            primary_traceback = (
                None
                if isinstance(
                    primary,
                    (
                        CancelledError,
                        ConfigError,
                        EndpointPolicyError,
                        TimeoutError,
                    ),
                )
                else primary.__traceback__
            )
            _recover_claimed_gate_for_cleanup(
                gate,
                permit,
                claim_id=claim_id,
            )
            _raise_resolver_primary(primary, primary_traceback)

        handle: CredentialHandle | None = None
        handle_state: _HandleState | None = None
        handle_id: UUID | None = None
        handle_digest: Digest256 | None = None
        primary: BaseException | None = None
        primary_traceback: object | None = None
        try:
            binding, operation = _frozen_glm_binding(permit)
            secret = _read_validated_secret(
                self._source,
                binding.credential_ref,
            )
            handle = self._ledger._issue(
                publication_id=exact_publication_id,
                permit=permit,
                operation_id=operation.operation_id,
                credential_injection_slot=binding.credential_injection_slot,
                credential_value_scheme=binding.credential_value_scheme,
                secret=secret,
            )
            with self._ledger._lock:
                handle_state = self._ledger._states.get(handle)
                if (
                    handle_state is None
                    or handle_state.handle is not handle
                    or handle_state.permit is not permit
                    or handle_state.gate is not gate
                    or handle_state.publication_id != exact_publication_id
                ):
                    _raise_credential_policy_error()
                handle_id = handle_state.handle_id
                handle_digest = handle_state.handle_digest
            gate._confirm_credential_resolution(
                permit,
                claim_id=claim_id,
                publication_id=exact_publication_id,
                resolved_binding_digest=binding.credential_binding_digest,
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
            if not self._published_handle_is_exact_for_transport(
                handle,
                permit=permit,
                publication_id=exact_publication_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            ):
                _raise_credential_policy_error()
            return handle
        except BaseException as error:
            primary = error
            primary_traceback = (
                None
                if isinstance(
                    error,
                    (
                        CancelledError,
                        ConfigError,
                        EndpointPolicyError,
                        TimeoutError,
                    ),
                )
                else error.__traceback__
            )

        # Gate terminalization precedes ledger zeroization and uses only the
        # Gate/credential-ledger snapshots captured before any return wrapper
        # can mutate public permit or handle slots.
        terminal = False
        if (
            handle is not None
            and handle_state is not None
            and type(handle_id) is UUID
            and type(handle_digest) is Digest256
        ):
            terminal = _recover_resolved_gate_for_cleanup(
                gate,
                permit,
                publication_id=exact_publication_id,
                handle_id=handle_id,
                handle_digest=handle_digest,
            )
        if not terminal:
            terminal = _recover_claimed_gate_for_cleanup(
                gate,
                permit,
                claim_id=claim_id,
            )

        if terminal:
            if handle is not None and handle_state is not None:
                try:
                    self._ledger._force_discard_unpublished(
                        handle,
                        handle_state,
                    )
                except BaseException:
                    pass
            self._ledger._force_discard_for_permit(permit)

        assert primary is not None
        _raise_resolver_primary(primary, primary_traceback)
        raise AssertionError("unreachable")

    def _recover_published_handle_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Recover and close one published handle before returning.

        This is the loss-recovery form used when an outer ``resolve`` wrapper
        raises after the handle was published but before the caller received
        it.  No handle or secret leaves this method.  The ledger-owned proof is
        used for the Gate check and final state observation, so cleanup still
        succeeds after same-process mutation of public handle slots.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential cleanup recovery requires transport")
        return self._recover_published_handle_state_for_cleanup(
            permit,
            publication_id=publication_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )

    def _recover_published_handle_state_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Independent ledger path for retrying lost-handle cleanup."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential cleanup recovery requires transport")
        if (
            type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
        ):
            return False

        recovered = self._ledger._recover_active_state_for_cleanup(
            permit,
            publication_id=publication_id,
        )
        if recovered is None:
            return False
        handle, state = recovered
        gate = state.gate
        if type(gate) is not AttemptGate:
            return False
        gate_terminal = _recover_resolved_gate_for_cleanup(
            gate,
            permit,
            publication_id=publication_id,
            handle_id=state.handle_id,
            handle_digest=state.handle_digest,
        )
        if gate_terminal:
            try:
                self._ledger._force_close_after_gate(handle, state)
            except BaseException:
                pass
        return (
            gate_terminal
            and self._ledger._cleanup_state_is_closed(handle, state)
        )

    def _published_handle_is_closed_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Observe terminal publication state without a returned handle."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential cleanup observation requires transport")
        if (
            type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
        ):
            return False
        return (
            self._ledger._publication_terminal_state_for_cleanup(
                permit,
                publication_id=publication_id,
            )
            == "closed"
        )

    def _published_handle_terminal_state_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        _authority: object | None = None,
    ) -> str:
        """Observe ``absent``/``closed`` or fail closed as ``ambiguous``.

        This is intentionally independent from the recovery method's return
        value.  It consults only resolver-owned immutable publication proof and
        exact permit/Gate identities; it never returns a handle or secret.
        """

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential cleanup observation requires transport")
        return self._ledger._publication_terminal_state_for_cleanup(
            permit,
            publication_id=publication_id,
        )

    def _published_handle_is_exact_for_transport(
        self,
        handle: CredentialHandle,
        *,
        permit: CredentialResolutionPermit,
        publication_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Attest one returned handle against ledger and Gate snapshots."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential publication attestation requires transport")
        if (
            type(handle) is not CredentialHandle
            or type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
        ):
            return False
        with self._ledger._lock:
            state = self._ledger._states.get(handle)
            if (
                state is None
                or state.handle is not handle
                or state.status != "active"
                or state.permit is not permit
                or type(state.gate) is not AttemptGate
                or state.publication_id != publication_id
                or type(state.handle_id) is not UUID
                or type(state.handle_digest) is not Digest256
                or type(state.secret) is not bytearray
            ):
                return False
            gate = state.gate
            handle_id = state.handle_id
            handle_digest = state.handle_digest
        try:
            return gate._resolved_credential_handle_is_active(
                permit,
                publication_id=publication_id,
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            return False

    def _handle_is_closed_for_cleanup(
        self,
        handle: CredentialHandle,
        *,
        _authority: object | None = None,
    ) -> bool:
        """Observe exact ledger terminal state without public handle fields."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential cleanup observation requires transport")
        if type(handle) is not CredentialHandle:
            return False
        with self._ledger._lock:
            state = self._ledger._states.get(handle)
            if state is None or state.handle is not handle:
                return False
        return self._ledger._cleanup_state_is_closed(handle, state)

    def close(self, handle: CredentialHandle) -> bool:
        state, permit, gate, integrity_is_valid = self._ledger._release_info(
            handle
        )
        if permit is None or gate is None:
            if not integrity_is_valid:
                _raise_credential_policy_error()
            return False
        # This private Gate transition is proof-exact.  It rejects a consumed
        # permit because ownership has moved to AttemptPermit/Transport.
        proof_candidates = [
            (
                getattr(state, "handle_id", None),
                getattr(state, "handle_digest", None),
            )
        ]
        public_handle_id = getattr(handle, "handle_id", None)
        public_handle_digest = getattr(handle, "handle_digest", None)
        if (
            type(public_handle_id) is UUID
            and type(public_handle_digest) is Digest256
            and (public_handle_id, public_handle_digest)
            != proof_candidates[0]
        ):
            # The handle and the ledger are independent proof copies.  Either
            # copy can terminalize an exact resolved Gate after same-process
            # slot tampering; a consumed Gate rejects both without zeroing.
            proof_candidates.append((public_handle_id, public_handle_digest))
        gate_error: BaseException | None = None
        gate_is_terminal = False
        gate_committed_after_error = False
        for handle_id, handle_digest in proof_candidates:
            transition_error: BaseException | None = None
            try:
                gate._abandon_resolved_credential_resolution(
                    permit,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
            except BaseException as error:
                gate_error = error
                transition_error = error
            try:
                gate_is_terminal = (
                    gate._credential_resolution_is_terminal_for_cleanup(
                        permit,
                        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                    )
                )
            except BaseException:
                gate_is_terminal = False
            if gate_is_terminal:
                gate_committed_after_error = transition_error is not None
                break
            if transition_error is None:
                gate_error = _credential_policy_error()
        if not gate_is_terminal:
            self._ledger._restore_active_after_gate_failure(handle, state)
            if gate_error is None:
                gate_error = _credential_policy_error()
            raise gate_error
        changed = False
        close_error: BaseException | None = None
        try:
            changed = self._ledger._close_after_gate(handle, state)
        except BaseException as error:
            close_error = error
        finally:
            changed = (
                self._ledger._force_close_after_gate(handle, state)
                or changed
            )
        if close_error is not None:
            raise close_error
        if not integrity_is_valid:
            _raise_credential_policy_error()
        if gate_committed_after_error:
            assert gate_error is not None
            raise gate_error
        return changed

    @staticmethod
    def _release_gate_borrow_marker(
        gate: AttemptGate,
        attempt_permit: AttemptPermit,
        *,
        borrow_id: UUID,
        handle_id: UUID,
        handle_digest: Digest256,
    ) -> None:
        last_error: BaseException | None = None
        for _ in range(2):
            transition_error: BaseException | None = None
            try:
                gate._finish_credential_borrow(
                    attempt_permit,
                    borrow_id=borrow_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException as error:
                last_error = error
                transition_error = error
            try:
                active = gate._credential_borrow_is_active(
                    attempt_permit,
                    borrow_id=borrow_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                active = True
            if not active:
                return
            if transition_error is None:
                last_error = _credential_policy_error()
        try:
            gate._force_finish_credential_borrow(
                attempt_permit,
                borrow_id=borrow_id,
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException as error:
            last_error = error
        try:
            active = gate._credential_borrow_is_active(
                attempt_permit,
                borrow_id=borrow_id,
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        except BaseException:
            active = True
        if not active:
            return
        if last_error is None:
            last_error = _credential_policy_error()
        raise last_error

    def _borrow_once(
        self,
        handle: CredentialHandle,
        attempt_permit: AttemptPermit,
        action: Callable[[memoryview], _ResultT],
        *,
        _authority: object | None = None,
    ) -> _ResultT:
        if _authority is not _TRANSPORT_CREDENTIAL_AUTHORITY:
            raise TypeError("credential borrowing requires trusted transport")
        if type(handle) is not CredentialHandle:
            raise TypeError("handle must be CredentialHandle")
        if type(attempt_permit) is not AttemptPermit:
            raise TypeError("attempt_permit must be AttemptPermit")
        if not callable(action):
            raise TypeError("action must be callable")

        gate = attempt_permit._attempt_gate
        if type(gate) is not AttemptGate:
            _raise_credential_policy_error()

        handle_id = handle.handle_id
        handle_digest = handle.handle_digest
        borrow_id = uuid4()
        try:
            gate._begin_credential_borrow(
                attempt_permit,
                borrow_id=borrow_id,
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            try:
                borrow_is_active = gate._credential_borrow_is_active(
                    attempt_permit,
                    borrow_id=borrow_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                borrow_is_active = False
            if not borrow_is_active:
                _raise_credential_policy_error()
        except BaseException as primary:
            primary_traceback = primary.__traceback__
            try:
                self._release_gate_borrow_marker(
                    gate,
                    attempt_permit,
                    borrow_id=borrow_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                )
            except BaseException:
                pass
            raise primary.with_traceback(primary_traceback)
        secret: bytearray | None = None
        writable_view: memoryview | None = None
        readonly_view: memoryview | None = None
        try:
            integrity_is_valid = True
            exact: tuple[bool, ...] = (False,)
            with self._ledger._lock:
                state = self._ledger._lookup_exact_locked(handle)
                integrity_is_valid = self._ledger._integrity_is_valid(
                    handle,
                    state,
                )
                if not integrity_is_valid:
                    secret = state.secret
                    state.secret = None
                    state.permit = None
                    state.gate = None
                    state.publication_id = None
                    state.status = "closed"
                else:
                    exact = (
                        state.status == "active",
                        state.handle is handle,
                        state.gate is gate,
                        attempt_permit._credential_permit is state.permit,
                        attempt_permit.credential_permit_id
                        == handle.credential_permit_id,
                        attempt_permit.credential_permit_digest
                        == handle.credential_permit_digest,
                        attempt_permit.context_id == handle.context_id,
                        attempt_permit.context_digest == handle.context_digest,
                        attempt_permit.session_id == handle.session_id,
                        attempt_permit.session_terms_digest
                        == handle.session_terms_digest,
                        attempt_permit.operation_id == handle.operation_id,
                        attempt_permit.request_envelope_digest
                        == handle.request_envelope_digest,
                        attempt_permit.credential_binding_digest
                        == handle.credential_binding_digest,
                        attempt_permit.credential_handle_id == state.handle_id,
                        attempt_permit.credential_handle_digest
                        == state.handle_digest,
                        attempt_permit.credential_handle_id == handle.handle_id,
                        attempt_permit.credential_handle_digest
                        == handle.handle_digest,
                        type(state.secret) is bytearray,
                    )
                    if all(exact):
                        state.status = "borrowing"
                        secret = state.secret

            if not integrity_is_valid:
                _best_effort_zero(secret)
                _raise_credential_policy_error()
            if secret is None or not all(exact):
                _raise_credential_policy_error()

            writable_view = memoryview(secret)
            readonly_view = writable_view.toreadonly()
            writable_view.release()
            writable_view = None
            return action(readonly_view)
        finally:
            if readonly_view is not None:
                try:
                    readonly_view.release()
                except BaseException:
                    pass
            if writable_view is not None:
                try:
                    writable_view.release()
                except BaseException:
                    pass
            try:
                if type(secret) is bytearray:
                    try:
                        self._ledger._finish_borrow(handle, secret)
                    except BaseException:
                        # The force path below has the exact mutable buffer and
                        # must preserve any callback primary exception.
                        pass
                    finally:
                        self._ledger._force_finish_borrow(handle, secret)
            finally:
                self._release_gate_borrow_marker(
                    gate,
                    attempt_permit,
                    borrow_id=borrow_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                )


__all__ = [
    "CREDENTIAL_HANDLE_SCHEMA_VERSION",
    "CREDENTIAL_RESOLVER_POLICY_VERSION",
    "MAX_CREDENTIAL_BYTES",
    "CredentialHandle",
    "CredentialResolver",
    "CredentialSource",
]
