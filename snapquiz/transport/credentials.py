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
        "permit",
        "gate",
        "secret",
        "status",
    )

    def __init__(
        self,
        *,
        handle: CredentialHandle,
        permit: CredentialResolutionPermit,
        gate: AttemptGate,
        secret: bytearray,
    ) -> None:
        self.handle = handle
        self.handle_id = handle.handle_id
        self.handle_digest = handle.handle_digest
        self.permit: CredentialResolutionPermit | None = permit
        self.gate: AttemptGate | None = gate
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
                    current.status = "closed"
                if state is not None:
                    secret = getattr(state, "secret", None)
                    state.secret = None
                    state.permit = None
                    state.gate = None
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
                    state.status = "closed"
        except BaseException:
            if state is not None:
                for name, value in (
                    ("secret", None),
                    ("permit", None),
                    ("gate", None),
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
    ) -> CredentialHandle:
        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
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
            for _ in range(2):
                try:
                    gate._fail_credential_resolution(
                        permit,
                        claim_id=claim_id,
                        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                    )
                except BaseException:
                    continue
                break
            _raise_resolver_primary(primary, primary_traceback)

        handle: CredentialHandle | None = None
        confirmed = False
        primary: BaseException | None = None
        primary_traceback: object | None = None
        try:
            binding, operation = _frozen_glm_binding(permit)
            secret = _read_validated_secret(
                self._source,
                binding.credential_ref,
            )
            handle = self._ledger._issue(
                permit=permit,
                operation_id=operation.operation_id,
                credential_injection_slot=binding.credential_injection_slot,
                credential_value_scheme=binding.credential_value_scheme,
                secret=secret,
            )
            gate._confirm_credential_resolution(
                permit,
                claim_id=claim_id,
                resolved_binding_digest=binding.credential_binding_digest,
                handle_id=handle.handle_id,
                handle_digest=handle.handle_digest,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
            confirmed = True
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

        # Gate terminalization precedes ledger zeroization.  Each transition
        # is owner/proof exact, so one pre-commit rollback can be retried
        # without touching another resolver.  Observing after every exception
        # also recognizes a commit-then-raise fault before any secret cleanup.
        def gate_is_terminal() -> bool:
            try:
                return gate._credential_resolution_is_terminal(
                    permit,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
            except BaseException:
                return False

        def fail_owned_claim() -> bool:
            for _ in range(2):
                try:
                    gate._fail_credential_resolution(
                        permit,
                        claim_id=claim_id,
                        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                    )
                except BaseException:
                    if gate_is_terminal():
                        return True
                else:
                    return True
            return gate_is_terminal()

        def abandon_resolved_proof() -> bool:
            if handle is None:
                return False
            for _ in range(2):
                try:
                    gate._abandon_resolved_credential_resolution(
                        permit,
                        handle_id=handle.handle_id,
                        handle_digest=handle.handle_digest,
                        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                    )
                except BaseException:
                    if gate_is_terminal():
                        return True
                else:
                    return True
            return gate_is_terminal()

        # Confirmation can linearize immediately before an injected
        # BaseException.  A claim-exact failure then rejects because ownership
        # has moved to the resolved proof; fall back to proof-exact abandon.
        terminal = (
            abandon_resolved_proof()
            if confirmed and handle is not None
            else fail_owned_claim()
        )
        if not terminal and handle is not None:
            terminal = abandon_resolved_proof()
        if not terminal:
            terminal = gate_is_terminal()

        if handle is not None and terminal:
            cleanup_state: _HandleState | None = None
            try:
                with self._ledger._lock:
                    cleanup_state = self._ledger._states.get(handle)
                self._ledger._discard_unpublished(handle)
            except BaseException:
                # Preserve the already-selected safe primary error.  Gate is
                # irreversibly terminal, so cleanup faults cannot authorize a
                # send and must not prevent the fallback detach/zero below.
                pass
            finally:
                self._ledger._force_discard_unpublished(
                    handle,
                    cleanup_state,
                )
        if terminal:
            self._ledger._force_discard_for_permit(permit)

        assert primary is not None
        _raise_resolver_primary(primary, primary_traceback)
        raise AssertionError("unreachable")

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
            try:
                gate._abandon_resolved_credential_resolution(
                    permit,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
            except BaseException as error:
                gate_error = error
            else:
                gate_is_terminal = True
                break
        if not gate_is_terminal:
            try:
                gate_is_terminal = gate._credential_resolution_is_terminal(
                    permit,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
            except BaseException:
                pass
            else:
                gate_committed_after_error = gate_is_terminal
        if not gate_is_terminal:
            self._ledger._restore_active_after_gate_failure(handle, state)
            assert gate_error is not None
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
            else:
                return
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
        else:
            return
        assert last_error is not None
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
