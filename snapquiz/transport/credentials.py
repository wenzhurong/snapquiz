"""One-shot credential handles and frozen-binding resolution for W09-B1.

This module is intentionally the only dependency direction between the two
layers: credentials depend on :mod:`snapquiz.runtime.attempt`; the AttemptGate
stores only primitive handle proof and never imports this module.  Importing or
constructing any object here performs no credential read and no I/O.
"""
from __future__ import annotations

import re
import sys
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
_STAGE_OWNER_AUTHORITY = object()
_STAGE_RECEIPT_AUTHORITY = object()
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
        "secret_length",
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
        secret_length: int | None = None,
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
        selected_length = len(secret) if secret_length is None else secret_length
        if (
            type(selected_length) is not int
            or not 1 <= selected_length <= len(secret)
        ):
            raise ValueError("secret length is invalid")
        self.secret_length = selected_length
        # This state is caller-unobservable until AttemptGate confirmation
        # returns and resolve() returns the handle.  Confirmation is the sole
        # publication linearization point, so no fallible ledger activation is
        # allowed after it.
        self.status = "active"


@runtime_final
class _CredentialStageReceipt:
    """Content-free proof that one preheld ledger owner was filled once."""

    __slots__ = (
        "publication_id",
        "owner_id",
        "credential_binding_digest",
        "secret_length",
        "receipt_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        publication_id: UUID,
        owner_id: UUID,
        credential_binding_digest: Digest256,
        secret_length: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _STAGE_RECEIPT_AUTHORITY:
            raise TypeError("credential stage receipts require their ledger")
        require_uuid(publication_id, "publication_id")
        require_uuid(owner_id, "owner_id")
        require_digest(
            credential_binding_digest,
            "credential_binding_digest",
        )
        if (
            type(secret_length) is not int
            or not 1 <= secret_length <= MAX_CREDENTIAL_BYTES
        ):
            raise ValueError("credential stage length is invalid")
        object.__setattr__(self, "publication_id", publication_id)
        object.__setattr__(self, "owner_id", owner_id)
        object.__setattr__(
            self,
            "credential_binding_digest",
            credential_binding_digest,
        )
        object.__setattr__(self, "secret_length", secret_length)
        selected = digest256(
            "CredentialStageReceipt",
            CREDENTIAL_RESOLVER_POLICY_VERSION,
            {
                "publication_id": publication_id,
                "owner_id": owner_id,
                "credential_binding_digest": credential_binding_digest,
                "secret_length": secret_length,
            },
        )
        object.__setattr__(self, "receipt_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("credential stage receipts are immutable")

    def __copy__(self) -> object:
        raise TypeError("credential stage receipts cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("credential stage receipts cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("credential stage receipts cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("credential stage receipts cannot be serialized")

    def __repr__(self) -> str:
        return "_CredentialStageReceipt(<content-free>)"

    def _validated_snapshot(
        self,
    ) -> tuple[UUID, UUID, Digest256, int]:
        publication_id = self.publication_id
        owner_id = self.owner_id
        credential_binding_digest = self.credential_binding_digest
        secret_length = self.secret_length
        receipt_digest = self.receipt_digest
        issued_digest = self._issued_digest
        require_uuid(publication_id, "publication_id")
        require_uuid(owner_id, "owner_id")
        require_digest(
            credential_binding_digest,
            "credential_binding_digest",
        )
        if (
            type(secret_length) is not int
            or not 1 <= secret_length <= MAX_CREDENTIAL_BYTES
        ):
            raise ValueError("credential stage length changed")
        require_digest(receipt_digest, "receipt_digest")
        require_digest(issued_digest, "issued_digest")
        expected = digest256(
            "CredentialStageReceipt",
            CREDENTIAL_RESOLVER_POLICY_VERSION,
            {
                "publication_id": publication_id,
                "owner_id": owner_id,
                "credential_binding_digest": credential_binding_digest,
                "secret_length": secret_length,
            },
        )
        if receipt_digest != expected or issued_digest != expected:
            raise ValueError("credential stage receipt integrity mismatch")
        if (
            self.publication_id,
            self.owner_id,
            self.credential_binding_digest,
            self.secret_length,
            self.receipt_digest,
            self._issued_digest,
        ) != (
            publication_id,
            owner_id,
            credential_binding_digest,
            secret_length,
            receipt_digest,
            issued_digest,
        ):
            raise ValueError("credential stage receipt changed during validation")
        return (
            publication_id,
            owner_id,
            credential_binding_digest,
            secret_length,
        )

    def validate_integrity(self) -> None:
        self._validated_snapshot()


@runtime_final
class _CredentialStagingOwner:
    """Ledger-anchored fixed storage allocated before a Keychain call."""

    __slots__ = (
        "publication_id",
        "publication_id_snapshot",
        "owner_id",
        "owner_digest",
        "_issued_digest",
        "permit",
        "permit_id_snapshot",
        "permit_digest_snapshot",
        "gate",
        "gate_id_snapshot",
        "credential_binding_digest",
        "credential_binding_digest_snapshot",
        "storage",
        "storage_identity",
        "source_publication",
        "secret_length",
        "receipt",
        "status",
        "action_lock",
    )

    def __init__(
        self,
        *,
        publication_id: UUID,
        permit: CredentialResolutionPermit,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _STAGE_OWNER_AUTHORITY:
            raise TypeError("credential staging owners require their ledger")
        require_uuid(publication_id, "publication_id")
        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
        permit.validate_integrity()
        storage = bytearray(MAX_CREDENTIAL_BYTES)
        owner_id = uuid4()
        selected_digest = digest256(
            "CredentialStagingOwner",
            CREDENTIAL_RESOLVER_POLICY_VERSION,
            {
                "publication_id": publication_id,
                "owner_id": owner_id,
                "permit_id": permit.permit_id,
                "permit_digest": permit.permit_digest,
                "gate_id": permit.gate_id,
                "credential_binding_digest": permit.credential_binding_digest,
            },
        )
        self.publication_id = publication_id
        self.publication_id_snapshot = publication_id
        self.owner_id = owner_id
        self.owner_digest = selected_digest
        self._issued_digest = selected_digest
        self.permit: CredentialResolutionPermit | None = permit
        self.permit_id_snapshot = permit.permit_id
        self.permit_digest_snapshot = permit.permit_digest
        self.gate: AttemptGate | None = permit._attempt_gate
        self.gate_id_snapshot = permit.gate_id
        self.credential_binding_digest = permit.credential_binding_digest
        self.credential_binding_digest_snapshot = permit.credential_binding_digest
        self.storage: bytearray | None = storage
        self.storage_identity = id(storage)
        self.source_publication: object | None = None
        self.secret_length = 0
        self.receipt: _CredentialStageReceipt | None = None
        self.status = "preheld"
        self.action_lock = RLock()

    def __repr__(self) -> str:
        return "_CredentialStagingOwner(<private>)"

    def __copy__(self) -> object:
        raise TypeError("credential staging owners cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("credential staging owners cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("credential staging owners cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("credential staging owners cannot be serialized")


class _CredentialLedger:
    __slots__ = ("_states", "_staged", "_lock")

    def __init__(self) -> None:
        self._states: dict[CredentialHandle, _HandleState] = {}
        self._staged: dict[UUID, _CredentialStagingOwner] = {}
        self._lock = RLock()

    @staticmethod
    def _staging_integrity_is_valid(
        owner: _CredentialStagingOwner,
    ) -> bool:
        try:
            if type(owner) is not _CredentialStagingOwner:
                return False
            require_uuid(owner.publication_id, "publication_id")
            require_uuid(owner.publication_id_snapshot, "publication_id_snapshot")
            require_uuid(owner.owner_id, "owner_id")
            require_digest(owner.owner_digest, "owner_digest")
            require_digest(owner._issued_digest, "issued_digest")
            require_digest(
                owner.credential_binding_digest,
                "credential_binding_digest",
            )
            require_digest(
                owner.credential_binding_digest_snapshot,
                "credential_binding_digest_snapshot",
            )
            expected = digest256(
                "CredentialStagingOwner",
                CREDENTIAL_RESOLVER_POLICY_VERSION,
                {
                    "publication_id": owner.publication_id_snapshot,
                    "owner_id": owner.owner_id,
                    "permit_id": owner.permit_id_snapshot,
                    "permit_digest": owner.permit_digest_snapshot,
                    "gate_id": owner.gate_id_snapshot,
                    "credential_binding_digest": (
                        owner.credential_binding_digest_snapshot
                    ),
                },
            )
            storage = owner.storage
            storage_valid = (
                type(storage) is bytearray
                and len(storage) == MAX_CREDENTIAL_BYTES
                and id(storage) == owner.storage_identity
            ) if owner.status not in ("transferred", "terminal") else (
                storage is None
            )
            return (
                owner.publication_id == owner.publication_id_snapshot
                and owner.owner_digest == expected
                and owner._issued_digest == expected
                and owner.credential_binding_digest
                == owner.credential_binding_digest_snapshot
                and storage_valid
                and (
                    owner.source_publication is None
                    or owner.status
                    in (
                        "preheld",
                        "staging",
                        "staged",
                        "cleanup_required",
                        "closing",
                    )
                )
            )
        except (TypeError, ValueError, AttributeError):
            return False

    def _prehold_keychain_owner(
        self,
        *,
        publication_id: UUID,
        permit: CredentialResolutionPermit,
    ) -> _CredentialStagingOwner:
        """Anchor zero-filled mutable storage before any Keychain call."""

        owner = _CredentialStagingOwner(
            publication_id=publication_id,
            permit=permit,
            _authority=_STAGE_OWNER_AUTHORITY,
        )
        try:
            with self._lock:
                if publication_id in self._staged or any(
                    state.publication_id_snapshot == publication_id
                    for state in self._states.values()
                ):
                    raise _credential_policy_error()
                self._staged[publication_id] = owner
            return owner
        except BaseException:
            storage = owner.storage
            owner.storage = None
            owner.status = "terminal"
            _best_effort_zero(storage)
            raise

    def _stage_keychain_view(
        self,
        owner: _CredentialStagingOwner,
        view: memoryview,
    ) -> None:
        """Validate a source's read-only view and fill the preheld owner once."""

        if type(owner) is not _CredentialStagingOwner:
            raise TypeError("owner must be a credential staging owner")
        if (
            type(view) is not memoryview
            or not view.readonly
            or view.ndim != 1
            or view.itemsize != 1
            or not view.c_contiguous
        ):
            _raise_credential_error()

        with owner.action_lock:
            with self._lock:
                if (
                    self._staged.get(owner.publication_id_snapshot) is not owner
                    or owner.status != "preheld"
                    or not self._staging_integrity_is_valid(owner)
                    or owner.permit is None
                    or owner.gate is None
                    or owner.secret_length != 0
                    or owner.receipt is not None
                    or owner.source_publication is None
                ):
                    _raise_credential_policy_error()
                owner.status = "staging"
                storage = owner.storage
            assert type(storage) is bytearray
            try:
                length = len(view)
                value_is_valid = (
                    1 <= length <= MAX_CREDENTIAL_BYTES
                    and _B64TOKEN_RE.fullmatch(view) is not None
                )
                if not value_is_valid:
                    _raise_credential_error()
                receipt = _CredentialStageReceipt(
                    publication_id=owner.publication_id_snapshot,
                    owner_id=owner.owner_id,
                    credential_binding_digest=(
                        owner.credential_binding_digest_snapshot
                    ),
                    secret_length=length,
                    _authority=_STAGE_RECEIPT_AUTHORITY,
                )
                # No bytes/bytearray is created from ``view``.  The only copy
                # lands directly in the fixed owner already held by the ledger.
                storage[:length] = view
                with self._lock:
                    if (
                        self._staged.get(owner.publication_id_snapshot)
                        is not owner
                        or owner.status != "staging"
                        or not self._staging_integrity_is_valid(owner)
                        or owner.storage is not storage
                    ):
                        _raise_credential_policy_error()
                    owner.secret_length = length
                    owner.receipt = receipt
                    owner.status = "staged"
            except BaseException:
                # The source publication still owns its action lock while this
                # callback runs.  Zero only the ledger buffer here; the outer
                # resolver recovery closes the source after ``consume_once``
                # has unwound, avoiding a callback-to-publication deadlock.
                _best_effort_zero(storage)
                with self._lock:
                    if (
                        self._staged.get(owner.publication_id_snapshot)
                        is owner
                        and owner.status == "staging"
                    ):
                        owner.secret_length = 0
                        owner.receipt = None
                        owner.status = "cleanup_required"
                raise

    def _recover_keychain_stage_receipt(
        self,
        owner: _CredentialStagingOwner,
    ) -> _CredentialStageReceipt | None:
        if type(owner) is not _CredentialStagingOwner:
            return None
        with self._lock:
            if (
                self._staged.get(owner.publication_id_snapshot) is not owner
                or owner.status != "staged"
                or not self._staging_integrity_is_valid(owner)
                or type(owner.receipt) is not _CredentialStageReceipt
            ):
                return None
            receipt = owner.receipt
            try:
                receipt_snapshot = receipt._validated_snapshot()
            except (TypeError, ValueError, AttributeError):
                return None
            if (
                receipt_snapshot[0] != owner.publication_id_snapshot
                or receipt_snapshot[1] != owner.owner_id
                or receipt_snapshot[2]
                != owner.credential_binding_digest_snapshot
                or receipt_snapshot[3] != owner.secret_length
            ):
                return None
            return receipt

    def _attach_keychain_publication(
        self,
        owner: _CredentialStagingOwner,
        publication: object,
    ) -> None:
        from snapquiz.transport import _darwin_keychain_source as keychain

        with self._lock:
            if (
                type(owner) is not _CredentialStagingOwner
                or type(publication) is not keychain._KeychainBufferPublication
                or self._staged.get(owner.publication_id_snapshot) is not owner
                or owner.status != "preheld"
                or owner.source_publication is not None
                or not self._staging_integrity_is_valid(owner)
            ):
                _raise_credential_policy_error()
            owner.source_publication = publication

    def _release_clean_keychain_publication(
        self,
        owner: _CredentialStagingOwner,
        publication: object,
    ) -> None:
        from snapquiz.transport import _darwin_keychain_source as keychain

        clean = (
            type(publication) is keychain._KeychainBufferPublication
            and publication._is_terminal_and_zero_for_credential_resolver(
                _authority=keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY,
            )
        )
        with self._lock:
            if (
                not clean
                or self._staged.get(owner.publication_id_snapshot) is not owner
                or owner.source_publication is not publication
                or owner.status != "staged"
            ):
                _raise_credential_policy_error()
            owner.source_publication = None

    def _issue_keychain_staged(
        self,
        *,
        owner: _CredentialStagingOwner,
        receipt: _CredentialStageReceipt,
        permit: CredentialResolutionPermit,
        operation_id: UUID,
        credential_injection_slot: CredentialInjectionSlot,
        credential_value_scheme: CredentialValueScheme,
    ) -> CredentialHandle:
        """Transfer the exact staged buffer into one handle state."""

        handle: CredentialHandle | None = None
        state: _HandleState | None = None
        storage: bytearray | None = None
        committed = False
        try:
            with owner.action_lock:
                with self._lock:
                    recovered = self._recover_keychain_stage_receipt(owner)
                    try:
                        receipt_snapshot = receipt._validated_snapshot()
                    except (TypeError, ValueError, AttributeError):
                        _raise_credential_policy_error()
                    if (
                        recovered is not receipt
                        or receipt_snapshot[0]
                        != owner.publication_id_snapshot
                        or receipt_snapshot[1] != owner.owner_id
                        or receipt_snapshot[2]
                        != owner.credential_binding_digest_snapshot
                        or receipt_snapshot[3] != owner.secret_length
                        or owner.permit is not permit
                        or owner.gate is not permit._attempt_gate
                        or owner.credential_binding_digest_snapshot
                        != permit.credential_binding_digest
                    ):
                        _raise_credential_policy_error()
                    owner.status = "transferring"
                    storage = owner.storage
                    secret_length = receipt_snapshot[3]
                assert type(storage) is bytearray
                handle = CredentialHandle(
                    slot_id=uuid4(),
                    permit=permit,
                    operation_id=operation_id,
                    credential_injection_slot=credential_injection_slot,
                    credential_value_scheme=credential_value_scheme,
                    ledger=self,
                    _authority=_HANDLE_FACTORY_AUTHORITY,
                )
                state = _HandleState(
                    handle=handle,
                    publication_id=owner.publication_id_snapshot,
                    permit=permit,
                    gate=permit._attempt_gate,
                    secret=storage,
                    secret_length=secret_length,
                )
                with self._lock:
                    if (
                        self._staged.get(owner.publication_id_snapshot)
                        is not owner
                        or owner.status != "transferring"
                        or owner.storage is not storage
                        or owner.receipt is not receipt
                        or owner.secret_length != secret_length
                        or owner.source_publication is not None
                        or handle in self._states
                    ):
                        _raise_credential_policy_error()
                    self._states[handle] = state
                    self._staged.pop(owner.publication_id_snapshot, None)
                    owner.storage = None
                    owner.secret_length = 0
                    owner.receipt = None
                    owner.source_publication = None
                    owner.permit = None
                    owner.gate = None
                    owner.status = "transferred"
                    committed = True
                return handle
        finally:
            if not committed:
                if handle is not None:
                    with self._lock:
                        self._states.pop(handle, None)
                if state is not None:
                    state.secret = None
                    state.secret_length = 0
                    state.permit = None
                    state.gate = None
                    state.publication_id = None
                    state.status = "closed"
                try:
                    self._close_keychain_owner(owner)
                finally:
                    # If interruption landed after the ledger maps changed but
                    # before the owner detach completed, ``storage`` is still
                    # the exact mutable buffer.  Never let that return gap drop
                    # the last recoverable zeroization capability.
                    if type(storage) is bytearray:
                        _best_effort_zero(storage)
                    with self._lock:
                        if owner.status not in ("terminal", "transferred"):
                            if (
                                self._staged.get(owner.publication_id_snapshot)
                                is not owner
                            ):
                                owner.storage = None
                                owner.source_publication = None
                                owner.secret_length = 0
                                owner.receipt = None
                                owner.permit = None
                                owner.gate = None
                                owner.status = "terminal"

    def _close_keychain_owner(
        self,
        owner: _CredentialStagingOwner,
    ) -> bool:
        """Retryable cleanup for one preheld/staged owner."""

        if type(owner) is not _CredentialStagingOwner:
            return False
        with owner.action_lock:
            storage: bytearray | None = None
            source_publication: object | None = None
            owner_key: UUID | None = None
            with self._lock:
                owner_keys = [
                    key
                    for key, candidate in self._staged.items()
                    if candidate is owner
                ]
                if len(owner_keys) != 1:
                    return False
                owner_key = owner_keys[0]
                if (
                    owner.status == "terminal"
                    and owner.storage is None
                    and owner.source_publication is None
                    and owner.secret_length == 0
                    and owner.receipt is None
                    and owner.permit is None
                    and owner.gate is None
                ):
                    return False
                owner.status = "closing"
                storage = owner.storage
                source_publication = owner.source_publication
            source_clean = source_publication is None
            try:
                if source_publication is not None:
                    from snapquiz.transport import (
                        _darwin_keychain_source as keychain,
                    )

                    if type(source_publication) is keychain._KeychainBufferPublication:
                        for _ in range(2):
                            source_is_clean = (
                                source_publication._is_terminal_and_zero_for_credential_resolver(
                                    _authority=(
                                        keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY
                                    ),
                                )
                            )
                            if source_is_clean:
                                break
                            source_publication.close()
                        source_clean = (
                            source_publication._is_terminal_and_zero_for_credential_resolver(
                                _authority=(
                                    keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY
                                ),
                            )
                        )
                if type(storage) is bytearray:
                    _best_effort_zero(storage)
            finally:
                with self._lock:
                    if (
                        owner_key is not None
                        and self._staged.get(owner_key) is owner
                        and owner.status == "closing"
                    ):
                        if (
                            not source_clean
                            or (type(storage) is bytearray and any(storage))
                        ):
                            owner.status = "cleanup_required"
                        else:
                            owner.storage = None
                            owner.source_publication = None
                            owner.secret_length = 0
                            owner.receipt = None
                            owner.permit = None
                            owner.gate = None
                            owner.status = "terminal"
            return owner.status == "terminal"

    def _recover_keychain_owner_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
    ) -> bool:
        with self._lock:
            owner = self._staged.get(publication_id)
            if owner is None:
                return False
            if (
                type(owner) is not _CredentialStagingOwner
                or not (
                    (
                        owner.permit is permit
                        and owner.gate is permit._attempt_gate
                    )
                    or (
                        owner.permit_id_snapshot == permit.permit_id
                        and owner.permit_digest_snapshot == permit.permit_digest
                        and owner.gate_id_snapshot == permit.gate_id
                    )
                )
            ):
                return False
        for _ in range(2):
            try:
                self._close_keychain_owner(owner)
            except BaseException:
                pass
            with self._lock:
                if (
                    owner.status == "terminal"
                    and owner.storage is None
                    and owner.permit is None
                    and owner.gate is None
                    and owner.receipt is None
                    and owner.source_publication is None
                ):
                    return True
        return False

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
                and current.secret_length == 0
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
                and state.secret_length == 0
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
                and state.secret_length == 0
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
        try:
            with self._lock:
                current = self._states.get(handle)
                if current is not state:
                    return False
                if current.status == "closed":
                    return False
                if current.status == "borrowing":
                    raise _credential_policy_error()
                # Capture the only mutable secret owner before detaching any
                # ledger field.  The finally block zeroes it even if an async
                # exception interrupts the multi-field terminal transition.
                secret = current.secret
                current.secret = None
                current.secret_length = 0
                current.permit = None
                current.gate = None
                current.publication_id = None
                current.status = "closed"
            return True
        finally:
            _best_effort_zero(secret)

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
                    current.secret_length = 0
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
                ("secret_length", 0),
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
                state.secret_length = 0
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
                    current.secret_length = 0
                    current.permit = None
                    current.gate = None
                    current.publication_id = None
                    current.status = "closed"
                if state is not None:
                    secret = getattr(state, "secret", None)
                    state.secret = None
                    state.secret_length = 0
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
                    ("secret_length", 0),
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
        staged_owners: list[_CredentialStagingOwner] = []
        try:
            with self._lock:
                for handle, state in tuple(self._states.items()):
                    if getattr(state, "permit", None) is permit:
                        self._states.pop(handle, None)
                        states.append(state)
                staged_owners = [
                    owner
                    for owner in self._staged.values()
                    if owner.permit is permit
                    or (
                        owner.permit_id_snapshot == permit.permit_id
                        and owner.permit_digest_snapshot == permit.permit_digest
                        and owner.gate_id_snapshot == permit.gate_id
                    )
                ]
                for state in states:
                    secrets.append(getattr(state, "secret", None))
                    state.secret = None
                    state.secret_length = 0
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
                    ("secret_length", 0),
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
        for owner in staged_owners:
            try:
                self._close_keychain_owner(owner)
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
                state.secret_length = 0
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
                    state.secret_length = 0
                    state.permit = None
                    state.gate = None
                    state.publication_id = None
                    state.status = "closed"
        except BaseException:
            if state is not None:
                for name, value in (
                    ("secret", None),
                    ("secret_length", 0),
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
        staged_owners: list[_CredentialStagingOwner] = []
        with self._lock:
            for state in self._states.values():
                if type(state.secret) is bytearray:
                    secrets.append(state.secret)
                state.secret = None
                state.secret_length = 0
                state.permit = None
                state.gate = None
                state.publication_id = None
                state.status = "closed"
            staged_owners = list(self._staged.values())
        for secret in secrets:
            _best_effort_zero(secret)
        for owner in staged_owners:
            try:
                self._close_keychain_owner(owner)
            except BaseException:
                pass

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


def _is_exact_darwin_keychain_source(source: object) -> bool:
    """Classify the private bridge without probing a source method."""

    from snapquiz.transport import _darwin_keychain_source as keychain

    return type(source) is keychain._DarwinKeychainCredentialSource


def _resolve_darwin_keychain_into_ledger(
    *,
    source: object,
    ledger: _CredentialLedger,
    permit: CredentialResolutionPermit,
    binding: CredentialBindingMetadata,
    operation: ExecutionPlanNetworkOperation,
    publication_id: UUID,
) -> CredentialHandle:
    """Bridge one caller-preheld Keychain value into its ledger owner.

    The only secret-bearing boundary is ``consume_once``'s read-only view.  The
    callback validates that view and copies it directly into the fixed mutable
    buffer already anchored by ``ledger`` before this function invokes any
    Keychain source or backend method.
    """

    from snapquiz.transport import _darwin_keychain_source as keychain

    if type(source) is not keychain._DarwinKeychainCredentialSource:
        raise TypeError("source must be the exact Darwin Keychain source")

    owner = ledger._prehold_keychain_owner(
        publication_id=publication_id,
        permit=permit,
    )
    publication: keychain._KeychainBufferPublication | None = None
    handle: CredentialHandle | None = None
    cleanup_error: BaseException | None = None
    try:
        # Publication construction is zero-I/O and follows the ledger anchor.
        publication = (
            keychain._new_keychain_buffer_publication_for_credential_resolver(
                _authority=keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY,
            )
        )
        ledger._attach_keychain_publication(owner, publication)
        receipt = source._read_exact_into_for_credential_resolver(
            binding.credential_ref,
            binding.credential_binding_digest,
            publication,
            _authority=keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY,
        )
        if type(receipt) is not keychain._KeychainReadReceipt:
            _raise_credential_error()
        try:
            (
                receipt_kind,
                receipt_binding_digest,
                receipt_resolver_binding_digest,
            ) = receipt._validated_snapshot()
        except (TypeError, ValueError, AttributeError):
            _raise_credential_error()
        if receipt_kind != "published":
            # This raises only a fresh, content-free typed failure after all
            # backend frames have returned and their tracebacks were cleared.
            receipt.raise_for_failure()
            raise AssertionError("unreachable")
        if (
            type(receipt_binding_digest) is not Digest256
            or receipt_resolver_binding_digest
            != binding.credential_binding_digest
        ):
            _raise_credential_policy_error()
        receipt = None

        def stage(view: memoryview) -> None:
            ledger._stage_keychain_view(owner, view)

        publication.consume_once(stage)
        stage = None  # type: ignore[assignment]
        if not publication._is_terminal_and_zero_for_credential_resolver(
            _authority=keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY,
        ):
            _raise_credential_policy_error()
        ledger._release_clean_keychain_publication(owner, publication)
        stage_receipt = ledger._recover_keychain_stage_receipt(owner)
        if type(stage_receipt) is not _CredentialStageReceipt:
            _raise_credential_policy_error()
        handle = ledger._issue_keychain_staged(
            owner=owner,
            receipt=stage_receipt,
            permit=permit,
            operation_id=operation.operation_id,
            credential_injection_slot=binding.credential_injection_slot,
            credential_value_scheme=binding.credential_value_scheme,
        )
        return handle
    finally:
        primary_is_active = sys.exc_info()[0] is not None
        if publication is not None:
            for _ in range(2):
                try:
                    if publication._is_terminal_and_zero_for_credential_resolver(
                        _authority=(
                            keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY
                        ),
                    ):
                        break
                    publication.close()
                except BaseException as error:
                    cleanup_error = error
            try:
                publication_clean = (
                    publication._is_terminal_and_zero_for_credential_resolver(
                        _authority=(
                            keychain._CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY
                        ),
                    )
                )
            except BaseException as error:
                publication_clean = False
                cleanup_error = error
            if publication_clean:
                cleanup_error = None
        if handle is None:
            try:
                if ledger._recover_keychain_owner_for_cleanup(
                    permit,
                    publication_id=publication_id,
                ):
                    cleanup_error = None
            except BaseException as error:
                cleanup_error = error
        # Any exceptional traceback can retain these locals, but by this point
        # they are either terminal/zero or still anchored for exact retry.
        publication = None
        owner = None  # type: ignore[assignment]
        if cleanup_error is not None and not primary_is_active:
            _raise_credential_policy_error()


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
            if _is_exact_darwin_keychain_source(self._source):
                handle = _resolve_darwin_keychain_into_ledger(
                    source=self._source,
                    ledger=self._ledger,
                    permit=permit,
                    binding=binding,
                    operation=operation,
                    publication_id=exact_publication_id,
                )
            else:
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

    def _recover_preheld_keychain_owner_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Retry cleanup of a source/ledger owner retained before publication."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential cleanup recovery requires transport")
        if (
            type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
        ):
            return False
        return self._ledger._recover_keychain_owner_for_cleanup(
            permit,
            publication_id=publication_id,
        )

    def _preheld_keychain_owner_is_closed_for_cleanup(
        self,
        permit: CredentialResolutionPermit,
        *,
        publication_id: UUID,
        _authority: object | None = None,
    ) -> bool:
        """Observe exact terminal/zero pre-publication ownership state."""

        if _authority is not _TRANSPORT_ATTEMPT_AUTHORITY:
            raise TypeError("credential cleanup observation requires transport")
        if (
            type(permit) is not CredentialResolutionPermit
            or type(publication_id) is not UUID
        ):
            return False
        with self._ledger._lock:
            owner = self._ledger._staged.get(publication_id)
            if type(owner) is not _CredentialStagingOwner:
                return False
            return (
                owner.publication_id_snapshot == publication_id
                and owner.permit_id_snapshot == permit.permit_id
                and owner.permit_digest_snapshot == permit.permit_digest
                and owner.gate_id_snapshot == permit.gate_id
                and owner.status == "terminal"
                and owner.storage is None
                and owner.source_publication is None
                and owner.secret_length == 0
                and owner.receipt is None
                and owner.permit is None
                and owner.gate is None
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
        # Snapshot the exact ledger state before ``_release_info`` publishes
        # ``closing``.  If an asynchronous exception lands after that write but
        # before its tuple reaches this frame, the finally block can still
        # restore the uncommitted claim or finish an already-terminal Gate.
        recovery_state: _HandleState | None = None
        claimed_by_this_call = False
        state: _HandleState | None = None
        permit: CredentialResolutionPermit | None = None
        gate: AttemptGate | None = None
        try:
            with self._ledger._lock:
                recovery_state = self._ledger._lookup_exact_locked(handle)
                claimed_by_this_call = recovery_state.status == "active"
                state, permit, gate, integrity_is_valid = (
                    self._ledger._release_info(handle)
                )
            if permit is None or gate is None:
                if not integrity_is_valid:
                    _raise_credential_policy_error()
                return False
            return self._close_claimed(
                handle,
                state,
                permit,
                gate,
                integrity_is_valid,
            )
        finally:
            primary_is_active = sys.exc_info()[0] is not None
            cleanup_error: BaseException | None = None
            recovery_secret: object | None = None
            try:
                with self._ledger._lock:
                    still_closing = (
                        claimed_by_this_call
                        and recovery_state is not None
                        and self._ledger._states.get(handle) is recovery_state
                        and recovery_state.status == "closing"
                    )
                    recovery_permit = (
                        recovery_state.permit
                        if recovery_state is not None
                        else None
                    )
                    recovery_gate = (
                        recovery_state.gate
                        if recovery_state is not None
                        else None
                    )
                if still_closing:
                    assert recovery_state is not None
                    gate_is_terminal = False
                    if (
                        type(recovery_permit) is CredentialResolutionPermit
                        and type(recovery_gate) is AttemptGate
                    ):
                        try:
                            gate_is_terminal = (
                                recovery_gate._credential_resolution_is_terminal_for_cleanup(
                                    recovery_permit,
                                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                                )
                            )
                        except BaseException:
                            # Fall back to the same exact private Gate entry.
                            # This avoids reviving a credential after Gate
                            # terminalization merely because an observer wrapper
                            # was interrupted.
                            try:
                                with recovery_gate._lock:
                                    gate_state = (
                                        recovery_gate._credential_permits.get(
                                            recovery_permit.permit_id
                                        )
                                    )
                                    gate_is_terminal = (
                                        gate_state is not None
                                        and gate_state.permit is recovery_permit
                                        and gate_state.status
                                        in ("abandoned", "finished")
                                    )
                            except BaseException:
                                gate_is_terminal = False
                    try:
                        if gate_is_terminal:
                            self._ledger._force_close_after_gate(
                                handle,
                                recovery_state,
                            )
                        else:
                            self._ledger._restore_active_after_gate_failure(
                                handle,
                                recovery_state,
                            )
                    except BaseException as error:
                        cleanup_error = error
                    # Bypass a faulting/no-op cleanup wrapper with the exact
                    # state already claimed by this invocation.  Terminal Gate
                    # state closes and zeroes; precommit state is retryable.
                    try:
                        with self._ledger._lock:
                            if (
                                self._ledger._states.get(handle)
                                is recovery_state
                            ):
                                if (
                                    gate_is_terminal
                                    and recovery_state.status != "closed"
                                ):
                                    recovery_secret = recovery_state.secret
                                    recovery_state.secret = None
                                    recovery_state.secret_length = 0
                                    recovery_state.permit = None
                                    recovery_state.gate = None
                                    recovery_state.publication_id = None
                                    recovery_state.status = "closed"
                                elif recovery_state.status == "closing":
                                    recovery_state.status = "active"
                    except BaseException as error:
                        if cleanup_error is None:
                            cleanup_error = error
            except BaseException as error:
                cleanup_error = error
            finally:
                _best_effort_zero(recovery_secret)
            # Do not leave an exceptional public close frame holding the
            # private state/permit/Gate graph after cleanup.
            state = None
            permit = None
            gate = None
            recovery_permit = None
            recovery_gate = None
            recovery_state = None
            recovery_secret = None
            if cleanup_error is not None and not primary_is_active:
                raise cleanup_error

    def _close_claimed(
        self,
        handle: CredentialHandle,
        state: _HandleState,
        permit: CredentialResolutionPermit,
        gate: AttemptGate,
        integrity_is_valid: bool,
    ) -> bool:
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
            try:
                self._ledger._restore_active_after_gate_failure(handle, state)
            except BaseException:
                # The public close wrapper owns an exact finally fallback.  A
                # cleanup fault here must not replace the Gate transition error.
                pass
            if gate_error is None:
                gate_error = _credential_policy_error()
            raise gate_error
        changed = False
        close_error: BaseException | None = None
        force_error: BaseException | None = None
        try:
            changed = self._ledger._close_after_gate(handle, state)
        except BaseException as error:
            close_error = error
        try:
            changed = (
                self._ledger._force_close_after_gate(handle, state)
                or changed
            )
        except BaseException as error:
            force_error = error
        if gate_committed_after_error:
            assert gate_error is not None
            raise gate_error
        if close_error is not None:
            raise close_error
        if not integrity_is_valid:
            _raise_credential_policy_error()
        if force_error is not None:
            raise force_error
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
        """Borrow once without exposing the Gate's private borrow owner.

        Existing trusted consumers that only need the credential continue to
        use this narrow wrapper.  The exact transport path uses
        ``_borrow_once_with_owner`` so its wire-start commit can be bound to
        the same active borrow instead of inspecting Gate internals.
        """

        if not callable(action):
            raise TypeError("action must be callable")
        return self._borrow_once_with_owner(
            handle,
            attempt_permit,
            lambda secret, _borrow_id: action(secret),
            _authority=_authority,
        )

    def _borrow_once_with_owner(
        self,
        handle: CredentialHandle,
        attempt_permit: AttemptPermit,
        action: Callable[[memoryview, UUID], _ResultT],
        *,
        _authority: object | None = None,
    ) -> _ResultT:
        """Borrow once and pass the exact active Gate owner to Transport.

        The owner is valid only for the dynamic extent of ``action``.  It is
        the only supported bridge to ``AttemptGate._commit_wire_start``;
        callers must never derive it by reading private Gate state.
        """

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

        def borrow_secret() -> _ResultT:
            secret: bytearray | None = None
            secret_length = 0
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
                        # Capture the mutable buffer before detaching the
                        # ledger, so every later exit can zero it.
                        secret = state.secret
                        state.secret = None
                        state.secret_length = 0
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
                            type(state.secret_length) is int,
                            1
                            <= state.secret_length
                            <= (
                                len(state.secret)
                                if type(state.secret) is bytearray
                                else 0
                            ),
                        )
                        if all(exact):
                            # Capture first, publish ``borrowing`` second.  The
                            # finally block already owns the exact buffer if an
                            # async exception lands after this transition.
                            secret = state.secret
                            secret_length = state.secret_length
                            state.status = "borrowing"

                if not integrity_is_valid:
                    _raise_credential_policy_error()
                if secret is None or not all(exact):
                    _raise_credential_policy_error()

                writable_view = memoryview(secret)[:secret_length]
                readonly_view = writable_view.toreadonly()
                writable_view.release()
                writable_view = None
                return action(readonly_view, borrow_id)
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
                if type(secret) is bytearray:
                    try:
                        self._ledger._finish_borrow(handle, secret)
                    except BaseException:
                        # The force path has the exact mutable buffer and closes
                        # the ledger before the Gate marker can be released.
                        pass
                    try:
                        self._ledger._force_finish_borrow(handle, secret)
                    except BaseException:
                        # Preserve an action primary even if a cleanup wrapper
                        # faults before entering its own non-throwing body.
                        try:
                            with self._ledger._lock:
                                state = self._ledger._states.get(handle)
                                if state is not None and state.handle is handle:
                                    state.secret = None
                                    state.secret_length = 0
                                    state.permit = None
                                    state.gate = None
                                    state.publication_id = None
                                    state.status = "closed"
                        except BaseException:
                            pass
                        _best_effort_zero(secret)

        # The Gate marker and its observation share one dynamic try/finally
        # with secret acquisition and callback execution.  Cleanup faults are
        # recorded separately so they cannot replace a callback primary.
        primary: BaseException | None = None
        primary_traceback: object | None = None
        cleanup_error: BaseException | None = None
        result: _ResultT
        try:
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
                result = borrow_secret()
            except BaseException as error:
                primary = error
                primary_traceback = error.__traceback__
        finally:
            try:
                self._release_gate_borrow_marker(
                    gate,
                    attempt_permit,
                    borrow_id=borrow_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                )
            except BaseException as error:
                cleanup_error = error
                # The normal helper already retried and used the Gate force
                # path.  Its final fallback may itself have been wrapped or
                # interrupted, so clear only this exact private owner directly.
                try:
                    with gate._lock:
                        state = gate._attempt_permits.get(
                            attempt_permit.attempt_permit_id
                        )
                        if (
                            state is not None
                            and state.permit is attempt_permit
                            and state.status in ("io_claimed", "wire_committed")
                            and state.credential_borrow_id == borrow_id
                            and attempt_permit.credential_handle_id == handle_id
                            and attempt_permit.credential_handle_digest
                            == handle_digest
                            and gate._wire_state_is_well_formed(state)
                        ):
                            gate._require_attempt_credential_proof_locked(
                                attempt_permit
                            )
                            state.credential_borrow_id = None
                except BaseException:
                    pass
            try:
                marker_is_active = gate._credential_borrow_is_active(
                    attempt_permit,
                    borrow_id=borrow_id,
                    handle_id=handle_id,
                    handle_digest=handle_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException:
                marker_is_active = True
            if not marker_is_active:
                cleanup_error = None

        if primary is not None:
            raise primary.with_traceback(primary_traceback)  # type: ignore[arg-type]
        if cleanup_error is not None:
            raise cleanup_error
        return result


__all__ = [
    "CREDENTIAL_HANDLE_SCHEMA_VERSION",
    "CREDENTIAL_RESOLVER_POLICY_VERSION",
    "MAX_CREDENTIAL_BYTES",
    "CredentialHandle",
    "CredentialResolver",
    "CredentialSource",
]
