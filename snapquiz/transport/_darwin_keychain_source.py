"""Fail-closed Darwin Keychain credential-source foundation for W09.

The active built-in profile still names the historical ``env:GLM_API_KEY``
locator.  This module therefore does not change production behaviour and does
not read Keychain on import or construction.  It freezes the narrower source
contract that a later signed application can bind to an exact generic-password
service/account/access-group tuple.

Only the injected test factory is available today.  The production factory
fails before constructing or calling a backend until the bundle identifiers,
Team identity, access group, and credential binding have been reviewed and
content-addressed by the application manifest.
"""
from __future__ import annotations

from threading import Lock, RLock, get_ident
from typing import Callable, Protocol

from snapquiz.domain._validation import require_digest, runtime_final
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CancelledError, ConfigError, TimeoutError


__all__ = ()


DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION = "snapquiz.darwin-keychain-source.v1"
DARWIN_KEYCHAIN_LOCATOR_SCHEME = "keychain-generic-password:v1"
PRODUCTION_CREDENTIAL_SOURCE_BINDING_ATTESTATION_VERSION = (
    "snapquiz.production-credential-source-binding.v1"
)
DARWIN_KEYCHAIN_SOURCE_FOUNDATION_AVAILABLE = True
PRODUCTION_DARWIN_KEYCHAIN_SOURCE_AVAILABLE = False

_BINDING_AUTHORITY = object()
_SOURCE_AUTHORITY = object()
_TEST_SOURCE_AUTHORITY = object()
_PUBLICATION_AUTHORITY = object()
_TEST_PUBLICATION_AUTHORITY = object()
_READ_RECEIPT_AUTHORITY = object()
_WRITER_AUTHORITY = object()
_CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY = object()
_MAX_LABEL_BYTES = 512
_MAX_CREDENTIAL_BYTES = 4_096


class _KeychainBackend(Protocol):
    """Narrow backend implemented by a future reviewed Security.framework edge."""

    def copy_generic_password(
        self,
        *,
        service: str,
        account: str,
        access_group: str | None,
        writer: "_KeychainPublicationWriter",
    ) -> None:
        """Publish one fresh mutable value and relinquish it before returning."""


def _source_error() -> ConfigError:
    error = ConfigError(
        stage="credential_source",
        retryable=False,
        safe_message="生产凭据来源尚未就绪。",
    )
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_source_error() -> None:
    raise _source_error() from None


def _flow_error(kind: str) -> CancelledError | TimeoutError:
    if kind == "cancelled":
        error: CancelledError | TimeoutError = CancelledError(
            stage="credential_source",
            retryable=False,
            safe_message="操作已取消。",
        )
    elif kind == "timeout":
        error = TimeoutError(
            stage="credential_source",
            retryable=True,
            safe_message="模型服务请求超时。",
        )
    else:  # pragma: no cover - private caller invariant
        raise AssertionError("unknown credential-source flow error")
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_source_failure(kind: str) -> None:
    if kind in ("cancelled", "timeout"):
        raise _flow_error(kind) from None
    _raise_source_error()


def _best_effort_zero(buffer: bytearray) -> None:
    """Overwrite fixed publication storage without resizing it."""

    fallback_required = False
    try:
        buffer[:] = b"\x00" * len(buffer)
    except BaseException as failure:
        # Drop the first interruption before entering the fallback.  If the
        # fallback is interrupted too, it must not expose the first traceback
        # (whose frame still referenced the buffer being erased).
        try:
            failure.__traceback__ = None
            failure.__cause__ = None
            failure.__context__ = None
            failure.__suppress_context__ = True
        except BaseException:
            pass
        failure = None
        fallback_required = True
    if fallback_required:
        # If the allocation-free fallback is itself interrupted, propagate so
        # the caller-preheld owner remains non-terminal and can retry cleanup.
        for index in range(len(buffer)):
            buffer[index] = 0


@runtime_final
class _KeychainReadReceipt:
    """Content-free result that can be raised after the source frame is gone."""

    __slots__ = (
        "kind",
        "binding_digest",
        "resolver_binding_digest",
        "receipt_digest",
        "_issued_digest",
    )

    def __init__(
        self,
        kind: str,
        *,
        binding_digest: Digest256 | None = None,
        resolver_binding_digest: Digest256 | None = None,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _READ_RECEIPT_AUTHORITY:
            raise TypeError("Keychain read receipts require their factory")
        if kind not in ("published", "cancelled", "timeout", "source"):
            raise ValueError("invalid Keychain read receipt")
        if kind == "published":
            require_digest(binding_digest, "binding_digest")
            if resolver_binding_digest is not None:
                require_digest(
                    resolver_binding_digest,
                    "resolver_binding_digest",
                )
        elif binding_digest is not None or resolver_binding_digest is not None:
            raise ValueError("failed Keychain receipts cannot bind a query")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "binding_digest", binding_digest)
        object.__setattr__(
            self,
            "resolver_binding_digest",
            resolver_binding_digest,
        )
        selected = digest256(
            "DarwinKeychainReadReceipt",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "kind": kind,
                "binding_digest": binding_digest,
                "resolver_binding_digest": resolver_binding_digest,
            },
        )
        object.__setattr__(self, "receipt_digest", selected)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("Keychain read receipts are immutable")

    def __repr__(self) -> str:
        return f"_KeychainReadReceipt(kind={self.kind!r}, <content-free>)"

    def __copy__(self) -> object:
        raise TypeError("Keychain read receipts cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("Keychain read receipts cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("Keychain read receipts cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("Keychain read receipts cannot be serialized")

    def _validated_snapshot(
        self,
    ) -> tuple[str, Digest256 | None, Digest256 | None]:
        kind = self.kind
        binding_digest = self.binding_digest
        resolver_binding_digest = self.resolver_binding_digest
        receipt_digest = self.receipt_digest
        issued_digest = self._issued_digest
        if kind not in ("published", "cancelled", "timeout", "source"):
            raise ValueError("invalid Keychain read receipt")
        if kind == "published":
            require_digest(binding_digest, "binding_digest")
            if resolver_binding_digest is not None:
                require_digest(
                    resolver_binding_digest,
                    "resolver_binding_digest",
                )
        elif binding_digest is not None or resolver_binding_digest is not None:
            raise ValueError("failed Keychain receipt binds a query")
        require_digest(receipt_digest, "receipt_digest")
        require_digest(issued_digest, "issued_digest")
        expected = digest256(
            "DarwinKeychainReadReceipt",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "kind": kind,
                "binding_digest": binding_digest,
                "resolver_binding_digest": resolver_binding_digest,
            },
        )
        if receipt_digest != expected or issued_digest != expected:
            raise ValueError("Keychain read receipt integrity failed")
        if (
            self.kind,
            self.binding_digest,
            self.resolver_binding_digest,
            self.receipt_digest,
            self._issued_digest,
        ) != (
            kind,
            binding_digest,
            resolver_binding_digest,
            receipt_digest,
            issued_digest,
        ):
            raise ValueError("Keychain read receipt changed during validation")
        return kind, binding_digest, resolver_binding_digest

    def validate_integrity(self) -> None:
        self._validated_snapshot()

    @property
    def succeeded(self) -> bool:
        return self._validated_snapshot()[0] == "published"

    def raise_for_failure(self) -> None:
        kind = self._validated_snapshot()[0]
        if kind != "published":
            _raise_source_failure(kind)


def _new_read_receipt(
    kind: str,
    binding_digest: Digest256 | None = None,
    resolver_binding_digest: Digest256 | None = None,
) -> _KeychainReadReceipt:
    return _KeychainReadReceipt(
        kind,
        binding_digest=binding_digest,
        resolver_binding_digest=resolver_binding_digest,
        _authority=_READ_RECEIPT_AUTHORITY,
    )


def _require_label(
    value: object,
    name: str,
    *,
    optional: bool = False,
) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ValueError(f"{name} must be valid UTF-8") from None
    if len(encoded) > _MAX_LABEL_BYTES:
        raise ValueError(f"{name} is too long")
    if any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in value
    ):
        raise ValueError(f"{name} contains control characters")
    return value


@runtime_final
class _KeychainPublicationWriter:
    """One exact backend's non-transferable publication capability."""

    __slots__ = ("_publication", "_nonce", "_thread_id")

    def __init__(
        self,
        publication: "_KeychainBufferPublication",
        nonce: object,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _WRITER_AUTHORITY:
            raise TypeError("Keychain writers require their publication")
        object.__setattr__(self, "_publication", publication)
        object.__setattr__(self, "_nonce", nonce)
        object.__setattr__(self, "_thread_id", get_ident())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("Keychain writers are immutable")

    def __copy__(self) -> object:
        raise TypeError("Keychain writers cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("Keychain writers cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("Keychain writers cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("Keychain writers cannot be serialized")

    def __repr__(self) -> str:
        return "_KeychainPublicationWriter(<private>)"

    def publish(self, value: bytearray) -> None:
        self._publication._publish_claimed(self, value)


@runtime_final
class _KeychainBufferPublication:
    """Caller-preheld, fixed-capacity owner for one Keychain value.

    The storage exists before the backend is invoked.  A conforming backend
    copies through the exact one-shot writer capability and relinquishes its
    temporary mutable buffer before returning.  The value can then be
    presented exactly once to a trusted callback as a read-only view.  Both
    normal and callback-exception completion release the view and overwrite the
    fixed-capacity storage before terminality.  If Python itself interrupts the
    cleanup instructions, the caller still owns this object and must retry
    :meth:`close` until terminal and zero are observed.

    This is deliberately not a ``CredentialSource``: no method returns secret
    bytes or a mutable buffer across a Python return boundary.
    """

    __slots__ = (
        "_storage",
        "_length",
        "_state",
        "_claim_digest",
        "_receipt_resolver_binding_digest",
        "_outcome_kind",
        "_writer",
        "_writer_nonce",
        "_lock",
        "_action_lock",
    )

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _PUBLICATION_AUTHORITY:
            raise TypeError("Keychain publications require their factory")
        object.__setattr__(self, "_storage", bytearray(_MAX_CREDENTIAL_BYTES))
        object.__setattr__(self, "_length", 0)
        object.__setattr__(self, "_state", "empty")
        object.__setattr__(self, "_claim_digest", None)
        object.__setattr__(self, "_receipt_resolver_binding_digest", None)
        object.__setattr__(self, "_outcome_kind", None)
        object.__setattr__(self, "_writer", None)
        object.__setattr__(self, "_writer_nonce", None)
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_action_lock", RLock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("Keychain publications are immutable")

    def __copy__(self) -> object:
        raise TypeError("Keychain publications cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("Keychain publications cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("Keychain publications cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("Keychain publications cannot be serialized")

    def __repr__(self) -> str:
        return "_KeychainBufferPublication(<private>)"

    def _is_empty(self) -> bool:
        with self._lock:
            return (
                self._state == "empty"
                and self._length == 0
                and self._claim_digest is None
                and self._receipt_resolver_binding_digest is None
                and self._outcome_kind is None
                and self._writer is None
                and self._writer_nonce is None
            )

    def _claim_read(
        self,
        binding_digest: Digest256,
    ) -> _KeychainPublicationWriter | None:
        require_digest(binding_digest, "binding_digest")
        nonce = object()
        writer = _KeychainPublicationWriter(
            self,
            nonce,
            _authority=_WRITER_AUTHORITY,
        )
        with self._lock:
            if (
                self._state != "empty"
                or self._length != 0
                or self._claim_digest is not None
                or self._receipt_resolver_binding_digest is not None
                or self._outcome_kind is not None
                or self._writer is not None
                or self._writer_nonce is not None
            ):
                return None
            object.__setattr__(self, "_claim_digest", binding_digest)
            object.__setattr__(self, "_writer", writer)
            object.__setattr__(self, "_writer_nonce", nonce)
            object.__setattr__(self, "_state", "reading")
            return writer

    def _is_claimed_by(
        self,
        writer: _KeychainPublicationWriter,
        binding_digest: Digest256,
    ) -> bool:
        with self._lock:
            return (
                type(writer) is _KeychainPublicationWriter
                and writer is self._writer
                and writer._publication is self
                and writer._nonce is self._writer_nonce
                and writer._thread_id == get_ident()
                and self._claim_digest == binding_digest
                and self._state in ("reading", "staged")
            )

    def has_value(self) -> bool:
        with self._lock:
            return (
                self._state == "published"
                and self._outcome_kind == "published"
            )

    def is_terminal(self) -> bool:
        with self._lock:
            return self._state == "terminal"

    def _publish_claimed(
        self,
        writer: _KeychainPublicationWriter,
        value: bytearray,
    ) -> None:
        """Copy one backend value into pre-existing owned storage.

        The supplied mutable buffer is overwritten even if validation, copy,
        or publication fails.  It must be a fresh backend-owned value; keeping
        aliases after this call is outside the reviewed backend contract.
        """

        with self._action_lock:
            try:
                if type(value) is not bytearray:
                    raise TypeError("Keychain publication requires bytearray")
                length = len(value)
                if not 1 <= length <= _MAX_CREDENTIAL_BYTES:
                    raise ValueError("Keychain value length is invalid")
                with self._lock:
                    if (
                        self._state != "reading"
                        or self._length != 0
                        or type(self._claim_digest) is not Digest256
                        or self._outcome_kind is not None
                        or type(writer) is not _KeychainPublicationWriter
                        or writer is not self._writer
                        or writer._publication is not self
                        or writer._nonce is not self._writer_nonce
                        or writer._thread_id != get_ident()
                    ):
                        raise ValueError("Keychain writer is not current")
                    # Secret bytes land in storage that the caller already
                    # owns.  If this assignment is interrupted, the source's
                    # failure path closes and overwrites the whole storage.
                    self._storage[:length] = value
                    object.__setattr__(self, "_length", length)
                    # The value is deliberately not consumable until the
                    # backend has returned normally and the source has
                    # revalidated the exact frozen query snapshot.
                    object.__setattr__(self, "_state", "staged")
            finally:
                if isinstance(value, bytearray):
                    _best_effort_zero(value)

    def _seal_success(
        self,
        writer: _KeychainPublicationWriter,
        binding_digest: Digest256,
        *,
        resolver_binding_digest: Digest256 | None = None,
    ) -> _KeychainReadReceipt | None:
        require_digest(binding_digest, "binding_digest")
        if resolver_binding_digest is not None:
            require_digest(
                resolver_binding_digest,
                "resolver_binding_digest",
            )
        with self._lock:
            if (
                self._state != "staged"
                or self._outcome_kind is not None
                or self._length < 1
                or self._claim_digest != binding_digest
                or type(writer) is not _KeychainPublicationWriter
                or writer is not self._writer
                or writer._publication is not self
                or writer._nonce is not self._writer_nonce
                or writer._thread_id != get_ident()
            ):
                return None
            object.__setattr__(self, "_state", "published")
            object.__setattr__(self, "_outcome_kind", "published")
            object.__setattr__(
                self,
                "_receipt_resolver_binding_digest",
                resolver_binding_digest,
            )
            object.__setattr__(self, "_writer", None)
            object.__setattr__(self, "_writer_nonce", None)
        return _new_read_receipt(
            "published",
            binding_digest,
            resolver_binding_digest,
        )

    def consume_once(self, callback: Callable[[memoryview], None]) -> None:
        """Invoke one trusted consumer with caller-recoverable erase cleanup."""

        if not callable(callback):
            raise TypeError("callback must be callable")
        view: memoryview | None = None
        with self._action_lock:
            try:
                with self._lock:
                    if self._state != "published":
                        raise ValueError("Keychain value is not consumable")
                    object.__setattr__(self, "_state", "consuming")
                    length = self._length
                view = memoryview(self._storage)[:length].toreadonly()
                result = callback(view)
                invalid_result = result is not None
                result = None
                if invalid_result:
                    raise TypeError("Keychain consumer must return None")
            finally:
                if view is not None:
                    try:
                        view.release()
                    except BaseException:
                        pass
                _best_effort_zero(self._storage)
                with self._lock:
                    object.__setattr__(self, "_length", 0)
                    object.__setattr__(self, "_writer", None)
                    object.__setattr__(self, "_writer_nonce", None)
                    object.__setattr__(self, "_state", "terminal")

    def _finish_failure(self, kind: str) -> _KeychainReadReceipt:
        if kind not in ("cancelled", "timeout", "source"):
            kind = "source"
        with self._action_lock:
            with self._lock:
                if self._state == "terminal":
                    selected = self._outcome_kind
                    if selected not in ("cancelled", "timeout", "source"):
                        selected = kind
                    return _new_read_receipt(selected)
                object.__setattr__(self, "_state", "closing")
            _best_effort_zero(self._storage)
            with self._lock:
                object.__setattr__(self, "_length", 0)
                object.__setattr__(self, "_outcome_kind", kind)
                object.__setattr__(
                    self,
                    "_receipt_resolver_binding_digest",
                    None,
                )
                object.__setattr__(self, "_writer", None)
                object.__setattr__(self, "_writer_nonce", None)
                object.__setattr__(self, "_state", "terminal")
        return _new_read_receipt(kind)

    def recover_read_receipt(
        self,
        *,
        _authority: object | None = None,
    ) -> _KeychainReadReceipt:
        if (
            _authority is not _TEST_SOURCE_AUTHORITY
            and _authority is not _CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY
        ):
            return _new_read_receipt("source")
        with self._lock:
            kind = self._outcome_kind
            state = self._state
            binding_digest = self._claim_digest
            resolver_binding_digest = self._receipt_resolver_binding_digest
        if kind == "published" and state in (
            "published",
            "consuming",
            "terminal",
        ):
            if type(binding_digest) is Digest256:
                return _new_read_receipt(
                    "published",
                    binding_digest,
                    resolver_binding_digest,
                )
            return _new_read_receipt("source")
        if kind in ("cancelled", "timeout", "source") and state == "terminal":
            return _new_read_receipt(kind)
        return _new_read_receipt("source")

    def close(self) -> bool:
        """Make the publication terminal and erase any partial/late value."""

        with self._action_lock:
            with self._lock:
                if self._state == "terminal":
                    return False
                object.__setattr__(self, "_state", "closing")
            _best_effort_zero(self._storage)
            with self._lock:
                object.__setattr__(self, "_length", 0)
                object.__setattr__(self, "_outcome_kind", "source")
                object.__setattr__(
                    self,
                    "_receipt_resolver_binding_digest",
                    None,
                )
                object.__setattr__(self, "_writer", None)
                object.__setattr__(self, "_writer_nonce", None)
                object.__setattr__(self, "_state", "terminal")
            return True

    def _storage_is_zero_for_test(self) -> bool:
        return not any(self._storage)

    def _is_terminal_and_zero_for_credential_resolver(
        self,
        *,
        _authority: object | None = None,
    ) -> bool:
        if _authority is not _CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY:
            return False
        with self._lock:
            terminal = self._state == "terminal" and self._length == 0
        return terminal and not any(self._storage)


def _new_keychain_buffer_publication_for_test(
    *,
    _authority: object | None = None,
) -> _KeychainBufferPublication:
    if _authority is not _TEST_PUBLICATION_AUTHORITY:
        raise TypeError("test Keychain publications require test authority")
    return _KeychainBufferPublication(_authority=_PUBLICATION_AUTHORITY)


def _new_keychain_buffer_publication_for_credential_resolver(
    *,
    _authority: object | None = None,
) -> _KeychainBufferPublication:
    """Issue the exact caller-owned publication used by CredentialResolver."""

    if _authority is not _CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY:
        raise TypeError("Keychain resolver publications require resolver authority")
    return _KeychainBufferPublication(_authority=_PUBLICATION_AUTHORITY)


@runtime_final
class _DarwinKeychainBinding:
    """Immutable exact locator-to-Keychain-query binding."""

    __slots__ = (
        "credential_ref",
        "service",
        "account",
        "access_group",
        "binding_digest",
        "_issued_digest",
        "resolver_credential_ref",
        "resolver_binding_digest",
        "resolver_mapping_digest",
        "_issued_resolver_mapping_digest",
    )

    def __init__(
        self,
        *,
        credential_ref: str,
        service: str,
        account: str,
        access_group: str | None,
        resolver_credential_ref: str | None = None,
        resolver_binding_digest: Digest256 | None = None,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _BINDING_AUTHORITY:
            raise TypeError("Keychain bindings require their factory")
        selected_ref = _require_label(credential_ref, "credential_ref")
        selected_service = _require_label(service, "service")
        selected_account = _require_label(account, "account")
        selected_group = _require_label(
            access_group,
            "access_group",
            optional=True,
        )
        assert selected_ref is not None
        assert selected_service is not None
        assert selected_account is not None
        if not selected_ref.startswith(f"{DARWIN_KEYCHAIN_LOCATOR_SCHEME}:"):
            raise ValueError("credential_ref uses another source scheme")
        if (resolver_credential_ref is None) != (
            resolver_binding_digest is None
        ):
            raise ValueError("resolver mapping must be supplied as one exact pair")
        selected_resolver_ref = _require_label(
            resolver_credential_ref,
            "resolver_credential_ref",
            optional=True,
        )
        if resolver_binding_digest is not None:
            require_digest(
                resolver_binding_digest,
                "resolver_binding_digest",
            )

        object.__setattr__(self, "credential_ref", selected_ref)
        object.__setattr__(self, "service", selected_service)
        object.__setattr__(self, "account", selected_account)
        object.__setattr__(self, "access_group", selected_group)
        selected_digest = digest256(
            "DarwinKeychainBinding",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "credential_ref": selected_ref,
                "service": selected_service,
                "account": selected_account,
                "access_group": selected_group,
            },
        )
        object.__setattr__(self, "binding_digest", selected_digest)
        object.__setattr__(self, "_issued_digest", selected_digest)
        object.__setattr__(
            self,
            "resolver_credential_ref",
            selected_resolver_ref,
        )
        object.__setattr__(
            self,
            "resolver_binding_digest",
            resolver_binding_digest,
        )
        selected_mapping_digest = digest256(
            "DarwinKeychainResolverMapping",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "keychain_binding_digest": selected_digest,
                "resolver_credential_ref": selected_resolver_ref,
                "resolver_binding_digest": resolver_binding_digest,
            },
        )
        object.__setattr__(
            self,
            "resolver_mapping_digest",
            selected_mapping_digest,
        )
        object.__setattr__(
            self,
            "_issued_resolver_mapping_digest",
            selected_mapping_digest,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("Darwin Keychain bindings are immutable")

    def __copy__(self) -> object:
        raise TypeError("Darwin Keychain bindings cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("Darwin Keychain bindings cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("Darwin Keychain bindings cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("Darwin Keychain bindings cannot be serialized")

    def validate_integrity(self) -> None:
        self._validated_snapshot()
        self._validated_resolver_mapping_snapshot()

    def _validated_snapshot(
        self,
    ) -> tuple[str, str, str, str | None, Digest256]:
        credential_ref = self.credential_ref
        service = self.service
        account = self.account
        access_group = self.access_group
        binding_digest = self.binding_digest
        issued_digest = self._issued_digest
        require_digest(binding_digest, "binding_digest")
        expected = digest256(
            "DarwinKeychainBinding",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "credential_ref": credential_ref,
                "service": service,
                "account": account,
                "access_group": access_group,
            },
        )
        if expected != issued_digest or binding_digest != expected:
            raise ValueError("Darwin Keychain binding integrity failed")
        return (
            credential_ref,
            service,
            account,
            access_group,
            binding_digest,
        )

    def _validated_resolver_mapping_snapshot(
        self,
        keychain_snapshot: tuple[
            str,
            str,
            str,
            str | None,
            Digest256,
        ] | None = None,
    ) -> tuple[str | None, Digest256 | None, Digest256]:
        if keychain_snapshot is None:
            keychain_snapshot = self._validated_snapshot()
        resolver_credential_ref = self.resolver_credential_ref
        resolver_binding_digest = self.resolver_binding_digest
        resolver_mapping_digest = self.resolver_mapping_digest
        issued_mapping_digest = self._issued_resolver_mapping_digest
        if (resolver_credential_ref is None) != (
            resolver_binding_digest is None
        ):
            raise ValueError("Darwin Keychain resolver mapping is incomplete")
        if resolver_credential_ref is not None:
            _require_label(
                resolver_credential_ref,
                "resolver_credential_ref",
            )
            require_digest(
                resolver_binding_digest,
                "resolver_binding_digest",
            )
        require_digest(resolver_mapping_digest, "resolver_mapping_digest")
        expected = digest256(
            "DarwinKeychainResolverMapping",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "keychain_binding_digest": keychain_snapshot[4],
                "resolver_credential_ref": resolver_credential_ref,
                "resolver_binding_digest": resolver_binding_digest,
            },
        )
        if (
            resolver_mapping_digest != expected
            or issued_mapping_digest != expected
        ):
            raise ValueError("Darwin Keychain resolver mapping integrity failed")
        return (
            resolver_credential_ref,
            resolver_binding_digest,
            resolver_mapping_digest,
        )

    def safe_metadata(self) -> dict[str, object]:
        snapshot = self._validated_snapshot()
        mapping = self._validated_resolver_mapping_snapshot(snapshot)
        return {
            "schema_version": DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            "binding_digest": str(snapshot[4]),
            "source_kind": "darwin_keychain_generic_password",
            "local_foundation_available": (
                DARWIN_KEYCHAIN_SOURCE_FOUNDATION_AVAILABLE
            ),
            "production_available": False,
            "resolver_mapping_bound": mapping[0] is not None,
            "resolver_mapping_digest": str(mapping[2]),
        }


def _new_darwin_keychain_binding(
    *,
    credential_ref: str,
    service: str,
    account: str,
    access_group: str | None,
    resolver_credential_ref: str | None = None,
    resolver_binding_digest: Digest256 | None = None,
) -> _DarwinKeychainBinding:
    return _DarwinKeychainBinding(
        credential_ref=credential_ref,
        service=service,
        account=account,
        access_group=access_group,
        resolver_credential_ref=resolver_credential_ref,
        resolver_binding_digest=resolver_binding_digest,
        _authority=_BINDING_AUTHORITY,
    )


@runtime_final
class _DarwinKeychainCredentialSource:
    """Exact-locator source with no ambient environment fallback."""

    __slots__ = (
        "_credential_ref",
        "_service",
        "_account",
        "_access_group",
        "_binding_digest",
        "_resolver_credential_ref",
        "_resolver_binding_digest",
        "_resolver_mapping_digest",
        "_query_digest",
        "_issued_query_digest",
        "_backend",
        "_lock",
    )

    def __init__(
        self,
        *,
        binding: _DarwinKeychainBinding,
        backend: _KeychainBackend,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _SOURCE_AUTHORITY:
            raise TypeError("Darwin Keychain sources require their factory")
        if type(binding) is not _DarwinKeychainBinding:
            raise TypeError("binding must be an exact Darwin Keychain binding")
        binding_snapshot = binding._validated_snapshot()
        resolver_mapping_snapshot = (
            binding._validated_resolver_mapping_snapshot(binding_snapshot)
        )
        credential_ref, service, account, access_group, binding_digest = (
            binding_snapshot
        )
        (
            resolver_credential_ref,
            resolver_binding_digest,
            resolver_mapping_digest,
        ) = resolver_mapping_snapshot
        selected_query_digest = digest256(
            "DarwinKeychainQuerySnapshot",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "credential_ref": credential_ref,
                "service": service,
                "account": account,
                "access_group": access_group,
                "binding_digest": binding_digest,
                "resolver_credential_ref": resolver_credential_ref,
                "resolver_binding_digest": resolver_binding_digest,
                "resolver_mapping_digest": resolver_mapping_digest,
            },
        )
        # Deliberately do not inspect or resolve the backend method here.
        object.__setattr__(self, "_credential_ref", credential_ref)
        object.__setattr__(self, "_service", service)
        object.__setattr__(self, "_account", account)
        object.__setattr__(self, "_access_group", access_group)
        object.__setattr__(self, "_binding_digest", binding_digest)
        object.__setattr__(
            self,
            "_resolver_credential_ref",
            resolver_credential_ref,
        )
        object.__setattr__(
            self,
            "_resolver_binding_digest",
            resolver_binding_digest,
        )
        object.__setattr__(
            self,
            "_resolver_mapping_digest",
            resolver_mapping_digest,
        )
        object.__setattr__(self, "_query_digest", selected_query_digest)
        object.__setattr__(self, "_issued_query_digest", selected_query_digest)
        object.__setattr__(self, "_backend", backend)
        object.__setattr__(self, "_lock", RLock())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("Darwin Keychain sources are immutable")

    def __copy__(self) -> object:
        raise TypeError("Darwin Keychain sources cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> object:
        del memo
        raise TypeError("Darwin Keychain sources cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("Darwin Keychain sources cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("Darwin Keychain sources cannot be serialized")

    def _validated_query_snapshot(
        self,
    ) -> tuple[
        str,
        str,
        str,
        str | None,
        Digest256,
        str | None,
        Digest256 | None,
        Digest256,
    ]:
        # Capture each field once.  Re-reading the slots after validating the
        # digest would permit a concurrent corruption to change the returned
        # Keychain query in the validation-to-use gap.
        credential_ref = self._credential_ref
        service = self._service
        account = self._account
        access_group = self._access_group
        binding_digest = self._binding_digest
        resolver_credential_ref = self._resolver_credential_ref
        resolver_binding_digest = self._resolver_binding_digest
        resolver_mapping_digest = self._resolver_mapping_digest
        query_digest = self._query_digest
        issued_query_digest = self._issued_query_digest
        require_digest(binding_digest, "binding_digest")
        if (resolver_credential_ref is None) != (
            resolver_binding_digest is None
        ):
            raise ValueError("Darwin Keychain resolver mapping is incomplete")
        if resolver_credential_ref is not None:
            _require_label(
                resolver_credential_ref,
                "resolver_credential_ref",
            )
            require_digest(
                resolver_binding_digest,
                "resolver_binding_digest",
            )
        require_digest(resolver_mapping_digest, "resolver_mapping_digest")
        expected_mapping = digest256(
            "DarwinKeychainResolverMapping",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "keychain_binding_digest": binding_digest,
                "resolver_credential_ref": resolver_credential_ref,
                "resolver_binding_digest": resolver_binding_digest,
            },
        )
        if resolver_mapping_digest != expected_mapping:
            raise ValueError("Darwin Keychain resolver mapping integrity failed")
        expected = digest256(
            "DarwinKeychainQuerySnapshot",
            DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            {
                "credential_ref": credential_ref,
                "service": service,
                "account": account,
                "access_group": access_group,
                "binding_digest": binding_digest,
                "resolver_credential_ref": resolver_credential_ref,
                "resolver_binding_digest": resolver_binding_digest,
                "resolver_mapping_digest": resolver_mapping_digest,
            },
        )
        if query_digest != expected or issued_query_digest != expected:
            raise ValueError("Darwin Keychain query snapshot integrity failed")
        return (
            credential_ref,
            service,
            account,
            access_group,
            binding_digest,
            resolver_credential_ref,
            resolver_binding_digest,
            resolver_mapping_digest,
        )

    def _perform_read_into(
        self,
        publication: _KeychainBufferPublication,
        writer: _KeychainPublicationWriter,
        query: tuple[
            str,
            str,
            str,
            str | None,
            Digest256,
            str | None,
            Digest256 | None,
            Digest256,
        ],
        *,
        receipt_resolver_binding_digest: Digest256 | None = None,
    ) -> _KeychainReadReceipt:
        """Run the reviewed backend boundary and retain only a safe result kind.

        Owned mutable aliases are overwritten; this does not claim to erase an
        immutable copy made by a non-conforming in-process backend.
        """

        result: object | None = None
        failure_kind: str | None = None
        _, service, account, access_group, binding_digest, *_ = query
        if not publication._is_claimed_by(writer, binding_digest):
            return publication._finish_failure("source")
        try:
            with self._lock:
                result = self._backend.copy_generic_password(
                    service=service,
                    account=account,
                    access_group=access_group,
                    writer=writer,
                )
        except BaseException as failure:
            if isinstance(failure, CancelledError):
                failure_kind = "cancelled"
            elif isinstance(failure, TimeoutError):
                failure_kind = "timeout"
            else:
                failure_kind = "source"
            # Never retain a backend traceback or a backend-controlled cause.
            try:
                failure.__traceback__ = None
                failure.__cause__ = None
                failure.__context__ = None
                failure.__suppress_context__ = True
            except BaseException:
                pass
            failure = None

        query_still_valid = False
        try:
            query_still_valid = self._validated_query_snapshot() == query
        except BaseException:
            query_still_valid = False
        valid = failure_kind is None and result is None and query_still_valid
        # A backend return value is outside the contract and may itself contain
        # sensitive data.  Drop the local before any public exception exists.
        result = None
        if valid:
            receipt = publication._seal_success(
                writer,
                binding_digest,
                resolver_binding_digest=receipt_resolver_binding_digest,
            )
            if type(receipt) is _KeychainReadReceipt:
                return receipt
        return publication._finish_failure(failure_kind or "source")

    def read_exact_into(
        self,
        credential_ref: str,
        publication: _KeychainBufferPublication,
        *,
        _authority: object | None = None,
    ) -> _KeychainReadReceipt:
        """Publish once and return an independently raisable safe receipt."""

        valid = False
        query: tuple[
            str,
            str,
            str,
            str | None,
            Digest256,
            str | None,
            Digest256 | None,
            Digest256,
        ] | None = None
        try:
            valid = (
                _authority is _TEST_SOURCE_AUTHORITY
                and type(publication) is _KeychainBufferPublication
                and type(credential_ref) is str
            )
            if valid:
                query = self._validated_query_snapshot()
                valid = credential_ref == query[0]
        except BaseException as failure:
            try:
                failure.__traceback__ = None
                failure.__cause__ = None
                failure.__context__ = None
                failure.__suppress_context__ = True
            except BaseException:
                pass
            failure = None
            valid = False
        if (
            not valid
            or type(publication) is not _KeychainBufferPublication
            or query is None
        ):
            return _new_read_receipt("source")
        writer: _KeychainPublicationWriter | None = None
        claim_failed = False
        try:
            writer = publication._claim_read(query[4])
        except BaseException as failure:
            try:
                failure.__traceback__ = None
                failure.__cause__ = None
                failure.__context__ = None
                failure.__suppress_context__ = True
            except BaseException:
                pass
            failure = None
            claim_failed = True
        # Keep cleanup outside the exception handler so a cleanup interruption
        # cannot chain the discarded claim failure (and its traceback) into a
        # caller-visible exception.
        if claim_failed:
            publication.close()
        if type(writer) is not _KeychainPublicationWriter:
            return _new_read_receipt("source")
        return self._perform_read_into(publication, writer, query)

    def _read_exact_into_for_credential_resolver(
        self,
        credential_ref: str,
        resolver_binding_digest: Digest256,
        publication: _KeychainBufferPublication,
        *,
        _authority: object | None = None,
    ) -> _KeychainReadReceipt:
        """Read through one frozen Registry-to-Keychain mapping.

        This private entry point exists only for the in-process resolver
        bridge.  It neither returns credential content nor accepts a physical
        Keychain locator from the resolver.
        """

        valid = False
        query: tuple[
            str,
            str,
            str,
            str | None,
            Digest256,
            str | None,
            Digest256 | None,
            Digest256,
        ] | None = None
        try:
            require_digest(
                resolver_binding_digest,
                "resolver_binding_digest",
            )
            valid = (
                _authority is _CREDENTIAL_RESOLVER_BRIDGE_AUTHORITY
                and type(publication) is _KeychainBufferPublication
                and type(credential_ref) is str
            )
            if valid:
                query = self._validated_query_snapshot()
                valid = (
                    credential_ref == query[5]
                    and resolver_binding_digest == query[6]
                )
        except BaseException as failure:
            try:
                failure.__traceback__ = None
                failure.__cause__ = None
                failure.__context__ = None
                failure.__suppress_context__ = True
            except BaseException:
                pass
            failure = None
            valid = False
        if (
            not valid
            or type(publication) is not _KeychainBufferPublication
            or query is None
        ):
            return _new_read_receipt("source")
        writer: _KeychainPublicationWriter | None = None
        claim_failed = False
        try:
            writer = publication._claim_read(query[4])
        except BaseException as failure:
            try:
                failure.__traceback__ = None
                failure.__cause__ = None
                failure.__context__ = None
                failure.__suppress_context__ = True
            except BaseException:
                pass
            failure = None
            claim_failed = True
        if claim_failed:
            publication.close()
        if type(writer) is not _KeychainPublicationWriter:
            return _new_read_receipt("source")
        return self._perform_read_into(
            publication,
            writer,
            query,
            receipt_resolver_binding_digest=resolver_binding_digest,
        )

    def safe_metadata(self) -> dict[str, object]:
        try:
            query = self._validated_query_snapshot()
        except BaseException as failure:
            try:
                failure.__traceback__ = None
                failure.__cause__ = None
                failure.__context__ = None
            except BaseException:
                pass
            failure = None
            return {
                "schema_version": DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
                "source_kind": "darwin_keychain_generic_password",
                "binding_integrity_valid": False,
                "local_foundation_available": False,
                "production_available": False,
            }
        metadata = {
            "schema_version": DARWIN_KEYCHAIN_SOURCE_SCHEMA_VERSION,
            "binding_digest": str(query[4]),
            "source_kind": "darwin_keychain_generic_password",
            "local_foundation_available": (
                DARWIN_KEYCHAIN_SOURCE_FOUNDATION_AVAILABLE
            ),
            "production_available": False,
        }
        metadata["binding_integrity_valid"] = True
        metadata["publication_contract"] = "caller_preheld_fixed_capacity_once"
        return metadata


def _new_darwin_keychain_source_for_test(
    *,
    binding: _DarwinKeychainBinding,
    backend: _KeychainBackend,
    _authority: object | None = None,
) -> _DarwinKeychainCredentialSource:
    if _authority is not _TEST_SOURCE_AUTHORITY:
        raise TypeError("test Keychain sources require test authority")
    return _DarwinKeychainCredentialSource(
        binding=binding,
        backend=backend,
        _authority=_SOURCE_AUTHORITY,
    )


def _new_production_darwin_keychain_source(
    *,
    binding: _DarwinKeychainBinding,
) -> _DarwinKeychainCredentialSource:
    del binding
    # Do not instantiate Security.framework or inspect the Keychain until the
    # exact app/team/access-group binding and production authority are present.
    if not PRODUCTION_DARWIN_KEYCHAIN_SOURCE_AVAILABLE:
        _raise_source_error()
    _raise_source_error()
