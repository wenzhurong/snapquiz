"""Private W09-B2b-S2c pre-secret startup composition contract.

The existing Darwin suspended-identity proof and S2a READY proof describe
different local foundations and cannot yet be safely joined as one production
process identity.  This module therefore freezes only the composition
boundary: a factory-owned immutable input binds the suspended-identity,
watch-registration, READY, bootstrap-binding, and epoch facts, and a
process-singleton ledger requires that exact input before any guarded
Registry, target, capture, credential, secret, or Attempt boundary.

Nothing here starts a process or accepts application data.  In particular it
does not read credentials or secrets and performs no DNS, socket, HTTP, or
Transport action.  No adapter from the current local Darwin proof types is
provided until one fixed bundled/Team-signed supervisor owns all of those
facts.  The production integration flag consequently remains false.
"""
from __future__ import annotations

from enum import Enum
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


__all__ = ()


STARTUP_BOOTSTRAP_INPUT_SCHEMA_VERSION = (
    "snapquiz.resolver-startup-bootstrap-input.v1"
)
STARTUP_COMPOSITION_PROOF_SCHEMA_VERSION = (
    "snapquiz.resolver-startup-composition-proof.v1"
)
STARTUP_BOUNDARY_PERMIT_SCHEMA_VERSION = (
    "snapquiz.resolver-startup-boundary-permit.v1"
)
PRODUCTION_STARTUP_INTEGRATION_AVAILABLE = False

_INPUT_AUTHORITY = object()
_INPUT_SOURCE_AUTHORITY = object()
_PROOF_AUTHORITY = object()
_PERMIT_AUTHORITY = object()
_COMPOSITION_AUTHORITY = object()
_PROCESS_COMPOSITION_ID = UUID("527f3143-7db7-5f84-9c3f-04adcd42a4fe")


class _StartupBoundary(str, Enum):
    REGISTRY = "registry"
    TARGET = "target"
    CAPTURE = "capture"
    CREDENTIAL = "credential"
    SECRET = "secret"
    ATTEMPT = "attempt"


_GUARDED_BOUNDARIES = tuple(_StartupBoundary)


class _InputStatus(str, Enum):
    ACTIVE = "active"
    POISONED = "poisoned"
    REPLACED = "replaced"
    INVALID = "invalid"


class _CompositionState(str, Enum):
    NEW = "new"
    STARTING = "starting"
    ACTIVE = "active"
    POISONED = "poisoned"


class _StartupPoisonReason(str, Enum):
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_INVALID = "evidence_invalid"
    EVIDENCE_POISONED = "evidence_poisoned"
    EVIDENCE_REPLAYED = "evidence_replayed"
    GENERATION_CHANGED = "generation_changed"
    LATE_BOOTSTRAP = "late_bootstrap"
    PROOF_MISSING = "proof_missing"
    PROOF_MISMATCH = "proof_mismatch"
    BOUNDARY_INPUT_INVALID = "boundary_input_invalid"
    BOUNDARY_REPLAYED = "boundary_replayed"
    PUBLICATION_UNCERTAIN = "publication_uncertain"
    EXPLICIT_POISON = "explicit_poison"


class _InputSourceSnapshot(NamedTuple):
    generation: int
    current: object | None
    poisoned: bool


class _StartupCompositionSnapshot(NamedTuple):
    state: _CompositionState
    poison_reason: _StartupPoisonReason | None
    attempted: bool
    bootstrap_input: object | None
    proof: object | None
    permits: tuple[object, ...]
    consumed_claim_ids: tuple[UUID, ...]


def _startup_error(
    safe_message: str = "resolver supervisor startup composition 不可用。",
) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="resolver_supervisor_startup_composition",
        retryable=False,
        safe_message=safe_message,
    )


def _raise_startup_error(
    safe_message: str = "resolver supervisor startup composition 不可用。",
) -> NoReturn:
    error = _startup_error(safe_message)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _input_payload(
    *,
    bootstrap_id: UUID,
    epoch_id: UUID,
    source_generation: int,
    suspended_identity_proof_digest: Digest256,
    watch_registration_digest: Digest256,
    ready_proof_digest: Digest256,
    bootstrap_binding_digest: Digest256,
) -> dict[str, object]:
    return {
        "bootstrap_binding_digest": bootstrap_binding_digest,
        "bootstrap_id": bootstrap_id,
        "epoch_id": epoch_id,
        "production_bundle_attested": False,
        "production_startup_wired": False,
        "ready_proof_digest": ready_proof_digest,
        "same_process_cross_proof_attested": False,
        "source_generation": source_generation,
        "suspended_identity_proof_digest": suspended_identity_proof_digest,
        "watch_registration_digest": watch_registration_digest,
    }


@runtime_final
class _UnwiredStartupBootstrapInput:
    """Exact immutable S2c input without production identity authority."""

    __slots__ = (
        "bootstrap_id",
        "epoch_id",
        "source_generation",
        "suspended_identity_proof_digest",
        "watch_registration_digest",
        "ready_proof_digest",
        "bootstrap_binding_digest",
        "input_digest",
        "_source",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        bootstrap_id: UUID,
        epoch_id: UUID,
        source_generation: int,
        suspended_identity_proof_digest: Digest256,
        watch_registration_digest: Digest256,
        ready_proof_digest: Digest256,
        bootstrap_binding_digest: Digest256,
        source: "_UnwiredStartupBootstrapInputSource",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _INPUT_AUTHORITY:
            raise TypeError("startup bootstrap input requires its source")
        checked_bootstrap = require_uuid(bootstrap_id, "bootstrap_id")
        checked_epoch = require_uuid(epoch_id, "epoch_id")
        checked_generation = require_plain_int(
            source_generation,
            "source_generation",
            minimum=1,
        )
        if checked_bootstrap == checked_epoch:
            raise ValueError("bootstrap_id and epoch_id must be distinct")
        digests = (
            require_digest(
                suspended_identity_proof_digest,
                "suspended_identity_proof_digest",
            ),
            require_digest(
                watch_registration_digest,
                "watch_registration_digest",
            ),
            require_digest(ready_proof_digest, "ready_proof_digest"),
            require_digest(
                bootstrap_binding_digest,
                "bootstrap_binding_digest",
            ),
        )
        if len(set(digests)) != len(digests):
            raise ValueError("startup bootstrap proof digests must be distinct")
        if type(source) is not _UnwiredStartupBootstrapInputSource:
            raise TypeError("startup bootstrap input source is invalid")
        payload = _input_payload(
            bootstrap_id=checked_bootstrap,
            epoch_id=checked_epoch,
            source_generation=checked_generation,
            suspended_identity_proof_digest=digests[0],
            watch_registration_digest=digests[1],
            ready_proof_digest=digests[2],
            bootstrap_binding_digest=digests[3],
        )
        selected = digest256(
            "ResolverStartupBootstrapInput",
            STARTUP_BOOTSTRAP_INPUT_SCHEMA_VERSION,
            payload,
        )
        object.__setattr__(self, "bootstrap_id", checked_bootstrap)
        object.__setattr__(self, "epoch_id", checked_epoch)
        object.__setattr__(self, "source_generation", checked_generation)
        object.__setattr__(
            self,
            "suspended_identity_proof_digest",
            digests[0],
        )
        object.__setattr__(self, "watch_registration_digest", digests[1])
        object.__setattr__(self, "ready_proof_digest", digests[2])
        object.__setattr__(self, "bootstrap_binding_digest", digests[3])
        object.__setattr__(self, "input_digest", selected)
        object.__setattr__(self, "_source", source)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("UnwiredStartupBootstrapInput is immutable")

    def __copy__(self) -> "_UnwiredStartupBootstrapInput":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_UnwiredStartupBootstrapInput":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("UnwiredStartupBootstrapInput cannot be serialized")

    def validate_integrity(self) -> None:
        payload = _input_payload(
            bootstrap_id=require_uuid(self.bootstrap_id, "bootstrap_id"),
            epoch_id=require_uuid(self.epoch_id, "epoch_id"),
            source_generation=require_plain_int(
                self.source_generation,
                "source_generation",
                minimum=1,
            ),
            suspended_identity_proof_digest=require_digest(
                self.suspended_identity_proof_digest,
                "suspended_identity_proof_digest",
            ),
            watch_registration_digest=require_digest(
                self.watch_registration_digest,
                "watch_registration_digest",
            ),
            ready_proof_digest=require_digest(
                self.ready_proof_digest,
                "ready_proof_digest",
            ),
            bootstrap_binding_digest=require_digest(
                self.bootstrap_binding_digest,
                "bootstrap_binding_digest",
            ),
        )
        if payload["bootstrap_id"] == payload["epoch_id"]:
            raise ValueError("startup bootstrap identifiers changed")
        proof_digests = (
            payload["suspended_identity_proof_digest"],
            payload["watch_registration_digest"],
            payload["ready_proof_digest"],
            payload["bootstrap_binding_digest"],
        )
        if len(set(proof_digests)) != len(proof_digests):
            raise ValueError("startup bootstrap proof digests changed")
        selected = digest256(
            "ResolverStartupBootstrapInput",
            STARTUP_BOOTSTRAP_INPUT_SCHEMA_VERSION,
            payload,
        )
        if (
            type(self._source) is not _UnwiredStartupBootstrapInputSource
            or type(self.input_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.input_digest != selected
            or self._issued_digest != selected
        ):
            raise ValueError("startup bootstrap input integrity failed")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "bootstrap_id": str(self.bootstrap_id),
            "epoch_id": str(self.epoch_id),
            "input_digest": str(self.input_digest),
            "production_bundle_attested": False,
            "production_startup_wired": False,
            "ready_input_bound": True,
            "same_process_cross_proof_attested": False,
            "source_generation": self.source_generation,
            "suspended_identity_input_bound": True,
            "transport_available": False,
            "watch_registration_input_bound": True,
        }


@runtime_final
class _UnwiredStartupBootstrapInputSource:
    """Local revocation/generation owner for factory-only composition input."""

    __slots__ = ("_lock", "_snapshot")

    def __init__(self, *, _authority: object | None = None) -> None:
        if _authority is not _INPUT_SOURCE_AUTHORITY:
            raise TypeError("startup input source requires its factory")
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(
            self,
            "_snapshot",
            _InputSourceSnapshot(0, None, False),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("UnwiredStartupBootstrapInputSource is immutable")

    def _build_input(
        self,
        *,
        generation: int,
        bootstrap_id: UUID,
        epoch_id: UUID,
        suspended_identity_proof_digest: Digest256,
        watch_registration_digest: Digest256,
        ready_proof_digest: Digest256,
        bootstrap_binding_digest: Digest256,
    ) -> _UnwiredStartupBootstrapInput:
        return _UnwiredStartupBootstrapInput(
            bootstrap_id=bootstrap_id,
            epoch_id=epoch_id,
            source_generation=generation,
            suspended_identity_proof_digest=suspended_identity_proof_digest,
            watch_registration_digest=watch_registration_digest,
            ready_proof_digest=ready_proof_digest,
            bootstrap_binding_digest=bootstrap_binding_digest,
            source=self,
            _authority=_INPUT_AUTHORITY,
        )

    def issue(
        self,
        *,
        bootstrap_id: UUID,
        epoch_id: UUID,
        suspended_identity_proof_digest: Digest256,
        watch_registration_digest: Digest256,
        ready_proof_digest: Digest256,
        bootstrap_binding_digest: Digest256,
    ) -> _UnwiredStartupBootstrapInput:
        with self._lock:
            if self._snapshot.current is not None:
                raise ValueError("startup input source already issued")
            selected = self._build_input(
                generation=1,
                bootstrap_id=bootstrap_id,
                epoch_id=epoch_id,
                suspended_identity_proof_digest=(
                    suspended_identity_proof_digest
                ),
                watch_registration_digest=watch_registration_digest,
                ready_proof_digest=ready_proof_digest,
                bootstrap_binding_digest=bootstrap_binding_digest,
            )
            object.__setattr__(
                self,
                "_snapshot",
                _InputSourceSnapshot(1, selected, False),
            )
            return selected

    def advance_generation(
        self,
        *,
        current: _UnwiredStartupBootstrapInput,
        bootstrap_id: UUID,
        epoch_id: UUID,
        suspended_identity_proof_digest: Digest256,
        watch_registration_digest: Digest256,
        ready_proof_digest: Digest256,
        bootstrap_binding_digest: Digest256,
    ) -> _UnwiredStartupBootstrapInput:
        with self._lock:
            snapshot = self._snapshot
            if snapshot.poisoned or snapshot.current is not current:
                raise ValueError("startup input generation is not current")
            current.validate_integrity()
            if (
                bootstrap_id == current.bootstrap_id
                or epoch_id == current.epoch_id
            ):
                raise ValueError("startup input generation must change identity")
            selected = self._build_input(
                generation=snapshot.generation + 1,
                bootstrap_id=bootstrap_id,
                epoch_id=epoch_id,
                suspended_identity_proof_digest=(
                    suspended_identity_proof_digest
                ),
                watch_registration_digest=watch_registration_digest,
                ready_proof_digest=ready_proof_digest,
                bootstrap_binding_digest=bootstrap_binding_digest,
            )
            object.__setattr__(
                self,
                "_snapshot",
                _InputSourceSnapshot(
                    snapshot.generation + 1,
                    selected,
                    False,
                ),
            )
            return selected

    def poison_current(
        self,
        *,
        current: _UnwiredStartupBootstrapInput,
    ) -> None:
        with self._lock:
            snapshot = self._snapshot
            if snapshot.current is not current or snapshot.poisoned:
                raise ValueError("startup input is not active")
            current.validate_integrity()
            object.__setattr__(
                self,
                "_snapshot",
                _InputSourceSnapshot(
                    snapshot.generation,
                    current,
                    True,
                ),
            )

    def _status_for(self, value: object) -> _InputStatus:
        with self._lock:
            if type(value) is not _UnwiredStartupBootstrapInput:
                return _InputStatus.INVALID
            try:
                value.validate_integrity()
            except (AttributeError, TypeError, ValueError):
                return _InputStatus.INVALID
            snapshot = self._snapshot
            if snapshot.current is not value:
                return _InputStatus.REPLACED
            if snapshot.poisoned:
                return _InputStatus.POISONED
            if snapshot.generation != value.source_generation:
                return _InputStatus.REPLACED
            return _InputStatus.ACTIVE


@runtime_final
class _StartupCompositionProof:
    """Exact activation proof for one process-local composition ledger."""

    __slots__ = (
        "composition_id",
        "bootstrap_id",
        "epoch_id",
        "bootstrap_input_digest",
        "proof_digest",
        "_bootstrap_input",
        "_owner",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        owner: "_ResolverStartupCompositionLedger",
        bootstrap_input: _UnwiredStartupBootstrapInput,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PROOF_AUTHORITY:
            raise TypeError("startup composition proof requires its ledger")
        bootstrap_input.validate_integrity()
        if type(owner) is not _ResolverStartupCompositionLedger:
            raise TypeError("startup composition proof owner is invalid")
        payload = {
            "bootstrap_id": bootstrap_input.bootstrap_id,
            "bootstrap_input_digest": bootstrap_input.input_digest,
            "composition_id": owner.composition_id,
            "epoch_id": bootstrap_input.epoch_id,
            "guarded_boundaries": tuple(
                boundary.value for boundary in _GUARDED_BOUNDARIES
            ),
            "production_startup_wired": False,
        }
        selected = digest256(
            "ResolverStartupCompositionProof",
            STARTUP_COMPOSITION_PROOF_SCHEMA_VERSION,
            payload,
        )
        object.__setattr__(self, "composition_id", owner.composition_id)
        object.__setattr__(self, "bootstrap_id", bootstrap_input.bootstrap_id)
        object.__setattr__(self, "epoch_id", bootstrap_input.epoch_id)
        object.__setattr__(
            self,
            "bootstrap_input_digest",
            bootstrap_input.input_digest,
        )
        object.__setattr__(self, "proof_digest", selected)
        object.__setattr__(self, "_bootstrap_input", bootstrap_input)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("StartupCompositionProof is immutable")

    def __copy__(self) -> "_StartupCompositionProof":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_StartupCompositionProof":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("StartupCompositionProof cannot be serialized")

    def _validate_structure(self) -> None:
        self._bootstrap_input.validate_integrity()
        if (
            type(self._owner) is not _ResolverStartupCompositionLedger
            or self.composition_id != self._owner.composition_id
            or self.bootstrap_id != self._bootstrap_input.bootstrap_id
            or self.epoch_id != self._bootstrap_input.epoch_id
            or self.bootstrap_input_digest != self._bootstrap_input.input_digest
        ):
            raise ValueError("startup composition proof owner changed")
        selected = digest256(
            "ResolverStartupCompositionProof",
            STARTUP_COMPOSITION_PROOF_SCHEMA_VERSION,
            {
                "bootstrap_id": self.bootstrap_id,
                "bootstrap_input_digest": require_digest(
                    self.bootstrap_input_digest,
                    "bootstrap_input_digest",
                ),
                "composition_id": require_uuid(
                    self.composition_id,
                    "composition_id",
                ),
                "epoch_id": require_uuid(self.epoch_id, "epoch_id"),
                "guarded_boundaries": tuple(
                    boundary.value for boundary in _GUARDED_BOUNDARIES
                ),
                "production_startup_wired": False,
            },
        )
        if (
            type(self.proof_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.proof_digest != selected
            or self._issued_digest != selected
        ):
            raise ValueError("startup composition proof integrity failed")

    def validate_integrity(self) -> None:
        self._validate_structure()
        if not self._owner._proof_is_active(self):
            raise ValueError("startup composition proof is not active")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "application_startup_order_attested": False,
            "bootstrap_id": str(self.bootstrap_id),
            "bootstrap_input_digest": str(self.bootstrap_input_digest),
            "composition_id": str(self.composition_id),
            "epoch_id": str(self.epoch_id),
            "local_gate_order_attested": True,
            "production_startup_integration_available": False,
            "proof_digest": str(self.proof_digest),
            "same_process_cross_proof_attested": False,
            "transport_available": False,
        }


@runtime_final
class _StartupBoundaryPermit:
    """One-shot exact permit proving a guarded call began after bootstrap."""

    __slots__ = (
        "claim_id",
        "boundary",
        "sequence",
        "composition_proof_digest",
        "bootstrap_input_digest",
        "permit_digest",
        "_startup_proof",
        "_owner",
        "_issued_digest",
    )

    def __init__(
        self,
        *,
        claim_id: UUID,
        boundary: _StartupBoundary,
        sequence: int,
        startup_proof: _StartupCompositionProof,
        owner: "_ResolverStartupCompositionLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PERMIT_AUTHORITY:
            raise TypeError("startup boundary permit requires its ledger")
        checked_claim = require_uuid(claim_id, "claim_id")
        if type(boundary) is not _StartupBoundary:
            raise TypeError("boundary must be StartupBoundary")
        checked_sequence = require_plain_int(sequence, "sequence", minimum=1)
        startup_proof._validate_structure()
        if startup_proof._owner is not owner:
            raise ValueError("startup boundary owner changed")
        payload = {
            "bootstrap_input_digest": startup_proof.bootstrap_input_digest,
            "boundary": boundary.value,
            "claim_id": checked_claim,
            "composition_proof_digest": startup_proof.proof_digest,
            "sequence": checked_sequence,
        }
        selected = digest256(
            "ResolverStartupBoundaryPermit",
            STARTUP_BOUNDARY_PERMIT_SCHEMA_VERSION,
            payload,
        )
        object.__setattr__(self, "claim_id", checked_claim)
        object.__setattr__(self, "boundary", boundary)
        object.__setattr__(self, "sequence", checked_sequence)
        object.__setattr__(
            self,
            "composition_proof_digest",
            startup_proof.proof_digest,
        )
        object.__setattr__(
            self,
            "bootstrap_input_digest",
            startup_proof.bootstrap_input_digest,
        )
        object.__setattr__(self, "permit_digest", selected)
        object.__setattr__(self, "_startup_proof", startup_proof)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_issued_digest", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("StartupBoundaryPermit is immutable")

    def __copy__(self) -> "_StartupBoundaryPermit":
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> "_StartupBoundaryPermit":
        del memo
        return self

    def __reduce__(self):
        raise TypeError("StartupBoundaryPermit cannot be serialized")

    def _validate_structure(self) -> None:
        self._startup_proof._validate_structure()
        if (
            type(self._owner) is not _ResolverStartupCompositionLedger
            or self._startup_proof._owner is not self._owner
            or self.composition_proof_digest
            != self._startup_proof.proof_digest
            or self.bootstrap_input_digest
            != self._startup_proof.bootstrap_input_digest
        ):
            raise ValueError("startup boundary permit owner changed")
        if type(self.boundary) is not _StartupBoundary:
            raise ValueError("startup boundary changed")
        selected = digest256(
            "ResolverStartupBoundaryPermit",
            STARTUP_BOUNDARY_PERMIT_SCHEMA_VERSION,
            {
                "bootstrap_input_digest": require_digest(
                    self.bootstrap_input_digest,
                    "bootstrap_input_digest",
                ),
                "boundary": self.boundary.value,
                "claim_id": require_uuid(self.claim_id, "claim_id"),
                "composition_proof_digest": require_digest(
                    self.composition_proof_digest,
                    "composition_proof_digest",
                ),
                "sequence": require_plain_int(
                    self.sequence,
                    "sequence",
                    minimum=1,
                ),
            },
        )
        if (
            type(self.permit_digest) is not Digest256
            or type(self._issued_digest) is not Digest256
            or self.permit_digest != selected
            or self._issued_digest != selected
        ):
            raise ValueError("startup boundary permit integrity failed")

    def validate_integrity(self) -> None:
        self._validate_structure()
        if not self._owner._permit_is_active(self):
            raise ValueError("startup boundary permit is not active")

    def safe_metadata(self) -> dict[str, object]:
        self.validate_integrity()
        return {
            "boundary": self.boundary.value,
            "claim_id": str(self.claim_id),
            "consumed": self._owner.boundary_consumed(self),
            "permit_digest": str(self.permit_digest),
            "production_startup_wired": False,
            "sequence": self.sequence,
            "transport_available": False,
        }


@runtime_final
class _ResolverStartupCompositionLedger:
    """Process-local one-shot pre-secret startup order ledger."""

    __slots__ = ("composition_id", "_lock", "_snapshot")

    def __init__(
        self,
        *,
        composition_id: UUID,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _COMPOSITION_AUTHORITY:
            raise TypeError("startup composition ledger requires its factory")
        object.__setattr__(
            self,
            "composition_id",
            require_uuid(composition_id, "composition_id"),
        )
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(
            self,
            "_snapshot",
            _StartupCompositionSnapshot(
                _CompositionState.NEW,
                None,
                False,
                None,
                None,
                (),
                (),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("ResolverStartupCompositionLedger is immutable")

    def _poison_locked(self, reason: _StartupPoisonReason) -> None:
        snapshot = self._snapshot
        selected = (
            snapshot.poison_reason
            if snapshot.poison_reason is not None
            else reason
        )
        object.__setattr__(
            self,
            "_snapshot",
            _StartupCompositionSnapshot(
                _CompositionState.POISONED,
                selected,
                True,
                snapshot.bootstrap_input,
                snapshot.proof,
                snapshot.permits,
                snapshot.consumed_claim_ids,
            ),
        )

    @staticmethod
    def _source_for_input(
        value: object,
    ) -> _UnwiredStartupBootstrapInputSource | None:
        if type(value) is not _UnwiredStartupBootstrapInput:
            return None
        try:
            source = value._source
        except AttributeError:
            return None
        if type(source) is not _UnwiredStartupBootstrapInputSource:
            return None
        return source

    def _refresh_active_input_locked(self) -> bool:
        """Observe revocation while ledger and exact source locks are held."""

        snapshot = self._snapshot
        if snapshot.state is not _CompositionState.ACTIVE:
            return snapshot.state is _CompositionState.ACTIVE
        failure = self._input_failure_reason(snapshot.bootstrap_input)
        if failure is None:
            return True
        self._poison_locked(failure)
        return False

    @staticmethod
    def _input_failure_reason(value: object) -> _StartupPoisonReason | None:
        if type(value) is not _UnwiredStartupBootstrapInput:
            return _StartupPoisonReason.EVIDENCE_MISSING
        try:
            value.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            return _StartupPoisonReason.EVIDENCE_INVALID
        status = value._source._status_for(value)
        if status is _InputStatus.ACTIVE:
            return None
        if status is _InputStatus.POISONED:
            return _StartupPoisonReason.EVIDENCE_POISONED
        if status is _InputStatus.REPLACED:
            return _StartupPoisonReason.GENERATION_CHANGED
        return _StartupPoisonReason.EVIDENCE_INVALID

    def _commit_activation(
        self,
        *,
        bootstrap_input: _UnwiredStartupBootstrapInput,
        proof: _StartupCompositionProof,
    ) -> None:
        snapshot = self._snapshot
        if (
            snapshot.state is not _CompositionState.STARTING
            or snapshot.bootstrap_input is not bootstrap_input
            or snapshot.proof is not None
        ):
            raise ValueError("startup activation publication changed")
        object.__setattr__(
            self,
            "_snapshot",
            _StartupCompositionSnapshot(
                _CompositionState.ACTIVE,
                None,
                True,
                bootstrap_input,
                proof,
                (),
                (),
            ),
        )

    def start(
        self,
        *,
        bootstrap_input: _UnwiredStartupBootstrapInput,
    ) -> _StartupCompositionProof:
        with self._lock:
            source = self._source_for_input(bootstrap_input)
            if source is None:
                return self._start_locked(bootstrap_input=bootstrap_input)
            with source._lock:
                return self._start_locked(bootstrap_input=bootstrap_input)

    def _start_locked(
        self,
        *,
        bootstrap_input: _UnwiredStartupBootstrapInput,
    ) -> _StartupCompositionProof:
        snapshot = self._snapshot
        if snapshot.state is _CompositionState.POISONED:
            _raise_startup_error()
        if snapshot.state is _CompositionState.ACTIVE:
            reason = (
                _StartupPoisonReason.EVIDENCE_REPLAYED
                if snapshot.bootstrap_input is bootstrap_input
                else _StartupPoisonReason.GENERATION_CHANGED
            )
            self._poison_locked(reason)
            _raise_startup_error("resolver supervisor startup 不允许重放。")
        if snapshot.state is _CompositionState.STARTING:
            self._poison_locked(_StartupPoisonReason.PUBLICATION_UNCERTAIN)
            _raise_startup_error()

        object.__setattr__(
            self,
            "_snapshot",
            _StartupCompositionSnapshot(
                _CompositionState.STARTING,
                None,
                True,
                bootstrap_input,
                None,
                (),
                (),
            ),
        )
        failure = self._input_failure_reason(bootstrap_input)
        if failure is not None:
            self._poison_locked(failure)
            _raise_startup_error("resolver supervisor startup 证明无效。")
        proof: _StartupCompositionProof | None = None
        try:
            proof = _StartupCompositionProof(
                owner=self,
                bootstrap_input=bootstrap_input,
                _authority=_PROOF_AUTHORITY,
            )
            proof._validate_structure()
            self._commit_activation(
                bootstrap_input=bootstrap_input,
                proof=proof,
            )
            return proof
        except BaseException:
            committed = (
                proof is not None
                and self._snapshot.state is _CompositionState.ACTIVE
                and self._snapshot.proof is proof
                and self._snapshot.bootstrap_input is bootstrap_input
            )
            if not committed:
                self._poison_locked(
                    _StartupPoisonReason.PUBLICATION_UNCERTAIN
                )
            _raise_startup_error(
                "resolver supervisor startup publication 未被调用方确认。"
            )

    def recover_bootstrap(
        self,
        *,
        bootstrap_input: _UnwiredStartupBootstrapInput,
    ) -> _StartupCompositionProof:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                return self._recover_bootstrap_locked(
                    bootstrap_input=bootstrap_input
                )
            with source._lock:
                return self._recover_bootstrap_locked(
                    bootstrap_input=bootstrap_input
                )

    def _recover_bootstrap_locked(
        self,
        *,
        bootstrap_input: _UnwiredStartupBootstrapInput,
    ) -> _StartupCompositionProof:
        snapshot = self._snapshot
        if snapshot.state is not _CompositionState.ACTIVE:
            if snapshot.state is not _CompositionState.POISONED:
                self._poison_locked(
                    _StartupPoisonReason.PUBLICATION_UNCERTAIN
                )
            _raise_startup_error()
        if snapshot.bootstrap_input is not bootstrap_input:
            self._poison_locked(_StartupPoisonReason.GENERATION_CHANGED)
            _raise_startup_error()
        failure = self._input_failure_reason(bootstrap_input)
        if failure is not None:
            self._poison_locked(failure)
            _raise_startup_error()
        proof = snapshot.proof
        if type(proof) is not _StartupCompositionProof:
            self._poison_locked(_StartupPoisonReason.PROOF_MISSING)
            _raise_startup_error()
        proof._validate_structure()
        return proof

    def _require_active_proof_locked(
        self,
        startup_proof: object,
    ) -> _StartupCompositionProof:
        snapshot = self._snapshot
        if snapshot.state is not _CompositionState.ACTIVE:
            if snapshot.state in (
                _CompositionState.NEW,
                _CompositionState.STARTING,
            ):
                self._poison_locked(_StartupPoisonReason.LATE_BOOTSTRAP)
            _raise_startup_error()
        if type(startup_proof) is not _StartupCompositionProof:
            self._poison_locked(_StartupPoisonReason.PROOF_MISSING)
            _raise_startup_error()
        if (
            snapshot.proof is not startup_proof
            or startup_proof._owner is not self
            or snapshot.bootstrap_input is not startup_proof._bootstrap_input
        ):
            self._poison_locked(_StartupPoisonReason.PROOF_MISMATCH)
            _raise_startup_error()
        try:
            startup_proof._validate_structure()
        except (AttributeError, TypeError, ValueError):
            self._poison_locked(_StartupPoisonReason.PROOF_MISMATCH)
            _raise_startup_error()
        failure = self._input_failure_reason(snapshot.bootstrap_input)
        if failure is not None:
            self._poison_locked(failure)
            _raise_startup_error()
        return startup_proof

    def _commit_boundary_permit(
        self,
        *,
        permit: _StartupBoundaryPermit,
    ) -> None:
        snapshot = self._snapshot
        if snapshot.state is not _CompositionState.ACTIVE:
            raise ValueError("startup boundary publication is not active")
        object.__setattr__(
            self,
            "_snapshot",
            _StartupCompositionSnapshot(
                snapshot.state,
                snapshot.poison_reason,
                snapshot.attempted,
                snapshot.bootstrap_input,
                snapshot.proof,
                snapshot.permits + (permit,),
                snapshot.consumed_claim_ids,
            ),
        )

    def claim_before(
        self,
        *,
        boundary: _StartupBoundary,
        claim_id: UUID,
        startup_proof: _StartupCompositionProof,
    ) -> _StartupBoundaryPermit:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                return self._claim_before_locked(
                    boundary=boundary,
                    claim_id=claim_id,
                    startup_proof=startup_proof,
                )
            with source._lock:
                return self._claim_before_locked(
                    boundary=boundary,
                    claim_id=claim_id,
                    startup_proof=startup_proof,
                )

    def _claim_before_locked(
        self,
        *,
        boundary: _StartupBoundary,
        claim_id: UUID,
        startup_proof: _StartupCompositionProof,
    ) -> _StartupBoundaryPermit:
        proof = self._require_active_proof_locked(startup_proof)
        if (
            type(boundary) is not _StartupBoundary
            or type(claim_id) is not UUID
        ):
            self._poison_locked(
                _StartupPoisonReason.BOUNDARY_INPUT_INVALID
            )
            _raise_startup_error()
        snapshot = self._snapshot
        if any(
            type(item) is _StartupBoundaryPermit
            and item.claim_id == claim_id
            for item in snapshot.permits
        ):
            self._poison_locked(_StartupPoisonReason.BOUNDARY_REPLAYED)
            _raise_startup_error(
                "resolver supervisor startup boundary 不允许重放。"
            )
        permit: _StartupBoundaryPermit | None = None
        try:
            permit = _StartupBoundaryPermit(
                claim_id=claim_id,
                boundary=boundary,
                sequence=len(snapshot.permits) + 1,
                startup_proof=proof,
                owner=self,
                _authority=_PERMIT_AUTHORITY,
            )
            permit._validate_structure()
            self._commit_boundary_permit(permit=permit)
            return permit
        except BaseException:
            committed = (
                permit is not None
                and self._permit_is_published_locked(permit)
            )
            if not committed:
                self._poison_locked(
                    _StartupPoisonReason.PUBLICATION_UNCERTAIN
                )
            _raise_startup_error(
                "resolver supervisor startup boundary publication 未确认。"
            )

    def recover_boundary(
        self,
        *,
        claim_id: UUID,
        startup_proof: _StartupCompositionProof,
    ) -> _StartupBoundaryPermit:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                return self._recover_boundary_locked(
                    claim_id=claim_id,
                    startup_proof=startup_proof,
                )
            with source._lock:
                return self._recover_boundary_locked(
                    claim_id=claim_id,
                    startup_proof=startup_proof,
                )

    def _recover_boundary_locked(
        self,
        *,
        claim_id: UUID,
        startup_proof: _StartupCompositionProof,
    ) -> _StartupBoundaryPermit:
        self._require_active_proof_locked(startup_proof)
        if type(claim_id) is not UUID:
            self._poison_locked(
                _StartupPoisonReason.BOUNDARY_INPUT_INVALID
            )
            _raise_startup_error()
        matches = tuple(
            item
            for item in self._snapshot.permits
            if type(item) is _StartupBoundaryPermit
            and item.claim_id == claim_id
        )
        if len(matches) != 1:
            self._poison_locked(_StartupPoisonReason.PROOF_MISSING)
            _raise_startup_error()
        permit = matches[0]
        permit._validate_structure()
        return permit

    def consume_boundary(self, permit: _StartupBoundaryPermit) -> None:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                self._consume_boundary_locked(permit)
                return
            with source._lock:
                self._consume_boundary_locked(permit)

    def _consume_boundary_locked(
        self,
        permit: _StartupBoundaryPermit,
    ) -> None:
        if type(permit) is not _StartupBoundaryPermit:
            if self._snapshot.state is not _CompositionState.POISONED:
                self._poison_locked(_StartupPoisonReason.PROOF_MISSING)
            _raise_startup_error()
        self._require_active_proof_locked(permit._startup_proof)
        if not self._permit_is_published_locked(permit):
            self._poison_locked(_StartupPoisonReason.PROOF_MISMATCH)
            _raise_startup_error()
        snapshot = self._snapshot
        if permit.claim_id in snapshot.consumed_claim_ids:
            self._poison_locked(_StartupPoisonReason.BOUNDARY_REPLAYED)
            _raise_startup_error(
                "resolver supervisor startup boundary 不允许重放。"
            )
        object.__setattr__(
            self,
            "_snapshot",
            _StartupCompositionSnapshot(
                snapshot.state,
                snapshot.poison_reason,
                snapshot.attempted,
                snapshot.bootstrap_input,
                snapshot.proof,
                snapshot.permits,
                snapshot.consumed_claim_ids + (permit.claim_id,),
            ),
        )

    def boundary_consumed(self, permit: _StartupBoundaryPermit) -> bool:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                return self._boundary_consumed_locked(permit)
            with source._lock:
                return self._boundary_consumed_locked(permit)

    def _boundary_consumed_locked(
        self,
        permit: _StartupBoundaryPermit,
    ) -> bool:
        return (
            self._refresh_active_input_locked()
            and type(permit) is _StartupBoundaryPermit
            and self._permit_is_published_locked(permit)
            and permit.claim_id in self._snapshot.consumed_claim_ids
        )

    def poison(self, *, startup_proof: _StartupCompositionProof) -> None:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                self._poison_with_proof_locked(startup_proof)
                return
            with source._lock:
                self._poison_with_proof_locked(startup_proof)

    def _poison_with_proof_locked(
        self,
        startup_proof: _StartupCompositionProof,
    ) -> None:
        self._require_active_proof_locked(startup_proof)
        self._poison_locked(_StartupPoisonReason.EXPLICIT_POISON)

    def _proof_is_active(self, proof: object) -> bool:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                return self._proof_is_active_locked(proof)
            with source._lock:
                return self._proof_is_active_locked(proof)

    def _proof_is_active_locked(self, proof: object) -> bool:
        if not self._refresh_active_input_locked():
            return False
        snapshot = self._snapshot
        return (
            snapshot.proof is proof
            and type(proof) is _StartupCompositionProof
            and snapshot.bootstrap_input is proof._bootstrap_input
        )

    def _permit_is_published_locked(self, permit: object) -> bool:
        return any(item is permit for item in self._snapshot.permits)

    def _permit_is_active(self, permit: object) -> bool:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                return self._permit_is_active_locked(permit)
            with source._lock:
                return self._permit_is_active_locked(permit)

    def _permit_is_active_locked(self, permit: object) -> bool:
        return (
            self._refresh_active_input_locked()
            and type(permit) is _StartupBoundaryPermit
            and self._snapshot.proof is permit._startup_proof
            and self._permit_is_published_locked(permit)
        )

    def safe_metadata(self) -> dict[str, object]:
        with self._lock:
            source = self._source_for_input(self._snapshot.bootstrap_input)
            if source is None:
                return self._safe_metadata_locked()
            with source._lock:
                return self._safe_metadata_locked()

    def _safe_metadata_locked(self) -> dict[str, object]:
        self._refresh_active_input_locked()
        snapshot = self._snapshot
        counts = {
            boundary.value: sum(
                1
                for permit in snapshot.permits
                if type(permit) is _StartupBoundaryPermit
                and permit.boundary is boundary
                and permit.claim_id in snapshot.consumed_claim_ids
            )
            for boundary in _GUARDED_BOUNDARIES
        }
        bootstrap_input = snapshot.bootstrap_input
        return {
            "application_startup_order_attested": False,
            "attempted": snapshot.attempted,
            "bootstrap_before_all_consumed_boundaries": (
                snapshot.proof is not None
            ),
            "bootstrap_input_committed": (
                snapshot.proof is not None
                and snapshot.state
                in (_CompositionState.ACTIVE, _CompositionState.POISONED)
            ),
            "bootstrap_id": (
                None
                if type(bootstrap_input)
                is not _UnwiredStartupBootstrapInput
                else str(bootstrap_input.bootstrap_id)
            ),
            "boundary_claim_count": len(snapshot.permits),
            "boundary_consumed_count": len(snapshot.consumed_claim_ids),
            "boundary_consumed_counts": counts,
            "composition_id": str(self.composition_id),
            "credential_material_accepted": False,
            "dns_action_count": 0,
            "epoch_id": (
                None
                if type(bootstrap_input)
                is not _UnwiredStartupBootstrapInput
                else str(bootstrap_input.epoch_id)
            ),
            "http_action_count": 0,
            "local_gate_order_attested": (
                snapshot.state is _CompositionState.ACTIVE
                and snapshot.proof is not None
            ),
            "poison_reason": (
                None
                if snapshot.poison_reason is None
                else snapshot.poison_reason.value
            ),
            "production_startup_integration_available": False,
            "process_action_count": 0,
            "same_process_cross_proof_attested": False,
            "secret_material_accepted": False,
            "socket_action_count": 0,
            "state": snapshot.state.value,
            "transport_available": False,
        }


def _new_unwired_startup_bootstrap_input_source(
) -> _UnwiredStartupBootstrapInputSource:
    return _UnwiredStartupBootstrapInputSource(
        _authority=_INPUT_SOURCE_AUTHORITY
    )


def _build_test_only_unwired_startup_composition_factory():
    """Keep the isolated-ledger authority out of mutable global lookup."""

    test_authority = object()

    def _new_test_only_unwired_startup_composition(
        *,
        composition_id: UUID,
        _authority: object | None = None,
    ) -> _ResolverStartupCompositionLedger:
        if _authority is not test_authority:
            raise TypeError(
                "isolated startup composition requires test authority"
            )
        return _ResolverStartupCompositionLedger(
            composition_id=composition_id,
            _authority=_COMPOSITION_AUTHORITY,
        )

    return _new_test_only_unwired_startup_composition, test_authority


(
    _new_test_only_unwired_startup_composition,
    _TEST_COMPOSITION_AUTHORITY,
) = _build_test_only_unwired_startup_composition_factory()
del _build_test_only_unwired_startup_composition_factory


def _build_process_resolver_startup_composition_factory():
    """Capture the sole process ledger outside mutable module attributes."""

    process_lock = Lock()
    process_composition: _ResolverStartupCompositionLedger | None = None

    def _process_resolver_startup_composition(
    ) -> _ResolverStartupCompositionLedger:
        nonlocal process_composition
        with process_lock:
            if process_composition is None:
                process_composition = _ResolverStartupCompositionLedger(
                    composition_id=_PROCESS_COMPOSITION_ID,
                    _authority=_COMPOSITION_AUTHORITY,
                )
            return process_composition

    return _process_resolver_startup_composition


_process_resolver_startup_composition = (
    _build_process_resolver_startup_composition_factory()
)
del _build_process_resolver_startup_composition_factory
