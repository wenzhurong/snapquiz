"""Local composition of the native resolver owner with the async supervisor.

This private module is executable, offline evidence only.  A caller creates a
construction plan before the async worker thread exists; that plan already
owns the native storage, the injected fixture, and the child adapter.  The
worker therefore performs no identity lookup and cannot lose the created
resource across a Python return-event gap.

The async child is durable-output-only.  It deliberately has no ``read_stdout``
method: output observation and ACK always enter the native single-slot ledger.
Its ``pid`` compatibility property is an operation-bound opaque integer, not
the process identifier.  Native pidless cleanup entry points keep the real PID
and every descriptor below the ctypes boundary.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, NoReturn

from snapquiz.domain._validation import (
    require_digest,
    require_plain_int,
    runtime_final,
)
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_resolver_owner as native_owner
from snapquiz.transport import _resolver_output_cache as output_cache
from snapquiz.transport import _resolver_supervisor_async as async_supervisor
from snapquiz.transport import _resolver_supervisor_contract as contract
from snapquiz.transport import resolver


__all__ = ()


DARWIN_RESOLVER_ASYNC_ADAPTER_SCHEMA_VERSION = (
    "snapquiz.darwin-resolver-async-adapter.v1"
)

LOCAL_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE = True
PRODUCTION_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE = False

_PLAN_AUTHORITY = object()
_WORKER_AUTHORITY = object()
_PLAN_CLAIMED = object()
_PLAN_PUBLISHED = object()
_MAX_PLANS = 64
# Keep compatibility identities injective over UUIDs and disjoint from every
# native int32 PID.  This is a namespace marker, not a bearer secret; the
# pre-held native slot remains the cleanup authority.
_OPAQUE_IDENTITY_NAMESPACE = 1 << 128


def _adapter_error(message: str) -> EndpointPolicyError:
    error = EndpointPolicyError(
        stage="resolver_supervisor_async",
        retryable=False,
        safe_message=message,
    )
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _raise_adapter_error(message: str) -> NoReturn:
    raise _adapter_error(message) from None


@runtime_final
class _DarwinResolverAsyncChild:
    """Durable-only child facade with no raw PID/descriptor surface."""

    __slots__ = ("_owner", "_opaque_identity", "_binding_digest")

    def __init__(
        self,
        *,
        owner: native_owner._DarwinResolverOwnerSlot,
        opaque_identity: int,
        binding_digest: Digest256,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PLAN_AUTHORITY:
            raise TypeError("DarwinResolverAsyncChild requires its plan")
        if type(owner) is not native_owner._DarwinResolverOwnerSlot:
            raise TypeError("owner must be DarwinResolverOwnerSlot")
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(
            self,
            "_opaque_identity",
            require_plain_int(opaque_identity, "opaque_identity", minimum=1),
        )
        object.__setattr__(
            self,
            "_binding_digest",
            require_digest(binding_digest, "binding_digest"),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinResolverAsyncChild identity is immutable")

    @property
    def pid(self) -> int:
        """Compatibility identity; intentionally not an operating-system PID."""

        return self._opaque_identity

    def _require_identity(self, opaque_identity: object) -> None:
        selected = require_plain_int(
            opaque_identity,
            "opaque_child_identity",
            minimum=1,
        )
        if selected != self._opaque_identity:
            _raise_adapter_error("resolver child opaque identity 已变化。")

    def checkpoint_liveness_exact(self, *, max_wait_ns: int) -> object:
        """Perform the bounded pre-takeover liveness checkpoint."""

        return self._owner.poll_liveness_exact(max_wait_ns=max_wait_ns)

    def recover_construction_exact(self) -> object:
        """Classify the pre-held native slot without exposing identifiers."""

        metadata = self._owner.safe_metadata()
        if metadata.get("pid_owned") is True:
            return async_supervisor._SPAWN_RECOVERY_ANCHOR_OWNED
        if metadata.get("state") == "create_failed":
            return (
                async_supervisor
                ._SPAWN_RECOVERY_ANCHOR_FAILED_BEFORE_CREATE
            )
        return async_supervisor._SPAWN_RECOVERY_ANCHOR_UNRESOLVED

    def write_start_datagram(
        self,
        frame: bytes,
        *,
        max_wait_ns: int,
    ) -> object:
        return self._owner.write_start_datagram(
            frame,
            max_wait_ns=max_wait_ns,
        )

    def observe_stdout_durable(
        self,
        max_bytes: int,
        *,
        publication: output_cache._ResolverOutputPublication,
        max_wait_ns: int,
    ) -> object:
        return self._owner.observe_stdout_durable(
            max_bytes,
            publication=publication,
            max_wait_ns=max_wait_ns,
        )

    def ack_stdout_durable(
        self,
        observation: output_cache._ResolverOutputObservation,
        *,
        max_wait_ns: int,
    ) -> object:
        return self._owner.ack_stdout_durable(
            observation,
            max_wait_ns=max_wait_ns,
        )

    def terminate_exact(
        self,
        opaque_identity: int,
        *,
        max_wait_ns: int,
    ) -> object:
        self._require_identity(opaque_identity)
        return self._owner.terminate_owned_exact(max_wait_ns=max_wait_ns)

    def reap_exact(
        self,
        opaque_identity: int,
        *,
        max_wait_ns: int,
    ) -> object:
        self._require_identity(opaque_identity)
        return self._owner.reap_owned_exact(max_wait_ns=max_wait_ns)

    def close_exact(self, *, max_wait_ns: int) -> object:
        return self._owner.close_exact(max_wait_ns=max_wait_ns)

    def safe_metadata(self) -> dict[str, object]:
        selected = self._owner.safe_metadata()
        return {
            "binding_digest": str(self._binding_digest),
            "durable_output_only": True,
            "liveness_checkpoint": selected.get("liveness_state"),
            "native_owner_state": selected.get("state"),
            "all_native_fds_closed": selected.get("all_fds_closed"),
            "production_available": (
                PRODUCTION_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE
            ),
        }


@runtime_final
class _DarwinResolverAsyncConstructionPlan:
    """One caller-preheld native slot bound to one supervisor operation."""

    __slots__ = (
        "operation_id",
        "binding_digest",
        "_owner",
        "_fixture",
        "_child",
        "_max_wait_ns",
        "_binding_snapshot",
        "_state",
    )

    def __init__(
        self,
        *,
        binding: contract._SupervisorOperationBinding,
        library_path: str | os.PathLike[str],
        fixture: object,
        max_wait_ns: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _PLAN_AUTHORITY:
            raise TypeError("DarwinResolverAsyncConstructionPlan requires factory")
        if type(binding) is not contract._SupervisorOperationBinding:
            raise TypeError("binding must be SupervisorOperationBinding")
        binding.validate_integrity()
        selected_path = Path(library_path)
        if not selected_path.is_absolute():
            raise ValueError("native owner library path must be absolute")
        selected_wait = require_plain_int(
            max_wait_ns,
            "max_wait_ns",
            minimum=1,
        )
        if selected_wait > native_owner.NATIVE_RESOLVER_MAX_WAIT_NS:
            raise ValueError("max_wait_ns exceeds native resolver deadline limit")

        # This allocation/load is deliberately completed by the caller before
        # the async worker thread and before any injected process creation.
        owner = native_owner._new_unwired_darwin_resolver_owner_slot(
            selected_path
        )
        opaque_identity = (
            _OPAQUE_IDENTITY_NAMESPACE | binding.operation_id.int
        )
        child = _DarwinResolverAsyncChild(
            owner=owner,
            opaque_identity=opaque_identity,
            binding_digest=binding.binding_digest,
            _authority=_PLAN_AUTHORITY,
        )
        object.__setattr__(self, "operation_id", binding.operation_id)
        object.__setattr__(self, "binding_digest", binding.binding_digest)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_fixture", fixture)
        object.__setattr__(self, "_child", child)
        object.__setattr__(self, "_max_wait_ns", selected_wait)
        object.__setattr__(
            self,
            "_binding_snapshot",
            (
                binding.epoch_id,
                binding.operation_id,
                binding.lifecycle_id,
                binding.publication_id,
                binding.spawn_request_digest,
                binding.binding_digest,
            ),
        )
        object.__setattr__(
            self,
            "_state",
            {
                "issued_operation_id": binding.operation_id,
                "issued_binding_digest": binding.binding_digest,
            },
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError(
            "DarwinResolverAsyncConstructionPlan identity is immutable"
        )

    def matches(self, binding: contract._SupervisorOperationBinding) -> bool:
        state = self._state.copy()
        if type(binding) is not contract._SupervisorOperationBinding:
            return False
        try:
            binding.validate_integrity()
        except (AttributeError, TypeError, ValueError):
            return False
        return (
            state.get("issued_operation_id") == self.operation_id
            and state.get("issued_binding_digest") == self.binding_digest
            and self._binding_snapshot
            == (
                binding.epoch_id,
                binding.operation_id,
                binding.lifecycle_id,
                binding.publication_id,
                binding.spawn_request_digest,
                binding.binding_digest,
            )
        )

    def construct_and_publish(
        self,
        *,
        binding: contract._SupervisorOperationBinding,
        publication: async_supervisor._SpawnConstructionPublication,
    ) -> None:
        if not self.matches(binding) or not publication.matches(
            self.operation_id,
            self.binding_digest,
        ):
            _raise_adapter_error("resolver async construction binding 已变化。")
        retained = self._state.setdefault("publication", publication)
        if retained is not publication:
            _raise_adapter_error("resolver async construction publication 已变化。")
        claim = self._state.setdefault("claim", _PLAN_CLAIMED)
        if claim is not _PLAN_CLAIMED:
            _raise_adapter_error("resolver async construction claim 已变化。")
        publication.attach_recovery_anchor(self._child)
        try:
            self._owner.construct(
                self._fixture,
                max_wait_ns=self._max_wait_ns,
            )
        except BaseException:
            try:
                metadata = self._owner.safe_metadata()
            except BaseException:
                return
            if metadata.get("pid_owned") is True:
                publication.publish(self._child)
                published = self._state.setdefault(
                    "published",
                    _PLAN_PUBLISHED,
                )
                if published is not _PLAN_PUBLISHED:
                    _raise_adapter_error(
                        "resolver async construction receipt 已变化。"
                    )
            elif metadata.get("state") == "create_failed":
                publication.fail_before_create()
            # Every other state remains begun-but-unpublished.  The async
            # publication converts that exact fact into an uncertainty fence.
            return
        publication.publish(self._child)
        published = self._state.setdefault("published", _PLAN_PUBLISHED)
        if published is not _PLAN_PUBLISHED:
            _raise_adapter_error("resolver async construction receipt 已变化。")

    def safe_metadata(self) -> dict[str, object]:
        state = self._state.copy()
        owner = self._owner.safe_metadata()
        return {
            "caller_preheld": True,
            "claimed": state.get("claim") is _PLAN_CLAIMED,
            "published": state.get("published") is _PLAN_PUBLISHED,
            "native_owner_state": owner.get("state"),
            "raw_identity_exposed": False,
            "production_available": (
                PRODUCTION_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE
            ),
        }


@runtime_final
class _DarwinResolverAsyncWorker:
    """Exact plan selector for the existing async worker publication seam."""

    __slots__ = ("_plans",)

    def __init__(
        self,
        plans: Iterable[_DarwinResolverAsyncConstructionPlan],
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _WORKER_AUTHORITY:
            raise TypeError("DarwinResolverAsyncWorker requires factory")
        selected = tuple(plans)
        if len(selected) > _MAX_PLANS:
            raise ValueError("resolver async construction plan limit exceeded")
        if any(
            type(plan) is not _DarwinResolverAsyncConstructionPlan
            for plan in selected
        ):
            raise TypeError("plans must be DarwinResolverAsyncConstructionPlan")
        operation_ids = tuple(plan.operation_id for plan in selected)
        if len(set(operation_ids)) != len(operation_ids):
            raise ValueError("resolver async construction plan identity duplicated")
        object.__setattr__(self, "_plans", selected)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("DarwinResolverAsyncWorker identity is immutable")

    def spawn(
        self,
        binding: contract._SupervisorOperationBinding,
        *,
        publication: async_supervisor._SpawnConstructionPublication,
    ) -> None:
        if type(publication) is not async_supervisor._SpawnConstructionPublication:
            raise TypeError("publication must be SpawnConstructionPublication")
        # This is the first semantic worker action and precedes every possible
        # injected construction call.
        publication.begin()
        selected = None
        for plan in self._plans:
            if plan.matches(binding):
                selected = plan
                break
        if selected is None:
            publication.fail_before_create()
            return None
        selected.construct_and_publish(
            binding=binding,
            publication=publication,
        )
        return None

    def safe_metadata(self) -> dict[str, object]:
        return {
            "caller_preheld_plan_count": len(self._plans),
            "production_available": (
                PRODUCTION_DARWIN_RESOLVER_ASYNC_ADAPTER_AVAILABLE
            ),
        }


def _new_unwired_darwin_resolver_async_plan(
    *,
    binding: contract._SupervisorOperationBinding,
    library_path: str | os.PathLike[str],
    fixture: object,
    max_wait_ns: int,
) -> _DarwinResolverAsyncConstructionPlan:
    return _DarwinResolverAsyncConstructionPlan(
        binding=binding,
        library_path=library_path,
        fixture=fixture,
        max_wait_ns=max_wait_ns,
        _authority=_PLAN_AUTHORITY,
    )


def _new_unwired_darwin_resolver_async_worker(
    plans: Iterable[_DarwinResolverAsyncConstructionPlan],
) -> _DarwinResolverAsyncWorker:
    return _DarwinResolverAsyncWorker(
        plans,
        _authority=_WORKER_AUTHORITY,
    )
