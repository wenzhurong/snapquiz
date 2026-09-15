"""W10 direct-multimodal pipeline composition.

This module composes the existing W05-W09 authorities without introducing a
second permission, credential, retry, or transport path.  Real macOS capture
belongs to W12.  The default transport below remains deliberately unwired
until the W09 production exit gates are satisfied.
"""
from __future__ import annotations

from datetime import datetime
from threading import Lock, RLock
from typing import NoReturn
from uuid import UUID

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.capture.policy import (
    CaptureAuthorization,
    CaptureAuthorizationLedger,
    CapturePolicy,
    ConsumedCaptureAuthorization,
    _CAPTURE_EXECUTION_OBSERVATION_AUTHORITY,
    _CAPTURE_VALIDATION_AUTHORITY,
)
from snapquiz.capture.topology import DisplayTopologySnapshot
from snapquiz.capture.validation import (
    CaptureArtifactFactory,
    InputValidator,
    ValidatedCapture,
)
from snapquiz.core.permissions import PermissionObservation
from snapquiz.domain._validation import (
    require_aware_datetime,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.adapter import AnswerCandidateResult, TransportResponse
from snapquiz.domain.capture import CaptureScope
from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import (
    CancelledError,
    CaptureError,
    ConfigError,
    EndpointPolicyError,
    InvalidOutputError,
    OperationError,
)
from snapquiz.domain.intent import SolveIntent
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.domain.plan import validate_phase1_remote_direct_plan
from snapquiz.domain.policy import ContractMarker
from snapquiz.domain.solve import (
    PipelineKind,
    SolveProvenance,
    SolveResult,
    StageProvenance,
)
from snapquiz.pipelines.contracts import (
    SolveRequest,
    SolveRequestFactory,
    StageInvocation,
    StageInvocationFactory,
)
from snapquiz.privacy.consent import AuthorizationContext, ConsentLedger
from snapquiz.privacy.egress import (
    EgressApprovalLedger,
    EgressGate,
    EgressPreviewController,
)
from snapquiz.result.validator import (
    validate_answer_candidate,
    validate_solve_result,
)
from snapquiz.routing.planner import PlannedExecution
from snapquiz.runtime.attempt import (
    AttemptGate,
    CredentialResolutionPermit,
    _CREDENTIAL_PERMIT_PUBLICATION_AUTHORITY,
    _CREDENTIAL_PERMIT_RECOVERY_AUTHORITY,
)
from snapquiz.runtime.authority import RegistryPolicyAuthorityLedger
from snapquiz.runtime.context import (
    CallContext,
    CallContextLedger,
    CancellationReason,
    CancellationSource,
    RuntimeCallFactory,
    _CAPTURE_START_AUTHORITY,
    _CONTEXT_RECOVERY_AUTHORITY,
    _RESULT_PUBLICATION_AUTHORITY,
)
from snapquiz.transport.credentials import CredentialResolver
from snapquiz.transport.http import (
    PreparedResolverAttempt,
    ResolverCleanupTicket,
    coordinate_resolver_attempt,
    issue_resolver_cleanup_ticket,
)
from snapquiz.transport.resolver import ResolverHelperLauncher
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger


W10_MULTIMODAL_PIPELINE_POLICY_VERSION = (
    "snapquiz.multimodal-pipeline.phase1-direct.v1"
)
PRODUCTION_MULTIMODAL_PIPELINE_AVAILABLE = False

_CAPTURE_OBSERVATION_AUTHORITY = object()
_CAPTURE_FRAME_AUTHORITY = object()
_CANCELLATION_HANDLE_AUTHORITY = object()
_EXECUTOR_CONSTRUCTION_AUTHORITY = object()
_TEST_PIPELINE_AUTHORITY = object()


class _RunRegistrationConflict(Exception):
    """Internal signal raised before this caller publishes any run owner."""

    __slots__ = ("cleanup_pending",)

    def __init__(self, *, cleanup_pending: bool) -> None:
        self.cleanup_pending = cleanup_pending
        super().__init__("run registration conflict")


def _capture_error(message: str) -> CaptureError:
    return CaptureError(
        stage="multimodal_capture",
        retryable=False,
        safe_message=message,
    )


def _pipeline_error(message: str) -> ConfigError:
    return ConfigError(
        stage="multimodal_pipeline",
        retryable=False,
        safe_message=message,
    )


def _transport_error() -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="multimodal_transport",
        retryable=False,
        safe_message="安全传输未能完成。",
    )


def _cleanup_error() -> EndpointPolicyError:
    return EndpointPolicyError(
        stage="multimodal_cleanup",
        retryable=False,
        safe_message="资源终结尚未得到证明；只能显式重试清理。",
    )


@runtime_final
class CaptureObservation:
    """One source-issued permission/topology observation at an exact time."""

    __slots__ = ("permission", "topology", "observed_at")

    def __init__(
        self,
        *,
        permission: PermissionObservation,
        topology: DisplayTopologySnapshot,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_OBSERVATION_AUTHORITY:
            raise TypeError("CaptureObservation requires MultimodalCaptureSource")
        if type(permission) is not PermissionObservation:
            raise TypeError("permission must be PermissionObservation")
        if type(topology) is not DisplayTopologySnapshot:
            raise TypeError("topology must be DisplayTopologySnapshot")
        if permission.observed_at != topology.observed_at:
            raise ValueError("permission and topology must share one observation time")
        object.__setattr__(self, "permission", permission)
        object.__setattr__(self, "topology", topology)
        object.__setattr__(self, "observed_at", permission.observed_at)
        self.validate_integrity()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CaptureObservation is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "CaptureObservation":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "CaptureObservation("
            f"observed_at={self.observed_at!r}, "
            f"permission_state={self.permission.state.value!r}, "
            f"topology_revision_prefix={str(self.topology.topology_revision)[:12]!r})"
        )

    def validate_integrity(self) -> None:
        if type(self.permission) is not PermissionObservation:
            raise ValueError("capture permission observation changed")
        if type(self.topology) is not DisplayTopologySnapshot:
            raise ValueError("capture topology observation changed")
        self.permission.validate_integrity()
        self.topology.validate_integrity()
        require_aware_datetime(self.observed_at, "observed_at")
        if (
            self.permission.observed_at != self.observed_at
            or self.topology.observed_at != self.observed_at
        ):
            raise ValueError("capture observation time changed")


@runtime_final
class CapturedFrame:
    """Ephemeral raw frame returned only after capture authority is consumed."""

    __slots__ = ("mime_type", "width_px", "height_px", "_data")

    def __init__(
        self,
        *,
        data: bytes,
        mime_type: str,
        width_px: int,
        height_px: int,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CAPTURE_FRAME_AUTHORITY:
            raise TypeError("CapturedFrame requires MultimodalCaptureSource")
        if type(data) is not bytes or not data:
            raise ValueError("captured frame data must be non-empty immutable bytes")
        require_text(mime_type, "mime_type", max_length=256)
        require_plain_int(width_px, "width_px", minimum=1)
        require_plain_int(height_px, "height_px", minimum=1)
        object.__setattr__(self, "mime_type", mime_type)
        object.__setattr__(self, "width_px", width_px)
        object.__setattr__(self, "height_px", height_px)
        object.__setattr__(self, "_data", data)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CapturedFrame is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "CapturedFrame":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "CapturedFrame("
            f"mime_type={self.mime_type!r}, width_px={self.width_px!r}, "
            f"height_px={self.height_px!r}, byte_size={len(self._data)!r})"
        )

    @property
    def data(self) -> bytes:
        return self._data

    def validate_integrity(self) -> None:
        if type(self._data) is not bytes or not self._data:
            raise ValueError("captured frame data changed")
        require_text(self.mime_type, "mime_type", max_length=256)
        require_plain_int(self.width_px, "width_px", minimum=1)
        require_plain_int(self.height_px, "height_px", minimum=1)

    def safe_metadata(self) -> dict[str, object]:
        return {
            "mime_type": self.mime_type,
            "width_px": self.width_px,
            "height_px": self.height_px,
            "byte_size": len(self._data),
        }


class MultimodalCaptureSource:
    """Trusted W12-facing source boundary; W10 tests use an offline fake."""

    __slots__ = ()

    @staticmethod
    def observation(
        *,
        permission: PermissionObservation,
        topology: DisplayTopologySnapshot,
    ) -> CaptureObservation:
        return CaptureObservation(
            permission=permission,
            topology=topology,
            _authority=_CAPTURE_OBSERVATION_AUTHORITY,
        )

    @staticmethod
    def frame(
        *,
        data: bytes,
        mime_type: str,
        width_px: int,
        height_px: int,
    ) -> CapturedFrame:
        return CapturedFrame(
            data=data,
            mime_type=mime_type,
            width_px=width_px,
            height_px=height_px,
            _authority=_CAPTURE_FRAME_AUTHORITY,
        )

    def observe_for_authorization(
        self,
        *,
        planned: PlannedExecution,
        now: datetime,
    ) -> CaptureObservation:
        del planned, now
        raise NotImplementedError

    def observe_before_capture(
        self,
        *,
        authorization: CaptureAuthorization,
        now: datetime,
    ) -> CaptureObservation:
        del authorization, now
        raise NotImplementedError

    def capture_once(
        self,
        *,
        consumed: ConsumedCaptureAuthorization,
    ) -> CapturedFrame:
        del consumed
        raise NotImplementedError

    def observe_after_capture(
        self,
        *,
        consumed: ConsumedCaptureAuthorization,
        frame: CapturedFrame,
        now: datetime,
    ) -> CaptureObservation:
        del consumed, frame, now
        raise NotImplementedError


class RemoteTransport:
    """Trusted one-shot transport boundary over a prepared W09 attempt."""

    __slots__ = ()

    def send_once(
        self,
        prepared_attempt: PreparedResolverAttempt,
    ) -> TransportResponse:
        del prepared_attempt
        raise NotImplementedError


@runtime_final
class UnwiredRemoteTransport(RemoteTransport):
    """Production-shaped transport that remains fail-closed by construction."""

    __slots__ = ()

    def send_once(
        self,
        prepared_attempt: PreparedResolverAttempt,
    ) -> TransportResponse:
        # Lazy import keeps normal pipeline imports free of socket/TLS setup.
        from snapquiz.transport._exact_transport import _send_exact_unwired

        return _send_exact_unwired(prepared_attempt)


class _CancellationBinding:
    """Atomic binding between one handle, one source, and one W10 run."""

    __slots__ = ("source", "owner")

    def __init__(self, source: CancellationSource, owner: object) -> None:
        self.source = source
        self.owner = owner


class _ReleasedCancellationBinding:
    """Digest-free terminal marker that retains no CancellationSource."""

    __slots__ = ("owner",)

    def __init__(self, owner: object) -> None:
        self.owner = owner


@runtime_final
class MultimodalCancellation:
    """Thread-safe cancellation handle that never exposes runtime authority."""

    __slots__ = (
        "_lock",
        "_binding",
        "_cancel_requested",
        "_cancel_committed",
    )

    def __init__(self) -> None:
        self._lock = RLock()
        self._binding: (
            _CancellationBinding | _ReleasedCancellationBinding | None
        ) = None
        self._cancel_requested = False
        self._cancel_committed = False

    def cancel(self) -> bool:
        """Request user cancellation before or during one execution."""

        with self._lock:
            if (
                type(self._binding) is _ReleasedCancellationBinding
                or self._cancel_committed
            ):
                return False
            first_request = not self._cancel_requested
            self._cancel_requested = True
            binding = self._binding
            if binding is None:
                return first_request
            return self._drive_pending_cancellation_locked(binding)

    @property
    def is_finished(self) -> bool:
        with self._lock:
            return type(self._binding) is _ReleasedCancellationBinding

    def safe_metadata(self) -> dict[str, bool]:
        with self._lock:
            return {
                "cancel_requested": self._cancel_requested,
                "bound": type(self._binding) is _CancellationBinding,
                "finished": (
                    type(self._binding) is _ReleasedCancellationBinding
                ),
            }

    def _drive_pending_cancellation_locked(
        self,
        binding: _CancellationBinding,
    ) -> bool:
        if self._binding is not binding or not self._cancel_requested:
            return False
        try:
            binding.source.cancel(reason=CancellationReason.USER_REQUEST)
        except BaseException:
            pass
        try:
            observed = binding.source.is_cancelled()
            committed = type(observed) is bool and observed is True
        except BaseException:
            committed = False
        if committed:
            self._cancel_committed = True
        return committed

    def _bind(
        self,
        source: CancellationSource,
        *,
        owner: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CANCELLATION_HANDLE_AUTHORITY:
            raise TypeError("cancellation binding requires the W10 executor")
        if type(source) is not CancellationSource:
            raise TypeError("source must be CancellationSource")
        if owner is None:
            raise TypeError("owner must be an identity object")
        with self._lock:
            if type(self._binding) is _ReleasedCancellationBinding:
                raise _pipeline_error("取消句柄已经终结。")
            current = self._binding
            if current is None:
                binding = _CancellationBinding(source, owner)
                self._binding = binding
                if self._binding is not binding:
                    raise _pipeline_error("取消句柄 binding publication 未提交。")
                return
            if (
                type(current) is _CancellationBinding
                and current.source is source
                and current.owner is owner
            ):
                return
            raise _pipeline_error("取消句柄已经绑定其他请求。")

    def _binding_is_exact(
        self,
        source: CancellationSource,
        *,
        owner: object,
        _authority: object | None = None,
    ) -> bool:
        if _authority is not _CANCELLATION_HANDLE_AUTHORITY:
            raise TypeError("cancellation observation requires the W10 executor")
        with self._lock:
            binding = self._binding
            return (
                type(binding) is _CancellationBinding
                and binding.source is source
                and binding.owner is owner
            )

    def _apply_pending_cancellation(
        self,
        source: CancellationSource,
        *,
        owner: object,
        _authority: object | None = None,
    ) -> bool:
        if _authority is not _CANCELLATION_HANDLE_AUTHORITY:
            raise TypeError("cancellation application requires the W10 executor")
        with self._lock:
            binding = self._binding
            if (
                type(binding) is not _CancellationBinding
                or binding.source is not source
                or binding.owner is not owner
            ):
                return False
            if not self._cancel_requested:
                return True
            if self._cancel_committed:
                try:
                    observed = source.is_cancelled()
                except BaseException:
                    return False
                return type(observed) is bool and observed is True
            return self._drive_pending_cancellation_locked(binding)

    def _pending_cancellation_is_settled(
        self,
        source: CancellationSource,
        *,
        owner: object,
        _authority: object | None = None,
    ) -> bool:
        if _authority is not _CANCELLATION_HANDLE_AUTHORITY:
            raise TypeError("cancellation observation requires the W10 executor")
        with self._lock:
            binding = self._binding
            if (
                type(binding) is not _CancellationBinding
                or binding.source is not source
                or binding.owner is not owner
            ):
                return False
            if not self._cancel_requested:
                return True
            try:
                observed = source.is_cancelled()
            except BaseException:
                return False
            return (
                self._cancel_committed is True
                and type(observed) is bool
                and observed is True
            )

    def _stop_is_requested(
        self,
        source: CancellationSource,
        *,
        owner: object,
        _authority: object | None = None,
    ) -> bool:
        if _authority is not _CANCELLATION_HANDLE_AUTHORITY:
            raise TypeError("cancellation request observation requires W10")
        with self._lock:
            binding = self._binding
            return (
                type(binding) is _CancellationBinding
                and binding.source is source
                and binding.owner is owner
                and type(self._cancel_requested) is bool
                and self._cancel_requested is True
            )

    def _release_for_run(
        self,
        *,
        owner: object,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _CANCELLATION_HANDLE_AUTHORITY:
            raise TypeError("cancellation cleanup requires the W10 executor")
        if owner is None:
            raise TypeError("owner must be an identity object")
        with self._lock:
            binding = self._binding
            if (
                type(binding) is not _CancellationBinding
                or binding.owner is not owner
            ):
                return
            self._binding = _ReleasedCancellationBinding(owner)

    def _is_released_for_run(
        self,
        *,
        owner: object,
        _authority: object | None = None,
    ) -> bool:
        if _authority is not _CANCELLATION_HANDLE_AUTHORITY:
            raise TypeError("cancellation cleanup observation requires W10")
        with self._lock:
            binding = self._binding
            return not (
                type(binding) is _CancellationBinding
                and binding.owner is owner
            )


class _CredentialPermitHolding:
    """One atomic caller-owned reference used only for cleanup recovery."""

    __slots__ = ("permit",)

    def __init__(self, permit: CredentialResolutionPermit) -> None:
        self.permit = permit


class _CaptureValidationHolding:
    """One atomic state publication for validation recovery inputs."""

    __slots__ = ("ledger", "consumed")

    def __init__(
        self,
        ledger: CaptureAuthorizationLedger,
        consumed: ConsumedCaptureAuthorization,
    ) -> None:
        if type(ledger) is not CaptureAuthorizationLedger:
            raise TypeError("ledger must be CaptureAuthorizationLedger")
        if type(consumed) is not ConsumedCaptureAuthorization:
            raise TypeError("consumed must be ConsumedCaptureAuthorization")
        self.ledger = ledger
        self.consumed = consumed


class _RunState:
    __slots__ = (
        "_lock",
        "request_id",
        "planned_execution_digest",
        "context_start_owner",
        "cancellation_owner",
        "context",
        "context_ledger",
        "cancellation",
        "_capture_validation_holding",
        "validated",
        "attempt_gate",
        "_credential_permit_holding",
        "cleanup_ticket",
        "prepared_attempt",
        "result",
        "failure",
    )

    def __init__(
        self,
        context_ledger: CallContextLedger,
        cancellation: MultimodalCancellation,
        *,
        request_id: UUID,
        planned_execution_digest: Digest256,
    ) -> None:
        self._lock = RLock()
        self.request_id = request_id
        self.planned_execution_digest = planned_execution_digest
        self.context_start_owner = object()
        self.cancellation_owner = object()
        self.context: CallContext | None = None
        self.context_ledger = context_ledger
        self.cancellation: MultimodalCancellation | None = cancellation
        self._capture_validation_holding: _CaptureValidationHolding | None = None
        self.validated: ValidatedCapture | None = None
        self.attempt_gate: AttemptGate | None = None
        self._credential_permit_holding: (
            _CredentialPermitHolding | None
        ) = None
        self.cleanup_ticket: ResolverCleanupTicket | None = None
        self.prepared_attempt: PreparedResolverAttempt | None = None
        self.result: SolveResult | None = None
        self.failure = None

    def cleanup(self) -> bool:
        """Best-effort ordered cleanup; retain every unproven recovery owner."""

        with self._lock:
            prepared_attempt = self.prepared_attempt
            cleanup_ticket = self.cleanup_ticket
            gate = self.attempt_gate
            permit_holding = self._credential_permit_holding
            credential_permit = (
                permit_holding.permit
                if type(permit_holding) is _CredentialPermitHolding
                else None
            )
            capture_holding = self._capture_validation_holding
            capture_ledger = (
                capture_holding.ledger
                if type(capture_holding) is _CaptureValidationHolding
                else None
            )
            consumed_capture = (
                capture_holding.consumed
                if type(capture_holding) is _CaptureValidationHolding
                else None
            )
            validated = self.validated
            context = self.context
            cancellation = self.cancellation

            context_recovery_proven = False
            try:
                recovered_context = (
                    self.context_ledger._recover_context_for_cleanup(
                        request_id=self.request_id,
                        planned_execution_digest=self.planned_execution_digest,
                        start_owner=self.context_start_owner,
                        _authority=_CONTEXT_RECOVERY_AUTHORITY,
                    )
                )
                recovery_conflict = (
                    context is not None
                    and recovered_context is not None
                    and recovered_context is not context
                )
                candidate_context = (
                    context if context is not None else recovered_context
                )
                observed = self.context_ledger._context_recovery_is_exact(
                    request_id=self.request_id,
                    planned_execution_digest=self.planned_execution_digest,
                    start_owner=self.context_start_owner,
                    expected_context=candidate_context,
                    _authority=_CONTEXT_RECOVERY_AUTHORITY,
                )
                context_recovery_proven = (
                    not recovery_conflict
                    and type(observed) is bool
                    and observed is True
                )
                # A recovery return is not authority by itself.  Adopt it only
                # after the independent ledger observer proves the exact
                # request, digest, and pre-held owner.  An already-held
                # context came from RuntimeCallFactory's proven return and is
                # retained even when this cleanup observation is transient.
                if (
                    context is None
                    and context_recovery_proven
                    and candidate_context is not None
                ):
                    context = candidate_context
                    self.context = candidate_context
            except BaseException:
                context_recovery_proven = False

            prepared_terminal = prepared_attempt is None
            if prepared_attempt is not None:
                try:
                    if not prepared_attempt.is_closed:
                        prepared_attempt.close()
                except BaseException:
                    pass
                try:
                    prepared_terminal = prepared_attempt.is_closed
                except BaseException:
                    prepared_terminal = False
                if prepared_terminal:
                    self.prepared_attempt = None

            ticket_terminal = cleanup_ticket is None
            if cleanup_ticket is not None:
                try:
                    metadata = cleanup_ticket.safe_metadata()
                    if metadata["state"] not in ("issued", "terminal"):
                        cleanup_ticket.retry_cleanup()
                        metadata = cleanup_ticket.safe_metadata()
                    ticket_terminal = metadata["state"] in ("issued", "terminal")
                except BaseException:
                    ticket_terminal = False
                if ticket_terminal:
                    self.cleanup_ticket = None

            permit_terminal = permit_holding is None
            if credential_permit is not None:
                if gate is not None and context is not None:
                    try:
                        gate._recover_published_credential_permit_for_cleanup(
                            credential_permit,
                            context=context,
                            context_ledger=self.context_ledger,
                            _authority=_CREDENTIAL_PERMIT_RECOVERY_AUTHORITY,
                        )
                    except BaseException:
                        pass
                    try:
                        observed = gate._published_credential_cleanup_is_exact(
                            credential_permit,
                            context=context,
                            context_ledger=self.context_ledger,
                            _authority=_CREDENTIAL_PERMIT_RECOVERY_AUTHORITY,
                        )
                        permit_terminal = (
                            type(observed) is bool and observed is True
                        )
                    except BaseException:
                        permit_terminal = False
                else:
                    permit_terminal = False
                if permit_terminal:
                    self._credential_permit_holding = None
                    self.attempt_gate = None
            elif gate is not None:
                self.attempt_gate = None

            capture_publication_absent = (
                validated is None
                and capture_holding is None
            )
            if (
                validated is None
                and capture_ledger is not None
                and consumed_capture is not None
            ):
                recovered_validated = None
                try:
                    recovered_validated = (
                        capture_ledger._validated_capture_for_cleanup(
                            consumed=consumed_capture,
                            _authority=_CAPTURE_VALIDATION_AUTHORITY,
                        )
                    )
                except BaseException:
                    recovered_validated = None
                if recovered_validated is None:
                    try:
                        absent = (
                            capture_ledger
                            ._validated_capture_publication_is_absent(
                                consumed=consumed_capture,
                                _authority=_CAPTURE_VALIDATION_AUTHORITY,
                            )
                        )
                        capture_publication_absent = (
                            type(absent) is bool and absent is True
                        )
                    except BaseException:
                        capture_publication_absent = False
                elif type(recovered_validated) is ValidatedCapture:
                    try:
                        recovered_is_exact = (
                            capture_ledger._validated_capture_is_exact(
                                consumed=consumed_capture,
                                validated_capture=recovered_validated,
                                validation_digest=(
                                    recovered_validated.validation_digest
                                ),
                                _authority=_CAPTURE_VALIDATION_AUTHORITY,
                            )
                        )
                    except BaseException:
                        recovered_is_exact = False
                    if (
                        type(recovered_is_exact) is bool
                        and recovered_is_exact is True
                    ):
                        validated = recovered_validated
                        self.validated = recovered_validated

            capture_terminal = capture_publication_absent
            if validated is not None:
                try:
                    validated.release()
                except BaseException:
                    pass
                try:
                    capture_terminal = validated.is_released
                except BaseException:
                    capture_terminal = False
                if capture_terminal:
                    self.validated = None
            if capture_terminal:
                self._capture_validation_holding = None

            owners_terminal = (
                prepared_terminal and ticket_terminal and permit_terminal
            )
            context_terminal = context is None and context_recovery_proven
            if context is not None and owners_terminal:
                try:
                    if not self.context_ledger.is_closed(context):
                        self.context_ledger.close(context)
                except BaseException:
                    pass
                try:
                    context_terminal = self.context_ledger.is_closed(context)
                except BaseException:
                    context_terminal = False
                if context_terminal:
                    self.context = None

            clean = (
                owners_terminal
                and capture_terminal
                and context_terminal
                and context_recovery_proven
            )
            if clean and cancellation is not None:
                try:
                    cancellation._release_for_run(
                        owner=self.cancellation_owner,
                        _authority=_CANCELLATION_HANDLE_AUTHORITY,
                    )
                except BaseException:
                    pass
                try:
                    cancellation_terminal = (
                        cancellation._is_released_for_run(
                            owner=self.cancellation_owner,
                            _authority=_CANCELLATION_HANDLE_AUTHORITY,
                        )
                    )
                except BaseException:
                    cancellation_terminal = False
                if (
                    type(cancellation_terminal) is bool
                    and cancellation_terminal is True
                ):
                    self.cancellation = None
                else:
                    clean = False
            return clean

    def publish_capture_validation_holding(
        self,
        ledger: CaptureAuthorizationLedger,
        consumed: ConsumedCaptureAuthorization,
    ) -> None:
        """Atomically publish both inputs needed for lease recovery."""

        holding = _CaptureValidationHolding(ledger, consumed)
        with self._lock:
            if self._capture_validation_holding is not None:
                raise _pipeline_error("截图校验恢复 owner 已经发布。")
            self._capture_validation_holding = holding

    def capture_validation_holding_is_exact(
        self,
        ledger: CaptureAuthorizationLedger,
        consumed: ConsumedCaptureAuthorization,
    ) -> bool:
        """Observe one exact atomic validation-recovery publication."""

        with self._lock:
            holding = self._capture_validation_holding
            return (
                type(holding) is _CaptureValidationHolding
                and holding.ledger is ledger
                and holding.consumed is consumed
            )

    def publish_credential_permit(
        self,
        permit: CredentialResolutionPermit,
    ) -> CredentialResolutionPermit:
        """Pre-hold the cleanup proof before AttemptGate publishes activity."""

        if type(permit) is not CredentialResolutionPermit:
            raise TypeError("permit must be CredentialResolutionPermit")
        with self._lock:
            if self._credential_permit_holding is not None:
                raise _pipeline_error("凭据授权清理 owner 已经发布。")
            holding = _CredentialPermitHolding(permit)
            self._credential_permit_holding = holding
            if self._credential_permit_holding is not holding:
                raise _pipeline_error("凭据授权清理 owner 未提交。")
            return permit

    @property
    def credential_permit(self) -> CredentialResolutionPermit | None:
        with self._lock:
            holding = self._credential_permit_holding
            if type(holding) is not _CredentialPermitHolding:
                return None
            return holding.permit

    def credential_permit_is_current(
        self,
        permit: CredentialResolutionPermit,
    ) -> bool:
        with self._lock:
            holding = self._credential_permit_holding
            return (
                type(holding) is _CredentialPermitHolding
                and holding.permit is permit
            )


class _ActiveRunOwner:
    """One caller-owned active marker with an exact in-progress signal."""

    __slots__ = ("state", "_live")

    def __init__(self, state: _RunState) -> None:
        self.state = state
        self._live = Lock()
        if self._live.acquire(blocking=False) is not True:
            raise RuntimeError("active owner initialization failed")

    @property
    def is_live(self) -> bool:
        return self._live.locked()

    def finish(self) -> None:
        if self._live.locked():
            self._live.release()


_FailureSnapshot = tuple[
    type[OperationError],
    str,
    bool,
    str,
    str | None,
    int | None,
]


def _snapshot_failure(error: BaseException) -> _FailureSnapshot:
    if isinstance(error, OperationError):
        return (
            type(error),
            error.stage,
            error.retryable,
            error.safe_message,
            error.provider_profile_id,
            error.attempt,
        )
    if isinstance(error, KeyboardInterrupt):
        return (
            CancelledError,
            "multimodal_pipeline",
            False,
            "操作已取消。",
            None,
            None,
        )
    return (
        ConfigError,
        "multimodal_pipeline",
        False,
        "多模态流水线未能安全完成。",
        None,
        None,
    )


def _raise_failure(snapshot: _FailureSnapshot) -> NoReturn:
    error_type, stage, retryable, message, provider_profile_id, attempt = snapshot
    try:
        error = error_type(
            stage=stage,
            retryable=retryable,
            safe_message=message,
            provider_profile_id=provider_profile_id,
            attempt=attempt,
        )
    except BaseException:
        error = _pipeline_error("多模态流水线未能安全完成。")
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error from None


def _finalize_run_state(state: _RunState) -> SolveResult:
    failure = state.failure
    if failure is not None:
        _raise_failure(failure)
    if type(state.result) is not SolveResult:
        raise _pipeline_error("多模态流水线没有可交付的终态结果。")
    return state.result


@runtime_final
class MultimodalPipelineExecutor:
    """Single-stage, single-operation Phase 1 direct pipeline executor."""

    __slots__ = (
        "_lock",
        "_active_request_ids",
        "_recovery_states",
        "_adapter",
        "_capture_source",
        "_preview_controller",
        "_launcher",
        "_credential_resolver",
        "_transport",
    )

    def __init__(
        self,
        *,
        adapter: DirectMultimodalAdapter,
        capture_source: MultimodalCaptureSource,
        preview_controller: EgressPreviewController,
        launcher: ResolverHelperLauncher,
        credential_resolver: CredentialResolver,
        transport: RemoteTransport,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _EXECUTOR_CONSTRUCTION_AUTHORITY:
            raise TypeError(
                "MultimodalPipelineExecutor requires a trusted composition factory"
            )
        if not isinstance(adapter, DirectMultimodalAdapter):
            raise TypeError("adapter must be DirectMultimodalAdapter")
        if not isinstance(capture_source, MultimodalCaptureSource):
            raise TypeError("capture_source must be MultimodalCaptureSource")
        if not isinstance(preview_controller, EgressPreviewController):
            raise TypeError("preview_controller must be EgressPreviewController")
        if type(launcher) is not ResolverHelperLauncher:
            raise TypeError("launcher must be ResolverHelperLauncher")
        if type(credential_resolver) is not CredentialResolver:
            raise TypeError("credential_resolver must be CredentialResolver")
        if not isinstance(transport, RemoteTransport):
            raise TypeError("transport must be RemoteTransport")
        self._lock = RLock()
        self._active_request_ids: dict[UUID, _ActiveRunOwner] = {}
        self._recovery_states: dict[UUID, _RunState] = {}
        self._adapter = adapter
        self._capture_source = capture_source
        self._preview_controller = preview_controller
        self._launcher = launcher
        self._credential_resolver = credential_resolver
        self._transport = transport

    @classmethod
    def _for_testing(
        cls,
        *,
        adapter: DirectMultimodalAdapter,
        capture_source: MultimodalCaptureSource,
        preview_controller: EgressPreviewController,
        launcher: ResolverHelperLauncher,
        credential_resolver: CredentialResolver,
        transport: RemoteTransport,
        _authority: object | None = None,
    ) -> "MultimodalPipelineExecutor":
        """Build an injected executor only for deterministic offline tests."""

        if _authority is not _TEST_PIPELINE_AUTHORITY:
            raise TypeError("offline pipeline injection requires test authority")
        return cls(
            adapter=adapter,
            capture_source=capture_source,
            preview_controller=preview_controller,
            launcher=launcher,
            credential_resolver=credential_resolver,
            transport=transport,
            _authority=_EXECUTOR_CONSTRUCTION_AUTHORITY,
        )

    @classmethod
    def production(cls) -> NoReturn:
        """Fail before dependency construction while production remains gated."""

        del cls
        raise EndpointPolicyError(
            stage="multimodal_pipeline",
            retryable=False,
            safe_message="生产多模态流水线尚未启用。",
        )

    @staticmethod
    def _validate_request(
        *,
        planned: PlannedExecution,
        intent: SolveIntent,
        consent_ledger: ConsentLedger,
        consent_grant_ids: tuple[UUID, ...],
        authority_ledger: RegistryPolicyAuthorityLedger,
        context_ledger: CallContextLedger,
        selected_scope: CaptureScope,
        capture_id: UUID,
    ) -> None:
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(intent) is not SolveIntent:
            raise TypeError("intent must be SolveIntent")
        if type(consent_ledger) is not ConsentLedger:
            raise TypeError("consent_ledger must be ConsentLedger")
        if (
            type(consent_grant_ids) is not tuple
            or not consent_grant_ids
            or not all(type(item) is UUID for item in consent_grant_ids)
        ):
            raise TypeError("consent_grant_ids must contain UUID values")
        if type(authority_ledger) is not RegistryPolicyAuthorityLedger:
            raise TypeError("authority_ledger must be RegistryPolicyAuthorityLedger")
        if type(context_ledger) is not CallContextLedger:
            raise TypeError("context_ledger must be CallContextLedger")
        if type(selected_scope) is not CaptureScope:
            raise TypeError("selected_scope must be CaptureScope")
        require_uuid(capture_id, "capture_id")
        try:
            planned.validate_integrity()
            intent.validate_integrity()
            selected_scope.validate_integrity()
            validate_phase1_remote_direct_plan(planned.plan)
        except (TypeError, ValueError, AttributeError):
            raise _pipeline_error("多模态请求、计划或选区合同无效。") from None
        if (
            planned.solve_intent_digest != intent.intent_digest
            or planned.plan.request_id != intent.request_id
            or planned.plan.pipeline_kind is not PipelineKind.DIRECT_MULTIMODAL
        ):
            raise _pipeline_error("请求意图与 direct multimodal 计划不匹配。")

    def _observe(
        self,
        action,
        *,
        expected_at: datetime,
    ) -> CaptureObservation:
        try:
            observation = action()
        except OperationError:
            raise
        except KeyboardInterrupt:
            raise CancelledError(stage="multimodal_capture") from None
        except BaseException:
            raise _capture_error("无法取得可信权限与显示器拓扑快照。") from None
        if type(observation) is not CaptureObservation:
            raise _capture_error("截图来源返回了无效观察值。")
        try:
            observation.validate_integrity()
            if observation.observed_at != expected_at:
                raise ValueError("capture observation does not match runtime sample")
        except (TypeError, ValueError, AttributeError):
            raise _capture_error("截图观察值未绑定当前运行时时间。") from None
        return observation

    @staticmethod
    def _sample_active(
        *,
        context_ledger: CallContextLedger,
        context: CallContext,
        cancellation: MultimodalCancellation,
        cancellation_source: CancellationSource,
        cancellation_owner: object,
    ):
        """Redrive one pending stop before every W10 authority checkpoint."""

        try:
            cancellation._apply_pending_cancellation(
                cancellation_source,
                owner=cancellation_owner,
                _authority=_CANCELLATION_HANDLE_AUTHORITY,
            )
        except BaseException:
            pass
        try:
            settled = cancellation._pending_cancellation_is_settled(
                cancellation_source,
                owner=cancellation_owner,
                _authority=_CANCELLATION_HANDLE_AUTHORITY,
            )
        except BaseException:
            settled = False
        if type(settled) is not bool or settled is not True:
            try:
                stop_requested = cancellation._stop_is_requested(
                    cancellation_source,
                    owner=cancellation_owner,
                    _authority=_CANCELLATION_HANDLE_AUTHORITY,
                )
            except BaseException:
                stop_requested = False
            if type(stop_requested) is bool and stop_requested is True:
                try:
                    context_ledger.sample_active(context)
                except OperationError:
                    raise
                raise CancelledError(stage="call_context")
            raise _pipeline_error("取消状态未能安全确认。")
        return context_ledger.sample_active(context)

    def _capture(
        self,
        consumed: ConsumedCaptureAuthorization,
    ) -> CapturedFrame:
        try:
            frame = self._capture_source.capture_once(consumed=consumed)
        except OperationError:
            raise
        except KeyboardInterrupt:
            raise CancelledError(stage="multimodal_capture") from None
        except BaseException:
            raise _capture_error("截图来源未能安全返回图像。") from None
        if type(frame) is not CapturedFrame:
            raise _capture_error("截图来源返回了无效图像。")
        try:
            frame.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _capture_error("截图来源返回的图像合同无效。") from None
        return frame

    def _prepare(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        operation_id: UUID,
    ) -> PreparedOutbound:
        try:
            prepared = self._adapter.prepare(
                planned=planned,
                invocation=invocation,
                operation_id=operation_id,
            )
        except OperationError:
            raise
        except KeyboardInterrupt:
            raise CancelledError(stage="multimodal_adapter") from None
        except BaseException:
            raise _pipeline_error("多模态 Adapter 未能安全准备请求。") from None
        if type(prepared) is not PreparedOutbound:
            raise _pipeline_error("多模态 Adapter 返回了无效请求包络。")
        return prepared

    def _send(
        self,
        *,
        prepared_attempt: PreparedResolverAttempt,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
    ) -> TransportResponse:
        try:
            response = self._transport.send_once(prepared_attempt)
        except OperationError:
            raise
        except KeyboardInterrupt:
            raise CancelledError(stage="multimodal_transport") from None
        except BaseException:
            raise _transport_error() from None
        if type(response) is not TransportResponse:
            raise _transport_error()
        try:
            response.validate_integrity()
        except (TypeError, ValueError, AttributeError):
            raise _transport_error() from None
        if (
            response.plan_id != planned.plan.plan_id
            or response.stage_id != invocation.stage_id
            or response.operation_id != prepared.operation_id
            or response.request_envelope_digest
            != prepared.request_envelope_digest
            or prepared_attempt.attempt_permit.operation_id
            != prepared.operation_id
            or prepared_attempt.attempt_permit.request_envelope_digest
            != prepared.request_envelope_digest
            or not prepared_attempt.is_closed
        ):
            raise _transport_error()
        return response

    def _register_run(
        self,
        state: _RunState,
        *,
        active_owner: _ActiveRunOwner,
    ) -> bool:
        """Publish recovery first, then an exact caller-owned active marker."""

        with self._lock:
            if self._active_request_ids:
                raise _RunRegistrationConflict(cleanup_pending=False)
            if self._recovery_states:
                raise _RunRegistrationConflict(cleanup_pending=True)
            self._recovery_states[state.request_id] = state
            self._active_request_ids[state.request_id] = active_owner
            return (
                self._recovery_states.get(state.request_id) is state
                and self._active_request_ids.get(state.request_id)
                is active_owner
            )

    def _run_bookkeeping_is_settled(
        self,
        state: _RunState,
        *,
        active_owner: _ActiveRunOwner,
        cleanup_complete: bool,
    ) -> bool:
        """Independently observe active/recovery bookkeeping terminality."""

        if type(cleanup_complete) is not bool:
            return False
        with self._lock:
            active_is_absent = (
                state.request_id not in self._active_request_ids
                and not any(
                    owner is active_owner
                    for owner in self._active_request_ids.values()
                )
            )
            current = self._recovery_states.get(state.request_id)
            if cleanup_complete:
                recovery_is_exact = (
                    current is None
                    and not any(
                        candidate is state
                        for candidate in self._recovery_states.values()
                    )
                )
            else:
                recovery_is_exact = (
                    current is state
                    and sum(
                        candidate is state
                        for candidate in self._recovery_states.values()
                    )
                    == 1
                )
            return active_is_absent and recovery_is_exact

    def _settle_run_bookkeeping(
        self,
        state: _RunState,
        *,
        active_owner: _ActiveRunOwner,
        cleanup_complete: bool,
    ) -> None:
        """Best-effort exact cleanup for interruptible collection mutations."""

        with self._lock:
            try:
                active = self._active_request_ids.get(state.request_id)
            except BaseException:
                return
            if active is active_owner:
                try:
                    del self._active_request_ids[state.request_id]
                except BaseException:
                    pass
            elif active is not None:
                return

            # Recovery is the sole durable route to repair an orphaned active
            # marker.  Never delete it until independent observation proves
            # that this owner's key and every possible alias are absent.
            try:
                active_is_absent = (
                    state.request_id not in self._active_request_ids
                    and not any(
                        candidate is active_owner
                        for candidate in self._active_request_ids.values()
                    )
                )
            except BaseException:
                return
            if not active_is_absent:
                return

            try:
                current = self._recovery_states.get(state.request_id)
            except BaseException:
                return
            if cleanup_complete:
                if current is state:
                    try:
                        del self._recovery_states[state.request_id]
                    except BaseException:
                        pass
                return
            if current is None:
                try:
                    self._recovery_states[state.request_id] = state
                except BaseException:
                    pass

    def _retain_run_for_recovery(
        self,
        state: _RunState,
        *,
        active_owner: _ActiveRunOwner,
    ) -> None:
        """Restore a cleanup-only route whenever terminal removal is unproven."""

        try:
            self._settle_run_bookkeeping(
                state,
                active_owner=active_owner,
                cleanup_complete=False,
            )
        except BaseException:
            pass

    def _settle_and_observe_run_bookkeeping(
        self,
        state: _RunState,
        *,
        active_owner: _ActiveRunOwner,
        cleanup_complete: bool,
    ) -> bool:
        """Atomically settle, observe, and restore the recovery route."""

        with self._lock:
            try:
                self._settle_run_bookkeeping(
                    state,
                    active_owner=active_owner,
                    cleanup_complete=cleanup_complete,
                )
            except BaseException:
                pass
            try:
                settled = self._run_bookkeeping_is_settled(
                    state,
                    active_owner=active_owner,
                    cleanup_complete=cleanup_complete,
                )
                bookkeeping_complete = (
                    type(settled) is bool and settled is True
                )
            except BaseException:
                bookkeeping_complete = False
            if not bookkeeping_complete:
                self._retain_run_for_recovery(
                    state,
                    active_owner=active_owner,
                )
            return bookkeeping_complete

    def _run(
        self,
        *,
        state: _RunState,
        planned: PlannedExecution,
        intent: SolveIntent,
        consent_ledger: ConsentLedger,
        consent_grant_ids: tuple[UUID, ...],
        authority_ledger: RegistryPolicyAuthorityLedger,
        context_ledger: CallContextLedger,
        selected_scope: CaptureScope,
        capture_id: UUID,
        cancellation: MultimodalCancellation,
    ) -> SolveResult:
        stage = planned.plan.stages[0]
        operation = stage.network_operations[0]
        if (
            self._adapter.adapter_family != stage.adapter_family
            or self._adapter.adapter_version != stage.adapter_version
        ):
            raise _pipeline_error("Adapter 与冻结阶段 binding 不匹配。")

        authorization, context, cancellation_source = (
            RuntimeCallFactory.authorize_and_start(
                planned=planned,
                consent_ledger=consent_ledger,
                consent_grant_ids=consent_grant_ids,
                authority_ledger=authority_ledger,
                context_ledger=context_ledger,
                _start_owner=state.context_start_owner,
                _authority=_CONTEXT_RECOVERY_AUTHORITY,
            )
        )
        try:
            start_result_is_exact = (
                context_ledger._context_start_result_is_exact(
                    request_id=state.request_id,
                    planned_execution_digest=state.planned_execution_digest,
                    start_owner=state.context_start_owner,
                    authorization=authorization,
                    context=context,
                    source=cancellation_source,
                    _authority=_CONTEXT_RECOVERY_AUTHORITY,
                )
            )
        except BaseException:
            start_result_is_exact = False
        if (
            type(start_result_is_exact) is not bool
            or start_result_is_exact is not True
        ):
            raise _pipeline_error("CallContext factory 返回绑定无法证明。")
        state.context = context
        binding_failure: BaseException | None = None
        try:
            cancellation._bind(
                cancellation_source,
                owner=state.cancellation_owner,
                _authority=_CANCELLATION_HANDLE_AUTHORITY,
            )
        except BaseException as error:
            binding_failure = error
        try:
            binding_is_exact = cancellation._binding_is_exact(
                cancellation_source,
                owner=state.cancellation_owner,
                _authority=_CANCELLATION_HANDLE_AUTHORITY,
            )
        except BaseException:
            binding_is_exact = False
        if type(binding_is_exact) is not bool or binding_is_exact is not True:
            if binding_failure is not None:
                raise binding_failure from None
            raise _pipeline_error("取消句柄 binding 未提交。")

        def sample_active():
            return self._sample_active(
                context_ledger=context_ledger,
                context=context,
                cancellation=cancellation,
                cancellation_source=cancellation_source,
                cancellation_owner=state.cancellation_owner,
            )

        first_sample = sample_active()
        first_observation = self._observe(
            lambda: self._capture_source.observe_for_authorization(
                planned=planned,
                now=first_sample.wall_time,
            ),
            expected_at=first_sample.wall_time,
        )
        sample_active()
        capture_ledger = CaptureAuthorizationLedger()
        capture_authorization = CapturePolicy().authorize(
            planned=planned,
            privacy_authorization=authorization,
            consent_ledger=consent_ledger,
            permission_observation=first_observation.permission,
            topology=first_observation.topology,
            selected_scope=selected_scope,
            capture_id=capture_id,
            capture_ledger=capture_ledger,
            now=first_observation.observed_at,
        )
        try:
            capture_authorization_is_exact = (
                capture_ledger._authorization_is_exact_for_execution(
                    capture_authorization,
                    _authority=_CAPTURE_EXECUTION_OBSERVATION_AUTHORITY,
                )
            )
        except BaseException:
            capture_authorization_is_exact = False
        if (
            type(capture_authorization_is_exact) is not bool
            or capture_authorization_is_exact is not True
        ):
            raise _pipeline_error(
                "CapturePolicy 授权返回绑定无法证明。"
            )

        pre_sample = sample_active()
        pre_observation = self._observe(
            lambda: self._capture_source.observe_before_capture(
                authorization=capture_authorization,
                now=pre_sample.wall_time,
            ),
            expected_at=pre_sample.wall_time,
        )
        sample_active()
        consumed = CapturePolicy().prepare_capture(
            planned=planned,
            privacy_authorization=authorization,
            consent_ledger=consent_ledger,
            authorization=capture_authorization,
            capture_ledger=capture_ledger,
            permission_observation=pre_observation.permission,
            topology=pre_observation.topology,
            now=pre_observation.observed_at,
        )
        try:
            capture_consumption_is_exact = (
                capture_ledger._consumption_is_exact_for_execution(
                    consumed,
                    authorization=capture_authorization,
                    _authority=_CAPTURE_EXECUTION_OBSERVATION_AUTHORITY,
                )
            )
        except BaseException:
            capture_consumption_is_exact = False
        if (
            type(capture_consumption_is_exact) is not bool
            or capture_consumption_is_exact is not True
        ):
            raise _pipeline_error(
                "CapturePolicy 消费返回绑定无法证明。"
            )
        capture_holding_failure: BaseException | None = None
        try:
            state.publish_capture_validation_holding(
                capture_ledger,
                consumed,
            )
        except BaseException as error:
            capture_holding_failure = error
        try:
            capture_holding_is_exact = (
                state.capture_validation_holding_is_exact(
                    capture_ledger,
                    consumed,
                )
            )
        except BaseException:
            capture_holding_is_exact = False
        if (
            type(capture_holding_is_exact) is not bool
            or capture_holding_is_exact is not True
        ):
            if capture_holding_failure is not None:
                raise capture_holding_failure from None
            raise _pipeline_error(
                "截图校验恢复 owner publication 未提交。"
            )
        sample_active()
        # The consent/capture consumption above and this runtime claim are two
        # ordered race fences.  Cancellation/reload before this claim prevents
        # capture; after it commits, the one synchronous capture has started
        # and later cancellation is enforced at the post-capture checkpoint.
        capture_claim_failure: BaseException | None = None
        try:
            context_ledger._claim_capture_start(
                context,
                _authority=_CAPTURE_START_AUTHORITY,
            )
        except BaseException as error:
            capture_claim_failure = error
        try:
            capture_claimed = context_ledger._capture_start_is_claimed(
                context,
                _authority=_CAPTURE_START_AUTHORITY,
            )
        except BaseException:
            if capture_claim_failure is not None:
                raise capture_claim_failure from None
            raise
        if type(capture_claimed) is not bool or capture_claimed is not True:
            if capture_claim_failure is not None:
                raise capture_claim_failure from None
            raise _pipeline_error("截图开始 claim 未提交。")
        frame = self._capture(consumed)
        post_sample = sample_active()
        artifact = CaptureArtifactFactory.create(
            consumed=consumed,
            capture_ledger=capture_ledger,
            data=frame.data,
            mime_type=frame.mime_type,
            width_px=frame.width_px,
            height_px=frame.height_px,
            captured_at=post_sample.wall_time,
        )
        observation_sample = sample_active()
        post_observation = self._observe(
            lambda: self._capture_source.observe_after_capture(
                consumed=consumed,
                frame=frame,
                now=observation_sample.wall_time,
            ),
            expected_at=observation_sample.wall_time,
        )
        # An observation implementation may block.  Check the monotonic
        # authority again before accepting its earlier wall-time evidence.
        sample_active()
        validated = InputValidator.validate(
            planned=planned,
            privacy_authorization=authorization,
            consent_ledger=consent_ledger,
            consumed=consumed,
            capture_ledger=capture_ledger,
            artifact=artifact,
            permission_observation=post_observation.permission,
            topology=post_observation.topology,
            now=post_observation.observed_at,
        )
        try:
            validated_is_exact = capture_ledger._validated_capture_is_exact(
                consumed=consumed,
                validated_capture=validated,
                validation_digest=validated.validation_digest,
                _authority=_CAPTURE_VALIDATION_AUTHORITY,
            )
        except BaseException:
            validated_is_exact = False
        if (
            type(validated_is_exact) is not bool
            or validated_is_exact is not True
        ):
            raise _pipeline_error(
                "InputValidator 返回绑定无法证明。"
            )
        state.validated = validated

        solve_request = SolveRequestFactory.create(
            planned=planned,
            intent=intent,
            validated_capture=validated,
        )
        solve_request_is_exact = False
        if type(solve_request) is SolveRequest:
            try:
                solve_request.validate_integrity()
                solve_request_is_exact = (
                    solve_request.input is validated
                    and solve_request.request_id == planned.plan.request_id
                    and solve_request.plan_id == planned.plan.plan_id
                    and solve_request.plan_digest == planned.plan.plan_digest
                    and solve_request.planned_execution_digest
                    == planned.planned_execution_digest
                    and solve_request.solve_intent_digest
                    == intent.intent_digest
                    and solve_request.input_digest
                    == validated.validation_digest
                )
            except BaseException:
                solve_request_is_exact = False
        if (
            type(solve_request_is_exact) is not bool
            or solve_request_is_exact is not True
        ):
            raise _pipeline_error(
                "SolveRequest factory 返回绑定无法证明。"
            )
        invocation = StageInvocationFactory.create(
            planned=planned,
            solve_request=solve_request,
            stage_id=stage.stage_id,
        )
        invocation_is_exact = False
        if type(invocation) is StageInvocation:
            try:
                invocation.validate_integrity()
                invocation_is_exact = (
                    invocation.input is validated
                    and invocation.request_id == planned.plan.request_id
                    and invocation.plan_id == planned.plan.plan_id
                    and invocation.plan_digest == planned.plan.plan_digest
                    and invocation.planned_execution_digest
                    == planned.planned_execution_digest
                    and invocation.stage_id == stage.stage_id
                    and invocation.solve_request_digest
                    == solve_request.solve_request_digest
                    and invocation.input_digest
                    == validated.validation_digest
                )
            except BaseException:
                invocation_is_exact = False
        if (
            type(invocation_is_exact) is not bool
            or invocation_is_exact is not True
        ):
            raise _pipeline_error(
                "StageInvocation factory 返回绑定无法证明。"
            )
        prepared = self._prepare(
            planned=planned,
            invocation=invocation,
            operation_id=operation.operation_id,
        )
        sample_active()

        approval_ledger = EgressApprovalLedger()
        approval = EgressGate().approve(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            approval_ledger=approval_ledger,
            preview_controller=self._preview_controller,
        )
        session_sample = sample_active()
        session_ledger = SendSessionLedger()
        session = SendSessionFactory.create(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            approval=approval,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            now=session_sample.wall_time,
        )
        sample_active()

        gate = AttemptGate()
        state.attempt_gate = gate
        credential_permit = gate.authorize_credential_resolution(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            authorization=authorization,
            consent_ledger=consent_ledger,
            session=session,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            authority_ledger=authority_ledger,
            context=context,
            context_ledger=context_ledger,
            _publication=state.publish_credential_permit,
            _publication_is_current=state.credential_permit_is_current,
            _authority=_CREDENTIAL_PERMIT_PUBLICATION_AUTHORITY,
        )
        if state.credential_permit is not credential_permit:
            raise _pipeline_error("凭据授权 publication 未提交。")

        sample_active()

        cleanup_ticket = issue_resolver_cleanup_ticket()
        state.cleanup_ticket = cleanup_ticket
        prepared_attempt = coordinate_resolver_attempt(
            launcher=self._launcher,
            credential_resolver=self._credential_resolver,
            gate=gate,
            credential_permit=credential_permit,
            cleanup_ticket=cleanup_ticket,
        )
        try:
            prepared_attempt_is_exact = (
                cleanup_ticket._prepared_is_exact_for_caller(
                    prepared_attempt,
                    launcher=self._launcher,
                    credential_resolver=self._credential_resolver,
                    gate=gate,
                    credential_permit=credential_permit,
                    context_id=context.context_id,
                    session_id=session.session_id,
                    operation_id=operation.operation_id,
                    request_envelope_digest=prepared.request_envelope_digest,
                )
            )
        except BaseException:
            prepared_attempt_is_exact = False
        if (
            type(prepared_attempt_is_exact) is not bool
            or prepared_attempt_is_exact is not True
        ):
            raise _pipeline_error(
                "resolver attempt 返回绑定无法证明。"
            )
        state.prepared_attempt = prepared_attempt
        sample_active()
        response = self._send(
            prepared_attempt=prepared_attempt,
            planned=planned,
            invocation=invocation,
            prepared=prepared,
        )
        transport_finished = sample_active()
        transport_started_ns = (
            prepared_attempt.attempt_permit.reserved_monotonic_ns
        )
        if transport_finished.monotonic_after_ns < transport_started_ns:
            raise _transport_error()
        transport_latency_ms = (
            transport_finished.monotonic_after_ns
            - transport_started_ns
            + 999_999
        ) // 1_000_000

        candidate = self._adapter.decode(
            planned=planned,
            invocation=invocation,
            prepared=prepared,
            response=response,
        )
        if type(candidate) is not AnswerCandidateResult:
            raise InvalidOutputError(stage="adapter_decode")
        if candidate.response_body_digest != response.response_body_digest:
            raise InvalidOutputError(stage="adapter_decode")
        sample_active()

        operation_budget = context_ledger.snapshot_budget(
            context.operation_budgets[0]
        )
        global_budget = context_ledger.snapshot_budget(
            context.global_network_budget
        )
        billable_budget = context_ledger.snapshot_budget(
            context.billable_budget
        )
        expected_billable = (
            1
            if operation.billable is True
            or operation.billable is ContractMarker.UNKNOWN
            else 0
        )
        if (
            operation_budget.consumed != 1
            or global_budget.consumed != 1
            or billable_budget.consumed != expected_billable
        ):
            raise _transport_error()

        resolved_stage = planned.resolved_pipeline.stages[0]
        provenance = SolveProvenance(
            pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
            plan_id=planned.plan.plan_id,
            stages=(
                StageProvenance(
                    stage_id=stage.stage_id,
                    role=stage.role,
                    binding_id=stage.binding_id,
                    provider_profile_id=stage.provider_profile_id,
                    provider_profile_digest=stage.provider_profile_digest,
                    provider_id=stage.provider_id,
                    model_id=stage.model_id,
                    component_id=None,
                    component_version=None,
                    adapter_family=stage.adapter_family,
                    adapter_version=stage.adapter_version,
                    capabilities_ref=stage.capabilities_ref,
                    capabilities_digest=stage.capabilities_digest,
                    attempts=operation_budget.consumed,
                    network_calls=global_budget.consumed,
                    latency_ms=transport_latency_ms,
                    usage=candidate.usage,
                ),
            ),
        )
        provider_profile_id = (
            resolved_stage.provider_profile.provider_profile_id
        )
        result = validate_answer_candidate(
            candidate,
            provenance=provenance,
            request_id=planned.plan.request_id,
            plan_id=planned.plan.plan_id,
            plan_digest=planned.plan.plan_digest,
            stage_id=stage.stage_id,
            operation_id=operation.operation_id,
            invocation_digest=invocation.invocation_digest,
            request_envelope_digest=prepared.request_envelope_digest,
            provider_profile_id=provider_profile_id,
        )
        try:
            candidate.validate_binding(
                request_id=planned.plan.request_id,
                plan_id=planned.plan.plan_id,
                plan_digest=planned.plan.plan_digest,
                stage_id=stage.stage_id,
                operation_id=operation.operation_id,
                invocation_digest=invocation.invocation_digest,
                request_envelope_digest=prepared.request_envelope_digest,
            )
            expected_result = validate_solve_result(
                candidate.candidate_payload,
                provenance=provenance,
                provider_profile_id=provider_profile_id,
            )
        except InvalidOutputError:
            raise
        except (TypeError, ValueError, AttributeError):
            raise InvalidOutputError(
                stage="result_validation",
                provider_profile_id=provider_profile_id,
            ) from None
        result_is_exact = False
        if type(result) is SolveResult:
            try:
                result_is_exact = (
                    result.provenance is provenance
                    and all(
                        getattr(result, field) == getattr(expected_result, field)
                        for field in SolveResult.__slots__
                    )
                )
            except BaseException:
                result_is_exact = False
        if type(result_is_exact) is not bool or result_is_exact is not True:
            raise InvalidOutputError(
                stage="result_validation",
                provider_profile_id=provider_profile_id,
            )
        state.result = result
        sample_active()
        result_claim_failure: BaseException | None = None
        try:
            context_ledger._claim_result_publication(
                context,
                _authority=_RESULT_PUBLICATION_AUTHORITY,
            )
        except BaseException as error:
            result_claim_failure = error
        try:
            result_claimed = context_ledger._result_publication_is_claimed(
                context,
                _authority=_RESULT_PUBLICATION_AUTHORITY,
            )
        except BaseException:
            if result_claim_failure is not None:
                raise result_claim_failure from None
            raise
        if type(result_claimed) is not bool or result_claimed is not True:
            if result_claim_failure is not None:
                raise result_claim_failure from None
            raise _pipeline_error("结果发布 claim 未提交。")
        return result

    def execute(
        self,
        *,
        planned: PlannedExecution,
        intent: SolveIntent,
        consent_ledger: ConsentLedger,
        consent_grant_ids: tuple[UUID, ...],
        authority_ledger: RegistryPolicyAuthorityLedger,
        context_ledger: CallContextLedger,
        selected_scope: CaptureScope,
        capture_id: UUID,
        cancellation: MultimodalCancellation | None = None,
    ) -> SolveResult:
        """Execute one test-authorized request and retain uncertain cleanup."""

        self._validate_request(
            planned=planned,
            intent=intent,
            consent_ledger=consent_ledger,
            consent_grant_ids=consent_grant_ids,
            authority_ledger=authority_ledger,
            context_ledger=context_ledger,
            selected_scope=selected_scope,
            capture_id=capture_id,
        )
        if cancellation is None:
            cancellation = MultimodalCancellation()
        elif type(cancellation) is not MultimodalCancellation:
            raise TypeError("cancellation must be MultimodalCancellation")
        if cancellation.is_finished:
            raise _pipeline_error("取消句柄已经终结。")

        request_id = planned.plan.request_id
        state = _RunState(
            context_ledger,
            cancellation,
            request_id=request_id,
            planned_execution_digest=planned.planned_execution_digest,
        )
        active_owner = _ActiveRunOwner(state)
        cleanup_complete = False
        bookkeeping_complete = False
        registration_conflict: _RunRegistrationConflict | None = None
        try:
            try:
                registration = self._register_run(
                    state,
                    active_owner=active_owner,
                )
                if type(registration) is not bool or registration is not True:
                    raise _pipeline_error("请求恢复 owner publication 未提交。")
                self._run(
                    state=state,
                    planned=planned,
                    intent=intent,
                    consent_ledger=consent_ledger,
                    consent_grant_ids=consent_grant_ids,
                    authority_ledger=authority_ledger,
                    context_ledger=context_ledger,
                    selected_scope=selected_scope,
                    capture_id=capture_id,
                    cancellation=cancellation,
                )
            except BaseException as error:
                if type(error) is _RunRegistrationConflict:
                    registration_conflict = error
                else:
                    result_committed = False
                    if (
                        type(state.result) is SolveResult
                        and state.context is not None
                    ):
                        try:
                            observed = (
                                context_ledger._result_publication_is_claimed(
                                    state.context,
                                    _authority=_RESULT_PUBLICATION_AUTHORITY,
                                )
                            )
                            result_committed = (
                                type(observed) is bool and observed is True
                            )
                        except BaseException:
                            result_committed = False
                    if result_committed:
                        state.failure = None
                    else:
                        state.failure = _snapshot_failure(error)
        finally:
            if registration_conflict is None:
                try:
                    cleanup_complete = state.cleanup()
                except BaseException:
                    cleanup_complete = False
                try:
                    bookkeeping_complete = (
                        self._settle_and_observe_run_bookkeeping(
                            state,
                            active_owner=active_owner,
                            cleanup_complete=cleanup_complete,
                        )
                    )
                except BaseException:
                    bookkeeping_complete = False
                    self._retain_run_for_recovery(
                        state,
                        active_owner=active_owner,
                    )
            try:
                active_owner.finish()
            except BaseException:
                pass
        if registration_conflict is not None:
            if registration_conflict.cleanup_pending:
                raise _cleanup_error() from None
            raise _pipeline_error("该执行器已有请求正在执行。") from None
        if not cleanup_complete or not bookkeeping_complete:
            raise _cleanup_error() from None
        return _finalize_run_state(state)

    def retry_cleanup_and_finalize(self, request_id: UUID) -> SolveResult:
        """Terminalize retained owners, then deliver the original outcome."""

        require_uuid(request_id, "request_id")
        active_owner: _ActiveRunOwner | None = None
        state: _RunState | None = None
        registration = False
        missing = False
        busy = False
        try:
            with self._lock:
                state = self._recovery_states.get(request_id)
                if state is None:
                    missing = True
                else:
                    for owner_request_id, current_owner in tuple(
                        self._active_request_ids.items()
                    ):
                        if (
                            type(current_owner) is _ActiveRunOwner
                            and current_owner.state is state
                            and current_owner.is_live is False
                        ):
                            try:
                                del self._active_request_ids[
                                    owner_request_id
                                ]
                            except BaseException:
                                pass
                        else:
                            busy = True
                    if self._active_request_ids:
                        registration = False
                    elif not busy:
                        active_owner = _ActiveRunOwner(state)
                        self._active_request_ids[request_id] = active_owner
                        registration = (
                            self._active_request_ids.get(request_id)
                            is active_owner
                            and self._recovery_states.get(request_id) is state
                        )
        except BaseException:
            registration = False
        if missing:
            raise _pipeline_error("没有该请求的待恢复清理状态。")
        if busy:
            raise _pipeline_error("该请求的清理当前正在执行。")
        if type(registration) is not bool or registration is not True:
            if state is not None and active_owner is not None:
                try:
                    settled = self._settle_and_observe_run_bookkeeping(
                        state,
                        active_owner=active_owner,
                        cleanup_complete=False,
                    )
                except BaseException:
                    settled = False
                    self._retain_run_for_recovery(
                        state,
                        active_owner=active_owner,
                    )
                try:
                    active_owner.finish()
                except BaseException:
                    pass
            raise _pipeline_error("无法开始待恢复资源清理。") from None
        assert state is not None
        assert active_owner is not None
        cleanup_complete = False
        bookkeeping_complete = False
        try:
            try:
                cleanup_complete = state.cleanup()
            except BaseException:
                cleanup_complete = False
        finally:
            try:
                bookkeeping_complete = (
                    self._settle_and_observe_run_bookkeeping(
                        state,
                        active_owner=active_owner,
                        cleanup_complete=cleanup_complete,
                    )
                )
            except BaseException:
                bookkeeping_complete = False
                self._retain_run_for_recovery(
                    state,
                    active_owner=active_owner,
                )
            try:
                active_owner.finish()
            except BaseException:
                pass
        if not cleanup_complete or not bookkeeping_complete:
            raise _cleanup_error() from None
        return _finalize_run_state(state)

    def pending_cleanup_metadata(self) -> dict[str, object]:
        """Expose only safe identifiers for retained cleanup work."""

        with self._lock:
            pending: list[str] = []
            for request_id, state in self._recovery_states.items():
                owner = self._active_request_ids.get(request_id)
                if owner is None or (
                    type(owner) is _ActiveRunOwner
                    and owner.state is state
                    and owner.is_live is False
                ):
                    pending.append(str(request_id))
            identifiers = tuple(sorted(pending))
            active_count = sum(
                not (
                    type(owner) is _ActiveRunOwner
                    and owner.is_live is False
                )
                for owner in self._active_request_ids.values()
            )
            return {
                "pending_cleanup_count": len(identifiers),
                "pending_request_ids": identifiers,
                "active_request_count": active_count,
            }


__all__ = [
    "PRODUCTION_MULTIMODAL_PIPELINE_AVAILABLE",
    "W10_MULTIMODAL_PIPELINE_POLICY_VERSION",
    "CaptureObservation",
    "CapturedFrame",
    "MultimodalCancellation",
    "MultimodalCaptureSource",
    "MultimodalPipelineExecutor",
    "RemoteTransport",
    "UnwiredRemoteTransport",
]
