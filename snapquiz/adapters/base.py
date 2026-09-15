"""Provider-neutral contracts for direct multimodal Adapters.

Concrete Adapters are pure: they may only transform already-authorized
contracts into a :class:`PreparedOutbound` and decode a bounded
:class:`TransportResponse`.  Credential access and network I/O belong to the
W09 transport chain, not to this interface.
"""
from __future__ import annotations

from uuid import UUID

from snapquiz.domain.adapter import AnswerCandidateResult, TransportResponse
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.pipelines.contracts import StageInvocation
from snapquiz.routing.planner import PlannedExecution


class DirectMultimodalAdapter:
    """Trusted, pure Adapter boundary used by the W10 executor."""

    __slots__ = ()

    adapter_family = ""
    adapter_version = ""

    def prepare(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        operation_id: UUID,
    ) -> PreparedOutbound:
        raise NotImplementedError

    def decode(
        self,
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        response: TransportResponse,
    ) -> AnswerCandidateResult:
        raise NotImplementedError


__all__ = ["DirectMultimodalAdapter"]
