"""Deterministic, local-only helpers for W08 authority contract tests."""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

from snapquiz.adapters.openai_chat_compatible import OpenAIChatCompatibleAdapter
from snapquiz.privacy.egress import (
    EgressApprovalLedger,
    EgressGate,
    EgressPreview,
    EgressPreviewController,
    EgressPreviewDecision,
)

from tests.w06_helpers import NOW
from tests.w07_helpers import make_w07_authorities


PREVIEW_DECISION_ID = UUID("50000000-0000-0000-0000-000000000001")
PREVIEW_DECIDED_AT = NOW + timedelta(seconds=4)


class FixedPreviewController(EgressPreviewController):
    __slots__ = (
        "decision_id",
        "decided_at",
        "approved",
        "reviews",
        "last_preview",
        "last_decision",
    )

    def __init__(
        self,
        *,
        decision_id: UUID = PREVIEW_DECISION_ID,
        decided_at: datetime = PREVIEW_DECIDED_AT,
        approved: bool = True,
    ) -> None:
        self.decision_id = decision_id
        self.decided_at = decided_at
        self.approved = approved
        self.reviews = 0
        self.last_preview: EgressPreview | None = None
        self.last_decision: EgressPreviewDecision | None = None

    def review(self, preview: EgressPreview) -> EgressPreviewDecision:
        self.reviews += 1
        self.last_preview = preview
        factory = self.approve if self.approved else self.cancel
        decision = factory(
            preview,
            decision_id=self.decision_id,
            decided_at=self.decided_at,
        )
        self.last_decision = decision
        return decision


def prepare_w08(authorities: SimpleNamespace):
    return OpenAIChatCompatibleAdapter.prepare(
        planned=authorities.planned,
        invocation=authorities.invocation,
        operation_id=authorities.operation.operation_id,
    )


def make_w08_authorities(
    *,
    user_hint: str | None = None,
    decision_id: UUID = PREVIEW_DECISION_ID,
    decided_at: datetime = PREVIEW_DECIDED_AT,
    one_shot_consent: bool = False,
) -> SimpleNamespace:
    base = make_w07_authorities(
        user_hint=user_hint,
        one_shot_consent=one_shot_consent,
    )
    prepared = prepare_w08(base)
    approval_ledger = EgressApprovalLedger()
    preview_controller = FixedPreviewController(
        decision_id=decision_id,
        decided_at=decided_at,
    )
    approval = EgressGate().approve(
        planned=base.planned,
        invocation=base.invocation,
        prepared=prepared,
        authorization=base.privacy,
        consent_ledger=base.consent_ledger,
        approval_ledger=approval_ledger,
        preview_controller=preview_controller,
    )
    return SimpleNamespace(
        **vars(base),
        prepared=prepared,
        approval_ledger=approval_ledger,
        preview_controller=preview_controller,
        approval=approval,
    )
