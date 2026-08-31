from __future__ import annotations

import copy
from dataclasses import asdict
from datetime import timedelta
import os
import socket
from threading import Barrier, Lock, Thread
import time
import traceback
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.errors import CancelledError, EndpointPolicyError
from snapquiz.domain.outbound import NonSecretHeader, PreparedOutbound
from snapquiz.privacy.egress import (
    EgressApproval,
    EgressApprovalLedger,
    EgressGate,
    EgressPreview,
    EgressPreviewController,
    EgressPreviewDecision,
)

from tests.w06_helpers import NOW
from tests.w07_helpers import canonical_png_bytes, make_w07_authorities
from tests.w08_helpers import (
    FixedPreviewController,
    PREVIEW_DECIDED_AT,
    PREVIEW_DECISION_ID,
    make_w08_authorities,
    prepare_w08,
)


class _ForbiddenEnvironment:
    def _reject(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("environment access")

    __getitem__ = _reject
    __iter__ = _reject
    __len__ = _reject
    __contains__ = _reject
    get = _reject
    keys = _reject
    items = _reject
    values = _reject


def _approve(base, prepared, ledger, controller):
    return EgressGate().approve(
        planned=base.planned,
        invocation=base.invocation,
        prepared=prepared,
        authorization=base.privacy,
        consent_ledger=base.consent_ledger,
        approval_ledger=ledger,
        preview_controller=controller,
    )


class PreviewContractTest(unittest.TestCase):
    def test_preview_is_exact_ephemeral_pass_through_and_redacted(self):
        canary = "PRIVATE-EGRESS-HINT-CANARY"
        authorities = make_w08_authorities(user_hint=canary)
        preview = authorities.preview_controller.last_preview
        decision = authorities.preview_controller.last_decision
        self.assertIsNotNone(preview)
        self.assertIsNotNone(decision)
        assert preview is not None and decision is not None
        self.assertEqual(preview.image_bytes, canonical_png_bytes())
        self.assertEqual(preview.user_hint, canary)
        self.assertEqual(preview.request_envelope_digest, authorities.prepared.request_envelope_digest)
        self.assertEqual(preview.preview_image_sha256, authorities.validated.artifact_sha256)
        self.assertEqual(preview.source_digests, authorities.prepared.source_digests)
        preview.validate_integrity()
        decision.validate_integrity()
        self.assertIs(decision._preview, preview)
        self.assertIs(copy.deepcopy(preview), preview)
        self.assertIs(copy.deepcopy(decision), decision)
        for value in (preview, preview.safe_metadata(), decision, authorities.approval):
            rendered = repr(value)
            self.assertNotIn(canary, rendered)
            self.assertNotIn(canonical_png_bytes().hex(), rendered)
            self.assertNotIn(str(preview.preview_subject_digest), rendered)
        with self.assertRaises(TypeError):
            asdict(preview)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            type("UnsafePreview", (EgressPreview,), {})

    def test_preview_decision_cannot_be_directly_constructed(self):
        authorities = make_w08_authorities()
        preview = authorities.preview_controller.last_preview
        assert preview is not None
        with self.assertRaises(TypeError):
            EgressPreviewDecision(
                decision_id=PREVIEW_DECISION_ID,
                preview_subject_digest=preview.preview_subject_digest,
                decided_at=PREVIEW_DECIDED_AT,
                approved=True,
                preview=preview,
            )

    def test_cancel_never_issues_an_approval(self):
        base = make_w07_authorities()
        prepared = prepare_w08(base)
        ledger = EgressApprovalLedger()
        controller = FixedPreviewController(approved=False)
        with self.assertRaises(CancelledError):
            _approve(base, prepared, ledger, controller)
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)
        self.assertEqual(controller.reviews, 1)

    def test_controller_failure_does_not_retain_sensitive_exception_context(self):
        canary = "CONTROLLER-SECRET-CANARY"

        class FailingController(EgressPreviewController):
            __slots__ = ()

            def review(self, preview):
                del preview
                raise RuntimeError(canary)

        base = make_w07_authorities(user_hint=canary)
        with patch(
            "logging.Logger._log",
            side_effect=AssertionError("preview content must not be logged"),
        ):
            with self.assertRaises(EndpointPolicyError) as caught:
                _approve(
                    base,
                    prepare_w08(base),
                    EgressApprovalLedger(),
                    FailingController(),
                )
        self.assertNotIn(canary, repr(caught.exception))
        self.assertNotIn(
            canary,
            "".join(
                traceback.format_exception(
                    type(caught.exception),
                    caught.exception,
                    caught.exception.__traceback__,
                )
            ),
        )
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_replayed_decision_object_cannot_authorize_a_new_preview_or_ledger(self):
        first = make_w08_authorities()
        cached = first.preview_controller.last_decision
        assert cached is not None

        class ReplayController(EgressPreviewController):
            __slots__ = ()

            def review(self, preview):
                del preview
                return cached

        base = make_w07_authorities()
        with self.assertRaises(EndpointPolicyError):
            _approve(base, prepare_w08(base), EgressApprovalLedger(), ReplayController())


class ApprovalContractTest(unittest.TestCase):
    def test_approval_golden_and_exact_bindings(self):
        authorities = make_w08_authorities()
        approval = authorities.approval
        self.assertEqual(
            str(approval.approval_id),
            "f7749597-13c7-5770-97c1-1639f045fa9f",
        )
        self.assertEqual(
            str(approval.approval_terms_digest),
            "4ba8812c99c3b59fe279bd89e20aba89d9b76b664df75c49241fd5fc7478c968",
        )
        self.assertEqual(
            str(approval.approval_digest),
            "8f08a2477af5b6620aed2e6376676be7e72753a9124d4662595aa2ea0452da4d",
        )
        self.assertEqual(approval.request_id, authorities.invocation.request_id)
        self.assertEqual(approval.invocation_id, authorities.invocation.invocation_id)
        self.assertEqual(approval.source_ids, authorities.prepared.source_ids)
        self.assertEqual(approval.source_digests, authorities.prepared.source_digests)
        self.assertEqual(approval.capture_scope_fingerprint, authorities.validated.scope_fingerprint)
        self.assertEqual(approval.request_envelope_digest, authorities.prepared.request_envelope_digest)
        self.assertEqual(approval.body_digest, authorities.prepared.body_digest)
        self.assertEqual(approval.max_network_attempts, 2)
        self.assertEqual(approval.approved_at, PREVIEW_DECIDED_AT)
        self.assertEqual(
            approval.expires_at,
            authorities.privacy.authorized_at
            + timedelta(milliseconds=authorities.planned.plan.timeout_budget_ms),
        )
        approval.validate_integrity()
        authorities.approval_ledger.validate_active(
            approval,
            now=PREVIEW_DECIDED_AT,
        )

    def test_approval_is_factory_only_final_immutable_and_ledger_bound(self):
        authorities = make_w08_authorities()
        approval = authorities.approval
        preview = authorities.preview_controller.last_preview
        decision = authorities.preview_controller.last_decision
        assert preview is not None and decision is not None
        with self.assertRaises(TypeError):
            EgressApproval(
                approval_id=approval.approval_id,
                preview=preview,
                decision=decision,
                max_network_attempts=approval.max_network_attempts,
                billable=approval.billable,
                approved_at=approval.approved_at,
                expires_at=approval.expires_at,
                consumed_at=None,
                revoked_at=None,
                approval_ledger=authorities.approval_ledger,
            )
        with self.assertRaises(AttributeError):
            approval.consumed_at = NOW  # type: ignore[misc]
        with self.assertRaises(TypeError):
            type("UnsafeApproval", (EgressApproval,), {})
        self.assertIs(copy.deepcopy(approval), approval)
        with self.assertRaises(EndpointPolicyError):
            EgressApprovalLedger().validate_active(
                approval,
                now=PREVIEW_DECIDED_AT,
            )

    def test_expiry_is_half_open_and_revoke_makes_original_revision_stale(self):
        authorities = make_w08_authorities()
        approval = authorities.approval
        ledger = authorities.approval_ledger
        ledger.validate_active(
            approval,
            now=approval.expires_at - timedelta(microseconds=1),
        )
        with self.assertRaises(EndpointPolicyError):
            ledger.validate_active(approval, now=approval.expires_at)
        revoked = ledger.revoke(
            approval_id=approval.approval_id,
            revoked_at=approval.approved_at + timedelta(seconds=1),
        )
        self.assertTrue(revoked.revoked_at)
        revoked.validate_integrity()
        self.assertEqual(revoked.approval_terms_digest, approval.approval_terms_digest)
        self.assertNotEqual(revoked.approval_digest, approval.approval_digest)
        with self.assertRaises(EndpointPolicyError):
            ledger.validate_active(
                approval,
                now=approval.approved_at + timedelta(seconds=2),
            )
        with self.assertRaises(EndpointPolicyError):
            ledger.validate_active(
                revoked,
                now=approval.approved_at + timedelta(seconds=2),
            )

    def test_same_preview_decision_can_issue_only_once_under_concurrency(self):
        base = make_w07_authorities()
        prepared = prepare_w08(base)
        ledger = EgressApprovalLedger()
        controller = FixedPreviewController()
        barrier = Barrier(16)
        lock = Lock()
        successes = []
        failures = []

        def worker():
            barrier.wait()
            try:
                value = _approve(base, prepared, ledger, controller)
            except EndpointPolicyError as error:
                with lock:
                    failures.append(error)
            else:
                with lock:
                    successes.append(value)

        threads = [Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 15)
        self.assertEqual(ledger.safe_metadata()["approval_count"], 1)
        self.assertEqual(ledger.safe_metadata()["preview_decision_count"], 1)


class EgressBindingFailureTest(unittest.TestCase):
    def _assert_mutation_rejected(self, name, value):
        base = make_w07_authorities()
        prepared = prepare_w08(base)
        object.__setattr__(prepared, name, value)
        ledger = EgressApprovalLedger()
        controller = FixedPreviewController()
        with self.assertRaises(EndpointPolicyError):
            _approve(base, prepared, ledger, controller)
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)
        self.assertEqual(controller.reviews, 0)

    def test_source_scope_body_header_and_envelope_mutations_fail_before_preview(self):
        other_id = UUID("50000000-0000-0000-0000-000000000099")
        self._assert_mutation_rejected("source_ids", (other_id, other_id))
        self._assert_mutation_rejected("source_digests", tuple(reversed(make_w08_authorities().prepared.source_digests)))
        self._assert_mutation_rejected("capture_scope_fingerprint", make_w08_authorities().prepared.body_digest)
        self._assert_mutation_rejected("body", b"mutated outbound body")
        self._assert_mutation_rejected(
            "non_secret_headers",
            (NonSecretHeader(lowercase_name="x-test", normalized_value="changed"),),
        )
        self._assert_mutation_rejected("request_envelope_digest", make_w08_authorities().prepared.body_digest)

    def test_cross_invocation_and_cross_ledger_authorization_are_rejected(self):
        first = make_w07_authorities()
        second = make_w07_authorities(
            request_id=UUID("50000000-0000-0000-0000-000000000077"),
            capture_id=UUID("50000000-0000-0000-0000-000000000078"),
        )
        with self.assertRaises(EndpointPolicyError):
            EgressGate().approve(
                planned=second.planned,
                invocation=second.invocation,
                prepared=prepare_w08(first),
                authorization=second.privacy,
                consent_ledger=second.consent_ledger,
                approval_ledger=EgressApprovalLedger(),
                preview_controller=FixedPreviewController(),
            )
        with self.assertRaises(EndpointPolicyError):
            EgressGate().approve(
                planned=first.planned,
                invocation=first.invocation,
                prepared=prepare_w08(first),
                authorization=second.privacy,
                consent_ledger=first.consent_ledger,
                approval_ledger=EgressApprovalLedger(),
                preview_controller=FixedPreviewController(),
            )

    def test_mutation_during_preview_is_detected_before_issue(self):
        base = make_w07_authorities()
        prepared = prepare_w08(base)

        class MutatingController(FixedPreviewController):
            __slots__ = ()

            def review(self, preview):
                decision = super().review(preview)
                object.__setattr__(prepared, "body", b"changed after review")
                return decision

        ledger = EgressApprovalLedger()
        with self.assertRaises(EndpointPolicyError):
            _approve(base, prepared, ledger, MutatingController())
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)

    def test_consent_revocation_during_preview_prevents_approval(self):
        base = make_w07_authorities(user_hint="revoke during preview")
        prepared = prepare_w08(base)

        class RevokingController(FixedPreviewController):
            __slots__ = ()

            def review(self, preview):
                decision = super().review(preview)
                base.consent_ledger.revoke(
                    grant_id=base.privacy.consent_grant_ids[0],
                    revoked_at=PREVIEW_DECIDED_AT,
                )
                return decision

        ledger = EgressApprovalLedger()
        with self.assertRaises(EndpointPolicyError):
            _approve(base, prepared, ledger, RevokingController())
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)
        self.assertEqual(ledger.safe_metadata()["preview_decision_count"], 0)

    def test_self_consistent_alternate_body_is_not_trusted_adapter_output(self):
        base = make_w07_authorities()
        expected = prepare_w08(base)
        alternate = PreparedOutbound(
            plan_id=expected.plan_id,
            plan_digest=expected.plan_digest,
            stage_id=expected.stage_id,
            operation_id=expected.operation_id,
            source_ids=expected.source_ids,
            source_digests=expected.source_digests,
            capture_scope_fingerprint=expected.capture_scope_fingerprint,
            http_method=expected.http_method,
            canonical_url=expected.canonical_url,
            content_type=expected.content_type,
            non_secret_headers=expected.non_secret_headers,
            credential_binding_digest=expected.credential_binding_digest,
            outbound_data=expected.outbound_data,
            body=b'{"unreviewed_secret":"EXFILTRATE"}',
        )
        alternate.validate_integrity()
        self.assertNotEqual(alternate.body_digest, expected.body_digest)
        ledger = EgressApprovalLedger()
        controller = FixedPreviewController()
        with self.assertRaises(EndpointPolicyError):
            _approve(base, alternate, ledger, controller)
        self.assertEqual(controller.reviews, 0)
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)

    def test_released_capture_before_or_during_review_is_endpoint_policy_error(self):
        before = make_w07_authorities()
        prepared_before = prepare_w08(before)
        before.validated.release()
        controller = FixedPreviewController()
        with self.assertRaises(EndpointPolicyError):
            _approve(
                before,
                prepared_before,
                EgressApprovalLedger(),
                controller,
            )
        self.assertEqual(controller.reviews, 0)

        during = make_w07_authorities(user_hint="release during review")
        prepared_during = prepare_w08(during)

        class ReleasingController(FixedPreviewController):
            __slots__ = ()

            def review(self, preview):
                decision = super().review(preview)
                during.validated.release()
                return decision

        ledger = EgressApprovalLedger()
        with self.assertRaises(EndpointPolicyError):
            _approve(during, prepared_during, ledger, ReleasingController())
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)

    def test_controller_cancelled_error_is_replaced_with_fixed_safe_error(self):
        canary = "CANCELLED-CONTROLLER-PRIVATE-CANARY"

        class UnsafeCancellationController(EgressPreviewController):
            __slots__ = ()

            def review(self, preview):
                del preview
                raise CancelledError(stage="unsafe_ui", safe_message=canary)

        base = make_w07_authorities(user_hint=canary)
        with self.assertRaises(CancelledError) as caught:
            _approve(
                base,
                prepare_w08(base),
                EgressApprovalLedger(),
                UnsafeCancellationController(),
            )
        self.assertNotIn(canary, repr(caught.exception))
        self.assertEqual(caught.exception.stage, "egress_gate")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_confirmation_at_plan_wall_deadline_is_rejected(self):
        base = make_w07_authorities()
        deadline = base.privacy.authorized_at + timedelta(
            milliseconds=base.planned.plan.timeout_budget_ms
        )
        ledger = EgressApprovalLedger()
        with self.assertRaises(EndpointPolicyError):
            _approve(
                base,
                prepare_w08(base),
                ledger,
                FixedPreviewController(decided_at=deadline),
            )
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)

    def test_one_shot_consent_is_rejected_until_w09_lease_semantics_exist(self):
        base = make_w07_authorities(one_shot_consent=True)
        ledger = EgressApprovalLedger()
        with self.assertRaises(EndpointPolicyError):
            _approve(base, prepare_w08(base), ledger, FixedPreviewController())
        self.assertEqual(ledger.safe_metadata()["approval_count"], 0)

    def test_gate_has_no_environment_file_sleep_or_network_side_effect(self):
        base = make_w07_authorities()
        prepared = prepare_w08(base)
        ledger = EgressApprovalLedger()
        controller = FixedPreviewController()
        with (
            patch.object(os, "environ", _ForbiddenEnvironment()),
            patch("builtins.open", side_effect=AssertionError("file access")),
            patch.object(socket, "socket", side_effect=AssertionError("socket access")),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network access"),
            ),
            patch.object(time, "sleep", side_effect=AssertionError("sleep")),
        ):
            approval = _approve(base, prepared, ledger, controller)
        self.assertEqual(approval.request_envelope_digest, prepared.request_envelope_digest)


if __name__ == "__main__":
    unittest.main()
