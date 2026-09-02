"""Offline security contract for W09-A two-stage attempt authority."""
from __future__ import annotations

import builtins
import copy
from datetime import timedelta
from threading import Barrier, Event, Lock, Thread
import os
import socket
import time
import unittest
from unittest.mock import patch
from uuid import UUID, uuid5

from snapquiz.adapters.openai_chat_compatible import (
    OpenAIChatCompatibleAdapter,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import CancelledError, EndpointPolicyError, TimeoutError
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.privacy.egress import EgressApprovalLedger, EgressGate
from snapquiz.runtime.attempt import (
    ATTEMPT_PERMIT_SCHEMA_VERSION,
    CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION,
    HELPER_WAIT_QUANTUM_NS,
    AttemptGate,
    AttemptPermit,
    CredentialResolutionPermit,
    HelperStopAuthority,
    HelperWaitSlice,
    _CREDENTIAL_RESOLVER_AUTHORITY,
    _TRANSPORT_ATTEMPT_AUTHORITY,
    _AttemptPermitState,
    _CredentialPermitState,
    _attempt_permit_payload,
    _credential_permit_payload,
)
from snapquiz.runtime.context import (
    CallContextLedger,
    CancellationReason,
    _ATTEMPT_BUDGET_AUTHORITY,
)
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime


SESSION_ISSUED_AT = NOW + timedelta(seconds=5)
_TEST_HANDLE_NAMESPACE = UUID("10515800-6bd7-5f3c-ae75-a295863909b1")
_TEST_CLAIM_NAMESPACE = UUID("6a7ee735-79dd-5192-bfb5-ab7b4f4cf4b2")
_TEST_TRANSPORT_CLAIM_NAMESPACE = UUID(
    "1c78dcad-5aa4-58cd-9736-b353f3a0e393"
)
_TEST_TERMINAL_GUARD_NAMESPACE = UUID(
    "56133922-befc-5a9f-bd3e-086df91aaf86"
)
_TEST_DNS_START_NAMESPACE = UUID("b08c4dc4-4296-55cb-bfde-47ced6dc56a7")


def _handle_proof(
    permit: CredentialResolutionPermit,
) -> tuple[UUID, Digest256]:
    handle_id = uuid5(_TEST_HANDLE_NAMESPACE, str(permit.permit_id))
    return handle_id, digest256(
        "TestCredentialHandle",
        "snapquiz.test-credential-handle.v1",
        {
            "handle_id": handle_id,
            "credential_permit_id": permit.permit_id,
            "credential_permit_digest": permit.permit_digest,
        },
    )


def _claim_id(permit: CredentialResolutionPermit) -> UUID:
    return uuid5(_TEST_CLAIM_NAMESPACE, str(permit.permit_id))


def _transport_claim_id(permit: AttemptPermit, suffix: str = "owner") -> UUID:
    return uuid5(
        _TEST_TRANSPORT_CLAIM_NAMESPACE,
        f"{permit.attempt_permit_id}:{suffix}",
    )


def _terminal_guard_proof(
    permit: AttemptPermit,
) -> tuple[UUID, Digest256]:
    guard_id = uuid5(
        _TEST_TERMINAL_GUARD_NAMESPACE,
        str(permit.attempt_permit_id),
    )
    return guard_id, digest256(
        "TestAttemptTerminalGuard",
        "snapquiz.test-attempt-terminal-guard.v1",
        {
            "attempt_permit_id": permit.attempt_permit_id,
            "attempt_permit_digest": permit.attempt_permit_digest,
            "guard_id": guard_id,
        },
    )


def _dns_start_id(permit: AttemptPermit) -> UUID:
    return uuid5(_TEST_DNS_START_NAMESPACE, str(permit.attempt_permit_id))


def _make_runtime():
    runtime = make_w09_runtime()
    approval_ledger = EgressApprovalLedger()
    approval = EgressGate().approve(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval_ledger=approval_ledger,
        preview_controller=FixedPreviewController(),
    )
    runtime.clock.advance(milliseconds=5_000)
    session_ledger = SendSessionLedger()
    session = SendSessionFactory.create(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval=approval,
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        now=SESSION_ISSUED_AT,
    )
    runtime.approval = approval
    runtime.approval_ledger = approval_ledger
    runtime.session = session
    runtime.session_ledger = session_ledger
    return runtime


def _authorize(runtime, gate: AttemptGate) -> CredentialResolutionPermit:
    return gate.authorize_credential_resolution(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        session=runtime.session,
        approval_ledger=runtime.approval_ledger,
        session_ledger=runtime.session_ledger,
        authority_ledger=runtime.authority_ledger,
        context=runtime.call_context,
        context_ledger=runtime.context_ledger,
    )


def _resolve(gate: AttemptGate, permit: CredentialResolutionPermit) -> None:
    claim_id = _claim_id(permit)
    gate._claim_credential_resolution(
        permit,
        claim_id=claim_id,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )
    handle_id, handle_digest = _handle_proof(permit)
    gate._confirm_credential_resolution(
        permit,
        claim_id=claim_id,
        resolved_binding_digest=permit.credential_binding_digest,
        handle_id=handle_id,
        handle_digest=handle_digest,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )


def _abandon_resolved(
    gate: AttemptGate,
    permit: CredentialResolutionPermit,
) -> bool:
    handle_id, handle_digest = _handle_proof(permit)
    return gate._abandon_resolved_credential_resolution(
        permit,
        handle_id=handle_id,
        handle_digest=handle_digest,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )


def _reserve(runtime, gate: AttemptGate) -> tuple[
    CredentialResolutionPermit, AttemptPermit
]:
    credential = _authorize(runtime, gate)
    _resolve(gate, credential)
    handle_id, handle_digest = _handle_proof(credential)
    return credential, gate.reserve_attempt(
        credential_permit=credential,
        credential_handle_id=handle_id,
        credential_handle_digest=handle_digest,
    )


def _recover_resolved_credential(
    gate: AttemptGate,
    permit: CredentialResolutionPermit,
) -> bool:
    handle_id, handle_digest = _handle_proof(permit)
    return gate._recover_resolved_credential_for_cleanup(
        permit,
        publication_id=_claim_id(permit),
        handle_id=handle_id,
        handle_digest=handle_digest,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )


def _recover_active_attempt(
    gate: AttemptGate,
    credential: CredentialResolutionPermit,
    attempt: AttemptPermit,
) -> bool:
    handle_id, handle_digest = _handle_proof(credential)
    return gate._recover_attempt_for_cleanup(
        attempt,
        credential_permit=credential,
        credential_handle_id=handle_id,
        credential_handle_digest=handle_digest,
        claim_id=_transport_claim_id(attempt),
        guard_id=None,
        guard_digest=None,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )


def _prepare_helper_attempt(runtime, gate: AttemptGate) -> tuple[
    CredentialResolutionPermit,
    HelperStopAuthority,
    AttemptPermit,
    UUID,
    UUID,
    Digest256,
    UUID,
]:
    credential = _authorize(runtime, gate)
    stop_authority = gate._issue_helper_stop_authority(
        credential,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    _resolve(gate, credential)
    handle_id, handle_digest = _handle_proof(credential)
    attempt = gate.reserve_attempt(
        credential_permit=credential,
        credential_handle_id=handle_id,
        credential_handle_digest=handle_digest,
    )
    claim_id = _transport_claim_id(attempt)
    guard_id, guard_digest = _terminal_guard_proof(attempt)
    start_id = _dns_start_id(attempt)
    gate._claim_attempt(
        attempt,
        claim_id=claim_id,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    gate._bind_terminal_guard(
        attempt,
        claim_id=claim_id,
        guard_id=guard_id,
        guard_digest=guard_digest,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    gate._commit_dns_start(
        attempt,
        claim_id=claim_id,
        guard_id=guard_id,
        guard_digest=guard_digest,
        start_id=start_id,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    return (
        credential,
        stop_authority,
        attempt,
        claim_id,
        guard_id,
        guard_digest,
        start_id,
    )


def _mutated_prepared(value: PreparedOutbound) -> PreparedOutbound:
    return PreparedOutbound(
        plan_id=value.plan_id,
        plan_digest=value.plan_digest,
        stage_id=value.stage_id,
        operation_id=value.operation_id,
        source_ids=value.source_ids,
        source_digests=value.source_digests,
        capture_scope_fingerprint=value.capture_scope_fingerprint,
        http_method=value.http_method,
        canonical_url=value.canonical_url,
        content_type=value.content_type,
        non_secret_headers=value.non_secret_headers,
        credential_binding_digest=value.credential_binding_digest,
        outbound_data=value.outbound_data,
        body=value.body + b" ",
    )


def _slot_clone(value):
    clone = object.__new__(type(value))
    for name in value.__slots__:
        object.__setattr__(clone, name, getattr(value, name))
    return clone


class W09AttemptGateTest(unittest.TestCase):
    def test_noop_authority_release_rolls_back_terminal_commits(self):
        def no_op(*args, **kwargs):
            del args, kwargs

        with self.subTest(owner="credential"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)

            with patch.object(
                CredentialResolutionPermit,
                "_release_authority_refs",
                new=no_op,
            ):
                with self.assertRaisesRegex(
                    EndpointPolicyError,
                    "authority refs",
                ):
                    gate.abandon_credential_resolution(credential)

            state = gate._credential_permits[credential.permit_id]
            self.assertEqual(state.status, "authorized")
            self.assertFalse(credential._released)
            self.assertIs(credential._prepared, runtime.prepared)
            self.assertEqual(
                state.recovery_refs(),
                (runtime.call_context, runtime.context_ledger),
            )
            self.assertEqual(
                gate._active_by_session[credential.session_id],
                credential.permit_id,
            )
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                1,
            )

            self.assertTrue(gate.abandon_credential_resolution(credential))
            self.assertEqual(state.status, "abandoned")
            self.assertEqual(state.recovery_refs(), (None, None))

        with self.subTest(owner="attempt"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential, attempt = _reserve(runtime, gate)
            claim_id = _transport_claim_id(attempt)
            gate._claim_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

            with patch.object(
                AttemptPermit,
                "_release_authority_refs",
                new=no_op,
            ):
                with self.assertRaisesRegex(
                    EndpointPolicyError,
                    "authority refs",
                ):
                    gate.finish_attempt(
                        attempt,
                        claim_id=claim_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )

            state = gate._attempt_permits[attempt.attempt_permit_id]
            credential_state = gate._credential_permits[credential.permit_id]
            self.assertEqual(state.status, "io_claimed")
            self.assertEqual(credential_state.status, "consumed")
            self.assertFalse(attempt._released)
            self.assertFalse(credential._released)
            self.assertEqual(
                state.recovery_refs(),
                (
                    credential,
                    runtime.call_context,
                    runtime.context_ledger,
                    attempt._reservation,
                ),
            )
            self.assertEqual(
                credential_state.recovery_refs(),
                (runtime.call_context, runtime.context_ledger),
            )
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "in_flight_attempt_count"
                ],
                1,
            )

            self.assertTrue(
                gate.finish_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertEqual(state.status, "finished")
            self.assertEqual(
                state.recovery_refs(),
                (None, None, None, None),
            )

    def test_noop_recovery_ref_clear_rolls_back_recovered_cleanup(self):
        def no_op(*args, **kwargs):
            del args, kwargs

        with self.subTest(owner="credential"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)
            _resolve(gate, credential)
            state = gate._credential_permits[credential.permit_id]

            with patch.object(
                _CredentialPermitState,
                "clear_recovery_refs",
                new=no_op,
            ):
                self.assertFalse(
                    _recover_resolved_credential(gate, credential)
                )

            self.assertEqual(state.status, "resolved")
            self.assertFalse(credential._released)
            self.assertEqual(
                state.recovery_refs(),
                (runtime.call_context, runtime.context_ledger),
            )
            self.assertEqual(
                gate._active_by_session[credential.session_id],
                credential.permit_id,
            )
            self.assertTrue(_recover_resolved_credential(gate, credential))
            self.assertEqual(state.status, "abandoned")
            self.assertEqual(state.recovery_refs(), (None, None))

        with self.subTest(owner="attempt"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential, attempt = _reserve(runtime, gate)
            state = gate._attempt_permits[attempt.attempt_permit_id]
            credential_state = gate._credential_permits[credential.permit_id]
            reservation = attempt._reservation

            with patch.object(
                _AttemptPermitState,
                "clear_recovery_refs",
                new=no_op,
            ):
                self.assertFalse(
                    _recover_active_attempt(gate, credential, attempt)
                )

            self.assertEqual(state.status, "active")
            self.assertEqual(credential_state.status, "consumed")
            self.assertFalse(attempt._released)
            self.assertFalse(credential._released)
            self.assertEqual(
                state.recovery_refs(),
                (
                    credential,
                    runtime.call_context,
                    runtime.context_ledger,
                    reservation,
                ),
            )
            self.assertEqual(
                credential_state.recovery_refs(),
                (runtime.call_context, runtime.context_ledger),
            )
            self.assertTrue(
                _recover_active_attempt(gate, credential, attempt)
            )
            self.assertEqual(state.status, "abandoned")
            self.assertEqual(
                state.recovery_refs(),
                (None, None, None, None),
            )

    def test_context_noop_action_is_rejected_by_normal_cleanup(self):
        def no_op(*args, **kwargs):
            del args, kwargs

        with self.subTest(owner="credential"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)
            state = gate._credential_permits[credential.permit_id]

            with patch.object(
                CallContextLedger,
                "_finish_gate_activity",
                new=no_op,
            ):
                with self.assertRaisesRegex(
                    EndpointPolicyError,
                    "transaction",
                ):
                    gate.abandon_credential_resolution(credential)

            self.assertEqual(state.status, "authorized")
            self.assertFalse(credential._released)
            self.assertEqual(
                state.recovery_refs(),
                (runtime.call_context, runtime.context_ledger),
            )
            self.assertTrue(gate.abandon_credential_resolution(credential))
            self.assertEqual(state.status, "abandoned")

        with self.subTest(owner="attempt"):
            runtime = _make_runtime()
            gate = AttemptGate()
            _, attempt = _reserve(runtime, gate)
            claim_id = _transport_claim_id(attempt)
            gate._claim_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            state = gate._attempt_permits[attempt.attempt_permit_id]

            with patch.object(
                CallContextLedger,
                "_finish_attempt_and_activity",
                new=no_op,
            ):
                with self.assertRaisesRegex(
                    EndpointPolicyError,
                    "transaction",
                ):
                    gate.finish_attempt(
                        attempt,
                        claim_id=claim_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )

            self.assertEqual(state.status, "io_claimed")
            self.assertFalse(attempt._released)
            self.assertTrue(
                gate.finish_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertEqual(state.status, "finished")

    def test_context_noop_action_is_rejected_by_recovered_cleanup(self):
        def no_op(*args, **kwargs):
            del args, kwargs

        with self.subTest(owner="credential"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)
            _resolve(gate, credential)
            state = gate._credential_permits[credential.permit_id]

            with patch.object(
                CallContextLedger,
                "_finish_gate_activity",
                new=no_op,
            ):
                self.assertFalse(
                    _recover_resolved_credential(gate, credential)
                )

            self.assertEqual(state.status, "resolved")
            self.assertFalse(credential._released)
            self.assertTrue(_recover_resolved_credential(gate, credential))
            self.assertEqual(state.status, "abandoned")

        with self.subTest(owner="attempt"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential, attempt = _reserve(runtime, gate)
            state = gate._attempt_permits[attempt.attempt_permit_id]

            with patch.object(
                CallContextLedger,
                "_finish_attempt_and_activity",
                new=no_op,
            ):
                self.assertFalse(
                    _recover_active_attempt(gate, credential, attempt)
                )

            self.assertEqual(state.status, "active")
            self.assertFalse(attempt._released)
            self.assertTrue(
                _recover_active_attempt(gate, credential, attempt)
            )
            self.assertEqual(state.status, "abandoned")

    def test_credential_cleanup_fault_rolls_back_and_is_retryable(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        original_release = CredentialResolutionPermit._release_authority_refs

        def fail_after_release(selected, *, _authority=None):
            original_release(selected, _authority=_authority)
            raise RuntimeError("injected credential release failure")

        with patch.object(
            CredentialResolutionPermit,
            "_release_authority_refs",
            new=fail_after_release,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected credential"):
                gate.abandon_credential_resolution(credential)

        state = gate._credential_permits[credential.permit_id]
        self.assertEqual(state.status, "authorized")
        self.assertFalse(credential._released)
        self.assertIs(credential._prepared, runtime.prepared)
        self.assertEqual(
            gate._active_by_session[credential.session_id],
            credential.permit_id,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            1,
        )
        credential.validate_integrity()

        self.assertTrue(gate.abandon_credential_resolution(credential))
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))

    def test_attempt_second_release_fault_rolls_back_pair_and_context(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential, attempt = _reserve(runtime, gate)
        transport_claim_id = _transport_claim_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=transport_claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        original_release = AttemptPermit._release_authority_refs

        def fail_after_release(selected, *, _authority=None):
            original_release(selected, _authority=_authority)
            raise RuntimeError("injected attempt release failure")

        with patch.object(
            AttemptPermit,
            "_release_authority_refs",
            new=fail_after_release,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected attempt"):
                gate.finish_attempt(
                    attempt,
                    claim_id=transport_claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        attempt_state = gate._attempt_permits[attempt.attempt_permit_id]
        credential_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(attempt_state.status, "io_claimed")
        self.assertEqual(credential_state.status, "consumed")
        self.assertFalse(attempt._released)
        self.assertFalse(credential._released)
        self.assertIs(attempt._credential_permit, credential)
        self.assertIs(credential._prepared, runtime.prepared)
        self.assertEqual(
            gate._active_by_session[attempt.session_id],
            credential.permit_id,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            1,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            1,
        )
        credential.validate_integrity()
        attempt.validate_integrity()
        with self.assertRaises(EndpointPolicyError):
            _authorize(runtime, gate)

        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )

    def test_recomputed_digest_cannot_hide_exact_permit_field_tamper(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential, attempt = _reserve(runtime, gate)

        credential_clone = _slot_clone(credential)
        object.__setattr__(
            credential_clone,
            "authorized_monotonic_ns",
            credential.authorized_monotonic_ns + 1,
        )
        object.__setattr__(
            credential_clone,
            "permit_digest",
            digest256(
                "CredentialResolutionPermit",
                CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION,
                _credential_permit_payload(credential_clone),
            ),
        )
        with self.assertRaises(ValueError):
            credential_clone.validate_integrity()

        attempt_clone = _slot_clone(attempt)
        object.__setattr__(
            attempt_clone,
            "operation_attempt",
            attempt.operation_attempt + 1,
        )
        object.__setattr__(
            attempt_clone,
            "attempt_permit_digest",
            digest256(
                "AttemptPermit",
                ATTEMPT_PERMIT_SCHEMA_VERSION,
                _attempt_permit_payload(attempt_clone),
            ),
        )
        with self.assertRaises(ValueError):
            attempt_clone.validate_integrity()
        self.assertTrue(
            gate.abandon_attempt(
                attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_context_close_rejects_authorized_and_resolving_credential_activity(self):
        authorized = _make_runtime()
        authorized_gate = AttemptGate()
        authorized_permit = _authorize(authorized, authorized_gate)
        with self.assertRaises(EndpointPolicyError):
            authorized.context_ledger.close(authorized.call_context)
        self.assertEqual(
            authorized.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            1,
        )
        self.assertTrue(
            authorized_gate.abandon_credential_resolution(
                authorized_permit
            )
        )
        self.assertTrue(authorized.context_ledger.close(authorized.call_context))

        resolving = _make_runtime()
        resolving_gate = AttemptGate()
        resolving_permit = _authorize(resolving, resolving_gate)
        resolving_claim_id = _claim_id(resolving_permit)
        resolving_gate._claim_credential_resolution(
            resolving_permit,
            claim_id=resolving_claim_id,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
        with self.assertRaises(EndpointPolicyError):
            resolving.context_ledger.close(resolving.call_context)
        with self.assertRaises(EndpointPolicyError):
            resolving_gate.abandon_credential_resolution(
                resolving_permit
            )
        resolving_gate._fail_credential_resolution(
            resolving_permit,
            claim_id=resolving_claim_id,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
        self.assertTrue(resolving.context_ledger.close(resolving.call_context))

    def test_two_stage_permits_are_exact_immutable_and_budgeted_once(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)

        self.assertEqual(
            CREDENTIAL_RESOLUTION_PERMIT_SCHEMA_VERSION,
            "snapquiz.credential-resolution-permit.v1",
        )
        self.assertIs(type(credential), CredentialResolutionPermit)
        self.assertIs(copy.deepcopy(credential), credential)
        with self.assertRaises(AttributeError):
            credential.session_id = runtime.planned.plan.plan_id  # type: ignore[misc]
        with self.assertRaises(TypeError):
            handle_id, handle_digest = _handle_proof(credential)
            gate._confirm_credential_resolution(
                credential,
                claim_id=_claim_id(credential),
                resolved_binding_digest=credential.credential_binding_digest,
                handle_id=handle_id,
                handle_digest=handle_digest,
            )
        with self.assertRaises(EndpointPolicyError):
            handle_id, handle_digest = _handle_proof(credential)
            gate.reserve_attempt(
                credential_permit=credential,
                credential_handle_id=handle_id,
                credential_handle_digest=handle_digest,
            )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )

        _resolve(gate, credential)
        handle_id, handle_digest = _handle_proof(credential)
        attempt = gate.reserve_attempt(
            credential_permit=credential,
            credential_handle_id=handle_id,
            credential_handle_digest=handle_digest,
        )
        self.assertEqual(
            ATTEMPT_PERMIT_SCHEMA_VERSION,
            "snapquiz.attempt-permit.v2",
        )
        self.assertIs(type(attempt), AttemptPermit)
        self.assertIs(copy.deepcopy(attempt), attempt)
        self.assertEqual(attempt.context_id, runtime.call_context.context_id)
        self.assertEqual(attempt.session_id, runtime.session.session_id)
        self.assertEqual(
            (attempt.credential_handle_id, attempt.credential_handle_digest),
            _handle_proof(credential),
        )
        self.assertEqual(
            attempt.request_envelope_digest,
            runtime.prepared.request_envelope_digest,
        )
        self.assertEqual(attempt.operation_attempt, 1)
        self.assertEqual(attempt.global_attempt, 1)
        self.assertEqual(attempt.billable_attempt, 1)
        for budget in (
            runtime.call_context.operation_budgets[0],
            runtime.call_context.global_network_budget,
            runtime.call_context.billable_budget,
        ):
            self.assertEqual(budget.snapshot().consumed, 1)

        rendered = (
            repr(credential)
            + repr(credential.safe_metadata())
            + repr(attempt)
            + repr(attempt.safe_metadata())
        )
        self.assertNotIn(runtime.prepared.body.decode("utf-8"), rendered)
        self.assertNotIn(str(runtime.prepared.body_digest), rendered)
        with self.assertRaises(TypeError):
            gate.finish_attempt(attempt)
        with self.assertRaises(EndpointPolicyError):
            gate.finish_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        transport_claim_id = _transport_claim_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=transport_claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertFalse(
            gate.finish_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertFalse(gate.abandon_credential_resolution(credential))
        for name in (
            "_planned",
            "_invocation",
            "_prepared",
            "_authorization",
            "_consent_ledger",
            "_session",
            "_approval_ledger",
            "_session_ledger",
            "_authority_ledger",
            "_context",
            "_context_ledger",
        ):
            self.assertIsNone(getattr(credential, name), name)
        for name in (
            "_credential_permit",
            "_reservation",
            "_context_ledger",
        ):
            self.assertIsNone(getattr(attempt, name), name)
        credential.validate_integrity()
        attempt.validate_integrity()

    def test_resolver_claim_is_one_shot_and_revalidates_before_secret_read(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        permit = _authorize(runtime, gate)
        barrier = Barrier(3)
        lock = Lock()
        successes = []
        errors = []

        claim_ids = tuple(
            uuid5(_TEST_CLAIM_NAMESPACE, f"{permit.permit_id}:{index}")
            for index in range(2)
        )

        def worker(claim_id: UUID) -> None:
            barrier.wait()
            try:
                result = gate._claim_credential_resolution(
                    permit,
                    claim_id=claim_id,
                    _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
                )
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    successes.append((result, claim_id))

        threads = [
            Thread(target=worker, args=(claim_id,))
            for claim_id in claim_ids
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=3)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertIs(successes[0][0], permit)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        handle_id, handle_digest = _handle_proof(permit)
        gate._confirm_credential_resolution(
            permit,
            claim_id=successes[0][1],
            resolved_binding_digest=permit.credential_binding_digest,
            handle_id=handle_id,
            handle_digest=handle_digest,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )

        revoked = _make_runtime()
        revoked_gate = AttemptGate()
        revoked_permit = _authorize(revoked, revoked_gate)
        revoked.cancellation_source.cancel(
            reason=CancellationReason.USER_REQUEST
        )
        with self.assertRaises(CancelledError):
            revoked_gate._claim_credential_resolution(
                revoked_permit,
                claim_id=_claim_id(revoked_permit),
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        self.assertTrue(
            revoked_gate.abandon_credential_resolution(revoked_permit)
        )
        self.assertFalse(
            revoked_gate.abandon_credential_resolution(revoked_permit)
        )

    def test_invalid_gate_cannot_poison_context_and_two_valid_gates_have_one_winner(self):
        runtime = _make_runtime()
        bad_gate = AttemptGate()
        with self.assertRaises(EndpointPolicyError):
            bad_gate.authorize_credential_resolution(
                planned=runtime.planned,
                invocation=runtime.invocation,
                prepared=_mutated_prepared(runtime.prepared),
                authorization=runtime.runtime_authorization,
                consent_ledger=runtime.consent_ledger,
                session=runtime.session,
                approval_ledger=runtime.approval_ledger,
                session_ledger=runtime.session_ledger,
                authority_ledger=runtime.authority_ledger,
                context=runtime.call_context,
                context_ledger=runtime.context_ledger,
            )
        self.assertEqual(bad_gate.safe_metadata()["credential_permit_count"], 0)

        first = AttemptGate()
        second = AttemptGate()
        barrier = Barrier(3)
        lock = Lock()
        successes = []
        errors = []

        def worker(gate: AttemptGate) -> None:
            barrier.wait()
            try:
                result = _authorize(runtime, gate)
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    successes.append((gate, result))

        threads = [Thread(target=worker, args=(gate,)) for gate in (first, second)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=3)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        self.assertEqual(
            first.safe_metadata()["credential_permit_count"]
            + second.safe_metadata()["credential_permit_count"],
            1,
        )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )

    def test_reserve_vs_abandon_is_linearized_without_phantom_or_refund(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        _resolve(gate, credential)
        handle_id, handle_digest = _handle_proof(credential)
        entered = Event()
        release = Event()
        original = CallContextLedger._reserve_attempt_budgets
        result: list[AttemptPermit] = []
        errors: list[BaseException] = []

        def paused(ledger, **kwargs):
            entered.set()
            if not release.wait(timeout=3):
                raise AssertionError("reserve test barrier timed out")
            return original(ledger, **kwargs)

        def reserve_worker() -> None:
            try:
                result.append(
                    gate.reserve_attempt(
                        credential_permit=credential,
                        credential_handle_id=handle_id,
                        credential_handle_digest=handle_digest,
                    )
                )
            except BaseException as error:
                errors.append(error)

        with patch.object(
            CallContextLedger,
            "_reserve_attempt_budgets",
            new=paused,
        ):
            thread = Thread(target=reserve_worker)
            thread.start()
            self.assertTrue(entered.wait(timeout=3))
            with self.assertRaises(EndpointPolicyError):
                gate.abandon_credential_resolution(credential)
            release.set()
            thread.join(timeout=3)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(result), 1)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            1,
        )
        self.assertTrue(
            gate.abandon_attempt(
                result[0],
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertFalse(
            gate.abandon_attempt(
                result[0],
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertFalse(
            gate.finish_attempt(
                result[0],
                claim_id=_transport_claim_id(result[0]),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            1,
        )

    def test_budget_reservation_normal_noop_restores_resolved_state(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        _resolve(gate, credential)
        handle_id, handle_digest = _handle_proof(credential)

        with patch.object(
            CallContextLedger,
            "_reserve_attempt_budgets",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "reservation transaction 未提交",
            ):
                gate.reserve_attempt(
                    credential_permit=credential,
                    credential_handle_id=handle_id,
                    credential_handle_digest=handle_digest,
                )

        credential_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(credential_state.status, "resolved")
        self.assertEqual(gate._attempt_permits, {})
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )
        self.assertTrue(_abandon_resolved(gate, credential))
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))

    def test_attempt_ledger_publish_fault_restores_resolved_without_phantom(self):
        class InsertThenRaiseDict(dict):
            def __init__(self, values):
                super().__init__(values)
                self._fail_once = True

            def __setitem__(self, key, value):
                super().__setitem__(key, value)
                if self._fail_once:
                    self._fail_once = False
                    raise RuntimeError("injected attempt ledger publish failure")

        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        _resolve(gate, credential)
        handle_id, handle_digest = _handle_proof(credential)
        object.__setattr__(
            gate,
            "_attempt_permits",
            InsertThenRaiseDict(gate._attempt_permits),
        )

        with self.assertRaisesRegex(RuntimeError, "attempt ledger publish"):
            gate.reserve_attempt(
                credential_permit=credential,
                credential_handle_id=handle_id,
                credential_handle_digest=handle_digest,
            )

        credential_state = gate._credential_permits[credential.permit_id]
        self.assertEqual(credential_state.status, "resolved")
        self.assertEqual(gate.safe_metadata()["attempt_permit_count"], 0)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        # A reservation consumes budget even when pure permit publication fails;
        # only the phantom in-flight reservation and Gate publication roll back.
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            1,
        )
        self.assertTrue(_abandon_resolved(gate, credential))
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))

    def test_transport_claim_is_exactly_once_and_replay_fails(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        barrier = Barrier(3)
        lock = Lock()
        successes = []
        winning_claim_ids: list[UUID] = []
        errors = []

        def worker(suffix: str) -> None:
            claim_id = _transport_claim_id(attempt, suffix)
            barrier.wait()
            try:
                claimed = gate._claim_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    successes.append(claimed)
                    winning_claim_ids.append(claim_id)

        threads = [
            Thread(target=worker, args=(f"worker-{index}",))
            for index in range(2)
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=3)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(successes, [attempt])
        self.assertEqual(len(errors), 1)
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=winning_claim_ids[0],
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        with self.assertRaises(EndpointPolicyError):
            gate._claim_attempt(
                attempt,
                claim_id=_transport_claim_id(attempt, "replay"),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

    def test_transport_claim_owner_recovers_precommit_and_observes_postcommit(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        claim_id = _transport_claim_id(attempt)

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            side_effect=RuntimeError("synthetic claim precommit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "claim precommit"):
                gate._claim_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "active")
        self.assertIsNone(state.transport_claim_id)
        self.assertFalse(
            gate._attempt_claim_is_owned(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

        original = AttemptGate._run_authority_path

        def commit_then_raise(selected, **kwargs):
            original(selected, **kwargs)
            raise RuntimeError("synthetic claim postcommit")

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            new=commit_then_raise,
        ):
            with self.assertRaisesRegex(RuntimeError, "claim postcommit"):
                gate._claim_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        self.assertEqual(state.status, "io_claimed")
        self.assertTrue(
            gate._attempt_claim_is_owned(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertFalse(
            gate._attempt_claim_is_owned(
                attempt,
                claim_id=_transport_claim_id(attempt, "wrong-owner"),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_transport_claim_normal_noop_rolls_back_transient_state(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        claim_id = _transport_claim_id(attempt)

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "claim transaction 未提交",
            ):
                gate._claim_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "active")
        self.assertIsNone(state.transport_claim_id)
        self.assertTrue(
            gate.abandon_attempt(
                attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)

    def test_guard_and_dns_commit_are_owner_bound_and_zero_io(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        claim_id = _transport_claim_id(attempt)
        guard_id, guard_digest = _terminal_guard_proof(attempt)
        dns_start_id = _dns_start_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        gate._bind_terminal_guard(
            attempt,
            claim_id=claim_id,
            guard_id=guard_id,
            guard_digest=guard_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertTrue(
            gate._terminal_guard_is_bound(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        with self.assertRaises(EndpointPolicyError):
            gate._bind_terminal_guard(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        with self.assertRaises(EndpointPolicyError):
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        with self.assertRaises(EndpointPolicyError):
            gate._commit_dns_start(
                attempt,
                claim_id=_transport_claim_id(attempt, "wrong-owner"),
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=dns_start_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

        with (
            patch.object(builtins, "open") as open_file,
            patch.object(os, "getenv") as getenv,
            patch.object(socket, "getaddrinfo") as getaddrinfo,
            patch.object(socket, "socket") as socket_factory,
            patch.object(time, "sleep") as sleep,
        ):
            gate._commit_dns_start(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=dns_start_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            self.assertTrue(
                gate._dns_start_is_committed(
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=dns_start_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        open_file.assert_not_called()
        getenv.assert_not_called()
        getaddrinfo.assert_not_called()
        socket_factory.assert_not_called()
        sleep.assert_not_called()

    def test_dns_start_postcommit_fault_is_observable_and_not_reopened(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        claim_id = _transport_claim_id(attempt)
        guard_id, guard_digest = _terminal_guard_proof(attempt)
        dns_start_id = _dns_start_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        gate._bind_terminal_guard(
            attempt,
            claim_id=claim_id,
            guard_id=guard_id,
            guard_digest=guard_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        original = AttemptGate._run_authority_path

        def commit_then_raise(selected, **kwargs):
            original(selected, **kwargs)
            raise RuntimeError("synthetic DNS START postcommit")

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            new=commit_then_raise,
        ):
            with self.assertRaisesRegex(RuntimeError, "START postcommit"):
                gate._commit_dns_start(
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=dns_start_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "io_claimed")
        self.assertEqual(state.dns_start_id, dns_start_id)
        self.assertTrue(
            gate._dns_start_is_committed(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=dns_start_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_dns_start_normal_noop_rolls_back_transient_state(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        claim_id = _transport_claim_id(attempt)
        guard_id, guard_digest = _terminal_guard_proof(attempt)
        dns_start_id = _dns_start_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        gate._bind_terminal_guard(
            attempt,
            claim_id=claim_id,
            guard_id=guard_id,
            guard_digest=guard_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                EndpointPolicyError,
                "DNS START transaction 未提交",
            ):
                gate._commit_dns_start(
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=dns_start_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "io_claimed")
        self.assertIsNone(state.dns_start_id)
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        metadata = runtime.context_ledger.safe_metadata()
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["active_gate_activity_count"], 0)

    def test_cancel_before_dns_start_rolls_back_commit_and_stays_zero_io(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        claim_id = _transport_claim_id(attempt)
        guard_id, guard_digest = _terminal_guard_proof(attempt)
        dns_start_id = _dns_start_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        gate._bind_terminal_guard(
            attempt,
            claim_id=claim_id,
            guard_id=guard_id,
            guard_digest=guard_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        runtime.cancellation_source.cancel(
            reason=CancellationReason.USER_REQUEST
        )

        with (
            patch.object(socket, "getaddrinfo") as getaddrinfo,
            patch.object(socket, "socket") as socket_factory,
        ):
            with self.assertRaises(CancelledError):
                gate._commit_dns_start(
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=dns_start_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "io_claimed")
        self.assertIsNone(state.dns_start_id)
        self.assertFalse(
            gate._dns_start_is_committed(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=dns_start_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        getaddrinfo.assert_not_called()
        socket_factory.assert_not_called()
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_terminal_commit_then_raise_never_reopens_attempt_state(self):
        original = CallContextLedger._finish_attempt_and_activity

        def commit_then_raise(ledger, **kwargs):
            original(ledger, **kwargs)
            raise RuntimeError("synthetic terminal postcommit")

        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        claim_id = _transport_claim_id(attempt)
        gate._claim_attempt(
            attempt,
            claim_id=claim_id,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        with patch.object(
            CallContextLedger,
            "_finish_attempt_and_activity",
            new=commit_then_raise,
        ):
            with self.assertRaisesRegex(RuntimeError, "terminal postcommit"):
                gate.finish_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
        self.assertEqual(
            gate._attempt_permits[attempt.attempt_permit_id].status,
            "finished",
        )
        self.assertTrue(
            gate._attempt_is_terminal(
                attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )
        self.assertFalse(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

        abandoned_runtime = _make_runtime()
        abandoned_gate = AttemptGate()
        _, abandoned = _reserve(abandoned_runtime, abandoned_gate)
        with patch.object(
            CallContextLedger,
            "_finish_attempt_and_activity",
            new=commit_then_raise,
        ):
            with self.assertRaisesRegex(RuntimeError, "terminal postcommit"):
                abandoned_gate.abandon_attempt(
                    abandoned,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
        self.assertEqual(
            abandoned_gate._attempt_permits[
                abandoned.attempt_permit_id
            ].status,
            "abandoned",
        )
        self.assertTrue(
            abandoned_gate._attempt_is_terminal(
                abandoned,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertFalse(
            abandoned_gate.abandon_attempt(
                abandoned,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_transport_claim_rejects_gate_handle_proof_replacement_and_recovers(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential, attempt = _reserve(runtime, gate)
        credential_state = gate._credential_permits[credential.permit_id]
        original_digest = credential_state.credential_handle_digest
        replacement_digest = Digest256("f" * 64)
        self.assertNotEqual(replacement_digest, original_digest)
        credential_state.credential_handle_digest = replacement_digest
        transport_claim_id = _transport_claim_id(attempt)

        with self.assertRaises(EndpointPolicyError):
            gate._claim_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        self.assertEqual(
            gate._attempt_permits[attempt.attempt_permit_id].status,
            "active",
        )

        credential_state.credential_handle_digest = original_digest
        self.assertIs(
            gate._claim_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            ),
            attempt,
        )
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertEqual(
            runtime.context_ledger.safe_metadata()["in_flight_attempt_count"],
            0,
        )

    def test_paused_transport_claim_cannot_be_cleaned_or_reopened_by_non_owner(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        _, attempt = _reserve(runtime, gate)
        entered = Event()
        release = Event()
        original = AttemptGate._run_authority_path
        claimed: list[AttemptPermit] = []
        errors: list[BaseException] = []
        transport_claim_id = _transport_claim_id(attempt)

        def paused(selected_gate, **kwargs):
            entered.set()
            if not release.wait(timeout=3):
                raise AssertionError("transport claim barrier timed out")
            return original(selected_gate, **kwargs)

        def claim_worker() -> None:
            try:
                claimed.append(
                    gate._claim_attempt(
                        attempt,
                        claim_id=transport_claim_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )
            except BaseException as error:
                errors.append(error)

        with patch.object(AttemptGate, "_run_authority_path", new=paused):
            thread = Thread(target=claim_worker)
            thread.start()
            self.assertTrue(entered.wait(timeout=3))
            with self.assertRaises(EndpointPolicyError):
                gate.abandon_attempt(
                    attempt,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            with self.assertRaises(TypeError):
                gate.finish_attempt(attempt)
            with self.assertRaises(EndpointPolicyError):
                gate.finish_attempt(
                    attempt,
                    claim_id=_transport_claim_id(attempt, "wrong-owner"),
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                1,
            )
            with self.assertRaises(EndpointPolicyError):
                runtime.context_ledger.close(runtime.call_context)
            release.set()
            thread.join(timeout=3)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(claimed, [attempt])
        with self.assertRaises(EndpointPolicyError):
            _authorize(runtime, gate)
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        retry_credential = _authorize(runtime, gate)
        self.assertTrue(
            gate.abandon_credential_resolution(retry_credential)
        )
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))

    def test_each_stage_reprepares_exact_envelope_and_performs_no_io(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        original_prepare = OpenAIChatCompatibleAdapter.prepare

        with (
            patch.object(
                OpenAIChatCompatibleAdapter,
                "prepare",
                wraps=original_prepare,
            ) as prepare,
            patch.object(builtins, "open") as open_file,
            patch.object(os, "getenv") as getenv,
            patch.object(socket, "getaddrinfo") as getaddrinfo,
            patch.object(socket, "socket") as socket_factory,
            patch.object(time, "sleep") as sleep,
        ):
            credential, attempt = _reserve(runtime, gate)
            transport_claim_id = _transport_claim_id(attempt)
            gate._claim_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            gate.finish_attempt(
                attempt,
                claim_id=transport_claim_id,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

        # Authorize, resolver claim, resolver post-read confirmation, reserve
        # and transport claim each rebuild the exact trusted request.
        self.assertEqual(prepare.call_count, 5)
        self.assertIsNotNone(credential)
        open_file.assert_not_called()
        getenv.assert_not_called()
        getaddrinfo.assert_not_called()
        socket_factory.assert_not_called()
        sleep.assert_not_called()

    def test_approval_ledger_identity_revocation_and_budget_failure_are_closed(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        with self.assertRaises(EndpointPolicyError):
            gate.authorize_credential_resolution(
                planned=runtime.planned,
                invocation=runtime.invocation,
                prepared=runtime.prepared,
                authorization=runtime.runtime_authorization,
                consent_ledger=runtime.consent_ledger,
                session=runtime.session,
                approval_ledger=EgressApprovalLedger(),
                session_ledger=runtime.session_ledger,
                authority_ledger=runtime.authority_ledger,
                context=runtime.call_context,
                context_ledger=runtime.context_ledger,
            )
        self.assertEqual(gate.safe_metadata()["credential_permit_count"], 0)

        credential = _authorize(runtime, gate)
        _resolve(gate, credential)
        handle_id, handle_digest = _handle_proof(credential)
        runtime.authority_ledger.revoke()
        with self.assertRaises(EndpointPolicyError):
            gate.reserve_attempt(
                credential_permit=credential,
                credential_handle_id=handle_id,
                credential_handle_digest=handle_digest,
            )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )
        self.assertTrue(_abandon_resolved(gate, credential))

    def test_session_deadline_is_exact_and_half_open_before_budget(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        session_id = runtime.session.session_id
        short_expiry = runtime.clock.wall_time + timedelta(seconds=1)
        runtime.context_ledger._run_active_action(
            context=runtime.call_context,
            attempt_gate=gate,
            session_id=session_id,
            session_valid_until=short_expiry,
            action=lambda sample: sample,
            _authority=_ATTEMPT_BUDGET_AUTHORITY,
        )
        with self.assertRaises(EndpointPolicyError):
            runtime.context_ledger._run_active_action(
                context=runtime.call_context,
                attempt_gate=gate,
                session_id=session_id,
                session_valid_until=short_expiry + timedelta(seconds=1),
                action=lambda sample: sample,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
        runtime.clock.advance(milliseconds=1_000)
        with self.assertRaises(TimeoutError):
            runtime.context_ledger._run_active_action(
                context=runtime.call_context,
                attempt_gate=gate,
                session_id=session_id,
                session_valid_until=short_expiry,
                action=lambda sample: sample,
                _authority=_ATTEMPT_BUDGET_AUTHORITY,
            )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )

    def test_wrong_binding_confirmation_is_zero_budget_and_cleanup_is_idempotent(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        claim_id = _claim_id(credential)
        gate._claim_credential_resolution(
            credential,
            claim_id=claim_id,
            _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
        )
        handle_id, handle_digest = _handle_proof(credential)
        with self.assertRaises(EndpointPolicyError):
            gate._confirm_credential_resolution(
                credential,
                claim_id=claim_id,
                resolved_binding_digest=Digest256("0" * 64),
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        with self.assertRaises(EndpointPolicyError):
            gate._confirm_credential_resolution(
                credential,
                claim_id=claim_id,
                resolved_binding_digest=credential.credential_binding_digest,
                handle_id=handle_id,
                handle_digest=handle_digest,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )
        self.assertFalse(gate.abandon_credential_resolution(credential))
        self.assertTrue(credential._released)
        self.assertEqual(
            runtime.context_ledger.safe_metadata()[
                "active_gate_activity_count"
            ],
            0,
        )
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))

    def test_helper_stop_authority_issues_bounded_factory_only_slices(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        authority = gate._issue_helper_stop_authority(
            credential,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertIs(
            gate._issue_helper_stop_authority(
                credential,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            ),
            authority,
        )
        authority.validate_integrity()
        self.assertEqual(authority.gate_id, gate._gate_id)
        self.assertEqual(authority.context_id, runtime.call_context.context_id)
        self.assertEqual(authority.session_id, runtime.session.session_id)
        self.assertEqual(
            authority.runtime_deadline_digest,
            runtime.call_context.runtime_deadline.deadline_digest,
        )
        self.assertEqual(
            authority.cancellation_token_digest,
            runtime.call_context.cancellation_token.token_digest,
        )

        first = authority._checkpoint(
            "resolver_helper.spawn",
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        runtime.clock.advance(milliseconds=1)
        second = authority._checkpoint(
            "resolver_helper.ready",
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        for wait_slice in (first, second):
            self.assertIs(type(wait_slice), HelperWaitSlice)
            wait_slice.validate_integrity()
            self.assertGreater(wait_slice.max_wait_ns, 0)
            self.assertLessEqual(wait_slice.max_wait_ns, HELPER_WAIT_QUANTUM_NS)
            self.assertEqual(
                wait_slice.effective_deadline_ns,
                authority.effective_deadline_ns,
            )
            self.assertLess(
                wait_slice.observed_monotonic_ns,
                wait_slice.effective_deadline_ns,
            )
        self.assertEqual((first.sequence, second.sequence), (1, 2))
        with self.assertRaises(TypeError):
            HelperStopAuthority(
                credential_permit=credential,
                context=runtime.call_context,
                context_ledger=runtime.context_ledger,
                session=runtime.session,
                effective_deadline_ns=authority.effective_deadline_ns,
                attempt_gate=gate,
            )
        with self.assertRaises(TypeError):
            HelperWaitSlice(
                stop_authority=authority,
                sequence=3,
                phase="resolver_helper.start",
                effective_deadline_ns=authority.effective_deadline_ns,
                observed_monotonic_ns=runtime.clock.monotonic_ns,
            )

        self.assertTrue(gate.abandon_credential_resolution(credential))
        self.assertTrue(
            gate._helper_stop_authority_is_released(
                authority,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_helper_stop_release_noop_rolls_back_terminal_commits(self):
        with self.subTest(owner="credential"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)
            authority = gate._issue_helper_stop_authority(
                credential,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

            with patch.object(
                AttemptGate,
                "_release_helper_stop_locked",
                return_value=None,
            ):
                with self.assertRaisesRegex(
                    EndpointPolicyError,
                    "terminal release",
                ):
                    gate.abandon_credential_resolution(credential)

            credential_state = gate._credential_permits[credential.permit_id]
            stop_state = gate._helper_stop_authorities[authority.authority_id]
            self.assertEqual(credential_state.status, "authorized")
            self.assertEqual(stop_state.status, "active")
            self.assertFalse(authority._released)
            self.assertFalse(
                gate._helper_stop_authority_is_released(
                    authority,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "active_gate_activity_count"
                ],
                1,
            )

            self.assertTrue(gate.abandon_credential_resolution(credential))
            self.assertTrue(
                gate._helper_stop_authority_is_released(
                    authority,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )

        with self.subTest(owner="attempt"):
            runtime = _make_runtime()
            gate = AttemptGate()
            (
                credential,
                authority,
                attempt,
                claim_id,
                guard_id,
                guard_digest,
                _,
            ) = _prepare_helper_attempt(runtime, gate)

            with patch.object(
                AttemptGate,
                "_release_helper_stop_locked",
                return_value=None,
            ):
                with self.assertRaisesRegex(
                    EndpointPolicyError,
                    "terminal release",
                ):
                    gate.finish_attempt(
                        attempt,
                        claim_id=claim_id,
                        guard_id=guard_id,
                        guard_digest=guard_digest,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )

            attempt_state = gate._attempt_permits[attempt.attempt_permit_id]
            credential_state = gate._credential_permits[credential.permit_id]
            stop_state = gate._helper_stop_authorities[authority.authority_id]
            self.assertEqual(attempt_state.status, "io_claimed")
            self.assertEqual(credential_state.status, "consumed")
            self.assertEqual(stop_state.status, "active")
            self.assertFalse(authority._released)
            self.assertFalse(attempt._released)
            self.assertFalse(credential._released)
            self.assertEqual(
                runtime.context_ledger.safe_metadata()[
                    "in_flight_attempt_count"
                ],
                1,
            )

            self.assertTrue(
                gate.finish_attempt(
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertTrue(
                gate._helper_stop_authority_is_released(
                    authority,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )

    def test_helper_checkpoint_rejects_same_phase_stale_slice_alias(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        authority = gate._issue_helper_stop_authority(
            credential,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        phase = "resolver_helper.ready"
        first = authority._checkpoint(
            phase,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        remaining_ns = (
            authority.effective_deadline_ns - runtime.clock.monotonic_ns
        )
        self.assertGreater(remaining_ns, 1_000_000)
        self.assertEqual(remaining_ns % 1_000_000, 0)
        runtime.clock.advance(
            milliseconds=(remaining_ns // 1_000_000) - 1
        )
        current_remaining_ns = (
            authority.effective_deadline_ns - runtime.clock.monotonic_ns
        )
        self.assertEqual(current_remaining_ns, 1_000_000)
        self.assertGreater(first.max_wait_ns, current_remaining_ns)

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            return_value=first,
        ):
            with self.assertRaises(EndpointPolicyError):
                authority._checkpoint(
                    phase,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        state = gate._helper_stop_authorities[authority.authority_id]
        self.assertEqual(state.sequence, 1)
        self.assertIs(state.issued_wait_slice, first)
        self.assertEqual(state.issued_wait_slice_digest, first.slice_digest)

    def test_helper_checkpoint_rejects_authority_path_noop(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        authority = gate._issue_helper_stop_authority(
            credential,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            return_value=None,
        ):
            with self.assertRaises(EndpointPolicyError):
                authority._checkpoint(
                    "resolver_helper.spawn",
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        state = gate._helper_stop_authorities[authority.authority_id]
        self.assertEqual(state.sequence, 0)
        self.assertIsNone(state.issued_wait_slice)
        self.assertIsNone(state.issued_wait_slice_digest)

    def test_helper_checkpoint_rejects_return_alias_after_exact_commit(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        credential = _authorize(runtime, gate)
        authority = gate._issue_helper_stop_authority(
            credential,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        phase = "resolver_helper.result"
        first = authority._checkpoint(
            phase,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        original = AttemptGate._run_authority_path
        committed: list[HelperWaitSlice] = []

        def return_old_alias(selected_gate, **kwargs):
            committed.append(original(selected_gate, **kwargs))
            return first

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            new=return_old_alias,
        ):
            with self.assertRaises(EndpointPolicyError):
                authority._checkpoint(
                    phase,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        self.assertEqual(len(committed), 1)
        second = committed[0]
        state = gate._helper_stop_authorities[authority.authority_id]
        self.assertEqual(state.sequence, 2)
        self.assertIs(state.issued_wait_slice, second)
        self.assertIsNot(second, first)
        self.assertEqual(second.sequence, 2)

        third = authority._checkpoint(
            phase,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertEqual(third.sequence, 3)
        self.assertIs(state.issued_wait_slice, third)

    def test_helper_checkpoint_is_half_open_and_cancellation_wins_boundary(self):
        with self.subTest(stop="timeout"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)
            authority = gate._issue_helper_stop_authority(
                credential,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            remaining_ns = (
                authority.effective_deadline_ns - runtime.clock.monotonic_ns
            )
            self.assertGreater(remaining_ns, 0)
            self.assertEqual(remaining_ns % 1_000_000, 0)
            runtime.clock.advance(milliseconds=remaining_ns // 1_000_000)
            with self.assertRaises(TimeoutError):
                authority._checkpoint(
                    "resolver_helper.result",
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

        with self.subTest(stop="cancel-priority"):
            runtime = _make_runtime()
            gate = AttemptGate()
            credential = _authorize(runtime, gate)
            authority = gate._issue_helper_stop_authority(
                credential,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
            remaining_ns = (
                authority.effective_deadline_ns - runtime.clock.monotonic_ns
            )
            runtime.clock.advance(milliseconds=remaining_ns // 1_000_000)
            self.assertTrue(
                runtime.cancellation_source.cancel(
                    reason=CancellationReason.USER_REQUEST
                )
            )
            with self.assertRaises(CancelledError):
                authority._checkpoint(
                    "resolver_helper.result",
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )

    def test_resolver_completion_is_independent_exact_and_releases_refs(self):
        runtime = _make_runtime()
        gate = AttemptGate()
        (
            credential,
            authority,
            attempt,
            claim_id,
            guard_id,
            guard_digest,
            start_id,
        ) = _prepare_helper_attempt(runtime, gate)
        receipt_digest = digest256(
            "TestResolverResultReceipt",
            "snapquiz.test-resolver-result-receipt.v1",
            {
                "attempt_permit_id": attempt.attempt_permit_id,
                "authority_id": authority.authority_id,
            },
        )

        gate._commit_resolver_completion(
            authority,
            attempt,
            claim_id=claim_id,
            guard_id=guard_id,
            guard_digest=guard_digest,
            start_id=start_id,
            result_receipt_digest=receipt_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "io_claimed")
        self.assertEqual(state.resolver_completion_status, "committed")
        self.assertTrue(
            gate._resolver_completion_is_committed(
                authority,
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=receipt_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertFalse(
            gate._resolver_completion_is_committed(
                authority,
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=Digest256("0" * 64),
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        with self.assertRaises(EndpointPolicyError):
            gate._commit_resolver_completion(
                authority,
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=receipt_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )

        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(authority._released)
        self.assertEqual(
            (
                authority._attempt_gate,
                authority._credential_permit,
                authority._context,
                authority._context_ledger,
                authority._session,
                authority._runtime_deadline,
                authority._cancellation_token,
            ),
            (None, None, None, None, None, None, None),
        )
        authority.validate_integrity()
        self.assertTrue(
            gate._helper_stop_authority_is_released(
                authority,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertTrue(
            gate._resolver_completion_is_committed(
                authority,
                attempt,
                claim_id=claim_id,
                guard_id=guard_id,
                guard_digest=guard_digest,
                start_id=start_id,
                result_receipt_digest=receipt_digest,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        with self.assertRaises(EndpointPolicyError):
            authority._checkpoint(
                "resolver_helper.result_close",
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        self.assertTrue(credential._released)

    def test_resolver_completion_distinguishes_precommit_and_postcommit_faults(self):
        with self.subTest(fault="precommit"):
            runtime = _make_runtime()
            gate = AttemptGate()
            (
                _,
                authority,
                attempt,
                claim_id,
                guard_id,
                guard_digest,
                start_id,
            ) = _prepare_helper_attempt(runtime, gate)
            receipt_digest = digest256(
                "TestResolverResultReceipt",
                "snapquiz.test-resolver-result-receipt.v1",
                {"attempt_permit_id": attempt.attempt_permit_id},
            )
            with patch.object(AttemptGate, "_run_authority_path", return_value=None):
                with self.assertRaises(EndpointPolicyError):
                    gate._commit_resolver_completion(
                        authority,
                        attempt,
                        claim_id=claim_id,
                        guard_id=guard_id,
                        guard_digest=guard_digest,
                        start_id=start_id,
                        result_receipt_digest=receipt_digest,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
            state = gate._attempt_permits[attempt.attempt_permit_id]
            self.assertEqual(state.resolver_completion_status, "uncommitted")
            self.assertFalse(
                gate._resolver_completion_is_committed(
                    authority,
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=start_id,
                    result_receipt_digest=receipt_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )

        with self.subTest(fault="postcommit"):
            runtime = _make_runtime()
            gate = AttemptGate()
            (
                _,
                authority,
                attempt,
                claim_id,
                guard_id,
                guard_digest,
                start_id,
            ) = _prepare_helper_attempt(runtime, gate)
            receipt_digest = digest256(
                "TestResolverResultReceipt",
                "snapquiz.test-resolver-result-receipt.v1",
                {"attempt_permit_id": attempt.attempt_permit_id},
            )
            original = AttemptGate._run_authority_path

            def raise_after_commit(selected_gate, **kwargs):
                original(selected_gate, **kwargs)
                raise RuntimeError("injected completion postcommit failure")

            with patch.object(
                AttemptGate,
                "_run_authority_path",
                new=raise_after_commit,
            ):
                with self.assertRaisesRegex(RuntimeError, "postcommit"):
                    gate._commit_resolver_completion(
                        authority,
                        attempt,
                        claim_id=claim_id,
                        guard_id=guard_id,
                        guard_digest=guard_digest,
                        start_id=start_id,
                        result_receipt_digest=receipt_digest,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
            self.assertTrue(
                gate._resolver_completion_is_committed(
                    authority,
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=start_id,
                    result_receipt_digest=receipt_digest,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
            )
            self.assertEqual(
                gate._attempt_permits[
                    attempt.attempt_permit_id
                ].resolver_completion_status,
                "committed",
            )


if __name__ == "__main__":
    unittest.main()
