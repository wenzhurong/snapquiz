"""Offline contract for session-bound one-shot consent use in W09-A."""
from __future__ import annotations

import builtins
import copy
from datetime import timedelta
import os
import socket
import time
from threading import Barrier, Event, Lock, Thread
import unittest
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import digest256
from snapquiz.domain.errors import EndpointPolicyError, TimeoutError as SnapTimeoutError
from snapquiz.privacy.consent import (
    CONSENT_USE_LEASE_SCHEMA_VERSION,
    ConsentLedger,
    ConsentUseLease,
    PrivacyGate,
    _consent_use_lease_id_for,
    _consent_use_lease_identifier_payload,
    _consent_use_lease_terms_payload,
)
from snapquiz.privacy.egress import EgressApprovalLedger, EgressGate
from snapquiz.runtime.attempt import (
    AttemptGate,
    _CREDENTIAL_RESOLVER_AUTHORITY,
    _TRANSPORT_ATTEMPT_AUTHORITY,
)
from snapquiz.transport.session import SendSessionFactory, SendSessionLedger

from tests.w06_helpers import NOW
from tests.w08_helpers import FixedPreviewController
from tests.w09_helpers import make_w09_runtime


SESSION_AT = NOW + timedelta(seconds=5)
SECOND_DECISION_ID = UUID("50000000-0000-0000-0000-000000000002")


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


def _approve(runtime, *, ledger=None, decision_id=None):
    selected_ledger = ledger or EgressApprovalLedger()
    controller_kwargs = {}
    if decision_id is not None:
        controller_kwargs["decision_id"] = decision_id
    approval = EgressGate().approve(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval_ledger=selected_ledger,
        preview_controller=FixedPreviewController(**controller_kwargs),
    )
    return approval, selected_ledger


def _create_session(
    runtime,
    *,
    approval,
    approval_ledger,
    session_ledger=None,
    now=SESSION_AT,
):
    selected_ledger = session_ledger or SendSessionLedger()
    session = SendSessionFactory.create(
        planned=runtime.planned,
        invocation=runtime.invocation,
        prepared=runtime.prepared,
        authorization=runtime.runtime_authorization,
        consent_ledger=runtime.consent_ledger,
        approval=approval,
        approval_ledger=approval_ledger,
        session_ledger=selected_ledger,
        now=now,
    )
    return session, selected_ledger


def _make_one_shot_session():
    runtime = make_w09_runtime(one_shot_consent=True)
    approval, approval_ledger = _approve(runtime)
    runtime.clock.advance(milliseconds=5_000)
    session, session_ledger = _create_session(
        runtime,
        approval=approval,
        approval_ledger=approval_ledger,
    )
    runtime.approval = approval
    runtime.approval_ledger = approval_ledger
    runtime.session = session
    runtime.session_ledger = session_ledger
    return runtime


def _authorize(runtime, gate):
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


def _resolve(gate, credential):
    gate._claim_credential_resolution(
        credential,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )
    gate._confirm_credential_resolution(
        credential,
        resolved_binding_digest=credential.credential_binding_digest,
        _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
    )


def _finish_one_attempt(runtime, gate):
    credential = _authorize(runtime, gate)
    _resolve(gate, credential)
    attempt = gate.reserve_attempt(credential_permit=credential)
    gate._claim_attempt(
        attempt,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    gate.finish_attempt(
        attempt,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    return credential, attempt


class W09ConsentUseLeaseTest(unittest.TestCase):
    def test_session_atomically_consumes_grant_and_issues_exact_lease(self):
        runtime = _make_one_shot_session()
        current = runtime.consent_ledger.snapshot_for_ids(
            (runtime.grant.grant_id,)
        )[0]
        lease = runtime.consent_ledger.snapshot_use_lease_for_session(
            runtime.session.session_id
        )

        self.assertIsNot(current, runtime.grant)
        self.assertEqual(current.consumed_at, runtime.session.issued_at)
        self.assertEqual(lease.authorized_grant_digest, runtime.grant.grant_digest)
        self.assertEqual(lease.consumed_grant_digest, current.grant_digest)
        self.assertEqual(
            lease.consumed_approval_digest,
            runtime.session.consumed_approval_digest,
        )
        self.assertEqual(lease.session_terms_digest, runtime.session.session_terms_digest)
        self.assertEqual(lease.authorization_id, runtime.privacy.authorization_id)
        self.assertEqual(lease.request_envelope_digest, runtime.prepared.request_envelope_digest)
        self.assertEqual(lease.valid_until, runtime.session.valid_until)
        self.assertIs(lease._consent_ledger, runtime.consent_ledger)
        self.assertIs(lease._session, runtime.session)
        self.assertEqual(
            str(lease.lease_id),
            "784c31d9-f8f4-5a82-897e-7bd588d08da0",
        )
        self.assertEqual(
            str(lease.lease_terms_digest),
            "3da33c5640471a50db052abc23c301c32847fb28f47b100060b263617e71e468",
        )
        self.assertEqual(
            str(lease.lease_digest),
            "e4a7bb4c533706cffc2b623ba53bc4acc427054b8c439485f62f72a87b6d5042",
        )
        self.assertEqual(
            str(current.grant_digest),
            "cf4a9947fbc7d254866357cb521ee310b6316e3e5acb1cf120abbb154fa6aaa9",
        )
        self.assertEqual(
            runtime.consent_ledger.safe_metadata()["use_lease_count"],
            1,
        )

    def test_plain_authorization_dies_but_exact_session_attempt_survives(self):
        runtime = _make_one_shot_session()
        with self.assertRaises(EndpointPolicyError):
            PrivacyGate().validate_authorization(
                planned=runtime.planned,
                authorization=runtime.runtime_authorization,
                ledger=runtime.consent_ledger,
                now=runtime.clock.wall_time,
            )

        gate = AttemptGate()
        _finish_one_attempt(runtime, gate)
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            1,
        )

    def test_two_approvals_racing_for_one_grant_have_one_complete_winner(self):
        runtime = make_w09_runtime(one_shot_consent=True)
        approval_ledger = EgressApprovalLedger()
        first, _ = _approve(runtime, ledger=approval_ledger)
        second, _ = _approve(
            runtime,
            ledger=approval_ledger,
            decision_id=SECOND_DECISION_ID,
        )
        session_ledger = SendSessionLedger()
        barrier = Barrier(3)
        lock = Lock()
        sessions = []
        errors = []

        def worker(approval):
            barrier.wait()
            try:
                session, _ = _create_session(
                    runtime,
                    approval=approval,
                    approval_ledger=approval_ledger,
                    session_ledger=session_ledger,
                )
            except BaseException as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    sessions.append(session)

        threads = (Thread(target=worker, args=(first,)), Thread(target=worker, args=(second,)))
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        self.assertEqual(session_ledger.safe_metadata()["session_count"], 1)
        self.assertEqual(runtime.consent_ledger.safe_metadata()["use_lease_count"], 1)
        winner_id = sessions[0].approval_id
        loser_id = second.approval_id if winner_id == first.approval_id else first.approval_id
        self.assertIsNotNone(approval_ledger.snapshot(winner_id).consumed_at)
        self.assertIsNone(approval_ledger.snapshot(loser_id).consumed_at)

    def test_post_approval_commit_failure_rolls_back_grant_lease_and_session(self):
        runtime = make_w09_runtime(one_shot_consent=True)
        approval, approval_ledger = _approve(runtime)
        session_ledger = SendSessionLedger()
        initial_consent_revision = runtime.consent_ledger.safe_metadata()["revision"]
        original = ConsentLedger._consume_for_session

        def fail_after_consent_commit(selected, **kwargs):
            original(selected, **kwargs)
            raise RuntimeError("injected post-consent failure")

        with patch.object(
            ConsentLedger,
            "_consume_for_session",
            new=fail_after_consent_commit,
        ):
            with self.assertRaisesRegex(RuntimeError, "post-consent"):
                _create_session(
                    runtime,
                    approval=approval,
                    approval_ledger=approval_ledger,
                    session_ledger=session_ledger,
                )

        self.assertIs(
            runtime.consent_ledger.snapshot_for_ids((runtime.grant.grant_id,))[0],
            runtime.grant,
        )
        self.assertEqual(
            runtime.consent_ledger.safe_metadata(),
            {
                "revision": initial_consent_revision,
                "grant_count": 1,
                "use_lease_count": 0,
            },
        )
        self.assertEqual(
            session_ledger.safe_metadata(),
            {"revision": 0, "session_count": 0},
        )
        burned = approval_ledger.snapshot(approval.approval_id)
        self.assertEqual(burned.consumed_at, SESSION_AT)
        with self.assertRaises(EndpointPolicyError):
            _create_session(
                runtime,
                approval=approval,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
            )

        retry, _ = _approve(
            runtime,
            ledger=approval_ledger,
            decision_id=SECOND_DECISION_ID,
        )
        session, _ = _create_session(
            runtime,
            approval=retry,
            approval_ledger=approval_ledger,
            session_ledger=session_ledger,
            now=SESSION_AT + timedelta(seconds=1),
        )
        self.assertEqual(
            runtime.consent_ledger.snapshot_use_lease_for_session(
                session.session_id
            ).session_id,
            session.session_id,
        )

    def test_pre_consent_failure_removes_session_but_burns_approval(self):
        runtime = make_w09_runtime(one_shot_consent=True)
        approval, approval_ledger = _approve(runtime)
        session_ledger = SendSessionLedger()

        def fail_before_consent_commit(*args, **kwargs):
            del args, kwargs
            raise RuntimeError("injected pre-consent failure")

        with patch.object(
            ConsentLedger,
            "_consume_for_session",
            new=fail_before_consent_commit,
        ):
            with self.assertRaisesRegex(RuntimeError, "pre-consent"):
                _create_session(
                    runtime,
                    approval=approval,
                    approval_ledger=approval_ledger,
                    session_ledger=session_ledger,
                )
        self.assertIs(
            runtime.consent_ledger.snapshot_for_ids((runtime.grant.grant_id,))[0],
            runtime.grant,
        )
        self.assertEqual(runtime.consent_ledger.safe_metadata()["use_lease_count"], 0)
        self.assertEqual(session_ledger.safe_metadata()["session_count"], 0)
        self.assertEqual(
            approval_ledger.snapshot(approval.approval_id).consumed_at,
            SESSION_AT,
        )

    def test_session_publish_faults_leave_no_orphan(self):
        original_publish = SendSessionLedger._publish_locked

        for one_shot in (False, True):
            for mode in ("partial", "after"):
                with self.subTest(one_shot=one_shot, mode=mode):
                    runtime = make_w09_runtime(one_shot_consent=one_shot)
                    approval, approval_ledger = _approve(runtime)
                    session_ledger = SendSessionLedger()
                    sessions = []

                    def fail_publish(selected, session):
                        sessions.append(session)
                        if mode == "partial":
                            selected._sessions[session.session_id] = session
                        else:
                            original_publish(selected, session)
                        raise RuntimeError(f"injected {mode} publish failure")

                    with patch.object(
                        SendSessionLedger,
                        "_publish_locked",
                        new=fail_publish,
                    ):
                        with self.assertRaisesRegex(RuntimeError, mode):
                            _create_session(
                                runtime,
                                approval=approval,
                                approval_ledger=approval_ledger,
                                session_ledger=session_ledger,
                            )

                    self.assertEqual(
                        session_ledger.safe_metadata(),
                        {"revision": 0, "session_count": 0},
                    )
                    with self.assertRaises(EndpointPolicyError):
                        session_ledger.snapshot(sessions[0].session_id)
                    self.assertIs(
                        runtime.consent_ledger.snapshot_for_ids(
                            (runtime.grant.grant_id,)
                        )[0],
                        runtime.grant,
                    )
                    self.assertEqual(
                        runtime.consent_ledger.safe_metadata()["use_lease_count"],
                        0,
                    )
                    self.assertEqual(
                        approval_ledger.snapshot(approval.approval_id).consumed_at,
                        SESSION_AT,
                    )

                    runtime.approval_ledger = approval_ledger
                    runtime.session = sessions[0]
                    runtime.session_ledger = session_ledger
                    with self.assertRaises(EndpointPolicyError):
                        _authorize(runtime, AttemptGate())
                    self.assertEqual(
                        runtime.call_context.global_network_budget.snapshot().consumed,
                        0,
                    )

    def test_session_is_not_observable_before_lease_commit(self):
        runtime = make_w09_runtime(one_shot_consent=True)
        approval, approval_ledger = _approve(runtime)
        session_ledger = SendSessionLedger()
        entered = Event()
        release = Event()
        observer_started = Event()
        observer_done = Event()
        session_id_holder = []
        created = []
        observed = []
        errors = []
        original = ConsentLedger._consume_for_session

        def pause_before_consent_commit(selected, **kwargs):
            session_id_holder.append(kwargs["session"].session_id)
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("test did not release consent commit")
            return original(selected, **kwargs)

        def create_worker():
            try:
                session, _ = _create_session(
                    runtime,
                    approval=approval,
                    approval_ledger=approval_ledger,
                    session_ledger=session_ledger,
                )
                created.append(session)
            except BaseException as error:
                errors.append(error)

        def observe_worker():
            observer_started.set()
            try:
                observed.append(
                    session_ledger.snapshot(session_id_holder[0])
                )
            except BaseException as error:
                errors.append(error)
            finally:
                observer_done.set()

        with patch.object(
            ConsentLedger,
            "_consume_for_session",
            new=pause_before_consent_commit,
        ):
            creator = Thread(target=create_worker)
            creator.start()
            self.assertTrue(entered.wait(timeout=5))
            observer = Thread(target=observe_worker)
            observer.start()
            self.assertTrue(observer_started.wait(timeout=5))
            self.assertFalse(observer_done.wait(timeout=0.05))
            release.set()
            creator.join(timeout=5)
            observer.join(timeout=5)

        self.assertFalse(creator.is_alive())
        self.assertFalse(observer.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(created), 1)
        self.assertEqual(observed, created)
        self.assertEqual(
            runtime.consent_ledger.snapshot_use_lease_for_session(
                created[0].session_id
            ).session_id,
            created[0].session_id,
        )

    def test_direct_consume_does_not_fabricate_or_authorize_a_lease(self):
        runtime = make_w09_runtime(one_shot_consent=True)
        approval, approval_ledger = _approve(runtime)
        runtime.consent_ledger.consume(
            grant_id=runtime.grant.grant_id,
            consumed_at=SESSION_AT,
        )
        session_ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            _create_session(
                runtime,
                approval=approval,
                approval_ledger=approval_ledger,
                session_ledger=session_ledger,
            )
        self.assertIsNone(
            approval_ledger.snapshot(approval.approval_id).consumed_at
        )
        self.assertEqual(runtime.consent_ledger.safe_metadata()["use_lease_count"], 0)
        self.assertEqual(session_ledger.safe_metadata()["session_count"], 0)

    def test_lease_is_factory_only_immutable_and_tamper_evident(self):
        runtime = _make_one_shot_session()
        lease = runtime.consent_ledger.snapshot_use_lease_for_session(
            runtime.session.session_id
        )
        current = runtime.consent_ledger.snapshot_for_ids(
            (runtime.grant.grant_id,)
        )[0]
        with self.assertRaises(TypeError):
            ConsentUseLease(
                authorized_grant=runtime.grant,
                consumed_grant=current,
                authorization=runtime.runtime_authorization,
                planned=runtime.planned,
                stage=runtime.planned.plan.stages[0],
                session=runtime.session,
                consent_ledger=runtime.consent_ledger,
                session_ledger=runtime.session_ledger,
            )
        self.assertIs(copy.deepcopy(lease), lease)
        with self.assertRaises(AttributeError):
            lease.session_id = UUID(int=1)  # type: ignore[misc]

        original_session_id = runtime.session.session_id
        object.__setattr__(lease, "session_id", UUID(int=2))
        object.__setattr__(
            lease,
            "lease_id",
            _consent_use_lease_id_for(
                _consent_use_lease_identifier_payload(lease)
            ),
        )
        object.__setattr__(
            lease,
            "lease_terms_digest",
            digest256(
                "ConsentUseLeaseTerms",
                CONSENT_USE_LEASE_SCHEMA_VERSION,
                _consent_use_lease_terms_payload(lease),
            ),
        )
        object.__setattr__(
            lease,
            "lease_digest",
            digest256(
                "ConsentUseLease",
                CONSENT_USE_LEASE_SCHEMA_VERSION,
                {"lease_terms_digest": lease.lease_terms_digest},
            ),
        )
        with self.assertRaises(EndpointPolicyError):
            runtime.consent_ledger.snapshot_use_lease_for_session(
                original_session_id
            )

    def test_snapshot_rejects_session_index_alias(self):
        runtime = _make_one_shot_session()
        lease = runtime.consent_ledger.snapshot_use_lease_for_session(
            runtime.session.session_id
        )
        alias_session_id = UUID(int=99)
        with runtime.consent_ledger._lock:
            runtime.consent_ledger._use_lease_by_session[
                alias_session_id
            ] = lease.lease_id
        with self.assertRaises(EndpointPolicyError):
            runtime.consent_ledger.snapshot_use_lease_for_session(
                alias_session_id
            )

    def test_exact_session_identity_prevents_cross_ledger_alias(self):
        first = _make_one_shot_session()
        second = _make_one_shot_session()
        self.assertEqual(first.session.session_id, second.session.session_id)
        self.assertIsNot(first.session, second.session)

        gate = AttemptGate()
        with self.assertRaises(EndpointPolicyError):
            gate.authorize_credential_resolution(
                planned=first.planned,
                invocation=first.invocation,
                prepared=first.prepared,
                authorization=first.runtime_authorization,
                consent_ledger=first.consent_ledger,
                session=second.session,
                approval_ledger=second.approval_ledger,
                session_ledger=second.session_ledger,
                authority_ledger=first.authority_ledger,
                context=first.call_context,
                context_ledger=first.context_ledger,
            )

    def test_one_shot_lease_allows_two_attempts_but_not_a_third(self):
        runtime = _make_one_shot_session()
        gate = AttemptGate()
        _finish_one_attempt(runtime, gate)
        _finish_one_attempt(runtime, gate)
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            2,
        )
        credential = _authorize(runtime, gate)
        _resolve(gate, credential)
        with self.assertRaises(EndpointPolicyError):
            gate.reserve_attempt(credential_permit=credential)
        gate.abandon_credential_resolution(credential)
        self.assertEqual(runtime.consent_ledger.safe_metadata()["use_lease_count"], 1)

    def test_session_factory_and_lease_expiry_are_half_open(self):
        before = make_w09_runtime(
            one_shot_consent=True,
            grant_expires_at=SESSION_AT,
        )
        before_approval, before_approval_ledger = _approve(before)
        before_session, _ = _create_session(
            before,
            approval=before_approval,
            approval_ledger=before_approval_ledger,
            now=SESSION_AT - timedelta(milliseconds=1),
        )
        self.assertEqual(before_session.valid_until, SESSION_AT)

        at_expiry = make_w09_runtime(
            one_shot_consent=True,
            grant_expires_at=SESSION_AT,
        )
        expiry_approval, expiry_approval_ledger = _approve(at_expiry)
        expiry_session_ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            _create_session(
                at_expiry,
                approval=expiry_approval,
                approval_ledger=expiry_approval_ledger,
                session_ledger=expiry_session_ledger,
                now=SESSION_AT,
            )
        self.assertIsNone(
            expiry_approval_ledger.snapshot(
                expiry_approval.approval_id
            ).consumed_at
        )
        self.assertIs(
            at_expiry.consent_ledger.snapshot_for_ids(
                (at_expiry.grant.grant_id,)
            )[0],
            at_expiry.grant,
        )
        self.assertEqual(expiry_session_ledger.safe_metadata()["session_count"], 0)

    def test_lease_expiry_is_rechecked_before_secret_read_and_wire(self):
        before_read = make_w09_runtime(
            one_shot_consent=True,
            grant_expires_at=NOW + timedelta(seconds=10),
        )
        approval, approval_ledger = _approve(before_read)
        before_read.clock.advance(milliseconds=5_000)
        session, session_ledger = _create_session(
            before_read,
            approval=approval,
            approval_ledger=approval_ledger,
        )
        before_read.approval_ledger = approval_ledger
        before_read.session = session
        before_read.session_ledger = session_ledger
        credential = _authorize(before_read, AttemptGate())
        read_gate = credential._attempt_gate
        before_read.clock.advance(milliseconds=5_000)
        with self.assertRaises((EndpointPolicyError, SnapTimeoutError)):
            read_gate._claim_credential_resolution(
                credential,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        self.assertEqual(
            before_read.call_context.global_network_budget.snapshot().consumed,
            0,
        )
        read_gate.abandon_credential_resolution(credential)

        before_wire = make_w09_runtime(
            one_shot_consent=True,
            grant_expires_at=NOW + timedelta(seconds=10),
        )
        approval, approval_ledger = _approve(before_wire)
        before_wire.clock.advance(milliseconds=5_000)
        session, session_ledger = _create_session(
            before_wire,
            approval=approval,
            approval_ledger=approval_ledger,
        )
        before_wire.approval_ledger = approval_ledger
        before_wire.session = session
        before_wire.session_ledger = session_ledger
        wire_gate = AttemptGate()
        wire_credential = _authorize(before_wire, wire_gate)
        _resolve(wire_gate, wire_credential)
        attempt = wire_gate.reserve_attempt(credential_permit=wire_credential)
        before_wire.clock.advance(milliseconds=5_000)
        with self.assertRaises((EndpointPolicyError, SnapTimeoutError)):
            wire_gate._claim_attempt(
                attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        self.assertEqual(
            before_wire.call_context.global_network_budget.snapshot().consumed,
            1,
        )
        wire_gate.abandon_attempt(attempt)

    def test_wall_clock_rollback_before_lease_issue_is_rejected(self):
        runtime = _make_one_shot_session()
        runtime.clock.advance(
            milliseconds=1_000,
            wall_delta=timedelta(seconds=-2),
        )
        with self.assertRaises(EndpointPolicyError):
            _authorize(runtime, AttemptGate())
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            0,
        )

    def test_persistent_session_remains_unconsumed_and_lease_free(self):
        runtime = make_w09_runtime(one_shot_consent=False)
        approval, approval_ledger = _approve(runtime)
        runtime.clock.advance(milliseconds=5_000)
        session, session_ledger = _create_session(
            runtime,
            approval=approval,
            approval_ledger=approval_ledger,
        )
        runtime.approval_ledger = approval_ledger
        runtime.session = session
        runtime.session_ledger = session_ledger
        self.assertIs(
            runtime.consent_ledger.snapshot_for_ids((runtime.grant.grant_id,))[0],
            runtime.grant,
        )
        self.assertIsNone(runtime.grant.consumed_at)
        self.assertEqual(runtime.consent_ledger.safe_metadata()["use_lease_count"], 0)
        with self.assertRaises(EndpointPolicyError):
            runtime.consent_ledger.snapshot_use_lease_for_session(
                session.session_id
            )
        PrivacyGate().validate_authorization(
            planned=runtime.planned,
            authorization=runtime.runtime_authorization,
            ledger=runtime.consent_ledger,
            now=runtime.clock.wall_time,
        )
        gate = AttemptGate()
        _finish_one_attempt(runtime, gate)
        _finish_one_attempt(runtime, gate)
        self.assertEqual(
            runtime.call_context.global_network_budget.snapshot().consumed,
            2,
        )

    def test_terminal_cleanup_never_revives_consumed_grant(self):
        runtime = _make_one_shot_session()
        gate = AttemptGate()
        _finish_one_attempt(runtime, gate)
        runtime.session_ledger.revoke(
            session_id=runtime.session.session_id,
            revoked_at=runtime.clock.wall_time + timedelta(seconds=1),
        )
        self.assertTrue(runtime.context_ledger.close(runtime.call_context))
        current = runtime.consent_ledger.snapshot_for_ids(
            (runtime.grant.grant_id,)
        )[0]
        self.assertIsNot(current, runtime.grant)
        self.assertEqual(current.consumed_at, runtime.session.issued_at)
        self.assertIsNone(current.revoked_at)

    def test_session_create_vs_grant_revoke_is_linearizable(self):
        for _ in range(10):
            runtime = make_w09_runtime(one_shot_consent=True)
            approval, approval_ledger = _approve(runtime)
            session_ledger = SendSessionLedger()
            runtime.clock.advance(milliseconds=5_000)
            barrier = Barrier(3)
            outcomes = []
            lock = Lock()

            def create_worker():
                barrier.wait()
                try:
                    session, _ = _create_session(
                        runtime,
                        approval=approval,
                        approval_ledger=approval_ledger,
                        session_ledger=session_ledger,
                    )
                except BaseException as error:
                    result = ("create_error", error)
                else:
                    result = ("create", session)
                with lock:
                    outcomes.append(result)

            def revoke_worker():
                barrier.wait()
                try:
                    revoked = runtime.consent_ledger.revoke(
                        grant_id=runtime.grant.grant_id,
                        revoked_at=SESSION_AT,
                    )
                except BaseException as error:
                    result = ("revoke_error", error)
                else:
                    result = ("revoke", revoked)
                with lock:
                    outcomes.append(result)

            threads = (Thread(target=create_worker), Thread(target=revoke_worker))
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=5)
            self.assertTrue(all(not thread.is_alive() for thread in threads))

            labels = {label for label, _ in outcomes}
            self.assertIn("revoke", labels)
            if "create" in labels:
                session = next(value for label, value in outcomes if label == "create")
                self.assertEqual(session_ledger.safe_metadata()["session_count"], 1)
                self.assertEqual(runtime.consent_ledger.safe_metadata()["use_lease_count"], 1)
                self.assertIsNotNone(
                    approval_ledger.snapshot(approval.approval_id).consumed_at
                )
                runtime.session = session
                runtime.session_ledger = session_ledger
                runtime.approval_ledger = approval_ledger
                with self.assertRaises(EndpointPolicyError):
                    _authorize(runtime, AttemptGate())
            else:
                self.assertIn("create_error", labels)
                self.assertEqual(session_ledger.safe_metadata()["session_count"], 0)
                self.assertEqual(runtime.consent_ledger.safe_metadata()["use_lease_count"], 0)
                self.assertIsNone(
                    approval_ledger.snapshot(approval.approval_id).consumed_at
                )

    def test_grant_revoke_is_rechecked_before_secret_read_and_wire(self):
        before_read = _make_one_shot_session()
        read_gate = AttemptGate()
        credential = _authorize(before_read, read_gate)
        before_read.clock.advance(milliseconds=1_000)
        before_read.consent_ledger.revoke(
            grant_id=before_read.grant.grant_id,
            revoked_at=before_read.clock.wall_time,
        )
        with self.assertRaises(EndpointPolicyError):
            read_gate._claim_credential_resolution(
                credential,
                _authority=_CREDENTIAL_RESOLVER_AUTHORITY,
            )
        self.assertEqual(
            before_read.call_context.global_network_budget.snapshot().consumed,
            0,
        )
        read_gate.abandon_credential_resolution(credential)

        before_wire = _make_one_shot_session()
        wire_gate = AttemptGate()
        wire_credential = _authorize(before_wire, wire_gate)
        _resolve(wire_gate, wire_credential)
        attempt = wire_gate.reserve_attempt(credential_permit=wire_credential)
        before_wire.clock.advance(milliseconds=1_000)
        before_wire.consent_ledger.revoke(
            grant_id=before_wire.grant.grant_id,
            revoked_at=before_wire.clock.wall_time,
        )
        with self.assertRaises(EndpointPolicyError):
            wire_gate._claim_attempt(
                attempt,
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        self.assertEqual(
            before_wire.call_context.global_network_budget.snapshot().consumed,
            1,
        )
        wire_gate.abandon_attempt(attempt)

    def test_one_shot_full_authority_path_has_zero_external_side_effects(self):
        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("external side effect")

        with (
            patch.object(builtins, "open", forbidden),
            patch("os.getenv", forbidden),
            patch.object(os, "environ", _ForbiddenEnvironment()),
            patch.object(time, "sleep", forbidden),
            patch.object(socket, "getaddrinfo", forbidden),
            patch.object(socket, "socket", forbidden),
            patch.object(socket, "create_connection", forbidden),
        ):
            runtime = _make_one_shot_session()
            gate = AttemptGate()
            _finish_one_attempt(runtime, gate)


if __name__ == "__main__":
    unittest.main()
