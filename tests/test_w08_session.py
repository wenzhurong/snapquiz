from __future__ import annotations

import builtins
import copy
from dataclasses import asdict
from datetime import timedelta
import os
import socket
from threading import Barrier, Lock, Thread
import time
import unittest
from unittest.mock import patch

from snapquiz.domain.digest import Digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.privacy.egress import EgressApprovalLedger
from snapquiz.transport.session import (
    AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
    SEND_SESSION_POLICY_VERSION,
    AuthorizedSendSession,
    SendSessionFactory,
    SendSessionLedger,
)

from tests.w06_helpers import NOW
from tests.w08_helpers import make_w08_authorities


SESSION_ISSUED_AT = NOW + timedelta(seconds=5)


def _create_session(authorities, *, ledger=None, now=SESSION_ISSUED_AT):
    selected_ledger = SendSessionLedger() if ledger is None else ledger
    session = SendSessionFactory.create(
        planned=authorities.planned,
        invocation=authorities.invocation,
        prepared=authorities.prepared,
        authorization=authorities.privacy,
        consent_ledger=authorities.consent_ledger,
        approval=authorities.approval,
        approval_ledger=authorities.approval_ledger,
        session_ledger=selected_ledger,
        now=now,
    )
    return session, selected_ledger


class W08StaticSendSessionTest(unittest.TestCase):
    def test_exact_static_session_binding_and_golden(self):
        authorities = make_w08_authorities()
        session, ledger = _create_session(authorities)
        consumed = authorities.approval_ledger.snapshot(
            authorities.approval.approval_id
        )

        self.assertEqual(
            AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
            "snapquiz.authorized-send-session.v1",
        )
        self.assertEqual(
            SEND_SESSION_POLICY_VERSION,
            "snapquiz.send-session.static-w08.v1",
        )
        self.assertEqual(session.approval_id, authorities.approval.approval_id)
        self.assertEqual(
            session.approval_terms_digest,
            authorities.approval.approval_terms_digest,
        )
        self.assertEqual(session.consumed_approval_digest, consumed.approval_digest)
        self.assertEqual(consumed.consumed_at, SESSION_ISSUED_AT)
        self.assertEqual(session.request_id, authorities.planned.plan.request_id)
        self.assertEqual(session.plan_id, authorities.planned.plan.plan_id)
        self.assertEqual(session.plan_digest, authorities.planned.plan.plan_digest)
        self.assertEqual(
            session.planned_execution_digest,
            authorities.planned.planned_execution_digest,
        )
        self.assertEqual(
            session.registry_revision,
            authorities.planned.resolved_pipeline.registry_revision,
        )
        self.assertEqual(
            session.registry_digest,
            authorities.planned.resolved_pipeline.registry_digest,
        )
        self.assertEqual(
            session.privacy_authorization_id,
            authorities.privacy.authorization_id,
        )
        self.assertEqual(
            session.privacy_authorization_digest,
            authorities.privacy.authorization_digest,
        )
        self.assertEqual(session.stage_id, authorities.invocation.stage_id)
        self.assertEqual(session.operation_id, authorities.operation.operation_id)
        self.assertEqual(session.invocation_id, authorities.invocation.invocation_id)
        self.assertEqual(
            session.invocation_digest,
            authorities.invocation.invocation_digest,
        )
        self.assertEqual(session.source_ids, authorities.prepared.source_ids)
        self.assertEqual(session.source_digests, authorities.prepared.source_digests)
        self.assertEqual(
            session.capture_scope_fingerprint,
            authorities.validated.scope_fingerprint,
        )
        for name in (
            "http_method",
            "canonical_url",
            "content_type",
            "non_secret_headers_digest",
            "credential_binding_digest",
            "outbound_data",
            "body_digest",
            "payload_byte_size",
            "request_envelope_digest",
        ):
            self.assertEqual(
                getattr(session, name),
                getattr(authorities.prepared, name),
            )
        self.assertEqual(
            session.max_network_attempts,
            authorities.approval.max_network_attempts,
        )
        self.assertEqual(session.billable, authorities.approval.billable)
        self.assertEqual(session.issued_at, SESSION_ISSUED_AT)
        self.assertEqual(session.valid_until, authorities.approval.expires_at)
        self.assertIsNone(session.revoked_at)
        self.assertIs(ledger.snapshot(session.session_id), session)
        session.validate_integrity()

        self.assertEqual(
            str(session.session_id),
            "244ba3b8-8cbf-574e-acbd-1977a3ea66a2",
        )
        self.assertEqual(
            str(session.consumed_approval_digest),
            "5e4948b24602695b552f48edc943925880416469a8ae93519249dd3bd448f44d",
        )
        self.assertEqual(
            str(session.session_terms_digest),
            "c7ea9a79fd17b4efa6ddfd0598171e9476f7a7ec30a18644097e314d51ab5b13",
        )
        self.assertEqual(
            str(session.session_digest),
            "ab9f4b9a9814a05749f3620d818d1a26f8fd5612a9a8e392880cf3837ee4d0e4",
        )

    def test_session_is_factory_only_immutable_redacted_and_has_no_w09_state(self):
        secret_hint = "session-secret-hint-must-not-leak"
        authorities = make_w08_authorities(user_hint=secret_hint)
        session, _ = _create_session(authorities)
        consumed = authorities.approval_ledger.snapshot(
            authorities.approval.approval_id
        )

        with self.assertRaises(TypeError):
            AuthorizedSendSession(
                session_id=session.session_id,
                consumed_approval=consumed,
                issued_at=session.issued_at,
                valid_until=session.valid_until,
                session_ledger=SendSessionLedger(),
            )
        with self.assertRaises(AttributeError):
            session.operation_id = authorities.planned.plan.plan_id  # type: ignore[misc]
        with self.assertRaises(TypeError):
            asdict(session)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            vars(session)
        self.assertIs(copy.deepcopy(session), session)

        rendered = repr(session) + repr(session.safe_metadata())
        self.assertNotIn(secret_hint, rendered)
        self.assertNotIn(authorities.prepared.body.decode("utf-8"), rendered)
        for digest in (
            session.planned_execution_digest,
            session.body_digest,
            session.request_envelope_digest,
            session.session_terms_digest,
            session.session_digest,
        ):
            self.assertNotIn(str(digest), rendered)
        for forbidden in (
            "runtime_deadline",
            "attempts_remaining",
            "global_network_budget_id",
            "billable_budget_id",
            "authorization_lease_id",
            "cancellation_token_id",
            "credential_handle_id",
            "credential_handle",
            "http_client",
        ):
            self.assertFalse(hasattr(session, forbidden), forbidden)

    def test_concurrent_factory_consumption_has_exactly_one_winner(self):
        authorities = make_w08_authorities()
        ledger = SendSessionLedger()
        barrier = Barrier(3)
        lock = Lock()
        sessions: list[AuthorizedSendSession] = []
        errors: list[BaseException] = []

        def worker() -> None:
            barrier.wait()
            try:
                result, _ = _create_session(authorities, ledger=ledger)
                with lock:
                    sessions.append(result)
            except BaseException as error:  # test thread must report every failure
                with lock:
                    errors.append(error)

        threads = [Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], EndpointPolicyError)
        self.assertEqual(ledger.safe_metadata()["session_count"], 1)
        current = authorities.approval_ledger.snapshot(
            authorities.approval.approval_id
        )
        self.assertEqual(current.consumed_at, SESSION_ISSUED_AT)

    def test_approval_revoke_race_with_session_create_has_one_winner(self):
        authorities = make_w08_authorities(user_hint="approval revoke race")
        session_ledger = SendSessionLedger()
        barrier = Barrier(3)
        lock = Lock()
        successes = []
        errors = []

        def create_worker() -> None:
            barrier.wait()
            try:
                session, _ = _create_session(authorities, ledger=session_ledger)
            except BaseException as error:
                with lock:
                    errors.append(("create", error))
            else:
                with lock:
                    successes.append(("create", session))

        def revoke_worker() -> None:
            barrier.wait()
            try:
                revoked = authorities.approval_ledger.revoke(
                    approval_id=authorities.approval.approval_id,
                    revoked_at=SESSION_ISSUED_AT,
                )
            except BaseException as error:
                with lock:
                    errors.append(("revoke", error))
            else:
                with lock:
                    successes.append(("revoke", revoked))

        threads = [Thread(target=create_worker), Thread(target=revoke_worker)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0][1], EndpointPolicyError)
        current = authorities.approval_ledger.snapshot(
            authorities.approval.approval_id
        )
        if successes[0][0] == "create":
            self.assertEqual(current.consumed_at, SESSION_ISSUED_AT)
            self.assertIsNone(current.revoked_at)
            self.assertEqual(session_ledger.safe_metadata()["session_count"], 1)
        else:
            self.assertIsNone(current.consumed_at)
            self.assertEqual(current.revoked_at, SESSION_ISSUED_AT)
            self.assertEqual(session_ledger.safe_metadata()["session_count"], 0)

    def test_consent_revoke_race_with_session_create_linearizes_without_deadlock(self):
        authorities = make_w08_authorities(user_hint="consent revoke race")
        session_ledger = SendSessionLedger()
        barrier = Barrier(3)
        lock = Lock()
        sessions = []
        create_errors = []
        revoke_results = []
        revoke_errors = []

        def create_worker() -> None:
            barrier.wait()
            try:
                session, _ = _create_session(authorities, ledger=session_ledger)
            except BaseException as error:
                with lock:
                    create_errors.append(error)
            else:
                with lock:
                    sessions.append(session)

        def revoke_worker() -> None:
            barrier.wait()
            try:
                revoked = authorities.consent_ledger.revoke(
                    grant_id=authorities.privacy.consent_grant_ids[0],
                    revoked_at=SESSION_ISSUED_AT,
                )
            except BaseException as error:
                with lock:
                    revoke_errors.append(error)
            else:
                with lock:
                    revoke_results.append(revoked)

        threads = [Thread(target=create_worker), Thread(target=revoke_worker)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(revoke_results), 1)
        self.assertEqual(revoke_errors, [])
        self.assertEqual(len(sessions) + len(create_errors), 1)
        if create_errors:
            self.assertIsInstance(create_errors[0], EndpointPolicyError)
            self.assertIs(
                authorities.approval_ledger.snapshot(
                    authorities.approval.approval_id
                ),
                authorities.approval,
            )
            self.assertEqual(session_ledger.safe_metadata()["session_count"], 0)
        else:
            current = authorities.approval_ledger.snapshot(
                authorities.approval.approval_id
            )
            self.assertEqual(current.consumed_at, SESSION_ISSUED_AT)
            self.assertEqual(session_ledger.safe_metadata()["session_count"], 1)

    def test_expired_revoked_and_privacy_revoked_approval_do_not_create_session(self):
        expired = make_w08_authorities()
        expired_ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            _create_session(
                expired,
                ledger=expired_ledger,
                now=expired.approval.expires_at,
            )
        self.assertIs(
            expired.approval_ledger.snapshot(expired.approval.approval_id),
            expired.approval,
        )
        self.assertIsNone(expired.approval.consumed_at)
        self.assertEqual(expired_ledger.safe_metadata()["session_count"], 0)

        revoked = make_w08_authorities()
        revoked.approval_ledger.revoke(
            approval_id=revoked.approval.approval_id,
            revoked_at=SESSION_ISSUED_AT,
        )
        revoked_ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            _create_session(revoked, ledger=revoked_ledger)
        self.assertEqual(revoked_ledger.safe_metadata()["session_count"], 0)

        privacy_revoked = make_w08_authorities()
        privacy_revoked.consent_ledger.revoke(
            grant_id=privacy_revoked.privacy.consent_grant_ids[0],
            revoked_at=SESSION_ISSUED_AT,
        )
        privacy_ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            _create_session(privacy_revoked, ledger=privacy_ledger)
        self.assertIsNone(privacy_revoked.approval.consumed_at)
        self.assertEqual(privacy_ledger.safe_metadata()["session_count"], 0)

    def test_wrong_approval_or_session_ledger_fails_closed(self):
        authorities = make_w08_authorities()
        session_ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            SendSessionFactory.create(
                planned=authorities.planned,
                invocation=authorities.invocation,
                prepared=authorities.prepared,
                authorization=authorities.privacy,
                consent_ledger=authorities.consent_ledger,
                approval=authorities.approval,
                approval_ledger=EgressApprovalLedger(),
                session_ledger=session_ledger,
                now=SESSION_ISSUED_AT,
            )
        self.assertIsNone(authorities.approval.consumed_at)
        self.assertEqual(session_ledger.safe_metadata()["session_count"], 0)

        owner = make_w08_authorities()
        session, owner_ledger = _create_session(owner)
        with self.assertRaises(EndpointPolicyError):
            SendSessionLedger().validate_active(
                session,
                now=SESSION_ISSUED_AT,
            )
        owner_ledger.validate_active(session, now=SESSION_ISSUED_AT)

    def test_cross_execution_and_mutated_approval_fail_before_consumption(self):
        owner = make_w08_authorities()
        other = make_w08_authorities(user_hint="different authority")
        ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            SendSessionFactory.create(
                planned=other.planned,
                invocation=other.invocation,
                prepared=other.prepared,
                authorization=other.privacy,
                consent_ledger=other.consent_ledger,
                approval=owner.approval,
                approval_ledger=owner.approval_ledger,
                session_ledger=ledger,
                now=SESSION_ISSUED_AT,
            )
        self.assertIsNone(owner.approval.consumed_at)
        self.assertEqual(ledger.safe_metadata()["session_count"], 0)

        mutated = make_w08_authorities()
        object.__setattr__(
            mutated.approval,
            "request_envelope_digest",
            Digest256("f" * 64),
        )
        mutated_ledger = SendSessionLedger()
        with self.assertRaises(EndpointPolicyError):
            _create_session(mutated, ledger=mutated_ledger)
        self.assertEqual(mutated_ledger.safe_metadata()["session_count"], 0)

    def test_session_tamper_expiry_and_revocation_are_fail_closed(self):
        active = make_w08_authorities()
        session, ledger = _create_session(active)
        ledger.validate_active(session, now=session.issued_at)
        with self.assertRaises(EndpointPolicyError):
            ledger.validate_active(session, now=session.valid_until)

        object.__setattr__(session, "body_digest", Digest256("e" * 64))
        with self.assertRaises(EndpointPolicyError):
            ledger.validate_active(session, now=SESSION_ISSUED_AT)

        revocable = make_w08_authorities(user_hint="revocable")
        original, revocation_ledger = _create_session(revocable)
        replacement = revocation_ledger.revoke(
            session_id=original.session_id,
            revoked_at=SESSION_ISSUED_AT + timedelta(seconds=1),
        )
        self.assertEqual(replacement.session_terms_digest, original.session_terms_digest)
        self.assertNotEqual(replacement.session_digest, original.session_digest)
        self.assertIs(revocation_ledger.snapshot(original.session_id), replacement)
        with self.assertRaises(EndpointPolicyError):
            revocation_ledger.validate_active(
                original,
                now=SESSION_ISSUED_AT + timedelta(seconds=2),
            )
        with self.assertRaises(EndpointPolicyError):
            revocation_ledger.validate_active(
                replacement,
                now=SESSION_ISSUED_AT + timedelta(seconds=2),
            )

    def test_session_ledger_collision_burns_second_approval(self):
        first = make_w08_authorities()
        second = make_w08_authorities()
        shared = SendSessionLedger()
        first_session, _ = _create_session(first, ledger=shared)

        with self.assertRaises(EndpointPolicyError):
            _create_session(second, ledger=shared)
        self.assertEqual(shared.safe_metadata()["session_count"], 1)
        self.assertIs(shared.snapshot(first_session.session_id), first_session)
        second_current = second.approval_ledger.snapshot(
            second.approval.approval_id
        )
        self.assertIsNot(second_current, second.approval)
        self.assertEqual(second_current.consumed_at, SESSION_ISSUED_AT)
        self.assertNotEqual(
            second_current.approval_digest,
            second.approval.approval_digest,
        )
        with self.assertRaises(EndpointPolicyError):
            _create_session(second, ledger=shared)

    def test_approval_consumption_commits_before_session_issue(self):
        authorities = make_w08_authorities()
        ledger = SendSessionLedger()
        original_issue = SendSessionLedger._issue
        observed_digests = []

        def inspect_then_issue(target_ledger, session, *, _authority=None):
            current = authorities.approval_ledger.snapshot(
                authorities.approval.approval_id
            )
            self.assertEqual(current.consumed_at, SESSION_ISSUED_AT)
            self.assertEqual(current.approval_digest, session.consumed_approval_digest)
            observed_digests.append(current.approval_digest)
            return original_issue(
                target_ledger,
                session,
                _authority=_authority,
            )

        with patch.object(SendSessionLedger, "_issue", inspect_then_issue):
            session, _ = _create_session(authorities, ledger=ledger)
        self.assertEqual(observed_digests, [session.consumed_approval_digest])
        self.assertIs(ledger.snapshot(session.session_id), session)

    def test_factory_has_zero_file_environment_sleep_or_network_side_effect(self):
        authorities = make_w08_authorities()

        def forbidden(*args, **kwargs):
            del args, kwargs
            raise AssertionError("external side effect")

        with (
            patch.object(builtins, "open", forbidden),
            patch("os.getenv", forbidden),
            patch.object(os, "environ", {}),
            patch.object(time, "sleep", forbidden),
            patch.object(socket, "socket", forbidden),
            patch.object(socket, "create_connection", forbidden),
            patch.object(socket, "getaddrinfo", forbidden),
        ):
            session, ledger = _create_session(authorities)
        ledger.validate_active(session, now=SESSION_ISSUED_AT)


if __name__ == "__main__":
    unittest.main()
