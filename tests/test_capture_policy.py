import unittest
from datetime import timedelta
from threading import Barrier, Event, Lock, Thread
from unittest.mock import patch
from uuid import UUID

from snapquiz.capture.policy import (
    CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
    CaptureAuthorization,
    CaptureAuthorizationLedger,
    CapturePolicy,
    ConsumedCaptureAuthorization,
)
from snapquiz.core.permissions import PermissionGate, ScreenPermissionState
from snapquiz.domain.capture import CaptureRect
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import (
    CaptureError,
    EndpointPolicyError,
    PermissionDeniedError,
)
from tests.w06_helpers import (
    CAPTURE_ID,
    NOW,
    granted_permission,
    permission_observation,
    planned_execution,
    privacy_authorization,
    selected_scope,
    topology,
)


class CapturePolicyContractTest(unittest.TestCase):
    def _authorization(
        self,
        *,
        expires_at=None,
        bind_scope: bool = True,
        one_shot: bool = False,
    ):
        current_topology = topology()
        scope = selected_scope(current_topology)
        planned = planned_execution(current_topology)
        consent_ledger, privacy = privacy_authorization(
            planned,
            expires_at=expires_at,
            scope_fingerprint=scope.fingerprint if bind_scope else None,
            one_shot=one_shot,
        )
        capture_ledger = CaptureAuthorizationLedger()
        authorization = CapturePolicy().authorize(
            planned=planned,
            privacy_authorization=privacy,
            consent_ledger=consent_ledger,
            permission_observation=granted_permission(),
            topology=current_topology,
            selected_scope=scope,
            capture_id=CAPTURE_ID,
            capture_ledger=capture_ledger,
            now=NOW,
        )
        return (
            current_topology,
            scope,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        )

    def test_authorization_binds_plan_privacy_permission_topology_and_scope(self):
        (
            current_topology,
            scope,
            planned,
            _,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()

        self.assertEqual(authorization.capture_id, CAPTURE_ID)
        self.assertEqual(authorization.request_id, planned.plan.request_id)
        self.assertEqual(authorization.plan_id, planned.plan.plan_id)
        self.assertEqual(authorization.plan_digest, planned.plan.plan_digest)
        self.assertEqual(
            authorization.planned_execution_digest,
            planned.planned_execution_digest,
        )
        self.assertEqual(
            authorization.privacy_authorization_id,
            privacy.authorization_id,
        )
        self.assertEqual(
            authorization.privacy_authorization_digest,
            privacy.authorization_digest,
        )
        self.assertEqual(
            authorization.topology_revision,
            current_topology.topology_revision,
        )
        self.assertIs(authorization.scope, scope)
        self.assertIs(
            authorization.constraints,
            planned.plan.capture_constraints,
        )
        self.assertEqual(
            capture_ledger.safe_metadata(),
            {
                "revision": 1,
                "authorization_count": 1,
                "consumed_count": 0,
            },
        )
        authorization.validate_integrity()

    def test_capture_authority_objects_cannot_be_forged(self):
        *_, authorization = self._authorization()
        with self.assertRaises(TypeError):
            CaptureAuthorization(  # type: ignore[call-arg]
                capture_authorization_id=authorization.capture_authorization_id,
                capture_id=authorization.capture_id,
                request_id=authorization.request_id,
                plan_id=authorization.plan_id,
                plan_digest=authorization.plan_digest,
                planned_execution_digest=authorization.planned_execution_digest,
                privacy_authorization_id=authorization.privacy_authorization_id,
                privacy_authorization_digest=(
                    authorization.privacy_authorization_digest
                ),
                permission_observation_digest=(
                    authorization.permission_observation_digest
                ),
                topology_revision=authorization.topology_revision,
                scope=authorization.scope,
                constraints=authorization.constraints,
                authorized_at=authorization.authorized_at,
                valid_until=authorization.valid_until,
            )
        with self.assertRaises(TypeError):
            ConsumedCaptureAuthorization(  # type: ignore[call-arg]
                authorization=authorization,
                consumed_at=NOW + timedelta(seconds=1),
                pre_capture_permission_observation_digest=Digest256("1" * 64),
                pre_capture_topology_snapshot_digest=Digest256("2" * 64),
            )

    def test_privacy_context_from_another_plan_is_rejected(self):
        first_topology = topology()
        first_planned = planned_execution(first_topology)
        consent_ledger, privacy = privacy_authorization(first_planned)
        second_planned = planned_execution(
            first_topology,
            request_id=UUID("20000000-0000-0000-0000-000000000001"),
        )

        with self.assertRaises(EndpointPolicyError):
            CapturePolicy().authorize(
                planned=second_planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                permission_observation=granted_permission(),
                topology=first_topology,
                selected_scope=selected_scope(first_topology),
                capture_id=CAPTURE_ID,
                capture_ledger=CaptureAuthorizationLedger(),
                now=NOW,
            )

    def test_revoked_privacy_context_cannot_issue_capture_authorization(self):
        current_topology = topology()
        planned = planned_execution(current_topology)
        consent_ledger, privacy = privacy_authorization(planned)
        consent_ledger.revoke(
            grant_id=privacy.consent_grant_ids[0],
            revoked_at=NOW,
        )

        with self.assertRaises(EndpointPolicyError):
            CapturePolicy().authorize(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                permission_observation=granted_permission(),
                topology=current_topology,
                selected_scope=selected_scope(current_topology),
                capture_id=CAPTURE_ID,
                capture_ledger=CaptureAuthorizationLedger(),
                now=NOW,
            )

    def test_revocation_between_precheck_and_atomic_issue_is_rejected(self):
        current_topology = topology()
        scope = selected_scope(current_topology)
        planned = planned_execution(current_topology)
        consent_ledger, privacy = privacy_authorization(
            planned,
            scope_fingerprint=scope.fingerprint,
        )
        capture_ledger = CaptureAuthorizationLedger()
        original_validation = CaptureAuthorization.validate_integrity
        revoked = False

        def validate_then_revoke(value):
            nonlocal revoked
            original_validation(value)
            if not revoked:
                consent_ledger.revoke(
                    grant_id=privacy.consent_grant_ids[0],
                    revoked_at=NOW,
                )
                revoked = True

        with (
            patch.object(
                CaptureAuthorization,
                "validate_integrity",
                new=validate_then_revoke,
            ),
            self.assertRaises(EndpointPolicyError),
        ):
            CapturePolicy().authorize(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                permission_observation=granted_permission(),
                topology=current_topology,
                selected_scope=scope,
                capture_id=CAPTURE_ID,
                capture_ledger=capture_ledger,
                now=NOW,
            )
        self.assertEqual(capture_ledger.safe_metadata()["authorization_count"], 0)

    def test_denied_unknown_and_stale_permission_fail_before_issue(self):
        current_topology = topology()
        planned = planned_execution(current_topology)
        consent_ledger, privacy = privacy_authorization(planned)

        observations = (
            permission_observation(
                ScreenPermissionState.DENIED,
                observed_at=NOW,
            ),
            permission_observation(
                ScreenPermissionState.UNKNOWN,
                observed_at=NOW,
            ),
            granted_permission(observed_at=NOW - timedelta(microseconds=1)),
        )
        for observation in observations:
            capture_ledger = CaptureAuthorizationLedger()
            with self.subTest(state=observation.state), self.assertRaises(
                PermissionDeniedError
            ):
                CapturePolicy().authorize(
                    planned=planned,
                    privacy_authorization=privacy,
                    consent_ledger=consent_ledger,
                    permission_observation=observation,
                    topology=current_topology,
                    selected_scope=selected_scope(current_topology),
                    capture_id=CAPTURE_ID,
                    capture_ledger=capture_ledger,
                    now=NOW,
                )
            self.assertEqual(capture_ledger.safe_metadata()["authorization_count"], 0)

    def test_topology_time_revision_scope_and_plan_bounds_fail_closed(self):
        current_topology = topology()
        planned = planned_execution(current_topology)
        consent_ledger, privacy = privacy_authorization(planned)

        cases = (
            (
                topology(observed_at=NOW - timedelta(microseconds=1)),
                selected_scope(current_topology),
            ),
            (
                topology(primary_pixel_width=2_561),
                selected_scope(
                    topology(primary_pixel_width=2_561),
                ),
            ),
            (
                current_topology,
                selected_scope(
                    current_topology,
                    display_geometry_revision=str(Digest256("e" * 64)),
                ),
            ),
            (
                current_topology,
                selected_scope(current_topology, display_id="display-2"),
            ),
            (
                current_topology,
                selected_scope(
                    current_topology,
                    rect=CaptureRect(left=0, top=0, width=2_560, height=1_600),
                ),
            ),
            (
                current_topology,
                selected_scope(
                    current_topology,
                    rect=CaptureRect(left=0, top=0, width=2_001, height=100),
                ),
            ),
        )
        for candidate_topology, scope in cases:
            capture_ledger = CaptureAuthorizationLedger()
            with self.subTest(scope=scope), self.assertRaises(CaptureError):
                CapturePolicy().authorize(
                    planned=planned,
                    privacy_authorization=privacy,
                    consent_ledger=consent_ledger,
                    permission_observation=granted_permission(),
                    topology=candidate_topology,
                    selected_scope=scope,
                    capture_id=CAPTURE_ID,
                    capture_ledger=capture_ledger,
                    now=NOW,
                )
            self.assertEqual(capture_ledger.safe_metadata()["authorization_count"], 0)

    def test_prepare_rechecks_permission_and_topology_before_consuming(self):
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        capture_time = NOW + timedelta(seconds=1)

        with self.assertRaises(PermissionDeniedError):
            CapturePolicy().prepare_capture(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                authorization=authorization,
                capture_ledger=capture_ledger,
                permission_observation=permission_observation(
                    ScreenPermissionState.DENIED,
                    observed_at=capture_time,
                ),
                topology=topology(observed_at=capture_time),
                now=capture_time,
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)

        with self.assertRaises(CaptureError):
            CapturePolicy().prepare_capture(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                authorization=authorization,
                capture_ledger=capture_ledger,
                permission_observation=granted_permission(
                    observed_at=capture_time
                ),
                topology=topology(
                    observed_at=capture_time,
                    primary_pixel_width=2_561,
                ),
                now=capture_time,
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)

        consumed = CapturePolicy().prepare_capture(
            planned=planned,
            privacy_authorization=privacy,
            consent_ledger=consent_ledger,
            authorization=authorization,
            capture_ledger=capture_ledger,
            permission_observation=granted_permission(observed_at=capture_time),
            topology=topology(observed_at=capture_time),
            now=capture_time,
        )
        self.assertIs(consumed.authorization, authorization)
        consumed.validate_integrity()
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 1)

    def test_capture_authorization_is_one_shot(self):
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        capture_time = NOW + timedelta(seconds=1)
        arguments = {
            "planned": planned,
            "privacy_authorization": privacy,
            "consent_ledger": consent_ledger,
            "authorization": authorization,
            "capture_ledger": capture_ledger,
            "permission_observation": granted_permission(
                observed_at=capture_time
            ),
            "topology": topology(observed_at=capture_time),
            "now": capture_time,
        }

        CapturePolicy().prepare_capture(**arguments)
        with self.assertRaises(CaptureError):
            CapturePolicy().prepare_capture(**arguments)
        self.assertEqual(
            capture_ledger.safe_metadata(),
            {
                "revision": 2,
                "authorization_count": 1,
                "consumed_count": 1,
            },
        )

    def test_concurrent_prepare_has_at_most_one_winner(self):
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        capture_time = NOW + timedelta(seconds=1)
        permission = granted_permission(observed_at=capture_time)
        current_topology = topology(observed_at=capture_time)
        barrier = Barrier(3)
        outcome_lock = Lock()
        outcomes: list[str] = []

        def prepare() -> None:
            barrier.wait()
            try:
                CapturePolicy().prepare_capture(
                    planned=planned,
                    privacy_authorization=privacy,
                    consent_ledger=consent_ledger,
                    authorization=authorization,
                    capture_ledger=capture_ledger,
                    permission_observation=permission,
                    topology=current_topology,
                    now=capture_time,
                )
            except CaptureError:
                outcome = "rejected"
            else:
                outcome = "consumed"
            with outcome_lock:
                outcomes.append(outcome)

        threads = (Thread(target=prepare), Thread(target=prepare))
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

        self.assertCountEqual(outcomes, ("consumed", "rejected"))
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 1)

    def test_expiry_boundary_and_wrong_ledger_do_not_consume(self):
        expiry = NOW + timedelta(seconds=2)
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization(expires_at=expiry)
        expired_arguments = {
            "planned": planned,
            "privacy_authorization": privacy,
            "consent_ledger": consent_ledger,
            "authorization": authorization,
            "capture_ledger": capture_ledger,
            "permission_observation": granted_permission(observed_at=expiry),
            "topology": topology(observed_at=expiry),
            "now": expiry,
        }
        with self.assertRaises(EndpointPolicyError):
            CapturePolicy().prepare_capture(**expired_arguments)
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)

        capture_time = NOW + timedelta(seconds=1)
        wrong_ledger = CaptureAuthorizationLedger()
        with self.assertRaises(CaptureError):
            CapturePolicy().prepare_capture(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                authorization=authorization,
                capture_ledger=wrong_ledger,
                permission_observation=granted_permission(
                    observed_at=capture_time
                ),
                topology=topology(observed_at=capture_time),
                now=capture_time,
            )
        self.assertEqual(wrong_ledger.safe_metadata()["consumed_count"], 0)

    def test_duplicate_deterministic_authorization_cannot_replace_ledger_entry(self):
        (
            current_topology,
            scope,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()

        with self.assertRaises(CaptureError):
            CapturePolicy().authorize(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                permission_observation=granted_permission(),
                topology=current_topology,
                selected_scope=scope,
                capture_id=CAPTURE_ID,
                capture_ledger=capture_ledger,
                now=NOW,
            )
        self.assertEqual(capture_ledger.safe_metadata()["authorization_count"], 1)
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)
        authorization.validate_integrity()

    def test_external_consume_without_policy_authority_is_rejected(self):
        *_, capture_ledger, authorization = self._authorization()
        capture_time = NOW + timedelta(seconds=1)
        permission = granted_permission(observed_at=capture_time)
        current_topology = topology(observed_at=capture_time)

        with self.assertRaises(TypeError):
            capture_ledger._consume(
                authorization=authorization,
                now=capture_time,
                pre_capture_permission_observation_digest=(
                    permission.observation_digest
                ),
                pre_capture_topology_snapshot_digest=(
                    current_topology.snapshot_digest
                ),
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)

    def test_rewritten_authorization_cannot_alias_another_ledger_entry(self):
        current_topology = topology()
        scope = selected_scope(current_topology)
        planned = planned_execution(current_topology)
        consent_ledger, privacy = privacy_authorization(
            planned,
            scope_fingerprint=scope.fingerprint,
        )
        capture_ledger = CaptureAuthorizationLedger()
        permission = granted_permission()
        policy = CapturePolicy()
        authorization_a = policy.authorize(
            planned=planned,
            privacy_authorization=privacy,
            consent_ledger=consent_ledger,
            permission_observation=permission,
            topology=current_topology,
            selected_scope=scope,
            capture_id=CAPTURE_ID,
            capture_ledger=capture_ledger,
            now=NOW,
        )
        authorization_b = policy.authorize(
            planned=planned,
            privacy_authorization=privacy,
            consent_ledger=consent_ledger,
            permission_observation=permission,
            topology=current_topology,
            selected_scope=scope,
            capture_id=UUID("20000000-0000-0000-0000-000000000003"),
            capture_ledger=capture_ledger,
            now=NOW,
        )
        object.__setattr__(
            authorization_a,
            "capture_id",
            authorization_b.capture_id,
        )
        object.__setattr__(
            authorization_a,
            "capture_authorization_id",
            authorization_b.capture_authorization_id,
        )
        object.__setattr__(
            authorization_a,
            "capture_authorization_digest",
            authorization_b.capture_authorization_digest,
        )
        authorization_a.validate_integrity()
        capture_time = NOW + timedelta(seconds=1)
        arguments = {
            "planned": planned,
            "privacy_authorization": privacy,
            "consent_ledger": consent_ledger,
            "capture_ledger": capture_ledger,
            "permission_observation": granted_permission(
                observed_at=capture_time
            ),
            "topology": topology(observed_at=capture_time),
            "now": capture_time,
        }

        with self.assertRaises(CaptureError):
            policy.prepare_capture(
                authorization=authorization_a,
                **arguments,
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)
        consumed = policy.prepare_capture(
            authorization=authorization_b,
            **arguments,
        )
        self.assertIs(consumed.authorization, authorization_b)
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 1)

    def test_same_capture_id_cannot_rebind_scope_or_privacy_authorization(self):
        (
            current_topology,
            scope,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization(bind_scope=False)
        changed_scope = selected_scope(
            current_topology,
            rect=CaptureRect(left=40, top=50, width=600, height=400),
        )
        self.assertNotEqual(changed_scope.fingerprint, scope.fingerprint)

        with self.assertRaises(CaptureError):
            CapturePolicy().authorize(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                permission_observation=granted_permission(),
                topology=current_topology,
                selected_scope=changed_scope,
                capture_id=CAPTURE_ID,
                capture_ledger=capture_ledger,
                now=NOW,
            )

        alternate_ledger, alternate_privacy = privacy_authorization(
            planned,
            scope_fingerprint=scope.fingerprint,
            grant_id=UUID("20000000-0000-0000-0000-000000000002"),
        )
        self.assertNotEqual(
            alternate_privacy.authorization_id,
            privacy.authorization_id,
        )
        with self.assertRaises(CaptureError):
            CapturePolicy().authorize(
                planned=planned,
                privacy_authorization=alternate_privacy,
                consent_ledger=alternate_ledger,
                permission_observation=granted_permission(),
                topology=current_topology,
                selected_scope=scope,
                capture_id=CAPTURE_ID,
                capture_ledger=capture_ledger,
                now=NOW,
            )

        self.assertEqual(capture_ledger.safe_metadata()["authorization_count"], 1)
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)
        authorization.validate_integrity()

    def test_revoked_or_consumed_consent_rejects_prepare(self):
        capture_time = NOW + timedelta(seconds=1)

        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        consent_ledger.revoke(
            grant_id=privacy.consent_grant_ids[0],
            revoked_at=capture_time,
        )
        with self.assertRaises(EndpointPolicyError):
            CapturePolicy().prepare_capture(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                authorization=authorization,
                capture_ledger=capture_ledger,
                permission_observation=granted_permission(
                    observed_at=capture_time
                ),
                topology=topology(observed_at=capture_time),
                now=capture_time,
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)

    def test_revocation_between_precheck_and_atomic_consume_is_rejected(self):
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        capture_time = NOW + timedelta(seconds=1)
        original_gate = PermissionGate.require_granted
        revoked = False

        def grant_then_revoke(*, observation, now):
            nonlocal revoked
            original_gate(observation=observation, now=now)
            if not revoked:
                consent_ledger.revoke(
                    grant_id=privacy.consent_grant_ids[0],
                    revoked_at=now,
                )
                revoked = True

        with (
            patch.object(
                PermissionGate,
                "require_granted",
                side_effect=grant_then_revoke,
            ),
            self.assertRaises(EndpointPolicyError),
        ):
            CapturePolicy().prepare_capture(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                authorization=authorization,
                capture_ledger=capture_ledger,
                permission_observation=granted_permission(
                    observed_at=capture_time
                ),
                topology=topology(observed_at=capture_time),
                now=capture_time,
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)

    def test_atomic_consume_linearizes_before_concurrent_revocation(self):
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        capture_time = NOW + timedelta(seconds=1)
        consume_entered = Event()
        allow_consume = Event()
        revoke_started = Event()
        revoke_finished = Event()
        consumed_values = []
        errors: list[BaseException] = []
        original_consume = CaptureAuthorizationLedger._consume

        def blocking_consume(ledger, **kwargs):
            consume_entered.set()
            if not allow_consume.wait(timeout=5):
                raise AssertionError("test did not release capture consumption")
            return original_consume(ledger, **kwargs)

        def prepare() -> None:
            try:
                consumed_values.append(
                    CapturePolicy().prepare_capture(
                        planned=planned,
                        privacy_authorization=privacy,
                        consent_ledger=consent_ledger,
                        authorization=authorization,
                        capture_ledger=capture_ledger,
                        permission_observation=granted_permission(
                            observed_at=capture_time
                        ),
                        topology=topology(observed_at=capture_time),
                        now=capture_time,
                    )
                )
            except BaseException as error:  # pragma: no cover - assertion path
                errors.append(error)

        def revoke() -> None:
            revoke_started.set()
            try:
                consent_ledger.revoke(
                    grant_id=privacy.consent_grant_ids[0],
                    revoked_at=capture_time,
                )
            except BaseException as error:  # pragma: no cover - assertion path
                errors.append(error)
            finally:
                revoke_finished.set()

        with patch.object(
            CaptureAuthorizationLedger,
            "_consume",
            new=blocking_consume,
        ):
            prepare_thread = Thread(target=prepare)
            prepare_thread.start()
            self.assertTrue(consume_entered.wait(timeout=5))
            revoke_thread = Thread(target=revoke)
            revoke_thread.start()
            self.assertTrue(revoke_started.wait(timeout=5))
            self.assertFalse(revoke_finished.wait(timeout=0.1))
            allow_consume.set()
            prepare_thread.join(timeout=5)
            revoke_thread.join(timeout=5)

        self.assertFalse(prepare_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(consumed_values), 1)
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 1)

        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization(one_shot=True)
        consent_ledger.consume(
            grant_id=privacy.consent_grant_ids[0],
            consumed_at=capture_time,
        )
        with self.assertRaises(EndpointPolicyError):
            CapturePolicy().prepare_capture(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                authorization=authorization,
                capture_ledger=capture_ledger,
                permission_observation=granted_permission(
                    observed_at=capture_time
                ),
                topology=topology(observed_at=capture_time),
                now=capture_time,
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)

    def test_consumed_proof_digest_binds_fresh_permission_and_topology(self):
        (
            authorization_topology,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        capture_time = NOW + timedelta(seconds=1)
        permission = granted_permission(observed_at=capture_time)
        current_topology = topology(observed_at=capture_time)

        consumed = CapturePolicy().prepare_capture(
            planned=planned,
            privacy_authorization=privacy,
            consent_ledger=consent_ledger,
            authorization=authorization,
            capture_ledger=capture_ledger,
            permission_observation=permission,
            topology=current_topology,
            now=capture_time,
        )

        self.assertEqual(
            consumed.pre_capture_permission_observation_digest,
            permission.observation_digest,
        )
        self.assertEqual(
            consumed.pre_capture_topology_snapshot_digest,
            current_topology.snapshot_digest,
        )
        self.assertEqual(
            current_topology.topology_revision,
            authorization_topology.topology_revision,
        )
        self.assertNotEqual(
            current_topology.snapshot_digest,
            authorization_topology.snapshot_digest,
        )
        self.assertEqual(
            consumed.consumption_digest,
            digest256(
                "ConsumedCaptureAuthorization",
                CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
                {
                    "capture_authorization_id": (
                        authorization.capture_authorization_id
                    ),
                    "capture_authorization_digest": (
                        authorization.capture_authorization_digest
                    ),
                    "consumed_at": capture_time,
                    "pre_capture_permission_observation_digest": (
                        permission.observation_digest
                    ),
                    "pre_capture_topology_snapshot_digest": (
                        current_topology.snapshot_digest
                    ),
                },
            ),
        )

        permission_digest = consumed.pre_capture_permission_observation_digest
        topology_digest = consumed.pre_capture_topology_snapshot_digest
        object.__setattr__(
            consumed,
            "pre_capture_permission_observation_digest",
            Digest256("3" * 64),
        )
        with self.assertRaises(ValueError):
            consumed.validate_integrity()
        object.__setattr__(
            consumed,
            "pre_capture_permission_observation_digest",
            permission_digest,
        )
        object.__setattr__(
            consumed,
            "pre_capture_topology_snapshot_digest",
            Digest256("4" * 64),
        )
        with self.assertRaises(ValueError):
            consumed.validate_integrity()
        object.__setattr__(
            consumed,
            "pre_capture_topology_snapshot_digest",
            topology_digest,
        )
        consumed.validate_integrity()

    def test_ledger_rejects_rewritten_consumption_proof_with_valid_digest(self):
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        capture_time = NOW + timedelta(seconds=1)
        consumed = CapturePolicy().prepare_capture(
            planned=planned,
            privacy_authorization=privacy,
            consent_ledger=consent_ledger,
            authorization=authorization,
            capture_ledger=capture_ledger,
            permission_observation=granted_permission(
                observed_at=capture_time
            ),
            topology=topology(observed_at=capture_time),
            now=capture_time,
        )

        rewritten_time = capture_time + timedelta(microseconds=1)
        rewritten_permission = Digest256("3" * 64)
        rewritten_topology = Digest256("4" * 64)
        object.__setattr__(consumed, "consumed_at", rewritten_time)
        object.__setattr__(
            consumed,
            "pre_capture_permission_observation_digest",
            rewritten_permission,
        )
        object.__setattr__(
            consumed,
            "pre_capture_topology_snapshot_digest",
            rewritten_topology,
        )
        object.__setattr__(
            consumed,
            "consumption_digest",
            digest256(
                "ConsumedCaptureAuthorization",
                CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
                {
                    "capture_authorization_id": (
                        authorization.capture_authorization_id
                    ),
                    "capture_authorization_digest": (
                        authorization.capture_authorization_digest
                    ),
                    "consumed_at": rewritten_time,
                    "pre_capture_permission_observation_digest": (
                        rewritten_permission
                    ),
                    "pre_capture_topology_snapshot_digest": (
                        rewritten_topology
                    ),
                },
            ),
        )
        consumed.validate_integrity()

        with self.assertRaises(CaptureError):
            capture_ledger.safe_capture_metadata(consumed=consumed)

    def test_authorization_tampering_is_rejected_before_consumption(self):
        (
            _,
            _,
            planned,
            consent_ledger,
            privacy,
            capture_ledger,
            authorization,
        ) = self._authorization()
        object.__setattr__(authorization, "plan_digest", Digest256("f" * 64))
        capture_time = NOW + timedelta(seconds=1)

        with self.assertRaises(CaptureError):
            CapturePolicy().prepare_capture(
                planned=planned,
                privacy_authorization=privacy,
                consent_ledger=consent_ledger,
                authorization=authorization,
                capture_ledger=capture_ledger,
                permission_observation=granted_permission(
                    observed_at=capture_time
                ),
                topology=topology(observed_at=capture_time),
                now=capture_time,
            )
        self.assertEqual(capture_ledger.safe_metadata()["consumed_count"], 0)


if __name__ == "__main__":
    unittest.main()
