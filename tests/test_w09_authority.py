"""Offline contract tests for the W09 Registry-policy authority."""
from __future__ import annotations

from datetime import timedelta
from threading import Event, Thread
import unittest
from uuid import UUID

from snapquiz.config.profiles import build_builtin_registry
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.runtime.authority import (
    RegistryPolicyAuthorityLedger,
    RegistryPolicyLease,
    _ATTEMPT_AUTHORITY,
    _CONTEXT_AUTHORITY,
)

from tests.w06_helpers import NOW
from tests.w07_helpers import (
    make_w07_authorities,
    registry_with_fixed_parameters,
)


SECOND_REQUEST_ID = UUID("90000000-0000-0000-0000-000000000002")


def _planned_for(registry, *, request_id=None):
    kwargs = {"registry": registry}
    if request_id is not None:
        kwargs["request_id"] = request_id
    return make_w07_authorities(**kwargs).planned


def _issue(ledger, planned, *, issued_at=NOW):
    return ledger._issue_with(
        planned=planned,
        issued_at=issued_at,
        action=lambda lease: lease,
        _authority=_CONTEXT_AUTHORITY,
    )


def _use(ledger, lease, planned, action=lambda: "used"):
    return ledger._run_active_action(
        lease=lease,
        planned=planned,
        action=action,
        _authority=_ATTEMPT_AUTHORITY,
    )


class RegistryPolicyAuthorityTest(unittest.TestCase):
    def test_lease_is_factory_only_final_immutable_and_exactly_bound(self):
        registry = build_builtin_registry()
        planned = _planned_for(registry)
        ledger = RegistryPolicyAuthorityLedger(registry)

        with self.assertRaises(TypeError):
            RegistryPolicyLease(
                planned=planned,
                registry=registry,
                authority_epoch=1,
                issued_at=NOW,
                authority_ledger=ledger,
            )

        with self.assertRaises(TypeError):
            class ForgedLease(RegistryPolicyLease):
                pass

        lease = _issue(ledger, planned)
        lease.validate_integrity()
        self.assertIs(ledger.snapshot(lease.lease_id), lease)
        self.assertIs(lease._registry_snapshot, registry)
        self.assertIs(lease._planned_execution, planned)
        self.assertIs(lease._authority_ledger, ledger)
        self.assertEqual(lease.authority_epoch, 1)
        self.assertEqual(lease.registry_digest, registry.registry_digest)
        self.assertEqual(
            lease.pipeline_profile_digest,
            planned.plan.pipeline_profile_digest,
        )
        self.assertEqual(_use(ledger, lease, planned), "used")
        with self.assertRaises(AttributeError):
            lease.authority_epoch = 2

    def test_content_equal_registry_cannot_impersonate_exact_generation(self):
        planning_registry = build_builtin_registry()
        content_equal_registry = build_builtin_registry()
        self.assertIsNot(planning_registry, content_equal_registry)
        self.assertEqual(
            planning_registry.registry_digest,
            content_equal_registry.registry_digest,
        )
        planned = _planned_for(planning_registry)
        ledger = RegistryPolicyAuthorityLedger(content_equal_registry)

        with self.assertRaises(EndpointPolicyError) as raised:
            _issue(ledger, planned)

        self.assertEqual(raised.exception.stage, "call_context_factory")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(
            str(raised.exception),
            "执行计划不属于当前注册表或策略世代。",
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(ledger.safe_metadata()["lease_count"], 0)

    def test_transport_binding_changes_with_registry_backed_adapter_policy(self):
        first_registry = build_builtin_registry()
        second_registry = registry_with_fixed_parameters(
            (("temperature", "0"),)
        )
        first_planned = _planned_for(first_registry)
        second_planned = _planned_for(
            second_registry,
            request_id=SECOND_REQUEST_ID,
        )
        ledger = RegistryPolicyAuthorityLedger(first_registry)
        first_lease = _issue(ledger, first_planned)

        ledger.reload(second_registry)
        second_lease = _issue(
            ledger,
            second_planned,
            issued_at=NOW + timedelta(seconds=1),
        )

        self.assertNotEqual(
            first_lease.transport_binding_digest,
            second_lease.transport_binding_digest,
        )
        self.assertNotEqual(
            first_lease.registry_digest,
            second_lease.registry_digest,
        )
        self.assertIs(second_lease._registry_snapshot, second_registry)
        self.assertEqual(_use(ledger, second_lease, second_planned), "used")
        with self.assertRaises(EndpointPolicyError):
            _use(ledger, first_lease, first_planned)

    def test_revoke_and_reload_advance_epoch_and_invalidate_old_lease(self):
        first_registry = build_builtin_registry()
        first_planned = _planned_for(first_registry)
        ledger = RegistryPolicyAuthorityLedger(first_registry)
        first_lease = _issue(ledger, first_planned)

        ledger.revoke()
        metadata = ledger.safe_metadata()
        self.assertTrue(metadata["revoked"])
        self.assertEqual(metadata["authority_epoch"], 2)
        with self.assertRaises(EndpointPolicyError):
            ledger.snapshot(first_lease.lease_id)
        with self.assertRaises(EndpointPolicyError):
            _use(ledger, first_lease, first_planned)
        with self.assertRaises(EndpointPolicyError):
            ledger._issue_with(
                planned=first_planned,
                issued_at=NOW + timedelta(seconds=1),
                action=lambda lease: lease,
                _authority=_CONTEXT_AUTHORITY,
            )

        second_registry = registry_with_fixed_parameters(
            (("temperature", "0"),)
        )
        second_planned = _planned_for(
            second_registry,
            request_id=SECOND_REQUEST_ID,
        )
        ledger.reload(second_registry)
        second_lease = _issue(
            ledger,
            second_planned,
            issued_at=NOW + timedelta(seconds=2),
        )
        self.assertEqual(second_lease.authority_epoch, 3)
        self.assertFalse(ledger.safe_metadata()["revoked"])
        self.assertEqual(_use(ledger, second_lease, second_planned), "used")

    def test_current_object_and_digest_are_ledger_owned_and_errors_fixed(self):
        registry = build_builtin_registry()
        planned = _planned_for(registry)
        ledger = RegistryPolicyAuthorityLedger(registry)
        lease = _issue(ledger, planned)

        object.__setattr__(
            lease,
            "registry_revision",
            "sensitive-caller-value",
        )
        with self.assertRaises(EndpointPolicyError) as raised:
            _use(ledger, lease, planned)

        self.assertEqual(
            str(raised.exception),
            "注册表或传输策略授权已经变化。",
        )
        self.assertNotIn("sensitive-caller-value", str(raised.exception))
        self.assertEqual(raised.exception.stage, "attempt_gate")
        self.assertFalse(raised.exception.retryable)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_issue_callback_failure_does_not_publish_lease_or_request_id(self):
        registry = build_builtin_registry()
        planned = _planned_for(registry)
        ledger = RegistryPolicyAuthorityLedger(registry)

        def fail(_lease):
            raise RuntimeError("trusted callback failed")

        with self.assertRaisesRegex(RuntimeError, "trusted callback failed"):
            ledger._issue_with(
                planned=planned,
                issued_at=NOW,
                action=fail,
                _authority=_CONTEXT_AUTHORITY,
            )
        self.assertEqual(ledger.safe_metadata()["lease_count"], 0)

        lease = _issue(ledger, planned)
        self.assertIs(ledger.snapshot(lease.lease_id), lease)

    def test_private_callbacks_require_their_exact_tcb_tokens(self):
        registry = build_builtin_registry()
        planned = _planned_for(registry)
        ledger = RegistryPolicyAuthorityLedger(registry)

        with self.assertRaises(TypeError):
            ledger._issue_with(
                planned=planned,
                issued_at=NOW,
                action=lambda lease: lease,
                _authority=object(),
            )
        lease = _issue(ledger, planned)
        with self.assertRaises(TypeError):
            ledger._run_active_action(
                lease=lease,
                planned=planned,
                action=lambda: None,
                _authority=object(),
            )

    def test_active_callback_holds_lock_against_concurrent_revoke(self):
        registry = build_builtin_registry()
        planned = _planned_for(registry)
        ledger = RegistryPolicyAuthorityLedger(registry)
        lease = _issue(ledger, planned)
        entered = Event()
        release = Event()
        attempt_finished = Event()
        revoke_finished = Event()
        results = []

        def action():
            entered.set()
            results.append("used" if release.wait(timeout=2) else "timeout")

        def run_attempt():
            _use(ledger, lease, planned, action)
            attempt_finished.set()

        def run_revoke():
            ledger.revoke()
            revoke_finished.set()

        attempt_thread = Thread(target=run_attempt)
        revoke_thread = Thread(target=run_revoke)
        attempt_thread.start()
        self.assertTrue(entered.wait(timeout=2))
        revoke_thread.start()
        self.assertFalse(revoke_finished.wait(timeout=0.05))
        release.set()
        attempt_thread.join(timeout=2)
        revoke_thread.join(timeout=2)

        self.assertTrue(attempt_finished.is_set())
        self.assertTrue(revoke_finished.is_set())
        self.assertEqual(results, ["used"])
        with self.assertRaises(EndpointPolicyError):
            _use(ledger, lease, planned)

    def test_safe_views_never_expose_credential_locator_or_endpoint(self):
        registry = build_builtin_registry()
        planned = _planned_for(registry)
        ledger = RegistryPolicyAuthorityLedger(registry)
        lease = _issue(ledger, planned)
        credential = registry.provider_profiles[0].credential_binding
        rendered = (
            repr(lease)
            + repr(lease.safe_metadata())
            + repr(ledger.safe_metadata())
        )

        self.assertNotIn(credential.credential_ref, rendered)
        self.assertNotIn(
            planned.plan.stages[0].network_operations[0].canonical_endpoint,
            rendered,
        )


if __name__ == "__main__":
    unittest.main()
