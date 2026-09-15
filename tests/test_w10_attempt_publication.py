"""W10 caller-owned recovery for interrupted credential publication."""
from __future__ import annotations

import unittest
from unittest import mock

from snapquiz.domain.errors import CancelledError
import snapquiz.pipelines.multimodal as multimodal_module
from snapquiz.runtime.attempt import AttemptGate, CredentialResolutionPermit

from tests.w10_helpers import execute_fixture, make_w10_fixture


class _CommitThenRaiseDict(dict):
    """Commit one selected mapping write, then emulate an async interrupt."""

    def __init__(self, source) -> None:
        super().__init__(source)
        self.armed = True

    def __setitem__(self, key, value) -> None:
        super().__setitem__(key, value)
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt


class W10CredentialPublicationRecoveryTest(unittest.TestCase):
    def _execute_with_gate(self, fixture, gate: AttemptGate):
        published: list[CredentialResolutionPermit] = []
        original = multimodal_module._RunState.publish_credential_permit

        def record(owner, permit):
            published.append(permit)
            return original(owner, permit)

        with (
            mock.patch.object(
                multimodal_module,
                "AttemptGate",
                new=lambda: gate,
            ),
            mock.patch.object(
                multimodal_module._RunState,
                "publish_credential_permit",
                new=record,
            ),
        ):
            with self.assertRaises(CancelledError):
                execute_fixture(fixture)

        self.assertEqual(len(published), 1)
        permit = published[0]
        self.assertTrue(permit._released)
        self.assertTrue(
            AttemptGate._credential_permit_refs_are_released(permit)
        )
        self.assertEqual(gate._active_by_session, {})
        self.assertFalse(
            any(
                state.permit is permit
                and state.status not in ("abandoned", "finished")
                for state in gate._credential_permits.values()
            )
        )
        metadata = fixture.context_ledger.safe_metadata()
        self.assertEqual(metadata["active_gate_activity_count"], 0)
        self.assertEqual(metadata["in_flight_attempt_count"], 0)
        self.assertEqual(metadata["pending_start_count"], 0)
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)
        self.assertEqual(
            fixture.executor.pending_cleanup_metadata()["pending_cleanup_count"],
            0,
        )

    def test_publisher_commit_then_raise_releases_preheld_permit(self):
        fixture = make_w10_fixture()
        gate = AttemptGate()
        original = multimodal_module._RunState.publish_credential_permit

        def publish_then_interrupt(owner, permit):
            original(owner, permit)
            raise KeyboardInterrupt

        published: list[CredentialResolutionPermit] = []

        def capture_then_interrupt(owner, permit):
            published.append(permit)
            return publish_then_interrupt(owner, permit)

        with (
            mock.patch.object(
                multimodal_module,
                "AttemptGate",
                new=lambda: gate,
            ),
            mock.patch.object(
                multimodal_module._RunState,
                "publish_credential_permit",
                new=capture_then_interrupt,
            ),
        ):
            with self.assertRaises(CancelledError):
                execute_fixture(fixture)

        self.assertEqual(len(published), 1)
        self.assertTrue(
            AttemptGate._credential_permit_refs_are_released(published[0])
        )
        self.assertEqual(gate._credential_permits, {})
        self.assertEqual(gate._active_by_session, {})
        self.assertEqual(
            fixture.context_ledger.safe_metadata()["active_gate_activity_count"],
            0,
        )
        self.assertEqual(fixture.credential_source.calls, [])
        self.assertEqual(fixture.transport.calls, 0)

    def test_context_registration_commit_then_raise_is_normalized(self):
        fixture = make_w10_fixture()
        gate = AttemptGate()
        original = fixture.context_ledger._register_gate_activity

        def register_then_interrupt(**kwargs):
            original(**kwargs)
            raise KeyboardInterrupt

        with mock.patch.object(
            type(fixture.context_ledger),
            "_register_gate_activity",
            new=lambda owner, **kwargs: register_then_interrupt(**kwargs),
        ):
            self._execute_with_gate(fixture, gate)

    def test_credential_map_commit_then_raise_is_normalized(self):
        fixture = make_w10_fixture()
        gate = AttemptGate()
        object.__setattr__(
            gate,
            "_credential_permits",
            _CommitThenRaiseDict(gate._credential_permits),
        )

        self._execute_with_gate(fixture, gate)

    def test_session_index_commit_then_raise_is_normalized(self):
        fixture = make_w10_fixture()
        gate = AttemptGate()
        object.__setattr__(
            gate,
            "_active_by_session",
            _CommitThenRaiseDict(gate._active_by_session),
        )

        self._execute_with_gate(fixture, gate)


if __name__ == "__main__":
    unittest.main()
