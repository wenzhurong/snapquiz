"""W09-B3 provider-wire linearization tests."""
from __future__ import annotations

import sys
from threading import Barrier, Lock, Thread
import unittest
from unittest.mock import patch
from uuid import UUID, uuid5

from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.runtime.attempt import AttemptGate, _TRANSPORT_ATTEMPT_AUTHORITY

from tests.test_w09_attempt import (
    _authorize,
    _dns_start_id,
    _handle_proof,
    _make_runtime,
    _prepare_helper_attempt,
    _resolve,
    _terminal_guard_proof,
    _transport_claim_id,
)


_BORROW_NAMESPACE = UUID("95da5be4-6aa7-5d3f-930d-52eb622cfb31")
_WIRE_NAMESPACE = UUID("52b053ee-7473-55cb-9a3e-acf4eb5dc6a2")


def _wire_fixture():
    runtime = _make_runtime()
    gate = AttemptGate()
    (
        credential,
        stop_authority,
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
    gate._commit_resolver_completion(
        stop_authority,
        attempt,
        claim_id=claim_id,
        guard_id=guard_id,
        guard_digest=guard_digest,
        start_id=start_id,
        result_receipt_digest=receipt_digest,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    borrow_id = uuid5(_BORROW_NAMESPACE, str(attempt.attempt_permit_id))
    gate._begin_credential_borrow(
        attempt,
        borrow_id=borrow_id,
        handle_id=attempt.credential_handle_id,
        handle_digest=attempt.credential_handle_digest,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )
    wire_commit_id = uuid5(_WIRE_NAMESPACE, str(attempt.attempt_permit_id))
    evidence_digest = digest256(
        "TestWireEvidence",
        "snapquiz.test-wire-evidence.v1",
        {
            "attempt_permit_id": attempt.attempt_permit_id,
            "peer": "8.8.8.8:443",
            "tls": "http/1.1",
        },
    )
    values = {
        "claim_id": claim_id,
        "guard_id": guard_id,
        "guard_digest": guard_digest,
        "start_id": start_id,
        "result_receipt_digest": receipt_digest,
        "borrow_id": borrow_id,
        "wire_commit_id": wire_commit_id,
        "wire_evidence_digest": evidence_digest,
    }
    return runtime, gate, credential, stop_authority, attempt, values


def _active_attempt_fixture():
    runtime = _make_runtime()
    gate = AttemptGate()
    credential = _authorize(runtime, gate)
    _resolve(gate, credential)
    handle_id, handle_digest = _handle_proof(credential)
    attempt = gate.reserve_attempt(
        credential_permit=credential,
        credential_handle_id=handle_id,
        credential_handle_digest=handle_digest,
    )
    return runtime, gate, credential, attempt


def _commit(gate: AttemptGate, attempt, values: dict[str, object]) -> None:
    gate._commit_wire_start(
        attempt,
        **values,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )


def _observed(gate: AttemptGate, attempt, values: dict[str, object]) -> bool:
    return gate._wire_start_is_committed(
        attempt,
        **values,
        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
    )


class WireCommitTest(unittest.TestCase):
    def test_async_interrupt_during_attempt_claim_partial_is_retryable(self):
        for phase in ("status_only", "owner_bound"):
            with self.subTest(phase=phase):
                _, gate, _, attempt = _active_attempt_fixture()
                claim_id = _transport_claim_id(attempt)
                primary = KeyboardInterrupt(f"synthetic claim {phase}")

                def interrupt_claim(frame, event, arg):
                    del arg
                    if (
                        event == "line"
                        and frame.f_code is AttemptGate._claim_attempt.__code__
                    ):
                        state = gate._attempt_permits[
                            attempt.attempt_permit_id
                        ]
                        owner_matches = (
                            state.transport_claim_id is None
                            if phase == "status_only"
                            else state.transport_claim_id == claim_id
                        )
                        if state.status == "claiming" and owner_matches:
                            sys.settrace(None)
                            raise primary
                    return interrupt_claim

                sys.settrace(interrupt_claim)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate._claim_attempt(
                            attempt,
                            claim_id=claim_id,
                            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._attempt_permits[attempt.attempt_permit_id]
                self.assertEqual(state.status, "active")
                self.assertIsNone(state.transport_claim_id)
                gate._claim_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
                self.assertTrue(
                    gate.finish_attempt(
                        attempt,
                        claim_id=claim_id,
                        _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                    )
                )

    def test_async_interrupt_during_recovered_abandon_is_retryable(self):
        _, gate, credential, attempt = _active_attempt_fixture()
        claim_id = _transport_claim_id(attempt)
        primary = KeyboardInterrupt("synthetic recovered abandon")

        def interrupt_abandon(frame, event, arg):
            del arg
            state = gate._attempt_permits[attempt.attempt_permit_id]
            if (
                event == "line"
                and frame.f_code
                is AttemptGate._abandon_recovered_attempt_for_cleanup.__code__
                and state.status == "abandoning"
            ):
                sys.settrace(None)
                raise primary
            return interrupt_abandon

        arguments = {
            "credential_permit": credential,
            "credential_handle_id": attempt.credential_handle_id,
            "credential_handle_digest": attempt.credential_handle_digest,
            "claim_id": claim_id,
            "guard_id": None,
            "guard_digest": None,
            "_authority": _TRANSPORT_ATTEMPT_AUTHORITY,
        }
        sys.settrace(interrupt_abandon)
        try:
            self.assertFalse(
                gate._recover_attempt_for_cleanup(attempt, **arguments)
            )
        finally:
            sys.settrace(None)
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "active")
        self.assertTrue(
            gate._recover_attempt_for_cleanup(attempt, **arguments)
        )

    def test_async_interrupt_during_terminal_guard_partial_is_retryable(self):
        phases = (
            "status_only",
            "owner_bound",
            "proof_bound",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                _, gate, _, attempt = _active_attempt_fixture()
                claim_id = _transport_claim_id(attempt)
                guard_id, guard_digest = _terminal_guard_proof(attempt)
                gate._claim_attempt(
                    attempt,
                    claim_id=claim_id,
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
                primary = KeyboardInterrupt(f"synthetic guard {phase}")

                def interrupt_guard(frame, event, arg):
                    del arg
                    if (
                        event == "line"
                        and frame.f_code
                        is AttemptGate._bind_terminal_guard.__code__
                    ):
                        state = gate._attempt_permits[
                            attempt.attempt_permit_id
                        ]
                        phase_matches = (
                            phase == "status_only"
                            and state.terminal_guard_id is None
                            and state.terminal_guard_digest is None
                            or phase == "owner_bound"
                            and state.terminal_guard_id == guard_id
                            and state.terminal_guard_digest is None
                            or phase == "proof_bound"
                            and state.terminal_guard_id == guard_id
                            and state.terminal_guard_digest == guard_digest
                        )
                        if state.status == "guard_binding" and phase_matches:
                            sys.settrace(None)
                            raise primary
                    return interrupt_guard

                sys.settrace(interrupt_guard)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate._bind_terminal_guard(
                            attempt,
                            claim_id=claim_id,
                            guard_id=guard_id,
                            guard_digest=guard_digest,
                            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._attempt_permits[attempt.attempt_permit_id]
                self.assertEqual(state.status, "io_claimed")
                self.assertIsNone(state.terminal_guard_id)
                self.assertIsNone(state.terminal_guard_digest)
                gate._bind_terminal_guard(
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
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

    def test_async_interrupt_during_dns_start_partial_is_retryable(self):
        for phase in ("status_only", "owner_bound"):
            with self.subTest(phase=phase):
                _, gate, _, attempt = _active_attempt_fixture()
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
                primary = KeyboardInterrupt(f"synthetic DNS {phase}")

                def interrupt_dns(frame, event, arg):
                    del arg
                    if (
                        event == "line"
                        and frame.f_code
                        is AttemptGate._commit_dns_start.__code__
                    ):
                        state = gate._attempt_permits[
                            attempt.attempt_permit_id
                        ]
                        owner_matches = (
                            state.dns_start_id is None
                            if phase == "status_only"
                            else state.dns_start_id == start_id
                        )
                        if state.status == "dns_starting" and owner_matches:
                            sys.settrace(None)
                            raise primary
                    return interrupt_dns

                sys.settrace(interrupt_dns)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate._commit_dns_start(
                            attempt,
                            claim_id=claim_id,
                            guard_id=guard_id,
                            guard_digest=guard_digest,
                            start_id=start_id,
                            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._attempt_permits[attempt.attempt_permit_id]
                self.assertEqual(state.status, "io_claimed")
                self.assertIsNone(state.dns_start_id)
                gate._commit_dns_start(
                    attempt,
                    claim_id=claim_id,
                    guard_id=guard_id,
                    guard_digest=guard_digest,
                    start_id=start_id,
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

    def test_async_interrupt_during_resolver_completion_partial_is_retryable(self):
        phases = (
            "status_only",
            "attempt_partial",
            "stop_partial",
            "all_proof",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                runtime = _make_runtime()
                gate = AttemptGate()
                (
                    _,
                    stop_authority,
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
                primary = KeyboardInterrupt(
                    f"synthetic resolver completion {phase}"
                )

                def interrupt_completion(frame, event, arg):
                    del arg
                    if (
                        event == "line"
                        and (
                            frame.f_code
                            is AttemptGate._commit_resolver_completion.__code__
                            or frame.f_code.co_name == "commit"
                        )
                    ):
                        state = gate._attempt_permits[
                            attempt.attempt_permit_id
                        ]
                        stop_state = gate._helper_stop_authorities[
                            stop_authority.authority_id
                        ]
                        phase_matches = (
                            phase == "status_only"
                            and state.resolver_completion_authority_id is None
                            or phase == "attempt_partial"
                            and state.resolver_completion_authority_id
                            == stop_authority.authority_id
                            and state.resolver_completion_claim_id is None
                            or phase == "stop_partial"
                            and stop_state.completion_attempt_id
                            == attempt.attempt_permit_id
                            and stop_state.completion_receipt_digest is None
                            or phase == "all_proof"
                            and stop_state.completion_receipt_digest
                            == receipt_digest
                        )
                        if (
                            state.resolver_completion_status == "committing"
                            and phase_matches
                        ):
                            sys.settrace(None)
                            raise primary
                    return interrupt_completion

                arguments = {
                    "claim_id": claim_id,
                    "guard_id": guard_id,
                    "guard_digest": guard_digest,
                    "start_id": start_id,
                    "result_receipt_digest": receipt_digest,
                    "_authority": _TRANSPORT_ATTEMPT_AUTHORITY,
                }
                sys.settrace(interrupt_completion)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        gate._commit_resolver_completion(
                            stop_authority,
                            attempt,
                            **arguments,
                        )
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._attempt_permits[attempt.attempt_permit_id]
                stop_state = gate._helper_stop_authorities[
                    stop_authority.authority_id
                ]
                self.assertEqual(
                    state.resolver_completion_status,
                    "uncommitted",
                )
                self.assertIsNone(state.resolver_completion_authority_id)
                self.assertIsNone(state.resolver_completion_claim_id)
                self.assertIsNone(state.resolver_completion_guard_id)
                self.assertIsNone(state.resolver_completion_guard_digest)
                self.assertIsNone(state.resolver_completion_start_id)
                self.assertIsNone(state.resolver_completion_receipt_digest)
                self.assertIsNone(stop_state.completion_attempt_id)
                self.assertIsNone(stop_state.completion_receipt_digest)
                gate._commit_resolver_completion(
                    stop_authority,
                    attempt,
                    **arguments,
                )
                self.assertTrue(
                    gate._resolver_completion_is_committed(
                        stop_authority,
                        attempt,
                        **arguments,
                    )
                )

    def test_transport_checkpoints_bind_prewire_and_postwire_state(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        shared = {
            "claim_id": values["claim_id"],
            "guard_id": values["guard_id"],
            "guard_digest": values["guard_digest"],
            "start_id": values["start_id"],
            "result_receipt_digest": values["result_receipt_digest"],
        }
        prewire = gate._checkpoint_transport_io(
            attempt,
            **shared,
            phase="tls-handshake",
            borrow_id=values["borrow_id"],
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertEqual(prewire.phase, "transport:tls-handshake")
        self.assertGreater(prewire.max_wait_ns, 0)

        _commit(gate, attempt, values)
        postwire = gate._checkpoint_transport_io(
            attempt,
            **shared,
            phase="request-write",
            borrow_id=values["borrow_id"],
            wire_commit_id=values["wire_commit_id"],
            wire_evidence_digest=values["wire_evidence_digest"],
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertGreater(postwire.sequence, prewire.sequence)
        gate._finish_credential_borrow(
            attempt,
            borrow_id=values["borrow_id"],
            handle_id=attempt.credential_handle_id,
            handle_digest=attempt.credential_handle_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        response_read = gate._checkpoint_transport_io(
            attempt,
            **shared,
            phase="response-read",
            borrow_id=values["borrow_id"],
            wire_commit_id=values["wire_commit_id"],
            wire_evidence_digest=values["wire_evidence_digest"],
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertGreater(response_read.sequence, postwire.sequence)

    def test_transport_checkpoint_rejects_cross_phase_proof(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        shared = {
            "claim_id": values["claim_id"],
            "guard_id": values["guard_id"],
            "guard_digest": values["guard_digest"],
            "start_id": values["start_id"],
            "result_receipt_digest": values["result_receipt_digest"],
            "phase": "numeric-connect",
            "borrow_id": values["borrow_id"],
            "_authority": _TRANSPORT_ATTEMPT_AUTHORITY,
        }
        wrong = dict(shared)
        wrong["result_receipt_digest"] = Digest256("2" * 64)
        with self.assertRaises(EndpointPolicyError):
            gate._checkpoint_transport_io(attempt, **wrong)
        wrong = dict(shared)
        wrong["borrow_id"] = UUID(int=999)
        with self.assertRaises(EndpointPolicyError):
            gate._checkpoint_transport_io(attempt, **wrong)
        wrong = dict(shared)
        wrong["wire_commit_id"] = values["wire_commit_id"]
        with self.assertRaises(EndpointPolicyError):
            gate._checkpoint_transport_io(attempt, **wrong)

    def test_exact_commit_is_one_way_and_survives_borrow_release(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        _commit(gate, attempt, values)
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "wire_committed")
        self.assertEqual(state.wire_commit_id, values["wire_commit_id"])
        self.assertEqual(
            state.wire_evidence_digest,
            values["wire_evidence_digest"],
        )
        self.assertTrue(_observed(gate, attempt, values))
        wrong = dict(values)
        wrong["wire_evidence_digest"] = Digest256("0" * 64)
        self.assertFalse(_observed(gate, attempt, wrong))
        with self.assertRaises(EndpointPolicyError):
            _commit(gate, attempt, values)

        gate._finish_credential_borrow(
            attempt,
            borrow_id=values["borrow_id"],
            handle_id=attempt.credential_handle_id,
            handle_digest=attempt.credential_handle_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        self.assertTrue(_observed(gate, attempt, values))
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=values["claim_id"],
                guard_id=values["guard_id"],
                guard_digest=values["guard_digest"],
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )
        self.assertEqual(state.status, "finished")
        self.assertIsNone(state.wire_commit_id)
        self.assertIsNone(state.wire_evidence_digest)
        self.assertIsNone(state.wire_borrow_id)

    def test_commit_requires_exact_active_borrow_and_resolver_receipt(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        gate._finish_credential_borrow(
            attempt,
            borrow_id=values["borrow_id"],
            handle_id=attempt.credential_handle_id,
            handle_digest=attempt.credential_handle_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        with self.assertRaises(EndpointPolicyError):
            _commit(gate, attempt, values)

        second = _wire_fixture()
        gate = second[1]
        attempt = second[4]
        values = second[5]
        wrong = dict(values)
        wrong["result_receipt_digest"] = Digest256("1" * 64)
        with self.assertRaises(EndpointPolicyError):
            _commit(gate, attempt, wrong)
        wrong = dict(values)
        wrong["borrow_id"] = UUID(int=123)
        with self.assertRaises(EndpointPolicyError):
            _commit(gate, attempt, wrong)

    def test_precommit_noop_rolls_back_without_burning_wire_owner(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        with patch.object(AttemptGate, "_run_authority_path", return_value=None):
            with self.assertRaises(EndpointPolicyError):
                _commit(gate, attempt, values)
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "io_claimed")
        self.assertIsNone(state.wire_commit_id)
        self.assertIsNone(state.wire_evidence_digest)
        self.assertIsNone(state.wire_borrow_id)
        self.assertEqual(state.credential_borrow_id, values["borrow_id"])
        self.assertFalse(_observed(gate, attempt, values))
        _commit(gate, attempt, values)
        self.assertTrue(_observed(gate, attempt, values))

    def test_async_interrupt_during_partial_transition_is_retryable(self):
        predicates = (
            lambda state, values: state.wire_commit_id is None,
            lambda state, values: (
                state.wire_commit_id == values["wire_commit_id"]
                and state.wire_evidence_digest is None
            ),
            lambda state, values: (
                state.wire_evidence_digest == values["wire_evidence_digest"]
                and state.wire_borrow_id is None
            ),
        )
        for predicate in predicates:
            with self.subTest(predicate=predicates.index(predicate)):
                _, gate, _, _, attempt, values = _wire_fixture()
                primary = KeyboardInterrupt("synthetic partial transition")

                def interrupt_partial(frame, event, arg):
                    del arg
                    if (
                        event == "line"
                        and frame.f_code
                        is AttemptGate._commit_wire_start.__code__
                    ):
                        state = gate._attempt_permits[
                            attempt.attempt_permit_id
                        ]
                        if (
                            state.status == "wire_committing"
                            and predicate(state, values)
                        ):
                            sys.settrace(None)
                            raise primary
                    return interrupt_partial

                sys.settrace(interrupt_partial)
                try:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        _commit(gate, attempt, values)
                finally:
                    sys.settrace(None)
                self.assertIs(raised.exception, primary)
                state = gate._attempt_permits[attempt.attempt_permit_id]
                self.assertEqual(state.status, "io_claimed")
                self.assertIsNone(state.wire_commit_id)
                self.assertIsNone(state.wire_evidence_digest)
                self.assertIsNone(state.wire_borrow_id)
                self.assertEqual(
                    state.credential_borrow_id,
                    values["borrow_id"],
                )
                _commit(gate, attempt, values)
                self.assertTrue(_observed(gate, attempt, values))

    def test_commit_then_raise_is_observable_and_must_not_replay(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        original = AttemptGate._run_authority_path

        def raise_after_commit(selected, **kwargs):
            original(selected, **kwargs)
            raise RuntimeError("injected postcommit failure")

        with patch.object(
            AttemptGate,
            "_run_authority_path",
            new=raise_after_commit,
        ):
            with self.assertRaisesRegex(RuntimeError, "postcommit"):
                _commit(gate, attempt, values)
        self.assertTrue(_observed(gate, attempt, values))
        with self.assertRaises(EndpointPolicyError):
            _commit(gate, attempt, values)

    def test_async_interrupt_after_finish_transition_restores_wire_owner(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        _commit(gate, attempt, values)
        gate._finish_credential_borrow(
            attempt,
            borrow_id=values["borrow_id"],
            handle_id=attempt.credential_handle_id,
            handle_digest=attempt.credential_handle_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        primary = KeyboardInterrupt("synthetic attempt finish transition")

        def interrupt_finish(frame, event, arg):
            del arg
            if (
                event == "line"
                and frame.f_code is AttemptGate.finish_attempt.__code__
                and gate._attempt_permits[
                    attempt.attempt_permit_id
                ].status
                == "finishing"
            ):
                sys.settrace(None)
                raise primary
            return interrupt_finish

        sys.settrace(interrupt_finish)
        try:
            with self.assertRaises(KeyboardInterrupt) as raised:
                gate.finish_attempt(
                    attempt,
                    claim_id=values["claim_id"],
                    guard_id=values["guard_id"],
                    guard_digest=values["guard_digest"],
                    _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
                )
        finally:
            sys.settrace(None)
        self.assertIs(raised.exception, primary)
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "wire_committed")
        self.assertTrue(_observed(gate, attempt, values))
        self.assertTrue(
            gate.finish_attempt(
                attempt,
                claim_id=values["claim_id"],
                guard_id=values["guard_id"],
                guard_digest=values["guard_digest"],
                _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
            )
        )

    def test_async_interrupt_in_recovery_restores_wire_owner_for_retry(self):
        _, gate, credential, _, attempt, values = _wire_fixture()
        _commit(gate, attempt, values)
        gate._finish_credential_borrow(
            attempt,
            borrow_id=values["borrow_id"],
            handle_id=attempt.credential_handle_id,
            handle_digest=attempt.credential_handle_digest,
            _authority=_TRANSPORT_ATTEMPT_AUTHORITY,
        )
        primary = KeyboardInterrupt("synthetic recovered finish transition")

        def interrupt_recovery(frame, event, arg):
            del arg
            if (
                event == "line"
                and frame.f_code
                is AttemptGate._recover_attempt_for_cleanup.__code__
                and gate._attempt_permits[
                    attempt.attempt_permit_id
                ].status
                == "finishing"
            ):
                sys.settrace(None)
                raise primary
            return interrupt_recovery

        arguments = {
            "credential_permit": credential,
            "credential_handle_id": attempt.credential_handle_id,
            "credential_handle_digest": attempt.credential_handle_digest,
            "claim_id": values["claim_id"],
            "guard_id": values["guard_id"],
            "guard_digest": values["guard_digest"],
            "_authority": _TRANSPORT_ATTEMPT_AUTHORITY,
        }
        sys.settrace(interrupt_recovery)
        try:
            self.assertFalse(
                gate._recover_attempt_for_cleanup(attempt, **arguments)
            )
        finally:
            sys.settrace(None)
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "wire_committed")
        self.assertTrue(_observed(gate, attempt, values))
        self.assertTrue(
            gate._recover_attempt_for_cleanup(attempt, **arguments)
        )

    def test_concurrent_commit_has_one_exact_winner(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        barrier = Barrier(3)
        lock = Lock()
        outcomes: list[tuple[str, UUID]] = []

        def worker(index: int) -> None:
            selected = dict(values)
            selected["wire_commit_id"] = uuid5(
                _WIRE_NAMESPACE,
                f"{attempt.attempt_permit_id}:{index}",
            )
            barrier.wait()
            try:
                _commit(gate, attempt, selected)
            except EndpointPolicyError:
                outcome = "rejected"
            else:
                outcome = "committed"
            with lock:
                outcomes.append((outcome, selected["wire_commit_id"]))

        threads = [Thread(target=worker, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(
            sorted(outcome for outcome, _ in outcomes),
            ["committed", "rejected"],
        )
        winner = next(value for outcome, value in outcomes if outcome == "committed")
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.wire_commit_id, winner)

    def test_type_and_authority_checks_fail_before_state_change(self):
        _, gate, _, _, attempt, values = _wire_fixture()
        with self.assertRaises(TypeError):
            gate._commit_wire_start(attempt, **values)
        malformed = dict(values)
        malformed["wire_commit_id"] = True
        with self.assertRaises(EndpointPolicyError):
            _commit(gate, attempt, malformed)
        state = gate._attempt_permits[attempt.attempt_permit_id]
        self.assertEqual(state.status, "io_claimed")
        self.assertIsNone(state.wire_commit_id)


if __name__ == "__main__":
    unittest.main()
