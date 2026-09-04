"""Offline acceptance for the W09-B2b-S2c startup order contract."""
from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import os
from pathlib import Path
import pickle
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
import urllib.request
from uuid import UUID

from snapquiz.domain.digest import digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _resolver_startup_composition as startup


def _uuid(prefix: int, index: int) -> UUID:
    return UUID(int=(prefix << 64) | index)


def _digest(prefix: int, label: str):
    return digest256(
        "ResolverStartupCompositionTest",
        "snapquiz.test.resolver-startup-composition.v1",
        {"label": label, "prefix": prefix},
    )


def _issue_input(prefix: int = 0xA1):
    source = startup._new_unwired_startup_bootstrap_input_source()
    selected = source.issue(
        bootstrap_id=_uuid(prefix, 1),
        epoch_id=_uuid(prefix, 2),
        suspended_identity_proof_digest=_digest(prefix, "identity"),
        watch_registration_digest=_digest(prefix, "watch"),
        ready_proof_digest=_digest(prefix, "ready"),
        bootstrap_binding_digest=_digest(prefix, "binding"),
    )
    return source, selected


def _advance_input(source, current, prefix: int = 0xA2):
    return source.advance_generation(
        current=current,
        bootstrap_id=_uuid(prefix, 1),
        epoch_id=_uuid(prefix, 2),
        suspended_identity_proof_digest=_digest(prefix, "identity"),
        watch_registration_digest=_digest(prefix, "watch"),
        ready_proof_digest=_digest(prefix, "ready"),
        bootstrap_binding_digest=_digest(prefix, "binding"),
    )


@contextmanager
def _fresh_composition():
    selected = startup._new_test_only_unwired_startup_composition(
        composition_id=_uuid(0xAA, 1),
        _authority=startup._TEST_COMPOSITION_AUTHORITY,
    )
    if selected is startup._process_resolver_startup_composition():
        raise AssertionError("isolated test composition must not be process one")
    yield selected


def _assert_safe_error(test: unittest.TestCase, error: EndpointPolicyError):
    test.assertEqual(
        error.stage,
        "resolver_supervisor_startup_composition",
    )
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertTrue(error.__suppress_context__)


@contextmanager
def _interrupt_return(function):
    target = function.__code__
    previous = sys.gettrace()
    fired = [False]

    def interrupt(frame, event, arg):
        del arg
        if not fired[0] and event == "return" and frame.f_code is target:
            fired[0] = True
            sys.settrace(previous)
            raise KeyboardInterrupt("startup-composition:return-publication")
        return interrupt

    sys.settrace(interrupt)
    try:
        yield fired
    finally:
        sys.settrace(previous)


class ResolverStartupCompositionTests(unittest.TestCase):
    def test_input_source_concurrent_issue_and_generation_are_one_winner(self):
        source = startup._new_unwired_startup_bootstrap_input_source()

        def issue(index):
            try:
                return source.issue(
                    bootstrap_id=_uuid(0x90 + index, 1),
                    epoch_id=_uuid(0x90 + index, 2),
                    suspended_identity_proof_digest=_digest(index, "identity"),
                    watch_registration_digest=_digest(index, "watch"),
                    ready_proof_digest=_digest(index, "ready"),
                    bootstrap_binding_digest=_digest(index, "binding"),
                )
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            issued = tuple(pool.map(issue, range(16)))
        winners = tuple(value for value in issued if value is not None)
        self.assertEqual(len(winners), 1)
        current = winners[0]

        def advance(index):
            try:
                return _advance_input(source, current, 0x500 + index)
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            advanced = tuple(pool.map(advance, range(16)))
        next_winners = tuple(value for value in advanced if value is not None)
        self.assertEqual(len(next_winners), 1)
        self.assertEqual(next_winners[0].source_generation, 2)

    def test_process_factory_is_singleton_and_concurrent_reads_match(self):
        values = ()
        injected = object()
        had_decoy = hasattr(startup, "_PROCESS_STARTUP_COMPOSITION")
        previous_decoy = getattr(startup, "_PROCESS_STARTUP_COMPOSITION", None)
        try:
            startup._PROCESS_STARTUP_COMPOSITION = injected
            with ThreadPoolExecutor(max_workers=8) as pool:
                values = tuple(
                    pool.map(
                        lambda _: startup._process_resolver_startup_composition(),
                        range(32),
                    )
                )
            startup._PROCESS_STARTUP_COMPOSITION = None
            self.assertIs(
                startup._process_resolver_startup_composition(),
                values[0],
            )
        finally:
            if had_decoy:
                startup._PROCESS_STARTUP_COMPOSITION = previous_decoy
            else:
                del startup._PROCESS_STARTUP_COMPOSITION
        self.assertTrue(all(value is values[0] for value in values))
        self.assertFalse(startup.PRODUCTION_STARTUP_INTEGRATION_AVAILABLE)

    def test_isolated_factory_requires_closure_bound_test_authority(self):
        with self.assertRaises(TypeError):
            startup._new_test_only_unwired_startup_composition(
                composition_id=_uuid(0xAB, 1)
            )
        original = startup._TEST_COMPOSITION_AUTHORITY
        replacement = object()
        with patch.object(
            startup,
            "_TEST_COMPOSITION_AUTHORITY",
            replacement,
        ):
            with self.assertRaises(TypeError):
                startup._new_test_only_unwired_startup_composition(
                    composition_id=_uuid(0xAB, 2),
                    _authority=replacement,
                )
            selected = startup._new_test_only_unwired_startup_composition(
                composition_id=_uuid(0xAB, 3),
                _authority=original,
            )
        self.assertIsNot(
            selected,
            startup._process_resolver_startup_composition(),
        )

    def test_concurrent_bootstrap_replay_poison_blocks_all_boundaries(self):
        _, bootstrap_input = _issue_input()

        def start_once(composition):
            try:
                return composition.start(bootstrap_input=bootstrap_input)
            except EndpointPolicyError:
                return None

        with _fresh_composition() as composition:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = tuple(
                    pool.map(start_once, (composition, composition))
                )
            self.assertEqual(sum(value is not None for value in results), 1)
            self.assertEqual(composition.safe_metadata()["state"], "poisoned")
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "evidence_replayed",
            )
            proof = next(value for value in results if value is not None)
            with self.assertRaises(EndpointPolicyError):
                composition.claim_before(
                    boundary=startup._StartupBoundary.REGISTRY,
                    claim_id=_uuid(0xB0, 1),
                    startup_proof=proof,
                )

    def test_factory_only_values_are_immutable_and_nonserializable(self):
        source, bootstrap_input = _issue_input()
        with self.assertRaises(TypeError):
            startup._UnwiredStartupBootstrapInputSource()
        with self.assertRaises(TypeError):
            startup._ResolverStartupCompositionLedger(
                composition_id=_uuid(0xB1, 1)
            )
        with self.assertRaises(TypeError):
            startup._UnwiredStartupBootstrapInput(
                bootstrap_id=bootstrap_input.bootstrap_id,
                epoch_id=bootstrap_input.epoch_id,
                source_generation=1,
                suspended_identity_proof_digest=(
                    bootstrap_input.suspended_identity_proof_digest
                ),
                watch_registration_digest=(
                    bootstrap_input.watch_registration_digest
                ),
                ready_proof_digest=bootstrap_input.ready_proof_digest,
                bootstrap_binding_digest=(
                    bootstrap_input.bootstrap_binding_digest
                ),
                source=source,
            )
        self.assertIs(copy.copy(bootstrap_input), bootstrap_input)
        self.assertIs(copy.deepcopy(bootstrap_input), bootstrap_input)
        with self.assertRaises(AttributeError):
            bootstrap_input.epoch_id = _uuid(0xB1, 2)
        with self.assertRaises(TypeError):
            pickle.dumps(bootstrap_input)
        with self.assertRaises(TypeError):
            class _BadInput(startup._UnwiredStartupBootstrapInput):
                pass

    def test_bootstrap_input_binds_digest_references_without_attesting_facts(self):
        _, bootstrap_input = _issue_input()
        bootstrap_input.validate_integrity()
        metadata = bootstrap_input.safe_metadata()
        self.assertTrue(metadata["suspended_identity_input_bound"])
        self.assertTrue(metadata["watch_registration_input_bound"])
        self.assertTrue(metadata["ready_input_bound"])
        self.assertFalse(metadata["same_process_cross_proof_attested"])
        self.assertFalse(metadata["production_bundle_attested"])
        self.assertFalse(metadata["production_startup_wired"])
        self.assertFalse(metadata["transport_available"])

    def test_bootstrap_precedes_every_guarded_boundary(self):
        _, bootstrap_input = _issue_input()
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            self.assertIs(
                composition.recover_bootstrap(
                    bootstrap_input=bootstrap_input
                ),
                proof,
            )
            proof.validate_integrity()
            proof_metadata = proof.safe_metadata()
            self.assertTrue(proof_metadata["local_gate_order_attested"])
            self.assertFalse(
                proof_metadata["application_startup_order_attested"]
            )
            self.assertFalse(
                proof_metadata[
                    "production_startup_integration_available"
                ]
            )

            permits = []
            for index, boundary in enumerate(startup._StartupBoundary, 1):
                permit = composition.claim_before(
                    boundary=boundary,
                    claim_id=_uuid(0xC1, index),
                    startup_proof=proof,
                )
                permit.validate_integrity()
                self.assertFalse(composition.boundary_consumed(permit))
                composition.consume_boundary(permit)
                self.assertTrue(composition.boundary_consumed(permit))
                permits.append(permit)

            metadata = composition.safe_metadata()
            self.assertEqual(metadata["state"], "active")
            self.assertTrue(metadata["bootstrap_input_committed"])
            self.assertTrue(
                metadata["bootstrap_before_all_consumed_boundaries"]
            )
            self.assertEqual(metadata["boundary_claim_count"], 6)
            self.assertEqual(metadata["boundary_consumed_count"], 6)
            self.assertEqual(
                metadata["boundary_consumed_counts"],
                {
                    "registry": 1,
                    "target": 1,
                    "capture": 1,
                    "credential": 1,
                    "secret": 1,
                    "attempt": 1,
                },
            )
            self.assertTrue(
                all(permit.safe_metadata()["consumed"] for permit in permits)
            )

    def test_each_boundary_before_bootstrap_permanently_poisoned_as_late(self):
        for index, boundary in enumerate(startup._StartupBoundary, 1):
            with self.subTest(boundary=boundary.value):
                _, bootstrap_input = _issue_input(0xD0 + index)
                with _fresh_composition() as composition:
                    with self.assertRaises(EndpointPolicyError) as raised:
                        composition.claim_before(
                            boundary=boundary,
                            claim_id=_uuid(0xD1, index),
                            startup_proof=None,
                        )
                    _assert_safe_error(self, raised.exception)
                    metadata = composition.safe_metadata()
                    self.assertEqual(metadata["state"], "poisoned")
                    self.assertEqual(
                        metadata["poison_reason"],
                        "late_bootstrap",
                    )
                    with self.assertRaises(EndpointPolicyError):
                        composition.start(bootstrap_input=bootstrap_input)
                    self.assertEqual(
                        composition.safe_metadata()["poison_reason"],
                        "late_bootstrap",
                    )

    def test_missing_or_tampered_bootstrap_input_is_one_shot_poison(self):
        with _fresh_composition() as composition:
            with self.assertRaises(EndpointPolicyError) as raised:
                composition.start(bootstrap_input=None)
            _assert_safe_error(self, raised.exception)
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "evidence_missing",
            )
            _, valid = _issue_input(0xE1)
            with self.assertRaises(EndpointPolicyError):
                composition.start(bootstrap_input=valid)

        _, tampered = _issue_input(0xE2)
        object.__setattr__(
            tampered,
            "ready_proof_digest",
            _digest(0xE2, "changed-ready"),
        )
        with _fresh_composition() as composition:
            with self.assertRaises(EndpointPolicyError):
                composition.start(bootstrap_input=tampered)
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "evidence_invalid",
            )

    def test_start_replay_is_not_recovery_and_poisoned(self):
        _, bootstrap_input = _issue_input()
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            self.assertIs(
                composition.recover_bootstrap(
                    bootstrap_input=bootstrap_input
                ),
                proof,
            )
            with self.assertRaises(EndpointPolicyError) as raised:
                composition.start(bootstrap_input=bootstrap_input)
            _assert_safe_error(self, raised.exception)
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "evidence_replayed",
            )
            with self.assertRaises(ValueError):
                proof.validate_integrity()

    def test_generation_replacement_invalidates_active_composition(self):
        source, first = _issue_input()
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=first)
            permit = composition.claim_before(
                boundary=startup._StartupBoundary.SECRET,
                claim_id=_uuid(0xF1, 9),
                startup_proof=proof,
            )
            second = _advance_input(source, first)
            with self.assertRaises(ValueError):
                permit.validate_integrity()
            with self.assertRaises(ValueError):
                proof.validate_integrity()
            self.assertFalse(composition.boundary_consumed(permit))
            metadata = composition.safe_metadata()
            self.assertEqual(metadata["state"], "poisoned")
            self.assertFalse(metadata["local_gate_order_attested"])
            self.assertEqual(
                metadata["poison_reason"],
                "generation_changed",
            )
            with self.assertRaises(EndpointPolicyError):
                composition.consume_boundary(permit)
            with self.assertRaises(EndpointPolicyError):
                composition.claim_before(
                    boundary=startup._StartupBoundary.REGISTRY,
                    claim_id=_uuid(0xF1, 1),
                    startup_proof=proof,
                )
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "generation_changed",
            )
            with self.assertRaises(EndpointPolicyError):
                composition.start(bootstrap_input=second)

    def test_source_poison_invalidates_old_proof_permit_and_metadata(self):
        source, bootstrap_input = _issue_input(0xF9)
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            permit = composition.claim_before(
                boundary=startup._StartupBoundary.ATTEMPT,
                claim_id=_uuid(0xF9, 7),
                startup_proof=proof,
            )
            source.poison_current(current=bootstrap_input)

            metadata = composition.safe_metadata()
            self.assertEqual(metadata["state"], "poisoned")
            self.assertEqual(
                metadata["poison_reason"],
                "evidence_poisoned",
            )
            self.assertFalse(metadata["local_gate_order_attested"])
            with self.assertRaises(ValueError):
                proof.validate_integrity()
            with self.assertRaises(ValueError):
                permit.validate_integrity()
            self.assertFalse(composition.boundary_consumed(permit))
            with self.assertRaises(EndpointPolicyError):
                composition.consume_boundary(permit)

    def test_changed_generation_cannot_replace_an_active_bootstrap(self):
        source, first = _issue_input()
        with _fresh_composition() as composition:
            composition.start(bootstrap_input=first)
            second = _advance_input(source, first)
            with self.assertRaises(EndpointPolicyError):
                composition.start(bootstrap_input=second)
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "generation_changed",
            )

    def test_input_poison_and_explicit_poison_fail_closed(self):
        source, bootstrap_input = _issue_input()
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            source.poison_current(current=bootstrap_input)
            with self.assertRaises(EndpointPolicyError):
                composition.claim_before(
                    boundary=startup._StartupBoundary.TARGET,
                    claim_id=_uuid(0xF2, 1),
                    startup_proof=proof,
                )
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "evidence_poisoned",
            )

        _, second = _issue_input(0xF3)
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=second)
            permit = composition.claim_before(
                boundary=startup._StartupBoundary.CAPTURE,
                claim_id=_uuid(0xF3, 2),
                startup_proof=proof,
            )
            composition.poison(startup_proof=proof)
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "explicit_poison",
            )
            with self.assertRaises(ValueError):
                proof.validate_integrity()
            with self.assertRaises(ValueError):
                permit.validate_integrity()
            self.assertFalse(composition.boundary_consumed(permit))
            with self.assertRaises(EndpointPolicyError):
                composition.consume_boundary(permit)
            with self.assertRaises(EndpointPolicyError):
                composition.claim_before(
                    boundary=startup._StartupBoundary.CAPTURE,
                    claim_id=_uuid(0xF3, 3),
                    startup_proof=proof,
                )

    def test_missing_or_wrong_boundary_proof_poisoned(self):
        _, bootstrap_input = _issue_input()
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            permit = composition.claim_before(
                boundary=startup._StartupBoundary.REGISTRY,
                claim_id=_uuid(0xF4, 2),
                startup_proof=proof,
            )
            with self.assertRaises(EndpointPolicyError):
                composition.claim_before(
                    boundary=startup._StartupBoundary.SECRET,
                    claim_id=_uuid(0xF4, 1),
                    startup_proof=None,
                )
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "proof_missing",
            )
            with self.assertRaises(ValueError):
                proof.validate_integrity()
            with self.assertRaises(ValueError):
                permit.validate_integrity()
            self.assertFalse(composition.boundary_consumed(permit))
            with self.assertRaises(EndpointPolicyError):
                composition.consume_boundary(permit)

    def test_concurrent_distinct_boundary_issuance_is_totally_ordered(self):
        _, bootstrap_input = _issue_input(0xFA)
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)

            def claim(index):
                return composition.claim_before(
                    boundary=tuple(startup._StartupBoundary)[index % 6],
                    claim_id=_uuid(0xFA, index + 1),
                    startup_proof=proof,
                )

            with ThreadPoolExecutor(max_workers=8) as pool:
                permits = tuple(pool.map(claim, range(24)))

            self.assertEqual(
                sorted(permit.sequence for permit in permits),
                list(range(1, 25)),
            )
            with ThreadPoolExecutor(max_workers=8) as pool:
                tuple(pool.map(composition.consume_boundary, permits))
            self.assertEqual(
                composition.safe_metadata()["boundary_consumed_count"],
                24,
            )

    def test_concurrent_generation_change_and_consume_are_linearized(self):
        for index in range(20):
            source, bootstrap_input = _issue_input(0x200 + index)
            with _fresh_composition() as composition:
                proof = composition.start(bootstrap_input=bootstrap_input)
                permit = composition.claim_before(
                    boundary=startup._StartupBoundary.TARGET,
                    claim_id=_uuid(0x300 + index, 1),
                    startup_proof=proof,
                )

                def consume():
                    try:
                        composition.consume_boundary(permit)
                        return True
                    except EndpointPolicyError:
                        return False

                with ThreadPoolExecutor(max_workers=2) as pool:
                    consume_future = pool.submit(consume)
                    advance_future = pool.submit(
                        _advance_input,
                        source,
                        bootstrap_input,
                        0x400 + index,
                    )
                    consumed = consume_future.result()
                    advance_future.result()

                metadata = composition.safe_metadata()
                self.assertEqual(metadata["state"], "poisoned")
                self.assertEqual(
                    metadata["poison_reason"],
                    "generation_changed",
                )
                self.assertEqual(
                    metadata["boundary_consumed_count"],
                    1 if consumed else 0,
                )
                with self.assertRaises(ValueError):
                    permit.validate_integrity()

    def test_boundary_claim_and_consume_replay_poisoned(self):
        _, bootstrap_input = _issue_input()
        claim_id = _uuid(0xF5, 1)
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            composition.claim_before(
                boundary=startup._StartupBoundary.CREDENTIAL,
                claim_id=claim_id,
                startup_proof=proof,
            )
            with self.assertRaises(EndpointPolicyError):
                composition.claim_before(
                    boundary=startup._StartupBoundary.CREDENTIAL,
                    claim_id=claim_id,
                    startup_proof=proof,
                )
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "boundary_replayed",
            )

        _, second = _issue_input(0xF6)
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=second)
            permit = composition.claim_before(
                boundary=startup._StartupBoundary.ATTEMPT,
                claim_id=_uuid(0xF6, 1),
                startup_proof=proof,
            )
            composition.consume_boundary(permit)
            with self.assertRaises(EndpointPolicyError):
                composition.consume_boundary(permit)
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "boundary_replayed",
            )

    def test_activation_commit_then_raise_is_observer_recoverable(self):
        _, bootstrap_input = _issue_input()
        with _fresh_composition() as composition:
            with _interrupt_return(
                startup._ResolverStartupCompositionLedger._commit_activation
            ) as fired:
                with self.assertRaises(EndpointPolicyError) as raised:
                    composition.start(bootstrap_input=bootstrap_input)
            self.assertTrue(fired[0])
            _assert_safe_error(self, raised.exception)
            self.assertEqual(composition.safe_metadata()["state"], "active")
            proof = composition.recover_bootstrap(
                bootstrap_input=bootstrap_input
            )
            proof.validate_integrity()

    def test_activation_outer_return_gap_is_observer_recoverable(self):
        _, bootstrap_input = _issue_input(0xFB)
        with _fresh_composition() as composition:
            with _interrupt_return(composition.start) as fired:
                with self.assertRaises(KeyboardInterrupt):
                    composition.start(bootstrap_input=bootstrap_input)
            self.assertTrue(fired[0])
            proof = composition.recover_bootstrap(
                bootstrap_input=bootstrap_input
            )
            proof.validate_integrity()

    def test_boundary_commit_then_raise_has_separate_recovery_path(self):
        _, bootstrap_input = _issue_input()
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            claim_id = _uuid(0xF7, 1)
            with _interrupt_return(
                startup._ResolverStartupCompositionLedger._commit_boundary_permit
            ) as fired:
                with self.assertRaises(EndpointPolicyError) as raised:
                    composition.claim_before(
                        boundary=startup._StartupBoundary.REGISTRY,
                        claim_id=claim_id,
                        startup_proof=proof,
                    )
            self.assertTrue(fired[0])
            _assert_safe_error(self, raised.exception)
            self.assertEqual(composition.safe_metadata()["state"], "active")
            permit = composition.recover_boundary(
                claim_id=claim_id,
                startup_proof=proof,
            )
            composition.consume_boundary(permit)
            self.assertTrue(composition.boundary_consumed(permit))

    def test_boundary_outer_return_gap_has_separate_recovery_path(self):
        _, bootstrap_input = _issue_input(0xFC)
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            claim_id = _uuid(0xFC, 1)
            with _interrupt_return(composition.claim_before) as fired:
                with self.assertRaises(KeyboardInterrupt):
                    composition.claim_before(
                        boundary=startup._StartupBoundary.CREDENTIAL,
                        claim_id=claim_id,
                        startup_proof=proof,
                    )
            self.assertTrue(fired[0])
            permit = composition.recover_boundary(
                claim_id=claim_id,
                startup_proof=proof,
            )
            composition.consume_boundary(permit)
            self.assertTrue(composition.boundary_consumed(permit))

    def test_boundary_consume_outer_return_gap_is_observable_not_replayed(self):
        _, bootstrap_input = _issue_input(0xFD)
        with _fresh_composition() as composition:
            proof = composition.start(bootstrap_input=bootstrap_input)
            permit = composition.claim_before(
                boundary=startup._StartupBoundary.ATTEMPT,
                claim_id=_uuid(0xFD, 1),
                startup_proof=proof,
            )
            with _interrupt_return(composition.consume_boundary) as fired:
                with self.assertRaises(KeyboardInterrupt):
                    composition.consume_boundary(permit)
            self.assertTrue(fired[0])
            self.assertTrue(composition.boundary_consumed(permit))
            with self.assertRaises(EndpointPolicyError):
                composition.consume_boundary(permit)
            self.assertEqual(
                composition.safe_metadata()["poison_reason"],
                "boundary_replayed",
            )

    def test_no_secret_dns_socket_or_http_surface_or_action(self):
        source_path = Path(startup.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_imports = {
            "http",
            "httpx",
            "openai",
            "os",
            "requests",
            "socket",
            "ssl",
            "subprocess",
            "urllib",
        }
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertTrue(forbidden_imports.isdisjoint(imported_roots))

        with (
            patch("builtins.open", side_effect=AssertionError("file I/O")),
            patch.object(
                socket,
                "getaddrinfo",
                side_effect=AssertionError("DNS"),
            ),
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("socket"),
            ),
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=AssertionError("HTTP"),
            ),
            patch.object(os, "open", side_effect=AssertionError("file I/O")),
            patch.object(os, "pipe", side_effect=AssertionError("pipe I/O")),
            patch.object(
                os,
                "posix_spawn",
                side_effect=AssertionError("process"),
            ),
            patch.object(
                subprocess,
                "Popen",
                side_effect=AssertionError("process"),
            ),
        ):
            _, bootstrap_input = _issue_input(0xF8)
            with _fresh_composition() as composition:
                proof = composition.start(bootstrap_input=bootstrap_input)
                for index, boundary in enumerate(
                    startup._StartupBoundary,
                    1,
                ):
                    permit = composition.claim_before(
                        boundary=boundary,
                        claim_id=_uuid(0xF8, index),
                        startup_proof=proof,
                    )
                    composition.consume_boundary(permit)
                metadata = composition.safe_metadata()

        self.assertFalse(metadata["credential_material_accepted"])
        self.assertFalse(metadata["secret_material_accepted"])
        self.assertEqual(metadata["dns_action_count"], 0)
        self.assertEqual(metadata["socket_action_count"], 0)
        self.assertEqual(metadata["http_action_count"], 0)
        self.assertEqual(metadata["process_action_count"], 0)
        self.assertFalse(metadata["transport_available"])
        self.assertFalse(
            metadata["production_startup_integration_available"]
        )


if __name__ == "__main__":
    unittest.main()
