"""W09-B2b-S3-0 canonical resolver-supervisor wire contract tests."""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import pickle
import subprocess
import sys
from types import MappingProxyType
import unittest
from uuid import UUID

from snapquiz.domain.digest import Digest256, canonical_json_bytes, digest256
from snapquiz.transport import _resolver_supervisor_wire as wire


EPOCH_ID = UUID("8a000000-0000-0000-0000-000000000001")
OPERATION_ID = UUID("8a000000-0000-0000-0000-000000000002")
CONTROL_CHANNEL_ID = UUID("8a000000-0000-0000-0000-000000000003")
LIFECYCLE_ID = UUID("8a000000-0000-0000-0000-000000000004")
PUBLICATION_ID = UUID("8a000000-0000-0000-0000-000000000005")
PROXY_ID = UUID("8a000000-0000-0000-0000-000000000006")
QUERY_ID = UUID("8a000000-0000-0000-0000-000000000007")
COMMAND_ID = UUID("8a000000-0000-0000-0000-000000000008")
TOMBSTONE_ID = UUID("8a000000-0000-0000-0000-000000000009")
OTHER_ID = UUID("8a000000-0000-0000-0000-00000000000a")
ACTION_ID = UUID("8a000000-0000-0000-0000-00000000000b")
ATTACH_COMMAND_ID = UUID("8a000000-0000-0000-0000-00000000000c")
ARM_COMMAND_ID = UUID("8a000000-0000-0000-0000-00000000000d")
SPAWN_EVENT_ID = UUID("8a000000-0000-0000-0000-00000000000e")
READY_EVENT_ID = UUID("8a000000-0000-0000-0000-00000000000f")
START_COMMAND_ID = UUID("8a000000-0000-0000-0000-000000000010")
RESULT_EVENT_ID = UUID("8a000000-0000-0000-0000-000000000011")
TERMINAL_ID = UUID("8a000000-0000-0000-0000-000000000012")
SPAWN_REQUEST_DIGEST = Digest256("b" * 64)
PUBLICATION_PROOF_DIGEST = Digest256("c" * 64)
RESERVATION_ATTESTATION_DIGEST = Digest256("d" * 64)
CANCEL_PAYLOAD_DIGEST = Digest256("e" * 64)
TERMINAL_ATTESTATION_DIGEST = Digest256("f" * 64)
ATTESTATION_DIGEST = Digest256("1" * 64)
RESULT_DIGEST = Digest256("2" * 64)
START_PAYLOAD_DIGEST = Digest256("3" * 64)
ACKED_FRAME_DIGEST = Digest256("4" * 64)
OPERATION_BINDING_DIGEST = digest256(
    "ResolverSupervisorOperationBinding",
    "snapquiz.resolver-supervisor-operation-binding.v1",
    {
        "epoch_id": EPOCH_ID,
        "lifecycle_id": LIFECYCLE_ID,
        "operation_id": OPERATION_ID,
        "publication_id": PUBLICATION_ID,
        "spawn_request_digest": SPAWN_REQUEST_DIGEST,
    },
)

FRAME_IDS = {
    kind: UUID(int=0x8A000000000000000000000000000100 + index)
    for index, kind in enumerate(wire._SupervisorWireKind)
}


def _state_attestation_digest(payload: dict[str, object]) -> Digest256:
    facts = dict(payload)
    facts.pop("attestation_digest")
    facts.pop("proxy_id")
    facts.pop("query_id")
    facts["binding_digest"] = OPERATION_BINDING_DIGEST
    return digest256(
        "ResolverSupervisorOperationAttestation",
        "snapquiz.resolver-supervisor-attestation.v1",
        facts,
    )


def _redigest_state_payload(payload: dict[str, object]) -> dict[str, object]:
    selected = dict(payload)
    selected["attestation_digest"] = _state_attestation_digest(selected)
    return selected


def _state_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "arm_command_id": None,
        "attachment_command_id": None,
        "attachment_proof_digest": None,
        "attestation_digest": ATTESTATION_DIGEST,
        "cancel_command_id": None,
        "cancel_latched": False,
        "cancel_payload_digest": None,
        "child_ever_owned": False,
        "cleanup_phase": wire._SupervisorWireCleanupPhase.NONE,
        "close_action_id": None,
        "poison_reason": None,
        "proxy_id": PROXY_ID,
        "query_id": QUERY_ID,
        "ready_event_id": None,
        "reap_action_id": None,
        "release_tombstone_id": None,
        "result_digest": None,
        "result_event_id": None,
        "success_cleanup_event_id": None,
        "durable_eof_ack_digest": None,
        "revision": 0,
        "spawn_created": None,
        "spawn_event_id": None,
        "start_command_id": None,
        "start_committed": False,
        "start_payload_digest": None,
        "state": wire._SupervisorWireState.RESERVED,
        "terminal_attestation_id": None,
        "terminal_kind": None,
        "terminal_status": None,
        "terminate_action_id": None,
    }
    payload.update(overrides)
    if "attestation_digest" not in overrides:
        payload["attestation_digest"] = _state_attestation_digest(payload)
    return payload


def _state_payloads_by_state() -> dict[
    wire._SupervisorWireState, dict[str, object]
]:
    attached = {
        "attachment_command_id": ATTACH_COMMAND_ID,
        "attachment_proof_digest": PUBLICATION_PROOF_DIGEST,
    }
    armed = {**attached, "arm_command_id": ARM_COMMAND_ID}
    child = {
        **armed,
        "child_ever_owned": True,
        "spawn_created": True,
        "spawn_event_id": SPAWN_EVENT_ID,
    }
    ready = {**child, "ready_event_id": READY_EVENT_ID}
    started = {
        **ready,
        "start_command_id": START_COMMAND_ID,
        "start_committed": True,
        "start_payload_digest": START_PAYLOAD_DIGEST,
    }
    result = {
        **started,
        "result_digest": RESULT_DIGEST,
        "result_event_id": RESULT_EVENT_ID,
    }
    terminal = {
        "cancel_command_id": COMMAND_ID,
        "cancel_latched": True,
        "cancel_payload_digest": CANCEL_PAYLOAD_DIGEST,
        "cleanup_phase": wire._SupervisorWireCleanupPhase.COMPLETE,
        "terminal_attestation_id": COMMAND_ID,
        "terminal_kind": wire._SupervisorWireTerminalKind.ZERO_CHILD_CANCEL,
    }
    return {
        wire._SupervisorWireState.RESERVED: _state_payload(
            state=wire._SupervisorWireState.RESERVED,
        ),
        wire._SupervisorWireState.ATTACHED: _state_payload(
            **attached,
            revision=1,
            state=wire._SupervisorWireState.ATTACHED,
        ),
        wire._SupervisorWireState.SPAWN_INFLIGHT: _state_payload(
            **armed,
            revision=2,
            state=wire._SupervisorWireState.SPAWN_INFLIGHT,
        ),
        wire._SupervisorWireState.CANCEL_WAIT_SPAWN: _state_payload(
            **armed,
            cancel_command_id=COMMAND_ID,
            cancel_latched=True,
            cancel_payload_digest=CANCEL_PAYLOAD_DIGEST,
            revision=3,
            state=wire._SupervisorWireState.CANCEL_WAIT_SPAWN,
        ),
        wire._SupervisorWireState.CHILD_OWNED: _state_payload(
            **child,
            revision=3,
            state=wire._SupervisorWireState.CHILD_OWNED,
        ),
        wire._SupervisorWireState.READY: _state_payload(
            **ready,
            revision=4,
            state=wire._SupervisorWireState.READY,
        ),
        wire._SupervisorWireState.STARTED: _state_payload(
            **started,
            revision=5,
            state=wire._SupervisorWireState.STARTED,
        ),
        wire._SupervisorWireState.RESULT_PENDING_TERMINAL: _state_payload(
            **result,
            revision=6,
            state=wire._SupervisorWireState.RESULT_PENDING_TERMINAL,
        ),
        wire._SupervisorWireState.TERMINAL_ATTESTED: _state_payload(
            **terminal,
            revision=1,
            state=wire._SupervisorWireState.TERMINAL_ATTESTED,
        ),
        wire._SupervisorWireState.RELEASED: _state_payload(
            **terminal,
            release_tombstone_id=TOMBSTONE_ID,
            revision=2,
            state=wire._SupervisorWireState.RELEASED,
        ),
        wire._SupervisorWireState.POISONED: _state_payload(
            poison_reason=wire._SupervisorWirePoisonReason.EPOCH_LOST,
            revision=1,
            state=wire._SupervisorWireState.POISONED,
        ),
    }


def _payloads() -> dict[wire._SupervisorWireKind, dict[str, object]]:
    return {
        wire._SupervisorWireKind.RESERVE: {
            "lifecycle_id": LIFECYCLE_ID,
            "publication_id": PUBLICATION_ID,
            "spawn_request_digest": SPAWN_REQUEST_DIGEST,
        },
        wire._SupervisorWireKind.ATTACH: {
            "command_id": COMMAND_ID,
            "proxy_id": PROXY_ID,
            "publication_id": PUBLICATION_ID,
            "publication_proof_digest": PUBLICATION_PROOF_DIGEST,
            "reservation_attestation_digest": (
                RESERVATION_ATTESTATION_DIGEST
            ),
        },
        wire._SupervisorWireKind.ARM: {
            "command_id": COMMAND_ID,
            "proxy_id": PROXY_ID,
        },
        wire._SupervisorWireKind.CANCEL: {
            "cancel_payload_digest": CANCEL_PAYLOAD_DIGEST,
            "command_id": COMMAND_ID,
            "proxy_id": PROXY_ID,
        },
        wire._SupervisorWireKind.QUERY: {
            "proxy_id": PROXY_ID,
            "query_id": QUERY_ID,
        },
        wire._SupervisorWireKind.RELEASE: {
            "proxy_id": PROXY_ID,
            "terminal_attestation_digest": TERMINAL_ATTESTATION_DIGEST,
            "tombstone_id": TOMBSTONE_ID,
        },
        wire._SupervisorWireKind.ACK: {
            "acked_frame_digest": ACKED_FRAME_DIGEST,
            "acked_frame_id": FRAME_IDS[wire._SupervisorWireKind.RESERVE],
            "acked_kind": wire._SupervisorWireKind.RESERVE,
            "attestation_digest": ATTESTATION_DIGEST,
            "proxy_id": None,
            "revision": 0,
        },
        wire._SupervisorWireKind.STATE: _state_payload(),
    }


def _frame(
    kind: wire._SupervisorWireKind,
    *,
    payload: dict[str, object] | None = None,
    epoch_id: UUID = EPOCH_ID,
    operation_id: UUID = OPERATION_ID,
    control_channel_id: UUID = CONTROL_CHANNEL_ID,
    operation_binding_digest: Digest256 = OPERATION_BINDING_DIGEST,
    frame_id: UUID | None = None,
) -> wire._SupervisorWireFrame:
    return wire._new_supervisor_wire_frame(
        kind=kind,
        epoch_id=epoch_id,
        operation_id=operation_id,
        control_channel_id=control_channel_id,
        operation_binding_digest=operation_binding_digest,
        frame_id=FRAME_IDS[kind] if frame_id is None else frame_id,
        payload=_payloads()[kind] if payload is None else payload,
    )


def _canonical_mutation(
    frame: wire._SupervisorWireFrame,
    mutate,
) -> bytes:
    parsed = json.loads(wire._encode_supervisor_wire_frame(frame))
    mutate(parsed)
    return canonical_json_bytes(parsed) + b"\n"


class ResolverSupervisorWireTest(unittest.TestCase):
    def test_module_is_private_dependency_isolated_and_zero_io(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_resolver_supervisor_wire.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertEqual(
            imported,
            {
                "__future__",
                "enum",
                "json",
                "snapquiz.domain._validation",
                "snapquiz.domain.digest",
                "types",
                "uuid",
            },
        )
        self.assertNotIn("_resolver_supervisor_contract", source)
        self.assertEqual(wire.__all__, ())

        script = """
import builtins
import importlib
import os
import socket
import subprocess
import sys
import time
from unittest.mock import patch
from uuid import UUID

from snapquiz.domain.digest import Digest256, digest256
import snapquiz.transport

sys.modules.pop('snapquiz.transport._resolver_supervisor_wire', None)

def forbidden(*args, **kwargs):
    raise AssertionError((args, kwargs))

with patch.object(builtins, 'open', side_effect=forbidden), patch.object(
    os, 'getenv', side_effect=forbidden
), patch.object(os, 'read', side_effect=forbidden), patch.object(
    os, 'write', side_effect=forbidden
), patch.object(socket, 'socket', side_effect=forbidden), patch.object(
    subprocess, 'Popen', side_effect=forbidden
), patch.object(time, 'monotonic_ns', side_effect=forbidden):
    module = importlib.import_module(
        'snapquiz.transport._resolver_supervisor_wire'
    )
    frame = module._new_supervisor_wire_frame(
        kind=module._SupervisorWireKind.RESERVE,
        epoch_id=UUID('8a000000-0000-0000-0000-000000000001'),
        operation_id=UUID('8a000000-0000-0000-0000-000000000002'),
        control_channel_id=UUID(
            '8a000000-0000-0000-0000-000000000003'
        ),
        operation_binding_digest=digest256(
            'ResolverSupervisorOperationBinding',
            'snapquiz.resolver-supervisor-operation-binding.v1',
            {
                'epoch_id': UUID(
                    '8a000000-0000-0000-0000-000000000001'
                ),
                'lifecycle_id': UUID(
                    '8a000000-0000-0000-0000-000000000004'
                ),
                'operation_id': UUID(
                    '8a000000-0000-0000-0000-000000000002'
                ),
                'publication_id': UUID(
                    '8a000000-0000-0000-0000-000000000005'
                ),
                'spawn_request_digest': Digest256('b' * 64),
            },
        ),
        frame_id=UUID('8a000000-0000-0000-0000-000000000100'),
        payload={
            'lifecycle_id': UUID(
                '8a000000-0000-0000-0000-000000000004'
            ),
            'publication_id': UUID(
                '8a000000-0000-0000-0000-000000000005'
            ),
            'spawn_request_digest': Digest256('b' * 64),
        },
    )
    encoded = module._encode_supervisor_wire_frame(frame)
    decoded = module._decode_supervisor_wire_frame(encoded)
    assert decoded.frame_digest == frame.frame_digest
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=source_path.parents[2],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_kind_and_state_vocabularies_are_frozen(self):
        self.assertEqual(
            [kind.value for kind in wire._SupervisorWireKind],
            [
                "RESERVE",
                "ATTACH",
                "ARM",
                "CANCEL",
                "QUERY",
                "RELEASE",
                "ACK",
                "STATE",
            ],
        )
        self.assertEqual(
            {state.value for state in wire._SupervisorWireState},
            {
                "reserved",
                "attached",
                "spawn_inflight",
                "cancel_wait_spawn",
                "child_owned",
                "ready",
                "started",
                "result_pending_terminal",
                "terminal_attested",
                "released",
                "poisoned",
            },
        )
        self.assertEqual(wire.MAX_SUPERVISOR_WIRE_FRAME_BYTES, 4_096)
        self.assertEqual(
            wire.SUPERVISOR_WIRE_PROTOCOL_VERSION,
            "snapquiz.resolver-supervisor-wire.v1",
        )

    def test_all_frame_kinds_round_trip_as_one_canonical_bounded_record(self):
        for kind in wire._SupervisorWireKind:
            with self.subTest(kind=kind.value):
                original = _frame(kind)
                encoded = wire._encode_supervisor_wire_frame(original)
                self.assertIs(type(encoded), bytes)
                self.assertTrue(encoded.endswith(b"\n"))
                self.assertNotIn(b"\n", encoded[:-1])
                self.assertLessEqual(
                    len(encoded), wire.MAX_SUPERVISOR_WIRE_FRAME_BYTES
                )
                self.assertEqual(
                    canonical_json_bytes(json.loads(encoded[:-1])) + b"\n",
                    encoded,
                )
                decoded = wire._decode_supervisor_wire_frame(encoded)
                self.assertIs(type(decoded), wire._SupervisorWireFrame)
                self.assertIs(decoded.kind, kind)
                self.assertEqual(decoded.epoch_id, EPOCH_ID)
                self.assertEqual(decoded.operation_id, OPERATION_ID)
                self.assertEqual(decoded.control_channel_id, CONTROL_CHANNEL_ID)
                self.assertEqual(
                    decoded.operation_binding_digest,
                    OPERATION_BINDING_DIGEST,
                )
                self.assertEqual(decoded.frame_id, FRAME_IDS[kind])
                self.assertEqual(dict(decoded.payload), _payloads()[kind])
                self.assertEqual(decoded.frame_digest, original.frame_digest)
                self.assertEqual(
                    wire._encode_supervisor_wire_frame(decoded), encoded
                )

    def test_reserve_wire_vector_freezes_the_envelope_and_payload_shape(self):
        encoded = wire._encode_supervisor_wire_frame(
            _frame(wire._SupervisorWireKind.RESERVE)
        )
        expected = (
            '{"control_channel_id":"8a000000-0000-0000-0000-000000000003",'
            '"epoch_id":"8a000000-0000-0000-0000-000000000001",'
            '"frame_id":"8a000000-0000-0000-0000-000000000100",'
            '"kind":"RESERVE","operation_binding_digest":"'
            + str(OPERATION_BINDING_DIGEST)
            + '","operation_id":"8a000000-0000-0000-0000-000000000002",'
            '"payload":{"lifecycle_id":"'
            '8a000000-0000-0000-0000-000000000004",'
            '"publication_id":"8a000000-0000-0000-0000-000000000005",'
            '"spawn_request_digest":"'
            + "b" * 64
            + '"},"protocol_version":"snapquiz.resolver-supervisor-wire.v1",'
            '"schema_version":"snapquiz.resolver-supervisor-wire-frame.v1"}\n'
        ).encode("ascii")
        self.assertEqual(encoded, expected)

    def test_epoch_operation_channel_and_binding_are_digest_bound(self):
        kind = wire._SupervisorWireKind.ARM
        variants = (
            _frame(kind),
            _frame(kind, epoch_id=OTHER_ID),
            _frame(kind, operation_id=OTHER_ID),
            _frame(kind, control_channel_id=OTHER_ID),
            _frame(kind, operation_binding_digest=Digest256("9" * 64)),
        )
        self.assertEqual(len({item.frame_digest for item in variants}), 5)
        self.assertEqual(
            len(
                {
                    wire._encode_supervisor_wire_frame(item)
                    for item in variants
                }
            ),
            5,
        )
        variants[0].require_binding(
            epoch_id=EPOCH_ID,
            operation_id=OPERATION_ID,
            control_channel_id=CONTROL_CHANNEL_ID,
            operation_binding_digest=OPERATION_BINDING_DIGEST,
        )
        wrong_bindings = (
            {"epoch_id": OTHER_ID},
            {"operation_id": OTHER_ID},
            {"control_channel_id": OTHER_ID},
            {"operation_binding_digest": Digest256("9" * 64)},
        )
        expected: dict[str, object] = {
            "epoch_id": EPOCH_ID,
            "operation_id": OPERATION_ID,
            "control_channel_id": CONTROL_CHANNEL_ID,
            "operation_binding_digest": OPERATION_BINDING_DIGEST,
        }
        for override in wrong_bindings:
            selected = dict(expected)
            selected.update(override)
            with self.subTest(binding=next(iter(override))), self.assertRaises(
                ValueError
            ):
                variants[0].require_binding(**selected)

    def test_frame_is_factory_only_deeply_immutable_and_nonserializable(self):
        payload = _payloads()[wire._SupervisorWireKind.RESERVE]
        frame = _frame(wire._SupervisorWireKind.RESERVE, payload=payload)
        payload["lifecycle_id"] = OTHER_ID
        self.assertEqual(frame.payload["lifecycle_id"], LIFECYCLE_ID)
        self.assertIs(copy.copy(frame), frame)
        self.assertIs(copy.deepcopy(frame), frame)
        with self.assertRaises(AttributeError):
            frame.epoch_id = OTHER_ID
        with self.assertRaises(TypeError):
            frame.payload["lifecycle_id"] = OTHER_ID
        with self.assertRaises(TypeError):
            pickle.dumps(frame)
        with self.assertRaises(TypeError):
            json.dumps(frame)
        with self.assertRaises(TypeError):
            wire._SupervisorWireFrame(
                kind=wire._SupervisorWireKind.RESERVE,
                epoch_id=EPOCH_ID,
                operation_id=OPERATION_ID,
                control_channel_id=CONTROL_CHANNEL_ID,
                operation_binding_digest=OPERATION_BINDING_DIGEST,
                frame_id=FRAME_IDS[wire._SupervisorWireKind.RESERVE],
                payload=_payloads()[wire._SupervisorWireKind.RESERVE],
            )
        with self.assertRaises(TypeError):
            class ForgedFrame(wire._SupervisorWireFrame):
                pass

    def test_integrity_rejects_slot_tampering_even_if_public_digest_is_replaced(self):
        frame = _frame(wire._SupervisorWireKind.QUERY)
        object.__setattr__(frame, "operation_id", OTHER_ID)
        with self.assertRaises(ValueError):
            frame.validate_integrity()
        with self.assertRaises(ValueError):
            wire._encode_supervisor_wire_frame(frame)

        frame = _frame(wire._SupervisorWireKind.QUERY)
        object.__setattr__(frame, "frame_digest", Digest256("9" * 64))
        with self.assertRaises(ValueError):
            frame.validate_integrity()

        frame = _frame(wire._SupervisorWireKind.QUERY)
        object.__setattr__(
            frame,
            "payload",
            MappingProxyType({"proxy_id": OTHER_ID, "query_id": QUERY_ID}),
        )
        with self.assertRaises(ValueError):
            frame.validate_integrity()

    def test_factory_requires_exact_common_and_kind_specific_types(self):
        reserve = _payloads()[wire._SupervisorWireKind.RESERVE]
        common_bad = (
            {"kind": "RESERVE"},
            {"epoch_id": str(EPOCH_ID)},
            {"operation_id": str(OPERATION_ID)},
            {"control_channel_id": str(CONTROL_CHANNEL_ID)},
            {"operation_binding_digest": str(OPERATION_BINDING_DIGEST)},
            {"frame_id": str(FRAME_IDS[wire._SupervisorWireKind.RESERVE])},
            {"payload": MappingProxyType(reserve)},
        )
        defaults: dict[str, object] = {
            "kind": wire._SupervisorWireKind.RESERVE,
            "epoch_id": EPOCH_ID,
            "operation_id": OPERATION_ID,
            "control_channel_id": CONTROL_CHANNEL_ID,
            "operation_binding_digest": OPERATION_BINDING_DIGEST,
            "frame_id": FRAME_IDS[wire._SupervisorWireKind.RESERVE],
            "payload": reserve,
        }
        for override in common_bad:
            with self.subTest(override=next(iter(override))):
                selected = dict(defaults)
                selected.update(override)
                with self.assertRaises((TypeError, ValueError)):
                    wire._new_supervisor_wire_frame(**selected)

        for kind, payload in _payloads().items():
            with self.subTest(kind=kind.value, case="unknown"):
                changed = dict(payload)
                changed["unknown"] = OTHER_ID
                with self.assertRaises(ValueError):
                    _frame(kind, payload=changed)
            with self.subTest(kind=kind.value, case="missing"):
                changed = dict(payload)
                changed.pop(next(iter(changed)))
                with self.assertRaises(ValueError):
                    _frame(kind, payload=changed)

        changed = dict(reserve)
        changed["spawn_request_digest"] = str(SPAWN_REQUEST_DIGEST)
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.RESERVE, payload=changed)
        with self.assertRaises(ValueError):
            _frame(
                wire._SupervisorWireKind.RESERVE,
                operation_binding_digest=Digest256("9" * 64),
            )
        changed = _payloads()[wire._SupervisorWireKind.ARM]
        changed["command_id"] = str(COMMAND_ID)
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.ARM, payload=changed)

    def test_ack_schema_rejects_query_ack_and_proxy_binding_ambiguity(self):
        payload = _payloads()[wire._SupervisorWireKind.ACK]
        payload["acked_kind"] = wire._SupervisorWireKind.QUERY
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.ACK, payload=payload)

        payload = _payloads()[wire._SupervisorWireKind.ACK]
        payload["proxy_id"] = PROXY_ID
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.ACK, payload=payload)

        payload = _payloads()[wire._SupervisorWireKind.ACK]
        payload["acked_kind"] = wire._SupervisorWireKind.ARM
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.ACK, payload=payload)

        payload["proxy_id"] = PROXY_ID
        frame = _frame(wire._SupervisorWireKind.ACK, payload=payload)
        self.assertEqual(frame.payload["proxy_id"], PROXY_ID)

        payload = _payloads()[wire._SupervisorWireKind.ACK]
        payload["acked_frame_digest"] = str(ACKED_FRAME_DIGEST)
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.ACK, payload=payload)

        for invalid in (True, -1, wire.MAX_SUPERVISOR_WIRE_COUNTER + 1):
            payload = _payloads()[wire._SupervisorWireKind.ACK]
            payload["revision"] = invalid
            with self.subTest(revision=invalid), self.assertRaises(ValueError):
                _frame(wire._SupervisorWireKind.ACK, payload=payload)

    def test_ack_is_bound_to_the_exact_command_frame_bytes(self):
        command = _frame(wire._SupervisorWireKind.ARM)
        payload = _payloads()[wire._SupervisorWireKind.ACK]
        payload.update(
            {
                "acked_frame_digest": command.frame_digest,
                "acked_frame_id": command.frame_id,
                "acked_kind": command.kind,
                "proxy_id": PROXY_ID,
                "revision": 2,
            }
        )
        acknowledgement = _frame(
            wire._SupervisorWireKind.ACK,
            payload=payload,
        )
        acknowledgement.require_acknowledges(command)

        wrong_commands = (
            _frame(wire._SupervisorWireKind.ATTACH),
            _frame(
                wire._SupervisorWireKind.ARM,
                control_channel_id=OTHER_ID,
            ),
            _frame(
                wire._SupervisorWireKind.ARM,
                frame_id=OTHER_ID,
            ),
        )
        for candidate in wrong_commands:
            with self.subTest(kind=candidate.kind.value), self.assertRaises(
                ValueError
            ):
                acknowledgement.require_acknowledges(candidate)
        with self.assertRaises(TypeError):
            acknowledgement.require_acknowledges(object())
        with self.assertRaises(ValueError):
            command.require_acknowledges(command)

    def test_state_schema_preserves_recovery_facts_and_rejects_inconsistency(self):
        terminal = _state_payload(
            cancel_command_id=COMMAND_ID,
            cancel_latched=True,
            cancel_payload_digest=CANCEL_PAYLOAD_DIGEST,
            cleanup_phase=wire._SupervisorWireCleanupPhase.COMPLETE,
            revision=1,
            state=wire._SupervisorWireState.TERMINAL_ATTESTED,
            terminal_attestation_id=COMMAND_ID,
            terminal_kind=wire._SupervisorWireTerminalKind.ZERO_CHILD_CANCEL,
        )
        terminal_frame = _frame(
            wire._SupervisorWireKind.STATE, payload=terminal
        )
        self.assertEqual(
            wire._decode_supervisor_wire_frame(
                wire._encode_supervisor_wire_frame(terminal_frame)
            ).payload["cancel_command_id"],
            COMMAND_ID,
        )

        released = _redigest_state_payload(
            {
                **terminal,
                "release_tombstone_id": TOMBSTONE_ID,
                "revision": 2,
                "state": wire._SupervisorWireState.RELEASED,
            }
        )
        _frame(wire._SupervisorWireKind.STATE, payload=released)

        poisoned_after_terminal = _redigest_state_payload(
            {
                **terminal,
                "poison_reason": wire._SupervisorWirePoisonReason.EPOCH_LOST,
                "state": wire._SupervisorWireState.POISONED,
            }
        )
        _frame(wire._SupervisorWireKind.STATE, payload=poisoned_after_terminal)

        invalid_changes = (
            {"cancel_latched": True},
            {"spawn_created": True},
            {"start_committed": True},
            {"state": "reserved"},
            {"cleanup_phase": "none"},
            {"terminal_status": True},
            {"revision": True},
            {"revision": wire.MAX_SUPERVISOR_WIRE_COUNTER + 1},
            {"release_tombstone_id": TOMBSTONE_ID},
            {
                "state": wire._SupervisorWireState.POISONED,
                "poison_reason": None,
            },
            {
                "cleanup_phase": wire._SupervisorWireCleanupPhase.REAP_CLAIMED,
                "terminate_action_id": ACTION_ID,
                "reap_action_id": None,
            },
        )
        for change in invalid_changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                _frame(
                    wire._SupervisorWireKind.STATE,
                    payload=_state_payload(**change),
                )

    def test_every_authoritative_state_has_one_valid_and_invalid_wire_shape(self):
        valid = _state_payloads_by_state()
        self.assertEqual(set(valid), set(wire._SupervisorWireState))
        for state, payload in valid.items():
            with self.subTest(state=state.value, case="valid"):
                frame = _frame(wire._SupervisorWireKind.STATE, payload=payload)
                decoded = wire._decode_supervisor_wire_frame(
                    wire._encode_supervisor_wire_frame(frame)
                )
                self.assertIs(decoded.payload["state"], state)

        invalid = {
            wire._SupervisorWireState.RESERVED: _state_payload(
                attachment_command_id=ATTACH_COMMAND_ID,
                attachment_proof_digest=PUBLICATION_PROOF_DIGEST,
            ),
            wire._SupervisorWireState.ATTACHED: _state_payload(
                state=wire._SupervisorWireState.ATTACHED,
            ),
            wire._SupervisorWireState.SPAWN_INFLIGHT: _state_payload(
                attachment_command_id=ATTACH_COMMAND_ID,
                attachment_proof_digest=PUBLICATION_PROOF_DIGEST,
                state=wire._SupervisorWireState.SPAWN_INFLIGHT,
            ),
            wire._SupervisorWireState.CANCEL_WAIT_SPAWN: _state_payload(
                attachment_command_id=ATTACH_COMMAND_ID,
                attachment_proof_digest=PUBLICATION_PROOF_DIGEST,
                arm_command_id=ARM_COMMAND_ID,
                state=wire._SupervisorWireState.CANCEL_WAIT_SPAWN,
            ),
            wire._SupervisorWireState.CHILD_OWNED: _state_payload(
                attachment_command_id=ATTACH_COMMAND_ID,
                attachment_proof_digest=PUBLICATION_PROOF_DIGEST,
                arm_command_id=ARM_COMMAND_ID,
                state=wire._SupervisorWireState.CHILD_OWNED,
            ),
            wire._SupervisorWireState.READY: _redigest_state_payload(
                {
                    **valid[wire._SupervisorWireState.CHILD_OWNED],
                    "state": wire._SupervisorWireState.READY,
                }
            ),
            wire._SupervisorWireState.STARTED: _redigest_state_payload(
                {
                    **valid[wire._SupervisorWireState.READY],
                    "state": wire._SupervisorWireState.STARTED,
                }
            ),
            wire._SupervisorWireState.RESULT_PENDING_TERMINAL: (
                _redigest_state_payload(
                    {
                        **valid[wire._SupervisorWireState.STARTED],
                        "state": (
                            wire._SupervisorWireState.RESULT_PENDING_TERMINAL
                        ),
                    }
                )
            ),
            wire._SupervisorWireState.TERMINAL_ATTESTED: _state_payload(
                state=wire._SupervisorWireState.TERMINAL_ATTESTED,
            ),
            wire._SupervisorWireState.RELEASED: _redigest_state_payload(
                {
                    **valid[wire._SupervisorWireState.TERMINAL_ATTESTED],
                    "state": wire._SupervisorWireState.RELEASED,
                }
            ),
            wire._SupervisorWireState.POISONED: _state_payload(
                state=wire._SupervisorWireState.POISONED,
            ),
        }
        for state, payload in invalid.items():
            with self.subTest(state=state.value, case="invalid"), self.assertRaises(
                ValueError
            ):
                _frame(wire._SupervisorWireKind.STATE, payload=payload)

    def test_terminal_kind_and_cleanup_phase_lattices_are_frozen(self):
        spawn_failed = _state_payload(
            arm_command_id=ARM_COMMAND_ID,
            attachment_command_id=ATTACH_COMMAND_ID,
            attachment_proof_digest=PUBLICATION_PROOF_DIGEST,
            cleanup_phase=wire._SupervisorWireCleanupPhase.COMPLETE,
            spawn_created=False,
            spawn_event_id=SPAWN_EVENT_ID,
            state=wire._SupervisorWireState.TERMINAL_ATTESTED,
            terminal_attestation_id=SPAWN_EVENT_ID,
            terminal_kind=wire._SupervisorWireTerminalKind.SPAWN_FAILED,
            terminal_status=70,
        )
        _frame(wire._SupervisorWireKind.STATE, payload=spawn_failed)

        child_exited = _state_payload(
            arm_command_id=ARM_COMMAND_ID,
            attachment_command_id=ATTACH_COMMAND_ID,
            attachment_proof_digest=PUBLICATION_PROOF_DIGEST,
            child_ever_owned=True,
            cleanup_phase=wire._SupervisorWireCleanupPhase.COMPLETE,
            spawn_created=True,
            spawn_event_id=SPAWN_EVENT_ID,
            state=wire._SupervisorWireState.TERMINAL_ATTESTED,
            terminal_attestation_id=TERMINAL_ID,
            terminal_kind=wire._SupervisorWireTerminalKind.CHILD_EXITED,
            terminal_status=0,
        )
        _frame(wire._SupervisorWireKind.STATE, payload=child_exited)

        phase_actions = {
            wire._SupervisorWireCleanupPhase.NONE: (None, None, None),
            wire._SupervisorWireCleanupPhase.TERMINATE_REQUIRED: (
                None,
                None,
                None,
            ),
            wire._SupervisorWireCleanupPhase.TERMINATE_CLAIMED: (
                ACTION_ID,
                None,
                None,
            ),
            wire._SupervisorWireCleanupPhase.REAP_REQUIRED: (
                ACTION_ID,
                None,
                None,
            ),
            wire._SupervisorWireCleanupPhase.REAP_CLAIMED: (
                ACTION_ID,
                OTHER_ID,
                None,
            ),
            wire._SupervisorWireCleanupPhase.CLOSE_REQUIRED: (
                ACTION_ID,
                OTHER_ID,
                None,
            ),
            wire._SupervisorWireCleanupPhase.CLOSE_CLAIMED: (
                ACTION_ID,
                OTHER_ID,
                TERMINAL_ID,
            ),
            wire._SupervisorWireCleanupPhase.COMPLETE: (None, None, None),
        }
        for phase, actions in phase_actions.items():
            with self.subTest(phase=phase.value):
                _frame(
                    wire._SupervisorWireKind.STATE,
                    payload=_state_payload(
                        cleanup_phase=phase,
                        poison_reason=(
                            wire._SupervisorWirePoisonReason.EPOCH_LOST
                        ),
                        state=wire._SupervisorWireState.POISONED,
                        terminate_action_id=actions[0],
                        reap_action_id=actions[1],
                        close_action_id=actions[2],
                    ),
                )

        invalid_spawn = _redigest_state_payload(
            {**spawn_failed, "terminal_status": 71}
        )
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.STATE, payload=invalid_spawn)
        invalid_child = _redigest_state_payload(
            {**child_exited, "child_ever_owned": False}
        )
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.STATE, payload=invalid_child)

        cancelled_child_without_actions = _redigest_state_payload(
            {
                **child_exited,
                "cancel_command_id": COMMAND_ID,
                "cancel_latched": True,
                "cancel_payload_digest": CANCEL_PAYLOAD_DIGEST,
            }
        )
        with self.assertRaises(ValueError):
            _frame(
                wire._SupervisorWireKind.STATE,
                payload=cancelled_child_without_actions,
            )
        cancelled_child_with_actions = _redigest_state_payload(
            {
                **cancelled_child_without_actions,
                "close_action_id": TERMINAL_ID,
                "reap_action_id": OTHER_ID,
                "terminate_action_id": ACTION_ID,
            }
        )
        _frame(
            wire._SupervisorWireKind.STATE,
            payload=cancelled_child_with_actions,
        )

    def test_success_cleanup_state_requires_paired_eof_ack_and_no_terminate(self):
        result = _state_payloads_by_state()[
            wire._SupervisorWireState.RESULT_PENDING_TERMINAL
        ]
        success = _redigest_state_payload(
            {
                **result,
                "cleanup_phase": wire._SupervisorWireCleanupPhase.REAP_REQUIRED,
                "durable_eof_ack_digest": ACKED_FRAME_DIGEST,
                "revision": result["revision"] + 1,
                "success_cleanup_event_id": OTHER_ID,
            }
        )
        frame = _frame(wire._SupervisorWireKind.STATE, payload=success)
        self.assertEqual(
            wire._decode_supervisor_wire_frame(
                wire._encode_supervisor_wire_frame(frame)
            ).payload,
            frame.payload,
        )

        missing_digest = _redigest_state_payload(
            {**success, "durable_eof_ack_digest": None}
        )
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.STATE, payload=missing_digest)
        with_terminate = _redigest_state_payload(
            {**success, "terminate_action_id": ACTION_ID}
        )
        with self.assertRaises(ValueError):
            _frame(wire._SupervisorWireKind.STATE, payload=with_terminate)

    def test_state_attestation_digest_rejects_same_revision_fact_equivocation(self):
        ready = _state_payloads_by_state()[wire._SupervisorWireState.READY]
        frame = _frame(wire._SupervisorWireKind.STATE, payload=ready)
        encoded = wire._encode_supervisor_wire_frame(frame)
        parsed = json.loads(encoded)
        parsed["payload"]["ready_event_id"] = str(OTHER_ID)
        equivocation = canonical_json_bytes(parsed) + b"\n"
        self.assertEqual(
            json.loads(equivocation)["payload"]["revision"],
            ready["revision"],
        )
        self.assertEqual(
            json.loads(equivocation)["payload"]["attestation_digest"],
            str(ready["attestation_digest"]),
        )
        with self.assertRaises(ValueError):
            wire._decode_supervisor_wire_frame(equivocation)

    def test_decoder_rejects_unknown_missing_version_and_wrong_type_fields(self):
        reserve = _frame(wire._SupervisorWireKind.RESERVE)
        cases = (
            _canonical_mutation(
                reserve, lambda value: value.update({"unknown": "x"})
            ),
            _canonical_mutation(
                reserve, lambda value: value.pop("operation_id")
            ),
            _canonical_mutation(
                reserve, lambda value: value.update({"kind": "UNKNOWN"})
            ),
            _canonical_mutation(
                reserve,
                lambda value: value.update({"protocol_version": "v2"}),
            ),
            _canonical_mutation(
                reserve,
                lambda value: value.update({"schema_version": "v2"}),
            ),
            _canonical_mutation(
                reserve, lambda value: value.update({"epoch_id": 7})
            ),
            _canonical_mutation(
                reserve,
                lambda value: value["payload"].update({"unknown": "x"}),
            ),
            _canonical_mutation(
                reserve,
                lambda value: value["payload"].pop("lifecycle_id"),
            ),
        )
        for index, candidate in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                wire._decode_supervisor_wire_frame(candidate)

        ack = _frame(wire._SupervisorWireKind.ACK)
        invalid_revisions = [
            (
                repr(invalid),
                _canonical_mutation(
                    ack,
                    lambda value, selected=invalid: value["payload"].update(
                        {"revision": selected}
                    ),
                ),
            )
            for invalid in (True, -1, 10**19)
        ]
        encoded_ack = wire._encode_supervisor_wire_frame(ack)
        invalid_revisions.append(
            (
                "1.0",
                encoded_ack.replace(b'"revision":0', b'"revision":1.0', 1),
            )
        )
        for label, candidate in invalid_revisions:
            with self.subTest(revision=label), self.assertRaises(ValueError):
                wire._decode_supervisor_wire_frame(candidate)

    def test_decoder_rejects_noncanonical_uuid_and_digest_text(self):
        reserve = _frame(wire._SupervisorWireKind.RESERVE)
        cases = (
            _canonical_mutation(
                reserve,
                lambda value: value.update(
                    {"epoch_id": str(EPOCH_ID).upper()}
                ),
            ),
            _canonical_mutation(
                reserve,
                lambda value: value.update(
                    {"epoch_id": "{" + str(EPOCH_ID) + "}"}
                ),
            ),
            _canonical_mutation(
                reserve,
                lambda value: value.update(
                    {"operation_binding_digest": "A" * 64}
                ),
            ),
            _canonical_mutation(
                reserve,
                lambda value: value["payload"].update(
                    {"spawn_request_digest": "b" * 63}
                ),
            ),
        )
        for index, candidate in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                wire._decode_supervisor_wire_frame(candidate)

    def test_decoder_rejects_duplicate_keys_at_every_object_level(self):
        valid = wire._encode_supervisor_wire_frame(
            _frame(wire._SupervisorWireKind.RESERVE)
        )
        body = valid[:-1]
        duplicate_top = (
            b'{"control_channel_id":"'
            + str(CONTROL_CHANNEL_ID).encode("ascii")
            + b'",'
            + body[1:]
            + b"\n"
        )
        needle = b'"payload":{"lifecycle_id":'
        replacement = (
            b'"payload":{"lifecycle_id":"'
            + str(LIFECYCLE_ID).encode("ascii")
            + b'","lifecycle_id":'
        )
        duplicate_payload = body.replace(needle, replacement, 1) + b"\n"
        for candidate in (duplicate_top, duplicate_payload):
            with self.assertRaises(ValueError):
                wire._decode_supervisor_wire_frame(candidate)

    def test_decoder_rejects_noncanonical_trailing_and_oversize_records(self):
        valid = wire._encode_supervisor_wire_frame(
            _frame(wire._SupervisorWireKind.RESERVE)
        )
        parsed = json.loads(valid)
        reordered = {"schema_version": parsed.pop("schema_version"), **parsed}
        cases = (
            b"",
            b"\n",
            b" \n",
            b"\xff\n",
            b"\xef\xbb\xbf" + valid,
            valid[:-1],
            valid + b"x",
            valid + b"\n",
            valid + valid,
            json.dumps(parsed, indent=1, sort_keys=True).encode("utf-8") + b"\n",
            json.dumps(reordered, separators=(",", ":")).encode("utf-8")
            + b"\n",
            canonical_json_bytes([]) + b"\n",
            b"x" * (wire.MAX_SUPERVISOR_WIRE_FRAME_BYTES + 1),
        )
        for index, candidate in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                wire._decode_supervisor_wire_frame(candidate)
        with self.assertRaises(ValueError):
            wire._decode_supervisor_wire_frame(bytearray(valid))

    def test_decode_failure_is_content_free_and_drops_raw_exception_context(self):
        candidate = b'{"private_canary":"must-not-escape"}\n'
        try:
            wire._decode_supervisor_wire_frame(candidate)
        except ValueError as error:
            self.assertEqual(
                str(error), "resolver supervisor wire frame is invalid"
            )
            self.assertNotIn("private_canary", repr(error))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
        else:
            self.fail("malformed frame was accepted")

    def test_safe_metadata_contains_only_common_binding_and_digest_prefixes(self):
        frame = _frame(wire._SupervisorWireKind.CANCEL)
        metadata = frame.safe_metadata()
        self.assertEqual(metadata["kind"], "CANCEL")
        self.assertEqual(metadata["operation_id"], str(OPERATION_ID))
        self.assertEqual(len(metadata["frame_digest_prefix"]), 12)
        self.assertEqual(
            len(metadata["operation_binding_digest_prefix"]), 12
        )
        rendered = repr(metadata)
        self.assertNotIn(str(CANCEL_PAYLOAD_DIGEST), rendered)
        self.assertNotIn(str(OPERATION_BINDING_DIGEST), rendered)


if __name__ == "__main__":
    unittest.main()
