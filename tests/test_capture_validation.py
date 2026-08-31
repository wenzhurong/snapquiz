from __future__ import annotations

import binascii
from dataclasses import asdict
from datetime import datetime, timedelta
import os
from pathlib import Path
import struct
import subprocess
import sys
from threading import Barrier, Event, Lock, Thread
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID
import zlib

import snapquiz.capture.validation as capture_validation_module
from snapquiz.capture.policy import (
    CAPTURE_AUTHORIZATION_SCHEMA_VERSION,
    CaptureAuthorizationLedger,
    CapturePolicy,
)
from snapquiz.capture.validation import (
    BLACK_LUMA_MAX,
    MIN_VISIBLE_LUMA_SPAN,
    CaptureArtifactFactory,
    InputValidator,
    ValidatedCapture,
)
from snapquiz.core.permissions import ScreenPermissionState
from snapquiz.domain.capture import CaptureArtifact, CaptureRect
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import (
    CaptureError,
    EndpointPolicyError,
    PayloadTooLargeError,
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


PRE_CAPTURE_TIME = NOW + timedelta(seconds=1)
CAPTURED_TIME = NOW + timedelta(seconds=2)
POST_CAPTURE_TIME = NOW + timedelta(seconds=3)
OTHER_REQUEST_ID = UUID("20000000-0000-0000-0000-000000000001")
OTHER_CAPTURE_ID = UUID("20000000-0000-0000-0000-000000000004")

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk(chunk_type: bytes, payload: bytes) -> bytes:
    checksum = binascii.crc32(chunk_type)
    checksum = binascii.crc32(payload, checksum) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(payload))
        + chunk_type
        + payload
        + struct.pack(">I", checksum)
    )


def _channel_count(color_type: int) -> int:
    return {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)


def _default_pixels(width: int, height: int, color_type: int) -> bytes:
    channels = _channel_count(color_type)
    pixels = bytearray()
    for index in range(width * height):
        value = 255 if index % 2 else 0
        if color_type == 6:
            pixels.extend((value, value, value, 255))
        else:
            pixels.extend((value,) * channels)
    return bytes(pixels)


def _filter_predictor(
    filter_type: int,
    *,
    left: int,
    up: int,
    upper_left: int,
) -> int:
    if filter_type == 0:
        return 0
    if filter_type == 1:
        return left
    if filter_type == 2:
        return up
    if filter_type == 3:
        return (left + up) // 2
    if filter_type != 4:
        raise ValueError("unsupported test PNG filter")
    prediction = left + up - upper_left
    distances = (
        (abs(prediction - left), left),
        (abs(prediction - up), up),
        (abs(prediction - upper_left), upper_left),
    )
    return min(distances, key=lambda item: item[0])[1]


def _encode_filtered_row(
    row: bytes,
    previous_row: bytes,
    *,
    channels: int,
    filter_type: int,
) -> bytes:
    encoded = bytearray(len(row))
    for index, value in enumerate(row):
        left = row[index - channels] if index >= channels else 0
        up = previous_row[index]
        upper_left = (
            previous_row[index - channels] if index >= channels else 0
        )
        predictor = _filter_predictor(
            filter_type,
            left=left,
            up=up,
            upper_left=upper_left,
        )
        encoded[index] = (value - predictor) & 0xFF
    return bytes(encoded)


def _png(
    *,
    width: int = 4,
    height: int = 2,
    color_type: int = 2,
    bit_depth: int = 8,
    interlace: int = 0,
    pixels: bytes | None = None,
    extra_chunks: tuple[tuple[bytes, bytes], ...] = (),
    decompressed_suffix: bytes = b"",
    compressed_suffix: bytes = b"",
    trailing: bytes = b"",
    filter_type: int = 0,
) -> bytes:
    channels = _channel_count(color_type)
    pixel_bytes = (
        _default_pixels(width, height, color_type)
        if pixels is None
        else pixels
    )
    expected_length = width * height * channels
    if len(pixel_bytes) != expected_length:
        raise ValueError("pixels do not match width, height and color type")
    rows = []
    row_size = width * channels
    previous_row = bytes(row_size)
    for row_index in range(height):
        start = row_index * row_size
        row = pixel_bytes[start : start + row_size]
        rows.append(
            bytes((filter_type,))
            + _encode_filtered_row(
                row,
                previous_row,
                channels=channels,
                filter_type=filter_type,
            )
        )
        previous_row = row
    raw = b"".join(rows) + decompressed_suffix
    ihdr = struct.pack(
        ">IIBBBBB",
        width,
        height,
        bit_depth,
        color_type,
        0,
        0,
        interlace,
    )
    compressed = zlib.compress(raw) + compressed_suffix
    return (
        _PNG_SIGNATURE
        + _chunk(b"IHDR", ihdr)
        + b"".join(_chunk(kind, payload) for kind, payload in extra_chunks)
        + _chunk(b"IDAT", compressed)
        + _chunk(b"IEND", b"")
        + trailing
    )


def _gray_pixels(
    values: tuple[int, ...],
    *,
    width: int = 4,
    height: int = 2,
) -> bytes:
    if not values:
        raise ValueError("values must be non-empty")
    result = bytearray()
    for index in range(width * height):
        value = values[index % len(values)]
        result.extend((value, value, value))
    return bytes(result)


def _rgba_pixels(
    values: tuple[tuple[int, int, int, int], ...],
    *,
    width: int = 4,
    height: int = 2,
) -> bytes:
    if not values:
        raise ValueError("values must be non-empty")
    result = bytearray()
    for index in range(width * height):
        result.extend(values[index % len(values)])
    return bytes(result)


def _prepared_attempt() -> SimpleNamespace:
    initial_topology = topology()
    scope = selected_scope(
        initial_topology,
        rect=CaptureRect(left=20, top=30, width=4, height=2),
    )
    planned = planned_execution(initial_topology)
    consent_ledger, privacy = privacy_authorization(
        planned,
        scope_fingerprint=scope.fingerprint,
    )
    capture_ledger = CaptureAuthorizationLedger()
    authorization = CapturePolicy().authorize(
        planned=planned,
        privacy_authorization=privacy,
        consent_ledger=consent_ledger,
        permission_observation=granted_permission(),
        topology=initial_topology,
        selected_scope=scope,
        capture_id=CAPTURE_ID,
        capture_ledger=capture_ledger,
        now=NOW,
    )
    consumed = CapturePolicy().prepare_capture(
        planned=planned,
        privacy_authorization=privacy,
        consent_ledger=consent_ledger,
        authorization=authorization,
        capture_ledger=capture_ledger,
        permission_observation=granted_permission(
            observed_at=PRE_CAPTURE_TIME
        ),
        topology=topology(observed_at=PRE_CAPTURE_TIME),
        now=PRE_CAPTURE_TIME,
    )
    return SimpleNamespace(
        initial_topology=initial_topology,
        scope=scope,
        planned=planned,
        consent_ledger=consent_ledger,
        privacy=privacy,
        capture_ledger=capture_ledger,
        authorization=authorization,
        consumed=consumed,
    )


def _materialize(
    attempt: SimpleNamespace,
    data: bytes,
    *,
    mime_type: str = "image/png",
    width_px: int = 4,
    height_px: int = 2,
    captured_at: datetime = CAPTURED_TIME,
) -> CaptureArtifact:
    return CaptureArtifactFactory.create(
        consumed=attempt.consumed,
        capture_ledger=attempt.capture_ledger,
        data=data,
        mime_type=mime_type,
        width_px=width_px,
        height_px=height_px,
        captured_at=captured_at,
    )


def _rewrite_consumption_proof(attempt: SimpleNamespace) -> tuple[object, ...]:
    consumed = attempt.consumed
    original = (
        consumed.consumed_at,
        consumed.pre_capture_permission_observation_digest,
        consumed.pre_capture_topology_snapshot_digest,
        consumed.consumption_digest,
    )
    rewritten_time = consumed.consumed_at + timedelta(microseconds=1)
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
                    attempt.authorization.capture_authorization_id
                ),
                "capture_authorization_digest": (
                    attempt.authorization.capture_authorization_digest
                ),
                "consumed_at": rewritten_time,
                "pre_capture_permission_observation_digest": (
                    rewritten_permission
                ),
                "pre_capture_topology_snapshot_digest": rewritten_topology,
            },
        ),
    )
    consumed.validate_integrity()
    return original


def _restore_consumption_proof(
    attempt: SimpleNamespace,
    original: tuple[object, ...],
) -> None:
    consumed = attempt.consumed
    for name, value in zip(
        (
            "consumed_at",
            "pre_capture_permission_observation_digest",
            "pre_capture_topology_snapshot_digest",
            "consumption_digest",
        ),
        original,
        strict=True,
    ):
        object.__setattr__(consumed, name, value)
    consumed.validate_integrity()


def _validate(
    attempt: SimpleNamespace,
    artifact: CaptureArtifact,
    *,
    planned=None,
    privacy=None,
    consent_ledger=None,
    permission=None,
    current_topology=None,
    now: datetime = POST_CAPTURE_TIME,
) -> ValidatedCapture:
    return InputValidator.validate(
        planned=attempt.planned if planned is None else planned,
        privacy_authorization=(
            attempt.privacy if privacy is None else privacy
        ),
        consent_ledger=(
            attempt.consent_ledger
            if consent_ledger is None
            else consent_ledger
        ),
        consumed=attempt.consumed,
        capture_ledger=attempt.capture_ledger,
        artifact=artifact,
        permission_observation=(
            granted_permission(observed_at=now)
            if permission is None
            else permission
        ),
        topology=(
            topology(observed_at=now)
            if current_topology is None
            else current_topology
        ),
        now=now,
    )


class CanonicalPngValidationTest(unittest.TestCase):
    def assert_png_rejected(
        self,
        data: bytes,
        expected_error: type[BaseException] = CaptureError,
    ) -> None:
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, data)
        with self.assertRaises(expected_error):
            _validate(attempt, artifact)

    def test_canonical_rgb_and_rgba_png_succeed(self):
        images = (
            _png(color_type=2),
            _png(
                color_type=6,
                pixels=_rgba_pixels(
                    (
                        (0, 0, 0, 255),
                        (255, 255, 255, 255),
                        (64, 64, 64, 255),
                    )
                ),
            ),
        )
        for data in images:
            with self.subTest(color_type=data[25]):
                attempt = _prepared_attempt()
                artifact = _materialize(attempt, data)
                validated = _validate(attempt, artifact)
                self.assertIs(validated.artifact, artifact)
                validated.validate_integrity()
                validated.release()

    def test_sub_up_average_and_paeth_filters_succeed(self):
        for filter_type in (1, 2, 3, 4):
            with self.subTest(filter_type=filter_type):
                attempt = _prepared_attempt()
                artifact = _materialize(
                    attempt,
                    _png(filter_type=filter_type),
                )
                validated = _validate(attempt, artifact)
                validated.validate_integrity()
                validated.release()

    def test_signature_crc_truncation_and_noncanonical_chunks_are_rejected(self):
        valid = _png()
        corrupt_crc = bytearray(valid)
        corrupt_crc[-1] ^= 1
        cases = {
            "signature": b"X" + valid[1:],
            "crc": bytes(corrupt_crc),
            "truncated": valid[:-1],
            "unknown_ancillary": _png(
                extra_chunks=((b"tEXt", b"key\x00value"),)
            ),
            "apng": _png(
                extra_chunks=((b"acTL", struct.pack(">II", 1, 0)),)
            ),
            "trailing": _png(trailing=b"unexpected"),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                self.assert_png_rejected(data)

    def test_interlace_bit_depth_and_color_type_are_rejected(self):
        cases = {
            "interlace": _png(interlace=1),
            "bit_depth": _png(bit_depth=16),
            "grayscale": _png(color_type=0),
            "indexed": _png(color_type=3),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                self.assert_png_rejected(data)

    def test_zlib_trailing_data_and_decompressed_overrun_are_rejected(self):
        self.assert_png_rejected(_png(compressed_suffix=b"trailing"))
        self.assert_png_rejected(
            _png(decompressed_suffix=b"\x00"),
            PayloadTooLargeError,
        )

        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        with (
            patch(
                "snapquiz.capture.validation.MAX_CANONICAL_DECODED_BYTES",
                25,
            ),
            self.assertRaises(PayloadTooLargeError),
        ):
            _validate(attempt, artifact)

    def test_real_png_dimensions_must_match_metadata_and_scope(self):
        attempt = _prepared_attempt()
        with self.assertRaises(CaptureError):
            _materialize(
                attempt,
                _png(width=3, height=2),
                width_px=3,
                height_px=2,
            )

        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png(width=3, height=2))
        with self.assertRaises(CaptureError):
            _validate(attempt, artifact)

    def test_black_blank_transparent_and_luma_thresholds(self):
        rejected = {
            "black": _png(
                pixels=_gray_pixels((0, BLACK_LUMA_MAX))
            ),
            "blank": _png(pixels=_gray_pixels((200,))),
            "all_transparent": _png(
                color_type=6,
                pixels=_rgba_pixels(
                    ((0, 0, 0, 0), (255, 255, 255, 0))
                ),
            ),
            "alpha_1": _png(
                color_type=6,
                pixels=_rgba_pixels(
                    ((0, 0, 0, 1), (255, 255, 255, 1))
                ),
            ),
            "alpha_254": _png(
                color_type=6,
                pixels=_rgba_pixels(
                    ((0, 0, 0, 254), (255, 255, 255, 254))
                ),
            ),
            "below_span_threshold": _png(
                pixels=_gray_pixels(
                    (20, 20 + MIN_VISIBLE_LUMA_SPAN - 1)
                )
            ),
        }
        for name, data in rejected.items():
            with self.subTest(name=name):
                self.assert_png_rejected(data)

        attempt = _prepared_attempt()
        boundary = _png(
            pixels=_gray_pixels((20, 20 + MIN_VISIBLE_LUMA_SPAN))
        )
        validated = _validate(attempt, _materialize(attempt, boundary))
        self.assertFalse(validated.is_released)
        validated.release()


class CaptureArtifactFactoryTest(unittest.TestCase):
    def test_factory_is_png_only_and_enforces_scope_time_and_byte_limits(self):
        valid = _png()
        invalid_calls = (
            {"data": valid, "mime_type": "image/jpeg"},
            {"data": valid, "width_px": 3},
            {"data": valid, "height_px": 3},
            {
                "data": valid,
                "captured_at": PRE_CAPTURE_TIME - timedelta(microseconds=1),
            },
            {
                "data": valid,
                "captured_at": NOW + timedelta(hours=1),
            },
        )
        for arguments in invalid_calls:
            with self.subTest(arguments=arguments):
                attempt = _prepared_attempt()
                with self.assertRaises(CaptureError):
                    _materialize(attempt, **arguments)
                self.assertTrue(
                    attempt.capture_ledger.safe_capture_metadata(
                        consumed=attempt.consumed
                    )["artifact_attempted"]
                )
                self.assertIsNone(
                    attempt.capture_ledger.safe_capture_metadata(
                        consumed=attempt.consumed
                    )[
                        "artifact_claim_digest_prefix"
                    ]
                )
                with self.assertRaises(CaptureError):
                    _materialize(attempt, valid)

        attempt = _prepared_attempt()
        oversized = b"x" * (attempt.authorization.constraints.max_bytes + 1)
        with self.assertRaises(PayloadTooLargeError):
            _materialize(attempt, oversized)
        self.assertTrue(
            attempt.capture_ledger.safe_capture_metadata(
                consumed=attempt.consumed
            )["artifact_attempted"]
        )
        self.assertIsNone(
            attempt.capture_ledger.safe_capture_metadata(
                consumed=attempt.consumed
            )[
                "artifact_claim_digest_prefix"
            ]
        )
        with self.assertRaises(CaptureError):
            _materialize(attempt, valid)

        attempt = _prepared_attempt()
        artifact = _materialize(attempt, valid)
        self.assertEqual(artifact.id, CAPTURE_ID)
        self.assertIs(artifact.scope, attempt.scope)
        self.assertEqual(artifact.data, valid)
        self.assertIsNotNone(
            attempt.capture_ledger.safe_capture_metadata(
                consumed=attempt.consumed
            )[
                "artifact_claim_digest_prefix"
            ]
        )

    def test_concurrent_factory_materialization_has_exactly_one_winner(self):
        attempt = _prepared_attempt()
        data = _png()
        barrier = Barrier(3)
        result_lock = Lock()
        outcomes: list[str] = []

        def materialize() -> None:
            barrier.wait()
            try:
                _materialize(attempt, data)
            except CaptureError:
                outcome = "rejected"
            else:
                outcome = "materialized"
            with result_lock:
                outcomes.append(outcome)

        threads = (Thread(target=materialize), Thread(target=materialize))
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

        self.assertCountEqual(outcomes, ("materialized", "rejected"))
        self.assertIsNotNone(
            attempt.capture_ledger.safe_capture_metadata(
                consumed=attempt.consumed
            )[
                "artifact_claim_digest_prefix"
            ]
        )

    def test_returned_proof_cannot_reset_ledger_attempt_state(self):
        attempt = _prepared_attempt()
        with self.assertRaises(CaptureError):
            _materialize(attempt, b"")
        with self.assertRaises(AttributeError):
            object.__setattr__(attempt.consumed, "_artifact_attempted", False)
        with self.assertRaises(CaptureError):
            _materialize(attempt, _png())

    def test_rewritten_consumption_proof_cannot_materialize_artifact(self):
        attempt = _prepared_attempt()
        original = _rewrite_consumption_proof(attempt)

        with self.assertRaises(CaptureError):
            _materialize(attempt, _png())
        _restore_consumption_proof(attempt, original)
        self.assertFalse(
            attempt.capture_ledger.safe_capture_metadata(
                consumed=attempt.consumed
            )["artifact_attempted"]
        )
        self.assertEqual(_materialize(attempt, _png()).id, CAPTURE_ID)

    def test_consumption_proof_cannot_alias_another_ledger_entry(self):
        attempt_a = _prepared_attempt()
        policy = CapturePolicy()
        authorization_b = policy.authorize(
            planned=attempt_a.planned,
            privacy_authorization=attempt_a.privacy,
            consent_ledger=attempt_a.consent_ledger,
            permission_observation=granted_permission(),
            topology=attempt_a.initial_topology,
            selected_scope=attempt_a.scope,
            capture_id=OTHER_CAPTURE_ID,
            capture_ledger=attempt_a.capture_ledger,
            now=NOW,
        )
        consumed_b = policy.prepare_capture(
            planned=attempt_a.planned,
            privacy_authorization=attempt_a.privacy,
            consent_ledger=attempt_a.consent_ledger,
            authorization=authorization_b,
            capture_ledger=attempt_a.capture_ledger,
            permission_observation=granted_permission(
                observed_at=PRE_CAPTURE_TIME
            ),
            topology=topology(observed_at=PRE_CAPTURE_TIME),
            now=PRE_CAPTURE_TIME,
        )
        consumed_a = attempt_a.consumed
        for name in (
            "authorization",
            "consumed_at",
            "pre_capture_permission_observation_digest",
            "pre_capture_topology_snapshot_digest",
            "consumption_digest",
        ):
            object.__setattr__(
                consumed_a,
                name,
                getattr(consumed_b, name),
            )
        consumed_a.validate_integrity()

        with self.assertRaises(CaptureError):
            _materialize(attempt_a, _png())
        attempt_b = SimpleNamespace(
            consumed=consumed_b,
            capture_ledger=attempt_a.capture_ledger,
        )
        artifact_b = _materialize(attempt_b, _png())
        self.assertEqual(artifact_b.id, OTHER_CAPTURE_ID)

    def test_wrong_ledger_cannot_materialize_or_burn_owner_state(self):
        attempt = _prepared_attempt()
        wrong_ledger = CaptureAuthorizationLedger()
        with self.assertRaises(CaptureError):
            CaptureArtifactFactory.create(
                consumed=attempt.consumed,
                capture_ledger=wrong_ledger,
                data=_png(),
                mime_type="image/png",
                width_px=4,
                height_px=2,
                captured_at=CAPTURED_TIME,
            )
        artifact = _materialize(attempt, _png())
        self.assertEqual(artifact.id, CAPTURE_ID)


class InputValidatorContractTest(unittest.TestCase):
    def test_rewritten_consumption_proof_cannot_start_validation(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        original = _rewrite_consumption_proof(attempt)

        with self.assertRaises(CaptureError):
            _validate(attempt, artifact)
        _restore_consumption_proof(attempt, original)
        self.assertFalse(
            attempt.capture_ledger.safe_capture_metadata(
                consumed=attempt.consumed
            )["validation_attempted"]
        )
        validated = _validate(attempt, artifact)
        validated.release()

    def test_wrong_ledger_cannot_validate_or_burn_owner_state(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        with self.assertRaises(CaptureError):
            InputValidator.validate(
                planned=attempt.planned,
                privacy_authorization=attempt.privacy,
                consent_ledger=attempt.consent_ledger,
                consumed=attempt.consumed,
                capture_ledger=CaptureAuthorizationLedger(),
                artifact=artifact,
                permission_observation=granted_permission(
                    observed_at=POST_CAPTURE_TIME
                ),
                topology=topology(observed_at=POST_CAPTURE_TIME),
                now=POST_CAPTURE_TIME,
            )
        validated = _validate(attempt, artifact)
        validated.release()

    def test_post_capture_permission_is_rechecked(self):
        observations = (
            permission_observation(
                ScreenPermissionState.DENIED,
                observed_at=POST_CAPTURE_TIME,
            ),
            permission_observation(
                ScreenPermissionState.UNKNOWN,
                observed_at=POST_CAPTURE_TIME,
            ),
            granted_permission(
                observed_at=POST_CAPTURE_TIME - timedelta(microseconds=1)
            ),
        )
        for observation in observations:
            with self.subTest(state=observation.state):
                attempt = _prepared_attempt()
                artifact = _materialize(attempt, _png())
                with self.assertRaises(PermissionDeniedError):
                    _validate(
                        attempt,
                        artifact,
                        permission=observation,
                    )

    def test_post_capture_topology_is_rechecked(self):
        topologies = (
            topology(
                observed_at=POST_CAPTURE_TIME
                - timedelta(microseconds=1)
            ),
            topology(
                observed_at=POST_CAPTURE_TIME,
                primary_pixel_width=2_561,
            ),
        )
        for current_topology in topologies:
            with self.subTest(revision=current_topology.topology_revision):
                attempt = _prepared_attempt()
                artifact = _materialize(attempt, _png())
                with self.assertRaises(CaptureError):
                    _validate(
                        attempt,
                        artifact,
                        current_topology=current_topology,
                    )

    def test_post_capture_privacy_revocation_is_rechecked(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        attempt.consent_ledger.revoke(
            grant_id=attempt.privacy.consent_grant_ids[0],
            revoked_at=CAPTURED_TIME,
        )

        with self.assertRaises(EndpointPolicyError):
            _validate(attempt, artifact)

    def test_revocation_during_validation_prevents_lease_issuance(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        original_decode = capture_validation_module._decode_bounded_png
        revoked = False

        def decode_then_revoke(**kwargs):
            nonlocal revoked
            inspection = original_decode(**kwargs)
            if not revoked:
                attempt.consent_ledger.revoke(
                    grant_id=attempt.privacy.consent_grant_ids[0],
                    revoked_at=POST_CAPTURE_TIME,
                )
                revoked = True
            return inspection

        with (
            patch.object(
                capture_validation_module,
                "_decode_bounded_png",
                side_effect=decode_then_revoke,
            ),
            self.assertRaises(EndpointPolicyError),
        ):
            _validate(attempt, artifact)
        state = attempt.capture_ledger.safe_capture_metadata(
            consumed=attempt.consumed
        )
        self.assertTrue(state["validation_attempted"])
        self.assertFalse(state["validated"])

    def test_atomic_validation_linearizes_before_concurrent_revocation(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        validation_entered = Event()
        allow_validation = Event()
        revoke_started = Event()
        revoke_finished = Event()
        leases: list[ValidatedCapture] = []
        errors: list[BaseException] = []
        original_complete = CaptureAuthorizationLedger._complete_validation

        def blocking_complete(ledger, **kwargs):
            validation_entered.set()
            if not allow_validation.wait(timeout=5):
                raise AssertionError("test did not release validation")
            return original_complete(ledger, **kwargs)

        def validate() -> None:
            try:
                leases.append(_validate(attempt, artifact))
            except BaseException as error:  # pragma: no cover - assertion path
                errors.append(error)

        def revoke() -> None:
            revoke_started.set()
            try:
                attempt.consent_ledger.revoke(
                    grant_id=attempt.privacy.consent_grant_ids[0],
                    revoked_at=POST_CAPTURE_TIME,
                )
            except BaseException as error:  # pragma: no cover - assertion path
                errors.append(error)
            finally:
                revoke_finished.set()

        with patch.object(
            CaptureAuthorizationLedger,
            "_complete_validation",
            new=blocking_complete,
        ):
            validation_thread = Thread(target=validate)
            validation_thread.start()
            self.assertTrue(validation_entered.wait(timeout=5))
            revoke_thread = Thread(target=revoke)
            revoke_thread.start()
            self.assertTrue(revoke_started.wait(timeout=5))
            self.assertFalse(revoke_finished.wait(timeout=0.1))
            allow_validation.set()
            validation_thread.join(timeout=5)
            revoke_thread.join(timeout=5)

        self.assertFalse(validation_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(leases), 1)
        state = attempt.capture_ledger.safe_capture_metadata(
            consumed=attempt.consumed
        )
        self.assertTrue(state["validated"])
        leases[0].release()

    def test_capture_authorization_must_match_current_plan(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        other_planned = planned_execution(
            attempt.initial_topology,
            request_id=OTHER_REQUEST_ID,
        )
        other_ledger, other_privacy = privacy_authorization(other_planned)

        with self.assertRaises(CaptureError):
            _validate(
                attempt,
                artifact,
                planned=other_planned,
                privacy=other_privacy,
                consent_ledger=other_ledger,
            )

    def test_validator_rejects_artifact_not_returned_by_factory(self):
        attempt = _prepared_attempt()
        original = _materialize(attempt, _png())
        substitute_data = _png(
            pixels=_gray_pixels((32, 224)),
        )
        self.assertNotEqual(original.data, substitute_data)
        substitute = CaptureArtifact(
            id=original.id,
            data=substitute_data,
            mime_type=original.mime_type,
            width_px=original.width_px,
            height_px=original.height_px,
            scope=original.scope,
            captured_at=original.captured_at,
        )

        with self.assertRaises(CaptureError):
            _validate(attempt, substitute)

    def test_validator_rejects_same_hash_with_different_metadata(self):
        attempt = _prepared_attempt()
        original = _materialize(attempt, _png())
        substitute = CaptureArtifact(
            id=original.id,
            data=original.data,
            mime_type=original.mime_type,
            width_px=original.width_px,
            height_px=original.height_px,
            scope=original.scope,
            captured_at=original.captured_at + timedelta(microseconds=1),
        )
        self.assertEqual(original.sha256, substitute.sha256)
        self.assertNotEqual(original.captured_at, substitute.captured_at)

        with self.assertRaises(CaptureError):
            _validate(attempt, substitute)

    def test_only_one_validated_lease_can_be_issued(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        validated = _validate(attempt, artifact)
        with self.assertRaises(AttributeError):
            object.__setattr__(attempt.consumed, "_validation_claimed", False)
        with self.assertRaises(CaptureError):
            _validate(attempt, artifact)
        validated.release()

    def test_concurrent_validation_has_exactly_one_winner(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        barrier = Barrier(3)
        result_lock = Lock()
        outcomes: list[str] = []
        leases: list[ValidatedCapture] = []

        def validate() -> None:
            barrier.wait()
            try:
                lease = _validate(attempt, artifact)
            except CaptureError:
                outcome = "rejected"
            else:
                outcome = "validated"
                leases.append(lease)
            with result_lock:
                outcomes.append(outcome)

        threads = (Thread(target=validate), Thread(target=validate))
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

        self.assertCountEqual(outcomes, ("validated", "rejected"))
        self.assertEqual(len(leases), 1)
        leases[0].release()

    def test_release_and_context_manager_drop_the_artifact_reference(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        validated = _validate(attempt, artifact)

        self.assertIs(validated.artifact, artifact)
        self.assertTrue(validated.release())
        self.assertFalse(validated.release())
        self.assertTrue(validated.is_released)
        with self.assertRaises(CaptureError):
            _ = validated.artifact
        validated.validate_integrity()

        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        validated = _validate(attempt, artifact)
        with self.assertRaisesRegex(RuntimeError, "test cleanup"):
            with validated as active:
                self.assertIs(active.artifact, artifact)
                raise RuntimeError("test cleanup")
        self.assertTrue(validated.is_released)
        with self.assertRaises(CaptureError):
            _ = validated.artifact

    def test_repr_asdict_vars_and_safe_metadata_do_not_leak_image_bytes(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        validated = _validate(attempt, artifact)

        representation = repr(validated)
        metadata = validated.safe_metadata()
        self.assertNotIn(repr(artifact.data), representation)
        self.assertNotIn(str(artifact.sha256), representation)
        self.assertNotIn(str(validated.validation_digest), representation)
        self.assertNotIn(artifact.data, metadata.values())
        self.assertNotIn(str(artifact.sha256), metadata.values())
        self.assertNotIn(
            str(validated.validation_digest),
            metadata.values(),
        )
        with self.assertRaises(TypeError):
            asdict(validated)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            vars(validated)
        validated.release()


class W06GoldenVectorTest(unittest.TestCase):
    def test_end_to_end_authority_and_validation_digests_are_fixed(self):
        attempt = _prepared_attempt()
        artifact = _materialize(attempt, _png())
        validated = _validate(attempt, artifact)

        expected = {
            "permission_observation_digest": (
                "561e71a5d080e6981e6be6bbb7b64991"
                "ad2adc6a9da107b945fb1002d20e1831"
            ),
            "topology_revision": (
                "44427e62ca3bcb355264ee5b0f65d18c"
                "cfbf0582114990a6cf215f659c3f058a"
            ),
            "topology_snapshot_digest": (
                "baba2b8e73c64065dc05269574a7071a"
                "43428b82789abf7e2339f8f50e59c645"
            ),
            "scope_fingerprint": (
                "7de10e3855b0a350ddb932963551f9df"
                "9862e8ecb6fe63e2d1d9f5dd970755ad"
            ),
            "capture_authorization_id": (
                "b373057b-417e-584b-bc7f-a2a07689d3b2"
            ),
            "capture_authorization_digest": (
                "389407e6ee86dc1eba1eba3926e6501a"
                "05eb8ffc851df5246640a39aefa25251"
            ),
            "consumption_digest": (
                "58234d733ae66d1b65c588f32e1d7ab"
                "3f420be6ae5cec26b158c05c376331032"
            ),
            "artifact_sha256": (
                "5589c8bdac912d404d5fb722a09eefad"
                "0a68bae711f7d5748508bacc0fbdb50c"
            ),
            "validation_digest": (
                "830c5b457dd21d4166ce8ba8ab341a7f"
                "f03c8528dd4dbf07da2b5cde1c987b73"
            ),
        }
        actual = {
            "permission_observation_digest": str(
                attempt.authorization.permission_observation_digest
            ),
            "topology_revision": str(
                attempt.initial_topology.topology_revision
            ),
            "topology_snapshot_digest": str(
                attempt.initial_topology.snapshot_digest
            ),
            "scope_fingerprint": str(attempt.scope.fingerprint),
            "capture_authorization_id": str(
                attempt.authorization.capture_authorization_id
            ),
            "capture_authorization_digest": str(
                attempt.authorization.capture_authorization_digest
            ),
            "consumption_digest": str(attempt.consumed.consumption_digest),
            "artifact_sha256": str(artifact.sha256),
            "validation_digest": str(validated.validation_digest),
        }
        self.assertEqual(actual, expected)
        validated.release()


class CaptureValidationImportPurityTest(unittest.TestCase):
    def test_import_has_no_quartz_sdk_or_network_side_effect(self):
        repository_root = Path(__file__).resolve().parents[1]
        script = r'''
import builtins
import socket
import sys

blocked_roots = {
    "Quartz", "mss", "openai", "anthropic", "httpx", "requests"
}
original_import = builtins.__import__

def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.split(".", 1)[0] in blocked_roots:
        raise AssertionError(f"forbidden import: {name}")
    return original_import(name, globals, locals, fromlist, level)

def forbidden_network(*args, **kwargs):
    raise AssertionError("network access during import")

builtins.__import__ = guarded_import
socket.socket = forbidden_network
socket.create_connection = forbidden_network

import snapquiz.capture.validation

assert "Quartz" not in sys.modules
assert not blocked_roots.intersection(sys.modules)
'''
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(repository_root),
        }
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repository_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
