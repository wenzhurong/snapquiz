"""Offline W09-B3 exact HTTP/1.1 codec tests."""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import pickle
import re
from types import TracebackType
import unittest
from unittest import mock

from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.domain.outbound import NonSecretHeader, PreparedOutbound
from snapquiz.transport import _exact_http1 as http1

from tests.w09_helpers import make_w09_runtime


def _prepared(
    *,
    body: bytes | None = None,
    headers: tuple[NonSecretHeader, ...] | None = None,
    url: str | None = None,
) -> PreparedOutbound:
    original = make_w09_runtime().prepared
    return PreparedOutbound(
        plan_id=original.plan_id,
        plan_digest=original.plan_digest,
        stage_id=original.stage_id,
        operation_id=original.operation_id,
        source_ids=original.source_ids,
        source_digests=original.source_digests,
        capture_scope_fingerprint=original.capture_scope_fingerprint,
        http_method=original.http_method,
        canonical_url=original.canonical_url if url is None else url,
        content_type=original.content_type,
        non_secret_headers=(
            original.non_secret_headers if headers is None else headers
        ),
        credential_binding_digest=original.credential_binding_digest,
        outbound_data=original.outbound_data,
        body=original.body if body is None else body,
    )


def _token(value: bytes = b"test-token_123=") -> memoryview:
    return memoryview(bytearray(value)).toreadonly()


def _discard_request(request: memoryview) -> None:
    del request


def _parse(frame: bytes, cuts: tuple[int, ...] = ()):
    parser = http1._new_exact_http1_response_parser()
    previous = 0
    result = http1._PENDING
    for cut in cuts + (len(frame),):
        result = parser.feed(frame[previous:cut])
        previous = cut
    return parser, result


def _assert_safe_error(case: unittest.TestCase, error: BaseException) -> None:
    case.assertIs(type(error), EndpointPolicyError)
    case.assertEqual(error.stage, "http1_transport")
    case.assertFalse(error.retryable)
    case.assertIsNone(error.__cause__)
    case.assertIsNone(error.__context__)


class _TrackingBuffer(bytearray):
    def __init__(self) -> None:
        super().__init__()
        self.maximum_extension = 0

    def extend(self, value: object) -> None:
        self.maximum_extension = max(
            self.maximum_extension,
            len(value),  # type: ignore[arg-type]
        )
        super().extend(value)  # type: ignore[arg-type]


class ExactHttp1CodecTest(unittest.TestCase):
    def test_module_is_private_and_network_free(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_exact_http1.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
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
        self.assertNotIn("socket", imported)
        self.assertNotIn("ssl", imported)
        self.assertNotIn("os", imported)
        self.assertEqual(http1.__all__, ())

    def test_policy_digest_addresses_versions_limits_and_exact_regexes(self):
        payload = http1._exact_http1_policy_payload()
        declared_limits = {
            name
            for name, value in vars(http1).items()
            if name.startswith("MAX_") and type(value) is int
        }
        self.assertEqual(set(payload["limits"]), declared_limits)
        self.assertEqual(
            payload["policy_version"],
            http1.EXACT_HTTP1_POLICY_VERSION,
        )
        regex_names = {
            "_CHUNK_SIZE_RE",
            "_HOST_RE",
            "_STATUS_LINE_RE",
            "_TOKEN_RE",
        }
        self.assertEqual(set(payload["regex_contracts"]), regex_names)
        for name in regex_names:
            compiled = getattr(http1, name)
            self.assertIs(type(compiled), re.Pattern)
            binding = payload["regex_contracts"][name]
            self.assertEqual(binding["flags"], compiled.flags)
            if type(compiled.pattern) is bytes:
                self.assertEqual(binding["pattern_kind"], "bytes")
                self.assertEqual(binding["pattern"], compiled.pattern.hex())
            else:
                self.assertIs(type(compiled.pattern), str)
                self.assertEqual(binding["pattern_kind"], "text")
                self.assertEqual(binding["pattern"], compiled.pattern)
        selected = digest256(
            "ExactHttp1Policy",
            http1.EXACT_HTTP1_POLICY_SCHEMA_VERSION,
            payload,
        )
        self.assertIs(type(selected), Digest256)
        self.assertEqual(selected, http1.EXACT_HTTP1_POLICY_DIGEST)
        self.assertEqual(
            str(selected),
            "16a5bc342f274e1d893a26de9417e75ead96b5cd2f06969faf09c6aba8a4d13c",
        )
        self.assertEqual(
            http1._require_exact_http1_policy_digest(),
            selected,
        )

        for name in (
            "EXACT_HTTP1_POLICY_SCHEMA_VERSION",
            "EXACT_HTTP1_POLICY_VERSION",
            *sorted(declared_limits),
        ):
            original = getattr(http1, name)
            drifted = original + ".drift" if type(original) is str else original + 1
            with self.subTest(name=name), mock.patch.object(
                http1,
                name,
                drifted,
            ), self.assertRaises(EndpointPolicyError) as raised:
                http1._require_exact_http1_policy_digest()
            _assert_safe_error(self, raised.exception)

        for name in sorted(regex_names):
            original = getattr(http1, name)
            suffix = b"(?:)" if type(original.pattern) is bytes else "(?:)"
            changed_pattern = re.compile(
                original.pattern + suffix,
                original.flags,
            )
            changed_flags = re.compile(
                original.pattern,
                original.flags | re.IGNORECASE,
            )
            for drift_kind, replacement in (
                ("pattern", changed_pattern),
                ("flags", changed_flags),
                ("type", object()),
            ):
                with self.subTest(
                    name=name,
                    drift_kind=drift_kind,
                ), mock.patch.object(
                    http1,
                    name,
                    replacement,
                ), self.assertRaises(EndpointPolicyError) as raised:
                    http1._require_exact_http1_policy_digest()
                _assert_safe_error(self, raised.exception)

    def test_http2_status_regex_replacement_is_rejected_before_parse(self):
        parser = http1._new_exact_http1_response_parser()
        http2_pattern = re.compile(
            rb"HTTP/2\.0 ([0-9]{3})(?: ([\x20-\x7e]*))?\Z"
        )
        frame = b"HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"

        with mock.patch.object(
            http1,
            "_STATUS_LINE_RE",
            http2_pattern,
        ), self.assertRaises(EndpointPolicyError) as raised:
            parser.feed(frame)

        _assert_safe_error(self, raised.exception)
        self.assertEqual(parser._state, http1._ParserState.FAILED)

    def test_policy_drift_blocks_request_and_parser_before_use(self):
        action = mock.Mock(
            side_effect=AssertionError("request action must stay dark")
        )
        with mock.patch.object(
            http1,
            "MAX_HTTP_HEADER_BYTES",
            http1.MAX_HTTP_HEADER_BYTES + 1,
        ):
            with self.assertRaises(EndpointPolicyError) as request_error:
                http1._encode_exact_http1_request(
                    prepared=_prepared(),
                    bearer_token=_token(),
                    action=action,
                )
            with self.assertRaises(EndpointPolicyError) as parser_error:
                http1._new_exact_http1_response_parser()
        _assert_safe_error(self, request_error.exception)
        _assert_safe_error(self, parser_error.exception)
        action.assert_not_called()

    def test_request_is_one_exact_identity_encoded_shape(self):
        prepared = _prepared()
        expected = bytearray(
            b"POST /api/paas/v4/chat/completions HTTP/1.1\r\n"
            b"host: open.bigmodel.cn\r\n"
            b"content-type: application/json\r\n"
            b"authorization: Bearer test-token_123=\r\n"
            b"accept-encoding: identity\r\n"
            b"connection: close\r\n"
            b"content-length: "
            + str(len(prepared.body)).encode("ascii")
            + b"\r\n\r\n"
            + prepared.body
        )
        captured_views: list[memoryview] = []
        captured_buffers: list[bytearray] = []

        def consume(request: memoryview) -> str:
            self.assertIs(type(request), memoryview)
            self.assertTrue(request.readonly)
            self.assertEqual(request, expected)
            self.assertIs(type(request.obj), bytearray)
            captured_views.append(request)
            captured_buffers.append(request.obj)
            return "consumed"

        try:
            result = http1._encode_exact_http1_request(
                prepared=prepared,
                bearer_token=_token(),
                action=consume,
            )
        finally:
            for index in range(len(expected)):
                expected[index] = 0
            expected.clear()
        self.assertEqual(result, "consumed")
        self.assertEqual(captured_buffers, [bytearray()])
        with self.assertRaises(ValueError):
            captured_views[0].tobytes()

    def test_request_rejects_credential_url_body_and_header_expansion(self):
        for invalid in (
            b"",
            b"white space",
            b"line\rbreak",
            b"x" * (http1.MAX_BEARER_TOKEN_BYTES + 1),
        ):
            with self.subTest(token=invalid[:8]):
                with self.assertRaises(ValueError):
                    http1._encode_exact_http1_request(
                        prepared=_prepared(),
                        bearer_token=_token(invalid),
                        action=_discard_request,
                    )
        with self.assertRaises(TypeError):
            http1._encode_exact_http1_request(
                prepared=_prepared(),
                bearer_token=b"secret",
                action=_discard_request,
            )
        for url in (
            "http://open.bigmodel.cn/api",
            "https://open.bigmodel.cn:444/api",
            "https://user@open.bigmodel.cn/api",
            "https://open.bigmodel.cn/api?q=1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                    http1._encode_exact_http1_request(
                        prepared=_prepared(url=url),
                        bearer_token=_token(),
                        action=_discard_request,
                    )
        with self.assertRaises(ValueError):
            http1._encode_exact_http1_request(
                prepared=_prepared(
                    body=b"x" * (http1.MAX_HTTP_REQUEST_BODY_BYTES + 1)
                ),
                bearer_token=_token(),
                action=_discard_request,
            )
        for name in ("authorization", "content-length", "expect", "host"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                http1._encode_exact_http1_request(
                    prepared=_prepared(
                        headers=(
                            NonSecretHeader(
                                lowercase_name=name,
                                normalized_value="x",
                            ),
                        )
                    ),
                    bearer_token=_token(),
                    action=_discard_request,
                )

    def test_request_rejects_content_encoding_before_borrowing_secret(self):
        for value in ("identity", "gzip"):
            called = False

            def consume(request: memoryview) -> None:
                nonlocal called
                called = True
                del request

            with self.subTest(value=value), self.assertRaises(ValueError):
                http1._encode_exact_http1_request(
                    prepared=_prepared(
                        headers=(
                            NonSecretHeader(
                                lowercase_name="content-encoding",
                                normalized_value=value,
                            ),
                        )
                    ),
                    bearer_token=_token(b"secret-must-not-be-copied"),
                    action=consume,
                )
            self.assertFalse(called)

    def test_request_finishes_all_non_secret_limits_before_token_validation(self):
        invalid_bearer = _token(b"contains a space")
        too_many = tuple(
            NonSecretHeader(
                lowercase_name=f"x-field-{index:03d}",
                normalized_value="v",
            )
            for index in range(123)
        )
        with self.assertRaisesRegex(ValueError, "header field limit"):
            http1._encode_exact_http1_request(
                prepared=_prepared(headers=too_many),
                bearer_token=invalid_bearer,
                action=_discard_request,
            )

        oversized_head = tuple(
            NonSecretHeader(
                lowercase_name=f"x-wide-{index:03d}",
                normalized_value="x" * 4_096,
            )
            for index in range(16)
        )
        with self.assertRaisesRegex(ValueError, "header byte limit"):
            http1._encode_exact_http1_request(
                prepared=_prepared(headers=oversized_head),
                bearer_token=invalid_bearer,
                action=_discard_request,
            )

    def test_request_callback_failure_zeros_buffer_and_retains_no_secret_copy(self):
        secret = b"synthetic-valid-secret-MUST-NOT-RETAIN"
        source = bytearray(secret)
        borrowed = memoryview(source).toreadonly()
        captured_buffers: list[bytearray] = []

        class CallbackFailure(Exception):
            pass

        def fail(request: memoryview) -> None:
            captured_buffers.append(request.obj)
            raise CallbackFailure

        try:
            http1._encode_exact_http1_request(
                prepared=_prepared(),
                bearer_token=borrowed,
                action=fail,
            )
        except CallbackFailure as error:
            traceback = error.__traceback__
            while traceback is not None:
                frame = traceback.tb_frame
                if frame.f_code.co_name == "_encode_exact_http1_request":
                    for value in frame.f_locals.values():
                        if type(value) in (bytes, bytearray):
                            self.assertNotIn(secret, value)
                traceback = traceback.tb_next
        else:
            self.fail("request callback did not fail")
        finally:
            borrowed.release()
            for index in range(len(source)):
                source[index] = 0
            source.clear()
        self.assertEqual(captured_buffers, [bytearray()])

    def test_request_callback_cannot_return_a_byte_bearing_escape(self):
        captured_buffers: list[bytearray] = []

        def copy_request(request: memoryview) -> bytes:
            captured_buffers.append(request.obj)
            return request.tobytes()

        with self.assertRaisesRegex(TypeError, "must not return byte-bearing"):
            http1._encode_exact_http1_request(
                prepared=_prepared(),
                bearer_token=_token(),
                action=copy_request,
            )
        self.assertEqual(captured_buffers, [bytearray()])

    def test_content_length_response_accepts_every_fragment_boundary(self):
        frame = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 7\r\n\r\n"
            b'{"a":1}'
        )
        for cut in range(len(frame) + 1):
            with self.subTest(cut=cut):
                parser, result = _parse(frame, (cut,))
                self.assertTrue(parser.is_complete)
                self.assertEqual(result.status, 200)
                self.assertEqual(result.body, b'{"a":1}')
                self.assertEqual(parser.finish_eof().body, b'{"a":1}')

    def test_chunked_response_accepts_bytewise_input_without_trailers(self):
        frame = (
            b"HTTP/1.1 503 Busy\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"
        )
        parser = http1._new_exact_http1_response_parser()
        result = http1._PENDING
        for byte in frame:
            result = parser.feed(bytes((byte,)))
        self.assertEqual(result.status, 503)
        self.assertEqual(result.body, b"abcdefg")
        self.assertTrue(parser.is_complete)

    def test_response_requires_exact_non_ambiguous_framing(self):
        invalid = (
            b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                b"Content-Length: 0\r\n\r\n"
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            ),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            (
                b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n"
                b"Content-Length: 0\r\n\r\n"
            ),
            b"HTTP/1.1 200 OK\r\n bad: fold\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
        )
        for frame in invalid:
            with self.subTest(frame=frame[:40]):
                parser = http1._new_exact_http1_response_parser()
                with self.assertRaises(EndpointPolicyError) as raised:
                    parser.feed(frame)
                _assert_safe_error(self, raised.exception)

    def test_response_rejects_limits_before_unbounded_growth(self):
        cases = (
            (
                b"HTTP/1.1 200 OK\r\nX: "
                + b"x" * http1.MAX_HTTP_LINE_BYTES
                + b"\r\nContent-Length: 0\r\n\r\n"
            ),
            (
                b"HTTP/1.1 200 OK\r\n"
                + b"X: y\r\n" * (http1.MAX_HTTP_HEADER_FIELDS + 1)
                + b"Content-Length: 0\r\n\r\n"
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(http1.MAX_HTTP_RESPONSE_BODY_BYTES + 1).encode("ascii")
                + b"\r\n\r\n"
            ),
        )
        for frame in cases:
            with self.subTest(size=len(frame)):
                with self.assertRaises(EndpointPolicyError):
                    http1._new_exact_http1_response_parser().feed(frame)

    def test_unterminated_header_line_fails_at_exact_incremental_limit(self):
        parser = http1._new_exact_http1_response_parser()
        prefix = b"HTTP/1.1 200 OK\r\nX: "
        legal_fragment = prefix + b"x" * (
            http1.MAX_HTTP_LINE_BYTES - len(b"X: ")
        )
        self.assertIs(parser.feed(legal_fragment), http1._PENDING)
        self.assertEqual(parser._header_scan_offset, len(parser._buffer))
        with self.assertRaises(EndpointPolicyError):
            parser.feed(b"x")

    def test_feed_never_copies_an_unbounded_input_record(self):
        parser = http1._new_exact_http1_response_parser()
        tracking = _TrackingBuffer()
        parser._buffer = tracking
        frame = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            + b"x" * (2 * http1.MAX_HTTP_HEADER_BYTES)
        )
        with self.assertRaises(EndpointPolicyError):
            parser.feed(frame)
        self.assertLessEqual(
            tracking.maximum_extension,
            http1.MAX_HTTP_HEADER_BYTES,
        )

    def test_long_decimal_content_length_is_version_independent_safe_failure(self):
        parser = http1._new_exact_http1_response_parser()
        frame = (
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + b"0" * 5_000
            + b"\r\n\r\n"
        )
        with self.assertRaises(EndpointPolicyError) as raised:
            parser.feed(frame)
        _assert_safe_error(self, raised.exception)
        self.assertEqual(parser._state, http1._ParserState.FAILED)
        self.assertEqual(parser._buffer, bytearray())

    def test_chunk_extensions_trailers_terminators_and_trailing_bytes_fail(self):
        invalid = (
            b"1;x=y\r\na\r\n0\r\n\r\n",
            b"1\r\naX\r\n0\r\n\r\n",
            b"0\r\nX-Trailer: y\r\n\r\n",
            b"0\r\n\r\nextra",
        )
        head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        for body in invalid:
            with self.subTest(body=body):
                with self.assertRaises(EndpointPolicyError):
                    http1._new_exact_http1_response_parser().feed(head + body)

    def test_chunk_count_and_metadata_limits_are_incremental(self):
        head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        too_many = b"1\r\nx\r\n" * (http1.MAX_HTTP_CHUNKS + 1)
        with self.assertRaises(EndpointPolicyError):
            http1._new_exact_http1_response_parser().feed(
                head + too_many + b"0\r\n\r\n"
            )
        parser = http1._new_exact_http1_response_parser()
        self.assertIs(parser.feed(head), http1._PENDING)
        for _ in range(8):
            self.assertIs(parser.feed(b"0000000000000001\r\nx\r\n"), http1._PENDING)
        self.assertLess(
            parser._chunk_metadata_bytes,
            http1.MAX_HTTP_CHUNK_METADATA_BYTES,
        )

    def test_eof_never_completes_an_incomplete_or_close_delimited_response(self):
        for frame in (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
        ):
            parser = http1._new_exact_http1_response_parser()
            self.assertIs(parser.feed(frame), http1._PENDING)
            with self.assertRaises(EndpointPolicyError):
                parser.finish_eof()

    def test_complete_parser_rejects_any_second_response_or_tail(self):
        frame = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        parser = http1._new_exact_http1_response_parser()
        result = parser.feed(frame)
        self.assertIs(parser.feed(b""), result)
        with self.assertRaises(EndpointPolicyError):
            parser.feed(frame)
        with self.assertRaises(EndpointPolicyError):
            http1._new_exact_http1_response_parser().feed(frame + b"x")

    def test_response_is_factory_only_immutable_and_content_addressed(self):
        frame = b"HTTP/1.1 204 Empty\r\nContent-Length: 0\r\n\r\n"
        _, response = _parse(frame)
        response.validate_integrity()
        self.assertIs(copy.copy(response), response)
        self.assertIs(copy.deepcopy(response), response)
        with self.assertRaises(TypeError):
            pickle.dumps(response)
        with self.assertRaises(AttributeError):
            response.status = 200
        with self.assertRaises(TypeError):
            http1._ExactHttp1Response(status=204, headers=(), body=b"")
        self.assertEqual(
            response.safe_metadata()["response_digest_prefix"],
            str(response.response_digest)[:12],
        )

    def test_parse_errors_do_not_retain_input_bytes(self):
        secret_marker = b"never-retain-this-response-fragment"
        frames = (
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\nX: "
                + secret_marker
                + b"\r\n\r\n"
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                + secret_marker
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"1\r\nxQ"
                + secret_marker
            ),
        )
        source_path = str(Path(http1.__file__).resolve())
        for raw_frame in frames:
            parser = http1._new_exact_http1_response_parser()
            with self.subTest(raw_frame=raw_frame[:48]):
                with self.assertRaises(EndpointPolicyError) as raised:
                    parser.feed(raw_frame)
                _assert_safe_error(self, raised.exception)
                self.assertNotIn(secret_marker, str(raised.exception).encode())
                self.assertEqual(parser._buffer, bytearray())
                self.assertEqual(parser._body, bytearray())
                traceback: TracebackType | None = raised.exception.__traceback__
                while traceback is not None:
                    frame = traceback.tb_frame
                    if str(Path(frame.f_code.co_filename).resolve()) == source_path:
                        self.assertNotIn(
                            secret_marker.decode("ascii"),
                            repr(frame.f_locals),
                        )
                    traceback = traceback.tb_next


if __name__ == "__main__":
    unittest.main()
