"""Offline W09-B3 exact TLS policy tests."""
from __future__ import annotations

import ast
import copy
import os
from pathlib import Path
import pickle
import ssl
import unittest
from unittest import mock

from snapquiz.config.profiles import GLM_TLS_POLICY_REF
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _exact_tls as exact_tls


def _clean_environment():
    return mock.patch.dict(
        os.environ,
        {
            key: os.environ[key]
            for key in os.environ
            if key not in exact_tls.FORBIDDEN_TLS_ENVIRONMENT_KEYS
        },
        clear=True,
    )


def _assert_safe(case: unittest.TestCase, error: BaseException) -> None:
    case.assertIs(type(error), EndpointPolicyError)
    case.assertEqual(error.stage, "tls_transport")
    case.assertFalse(error.retryable)
    case.assertIsNone(error.__cause__)
    case.assertIsNone(error.__context__)


class ExactTlsPolicyTest(unittest.TestCase):
    def test_policy_ref_matches_the_normative_registry_value(self):
        self.assertEqual(
            exact_tls.EXACT_TLS_POLICY_REF,
            "snapquiz.tls.system-default-h1.v1",
        )
        self.assertEqual(GLM_TLS_POLICY_REF, exact_tls.EXACT_TLS_POLICY_REF)

    def test_factory_creates_only_system_default_client_context(self):
        with _clean_environment():
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
            policy.validate_integrity()
            context = policy._context_for_wrap(
                server_hostname="open.bigmodel.cn",
                _authority=exact_tls._POLICY_AUTHORITY,
            )
            self.assertIs(type(context), ssl.SSLContext)
            self.assertEqual(context.protocol, ssl.PROTOCOL_TLS_CLIENT)
            self.assertTrue(context.check_hostname)
            self.assertIsNone(context.keylog_filename)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(
                context.minimum_version,
                ssl.TLSVersion.TLSv1_2,
            )
            self.assertEqual(
                context.maximum_version,
                ssl.TLSVersion.MAXIMUM_SUPPORTED,
            )
            self.assertTrue(context.options & ssl.OP_NO_COMPRESSION)

    def test_policy_digest_addresses_forbidden_environment_contract(self):
        expected_keys = (
            "OPENSSL_CONF",
            "OPENSSL_CONF_INCLUDE",
            "OPENSSL_ENGINES",
            "OPENSSL_MODULES",
            "SSLKEYLOGFILE",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
        )
        payload = exact_tls._exact_tls_policy_payload(
            hostname="open.bigmodel.cn"
        )
        self.assertEqual(
            payload["forbidden_environment_keys"],
            expected_keys,
        )
        self.assertIs(payload["key_logging"], False)
        selected = digest256(
            "ExactTlsPolicy",
            exact_tls.EXACT_TLS_POLICY_SCHEMA_VERSION,
            payload,
        )
        self.assertIs(type(selected), Digest256)
        with _clean_environment():
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
        self.assertEqual(policy.policy_digest, selected)

    def test_forbidden_environment_presence_fails_before_context_creation(self):
        for key in exact_tls.FORBIDDEN_TLS_ENVIRONMENT_KEYS:
            with self.subTest(key=key), _clean_environment(), mock.patch.dict(
                os.environ,
                {key: ""},
            ), mock.patch.object(
                ssl,
                "create_default_context",
                side_effect=AssertionError("must not construct context"),
            ) as factory:
                with self.assertRaises(EndpointPolicyError) as raised:
                    exact_tls._new_exact_tls_policy(
                        hostname="open.bigmodel.cn"
                    )
                _assert_safe(self, raised.exception)
                factory.assert_not_called()
                self.assertNotIn(key, str(raised.exception))

    def test_environment_is_rechecked_after_policy_creation(self):
        with _clean_environment():
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
            for key in exact_tls.FORBIDDEN_TLS_ENVIRONMENT_KEYS:
                with self.subTest(key=key), mock.patch.dict(
                    os.environ,
                    {key: "secret-path"},
                ):
                    with self.assertRaises(EndpointPolicyError) as raised:
                        policy.validate_integrity()
                    _assert_safe(self, raised.exception)
                    self.assertNotIn("secret-path", str(raised.exception))

    def test_hostname_sni_and_negotiation_are_exact(self):
        invalid_hosts = (
            "Open.Bigmodel.cn",
            "open.bigmodel.cn.",
            "127.0.0.1",
            "bad_name.example",
            "",
        )
        with _clean_environment():
            for hostname in invalid_hosts:
                with self.subTest(hostname=hostname), self.assertRaises(
                    ValueError
                ):
                    exact_tls._new_exact_tls_policy(hostname=hostname)
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
            with self.assertRaises(EndpointPolicyError):
                policy._context_for_wrap(
                    server_hostname="other.example",
                    _authority=exact_tls._POLICY_AUTHORITY,
                )
            policy._attest_negotiated_values(
                server_hostname="open.bigmodel.cn",
                selected_alpn_protocol="http/1.1",
                negotiated_version="TLSv1.3",
                _authority=exact_tls._POLICY_AUTHORITY,
            )
            for alpn, version in (
                (None, "TLSv1.3"),
                ("h2", "TLSv1.3"),
                ("http/1.1", "TLSv1.1"),
                ("http/1.1", None),
            ):
                with self.subTest(alpn=alpn, version=version), self.assertRaises(
                    EndpointPolicyError
                ):
                    policy._attest_negotiated_values(
                        server_hostname="open.bigmodel.cn",
                        selected_alpn_protocol=alpn,
                        negotiated_version=version,
                        _authority=exact_tls._POLICY_AUTHORITY,
                    )

    def test_mutated_context_never_remains_eligible(self):
        with _clean_environment():
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
            policy._context.check_hostname = False
            with self.assertRaises(EndpointPolicyError):
                policy.validate_integrity()

    def test_policy_is_factory_only_immutable_and_nonserializable(self):
        with _clean_environment():
            policy = exact_tls._new_exact_tls_policy(
                hostname="open.bigmodel.cn"
            )
            self.assertIs(copy.copy(policy), policy)
            self.assertIs(copy.deepcopy(policy), policy)
            with self.assertRaises(TypeError):
                pickle.dumps(policy)
            with self.assertRaises(AttributeError):
                policy.hostname = "other.example"
            with self.assertRaises(TypeError):
                exact_tls._ExactTlsPolicy(
                    hostname="open.bigmodel.cn",
                    context=ssl.create_default_context(),
                )
            metadata = policy.safe_metadata()
            self.assertEqual(metadata["alpn"], "http/1.1")
            self.assertEqual(metadata["policy_ref"], GLM_TLS_POLICY_REF)

    def test_import_has_no_environment_or_context_side_effect(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "snapquiz"
            / "transport"
            / "_exact_tls.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "create_default_context"
        ]
        self.assertEqual(len(calls), 1)
        factory = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_new_exact_tls_policy"
        )
        self.assertIn(calls[0], tuple(ast.walk(factory)))
        self.assertEqual(exact_tls.__all__, ())


if __name__ == "__main__":
    unittest.main()
