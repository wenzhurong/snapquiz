"""Darwin-local tests for the S2b-I1 connection-peer identity foundation."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import os
from pathlib import Path
import pickle
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.transport import _darwin_process_identity as identity
from snapquiz.transport.resolver import (
    FailClosedProductionHelperSpawner,
    ResolverHelperLauncher,
)


FIXTURE_SOURCE = (
    Path(__file__).with_name("fixtures") / "darwin_identity_peer.c"
)
FIXTURE_IDENTIFIER = "ai.snapquiz.identity-peer"
CS_VALID = 0x00000001
CS_ADHOC = 0x00000002
CS_GET_TASK_ALLOW = 0x00000004
CS_FORCED_LV = 0x00000010
CS_INVALID_ALLOWED = 0x00000020
CS_HARD = 0x00000100
CS_KILL = 0x00000200
CS_ENFORCEMENT = 0x00001000
CS_RUNTIME = 0x00010000
CS_KILLED = 0x01000000
CS_PLATFORM_BINARY = 0x04000000
CS_DEBUGGED = 0x10000000
CS_SIGNED = 0x20000000
REQUIRED_DYNAMIC_STATUS = (
    CS_VALID
    | CS_FORCED_LV
    | CS_HARD
    | CS_KILL
    | CS_ENFORCEMENT
    | CS_RUNTIME
    | CS_SIGNED
)
FORBIDDEN_DYNAMIC_STATUS = (
    CS_GET_TASK_ALLOW | CS_INVALID_ALLOWED | CS_KILLED | CS_DEBUGGED
)


def _assert_safe_error(
    test: unittest.TestCase,
    error: EndpointPolicyError,
) -> None:
    test.assertEqual(error.stage, "resolver_supervisor_identity")
    test.assertFalse(error.retryable)
    test.assertIsNone(error.__cause__)
    test.assertTrue(error.__suppress_context__)
    test.assertNotIn("/private/", str(error))
    test.assertNotIn("CDHash", str(error))


@unittest.skipUnless(sys.platform == "darwin", "Darwin process identity")
class DarwinConnectionPeerIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not Path("/usr/bin/clang").is_file() or not Path(
            "/usr/bin/codesign"
        ).is_file():
            raise unittest.SkipTest("Apple clang and codesign are required")
        cls._build_root = tempfile.TemporaryDirectory(
            prefix="snapquiz-identity-build-",
            dir="/tmp",
        )
        output = Path(cls._build_root.name) / "identity-peer"
        subprocess.run(
            [
                "/usr/bin/clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Os",
                str(FIXTURE_SOURCE),
                "-o",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--identifier",
                FIXTURE_IDENTIFIER,
                "--options",
                "runtime",
                "--timestamp=none",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        details = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(output)],
            check=False,
            capture_output=True,
            text=True,
        )
        if details.returncode != 0:
            raise unittest.SkipTest("could not inspect local ad-hoc fixture")
        report = details.stdout + details.stderr
        match = re.search(r"(?m)^CDHash=([0-9a-f]{40})$", report)
        if match is None:
            raise unittest.SkipTest("codesign did not publish a 20-byte CDHash")
        cls.executable = str(output.resolve())
        cls.cdhash = match.group(1)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._build_root.cleanup()

    def _policy(self, **overrides):
        values = {
            "expected_executable": self.executable,
            "expected_code_identifier": FIXTURE_IDENTIFIER,
            "expected_team_identifier": None,
            "expected_code_directory_hash": self.cdhash,
            "expected_effective_user_id": os.geteuid(),
            "required_static_code_flags": CS_ADHOC | CS_RUNTIME,
            "forbidden_static_code_flags": 0,
            "required_dynamic_code_status": REQUIRED_DYNAMIC_STATUS,
            "forbidden_dynamic_code_status": FORBIDDEN_DYNAMIC_STATUS,
            "expected_adhoc": True,
        }
        values.update(overrides)
        return identity._new_local_darwin_process_identity_policy(**values)

    @contextmanager
    def _native_peer(self, *extra_args: str):
        with tempfile.TemporaryDirectory(
            prefix="sq-peer-",
            dir="/tmp",
        ) as root:
            socket_path = str(Path(root) / "identity.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.settimeout(5)
            listener.bind(socket_path)
            os.chmod(socket_path, 0o600)
            listener.listen(1)
            process = subprocess.Popen(
                [self.executable, socket_path, *extra_args],
                close_fds=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            peer = None
            try:
                peer, _ = listener.accept()
                peer.settimeout(5)
                yield process, peer
            finally:
                if peer is not None:
                    peer.close()
                listener.close()
                try:
                    _, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, stderr = process.communicate(timeout=5)
                if process.returncode != 0:
                    self.fail(
                        "native identity fixture failed with "
                        f"{process.returncode}: {stderr!r}"
                    )

    def test_policy_is_factory_owned_immutable_and_development_only(self):
        policy = self._policy()
        self.assertIs(copy.copy(policy), policy)
        self.assertIs(copy.deepcopy(policy), policy)
        with self.assertRaises(TypeError):
            pickle.dumps(policy)
        with self.assertRaises(AttributeError):
            policy.expected_executable = "/usr/bin/false"
        with self.assertRaises(TypeError):
            identity._LocalDarwinProcessIdentityPolicy(
                expected_executable=self.executable,
                expected_code_identifier=FIXTURE_IDENTIFIER,
                expected_team_identifier=None,
                expected_code_directory_hash=self.cdhash,
                expected_effective_user_id=os.geteuid(),
                required_static_code_flags=CS_ADHOC | CS_RUNTIME,
                forbidden_static_code_flags=0,
                required_dynamic_code_status=REQUIRED_DYNAMIC_STATUS,
                forbidden_dynamic_code_status=FORBIDDEN_DYNAMIC_STATUS,
                expected_adhoc=True,
            )
        self.assertEqual(
            policy.safe_metadata(),
            {
                "expected_adhoc": True,
                "identity_scope": (
                    "darwin_connection_peer_dynamic_code_development"
                ),
                "policy_digest": str(policy.policy_digest),
                "production_eligible": False,
            },
        )
        tampered = self._policy()
        object.__setattr__(
            tampered,
            "policy_digest",
            str(tampered.policy_digest),
        )
        with self.assertRaises(ValueError):
            tampered.validate_integrity()

    def test_policy_rejects_incoherent_ad_hoc_and_flag_claims(self):
        bad_cases = (
            {"expected_code_directory_hash": "A" * 40},
            {"expected_code_identifier": 'bad"identifier'},
            {"expected_team_identifier": "SHORT"},
            {
                "required_static_code_flags": CS_RUNTIME,
                "expected_adhoc": True,
            },
            {
                "forbidden_static_code_flags": CS_ADHOC,
                "expected_adhoc": True,
            },
            {
                "required_dynamic_code_status": REQUIRED_DYNAMIC_STATUS,
                "forbidden_dynamic_code_status": CS_VALID,
            },
            {"expected_team_identifier": "ABCDEFGHIJ"},
        )
        for changes in bad_cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self._policy(**changes)

    def test_real_native_peer_binds_kernel_pid_generation_and_dynamic_code(self):
        policy = self._policy()
        with self._native_peer() as (process, peer):
            pre_resume_token = identity._copy_process_audit_token(
                expected_process_id=process.pid,
            )
            self.assertEqual(len(pre_resume_token), 32)
            self.assertEqual(
                pre_resume_token,
                peer.getsockopt(0, 0x006, 32),
            )
            running = identity._observe_running_code_by_pid(
                expected_process_id=process.pid,
                policy=policy,
            )
            self.assertEqual(running.process_id, process.pid)
            self.assertEqual(running.executable, self.executable)
            self.assertEqual(running.code_identifier, FIXTURE_IDENTIFIER)
            self.assertEqual(running.code_directory_hash, self.cdhash)
            proof = identity._attest_darwin_connection_peer(
                peer_socket=peer,
                expected_process_id=process.pid,
                policy=policy,
            )
            self.assertEqual(proof.process_id, process.pid)
            self.assertGreater(proof.process_version, 0)
            self.assertEqual(proof.executable, self.executable)
            self.assertEqual(proof.code_identifier, FIXTURE_IDENTIFIER)
            self.assertIsNone(proof.team_identifier)
            self.assertEqual(proof.code_directory_hash, self.cdhash)
            self.assertEqual(
                proof.static_code_flags & (CS_ADHOC | CS_RUNTIME),
                CS_ADHOC | CS_RUNTIME,
            )
            metadata = proof.safe_metadata()
            self.assertTrue(metadata["connection_peer_identity_attested"])
            self.assertFalse(metadata["continuous_running_identity_attested"])
            self.assertFalse(metadata["production_bundle_attested"])
            self.assertFalse(metadata["startup_order_attested"])
            self.assertFalse(metadata["transport_available"])
            self.assertNotIn("audit_token", metadata)
            self.assertNotIn("executable", metadata)
            self.assertIs(copy.copy(proof), proof)
            self.assertIs(copy.deepcopy(proof), proof)
            with self.assertRaises(TypeError):
                pickle.dumps(proof)
            object.__setattr__(
                proof,
                "policy_digest",
                str(proof.policy_digest),
            )
            with self.assertRaises(ValueError):
                proof.validate_integrity()
            with self.assertRaises(TypeError):
                identity._DarwinConnectionPeerIdentityAttestation(
                    observed=None,
                    policy=policy,
                )

    def test_wrong_pid_path_signature_user_and_flags_fail_closed(self):
        policies = (
            self._policy(
                expected_executable="/usr/bin/false",
            ),
            self._policy(
                expected_code_identifier="ai.snapquiz.wrong-peer",
            ),
            self._policy(
                expected_code_directory_hash="0" * 40,
            ),
            self._policy(
                expected_effective_user_id=os.geteuid() + 1,
            ),
            self._policy(
                required_static_code_flags=(
                    CS_ADHOC | CS_RUNTIME | CS_PLATFORM_BINARY
                ),
            ),
            self._policy(
                required_dynamic_code_status=(
                    REQUIRED_DYNAMIC_STATUS | CS_PLATFORM_BINARY
                ),
            ),
            self._policy(
                expected_adhoc=False,
                required_static_code_flags=CS_RUNTIME,
                forbidden_static_code_flags=CS_ADHOC,
            ),
        )
        with self._native_peer() as (process, peer):
            cases = ((process.pid + 1, self._policy()),) + tuple(
                (process.pid, policy) for policy in policies
            )
            for expected_pid, policy in cases:
                with self.subTest(
                    expected_pid=expected_pid,
                    policy_digest=policy.policy_digest,
                ), self.assertRaises(EndpointPolicyError) as raised:
                    identity._attest_darwin_connection_peer(
                        peer_socket=peer,
                        expected_process_id=expected_pid,
                        policy=policy,
                    )
                _assert_safe_error(self, raised.exception)

    def test_policy_tamper_and_invalid_socket_are_content_free(self):
        policy = self._policy()
        object.__setattr__(policy, "expected_executable", "/usr/bin/false")
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            for peer in (left, object()):
                with self.subTest(peer=type(peer).__name__), self.assertRaises(
                    EndpointPolicyError
                ) as raised:
                    identity._attest_darwin_connection_peer(
                        peer_socket=peer,
                        expected_process_id=os.getpid(),
                        policy=policy,
                    )
                _assert_safe_error(self, raised.exception)
        finally:
            left.close()
            right.close()

    def test_inherited_socketpair_cannot_impersonate_spawned_child(self):
        parent_endpoint, inherited_endpoint = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(1)"],
            pass_fds=(inherited_endpoint.fileno(),),
            close_fds=True,
        )
        inherited_endpoint.close()
        try:
            with self.assertRaises(EndpointPolicyError) as raised:
                identity._attest_darwin_connection_peer(
                    peer_socket=parent_endpoint,
                    expected_process_id=process.pid,
                    policy=self._policy(),
                )
            _assert_safe_error(self, raised.exception)
        finally:
            parent_endpoint.close()
            process.wait(timeout=5)

    def test_proof_does_not_authorize_bytes_after_peer_fork_and_exec(self):
        with self._native_peer("fork-exec-writer") as (process, peer):
            proof = identity._attest_darwin_connection_peer(
                peer_socket=peer,
                expected_process_id=process.pid,
                policy=self._policy(),
            )
            self.assertTrue(
                proof.safe_metadata()["connection_peer_identity_attested"]
            )
            self.assertFalse(
                proof.safe_metadata()["continuous_running_identity_attested"]
            )
            # The connected descriptor was inherited by /bin/sh, proving why
            # this I1 proof cannot authorize later READY/control bytes.
            self.assertEqual(peer.recv(1), b"x")

    def test_shebang_claim_resolves_to_interpreter_and_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sq-script-", dir="/tmp") as root:
            socket_path = str(Path(root) / "identity.sock")
            claimed_script = str((Path(root) / "claimed.py").resolve())
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.settimeout(5)
            listener.bind(socket_path)
            listener.listen(1)
            source = (
                "import socket,sys,time;"
                "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
                "s.connect(sys.argv[1]);time.sleep(1)"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", source, socket_path],
                close_fds=True,
            )
            peer, _ = listener.accept()
            try:
                policy = identity._new_local_darwin_process_identity_policy(
                    expected_executable=claimed_script,
                    expected_code_identifier="ai.snapquiz.claimed-script",
                    expected_team_identifier=None,
                    expected_code_directory_hash="0" * 40,
                    expected_effective_user_id=os.geteuid(),
                    required_static_code_flags=CS_ADHOC,
                    forbidden_static_code_flags=0,
                    required_dynamic_code_status=0x00000001,
                    forbidden_dynamic_code_status=FORBIDDEN_DYNAMIC_STATUS,
                    expected_adhoc=True,
                )
                with self.assertRaises(EndpointPolicyError) as raised:
                    identity._attest_darwin_connection_peer(
                        peer_socket=peer,
                        expected_process_id=process.pid,
                        policy=policy,
                    )
                _assert_safe_error(self, raised.exception)
            finally:
                peer.close()
                listener.close()
                process.wait(timeout=5)

    def test_exited_peer_token_cannot_attest_a_stale_process_generation(self):
        policy = self._policy()
        with self._native_peer("exit-after-connect") as (process, peer):
            process.wait(timeout=5)
            with self.assertRaises(EndpointPolicyError) as raised:
                identity._attest_darwin_connection_peer(
                    peer_socket=peer,
                    expected_process_id=process.pid,
                    policy=policy,
                )
            _assert_safe_error(self, raised.exception)

    def test_import_and_production_resolver_remain_zero_process_unwired(self):
        root = Path(__file__).resolve().parents[1]
        script = r'''
import ctypes
import os
import socket

def poison(*args, **kwargs):
    raise AssertionError("external capability used during import")

ctypes.CDLL = poison
os.open = poison
socket.socket = poison
import snapquiz.transport._darwin_process_identity
'''
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        launcher = ResolverHelperLauncher.production(executable=self.executable)
        self.assertIs(type(launcher._spawner), FailClosedProductionHelperSpawner)
        self.assertNotIn(
            "_darwin_process_identity",
            sys.modules.get("snapquiz.transport.resolver").__dict__,
        )


if __name__ == "__main__":
    unittest.main()
