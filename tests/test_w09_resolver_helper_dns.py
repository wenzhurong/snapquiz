"""Offline acceptance tests for the S5 resolver-helper/DNS foundation."""
from __future__ import annotations

from contextlib import contextmanager
import ast
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from uuid import UUID

from snapquiz.domain.digest import Digest256, canonical_json_bytes
from snapquiz.transport import _resolver_helper_dns as helper
from snapquiz.transport import _resolver_supervisor_async as async_module
from snapquiz.transport import address_policy, resolver
from tests.test_w09_resolver_supervisor_async import (
    WAIT_NS,
    _FakeChild,
    _Worker,
    _call_with_line_interrupt,
    _drive_active,
    _new_stack,
    _request_and_publication,
    _wait_ready,
)


FIXTURE = (
    Path(__file__).with_name("fixtures")
    / "resolver_dns_helper_child.py"
)
PROCESS_WAIT_NS = 25_000_000
PROCESS_DEADLINE_SECONDS = 3.0


def _start_frame() -> bytes:
    return resolver.encode_start_frame(
        hostname="open.bigmodel.cn",
        port=443,
        network_policy_ref=(
            address_policy.INTERNET_PUBLIC_ADDRESS_POLICY_REF
        ),
        network_policy_digest=(
            address_policy.INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST
        ),
        attempt_permit_id=UUID(
            "8d000000-0000-0000-0000-000000000001"
        ),
        attempt_permit_digest=Digest256("1" * 64),
        transport_claim_id=UUID(
            "8d000000-0000-0000-0000-000000000002"
        ),
        terminal_guard_id=UUID(
            "8d000000-0000-0000-0000-000000000003"
        ),
        terminal_guard_digest=Digest256("2" * 64),
        dns_start_id=UUID(
            "8d000000-0000-0000-0000-000000000004"
        ),
    )


def _valid_getaddrinfo_results() -> list[tuple[object, ...]]:
    return [
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("2001:4860:4860::8888", 443, 0, 0),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("8.8.8.8", 443),
        ),
    ]


def _wait_value(call, *, label: str) -> object:
    deadline = time.monotonic() + PROCESS_DEADLINE_SECONDS
    while time.monotonic() < deadline:
        selected = call()
        if selected is not resolver.PENDING:
            return selected
    raise AssertionError(f"{label} remained PENDING")


def _read_to_eof(call) -> bytes:
    selected = bytearray()
    deadline = time.monotonic() + PROCESS_DEADLINE_SECONDS
    while time.monotonic() < deadline:
        chunk = call()
        if chunk is resolver.PENDING:
            continue
        if type(chunk) is not bytes:
            raise AssertionError("stdout returned a non-bytes value")
        if chunk == b"":
            return bytes(selected)
        selected.extend(chunk)
    raise AssertionError("stdout did not reach EOF")


def _status_value(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 256 + os.WTERMSIG(status)
    raise AssertionError("child did not reach a terminal status")


class _LocalHelperChild:
    """Test-only OS adapter satisfying the injected S4 child shape."""

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        control: socket.socket,
    ) -> None:
        self.process = process
        self.pid = process.pid
        self._control = control
        self._sent_frame: bytes | None = None
        self._terminate_called = False
        self._wait_status: int | None = None
        self._closed = False

    @staticmethod
    def _poll(fd: int, events: int, max_wait_ns: int) -> bool:
        if type(max_wait_ns) is not int or max_wait_ns <= 0:
            raise AssertionError("child operation must be bounded")
        poller = select.poll()
        poller.register(fd, events)
        timeout_ms = max(1, (max_wait_ns + 999_999) // 1_000_000)
        return bool(poller.poll(timeout_ms))

    def read_stdout(self, max_bytes: int, *, max_wait_ns: int) -> object:
        if type(max_bytes) is not int or max_bytes <= 0:
            raise AssertionError("stdout maximum must be positive")
        stream = self.process.stdout
        if stream is None:
            raise AssertionError("stdout is unavailable")
        fd = stream.fileno()
        if not self._poll(
            fd,
            select.POLLIN | select.POLLHUP | select.POLLERR,
            max_wait_ns,
        ):
            return resolver.PENDING
        try:
            return os.read(fd, max_bytes)
        except BlockingIOError:
            return resolver.PENDING

    def write_start_datagram(
        self,
        frame: bytes,
        *,
        max_wait_ns: int,
    ) -> object:
        if self._sent_frame is not None:
            if frame != self._sent_frame:
                raise AssertionError("START replay changed")
            return resolver.COMPLETE
        if not self._poll(
            self._control.fileno(),
            select.POLLOUT | select.POLLERR | select.POLLHUP,
            max_wait_ns,
        ):
            return resolver.PENDING
        try:
            written = self._control.send(frame)
        except BlockingIOError:
            return resolver.PENDING
        if written != len(frame):
            raise AssertionError("START datagram was not written exactly")
        self._sent_frame = bytes(frame)
        return resolver.COMPLETE

    def terminate_exact(self, pid: int, *, max_wait_ns: int) -> object:
        if pid != self.pid or self._terminate_called:
            raise AssertionError("terminate is not exact-once")
        self._poll(
            self.process.stdout.fileno(),
            select.POLLIN | select.POLLHUP | select.POLLERR,
            max_wait_ns,
        )
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            self._wait_status = status
        elif waited_pid != 0:
            raise AssertionError("waitpid observed a foreign process")
        else:
            os.kill(pid, signal.SIGKILL)
        self._terminate_called = True
        return resolver.COMPLETE

    def reap_exact(self, pid: int, *, max_wait_ns: int) -> object:
        if pid != self.pid or not self._terminate_called:
            raise AssertionError("reap is not bound to terminate")
        if self._wait_status is None:
            self._poll(
                self.process.stdout.fileno(),
                select.POLLIN | select.POLLHUP | select.POLLERR,
                max_wait_ns,
            )
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
            if waited_pid == 0:
                return resolver.PENDING
            if waited_pid != pid:
                raise AssertionError("waitpid observed a foreign process")
            self._wait_status = status
        value = _status_value(self._wait_status)
        self.process.returncode = (
            -os.WTERMSIG(self._wait_status)
            if os.WIFSIGNALED(self._wait_status)
            else value
        )
        return value

    def close_exact(self, *, max_wait_ns: int) -> object:
        if self._closed:
            raise AssertionError("pipes were closed twice")
        if type(max_wait_ns) is not int or max_wait_ns <= 0:
            raise AssertionError("close must be bounded")
        self._closed = True
        self._control.close()
        for stream in (
            self.process.stdout,
            self.process.stderr,
        ):
            if stream is not None:
                stream.close()
        return resolver.COMPLETE

    def force_cleanup(self) -> None:
        try:
            self._control.close()
        except BaseException:
            pass
        if self._wait_status is None and self.process.returncode is None:
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=1)
            except (ChildProcessError, subprocess.TimeoutExpired):
                pass
        for stream in (
            self.process.stdout,
            self.process.stderr,
        ):
            if stream is not None and not stream.closed:
                stream.close()


@contextmanager
def _spawn_fixture(mode: str):
    parent_control: socket.socket | None = None
    child_control: socket.socket | None = None
    child: _LocalHelperChild | None = None
    with tempfile.TemporaryDirectory(
        prefix="snapquiz-resolver-dns-helper-"
    ) as temporary_root:
        link = (
            Path(temporary_root)
            / f"resolver_dns_helper_child__{mode}.py"
        )
        link.symlink_to(FIXTURE)
        try:
            parent_control, child_control = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_DGRAM,
            )
            for endpoint in (parent_control, child_control):
                endpoint.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_SNDBUF,
                    helper.MAX_START_FRAME_BYTES * 4,
                )
                endpoint.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_RCVBUF,
                    helper.MAX_START_FRAME_BYTES * 4,
                )
            parent_control.shutdown(socket.SHUT_RD)
            child_control.shutdown(socket.SHUT_WR)
            parent_control.setblocking(False)
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(link),
                    helper.RESOLVER_HELPER_PROTOCOL_FLAG,
                ],
                stdin=child_control,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            child_control.close()
            child_control = None
            if process.stdout is None or process.stderr is None:
                raise AssertionError("fixture pipes are unavailable")
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)
            child = _LocalHelperChild(
                process=process,
                control=parent_control,
            )
            parent_control = None
            yield child
        finally:
            if child is not None:
                child.force_cleanup()
            for endpoint in (parent_control, child_control):
                if endpoint is not None:
                    endpoint.close()


class _RecvmsgProbe:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[int, int]] = []

    def recvmsg(self, maximum: int, ancillary: int) -> object:
        self.calls.append((maximum, ancillary))
        return self.result


class ResolverHelperDnsUnitTest(unittest.TestCase):
    def test_contract_parity_and_production_remain_hard_closed(self):
        self.assertEqual(
            helper.INTERNET_PUBLIC_ADDRESS_POLICY_REF,
            address_policy.INTERNET_PUBLIC_ADDRESS_POLICY_REF,
        )
        self.assertEqual(
            helper.INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST,
            str(address_policy.INTERNET_PUBLIC_ADDRESS_POLICY_DIGEST),
        )
        self.assertEqual(
            helper.NETWORK_POLICY_VERSION,
            address_policy.GLM_NETWORK_POLICY_VERSION,
        )
        self.assertEqual(
            helper.MAX_RESULT_CANDIDATES,
            address_policy.MAX_RAW_RESOLUTION_CANDIDATES,
        )
        self.assertEqual(
            helper.MAX_RESULT_TRANSCRIPT_BYTES,
            address_policy.MAX_RAW_RESOLUTION_BYTES,
        )
        facts = helper._production_availability()
        self.assertTrue(facts["local_dns_contract_available"])
        self.assertFalse(facts["native_helper_identity_attested"])
        self.assertFalse(facts["native_liveness_owner_attested"])
        self.assertFalse(facts["durable_result_delivery_ack_attested"])
        self.assertFalse(facts["network_connect_available"])
        self.assertFalse(facts["production_available"])
        launcher = resolver.ResolverHelperLauncher.production(
            executable="/opt/snapquiz/libexec/resolver-helper"
        )
        self.assertIs(
            type(launcher._spawner),
            resolver.FailClosedProductionHelperSpawner,
        )
        resolver_source = Path(resolver.__file__).read_text(encoding="utf-8")
        self.assertNotIn("_resolver_helper_dns", resolver_source)

    def test_helper_module_is_stdlib_only_and_has_no_connect_call(self):
        source_path = Path(helper.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
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
        self.assertFalse(
            any(name == "snapquiz" or name.startswith("snapquiz.") for name in imported)
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"connect", "connect_ex"}
                for node in ast.walk(tree)
            )
        )

    def test_start_parser_is_exact_and_digest_matches_application(self):
        frame = _start_frame()
        parsed = helper._parse_start_frame(frame)
        self.assertEqual(parsed.hostname, "open.bigmodel.cn")
        self.assertEqual(parsed.port, 443)
        self.assertEqual(
            parsed.start_frame_digest,
            str(resolver.start_frame_digest(frame)),
        )

        payload = json.loads(frame)
        payload["network_policy_digest"] = "3" * 64
        invalid_policy = canonical_json_bytes(payload) + b"\n"
        duplicate_kind = frame.replace(
            b'"kind":"START",',
            b'"kind":"START","kind":"START",',
            1,
        )
        for selected in (
            frame[:-1],
            frame[:-1] + b" \n",
            invalid_policy,
            duplicate_kind,
            b"{}\n",
        ):
            with self.subTest(selected=selected[:40]):
                with self.assertRaises(helper._ResolverHelperDnsFailure):
                    helper._parse_start_frame(selected)

    def test_exactly_one_getaddrinfo_yields_complete_canonical_transcript(self):
        calls: list[tuple[object, ...]] = []

        def resolve(*args: object) -> object:
            calls.append(args)
            return _valid_getaddrinfo_results()

        frame = _start_frame()
        transcript = helper._resolve_start_frame(
            frame,
            getaddrinfo_call=resolve,
        )
        self.assertEqual(
            calls,
            [
                (
                    "open.bigmodel.cn",
                    443,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    0,
                )
            ],
        )
        payload = json.loads(transcript)
        self.assertEqual(canonical_json_bytes(payload), transcript)
        self.assertEqual(
            payload["candidates"],
            [
                {
                    "address": "2001:4860:4860::8888",
                    "family": "AF_INET6",
                    "flowinfo": 0,
                    "port": 443,
                    "protocol": "IPPROTO_TCP",
                    "scope_id": 0,
                    "socket_type": "SOCK_STREAM",
                },
                {
                    "address": "8.8.8.8",
                    "family": "AF_INET",
                    "port": 443,
                    "protocol": "IPPROTO_TCP",
                    "socket_type": "SOCK_STREAM",
                },
            ],
        )
        self.assertLessEqual(
            len(transcript), helper.MAX_RESULT_TRANSCRIPT_BYTES
        )
        normalized = address_policy.normalize_resolution_transcript(
            transcript,
            expected_port=443,
        )
        self.assertEqual(normalized.raw_candidate_count, 2)
        self.assertEqual(
            tuple(item.canonical_text for item in normalized.candidates),
            ("8.8.8.8", "2001:4860:4860::8888"),
        )

    def test_resolution_failure_never_retries_or_leaks_raw_exception(self):
        outcomes: tuple[object, ...] = (
            [],
            tuple(_valid_getaddrinfo_results()),
            _valid_getaddrinfo_results()
            * (helper.MAX_RESULT_CANDIDATES // 2 + 1),
            [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("999.8.8.8", 443),
                )
            ],
            [
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("2001:db8:::1", 443, 0, 0),
                )
            ],
            socket.gaierror(socket.EAI_FAIL, "synthetic hostname leak"),
        )
        for outcome in outcomes:
            with self.subTest(outcome=type(outcome).__name__):
                calls = 0

                def resolve(*args: object) -> object:
                    nonlocal calls
                    del args
                    calls += 1
                    if isinstance(outcome, BaseException):
                        raise outcome
                    return outcome

                with self.assertRaises(
                    helper._ResolverHelperDnsFailure
                ) as raised:
                    helper._resolve_start_frame(
                        _start_frame(),
                        getaddrinfo_call=resolve,
                    )
                self.assertEqual(calls, 1)
                self.assertIsNone(raised.exception.__cause__)
                self.assertTrue(raised.exception.__suppress_context__)
                self.assertNotIsInstance(raised.exception, NameError)

    def test_malformed_start_does_not_call_getaddrinfo(self):
        calls = 0

        def forbidden(*args: object) -> object:
            nonlocal calls
            del args
            calls += 1
            raise AssertionError("DNS must not run")

        with self.assertRaises(helper._ResolverHelperDnsFailure):
            helper._resolve_start_frame(
                b"{}\n",
                getaddrinfo_call=forbidden,
            )
        self.assertEqual(calls, 0)

    def test_recvmsg_is_exactly_once_and_rejects_record_boundary_faults(self):
        frame = _start_frame()
        probe = _RecvmsgProbe((frame, [], 0, None))
        self.assertEqual(helper._receive_start_frame_once(probe), frame)
        self.assertEqual(
            probe.calls,
            [
                (
                    helper.MAX_START_FRAME_BYTES + 1,
                    helper._ANCILLARY_BUFFER_BYTES,
                )
            ],
        )

        failures = (
            (frame, [(1, 1, b"x")], 0, None),
            (frame, [], socket.MSG_TRUNC, None),
            (frame, [], socket.MSG_CTRUNC, None),
            (b"x" * (helper.MAX_START_FRAME_BYTES + 1), [], 0, None),
            (b"", [], 0, None),
        )
        for outcome in failures:
            with self.subTest(outcome=outcome[2]):
                selected = _RecvmsgProbe(outcome)
                with self.assertRaises(helper._ResolverHelperDnsFailure):
                    helper._receive_start_frame_once(selected)
                self.assertEqual(len(selected.calls), 1)

    def test_result_read_interrupt_is_a_proven_production_blocker(self):
        result = b'{"kind":"RESULT"}\n'
        child = _FakeChild(
            stdout=(resolver.READY_FRAME, result, b""),
        )
        channel, spawner = _new_stack(_Worker(child))
        request, publication = _request_and_publication()
        kernel = _drive_active(spawner, request, publication)
        self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
        frame = _start_frame()
        self.assertIs(
            kernel.write_stdin(frame, max_wait_ns=WAIT_NS),
            resolver.COMPLETE,
        )

        with self.assertRaises(KeyboardInterrupt):
            _call_with_line_interrupt(
                async_module._AsyncSupervisorEventOwner.read_stdout,
                "if selected is resolver.PENDING:",
                lambda: kernel.read_stdout(
                    helper.MAX_RESULT_TRANSCRIPT_BYTES + 1,
                    max_wait_ns=WAIT_NS,
                ),
            )
        self.assertEqual(child.stdout, [b""])
        self.assertEqual(
            kernel.read_stdout(
                helper.MAX_RESULT_TRANSCRIPT_BYTES + 1,
                max_wait_ns=WAIT_NS,
            ),
            b"",
        )
        facts = helper._production_availability()
        self.assertFalse(facts["durable_result_delivery_ack_attested"])
        self.assertFalse(facts["production_available"])
        channel.event_owner.observe_broker_crash()


@unittest.skipUnless(
    hasattr(socket, "AF_UNIX"),
    "Unix datagram helper fixture",
)
class ResolverHelperDnsProcessTest(unittest.TestCase):
    def test_real_child_emits_one_result_lf_then_stdout_eof(self):
        with _spawn_fixture("success") as child:
            self.assertEqual(
                _wait_value(
                    lambda: child.read_stdout(
                        len(resolver.READY_FRAME),
                        max_wait_ns=PROCESS_WAIT_NS,
                    ),
                    label="READY",
                ),
                resolver.READY_FRAME,
            )
            frame = _start_frame()
            self.assertIs(
                _wait_value(
                    lambda: child.write_start_datagram(
                        frame,
                        max_wait_ns=PROCESS_WAIT_NS,
                    ),
                    label="START",
                ),
                resolver.COMPLETE,
            )
            output = _read_to_eof(
                lambda: child.read_stdout(
                    helper.MAX_RESULT_TRANSCRIPT_BYTES + 1,
                    max_wait_ns=PROCESS_WAIT_NS,
                )
            )
            self.assertEqual(output.count(b"\n"), 1)
            self.assertTrue(output.endswith(b"\n"))
            transcript = output[:-1]
            normalized = address_policy.normalize_resolution_transcript(
                transcript,
                expected_port=443,
            )
            self.assertEqual(normalized.raw_candidate_count, 2)
            self.assertEqual(child.process.wait(timeout=1), 0)
            stderr = child.process.stderr.read()
            self.assertEqual(stderr, b"")

    def test_real_child_failures_are_fixed_and_content_free(self):
        for mode in (
            "error",
            "empty",
            "overflow",
            "malformed_ipv4",
            "malformed_ipv6",
        ):
            with self.subTest(mode=mode), _spawn_fixture(mode) as child:
                self.assertEqual(
                    _wait_value(
                        lambda: child.read_stdout(
                            len(resolver.READY_FRAME),
                            max_wait_ns=PROCESS_WAIT_NS,
                        ),
                        label="READY",
                    ),
                    resolver.READY_FRAME,
                )
                self.assertIs(
                    _wait_value(
                        lambda: child.write_start_datagram(
                            _start_frame(),
                            max_wait_ns=PROCESS_WAIT_NS,
                        ),
                        label="START",
                    ),
                    resolver.COMPLETE,
                )
                self.assertEqual(
                    _read_to_eof(
                        lambda: child.read_stdout(
                            helper.MAX_RESULT_TRANSCRIPT_BYTES + 1,
                            max_wait_ns=PROCESS_WAIT_NS,
                        )
                    ),
                    b"",
                )
                self.assertEqual(child.process.wait(timeout=1), 70)
                self.assertEqual(
                    child.process.stderr.read(),
                    b"SNAPQUIZ-RESOLVER/2 ERROR\n",
                )

    def test_control_eof_and_second_record_terminate_blocked_resolution(self):
        with _spawn_fixture("block") as child:
            self.assertEqual(
                _wait_value(
                    lambda: child.read_stdout(
                        len(resolver.READY_FRAME),
                        max_wait_ns=PROCESS_WAIT_NS,
                    ),
                    label="READY",
                ),
                resolver.READY_FRAME,
            )
            self.assertIs(
                _wait_value(
                    lambda: child.write_start_datagram(
                        _start_frame(),
                        max_wait_ns=PROCESS_WAIT_NS,
                    ),
                    label="START",
                ),
                resolver.COMPLETE,
            )
            child._control.close()
            self.assertEqual(child.process.wait(timeout=2), 71)
            self.assertEqual(child.process.stdout.read(), b"")
            self.assertEqual(child.process.stderr.read(), b"")

        with _spawn_fixture("block") as child:
            self.assertEqual(
                _wait_value(
                    lambda: child.read_stdout(
                        len(resolver.READY_FRAME),
                        max_wait_ns=PROCESS_WAIT_NS,
                    ),
                    label="READY",
                ),
                resolver.READY_FRAME,
            )
            self.assertIs(
                _wait_value(
                    lambda: child.write_start_datagram(
                        _start_frame(),
                        max_wait_ns=PROCESS_WAIT_NS,
                    ),
                    label="START",
                ),
                resolver.COMPLETE,
            )
            deadline = time.monotonic() + 1
            while True:
                try:
                    written = child._control.send(b"second-record")
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("second record remained blocked")
            self.assertEqual(written, len(b"second-record"))
            self.assertEqual(child.process.wait(timeout=2), 71)
            self.assertEqual(child.process.stdout.read(), b"")
            self.assertEqual(child.process.stderr.read(), b"")

    def test_real_child_satisfies_s4_shape_and_cancel_reaps_exact_pid(self):
        with _spawn_fixture("block") as child:
            self.assertEqual(async_module._require_child(child), child.pid)
            channel, spawner = _new_stack(_Worker(child))
            request, publication = _request_and_publication()
            kernel = _drive_active(spawner, request, publication)
            self.assertEqual(_wait_ready(kernel), resolver.READY_FRAME)
            self.assertIs(
                _wait_value(
                    lambda: kernel.write_stdin(
                        _start_frame(),
                        max_wait_ns=WAIT_NS,
                    ),
                    label="S4 START",
                ),
                resolver.COMPLETE,
            )
            self.assertIs(
                _wait_value(
                    lambda: kernel.terminate(max_wait_ns=WAIT_NS),
                    label="S4 terminate",
                ),
                resolver.COMPLETE,
            )
            status = _wait_value(
                lambda: kernel.reap(max_wait_ns=WAIT_NS),
                label="S4 reap",
            )
            self.assertEqual(status, 256 + signal.SIGKILL)
            self.assertIs(
                _wait_value(
                    lambda: kernel.close_pipes(max_wait_ns=WAIT_NS),
                    label="S4 close",
                ),
                resolver.COMPLETE,
            )
            self.assertTrue(child._closed)
            self.assertFalse(channel.session_closed)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)


if __name__ == "__main__":
    unittest.main()
