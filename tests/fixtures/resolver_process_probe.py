#!/usr/bin/python3
"""Standalone, network-free process probe for Darwin resolver tests.

The probe intentionally uses only one local Unix datagram on stdin,
stdout/stderr pipes, and standard-library process primitives.  Its mode is
selected by the executable basename so the production spawn environment can
remain exactly ``LANG=C, LC_ALL=C``:

* ``*__block_ready*``: never publishes READY;
* ``*__block_result*``: publishes READY, consumes START, then waits forever;
* ``*__nonzero*``: publishes a fixed synthetic RESULT and exits with status 7;
* ``*__stderr_overflow*``: writes 4,097 safe bytes to stderr before READY.
* ``*__late_stderr_overflow*``: closes stdout after RESULT, then overflows
  stderr immediately before a nominal exit 0.

Every other basename follows the successful path.  The RESULT reports only
booleans/counts for environment and descriptor canaries; it never copies START,
environment values, or arbitrary stderr into output.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import sys
import time


READY_FRAME = b"SNAPQUIZ-RESOLVER/2 READY\n"
PROTOCOL_FLAG = "--snapquiz-resolver-helper-v2"
MAX_START_FRAME_BYTES = 4_096
STDERR_OVERFLOW_BYTES = 4_097
START_SCHEMA_VERSION = "snapquiz.resolver-start.v2"


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise SystemExit(70)
        view = view[written:]


def _read_start() -> bytes:
    channel = socket.socket(fileno=0)
    try:
        if (
            channel.family != socket.AF_UNIX
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            != socket.SOCK_DGRAM
        ):
            raise SystemExit(71)
        frame, ancillary, message_flags, _ = channel.recvmsg(
            MAX_START_FRAME_BYTES + 1,
            256,
        )
        try:
            channel.send(b"forbidden-reverse-record")
        except OSError:
            reverse_write_blocked = True
        else:
            reverse_write_blocked = False
    finally:
        # Preserve fd 0 as process-owned rather than giving the temporary
        # socket wrapper authority to close a descriptor it did not create.
        channel.detach()

    if (
        not frame
        or len(frame) > MAX_START_FRAME_BYTES
        or not frame.endswith(b"\n")
        or ancillary
        or message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        or not reverse_write_blocked
    ):
        raise SystemExit(72)
    try:
        payload = json.loads(frame)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit(73) from None
    if (
        type(payload) is not dict
        or payload.get("kind") != "START"
        or payload.get("schema_version") != START_SCHEMA_VERSION
    ):
        raise SystemExit(73)
    return frame


def _wait_forever() -> None:
    while True:
        signal.pause()


def _extra_fd_count() -> int:
    count = 0
    # Include a deliberately high canary range.  Scanning only the traditional
    # 0..1023 select range would not prove CLOEXEC_DEFAULT for descriptors that
    # are valid under modern macOS's much larger RLIMIT_NOFILE.
    for descriptor in range(3, 8_192):
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        count += 1
    return count


def _result_frame(start_frame: bytes) -> bytes:
    # Python on Darwin may synthesize ``__CF_USER_TEXT_ENCODING`` itself.  The
    # Apple toolchain's /usr/bin/python3 shim can additionally synthesize the
    # SDK search variables below even when posix_spawn received only LANG and
    # LC_ALL.  They are not inherited parent values, so report them separately
    # from the parent-canary check rather than copying any value into output.
    interpreter_bootstrap_keys = {
        "CPATH",
        "LIBRARY_PATH",
        "MANPATH",
        "SDKROOT",
        "__CF_USER_TEXT_ENCODING",
    }
    environment_allowlist_only = (
        set(os.environ).issubset(
            {"LANG", "LC_ALL"} | interpreter_bootstrap_keys
        )
        and os.environ.get("LANG") == "C"
        and os.environ.get("LC_ALL") == "C"
    )
    payload = {
        "environment_allowlist_only": environment_allowlist_only,
        "extra_fd_count": _extra_fd_count(),
        "kind": "RESULT",
        "parent_environment_canary_absent": (
            "SNAPQUIZ_RESOLVER_PROCESS_PARENT_CANARY" not in os.environ
        ),
        "schema_version": "snapquiz.resolver-process-probe.v1",
        "start_frame_byte_size": len(start_frame),
        "start_frame_sha256": hashlib.sha256(start_frame).hexdigest(),
        "status": "ok",
        "stdin_is_unix_datagram": True,
        "stdin_reverse_write_blocked": True,
    }
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        + b"\n"
    )


def main() -> int:
    if sys.argv[1:] != [PROTOCOL_FLAG]:
        return 64

    executable_name = os.path.basename(sys.argv[0]).replace("-", "_")
    if "__block_ready" in executable_name:
        _wait_forever()

    if "__stderr_overflow" in executable_name:
        _write_all(2, b"E" * STDERR_OVERFLOW_BYTES)

    _write_all(1, READY_FRAME)
    start_frame = _read_start()

    if "__block_result" in executable_name:
        _wait_forever()

    if "__late_stderr_overflow" in executable_name:
        _write_all(1, _result_frame(start_frame))
        os.close(1)
        time.sleep(0.05)
        _write_all(2, b"E" * STDERR_OVERFLOW_BYTES)
        return 0

    _write_all(1, _result_frame(start_frame))
    if "__nonzero" in executable_name:
        return 7
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
