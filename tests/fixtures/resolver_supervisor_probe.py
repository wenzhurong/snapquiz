#!/usr/bin/python3
"""Network-free development probe for the S2a supervisor bootstrap."""
from __future__ import annotations

import json
import os
import sys
import time


PROTOCOL_FLAG = "--snapquiz-resolver-supervisor-bootstrap-v1"
PROTOCOL_VERSION = "snapquiz.resolver-supervisor-bootstrap.v1"
READY_SCHEMA_VERSION = "snapquiz.resolver-supervisor-ready.v1"
PARENT_CANARY = "SNAPQUIZ_SUPERVISOR_PARENT_CANARY"


def _extra_fd_count(expected: set[int]) -> int:
    unexpected = 0
    for descriptor in range(3, 8_192):
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        if descriptor not in expected:
            unexpected += 1
    return unexpected


def _send(payload: dict[str, object]) -> None:
    frame = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        + b"\n"
    )
    remaining = memoryview(frame)
    while remaining:
        written = os.write(1, remaining)
        if type(written) is not int or written <= 0:
            raise SystemExit(72)
        remaining = remaining[written:]


def main() -> int:
    if len(sys.argv) != 13 or sys.argv[1] != PROTOCOL_FLAG:
        return 64
    (
        _,
        _,
        bootstrap_id,
        epoch_id,
        challenge_id,
        control_channel_id,
        parent_liveness_id,
        supervisor_liveness_id,
        local_probe_policy_digest,
        executable_sha256,
        binding_digest,
        parent_liveness_fd_text,
        supervisor_liveness_fd_text,
    ) = sys.argv
    try:
        parent_liveness_fd = int(parent_liveness_fd_text)
        supervisor_liveness_fd = int(supervisor_liveness_fd_text)
    except ValueError:
        return 65
    if (
        parent_liveness_fd < 3
        or supervisor_liveness_fd < 3
        or parent_liveness_fd == supervisor_liveness_fd
    ):
        return 65

    basename = os.path.basename(sys.argv[0])
    if "exit_before_ready" in basename:
        return 66
    if "stderr" in basename:
        os.write(2, b"x" * 4_097)
    if "block_ready" in basename:
        os.read(parent_liveness_fd, 1)
        return 0

    interpreter_bootstrap_keys = {
        "CPATH",
        "LIBRARY_PATH",
        "MANPATH",
        "SDKROOT",
        "__CF_USER_TEXT_ENCODING",
    }
    payload: dict[str, object] = {
        "binding_digest": binding_digest,
        "bootstrap_id": bootstrap_id,
        "challenge_id": challenge_id,
        "control_channel_id": control_channel_id,
        "environment_allowlist_only": (
            set(os.environ).issubset(
                {"LANG", "LC_ALL"} | interpreter_bootstrap_keys
            )
            and os.environ.get("LANG") == "C"
            and os.environ.get("LC_ALL") == "C"
        ),
        "epoch_id": epoch_id,
        "executable_sha256": executable_sha256,
        "kind": "READY",
        "local_probe_policy_digest": local_probe_policy_digest,
        "operation_children_created": 0,
        "parent_environment_canary_absent": PARENT_CANARY not in os.environ,
        "parent_liveness_id": parent_liveness_id,
        "parent_process_id": os.getppid(),
        "process_id": os.getpid(),
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": READY_SCHEMA_VERSION,
        "supervisor_liveness_id": supervisor_liveness_id,
        "unexpected_fd_count": _extra_fd_count(
            {parent_liveness_fd, supervisor_liveness_fd}
        ),
    }
    if "wrong_epoch" in basename:
        payload["epoch_id"] = "00000000-0000-0000-0000-000000000000"
    if "wrong_bootstrap" in basename:
        payload["bootstrap_id"] = "00000000-0000-0000-0000-000000000000"
    if "wrong_digest" in basename:
        payload["executable_sha256"] = "0" * 64
    if "wrong_policy" in basename:
        payload["local_probe_policy_digest"] = "0" * 64
    if "wrong_pid" in basename:
        payload["process_id"] = os.getpid() + 1
    if "extra_key" in basename:
        payload["unexpected"] = True

    _send(payload)
    if "double_ready" in basename:
        _send(payload)
    if "exit_after_ready" in basename:
        return 67
    if "liveness_byte" in basename:
        os.write(supervisor_liveness_fd, b"x")
    if "stubborn" in basename:
        while True:
            time.sleep(1)

    # This read is the parent-death capability.  The normal protocol sends no
    # bytes: EOF means either explicit parent shutdown or parent process death.
    observed = os.read(parent_liveness_fd, 1)
    return 0 if observed == b"" else 68


if __name__ == "__main__":
    raise SystemExit(main())
