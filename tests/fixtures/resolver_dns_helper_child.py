#!/usr/bin/python3
"""Network-free child fixture for the S5 resolver/DNS helper foundation.

The executable basename selects one synthetic ``getaddrinfo`` outcome.  This
keeps the child argv fixed to the real protocol flag and avoids putting test
controls in the helper environment or START record.  The fixture deliberately
injects the resolver call; it never asks the host resolver or opens an Internet
socket.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from snapquiz.transport import _resolver_helper_dns as helper  # noqa: E402


def _wait_forever() -> None:
    while True:
        signal.pause()


def _synthetic_getaddrinfo(*args: object) -> object:
    del args
    executable_name = os.path.basename(sys.argv[0]).replace("-", "_")
    if "__block" in executable_name:
        _wait_forever()
    if "__error" in executable_name:
        raise socket.gaierror(socket.EAI_FAIL, "synthetic")
    if "__empty" in executable_name:
        return []
    if "__overflow" in executable_name:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (f"8.8.8.{(index % 250) + 1}", 443),
            )
            for index in range(helper.MAX_RESULT_CANDIDATES + 1)
        ]
    if "__malformed_ipv4" in executable_name:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("999.8.8.8", 443),
            )
        ]
    if "__malformed_ipv6" in executable_name:
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2001:db8:::1", 443, 0, 0),
            )
        ]
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


def main() -> int:
    return helper._run_helper(
        argv=tuple(sys.argv[1:]),
        getaddrinfo_call=_synthetic_getaddrinfo,
    )


if __name__ == "__main__":
    os._exit(main())
