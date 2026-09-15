"""TLS 环境加固。

从 v3 `_exact_tls.py` 抄出的那一小块真正便宜且正确的东西：如果进程环境里存在
能改变信任链或导出 TLS 密钥的变量，就拒绝发送。这些变量即使值为空也危险
（OpenSSL 对空值的处理不一致），所以只看键是否存在，从不读取其值。

v3 原版 275 行里另有主机名正则、策略 digest、proof 对象等，随 plan 机制一并移除。
"""
from __future__ import annotations

import os

FORBIDDEN_TLS_ENVIRONMENT_KEYS = (
    "OPENSSL_CONF",
    "OPENSSL_CONF_INCLUDE",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSLKEYLOGFILE",
)


class TlsEnvironmentUnsafe(Exception):
    """进程环境可以改变 TLS 信任或导出会话密钥。只报键名，不报值。"""


def require_safe_tls_environment() -> None:
    present = [k for k in FORBIDDEN_TLS_ENVIRONMENT_KEYS if k in os.environ]
    if present:
        raise TlsEnvironmentUnsafe(
            "以下环境变量会影响 TLS 信任或可能导出会话密钥,已拒绝发送:"
            + ", ".join(present)
        )
