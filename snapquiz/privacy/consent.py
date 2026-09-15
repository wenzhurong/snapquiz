"""一次性的数据政策同意记录。

v3 版本有 2,279 行：进程内 ConsentLedger、grant revision 重绑防护、
processing-region / retention / data / cost 四个维度各自的 unknown 确认。
对一个把自己的截图发给自己选定的服务商的个人工具来说，那套东西答非所问。

真正需要的是两条：
1. 第一次用之前，明确告诉用户「截图会离开这台机器，传给谁」，并拿到一次确认；
2. 这条记录可以撤销，撤销后下次再问。

逐次发送的批准是**另一层**（``privacy/preview.py`` + app 里的确认），
不能用这条一次性同意替代 —— 同意的是「政策」，批准的是「这一张图」。
"""
from __future__ import annotations

import json
import os
import pathlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

CONSENT_SCHEMA_VERSION = "snapquiz.consent.v1"

STATE_DIR = pathlib.Path(os.path.expanduser("~/.snapquiz"))
CONSENT_PATH = STATE_DIR / "consent.json"


@dataclass(frozen=True)
class ConsentRecord:
    schema_version: str
    granted_at: str
    provider_id: str
    endpoint: str
    #: 记录同意时的实际去向。换了 provider/endpoint 就要重新问 —— 用户同意的是
    #: 「传给这一家」，不是「传给任何一家」。
    def matches(self, *, provider_id: str, endpoint: str) -> bool:
        return self.provider_id == provider_id and self.endpoint == endpoint


def _read() -> Optional[ConsentRecord]:
    try:
        raw = json.loads(CONSENT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or raw.get("schema_version") != CONSENT_SCHEMA_VERSION:
        return None
    try:
        return ConsentRecord(
            schema_version=raw["schema_version"],
            granted_at=raw["granted_at"],
            provider_id=raw["provider_id"],
            endpoint=raw["endpoint"],
        )
    except KeyError:
        return None


def load(*, provider_id: str, endpoint: str) -> Optional[ConsentRecord]:
    """返回**适用于这个去向**的同意记录；不适用则视作没有。"""

    record = _read()
    if record is None or not record.matches(
        provider_id=provider_id, endpoint=endpoint
    ):
        return None
    return record


def grant(*, provider_id: str, endpoint: str) -> ConsentRecord:
    record = ConsentRecord(
        schema_version=CONSENT_SCHEMA_VERSION,
        granted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        provider_id=provider_id,
        endpoint=endpoint,
    )
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    CONSENT_PATH.write_text(
        json.dumps(asdict(record), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    os.chmod(CONSENT_PATH, 0o600)
    return record


def revoke() -> bool:
    """撤销同意。返回是否确实删掉了一条记录。"""

    try:
        CONSENT_PATH.unlink()
        return True
    except OSError:
        return False


def disclosure(*, provider_id: str, endpoint: str, model: str) -> str:
    return (
        "snapquiz 会把你框选的那块屏幕内容作为图片上传到云端模型服务。\n\n"
        f"  服务商   {provider_id}\n"
        f"  地址     {endpoint}\n"
        f"  模型     {model}\n\n"
        "请注意:\n"
        "  · 截图一旦发出就离开了这台机器,对方如何留存由对方的政策决定;\n"
        "  · 框选区域里的任何内容都会一起上传 —— 发送前会让你先看一眼实际要传的图;\n"
        "  · 模型可能自信地答错,答案仅供自学参考。\n\n"
        "以后每次发送仍会单独征求你的确认,这里只问一次「是否接受上述数据政策」。"
    )
