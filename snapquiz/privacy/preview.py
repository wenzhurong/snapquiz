"""发送前预览：把**即将发出的字节**里的图片解出来给人看。

这是 v3 `privacy/egress.py`（2,072 行）里唯一真正对上本产品威胁的功能，
提炼成这一个模块。本产品的头号真实风险不是 DNS rebinding，是**手滑把含隐私的
屏幕内容传上去**。

核心不变量：预览的图**必须**从 ``OutboundRequest.body`` 里解出来，不能用调用方
手上那份原始 PNG。否则「预览的」和「发出的」只是碰巧相同，而不是同一份东西 ——
一旦中间哪一步动了 body，预览就会骗人。

预览文件写在 0700 的私有目录里，用完立刻删。
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from snapquiz.domain.outbound import OutboundRequest

PREVIEW_TIMEOUT_SECONDS = 120


class PreviewUnavailable(Exception):
    """无法从出站字节里还原出可预览的图片。此时必须当作拒绝发送。"""


@dataclass(frozen=True)
class OutboundPreview:
    """从实际出站字节里还原出来的、可展示给人看的内容。"""

    image_png: bytes
    image_media_type: str
    user_hint: Optional[str]
    model: str
    endpoint: str
    payload_byte_size: int
    envelope_digest_prefix: str

    @property
    def image_kib(self) -> float:
        return len(self.image_png) / 1024

    def describe(self) -> str:
        lines = [
            f"即将上传一张 {self.image_kib:.0f} KB 的 {self.image_media_type} 截图",
            f"  目标   {self.endpoint}",
            f"  模型   {self.model}",
            f"  总大小 {self.payload_byte_size / 1024:.0f} KB"
            f"(envelope {self.envelope_digest_prefix})",
        ]
        if self.user_hint:
            lines.append(f"  附带提示 {self.user_hint!r}")
        return "\n".join(lines)


def build_preview(prepared: OutboundRequest) -> OutboundPreview:
    """从 prepared.body 解析出人可以核对的内容。

    刻意不接受「调用方另外给一份图」—— 那样就失去了预览的意义。
    """

    if type(prepared) is not OutboundRequest:
        raise TypeError("prepared must be OutboundRequest")
    # 先确认字节自 prepare 之后没被动过。
    prepared.validate_integrity()

    try:
        body = json.loads(prepared.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreviewUnavailable("出站 body 不是可解析的 JSON") from exc

    image_uri = None
    hint = None
    try:
        for message in body["messages"]:
            content = message.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if part.get("type") == "image_url":
                    image_uri = part["image_url"]["url"]
                elif part.get("type") == "text":
                    hint = part.get("text")
        model = body["model"]
    except (KeyError, TypeError, AttributeError) as exc:
        raise PreviewUnavailable("出站 body 的形状不是预期的 chat 请求") from exc

    if not isinstance(image_uri, str) or not image_uri.startswith("data:image/"):
        raise PreviewUnavailable("出站 body 里没有可预览的内联图片")

    try:
        header, _, payload = image_uri.partition(",")
        media_type = header[len("data:") : header.index(";")]
        if not header.endswith(";base64"):
            raise PreviewUnavailable("内联图片不是 base64 编码")
        image_png = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PreviewUnavailable("内联图片无法解码") from exc
    if not image_png:
        raise PreviewUnavailable("内联图片为空")

    return OutboundPreview(
        image_png=image_png,
        image_media_type=media_type,
        # 用户提示混在固定指令里，这里只在确实带了 hint 时才显示它。
        user_hint=_extract_hint(hint),
        model=model,
        endpoint=prepared.canonical_url,
        payload_byte_size=prepared.payload_byte_size,
        envelope_digest_prefix=str(prepared.envelope_digest)[:12],
    )


def _extract_hint(text: Optional[str]) -> Optional[str]:
    """从 user 指令里取回 user_hint。

    ``adapters.prompt.build_user_instruction`` 把 ``{"locale":…,"user_hint":…}``
    以 canonical JSON 追加在固定前缀之后，所以从最后一个 ``{`` 开始解析。
    """

    if not text:
        return None
    start = text.rfind("{")
    if start < 0:
        return None
    try:
        context = json.loads(text[start:])
    except json.JSONDecodeError:
        return None
    hint = context.get("user_hint") if isinstance(context, dict) else None
    return hint if isinstance(hint, str) and hint.strip() else None


def show_image(preview: OutboundPreview) -> Optional[pathlib.Path]:
    """用 Quick Look 弹出这张图。返回临时文件路径,调用方负责 ``discard``。

    失败不抛错 —— 看不到图不该让整条链崩掉,但调用方应当据此提醒用户
    「没能显示图片」,让人自己决定要不要盲发。
    """

    directory = pathlib.Path(tempfile.mkdtemp(prefix="snapquiz-preview-"))
    os.chmod(directory, 0o700)
    path = directory / "outbound.png"
    path.write_bytes(preview.image_png)
    os.chmod(path, 0o600)
    try:
        # -p = Quick Look 预览;不阻塞,用户点掉即可。
        subprocess.Popen(
            ["qlmanage", "-p", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return path
    return path


def discard(path: Optional[pathlib.Path]) -> None:
    """删掉预览临时文件与目录。幂等。"""

    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
        path.parent.rmdir()
    except OSError:
        pass
