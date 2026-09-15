import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from snapquiz.adapters.openai_chat import OpenAIChatAdapter
from snapquiz.capture.select import (
    SelectionCancelled,
    SelectionFailed,
    select_region_png,
)
from snapquiz.config import Config
from snapquiz.domain.outbound import (
    NonSecretHeader,
    OutboundDataKind,
    OutboundRequest,
)
from snapquiz.privacy import consent
from snapquiz.privacy.preview import (
    PreviewUnavailable,
    build_preview,
    discard,
    show_image,
)
from snapquiz.providers import OPENCODE_GO, ZHIPU

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
QUESTION = (FIXTURES / "sample_question.png").read_bytes()


def cfg(**over):
    base = dict(provider=ZHIPU, model="glm-4.6v", region=(0, 0, 640, 480))
    base.update(over)
    return Config(**base)


class PreviewTest(unittest.TestCase):
    """预览必须从**实际出站字节**里解出来,而不是调用方另给的一份图。"""

    def test_image_is_recovered_from_the_outbound_body(self):
        prepared = OpenAIChatAdapter().prepare(config=cfg(), png=QUESTION)
        preview = build_preview(prepared)
        self.assertEqual(preview.image_png, QUESTION)
        self.assertEqual(preview.image_media_type, "image/png")
        self.assertEqual(preview.model, "glm-4.6v")
        self.assertIn("open.bigmodel.cn", preview.endpoint)

    def test_preview_reflects_the_model_actually_being_sent(self):
        """换了模型/provider,预览必须跟着变 —— 否则预览会骗人。"""

        other = OpenAIChatAdapter().prepare(
            config=cfg(provider=OPENCODE_GO, model="glm-5.3-flash"), png=QUESTION
        )
        preview = build_preview(other)
        self.assertEqual(preview.model, "glm-5.3-flash")
        self.assertIn("opencode.ai", preview.endpoint)

    def test_hint_is_surfaced_only_when_present(self):
        without = build_preview(
            OpenAIChatAdapter().prepare(config=cfg(), png=QUESTION)
        )
        self.assertIsNone(without.user_hint)
        with_hint = build_preview(
            OpenAIChatAdapter().prepare(
                config=cfg(), png=QUESTION, user_hint="这是几何题"
            )
        )
        self.assertEqual(with_hint.user_hint, "这是几何题")
        self.assertIn("这是几何题", with_hint.describe())

    def test_describe_states_size_target_and_digest(self):
        text = build_preview(
            OpenAIChatAdapter().prepare(config=cfg(), png=QUESTION)
        ).describe()
        self.assertIn("KB", text)
        self.assertIn("open.bigmodel.cn", text)
        self.assertIn("envelope", text)

    def test_non_image_payload_is_refused(self):
        prepared = OutboundRequest(
            http_method="POST",
            canonical_url="https://example.invalid/x",
            content_type="application/json",
            non_secret_headers=(
                NonSecretHeader(lowercase_name="accept", normalized_value="a"),
            ),
            outbound_data=(OutboundDataKind.IMAGE,),
            body=json.dumps(
                {"model": "m", "messages": [{"role": "user", "content": "text only"}]}
            ).encode(),
        )
        with self.assertRaises(PreviewUnavailable):
            build_preview(prepared)

    def test_unparsable_body_is_refused(self):
        prepared = OutboundRequest(
            http_method="POST",
            canonical_url="https://example.invalid/x",
            content_type="application/json",
            non_secret_headers=(),
            outbound_data=(OutboundDataKind.IMAGE,),
            body=b"\xff\xfe not json",
        )
        with self.assertRaises(PreviewUnavailable):
            build_preview(prepared)

    def test_only_accepts_outbound_request(self):
        with self.assertRaises(TypeError):
            build_preview({"body": b"{}"})

    def test_preview_file_is_private_and_removable(self):
        preview = build_preview(
            OpenAIChatAdapter().prepare(config=cfg(), png=QUESTION)
        )
        with patch("subprocess.Popen"):
            path = show_image(preview)
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_bytes(), QUESTION)
        discard(path)
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())
        discard(path)  # 幂等


class ConsentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="snapquiz-consent-test-"))
        patcher = patch.multiple(
            consent, STATE_DIR=self.tmp, CONSENT_PATH=self.tmp / "consent.json"
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_absent_until_granted(self):
        self.assertIsNone(consent.load(provider_id="zhipu", endpoint="https://a/x"))
        consent.grant(provider_id="zhipu", endpoint="https://a/x")
        self.assertIsNotNone(
            consent.load(provider_id="zhipu", endpoint="https://a/x")
        )

    def test_consent_is_scoped_to_the_destination(self):
        """同意的是「传给这一家」,不是「传给任何一家」。"""

        consent.grant(provider_id="zhipu", endpoint="https://a/x")
        self.assertIsNone(
            consent.load(provider_id="opencode_go", endpoint="https://a/x")
        )
        self.assertIsNone(
            consent.load(provider_id="zhipu", endpoint="https://other/x")
        )

    def test_revoke(self):
        consent.grant(provider_id="zhipu", endpoint="https://a/x")
        self.assertTrue(consent.revoke())
        self.assertIsNone(consent.load(provider_id="zhipu", endpoint="https://a/x"))
        self.assertFalse(consent.revoke())

    def test_record_file_is_private(self):
        consent.grant(provider_id="zhipu", endpoint="https://a/x")
        self.assertEqual(
            consent.CONSENT_PATH.stat().st_mode & 0o777, 0o600
        )

    def test_corrupt_or_old_schema_is_treated_as_absent(self):
        for raw in ("not json", '{"schema_version":"ancient"}', "[]"):
            consent.CONSENT_PATH.write_text(raw, encoding="utf-8")
            self.assertIsNone(
                consent.load(provider_id="zhipu", endpoint="https://a/x")
            )

    def test_disclosure_names_the_real_destination(self):
        text = consent.disclosure(
            provider_id="zhipu", endpoint="https://open.bigmodel.cn/x", model="glm-4.6v"
        )
        self.assertIn("open.bigmodel.cn", text)
        self.assertIn("glm-4.6v", text)
        self.assertIn("离开", text)


class SelectionTest(unittest.TestCase):
    def _run(self, returncode, write=None):
        def fake(cmd, **kwargs):
            target = pathlib.Path(cmd[-1])
            if write is not None:
                target.write_bytes(write)
            return subprocess.CompletedProcess(cmd, returncode)

        return patch("subprocess.run", side_effect=fake)

    def test_escape_produces_cancelled_not_a_blank_image(self):
        """按 Esc 时 screencapture 返回 0 但不写文件 —— 必须当作取消。"""

        with self._run(0), self.assertRaises(SelectionCancelled):
            select_region_png()

    def test_nonzero_exit_is_cancelled(self):
        with self._run(1), self.assertRaises(SelectionCancelled):
            select_region_png()

    def test_successful_selection_returns_png_and_leaves_no_file(self):
        captured = {}

        def fake(cmd, **kwargs):
            target = pathlib.Path(cmd[-1])
            captured["dir"] = target.parent
            target.write_bytes(QUESTION)
            return subprocess.CompletedProcess(cmd, 0)

        with patch("subprocess.run", side_effect=fake):
            self.assertEqual(select_region_png(), QUESTION)
        self.assertFalse(captured["dir"].exists(), "临时目录必须清掉")

    def test_blank_selection_is_refused(self):
        import struct
        import zlib

        def solid_png(w, h, rgb):
            raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))

            def chunk(t, d):
                c = t + d
                return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c))

            return (
                b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw))
                + chunk(b"IEND", b"")
            )

        from snapquiz.capture.validation import CaptureQualityError

        with self._run(0, write=solid_png(60, 40, (0, 0, 0))):
            with self.assertRaises(CaptureQualityError):
                select_region_png()

    def test_missing_screencapture_is_a_failure_not_a_cancel(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(SelectionFailed):
                select_region_png()


if __name__ == "__main__":
    unittest.main()


class DeclineIsAirtightTest(unittest.TestCase):
    """拒绝预览之后必须什么都没发生:零网络、零密钥读取、无临时文件残留。"""

    def setUp(self):
        import os

        os.environ["GLM_API_KEY"] = "zp-must-not-be-read"
        self.addCleanup(os.environ.pop, "GLM_API_KEY", None)

    def _orchestrator(self, recorder, answer):
        from snapquiz.app import _confirm_in_terminal
        from snapquiz.core.orchestrator import Orchestrator

        def send(*a, **kw):
            recorder["sends"] += 1
            raise AssertionError("拒绝之后不得发送")

        original_resolve = __import__(
            "snapquiz.config", fromlist=["resolve_api_key"]
        ).resolve_api_key

        def counting_resolve(cfg):
            recorder["key_reads"] += 1
            return original_resolve(cfg)

        self.resolve_patch = patch(
            "snapquiz.core.orchestrator.resolve_api_key", counting_resolve
        )
        self.input_patch = patch("builtins.input", lambda *_: answer)
        self.ql_patch = patch("subprocess.Popen")
        return Orchestrator(
            config=cfg(),
            adapter=OpenAIChatAdapter(),
            capture_fn=lambda: QUESTION,
            send_fn=send,
            present_fn=lambda r: recorder.__setitem__("presented", True),
            require_permission_fn=lambda: None,
            on_error=lambda m: recorder["errors"].append(m),
            approve_fn=_confirm_in_terminal,
        )

    def test_declining_sends_nothing_and_reads_no_key(self):
        rec = {"sends": 0, "key_reads": 0, "errors": [], "presented": False}
        orch = self._orchestrator(rec, "n")
        with self.resolve_patch, self.input_patch, self.ql_patch:
            self.assertIsNone(orch.run_once())
        self.assertEqual(rec["sends"], 0)
        self.assertEqual(rec["key_reads"], 0, "批准前密钥解析次数必须为 0")
        self.assertFalse(rec["presented"])
        self.assertEqual(len(rec["errors"]), 1)

    def test_empty_answer_is_a_decline(self):
        rec = {"sends": 0, "key_reads": 0, "errors": [], "presented": False}
        orch = self._orchestrator(rec, "")
        with self.resolve_patch, self.input_patch, self.ql_patch:
            orch.run_once()
        self.assertEqual((rec["sends"], rec["key_reads"]), (0, 0))

    def test_preview_temp_file_is_gone_after_declining(self):
        created = []
        real_mkdtemp = tempfile.mkdtemp

        def tracking(*a, **kw):
            path = real_mkdtemp(*a, **kw)
            created.append(pathlib.Path(path))
            return path

        rec = {"sends": 0, "key_reads": 0, "errors": [], "presented": False}
        orch = self._orchestrator(rec, "n")
        with self.resolve_patch, self.input_patch, self.ql_patch, patch(
            "tempfile.mkdtemp", tracking
        ):
            orch.run_once()
        self.assertTrue(created, "应当确实创建过预览目录")
        for path in created:
            self.assertFalse(path.exists(), f"预览目录未清理: {path}")
