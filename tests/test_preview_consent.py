import io
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


class CaptureModeTest(unittest.TestCase):
    """选区模式的判定。

    这是实测暴露出来的洞：我的验收脚本显式传了 --select，所以从没跑过
    「什么都不加」这条默认路径，而用户用的正是那条。
    """

    def setUp(self):
        from snapquiz.app import CaptureModeError, choose_interactive

        self.choose = choose_interactive
        self.error = CaptureModeError

    def test_no_region_configured_means_drag(self):
        self.assertTrue(
            self.choose(cfg(region=None), select=False, region=False)
        )

    def test_configured_region_means_fixed(self):
        self.assertFalse(
            self.choose(cfg(region=(0, 0, 10, 10)), select=False, region=False)
        )

    def test_select_overrides_a_configured_region(self):
        """SNAPQUIZ_REGION 写在 .env 里时,shell 的 unset 无效,只能靠 --select。"""

        self.assertTrue(
            self.choose(cfg(region=(0, 0, 10, 10)), select=True, region=False)
        )

    def test_region_without_configuration_is_an_error_not_a_silent_fallback(self):
        with self.assertRaises(self.error):
            self.choose(cfg(region=None), select=False, region=True)

    def test_both_flags_is_an_error(self):
        with self.assertRaises(self.error):
            self.choose(cfg(region=(0, 0, 10, 10)), select=True, region=True)

    def test_default_invocation_uses_the_interactive_selector(self):
        """端到端钉死：不带任何参数时，capture_fn 必须是拖框那个。"""

        from snapquiz.app import _build_capture_fn
        from snapquiz.capture.select import select_region_png

        interactive = self.choose(cfg(region=None), select=False, region=False)
        self.assertIs(
            _build_capture_fn(cfg(region=None), interactive=interactive),
            select_region_png,
        )


@patch("sys.stdout", new_callable=io.StringIO)
class ShippedScriptsTest(unittest.TestCase):
    """README 里让用户跑的脚本必须真的能跑。

    这一条是「干净 clone 验收」抓出来的:grant_check.py 在 Task 2 重写
    permissions.py 之后一直 import 一个已删除的函数,而它是 README 的
    首次运行步骤 —— 单测只覆盖 snapquiz/,从没碰过 scripts/。
    """

    def _script(self, name):
        return pathlib.Path(__file__).parent.parent / "scripts" / name

    def test_every_shipped_script_imports_cleanly(self, _stdout):
        import py_compile
        import importlib.util
        import sys

        scripts = sorted((pathlib.Path(__file__).parent.parent / "scripts").glob("*.py"))
        self.assertTrue(scripts, "scripts/ 不该是空的")
        for script in scripts:
            with self.subTest(script=script.name):
                py_compile.compile(str(script), doraise=True)
                spec = importlib.util.spec_from_file_location(
                    f"_shipped_{script.stem}", script
                )
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                except SystemExit:
                    pass  # 脚本以 main() 收尾时不会触发,这里只是保险
                self.assertTrue(hasattr(module, "main"), f"{script.name} 应有 main()")

    def test_grant_check_reports_all_three_permission_states(self, _stdout):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_grant_check", self._script("grant_check.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        from snapquiz.platform import (
            PermissionObservation,
            PermissionReason,
            ScreenPermissionState,
        )

        class FakePlatform:
            name = "fake"

            def __init__(self, observation):
                self._observation = observation

            def screen_permission(self):
                return self._observation

            def request_screen_permission(self):
                return False

            def install_hotkey(self, spec, on_trigger):  # pragma: no cover
                raise NotImplementedError

        cases = [
            (ScreenPermissionState.GRANTED, PermissionReason.GRANTED, 0),
            (ScreenPermissionState.DENIED, PermissionReason.DENIED, 1),
            (ScreenPermissionState.UNKNOWN, PermissionReason.API_ERROR, 1),
        ]
        for state, reason, expected in cases:
            with self.subTest(state=state), patch.object(
                module, "current",
                lambda s=state, r=reason: FakePlatform(PermissionObservation(s, r)),
            ):
                self.assertEqual(module.main(), expected)


class PackagedAppConfigTest(unittest.TestCase):
    """打包成 .app 之后工作目录是 `/`，仓库里的 .env 根本不在搜索路径上。"""

    def setUp(self):
        from snapquiz import app

        self.app = app
        self.home = pathlib.Path(tempfile.mkdtemp(prefix="snapquiz-home-"))
        self.cwd = pathlib.Path(tempfile.mkdtemp(prefix="snapquiz-cwd-"))
        patcher = patch.multiple(
            app,
            USER_CONFIG_DIR=self.home,
            USER_ENV_PATH=self.home / ".env",
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _load_with(self, user_env=None, local_env=None):
        import os

        if user_env is not None:
            (self.home / ".env").write_text(user_env, encoding="utf-8")
        if local_env is not None:
            (self.cwd / ".env").write_text(local_env, encoding="utf-8")
        keys = ("SNAPQUIZ_PROVIDER", "SNAPQUIZ_TESTVAL")
        saved = {k: os.environ.pop(k, None) for k in keys}
        old = os.getcwd()
        try:
            os.chdir(self.cwd)
            self.app.load_environment()
            return {k: os.environ.get(k) for k in keys}
        finally:
            os.chdir(old)
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_user_level_env_is_found_regardless_of_cwd(self):
        got = self._load_with(user_env="SNAPQUIZ_TESTVAL=from-user\n")
        self.assertEqual(got["SNAPQUIZ_TESTVAL"], "from-user")

    def test_nearby_env_overrides_the_user_level_one(self):
        """从仓库里跑时，手头那份配置更贴近当下的工作，应当压过全局。"""

        got = self._load_with(
            user_env="SNAPQUIZ_TESTVAL=from-user\n",
            local_env="SNAPQUIZ_TESTVAL=from-local\n",
        )
        self.assertEqual(got["SNAPQUIZ_TESTVAL"], "from-local")

    def test_missing_both_is_not_an_error(self):
        self._load_with()  # 不抛错即可

    def test_gui_missing_key_message_names_the_fixed_path(self):
        text = self.app.missing_key_help("GLM_API_KEY", gui=True)
        self.assertIn(str(self.home / ".env"), text)
        self.assertIn("GLM_API_KEY", text)

    def test_terminal_missing_key_message_points_at_the_project(self):
        text = self.app.missing_key_help("GLM_API_KEY", gui=False)
        self.assertIn(".env.example", text)

    def test_gui_launch_detected_without_a_tty(self):
        import io

        with patch("sys.stdin", io.StringIO("")):
            self.assertTrue(self.app.is_gui_launch())
