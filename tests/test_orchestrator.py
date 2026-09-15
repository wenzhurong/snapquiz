import json
import unittest

from snapquiz.adapters.glm import GlmChatAdapter
from snapquiz.config import Config
from snapquiz.core.orchestrator import Orchestrator
from snapquiz.core.permissions import PermissionDenied
from snapquiz.domain.adapter import TransportResponse
from snapquiz.domain.solve import SolveStatus

PNG = b"\x89PNG\r\n\x1a\nfake-pixels"


def _success_body(model="glm-4.6v-flash", answer="B"):
    payload = {
        "schema_version": "snapquiz.solve-result.v2",
        "status": "answered",
        "question_summary": "一道选择题",
        "answer": answer,
        "rationale": "因为 B 选项符合题意。",
        "confidence": 0.82,
        "confidence_kind": "model_self_reported",
        "confidence_calibration_ref": None,
        "warnings": [],
    }
    return json.dumps(
        {
            "id": "task-1",
            "request_id": "req-1",
            "created": 1788134400,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": json.dumps(payload)},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 90, "completion_tokens": 30, "total_tokens": 120},
        }
    ).encode()


class Recorder:
    def __init__(self):
        self.captures = 0
        self.sends = 0
        self.presented = []
        self.errors = []
        self.key_resolutions = 0


def build(recorder, *, approve=True, capture_exc=None, permission_exc=None, env_key="k"):
    cfg = Config(region=(0, 0, 640, 480))

    def capture():
        recorder.captures += 1
        if capture_exc:
            raise capture_exc
        return PNG

    def send(prepared, *, api_key, timeout, provider_profile_id):
        recorder.sends += 1
        recorder.key_resolutions += 1
        assert api_key == env_key
        return TransportResponse(
            request_envelope_digest=prepared.envelope_digest,
            http_status=200,
            body=_success_body(model=cfg.model),
        )

    def permission():
        if permission_exc:
            raise permission_exc

    return cfg, Orchestrator(
        config=cfg,
        adapter=GlmChatAdapter(),
        capture_fn=capture,
        send_fn=send,
        present_fn=recorder.presented.append,
        require_permission_fn=permission,
        on_error=recorder.errors.append,
        approve_fn=lambda prepared: approve,
    )


class OrchestratorTest(unittest.TestCase):
    def setUp(self):
        import os

        os.environ["GLM_API_KEY"] = "k"
        self.addCleanup(os.environ.pop, "GLM_API_KEY", None)

    def test_happy_path_presents_validated_result(self):
        rec = Recorder()
        _, orch = build(rec)
        result = orch.run_once()
        self.assertIsNotNone(result)
        self.assertEqual(result.status, SolveStatus.ANSWERED)
        self.assertEqual(result.answer, "B")
        self.assertEqual(rec.presented, [result])
        self.assertEqual((rec.captures, rec.sends), (1, 1))
        self.assertEqual(rec.errors, [])

    def test_declining_approval_sends_nothing_and_resolves_no_key(self):
        rec = Recorder()
        _, orch = build(rec, approve=False)
        self.assertIsNone(orch.run_once())
        self.assertEqual(rec.captures, 1)
        self.assertEqual(rec.sends, 0, "取消后不得发送")
        self.assertEqual(rec.key_resolutions, 0, "取消后不得解析密钥")
        self.assertEqual(len(rec.errors), 1)

    def test_permission_denied_never_captures(self):
        rec = Recorder()
        _, orch = build(rec, permission_exc=PermissionDenied("denied"))
        self.assertIsNone(orch.run_once())
        self.assertEqual(rec.captures, 0, "权限没过就不能截图")
        self.assertEqual(rec.sends, 0)

    def test_capture_failure_never_sends(self):
        rec = Recorder()
        _, orch = build(rec, capture_exc=RuntimeError("黑帧"))
        self.assertIsNone(orch.run_once())
        self.assertEqual(rec.sends, 0)
        self.assertEqual(len(rec.errors), 1)

    def test_errors_do_not_escape_to_caller(self):
        rec = Recorder()
        _, orch = build(rec, permission_exc=PermissionDenied("x"))
        try:
            orch.run_once()
        except Exception as exc:  # pragma: no cover
            self.fail(f"run_once 不应抛给调用方:{exc!r}")

    def test_secret_never_appears_in_error_text(self):
        rec = Recorder()
        _, orch = build(rec, capture_exc=RuntimeError("boom"))
        orch.run_once()
        for message in rec.errors:
            self.assertNotIn("k", message.split(":")[-1].strip().replace("boom", ""))


if __name__ == "__main__":
    unittest.main()
