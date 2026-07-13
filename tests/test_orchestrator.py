import unittest

from snapquiz.core.orchestrator import Orchestrator
from snapquiz.llm.base import AnswerResult


class FakeProvider:
    def __init__(self, result):
        self.result = result
        self.seen_url = None

    def answer(self, image_data_url, question_hint=None):
        self.seen_url = image_data_url
        return self.result


def make_result(answer="B"):
    return AnswerResult(answer=answer, rationale="r", confidence=0.9, raw="{}", parsed_ok=True)


class OrchestratorTest(unittest.TestCase):
    def test_happy_path_capture_answer_present(self):
        result = make_result()
        provider = FakeProvider(result)
        presented = []
        orch = Orchestrator(
            provider=provider,
            capture_fn=lambda: "data:image/png;base64,ZZ",
            present_fn=presented.append,
            has_permission_fn=lambda: True,
            on_denied=lambda: presented.append("DENIED"),
        )

        orch.run_once()

        self.assertEqual(provider.seen_url, "data:image/png;base64,ZZ")
        self.assertEqual(presented, [result])

    def test_permission_denied_short_circuits(self):
        provider = FakeProvider(make_result())
        captured = []
        presented = []
        denied = []
        orch = Orchestrator(
            provider=provider,
            capture_fn=lambda: captured.append(1) or "x",
            present_fn=presented.append,
            has_permission_fn=lambda: False,
            on_denied=lambda: denied.append(1),
        )

        orch.run_once()

        self.assertEqual(denied, [1])
        self.assertEqual(captured, [])           # 未授权则不截屏(fail-closed)
        self.assertIsNone(provider.seen_url)     # 未调用模型
        self.assertEqual(presented, [])


if __name__ == "__main__":
    unittest.main()
