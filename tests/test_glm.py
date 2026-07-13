import json
import logging
import unittest

from snapquiz.llm.glm import GLMProvider

# 重试路径会打 WARNING 日志;测试里刻意触发失败,静音以保持输出干净
logging.getLogger("snapquiz.llm.glm").setLevel(logging.ERROR)


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content):
        self.choices = [_Choice(content)]


class FakeCompletions:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.script[len(self.calls) - 1]
        if isinstance(item, Exception):
            raise item
        return _Resp(item)


class FakeClient:
    def __init__(self, script):
        self.chat = type("Chat", (), {"completions": FakeCompletions(script)})()


def make_provider(script, max_retries=2):
    client = FakeClient(script)
    provider = GLMProvider(
        model="glm-4.6v-flash",
        client=client,
        max_retries=max_retries,
        backoff=lambda n: None,  # 测试中不真正 sleep
    )
    return provider, client


class GLMProviderTest(unittest.TestCase):
    def test_parses_successful_response(self):
        provider, client = make_provider(
            ['{"answer": "B", "rationale": "因为…", "confidence": 0.5}']
        )
        result = provider.answer("data:image/png;base64,ZZ")
        self.assertEqual(result.answer, "B")
        self.assertEqual(result.confidence, 0.5)

    def test_sends_model_and_image_url(self):
        provider, client = make_provider(['{"answer": "A", "rationale": "x"}'])
        provider.answer("data:image/png;base64,ZZ")
        call = client.chat.completions.calls[0]
        self.assertEqual(call["model"], "glm-4.6v-flash")
        self.assertIn("data:image/png;base64,ZZ", json.dumps(call["messages"]))

    def test_retries_then_succeeds(self):
        provider, client = make_provider(
            [RuntimeError("net"), RuntimeError("net"), '{"answer": "A", "rationale": "x"}'],
            max_retries=2,
        )
        result = provider.answer("url")
        self.assertEqual(result.answer, "A")
        self.assertEqual(len(client.chat.completions.calls), 3)

    def test_raises_after_exhausting_retries(self):
        provider, _ = make_provider(
            [RuntimeError("net"), RuntimeError("net"), RuntimeError("net")],
            max_retries=2,
        )
        with self.assertRaises(RuntimeError):
            provider.answer("url")


if __name__ == "__main__":
    unittest.main()
