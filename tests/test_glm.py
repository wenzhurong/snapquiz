import unittest

from snapquiz.core.legacy import LegacyPipelineDisabledError
from snapquiz.llm.glm import GLMProvider

class GLMProviderTest(unittest.TestCase):
    def test_answer_is_disabled_without_client_or_retry_calls(self):
        calls = []

        class Client:
            @property
            def chat(self):
                calls.append("client")
                raise AssertionError("client must not be accessed")

        provider = GLMProvider(
            model="glm-4.6v-flash",
            client=Client(),
            max_retries=99,
            backoff=lambda seconds: calls.append(("backoff", seconds)),
        )

        with self.assertRaises(LegacyPipelineDisabledError):
            provider.answer("data:image/png;base64,SECRET")

        self.assertEqual(calls, [])

    def test_from_config_is_disabled_without_reading_config(self):
        class PoisonConfig:
            def __getattribute__(self, name):
                raise AssertionError(f"config must not be read: {name}")

        with self.assertRaises(LegacyPipelineDisabledError):
            GLMProvider.from_config(PoisonConfig())


if __name__ == "__main__":
    unittest.main()
