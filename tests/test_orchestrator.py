import unittest

from snapquiz.core.orchestrator import Orchestrator
from snapquiz.core.legacy import LegacyPipelineDisabledError


class OrchestratorTest(unittest.TestCase):
    def test_run_once_is_disabled_before_all_injected_capabilities(self):
        calls = []

        class Provider:
            def answer(self, *args, **kwargs):
                calls.append("provider")

        orch = Orchestrator(
            provider=Provider(),
            capture_fn=lambda: calls.append("capture"),
            present_fn=lambda result: calls.append("present"),
            has_permission_fn=lambda: calls.append("permission") or True,
            on_denied=lambda: calls.append("denied"),
        )

        with self.assertRaises(LegacyPipelineDisabledError):
            orch.run_once()

        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
