import subprocess
import sys
import unittest
from pathlib import Path


class DomainImportBoundaryTest(unittest.TestCase):
    def test_domain_and_result_import_without_provider_or_capture_dependencies(self):
        root = Path(__file__).resolve().parents[1]
        script = """
import sys
import snapquiz.domain
import snapquiz.result
for forbidden in ('openai', 'mss', 'Quartz'):
    assert forbidden not in sys.modules, forbidden
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
