import builtins
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from snapquiz import app
from snapquiz.core.legacy import (
    LEGACY_DISABLED_EXIT_CODE,
    LEGACY_DISABLED_MESSAGE,
    LegacyPipelineDisabledError,
)


class SideEffectProbe:
    """M0 统一副作用探针：任何 capability 被触达都让测试立即失败。"""

    def __init__(self):
        self.events = []

    def trip(self, name):
        def forbidden(*args, **kwargs):
            del args, kwargs
            self.events.append(name)
            raise AssertionError(f"forbidden side effect: {name}")

        return forbidden


class M0FailClosedTest(unittest.TestCase):
    def test_v3_config_package_does_not_reexport_legacy_secret_config(self):
        import snapquiz.config as config_package

        spec = importlib.util.find_spec("snapquiz.config")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.submodule_search_locations)
        self.assertFalse(hasattr(config_package, "Config"))
        self.assertFalse(hasattr(config_package, "load_config"))

    def test_fresh_cli_process_has_poisoned_optional_import_and_network_boundary(self):
        repository_root = Path(__file__).resolve().parents[1]
        sitecustomize = """
import builtins
import socket

_original_import = builtins.__import__

def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if (
        name.split('.', 1)[0] in {'dotenv', 'mss', 'Quartz', 'openai', 'pynput'}
        or name == 'snapquiz.config'
        or name.startswith('snapquiz.config.')
        or name == 'snapquiz.legacy_config'
    ):
        raise RuntimeError('forbidden optional import: ' + name)
    return _original_import(name, globals, locals, fromlist, level)

def _forbidden_network(*args, **kwargs):
    raise RuntimeError('forbidden network capability')

builtins.__import__ = _guarded_import
socket.getaddrinfo = _forbidden_network
socket.socket = _forbidden_network
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            Path(temporary_directory, "sitecustomize.py").write_text(
                sitecustomize, encoding="utf-8"
            )
            child_environment = {
                "PYTHONPATH": os.pathsep.join(
                    (temporary_directory, str(repository_root))
                ),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            for trigger in ("stdin", "hotkey"):
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "snapquiz.app",
                        "--trigger",
                        trigger,
                    ],
                    cwd=repository_root,
                    env=child_environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                with self.subTest(trigger=trigger):
                    self.assertEqual(completed.returncode, LEGACY_DISABLED_EXIT_CODE)
                    self.assertIn(LEGACY_DISABLED_MESSAGE, completed.stderr)
                    self.assertNotIn("forbidden", completed.stderr)

    def test_all_cli_triggers_exit_before_secret_permission_capture_sdk_or_network(self):
        for trigger in ("stdin", "hotkey"):
            with self.subTest(trigger=trigger):
                probe = SideEffectProbe()
                fake_openai = types.ModuleType("openai")
                fake_openai.OpenAI = probe.trip("sdk_construct")
                stderr = io.StringIO()
                original_import = builtins.__import__

                def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
                    root_name = name.split(".", 1)[0]
                    if root_name in {"dotenv", "mss", "Quartz", "openai", "pynput"}:
                        return probe.trip(f"import:{root_name}")()
                    return original_import(name, globals, locals, fromlist, level)

                with (
                    patch(
                        "snapquiz.legacy_config.load_config",
                        probe.trip("secret_resolve"),
                    ),
                    patch(
                        "snapquiz.core.permissions.has_screen_recording",
                        probe.trip("permission"),
                    ),
                    patch(
                        "snapquiz.core.permissions.request_screen_recording",
                        probe.trip("permission_request"),
                    ),
                    patch(
                        "snapquiz.capture.screen.capture_data_url",
                        probe.trip("capture"),
                    ),
                    patch(
                        "snapquiz.llm.glm.GLMProvider.answer",
                        probe.trip("http"),
                    ),
                    patch("socket.getaddrinfo", probe.trip("dns")),
                    patch("socket.socket", probe.trip("socket")),
                    patch.dict(sys.modules, {"openai": fake_openai}),
                    patch.dict("os.environ", {}, clear=True),
                    patch("builtins.__import__", guarded_import),
                    contextlib.redirect_stderr(stderr),
                ):
                    status = app.main(["--trigger", trigger])

                self.assertEqual(status, LEGACY_DISABLED_EXIT_CODE)
                self.assertEqual(probe.events, [])
                self.assertIn(LEGACY_DISABLED_MESSAGE, stderr.getvalue())

    def test_legacy_app_helpers_raise_without_reading_inputs(self):
        class PoisonConfig:
            def __getattribute__(self, name):
                raise AssertionError(f"config must not be read: {name}")

        with self.assertRaises(LegacyPipelineDisabledError):
            app._build_orchestrator(PoisonConfig())
        with self.assertRaises(LegacyPipelineDisabledError):
            app._startup_permission_hint()


if __name__ == "__main__":
    unittest.main()
