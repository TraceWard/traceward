import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceward.config import load_observer_env


class ConfigTests(unittest.TestCase):
    def test_only_observer_settings_and_environment_wins(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"UNSLOTH_TOKEN": "external"}, clear=True):
            env = Path(directory) / ".env"
            env.write_text('UNSLOTH_TOKEN=file-value\nexport TRACEWARD_LAYA_MODEL="laya-english" # note\n'
                           'TRACEWARD_LAYA_URL=http://localhost:8888/v1/systemone\nHOME=wrong\nPYTHONPATH=wrong\n')
            load_observer_env(env)
            self.assertEqual(os.environ["UNSLOTH_TOKEN"], "external")
            self.assertEqual(os.environ["TRACEWARD_LAYA_MODEL"], "laya-english")
            self.assertNotIn("HOME", os.environ)
            self.assertNotIn("PYTHONPATH", os.environ)

    def test_never_sources_shell_commands_and_does_not_echo_invalid_values(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            env = Path(directory) / ".env"
            env.write_text("UNSLOTH_TOKEN='$(do-not-execute)'\n")
            load_observer_env(env)
            self.assertEqual(os.environ["UNSLOTH_TOKEN"], "$(do-not-execute)")
            del os.environ["UNSLOTH_TOKEN"]
            env.write_text('UNSLOTH_TOKEN="private-value\n')
            with self.assertRaises(ValueError) as raised:
                load_observer_env(env)
            self.assertNotIn("private-value", str(raised.exception))

    def test_checkout_file_not_untrusted_working_directory(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            root = Path(directory) / "observer"
            root.mkdir()
            (root / "pyproject.toml").touch()
            (root / ".env").write_text("UNSLOTH_TOKEN=observer\n")
            hostile = Path(directory) / "task"
            hostile.mkdir()
            (hostile / ".env").write_text("UNSLOTH_TOKEN=hostile\n")
            with patch("traceward.config.__file__", str(root / "src/traceward/config.py")), patch("os.getcwd", return_value=str(hostile)):
                load_observer_env()
            self.assertEqual(os.environ["UNSLOTH_TOKEN"], "observer")

    def test_explicit_missing_file_is_an_error(self):
        with patch.dict(os.environ, {"TRACEWARD_ENV_FILE": "/not/a/traceward/settings/file"}, clear=True):
            with self.assertRaises(ValueError):
                load_observer_env()
