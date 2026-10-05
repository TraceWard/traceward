"""Host setup/credential regressions without touching actual credentials."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceward.cli import _parse_run
from traceward.runtime import ManagedRuntime, codex_home, hook_overrides, workspace_root


class RuntimeTests(unittest.TestCase):
    def test_codex_flags_are_forwarded_verbatim_after_agent_name(self):
        options = _parse_run(['--goal','Fix tests','--runner-image','runner:v1','--workspace','/workspace',
                              'codex','exec','--config','model="example"','two words'])
        self.assertEqual(options[2], ['exec','--config','model="example"','two words'])
        self.assertEqual(options[3:5], ('runner:v1','/workspace'))
        self.assertIn('/opt/traceward-hooks', ' '.join(hook_overrides()))

    def test_keychain_rejected_without_extracting_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'config.toml').write_text('cli_auth_credentials_store="keyring"')
            (root/'auth.json').write_text('not json and never read')
            with patch.dict(os.environ, {'CODEX_HOME':directory}):
                with self.assertRaisesRegex(RuntimeError, 'Keychain'):
                    codex_home()

    def test_file_credentials_detected_without_reading_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'auth.json').write_text('opaque credential file')
            with patch.dict(os.environ, {'CODEX_HOME':directory}):
                self.assertEqual(codex_home(), root.resolve())

    def test_guest_does_not_mount_collector_or_observer_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace, home, run = root/'workspace', root/'home', root/'run'
            for path in (workspace,home,run): path.mkdir()
            (home/'auth.json').touch()
            with patch('traceward.runtime.Path.cwd',return_value=workspace), \
                 patch('traceward.runtime.ensure_image',return_value={'Id':'sha256:test','Architecture':'arm64'}), \
                 patch.dict(os.environ, {'CODEX_HOME':str(home),'TRACEWARD_MANAGED_RUNNER':'0',
                                        'UNSLOTH_TOKEN':'NEVER_FORWARD','TRACEWARD_ENV_FILE':str(root/'observer.env')}):
                runtime = ManagedRuntime(run,'uuid',['exec','hello'],workspace=str(workspace))
            request = json.loads((run/'request.json').read_text())
            self.assertNotIn('NEVER_FORWARD', json.dumps(request))
            self.assertNotIn('UNSLOTH_TOKEN', request['env'])
            targets = [m[1] for m in request['guest_mounts']]
            self.assertNotIn('/observer-run', targets)
            self.assertIn('/traceward-hooks/hooks.jsonl', targets)
            self.assertNotIn('--privileged',runtime.command)
            self.assertNotIn('/var/run/docker.sock',' '.join(runtime.command))
            self.assertEqual((run/'request.json').stat().st_mode & 0o777,0o600)

    def test_workspace_must_contain_current_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.assertRaises(ValueError):
                workspace_root(root, '/not-a-workspace')
