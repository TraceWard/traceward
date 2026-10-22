"""Host setup/credential regressions without touching actual credentials."""
import json
import os
import tempfile
import tomllib
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from traceward.cli import _parse_run
from traceward.runtime import CODEX_HOOK_EVENTS, ManagedRuntime, codex_home, hook_overrides, workspace_root
from traceward.hook_sink import compact_hook
from traceward.ocsf import project


class RuntimeTests(unittest.TestCase):
    def test_all_codex_hooks_are_passive_and_unfiltered(self):
        overrides = hook_overrides()
        config = tomllib.loads('\n'.join(overrides[1::2]))['hooks']
        self.assertEqual(set(config), set(CODEX_HOOK_EVENTS))
        self.assertEqual(len(config), 12)
        for event, groups in config.items():
            self.assertNotIn('matcher', groups[0])
            handler = groups[0]['hooks'][0]
            self.assertEqual(handler['type'], 'command')
            if event in {'Interrupt', 'SessionEnd'}:
                self.assertLessEqual(handler['timeout'], 3)

    def test_lifecycle_metadata_survives_projection_without_prompt_capture(self):
        for event in CODEX_HOOK_EVENTS:
            hook = compact_hook({'hook_event_name': event, 'source': 'startup',
                'reason': 'clear', 'agent_id': 'child', 'agent_type': 'worker',
                'prompt': 'PRIVATE PROMPT', 'transcript_path': '/private/transcript',
                'headers': {'Authorization': 'PRIVATE HEADER'}})
            meta = project('hook', hook, 'r')['unmapped']['traceward']
            self.assertEqual(meta['hook_event'], event)
            self.assertEqual(meta['hook_metadata']['source'], 'startup')
            self.assertEqual(meta['hook_metadata']['agent_id'], 'child')
            self.assertNotIn('PRIVATE', json.dumps(meta))
            self.assertNotIn('/private/transcript', json.dumps(meta))

    def test_stop_hooks_return_neutral_json_even_when_evidence_write_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            for event in ('Stop', 'SubagentStop'):
                result = subprocess.run([sys.executable, '-m', 'traceward.hook_sink'],
                    input=json.dumps({'hook_event_name': event}), capture_output=True, text=True,
                    env=dict(os.environ, TRACEWARD_HOOK_FILE=str(Path(directory) / 'missing' / 'hooks.jsonl')))
                self.assertEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout), {})

    def test_codex_flags_are_forwarded_verbatim_after_agent_name(self):
        options = _parse_run(['--runner-image','runner:v1','--workspace','/workspace',
                              'codex','exec','--config','model="example"','two words'])
        self.assertEqual(options[1], ['exec','--config','model="example"','two words'])
        self.assertEqual(options[0], 'two words')
        self.assertEqual(options[2:4], ('runner:v1','/workspace'))
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
                                        'TRACEWARD_JUDGE_TOKEN':'NEVER_FORWARD','OPENROUTER_KEY':'NEVER_FORWARD',
                                        'LMSTUDIO_API_KEY':'NEVER_FORWARD','TRACEWARD_ENV_FILE':str(root/'observer.env')}):
                runtime = ManagedRuntime(run,'uuid',['exec','hello'],workspace=str(workspace))
            request = json.loads((run/'request.json').read_text())
            self.assertNotIn('NEVER_FORWARD', json.dumps(request))
            for key in ('TRACEWARD_JUDGE_TOKEN','OPENROUTER_KEY','LMSTUDIO_API_KEY'):
                self.assertNotIn(key, request['env'])
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
