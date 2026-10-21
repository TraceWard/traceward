"""Correlation and replay regressions using structured gVisor fixtures."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen
from traceward.engine import Engine
from traceward.hook_sink import compact_hook
from traceward.evidence_packet import packet
from traceward.ocsf import CLASSES, EvidenceStore, project, validate_minimum
from traceward.replay import replay
from traceward.gvisor import GvisorParser
from test_gvisor import scenario, record, done
HOOK = {"event": "PreToolUse", "source": "codex_hook", "time": 100.0,
        "tool_name": "Bash", "tool_use_id": "tool-1", "session_id": "session-1",
        "command": "npm test", "cwd": "/workspace"}

class TracewardTests(unittest.TestCase):
    def exercise(self, command="npm test", hidden=True, hooks=True, extra=()):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        alerts = []
        root = Path(directory.name)
        engine = Engine("Fix tests", EvidenceStore(root, "fixture"),
                        judge_fn=lambda _: {"status": "unavailable", "reason": "test"},
                        alert_fn=alerts.append, measure_latency=False)
        if hooks:
            engine.hook({**HOOK, "command": command})
        parser = GvisorParser("/workspace")
        for line in [*scenario(command, hidden), *extra]:
            event = parser.parse(line)
            if event: engine.effect(event)
        if hooks:
            engine.hook({**HOOK, "event": "PostToolUse", "time": 102})
        engine.finish()
        return engine, alerts, root

    def test_hidden_child_effect_is_linked_and_alerted(self):
        engine, alerts, root = self.exercise()
        self.assertEqual(engine._tool_for("fixture:201:201000"), "tool-1")
        self.assertEqual(engine.summary()["finding_count"], 1)
        self.assertEqual(alerts[0]["observed_effects"], ["file_read", "network_send"])
        self.assertTrue(alerts[-1]["episode_complete"])
        self.assertGreaterEqual(len(alerts[-1]["evidence_ids"]), 4)
        for line in (root/"events.jsonl").read_text().splitlines(): validate_minimum(json.loads(line))

    def test_ordinary_case_and_missing_hook(self):
        engine, alerts, _ = self.exercise(hidden=False)
        self.assertFalse(alerts)
        engine, alerts, _ = self.exercise(hooks=False)
        self.assertFalse(alerts)
        self.assertTrue(any("no Codex hooks" in g for g in engine.coverage_gaps))

    def test_sensitive_write_has_distinct_finding(self):
        extra = [record(7, pid=201, time=101, pathname='/workspace/synthetic-auth-config.json', exit=done(3)),
                 record(34, pid=201, time=101.1, fd=3, exit=done(20))]
        engine, alerts, _ = self.exercise(command='npm run coverage', hidden=False, extra=extra)
        self.assertEqual(alerts[0]['observed_effects'], ['file_write'])
        self.assertEqual(engine.summary()['finding_count'], 1)

    def test_pid_reuse_does_not_link_new_process_to_old_tool(self):
        extra = [record(3, pid=200, start=999999, time=103, binary_path='/bin/sh'),
                 record(34, pid=200, start=999999, time=103.1, fd=3, fd_path='/workspace/synthetic-auth-config.json', exit=done(3))]
        engine, alerts, _ = self.exercise(hidden=False, extra=extra)
        self.assertIsNone(engine._tool_for('fixture:200:999999'))
        self.assertEqual(engine.summary()['finding_count'], 1)
        self.assertIsNone(alerts[-1]['tool_use_id'])
        self.assertEqual(alerts[-1]['attribution'], 'uncertain')

    def test_ambiguous_hook_attribution_is_withdrawn(self):
        extra = [record(3, pid=202, time=100.25, binary_path='/bin/sh', command_candidates=['npm test'])]
        engine, _, _ = self.exercise(hidden=False, extra=extra)
        self.assertNotIn('tool-1', engine.links.values())
        self.assertEqual(engine.summary()['ambiguous_tool_attributions'], 1)

    def test_offline_replay_preserves_structured_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hooks, trace = root/'hooks.jsonl', root/'raw.gvisor.jsonl'
            hooks.write_text(json.dumps(HOOK)+'\n')
            trace.write_text('\n'.join(scenario())+'\n')
            with patch.dict(os.environ, {'XDG_STATE_HOME': str(root/'state')}):
                self.assertEqual(replay(['--goal','Fix tests','--hooks',str(hooks),'--trace',str(trace),'--offline']),0)
            summary = next((root/'state/traceward/runs').glob('*/summary.json'))
            self.assertEqual(json.loads(summary.read_text())['finding_count'],0)
            self.assertEqual(json.loads(summary.read_text())['assessment_count'],2)
            findings = [json.loads(line) for line in (summary.parent/'assessments.jsonl').read_text().splitlines()]
            self.assertEqual({f.get('candidate_kind') for f in findings}, {'sensitive_access','network_effect'})

    def test_hook_redacts_and_never_persists_response(self):
        item = compact_hook({"hook_event_name": "PreToolUse", "tool_input": {
            "command": "echo API_KEY=sk-123456789abc"}, "tool_response": {"secret": "do-not-save"}})
        encoded = json.dumps(item)
        self.assertNotIn("sk-123456789abc", encoded)
        self.assertNotIn("do-not-save", encoded)

    def test_evidence_packet_has_no_payload(self):
        finding = {"title": "Suspicious", "attribution": "command-and-process-lineage"}
        evidence = packet("Fix tests", finding, [{"event_id": "e1", "kind": "file_read",
                                                  "path": "/tmp/credential", "buffer": "SECRET"}], [])
        self.assertNotIn("SECRET", json.dumps(evidence))

    @unittest.skipUnless(os.environ.get("TRACEWARD_TEST_OCSF_ONLINE") == "1", "opt-in official OCSF v1.8 validator")
    def test_pinned_official_ocsf_schema(self):
        sample = {"time": 100, "pid": 7, "parent_pid": 6, "name": "/bin/sh",
                  "command": "/bin/sh", "path": "/tmp/test", "bytes": 3,
                  "endpoint": "127.0.0.1:8800", "finding_id": "f1", "title": "Test",
                  "message": "Test", "revision": 1, "evidence_ids": []}
        cases = [(kind, sample) for kind in CLASSES]
        cases.append(("finding", {**sample, "revision": 2, "status": "consistent_with_goal"}))
        for kind, item in cases:
            with self.subTest(kind=kind, revision=item["revision"]):
                body = json.dumps(project(kind, item, "test")).encode()
                request = Request("https://schema.ocsf.io/1.8.0/api/v2/validate",
                                  data=body, headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=20) as response:
                    result = json.load(response)
                self.assertEqual(result["error_count"], 0, result["errors"])


if __name__ == "__main__":
    unittest.main()
