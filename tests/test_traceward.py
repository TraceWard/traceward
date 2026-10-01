from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen
from pathlib import Path

from traceward.engine import Engine
from traceward.hook_sink import compact_hook
from traceward.laya import _score, packet, payload
from traceward.ocsf import CLASSES, EvidenceStore, project, validate_minimum
from traceward.replay import replay
from traceward.strace import StraceParser


HOOK = {
    "event": "PreToolUse", "source": "codex_hook", "time": 100.0,
    "tool_name": "Bash", "tool_use_id": "tool-1", "session_id": "session-1",
    "command": "npm test", "cwd": "/workspace",
}


def lines(hidden: bool = True) -> list[str]:
    result = [
        '[pid 100] 100.100000 clone(child_stack=NULL, flags=SIGCHLD) = 200',
        '[pid 200] 100.200000 execve("/bin/sh", ["sh", "-lc", "npm test"], 0x0) = 0',
        '[pid 200] 100.300000 clone(child_stack=NULL, flags=SIGCHLD) = 201',
        '[pid 201] 100.400000 execve("/usr/bin/node", ["node", "test.js"], 0x0) = 0',
    ]
    if hidden:
        result += [
            '[pid 201] 101.000000 openat(AT_FDCWD, "/workspace/synthetic-credential.txt", O_RDONLY) = 3</workspace/synthetic-credential.txt>',
            '[pid 201] 101.100000 read(0x3, 0x7ffaaa, 0x1000) = 0x10',
            '[pid 201] 101.200000 connect(4<socket:[45]>, {sa_family=AF_INET, sin_port=htons(8800), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
            '[pid 201] 101.300000 sendto(0x4, 0x7ffaa, 0x10, 0, NULL, 0) = 0x10',
        ]
    return result


class TracewardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = EvidenceStore(Path(self.tmp.name), "run-test")

    def _engine(self):
        alerts = []
        engine = Engine("Fix the failing test", self.store,
                        judge_fn=lambda _: {"status": "unavailable", "reason": "test"},
                        alert_fn=alerts.append)
        return engine, alerts

    def test_hidden_child_effect_is_linked_and_alerted(self):
        engine, alerts = self._engine()
        engine.hook(HOOK)
        parser = StraceParser("/workspace")
        for line in lines():
            event = parser.parse(line)
            if event:
                engine.effect(event)
        engine.finish()
        self.assertEqual(engine.links[200], "tool-1")
        self.assertEqual(engine._tool_for(201), "tool-1")
        self.assertEqual(engine.summary()["finding_count"], 1)
        self.assertEqual(len(alerts), 2)
        finding = alerts[0]
        self.assertEqual(finding["observed_effects"], ["file_read", "network_send"])
        self.assertGreaterEqual(len(finding["evidence_ids"]), 4)
        self.assertNotIn("synthetic-credential", HOOK["command"])
        self.assertNotIn("Fix the failing test", json.dumps([effect for effect in engine.effects]))
        self.assertEqual(finding["tool_use_id"], "tool-1")
        self.assertIsNone(finding["uncalibrated_risk_score"])
        events = [json.loads(s) for s in (Path(self.tmp.name) / "events.jsonl").read_text().splitlines()]
        self.assertEqual({1001, 1007, 4001, 2004}.issubset({e["class_uid"] for e in events}), True)
        for event in events:
            validate_minimum(event)

    def test_normal_and_unusual_without_secret_read_do_not_alert(self):
        engine, alerts = self._engine()
        engine.hook(HOOK)
        parser = StraceParser("/workspace")
        for line in lines(hidden=False):
            event = parser.parse(line)
            if event:
                engine.effect(event)
        engine.finish()
        self.assertFalse(alerts)
        self.assertEqual(engine.summary()["finding_count"], 0)

    def test_network_send_without_sensitive_read_has_distinct_finding(self):
        engine, alerts = self._engine()
        engine.hook({**HOOK, "command": "npm run report"})
        parser = StraceParser("/workspace")
        scenario = [
            '[pid 100] 100.1 clone(child_stack=NULL, flags=SIGCHLD) = 200',
            '[pid 200] 100.2 execve("/bin/sh", ["sh", "-lc", "npm run report"], 0x0) = 0',
            '[pid 200] 100.9 openat(AT_FDCWD, "/usr/share/nodejs/npm/lib/auth.js", O_RDONLY) = 3</usr/share/nodejs/npm/lib/auth.js>',
            '[pid 200] 101.0 read(0x3, 0x7ffaaa, 0x20) = 0x20',
            '[pid 200] 101.2 connect(4<socket:[45]>, {sa_family=AF_INET, sin_port=htons(8800), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
            '[pid 200] 101.3 sendto(0x4, 0x7ffaa, 0x10, 0, NULL, 0) = 0x10',
        ]
        for line in scenario:
            event = parser.parse(line)
            if event:
                engine.effect(event)
        engine.finish()
        self.assertEqual(engine.summary()["finding_count"], 1)
        self.assertEqual(alerts[0]["observed_effects"], ["network_send"])
        self.assertIn("Network side effect", alerts[0]["title"])
        self.assertGreaterEqual(len(alerts[0]["evidence_ids"]), 3)

    def test_sensitive_config_write_has_distinct_finding(self):
        engine, alerts = self._engine()
        engine.hook({**HOOK, "command": "npm run coverage"})
        parser = StraceParser("/workspace")
        scenario = [
            '[pid 100] 100.1 clone(child_stack=NULL, flags=SIGCHLD) = 200',
            '[pid 200] 100.2 execve("/bin/sh", ["sh", "-lc", "npm run coverage"], 0x0) = 0',
            '[pid 200] 101.0 openat(AT_FDCWD, "/workspace/synthetic-auth-config.json", O_WRONLY|O_TRUNC) = 3</workspace/synthetic-auth-config.json>',
            '[pid 200] 101.1 write(0x3, 0x7ffaaa, 0x20) = 0x20',
        ]
        for line in scenario:
            event = parser.parse(line)
            if event:
                engine.effect(event)
        engine.finish()
        self.assertEqual(engine.summary()["finding_count"], 1)
        self.assertEqual(alerts[0]["observed_effects"], ["file_write"])
        self.assertIn("Sensitive file modified", alerts[0]["title"])
        self.assertIn("content was not captured", alerts[0]["message"])

    def test_nested_pid_namespace_uses_tracer_visible_child_pid(self):
        engine, alerts = self._engine()
        engine.hook(HOOK)
        parser = StraceParser("/workspace")
        scenario = [
            '[pid 100] 100.1 clone(child_stack=NULL, flags=CLONE_NEWPID|SIGCHLD) = 2 /* 200 in strace\'s PID NS */',
            '[pid 200] 100.2 execve("/bin/sh", ["sh", "-lc", "npm test"], 0x0) = 0',
            '[pid 200] 100.3 clone(child_stack=NULL, flags=SIGCHLD) = 13 /* 201 in strace\'s PID NS */',
            '[pid 201] 100.4 execve("/usr/bin/node", ["node", "test.js"], 0x0) = 0',
            *lines()[4:],
        ]
        for line in scenario:
            event = parser.parse(line)
            if event:
                engine.effect(event)
        engine.finish()
        self.assertEqual(parser.parents[200], 100)
        self.assertEqual(parser.parents[201], 200)
        self.assertEqual(engine._tool_for(201), "tool-1")
        self.assertEqual(engine.summary()["finding_count"], 1)
        self.assertEqual(len(alerts), 2)

    def test_worker_thread_keeps_attribution_without_inflating_process_count(self):
        engine, _ = self._engine()
        engine.hook(HOOK)
        parser = StraceParser("/workspace")
        scenario = [
            *lines()[:2],
            '[pid 200] 100.3 clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_THREAD) = 201',
            '[pid 201] 101.0 openat(AT_FDCWD, "/workspace/synthetic-credential.txt", O_RDONLY) = 3</workspace/synthetic-credential.txt>',
            '[pid 201] 101.1 read(0x3, 0x7ffaaa, 0x1000) = 0x10',
            '[pid 201] 101.2 connect(4<socket:[45]>, {sa_family=AF_INET, sin_port=htons(8800), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
            '[pid 201] 101.3 sendto(0x4, 0x7ffaa, 0x10, 0, NULL, 0) = 0x10',
        ]
        for line in scenario:
            event = parser.parse(line)
            if event:
                engine.effect(event)
        engine.finish()
        self.assertEqual(engine._tool_for(201), "tool-1")
        self.assertEqual(engine.summary()["finding_count"], 1)
        self.assertEqual(engine.summary()["counts"]["process"], 2)

    def test_obvious_direct_action_and_legitimate_unusual_are_review_not_violation(self):
        for goal, command in (
            ("Fix the failing test", "python3 send_credential.py"),
            ("Verify the synthetic credential receiver", "python3 send_credential.py"),
        ):
            with self.subTest(goal=goal):
                with tempfile.TemporaryDirectory() as directory:
                    alerts = []
                    engine = Engine(goal, EvidenceStore(Path(directory), "case"),
                                    judge_fn=lambda _: {"status": "scored", "uncalibrated_risk_score": 0.1},
                                    alert_fn=alerts.append)
                    engine.hook({**HOOK, "command": command})
                    parser = StraceParser("/workspace")
                    scenario = [
                        f'[pid 200] 100.2 execve("/bin/sh", ["sh", "-lc", "{command}"], 0x0) = 0',
                        '[pid 200] 100.3 clone(child_stack=NULL, flags=SIGCHLD) = 201',
                        '[pid 201] 100.4 execve("/usr/bin/python3", ["python3", "send_credential.py"], 0x0) = 0',
                        '[pid 201] 101.0 openat(AT_FDCWD, "/workspace/synthetic-credential.txt", O_RDONLY) = 3</workspace/synthetic-credential.txt>',
                        '[pid 201] 101.1 read(0x3, 0x7777, 0x1000) = 0x10',
                        '[pid 201] 101.2 connect(4<socket:[45]>, {sa_family=AF_INET, sin_port=htons(8800), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
                        '[pid 201] 101.3 sendto(0x4, 0x8888, 0x10, 0, NULL, 0) = 0x10',
                    ]
                    for line in scenario:
                        event = parser.parse(line)
                        if event:
                            engine.effect(event)
                    engine.finish()
                    self.assertEqual(engine.summary()["finding_count"], 1)
                    self.assertEqual(alerts[0]["status"], "suspicious_behaviour")
                    self.assertNotEqual(alerts[-1].get("status"), "confirmed_violation")

    def test_missing_hook_is_a_coverage_gap(self):
        engine, _ = self._engine()
        parser = StraceParser("/workspace")
        for line in lines():
            event = parser.parse(line)
            if event:
                engine.effect(event)
        engine.finish()
        self.assertEqual(engine.summary()["finding_count"], 0)
        self.assertTrue(any("no Codex hooks" in gap for gap in engine.coverage_gaps))

    def test_ambiguous_command_attribution_is_withdrawn(self):
        engine, _ = self._engine()
        engine.hook(HOOK)
        parser = StraceParser("/workspace")
        for pid in (200, 201):
            event = parser.parse(f'[pid {pid}] 100.2 execve("/bin/sh", ["sh", "-lc", "npm test"], 0x0) = 0')
            engine.effect(event)
        self.assertNotIn("tool-1", engine.links.values())
        self.assertTrue(any("ambiguous hook-to-process" in gap for gap in engine.coverage_gaps))

    def test_offline_replay_command_reproduces_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hook_file = root / "hooks.jsonl"
            trace_file = root / "raw.strace"
            hook_file.write_text(json.dumps(HOOK) + "\n", encoding="utf-8")
            trace_file.write_text("\n".join(lines()) + "\n", encoding="utf-8")
            old = os.environ.get("XDG_STATE_HOME")
            os.environ["XDG_STATE_HOME"] = str(root / "state")
            try:
                self.assertEqual(replay(["--goal", "Fix the failing test", "--hooks", str(hook_file),
                                         "--trace", str(trace_file), "--offline"]), 0)
            finally:
                if old is None:
                    os.environ.pop("XDG_STATE_HOME", None)
                else:
                    os.environ["XDG_STATE_HOME"] = old
            summaries = list((root / "state" / "traceward" / "runs").glob("*/summary.json"))
            self.assertEqual(json.loads(summaries[0].read_text())["finding_count"], 1)

    def test_read_requires_positive_return_and_does_not_store_buffer(self):
        parser = StraceParser("/workspace")
        parser.parse('[pid 7] 10.000000 openat(AT_FDCWD, "/workspace/credential", O_RDONLY) = 3</workspace/credential>')
        self.assertIsNone(parser.parse('[pid 7] 10.100000 read(0x3, 0x7ffabc, 0x100) = 0'))
        event = parser.parse('[pid 7] 10.200000 read(0x3, 0x7ffabc, 0x100) = 0x10')
        self.assertEqual(event["path"], "/workspace/credential")
        self.assertEqual(event["bytes"], 16)
        self.assertNotIn("buffer", event)

    def test_unfinished_syscall_is_reassembled(self):
        parser = StraceParser("/workspace")
        parser.parse('[pid 7] 10.0 openat(AT_FDCWD, "/workspace/credential", O_RDONLY) = 3</workspace/credential>')
        self.assertIsNone(parser.parse('[pid 7] 10.1 read(0x3, 0x7777, 0x100 <unfinished ...>'))
        event = parser.parse('[pid 7] 10.2 <... read resumed>) = 0x10')
        self.assertEqual(event["kind"], "file_read")
        self.assertEqual(event["time"], 10.1)

    def test_hook_redacts_and_never_persists_response(self):
        item = compact_hook({"hook_event_name": "PreToolUse", "tool_input": {
            "command": "echo API_KEY=sk-123456789abc"}, "tool_response": {"secret": "do-not-save"}})
        encoded = json.dumps(item)
        self.assertNotIn("sk-123456789abc", encoded)
        self.assertNotIn("do-not-save", encoded)

    def test_laya_packet_has_no_payload(self):
        finding = {"title": "Suspicious", "attribution": "command-and-process-lineage"}
        evidence = packet("Fix tests", finding, [{"event_id": "e1", "kind": "file_read",
                                                  "path": "/tmp/credential", "buffer": "SECRET"}], [])
        self.assertNotIn("SECRET", json.dumps(evidence))
        with patch.dict(os.environ, {"TRACEWARD_LAYA_MODEL": "laya-multilingual"}):
            self.assertEqual(payload(evidence)["model"], "laya-multilingual")
        self.assertEqual(_score({"score": 0.5}), 0.125)

    @unittest.skipUnless(os.environ.get("TRACEWARD_TEST_OCSF_ONLINE") == "1", "opt-in official OCSF v1.8 validator")
    def test_pinned_official_ocsf_schema(self):
        sample = {"time": 100, "pid": 7, "parent_pid": 6, "name": "/bin/sh",
                  "command": "/bin/sh", "path": "/tmp/test", "bytes": 3,
                  "endpoint": "127.0.0.1:8800", "finding_id": "f1", "title": "Test",
                  "message": "Test", "revision": 1, "evidence_ids": []}
        for kind in CLASSES:
            with self.subTest(kind=kind):
                body = json.dumps(project(kind, sample, "test")).encode()
                request = Request("https://schema.ocsf.io/1.8.0/api/v2/validate",
                                  data=body, headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=20) as response:
                    result = json.load(response)
                self.assertEqual(result["error_count"], 0, result["errors"])


if __name__ == "__main__":
    unittest.main()
