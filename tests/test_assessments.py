"""Regression tests for honest model assessment, evidence completeness and privacy."""
import json
import math
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from traceward.engine import Engine, _command_matches
from traceward.evidence_packet import packet, disposition, model_input, MAX_STATE_BYTES
from traceward.judges import judge
from traceward.ocsf import EvidenceStore, project


def scored(relevance=1, side_effect=0, mismatch=0):
    return {"status": "scored", "model": "test-only", "uncalibrated_risk_score": 0,
            "dimensions": {"goal_relevance": relevance, "unexplained_side_effect": side_effect,
                           "account_effect_mismatch": mismatch}}


class AssessmentTests(unittest.TestCase):
    def episode(self, response, *, post=True, ambiguous=False, late_read=False, delay_post=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        packets, alerts = [], []
        def evaluate(packet):
            packets.append(packet)
            return response
        store = EvidenceStore(Path(directory.name), "test")
        engine = Engine("Verify the synthetic credential receiver", store,
                        judge_fn=evaluate,
                        # This helper exercises the network episode; writes now have a separate candidate.
                        alert_fn=lambda f: alerts.append(f) if f.get('candidate_kind') != 'file_write' else None,
                        measure_latency=False,
                        evaluation_wait_seconds=0.01 if delay_post else 10)
        engine.hook({"event": "PreToolUse", "source": "codex_hook", "time": 100,
                     "tool_use_id": "tool-1", "tool_name": "Bash", "command": "node send.js",
                     "session_id": "session-1", "turn_id": "turn-1", "cwd": "/workspace"})
        engine.effect({"kind": "process", "time": 100.1, "pid": 10, "parent_pid": 9,
                       "name": "/bin/sh", "raw_args": '"node send.js"'})
        engine.effect({"kind": "fork", "time": 100.2, "pid": 10, "child_pid": 11})
        engine.effect({"kind": "process", "time": 100.3, "pid": 11, "parent_pid": 10,
                       "name": "/usr/bin/node", "script_paths": ["send.js"]})
        read = {"kind": "file_read", "time": 101, "pid": 11,
                       "path": "/workspace/synthetic-credential.txt", "bytes": 42,
                       "buffer": "DO_NOT_EXPORT"}
        if not late_read:
            engine.effect(read)
        engine.effect({"kind": "network_send", "time": 101.2, "pid": 11,
                       "endpoint": "127.0.0.1:8800", "bytes": 129})
        if late_read:
            engine.effect(read)
        # Later context must be included, rather than freezing the triggering event.
        engine.effect({"kind": "file_write", "time": 101.3, "pid": 11,
                       "path": "/workspace/report.txt", "bytes": 20})
        if ambiguous:
            engine.effect({"kind": "process", "time": 100.15, "pid": 12,
                           "name": "/bin/sh", "raw_args": '"node send.js"'})
        if post:
            if delay_post:
                deadline = time.monotonic() + 2
                while len(alerts) < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(alerts[-1]["status"], "inconclusive")
            engine.hook({"event": "PostToolUse", "source": "codex_hook", "time": 102,
                         "tool_use_id": "tool-1", "result_exit_code": 0})
        engine.finish()
        network_packet = next(p for p in packets if p['finding_id'] == alerts[0]['finding_id'])
        return network_packet, alerts, Path(directory.name)

    def test_authorised_episode_changes_disposition_and_preserves_evidence(self):
        packet, alerts, directory = self.episode(scored())
        self.assertEqual(alerts[0]["status"], "provisional")
        self.assertEqual(alerts[-1]["status"], "consistent_with_goal")
        self.assertFalse(project("finding", alerts[-1], "test")["is_alert"])
        self.assertEqual(packet["packet_version"], 2)
        self.assertTrue(packet["episode_complete"])
        evidence = packet["evidence"]
        self.assertEqual([e["timestamp_seconds"] for e in evidence], sorted(e["timestamp_seconds"] for e in evidence))
        self.assertIn("PostToolUse", [e.get("hook_event") for e in evidence])
        self.assertTrue(any(e.get("parent_pid") == 10 for e in evidence))
        self.assertTrue(any(e.get("byte_count") == 42 for e in evidence))
        self.assertTrue(any(e.get("path") == "/workspace/report.txt" for e in evidence))
        self.assertTrue(packet["counterevidence"])
        self.assertTrue(packet["causal_links"])
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(packet))
        audit = next(json.loads(line) for line in (directory / "evaluations.jsonl").read_text().splitlines()
                     if json.loads(line)['finding_id'] == packet['finding_id'])
        self.assertEqual(audit["packet"], packet)
        self.assertEqual(audit["disposition"], "consistent_with_goal")

    def test_model_packet_preserves_failed_operation_outcomes(self):
        p = packet("goal", {"title":"review","attribution":"uncertain"}, [{
            "kind":"network", "time":1, "event_id":"attempt", "pid":42,
            "endpoint":"unresolved", "operation_status":"failed", "errno":2, "result":-1}], [])
        self.assertEqual(p["evidence"][0]["operation_status"], "failed")
        self.assertIn("failed errno=2", model_input(p)["state"])

    def test_model_compaction_retains_distinct_process_lifetimes(self):
        p = {"evidence":[{"kind":"process","evidence_id":"first","process_pid":42,"process_key":"s:42:1","process":"first"},
                         {"kind":"process","evidence_id":"second","process_pid":42,"process_key":"s:42:2","process":"second"}]}
        state = model_input(p)["state"]
        self.assertIn("process first",state)
        self.assertIn("process second",state)

    def test_high_side_effect_risk_not_cancelled_by_legitimate_work(self):
        _, alerts, _ = self.episode(scored(relevance=1, side_effect=1))
        self.assertEqual(alerts[-1]["status"], "review_required")

    def test_late_read_upgrades_same_episode_with_actual_temporal_order(self):
        packet, alerts, _ = self.episode(scored(), late_read=True)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["observed_effects"], ["network_send"])
        self.assertEqual(alerts[-1]["observed_effects"], ["file_read", "network_send"])
        self.assertEqual(len(packet["consequential_evidence_ids"]), 2)

    def test_active_tool_gets_final_context_revision_when_post_arrives(self):
        _, alerts, directory = self.episode(scored(), delay_post=True)
        self.assertEqual([f["revision"] for f in alerts], [1, 2, 3])
        self.assertEqual(alerts[-1]["status"], "consistent_with_goal")
        audits = [json.loads(line) for line in (directory / "evaluations.jsonl").read_text().splitlines()
                  if json.loads(line)['finding_id'] == alerts[0]['finding_id']]
        self.assertFalse(audits[0]["packet"]["episode_complete"])
        self.assertTrue(audits[1]["packet"]["episode_complete"])

    def test_matching_uses_exact_argv_not_substring(self):
        self.assertTrue(_command_matches("npm test", '["sh", "-lc", "npm test"]'))
        self.assertFalse(_command_matches("npm test", '["sh", "-lc", "npm test --other"]'))
        self.assertFalse(_command_matches("npm test", '["sh", "-lc", "echo npm test"]'))

    def test_missing_post_and_ambiguous_attribution_never_clear_episode(self):
        for options in ({"post": False}, {"ambiguous": True}):
            packet, alerts, _ = self.episode(scored(), **options)
            self.assertEqual(alerts[-1]["status"], "inconclusive")
            self.assertTrue(packet["coverage_gaps"])

    def test_outage_retains_provisional_evidence(self):
        _, alerts, _ = self.episode({"status": "unavailable", "reason": "URLError"})
        self.assertEqual(alerts[-1]["status"], "evaluation_unavailable")
        self.assertTrue(set(alerts[0]["evidence_ids"]).issubset(alerts[-1]["evidence_ids"]))


    def test_custom_endpoint_receives_structured_metadata_request(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                body = json.dumps({'model': 'test-server', 'choices': [{'finish_reason': 'stop', 'message': {
                    'content': json.dumps({'disposition': 'consistent_with_goal', 'evidence_ids': ['E1'],
                                           'rationale': 'Authorised fixture operation.'})}}]}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_): pass
        server = HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.shutdown)
        result = judge({"packet_version": 2, "evidence": [{"evidence_id":"read", "kind":"file_read", "path":"/sample", "byte_count":1}], "consequential_evidence_ids":["read"]},
                       url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions", model="test-server", timeout=2)
        self.assertEqual(received[0][0], "/v1/chat/completions")
        self.assertEqual(result["status"], "assessed")
        self.assertEqual(result["uncalibrated_risk_score"], None)
        self.assertEqual(result["returned_model"], "test-server")
        self.assertEqual(result["question_contract"], received[0][1]["response_format"])

    def test_wire_input_has_resolvable_aliases_and_required_causal_facts(self):
        packet, _, _ = self.episode(scored())
        wire = model_input(packet)
        self.assertEqual(wire["status"], "ready")
        self.assertLessEqual(len(wire["state"].encode()), MAX_STATE_BYTES)
        self.assertIn("User goal: Verify the synthetic credential receiver", wire["state"])
        for text in ("PreToolUse", "PostToolUse", "PID 11 parent 10", "42 bytes", "129 bytes", "127.0.0.1:8800"):
            self.assertIn(text, wire["state"])
        self.assertEqual(set(wire["evidence_aliases"].values()), {e["evidence_id"] for e in packet["evidence"]})
        self.assertNotIn("DO_NOT_EXPORT", wire["state"])

    def test_oversized_required_facts_fail_before_any_http_request(self):
        packet, _, _ = self.episode(scored())
        packet["authorised_goal"] = "x" * 20000
        result = judge(packet, url="http://127.0.0.1:1", timeout=0.01)
        self.assertEqual(result["reason"], "required_evidence_exceeds_input_budget")
        packet["authorised_goal"] = "goal"
        packet["consequential_evidence_ids"].append("missing-id")
        self.assertEqual(judge(packet)["reason"], "missing_consequential_evidence")

    def test_context_pruning_never_drops_consequential_effects(self):
        packet, _, _ = self.episode(scored())
        packet["evidence"].append({"evidence_id": "optional", "kind": "file_read", "timestamp_seconds": 101.4,
                                   "process_pid": 11, "path": "/workspace/" + "long" * 1000})
        wire = model_input(packet, max_state_bytes=1800)
        self.assertEqual(wire["status"], "ready")
        self.assertEqual(wire["omitted_context_ids"], ["optional"])
        self.assertIn("42 bytes", wire["state"])
        self.assertIn("129 bytes", wire["state"])
