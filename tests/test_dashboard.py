"""Dashboard ingestion, revision semantics, and local-only API tests."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from traceward.dashboard import RunIndex, create_app

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None


@unittest.skipIf(TestClient is None, "install dashboard optional dependencies")
class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runs = self.root / "runs"
        self.runs.mkdir()
        self.run_id = str(uuid.uuid4())
        self.run_dir = self.runs / self.run_id
        self.run_dir.mkdir()
        (self.run_dir / "run.json").write_text(json.dumps({"goal": "Fix tests", "started_at": time.time(),
                                                          "heartbeat_at": time.time()}))
        self.index = RunIndex(self.runs, self.root / "index.sqlite")
        self.client = TestClient(create_app(self.index), base_url="http://127.0.0.1:8765")
        self.addCleanup(self.client.close)

    def _event(self, event_id: str, kind: str = "process") -> dict:
        uid = 1007 if kind == "process" else 1001
        return {"metadata": {"uid": event_id}, "class_uid": uid, "activity_id": 1 if uid == 1007 else 2,
                "activity_name": "Launch" if uid == 1007 else "Read", "time": 100000,
                "process": {"pid": 42, "name": "sh"} if uid == 1007 else None,
                "actor": {"process": {"pid": 42}},
                "unmapped": {"traceward": {"source": "strace", "raw_trace_ref": "raw.strace:2"}}}

    def test_partial_jsonl_and_live_manifest(self):
        path = self.run_dir / "events.jsonl"
        first = json.dumps(self._event("one")) + "\n"
        second = json.dumps(self._event("two", "file"))
        path.write_text(first + second)
        result = self.client.get(f"/api/runs/{self.run_id}")
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["status"], "live")
        self.assertEqual(result.json()["goal"], "Fix tests")
        self.assertEqual(len(self.client.get(f"/api/runs/{self.run_id}/events").json()["events"]), 1)
        with path.open("a") as stream:
            stream.write("\n")
        data = self.client.get(f"/api/runs/{self.run_id}/events").json()
        self.assertEqual([item["metadata"]["uid"] for item in data["events"]], ["one", "two"])
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/events?kind=file_read").json()["events"][0]["metadata"]["uid"], "two")

    def test_latest_finding_keeps_revision_history_and_evidence(self):
        (self.run_dir / "events.jsonl").write_text(json.dumps(self._event("evidence")) + "\n")
        first = {"finding_id": "finding-1", "revision": 1, "time": 100,
                 "title": "Review", "evidence_ids": ["evidence"], "uncalibrated_risk_score": None}
        second = {**first, "revision": 2, "time": 101, "uncalibrated_risk_score": 0.8,
                  "laya": {"status": "scored", "not_a_probability": True}}
        (self.run_dir / "findings.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
        findings = self.client.get(f"/api/runs/{self.run_id}/findings").json()["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["revision"], 2)
        self.assertEqual(len(findings[0]["revisions"]), 2)
        evidence = self.client.get(f"/api/runs/{self.run_id}/evidence?ids=evidence").json()["events"]
        self.assertEqual(evidence[0]["metadata"]["uid"], "evidence")
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}").json()["finding_count"], 1)
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}").json()["finding_title"], "Review")

    def test_raw_is_explicitly_fetched_and_paths_are_fixed(self):
        (self.run_dir / "raw.strace").write_text("one\ntwo\nsecret argument\n")
        path = f"/api/runs/{self.run_id}/raw?source=strace&line=2"
        result = self.client.get(path)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["lines"][1]["text"], "two")
        self.assertEqual(self.client.get(path + "&source=../../etc/passwd").status_code, 404)
        self.assertEqual(self.client.get("/api/runs/not-a-uuid/events").status_code, 404)
        self.assertNotIn("secret argument", json.dumps(self.client.get(f"/api/runs/{self.run_id}").json()))

    def test_cross_origin_and_host_rejected(self):
        self.assertEqual(self.client.get("/api/runs", headers={"Host": "attacker.example"}).status_code, 403)
        self.assertEqual(self.client.get("/api/runs", headers={"Origin": "https://attacker.example"}).status_code, 403)

    def test_index_restarts_and_completion_status(self):
        (self.run_dir / "events.jsonl").write_text(json.dumps(self._event("one")) + "\n")
        self.index.refresh()
        restarted = RunIndex(self.runs, self.root / "index.sqlite")
        restarted.refresh()
        self.assertEqual(len(restarted.events(self.run_id)["events"]), 1)
        (self.run_dir / "summary.json").write_text(json.dumps({"goal": "Fix tests", "codex_exit_code": 0}))
        restarted.refresh()
        self.assertEqual(restarted.run(self.run_id)["status"], "complete")


if __name__ == "__main__":
    unittest.main()
