"""Dashboard ingestion, revision semantics, and local-only API tests."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from traceward.dashboard import RunIndex, create_app
from traceward.ocsf import EvidenceStore

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None


@unittest.skipIf(TestClient is None, "install dashboard optional dependencies")
class DashboardTests(unittest.TestCase):
    def test_retained_verdict_and_observed_telemetry_survive_cancelled_final_review(self):
        store=EvidenceStore(self.run_dir,self.run_id)
        store.event('file_delete',dict(event_id='delete',time=100,pid=2,path='/workspace/empty',source='gvisor',operation_status='succeeded'))
        prior=dict(finding_id='f',revision=1,time=101,title='Deletion',message='Observed removal',
            status='review_required',is_alert=True,evidence_ids=['delete'],consequential_evidence_ids=['delete'],
            judge={'status':'assessed','model':'qwen-test','rationale':'Observed removal','cited_evidence_ids':['delete']})
        store.assessment(prior)
        store.assessment({**prior,'revision':2,'retained_review_revision':1,
            'judge':{'status':'unavailable','reason':'assessment_cancelled_on_shutdown'}})
        summary=dict(assessment_wait_cancelled=True,coverage_gaps=['gVisor telemetry was not established; run coverage is incomplete'])
        (self.run_dir/'summary.json').write_text(json.dumps(summary))
        before={f.name:f.read_bytes() for f in self.run_dir.iterdir() if f.is_file()}
        run=self.client.get(f'/api/runs/{self.run_id}').json()
        self.assertEqual(run['evaluation_label'],'Assessed · final review cancelled')
        self.assertTrue(run['analysis_incomplete'])
        self.assertTrue(run['telemetry_status']['trace_established'])
        self.assertFalse(run['telemetry_status']['finalized'])
        self.assertNotIn('was not established',' '.join(run['summary']['coverage_gaps']))
        finding=self.client.get(f'/api/runs/{self.run_id}/findings').json()['findings'][0]
        self.assertEqual(finding['judge']['reason'],'assessment_cancelled_on_shutdown')
        self.assertEqual(finding['effective_judge'],prior['judge'])
        self.assertEqual(finding['effective_judge_revision'],1)
        self.assertEqual(finding['assessment_attempt_status'],'cancelled')
        self.assertEqual(self.client.get(f'/api/runs/{self.run_id}/events?kind=file_delete').json()['events'][0]['metadata']['uid'],'delete')
        self.assertEqual(before,{f.name:f.read_bytes() for f in self.run_dir.iterdir() if f.is_file()})
        store.assessment({**prior,'revision':3,'retained_review_revision':1,
            'judge':{'status':'unavailable','reason':'connection_failed'}})
        run=self.client.get(f'/api/runs/{self.run_id}').json()
        self.assertEqual(run['evaluation_label'],'Earlier assessment retained · latest assessment unavailable')
        finding=self.client.get(f'/api/runs/{self.run_id}/findings').json()['findings'][0]
        self.assertEqual(finding['assessment_attempt_status'],'unavailable')
        self.assertEqual(finding['effective_judge'],prior['judge'])

    def test_hook_filter_finds_early_lifecycle_events_and_paginates_by_name(self):
        store = EvidenceStore(self.run_dir, self.run_id)
        for i, name in enumerate(('SessionStart', 'PreToolUse', 'PostToolUse', 'Stop', 'SessionEnd')):
            store.event('hook', {'event_id': f'h{i}', 'event': name, 'time': i,
                                'hook_metadata': {'reason': 'quit'}})
        for i in range(300):
            store.event('file_read', {'event_id': f'f{i}', 'time': i+10, 'pid': 1, 'path': '/workspace/app.py'})
        url = f'/api/runs/{self.run_id}/events'
        self.assertFalse(any(e['class_uid'] == 0 for e in self.client.get(url).json()['events']))
        first = self.client.get(url + '?kind=hook&limit=2').json()
        self.assertEqual([e['metadata']['uid'] for e in first['events']], ['h3', 'h4'])
        self.assertEqual(set(first['hook_events']), {'SessionStart', 'PreToolUse', 'PostToolUse', 'Stop', 'SessionEnd'})
        second = self.client.get(url + f"?kind=hook&limit=2&before={first['next_before']}").json()
        self.assertEqual([e['metadata']['uid'] for e in second['events']], ['h1', 'h2'])
        selected = self.client.get(url + '?kind=hook&hook_event=SessionStart').json()
        self.assertEqual([e['metadata']['uid'] for e in selected['events']], ['h0'])
        self.assertEqual(selected['events'][0]['unmapped']['traceward']['hook_metadata']['reason'], 'quit')
        self.assertEqual(self.client.get(url + '?kind=hook&hook_event=missing').json()['events'], [])

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
                  "status": "review_required",
                  "judge": {"status": "scored", "not_a_probability": True}}
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

    def test_cleared_assessment_is_not_a_finding_and_withdraws_prior_review(self):
        from traceward.ocsf import EvidenceStore
        store=EvidenceStore(self.run_dir,self.run_id)
        first={'finding_id':'candidate','revision':1,'time':100,'title':'Private file access',
               'message':'Observed read','status':'review_required','is_alert':True,'evidence_ids':[]}
        store.assessment(first)
        self.assertEqual(len(self.client.get(f'/api/runs/{self.run_id}/findings').json()['findings']),1)
        store.assessment({**first,'revision':2,'time':101,'status':'consistent_with_goal','is_alert':False})
        self.assertEqual(self.client.get(f'/api/runs/{self.run_id}/findings').json()['findings'],[])
        audit=self.client.get(f'/api/runs/{self.run_id}/assessments').json()['assessments']
        self.assertEqual(audit[0]['status'],'consistent_with_goal')
        self.assertEqual(len(audit[0]['revisions']),2)
        run=self.client.get(f'/api/runs/{self.run_id}').json()
        self.assertEqual(run['finding_count'],0);self.assertIsNone(run['finding_title'])
        self.assertEqual(run['assessment_count'],1)
        rows=[json.loads(x) for x in (self.run_dir/'findings.jsonl').read_text().splitlines()]
        self.assertEqual([r['status'] for r in rows],['review_required','withdrawn'])

    def test_cross_origin_and_host_rejected(self):
        self.assertEqual(self.client.get("/api/runs", headers={"Host": "attacker.example"}).status_code, 403)
        self.assertEqual(self.client.get("/api/runs", headers={"Origin": "https://attacker.example"}).status_code, 403)

    def test_cross_run_findings_use_latest_revision_per_run_and_exclude_audit(self):
        from traceward.ocsf import EvidenceStore
        other_id = str(uuid.uuid4())
        other = self.runs / other_id
        other.mkdir()
        (other / 'run.json').write_text(json.dumps({'name': 'Dependency audit', 'source': 'pi'}))
        base = {'finding_id': 'shared-id', 'revision': 1, 'time': 100,
                'title': 'Review dependency', 'message': 'Synthetic review',
                'status': 'review_required', 'evidence_ids': ['event']}
        first = EvidenceStore(self.run_dir, self.run_id)
        second = EvidenceStore(other, other_id)
        first.assessment(base)
        second.assessment({**base, 'time': 102})
        first.assessment({**base, 'revision': 2, 'time': 103, 'status': 'consistent_with_goal'})
        second.assessment({**base, 'finding_id': 'pending', 'status': 'inconclusive'})
        response = self.client.get('/api/findings')
        self.assertEqual(response.status_code, 200)
        findings = response.json()['findings']
        self.assertEqual([(f['run_id'], f['finding_id'], f['revision']) for f in findings],
                         [(other_id, 'shared-id', 1)])
        self.assertEqual(findings[0]['evidence_ids'], ['event'])
        self.assertEqual(self.client.get(f'/api/runs/{other_id}').json()['name'], 'Dependency audit')
        second.assessment({**base, 'revision': 2, 'time': 104, 'status': 'withdrawn'})
        self.assertEqual(self.client.get('/api/findings').json()['findings'], [])

    def test_gvisor_source_and_pid_reuse_preserve_distinct_evidence(self):
        first = self._event("first")
        second = self._event("second")
        first["unmapped"]["traceward"] = {"source": "gvisor", "process_key": "s:42:100", "raw_trace_ref": "raw.gvisor.jsonl:1"}
        second["unmapped"]["traceward"] = {"source": "gvisor", "process_key": "s:42:200", "raw_trace_ref": "raw.gvisor.jsonl:2"}
        (self.run_dir / "events.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
        (self.run_dir / "raw.gvisor.jsonl").write_text('{"metadata":"first"}\n{"metadata":"second"}\n')
        events = self.client.get(f"/api/runs/{self.run_id}/processes").json()["processes"]
        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0]["unmapped"]["traceward"]["process_key"], events[1]["unmapped"]["traceward"]["process_key"])
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/raw?source=gvisor&line=2").status_code, 200)

    def test_index_restarts_and_completion_status(self):
        (self.run_dir / "events.jsonl").write_text(json.dumps(self._event("one")) + "\n")
        self.index.refresh()
        restarted = RunIndex(self.runs, self.root / "index.sqlite")
        restarted.refresh()
        self.assertEqual(len(restarted.events(self.run_id)["events"]), 1)
        (self.run_dir / "summary.json").write_text(json.dumps({"goal": "Fix tests", "codex_exit_code": 0}))
        restarted.refresh()
        self.assertEqual(restarted.run(self.run_id)["status"], "complete")

    def test_out_of_order_timestamps_paginate_without_duplicates_or_omissions(self):
        items = [{**self._event(name), "time": timestamp} for name, timestamp in
                 (("new", 103), ("old", 100), ("tie-a", 102), ("middle", 101), ("tie-b", 102))]
        (self.run_dir / "events.jsonl").write_text("".join(json.dumps(item) + "\n" for item in items))
        self.index.refresh()
        page = self.index.events(self.run_id, limit=2)
        pages = [page["events"]]
        while page["next_before"]:
            page = self.index.events(self.run_id, before=page["next_before"], limit=2)
            pages.insert(0, page["events"])
        events = [e for batch in pages for e in batch]
        self.assertEqual([e["metadata"]["uid"] for e in events], ["old", "middle", "tie-a", "tie-b", "new"])
        self.assertEqual([e["time"] for e in events], sorted(e["time"] for e in events))
        evidence = self.index.evidence(self.run_id, ["new", "old", "middle"])
        self.assertEqual([e["metadata"]["uid"] for e in evidence], ["old", "middle", "new"])


if __name__ == "__main__":
    unittest.main()
