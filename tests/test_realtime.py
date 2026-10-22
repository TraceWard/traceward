"""Detailed live judgements and bounded exit, including queued and late calls."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from traceward.engine import Engine
from traceward.ocsf import EvidenceStore
from traceward.dashboard import RunIndex
from traceward.records import effective_assessment
from traceward.judges import generative_judge
from traceward.state import StateObserver
from demo.evaluator import fixture_answer

class RealtimeTests(unittest.TestCase):
    def wait(self,condition):
        deadline=time.monotonic()+2
        while not condition() and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue(condition())
    def engine(self,path,judge):
        e=Engine('No network',EvidenceStore(path,'r'),extended_analysis=True,realtime=True,
                 workspace='/workspace',evaluation_wait_seconds=0,judge_fn=judge)
        e.window_stride_seconds=.01
        return e
    def send(self,e,pid=2,size=1):
        e.effect(dict(kind='network_send',time=100+size/100,pid=pid,
                      endpoint='203.0.113.1:443',bytes=size))
    def test_completed_live_verdict_is_not_repeated_or_marked_pending_at_exit(self):
        with tempfile.TemporaryDirectory() as d:
            calls=[];e=self.engine(Path(d),lambda p:calls.append(p) or dict(status='assessed',disposition='review_required'))
            self.send(e);self.wait(lambda:bool(e.assessed_packets))
            self.assertEqual(calls[0]['assessment_contract'],'goal-effects-live-v2')
            e.stop_live_assessments();start=time.monotonic();e.finish()
            self.assertLess(time.monotonic()-start,.2)
            self.assertEqual(len(calls),1);self.assertTrue(e.summary()['final_review_complete'])
            self.assertEqual(e.summary()['pending_assessment_count'],0)
            for t in e.threads:t.join(1)
    def test_stalled_and_queued_calls_do_not_delay_exit_or_write_late_results(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);calls=[];release=threading.Event()
            def judge(p):calls.append(p);release.wait(3);return dict(status='assessed',disposition='consistent_with_goal')
            e=self.engine(root,judge)
            try:
                for pid in (2,3,4):self.send(e,pid)
                self.wait(lambda:len(calls)==2)
                e.stop_live_assessments();start=time.monotonic();e.finish()
                self.assertLess(time.monotonic()-start,.2)
                self.assertFalse(e.assessments_cancelled)
                self.assertEqual(e.summary()['pending_assessment_count'],3)
                self.assertFalse(e.summary()['final_review_complete'])
                latest={x['finding_id']:x for x in map(json.loads,(root/'assessments.jsonl').read_text().splitlines())}
                self.assertTrue(all(x['judge']['status']=='pending' for x in latest.values()))
                before={p.name:p.read_bytes() for p in root.glob('*.jsonl')}
                release.set()
                for t in e.threads:t.join(1)
                self.assertEqual(len(calls),2)
                self.assertEqual(before,{p.name:p.read_bytes() for p in root.glob('*.jsonl')})
            finally:release.set()
    def test_pending_new_evidence_retains_prior_review_with_original_scope(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);calls=[];release=threading.Event();blocked=threading.Event()
            def judge(p):
                calls.append(p)
                if len(calls)>1:blocked.set();release.wait(3)
                return dict(status='assessed',disposition='review_required',model='synthetic',rationale='Synthetic review')
            e=self.engine(root,judge)
            try:
                self.send(e);self.wait(lambda:bool(e.assessed_packets))
                prior=next(iter(e.last_reviews.values()))
                self.send(e,size=2);self.assertTrue(blocked.wait(2))
                e.stop_live_assessments();e.finish()
                rows=list(map(json.loads,(root/'assessments.jsonl').read_text().splitlines()))
                view=effective_assessment(rows[-1],rows)
                self.assertEqual(view['status'],'review_required')
                self.assertEqual(view['assessment_attempt_status'],'pending')
                self.assertEqual(view['effective_judge'],prior['judge'])
                self.assertEqual(view['evidence_ids'],prior['evidence_ids'])
                self.assertEqual(e.summary()['finding_count'],1)
                self.assertFalse(e.summary()['final_review_complete'])
            finally:
                release.set()
                for t in e.threads:t.join(1)
    def test_new_shutdown_only_candidate_is_saved_without_starting_inference(self):
        with tempfile.TemporaryDirectory() as d:
            calls=[];e=self.engine(Path(d),lambda p:calls.append(p))
            e.stop_live_assessments()
            e.observe(dict(kind='file_state',time=101,path='/workspace/new',phase='final',change='created',sha256='new'))
            e.finish()
            for t in e.threads:t.join(1)
            self.assertFalse(calls);self.assertEqual(e.summary()['pending_assessment_count'],1)
    def test_live_state_samples_change_only_and_duplicate_final_state_is_not_reassessed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);workspace=root/'workspace';workspace.mkdir();run=root/'run';run.mkdir()
            path=workspace/'file.txt';path.write_text('first')
            state=StateObserver(workspace);baseline=state.begin();self.assertFalse(state.sample())
            path.write_text('second');sample=state.sample();self.assertEqual(len(sample),1)
            self.assertEqual(sample[0]['phase'],'live');self.assertFalse(state.sample())
            calls=[];e=self.engine(run,lambda p:calls.append(p) or dict(status='assessed',disposition='review_required'))
            for item in baseline+sample:e.observe(item)
            self.wait(lambda:bool(e.assessed_packets))
            for item in state.end():e.observe(item)
            time.sleep(.05);self.assertEqual(len(calls),1)
            e.stop_live_assessments();e.finish();self.assertTrue(e.summary()['final_review_complete'])
    def test_detailed_contract_is_used_during_live_execution(self):
        class Reply:
            def __init__(self,result):self.result=result
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps(self.result).encode()[:n]
        calls=[]
        def post(request,**kwargs):
            body=json.loads(request.data);calls.append(body)
            return Reply({'model':body['model'],'choices':[{'finish_reason':'stop','message':{'content':json.dumps(fixture_answer(body))}}]})
        with tempfile.TemporaryDirectory() as d:
            packets=[];e=self.engine(Path(d),lambda p:packets.append(p) or dict(status='assessed',disposition='review_required'))
            self.send(e);self.wait(lambda:bool(e.assessed_packets));e.finish()
            with patch('traceward.judges.urlopen',post):
                answer=generative_judge(packets[0],model='demo-deterministic-evaluator')
            self.assertEqual(answer['status'],'assessed',answer.get('validation_error'))
            self.assertEqual(answer['contract_version'],'goal-effects-live-v2')
            self.assertIn('assessment',answer);self.assertIn('claims',answer)
            self.assertEqual(calls[0]['max_tokens'],1600)
            self.assertIn('assessment',calls[0]['response_format']['json_schema']['schema']['properties'])
    def test_process_attribution_is_stored_before_finish(self):
        with tempfile.TemporaryDirectory() as d:
            e=self.engine(Path(d),lambda p:dict(status='assessed',disposition='review_required'))
            e.hook(dict(event='PreToolUse',time=100,tool_use_id='t',command='curl example.com'))
            e.effect(dict(kind='process',time=100.01,pid=2,process_key='p',raw_args='"curl example.com"'))
            self.send(e)
            rows=e.graph.db.execute('SELECT tool_id FROM observations WHERE kind="process"').fetchall()
            self.assertEqual(rows,[('t',)])
            e.finish()
    def test_explicit_cancellation_remains_distinct_from_automatic_pending_exit(self):
        with tempfile.TemporaryDirectory() as d:
            e=self.engine(Path(d),lambda _:self.fail('closed engine started inference'))
            e.stop_live_assessments();self.send(e);e.cancel_assessments();e.finish()
            last=json.loads((Path(d)/'assessments.jsonl').read_text().splitlines()[-1])
            self.assertEqual(last['judge']['reason'],'assessment_cancelled_on_shutdown')
            self.assertEqual(effective_assessment(last,[last])['assessment_attempt_status'],'cancelled')
    def test_unavailable_final_packet_scope_does_not_prevent_saving_pending_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            e=self.engine(Path(d),lambda _:self.fail('closed engine started inference'))
            e.stop_live_assessments();self.send(e)
            e._episode=lambda *_:(_ for _ in ()).throw(RuntimeError('synthetic packet failure'))
            e.finish()
            self.assertEqual(e.summary()['pending_assessment_count'],1)
            self.assertFalse(e.summary()['final_review_complete'])
    def test_interactive_goal_arriving_after_exit_cannot_start_inference(self):
        with tempfile.TemporaryDirectory() as d:
            calls=[]
            e=Engine('',EvidenceStore(Path(d),'r'),extended_analysis=True,realtime=True,
                     defer_evaluation=True,judge_fn=lambda p:calls.append(p))
            e.stop_live_assessments();self.send(e)
            e.set_goal('No network');e.finish()
            for t in e.threads:t.join(1)
            self.assertFalse(calls)
            self.assertEqual(e.summary()['pending_assessment_count'],1)
