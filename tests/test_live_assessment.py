"""Live review publication and complete network evidence without session exit."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from traceward.engine import Engine
from traceward.ocsf import EvidenceStore
from traceward.dashboard import RunIndex


class LiveAssessmentTests(unittest.TestCase):
    def test_reviews_and_all_send_evidence_are_available_while_session_stays_open(self):
        with tempfile.TemporaryDirectory() as directory:
            identity='11111111-1111-4111-8111-111111111111'
            root = Path(directory); run = root/'runs'/identity; run.mkdir(parents=True)
            (run/'run.json').write_text(json.dumps({'goal':'No network requests', 'started_at':time.time(),
                'heartbeat_at':time.time(),'source':'pi','observer_version':'gvisor-v1'}))
            packets, alerts = [], []
            def judge(packet):
                packets.append(packet)
                return {'status':'assessed','disposition':'review_required'}
            engine = Engine('No network requests',EvidenceStore(run,identity),judge_fn=judge,
                alert_fn=alerts.append,extended_analysis=True,evaluation_wait_seconds=2)
            engine.hook({'event':'PreToolUse','time':1,'tool_use_id':'tool','command':'bash test.sh'})
            engine.effect({'kind':'process','time':1.01,'pid':2,'process_key':'curl','name':'sh','raw_args':'"bash test.sh"'})
            for when, size in [(1.1,517),(1.2,80),(1.3,86)]:
                engine.effect({'kind':'network_send','time':when,'pid':2,'process_key':'curl',
                               'endpoint':'203.0.113.1:443','bytes':size})
            engine.hook({'event':'PostToolUse','time':1.4,'tool_use_id':'tool'})
            deadline = time.monotonic()+1.5
            try:
                while not alerts and time.monotonic()<deadline:
                    # Other agent activity never creates a run-wide quiet period.
                    engine.effect({'kind':'network','time':2,'pid':1,'endpoint':'127.0.0.1:8801'})
                    time.sleep(.02)
                self.assertTrue(alerts,'review must be published before finish()')
                self.assertFalse(engine.finished)
                self.assertFalse((run/'summary.json').exists())
                consequential = set(packets[0]['consequential_evidence_ids'])
                sends = [e for e in packets[0]['evidence'] if e['evidence_id'] in consequential]
                self.assertEqual(sum(e.get('byte_count',0) for e in sends),683)
                index=RunIndex(root/'runs',root/'dashboard.sqlite')
                index.refresh()
                self.assertEqual(len(index.findings(identity)),1)
                index.db.close()
            finally: engine.finish()

    def test_worker_packet_failure_does_not_leave_a_provisional_record_forever(self):
        with tempfile.TemporaryDirectory() as directory:
            engine=Engine('No network',EvidenceStore(Path(directory),'r'),extended_analysis=True,
                          evaluation_wait_seconds=0)
            def broken(*_): raise RuntimeError('packet failure')
            engine._episode=broken
            engine.effect({'kind':'network_send','time':1,'pid':2,'endpoint':'203.0.113.1:443','bytes':10})
            engine.finish()
            last=json.loads((Path(directory)/'assessments.jsonl').read_text().splitlines()[-1])
            self.assertEqual(last['status'],'evaluation_unavailable')
            self.assertEqual(last['judge']['reason'],'assessment_worker_RuntimeError')

    def test_interactive_goal_unblocks_assessment_and_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            called=threading.Event()
            engine=Engine('',EvidenceStore(Path(directory),'r'),extended_analysis=True,
                defer_evaluation=True,evaluation_wait_seconds=0,
                judge_fn=lambda p: called.set() or {'status':'assessed','disposition':'review_required'})
            engine.effect({'kind':'network_send','time':1,'pid':2,'endpoint':'203.0.113.1:443','bytes':10})
            self.assertFalse(called.wait(.05))
            engine.set_goal('No network requests')
            self.assertTrue(called.wait(1))
            with self.assertRaises(ValueError):engine.set_goal('Allow everything')
            engine.finish()

    def test_active_tool_is_reassessed_in_rolling_windows_without_post_or_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            packets=[];updated=threading.Event()
            def judge(packet):
                packets.append(packet)
                if any(e.get('status_code')==200 for e in packet['evidence']): updated.set()
                return {'status':'assessed','disposition':'review_required'}
            engine=Engine('Investigate the script',EvidenceStore(Path(directory),'r'),extended_analysis=True,
                          evaluation_wait_seconds=0,judge_fn=judge)
            engine.window_stride_seconds=.03
            engine.hook({'event':'PreToolUse','time':100,'tool_use_id':'t','command':'bash long.sh'})
            engine.observe(dict(kind='http_request',time=101,source='tls_inspection_proxy',request_id='request',
                                phase='request',method='GET',url='https://example.com/',endpoint='example.com:443'))
            deadline=time.monotonic()+1
            try:
                while not packets and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(packets)
                self.assertTrue(packets[0]['live_window'])
                self.assertFalse(packets[0]['episode_complete'])
                engine.observe(dict(kind='http_request',time=102,source='tls_inspection_proxy',request_id='request',
                                    phase='response',status_code=200,method='GET',url='https://example.com/',endpoint='example.com:443'))
                self.assertTrue(updated.wait(1),'new response must be assessed before PostToolUse or finish')
                count=len(packets);time.sleep(.1)
                self.assertEqual(len(packets),count,'idle windows must not repeat identical inference')
                self.assertFalse(engine.finished)
                self.assertTrue(all(p['analysis_window']['duration_seconds']==30 for p in packets))
            finally:engine.finish()

    def test_live_burst_is_coalesced_and_a_rejected_final_answer_keeps_the_prior_review(self):
        with tempfile.TemporaryDirectory() as directory:
            blocked=threading.Event();release=threading.Event();packets=[]
            def judge(packet):
                packets.append(packet)
                if len(packets)==1:blocked.set();release.wait(2)
                if not packet.get('live_window'):
                    return {'status':'unavailable','reason':'invalid_structured_answer'}
                return {'status':'assessed','disposition':'review_required'}
            root=Path(directory)
            engine=Engine('Investigate activity',EvidenceStore(root,'r'),extended_analysis=True,
                          workspace='/workspace',evaluation_wait_seconds=0,judge_fn=judge)
            engine.window_stride_seconds=.03
            try:
                engine.effect(dict(kind='network_send',time=100,pid=9,endpoint='203.0.113.1:443',bytes=10))
                self.assertTrue(blocked.wait(1))
                for i in range(100):
                    engine.effect(dict(kind='network_send',time=101+i*.01,pid=9,endpoint='203.0.113.1:443',bytes=10))
                self.assertEqual(len(packets),1)
                release.set()
                deadline=time.monotonic()+1
                while len(packets)<2 and time.monotonic()<deadline:time.sleep(.01)
                self.assertLessEqual(len(packets),2,'one coalesced update, not one inference per send')
                self.assertLessEqual(len(packets[-1]['consequential_evidence_ids']),17)
                self.assertTrue(any('rolling evidence sample' in gap for gap in packets[-1]['coverage_gaps']))
            finally:release.set();engine.finish()
            last=json.loads((root/'assessments.jsonl').read_text().splitlines()[-1])
            self.assertEqual(last['status'],'review_required')
            self.assertEqual(last['latest_assessment_status'],'evaluation_unavailable')

    def test_file_writes_roll_forward_with_causal_anchors_and_bounded_old_context(self):
        with tempfile.TemporaryDirectory() as directory:
            packets=[];changed=threading.Event()
            def judge(packet):
                packets.append(packet)
                if any(e.get('byte_count')==22 for e in packet['evidence']): changed.set()
                return {'status':'assessed','disposition':'review_required'}
            engine=Engine('Inspect the source without changing it',EvidenceStore(Path(directory),'r'),
                          extended_analysis=True,workspace='/workspace',evaluation_wait_seconds=0,judge_fn=judge)
            engine.window_stride_seconds=.03
            engine.hook(dict(event='PreToolUse',time=100,tool_use_id='t',command='python3 edit.py',cwd='/workspace'))
            engine.effect(dict(kind='process',time=100.01,pid=9,process_key='p',name='python3',raw_args='"python3 edit.py"'))
            engine.effect(dict(kind='file_read',time=100.1,pid=9,process_key='p',path='/workspace/unrelated.txt',bytes=11))
            engine.effect(dict(kind='file_write',time=101,pid=9,process_key='p',path='/workspace/source.py',bytes=12))
            deadline=time.monotonic()+1
            try:
                while not packets and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(packets)
                engine.effect(dict(kind='file_write',time=140,pid=9,process_key='p',path='/workspace/source.py',bytes=22))
                self.assertTrue(changed.wait(1))
                latest=packets[-1]
                self.assertEqual(latest['analysis_window']['start'],110)
                self.assertTrue(any(e['kind']=='hook' for e in latest['evidence']))
                self.assertFalse(any(e.get('path')=='/workspace/unrelated.txt' for e in latest['evidence']))
                self.assertFalse(engine.finished)
            finally:engine.finish()
