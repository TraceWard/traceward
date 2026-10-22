"""Final counters, model cancellation and process exit are distinct states."""
import json
import os
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from traceward.collector_status import read_status,write_status,describe_status
from traceward.records import effective_assessment
from traceward.runtime import ManagedRuntime

class CollectorStatusTests(unittest.TestCase):
    def test_snapshots_are_atomic_owner_only_and_finalization_is_explicit(self):
        receiver=SimpleNamespace(handshakes=1,messages=42,dropped=0,errors=0,queue_losses=0,persistence_failed=False)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            write_status(root,receiver,abi='arm64',established=True,finalized=False)
            first=read_status(root/'runtime-status.json')
            self.assertFalse(first['finalized']);self.assertEqual(first['source_messages'],42)
            self.assertEqual((root/'runtime-status.json').stat().st_mode&0o777,0o600)
            self.assertFalse((root/'runtime-status.json.tmp').exists())
            self.assertEqual(describe_status(first)['status'],'incomplete')
            write_status(root,receiver,abi='arm64',established=True,finalized=True)
            self.assertEqual(describe_status(read_status(root/'runtime-status.json'))['status'],'complete')

    def test_missing_status_does_not_erase_observed_telemetry(self):
        self.assertEqual(describe_status({},20)['trace_established'],True)
        self.assertEqual(describe_status({},20)['status'],'incomplete')
        self.assertEqual(describe_status({})['status'],'unknown')
        self.assertEqual(describe_status({'trace_established':False,'finalized':True})['status'],'not_established')
        self.assertEqual(describe_status({'handshakes':1,'source_messages':10})['status'],'complete')
        self.assertEqual(describe_status({'handshakes':1,'source_messages':10,'finalized':True,'dropped_messages':1})['status'],'incomplete')

    def test_runtime_wait_is_skipped_on_cancellation_and_ends_after_final_snapshot(self):
        runtime=ManagedRuntime.__new__(ManagedRuntime);runtime.embedded=False;runtime.container='test'
        with tempfile.TemporaryDirectory() as directory:
            runtime.run_dir=Path(directory)
            with patch('traceward.runtime.subprocess.run') as docker:
                runtime.await_final_status(lambda:True)
                docker.assert_not_called()
                (runtime.run_dir/'runtime-status.json').write_text('{"finalized":true}')
                runtime.await_final_status()
                docker.assert_not_called()
            (runtime.run_dir/'runtime-status.json').unlink()
            with patch('traceward.runtime.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='true')) as docker, \
                 patch('traceward.runtime.time.sleep',side_effect=lambda _: (runtime.run_dir/'runtime-status.json').write_text('{"finalized":true}')):
                runtime.await_final_status()
                self.assertEqual(docker.call_count,1)

    def test_retained_verdict_is_scope_checked_and_audit_input_unchanged(self):
        prior=dict(finding_id='f',revision=2,status='review_required',evidence_ids=['e'],
            consequential_evidence_ids=['e'],judge={'status':'assessed','model':'qwen','rationale':'Observed deletion'})
        cancelled={**prior,'revision':3,'retained_review_revision':2,
            'judge':{'status':'unavailable','reason':'assessment_cancelled_on_shutdown'}}
        before=json.dumps(cancelled,sort_keys=True)
        view=effective_assessment(cancelled,[prior,cancelled])
        self.assertEqual(view['assessment_attempt_status'],'cancelled')
        self.assertEqual(view['effective_judge'],prior['judge'])
        self.assertEqual(view['effective_judge_revision'],2)
        self.assertEqual(json.dumps(cancelled,sort_keys=True),before)
        for wrong in ([{**prior,'finding_id':'other'}],[{**prior,'evidence_ids':['other']}],[]):
            view=effective_assessment(cancelled,wrong)
            self.assertIsNone(view['effective_judge']);self.assertTrue(view['effective_judge_error'])
        alone=effective_assessment({**cancelled,'retained_review_revision':None},[])
        self.assertIsNone(alone['effective_judge']);self.assertEqual(alone['assessment_attempt_status'],'cancelled')
        outage=effective_assessment({**cancelled,'judge':{'status':'unavailable','reason':'connection_failed'}},[prior])
        self.assertEqual(outage['assessment_attempt_status'],'unavailable')
        self.assertEqual(outage['effective_judge']['model'],'qwen')

    def test_records_written_during_attachment_grace_are_drained(self):
        from traceward import cli
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);workspace=root/'workspace';workspace.mkdir()
            class Runtime:
                gaps=[];transport_endpoints=();agent_state_roots=();permission_log=None
                hook_setup_hint='synthetic';image='synthetic';home=root
                def __init__(self,run_dir,run_id,args,**options):
                    self.run_dir=run_dir;self.metadata={'workspace':str(workspace)}
                    self.command=[sys.executable,'-c','pass']
                def await_final_status(self,cancelled):
                    (self.run_dir/'raw.gvisor.jsonl').write_text('late deletion\n')
                    (self.run_dir/'runtime-status.json').write_text(json.dumps(
                        dict(trace_established=True,finalized=True,source_messages=1)))
                def cleanup(self):pass
            class Parser:
                gaps=[];unparsed=0
                def __init__(self,*args):pass
                def parse(self,line):
                    return dict(kind='file_delete',time=1,pid=2,path=str(workspace/'transient'),
                        operation_status='succeeded',source='gvisor',result=0)
            with patch.dict(os.environ,{'XDG_STATE_HOME':str(root/'state')}), \
                 patch('traceward.cli.GvisorParser',Parser), \
                 patch('traceward.judges.judge',return_value={'status':'assessed','disposition':'inconclusive',
                     'rationale':'Synthetic drain-order check','evidence_ids':[]}):
                self.assertEqual(cli.run(['--goal','Read only','--defer-judge','codex'],runtime_factory=Runtime),0)
            run=next((root/'state/traceward/runs').iterdir())
            events=[json.loads(line) for line in (run/'events.jsonl').read_text().splitlines()]
            self.assertTrue(any(e['unmapped']['traceward'].get('event_kind')=='file_delete' for e in events))
