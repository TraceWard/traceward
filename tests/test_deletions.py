"""Deletion effects must not depend on file contents, shell claims or snapshots."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from traceward._gvisor import syscall_pb2
from traceward.gvisor import GvisorParser, decode_packet, trace_config
from traceward.engine import Engine
from traceward.ocsf import EvidenceStore, project
from traceward.state import StateObserver
from test_gvisor import record, done


class DeletionTests(unittest.TestCase):
    def deletion(self, path='empty.txt', *, abi='arm64', error=0, directory=False, base='/workspace'):
        return GvisorParser('/workspace', abi).parse(record(39, pid=2, time=101,
            sysno=263 if abi=='amd64' else 35, dirfd=-100, pathname=path,
            start_path=base, directory=directory, exit=done(-1 if error else 0, error)))

    def engine(self, root, goal='Read-only operations; do not read .env', **kwargs):
        packets=[]
        def judge(packet):
            packets.append(packet)
            return {'status':'assessed','disposition':'consistent_with_goal' if 'Delete empty.txt' == goal else 'review_required'}
        e=Engine(goal, EvidenceStore(root, 'r'), workspace='/workspace', extended_analysis=True,
            defer_evaluation=True, measure_latency=False, judge_fn=judge, **kwargs)
        return e,packets

    def tool(self,e,command='rm empty.txt',tid='t',time=100):
        e.hook(dict(event='PreToolUse',tool_use_id=tid,command=command,time=time,cwd='/workspace'))
        e.effect(dict(kind='process',pid=2,process_key='fixture:2:2000',time=time+.01,name='/bin/sh',raw_args=json.dumps([command])))
        e.hook(dict(event='PostToolUse',tool_use_id=tid,time=time+2,result_exit_code=0))

    def test_zero_result_is_success_and_paths_are_captured_not_guessed(self):
        for abi in ('arm64','amd64'):
            for path,base,expected in [('empty.txt','/workspace','/workspace/empty.txt'),
                     ('/tmp/absolute','/workspace','/tmp/absolute'),('item','/workspace/sub','/workspace/sub/item')]:
                event=self.deletion(path,abi=abi,base=base)
                self.assertEqual(event['kind'],'file_delete')
                self.assertEqual(event['path'],expected)
                self.assertEqual(event['operation_status'],'succeeded')
                self.assertNotIn('bytes',event)
                ocsf=project('file_delete',event,'r')
                self.assertEqual((ocsf['class_uid'],ocsf['activity_id'],ocsf['status_id']),(1001,4,1))
            failed=self.deletion(error=2,abi=abi)
            self.assertEqual(failed['operation_status'],'failed')
            parser=GvisorParser('/workspace',abi)
            unknown=parser.parse(record(39,pid=2,pathname='relative',start_path='',exit=done()))
            self.assertEqual(unknown['path'],'')
            self.assertTrue(parser.gaps)

    def test_typed_packet_and_required_capability(self):
        message=syscall_pb2.FileDelete(sysno=35,dirfd=8,pathname='item',start_path='/workspace/sub',directory=True)
        message.context_data.thread_group_id=2
        message.context_data.thread_group_start_time_ns=2000
        message.context_data.time_ns=101000000000
        message.exit.result=0
        raw,_=decode_packet(struct.pack('<HHI',8,39,0)+message.SerializeToString(),'fixture')
        e=GvisorParser('/workspace').normalize(raw)
        self.assertTrue(e['directory'])
        self.assertEqual(e['path'],'/workspace/sub/item')
        for abi in ('amd64','arm64'):
            self.assertIn('sentry/file_delete',[p['name'] for p in trace_config('/socket',abi)['trace_session']['points']])

    def test_deletion_fact_and_decision_order_do_not_bypass_validation(self):
        from traceward.structured import factual_predicates,request_payload
        evidence=[dict(evidence_id='delete',kind='file_delete',operation_status='succeeded',path='/workspace/empty')]
        facts=factual_predicates(evidence,{'E1':'delete'},['delete'])
        self.assertTrue(any(f['fact_type']=='observed_operation' and f['evidence_ids']==['E1'] for f in facts.values()))
        schema=request_payload('state','qwen',enriched=True,facts=facts)['response_format']['json_schema']['schema']
        self.assertEqual(list(schema['properties'])[-1],'disposition')

    def test_invalid_final_assessment_is_not_reported_as_completed_review(self):
        with tempfile.TemporaryDirectory() as temp:
            engine=Engine('Read-only',EvidenceStore(Path(temp),'r'),workspace='/workspace',extended_analysis=True,
                defer_evaluation=True,judge_fn=lambda p:{'status':'unavailable','reason':'invalid_structured_answer'})
            self.tool(engine);engine.effect(self.deletion());engine.finish()
            self.assertFalse(engine.summary()['final_review_complete'])

    def test_grouped_deletions_keep_every_target_and_snapshot_does_not_duplicate(self):
        with tempfile.TemporaryDirectory() as temp:
            e,packets=self.engine(Path(temp))
            self.tool(e)
            for path in ('empty.txt','second.txt','third.txt'):
                e.effect(self.deletion(path))
            e.observe(dict(kind='file_state',source='host_state',time=104,path='/workspace/empty.txt',phase='final',change='deleted'))
            self.assertEqual(len(e.candidate_seeds),1)
            e.finish()
            final=packets[-1]
            targets={x['path'] for x in final['evidence'] if x['kind']=='file_delete'}
            self.assertEqual(targets,{'/workspace/empty.txt','/workspace/second.txt','/workspace/third.txt'})
            self.assertEqual(final['attribution'],'command-and-process-lineage')
            self.assertTrue(any(x['kind']=='file_state' for x in final['evidence']))
            self.assertEqual(e.summary()['finding_count'],1)

    def test_authorised_delete_can_clear_and_failed_delete_is_only_an_attempt(self):
        for goal,error,expected in [('Delete empty.txt',0,'consistent_with_goal'),('Read-only operations',13,'review_required')]:
            with self.subTest(goal=goal),tempfile.TemporaryDirectory() as temp:
                e,packets=self.engine(Path(temp),goal)
                self.tool(e);e.effect(self.deletion(error=error));e.finish()
                rows=[json.loads(x) for x in (Path(temp)/'assessments.jsonl').read_text().splitlines()]
                self.assertEqual(rows[-1]['status'],expected)
                effects=[x for x in packets[-1]['evidence'] if x['kind']=='file_delete']
                self.assertEqual(effects[0]['operation_status'],'failed' if error else 'succeeded')
                if error:self.assertEqual(effects[0]['errno'],13)

    def test_transient_empty_file_and_missing_hook_still_generate_independent_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ws=root/'workspace';ws.mkdir();out=root/'run';out.mkdir()
            observer=StateObserver(ws);observer.begin()
            (ws/'transient').touch();(ws/'transient').unlink()
            self.assertFalse(any(x.get('change') for x in observer.end()))
            e,packets=self.engine(out)
            e.effect(self.deletion('transient'));e.finish()
            self.assertEqual(len(e.candidate_seeds),1)
            self.assertEqual(packets[-1]['attribution'],'uncertain')
            self.assertEqual(packets[-1]['evidence'][0]['kind'],'file_delete')

    def test_late_hook_and_pid_reuse_do_not_invent_attribution(self):
        with tempfile.TemporaryDirectory() as temp:
            e,packets=self.engine(Path(temp))
            e.effect(self.deletion())
            self.tool(e)
            # Reused numeric PID belongs to a different process lifetime.
            event=self.deletion('other.txt');event['process_key']='fixture:2:9999';event['time']=104
            e.effect(event);e.finish()
            scoped=[p for p in packets if any(x.get('path')=='/workspace/empty.txt' and x['kind']=='file_delete' for x in p['evidence'])]
            self.assertTrue(any(p['attribution']=='command-and-process-lineage' for p in scoped))
            self.assertTrue(any(p['attribution']=='uncertain' for p in packets))

    def test_agent_state_maintenance_and_ordinary_reads_do_not_generate_deletions(self):
        with tempfile.TemporaryDirectory() as temp:
            e,_=self.engine(Path(temp),agent_state_roots=('/pi-home',))
            event=self.deletion('/pi-home/auth.json');event['pid']=1;e.effect(event)
            e.effect(dict(kind='file_read',time=102,pid=1,path='/workspace/ordinary.txt',bytes=2))
            e.finish();self.assertEqual(len(e.candidate_seeds),0)
