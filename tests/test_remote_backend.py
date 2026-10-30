"""Remote registry, durable ingestion and server analysis against real PostgreSQL.

Set TRACEWARD_TEST_DATABASE_URL to a disposable database. Judge responses here
are explicitly software-test fixtures; live acceptance uses the actual judge.
"""
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from traceward.cli import _parse_run
from traceward.remote import Client,Upload,base_url,private_json


class RemoteOptions(unittest.TestCase):
    def test_live_capture_requires_backend_and_never_judges_locally(self):
        import sys
        from traceward.capture import run
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);workspace=root/'workspace';workspace.mkdir()
            class Receiver:
                url='http://localhost:8765'
                records=[]
                completed=False
                def post(self,path,body,timeout=5):
                    if path=='/runs':return {'run_id':body['run_id'],'agent_id':None,'agent_slug':None,'goal':body['goal']}
                    if path.endswith('/ingest'):
                        self.records.extend(body['records']);return {'accepted_seq':body['records'][-1]['seq']}
                    if path.endswith('/complete'):self.completed=True
                    return {}
            class Runtime:
                gaps=[];transport_endpoints=();agent_state_roots=();permission_log=None
                image='synthetic';home=root
                def __init__(self,directory,identity,args,**kwargs):
                    self.metadata={'workspace':str(workspace),'abi':'arm64'}
                    self.directory=directory
                    self.command=[sys.executable,'-c', 'print("synthetic native agent")']
                def cleanup(self):
                    private_json(self.directory/'runtime-status.json',{'finalized':True})
            receiver=Receiver()
            with patch.dict(os.environ,{'XDG_STATE_HOME':str(root/'state')}), \
                 patch('traceward.capture.Client',return_value=receiver), \
                 patch('traceward.judges.judge',side_effect=AssertionError('CLI must not judge')):
                self.assertEqual(run(['--goal','Read only','codex'],runtime_factory=Runtime),0)
            self.assertTrue(receiver.completed)
            with patch('traceward.capture.Client') as client:
                client.return_value.post.side_effect=RuntimeError('backend unavailable')
                with patch('traceward.capture.ManagedRuntime') as runtime:
                    with self.assertRaisesRegex(RuntimeError,'backend unavailable'):run(['--goal','Read only','codex'])
                    runtime.assert_not_called()

    def test_registered_goal_bypasses_goal_file_and_prompt_inference(self):
        with patch('traceward.cli.codex_instruction',side_effect=AssertionError('must not infer')):
            parsed=_parse_run(['--agent-slug','audit','--goal','ignored','--goal-file','/missing/ignored','codex','--unknown-native-option'])
        self.assertIsNone(parsed[0]);self.assertEqual(parsed[1],['--unknown-native-option'])
        self.assertEqual(parsed[-1]['agent_slug'],'audit')
        with self.assertRaisesRegex(ValueError,'choose --agent-id'):
            _parse_run(['--agent-id','one','--agent-slug','two','codex'])
    def test_url_normalization(self):
        self.assertEqual(base_url('https://example.test/api/'),'https://example.test')
        for url in ('ftp://example.test','https://user:password@example.test','http://example.test?token=x'):
            with self.assertRaises(ValueError):base_url(url)
    def test_torn_spool_tail_is_removed_before_new_append(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)/str(uuid.uuid4());directory.mkdir()
            (directory/'upload.jsonl').write_bytes(b'{"seq":1,"type":"coverage","data":{"message":"gap"}}\n{"seq":2')
            upload=Upload(directory,object())
            self.assertEqual(upload.append('coverage',data={'message':'recovered'}),2)
            self.assertEqual([json.loads(line)['seq'] for line in upload.path.read_text().splitlines()],[1,2])
    def test_spool_retries_same_input_without_losing_checkpoint(self):
        class Receiver:
            attempts=[]
            def post(self,path,body):
                self.attempts.append(body)
                if len(self.attempts)==1:raise RuntimeError('network interruption')
                return {'accepted_seq':body['records'][-1]['seq']}
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)/str(uuid.uuid4());directory.mkdir()
            receiver=Receiver();spool=Upload(directory,receiver)
            spool.append('coverage',data={'message':'source gap'})
            with self.assertRaises(RuntimeError):spool.once()
            self.assertFalse((directory/'upload-state.json').exists())
            self.assertEqual(spool.once()[1]['accepted_seq'],1)
            self.assertEqual(receiver.attempts[0],receiver.attempts[1])
            self.assertFalse(spool.once()[0])


@unittest.skipUnless(os.environ.get('TRACEWARD_TEST_DATABASE_URL'),'disposable PostgreSQL not configured')
class BackendTests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from traceward.postgres import Database
        from traceward.backend import application
        self.database=Database(os.environ['TRACEWARD_TEST_DATABASE_URL'])
        with self.database.pool.connection() as c:
            c.execute('TRUNCATE agents,runs,inputs,raw_sources,events,findings,evaluations,graph_observations,graph_edges RESTART IDENTITY CASCADE')
        self.judge_calls=[]
        def fixture_judge(packet):
            self.judge_calls.append(packet)
            return {'status':'assessed','disposition':'review_required','model':'synthetic-unit-test',
                    'rationale':'Synthetic test decision for observed modification.',
                    'evidence_ids':[e['evidence_id'] for e in packet['evidence']]}
        self.client=TestClient(application(self.database,fixture_judge),base_url='http://localhost')
        self.client.__enter__()
        self.addCleanup(self.database.close)
        self.addCleanup(lambda:self.client.__exit__(None,None,None))
    def agent(self):
        response=self.client.post('/api/agents',json={'goal':'Read-only audit. Do not modify any files.','agent_slug':'audit'})
        self.assertEqual(response.status_code,201,response.text);return response.json()
    def register(self,**kwargs):
        identity=str(uuid.uuid4())
        response=self.client.post('/api/runs',json={'run_id':identity,'harness':'pi',**kwargs})
        self.assertEqual(response.status_code,201,response.text);return identity,response.json()
    def ready(self,identity):
        r=self.client.post(f'/api/runs/{identity}/heartbeat',json={'metadata':{'workspace':'/workspace','abi':'arm64','collector_ready':True}})
        self.assertEqual(r.status_code,200,r.text)
    def wait_analysis(self,identity):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            result=self.client.get('/api/runs/'+identity)
            self.assertEqual(result.status_code,200,result.text)
            run=result.json()
            if run['analysis_state'] not in ('pending','running'):return run
            time.sleep(.1)
        self.fail('analysis did not finish: '+str(run))
    def test_registry_goal_binding_and_unattributed(self):
        agent=self.agent()
        self.assertEqual(self.client.post('/api/agents',json={'goal':'x','agent_slug':'audit'}).status_code,409)
        self.assertEqual(self.client.post('/api/agents',json={'goal':' '}).status_code,422)
        identity,binding=self.register(agent_slug='audit',goal='Ignored goal')
        self.assertEqual(binding['goal'],agent['goal']);self.assertEqual(binding['agent_id'],agent['agent_id'])
        self.assertEqual(len(self.client.get(f'/api/agents/{agent["agent_id"]}/runs').json()['runs']),1)
        _,plain=self.register(goal='Unattributed task');self.assertIsNone(plain['agent_id'])
        self.assertEqual(self.client.post('/api/runs',json={'run_id':str(uuid.uuid4()),'agent_slug':'missing'}).status_code,404)
    def test_ordered_deduplication_raw_excerpts_and_final_analysis(self):
        agent=self.agent();identity,_=self.register(agent_id=agent['agent_id'])
        self.ready(identity)
        now=time.time()
        records=[{'seq':1,'type':'source','source':'hooks.jsonl','line':1,'text':json.dumps({'event':'SessionStart','time':now})+'\n'},
                 {'seq':2,'type':'observation','data':{'kind':'file_state','time':now,'source':'host_state','trust':'independent_observation',
                  'path':'/workspace/app.py','phase':'live','change':'modified','before_sha256':'a','after_sha256':'b','sha256':'b'}}]
        path=f'/api/runs/{identity}/ingest'
        self.assertEqual(self.client.post(path,json={'records':[records[1]]}).status_code,409)
        for _ in range(2):
            response=self.client.post(path,json={'records':records})
            self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(self.client.post(path,json={'records':[{**records[0],'text':'different'}]}).status_code,409)
        self.assertEqual(self.client.post(f'/api/runs/{identity}/complete',json={'last_seq':3,'result':{}}).status_code,409)
        response=self.client.post(f'/api/runs/{identity}/complete',json={'last_seq':2,'result':{'agent_exit_code':0}})
        self.assertEqual(response.status_code,200,response.text)
        run=self.wait_analysis(identity)
        self.assertEqual(run['status'],'complete');self.assertEqual(run['analysis_state'],'complete',run.get('analysis_error'))
        events=self.client.get(f'/api/runs/{identity}/events').json()['events']
        self.assertTrue(events)
        self.assertTrue(all(e['unmapped']['traceward']['agent_id']==agent['agent_id'] for e in events))
        with self.database.pool.connection() as c:
            graph=c.execute('SELECT payload FROM graph_observations WHERE run_id=%s',(identity,)).fetchall()
        self.assertTrue(graph)
        self.assertTrue(all(body['agent_id']==agent['agent_id'] and body['agent_slug']==agent['agent_slug'] for body, in graph))
        findings=self.client.get(f'/api/runs/{identity}/findings').json()['findings']
        self.assertEqual(len(findings),1,findings)
        for evidence_id in findings[0]['evidence_ids']:
            self.assertTrue(self.client.get(f'/api/runs/{identity}/evidence?ids={evidence_id}').json()['events'])
        self.assertEqual(self.client.get(f'/api/runs/{identity}/raw?source=hooks&line=1').status_code,200)
        self.assertEqual(self.client.get(f'/api/runs/{identity}/activity').status_code,200)
        self.assertEqual(self.client.get(f'/api/runs/{identity}/findings/{findings[0]["finding_id"]}/operation-chain').status_code,200)
        self.assertTrue(self.judge_calls)
        self.assertTrue(any(p.get('analysis_window',{}).get('duration_seconds')==30 for p in self.judge_calls))
    def test_interrupted_capture_retains_observations(self):
        identity,_=self.register(goal='Inspect files');self.ready(identity)
        self.client.post(f'/api/runs/{identity}/ingest',json={'records':[{'seq':1,'type':'coverage','data':{'message':'collector interrupted'}}]})
        self.client.post(f'/api/runs/{identity}/complete',json={'last_seq':1,'result':{'shutdown_signal':15}})
        run=self.wait_analysis(identity)
        self.assertEqual(run['status'],'incomplete')
        self.assertIn('collector interrupted',run['summary']['coverage_gaps'])

    def test_recovery_replays_sources_without_duplicate_events(self):
        from traceward.backend import Coordinator
        identity,_=self.register(goal='Inspect file metadata');self.ready(identity)
        records=[{'seq':n,'type':'observation','data':{'kind':'file_state','source':'host_state','time':time.time(),
                  'phase':'baseline','path':f'/workspace/file{n}.py','sha256':str(n)}} for n in range(1,6)]
        self.client.post(f'/api/runs/{identity}/ingest',json={'records':records})
        deadline=time.monotonic()+5
        while self.database.run(identity)['processed_seq']<5 and time.monotonic()<deadline:time.sleep(.1)
        self.client.__exit__(None,None,None)
        # Restart the actual coordinator over the same durable inputs.
        from fastapi.testclient import TestClient
        from traceward.backend import application
        self.client=TestClient(application(self.database,lambda p: self.fail('no candidate expected')),base_url='http://localhost')
        self.client.__enter__()
        self.client.post(f'/api/runs/{identity}/complete',json={'last_seq':5,'result':{'agent_exit_code':0}})
        self.assertEqual(self.wait_analysis(identity)['analysis_state'],'complete')
        events=self.client.get(f'/api/runs/{identity}/events').json()['events']
        self.assertEqual(len([e for e in events if e['unmapped']['traceward']['event_kind']=='file_state']),5)

    def test_recovery_preserves_accepted_assessment_revisions(self):
        identity,_=self.register(goal='Read-only. Do not modify source files.');self.ready(identity)
        record={'seq':1,'type':'observation','data':{'kind':'file_state','source':'host_state','time':time.time(),
                'phase':'live','path':'/workspace/app.py','change':'modified','sha256':'b','before_sha256':'a','after_sha256':'b'}}
        self.client.post(f'/api/runs/{identity}/ingest',json={'records':[record]})
        deadline=time.monotonic()+10
        accepted=[]
        while time.monotonic()<deadline:
            with self.database.pool.connection() as c:
                accepted=c.execute("SELECT finding_id,revision,body FROM findings WHERE run_id=%s AND body->>'status'='review_required'",(identity,)).fetchall()
            if accepted:break
            time.sleep(.1)
        self.assertTrue(accepted)
        self.client.__exit__(None,None,None)
        from fastapi.testclient import TestClient
        from traceward.backend import application
        self.client=TestClient(application(self.database,lambda p:{'status':'unavailable','reason':'recovery_test'}),base_url='http://localhost')
        self.client.__enter__()
        self.client.post(f'/api/runs/{identity}/complete',json={'last_seq':1,'result':{'agent_exit_code':0}})
        self.wait_analysis(identity)
        for fid,revision,body in accepted:
            with self.database.pool.connection() as c:
                saved=c.execute('SELECT body FROM findings WHERE run_id=%s AND finding_id=%s AND revision=%s',(identity,fid,revision)).fetchone()[0]
            self.assertEqual(saved,body,'recovery must not rewrite an accepted revision')

    def test_sync_recovers_unspooled_sources_after_collector_death(self):
        from traceward.remote import sync_main
        identity,binding=self.register(goal='Inspect only')
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)/identity;directory.mkdir()
            private_json(directory/'registration.json',{**binding,'traceward_url':'http://localhost'})
            private_json(directory/'collector-metadata.json',{'workspace':'/workspace','collector_ready':True,'abi':'arm64'})
            Upload(directory,object()).append('coverage',data={'message':'initial source gap'})
            (directory/'hooks.jsonl').write_text(json.dumps({'event':'SessionStart','time':time.time()})+'\n')
            (directory/'credentials.json').write_text('NEVER UPLOAD')
            outer=self
            class Receiver:
                url='http://localhost'
                def __init__(self,*args):pass
                def post(self,path,body):
                    response=outer.client.post('/api'+path,json=body)
                    outer.assertEqual(response.status_code,200,response.text)
                    return response.json()
            with patch('traceward.cli._safe_run_dir',return_value=directory),patch('traceward.remote.Client',Receiver):
                self.assertEqual(sync_main([identity]),0)
                self.assertEqual(sync_main([identity]),0)
            run=self.wait_analysis(identity)
            self.assertEqual(run['capture_state'],'interrupted')
            with self.database.pool.connection() as c:
                sources=c.execute('SELECT DISTINCT source FROM raw_sources WHERE run_id=%s',(identity,)).fetchall()
            self.assertEqual(sources,[('hooks.jsonl',)])


if __name__=='__main__':unittest.main()
