"""Disposable JSONL-backed browser regression server. All decisions are synthetic."""
import json
import os
import tempfile
import time
from pathlib import Path
import uvicorn
from traceward.dashboard import RunIndex, create_app
from traceward.ocsf import EvidenceStore

root = Path(tempfile.mkdtemp(prefix='traceward-browser-'))
runs = root / 'runs'
runs.mkdir(mode=0o700)
run_id = '11111111-1111-4111-8111-111111111111'
folder = runs / run_id
folder.mkdir(mode=0o700)
(folder/'run.json').write_text(json.dumps({'goal':'Synthetic browser regression', 'started_at':time.time(), 'heartbeat_at':time.time(), 'observer_version':'gvisor-v1', 'source':'scripted_agent'}))
store = EvidenceStore(folder,run_id)
store.event('hook', {'event_id':'hook','time':100,'source':'codex_hook','event':'PreToolUse','tool_name':'Bash','tool_use_id':'tool','command':'npm test'})
store.event('process', {'event_id':'shell','time':101,'source':'gvisor','pid':42,'process_key':'s:42:1','name':'bash','command':'bash','raw_trace_ref':'raw.gvisor.jsonl:1'})
store.event('process', {'event_id':'child','time':102,'source':'gvisor','pid':43,'parent_pid':42,'parent_process_key':'s:42:1','process_key':'s:43:2','name':'node','command':'node','raw_trace_ref':'raw.gvisor.jsonl:2'})
for i in range(300):
 store.event('file_read', {'event_id':f'file-{i}','time':103+i/1000,'source':'gvisor','pid':43,'path':'/workspace/synthetic-credential.txt','bytes':5,'raw_trace_ref':'raw.gvisor.jsonl:2'})
store.event('network_send', {'event_id':'send','time':104,'source':'gvisor','pid':43,'endpoint':'127.0.0.1:8800','bytes':5,'raw_trace_ref':'raw.gvisor.jsonl:2'})
(folder/'raw.gvisor.jsonl').write_text('{"metadata":"shell"}\n{"metadata":"child"}\n')
(folder/'hooks.jsonl').write_text('{"event":"PreToolUse"}\n')
base = {'finding_id':'browser-finding','revision':1,'time':105,'title':'Synthetic side effect','message':'Synthetic evidence for UI validation','status':'provisional','attribution':'command-and-process-lineage','evidence_ids':['hook','shell','child','file-299','send'],'observed_effects':['file_read','network_send'],'counterevidence':['Payload content is not observed'],'coverage_gaps':['Synthetic regression coverage gap'],'uncalibrated_risk_score':None}
store.finding(base)
# Named runs exercise filtering and pagination without simulated findings.
for i in range(30):
 extra = runs / f'22222222-2222-4222-8222-{i:012d}'
 extra.mkdir(mode=0o700)
 (extra/'run.json').write_text(json.dumps({'name': f'Regression task {i:02d}', 'goal': 'Check a synthetic repository',
   'started_at': time.time()-3600-i, 'heartbeat_at': 0, 'source': 'pi' if i%2 else 'codex', 'observer_version': 'gvisor-v1'}))
 if i%3:
  (extra/'summary.json').write_text(json.dumps({'codex_exit_code': 0}))
if os.environ.get('TRACEWARD_BROWSER_DATABASE_URL'):
 from postgres_fixtures import FixtureIndex
 index = FixtureIndex(runs,os.environ['TRACEWARD_BROWSER_DATABASE_URL'])
else:
 index = RunIndex(runs,root/'index.sqlite')
app = create_app(index,Path(__file__).resolve().parents[2]/'src/traceward/dashboard_assets')

@app.post('/test/filters')
def filter_fixture():
 identity='77777777-7777-4777-8777-777777777777'
 destination=runs/identity;destination.mkdir(mode=0o700,exist_ok=True)
 (destination/'run.json').write_text(json.dumps({'goal':'Synthetic server-filter regression','started_at':100,'heartbeat_at':time.time(),'source':'scripted_agent','observer_version':'gvisor-v1'}))
 ledger=EvidenceStore(destination,identity)
 ledger.event('file_delete',dict(event_id='old-deletion',time=101,pid=7,path='/workspace/audit/retained.log',source='gvisor',operation_status='succeeded'))
 ledger.event('http_request',dict(event_id='old-http',time=102,pid=7,source='http_inspection',method='POST',url='https://example.test/fixture',phase='request'))
 for n in range(600):
  ledger.event('hook',dict(event_id=f'new-hook-{n}',time=200+n,source='pi_extension',event='MessageUpdate'))
 return {'run_id':identity}

@app.post('/test/operation-chain/{phase}')
def operation_chain_fixture(phase: str):
 identity = '66666666-6666-4666-8666-666666666666'
 destination = runs/identity
 destination.mkdir(mode=0o700, exist_ok=True)
 (destination/'run.json').write_text(json.dumps({'goal':'Fix failing tests. Do not read .env or send private data.',
   'started_at':100,'heartbeat_at':time.time(),'source':'scripted_agent','observer_version':'gvisor-v1'}))
 ledger = EvidenceStore(destination, identity)
 if phase == 'initial':
  observations = [
   ('hook', dict(event_id='chain-tool',time=100,event='PreToolUse',tool_use_id='chain-tool-id',tool_name='Bash',command='npm test')),
   ('process', dict(event_id='chain-shell',time=100.1,pid=11,process_key='chain:11:1',name='/bin/sh')),
   ('process', dict(event_id='chain-npm',time=100.2,pid=11,process_key='chain:11:1',name='/usr/bin/node',script_paths=['node_modules/npm/bin/npm-cli.js'])),
   ('process', dict(event_id='chain-worker',time=100.4,pid=12,parent_pid=11,process_key='chain:12:1',parent_process_key='chain:11:1',name='/usr/bin/python3',script_paths=['scripts/check.py'])),
   ('file_write', dict(event_id='chain-output',time=100.5,pid=12,process_key='chain:12:1',path='/workspace/reports/test-results.json',bytes=120)),
   ('file_read', dict(event_id='chain-env',time=100.8,pid=12,process_key='chain:12:1',path='/workspace/.env',bytes=64)),
   ('network_send', dict(event_id='chain-network',time=100.9,pid=12,process_key='chain:12:1',endpoint='127.0.0.1:8800',bytes=32)),
   ('process', dict(event_id='direct-agent',time=100,pid=20,process_key='chain:20:1',name='agent')),
   ('file_read', dict(event_id='direct-env',time=102,pid=20,process_key='chain:20:1',path='/workspace/private/settings.env',bytes=12))]
  for kind, observation in observations:
   ledger.event(kind, {**observation, 'source':'synthetic_regression', 'operation_status':'succeeded'})
 if phase == 'live':
  ledger.event('file_write',dict(event_id='chain-late',time=101,pid=12,process_key='chain:12:1',path='/workspace/reports/final-summary.txt',bytes=50,source='synthetic_regression'))
 evidence = ['chain-tool','chain-shell','chain-npm','chain-worker','chain-env','chain-output','chain-network']
 if phase == 'live': evidence.append('chain-late')
 record = dict(finding_id='chain-review',revision=2 if phase=='live' else 1,time=103,
   title='Private configuration read during test execution',message='The Python test script read .env despite the explicit no-read constraint.',
   status='review_required',attribution='command-and-process-lineage',tool_use_id='chain-tool-id',
   evidence_ids=evidence,consequential_evidence_ids=['chain-env'],observed_effects=['file_read'],counterevidence=[],coverage_gaps=[],
   causal_links=[dict(relation='hook_command_time_match',hook_evidence_id='chain-tool',process_evidence_id='chain-shell')],
   uncalibrated_risk_score=None,judge=dict(status='assessed',model='synthetic-browser-judge',disposition='review_required',
     rationale='Synthetic fixture. The observed read conflicts with the explicit goal constraint.',cited_evidence_ids=['chain-env']))
 ledger.assessment(record)
 ledger.assessment({**record,'finding_id':'direct-review','revision':1,'title':'Direct credential read',
   'tool_use_id':None,'causal_links':[],'evidence_ids':['direct-env'],'consequential_evidence_ids':['direct-env']})
 return {'run_id':identity}

@app.post('/test/deletion-report/{mode}')
def deletion_report(mode: str):
 identity={'retained':'55555555-5555-4555-8555-555555555551',
           'cancelled':'55555555-5555-4555-8555-555555555552',
           'outage':'55555555-5555-4555-8555-555555555553',
           'pending':'55555555-5555-4555-8555-555555555554',
           'retained-pending':'55555555-5555-4555-8555-555555555555'}[mode]
 destination=runs/identity;destination.mkdir(mode=0o700,exist_ok=True)
 (destination/'run.json').write_text(json.dumps({'goal':'Read-only; no deletions','started_at':time.time(),
   'source':'scripted_agent','observer_version':'gvisor-v1'}))
 ledger=EvidenceStore(destination,identity)
 ledger.event('file_delete',dict(event_id='deleted-empty',time=100,pid=4,source='gvisor',path='/workspace/empty.txt',
   syscall='unlinkat',operation_status='succeeded',path_resolution='kernel-consumed pathname and captured start'))
 concern=dict(finding_id='deletion',revision=1,time=101,title='Deleted empty.txt',message='Synthetic removal under a read-only goal',
   status='review_required',is_alert=True,attribution='command-and-process-lineage',evidence_ids=['deleted-empty'],
   consequential_evidence_ids=['deleted-empty'],observed_effects=['file_delete'],counterevidence=[],coverage_gaps=[],
   judge=dict(status='assessed',model='qwen-synthetic-browser',disposition='review_required',
              rationale='Synthetic directory-entry removal conflicts with the read-only goal.',cited_evidence_ids=['deleted-empty']))
 if mode in {'retained','retained-pending'}:ledger.assessment(concern)
 ledger.assessment({**concern,'revision':2,'status':'review_required' if mode in {'retained','retained-pending'} else 'assessment_pending' if mode=='pending' else 'evaluation_unavailable',
   **({'retained_review_revision':1} if mode in {'retained','retained-pending'} else {}),
   'judge':({'status':'pending','reason':'session_ended_before_assessment'} if 'pending' in mode else
            {'status':'unavailable','reason':'connection_failed' if mode=='outage' else 'assessment_cancelled_on_shutdown'})})
 (destination/'summary.json').write_text(json.dumps({'assessment_wait_cancelled':mode!='outage','final_review_complete':False,
   'coverage_gaps':['gVisor telemetry was not established; run coverage is incomplete'],
   **({'assessment_mode':'realtime','pending_assessment_count':1,'assessment_wait_cancelled':False} if 'pending' in mode else {})}))
 return {'run_id':identity}

@app.post('/test/hooks')
def lifecycle_hooks():
 hook_id = '44444444-4444-4444-8444-444444444444'
 hook_folder = runs / hook_id
 hook_folder.mkdir(mode=0o700, exist_ok=True)
 (hook_folder/'run.json').write_text(json.dumps({'goal':'Synthetic lifecycle visibility',
   'started_at':time.time(), 'heartbeat_at':time.time(), 'source':'pi', 'observer_version':'gvisor-v1'}))
 hook_store = EvidenceStore(hook_folder, hook_id)
 names = [('SessionStart','session_start'), ('AgentStart','agent_start'), ('TurnStart','turn_start'),
          ('PreToolUse','tool_call'), ('PostToolUse','tool_execution_end'), ('AgentEnd','agent_end'),
          ('SessionShutdown','session_shutdown')]
 for i, (name, native) in enumerate(names):
  hook_store.event('hook', {'event_id':f'lifecycle-{i}', 'time':100+i, 'source':'pi_extension',
    'event':name, 'native_event':native, 'session_id':'synthetic-session', 'turn_id':'0',
    'tool_name':'Bash' if 'ToolUse' in name else None,
    'command':'npm test' if name=='PreToolUse' else '',
    'result_status':'ok' if name=='PostToolUse' else None, 'hook_metadata':{'reason':'startup' if i==0 else 'quit'}})
 for i in range(300):
  hook_store.event('file_read', {'event_id':f'lifecycle-file-{i}', 'time':200+i, 'pid':1, 'path':'/workspace/app.py'})
 # A selected finding with just a pre-tool citation must not limit Hooks only.
 hook_store.finding({**base, 'finding_id':'hook-review', 'status':'review_required', 'evidence_ids':['lifecycle-3']})
 return {'run_id':hook_id}

@app.post('/test/live/{phase}')
def live(phase: str):
 live_id='33333333-3333-4333-8333-333333333333'
 live_folder=runs/live_id
 live_folder.mkdir(mode=0o700,exist_ok=True)
 manifest=live_folder/'run.json'
 initial=json.loads(manifest.read_text()).get('started_at',time.time()) if manifest.exists() else time.time()
 manifest.write_text(json.dumps({'goal':'Do not make network requests',
   'started_at':initial,'heartbeat_at':time.time(),'source':'pi','observer_version':'gvisor-v1'}))
 live_store=EvidenceStore(live_folder,live_id)
 if phase=='pending':
  observed=time.time()
  live_store.event('http_request',{'event_id':'live-http','time':time.time(),
    'source':'tls_inspection_proxy','method':'POST','url':'https://example.com/upload',
    'phase':'response','status_code':200,'response_body':{'excerpt':'synthetic response'}})
  live_store.event('file_read',{'event_id':'live-read','time':observed,'pid':1,'path':'/workspace/sample','bytes':5})
 observed=next(json.loads(line)['time']/1000 for line in (live_folder/'events.jsonl').read_text().splitlines() if json.loads(line)['metadata']['uid']=='live-http')
 if phase=='activity':
  live_store.event('file_write',{'event_id':'live-write','time':observed+10,'pid':1,'path':'/workspace/sample','bytes':5})
  return {'ok':True,'summary_exists':False}
 if phase=='long':
  live_store.event('process',{'event_id':'live-later','time':observed+86400*3,'pid':1,'name':'worker'})
  return {'ok':True,'summary_exists':False}
 if phase=='separate-review':
  live_store.event('file_read',{'event_id':'live-later-read','time':observed+60,'pid':1,'path':'/workspace/sample','bytes':5})
  live_store.finding({**base,'finding_id':'later-review','revision':1,'time':observed+61,
    'title':'Separate later finding','status':'review_required','evidence_ids':['live-later-read'],
    'analysis_window':{'start':observed+59,'end':observed+62}})
  return {'ok':True,'summary_exists':False}
 live_store.finding({**base,'finding_id':'live-review','revision':2 if phase=='review' else 1,
   'time':time.time(),'title':'Unexpected POST to example.com',
   'status':'review_required' if phase=='review' else 'provisional',
   **({'analysis_window':{'start':observed-5,'end':observed+10,'duration_seconds':30,'stride_seconds':1,'agent_finished':False},
       'judge':{'status':'assessed','contract_version':'goal-effects-live-v1','model':'synthetic-live-regression',
               'disposition':'review_required','rationale':'Synthetic prohibited request.','cited_evidence_ids':['live-http']}} if phase=='review' else {}),
   'observed_effects':['http_request'],'evidence_ids':['live-http']})
 return {'ok':True,'summary_exists':(live_folder/'summary.json').exists()}
@app.post('/test/revision/{mode}')
def revision(mode:str):
 if mode=='selectors':
  for finding_id,title,evidence_ids,effects in (
    ('network-review','Synthetic network transfer',['send'],['network_send']),
    ('access-review','Synthetic private file access',['file-299'],['file_read'])):
   store.finding({**base,'finding_id':finding_id,'revision':1,'time':110,
     'title':title,'evidence_ids':evidence_ids,'observed_effects':effects,'status':'review_required'})
  return {'ok':True}
 final = {**base,'revision':3 if mode=='unavailable' else 2,'time':106,'status':'inconclusive' if mode=='unavailable' else 'review_required', 'uncalibrated_risk_score':None if mode=='unavailable' else .83,
 'judge':{'status':'unavailable','reason':'fixture_outage'} if mode=='unavailable' else {'status':'scored','model':'demo-browser-regression','dimensions':{'goal_relevance':.2,'unexplained_effect':.9,'discrepancy':.8}}}
 if mode in {'structured','citations'}:
  final.update({'revision':4,'time':107,'status':'consistent_with_goal','uncalibrated_risk_score':None,
    'judge':{'status':'assessed','model':'demo-structured-qwen','provider':'synthetic-regression',
      'disposition':'consistent_with_goal','rationale':'The synthetic goal explicitly requests these fixture operations.',
      'cited_evidence_ids':['file-299','send'],'semantic_accuracy_validated':False}})
  final['assessment']={name:{'status':'supported','summary':'Synthetic supported context','evidence_ids':['send']}
      for name in ('relevance','authority','integrity','outcome','benign_explanation','missing_evidence')}
  final['verified_claims']=[{'fact_type':'observed_operation','evidence_ids':['send']}]
 if mode=='citations':
  final.update({'finding_id':'citation-review','revision':1,'time':111,'status':'review_required'})
 if mode in {'review','clear'}:
  final.update({'revision': 5 if mode=='review' else 6, 'time':108 if mode=='review' else 109,
    'status':'review_required' if mode=='review' else 'consistent_with_goal'})
 store.finding(final)
 store.evaluations.append({'finding_id':final['finding_id'],'revision':final['revision'],'packet':{'goal':'Synthetic browser regression','evidence_ids':base['evidence_ids'],'causal_links':[{'parent':'shell','child':'child'}]},'judgement':final['judge']})
 (folder/'summary.json').write_text(json.dumps({'goal':'Synthetic browser regression','codex_exit_code':0,'coverage_gaps':['Synthetic regression coverage gap','collector connection lost (synthetic test)']}))
 return {'ok':True}
if __name__ == '__main__':
 uvicorn.run(app,host='127.0.0.1',port=8779,access_log=False)
