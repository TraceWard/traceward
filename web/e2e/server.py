"""Disposable JSONL-backed browser regression server. All decisions are synthetic."""
import json
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
index = RunIndex(runs,root/'index.sqlite')
app = create_app(index,Path(__file__).resolve().parents[2]/'src/traceward/dashboard_assets')
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
       'laya':{'status':'assessed','contract_version':'goal-effects-live-v1','model':'synthetic-live-regression',
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
 'laya':{'status':'unavailable','reason':'fixture_outage'} if mode=='unavailable' else {'status':'scored','model':'demo-browser-regression','dimensions':{'goal_relevance':.2,'unexplained_effect':.9,'discrepancy':.8}}}
 if mode in {'structured','citations'}:
  final.update({'revision':4,'time':107,'status':'consistent_with_goal','uncalibrated_risk_score':None,
    'laya':{'status':'assessed','model':'demo-structured-qwen','provider':'synthetic-regression',
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
 store.evaluations.append({'finding_id':final['finding_id'],'revision':final['revision'],'packet':{'goal':'Synthetic browser regression','evidence_ids':base['evidence_ids'],'causal_links':[{'parent':'shell','child':'child'}]},'judgement':final['laya']})
 (folder/'summary.json').write_text(json.dumps({'goal':'Synthetic browser regression','codex_exit_code':0,'coverage_gaps':['Synthetic regression coverage gap','collector connection lost (synthetic test)']}))
 return {'ok':True}
uvicorn.run(app,host='127.0.0.1',port=8779,access_log=False)
