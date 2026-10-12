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
index = RunIndex(runs,root/'index.sqlite')
app = create_app(index,Path(__file__).resolve().parents[2]/'src/traceward/dashboard_assets')
@app.post('/test/revision/{mode}')
def revision(mode:str):
 final = {**base,'revision':3 if mode=='unavailable' else 2,'time':106,'status':'inconclusive' if mode=='unavailable' else 'review_required', 'uncalibrated_risk_score':None if mode=='unavailable' else .83,
 'laya':{'status':'unavailable','reason':'fixture_outage'} if mode=='unavailable' else {'status':'scored','model':'demo-browser-regression','dimensions':{'goal_relevance':.2,'unexplained_effect':.9,'discrepancy':.8}}}
 if mode=='structured':
  final.update({'revision':4,'time':107,'status':'consistent_with_goal','uncalibrated_risk_score':None,
    'laya':{'status':'assessed','model':'demo-structured-qwen','provider':'synthetic-regression',
      'disposition':'consistent_with_goal','rationale':'The synthetic goal explicitly requests these fixture operations.',
      'cited_evidence_ids':['file-299','send'],'semantic_accuracy_validated':False}})
  final['assessment']={name:{'status':'supported','summary':'Synthetic supported context','evidence_ids':['send']}
      for name in ('relevance','authority','integrity','outcome','benign_explanation','missing_evidence')}
  final['verified_claims']=[{'fact_type':'observed_operation','evidence_ids':['send']}]
 store.finding(final)
 store.evaluations.append({'finding_id':base['finding_id'],'revision':final['revision'],'packet':{'goal':'Synthetic browser regression','evidence_ids':base['evidence_ids'],'causal_links':[{'parent':'shell','child':'child'}]},'judgement':final['laya']})
 (folder/'summary.json').write_text(json.dumps({'goal':'Synthetic browser regression','codex_exit_code':0,'coverage_gaps':['Synthetic regression coverage gap','collector connection lost (synthetic test)']}))
 return {'ok':True}
uvicorn.run(app,host='127.0.0.1',port=8779,access_log=False)
