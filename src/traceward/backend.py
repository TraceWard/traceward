"""Trusted-network API and restartable server-side analysis coordinator."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager

from .dashboard import create_app
from .engine import Engine
from .gvisor import GvisorParser
from .judges import judge
from .postgres import Database, PgIndex, PgStore, PgGraph, Missing, Conflict, encode
from .collector_status import describe_status

log=logging.getLogger(__name__)


class Coordinator:
    def __init__(self,database,judge_fn=None):
        self.database=database
        self.judge_fn=judge_fn or judge
        self.stop=threading.Event()
        self.workers={}
        self.slots=threading.BoundedSemaphore(2)
        self.thread=threading.Thread(target=self.loop,daemon=True,name='traceward-analysis')
    def start(self): self.thread.start()
    def close(self):
        self.stop.set()
        self.thread.join(3)
        for thread in list(self.workers.values()): thread.join(3)
    def loop(self):
        while not self.stop.is_set():
            try:
                with self.database.pool.connection() as c:
                    runs=c.execute("SELECT run_id FROM runs WHERE analysis_state IN ('pending','running') AND metadata->>'collector_ready'='true' "
                                   'AND (analysis_error IS NULL OR updated_at < %s)',(time.time()-5,)).fetchall()
                for (identity,) in runs:
                    old=self.workers.get(identity)
                    if old and old.is_alive(): continue
                    if sum(t.is_alive() for t in self.workers.values())>=4: break
                    thread=threading.Thread(target=self.analyse,args=(identity,),daemon=True,name='run-'+identity[:8])
                    self.workers[identity]=thread;thread.start()
            except Exception: log.exception('analysis scheduler unavailable')
            self.stop.wait(.5)
    def analyse(self,identity):
        engine=None
        try:
            # A dedicated session lock prevents two backend processes from owning a run.
            with self.database.pool.connection() as owner:
                key=int.from_bytes(hashlib.sha256(identity.encode()).digest()[:8],'big',signed=True)
                if not owner.execute('SELECT pg_try_advisory_lock(%s)',(key,)).fetchone()[0]: return
                try: self._analyse(identity)
                finally: owner.execute('SELECT pg_advisory_unlock(%s)',(key,))
        except Exception as exc:
            log.exception('analysis failed for %s',identity)
            try:
                with self.database.pool.connection() as c:
                    c.execute("UPDATE runs SET analysis_state='pending',analysis_error=%s,updated_at=%s WHERE run_id=%s",(type(exc).__name__+': '+str(exc)[:500],time.time(),identity))
            except Exception: log.exception('could not persist analysis failure')
    def _analyse(self,identity):
        run=self.database.run(identity); metadata=run['metadata']
        store=PgStore(self.database,run)
        def cached_judge(packet):
            signature=hashlib.sha256(Engine.assessment_signature(packet).encode()).hexdigest()
            with self.database.pool.connection() as c:
                cached=c.execute("SELECT body FROM evaluations WHERE run_id=%s AND signature=%s AND body->'judgement'->>'status' IN ('assessed','scored') ORDER BY revision DESC LIMIT 1",(identity,signature)).fetchone()
            if cached: return {**cached[0]['judgement'],'reused_assessment_signature':signature}
            return self.judge_fn(packet)
        engine=Engine(run['goal'] or '',store,judge_fn=cached_judge,workspace=metadata.get('workspace'),
                      extended_analysis=True,context_mode=metadata.get('context_mode','metadata'),
                      realtime=True,defer_evaluation=bool(metadata.get('defer_evaluation')),shared_roots=metadata.get('shared_roots',()),
                      transport_endpoints=metadata.get('transport_endpoints',()),
                      agent_state_roots=metadata.get('agent_state_roots',()),
                      graph_factory=lambda rid,roots:PgGraph(self.database,rid,roots))
        # Pause replay without selecting the separate deferred-analysis mode.
        # Engine chooses rolling windows at construction, before any inputs.
        engine.defer_evaluation=True
        engine.judge_slots=self.slots
        parser=GvisorParser(metadata.get('workspace','/workspace'),metadata.get('abi','arm64'))
        processed=0
        restored=False
        with self.database.pool.connection() as c:
            c.execute("UPDATE runs SET analysis_state='running',analysis_error=NULL WHERE run_id=%s",(identity,))
        try:
            while not self.stop.is_set():
                with self.database.pool.connection() as c:
                    records=c.execute('SELECT seq,body FROM inputs WHERE run_id=%s AND seq>%s ORDER BY seq LIMIT 500',(identity,processed)).fetchall()
                for seq,record in records:
                    store.input_id=str(uuid.uuid5(uuid.UUID(identity),'input:'+str(seq)))
                    if record['type']=='source':
                        source=record['source'];text=record['text']
                        if record.get('partial'):
                            engine.add_gap('incomplete final source record in '+source)
                        elif source=='raw.gvisor.jsonl':
                            item=parser.parse(text)
                            if item: engine.effect({**item,'_input_id':store.input_id})
                            for gap in parser.gaps: engine.add_gap(gap)
                        else:
                            try: item=json.loads(text)
                            except (ValueError,TypeError):
                                engine.add_gap('malformed '+source);item=None
                            if item:
                                item={**item,'_input_id':store.input_id}
                                if source=='hooks.jsonl':
                                    if not engine.goal and not run['agent_id'] and item.get('event')=='InitialInstruction' and item.get('input_source')=='interactive' and item.get('goal_text','').strip():
                                        engine.set_goal(item['goal_text'])
                                        with self.database.pool.connection() as c:
                                            c.execute('UPDATE runs SET goal=%s,manifest=manifest || %s::jsonb WHERE run_id=%s',
                                                      (engine.goal,encode({'goal':engine.goal,'goal_status':'established'}),identity))
                                    engine.hook(item)
                                elif item.get('kind')=='http_request': engine.observe(item)
                    elif record['type']=='observation':
                        engine.observe({**record['data'],'_input_id':store.input_id})
                    else: engine.add_gap(record['data']['message'])
                    processed=seq
                if records:
                    with self.database.pool.connection() as c:
                        c.execute('UPDATE runs SET processed_seq=%s WHERE run_id=%s',(processed,identity))
                current=self.database.run(identity)
                if processed>=current['accepted_seq']:
                    with engine.changed:
                        if not restored:
                            # Replaying inputs reconstructs correlation, while accepted
                            # decisions keep their original revision, scope and audit.
                            with self.database.pool.connection() as c:
                                audits=c.execute('SELECT body FROM evaluations WHERE run_id=%s ORDER BY (body->>\'revision\')::integer', (identity,)).fetchall()
                                decisions=c.execute('SELECT DISTINCT ON(finding_id) body FROM findings WHERE run_id=%s ORDER BY finding_id,revision DESC', (identity,)).fetchall()
                            for (audit,) in audits:
                                fid=audit['finding_id']
                                engine.assessed_packets[fid]=(audit['revision'],audit['packet'])
                                engine.assessment_states[fid]=audit['judgement'].get('status','unavailable')
                            for (decision,) in decisions:
                                fid=decision['finding_id']
                                if fid in engine.assessed_packets:
                                    _,packet=engine.assessed_packets[fid]
                                    engine.assessed_packets[fid]=(decision['revision'],packet)
                                if decision.get('status')=='review_required':
                                    engine.last_reviews[decision['finding_id']]=decision
                                    engine.review_ids.add(decision['finding_id'])
                            engine.counts['finding']=len(engine.review_ids)
                            restored=True
                        engine.defer_evaluation=bool(metadata.get('defer_evaluation')) or not bool(engine.goal)
                        engine.changed.notify_all()
                    if current['final_seq'] is not None and processed==current['final_seq']:
                        # The collector can exit immediately. The server, unlike the
                        # old local live wrapper, owns the final assessment lifecycle.
                        engine.realtime=False
                        if not engine.goal: engine.realtime_requested=False
                        with engine.changed:
                            engine.defer_evaluation=False
                            engine.changed.notify_all()
                        engine.finish()
                        result=current['capture_result'] or {}
                        summary={**engine.summary(),**metadata,**result,'run_id':identity,**store.attribution}
                        summary['telemetry_status']=describe_status(result.get('runtime_status',{}),
                            sum(engine.counts[k] for k in ('process','process_exit','file_open','file_read','file_write','file_delete','network','network_send')))
                        state='complete' if summary['final_review_complete'] else 'incomplete'
                        with self.database.pool.connection() as c,c.transaction():
                            c.execute('UPDATE runs SET summary=%s::jsonb,analysis_state=%s,updated_at=%s WHERE run_id=%s',
                                      (encode(summary),state,time.time(),identity));self.database.touch(c)
                        return
                if not records: self.stop.wait(.2)
        finally:
            engine.assessments_closed=True
            with engine.changed: engine.changed.notify_all()


def application(database,judge_fn=None):
    from fastapi import Request
    from fastapi.responses import JSONResponse
    index=PgIndex(database)
    app=create_app(index,bind_host=os.environ.get('TRACEWARD_PUBLIC_HOST','0.0.0.0'),
                   public_origin=os.environ.get('TRACEWARD_PUBLIC_ORIGIN') or None)
    coordinator=Coordinator(database,judge_fn)
    @asynccontextmanager
    async def lifespan(app):
        coordinator.start()
        try: yield
        finally: coordinator.close()
    app.router.lifespan_context=lifespan
    @app.exception_handler(Missing)
    async def missing(request,exc): return JSONResponse({'detail':str(exc)},status_code=404)
    @app.exception_handler(Conflict)
    async def conflict(request,exc): return JSONResponse({'detail':str(exc)},status_code=409)
    @app.exception_handler(ValueError)
    async def invalid(request,exc): return JSONResponse({'detail':str(exc)},status_code=422)
    @app.middleware('http')
    async def bounded_body(request,call_next):
        if request.method=='POST':
            try:
                data=await request.body()
                if len(data)>4*1024*1024: return JSONResponse({'detail':'request too large'},status_code=413)
            except Exception: return JSONResponse({'detail':'invalid request body'},status_code=400)
        return await call_next(request)
    @app.get('/api/agents')
    def agents(): return {'agents':database.agents()}
    @app.post('/api/agents',status_code=201)
    def create_agent(body:dict): return database.create_agent(body.get('goal'),body.get('agent_slug'))
    @app.get('/api/agents/{identity}')
    def agent(identity:str):
        found=next((a for a in database.agents() if a['agent_id']==identity),None)
        if not found: raise Missing('agent not found')
        return found
    @app.get('/api/agents/{identity}/runs')
    def agent_runs(identity:str):
        agent(identity)
        return {'runs':[r for r in index.runs() if r['agent_id']==identity]}
    @app.post('/api/runs',status_code=201)
    def register(body:dict):
        if not isinstance(body.get('run_id'),str): raise ValueError('run_id is required')
        return database.register(body)
    @app.post('/api/runs/{identity}/heartbeat')
    def heartbeat(identity:str,body:dict):
        database.heartbeat(identity,body.get('metadata'));return {'status':'ok'}
    @app.post('/api/runs/{identity}/ingest')
    def ingest(identity:str,body:dict): return database.ingest(identity,body.get('records'))
    @app.post('/api/runs/{identity}/complete')
    def complete(identity:str,body:dict):
        if not isinstance(body.get('last_seq'),int) or not isinstance(body.get('result'),dict):
            raise ValueError('last_seq and result are required')
        return database.complete(identity,body['last_seq'],body['result'])
    return app


def main(argv=None):
    parser=argparse.ArgumentParser(prog='traceward backend')
    parser.add_argument('--host',default='0.0.0.0');parser.add_argument('--port',type=int,default=8000)
    args=parser.parse_args(argv)
    from .config import load_observer_env
    load_observer_env(extra_keys={'DATABASE_URL','TRACEWARD_PUBLIC_HOST'})
    url=os.environ.get('DATABASE_URL')
    if not url: raise ValueError('DATABASE_URL is required for the backend')
    import uvicorn
    database=Database(url)
    try: uvicorn.run(application(database),host=args.host,port=args.port,access_log=False)
    finally: database.close()

if __name__=='__main__': main()
