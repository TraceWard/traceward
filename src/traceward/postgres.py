"""PostgreSQL persistence and adapters for the existing investigation read model.

The compatibility adapter is limited to the SQL used by the existing graph and
dashboard. Collection never receives a database connection or its credentials.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import threading
import time
import uuid
from pathlib import Path

from .dashboard import RunIndex
from .graph import EvidenceGraph
from .ocsf import project, validate_minimum




class Conflict(ValueError): pass
class Missing(ValueError): pass


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True, allow_nan=False)


class Row:
    def __init__(self, names, values):
        self.values = tuple(encode(v) if isinstance(v, (dict, list)) else v for v in values)
        self.mapping = dict(zip(names, self.values))
    def __getitem__(self, key): return self.values[key] if isinstance(key, int) else self.mapping[key]
    def __iter__(self): return iter(self.values)


class Rows:
    def __init__(self, rows): self.rows = rows
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return self.rows
    def __iter__(self): return iter(self.rows)


class ReadConnection:
    def __init__(self, database): self.database = database
    def execute(self, sql, params=()):
        sql = re.sub(r'json_extract\((\w+),\s*\'\$\.([^\']+)\'\)',
                     lambda m: f"({m[1]} #>> '{{{m[2].replace('.', ',')}}}')", sql)
        sql = sql.replace('?', '%s')
        sql = sql.replace(' AS INTEGER)', ' AS BIGINT)')
        with self.database.pool.connection() as connection:
            cursor = connection.execute(sql, params)
            names = [c.name for c in cursor.description] if cursor.description else []
            return Rows([Row(names, row) for row in cursor.fetchall()] if names else [])
    def commit(self): pass
    def close(self): pass


class GraphConnection(ReadConnection):
    def execute(self, sql, params=()):
        sql = re.sub(r'\bobservations\b', 'graph_observations', sql)
        sql = re.sub(r'\bedges\b', 'graph_edges', sql)
        sql = re.sub(r'"([^\"]+)"', r"'\1'", sql)
        if 'INSERT OR IGNORE' in sql:
            sql = sql.replace('INSERT OR IGNORE', 'INSERT') + ' ON CONFLICT DO NOTHING'
        if 'INSERT OR REPLACE INTO graph_observations' in sql:
            sql = sql.replace('INSERT OR REPLACE', 'INSERT') + (
                ' ON CONFLICT(id) DO UPDATE SET tool_id=excluded.tool_id,payload=excluded.payload')
        sql = sql.replace("json_set(payload,'$.tool_use_id',?)",
                          "jsonb_set(payload,'{tool_use_id}',COALESCE(to_jsonb(?::text),'null'::jsonb),true)")
        return super().execute(sql, params)


class PgGraph(EvidenceGraph):
    def __init__(self, database, run_id, shared_roots=()):
        self.run_id = run_id
        self.shared_roots = tuple(posixpath.normpath(str(p)).rstrip('/') + '/' for p in shared_roots)
        self.lock = threading.RLock()
        self.db = GraphConnection(database)
        run=database.run(run_id)
        self.attribution={key:run[key] for key in ('agent_id','agent_slug')}
    def add(self,item):
        super().add({**item,**self.attribution})


class Database:
    def __init__(self, url):
        from psycopg_pool import ConnectionPool
        self.pool = ConnectionPool(url, min_size=1, max_size=12, kwargs={'autocommit': True}, open=True)
        self.pool.wait(timeout=20)
        with self.pool.connection() as c, c.transaction():
            c.execute('SELECT pg_advisory_xact_lock(742091)')
            c.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY)')
            applied={row[0] for row in c.execute('SELECT version FROM schema_migrations')}
            for migration in sorted((Path(__file__).parent/'migrations').glob('*.sql')):
                version=int(migration.name.split('_',1)[0])
                if version not in applied:
                    c.execute(migration.read_text())
                    c.execute('INSERT INTO schema_migrations VALUES(%s)',(version,))

    def close(self): self.pool.close()
    def touch(self, c): c.execute('UPDATE changes SET revision=revision+1 WHERE id=1')
    def run(self, identity):
        with self.pool.connection() as c:
            row = c.execute('SELECT * FROM runs WHERE run_id=%s', (identity,)).fetchone()
            if not row: raise Missing('run not found')
            names = [d.name for d in c.execute('SELECT * FROM runs LIMIT 0').description]
            return dict(zip(names, row))

    def agents(self):
        with self.pool.connection() as c:
            return [dict(zip(('agent_id','agent_slug','goal','created_at'), r)) for r in
                    c.execute('SELECT * FROM agents ORDER BY created_at DESC')]

    def create_agent(self, goal, slug=None):
        if not isinstance(goal, str) or not goal.strip(): raise ValueError('goal is required')
        identity = str(uuid.uuid4())
        slug = slug if slug is not None else 'agent-' + identity.replace('-', '')[:12]
        if not isinstance(slug, str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', slug) or len(slug)>100:
            raise ValueError('slug must contain lowercase letters, numbers and single hyphens (maximum 100 characters)')
        from psycopg.errors import UniqueViolation
        try:
            with self.pool.connection() as c, c.transaction():
                c.execute('INSERT INTO agents VALUES(%s,%s,%s,%s)', (identity,slug,goal,time.time()))
                self.touch(c)
        except UniqueViolation as exc: raise Conflict('agent slug already exists') from exc
        return next(a for a in self.agents() if a['agent_id']==identity)

    def register(self, body):
        identity = str(uuid.UUID(body['run_id']))
        if body.get('agent_id') and body.get('agent_slug'): raise ValueError('choose agent_id or agent_slug')
        agent = None
        if body.get('agent_id') or body.get('agent_slug'):
            key = 'agent_id' if body.get('agent_id') else 'agent_slug'
            agent = next((a for a in self.agents() if a[key]==body[key]), None)
            if agent is None: raise Missing('agent not found')
        goal = agent['goal'] if agent else body.get('goal')
        if goal is not None and (not isinstance(goal,str) or not goal.strip()): raise ValueError('goal cannot be empty')
        attribution = {k:agent[k] if agent else None for k in ('agent_id','agent_slug')}
        now = time.time()
        manifest = {'run_id':identity, **attribution, 'goal':goal or 'Waiting for first user instruction',
                    'goal_status':'established' if goal else 'awaiting_instruction',
                    'started_at':now, 'heartbeat_at':now, 'source':body.get('harness','unknown'),
                    'observer_version':'gvisor-v1', 'runtime':'gvisor'}
        with self.pool.connection() as c, c.transaction():
            old = c.execute('SELECT agent_id,agent_slug,goal FROM runs WHERE run_id=%s', (identity,)).fetchone()
            if old and old != (attribution['agent_id'],attribution['agent_slug'],goal):
                raise Conflict('run identity or goal differs from the registered run')
            c.execute('INSERT INTO runs(run_id,agent_id,agent_slug,goal,manifest,updated_at,heartbeat_at) '
                      'VALUES(%s,%s,%s,%s,%s::jsonb,%s,%s) ON CONFLICT DO NOTHING',
                      (identity, attribution['agent_id'],attribution['agent_slug'],goal,encode(manifest),now,now))
            self.touch(c)
        return {'run_id':identity, **attribution, 'goal':goal}

    def heartbeat(self, identity, metadata=None):
        self.run(identity)
        metadata = metadata or {}
        allowed = {'workspace','abi','context_mode','shared_roots','transport_endpoints','agent_state_roots',
                   'collector_ready','defer_evaluation','runtime','enforcement_actors','actor_model','pi_version',
                   'pi_network','network','runner_image_id','guest_image_id','guest_os','codex_version'}
        selected = {k:v for k,v in metadata.items() if k in allowed}
        now = time.time()
        with self.pool.connection() as c, c.transaction():
            c.execute("UPDATE runs SET heartbeat_at=%s,updated_at=%s,metadata=metadata || %s::jsonb,"
                      "manifest=manifest || %s::jsonb,capture_state=CASE WHEN final_seq IS NULL THEN 'running' ELSE capture_state END "
                      'WHERE run_id=%s', (now,now,encode(selected),encode({'heartbeat_at':now}),identity))
            self.touch(c)

    def ingest(self, identity, records):
        if not isinstance(records,list) or not records or len(records)>500: raise ValueError('expected 1–500 records')
        self.run(identity)
        with self.pool.connection() as c, c.transaction():
            accepted, final = c.execute('SELECT accepted_seq,final_seq FROM runs WHERE run_id=%s FOR UPDATE',(identity,)).fetchone()
            for record in records:
                seq = record.get('seq')
                if not isinstance(seq,int) or isinstance(seq,bool) or seq<1: raise ValueError('invalid input sequence')
                text = encode(record)
                digest = hashlib.sha256(text.encode()).hexdigest()
                old = c.execute('SELECT digest FROM inputs WHERE run_id=%s AND seq=%s',(identity,seq)).fetchone()
                if old:
                    if old[0]!=digest: raise Conflict('sequence already contains different evidence')
                    continue
                if final is not None: raise Conflict('capture has already been closed')
                if seq != accepted+1: raise Conflict(f'expected sequence {accepted+1}')
                if record.get('type') not in {'source','observation','coverage'}: raise ValueError('unknown input type')
                if record['type']=='source':
                    if record.get('source') not in {'raw.gvisor.jsonl','hooks.jsonl','http-events.jsonl'}:
                        raise ValueError('source is not allowed')
                    if not isinstance(record.get('text'),str) or not isinstance(record.get('line'),int) or record['line']<1:
                        raise ValueError('invalid source record')
                    prior=c.execute('SELECT data FROM raw_sources WHERE run_id=%s AND source=%s AND line_no=%s',
                                    (identity,record['source'],record['line'])).fetchone()
                    if prior and bytes(prior[0])!=record['text'].encode(): raise Conflict('source line already contains different bytes')
                    c.execute('INSERT INTO raw_sources VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                              (identity,record['source'],record['line'],record['text'].encode()))
                elif not isinstance(record.get('data'),dict): raise ValueError('input data must be an object')
                elif record['type']=='coverage' and not isinstance(record['data'].get('message'),str): raise ValueError('coverage message required')
                elif record['type']=='observation' and (not isinstance(record['data'].get('kind'),str) or not isinstance(record['data'].get('time'),(int,float))): raise ValueError('observation kind and timestamp required')
                c.execute('INSERT INTO inputs VALUES(%s,%s,%s,%s::jsonb)',(identity,seq,digest,text))
                accepted=seq
            c.execute('UPDATE runs SET accepted_seq=%s,updated_at=%s,heartbeat_at=%s WHERE run_id=%s',
                      (accepted,time.time(),time.time(),identity))
            self.touch(c)
        return {'accepted_seq':accepted}

    def complete(self, identity, last_seq, result):
        with self.pool.connection() as c, c.transaction():
            row=c.execute('SELECT accepted_seq,final_seq,capture_result FROM runs WHERE run_id=%s FOR UPDATE',(identity,)).fetchone()
            if not row: raise Missing('run not found')
            if row[0]!=last_seq: raise Conflict('final sequence has not been fully received')
            if row[1] is not None and (row[1]!=last_seq or row[2]!=result): raise Conflict('capture completion differs')
            state='interrupted' if result.get('shutdown_signal') else 'failed' if result.get('setup_failed') else 'complete'
            c.execute('UPDATE runs SET final_seq=%s,capture_result=%s::jsonb,capture_state=%s,updated_at=%s WHERE run_id=%s',
                      (last_seq,encode(result),state,time.time(),identity))
            self.touch(c)
        return {'capture_state':state,'analysis_state':self.run(identity)['analysis_state']}


class PgIndex(RunIndex):
    def __init__(self, database):
        self.database=database
        self.db=ReadConnection(database)
        self.lock=threading.RLock()
        self.runs_dir=Path('/postgresql')
        self.revision=0
    def refresh(self):
        self.revision=self.db.execute('SELECT revision FROM changes WHERE id=1').fetchone()[0]
        return self.revision
    def _public_run(self,row):
        result=super()._public_run(row)
        connected=time.time()-row['heartbeat_at']<15
        capture=row['capture_state']
        result.update(agent_id=row['agent_id'],agent_slug=row['agent_slug'],
                      status='complete' if capture=='complete' else 'live' if capture in {'registered','running'} and connected else 'incomplete',
                      capture_state=capture if capture not in {'registered','running'} or connected else 'disconnected',
                      analysis_state=row['analysis_state'],analysis_incomplete=row['analysis_state']!='complete',
                      accepted_seq=row['accepted_seq'],processed_seq=row['processed_seq'],analysis_error=row['analysis_error'])
        if row['capture_result']:
            from .collector_status import describe_status
            capture_result=json.loads(row['capture_result'])
            observed=sum(result['event_counts'].get(k,0) for k in ('process','file_read','file_write','file_delete','network','network_send'))
            result['telemetry_status']=describe_status(capture_result.get('runtime_status',{}),observed)
        return result
    def evaluations(self,run_id):
        return [json.loads(r[0]) for r in self.db.execute('SELECT body FROM evaluations WHERE run_id=? ORDER BY signature',(run_id,))]
    def raw_excerpt(self,run_id,source,line,context=8):
        mapping={'gvisor':'raw.gvisor.jsonl','hooks':'hooks.jsonl','http':'http-events.jsonl'}
        if source not in mapping or line<1: raise ValueError('invalid source or line')
        context=min(max(context,0),40)
        with self.database.pool.connection() as c:
            rows=c.execute('SELECT line_no,data FROM raw_sources WHERE run_id=%s AND source=%s AND line_no BETWEEN %s AND %s ORDER BY line_no',
                           (run_id,mapping[source],max(1,line-context),line+context)).fetchall()
        if not rows: raise ValueError('raw source unavailable')
        return {'source':source,'lines':[{'line':n,'text':bytes(v).decode('utf8',errors='replace').rstrip('\n')[:2000]} for n,v in rows], 'truncated':any(len(bytes(v).decode('utf8',errors='replace').rstrip('\n'))>2000 for _,v in rows)}


class Sink:
    def __init__(self,append): self.append=append


class PgStore:
    def __init__(self,database,run):
        self.database,self.run_id=database,run['run_id']
        self.run_dir=Path('/postgresql')/self.run_id
        self.attribution={k:run[k] for k in ('agent_id','agent_slug')}
        self.active_findings=set()
        self.input_id='initial'
        self.identity_counts={}
        self.observations=Sink(lambda item: None)  # graph owns normalized observation persistence
        self.evaluations=Sink(self.evaluation)
    def new_id(self,kind,item):
        origin=item.get('origin_event_id') or item.get('_input_id') or self.input_id
        key=encode([kind,origin])
        n=self.identity_counts.get(key,0);self.identity_counts[key]=n+1
        return str(uuid.uuid5(uuid.UUID(self.run_id),key+':'+str(n)))
    def finding_id(self,key): return str(uuid.uuid5(uuid.UUID(self.run_id),'finding:'+encode(key)))
    def event(self,kind,item):
        record=project(kind,item,self.run_id)
        # Stable IDs for internal assessment/coverage events as well as sources.
        stable=encode([kind,item['finding_id'],item['revision']]) if item.get('finding_id') else kind+':'+encode(item)
        record['metadata']['uid']=item.get('event_id') or str(uuid.uuid5(uuid.UUID(self.run_id),stable))
        record['unmapped']['traceward'].update(self.attribution)
        validate_minimum(record)
        pid=(record.get('process') or record.get('actor',{}).get('process') or {}).get('pid')
        pid=pid if pid is not None else record['unmapped']['traceward'].get('pid')
        with self.database.pool.connection() as c:
            c.execute('INSERT INTO events(run_id,event_id,time_ms,kind,source,pid,body) VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING',
                      (self.run_id,record['metadata']['uid'],record['time'],kind,item.get('source','traceward'),pid,encode(record)))
        return record
    def finding(self,item): return self.assessment(item)
    def assessment(self,item):
        item={**item,**self.attribution}
        with self.database.pool.connection() as c,c.transaction():
            c.execute('INSERT INTO findings VALUES(%s,%s,%s,%s,%s::jsonb) ON CONFLICT(run_id,finding_id,revision) DO UPDATE SET body=excluded.body,time_s=excluded.time_s '
                      "WHERE findings.body->>'status'='provisional'",
                      (self.run_id,item['finding_id'],item['revision'],item.get('time'),encode(item)))
            self.database.touch(c)
        self.event('assessment',item)
        if item.get('status')=='review_required': self.active_findings.add(item['finding_id'])
        elif item['finding_id'] in self.active_findings: self.active_findings.discard(item['finding_id'])
    def evaluation(self,item):
        from .engine import Engine
        signature=hashlib.sha256(Engine.assessment_signature(item['packet']).encode()).hexdigest()
        judgement=item.get('judgement',{})
        request=None if judgement.get('reused_assessment_signature') else judgement.get('request')
        with self.database.pool.connection() as c:
            c.execute('INSERT INTO evaluations(run_id,signature,body,request_bytes,revision) VALUES(%s,%s,%s::jsonb,%s,%s) ON CONFLICT DO NOTHING',
                      (self.run_id,signature,encode({**item,**self.attribution}),json.dumps(request).encode() if request else None,item['revision']))
