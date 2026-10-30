"""Load synthetic browser fixtures into a disposable PostgreSQL test database.

This is test-only fixture construction, not a historical-run import command.
The browser exercises the same PostgreSQL read adapter used by the backend.
"""
import json
import threading
from traceward.postgres import Database, PgIndex, encode
from traceward.records import assessment_record


class FixtureIndex(PgIndex):
    def __init__(self, runs, url):
        super().__init__(Database(url))
        self.fixture_runs=runs
        self.fingerprints={}
        self.fixture_lock=threading.RLock()
        with self.database.pool.connection() as c:
            c.execute('TRUNCATE agents,runs,inputs,raw_sources,events,findings,evaluations,graph_observations,graph_edges RESTART IDENTITY CASCADE')

    def refresh(self):
        with self.fixture_lock:
            for folder in self.fixture_runs.iterdir():
                if not folder.is_dir():continue
                files=sorted(p for p in folder.iterdir() if p.is_file())
                fingerprint=tuple((p.name,p.stat().st_size,p.stat().st_mtime_ns) for p in files)
                if self.fingerprints.get(folder.name)==fingerprint:continue
                manifest=json.loads((folder/'run.json').read_text())
                summary=json.loads((folder/'summary.json').read_text()) if (folder/'summary.json').exists() else None
                complete=summary is not None
                with self.database.pool.connection() as c,c.transaction():
                    c.execute('INSERT INTO runs(run_id,goal,manifest,summary,updated_at,heartbeat_at,capture_state,analysis_state) VALUES(%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s) '
                              'ON CONFLICT(run_id) DO UPDATE SET manifest=excluded.manifest,summary=excluded.summary,heartbeat_at=excluded.heartbeat_at,capture_state=excluded.capture_state,analysis_state=excluded.analysis_state',
                              (folder.name,manifest['goal'],encode(manifest),encode(summary) if summary else None,
                               manifest['started_at'],manifest.get('heartbeat_at',0),'complete' if complete else 'running',
                               'incomplete' if summary and summary.get('final_review_complete') is False else 'complete' if complete else 'running'))
                    for path in files:
                        if path.name=='events.jsonl':
                            for line in path.read_text().splitlines():
                                item=json.loads(line);extra=item['unmapped']['traceward']
                                pid=(item.get('process') or item.get('actor',{}).get('process') or {}).get('pid',extra.get('pid'))
                                c.execute('INSERT INTO events(run_id,event_id,time_ms,kind,source,pid,body) VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING',
                                          (folder.name,item['metadata']['uid'],item['time'],extra['event_kind'],extra['source'],pid,encode(item)))
                        elif path.name in {'findings.jsonl','assessments.jsonl'}:
                            for line in path.read_text().splitlines():
                                item=assessment_record(json.loads(line))
                                c.execute('INSERT INTO findings VALUES(%s,%s,%s,%s,%s::jsonb) ON CONFLICT(run_id,finding_id,revision) DO UPDATE SET body=excluded.body',
                                          (folder.name,item['finding_id'],item['revision'],item['time'],encode(item)))
                        elif path.name in {'hooks.jsonl','raw.gvisor.jsonl','http-events.jsonl'}:
                            for n,line in enumerate(path.read_bytes().splitlines(keepends=True),1):
                                c.execute('INSERT INTO raw_sources VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',(folder.name,path.name,n,line))
                        elif path.name=='evaluations.jsonl':
                            for n,line in enumerate(path.read_text().splitlines()):
                                c.execute('INSERT INTO evaluations(run_id,signature,body,request_bytes) VALUES(%s,%s,%s::jsonb,NULL) ON CONFLICT DO NOTHING',(folder.name,str(n),line))
                    self.database.touch(c)
                self.fingerprints[folder.name]=fingerprint
        return super().refresh()
