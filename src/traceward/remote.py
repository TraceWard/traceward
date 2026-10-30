"""Durable, ordered upload spool. No inference or database access on the client."""
from __future__ import annotations
import argparse
import fcntl
import json
import os
import threading
import time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from urllib.parse import urlsplit,urlunsplit


def base_url(value=None):
    value=value or os.environ.get('TRACEWARD_URL') or 'http://localhost:8765'
    parsed=urlsplit(value)
    if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('TraceWard URL must be an HTTP(S) base URL without credentials, query or fragment')
    path=parsed.path.rstrip('/')
    if path.endswith('/api'):path=path[:-4]
    return urlunsplit((parsed.scheme,parsed.netloc,path,'',''))


class Client:
    def __init__(self,url=None): self.url=base_url(url)
    def get(self,path,timeout=5):
        try:
            with urlopen(self.url+'/api'+path,timeout=timeout) as response:return json.loads(response.read(16*1024*1024))
        except (OSError,URLError,TimeoutError,ValueError) as exc:
            raise RuntimeError(f'TraceWard backend unavailable at {self.url}: {exc}') from exc
    def post(self,path,body,timeout=5):
        data=json.dumps(body,separators=(',',':'),allow_nan=False).encode()
        request=Request(self.url+'/api'+path,data=data,headers={'Content-Type':'application/json'})
        try:
            with urlopen(request,timeout=timeout) as response: return json.loads(response.read(8*1024*1024))
        except HTTPError as exc:
            try: message=json.loads(exc.read(16384)).get('detail',str(exc))
            except (ValueError,AttributeError): message=str(exc)
            raise RuntimeError(f'TraceWard backend HTTP {exc.code}: {message}') from exc
        except (OSError,URLError,TimeoutError) as exc:
            raise RuntimeError(f'TraceWard backend unavailable at {self.url}: {exc}') from exc


def private_json(path,body):
    temporary=path.with_suffix(path.suffix+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(body,stream);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)


class Upload:
    def __init__(self,directory,client):
        self.directory,self.client=directory,client
        self.identity=directory.name
        self.path=directory/'upload.jsonl'
        self.path.touch(mode=0o600,exist_ok=True);self.path.chmod(0o600)
        self.lock=threading.RLock()
        self.stop=threading.Event()
        self.error=None
        self.seq=0
        with self.path.open('r+b') as stream:
            while line:=stream.readline():
                if not line.endswith(b'\n'):
                    stream.truncate(stream.tell()-len(line));break
                self.seq=json.loads(line)['seq']
        self.thread=threading.Thread(target=self.loop,daemon=True,name='traceward-upload')
    def append(self,kind,**fields):
        with self.lock:
            self.seq+=1
            with self.path.open('a') as stream:
                stream.write(json.dumps({'seq':self.seq,'type':kind,**fields},separators=(',',':'))+'\n')
                stream.flush();os.fsync(stream.fileno())
        return self.seq
    def start(self):self.thread.start()
    def once(self):
        checkpoint=self.directory/'upload-state.json'
        state=json.loads(checkpoint.read_text()) if checkpoint.exists() else {'offset':0,'accepted_seq':0}
        records=[];size=0
        with self.path.open() as stream:
            stream.seek(state['offset'])
            while len(records)<500 and size<1024*1024:
                position=stream.tell();line=stream.readline()
                if not line or not line.endswith('\n'):
                    stream.seek(position);break
                records.append(json.loads(line));size+=len(line)
            offset=stream.tell()
        if records:
            result=self.client.post(f'/runs/{self.identity}/ingest',{'records':records})
            state={'offset':offset,'accepted_seq':result['accepted_seq']}
            private_json(checkpoint,state)
        self.error=None
        return bool(records),state
    def loop(self):
        delay=.2
        while not self.stop.is_set():
            try:
                more,_=self.once();delay=.2
                if not more:self.stop.wait(.5)
            except Exception as exc:
                self.error=str(exc);self.stop.wait(delay);delay=min(delay*2,5)
    def close(self,timeout=6):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            state=self.directory/'upload-state.json'
            accepted=json.loads(state.read_text()).get('accepted_seq',0) if state.exists() else 0
            if accepted==self.seq:break
            time.sleep(.1)
        self.stop.set();self.thread.join(6)
        state=self.directory/'upload-state.json'
        accepted=json.loads(state.read_text()).get('accepted_seq',0) if state.exists() else 0
        if accepted!=self.seq:return False
        result=self.directory/'capture-result.json'
        if result.exists():
            try:
                self.client.post(f'/runs/{self.identity}/complete',{'last_seq':self.seq,'result':json.loads(result.read_text())})
                private_json(self.directory/'upload-complete.json',{'completed_at':time.time(),'traceward_url':self.client.url})
            except Exception as exc:self.error=str(exc);return False
        return True


def sync_main(argv):
    from .cli import _safe_run_dir
    parser=argparse.ArgumentParser(prog='traceward sync')
    parser.add_argument('run_id');parser.add_argument('--traceward-url')
    args=parser.parse_args(argv);directory=_safe_run_dir(args.run_id)
    if not (directory/'registration.json').is_file():raise ValueError('run has no remote upload spool')
    collector_lock=(directory/'collector.lock').open('a')
    try:fcntl.flock(collector_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise ValueError('capture is still active; its uploader is already running') from None
    client=Client(args.traceward_url or os.environ.get('TRACEWARD_URL') or json.loads((directory/'registration.json').read_text()).get('traceward_url'))
    metadata=json.loads((directory/'collector-metadata.json').read_text())
    client.post(f'/runs/{args.run_id}/heartbeat',{'metadata':metadata})
    upload=Upload(directory,client)
    if not (directory/'capture-result.json').exists():
        # A hard-killed collector can leave complete raw lines ahead of its
        # upload spool. Recover only the three explicitly permitted sources.
        seen={name:0 for name in ('hooks.jsonl','raw.gvisor.jsonl','http-events.jsonl')}
        with upload.path.open() as stream:
            for line in stream:
                item=json.loads(line)
                if item.get('type')=='source':seen[item['source']]=max(seen[item['source']],item['line'])
        for name,last in seen.items():
            path=directory/name
            if not path.exists():continue
            with path.open(encoding='utf8',errors='replace') as stream:
                for n,line in enumerate(stream,1):
                    if n>last:upload.append('source',source=name,line=n,text=line,**({'partial':True} if not line.endswith('\n') else {}))
        upload.append('coverage',data={'message':'collector ended without finalization; recovered partial sources; final state sampling unavailable'})
        private_json(directory/'capture-result.json',{'shutdown_signal':'unknown','recovered_capture':True})
    while True:
        more,state=upload.once()
        if not more:break
    result=directory/'capture-result.json'
    if result.exists():
        client.post(f'/runs/{args.run_id}/complete',{'last_seq':upload.seq,'result':json.loads(result.read_text())})
        private_json(directory/'upload-complete.json',{'completed_at':time.time(),'traceward_url':client.url})
    print(f'TraceWard: uploaded {state["accepted_seq"]} inputs for {args.run_id}')
    collector_lock.close()
    return 0
