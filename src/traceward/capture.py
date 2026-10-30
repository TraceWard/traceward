"""Managed-runtime collection client; all correlation and judgement is remote."""
from __future__ import annotations
import json
import fcntl
import os
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .remote import Client,Upload,private_json
from .runtime import ManagedRuntime
from .state import StateObserver,independent_validation
from .context import permissions,codex_session
from .collector_status import read_status


def run(args,*,runtime_factory=None,runtime_options=None,agent_name='codex',instruction_parser=None):
    from .cli import _parse_run,_safe_run_dir
    if any(arg.startswith('--judge-') for arg in args[:next((i for i,a in enumerate(args) if a=='codex'),len(args))]):
        raise ValueError('judge settings belong on the TraceWard backend; remove live-run --judge-* options')
    parsed=_parse_run(args,server_analysis=True,**({'instruction_parser':instruction_parser} if instruction_parser else {}))
    goal,agent_args,image,workspace,guest_image,_,options=parsed
    client=Client(options.pop('traceward_url',None))
    identity=str(uuid.uuid4())
    registration={'run_id':identity,'harness':agent_name,'goal':goal,
                  **{k:options.pop(k) for k in ('agent_id','agent_slug') if options.get(k)}}
    binding=client.post('/runs',registration)  # Fail before runtime setup or agent launch.
    goal=binding['goal']
    directory=_safe_run_dir(identity);directory.mkdir(parents=True,mode=0o700);directory.chmod(0o700)
    collector_lock=(directory/'collector.lock').open('a')
    fcntl.flock(collector_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    private_json(directory/'registration.json',{**binding,'traceward_url':client.url})
    private_json(directory/'run.json',{**binding,'started_at':time.time(),'source':agent_name})
    for name in ('hooks.jsonl','raw.gvisor.jsonl'):
        (directory/name).touch(mode=0o600);(directory/name).chmod(0o600)
    context_mode=options.get('context_mode','metadata')
    metadata={'workspace':str(Path.cwd()),'context_mode':context_mode,'abi':'arm64',
              'collector_ready':False,'defer_evaluation':options.get('defer_evaluation',False)}
    private_json(directory/'collector-metadata.json',metadata)
    upload=Upload(directory,client);upload.start()
    runtime=child=None
    shutdown_signal=None
    previous={}
    result={'agent_exit_code':None,'setup_failed':True}
    started=time.monotonic()
    source_offsets={name:0 for name in ('hooks.jsonl','raw.gvisor.jsonl','http-events.jsonl')}
    source_lines=dict.fromkeys(source_offsets,0)
    sessions=set();seen_gaps=set()
    def gap(message):
        if message not in seen_gaps:
            seen_gaps.add(message);upload.append('coverage',data={'message':message})
    def observations(items):
        for item in items:upload.append('observation',data=item)
    def drain():
        more=False
        for name in source_offsets:
            path=directory/name
            if not path.exists():continue
            with path.open('r',encoding='utf8',errors='replace') as stream:
                stream.seek(source_offsets[name]);read=0
                while read<65536:
                    position=stream.tell();line=stream.readline()
                    if not line or not line.endswith('\n'):
                        stream.seek(position);break
                    read+=len(line);source_lines[name]+=1
                    upload.append('source',source=name,line=source_lines[name],text=line)
                    if name=='hooks.jsonl':
                        try:
                            item=json.loads(line)
                            if item.get('session_id'):sessions.add(item['session_id'])
                        except ValueError:pass
                source_offsets[name]=stream.tell()
                more |= read>=65536
        return more
    def forward(signum,_frame):
        nonlocal shutdown_signal
        shutdown_signal=signum
        if runtime and child and child.poll() is None:runtime.signal(child,signum)
    try:
        runtime=(runtime_factory or ManagedRuntime)(directory,identity,agent_args,image=image,workspace=workspace,
            guest_image=guest_image,context_mode=context_mode,
            **{**(runtime_options or {}),'capture_initial_goal':goal is None})
        root=Path(runtime.metadata['workspace'])
        shared=options.get('shared_roots',[])
        if any(not Path(p).resolve().is_relative_to(root) for p in shared):raise ValueError('--shared-root must be inside the observed workspace')
        metadata={**metadata,**runtime.metadata,'collector_ready':True,'shared_roots':shared,
                  'transport_endpoints':list(runtime.transport_endpoints),'agent_state_roots':list(runtime.agent_state_roots)}
        private_json(directory/'collector-metadata.json',metadata)
        client.post(f'/runs/{identity}/heartbeat',{'metadata':metadata})
        for message in runtime.gaps:gap(message)
        states=StateObserver(root,context_mode);observations(states.begin())
        permission=options.get('permissions_file')
        if permission:
            items,gaps=permissions(Path(permission),workspace=root,run_id=identity)
            observations(items)
            for message in gaps:gap(message)
        checker=None
        runtime_image=runtime.image
        runtime_home=runtime.home
        permission_log=runtime.permission_log
        if options.get('validation_script'):
            source=Path(options['validation_script']).expanduser()
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size>1024*1024:raise ValueError('validation script must be a bounded regular file')
                data=os.read(fd,1024*1024+1)
            finally:os.close(fd)
            checker=directory/'independent-check.py';checker.write_bytes(data);checker.chmod(0o600)
        previous={s:signal.signal(s,forward) for s in (signal.SIGINT,signal.SIGTERM)}
        print(f'TraceWard run {identity} — {client.url}/#runs/{identity}',file=sys.stderr,flush=True)
        print(f'Agent: {binding.get("agent_slug") or "Unattributed"} · evidence spool: {directory}',file=sys.stderr,flush=True)
        child=subprocess.Popen(runtime.command)
        heartbeat=sampled=time.monotonic()
        while child.poll() is None:
            more=drain()
            if time.monotonic()-sampled>=2:
                observations(states.sample());sampled=time.monotonic()
            if time.monotonic()-heartbeat>=2:
                try:client.post(f'/runs/{identity}/heartbeat',{'metadata':{}},timeout=2)
                except RuntimeError:pass  # Evidence remains in the independent spool.
                heartbeat=time.monotonic()
            if not more:time.sleep(.1)
        exit_code=child.wait()
        if hasattr(runtime,'await_final_status'):runtime.await_final_status(lambda:False)
        while drain():pass
        runtime.cleanup();runtime=None
        while drain():pass
        if permission_log and permission_log.exists():
            items,gaps=permissions(permission_log,workspace=root,run_id=identity);observations(items)
            for message in gaps:gap(message)
        observations(states.end())
        for message in states.gaps:gap(message)
        for name,offset in source_offsets.items():
            path=directory/name
            if path.exists() and path.stat().st_size>offset:
                with path.open(encoding='utf8',errors='replace') as stream:
                    stream.seek(offset);tail=stream.read()
                upload.append('source',source=name,line=source_lines[name]+1,text=tail,partial=True)
                source_offsets[name]=path.stat().st_size
                gap('incomplete final source record in '+name)
        inspection=directory/'inspection-status.json'
        if inspection.exists() and json.loads(inspection.read_text()).get('healthy') is False:
            gap('HTTPS inspection proxy failed; HTTP coverage is incomplete')
        if agent_name=='codex' and context_mode=='redacted':
            # Runtime owns the credential home; retain its path before cleanup.
            for session in sessions:
                try:uuid.UUID(session)
                except (ValueError,TypeError):gap('invalid Codex session identity');continue
                matches=list((runtime_home/'sessions').rglob('*'+session+'*.jsonl'))[:2]
                if len(matches)!=1:gap('Codex session context file missing or ambiguous');continue
                items,gaps=codex_session(matches[0],expected_session_id=session);observations(items)
                for message in gaps:gap(message)
        if checker:observations([independent_validation(root,checker,runtime_image)])
        status=read_status(directory/'runtime-status.json')
        result={'agent_exit_code':exit_code,'codex_exit_code':exit_code if agent_name=='codex' else None,
                'runtime_status':status,'wall_seconds':round(time.monotonic()-started,3)}
        if shutdown_signal is not None:result['shutdown_signal']=shutdown_signal
        return_code=exit_code if exit_code>=0 else 128-exit_code
    except BaseException as exc:
        result={'agent_exit_code':None,'setup_failed':True,'error':type(exc).__name__}
        gap('collector setup or capture failed: '+type(exc).__name__)
        raise
    finally:
        for signum,handler in previous.items():signal.signal(signum,handler)
        if runtime:
            if child and child.poll() is None:runtime.signal(child,signal.SIGTERM)
            runtime.cleanup()
        while drain():pass
        if not metadata.get('collector_ready'):
            metadata['collector_ready']=True
            private_json(directory/'collector-metadata.json',metadata)
            try:client.post(f'/runs/{identity}/heartbeat',{'metadata':metadata})
            except RuntimeError:pass
        private_json(directory/'capture-result.json',result)
        if not upload.close():
            print(f'TraceWard: upload pending. Resume with traceward sync {identity} --traceward-url {client.url}',file=sys.stderr,flush=True)
            if upload.error:print(upload.error,file=sys.stderr)
        else:print('TraceWard: capture uploaded; backend analysis continues independently.',file=sys.stderr,flush=True)
        collector_lock.close()
    return return_code
