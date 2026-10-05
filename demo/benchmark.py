"""Comparable cached-container microbenchmark, excluding LLM and host analysis."""
import argparse
import json
import os
import statistics
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import patch
from traceward.runtime import ManagedRuntime

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--repeats',type=int,default=3)
options=parser.parse_args()
results=[]
with tempfile.TemporaryDirectory(prefix='traceward-benchmark-') as directory:
 root=Path(directory).resolve()
 workspace,home=root/'workspace',root/'home'
 workspace.mkdir();home.mkdir();(home/'auth.json').write_text('{}')
 (workspace/'bench.py').write_text('''import json,time
from pathlib import Path
started=time.time()
t=time.monotonic()
for i in range(500):
 p=Path('temporary-file');p.write_bytes(b'x'*1024);p.read_bytes();p.unlink()
Path('timing.json').write_text(json.dumps({'started_at':started,'execution_seconds':time.monotonic()-t}))
''')
 for backend in ('docker','gvisor'):
  for n in range(options.repeats):
   run=root/f'{backend}-{n}';run.mkdir();(run/'hooks.jsonl').touch()
   with patch('traceward.runtime.Path.cwd',return_value=workspace),patch.dict(os.environ,{'CODEX_HOME':str(home),'TRACEWARD_MANAGED_RUNNER':'0'}):
    runtime=ManagedRuntime(run,str(uuid.uuid4()),['--version'],workspace=str(workspace))
   if backend=='gvisor':
    request=json.loads((run/'request.json').read_text());request['command']=['python3','bench.py'];(run/'request.json').write_text(json.dumps(request))
    command=runtime.command
   else:
    command=['docker','run','--rm','--mount',f'type=bind,source={workspace},target=/workspace','-w','/workspace',
             '--entrypoint','/bin/sh','traceward-test-guest:local','-c',
             'python3 bench.py; cat /sys/fs/cgroup/cpu.stat; cat /sys/fs/cgroup/memory.peak']
   start=time.time();result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=60);end=time.time()
   if result.returncode:raise RuntimeError(result.stderr[-1000:])
   entry={'backend':backend,'wall_seconds':end-start,**json.loads((workspace/'timing.json').read_text())}
   entry['startup_seconds']=entry['started_at']-start
   if backend=='gvisor':
    status=json.loads((run/'runtime-status.json').read_text());entry['resources']=status.get('outer_container_resources',{});entry['source_messages']=status['source_messages'];entry['dropped_messages']=status['dropped_messages']
   else:entry['resources_output']=result.stdout.strip()
   results.append(entry);runtime.cleanup()
report={'scope':'ARM64 Docker Desktop, cached native images, 500 write/read/unlink cycles; no LLM or host normalization/model/dashboard cost',
        'method':'3 repetitions per backend; startup from host launch to guest script clock; wall includes shutdown; cgroup resources include supervisor/collector for gVisor',
        'measurements':results,'medians':{b:{k:statistics.median(r[k] for r in results if r['backend']==b) for k in ['wall_seconds','startup_seconds','execution_seconds']} for b in ['docker','gvisor']}}
options.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
options.output.touch(mode=0o600);options.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report['medians']))
