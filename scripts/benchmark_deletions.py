"""Compare capture-only overhead on one patched runtime, not model performance.

Run: .venv/bin/python scripts/benchmark_deletions.py --output /tmp/deletion-benchmark.json
The baseline explicitly disables only the new deletion trace point in this lab.
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import uuid
from unittest.mock import patch
from traceward.runtime import ManagedRuntime

parser=argparse.ArgumentParser()
parser.add_argument('--iterations',type=int,default=500)
parser.add_argument('--repetitions',type=int,default=3)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
assert args.iterations>0 and args.repetitions>0
samples=[]
with tempfile.TemporaryDirectory(prefix='traceward-delete-bench-') as temp:
    root=Path(temp).resolve()
    for repetition in range(args.repetitions):
        for enabled in ((False,True) if repetition%2==0 else (True,False)):
            folder=root/f'{repetition}-{enabled}';folder.mkdir()
            workspace,home,run=folder/'workspace',folder/'home',folder/'run'
            for path in (workspace,home,run):path.mkdir()
            (home/'auth.json').write_text('{}');(run/'hooks.jsonl').touch(mode=0o600)
            program=('import os,time,json;start=time.monotonic();'
                     f'[(os.close(os.open("sample",os.O_CREAT|os.O_WRONLY,0o600)),os.unlink("sample")) for _ in range({args.iterations})];'
                     'print(json.dumps({"workload_seconds":time.monotonic()-start}))')
            with patch('traceward.runtime.Path.cwd',return_value=workspace),patch.dict(os.environ,{'CODEX_HOME':str(home),'TRACEWARD_MANAGED_RUNNER':'0'}):
                runtime=ManagedRuntime(run,str(uuid.uuid4()),['--version'],workspace=str(workspace))
            request=json.loads((run/'request.json').read_text());request['command']=['python3','-c',program]
            (run/'request.json').write_text(json.dumps(request))
            command=runtime.command
            if not enabled:
                index=command.index(runtime.image)
                setup=('from pathlib import Path;from traceward import runner;'
                       'original=runner.trace_config;'
                       'runner.trace_config=lambda *a,**k: (lambda c: (c["trace_session"].update(points=[p for p in c["trace_session"]["points"] if p["name"]!="sentry/file_delete"]),c)[1])(original(*a,**k));'
                       'raise SystemExit(runner.supervise(Path("/observer-run/request.json")))')
                command=[*command[:index+1],'-c',setup]
            began=time.monotonic()
            try:
                result=subprocess.run(command,capture_output=True,text=True,timeout=90)
                assert result.returncode==0,result.stderr
                status=json.loads((run/'runtime-status.json').read_text())
                assert status['finalized'] and not status['decode_errors'] and not status['dropped_messages']
                events=[json.loads(line) for line in (run/'raw.gvisor.jsonl').read_text().splitlines()]
                deleted=sum(e.get('message_type')==39 for e in events)
                assert deleted==(args.iterations if enabled else 0),(deleted,enabled)
                samples.append(dict(repetition=repetition,deletion_observation=enabled,
                    wall_seconds=time.monotonic()-began,**json.loads(result.stdout.strip().splitlines()[-1]),
                    source_records=len(events),source_bytes=(run/'raw.gvisor.jsonl').stat().st_size,
                    deletion_records=deleted,image_id=runtime.metadata['runner_image_id']))
            finally:runtime.cleanup()
medians={str(enabled):statistics.median(s['workload_seconds'] for s in samples if s['deletion_observation']==enabled) for enabled in (False,True)}
report=dict(kind='capture_only_microbenchmark',iterations=args.iterations,repetitions=args.repetitions,
    limits='One native ARM64 host; empty-file create/unlink loop on shared workspace. Excludes host Engine, model, hooks and dashboard. End-to-end wall samples include startup/drain; no production performance claim.',
    median_workload_seconds=medians,relative_workload_change=(medians['True']/medians['False']-1),samples=samples)
args.output.write_text(json.dumps(report,indent=2)+'\n');args.output.chmod(0o600)
print(json.dumps({k:v for k,v in report.items() if k!='samples'},indent=2))
