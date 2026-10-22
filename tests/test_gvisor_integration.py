"""Opt-in real managed-runtime probes; no login, model, or simulated Codex claims."""
import json
import fcntl
import os
import pty
import shutil
import subprocess
import signal
import struct
import tempfile
import time
import termios
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from traceward.gvisor import GvisorParser
from traceward.runtime import ManagedRuntime


@unittest.skipUnless(os.environ.get('TRACEWARD_TEST_DOCKER') == '1' and shutil.which('docker'), 'opt-in Docker runtime checks')
class ManagedIntegrationTests(unittest.TestCase):
    def test_live_transient_deletions_dirfd_symlinks_failures_and_directory_removal(self):
        from traceward.state import StateObserver
        (self.workspace/'target').touch()
        states=StateObserver(self.workspace);states.begin()
        command=['python3','-c', '''
import os, subprocess
from pathlib import Path
Path('empty.txt').touch(); os.unlink('empty.txt')
Path('directory').mkdir(); Path('directory/item').touch()
fd=os.open('directory',os.O_RDONLY);os.unlink('item',dir_fd=fd);os.close(fd)
os.symlink('target','link');os.unlink('link');assert Path('target').exists()
os.rmdir('directory')
try:os.unlink('missing')
except FileNotFoundError:pass
subprocess.run(['/bin/bash','-c','touch child; rm child'],check=True)
''']
        runtime=self.runtime(command)
        result=subprocess.run(runtime.command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr)
        status=json.loads((self.run/'runtime-status.json').read_text())
        self.assertTrue(status['trace_established']);self.assertTrue(status['finalized'])
        self.assertTrue(status['gvisor_patch']['patch_sha256'])
        parser=GvisorParser(str(self.workspace),status['abi'])
        deletions=[e for line in (self.run/'raw.gvisor.jsonl').read_text().splitlines()
                   if (e:=parser.parse(line)) and e['kind']=='file_delete']
        self.assertEqual(parser.unparsed,0)
        by_name={Path(e['path']).relative_to(self.workspace).as_posix():e for e in deletions}
        self.assertEqual(set(by_name),{'empty.txt','directory/item','link','directory','missing','child'})
        self.assertEqual(by_name['missing']['operation_status'],'failed')
        self.assertTrue(by_name['directory']['directory'])
        self.assertEqual(by_name['directory/item']['dirfd']>=0,True)
        self.assertTrue(all(e['operation_status']=='succeeded' for name,e in by_name.items() if name!='missing'))
        self.assertFalse(any(e.get('change') for e in states.end()))

    def test_repeated_signals_during_collector_drain_preserve_final_status(self):
        runtime=self.runtime(['python3','-c','print("guest finished")'])
        index=runtime.command.index(runtime.image)
        injection=('import time;from pathlib import Path;from traceward import runner;'
            'original=runner.Receiver.close;'
            'runner.Receiver.close=lambda self:(Path("/observer-run/draining").touch(),time.sleep(1),original(self))[-1];'
            'raise SystemExit(runner.supervise(Path("/observer-run/request.json")))')
        child=subprocess.Popen(runtime.command[:index+1]+['-c',injection],stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            deadline=time.monotonic()+15
            while not (self.run/'draining').exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.02)
            self.assertTrue((self.run/'draining').exists())
            runtime.signal(child,signal.SIGINT);runtime.signal(child,signal.SIGTERM)
            out,err=child.communicate(timeout=15)
            self.assertEqual(child.returncode,0,err)
            self.assertIn('guest finished',out)
            status=json.loads((self.run/'runtime-status.json').read_text())
            self.assertTrue(status['finalized']);self.assertTrue(status['trace_established'])
        finally:
            if child.poll() is None:child.kill();child.communicate()

    def setUp(self):
        directory=tempfile.TemporaryDirectory(prefix='traceward-runtime-test-')
        self.addCleanup(directory.cleanup)
        self.root=Path(directory.name).resolve()
        self.workspace,self.home,self.run=self.root/'workspace',self.root/'home',self.root/'run'
        for p in (self.workspace,self.home,self.run):p.mkdir(mode=0o700)
        (self.home/'auth.json').write_text('{}')
        (self.run/'hooks.jsonl').touch(mode=0o600)

    def runtime(self, command, tty=False, guest_image=None):
        with patch('traceward.runtime.Path.cwd',return_value=self.workspace), \
             patch.dict(os.environ,{'CODEX_HOME':str(self.home),'TRACEWARD_MANAGED_RUNNER':'0'}):
            runtime=ManagedRuntime(self.run,str(uuid.uuid4()),['--version'],
                      image=os.environ.get('TRACEWARD_INTEGRATION_IMAGE'),workspace=str(self.workspace),guest_image=guest_image)
        request=json.loads((self.run/'request.json').read_text())
        request['command']=command
        (self.run/'request.json').write_text(json.dumps(request))
        if tty and '-t' not in runtime.command:
            runtime.command.insert(runtime.command.index('-i')+1,'-t')
        self.addCleanup(runtime.cleanup)
        return runtime

    def test_live_read_write_and_nested_processes_without_payload(self):
        (self.workspace/'fixture.py').write_text('from pathlib import Path\np=Path("synthetic-credential.txt")\np.write_text("SYNTHETIC_ONLY")\nprint(p.read_text())\n')
        command=['/bin/bash','-c','python3 fixture.py; result=$?; exit "$result"']
        runtime=self.runtime(command)
        result=subprocess.run(runtime.command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr)
        status=json.loads((self.run/'runtime-status.json').read_text())
        self.assertEqual(status['dropped_messages'],0)
        self.assertEqual(status['decode_errors'],0)
        parser=GvisorParser(str(self.workspace),status['abi'])
        effects=[e for line in (self.run/'raw.gvisor.jsonl').read_text().splitlines() if (e:=parser.parse(line))]
        self.assertEqual(parser.unparsed,0)
        self.assertTrue(any(e['kind']=='file_read' and e['path'].endswith('/synthetic-credential.txt') and e['bytes']>0 for e in effects))
        self.assertTrue(any(e['kind']=='file_write' and e['bytes']>0 for e in effects))
        self.assertTrue(any(e['kind']=='fork' for e in effects))
        self.assertNotIn('SYNTHETIC_ONLY',(self.run/'raw.gvisor.jsonl').read_text())

    def test_writable_home_preserves_atomic_credential_refresh_without_real_secrets(self):
        runtime=self.runtime(['/usr/local/bin/python3','-c',
            'from pathlib import Path;p=Path("/codex-home/auth.refresh");p.write_text("SYNTHETIC_REFRESH");p.replace("/codex-home/auth.json")'])
        result=subprocess.run(runtime.command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.home/'auth.json').read_text(),'SYNTHETIC_REFRESH')
        self.assertNotIn('SYNTHETIC_REFRESH',(self.run/'raw.gvisor.jsonl').read_text())

    def test_custom_guest_image(self):
        image='traceward-test-guest:local'
        built=subprocess.run(['docker','build','--target','guest','-t',image,'-f',
            'src/traceward/runner_image/Dockerfile','.'],capture_output=True,text=True,timeout=180)
        self.assertEqual(built.returncode,0,built.stderr)
        runtime=self.runtime(['/usr/local/bin/python3','-c','import sqlite3;open("custom-ok","w").write(sqlite3.sqlite_version)'],guest_image=image)
        result=subprocess.run(runtime.command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.workspace/'custom-ok').is_file())
        self.assertIn('guest_image_id',runtime.metadata)

    def test_collection_failure_does_not_terminate_guest(self):
        runtime=self.runtime(['python3','-c','import time;time.sleep(2);open("continued","w").write("ok")'])
        image_index=runtime.command.index(runtime.image)
        injection = ('import threading;from pathlib import Path;from traceward import runner;'
            'original=runner.Receiver.receive;'
            'runner.Receiver.receive=lambda self,conn:(threading.Timer(0.7,conn.close).start(),original(self,conn));'
            'raise SystemExit(runner.supervise(Path("/observer-run/request.json")))')
        command=runtime.command[:image_index+1]+['-c',injection]
        result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.workspace/'continued').exists())
        status=json.loads((self.run/'runtime-status.json').read_text())
        self.assertGreater(status['decode_errors'],0)
        self.assertTrue(any(r.get('message','').startswith('SecCheck connection failed') for r in map(json.loads,(self.run/'raw.gvisor.jsonl').read_text().splitlines())))

    def test_required_session_failure_never_starts_task(self):
        runtime=self.runtime(['python3','-c','open("must-not-run","w").write("bad")'])
        image_index=runtime.command.index(runtime.image)
        injection=('from pathlib import Path;from traceward import runner;'
            'original=runner.trace_config;'
            'runner.trace_config=lambda endpoint,abi:{"trace_session":{**original(endpoint,abi)["trace_session"],"points":[{"name":"unsupported-required-point"}]}};'
            'raise SystemExit(runner.supervise(Path("/observer-run/request.json")))')
        result=subprocess.run(runtime.command[:image_index+1]+['-c',injection],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.workspace/'must-not-run').exists())
        self.assertTrue(any('agent task was not started' in r.get('message','') for r in map(json.loads,(self.run/'raw.gvisor.jsonl').read_text().splitlines())))

    def test_persistence_failure_marks_status_and_guest_continues(self):
        runtime=self.runtime(['python3','-c','import time;from pathlib import Path;\n'
            'for _ in range(30):\n Path("progress").write_text("ok");time.sleep(.1)\n'
            'Path("continued").touch()'])
        image_index=runtime.command.index(runtime.image)
        injection=('import threading;from pathlib import Path;from traceward import runner;'
            'original=runner.decode_packet;failed=threading.Event();'
            'threading.Timer(.7,failed.set).start();'
            'runner.decode_packet=lambda *args:(_ for _ in ()).throw(OSError("synthetic disk failure")) if failed.is_set() else original(*args);'
            'raise SystemExit(runner.supervise(Path("/observer-run/request.json")))')
        result=subprocess.run(runtime.command[:image_index+1]+['-c',injection],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.workspace/'continued').exists())
        status=json.loads((self.run/'runtime-status.json').read_text())
        self.assertTrue(status['collector_failed'])
        self.assertGreater(status['decode_errors'],0)

    def test_status_persistence_failure_preserves_guest_exit(self):
        runtime=self.runtime(['/bin/bash','-c','sleep 1.2; touch continued; exit 7'])
        image_index=runtime.command.index(runtime.image)
        injection=('from pathlib import Path;from traceward import runner;'
            'runner.write_status=lambda *args,**kwargs:(_ for _ in ()).throw(OSError("synthetic status disk failure"));'
            'raise SystemExit(runner.supervise(Path("/observer-run/request.json")))')
        result=subprocess.run(runtime.command[:image_index+1]+['-c',injection],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,7,result.stderr)
        self.assertTrue((self.workspace/'continued').exists())
        self.assertFalse((self.run/'runtime-status.json').exists())
        records=list(map(json.loads,(self.run/'raw.gvisor.jsonl').read_text().splitlines()))
        self.assertEqual(sum('status persistence failed' in r.get('message','') for r in records),1)

    def test_exit_code(self):
        runtime=self.runtime(['/bin/bash','-c','exit 7'])
        result=subprocess.run(runtime.command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,7,result.stderr)

    def test_terminal_and_window_size(self):
        runtime=self.runtime(['/usr/local/bin/python3','-c',
            'import json,os,sys,time;from pathlib import Path;'
            'initial=list(os.get_terminal_size());Path("ready").touch();'
            '\nfor _ in range(100):\n'
            ' if list(os.get_terminal_size())!=initial:break\n'
            ' time.sleep(.1)\n'
            'Path("tty.json").write_text(json.dumps({"tty":[sys.stdin.isatty(),sys.stdout.isatty(),sys.stderr.isatty()],'
            '"initial":initial,"resized":list(os.get_terminal_size())}))'],tty=True)
        master,slave=pty.openpty()
        self.addCleanup(os.close,master)
        with os.fdopen(slave,'rb+',buffering=0) as terminal:
            fcntl.ioctl(terminal,termios.TIOCSWINSZ,struct.pack('HHHH',33,100,0,0))
            process=subprocess.Popen(runtime.command,stdin=terminal,stdout=terminal,stderr=terminal)
            self.addCleanup(lambda: process.poll() is None and process.kill())
            deadline=time.monotonic()+20
            while not (self.workspace/'ready').exists() and time.monotonic()<deadline:time.sleep(.05)
            self.assertTrue((self.workspace/'ready').exists())
            fcntl.ioctl(terminal,termios.TIOCSWINSZ,struct.pack('HHHH',50,132,0,0))
            process.send_signal(signal.SIGWINCH)
            self.assertEqual(process.wait(timeout=45),0)
        observed=json.loads((self.workspace/'tty.json').read_text())
        self.assertEqual(observed,{'tty':[True,True,True],'initial':[100,33],'resized':[132,50]})

    def test_git_worktree_metadata_is_available_at_original_path(self):
        main=self.root/'main'
        main.mkdir()
        commands=[['init'],['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                         'commit','--allow-empty','-m','fixture'],
                  ['worktree','add','-b','fixture',str(self.workspace)]]
        for args in commands:
            result=subprocess.run(['git','-C',str(main),*args],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
        runtime=self.runtime(['/bin/sh','-c','git status --porcelain; git rev-parse --show-toplevel > worktree-path'])
        result=subprocess.run(runtime.command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.workspace/'worktree-path').read_text().strip(),str(self.workspace))

    def test_operator_sigterm_reaches_guest(self):
        runtime=self.runtime(['/usr/local/bin/python3','-c',
            'import signal,time;from pathlib import Path;\n'
            'def stop(*_):\n Path("terminated").write_text("yes"); raise SystemExit(0)\n'
            'signal.signal(signal.SIGTERM,stop);Path("ready").touch();time.sleep(30)'])
        process=subprocess.Popen(runtime.command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline=time.monotonic()+20
        while not (self.workspace/'ready').exists() and time.monotonic()<deadline:time.sleep(.05)
        self.assertTrue((self.workspace/'ready').exists())
        runtime.signal(process,15)
        self.assertEqual(process.wait(timeout=15),0)
        self.assertEqual((self.workspace/'terminated').read_text(),'yes')
