"""Opt-in real gVisor/TLS probe with an independent loopback HTTPS receiver."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch
from traceward_pi.runtime import PiRuntime
from traceward_pi.transport import private_json


SUPERVISOR = r'''
import json,ssl,subprocess,sys,tempfile,threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
from unittest.mock import patch
from traceward.runner import supervise
from traceward_pi.runner import services

temporary=tempfile.TemporaryDirectory(prefix='tls-fixture-')
root=Path(temporary.name);cert=root/'fixture.pem';key=root/'fixture.key'
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
 '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],
 check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
received=[]
class Receiver(BaseHTTPRequestHandler):
 def do_POST(self):
  received.append(self.rfile.read(int(self.headers['Content-Length'])))
  self.reply()
 def do_GET(self):self.reply()
 def reply(self):
  data=b'{"ok":true,"token":"synthetic-response-secret"}'
  self.send_response(200);self.send_header('Content-Type','application/json')
  self.send_header('Set-Cookie','synthetic-cookie-secret');self.send_header('Content-Length',str(len(data)))
  self.end_headers();self.wfile.write(data)
 def log_message(self,*_):pass
server=HTTPServer(('127.0.0.1',9443),Receiver)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
server.socket=context.wrap_socket(server.socket,server_side=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
original=subprocess.Popen
def launch(command,*args,**kwargs):
 if command[0]=='/opt/inspection-bin/mitmdump':
  command=[*command,'--set','ssl_verify_upstream_trusted_ca='+str(cert)]
 return original(command,*args,**kwargs)
try:
 with patch('traceward_pi.inspection.subprocess.Popen',side_effect=launch):
  result=supervise(Path(sys.argv[1]),services_factory=services)
 assert received==[b'{"message":"synthetic-body","password":"synthetic-request-secret"}'],received
 print('INDEPENDENT_RECEIVER_VERIFIED')
 raise SystemExit(result)
finally:
 server.shutdown();server.server_close();temporary.cleanup()
'''

GUEST = r'''
import os,subprocess,urllib.request
from pathlib import Path
assert Path('/etc/ssl/certs/ca-certificates.crt').is_file()
assert Path('/usr/local/share/ca-certificates/traceward-inspection.crt').is_file()
assert not Path('/observer-run').exists()
os.environ['NO_PROXY']='';os.environ['no_proxy']=''
body='{"message":"synthetic-body","password":"synthetic-request-secret"}'
result=subprocess.run(['curl','--fail','--silent','--show-error','--max-time','15',
 '-H','Content-Type: application/json','-H','Authorization: Bearer synthetic-header-secret',
 '--data',body,'https://127.0.0.1:9443/upload?token=synthetic-query-secret'],capture_output=True,text=True)
assert result.returncode==0,result.stderr
assert '"ok":true' in result.stdout
assert urllib.request.urlopen('https://127.0.0.1:9443/python',timeout=10).status==200
node=r"""
const http=require('http'),tls=require('tls');
const r=http.request({host:'127.0.0.1',port:8802,method:'CONNECT',path:'localhost:9443'});
r.on('connect',(res,socket)=>{
 const s=tls.connect({socket,servername:'localhost'},()=>s.write('GET /node HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'));
 let output='';s.on('data',b=>output+=b);s.on('error',e=>{console.error(e);process.exit(1)});
 s.on('end',()=>{if(!output.startsWith('HTTP/1.1 200')&&!output.startsWith('HTTP/1.0 200'))process.exit(2)});
});r.on('error',()=>process.exit(3));r.end();
"""
subprocess.run(['node','-e',node],check=True,timeout=15)
print('CURL_PYTHON_NODE_TRUST_VERIFIED')
'''


@unittest.skipUnless(os.environ.get('TRACEWARD_TEST_INSPECTION')=='1' and shutil.which('docker'),
                     'opt-in TLS inspection integration probe')
class InspectionRuntimeTests(unittest.TestCase):
    def test_system_trust_streamed_https_bodies_and_hidden_ca_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();workspace=root/'workspace';run=root/'run'
            workspace.mkdir();run.mkdir();(run/'hooks.jsonl').touch(mode=0o600)
            with patch('traceward.runtime.Path.cwd',return_value=workspace), \
                 patch.dict(os.environ,{'TRACEWARD_MANAGED_RUNNER':'0'}):
                runtime=PiRuntime(run,str(uuid.uuid4()),[],guest_image='traceward-pi-dev:local',
                                  pi_network='bridge',pi_inspect_https=True)
            self.addCleanup(runtime.cleanup)
            request=json.loads((run/'request.json').read_text())
            request['command']=['/usr/local/bin/python3','-c',GUEST]
            private_json(run/'request.json',request)
            command=[*runtime.command[:-3],'-c',SUPERVISOR,'/observer-run/request.json']
            result=subprocess.run(command,capture_output=True,text=True,timeout=90)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            self.assertIn('INDEPENDENT_RECEIVER_VERIFIED',result.stdout)
            self.assertIn('CURL_PYTHON_NODE_TRUST_VERIFIED',result.stdout)
            text=(run/'http-events.jsonl').read_text()
            for secret in ['synthetic-request-secret','synthetic-response-secret','synthetic-query-secret',
                           'synthetic-header-secret','synthetic-cookie-secret']:
                self.assertNotIn(secret,text)
            events=[json.loads(line) for line in text.splitlines()]
            post=next(e for e in events if e['method']=='POST' and e['phase']=='request')
            self.assertIn('synthetic-body',post['request_body']['excerpt'])
            self.assertTrue(any(e.get('status_code')==200 for e in events))
            self.assertFalse(list(run.glob('**/*ca*.pem')))
