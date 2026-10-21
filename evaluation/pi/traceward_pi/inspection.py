"""Per-run proxy and CA, outside the observed guest and absent from host trust."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from .transport import private_json


class Inspection:
    def __init__(self, request, output):
        self.output = output
        self.directory = tempfile.TemporaryDirectory(prefix='traceward-tls-')
        conf = Path(self.directory.name)
        self.log = (output / 'inspection-proxy.log').open('w')
        os.chmod(output / 'inspection-proxy.log', 0o600)
        command = ['/opt/inspection-bin/mitmdump', '-q', '--listen-host', '127.0.0.1',
                   '--listen-port', '8802', '--set', 'confdir='+str(conf),
                   '--set', 'flow_detail=0', '--set', 'termlog_verbosity=error',
                   '--set', 'stream_large_bodies=1', '--set', 'ssl_insecure=false',
                   '-s', str(Path(__file__).with_name('inspection_addon.py'))]
        env = dict(os.environ, TRACEWARD_HTTP_EVENTS=str(output/'http-events.jsonl'))
        self.process = subprocess.Popen(command, env=env, stdout=self.log, stderr=self.log)
        cert = conf / 'mitmproxy-ca-cert.pem'
        try:
            deadline = time.monotonic()+30
            while time.monotonic() < deadline:
                if self.process.poll() is not None: raise RuntimeError('HTTPS inspection proxy failed to start')
                if cert.exists():
                    try:
                        with socket.create_connection(('127.0.0.1',8802), timeout=.2): break
                    except OSError: pass
                time.sleep(.1)
            else: raise RuntimeError('HTTPS inspection proxy startup timed out')
            root = Path(request.get('rootfs','/opt/traceward/rootfs'))
            ca = root/'usr/local/share/ca-certificates/traceward-inspection.crt'
            ca.parent.mkdir(parents=True,exist_ok=True)
            ca.write_bytes(cert.read_bytes()); ca.chmod(0o644)
            # System trust, not just curl flags. Executed before guest startup;
            # the resulting guest root is read-only during the observed run.
            subprocess.run(['chroot',str(root),'/usr/sbin/update-ca-certificates'],
                           check=True, stdout=self.log, stderr=self.log, timeout=30)
            bundle='/etc/ssl/certs/ca-certificates.crt'
            request['env'].update({'HTTP_PROXY':'http://127.0.0.1:8802','HTTPS_PROXY':'http://127.0.0.1:8802',
                'http_proxy':'http://127.0.0.1:8802','https_proxy':'http://127.0.0.1:8802',
                'NO_PROXY':'localhost,127.0.0.1,::1','no_proxy':'localhost,127.0.0.1,::1',
                'SSL_CERT_FILE':bundle,'REQUESTS_CA_BUNDLE':bundle,'CURL_CA_BUNDLE':bundle,
                'NODE_EXTRA_CA_CERTS':'/usr/local/share/ca-certificates/traceward-inspection.crt'})
            private_json(output/'inspection-status.json',{'enabled':True,'healthy':True,
                'system_trust_installed':True,'proxy':'127.0.0.1:8802','mitmproxy_version':'12.2.3',
                'coverage':'Explicit proxy clients only; direct connections, QUIC and certificate pinning are not decrypted'})
        except Exception:
            self.shutdown(); self.server_close()
            raise

    def check_health(self):
        if self.process.poll() is not None:
            private_json(self.output/'inspection-status.json',{'enabled':True,'healthy':False,
                         'reason':'inspection proxy exited during the run'})

    def shutdown(self):
        if self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()

    def server_close(self):
        self.log.close()
        self.directory.cleanup()  # CA private keys never persist in the run or guest.
