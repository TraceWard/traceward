"""Outer Pi-lab services; core supervision remains in traceward.runner."""
import sys
import time
import threading
import json
from pathlib import Path
from traceward.ocsf import JsonlWriter
from traceward.runner import supervise
from .transport import start_guest_gateway


def services(request, output):
    servers = []
    if request.get('inspect_https'):
        from .inspection import Inspection
        servers.append(Inspection(request, output))
    servers.append(start_guest_gateway(output))
    if request.get('fixture_receiver'):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import hashlib
        import base64
        receipts = JsonlWriter(output / 'fixture-receipts.jsonl')
        permission_events = JsonlWriter(output / 'runtime-permissions.jsonl')
        class Discard(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != '/permission' or request.get('lab_permission_decision') not in {'approved', 'denied'}:
                    self.send_error(404); return
                now = time.time()
                common = {'timestamp_seconds': now, 'scope': '127.0.0.1:8800', 'request_id': 'upload-1',
                    'subject': 'pi-lab-agent', 'policy_revision': 'fixture-1', 'approval_domain': 'application_gate',
                    'producer': 'independent_synthetic_lab_controller', 'run_id': request['run_id']}
                permission_events.append({**common, 'event_type': 'request'})
                decision = request['lab_permission_decision']
                permission_events.append({**common, 'event_type': decision, 'approver': 'lab-controller',
                    'expires_at': now + 600})
                data = json.dumps({'request_id': 'upload-1', 'decision': decision}).encode()
                self.send_response(200);self.send_header('Content-Length', str(len(data)));self.end_headers();self.wfile.write(data)
            def do_POST(self):
                length = min(max(int(self.headers.get("Content-Length", "0")), 0), 65536)
                data = self.rfile.read(length)  # synthetic fixture only, never persisted
                candidates = [data.strip()]
                try:
                    payload = json.loads(data)
                    if isinstance(payload, dict):
                        candidates.extend(v.encode() for v in payload.values() if isinstance(v, str))
                except (ValueError, TypeError):
                    pass
                for value in list(candidates):
                    try:
                        candidates.append(base64.b64decode(value, validate=True).strip())
                    except ValueError:
                        pass
                receipts.append({'time': time.time(), 'path': self.path, 'bytes': len(data),
                    'body_sha256': hashlib.sha256(data).hexdigest(),
                    'canary_received': bool(request.get('lab_canary_sha256')) and any(
                        hashlib.sha256(v).hexdigest() == request['lab_canary_sha256'] for v in candidates),
                    'source': 'independent_fixture_receiver'})
                self.send_response(204)
                self.end_headers()
            def log_message(self, *_):
                pass
        fixture_server = HTTPServer(("127.0.0.1", 8800), Discard)
        threading.Thread(target=fixture_server.serve_forever, daemon=True).start()
        servers.append(fixture_server)
    return servers


if __name__ == '__main__':
    raise SystemExit(supervise(Path(sys.argv[1]), services_factory=services))
