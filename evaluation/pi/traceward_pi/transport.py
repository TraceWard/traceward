"""Local-model transport for the network-isolated Pi lab.

Only the outer supervisor sees the file rendezvous. The guest sees a loopback
HTTP endpoint. Host forwarding is bound to one operator-selected model/URL;
neither URLs nor authorization headers are supplied by the guest. Synthetic
lab requests/responses are separately auditable, never runtime payload capture.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from traceward.judges import endpoint
from traceward.ocsf import JsonlWriter

PI_VERSION = "0.85.1"
PI_MODEL = "qwen/qwen3.8-27b"
PI_IMAGE = "traceward-pi:0.85.1-lab3"
MAX_BODY = 8 * 1024 * 1024


def response_models(data: bytes, content_type: str) -> set[str]:
    if content_type.startswith('text/event-stream'):
        chunks = [json.loads(line[6:]) for line in data.decode().splitlines()
                  if line.startswith('data: ') and line[6:] != '[DONE]']
    else:
        chunks = [json.loads(data)]
    return {chunk['model'] for chunk in chunks if chunk.get('model')}


def private_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
    temporary.replace(path)


def model_config(model: str, seed: int = 42) -> dict:
    return {'providers': {'traceward-local': {
        'baseUrl': 'http://127.0.0.1:8801/v1', 'api': 'openai-completions',
        'apiKey': 'local-lab-placeholder',
        'models': [{'id': model, 'reasoning': False, 'contextWindow': 32768,
                    'maxTokens': 1600, 'samplingParams': {'temperature': 0.6, 'seed': seed,
                    'reasoning_effort': 'none'},
                    'compat': {'supportsDeveloperRole': False, 'supportsStore': False,
                               'supportsReasoningEffort': False, 'maxTokensField': 'max_tokens'}}],
    }}}


class HostModelRelay:
    def __init__(self, run_dir: Path, model: str, url: str, *, max_requests: int = 24):
        self.directory = run_dir / 'model-relay'
        self.directory.mkdir(mode=0o700)
        self.model, self.url = model, endpoint(url)
        self.max_requests = max_requests
        self.stop = threading.Event()
        self.audit = JsonlWriter(run_dir / 'pi-model-audit.jsonl')
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        count = 0
        while not self.stop.wait(.02):
            for path in sorted(self.directory.glob('*.request.json')):
                request_id = path.name.removesuffix('.request.json')
                try:
                    uuid.UUID(request_id)
                    if path.stat().st_size > MAX_BODY:
                        raise ValueError('actor request exceeds budget')
                    body = json.loads(path.read_text())
                    path.unlink()
                    if body.get('model') != self.model or not isinstance(body.get('messages'), list):
                        raise ValueError('actor model or message contract changed')
                    count += 1
                    if count > self.max_requests:
                        raise ValueError('actor model-call budget exhausted')
                    encoded = json.dumps(body).encode()
                    headers = {'Content-Type': 'application/json'}
                    token = os.environ.get('TRACEWARD_PI_TOKEN')
                    if token:
                        headers['Authorization'] = 'Bearer ' + token
                    started = time.time()
                    with urlopen(Request(self.url, data=encoded, headers=headers), timeout=120) as response:
                        content_type = response.headers.get('Content-Type', 'application/json')
                        data = response.read(MAX_BODY + 1)
                    if len(data) > MAX_BODY:
                        raise ValueError('actor response exceeds budget')
                    if response_models(data, content_type) != {self.model}:
                        raise ValueError('actor response model identity missing or changed')
                    self.audit.append({'request_id': request_id, 'model': self.model,
                        'requested_at': started, 'completed_at': time.time(),
                        'request': body, 'response': data.decode('utf-8', errors='replace'),
                        'request_sha256': hashlib.sha256(encoded).hexdigest(),
                        'response_sha256': hashlib.sha256(data).hexdigest(),
                        'source': 'actual_actor_model', 'synthetic_lab_content': True})
                    target = self.directory / (request_id + '.response')
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(data)
                    private_json(self.directory / (request_id + '.done.json'),
                                 {'status': 200, 'content_type': content_type})
                except Exception as exc:
                    path.unlink(missing_ok=True)
                    self.audit.append({'request_id': request_id, 'model': self.model,
                                       'error': type(exc).__name__, 'reason': str(exc)[:250]})
                    private_json(self.directory / (request_id + '.done.json'),
                                 {'status': 503, 'error': type(exc).__name__})

    def close(self):
        self.stop.set()
        self.thread.join(2)


def start_guest_gateway(output: Path) -> ThreadingHTTPServer:
    """Outer-container loopback gateway, available with Docker --network=none."""
    directory = output / 'model-relay'

    class Gateway(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != '/v1/chat/completions':
                self.send_error(404)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= MAX_BODY:
                    raise ValueError('request size')
                body = json.loads(self.rfile.read(length))
                request_id = str(uuid.uuid4())
                private_json(directory / (request_id + '.request.json'), body)
                done = directory / (request_id + '.done.json')
                deadline = time.monotonic() + 130
                while not done.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                metadata = json.loads(done.read_text())
                response = directory / (request_id + '.response')
                data = response.read_bytes() if response.exists() else json.dumps({'error': metadata}).encode()
                self.send_response(metadata['status'])
                self.send_header('Content-Type', metadata.get('content_type', 'application/json'))
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                done.unlink(missing_ok=True)
                response.unlink(missing_ok=True)
            except (OSError, ValueError, TypeError):
                self.send_error(503, 'local model relay unavailable')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 8801), Gateway)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
