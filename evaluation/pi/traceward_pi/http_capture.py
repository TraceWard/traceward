"""Bounded, redacted HTTP evidence from the observer-side inspection proxy."""
import hashlib
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from traceward.ocsf import JsonlWriter
from traceward.state import content_redact

SENSITIVE = re.compile(r'authorization|cookie|password|secret|token|credential|api[-_]?key', re.I)
LIMIT = 4096


def safe_url(url):
    parts = urlsplit(url)
    host = parts.hostname or ''
    if ':' in host: host = '[' + host + ']'
    if parts.port: host += ':' + str(parts.port)
    query = urlencode([(k, '[REDACTED]' if SENSITIVE.search(k) else content_redact(v, 256))
                       for k, v in parse_qsl(parts.query, keep_blank_values=True)])
    return content_redact(urlunsplit((parts.scheme, host, parts.path, query, '')), 2048)


def safe_headers(headers):
    return {str(k)[:128]: '[REDACTED]' if SENSITIVE.search(str(k)) else content_redact(str(v), 512)
            for k, v in list(headers.items())[:40]}


class Capture:
    """Mitmproxy addon; streams bodies unchanged, retaining only a bounded prefix."""
    def __init__(self, output):
        self.writer = JsonlWriter(output)

    def _stream(self, flow, name):
        state = {'hash': hashlib.sha256(), 'size': 0, 'prefix': bytearray()}
        flow.metadata[name] = state
        def stream(chunk):
            state['hash'].update(chunk)
            state['size'] += len(chunk)
            state['prefix'].extend(chunk[:max(0, LIMIT - len(state['prefix']))])
            return chunk
        return stream

    def requestheaders(self, flow):
        flow.request.stream = self._stream(flow, 'request_capture')

    def responseheaders(self, flow):
        flow.response.stream = self._stream(flow, 'response_capture')

    def _body(self, flow, name, message):
        state = flow.metadata.get(name)
        if state is None:
            data = message.raw_content or b''
            state = {'size': len(data), 'prefix': data[:LIMIT], 'hash': hashlib.sha256(data)}
        content_type = message.headers.get('content-type', '')
        encoding = message.headers.get('content-encoding', '').lower()
        textual = any(t in content_type.lower() for t in ('text/', 'json', 'xml', 'form-urlencoded'))
        raw = bytes(state['prefix'])
        excerpt = content_redact(raw.decode('utf-8', errors='replace'), LIMIT) if textual and encoding in ('', 'identity') else None
        if excerpt is not None and 'form-urlencoded' in content_type.lower():
            excerpt = urlencode([(k, '[REDACTED]' if SENSITIVE.search(k) else content_redact(v, 256))
                                 for k, v in parse_qsl(raw.decode('utf-8', errors='replace'))])
        return {'bytes': state['size'], 'sha256': state['hash'].hexdigest(),
                'excerpt': excerpt, 'truncated': state['size'] > LIMIT,
                'content_type': content_type[:256], 'content_encoding': encoding or None,
                'excerpt_omitted_reason': 'encoded_body' if encoding not in ('', 'identity') else 'non_text_body' if not textual else None}

    def _event(self, flow, phase):
        request = flow.request
        return {'kind': 'http_request', 'source': 'tls_inspection_proxy',
                'trust': 'independent_proxy_observation', 'time': time.time(),
                'request_id': flow.id, 'phase': phase, 'method': request.method,
                'url': safe_url(request.pretty_url), 'endpoint': f'{request.host}:{request.port}',
                'scheme': request.scheme, 'http_version': request.http_version,
                'client_address': list(flow.client_conn.peername or ()),
                'headers': safe_headers(request.headers),
                'operation_status': 'observed_at_proxy'}

    def request(self, flow):
        event = self._event(flow, 'request')
        event['request_body'] = self._body(flow, 'request_capture', flow.request)
        self.writer.append(event)

    def response(self, flow):
        event = self._event(flow, 'response')
        event.update({'status_code': flow.response.status_code,
                      'response_headers': safe_headers(flow.response.headers),
                      'response_body': self._body(flow, 'response_capture', flow.response)})
        self.writer.append(event)

    def error(self, flow):
        event = self._event(flow, 'error')
        event.update({'operation_status': 'failed', 'error': content_redact(str(flow.error), 512)})
        self.writer.append(event)
