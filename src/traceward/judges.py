"""Observer-side judge selection, structured inference and source provenance."""
import hashlib
import json
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from . import openrouter
from .evidence_packet import model_input
from .privacy import redact
from .structured import request_payload, strict_object, validate_response, factual_predicates, RUBRIC_VERSION

DEFAULT_MODEL = 'qwen/qwen3.8-27b'
DEFAULT_URL = 'http://127.0.0.1:1234/v1/chat/completions'
OPENROUTER_URL = openrouter.CHAT_URL
JUDGE_PROVIDERS = {'lmstudio', 'openrouter'}
MAX_RESPONSE_BYTES = 256 * 1024


def sanitized(value, secrets=()):
    if isinstance(value, str):
        for secret in secrets:
            if secret: value = value.replace(secret, "[REDACTED]")
        return redact(value, 1000000)
    if isinstance(value, dict):
        return {k: sanitized(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitized(v, secrets) for v in value]
    return value


def endpoint(value):
    parsed = urlsplit(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('judge URL must be HTTP(S) without embedded credentials, query or fragment')
    path = parsed.path.rstrip('/')
    if path.endswith('/api/v1'):
        path = path[:-7] + '/v1/chat/completions'
    elif path in {'', '/v1'}:
        path = '/v1/chat/completions'
    elif not path.endswith('/v1/chat/completions'):
        raise ValueError('judge URL must name the chat-completions endpoint or server base')
    return urlunsplit((parsed.scheme, parsed.netloc, path, '', ''))


def generative_judge(packet, *, url=None, model=None, provider=None, timeout=60):
    selected_provider = provider or os.environ.get('TRACEWARD_JUDGE_PROVIDER', 'lmstudio')
    if selected_provider not in JUDGE_PROVIDERS:
        return {'status':'unavailable','reason':'unsupported_judge_provider'}
    selected_model = model or os.environ.get('TRACEWARD_JUDGE_MODEL')
    if selected_provider == 'openrouter':
        selected_url = OPENROUTER_URL
        token = os.environ.get('OPENROUTER_KEY', '').strip()
        if not selected_model or not selected_model.strip():
            return {'status':'unavailable','reason':'missing_judge_model','provider':selected_provider,'endpoint':selected_url}
        if not token:
            return {'status':'unavailable','reason':'missing_openrouter_key','provider':selected_provider,
                    'endpoint':selected_url,'requested_model':selected_model,'model':selected_model}
    else:
        selected_model = selected_model or DEFAULT_MODEL
        selected_url = endpoint(url or os.environ.get('TRACEWARD_JUDGE_URL', DEFAULT_URL))
        # Keep the former observer token as an LM Studio compatibility alias.
        token = os.environ.get('LMSTUDIO_API_KEY') or os.environ.get('TRACEWARD_JUDGE_TOKEN')
    realtime = packet.get('assessment_contract') == 'goal-effects-live-v2'
    live = bool(packet.get('live_window')) and not realtime
    enriched = packet.get('packet_version', 2) >= 3 and not live
    rendered = model_input(packet, max_state_bytes=12288 if enriched else 8192)
    visible_aliases = {a:eid for a,eid in rendered.get('evidence_aliases',{}).items()
                       if eid in rendered.get('represented_evidence_ids',[])}
    facts = factual_predicates(packet.get('evidence',[]),visible_aliases,packet.get('consequential_evidence_ids',[])) if enriched else None
    body = request_payload(rendered.get('state', ''), selected_model, enriched=enriched, facts=facts,evidence_aliases=visible_aliases, live=live, realtime=realtime)
    if selected_provider == 'openrouter': body = openrouter.adapt_request(body)
    encoded = json.dumps(body).encode()
    started = time.monotonic()
    provenance = {'provider': selected_provider, 'contract_version': 'goal-effects-live-v2' if realtime else 'goal-effects-live-v1' if live else 'goal-effects-v4' if enriched else 'goal-effects-v3',
        'endpoint': selected_url, 'requested_model': selected_model, 'model': selected_model, 'rubric_version': RUBRIC_VERSION,
        'request_sha256': hashlib.sha256(encoded).hexdigest(), 'request': body,
        'model_input': rendered, 'question_contract': body['response_format'],
        'evaluation_source': 'simulated' if 'demo' in selected_model.lower() else 'remote_model', 'semantic_accuracy_validated': False}
    def unavailable(reason, **extra):
        return {'status': 'unavailable', 'reason': reason, **provenance,
                'latency_seconds': round(time.monotonic()-started, 3), **extra}
    if rendered['status'] != 'ready':
        return unavailable('required_evidence_exceeds_input_budget' if rendered['status'] != 'missing_evidence' else 'missing_consequential_evidence')
    if enriched and len(body['messages'][1]['content'].encode()) > 14336:
        return unavailable('verified_predicates_exceed_input_budget')
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        with urlopen(Request(selected_url, data=encoded, headers=headers, method='POST'), timeout=timeout) as stream:
            raw = stream.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return unavailable('response_exceeds_budget')
            result = json.loads(raw, object_pairs_hook=strict_object,
                                parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
        return unavailable(type(exc).__name__, http_status=exc.code if isinstance(exc, HTTPError) else None)
    # Retain the exact redacted wire response, including rejected answers. Never
    # persist request headers or provider error bodies that may echo credentials.
    result = sanitized(result, (token,) if token else ())
    provenance['response'] = result
    if isinstance(result, dict) and result.get('error'):
        error = result['error']
        return unavailable('provider_error', error_code=error.get('code') if isinstance(error, dict) else None)
    try:
        identity_matches = (openrouter.model_matches(selected_model, result['model'])
                            if selected_provider == 'openrouter' else result['model'] == selected_model)
        if not identity_matches:
            return unavailable('returned_model_mismatch', returned_model=redact(str(result.get('model')), 128))
        answer = validate_response(result, visible_aliases, enriched=enriched, evidence=packet.get('evidence', []),facts=facts, live=live)
        required = set(packet.get('consequential_evidence_ids', []))
        cited = [visible_aliases[a] for a in answer['evidence_ids']]
        if required and not required.intersection(cited):
            return unavailable('no_consequential_evidence_cited')
        if enriched:
            claims = [visible_aliases[a] for fid in answer['claims'] for a in facts[fid]['evidence_ids']]
            if not required.intersection(claims): return unavailable('no_typed_claim_cites_consequential_evidence')
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return unavailable('invalid_structured_answer', validation_error=redact(str(exc), 256))
    return {'status': 'assessed', **provenance, 'returned_model': result['model'],
        'answer': sanitized(answer),
        **({'title': redact(answer['title'],160)} if live else {}),
        **({'title': redact(answer['title'], 160), 'assessment': {name: {**sanitized(facet),
            'evidence_ids': [visible_aliases[a] for a in facet['evidence_ids']]}
            for name, facet in answer['assessment'].items()},
            'claims': [{'fact_type': facts[fid]['fact_type'], 'evidence_ids': [visible_aliases[a] for a in facts[fid]['evidence_ids']]}
                       for fid in answer['claims']], 'factual_predicates': facts} if enriched else {}),
        'disposition': answer['disposition'], 'rationale': redact(answer['rationale'], 8000),
        'cited_evidence_ids': cited, 'omitted_context_ids': rendered.get('omitted_context_ids', []),
        'uncalibrated_risk_score': None, 'latency_seconds': round(time.monotonic()-started, 3),
        'usage': result.get('usage', {})}


def judge(packet, *, url=None, model=None, provider=None, timeout=60):
    return generative_judge(packet, url=url, model=model, provider=provider, timeout=timeout)
