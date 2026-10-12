"""Opt-in semantic excerpts. Session roles are claims, not operator authority."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path

from .state import content_redact

MAX_SESSION_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_EVENTS = 64


def text_content(value) -> str:
    if isinstance(value, str): return value
    if isinstance(value, list):
        return '\n'.join(text_content(part) for part in value if isinstance(part, (str, dict)))
    if isinstance(value, dict):
        return text_content(value.get('text', value.get('output', value.get('content', ''))))
    return ''


def excerpt_event(text: str, *, role: str, source: str, timestamp: float, tool_id=None,
                  reference=None, source_hash=None) -> dict:
    raw = text.encode('utf-8')
    return {'kind': 'agent_claim' if role == 'assistant' else 'context', 'source': source,
            'time': timestamp, 'trust': 'agent_claim' if role == 'assistant' else 'lower_trust_content',
            'role': role, 'tool_use_id': tool_id, 'source_reference': reference,
            'content_sha256': source_hash or hashlib.sha256(raw).hexdigest(),
            'excerpt': content_redact(text), 'excerpt_truncated': len(text) > 2048}


def hook_context(hook: dict, mode: str) -> list[dict]:
    if mode != 'redacted': return []
    role = 'assistant' if hook.get('event') == 'AgentMessage' else 'tool_result'
    text = hook.get('assistant_excerpt') if role == 'assistant' else hook.get('response_excerpt')
    if not isinstance(text, str) or not text: return []
    return [excerpt_event(text, role=role, source=str(hook.get('source', 'agent_hook')),
        timestamp=hook.get('time', time.time()), tool_id=hook.get('tool_use_id'),
        reference=hook.get('response_source', hook.get('tool_use_id')),
        source_hash=hook.get('response_sha256'))]


def codex_session(path: Path, *, expected_session_id: str | None = None) -> tuple[list[dict], list[str]]:
    """Supported rollout JSONL message/function-output formats, bounded and fail-closed."""
    records, gaps = [], []
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SESSION_BYTES:
            return [], ['Codex session is non-regular or exceeds the context budget']
        raw = os.read(fd, MAX_SESSION_BYTES + 1)
    finally: os.close(fd)
    lines = raw.decode('utf-8', errors='replace').splitlines()
    header = {}
    for line in lines[:4]:
        try:
            entry = json.loads(line)
            if entry.get('type') == 'session_meta': header = entry.get('payload', {}); break
        except (ValueError, TypeError): pass
    if expected_session_id and header.get('id') != expected_session_id:
        return [], ['Codex session identity mismatch; semantic excerpts not imported']
    for number, line in enumerate(lines, 1):
        if len(records) >= MAX_CONTEXT_EVENTS:
            gaps.append('Codex session excerpt count budget reached'); break
        try:
            entry = json.loads(line); payload = entry.get('payload', {})
            role, text, call_id = None, '', payload.get('call_id')
            if entry.get('type') == 'response_item':
                if payload.get('type') in {'function_call_output', 'custom_tool_call_output'}:
                    role, text = 'tool_result', text_content(payload.get('output'))
                elif payload.get('type') == 'message':
                    role, text = payload.get('role'), text_content(payload.get('content'))
            elif entry.get('type') == 'event_msg' and payload.get('type') == 'agent_message':
                role, text = 'assistant', payload.get('message', '')
            if role not in {'assistant', 'user', 'tool_result'} or not text: continue
            from datetime import datetime
            timestamp = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00')).timestamp()
            records.append(excerpt_event(text, role=role, source='codex_session', timestamp=timestamp,
                tool_id=call_id, reference=f'{path.name}:{number}',
                source_hash=hashlib.sha256(line.encode()).hexdigest()))
        except (ValueError, TypeError, KeyError):
            gaps.append(f'unsupported/malformed Codex session record at line {number}')
    return records, list(dict.fromkeys(gaps))


def permissions(path: Path, *, workspace: Path, run_id: str) -> tuple[list[dict], list[str]]:
    """Read an operator-selected external runtime audit, never an agent workspace claim.

    Supports normalized OpenShell governance fields and OCSF denied-network
    records. This imports evidence; it never grants or reverses a permission.
    """
    if path.resolve().is_relative_to(workspace.resolve()):
        raise ValueError('permission evidence must be outside the agent workspace')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_SESSION_BYTES:
            raise ValueError('permission evidence is non-regular or oversized')
        raw = os.read(fd, MAX_SESSION_BYTES + 1)
    finally: os.close(fd)
    result, gaps = [], []
    actions = {'request', 'denied', 'proposal', 'approved', 'rejected', 'revoked', 'retry'}
    aliases = {'denial_detected': 'denied', 'policy_proposed': 'proposal'}
    for number, line in enumerate(raw.decode('utf-8').splitlines(), 1):
        if len(result) >= MAX_CONTEXT_EVENTS:
            gaps.append('permission evidence budget reached'); break
        try:
            d = json.loads(line)
            if d.get('run_id') not in {None, run_id}: continue
            action = aliases.get(d.get('event_type'), d.get('event_type'))
            if d.get('class_uid') == 4001 and d.get('status_id') == 2 and (d.get('action_id') == 2 or d.get('disposition_id') == 2):
                action = 'denied'
                ep = d.get('dst_endpoint', {})
                d['scope'] = f'{ep.get("domain", ep.get("ip", "unknown"))}:{ep.get("port", "?")}'
                d['timestamp_seconds'] = d.get('time', 0) / 1000
            if 'timestamp_seconds' not in d and d.get('event_time'):
                from datetime import datetime
                et = d['event_time']
                d['timestamp_seconds'] = (float(et['seconds']) + float(et.get('nanos', 0))/1e9
                    if isinstance(et, dict) else datetime.fromisoformat(et.replace('Z', '+00:00')).timestamp())
            if action in actions and 'scope' not in d: d['scope'] = 'unknown'
            if action not in actions or not isinstance(d.get('scope'), str):
                gaps.append(f'unsupported permission record {number}'); continue
            item = {'kind': 'permission', 'source': 'external_runtime_audit',
                'trust': 'external_runtime_claim', 'approval_domain': d.get('approval_domain', 'runtime_permission')
                    if d.get('approval_domain', 'runtime_permission') in {'runtime_permission', 'application_gate'} else 'unknown',
                'source_integrity': 'operator_selected_file_not_authenticated',
                'time': float(d['timestamp_seconds']), 'action': action,
                'scope': content_redact(d['scope'], 256),
                'request_id': d.get('request_id', d.get('draft_id', d.get('chunk_id'))),
                'subject': content_redact(str(d.get('subject', 'unknown')), 128),
                'approver': content_redact(str(d.get('approver', 'unknown')), 128),
                'expires_at': d.get('expires_at'), 'policy_revision': d.get('policy_revision'),
                'source_reference': f'{path.name}:{number}',
                'content_sha256': hashlib.sha256(line.encode()).hexdigest()}
            if action == 'approved' and (item['scope'] == 'unknown' or not item['request_id'] or item['approver'] == 'unknown'
                    or not isinstance(item['expires_at'], (int, float)) or not item['policy_revision']):
                item['approval_complete'] = False
                gaps.append('approval identity/scope/expiry/revision incomplete; do not infer approval')
            else: item['approval_complete'] = action == 'approved'
            if item['approval_complete'] and item['expires_at'] <= item['time']:
                item['approval_complete'] = False
                gaps.append('approval expired before its recorded use; do not infer approval')
            result.append(item)
        except (ValueError, TypeError, KeyError):
            gaps.append(f'malformed permission evidence record {number}')
    return result, list(dict.fromkeys(gaps))
