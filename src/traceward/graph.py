"""Rebuildable local evidence graph. Path/time edges are inference, not data flow."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path


class EvidenceGraph:
    def __init__(self, path: Path, run_id: str, shared_roots=()):
        self.path, self.run_id = path, run_id
        self.shared_roots = tuple(str(Path(p).resolve()).rstrip('/') + '/' for p in shared_roots)
        self.lock = threading.RLock()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Owner-only from creation, including SQLite side files via DELETE journal mode.
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600); os.close(fd); path.chmod(0o600)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS observations (
            id TEXT PRIMARY KEY, run_id TEXT NOT NULL, time REAL, kind TEXT,
            path TEXT, version TEXT, content_hash TEXT, phase TEXT, tool_id TEXT, payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS graph_run_time ON observations(run_id,time);
          CREATE INDEX IF NOT EXISTS graph_version ON observations(version);
          CREATE INDEX IF NOT EXISTS graph_path_run ON observations(run_id,path);
          CREATE INDEX IF NOT EXISTS graph_content ON observations(content_hash);
          CREATE TABLE IF NOT EXISTS edges (source TEXT, target TEXT, relation TEXT, confidence TEXT,
            PRIMARY KEY(source,target,relation));
        ''')
        self.db.commit()

    def add(self, item: dict):
        allowed = {'event_id', 'kind', 'time', 'source', 'trust', 'role', 'pid', 'parent_pid', 'process_key',
            'parent_process_key', 'process_start_time_ns', 'sandbox_id', 'name', 'path', 'endpoint', 'bytes',
            'operation_status', 'errno', 'result', 'syscall_number', 'raw_trace_ref', 'script_paths',
            'tool_use_id', 'tool_name', 'native_tool_name', 'event', 'command', 'file_targets', 'agent_pid',
            'cwd', 'session_id', 'turn_id', 'result_status', 'result_exit_code', 'response_sha256',
            'response_bytes', 'resource_version', 'resource_identity', 'sha256', 'phase', 'change',
            'before_sha256', 'after_sha256', 'owner_uid', 'owner_gid', 'mode', 'birthtime_ns', 'mtime_ns',
            'size', 'relative_path', 'integrity_predicates', 'diff_excerpt', 'diff_truncated', 'excerpt',
            'excerpt_truncated', 'content_sha256', 'source_reference', 'action', 'scope', 'subject', 'approver',
            'request_id', 'expires_at', 'policy_revision', 'approval_complete', 'approval_domain', 'source_integrity',
            'passed', 'exit_code', 'validator_sha256', 'isolation', 'upstream_run_id', 'upstream_event_id',
            'upstream_record_sha256', 'origin_kind', 'path_resolution', 'origin_event_id', 'goal_at_collection',
            'method', 'url', 'scheme', 'http_version', 'status_code', 'headers', 'response_headers',
            'request_body', 'response_body', 'client_address', 'error'}
        exported = {k: v for k, v in item.items() if k in allowed}
        from .privacy import redact
        def scrub(value):
            if isinstance(value,str): return redact(value,100000)
            if isinstance(value,list): return [scrub(v) for v in value]
            if isinstance(value,dict): return {k:scrub(v) for k,v in value.items()}
            return value
        exported = scrub(exported)
        with self.lock:
            self.db.execute('INSERT OR REPLACE INTO observations VALUES (?,?,?,?,?,?,?,?,?,?)',
                (item['event_id'], self.run_id, item['time'], item['kind'], item.get('path'),
                 item.get('resource_version'), item.get('sha256'), item.get('phase'),
                 item.get('tool_use_id'), json.dumps(exported, sort_keys=True)))
            process_key = item.get('process_key')
            if process_key and item['kind'] != 'process':
                row = self.db.execute('SELECT id FROM observations WHERE run_id=? AND kind="process" '
                    'AND json_extract(payload,"$.process_key")=? AND time<=? ORDER BY time DESC LIMIT 1',
                    (self.run_id, process_key, item['time'])).fetchone()
                if row: self.db.execute('INSERT OR IGNORE INTO edges VALUES (?,?,?,?)',
                    (row[0], item['event_id'], 'process_emitted_effect', 'observed_process_identity'))
            if item.get('tool_use_id') and item['kind'] != 'hook':
                row = self.db.execute('SELECT id FROM observations WHERE run_id=? AND kind="hook" AND tool_id=? '
                    'AND json_extract(payload,"$.event")="PreToolUse" LIMIT 1', (self.run_id, item['tool_use_id'])).fetchone()
                if row: self.db.execute('INSERT OR IGNORE INTO edges VALUES (?,?,?,?)',
                    (row[0], item['event_id'], 'tool_effect', 'command_or_resource_time_inference'))
            self.db.commit()

    def edge(self, source, target, relation, confidence):
        with self.lock:
            self.db.execute('INSERT OR IGNORE INTO edges VALUES (?,?,?,?)', (source, target, relation, confidence))
            self.db.commit()

    def related(self, seeds: list[dict], tool_ids: set[str], *, limit=32) -> tuple[list[dict], list[dict], bool]:
        """Bounded connected context; arbitrary prior-run events never enter by path alone."""
        paths = {e.get('path') for e in seeds if e.get('path')}
        seed_ids = {e['event_id'] for e in seeds}
        result, links = {}, []
        with self.lock:
            current = self.db.execute('SELECT payload FROM observations WHERE run_id=? ORDER BY time,id',
                                      (self.run_id,)).fetchall()
            events = [json.loads(row[0]) for row in current]
            sampled_paths = {e.get('path') for e in events if e['kind']=='file_state'}
            # Repeated interpreter/package loads are not artifact hand-offs.
            # Cross-tool path associations target sampled workspace resources.
            related_paths = paths & sampled_paths if sampled_paths else paths
            # Related paths can span tools and the entire run, with explicit weak edges.
            for e in events:
                if e.get('path') in related_paths or e.get('tool_use_id') in tool_ids:
                    result[e['event_id']] = e
            # Context exposure and outcome evidence are relevant at the run level,
            # not automatically a causal explanation for a particular operation.
            relevant = [e for e in events if e['kind'] in {'context', 'agent_claim', 'permission', 'independent_validation'}]
            # Approval history must not disappear behind routine tool outputs.
            authority = [e for e in relevant if e['kind'] in {'permission', 'independent_validation'}]
            for e in [*authority, *[e for e in relevant if e['kind']=='context'][:4],
                      *[e for e in relevant if e['kind']=='agent_claim'][-2:]]:
                result[e['event_id']] = e
            # A tool may access more than the triggering resource (e.g. staged report).
            for e in events:
                if e.get('tool_use_id') in tool_ids and e.get('path'): paths.add(e['path'])
            snapshots = [e for e in events if e['kind'] == 'file_state' and e.get('path') in paths]
            hashes = {e.get('sha256') for e in snapshots if e.get('sha256')}
            for e in events:
                if e['kind'] == 'file_state' and (e.get('path') in paths or e.get('sha256') in hashes):
                    result[e['event_id']] = e
                    if e.get('path') not in paths:
                        links.append({'relation': 'same_content_hash', 'confidence': 'host_sampled_hash_match',
                                      'evidence_id': e['event_id'], 'sha256': e.get('sha256')})
            for index, e in enumerate(snapshots):
                for other in snapshots[index+1:]:
                    if e.get('sha256') and e.get('sha256') == other.get('sha256') and e['path'] != other['path']:
                        links.append({'relation': 'same_content_hash', 'confidence': 'host_sampled_hash_match',
                            'evidence_id': e['event_id'], 'other_evidence_id': other['event_id']})
            for e in snapshots:
                version = e.get('resource_version')
                if not version or not any(e['path'].startswith(p) for p in self.shared_roots): continue
                prior = self.db.execute('SELECT run_id,payload FROM observations WHERE version=? AND run_id<>? '
                                       'AND phase="final" ORDER BY time DESC LIMIT 4', (version, self.run_id)).fetchall()
                for run_id, payload in prior:
                    d = json.loads(payload)
                    # Local anchor carries immutable origin/hash; original JSONL remains authoritative.
                    origin = d['event_id']
                    identity = hashlib.sha256((self.run_id + ':' + origin).encode()).hexdigest()
                    anchor = {**d, 'event_id': identity, 'kind': 'external_evidence',
                        'source': 'evidence_graph', 'upstream_run_id': run_id, 'upstream_event_id': origin,
                        'upstream_record_sha256': hashlib.sha256(payload.encode()).hexdigest(),
                        'trust': 'prior_host_observation', 'origin_kind': d['kind']}
                    result[identity] = anchor
                    links.append({'relation': 'same_sampled_resource_version', 'confidence': 'host_device_inode_hash',
                        'evidence_id': e['event_id'], 'prior_evidence_id': identity, 'upstream_run_id': run_id,
                        'resource_version': version})
        priority = {'permission':0,'independent_validation':1,'file_state':2,
                    'external_evidence':3,'context':4,'agent_claim':5}
        selected = sorted((e for eid, e in result.items() if eid not in seed_ids),
            key=lambda e: (priority.get(e['kind'],6),e['time'],e['event_id']))
        omitted = len(selected) > limit
        for link in links:
            target = link.get('prior_evidence_id', link.get('other_evidence_id'))
            if target: self.edge(link['evidence_id'], target, link['relation'], link['confidence'])
        return sorted(selected[:limit],key=lambda e:(e['time'],e['event_id'])), links, omitted

    def close(self):
        with self.lock: self.db.close()

    def rebuild(self, runs: Path):
        """Explicitly replace the derived index from authoritative observation logs.

        Old runs without analysis-events retain only available hooks and effects.
        Resource versions cannot be reconstructed from paths or current files.
        """
        from .gvisor import GvisorParser
        count = 0
        original_run = self.run_id
        with self.lock:
            self.db.execute('DELETE FROM edges'); self.db.execute('DELETE FROM observations'); self.db.commit()
            try:
                for directory in sorted(runs.iterdir()):
                    manifest = directory/'run.json'
                    if not directory.is_dir() or directory.is_symlink() or not manifest.is_file(): continue
                    metadata = json.loads(manifest.read_text())
                    self.run_id = metadata['run_id']
                    for name in ('hooks.jsonl','analysis-events.jsonl'):
                        source = directory/name
                        if not source.is_file() or source.is_symlink(): continue
                        for line in source.read_text().splitlines():
                            item = json.loads(line)
                            item.setdefault('kind','hook')
                            # Raw hooks may lack the generated event ID. Stable derived ID.
                            item.setdefault('event_id',hashlib.sha256((self.run_id+name+line).encode()).hexdigest())
                            self.add(item);count += 1
                    source = directory/'raw.gvisor.jsonl'
                    if source.is_file() and not source.is_symlink():
                        parser = GvisorParser('/workspace','arm64')
                        for line in source.read_text().splitlines():
                            item = parser.parse(line)
                            if item:
                                item.setdefault('event_id',hashlib.sha256((self.run_id+line).encode()).hexdigest())
                                self.add(item);count += 1
            finally: self.run_id = original_run
        return count
