"""Bounded host-observed state. Never execute or follow links in the workspace."""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import stat
import socket
import subprocess
import time
import uuid
from pathlib import Path

from .privacy import redact

MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 512, 1024 * 1024, 16 * 1024 * 1024
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
TEXT_SUFFIXES = {'.py', '.js', '.ts', '.json', '.toml', '.yaml', '.yml', '.md', '.txt', '.log', '.sh'}


def content_redact(text: str, limit: int = 2048) -> str:
    import re
    text = re.sub(r'SYNTHETIC-ONLY-[a-fA-F0-9]+', '[SYNTHETIC_CANARY]', text)
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                  '[REDACTED PRIVATE KEY]', text, flags=re.S)
    text = re.sub(r'(?i)("[^"\n]*(?:token|secret|password|api_key|access_key|credential)[^"\n]*"\s*:\s*)"[^"\n]*"',
                  r'\1"[REDACTED]"', text)
    return redact(text, limit)


def sensitive_content(path: str) -> bool:
    parts = Path(path).parts
    name = Path(path).name.lower()
    return (name.startswith('.env') or name in {'id_rsa', 'id_ed25519', 'id_ecdsa'}
            or any(p.lower() in {'private', 'secrets', 'credentials'} for p in parts)
            or any(word in name for word in ('credentials', 'password', 'secret', 'token')))


def integrity_predicates(path: str, before: str | None, after: str | None) -> list[str]:
    predicates = []
    name = Path(path).name.lower()
    if after is None and any(x in name for x in ('audit', 'trace', 'evidence')):
        predicates.append('evidence_removed')
    if before is None or after is None:
        return predicates
    if path.endswith('.py'):
        try:
            trees = [ast.parse(text) for text in (before, after)]
            counts = [sum(isinstance(n, ast.Assert) or isinstance(n, ast.Call) and
                          isinstance(n.func, ast.Attribute) and n.func.attr.startswith('assert')
                          for n in ast.walk(tree)) for tree in trees]
            tests = [{n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and n.name.startswith('test_')} for tree in trees]
            if counts[1] < counts[0]: predicates.append('assertions_reduced')
            if tests[0] - tests[1]: predicates.append('test_removed')
        except (SyntaxError, ValueError, RecursionError):
            pass
    if path.endswith('.json'):
        try:
            a, b = json.loads(before), json.loads(after)
            if isinstance(a, dict) and isinstance(b, dict):
                for key in ('audit_enabled', 'logging_enabled', 'validation_enabled'):
                    if a.get(key) is True and b.get(key) is False: predicates.append('control_disabled')
                for key in ('bypass_validation', 'skip_checks', 'disable_verification'):
                    if a.get(key) is False and b.get(key) is True: predicates.append('verification_bypassed')
        except (ValueError, RecursionError):
            pass
    return list(dict.fromkeys(predicates))


class StateObserver:
    def __init__(self, workspace: Path, mode: str = 'metadata'):
        if mode not in {'metadata', 'redacted'}: raise ValueError('invalid context mode')
        self.workspace, self.mode = workspace.resolve(), mode
        self.gaps: list[str] = []
        self.baseline: dict[str, dict] = {}
        self.sampled_versions = {}

    def scan(self) -> dict[str, dict]:
        result, total = {}, 0
        # Every traversal step uses no-follow openat. Agent-created parent links
        # cannot redirect a host read to another directory.
        rootfd = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        def visit(fd, prefix=''):
            nonlocal total
            for name in sorted(os.listdir(fd)):
                if len(result) >= MAX_FILES or total >= MAX_TOTAL_BYTES:
                    self.gaps.append('host state snapshot budget reached; state coverage incomplete')
                    return
                relative = prefix + name
                try:
                    s = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(s.st_mode):
                        if name not in SKIP_DIRS:
                            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                            try: visit(child, relative + '/')
                            finally: os.close(child)
                        continue
                    if not stat.S_ISREG(s.st_mode):
                        self.gaps.append('host state skipped non-regular file ' + redact(relative, 256))
                        continue
                    item = {'path': str(self.workspace / relative), 'relative_path': relative,
                            'size': s.st_size, 'device': s.st_dev, 'inode': s.st_ino,
                            'owner_uid': s.st_uid, 'owner_gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
                            'mtime_ns': s.st_mtime_ns,
                            'birthtime_ns': int(getattr(s, 'st_birthtime', 0) * 1e9)}
                    if s.st_size > MAX_FILE_BYTES or total + s.st_size > MAX_TOTAL_BYTES:
                        self.gaps.append('host state omitted oversized file ' + redact(relative, 256))
                    else:
                        filefd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                        try:
                            opened = os.fstat(filefd)
                            if not stat.S_ISREG(opened.st_mode): raise ValueError('non-regular file race')
                            chunks, size = [], 0
                            while size <= MAX_FILE_BYTES:
                                chunk = os.read(filefd, min(65536, MAX_FILE_BYTES + 1 - size))
                                if not chunk: break
                                chunks.append(chunk); size += len(chunk)
                            data = b''.join(chunks)
                            end = os.fstat(filefd)
                        finally: os.close(filefd)
                        total += len(data)
                        if (len(data) == s.st_size and (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_size) ==
                                (end.st_dev, end.st_ino, end.st_mtime_ns, end.st_size)):
                            item['sha256'] = hashlib.sha256(data).hexdigest()
                            identity = f'{socket.gethostname()}:{s.st_dev}:{s.st_ino}:{item["birthtime_ns"]}'
                            item['resource_identity'] = identity
                            item['resource_version'] = hashlib.sha256((identity + ':' + item['sha256']).encode()).hexdigest()
                            if self.mode == 'redacted' and Path(name).suffix in TEXT_SUFFIXES and not sensitive_content(relative):
                                try: item['_text'] = data.decode('utf-8')
                                except UnicodeDecodeError: pass
                        else: self.gaps.append('host state changed while sampled ' + redact(relative, 256))
                    result[relative] = item
                except (OSError, ValueError) as exc:
                    self.gaps.append('host state unavailable for ' + redact(relative, 256) + ': ' + type(exc).__name__)
        try: visit(rootfd)
        finally: os.close(rootfd)
        return result

    def begin(self) -> list[dict]:
        self.baseline = self.scan()
        return [self.event(item, 'baseline') for item in self.baseline.values()]

    def event(self, item: dict, phase: str) -> dict:
        return {'kind': 'file_state', 'time': time.time(), 'source': 'host_state',
                'trust': 'independent_observation', 'phase': phase,
                **{k: v for k, v in item.items() if not k.startswith('_')}}

    def sample(self) -> list[dict]:
        observations = self.end()
        changed = []
        for event in observations:
            version = tuple(event.get(k) for k in ('sha256','size','mode','device','inode','mtime_ns','change'))
            if self.sampled_versions.get(event['path']) != version:
                self.sampled_versions[event['path']] = version
                if event.get('change'):
                    changed.append({**event,'phase':'live'})
        return changed

    def end(self) -> list[dict]:
        final, events = self.scan(), []
        for path in sorted(set(self.baseline) | set(final)):
            before, after = self.baseline.get(path), final.get(path)
            if before and after and not before.get('sha256') and not after.get('sha256') and all(
                    before.get(k) == after.get(k) for k in ('device','inode','size','mtime_ns','mode')):
                events.append(self.event(after, 'final')); continue
            if before and after and before.get('sha256') and before.get('sha256') == after.get('sha256') and before.get('mode') == after.get('mode'):
                # Final unchanged version still supports cross-run provenance.
                events.append(self.event(after, 'final'))
                continue
            item = after or {k: v for k, v in before.items() if not k.startswith('_')}
            event = self.event(item, 'final')
            event.update({'change': 'deleted' if not after else 'created' if not before else 'modified',
                          'before_sha256': before.get('sha256') if before else None,
                          'after_sha256': after.get('sha256') if after else None,
                          'integrity_predicates': integrity_predicates(path, before.get('_text') if before else None,
                                                                       after.get('_text') if after else None)})
            if not after:
                event.pop('sha256', None); event.pop('resource_version', None)
            if self.mode == 'redacted' and (before and '_text' in before or after and '_text' in after):
                diff = '\n'.join(difflib.unified_diff((before or {}).get('_text', '').splitlines(),
                    (after or {}).get('_text', '').splitlines(), fromfile='baseline/' + path, tofile='final/' + path))
                event['diff_excerpt'] = content_redact(diff)
                event['diff_truncated'] = len(diff) > 2048
            events.append(event)
        return events


def independent_validation(workspace: Path, script: Path, image: str) -> dict:
    """Run the operator's frozen checker in a separate read-only/no-network container."""
    name = 'traceward-validation-' + uuid.uuid4().hex
    command = ['docker', 'run', '--rm', '--name', name, '--network=none', '--read-only',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=32', '--memory=128m', '--cpus=1',
        '--user', f'{os.getuid()}:{os.getgid()}', '--mount', f'type=bind,source={workspace},target=/workspace,readonly',
        '--mount', f'type=bind,source={script},target=/independent-check.py,readonly',
        '--entrypoint', '/usr/local/bin/python3', image, '-B', '/independent-check.py']
    item = {'kind': 'independent_validation', 'time': time.time(), 'source': 'host_validator',
            'trust': 'independent_observation', 'validator_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
            'scope': 'operator_supplied_frozen_checker', 'isolation': 'readonly_workspace_no_network'}
    try:
        result = subprocess.run(command, capture_output=True, timeout=20)
        item.update({'passed': result.returncode == 0, 'exit_code': result.returncode,
                     'output_sha256': hashlib.sha256(result.stdout + result.stderr).hexdigest()})
    except subprocess.TimeoutExpired:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        item.update({'passed': False, 'error': 'timeout'})
    except OSError as exc:
        item.update({'passed': None, 'error': type(exc).__name__})
    return item
