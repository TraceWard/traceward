"""Real wrapper signals and cancellation with a deliberately stalled judge."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from traceward.engine import Engine
from traceward.ocsf import EvidenceStore
from traceward.cli import _tail_lines
from traceward.graph import EvidenceGraph


class AssessmentShutdownTests(unittest.TestCase):
    def test_final_attribution_preserves_evidence_and_skips_unchanged_records(self):
        with tempfile.TemporaryDirectory() as directory:
            graph = EvidenceGraph(Path(directory)/'graph.sqlite', 'r')
            try:
                graph.add(dict(event_id='hook', kind='hook', time=1, event='PreToolUse', tool_use_id='t'))
                event = dict(event_id='read', kind='file_read', time=2, path='/workspace/sample.txt', bytes=42)
                graph.add(event)
                graph.attribute(event, 't')
                row = graph.db.execute('SELECT tool_id,payload FROM observations WHERE id="read"').fetchone()
                self.assertEqual(row[0], 't')
                self.assertEqual(json.loads(row[1]), {**event, 'tool_use_id': 't'})
                self.assertEqual(graph.db.execute('SELECT source,target,relation FROM edges').fetchall(),
                                 [('hook', 'read', 'tool_effect')])
                changes = graph.db.total_changes
                graph.attribute(event, 't')
                self.assertEqual(graph.db.total_changes, changes)
                graph.attribute(dict(event_id='fork', kind='process', time=3, pid=3), None)
                self.assertIsNotNone(graph.db.execute('SELECT id FROM observations WHERE id="fork"').fetchone())
            finally: graph.close()

    def test_final_graph_attribution_stops_between_events_on_cancel(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = Engine('Inspect local files', EvidenceStore(Path(directory), 'r'), extended_analysis=True)
            for i in range(3):
                engine.effect(dict(kind='file_read', time=i, pid=1, path='/workspace/ordinary.txt', bytes=1))
            calls = []
            original = engine.graph.attribute
            def attribute(item, tid):
                calls.append(item['event_id'])
                original(item, tid)
                engine.cancel_assessments()
            engine.graph.attribute = attribute
            engine.finish()
            self.assertEqual(len(calls), 1)
            self.assertIn('final graph attribution interrupted', ' '.join(engine.coverage_gaps))

    def test_chunked_source_reader_preserves_partial_utf8_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'events.jsonl'
            expected = ['first', 'héllo 世界', 'last']
            path.write_text('\n'.join(expected)+'\n')
            offset, pending, result = 0, '', []
            while offset < path.stat().st_size:
                lines, offset, pending = _tail_lines(path, offset, pending, limit=3)
                result.extend(lines)
            self.assertEqual(result, expected)
            self.assertEqual(pending, '')

    def test_cancel_preserves_review_stops_queued_work_and_discards_late_answers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entered, release = threading.Event(), threading.Event()
            live_review = threading.Event()
            calls = []
            def judge(packet):
                calls.append(packet)
                if packet.get('live_window'):
                    return {'status': 'assessed', 'disposition': 'review_required'}
                entered.set()
                release.wait(5)
                return {'status': 'assessed', 'disposition': 'consistent_with_goal'}
            engine = Engine('No network', EvidenceStore(root, 'r'), extended_analysis=True,
                            evaluation_wait_seconds=0, judge_fn=judge, alert_fn=lambda _: live_review.set())
            engine.effect(dict(kind='network_send', time=1, pid=2, endpoint='203.0.113.1:443', bytes=1))
            self.assertTrue(live_review.wait(1))
            # Three deferred candidates compete for two slots. The third must
            # never start inference once shutdown has been cancelled.
            engine.defer_evaluation = True
            for pid in (3, 4):
                engine.effect(dict(kind='network_send', time=2, pid=pid, endpoint='203.0.113.1:443', bytes=1))
            finishing = threading.Thread(target=engine.finish)
            finishing.start()
            try:
                self.assertTrue(entered.wait(1))
                engine.cancel_assessments()
                finishing.join(1)
                self.assertFalse(finishing.is_alive(), 'shutdown must not wait for a stalled judge')
                assessments = [json.loads(line) for line in (root/'assessments.jsonl').read_text().splitlines()]
                latest = {a['finding_id']: a for a in assessments}
                self.assertEqual(sum(a['status'] == 'review_required' for a in latest.values()), 1)
                self.assertEqual(sum(a['status'] == 'evaluation_unavailable' for a in latest.values()), 2)
                retained = next(a for a in latest.values() if a['status'] == 'review_required')
                self.assertEqual(retained['judge']['reason'], 'assessment_cancelled_on_shutdown')
                self.assertEqual(engine.summary()['finding_count'], 1)
                before = {p.name: p.read_bytes() for p in root.glob('*.jsonl')}
                request_count = len(calls)
                release.set()
                for worker in engine.threads: worker.join(1)
                self.assertTrue(all(not t.is_alive() for t in engine.threads))
                self.assertEqual(len(calls), request_count, 'queued inference must not start after cancellation')
                self.assertEqual(before, {p.name: p.read_bytes() for p in root.glob('*.jsonl')},
                                 'late answers must not change saved findings or audit records')
            finally:
                release.set()
                finishing.join(1)


# The guest is a local disposable Python process here. We test actual OS signal
# delivery through core.run without Docker, credentials, or a model server.
WRAPPER = '''
import json, os, signal, sys, time
from pathlib import Path
from unittest.mock import patch
from traceward import cli
from traceward.engine import Engine
root = Path(sys.argv[1])
class Runtime:
    transport_endpoints = ()
    permission_log = None
    agent_state_roots = ()
    gaps = []
    hook_setup_hint = 'synthetic hook'
    image = 'synthetic'
    home = root
    def __init__(self, run_dir, run_id, args, **options):
        self.metadata = {'workspace': str(root/'workspace')}
        child = "import signal, sys, time; from pathlib import Path; " + \\
            "signal.signal(signal.SIGINT, lambda *_: sys.exit(130)); " + \\
            "Path(sys.argv[1]).touch(); time.sleep(30)"
        self.command = [sys.executable, '-c', child, str(root/'agent-ready')]
        (run_dir/'runtime-status.json').write_text(json.dumps({'handshakes':1,'source_messages':1}))
        if (root/'backlog').exists():
            (run_dir/'raw.gvisor.jsonl').write_text('event\\n'*5000)
    def signal(self, child, signum):
        child.send_signal(signum)
        if (root/'backlog').exists():
            child.wait(timeout=2)
            (root/'signal-forwarded').touch()
    def cleanup(self):
        (root/'cleaned-up').touch()
class SlowEngine(Engine):
    def __init__(self, *args, **options):
        def judge(packet):
            (root/'judge-started').touch()
            while not (root/'release-judge').exists(): time.sleep(.01)
            return {'status':'assessed','disposition':'review_required'}
        options['judge_fn'] = judge
        super().__init__(*args, **options)
        self.effect(dict(kind='network_send',time=1,pid=2,endpoint='203.0.113.1:443',bytes=1))
class Parser:
    unparsed = 0
    gaps = []
    def __init__(self, *args): pass
    def parse(self, line):
        (root/'normalizing').touch()
        time.sleep(.002)
        return None
with patch('traceward.cli.Engine', SlowEngine), patch('traceward.cli.GvisorParser', Parser):
    raise SystemExit(cli.run(['--goal','No network','codex'],runtime_factory=Runtime,agent_name='pi'))
'''


@unittest.skipIf(os.name == 'nt', 'POSIX signal test')
class WrapperSignalTests(unittest.TestCase):
    def wait_for(self, condition, child, stderr, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition(): return
            if child.poll() is not None: break
            time.sleep(.02)
        self.fail('wrapper did not reach expected state: ' + stderr.read_text())

    def run_wrapper(self, second_signal=None, first_signal=signal.SIGTERM, backlog=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'workspace').mkdir()
            if backlog: (root/'backlog').touch()
            script = root/'wrapper.py'; script.write_text(WRAPPER)
            stderr = root/'stderr'
            with stderr.open('w') as log:
                child = subprocess.Popen([sys.executable, str(script), str(root)],
                    env=dict(os.environ, XDG_STATE_HOME=str(root/'state')),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
                try:
                    self.wait_for(lambda: (root/'agent-ready').exists(), child, stderr)
                    child.send_signal(first_signal)
                    if backlog:
                        self.wait_for(lambda: (root/'signal-forwarded').exists(), child, stderr)
                        self.assertTrue((root/'normalizing').exists())
                    else:
                        self.wait_for(lambda: 'waiting for' in stderr.read_text(), child, stderr)
                        self.assertIsNone(child.poll(), 'the first signal must allow final assessment to finish')
                        self.assertIn('Press Ctrl+C or send SIGTERM again', stderr.read_text())
                    if second_signal is None:
                        (root/'release-judge').touch()
                    else:
                        child.send_signal(second_signal)
                    code = child.wait(timeout=3)
                    self.assertEqual(code, 128 + (first_signal if second_signal is None else second_signal))
                    self.assertTrue((root/'cleaned-up').exists())
                    summary_path = next((root/'state/traceward/runs').glob('*/summary.json'))
                    summary = json.loads(summary_path.read_text())
                    self.assertEqual(summary['assessment_wait_cancelled'], second_signal is not None)
                    self.assertEqual(summary['agent_exit_code'], 130 if first_signal == signal.SIGINT else -signal.SIGTERM)
                    self.assertNotIn('Traceback', stderr.read_text())
                    latest = json.loads((summary_path.parent/'assessments.jsonl').read_text().splitlines()[-1])
                    self.assertEqual(latest['status'], 'review_required' if second_signal is None else 'evaluation_unavailable')
                    if second_signal is not None:
                        self.assertEqual(latest['judge']['reason'], 'assessment_cancelled_on_shutdown')
                        self.assertIn('final review incomplete', ' '.join(summary['coverage_gaps']))
                        if backlog:
                            self.assertIn('observation processing interrupted', ' '.join(summary['coverage_gaps']))
                            self.assertEqual((summary_path.parent/'raw.gvisor.jsonl').read_text(), 'event\n'*5000)
                finally:
                    if child.poll() is None:
                        child.kill(); child.wait()

    def test_sigterm_during_final_assessment_saves_summary_without_traceback(self):
        self.run_wrapper(signal.SIGTERM)

    def test_ctrl_c_during_final_assessment_saves_summary_without_traceback(self):
        self.run_wrapper(signal.SIGINT, first_signal=signal.SIGINT)

    def test_first_sigterm_still_waits_for_successful_final_assessment(self):
        self.run_wrapper()

    def test_ctrl_c_is_not_swallowed_while_processing_a_dead_agents_backlog(self):
        self.run_wrapper(signal.SIGINT, backlog=True)
