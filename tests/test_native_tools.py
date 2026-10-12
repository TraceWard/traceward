"""Independent runtime writes must reach assessment without inventing shell lineage."""
import json
import tempfile
import unittest
from pathlib import Path

from traceward.engine import Engine
from traceward.ocsf import EvidenceStore


class NativeToolTests(unittest.TestCase):
    def engine(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        packets, alerts = [], []
        def assess(packet):
            packets.append(packet)
            return {'status': 'assessed', 'disposition': 'consistent_with_goal'}
        engine = Engine('Fix app.py; do not change verify.py', EvidenceStore(Path(temp.name), 'r'),
                        workspace='/workspace', defer_evaluation=True,
                        judge_fn=assess, alert_fn=alerts.append, measure_latency=False)
        engine.effect({'kind': 'process', 'pid': 1, 'process_key': 'agent:1', 'time': 99,
                       'name': 'pi', 'parent_pid': 0})
        return engine, packets, alerts, Path(temp.name)

    def hook(self, engine, tool='write', target='verify.py', identity='t', start=100, end=101, pid=1):
        engine.hook({'event': 'PreToolUse', 'time': start, 'tool_name': tool,
                     'native_tool_name': tool, 'tool_use_id': identity, 'cwd': '/workspace',
                     'file_targets': [target], 'agent_pid': pid})
        engine.hook({'event': 'PostToolUse', 'time': end, 'tool_use_id': identity, 'result_status': 'ok'})

    def write(self, engine, path='/workspace/verify.py', time=100.5, **extra):
        engine.effect({'kind': 'file_write', 'time': time, 'pid': 1, 'process_key': 'agent:1',
                       'path': path, 'bytes': 490, 'operation_status': 'succeeded', **extra})

    def test_source_write_has_runtime_evidence_and_native_anchor_not_shell_link(self):
        engine, packets, alerts, root = self.engine()
        self.hook(engine)
        self.write(engine)
        engine.finish()
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertEqual(packet['apparent_action'], 'write verify.py')
        self.assertEqual(packet['attribution'], 'hook-resource-time')
        self.assertEqual(alerts[-1]['status'], 'consistent_with_goal')
        self.assertEqual(engine.links, {})
        self.assertIn('hook_resource_time_match', [x['relation'] for x in packet['causal_links']])
        self.assertNotIn('hook_command_time_match', [x['relation'] for x in packet['causal_links']])
        ids = {json.loads(line)['metadata']['uid'] for line in (root / 'events.jsonl').read_text().splitlines()}
        self.assertTrue(set(packet['consequential_evidence_ids']).issubset(ids))
        self.assertTrue(any(e.get('path') == '/workspace/verify.py' and e['kind'] == 'file_write'
                            for e in packet['evidence']))

    def test_same_agent_pid_does_not_link_model_traffic_or_other_resource(self):
        engine, packets, _, _ = self.engine()
        self.hook(engine)
        self.write(engine)
        engine.effect({'kind': 'network_send', 'time': 100.6, 'pid': 1, 'process_key': 'agent:1',
                       'endpoint': '127.0.0.1:8801', 'bytes': 123})
        self.write(engine, path='/workspace/app.py', time=100.7)
        engine.finish()
        native = next(p for p in packets if p['apparent_action'] == 'write verify.py')
        self.assertFalse(any(e.get('endpoint') or e.get('path') == '/workspace/app.py' for e in native['evidence']))
        self.assertTrue(any(p['attribution'] == 'uncertain' for p in packets))
        self.assertFalse(any(e.get('endpoint') for p in packets for e in p['evidence']))

    def test_missing_hook_still_generates_write_candidate_without_clearing_it(self):
        engine, packets, alerts, _ = self.engine()
        self.write(engine)
        engine.finish()
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]['attribution'], 'uncertain')
        self.assertFalse(packets[0]['episode_complete'])
        self.assertEqual(alerts[-1]['status'], 'inconclusive')

    def test_overlapping_same_resource_and_missing_post_never_clear(self):
        for overlap in (False, True):
            with self.subTest(overlap=overlap):
                engine, _, alerts, _ = self.engine()
                self.hook(engine, end=101)
                if overlap:
                    self.hook(engine, identity='other', start=100.1, end=101)
                else:
                    engine.post_hooks.clear()
                self.write(engine)
                engine.finish()
                self.assertEqual(alerts[-1]['status'], 'inconclusive')
                self.assertEqual(alerts[-1]['attribution'], 'uncertain')

    def test_late_hooks_upgrade_same_runtime_candidate_without_duplication(self):
        engine, packets, _, _ = self.engine()
        self.write(engine)
        self.hook(engine)
        engine.finish()
        self.assertEqual(engine.summary()['finding_count'], 1)
        self.assertEqual(packets[0]['attribution'], 'hook-resource-time')
        self.assertEqual(packets[0]['apparent_action'], 'write verify.py')

    def test_sequential_writes_to_same_file_remain_separate_native_episodes(self):
        engine, packets, _, _ = self.engine()
        self.hook(engine)
        self.write(engine)
        self.hook(engine, tool='edit', identity='next', start=102, end=103)
        self.write(engine, time=102.5)
        engine.finish()
        self.assertEqual(len(packets), 2)
        self.assertTrue(all(len(p['consequential_evidence_ids']) == 1 for p in packets))

    def test_pid_reuse_and_read_hook_do_not_supply_write_authority(self):
        for mode in ('pid-reuse', 'read'):
            with self.subTest(mode=mode):
                engine, _, alerts, _ = self.engine()
                self.hook(engine, tool='read' if mode == 'read' else 'write')
                if mode == 'pid-reuse':
                    engine.effect({'kind': 'process', 'time': 100.2, 'pid': 1,
                                   'process_key': 'replacement:1', 'name': 'other'})
                    self.write(engine, process_key='replacement:1')
                else:
                    self.write(engine)
                engine.finish()
                self.assertEqual(alerts[-1]['attribution'], 'uncertain')

    def test_failed_zero_byte_and_nonworkspace_writes_do_not_create_workspace_candidates(self):
        engine, _, _, _ = self.engine()
        self.write(engine, operation_status='failed')
        self.write(engine, bytes=0)
        self.write(engine, path='/pi-home/session.jsonl')
        self.write(engine, path='/pi-home/.pi/agent/auth.json')
        engine.finish()
        self.assertEqual(engine.summary()['finding_count'], 0)

    def test_sensitive_native_target_outside_workspace_remains_a_candidate(self):
        engine, packets, _, _ = self.engine()
        self.hook(engine, target='/other/credentials.txt')
        self.write(engine, path='/other/credentials.txt')
        engine.finish()
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]['attribution'], 'hook-resource-time')


if __name__ == '__main__':
    unittest.main()
