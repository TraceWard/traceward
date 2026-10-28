"""Operation paths must preserve observed identities and honest attribution gaps."""
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from traceward.ocsf import project, EvidenceStore
from traceward.operation_chain import build_operation_chain

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None


def event(eid, kind='process', time=1, **fields):
    return project(kind, dict(event_id=eid, time=time, pid=1, name='python', source='gvisor', **fields), 'test')


def finding(**fields):
    return dict(finding_id='f', revision=1, evidence_ids=['read'], consequential_evidence_ids=['read'],
                attribution='command-and-process-lineage', **fields)


class OperationChainTests(unittest.TestCase):
    def chain(self, events, **fields):
        return build_operation_chain(finding(**fields), events)

    def test_script_read_and_shared_ancestors_have_observed_edges(self):
        events = [event('python', process_key='p', script_paths=['scripts/check.py']),
                  event('read', 'file_read', 2, process_key='p', path='/workspace/.env', bytes=10),
                  event('other', 'file_write', 3, process_key='p', path='/workspace/result.txt')]
        f = finding(); f['evidence_ids'].append('other')
        c = build_operation_chain(f, events)
        self.assertEqual(c['roots'], ['python'])
        self.assertEqual(len(c['nodes']), 3)
        self.assertTrue(next(n for n in c['nodes'] if n['id'] == 'read')['is_consequential'])
        self.assertFalse(next(n for n in c['nodes'] if n['id'] == 'other')['on_path'])
        self.assertEqual(c['edges'][0]['basis'], 'observed')
        self.assertEqual(c['nodes'][0]['event']['unmapped']['traceward']['script_paths'], ['scripts/check.py'])

    def test_multi_child_chain_stops_at_recorded_tool_anchor(self):
        hook = event('hook', 'hook', .9, event='PreToolUse', tool_name='Bash', tool_use_id='tool', command='npm test')
        events = [hook, event('agent', time=.5, process_key='agent'),
                  event('shell', process_key='shell', parent_process_key='agent', parent_pid=1),
                  event('child', time=2, process_key='child', parent_process_key='shell', parent_pid=1),
                  event('python', time=3, process_key='python', parent_process_key='child', parent_pid=1),
                  event('read', 'file_read', 4, process_key='python', path='/workspace/.env')]
        c = self.chain(events, tool_use_id='tool', causal_links=[dict(relation='hook_command_time_match',
                       hook_evidence_id='hook', process_evidence_id='shell')])
        self.assertEqual([n['id'] for n in c['nodes']], ['hook', 'shell', 'child', 'python', 'read'])
        self.assertEqual(c['roots'], ['hook'])
        self.assertEqual([e['relation'] for e in c['edges']],
                         ['process_emitted_effect', 'process_parent', 'process_parent', 'hook_command_time_match'])

    def test_same_lifetime_exec_uses_executable_at_effect_time(self):
        events = [event('sh', process_key='p'), event('python', time=2, process_key='p'),
                  event('read', 'file_read', 3, process_key='p', path='/workspace/.env'),
                  event('future', time=4, process_key='p')]
        c = self.chain(events)
        self.assertEqual([(e['source'], e['target'], e['relation']) for e in c['edges']],
                         [('python', 'read', 'process_emitted_effect'), ('sh', 'python', 'process_exec')])
        self.assertNotIn('future', [n['id'] for n in c['nodes']])

    def test_same_millisecond_events_use_ingestion_order(self):
        events = [event('sh', process_key='p'), event('read', 'file_read', path='/workspace/.env', process_key='p'),
                  event('python', process_key='p')]
        for i, e in enumerate(events): e['index_id'] = i + 1
        self.assertEqual(self.chain(events)['edges'][0]['source'], 'sh')

    def test_pid_reuse_does_not_attach_to_other_lifetime(self):
        events = [event('old', process_key='old'), event('new', time=3, process_key='new'),
                  event('read', 'file_read', 4, path='/workspace/.env')]
        c = self.chain(events)
        self.assertEqual(c['edges'], [])
        self.assertIn('uniquely resolved', ' '.join(c['gaps']))
        events[-1]['unmapped']['traceward']['process_key'] = 'new'
        self.assertEqual(self.chain(events)['edges'][0]['source'], 'new')

    def test_exited_lifetime_cannot_emit_later_effect(self):
        c = self.chain([event('python', process_key='p'), event('exit', 'process_exit', 2, process_key='p'),
                        event('read', 'file_read', 3, process_key='p', path='/workspace/.env')])
        self.assertEqual(c['edges'], [])

    def test_native_tool_has_no_invented_shell(self):
        c = self.chain([event('hook', 'hook', event='PreToolUse', tool_name='Read', tool_use_id='t'),
                        event('read', 'file_read', 2, process_key='agent', path='/workspace/.env')],
                       tool_use_id='t', causal_links=[dict(relation='hook_resource_time_match',
                        hook_evidence_id='hook', effect_evidence_id='read')])
        self.assertEqual([n['kind'] for n in c['nodes']], ['hook', 'file_read'])
        self.assertEqual(c['edges'][0]['basis'], 'inferred')

    def test_ambiguous_tool_match_is_not_asserted(self):
        f = finding(); f.update(attribution='uncertain', tool_use_id='t', causal_links=[dict(
            relation='hook_command_time_match', hook_evidence_id='hook', process_evidence_id='python')])
        c = build_operation_chain(f, [event('hook', 'hook', event='PreToolUse', tool_use_id='t'),
            event('python', process_key='p'), event('read', 'file_read', 2, process_key='p', path='/workspace/.env')])
        self.assertFalse(any(n['kind'] == 'hook' for n in c['nodes']))
        self.assertIn('uncertain', ' '.join(c['gaps']))

    def test_multiple_effects_merge_ancestors(self):
        f = finding(); f['consequential_evidence_ids'].append('send'); f['evidence_ids'].append('send')
        c = build_operation_chain(f, [event('python', process_key='p'),
            event('read', 'file_read', 2, process_key='p', path='/workspace/.env'),
            event('send', 'network_send', 3, process_key='p', endpoint='127.0.0.1:9000')])
        self.assertEqual(len(c['nodes']), 3)
        self.assertEqual(c['roots'], ['python'])
        self.assertEqual(sum(n['is_consequential'] for n in c['nodes']), 2)

    def test_missing_and_cyclic_parent_are_visible(self):
        for parent in ('missing', 'p'):
            c = self.chain([event('python', process_key='p', parent_process_key=parent),
                            event('read', 'file_read', 2, process_key='p', path='/workspace/.env')])
            self.assertTrue(c['gaps'])
            self.assertEqual(len(c['nodes']), 2)

    def test_legacy_records_never_infer_trigger_or_parent_by_time(self):
        f = finding(); del f['consequential_evidence_ids']
        c = build_operation_chain(f, [event('python'), event('read', 'file_read', 2, path='/workspace/.env')])
        self.assertFalse(any(n['is_consequential'] for n in c['nodes']))
        self.assertIn('no trigger is inferred', ' '.join(c['gaps']))
        self.assertEqual(c['edges'][0]['basis'], 'inferred')

    def test_temporal_read_send_is_supporting_context_not_flow(self):
        f = finding(); f.update(evidence_ids=['read', 'send'], consequential_evidence_ids=['send'],
            causal_links=[dict(relation='earlier_run_access', evidence_id='read', confidence='temporal_only_not_payload_flow')])
        c = build_operation_chain(f, [event('read', 'file_read', 1, process_key='p1', path='/workspace/.env'),
            event('send', 'network_send', 2, process_key='p2', endpoint='127.0.0.1:9000')])
        self.assertEqual(c['edges'], [])
        self.assertEqual([n['id'] for n in c['nodes']], ['send'])
        self.assertEqual(c['associations'][0]['relation'], 'earlier_run_access')

    def test_malformed_links_are_not_used_as_ancestry(self):
        for links in (None, 'invalid', [None, {'relation': []}, {'relation':'hook_command_time_match',
                       'hook_evidence_id': [], 'process_evidence_id': []}]):
            c = self.chain([event('read', 'file_read', path='/workspace/.env')], causal_links=links)
            self.assertEqual(c['edges'], [])

    def test_conflicting_recorded_tool_links_are_not_selected_arbitrarily(self):
        events = [event('hook1', 'hook', event='PreToolUse'), event('hook2', 'hook', event='PreToolUse'),
                  event('python', time=2, process_key='p'),
                  event('read', 'file_read', 3, process_key='p', path='/workspace/.env')]
        c = self.chain(events, causal_links=[dict(relation='hook_command_time_match', hook_evidence_id=h,
                       process_evidence_id='python') for h in ('hook1', 'hook2')])
        self.assertFalse(any(n['kind']=='hook' for n in c['nodes']))
        self.assertIn('Conflicting', ' '.join(c['gaps']))

    def test_recorded_parent_evidence_recovers_legacy_ancestry(self):
        shell = event('shell')
        child = event('child', time=2, parent_pid=1)
        child['process']['pid'] = 2
        read = event('read', 'file_read', 3, path='/workspace/.env')
        read['actor']['process']['pid'] = 2
        c = self.chain([shell, child, read], causal_links=[dict(relation='process_parent',
                       evidence_id='child', parent_evidence_id='shell')])
        self.assertEqual(c['roots'], ['shell'])
        self.assertEqual(c['edges'][-1]['label'], 'Recorded parent process')


@unittest.skipIf(TestClient is None, 'install dashboard optional dependencies')
class OperationChainAPITests(unittest.TestCase):
    def test_revision_pagination_live_additions_and_read_only_history(self):
        from traceward.dashboard import RunIndex, create_app
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); runs = root/'runs'; rid = str(uuid.uuid4()); folder = runs/rid
            folder.mkdir(parents=True)
            (folder/'run.json').write_text(json.dumps(dict(goal='Do not read .env', started_at=1)))
            store = EvidenceStore(folder, rid)
            # The relevant process is beyond the old /processes limit.
            for i in range(5001):
                store.event('process', dict(event_id=f'p{i}', time=i, pid=i+1, name='python', process_key=f'key{i}'))
            for i in range(105):
                store.event('file_read', dict(event_id=f'r{i}', time=6000+i, pid=5001,
                    process_key='key5000', path='/workspace/.env', bytes=1))
            record = dict(finding_id='f', revision=1, time=7000, title='Read .env', message='Synthetic',
                status='review_required', evidence_ids=[f'r{i}' for i in range(105)],
                consequential_evidence_ids=['r104'], observed_effects=['file_read'], attribution='uncertain')
            store.assessment(record)
            index = RunIndex(runs, root/'index.sqlite')
            self.addCleanup(index.db.close)
            with TestClient(create_app(index), base_url='http://localhost') as client:
                url = f'/api/runs/{rid}/findings/f/operation-chain'
                before = {p.name: p.read_bytes() for p in folder.iterdir()}
                chain = client.get(url+'?revision=1').json()
                self.assertEqual(len(chain['evidence']), 105)
                self.assertEqual(chain['edges'][0]['source'], 'p5000')
                self.assertEqual(before, {p.name: p.read_bytes() for p in folder.iterdir()})
                store.assessment({**record, 'revision': 2, 'status': 'consistent_with_goal',
                                  'consequential_evidence_ids': ['late'], 'evidence_ids': ['late']})
                self.assertEqual(client.get(url).json()['missing_evidence_ids'], ['late'])
                store.event('file_read', dict(event_id='late', time=7001, pid=5001,
                                              process_key='key5000', path='/workspace/.env'))
                self.assertEqual(client.get(url).json()['missing_evidence_ids'], [])
                self.assertEqual(client.get(url+'?revision=1').json()['revision'], 1)
                self.assertEqual(client.get(url).json()['revision'], 2)
                self.assertEqual(client.get(url+'?revision=999').status_code, 404)
                self.assertEqual(client.get(url+'?revision=0').status_code, 422)
                self.assertEqual(client.get(url.replace('/f/', '/missing/')).status_code, 404)
                self.assertEqual(client.get(f'/api/runs/{rid}/findings').json()['findings'], [])


if __name__ == '__main__':
    unittest.main()
