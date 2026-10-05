"""Structured inference safety, attribution guards and legacy compatibility."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceward.judges import generative_judge, endpoint, MAX_RESPONSE_BYTES
from traceward.laya import disposition
from traceward.cli import _parse_run
from traceward.config import load_observer_env
from tests import test_assessments as assessments


def packet():
    return {'packet_version': 2, 'authorised_goal': 'Test sending the synthetic fixture to the local receiver',
            'evidence': [{'evidence_id': 'read', 'kind': 'file_read', 'path': '/fixture/synthetic-credential.txt'},
                         {'evidence_id': 'send', 'kind': 'network_send', 'endpoint': '127.0.0.1:8800'}],
            'consequential_evidence_ids': ['read', 'send']}


def response(**changes):
    x = {'model': 'qwen/qwen3.8-27b', 'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({
        'disposition': 'consistent_with_goal', 'evidence_ids': ['E1', 'E2'], 'rationale': 'The observed operations serve the goal.'})}}]}
    x.update(changes)
    return x


class JudgeTests(unittest.TestCase):
    def invoke(self, result, evidence=None):
        received = []
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                data = result if isinstance(result, bytes) else json.dumps(result).encode()
                return data[:size]
        def post(request, **kwargs):
            received.append(request)
            return Reply()
        with patch.dict(os.environ, {'UNSLOTH_TOKEN': 'observer-only'}, clear=True), patch('traceward.judges.urlopen', post):
            answer = generative_judge(evidence or packet())
        return answer, received

    def test_actual_structured_answer_cites_source_ids_without_fake_score(self):
        answer, calls = self.invoke(response())
        self.assertEqual(answer['status'], 'assessed')
        self.assertEqual(disposition(answer), 'consistent_with_goal')
        self.assertIsNone(answer['uncalibrated_risk_score'])
        self.assertEqual(answer['cited_evidence_ids'], ['read', 'send'])
        self.assertEqual(answer['response'], response())
        self.assertNotIn('Authorization', dict(calls[0].header_items()))
        self.assertNotIn('observer-only', json.dumps(answer))
        request = json.loads(calls[0].data)
        self.assertTrue(request['response_format']['json_schema']['strict'])
        self.assertEqual(request['reasoning_effort'], 'none')

    def test_mismatched_model_and_response_budget_are_unavailable(self):
        answer, _ = self.invoke(response(model='another-model'))
        self.assertEqual(answer['reason'], 'returned_model_mismatch')
        answer, _ = self.invoke(b' ' * (MAX_RESPONSE_BYTES + 1))
        self.assertEqual(answer['reason'], 'response_exceeds_budget')

    def test_malformed_refused_truncated_and_invented_answers_are_unavailable(self):
        for mode in ['length', 'refused', 'invented', 'extra', 'duplicate', 'blank', 'tool']:
            result = response()
            message = result['choices'][0]['message']
            answer = json.loads(message['content'])
            if mode == 'length': result['choices'][0]['finish_reason'] = 'length'
            if mode == 'refused': message['refusal'] = 'refusal'
            if mode == 'invented': answer['evidence_ids'] = ['missing']
            if mode == 'extra': answer['score'] = 0.99
            if mode == 'blank': answer['rationale'] = ' '
            if mode == 'tool': message['tool_calls'] = [{'id': 'tool'}]
            message['content'] = json.dumps(answer)
            if mode == 'duplicate': message['content'] = '{"disposition":"review_required","disposition":"consistent_with_goal","evidence_ids":["E1"],"rationale":"text"}'
            with self.subTest(mode=mode):
                result, _ = self.invoke(result)
                self.assertEqual(result['status'], 'unavailable')

    def test_required_missing_evidence_prevents_network_request(self):
        p = packet();p['consequential_evidence_ids'].append('missing')
        answer, calls = self.invoke(response(), p)
        self.assertEqual(answer['reason'], 'missing_consequential_evidence')
        self.assertEqual(calls, [])

    def test_nonfinite_wire_json_is_not_persisted_as_valid(self):
        for wire in [b'{"model":"qwen/qwen3.8-27b","usage":NaN}',
                     b'{"model":"another-model","model":"qwen/qwen3.8-27b"}']:
            with self.subTest(wire=wire):
                answer, _ = self.invoke(wire)
                self.assertEqual(answer['status'], 'unavailable')

    def test_safe_redaction_preserves_json_structure(self):
        x = response();content = json.loads(x['choices'][0]['message']['content'])
        content['rationale'] = 'API_KEY=private-value observed in metadata'
        x['choices'][0]['message']['content'] = json.dumps(content)
        answer, _ = self.invoke(x)
        self.assertNotIn('private-value', json.dumps(answer))
        self.assertEqual(answer['status'], 'assessed')

    def test_base_url_normalization_and_codex_flags(self):
        self.assertEqual(endpoint('http://127.0.0.1:1234/api/v1'), 'http://127.0.0.1:1234/v1/chat/completions')
        for url in ['http://secret:password@localhost:1234', 'http://localhost:1234?token=private', 'file:///tmp/input']:
            with self.assertRaises(ValueError): endpoint(url)
        options = _parse_run(['--goal', 'Test', '--judge-url', 'http://localhost:1234/api/v1', '--judge-model', 'qwen/qwen3.8-27b', 'codex', 'exec', '--config', 'model="agent"'])
        self.assertEqual(options[2], ['exec', '--config', 'model="agent"'])
        self.assertEqual(options[6]['model'], 'qwen/qwen3.8-27b')

    def test_new_settings_are_observer_only(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {}, clear=True):
            file = Path(folder) / '.env'
            file.write_text('TRACEWARD_JUDGE_PROVIDER=lmstudio\nTRACEWARD_JUDGE_MODEL=qwen/qwen3.8-27b\nTRACEWARD_JUDGE_TOKEN=private\n')
            load_observer_env(file)
            self.assertEqual(os.environ['TRACEWARD_JUDGE_MODEL'], 'qwen/qwen3.8-27b')

    def test_engine_structured_verdict_retains_complete_episode_guards(self):
        # Reuse the real correlation fixture, not a second model implementation.
        helper = assessments.AssessmentTests()
        try:
            answer, _ = self.invoke(response())
            _, findings, _ = helper.episode(answer)
            self.assertEqual(findings[-1]['status'], 'consistent_with_goal')
            self.assertIsNone(findings[-1]['uncalibrated_risk_score'])
            _, findings, _ = helper.episode(answer, post=False)
            self.assertEqual(findings[-1]['status'], 'inconclusive')
            _, findings, _ = helper.episode(answer, ambiguous=True)
            self.assertEqual(findings[-1]['status'], 'inconclusive')
        finally:
            helper.doCleanups()
