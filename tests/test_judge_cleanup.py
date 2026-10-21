"""Structured inference and explicit simulation remain separate after cleanup."""
import json
import os
import unittest
from unittest.mock import patch

from demo.evaluator import fixture_answer
from traceward.cli import _parse_run
from traceward.evidence_packet import packet
from traceward.judges import generative_judge, judge


class JudgeCleanupTests(unittest.TestCase):
    def evidence(self, goal, live):
        finding = {'title': 'Synthetic read', 'attribution': 'hook-resource-time', 'episode_complete': True,
                   'consequential_evidence_ids': ['read']}
        result = packet(goal, finding, [{'event_id': 'read', 'kind': 'file_read', 'time': 1,
            'pid': 1, 'path': '/workspace/synthetic-credential.txt', 'bytes': 42}], [])
        result.update(packet_version=3, live_window=live)
        return result

    def test_simulator_emits_valid_live_and_detailed_answers_with_explicit_provenance(self):
        class Reply:
            def __init__(self, body): self.body = body
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, size): return json.dumps(self.body).encode()[:size]
        def post(request, **options):
            body = json.loads(request.data)
            answer = fixture_answer(body)
            return Reply({'model': 'demo-deterministic-evaluator', 'choices': [{'finish_reason': 'stop',
                          'message': {'content': json.dumps(answer)}}]})
        for live in (False, True):
            for authorised in (False, True):
                goal = ('Verify that the synthetic credential reaches the local fixture receiver'
                        if authorised else 'Diagnose the arithmetic test')
                with self.subTest(live=live, authorised=authorised), patch('traceward.judges.urlopen', post):
                    result = generative_judge(self.evidence(goal, live), model='demo-deterministic-evaluator')
                self.assertEqual(result['status'], 'assessed', result.get('validation_error'))
                self.assertEqual(result['evaluation_source'], 'simulated')
                self.assertEqual(result['disposition'], 'consistent_with_goal' if authorised else 'review_required')
                self.assertEqual(result['cited_evidence_ids'], ['read'])
        with self.assertRaises(ValueError): fixture_answer({'model': 'real-model'})

    def test_only_the_configured_judge_token_is_sent_and_never_persisted(self):
        calls = []
        def post(request, **options):
            calls.append(request)
            raise TimeoutError()
        with patch.dict(os.environ, {'TRACEWARD_JUDGE_TOKEN': 'synthetic-observer-token'}, clear=True), \
             patch('traceward.judges.urlopen', post):
            result = generative_judge(self.evidence('Read the fixture', True))
        self.assertEqual(calls[0].get_header('Authorization'), 'Bearer synthetic-observer-token')
        self.assertNotIn('synthetic-observer-token', json.dumps(result))

    def test_unsupported_provider_fails_without_a_fallback_or_runtime_launch(self):
        with patch('traceward.judges.urlopen') as post:
            self.assertEqual(judge({}, provider='retired-provider')['reason'], 'unsupported_judge_provider')
            post.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'judge provider must be lmstudio'):
            _parse_run(['--goal', 'Inspect files', '--judge-provider', 'retired-provider', 'codex'])
