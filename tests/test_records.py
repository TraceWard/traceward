"""Neutral result names preserve historical evidence and provenance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from traceward.dashboard import RunIndex
from traceward.ocsf import EvidenceStore
from traceward.records import assessment_record


class RecordTests(unittest.TestCase):
    def test_historical_result_is_normalized_without_mutating_the_source(self):
        result = {'status': 'scored', 'model': 'historical-checkpoint', 'dimensions': {'goal_relevance': .2}}
        original = {'finding_id': 'f', 'retired_provider': result, 'title': 'Historical finding'}
        before = copy.deepcopy(original)
        normalized = assessment_record(original)
        self.assertEqual(normalized['judge'], result)
        self.assertNotIn('retired_provider', normalized)
        self.assertEqual(original, before)

    def test_explicit_result_wins_and_ambiguous_or_invalid_slots_are_not_guessed(self):
        old = {'status': 'unavailable', 'reason': 'historical outage'}
        current = {'status': 'assessed', 'model': 'current-checkpoint'}
        self.assertEqual(assessment_record({'judge': current, 'retired_provider': old})['judge'], current)
        self.assertEqual(assessment_record({'one': old, 'two': current})['judge']['reason'], 'ambiguous_historical_judgement')
        self.assertEqual(assessment_record({'judge': None})['judge']['reason'], 'invalid_judge_record')
        self.assertEqual(assessment_record({'unknown': {'status': []}}), {'unknown': {'status': []}})

    def test_dashboard_reads_historical_revisions_without_rewriting_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); identity = '11111111-1111-4111-8111-111111111111'
            folder = root/'runs'/identity; folder.mkdir(parents=True)
            (folder/'run.json').write_text(json.dumps({'goal': 'Historical run', 'source': 'codex'}))
            store = EvidenceStore(folder, identity)
            finding = {'finding_id': 'f', 'revision': 1, 'time': 1, 'title': 'Historical review',
                'message': 'Preserved evidence', 'status': 'review_required', 'evidence_ids': [],
                'retired_provider': {'status': 'scored', 'model': 'historical-checkpoint'}}
            store.assessment(finding)
            before = {p.name: p.read_bytes() for p in folder.glob('*.jsonl')}
            index = RunIndex(root/'runs', root/'index.sqlite')
            try:
                index.refresh()
                current = index.findings(identity)[0]
                self.assertEqual(current['judge']['model'], 'historical-checkpoint')
                self.assertEqual(current['revisions'][0]['judge']['status'], 'scored')
                self.assertEqual(index.run(identity)['evaluation_label'], 'Model assessed')
                self.assertEqual(before, {p.name: p.read_bytes() for p in folder.glob('*.jsonl')})
            finally: index.db.close()
