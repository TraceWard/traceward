"""Whole-run activity counts, bounded buckets and evidence-backed finding bands."""
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from traceward.dashboard import RunIndex, create_app
from traceward.ocsf import EvidenceStore
try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None


@unittest.skipIf(TestClient is None, 'install dashboard optional dependencies')
class ActivityTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);runs=root/'runs';self.identity=str(uuid.uuid4())
        self.folder=runs/self.identity;self.folder.mkdir(parents=True)
        (self.folder/'run.json').write_text(json.dumps({'goal':'Observe activity','started_at':100,'heartbeat_at':0}))
        self.store=EvidenceStore(self.folder,self.identity)
        self.index=RunIndex(runs,root/'index.sqlite');self.addCleanup(self.index.db.close)
        self.client=TestClient(create_app(self.index),base_url='http://127.0.0.1:8765');self.addCleanup(self.client.close)

    def activity(self, interval=1):
        response=self.client.get(f'/api/runs/{self.identity}/activity?interval={interval}')
        self.assertEqual(response.status_code,200)
        return response.json()

    def review(self, **extra):
        item={'finding_id':'finding','revision':1,'time':500,'title':'Unexpected effect',
              'message':'Synthetic regression','status':'review_required','evidence_ids':['read'], **extra}
        self.store.assessment(item)
        return item

    def test_counts_all_events_beyond_the_evidence_page_and_excludes_assessment_records(self):
        for i in range(500):
            self.store.event('file_read',dict(event_id=f'read-{i}',time=100+i/100,pid=1,path='/workspace/file',bytes=1))
        self.review(evidence_ids=['read-0'])
        page=self.client.get(f'/api/runs/{self.identity}/events?limit=250').json()['events']
        self.assertEqual(len(page),250)
        activity=self.activity()
        self.assertEqual(activity['total_events'],500)
        self.assertEqual(sum(b['counts'].get('file_read',0) for b in activity['buckets']),500)

    def test_highlights_assessed_window_instead_of_delayed_model_response_time(self):
        for i in range(10):self.store.event('file_read',dict(event_id='read' if i==0 else f'r{i}',time=100+i,pid=1,path='/workspace/file',bytes=1))
        item=self.review(analysis_window={'start':100,'end':102})
        data=self.activity();marked=[b for b in data['buckets'] if b['finding_ids']]
        self.assertEqual([b['start'] for b in marked],[100000,101000,102000])
        self.assertEqual(data['findings'][0]['source'],'assessment_window')
        self.store.assessment({**item,'revision':2,'status':'consistent_with_goal'})
        self.assertFalse(any(b['finding_ids'] for b in self.activity()['buckets']))

    def test_older_review_uses_cited_event_times_and_live_appends_refresh_counts(self):
        self.store.event('file_read',dict(event_id='read',time=100,pid=1,path='/workspace/file',bytes=1))
        self.review()
        self.assertEqual(self.activity()['findings'][0]['start'],100000)
        self.store.event('http_request',dict(event_id='http',time=105,method='GET',phase='request',url='https://example.com/'))
        self.store.event('http_request',dict(event_id='response',time=105,method='GET',phase='response',status_code=200))
        data=self.activity()
        self.assertEqual(data['total_events'],3)
        self.assertEqual(data['buckets'][-1]['counts']['http_request'],2)

    def test_multi_day_run_returns_bounded_histogram_even_for_requested_one_second_bins(self):
        for when in [100,100+86400*3]:
            self.store.event('process',dict(event_id=str(when),time=when,pid=1,name='worker'))
        data=self.activity()
        self.assertLessEqual(len(data['buckets']),240)
        self.assertEqual(data['total_events'],2)
        self.assertGreater(data['interval_seconds'],1)

    def test_empty_data_and_parameter_validation(self):
        self.assertEqual(self.activity()['buckets'],[])
        self.assertEqual(self.client.get(f'/api/runs/{self.identity}/activity?interval=0').status_code,422)
        self.assertEqual(self.client.get('/api/runs/invalid/activity').status_code,404)
