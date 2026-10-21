"""Capture preserves streamed traffic while bounding and redacting evidence."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from traceward_pi.http_capture import Capture,LIMIT
from traceward.ocsf import project
from traceward.laya import packet,model_input
from traceward.structured import factual_predicates


class HttpCaptureTests(unittest.TestCase):
    def test_request_response_content_is_bounded_redacted_and_keeps_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'http.jsonl'; capture=Capture(path)
            request=SimpleNamespace(method='POST',pretty_url='https://user:password@example.com/upload?token=secret&x=ok',
                host='example.com',port=443,scheme='https',http_version='HTTP/1.1',raw_content=None,
                headers={'content-type':'application/json','Authorization':'Bearer private-value','Cookie':'session=secret'})
            response=SimpleNamespace(status_code=200,headers={'content-type':'text/plain','set-cookie':'private'},raw_content=None)
            flow=SimpleNamespace(id='request-1',request=request,response=response,
                                 client_conn=SimpleNamespace(peername=('127.0.0.1',40000)),metadata={})
            capture.requestheaders(flow)
            body=b'{"password":"body-secret","message":"synthetic hello"}'
            self.assertEqual(request.stream(body),body)
            request.stream(b'');capture.request(flow)
            capture.responseheaders(flow)
            content=b'response '+b'x'*(LIMIT+50)
            self.assertEqual(response.stream(content),content)
            response.stream(b'');capture.response(flow)
            text=path.read_text()
            for secret in ['body-secret','private-value','session=secret','user:password','token=secret']:
                self.assertNotIn(secret,text)
            events=[json.loads(line) for line in text.splitlines()]
            self.assertEqual(events[0]['method'],'POST')
            self.assertIn('synthetic hello',events[0]['request_body']['excerpt'])
            self.assertEqual(events[0]['request_body']['bytes'],len(body))
            self.assertTrue(events[1]['response_body']['truncated'])
            self.assertLessEqual(len(events[1]['response_body']['excerpt']),LIMIT+1)
            self.assertEqual(events[1]['status_code'],200)
            event={**events[0],'event_id':'http-1'}
            record=project('http_request',event,'r')
            self.assertEqual(record['unmapped']['traceward']['details']['method'],'POST')
            p=packet('No network',{'title':'HTTP request','attribution':'uncertain','consequential_evidence_ids':['http-1']},[event],[])
            self.assertIn('POST',model_input(p)['state'])
            facts=factual_predicates(p['evidence'],{'E1':'http-1'},['http-1'])
            self.assertTrue(facts)

    def test_encoded_body_is_counted_without_a_misleading_text_excerpt(self):
        with tempfile.TemporaryDirectory() as directory:
            capture=Capture(Path(directory)/'http.jsonl')
            message=SimpleNamespace(headers={'content-type':'application/json','content-encoding':'gzip'},
                                    raw_content=b'compressed bytes')
            body=capture._body(SimpleNamespace(metadata={}), 'missing',message)
            self.assertIsNone(body['excerpt'])
            self.assertEqual(body['excerpt_omitted_reason'],'encoded_body')
            self.assertEqual(body['bytes'],len(message.raw_content))
