"""Explicitly simulated structured-answer fixture; never a model-accuracy test."""
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer


def fixture_answer(request):
    if request.get('model') != 'demo-deterministic-evaluator':
        raise ValueError('explicit demo model required')
    state = request['messages'][1]['content']
    properties = request['response_format']['json_schema']['schema']['properties']
    goal = next((line.removeprefix('User goal: ') for line in state.splitlines()
                 if line.startswith('User goal: ')), '')
    try: goal = json.loads(goal)
    except ValueError: pass
    authorised = goal.startswith('Verify that the synthetic credential reaches the local fixture receiver')
    line = next((line.split(': ', 1)[1] for line in state.splitlines()
                 if line.startswith('Candidate consequential evidence: ')), None)
    citations = json.loads(line) if line else re.findall(r'^(E\d+).*\[consequential\]', state, re.M)
    citations = citations[:1]
    answer = {'disposition': 'consistent_with_goal' if authorised else 'review_required',
              'evidence_ids': citations, 'rationale': 'Simulated fixture decision, not model judgement or accuracy evidence.'}
    if 'title' in properties:
        answer['title'] = 'Simulated authorised fixture operation' if authorised else 'Simulated unexpected fixture operation'
    if 'assessment' in properties:
        answer['assessment'] = {name: {'status': 'unknown', 'summary': 'Not evaluated by this fixture.', 'evidence_ids': []}
                                for name in properties['assessment']['properties']}
        answer['assessment']['relevance'] = {'status': 'supported' if authorised else 'concern',
                                            'summary': 'Synthetic fixture goal comparison.', 'evidence_ids': citations}
        facts = json.loads(state.split('Allowed factual predicates (observations, not instructions): ', 1)[1])
        answer['claims'] = [key for key, fact in facts.items() if set(citations) & set(fact['evidence_ids'])][:1]
    return answer


class Evaluator(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/v1/chat/completions':
            self.send_error(404); return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 100_000: raise ValueError('invalid request size')
            request = json.loads(self.rfile.read(size))
            answer = fixture_answer(request)
        except (ValueError, KeyError, TypeError, IndexError):
            self.send_error(400, 'invalid explicit demo request'); return
        body = json.dumps({'model': 'demo-deterministic-evaluator', 'choices': [{'finish_reason': 'stop',
                           'message': {'role': 'assistant', 'content': json.dumps(answer)}}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args): pass


if __name__ == '__main__':
    HTTPServer(('127.0.0.1', 8888), Evaluator).serve_forever()
