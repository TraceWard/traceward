"""Deterministic typed-answer fixture, NOT the Laya model.

Use only to demonstrate revisions while Unsloth is unavailable. The dashboard
labels its model name as demo-deterministic-evaluator.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Evaluator(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/systemone":
            self.send_error(404)
            return
        size = min(int(self.headers.get("Content-Length", "0")), 100_000)
        request = json.loads(self.rfile.read(size))
        state = json.loads(request.get("state", "{}"))
        action = state.get("apparent_action", "")
        finding = state.get("finding", "")
        legitimate = state.get("authorised_goal", "").startswith(
            "Verify that the synthetic credential reaches the local fixture receiver"
        )
        mismatch = (0 if legitimate else 4 if action == "npm test" or
                    "Sensitive file modified" in finding else 3 if "Network side effect" in finding else 2)
        body = json.dumps({"answers": {
            "goal_relevance": {"score": 4 if legitimate else 0},
            "unexplained_side_effect": {"noul": 0 if legitimate else 1},
            "account_effect_mismatch": {"score": mismatch},
        }}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


HTTPServer(("127.0.0.1", 8888), Evaluator).serve_forever()
