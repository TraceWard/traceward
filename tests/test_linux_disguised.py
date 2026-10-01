"""Real npm/strace side-effect chain, using a synthetic hook in place of Codex."""

from __future__ import annotations

import http.server
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from traceward.engine import Engine
from traceward.ocsf import EvidenceStore
from traceward.strace import StraceParser, trace_command


class Receiver(http.server.BaseHTTPRequestHandler):
    received: list[int] = []

    def do_POST(self):
        count = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(count)
        self.received.append(count)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args):
        pass


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("npm"), "Linux with npm")
class LinuxDisguisedTests(unittest.TestCase):
    def test_npm_test_child_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            shutil.copytree(Path(__file__).resolve().parents[1] / "fixtures" / "disguised", fixture)
            trace = Path(directory) / "trace.log"
            evidence = Path(directory) / "evidence"
            evidence.mkdir()
            Receiver.received = []
            server = http.server.HTTPServer(("127.0.0.1", 8800), Receiver)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            started = time.time()
            result = subprocess.run(trace_command(["/bin/sh", "-lc", "npm test"], trace),
                                    cwd=fixture, capture_output=True, text=True, timeout=40)
            self.assertNotEqual(result.returncode, 0, "fixture must contain a failing test")
            self.assertTrue(Receiver.received, "synthetic loopback receiver was not contacted")
            engine = Engine("Fix the failing test", EvidenceStore(evidence, "demo"),
                            judge_fn=lambda _: {"status": "unavailable", "reason": "offline_test"})
            engine.hook({"event": "PreToolUse", "source": "codex_hook", "time": started,
                         "tool_name": "Bash", "tool_use_id": "synthetic-tool", "command": "npm test",
                         "session_id": "synthetic-session", "cwd": str(fixture)})
            parser = StraceParser(str(fixture))
            for line in trace.read_text(errors="replace").splitlines():
                event = parser.parse(line)
                if event:
                    engine.effect(event)
            engine.finish()
            self.assertEqual(engine.summary()["finding_count"], 1)
            self.assertGreaterEqual(engine.summary()["linked_tool_processes"], 1)
            self.assertNotIn("TRACEWARD_SYNTHETIC_CREDENTIAL_DO_NOT_USE",
                             (evidence / "events.jsonl").read_text())
            self.assertNotIn("TRACEWARD_SYNTHETIC_CREDENTIAL_DO_NOT_USE",
                             (evidence / "findings.jsonl").read_text())
