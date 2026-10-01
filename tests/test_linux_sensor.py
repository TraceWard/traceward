"""An actual Linux ptrace smoke test, separate from deterministic parser fixtures."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from traceward.strace import StraceParser, trace_command
from traceward.engine import Engine
from traceward.ocsf import EvidenceStore


def child(credential: str, port: int, pause: float = 0) -> None:
    with open(credential, "rb") as stream:
        body = stream.read()
    with socket.create_connection(("127.0.0.1", port)) as connection:
        connection.sendall(body)
    if pause:
        time.sleep(pause)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux strace test")
class LinuxSensorTests(unittest.TestCase):
    def test_real_file_read_and_loopback_send(self):
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "synthetic-credential.txt"
            credential.write_text("TRACEWARD_SYNTHETIC_ONLY\n", encoding="utf-8")
            trace = Path(directory) / "trace.log"
            server = socket.socket()
            self.addCleanup(server.close)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            received: list[bytes] = []

            def accept() -> None:
                connection, _ = server.accept()
                with connection:
                    received.append(connection.recv(1024))

            receiver = threading.Thread(target=accept, daemon=True)
            receiver.start()
            command = [sys.executable, str(Path(__file__).resolve()), "--child", str(credential), str(port)]
            result = subprocess.run(trace_command(command, trace), capture_output=True, text=True, timeout=20)
            receiver.join(timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(received, [b"TRACEWARD_SYNTHETIC_ONLY\n"])
            parser = StraceParser(directory)
            effects = [event for line in trace.read_text(errors="replace").splitlines()
                       if (event := parser.parse(line))]
            self.assertTrue(any(event["kind"] == "file_read" and
                                event["path"] == str(credential) for event in effects))
            self.assertTrue(any(event["kind"] == "network_send" and
                                event["endpoint"] == f"127.0.0.1:{port}" for event in effects))
            self.assertNotIn("TRACEWARD_SYNTHETIC_ONLY", trace.read_text(errors="replace"))

    def test_provisional_alert_before_child_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "synthetic-credential.txt"
            credential.write_text("TRACEWARD_SYNTHETIC_ONLY\n", encoding="utf-8")
            trace = Path(directory) / "trace.log"
            evidence = Path(directory) / "evidence"
            evidence.mkdir()
            server = socket.socket()
            self.addCleanup(server.close)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            def accept() -> None:
                connection, _ = server.accept()
                with connection:
                    connection.recv(1024)

            threading.Thread(target=accept, daemon=True).start()
            command = f'{sys.executable} {Path(__file__).resolve()} --child {credential} {port} --sleep'
            alerts: list[dict] = []
            engine = Engine("Fix the failing test", EvidenceStore(evidence, "live"),
                            judge_fn=lambda _: {"status": "unavailable", "reason": "offline_test"},
                            alert_fn=alerts.append)
            engine.hook({"event": "PreToolUse", "source": "codex_hook", "time": time.time(),
                         "tool_name": "Bash", "tool_use_id": "live-tool", "command": command})
            child_process = subprocess.Popen(trace_command(["/bin/sh", "-c", command], trace),
                                             cwd=directory, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.PIPE, text=True,
                                             env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")})
            self.addCleanup(child_process.stderr.close)
            self.addCleanup(lambda: child_process.poll() is None and child_process.kill())
            parser = StraceParser(directory)
            offset, pending = 0, ""
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and not alerts:
                if trace.exists():
                    with trace.open(errors="replace") as stream:
                        stream.seek(offset)
                        chunk = stream.read()
                        offset = stream.tell()
                    parts = (pending + chunk).split("\n")
                    pending = parts[-1]
                    for line in parts[:-1]:
                        event = parser.parse(line)
                        if event:
                            engine.effect(event)
                time.sleep(0.05)
            self.assertTrue(alerts, f"no provisional alert while traced process was active: "
                            f"{engine.summary()}, parser_unparsed={parser.unparsed}, "
                            f"effect_kinds={[event['kind'] for event in engine.effects][-12:]}, "
                            f"child_poll={child_process.poll()}, child_stderr={child_process.stderr.read() if child_process.poll() is not None else ''}, "
                            f"trace_tail={trace.read_text(errors='replace')[-1500:]}")
            self.assertIsNone(child_process.poll(), "finding came only after child exited")
            self.assertLessEqual(engine.first_alert_latency, 10)
            child_process.wait(timeout=8)
            engine.finish()


if __name__ == "__main__" and len(sys.argv) >= 4 and sys.argv[1] == "--child":
    child(sys.argv[2], int(sys.argv[3]), 3 if "--sleep" in sys.argv else 0)
