"""Linux wrapper smoke test with a fake Codex executable (not hook coverage)."""

from __future__ import annotations

import json
import os
import pty
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("strace"), "Linux with strace")
class LinuxCliTests(unittest.TestCase):
    def test_exit_status_and_codex_flag_passthrough(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            stub = bin_dir / "codex"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "open(os.environ['TRACEWARD_STUB_ARGS'], 'w').write(json.dumps(sys.argv[1:]))\n"
                "open(os.environ['TRACEWARD_TOKEN_SEEN'], 'w').write(str('UNSLOTH_TOKEN' in os.environ))\n"
                "raise SystemExit(7)\n", encoding="utf-8")
            stub.chmod(0o755)
            root_package = Path(__file__).resolve().parents[1] / "src"
            env = {**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                   "PYTHONPATH": str(root_package), "XDG_STATE_HOME": str(root / "state"),
                   "TRACEWARD_STUB_ARGS": str(root / "args.json"),
                   "TRACEWARD_TOKEN_SEEN": str(root / "token_seen"),
                   "UNSLOTH_TOKEN": "SYNTHETIC_TOKEN"}
            result = subprocess.run([sys.executable, "-m", "traceward.cli", "run", "--goal",
                                     "Fix tests", "codex", "exec", "--skip-git-repo-check", "hello"],
                                    env=env, cwd=root, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 7, result.stderr)
            args = json.loads((root / "args.json").read_text())
            self.assertEqual((root / "token_seen").read_text(), "False")
            self.assertEqual(args[-3:], ["exec", "--skip-git-repo-check", "hello"])
            summaries = list((root / "state" / "traceward" / "runs").glob("*/summary.json"))
            self.assertEqual(len(summaries), 1)
            summary = json.loads(summaries[0].read_text())
            self.assertEqual(summary["codex_exit_code"], 7)
            self.assertTrue(any("no Codex hooks" in gap for gap in summary["coverage_gaps"]))

    def test_tty_reaches_codex(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "codex"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "open(os.environ['TRACEWARD_TTY_RESULT'], 'w').write(json.dumps([sys.stdin.isatty(), sys.stdout.isatty(), sys.stderr.isatty()]))\n",
                encoding="utf-8")
            stub.chmod(0o755)
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                   "XDG_STATE_HOME": str(root / "state"),
                   "TRACEWARD_TTY_RESULT": str(root / "tty.json")}
            with os.fdopen(slave, "rb+", buffering=0) as terminal:
                process = subprocess.Popen([sys.executable, "-m", "traceward.cli", "run",
                                            "--goal", "Observe", "codex"], cwd=root, env=env,
                                           stdin=terminal, stdout=terminal, stderr=terminal)
                self.assertEqual(process.wait(timeout=20), 0)
            self.assertEqual(json.loads((root / "tty.json").read_text()), [True, True, True])

    def test_sigterm_reaches_codex(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "codex"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import os, signal, sys, time\n"
                "def stop(*_):\n"
                "    open(os.environ['TRACEWARD_TERM_RESULT'], 'w').write('received')\n"
                "    raise SystemExit(0)\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                "open(os.environ['TRACEWARD_READY'], 'w').write(str(os.getpid()))\n"
                "time.sleep(30)\n", encoding="utf-8")
            stub.chmod(0o755)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                   "XDG_STATE_HOME": str(root / "state"),
                   "TRACEWARD_READY": str(root / "ready"),
                   "TRACEWARD_TERM_RESULT": str(root / "terminated")}
            process = subprocess.Popen([sys.executable, "-m", "traceward.cli", "run",
                                        "--goal", "Observe", "codex"], cwd=root, env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(lambda: process.poll() is None and process.kill())
            deadline = time.monotonic() + 10
            while not (root / "ready").exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue((root / "ready").exists())
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
            self.assertTrue((root / "terminated").exists(), "Codex did not receive SIGTERM")
