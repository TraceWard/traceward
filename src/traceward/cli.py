"""One-command Codex wrapper and live finding watcher."""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from .engine import Engine
from .ocsf import EvidenceStore
from .strace import StraceParser, trace_command


def state_root() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "traceward" / "runs"


def _usage() -> str:
    return (
        "usage: traceward run [--goal TEXT | --goal-file PATH] [--laya-url URL] codex [CODEX FLAGS...]\n"
        "       traceward watch RUN_ID\n"
        "       traceward replay --goal TEXT --hooks FILE --trace FILE"
    )


def _parse_run(args: list[str]) -> tuple[str, str | None, list[str]]:
    goal = goal_file = laya_url = None
    index = 0
    while index < len(args) and args[index] != "codex":
        flag = args[index]
        if flag not in {"--goal", "--goal-file", "--laya-url"} or index + 1 >= len(args):
            raise ValueError(_usage())
        value = args[index + 1]
        if flag == "--goal":
            goal = value
        elif flag == "--goal-file":
            goal_file = value
        else:
            laya_url = value
        index += 2
    if index >= len(args) or args[index] != "codex":
        raise ValueError(_usage())
    if goal and goal_file:
        raise ValueError("choose --goal or --goal-file, not both")
    if goal_file:
        goal = Path(goal_file).read_text(encoding="utf-8").strip()
    if not goal:
        if sys.stdin.isatty():
            goal = input("Authorised goal for this run: ").strip()
        else:
            raise ValueError("a non-interactive run requires --goal or --goal-file")
    if not goal:
        raise ValueError("goal cannot be empty")
    return goal, laya_url, args[index + 1:]


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _hook_overrides() -> list[str]:
    package_root = str(Path(__file__).resolve().parents[1])
    hook_path = package_root + os.pathsep + os.environ.get("PYTHONPATH", "")
    command = f"PYTHONPATH={shlex.quote(hook_path)} {shlex.quote(sys.executable)} -m traceward.hook_sink"
    handler = f'{{type="command",command={_toml_string(command)},timeout=5}}'
    return [
        "-c", f"hooks.SessionStart=[{{hooks=[{handler}]}}]",
        "-c", f'hooks.PreToolUse=[{{matcher="Bash|apply_patch",hooks=[{handler}]}}]',
        "-c", f'hooks.PostToolUse=[{{matcher="Bash|apply_patch",hooks=[{handler}]}}]',
    ]


def _tail_lines(path: Path, offset: int, pending: str) -> tuple[list[str], int, str]:
    if not path.exists():
        return [], offset, pending
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        stream.seek(offset)
        chunk = stream.read()
        offset = stream.tell()
    content = pending + chunk
    parts = content.split("\n")
    return parts[:-1], offset, parts[-1]


def _preflight() -> None:
    if platform.system() != "Linux":
        raise RuntimeError("the PoC runtime sensor supports Linux only; no Codex process was started")
    if not shutil.which("strace"):
        raise RuntimeError("strace is required on Linux; no Codex process was started")
    if not shutil.which("codex"):
        raise RuntimeError("codex is not on PATH; no agent process was started")
    with tempfile.TemporaryDirectory(prefix="traceward-preflight-") as tmp:
        trace = Path(tmp) / "trace.log"
        probe = subprocess.run(trace_command(["/bin/true"], trace), capture_output=True, text=True)
        if probe.returncode or not trace.exists() or "execve" not in trace.read_text(errors="replace"):
            raise RuntimeError("strace cannot follow a child here; check ptrace/seccomp settings")


def _safe_run_dir(run_id: str) -> Path:
    try:
        parsed = uuid.UUID(run_id)
    except ValueError as exc:
        raise ValueError("run ID must be a UUID") from exc
    return state_root() / str(parsed)


def _signal_tree(tracer_pid: int, signum: int) -> None:
    """Forward an operator signal to tracees before signalling strace itself."""
    pending = [tracer_pid]
    descendants: list[int] = []
    seen: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        children_file = Path(f"/proc/{pid}/task/{pid}/children")
        try:
            children = [int(value) for value in children_file.read_text().split()]
        except (OSError, ValueError):
            continue
        descendants.extend(children)
        pending.extend(children)
    for pid in reversed(descendants):
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass
    try:
        os.kill(tracer_pid, signum)
    except ProcessLookupError:
        pass


def run(args: list[str]) -> int:
    goal, laya_url, codex_args = _parse_run(args)
    _preflight()
    run_id = str(uuid.uuid4())
    run_dir = _safe_run_dir(run_id)
    run_dir.mkdir(parents=True, mode=0o700)
    run_dir.chmod(0o700)
    hook_file = run_dir / "hooks.jsonl"
    trace_file = run_dir / "raw.strace"
    for file in (hook_file, trace_file):
        file.touch(mode=0o600)
        file.chmod(0o600)
    env = os.environ.copy()
    # The model endpoint credential belongs to the observer, not the agent.
    env.pop("UNSLOTH_TOKEN", None)
    env["TRACEWARD_RUN_ID"] = run_id
    env["TRACEWARD_HOOK_FILE"] = str(hook_file)
    if laya_url:
        env["TRACEWARD_LAYA_URL"] = laya_url
    # This preserves the user's CODEX_HOME and therefore the existing login.
    cmd = ["codex", *_hook_overrides(), *codex_args]
    store = EvidenceStore(run_dir, run_id)
    is_interactive = sys.stdout.isatty()

    def alert(finding: dict) -> None:
        if not is_interactive:
            print(f"[TraceWard] finding {finding['finding_id']} r{finding['revision']}: "
                  f"{finding['title']}", file=sys.stderr, flush=True)

    engine = Engine(goal, store, alert_fn=alert)
    parser = StraceParser(os.getcwd())
    print(f"TraceWard run {run_id} — evidence: {run_dir}", file=sys.stderr, flush=True)
    if is_interactive:
        print(f"Live findings: traceward watch {run_id} (in another terminal)", file=sys.stderr, flush=True)
    started = time.monotonic()
    child = subprocess.Popen(trace_command(cmd, trace_file), env=env)
    trace_pos = hook_pos = 0
    trace_pending = hook_pending = ""
    warned_hooks = False
    stopping = False

    def on_term(signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        if child.poll() is None:
            _signal_tree(child.pid, signum)

    old_term = signal.signal(signal.SIGTERM, on_term)
    try:
        while child.poll() is None or not stopping:
            trace_lines, trace_pos, trace_pending = _tail_lines(trace_file, trace_pos, trace_pending)
            hook_lines, hook_pos, hook_pending = _tail_lines(hook_file, hook_pos, hook_pending)
            for line in hook_lines:
                try:
                    item = json.loads(line)
                except ValueError:
                    engine.add_gap("malformed hook record")
                    continue
                if item.get("run_id") == run_id:
                    engine.hook(item)
            for line in trace_lines:
                effect = parser.parse(line)
                if effect:
                    engine.effect(effect)
            if child.poll() is not None:
                break
            if not warned_hooks and time.monotonic() - started > 15 and not engine.counts.get("hook"):
                warned_hooks = True
                print("TraceWard warning: no Codex hook has fired; check hook trust with /hooks. "
                      "Combined coverage is not yet established.", file=sys.stderr, flush=True)
            time.sleep(0.1)
        # Allow final hook/trace writes to drain after the child exits.
        for _ in range(5):
            trace_lines, trace_pos, trace_pending = _tail_lines(trace_file, trace_pos, trace_pending)
            hook_lines, hook_pos, hook_pending = _tail_lines(hook_file, hook_pos, hook_pending)
            for line in hook_lines:
                try:
                    item = json.loads(line)
                    if item.get("run_id") == run_id:
                        engine.hook(item)
                except ValueError:
                    engine.add_gap("malformed hook record")
            for line in trace_lines:
                effect = parser.parse(line)
                if effect:
                    engine.effect(effect)
            time.sleep(0.05)
    except KeyboardInterrupt:
        if child.poll() is None:
            _signal_tree(child.pid, signal.SIGINT)
    finally:
        signal.signal(signal.SIGTERM, old_term)
    exit_code = child.wait()
    if parser.unparsed:
        engine.add_gap(f"{parser.unparsed} strace lines were not parsed")
    engine.finish()
    summary = engine.summary()
    summary.update({"run_id": run_id, "codex_exit_code": exit_code,
                    "wall_seconds": round(time.monotonic() - started, 3),
                    "unparsed_strace_lines": parser.unparsed,
                    "source_event_loss": "unknown; strace text has no loss counter",
                    "runtime_overhead": "not measured without a comparable untraced Codex run"})
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (run_dir / "summary.json").chmod(0o600)
    print(f"TraceWard: {summary['finding_count']} finding(s), {len(summary['coverage_gaps'])} coverage gap(s). "
          f"Summary: {run_dir / 'summary.json'}", file=sys.stderr, flush=True)
    return exit_code if exit_code >= 0 else 128 - exit_code


def watch(run_id: str) -> int:
    run_dir = _safe_run_dir(run_id)
    if not run_dir.is_dir():
        raise ValueError(f"run not found: {run_id}")
    path = run_dir / "findings.jsonl"
    offset, pending = 0, ""
    while True:
        lines, offset, pending = _tail_lines(path, offset, pending)
        for line in lines:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            print(f"{item['time']:.3f} r{item['revision']} {item['finding_id']} {item['title']}")
            print(f"  {item['message']}")
            if item.get("uncalibrated_risk_score") is not None:
                print(f"  Laya uncalibrated risk score: {item['uncalibrated_risk_score']}")
        if (run_dir / "summary.json").exists():
            return 0
        time.sleep(0.2)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if not args or args[0] in {"-h", "--help"}:
            print(_usage())
            return 0
        if args[0] == "run":
            return run(args[1:])
        if args[0] == "watch" and len(args) == 2:
            return watch(args[1])
        if args[0] == "replay":
            from .replay import replay
            return replay(args[1:])
        raise ValueError(_usage())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"traceward: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
