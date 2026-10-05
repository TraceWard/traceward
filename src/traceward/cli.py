"""One-command Codex wrapper and live finding watcher."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .engine import Engine
from .config import load_observer_env
from .ocsf import EvidenceStore
from .privacy import redact
from .gvisor import GvisorParser
from .runtime import ManagedRuntime


def state_root() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "traceward" / "runs"


def _usage() -> str:
    return (
        "usage: traceward run [--goal TEXT | --goal-file PATH] [--judge-provider lmstudio|laya] [--judge-url URL] [--judge-model MODEL] [--laya-url URL] [--runner-image IMAGE] [--workspace PATH] [--guest-image IMAGE] codex [CODEX FLAGS...]\n"
        "       traceward watch RUN_ID\n"
        "       traceward dashboard [--runs-dir PATH] [--port PORT]\n"
        "       traceward replay --goal TEXT --hooks FILE --trace FILE"
    )


def _parse_run(args: list[str]) -> tuple[str, str | None, list[str], str | None, str | None, str | None, dict]:
    goal = goal_file = laya_url = image = workspace = guest_image = None
    judge_options = {}
    index = 0
    while index < len(args) and args[index] != "codex":
        flag = args[index]
        if flag not in {"--goal", "--goal-file", "--laya-url", "--runner-image", "--workspace", "--guest-image", "--judge-provider", "--judge-url", "--judge-model"} or index + 1 >= len(args):
            raise ValueError(_usage())
        value = args[index + 1]
        if flag == "--goal":
            goal = value
        elif flag == "--goal-file":
            goal_file = value
        elif flag == "--laya-url":
            laya_url = value
        elif flag == "--runner-image":
            image = value
        elif flag == "--workspace":
            workspace = value
        elif flag.startswith('--judge-'):
            judge_options[flag.removeprefix('--judge-')] = value
        else:
            guest_image = value
        index += 2
    if index >= len(args) or args[index] != "codex":
        raise ValueError(_usage())
    if goal and goal_file:
        raise ValueError("choose --goal or --goal-file, not both")
    if laya_url and judge_options:
        raise ValueError('choose --laya-url or --judge-* options')
    if judge_options.get('provider', 'lmstudio') not in {'lmstudio', 'laya'}:
        raise ValueError('judge provider must be lmstudio or laya')
    if goal_file:
        goal = Path(goal_file).read_text(encoding="utf-8").strip()
    if not goal:
        if sys.stdin.isatty():
            goal = input("Authorised goal for this run: ").strip()
        else:
            raise ValueError("a non-interactive run requires --goal or --goal-file")
    if not goal:
        raise ValueError("goal cannot be empty")
    return goal, laya_url, args[index + 1:], image, workspace, guest_image, judge_options


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


def _safe_run_dir(run_id: str) -> Path:
    try:
        parsed = uuid.UUID(run_id)
    except ValueError as exc:
        raise ValueError("run ID must be a UUID") from exc
    return state_root() / str(parsed)


def _write_manifest(path: Path, run_id: str, goal: str, started_at: float) -> None:
    """Atomically publish liveness without exposing an agent prompt or login data."""
    item = {"run_id": run_id, "goal": redact(goal, 1000), "started_at": started_at,
            "heartbeat_at": time.time(),
            "source": "scripted_agent" if os.environ.get("TRACEWARD_DEMO_CASE") else "codex",
            "demo_case": os.environ.get("TRACEWARD_REAL_CASE") or os.environ.get("TRACEWARD_DEMO_CASE"),
            "observer_version": "gvisor-v1", "runtime": "gvisor"}
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(item, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def run(args: list[str]) -> int:
    goal, laya_url, codex_args, image, workspace, guest_image, judge_options = _parse_run(args)
    run_id = str(uuid.uuid4())
    run_dir = _safe_run_dir(run_id)
    run_dir.mkdir(parents=True, mode=0o700)
    run_dir.chmod(0o700)
    hook_file, trace_file = run_dir / "hooks.jsonl", run_dir / "raw.gvisor.jsonl"
    for file in (hook_file, trace_file):
        file.touch(mode=0o600)
        file.chmod(0o600)
    started_at = time.time()
    _write_manifest(run_dir / "run.json", run_id, goal, started_at)
    try:
        runtime = ManagedRuntime(run_dir, run_id, codex_args, image=image,
                                 workspace=workspace, guest_image=guest_image)
    except Exception:
        path = run_dir / "summary.json"
        path.write_text(json.dumps({"run_id": run_id, "goal": redact(goal, 1000),
                                    "codex_exit_code": None, "finding_count": 0,
                                    "coverage_gaps": ["runtime setup failed; no agent task started"]}))
        path.chmod(0o600)
        raise
    store = EvidenceStore(run_dir, run_id)
    interactive = sys.stdout.isatty()
    def alert(finding: dict):
        if not interactive:
            print(f"[TraceWard] finding {finding['finding_id']} r{finding['revision']}: "
                  f"{finding['status']} — {finding['title']}", file=sys.stderr, flush=True)
    from .judges import judge
    engine = Engine(goal, store, alert_fn=alert, coverage_gaps=[],
                    judge_fn=lambda evidence: judge(evidence, laya_url=laya_url, **judge_options))
    for gap in runtime.gaps:
        engine.add_gap(gap)
    parser = GvisorParser(os.getcwd(), runtime.metadata.get("abi", "arm64"))
    print(f"TraceWard run {run_id} — evidence: {run_dir}", file=sys.stderr, flush=True)
    print("Runtime: managed gVisor (Linux guest)", file=sys.stderr, flush=True)
    if interactive:
        print(f"Live findings: traceward watch {run_id}", file=sys.stderr, flush=True)
    started = last_heartbeat = time.monotonic()
    trace_pos = hook_pos = 0
    trace_pending = hook_pending = ""
    warned_hooks = False
    child = None
    def forward(signum, _frame):
        if child and child.poll() is None:
            runtime.signal(child, signum)
    previous = {s: signal.signal(s, forward) for s in (signal.SIGTERM, signal.SIGINT)}
    def drain():
        nonlocal trace_pos, hook_pos, trace_pending, hook_pending
        trace_lines, trace_pos, trace_pending = _tail_lines(trace_file, trace_pos, trace_pending)
        hook_lines, hook_pos, hook_pending = _tail_lines(hook_file, hook_pos, hook_pending)
        for line in hook_lines:
            try:
                item = json.loads(line)
                if item.get("run_id") == run_id:
                    engine.hook(item)
            except (ValueError, TypeError):
                engine.add_gap("malformed hook record")
        for line in trace_lines:
            effect = parser.parse(line)
            if effect:
                engine.effect(effect)
        for gap in parser.gaps:
            engine.add_gap(gap)
    try:
        child = subprocess.Popen(runtime.command)
        while child.poll() is None:
            if time.monotonic() - last_heartbeat >= 2:
                _write_manifest(run_dir / "run.json", run_id, goal, started_at)
                last_heartbeat = time.monotonic()
            drain()
            if not warned_hooks and time.monotonic() - started > 15 and not engine.counts.get("hook"):
                warned_hooks = True
                print("TraceWard: no Codex hook received; review hook trust via /hooks. "
                      "Combined coverage is not established.", file=sys.stderr, flush=True)
            time.sleep(0.1)
        exit_code = child.wait()
        for _ in range(5):
            drain()
            time.sleep(0.05)
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
        runtime.cleanup()
    status_path = run_dir / "runtime-status.json"
    status = json.loads(status_path.read_text()) if status_path.exists() else {}
    if not status.get("handshakes") or not status.get("source_messages"):
        engine.add_gap("gVisor telemetry was not established; run coverage is incomplete")
    if status.get("collector_failed") or status.get("decode_errors") or status.get("collector_dropped_messages"):
        engine.add_gap("collector failure or rejected/dropped messages; run coverage is incomplete")
    if parser.unparsed:
        engine.add_gap(f"{parser.unparsed} gVisor records could not be normalized")
    engine.finish()
    summary = {**engine.summary(), **runtime.metadata, **status,
               "run_id": run_id, "codex_exit_code": exit_code,
               "wall_seconds": round(time.monotonic() - started, 3),
               "unparsed_runtime_records": parser.unparsed,
               "runtime_overhead": "see separate comparable-run measurements"}
    path = run_dir / "summary.json"
    path.write_text(json.dumps(summary, indent=2) + "\n")
    path.chmod(0o600)
    print(f"TraceWard: {summary['finding_count']} finding(s), {len(summary['coverage_gaps'])} coverage gap(s). "
          f"Summary: {path}", file=sys.stderr, flush=True)
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
                print(f"  Model uncalibrated risk score: {item['uncalibrated_risk_score']}")
            if item.get('laya', {}).get('rationale'):
                print(f"  Model: {item['laya'].get('model')} — {item['laya']['rationale']}")
        if (run_dir / "summary.json").exists():
            return 0
        time.sleep(0.2)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        load_observer_env()
        if not args or args[0] in {"-h", "--help"}:
            print(_usage())
            return 0
        if args[0] == "run":
            return run(args[1:])
        if args[0] == "watch" and len(args) == 2:
            return watch(args[1])
        if args[0] == "dashboard":
            from .dashboard import main as dashboard_main
            return dashboard_main(args[1:])
        if args[0] == "replay":
            from .replay import replay
            return replay(args[1:])
        raise ValueError(_usage())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"traceward: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
