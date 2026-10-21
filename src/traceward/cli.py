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
from .instructions import codex_instruction
from .records import assessment_record


def state_root() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "traceward" / "runs"


def _usage() -> str:
    return (
        "usage: traceward run [--goal TEXT | --goal-file PATH] [--context-mode metadata|redacted] [--validation-script PATH] [--permissions-file PATH] [--shared-root PATH] [--judge-provider lmstudio] [--judge-url URL] [--judge-model MODEL] [--runner-image IMAGE] [--workspace PATH] [--guest-image IMAGE] [--defer-judge] codex [AGENT FLAGS...] [INITIAL INSTRUCTION]\n"
        "       traceward eval pi [--cases CASE...] [--trials N] [--actor-model MODEL] [--actor-url URL]\n"
        "       traceward watch RUN_ID\n"
        "       traceward dashboard [--runs-dir PATH] [--port PORT]\n"
        "       traceward replay --goal TEXT --hooks FILE --trace FILE\n"
        "       traceward rebuild-graph"
    )


def _parse_run(args: list[str], *, instruction_parser=codex_instruction) -> tuple:
    goal = goal_file = image = workspace = guest_image = None
    judge_options = {}
    agent_options = {}
    index = 0
    while index < len(args) and args[index] not in {"codex"}:
        flag = args[index]
        if flag == '--defer-judge':
            agent_options['defer_evaluation'] = True
            index += 1
            continue
        if flag not in {"--goal", "--goal-file", "--runner-image", "--workspace", "--guest-image", "--judge-provider", "--judge-url", "--judge-model", '--context-mode', '--validation-script', '--permissions-file', '--shared-root'} or index + 1 >= len(args):
            raise ValueError(_usage())
        value = args[index + 1]
        if flag == '--goal':
            goal = value
        elif flag == '--goal-file':
            goal_file = value
        elif flag == "--runner-image":
            image = value
        elif flag == "--workspace":
            workspace = value
        elif flag.startswith('--judge-'):
            judge_options[flag.removeprefix('--judge-')] = value
        elif flag == '--shared-root':
            agent_options.setdefault('shared_roots', []).append(value)
        elif flag in {'--context-mode', '--validation-script', '--permissions-file'}:
            agent_options[flag[2:].replace('-', '_')] = value
        else:
            guest_image = value
        index += 2
    if index >= len(args) or args[index] not in {"codex"}:
        raise ValueError(_usage())
    agent_options['agent'] = args[index]
    if agent_options.get('context_mode', 'metadata') not in {'metadata', 'redacted'}:
        raise ValueError('--context-mode must be metadata or redacted')
    if judge_options.get('provider', 'lmstudio') != 'lmstudio':
        raise ValueError('judge provider must be lmstudio')
    if goal is not None and goal_file is not None:
        raise ValueError('choose --goal or --goal-file, not both')
    agent_args = args[index + 1:]
    if goal_file is not None:
        goal = Path(goal_file).expanduser().read_text(encoding='utf-8')
    if goal is not None:
        if not goal.strip():
            raise ValueError('goal cannot be empty')
        # Explicit operator scope does not depend on recovering a launch prompt.
        # Preserve stdin and all agent arguments, including interactive starts.
    else:
        goal, agent_args = instruction_parser(agent_args)
    return goal, agent_args, image, workspace, guest_image, judge_options, agent_options


def _tail_lines(path: Path, offset: int, pending: str, *, limit: int = -1) -> tuple[list[str], int, str]:
    if not path.exists():
        return [], offset, pending
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        stream.seek(offset)
        chunk = stream.read(limit)
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


def _write_manifest(path: Path, run_id: str, goal: str | None, started_at: float, agent: str = 'codex') -> None:
    """Atomically publish liveness without exposing an agent prompt or login data."""
    item = {"run_id": run_id, "goal": redact(goal, 1000) if goal is not None else 'Waiting for first user instruction',
            'goal_status': 'awaiting_instruction' if goal is None else 'established', "started_at": started_at,
            "heartbeat_at": time.time(),
            "source": "scripted_agent" if os.environ.get("TRACEWARD_DEMO_CASE") else agent,
            "demo_case": os.environ.get('TRACEWARD_EVALUATION_CASE') or os.environ.get("TRACEWARD_REAL_CASE") or os.environ.get("TRACEWARD_DEMO_CASE"),
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


def run(args: list[str], *, runtime_factory=None, runtime_options=None, agent_name='codex',
        instruction_parser=codex_instruction) -> int:
    goal, codex_args, image, workspace, guest_image, judge_options, agent_options = _parse_run(
        args, instruction_parser=instruction_parser)
    defer_evaluation = agent_options.pop('defer_evaluation', False)
    pending_goal = goal is None
    if pending_goal:
        runtime_options = {**(runtime_options or {}), 'capture_initial_goal': True}
    context_mode = agent_options.pop('context_mode', 'metadata')
    validator = agent_options.pop('validation_script', None)
    permission_file = agent_options.pop('permissions_file', None)
    shared_roots = agent_options.pop('shared_roots', [])
    agent_options.pop('agent')
    agent = agent_name
    run_id = str(uuid.uuid4())
    run_dir = _safe_run_dir(run_id)
    run_dir.mkdir(parents=True, mode=0o700)
    run_dir.chmod(0o700)
    hook_file, trace_file = run_dir / "hooks.jsonl", run_dir / "raw.gvisor.jsonl"
    for file in (hook_file, trace_file):
        file.touch(mode=0o600)
        file.chmod(0o600)
    started_at = time.time()
    _write_manifest(run_dir / "run.json", run_id, goal, started_at, agent)
    try:
        runtime = (runtime_factory or ManagedRuntime)(run_dir, run_id, codex_args, image=image,
                                 workspace=workspace, guest_image=guest_image, context_mode=context_mode, **(runtime_options or {}))
    except Exception:
        path = run_dir / "summary.json"
        path.write_text(json.dumps({"run_id": run_id, "goal": redact(goal or '', 1000),
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
    from .state import StateObserver, independent_validation
    from .context import codex_session, permissions
    root = Path(runtime.metadata['workspace'])
    for shared in shared_roots:
        if not Path(shared).resolve().is_relative_to(root):
            raise ValueError('--shared-root must be inside the observed workspace')
    frozen_validator = None
    if validator:
        source = Path(validator).expanduser()
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            import stat
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise ValueError('validation script must be a bounded regular file')
            data = os.read(fd, 1024 * 1024 + 1)
        finally: os.close(fd)
        frozen_validator = run_dir / 'independent-check.py'
        vfd = os.open(frozen_validator, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(vfd, 'wb') as stream: stream.write(data)
    engine = Engine(goal or '', store, alert_fn=alert, coverage_gaps=[],
                    workspace=runtime.metadata["workspace"],
                    defer_evaluation=defer_evaluation or pending_goal,
                    extended_analysis=True, context_mode=context_mode,
                    graph_path=state_root().parent / 'evidence-graph.sqlite', shared_roots=shared_roots,
                    transport_endpoints=runtime.transport_endpoints,
                    agent_state_roots=runtime.agent_state_roots,
                    judge_fn=lambda evidence: judge(evidence, **judge_options))
    for gap in runtime.gaps:
        engine.add_gap(gap)
    states = StateObserver(root, context_mode)
    for observation in states.begin(): engine.observe(observation)
    if permission_file:
        observations, gaps = permissions(Path(permission_file), workspace=root, run_id=run_id)
        for observation in observations: engine.observe(observation)
        for gap in gaps: engine.add_gap(gap)
    parser = GvisorParser(os.getcwd(), runtime.metadata.get("abi", "arm64"))
    print(f"TraceWard run {run_id} — evidence: {run_dir}", file=sys.stderr, flush=True)
    print("Runtime: managed gVisor (Linux guest)", file=sys.stderr, flush=True)
    if interactive:
        print(f"Live findings: traceward watch {run_id}", file=sys.stderr, flush=True)
    started = last_heartbeat = time.monotonic()
    trace_pos = hook_pos = 0
    trace_pending = hook_pending = ""
    http_pos, http_pending = 0, ''
    warned_hooks = False
    recovered_hooks = False
    ingestion_interrupted = False
    child = None
    finalizing = False
    shutdown_signal = None
    def forward(signum, _frame):
        nonlocal shutdown_signal, finalizing
        if finalizing or (child and child.poll() is not None):
            finalizing = True
            shutdown_signal = signum
            engine.cancel_assessments()
        elif child and child.poll() is None:
            runtime.signal(child, signum)
    previous = {s: signal.signal(s, forward) for s in (signal.SIGTERM, signal.SIGINT)}
    def drain():
        nonlocal trace_pos, hook_pos, trace_pending, hook_pending, goal, pending_goal, http_pos, http_pending, recovered_hooks, ingestion_interrupted
        if engine.assessments_cancelled:
            ingestion_interrupted = True
            return False
        # Read bounded chunks so hook delivery, heartbeats and operator signals
        # are not held behind an entire busy session's syscall backlog.
        hook_lines, hook_pos, hook_pending = _tail_lines(hook_file, hook_pos, hook_pending, limit=65536)
        for line in hook_lines:
            if engine.assessments_cancelled:
                ingestion_interrupted = True
                return False
            try:
                item = json.loads(line)
                if item.get("run_id") == run_id:
                    if pending_goal and item.get('event') == 'InitialInstruction' and item.get('input_source') == 'interactive':
                        text = item.get('goal_text')
                        if isinstance(text, str) and text.strip():
                            goal, pending_goal = text, False
                            engine.set_goal(text, defer_evaluation=defer_evaluation)
                            _write_manifest(run_dir / 'run.json', run_id, goal, started_at, agent)
                    engine.hook(item)
            except (ValueError, TypeError):
                engine.add_gap("malformed hook record")
        if warned_hooks and not recovered_hooks and engine.counts.get('hook'):
            recovered_hooks = True
            print(f'TraceWard: {agent} hooks received; the earlier no-hook warning no longer applies.',
                  file=sys.stderr, flush=True)
        trace_lines, trace_pos, trace_pending = _tail_lines(trace_file, trace_pos, trace_pending, limit=65536)
        for line in trace_lines:
            if engine.assessments_cancelled:
                ingestion_interrupted = True
                return False
            effect = parser.parse(line)
            if effect:
                engine.effect(effect)
        http_lines, http_pos, http_pending = _tail_lines(run_dir/'http-events.jsonl', http_pos, http_pending, limit=65536)
        for line in http_lines:
            if engine.assessments_cancelled:
                ingestion_interrupted = True
                return False
            try:
                item = json.loads(line)
                if item.get('kind') == 'http_request': engine.observe(item)
            except (ValueError, TypeError):
                engine.add_gap('malformed HTTP inspection record')
        inspection = run_dir/'inspection-status.json'
        if inspection.exists():
            try:
                status = json.loads(inspection.read_text())
                if status.get('healthy') is False: engine.add_gap('HTTPS inspection proxy failed; HTTP visibility is incomplete')
            except (ValueError, OSError): engine.add_gap('HTTPS inspection health unavailable')
        for gap in parser.gaps:
            engine.add_gap(gap)
        return any(path.exists() and offset < path.stat().st_size for path, offset in
                   ((trace_file, trace_pos), (hook_file, hook_pos), (run_dir/'http-events.jsonl', http_pos)))
    try:
        try:
            child = subprocess.Popen(runtime.command)
            while child.poll() is None:
                if time.monotonic() - last_heartbeat >= 2:
                    _write_manifest(run_dir / "run.json", run_id, goal, started_at, agent)
                    last_heartbeat = time.monotonic()
                more_events = drain()
                if not warned_hooks and time.monotonic() - started > 15 and not engine.counts.get("hook"):
                    warned_hooks = True
                    instruction = runtime.hook_setup_hint
                    print(f"TraceWard: no {agent} hook received; {instruction}. "
                          "Combined coverage is not established.", file=sys.stderr, flush=True)
                if not more_events: time.sleep(0.1)
            exit_code = child.wait()
            finalizing = True
            if trace_pos < trace_file.stat().st_size:
                print(f'TraceWard: {agent} has exited; processing remaining captured events. '
                      'Press Ctrl+C or send SIGTERM again to stop waiting and save partial results.',
                      file=sys.stderr, flush=True)
            for _ in range(5):
                while drain():
                    if time.monotonic() - last_heartbeat >= 2:
                        _write_manifest(run_dir/'run.json', run_id, goal, started_at, agent)
                        last_heartbeat = time.monotonic()
                if engine.assessments_cancelled: break
                time.sleep(0.05)
        finally:
            finalizing = True
            runtime.cleanup()
        status_path = run_dir / "runtime-status.json"
        status = json.loads(status_path.read_text()) if status_path.exists() else {}
        if not status.get("handshakes") or not status.get("source_messages"):
            engine.add_gap("gVisor telemetry was not established; run coverage is incomplete")
        if status.get("collector_failed") or status.get("decode_errors") or status.get("collector_dropped_messages"):
            engine.add_gap("collector failure or rejected/dropped messages; run coverage is incomplete")
        if parser.unparsed:
            engine.add_gap(f"{parser.unparsed} gVisor records could not be normalized")
        if ingestion_interrupted:
            engine.add_gap('observation processing interrupted during shutdown; raw source evidence retained; derived views incomplete')
        elif trace_pending or hook_pending or http_pending:
            engine.add_gap('incomplete final source record; raw source evidence retained')
        if runtime.permission_log and runtime.permission_log.exists():
            observations, gaps = permissions(runtime.permission_log, workspace=root, run_id=run_id)
            for observation in observations: engine.observe(observation)
            for gap in gaps: engine.add_gap(gap)
        for observation in states.end(): engine.observe(observation)
        for gap in set(states.gaps): engine.add_gap(gap)
        if context_mode == 'redacted' and agent == 'codex':
            sessions = {h.get('session_id') for h in engine.hooks if h.get('session_id')}
            for identity in sessions:
                try: uuid.UUID(identity)
                except (ValueError, TypeError):
                    engine.add_gap('invalid Codex session identity; semantic context not imported'); continue
                matches = list((runtime.home / 'sessions').rglob('*' + identity + '*.jsonl'))[:2]
                if len(matches) != 1:
                    engine.add_gap('Codex session context file missing or ambiguous'); continue
                try: observations, gaps = codex_session(matches[0], expected_session_id=identity)
                except (OSError, ValueError):
                    engine.add_gap('Codex session context could not be safely read'); continue
                for observation in observations: engine.observe(observation)
                for gap in gaps: engine.add_gap(gap)
        if frozen_validator:
            engine.observe(independent_validation(root, frozen_validator, runtime.image))
        waiting = sum(thread.is_alive() for thread in engine.threads)
        if waiting and not engine.assessments_cancelled:
            print(f"TraceWard: {agent} has exited; waiting for {waiting} pending assessment{'s' if waiting != 1 else ''} to finish. "
                  "Press Ctrl+C or send SIGTERM again to stop waiting and save unfinished assessments as incomplete.",
                  file=sys.stderr, flush=True)
        engine.finish()
        if engine.assessments_cancelled:
            print("TraceWard: stopped waiting for assessments; captured evidence and existing findings are retained.",
                  file=sys.stderr, flush=True)
        summary = {**engine.summary(), **runtime.metadata, **status,
                   "run_id": run_id, "agent_exit_code": exit_code,
                   "codex_exit_code": exit_code if agent == 'codex' else None,
                   "wall_seconds": round(time.monotonic() - started, 3),
                   "unparsed_runtime_records": parser.unparsed,
                   "runtime_overhead": "see separate comparable-run measurements"}
        summary['context_mode'] = context_mode
        summary['assessment_wait_cancelled'] = engine.assessments_cancelled
        if shutdown_signal is not None: summary['shutdown_signal'] = shutdown_signal
        summary['state_snapshot_gaps'] = list(set(states.gaps))
        path = run_dir / "summary.json"
        path.write_text(json.dumps(summary, indent=2) + "\n")
        path.chmod(0o600)
        print(f"TraceWard: {summary['finding_count']} finding(s), {len(summary['coverage_gaps'])} coverage gap(s). "
              f"Summary: {path}", file=sys.stderr, flush=True)
        if shutdown_signal is not None: return 128 + shutdown_signal
        return exit_code if exit_code >= 0 else 128 - exit_code
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


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
                item = assessment_record(json.loads(line))
            except ValueError:
                continue
            print(f"{item['time']:.3f} r{item['revision']} {item['finding_id']} {item['title']}")
            print(f"  {item['message']}")
            if item.get("uncalibrated_risk_score") is not None:
                print(f"  Model uncalibrated risk score: {item['uncalibrated_risk_score']}")
            if item.get('judge', {}).get('rationale'):
                print(f"  Model: {item['judge'].get('model')} — {item['judge']['rationale']}")
        if (run_dir / "summary.json").exists():
            return 0
        time.sleep(0.2)


def _agent_argument(args):
    index = 0
    while index < len(args) and args[index].startswith('--'):
        index += 1 if args[index] in {'--defer-judge', '--pi-inspect-https'} else 2
    return args[index] if index < len(args) else None


def _pi_harness():
    try:
        from traceward_pi import cli
        return cli
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith('traceward_pi'):
            raise RuntimeError('Pi is an optional evaluation harness. Install it with: pip install -e evaluation/pi') from exc
        raise


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        load_observer_env()
        if not args or args[0] in {"-h", "--help"}:
            print(_usage())
            return 0
        if args[0] == "run":
            if _agent_argument(args[1:]) == 'pi':
                return _pi_harness().run(args[1:])
            return run(args[1:])
        if args[:2] == ['eval', 'pi']:
            return _pi_harness().main(['eval', *args[2:]])
        if args[0] == "watch" and len(args) == 2:
            return watch(args[1])
        if args[0] == "dashboard":
            from .dashboard import main as dashboard_main
            return dashboard_main(args[1:])
        if args[0] == "replay":
            from .replay import replay
            return replay(args[1:])
        if args == ['rebuild-graph']:
            from .graph import EvidenceGraph
            graph = EvidenceGraph(state_root().parent/'evidence-graph.sqlite','rebuild')
            try: print(f'Rebuilt {graph.rebuild(state_root())} observations from JSONL')
            finally: graph.close()
            return 0
        raise ValueError(_usage())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"traceward: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
