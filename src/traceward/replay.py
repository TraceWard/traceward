"""Deterministic offline replay of captured hook and gVisor fixtures."""

from __future__ import annotations

import argparse
import json
import shutil
import time
import uuid
from pathlib import Path

from .engine import Engine
from .ocsf import EvidenceStore
from .gvisor import GvisorParser


def replay(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="traceward replay")
    parser.add_argument("--goal", required=True)
    parser.add_argument("--hooks", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--cwd", default="/workspace")
    parser.add_argument("--abi", choices=["arm64", "amd64"], default="arm64")
    parser.add_argument("--offline", action="store_true", help="Do not call the decision model")
    parser.add_argument('--analysis-events', type=Path)
    parser.add_argument('--context-mode', choices=['metadata', 'redacted'], default='metadata')
    parser.add_argument('--shared-root', action='append', default=[])
    options = parser.parse_args(argv)
    from .cli import state_root
    run_id = str(uuid.uuid4())
    run_dir = state_root() / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    run_dir.chmod(0o700)
    for source, name in ((options.trace, "raw.gvisor.jsonl"), (options.hooks, "hooks.jsonl")):
        target = run_dir / name
        shutil.copyfile(source, target)
        target.chmod(0o600)
    from .cli import _write_manifest
    _write_manifest(run_dir / "run.json", run_id, options.goal, time.time(), 'replay')
    store = EvidenceStore(run_dir, run_id)
    judge_fn = (lambda _packet: {"status": "unavailable", "reason": "offline_replay"}) if options.offline else None
    engine = Engine(options.goal, store, measure_latency=False, workspace=options.cwd,
                    defer_evaluation=True,
                    extended_analysis=True, context_mode='metadata', shared_roots=options.shared_root,
                    **({"judge_fn": judge_fn} if judge_fn else {}))
    trace_parser = GvisorParser(options.cwd, options.abi)
    observations: list[tuple[float, str, dict]] = []
    for line in options.trace.read_text(encoding="utf-8").splitlines():
        event = trace_parser.parse(line)
        if event:
            observations.append((event["time"], "effect", event))
    for line in options.hooks.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        observations.append((float(event["time"]), "hook", event))
    if options.analysis_events:
        for line in options.analysis_events.read_text().splitlines():
            event = json.loads(line)
            if options.context_mode == 'metadata':
                for field in ('excerpt', 'diff_excerpt'): event.pop(field, None)
                event.pop('integrity_predicates', None)
            observations.append((float(event['time']), 'observation', event))
    for _, source, event in sorted(observations, key=lambda entry: entry[0]):
        if source == "hook":
            engine.hook(event)
        elif source == 'observation': engine.observe(event)
        else:
            engine.effect(event)
    if trace_parser.unparsed:
        engine.add_gap(f"{trace_parser.unparsed} gVisor records could not be normalized")
    for gap in trace_parser.gaps:
        engine.add_gap(gap)
    engine.finish()
    summary = engine.summary()
    summary.update({"run_id": run_id, "replayed_at": time.time(), "mode": "offline_replay" if options.offline else 'model_replay',
                    'context_mode': options.context_mode})
    summary_file = run_dir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    summary_file.chmod(0o600)
    print(summary_file)
    return 0
