"""Deterministic offline replay of captured hook and strace fixtures."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from pathlib import Path

from .engine import Engine
from .ocsf import EvidenceStore
from .strace import StraceParser


def replay(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="traceward replay")
    parser.add_argument("--goal", required=True)
    parser.add_argument("--hooks", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--cwd", default="/workspace")
    parser.add_argument("--offline", action="store_true", help="Do not call Laya")
    options = parser.parse_args(argv)
    from .cli import state_root
    run_id = str(uuid.uuid4())
    run_dir = state_root() / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    run_dir.chmod(0o700)
    store = EvidenceStore(run_dir, run_id)
    judge_fn = (lambda _packet: {"status": "unavailable", "reason": "offline_replay"}) if options.offline else None
    engine = Engine(options.goal, store, measure_latency=False,
                    **({"judge_fn": judge_fn} if judge_fn else {}))
    trace_parser = StraceParser(options.cwd)
    observations: list[tuple[float, str, dict]] = []
    for line in options.trace.read_text(encoding="utf-8").splitlines():
        event = trace_parser.parse(line)
        if event:
            observations.append((event["time"], "effect", event))
    for line in options.hooks.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        observations.append((float(event["time"]), "hook", event))
    for _, source, event in sorted(observations, key=lambda entry: entry[0]):
        if source == "hook":
            engine.hook(event)
        else:
            engine.effect(event)
    if trace_parser.unparsed:
        engine.add_gap(f"{trace_parser.unparsed} strace lines were not parsed")
    engine.finish()
    summary = engine.summary()
    summary.update({"run_id": run_id, "replayed_at": time.time(), "mode": "offline_replay"})
    summary_file = run_dir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    summary_file.chmod(0o600)
    print(summary_file)
    return 0
