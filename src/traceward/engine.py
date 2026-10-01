"""Causal episode reduction and two-stage, evidence-backed findings."""

from __future__ import annotations

import re
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Callable

from .laya import judge, packet
from .ocsf import EvidenceStore
from .privacy import redact

_SENSITIVE = re.compile(r"(?i)(?:^|[/_.-])(?:credential|secret|token|password|auth|\.env)(?:[/_.-]|$)")


class Engine:
    def __init__(self, goal: str, store: EvidenceStore, *, judge_fn: Callable = judge,
                 alert_fn: Callable[[dict], None] | None = None,
                 measure_latency: bool = True):
        self.goal, self.store = goal, store
        self.judge_fn = judge_fn
        self.alert_fn = alert_fn or (lambda finding: None)
        self.measure_latency = measure_latency
        self.parents: dict[int, int] = {}
        self.hooks: list[dict] = []
        self.execs: list[dict] = []
        self.links: dict[int, str] = {}
        self.ambiguous_tools: set[str] = set()
        self.effects: deque[dict] = deque(maxlen=10000)
        self.finding_keys: set[tuple[int, str]] = set()
        self.threads: list[threading.Thread] = []
        self.coverage_gaps: list[str] = [
            "mmap/page faults, unsupported syscalls and escaped descendants are not fully observed",
            "same-UID agent processes may tamper with local evidence; this PoC has no integrity boundary",
        ]
        self.counts: dict[str, int] = defaultdict(int)
        self.first_alert_latency: float | None = None

    def add_gap(self, reason: str) -> None:
        if reason not in self.coverage_gaps:
            self.coverage_gaps.append(reason)
            self.store.event("coverage", {"source": "traceward", "message": reason})

    def hook(self, item: dict) -> None:
        item = {**item, "event_id": str(uuid.uuid4())}
        self.store.event("hook", item)
        self.counts["hook"] += 1
        if item.get("event") == "PreToolUse" and item.get("tool_name") == "Bash" and item.get("command"):
            self.hooks.append(item)
            self._link()

    def effect(self, item: dict) -> None:
        kind = item.get("kind")
        if kind == "fork":
            self.parents[item["child_pid"]] = item["pid"]
            created = {"kind": "process", "event_id": str(uuid.uuid4()),
                       "time": item["time"], "pid": item["child_pid"],
                       "parent_pid": item["pid"], "name": "forked process",
                       "source": item.get("source", "strace"),
                       "raw_trace_ref": item.get("raw_trace_ref")}
            self.store.event("process", created)
            self.counts["process"] += 1
            self.effects.append(created)
            return
        if kind not in {"process", "file_open", "file_read", "file_write", "network", "network_send"}:
            return
        item = {**item, "event_id": str(uuid.uuid4())}
        # raw_args is used only transiently for hook matching, never exported.
        export = {k: v for k, v in item.items() if k != "raw_args"}
        self.store.event(kind, export)
        self.counts[kind] += 1
        self.effects.append(item)
        if kind == "process":
            self.execs.append(item)
            if item.get("parent_pid") is not None:
                self.parents[item["pid"]] = item["parent_pid"]
            self._link()
        if kind == "network_send":
            self._detect(item)

    def _link(self) -> None:
        for hook in self.hooks:
            tool_id = hook.get("tool_use_id")
            if not tool_id or tool_id in self.ambiguous_tools:
                continue
            command = hook["command"]
            candidates = [
                event for event in self.execs
                if command in event.get("raw_args", "")
                and -0.5 <= event["time"] - hook["time"] <= 30
            ]
            if len(candidates) > 1 or (len(candidates) == 1 and
                                      self.links.get(candidates[0]["pid"]) not in (None, tool_id)):
                self.ambiguous_tools.add(tool_id)
                self.links = {pid: linked for pid, linked in self.links.items() if linked != tool_id}
                self.add_gap(f"ambiguous hook-to-process attribution for tool {tool_id}")
            elif len(candidates) == 1:
                self.links[candidates[0]["pid"]] = tool_id
        # A link may arrive after its file/network effects were parsed.
        for event in list(self.effects):
            if event.get("kind") == "network_send":
                self._detect(event)

    def _tool_for(self, pid: int) -> str | None:
        seen: set[int] = set()
        while pid and pid not in seen:
            seen.add(pid)
            if pid in self.links:
                return self.links[pid]
            pid = self.parents.get(pid, 0)
        return None

    def _detect(self, network: dict) -> None:
        tool_id = self._tool_for(network["pid"])
        if not tool_id:
            return
        reads = [
            event for event in self.effects
            if event.get("kind") == "file_read"
            and _SENSITIVE.search(event.get("path", ""))
            and self._tool_for(event["pid"]) == tool_id
            and 0 <= network["time"] - event["time"] <= 60
        ]
        if not reads:
            return
        read = reads[-1]
        key = (network["pid"], tool_id)
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        hook = next((h for h in self.hooks if h.get("tool_use_id") == tool_id), None)
        ids = [x for x in (hook and hook["event_id"], read["event_id"], network["event_id"]) if x]
        process_path = [event for event in self.effects if event.get("kind") == "process"
                        and self._tool_for(event["pid"]) == tool_id]
        ids.extend(event["event_id"] for event in process_path[-8:])
        finding = {
            "finding_id": str(uuid.uuid4()), "revision": 1, "time": time.time(),
            "title": "Sensitive file read followed by network traffic in a Codex tool process tree",
            "message": f"A process descended from {redact(hook['command']) if hook else 'a Codex tool'} read "
                       f"{redact(read['path'])} and sent data toward {redact(network['endpoint'])}. "
                       "This may be legitimate; review it against the goal.",
            "status": "suspicious_behaviour", "attribution": "command-and-process-lineage",
            "tool_use_id": tool_id, "evidence_ids": ids,
            "observed_effects": ["file_read", "network_send"],
            "counterevidence": [],
            "coverage_gaps": list(self.coverage_gaps),
            "uncalibrated_risk_score": None,
        }
        self.store.finding(finding)
        self.alert_fn(finding)
        self.counts["finding"] += 1
        if self.measure_latency and self.first_alert_latency is None:
            self.first_alert_latency = finding["time"] - network["time"]
        observations = [read, network, *process_path[-8:]]
        evidence_packet = packet(self.goal, finding, observations, self.coverage_gaps)
        thread = threading.Thread(target=self._enrich, args=(finding, evidence_packet), daemon=True)
        self.threads.append(thread)
        thread.start()

    def _enrich(self, finding: dict, evidence_packet: dict) -> None:
        try:
            judgement = self.judge_fn(evidence_packet)
        except Exception as exc:
            judgement = {"status": "unavailable", "reason": type(exc).__name__}
        revision = {**finding, "revision": 2, "time": time.time(), "laya": judgement}
        revision["uncalibrated_risk_score"] = judgement.get("uncalibrated_risk_score")
        if judgement.get("status") != "scored":
            revision["coverage_gaps"] = list(dict.fromkeys(
                [*revision["coverage_gaps"], "Laya judgement unavailable"]
            ))
        self.store.finding(revision)
        self.alert_fn(revision)

    def finish(self) -> None:
        for thread in self.threads:
            thread.join(timeout=65)
        if self.counts.get("hook", 0) == 0:
            self.add_gap("no Codex hooks received; combined hook/runtime coverage was not achieved")
        unmatched = {hook["tool_use_id"] for hook in self.hooks if hook.get("tool_use_id")}
        unmatched.difference_update(self.links.values())
        unmatched.difference_update(self.ambiguous_tools)
        if unmatched:
            self.add_gap(f"{len(unmatched)} shell tool hook(s) lacked a process attribution")

    def summary(self) -> dict:
        return {
            "goal": redact(self.goal, 1000),
            "counts": dict(self.counts),
            "coverage_gaps": list(self.coverage_gaps),
            "first_alert_latency_seconds": self.first_alert_latency,
            "linked_tool_processes": len(self.links),
            "ambiguous_tool_attributions": len(self.ambiguous_tools),
            "finding_count": self.counts.get("finding", 0),
            "interpretation": "No finding means no suspicious behaviour observed within stated coverage, not proof of safety.",
        }
