"""Causal episode reduction and two-stage, evidence-backed findings."""

from __future__ import annotations

import ast
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Callable

from .laya import disposition, packet
from .judges import judge
from .ocsf import EvidenceStore
from .privacy import redact

_SENSITIVE = re.compile(r"(?i)(?:^|[/_.-])(?:credentials?|secrets?|tokens?|passwords?|auth)(?:[/_.-]|$)")
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".go", ".h", ".js", ".jsx", ".mjs",
                    ".py", ".rs", ".so", ".ts", ".tsx"}


def _command_matches(command: str, raw_args: str) -> bool:
    for token in re.findall(r'"(?:\\.|[^"\\])*"', raw_args):
        try:
            if ast.literal_eval(token) == command:
                return True
        except (SyntaxError, ValueError):
            pass
    return False


def _key(item: dict):
    return item.get("process_key", item.get("pid"))


def _sensitive_path(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    if not name or any(part in {"node_modules", "__pycache__"} for part in parts):
        return False
    if any(name.endswith(suffix) for suffix in _SOURCE_SUFFIXES):
        return False
    if name.startswith(".env") or name in {"id_rsa", "id_ed25519", "id_ecdsa"}:
        return True
    return bool(_SENSITIVE.search(name) or
                any(part in {"credentials", "secrets"} for part in parts[:-1]))


class Engine:
    def __init__(self, goal: str, store: EvidenceStore, *, judge_fn: Callable = judge,
                 alert_fn: Callable[[dict], None] | None = None,
                 measure_latency: bool = True, evaluation_wait_seconds: float = 10, coverage_gaps: list[str] | None = None):
        self.goal, self.store = goal, store
        self.judge_fn = judge_fn
        self.alert_fn = alert_fn or (lambda finding: None)
        self.measure_latency = measure_latency
        self.evaluation_wait_seconds = evaluation_wait_seconds
        self.parents: dict[int, int] = {}
        self.hooks: list[dict] = []
        self.post_hooks: dict[str, dict] = {}
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.finished = False
        self.last_arrival = time.monotonic()
        self.execs: list[dict] = []
        self.links: dict[int, str] = {}
        self.ambiguous_tools: set[str] = set()
        self.effects: deque[dict] = deque(maxlen=10000)
        self.finding_keys: set[tuple[str, str, str]] = set()
        self.threads: list[threading.Thread] = []
        self.coverage_gaps = list(coverage_gaps if coverage_gaps is not None else [
            "unsupported runtime operations are not fully observed",
            "hook records are agent-writable; evidence is not tamper-proof",
        ])
        self.counts: dict[str, int] = defaultdict(int)
        self.first_alert_latency: float | None = None

    def add_gap(self, reason: str) -> None:
        if reason not in self.coverage_gaps:
            self.coverage_gaps.append(reason)
            self.store.event("coverage", {"source": "traceward", "message": reason})

    def hook(self, item: dict) -> None:
        with self.changed:
            self._hook(item)
            self.last_arrival = time.monotonic()
            self.changed.notify_all()

    def _hook(self, item: dict) -> None:
        item = {**item, "event_id": str(uuid.uuid4())}
        self.store.event("hook", item)
        self.counts["hook"] += 1
        if item.get("event") == "PreToolUse" and item.get("tool_name") == "Bash" and item.get("command"):
            self.hooks.append(item)
            self._link()
        elif item.get("event") == "PostToolUse" and item.get("tool_use_id"):
            self.post_hooks[item["tool_use_id"]] = item

    def effect(self, item: dict) -> None:
        with self.changed:
            self._effect(item)
            self.last_arrival = time.monotonic()
            self.changed.notify_all()

    def _effect(self, item: dict) -> None:
        kind = item.get("kind")
        if kind == "fork":
            self.parents[item.get("child_process_key", item["child_pid"])] = _key(item)
            if item.get("is_thread"):
                # Keep lineage for effects emitted by worker threads, but do
                # not present a CLONE_THREAD task as a new child process.
                self._link()
                return
            created = {"kind": "process", "event_id": str(uuid.uuid4()),
                       "time": item["time"], "pid": item["child_pid"],
                       "parent_pid": item["pid"], "name": "forked process",
                       "process_key": item.get("child_process_key", item["child_pid"]),
                       "parent_process_key": _key(item), "sandbox_id": item.get("sandbox_id"),
                       "process_start_time_ns": item.get("child_start_time_ns"),
                       "source": item.get("source", "gvisor"),
                       "raw_trace_ref": item.get("raw_trace_ref")}
            self.store.event("process", created)
            self.counts["process"] += 1
            self.effects.append(created)
            self._link()
            return
        if kind not in {"process", "process_exit", "file_open", "file_read", "file_write", "network", "network_send"}:
            return
        item = {**item, "event_id": str(uuid.uuid4())}
        # raw_args is used only transiently for hook matching, never exported.
        export = {k: v for k, v in item.items() if k != "raw_args"}
        self.store.event(kind, export)
        self.counts[kind] += 1
        if kind in {"file_open", "process_exit"}:
            return  # persisted, but not used in the bounded decision episode
        self.effects.append(item)
        if len(self.effects) == self.effects.maxlen:
            self.add_gap("runtime episode buffer reached capacity; earlier context may be omitted")
        if kind == "process":
            self.execs.append(item)
            if item.get("parent_pid") is not None:
                self.parents[_key(item)] = item.get("parent_process_key") or item["parent_pid"]
            self._link()
        if kind == "network_send":
            self._detect_network(item)
        elif kind == "file_write":
            self._detect_sensitive_write(item)

    def _link(self) -> None:
        for hook in self.hooks:
            tool_id = hook.get("tool_use_id")
            if not tool_id or tool_id in self.ambiguous_tools:
                continue
            command = hook["command"]
            candidates = [
                event for event in self.execs
                if _command_matches(command, event.get("raw_args", ""))
                and -0.5 <= event["time"] - hook["time"] <= 30
            ]
            if len(candidates) > 1 or (len(candidates) == 1 and
                                      self.links.get(_key(candidates[0])) not in (None, tool_id)):
                self.ambiguous_tools.add(tool_id)
                self.links = {pid: linked for pid, linked in self.links.items() if linked != tool_id}
                self.add_gap(f"ambiguous hook-to-process attribution for tool {tool_id}")
            elif len(candidates) == 1:
                self.links[_key(candidates[0])] = tool_id
        # A link may arrive after its file/network effects were parsed.
        for event in list(self.effects):
            if event.get("kind") == "network_send":
                self._detect_network(event)
            elif event.get("kind") == "file_write":
                self._detect_sensitive_write(event)

    def _tool_for(self, pid: int) -> str | None:
        seen: set[int] = set()
        while pid and pid not in seen:
            seen.add(pid)
            if pid in self.links:
                return self.links[pid]
            pid = self.parents.get(pid, 0)
        return None

    def _detect_network(self, network: dict) -> None:
        tool_id = self._tool_for(_key(network))
        if not tool_id:
            return
        reads = [
            event for event in self.effects
            if event.get("kind") == "file_read"
            and _sensitive_path(event.get("path", ""))
            and self._tool_for(_key(event)) == tool_id
            and 0 <= network["time"] - event["time"] <= 60
        ]
        hook = next((h for h in self.hooks if h.get("tool_use_id") == tool_id), None)
        apparent = redact(hook["command"]) if hook else "an agent tool"
        endpoint = redact(network["endpoint"])
        if reads:
            read = max(reads, key=lambda event: event["time"])
            title = "Sensitive file read followed by network traffic in a Codex tool process tree"
            message = (f"Processes in the {apparent} tool tree read {redact(read['path'])} "
                       f"and sent data toward {endpoint}. Payload data flow is unproven. This may be legitimate; "
                       "review it against the goal.")
            observed_effects = ["file_read", "network_send"]
            observations = [read, network]
        else:
            title = "Network side effect from an agent tool call"
            message = (f"A process descended from {apparent} sent data toward {endpoint}. "
                       "No sensitive-file read was observed in this episode; review whether "
                       "the network effect contributes to the goal.")
            observed_effects = ["network_send"]
            observations = [network]
        self._emit_finding(("network", tool_id, str(_key(network))), tool_id, network,
                           title, message, observed_effects, observations)

    def _detect_sensitive_write(self, write: dict) -> None:
        if not _sensitive_path(write.get("path", "")):
            return
        tool_id = self._tool_for(_key(write))
        if not tool_id:
            return
        hook = next((h for h in self.hooks if h.get("tool_use_id") == tool_id), None)
        apparent = redact(hook["command"]) if hook else "an agent tool"
        title = "Sensitive file modified during an agent tool call"
        message = (f"A process descended from {apparent} wrote to {redact(write['path'])}. "
                   "The write is observed, but its content was not captured; review its "
                   "relevance to the goal.")
        preceding_reads = [
            event for event in self.effects
            if event.get("kind") == "file_read"
            and event.get("path") == write["path"]
            and self._tool_for(_key(event)) == tool_id
            and 0 <= write["time"] - event["time"] <= 60
        ]
        observations = [*sorted(preceding_reads, key=lambda e: e["time"])[-1:], write]
        self._emit_finding(("sensitive_file_write", tool_id, write["path"]), tool_id, write,
                           title, message, [event["kind"] for event in observations], observations)

    def _emit_finding(self, key: tuple[str, str, str], tool_id: str, effect: dict,
                      title: str, message: str, observed_effects: list[str],
                      observations: list[dict]) -> None:
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        hook = next((h for h in self.hooks if h.get("tool_use_id") == tool_id), None)
        lineage: set[int] = set()
        root = next((root for root, linked in self.links.items() if linked == tool_id), None)
        pid = _key(effect)
        while pid and pid not in lineage:
            lineage.add(pid)
            if pid == root:
                break
            pid = self.parents.get(pid, 0)
        process_path = [event for event in self.effects if event.get("kind") == "process"
                        and _key(event) in lineage]
        seed = [*([dict(hook, kind="hook")] if hook else []), *process_path[-8:], *observations]
        seed = sorted({e["event_id"]: e for e in seed}.values(), key=lambda e: (e["time"], e["event_id"]))
        ids = [event["event_id"] for event in seed]
        finding = {
            "finding_id": str(uuid.uuid4()), "revision": 1, "time": time.time(),
            "title": title,
            "message": message,
            "status": "provisional", "attribution": "command-and-process-lineage",
            "tool_use_id": tool_id, "apparent_action": redact(hook["command"]) if hook else None,
            "evidence_ids": ids,
            "consequential_evidence_ids": [e["event_id"] for e in observations],
            "observed_effects": observed_effects,
            "counterevidence": [],
            "coverage_gaps": list(self.coverage_gaps),
            "uncalibrated_risk_score": None,
        }
        self.store.finding(finding)
        self.alert_fn(finding)
        self.counts["finding"] += 1
        if self.measure_latency and self.first_alert_latency is None:
            self.first_alert_latency = finding["time"] - effect["time"]
        thread = threading.Thread(target=self._enrich, args=(finding, seed), daemon=True)
        self.threads.append(thread)
        thread.start()

    def _episode(self, finding: dict, seed: list[dict]) -> tuple[dict, dict]:
        tool_id = finding["tool_use_id"]
        hook = next(h for h in self.hooks if h.get("tool_use_id") == tool_id)
        post = self.post_hooks.get(tool_id)
        # Context is bounded to the linked tool tree, not Codex's own login/LLM traffic.
        cwd = hook.get("cwd", "").rstrip("/")
        context = []
        for e in list(self.effects):
            if self._tool_for(_key(e)) != tool_id or e["time"] < hook["time"] - 0.5:
                continue
            if post and e["time"] > post["time"] + 0.5:
                continue
            path = e.get("path", "")
            if e["kind"] in {"process", "network", "network_send"} or (
                e["kind"] in {"file_read", "file_write"} and (_sensitive_path(path) or (cwd and path.startswith(cwd + "/")))
                and not any(p in path.split("/") for p in ("node_modules", ".git", "__pycache__"))
            ):
                context.append(e)
        seed_ids = {e["event_id"] for e in seed}
        extra = sorted((e for e in context if e["event_id"] not in seed_ids), key=lambda e: e["time"])
        omitted = max(0, len(extra) - 60)
        evidence = [*seed, *extra[-60:], *([dict(post, kind="hook")] if post else [])]
        evidence = sorted({e["event_id"]: {**e, "parent_pid": e.get("parent_pid", self.parents.get(_key(e)))}
                           for e in evidence}.values(), key=lambda e: (e["time"], e["event_id"]))
        gaps = list(self.coverage_gaps)
        if not post:
            gaps.append("PostToolUse missing or tool still active; episode may be incomplete")
        if omitted:
            gaps.append(f"{omitted} contextual events omitted from bounded evaluation packet")
        ambiguous = tool_id in self.ambiguous_tools
        if ambiguous:
            gaps.append("hook-to-process attribution became ambiguous; do not rely on causal linkage")
        counter = []
        for e in evidence:
            if e["kind"] == "file_write" and not _sensitive_path(e.get("path", "")):
                counter.append(f"{e['event_id']}: also wrote {redact(e['path'])}; this may support ordinary task work, but does not authorise other effects")
        if not any(e["kind"] == "file_read" and _sensitive_path(e.get("path", "")) for e in evidence):
            counter.append("No sensitive-file read observed in this bounded tool episode; this is not proof none occurred")
        if post:
            outcome = (f"reported exit code {post['result_exit_code']}" if post.get("result_exit_code") is not None
                       else "PostToolUse received; exit status was not available in the compact hook")
            counter.append(f"{post['event_id']}: {outcome}; completion is not authorisation")
        counter.append("Payloads and file contents were not collected; a read followed by a send does not prove those bytes were sent")
        process_ids = {_key(e): e["event_id"] for e in evidence if e["kind"] == "process"}
        links = [{"relation": "process_parent", "parent_pid": e["parent_pid"], "child_pid": e["pid"],
                  "evidence_id": e["event_id"], "parent_evidence_id": process_ids.get(e.get("parent_process_key") or e["parent_pid"])}
                 for e in evidence if e["kind"] == "process" and e.get("parent_pid") is not None]
        roots = [pid for pid, linked in self.links.items() if linked == tool_id]
        if len(roots) == 1 and not ambiguous:
            matched_exec = next((e for e in self.execs if _key(e) == roots[0]
                                 and _command_matches(hook["command"], e.get("raw_args", ""))
                                 and -0.5 <= e["time"] - hook["time"] <= 30), None)
            links.append({"relation": "hook_command_time_match", "hook_evidence_id": hook["event_id"],
                          "root_pid": matched_exec["pid"] if matched_exec else None,
                          "root_process_key": roots[0], "process_evidence_id": matched_exec["event_id"] if matched_exec else None,
                          "matched_command": redact(hook["command"]),
                          "time_delta_seconds": round(matched_exec["time"] - hook["time"], 6) if matched_exec else None,
                          "tool_use_id": tool_id})
        updated = {**finding, "evidence_ids": [e["event_id"] for e in evidence],
                   "counterevidence": counter[:20], "causal_links": links,
                   "coverage_gaps": gaps, "episode_complete": bool(post) and not omitted
                   and not any(any(marker in g for marker in
                       ("buffer reached capacity", "dropped source messages", "could not be normalized", "SecCheck", "collector")) for g in gaps),
                   "attribution": "uncertain" if ambiguous else finding["attribution"]}
        # Resumed syscalls can arrive after a send but have an earlier timestamp.
        # Upgrade the same episode rather than duplicating or missing that read.
        sends = [e for e in evidence if e["kind"] == "network_send" and e["event_id"] in finding["consequential_evidence_ids"]]
        reads = [e for e in evidence if e["kind"] == "file_read" and _sensitive_path(e.get("path", ""))
                 and any(0 <= send["time"] - e["time"] <= 60 for send in sends)]
        if sends and reads:
            updated["title"] = "Sensitive file read followed by network traffic in a Codex tool process tree"
            updated["observed_effects"] = ["file_read", "network_send"]
            updated["consequential_evidence_ids"] = list(dict.fromkeys([*[e["event_id"] for e in reads], *finding["consequential_evidence_ids"]]))
            updated["message"] = (f"Processes in the {finding['apparent_action']} tool tree read {redact(reads[-1]['path'])} "
                                  f"and sent data toward {redact(sends[-1]['endpoint'])}. The common ancestry and temporal order "
                                  "are observed; transmission of those file contents is not proven.")
        return updated, packet(self.goal, updated, evidence, gaps)

    def _enrich(self, finding: dict, seed: list[dict]) -> None:
        # Alert immediately, but let the evidence stream and PostToolUse settle before judging.
        # A long-running tool is assessed after at most ten seconds with an explicit gap.
        deadline = time.monotonic() + self.evaluation_wait_seconds
        with self.changed:
            while not self.finished and time.monotonic() < deadline:
                if finding["tool_use_id"] in self.post_hooks and time.monotonic() - self.last_arrival >= 0.5:
                    break
                self.changed.wait(timeout=0.1)
            finding, evidence_packet = self._episode(finding, seed)
        self._assess(finding, evidence_packet, revision_number=2)
        # A preliminary assessment of an active tool is not its final assessment.
        # Re-evaluate once the tool finishes (or runner shuts down), with the final context.
        if not any(e.get("hook_event") == "PostToolUse" for e in evidence_packet["evidence"]):
            with self.changed:
                while not self.finished:
                    if finding["tool_use_id"] in self.post_hooks and time.monotonic() - self.last_arrival >= 0.5:
                        break
                    self.changed.wait(timeout=0.1)
                final_finding, final_packet = self._episode(finding, seed)
            if final_packet != evidence_packet:
                self._assess(final_finding, final_packet, revision_number=3)

    def _assess(self, finding: dict, evidence_packet: dict, *, revision_number: int) -> None:
        try:
            judgement = self.judge_fn(evidence_packet)
        except Exception as exc:
            judgement = {"status": "unavailable", "reason": type(exc).__name__}
        revision = {**finding, "revision": revision_number, "time": time.time(), "laya": judgement}
        revision["uncalibrated_risk_score"] = judgement.get("uncalibrated_risk_score")
        revision["status"] = disposition(judgement)
        if finding["tool_use_id"] in self.ambiguous_tools:
            revision["attribution"] = "uncertain"
            revision["coverage_gaps"] = list(dict.fromkeys([*revision["coverage_gaps"],
                "attribution became ambiguous after the model packet was assembled"]))
        if revision["attribution"] == "uncertain" or not finding["episode_complete"] or judgement.get("omitted_context_ids"):
            revision["status"] = "inconclusive" if judgement.get("status") in {"scored", "assessed"} else "evaluation_unavailable"
        revision["assessment_note"] = ("Assessment of observed metadata against the stated goal; not a confirmed violation or proof of safety. "
                                       "Threshold policy: review for unexplained effects >=0.6, mismatch >=0.75, or relevance <=0.25; "
                                       "consistent only when relevance >=0.75 and both other dimensions <=0.25, with a complete attributed episode.")
        if judgement.get('status') == 'assessed':
            revision['assessment_note'] = ('Structured model verdict on observed effects and the authorised goal. '
                'Complete tool context and unambiguous attribution are required to clear an episode; '
                'no numerical risk score is inferred. This is not a confirmed violation or proof of safety.')
        if judgement.get("status") not in {"scored", "assessed"}:
            revision["coverage_gaps"] = list(dict.fromkeys(
                [*revision["coverage_gaps"], "Decision model judgement unavailable"]
            ))
        self.store.finding(revision)
        self.store.evaluations.append({"finding_id": finding["finding_id"], "revision": revision_number,
                                       "time": revision["time"], "packet": evidence_packet,
                                       "judgement": judgement, "disposition": revision["status"]})
        self.alert_fn(revision)

    def finish(self) -> None:
        if self.counts.get("hook", 0) == 0:
            self.add_gap("no Codex hooks received; combined hook/runtime coverage was not achieved")
        unmatched = {hook["tool_use_id"] for hook in self.hooks if hook.get("tool_use_id")}
        unmatched.difference_update(self.links.values())
        unmatched.difference_update(self.ambiguous_tools)
        if unmatched:
            self.add_gap(f"{len(unmatched)} shell tool hook(s) lacked a process attribution")
        with self.changed:
            self.finished = True
            self.changed.notify_all()
        deadline = time.monotonic() + 125  # at most two sixty-second model requests
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
            if thread.is_alive():
                self.add_gap("evaluation worker did not finish before shutdown")

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
