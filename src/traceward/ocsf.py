"""Small OCSF v1.8.0 projection for the supported PoC observations."""

from __future__ import annotations

import json
import ipaddress
import os
import socket
import threading
import time
import uuid
from pathlib import Path

from .privacy import redact

SCHEMA_VERSION = "1.8.0"
CLASSES = {
    "hook": (0, "Base Event", 0, "Uncategorized", 99, "Other"),
    "coverage": (0, "Base Event", 0, "Uncategorized", 99, "Other"),
    "process": (1007, "Process Activity", 1, "System Activity", 1, "Launch"),
    "file_open": (1001, "File System Activity", 1, "System Activity", 14, "Open"),
    "file_read": (1001, "File System Activity", 1, "System Activity", 2, "Read"),
    "file_write": (1001, "File System Activity", 1, "System Activity", 3, "Update"),
    "network": (4001, "Network Activity", 4, "Network Activity", 1, "Open"),
    "network_send": (4001, "Network Activity", 4, "Network Activity", 6, "Traffic"),
    "finding": (2004, "Detection Finding", 2, "Findings", 1, "Create"),
}


def project(kind: str, item: dict, run_id: str) -> dict:
    uid, class_name, category_uid, category_name, activity_id, activity_name = CLASSES[kind]
    when = item.get("time", time.time())
    event_id = item.get("event_id") or str(uuid.uuid4())
    record: dict = {
        "activity_id": activity_id,
        "activity_name": activity_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "class_uid": uid,
        "class_name": class_name,
        "metadata": {
            "uid": event_id,
            "version": SCHEMA_VERSION,
            "product": {"name": "TraceWard PoC", "vendor_name": "TraceWard", "version": "0.1.0"},
        },
        "severity_id": 3 if kind == "finding" else 1,
        "time": round(float(when) * 1000),
        "type_uid": uid * 100 + activity_id,
        "unmapped": {"traceward": {"run_id": run_id, "source": item.get("source", "traceward"),
                                   "event_id": event_id}},
    }
    if kind in {"process", "file_open", "file_read", "file_write"}:
        record["device"] = {"hostname": socket.gethostname(), "type_id": 0}
    if item.get("raw_trace_ref"):
        record["unmapped"]["traceward"]["raw_trace_ref"] = item["raw_trace_ref"]
    if kind == "process":
        proc = {"pid": int(item["pid"]), "name": redact(item.get("name", "unknown"), 128)}
        if item.get("parent_pid") is not None:
            proc["parent_process"] = {"pid": int(item["parent_pid"])}
        if item.get("command"):
            proc["cmd_line"] = redact(item["command"])
        record["process"] = proc
        record["actor"] = {"process": {"pid": int(item.get("parent_pid") or item["pid"])}}
    elif kind.startswith("file_"):
        record["actor"] = {"process": {"pid": int(item["pid"])}}
        record["file"] = {"path": redact(item["path"], 512),
                          "name": redact(os.path.basename(item["path"]), 255),
                          "type_id": 0}
        if item.get("bytes") is not None:
            record["unmapped"]["traceward"]["byte_count"] = int(item["bytes"])
    elif kind in {"network", "network_send"}:
        record["unmapped"]["traceward"]["pid"] = int(item["pid"])
        endpoint = item.get("endpoint", "")
        if endpoint:
            host, _, port = endpoint.rpartition(":")
            if host:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    record["dst_endpoint"] = {"domain": redact(host, 255)}
                else:
                    record["dst_endpoint"] = {"ip": host}
                if port.isdigit():
                    record["dst_endpoint"]["port"] = int(port)
        record["unmapped"]["traceward"]["endpoint"] = redact(endpoint, 255)
        if item.get("bytes") is not None:
            record["unmapped"]["traceward"]["byte_count"] = int(item["bytes"])
    elif kind == "finding":
        record["finding_info"] = {"uid": item["finding_id"], "title": item["title"]}
        record["is_alert"] = True
        record["message"] = redact(item["message"], 1000)
        record["unmapped"]["traceward"].update(
            {"revision": item["revision"], "evidence_ids": item["evidence_ids"]}
        )
    else:
        record["message"] = redact(item.get("message", kind), 1000)
        if kind == "hook":
            record["unmapped"]["traceward"].update(
                {"tool_use_id": item.get("tool_use_id"), "tool_name": item.get("tool_name"),
                 "session_id": item.get("session_id"), "hook_event": item.get("event"),
                 "apparent_command": redact(item.get("command", "")),
                 "file_targets": item.get("file_targets", []),
                 "result_status": item.get("result_status"),
                 "result_exit_code": item.get("result_exit_code")}
            )
    return record


def validate_minimum(record: dict) -> None:
    """Fail locally on broken OCSF envelopes; full schema tests run separately."""
    for key in ("activity_id", "category_uid", "class_uid", "metadata", "severity_id", "time", "type_uid"):
        if key not in record:
            raise ValueError(f"missing OCSF field: {key}")
    if record["type_uid"] != record["class_uid"] * 100 + record["activity_id"]:
        raise ValueError("invalid OCSF type_uid")
    if record["class_uid"] == 1001 and not all(k in record for k in ("file", "actor")):
        raise ValueError("file event requires file and actor")
    if record["class_uid"] == 1007 and "process" not in record:
        raise ValueError("process event requires process")
    if record["class_uid"] == 2004 and "finding_info" not in record:
        raise ValueError("finding requires finding_info")


class JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)

    def append(self, record: dict) -> None:
        with self.lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
            stream.flush()


class EvidenceStore:
    def __init__(self, run_dir: Path, run_id: str):
        self.run_id = run_id
        self.events = JsonlWriter(run_dir / "events.jsonl")
        self.findings = JsonlWriter(run_dir / "findings.jsonl")

    def event(self, kind: str, item: dict) -> dict:
        record = project(kind, item, self.run_id)
        validate_minimum(record)
        self.events.append(record)
        return record

    def finding(self, item: dict) -> dict:
        record = self.event("finding", item)
        self.findings.append(item)
        return record
