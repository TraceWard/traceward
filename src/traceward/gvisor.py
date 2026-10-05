"""Metadata-only SecCheck decoding and effect normalization.

Schemas are vendored from release-20260928.0. No debug-text parser or OS tracer
is used. Linux sockaddr and raw syscall layouts are selected by guest ABI.
"""
from __future__ import annotations

import ipaddress
import json
import os
import struct
from collections import defaultdict

from google.protobuf.json_format import MessageToDict
from ._gvisor import common_pb2 as common, sentry_pb2 as sentry, syscall_pb2 as syscall, container_pb2 as container
from .privacy import redact

RELEASE = "release-20260928.0"
MAX_PACKET = 1024 * 1024
CONTEXT = ["time", "thread_id", "task_start_time", "group_id", "thread_group_start_time",
           "container_id", "cwd", "process_name", "parent_thread_group_id"]
POINTS = {
    "sentry/clone": [], "sentry/execve": [], "sentry/exit_notify_parent": [],
    **{f"syscall/{name}/exit": ["fd_path"] for name in
       ("open", "openat", "creat", "close", "read", "readv", "pread64", "preadv",
        "write", "writev", "pwrite64", "pwritev", "connect", "dup", "dup2", "dup3", "fcntl")},
    "syscall/socket/exit": [],
}
TYPES = {1: container.Start, 2: sentry.CloneInfo, 3: sentry.ExecveInfo, 4: sentry.ExitNotifyParentInfo, 5: sentry.TaskExit,
         6: syscall.Syscall, 7: syscall.Open, 8: syscall.Close, 9: syscall.Read,
         10: syscall.Connect, 12: syscall.Socket, 18: syscall.Fcntl, 19: syscall.Dup,
         34: syscall.Write}


def trace_config(endpoint: str, abi: str) -> dict:
    # sendto/sendmsg lack schematized points. Only already-connected sockets
    # can be resolved; destination pointers are never treated as addresses.
    numbers = (44, 46, 307) if abi == "amd64" else (206, 211, 269)
    points = {**POINTS, **{f"syscall/sysno/{n}/exit": [] for n in numbers}}
    if abi == "arm64":
        for name in ("open", "creat", "dup2"):
            points.pop(f"syscall/{name}/exit", None)
    return {"trace_session": {"name": "Default", "ignore_missing": False,
        "points": [{"name": name, "optional_fields": fields,
                    "context_fields": [f for f in CONTEXT if name != "sentry/exit_notify_parent" or f != "cwd"]}
                   for name, fields in points.items()],
        "sinks": [{"name": "remote", "ignore_setup_error": False,
                   "config": {"endpoint": endpoint, "retries": 30, "backoff_max": "1ms"}}]}}


def scrub(value):
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items() if k not in {"env", "envv", "credentials"}}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return redact(value, 4096) if isinstance(value, str) else value


def decode_packet(data: bytes, sandbox: str) -> tuple[dict, int]:
    if len(data) < 8 or len(data) > MAX_PACKET:
        raise ValueError("invalid SecCheck packet length")
    size, kind, dropped = struct.unpack_from("<HHI", data)
    if size < 8 or size > len(data) or kind not in TYPES:
        raise ValueError("invalid header or unknown SecCheck message type")
    message = TYPES[kind]()
    message.ParseFromString(data[size:])
    fields = MessageToDict(message, preserving_proto_field_name=True,
                           always_print_fields_with_no_presence=True)
    # Full argv is transient. Retain only hook-match shell commands and script
    # paths; generic arguments can contain credentials or file contents.
    argv = fields.pop("argv", fields.pop("args", []))
    if kind == 3:
        fields["command_candidates"] = ([redact(argv[i + 1]) for i, arg in enumerate(argv[:-1])
                                         if arg in {"-c", "-lc", "-cl"}][:2]
            if os.path.basename(fields.get("binary_path", "")) in {"sh", "bash", "dash", "zsh", "fish"} else [])
        fields["script_paths"] = [redact(arg, 256) for arg in argv[1:] if
            arg.endswith((".js", ".mjs", ".py", ".sh")) and not any(c.isspace() for c in arg)][:8]
    return {"message_type": kind, "sandbox_id": sandbox, "data": scrub(fields)}, dropped


def endpoint(address: str) -> str | None:
    import base64
    try:
        data = base64.b64decode(address, validate=True)
        family = int.from_bytes(data[:2], "little")
        port = int.from_bytes(data[2:4], "big")
        if family == 2 and len(data) >= 8:
            return f"{ipaddress.ip_address(data[4:8])}:{port}"
        if family == 10 and len(data) >= 24:
            return f"{ipaddress.ip_address(data[8:24])}:{port}"
    except (ValueError, TypeError):
        pass
    return None


class GvisorParser:
    def __init__(self, cwd: str, abi: str = "arm64"):
        self.cwd, self.abi = cwd, abi
        self.tables: dict[str, dict[int, dict]] = defaultdict(dict)
        self.parents: dict[str, str] = {}
        self.latest: dict[tuple[str, int], str] = {}
        self.line_number = self.unparsed = 0
        self.gaps: set[str] = set()

    def parse(self, line: str) -> dict | None:
        self.line_number += 1
        try:
            record = json.loads(line)
            if record.get("message_type") == "coverage":
                self.gaps.add(record["message"])
                return None
            return self.normalize(record)
        except (ValueError, TypeError, KeyError, OverflowError):
            self.unparsed += 1
            return None

    def normalize(self, record: dict) -> dict | None:
        d, kind, sandbox = record["data"], int(record["message_type"]), record["sandbox_id"]
        c = d["context_data"]
        pid, start = int(c["thread_group_id"]), int(c["thread_group_start_time_ns"])
        if not pid or not start:
            raise ValueError("process identity missing")
        key = f"{sandbox}:{pid}:{start}"
        self.latest[sandbox, pid] = key
        parent_pid = int(c.get("parent_thread_group_id", 0))
        parent = self.parents.get(key) or self.latest.get((sandbox, parent_pid))
        common = {"time": int(c["time_ns"]) / 1e9, "pid": pid, "process_key": key,
                  "parent_pid": parent_pid or None, "parent_process_key": parent,
                  "sandbox_id": sandbox, "process_start_time_ns": start,
                  "source": "gvisor", "raw_trace_ref": f"raw.gvisor.jsonl:{self.line_number}"}
        table = self.tables[key]
        if kind == 2:
            child = int(d["created_thread_group_id"])
            if child == pid:  # threads use the existing group identity/table
                return None
            child_key = f"{sandbox}:{child}:{int(d['created_thread_start_time_ns'])}"
            self.latest[sandbox, child] = child_key
            self.parents[child_key] = key
            self.tables[child_key] = table if int(d.get("flags", 0)) & 0x400 else table.copy()
            return {**common, "kind": "fork", "child_pid": child, "child_process_key": child_key,
                    "child_start_time_ns": int(d["created_thread_start_time_ns"])}
        if kind == 3:
            # exec unshares a CLONE_FILES table and closes CLOEXEC descriptors.
            self.tables[key] = {fd: info for fd, info in table.items() if not info.get("cloexec")}
            return {**common, "kind": "process", "name": d.get("binary_path", "unknown"),
                    "command": d.get("binary_path", "unknown"), "script_paths": d.get("script_paths", []),
                    "raw_args": json.dumps(d.get("command_candidates", []))}
        if kind == 4:
            self.tables.pop(key, None)
            return {**common, "kind": "process_exit", "exit_status": int(d.get("exit_status", 0))}
        if "exit" not in d:
            return None
        result, error = int(d["exit"].get("result", 0)), int(d["exit"].get("errorno", 0))
        common.update({"syscall_number": int(d.get("sysno", 0)), "result": result,
                       "errno": error, "operation_status": "failed" if error or result < 0 else "succeeded"})
        fd = int(d.get("fd", -1))
        if kind == 7:
            path = d.get("pathname", "")
            base = c.get("cwd") or self.cwd
            if fd >= 0:
                base = d.get("fd_path") or table.get(fd, {}).get("path", "")
                if not base and not path.startswith("/"):
                    self.gaps.add("relative open path could not be resolved from dirfd")
                    return None
            path = os.path.normpath(os.path.join(base, path))
            if not error and result >= 0:
                table[result] = {"path": path, "cloexec": bool(int(d.get("flags", 0)) & 0x80000)}
            return {**common, "kind": "file_open", "path": path, "path_resolution": "lexical; may include symlinks"}
        if kind == 8 and not error:
            table.pop(fd, None)
        if kind == 12 and not error and result >= 0:
            table[result] = {"socket": {}, "cloexec": bool(int(d.get("type", 0)) & 0x80000)}
        if kind == 19 and not error and result >= 0:
            table[result] = {**table.get(int(d["old_fd"]), {}), "cloexec": bool(int(d.get("flags", 0)) & 0x80000)}
        if kind == 18 and not error:
            cmd = int(d.get("cmd", 0))
            if cmd in {0, 1030}:
                table[result] = {**table.get(fd, {}), "cloexec": cmd == 1030}
            elif cmd == 2 and fd in table:
                table[fd] = {**table[fd], "cloexec": bool(int(d.get("args", 0)) & 1)}
        if kind == 10:
            if error == 115:
                common["operation_status"] = "pending"
            target = endpoint(d.get("address", ""))
            # EINPROGRESS is an attempted asynchronous connection; later positive
            # socket writes are proof of a send, never this attempt alone.
            if target and (not error or error == 115):
                table.setdefault(fd, {}).setdefault("socket", {})["endpoint"] = target
            return {**common, "kind": "network", "endpoint": target or "unresolved"}
        if kind in {9, 34, 6}:
            if result <= 0 or error:
                return None
            if kind == 6:
                fd = int(d["arg1"])
            info = table.get(fd, {})
            path = d.get("fd_path") or info.get("path", "")
            target = info.get("socket", {}).get("endpoint")
            if kind in {34, 6} and target:
                if kind == 6 and common["syscall_number"] == (307 if self.abi == "amd64" else 269):
                    return {**common, "kind": "network_send", "endpoint": target, "message_count": result}
                return {**common, "kind": "network_send", "endpoint": target, "bytes": result}
            if kind in {9, 34} and path.startswith("/"):
                return {**common, "kind": "file_read" if kind == 9 else "file_write",
                        "path": path, "bytes": result, "path_resolution": "gvisor fd_path" if d.get("fd_path") else "descriptor table"}
            if kind == 6:
                self.gaps.add("send destination unresolved for an unconnected or inherited socket")
        return None
