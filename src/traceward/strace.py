"""Parse a bounded subset of strace's text protocol into effect metadata.

The runner uses --raw for payload-bearing syscalls. This module never stores
read/write buffers; a positive read return value is the proof of a read.
"""

from __future__ import annotations

import ast
import os
import re
from collections import defaultdict
from pathlib import Path

TRACE_SYSCALLS = (
    "clone,clone3,fork,vfork,execve,execveat,chdir,open,openat,openat2,"
    "close,read,readv,pread64,preadv,write,writev,pwrite64,pwritev,"
    "connect,sendto,sendmsg"
)
RAW_SYSCALLS = "read,readv,pread64,preadv,write,writev,pwrite64,pwritev,sendto,sendmsg"

_LINE = re.compile(r"^(?:\[pid\s+(?P<pid>\d+)\]\s+|(?P<plain_pid>\d+)\s+)?(?P<time>\d+\.\d+)\s+(?P<body>.*)$")
_SYSCALL = re.compile(r"^(?P<name>[a-zA-Z_][a-zA-Z_0-9]*)\((?P<args>.*)\)\s+=\s+(?P<result>.*)$")
_QUOTED = re.compile(r'"(?:\\.|[^"\\])*"')
_FD = re.compile(r"^(?:0x)?([0-9a-fA-F]+)(?:<([^>]+)>)?")
_IPV4 = re.compile(r'inet_addr\("([^" ]+)"\)')
_IPV6 = re.compile(r'inet_pton\(AF_INET6, "([^" ]+)"')
_PORT = re.compile(r"sin6?_port=htons\((\d+)\)")


def _number(value: str) -> int | None:
    match = re.match(r"\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+))", value)
    if not match or match.group(1).startswith("-"):
        return None
    token = match.group(1)
    try:
        return int(token, 16 if token.startswith("0x") else 10)
    except ValueError:
        return None


def _quoted(value: str) -> str | None:
    match = _QUOTED.search(value)
    if not match:
        return None
    try:
        return ast.literal_eval(match.group())
    except (SyntaxError, ValueError):
        return None


class StraceParser:
    def __init__(self, cwd: str):
        self.cwd = defaultdict(lambda: cwd)
        self.parents: dict[int, int] = {}
        self.fd_paths: dict[int, dict[int, str]] = defaultdict(dict)
        self.sockets: dict[int, dict[int, str]] = defaultdict(dict)
        self.unfinished: dict[int, tuple[float, str]] = {}
        self.unparsed = 0
        self.line_number = 0

    def _path(self, pid: int, call: str, args: str, result: str) -> str | None:
        # -yy reports a canonical path on successful opens, including dirfd paths.
        tagged = re.search(r"=\s+\d+<(/[^>]+)>", result)
        if tagged:
            return tagged.group(1)
        raw = _quoted(args)
        if raw is None:
            return None
        if os.path.isabs(raw):
            return os.path.normpath(raw)
        if call in {"openat", "openat2"}:
            base = re.match(r"[^,]+<(/[^>]+)>", args)
            if base:
                return os.path.normpath(os.path.join(base.group(1), raw))
        return os.path.normpath(os.path.join(self.cwd[pid], raw))

    def parse(self, line: str) -> dict | None:
        self.line_number += 1
        match = _LINE.match(line.strip())
        if not match:
            self.unparsed += 1
            return None
        pid_value = match.group("pid") or match.group("plain_pid")
        if pid_value is None:
            self.unparsed += 1
            return None
        pid, when = int(pid_value), float(match.group("time"))
        body = match.group("body")
        if body.startswith(("+++", "---")):
            return None
        if body.endswith(" <unfinished ...>"):
            self.unfinished[pid] = (when, body.removesuffix(" <unfinished ...>"))
            return None
        resumed = re.match(r"^<\.\.\. [a-zA-Z_0-9]+ resumed>(.*)$", body)
        if resumed:
            previous = self.unfinished.pop(pid, None)
            if previous is None:
                self.unparsed += 1
                return None
            when, prefix = previous
            body = prefix + resumed.group(1)
        call = _SYSCALL.match(body)
        if not call:
            self.unparsed += 1
            return None
        name, args, result = call.group("name"), call.group("args"), call.group("result")
        retval = _number(result)
        common = {"time": when, "pid": pid, "syscall": name, "source": "strace",
                  "raw_trace_ref": f"raw.strace:{self.line_number}"}
        if name in {"clone", "clone3", "fork", "vfork"} and retval and retval > 0:
            child = retval
            self.parents[child] = pid
            self.fd_paths[child] = self.fd_paths[pid].copy()
            self.sockets[child] = self.sockets[pid].copy()
            self.cwd[child] = self.cwd[pid]
            return {**common, "kind": "fork", "child_pid": child}
        if name in {"execve", "execveat"} and result.startswith("0"):
            command = _quoted(args) or "unknown"
            # The full argv is intentionally not retained; it may contain secrets.
            return {**common, "kind": "process", "name": command,
                    "parent_pid": self.parents.get(pid), "command": command,
                    "raw_args": args[:1024]}
        if name == "chdir" and result.startswith("0"):
            new_cwd = _quoted(args)
            if new_cwd:
                self.cwd[pid] = os.path.normpath(os.path.join(self.cwd[pid], new_cwd))
            return None
        if name in {"open", "openat", "openat2"} and retval is not None:
            path = self._path(pid, name, args, result)
            if path is None:
                return None
            self.fd_paths[pid][retval] = path
            return {**common, "kind": "file_open", "path": path, "fd": retval}
        if name == "close" and retval == 0:
            fd = _number(args.split(",", 1)[0])
            if fd is not None:
                self.fd_paths[pid].pop(fd, None)
                self.sockets[pid].pop(fd, None)
            return None
        if name in {"read", "readv", "pread64", "preadv", "write", "writev", "pwrite64", "pwritev"}:
            fd = _number(args.split(",", 1)[0])
            endpoint = self.sockets[pid].get(fd) if fd is not None else None
            if endpoint and retval and retval > 0 and name.startswith(("write", "pwrite")):
                return {**common, "kind": "network_send", "endpoint": endpoint, "bytes": retval}
            path = self.fd_paths[pid].get(fd) if fd is not None else None
            if path and retval and retval > 0:
                kind = "file_read" if name.startswith(("read", "pread")) else "file_write"
                return {**common, "kind": kind, "path": path, "bytes": retval}
            return None
        if name == "connect" and (retval == 0 or "EINPROGRESS" in result):
            fd = _number(args.split(",", 1)[0])
            ip = _IPV4.search(args) or _IPV6.search(args)
            port = _PORT.search(args)
            if fd is not None and ip:
                endpoint = f"{ip.group(1)}:{port.group(1) if port else '0'}"
                self.sockets[pid][fd] = endpoint
                return {**common, "kind": "network", "endpoint": endpoint}
        if name in {"sendto", "sendmsg"} and retval and retval > 0:
            fd = _number(args.split(",", 1)[0])
            endpoint = self.sockets[pid].get(fd) if fd is not None else None
            if endpoint:
                return {**common, "kind": "network_send", "endpoint": endpoint, "bytes": retval}
        return None


def trace_command(command: list[str], trace_file: Path) -> list[str]:
    return [
        "strace", "-f", "-ttt", "-yy", "-s", "256", "-e", f"trace={TRACE_SYSCALLS}",
        "-e", f"raw={RAW_SYSCALLS}", "-o", str(trace_file), "--", *command,
    ]
