"""Linux outer-container supervisor. Control files never enter the guest."""
from __future__ import annotations

import json
import os
import platform
import queue
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from google.protobuf.message import DecodeError

from ._gvisor.common_pb2 import Handshake
from .gvisor import MAX_PACKET, RELEASE, decode_packet, trace_config
from .ocsf import JsonlWriter
from .collector_status import write_status


class Receiver:
    def __init__(self, path: Path, output: Path, sandbox: str):
        self.path, self.sandbox = path, sandbox
        self.writer = JsonlWriter(output)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.server.bind(str(path))
        path.chmod(0o600)
        self.server.listen(4)
        self.server.settimeout(0.2)
        self.stopping = threading.Event()
        self.handshakes = self.messages = self.dropped = self.errors = 0
        self.pending = queue.Queue(maxsize=8192)
        self.pending_bytes = 0
        self.pending_lock = threading.Lock()
        self.queue_losses = 0
        self.persistence_failed = False
        self.disconnected_at = None
        self.worker = threading.Thread(target=self.persist, daemon=True)
        self.worker.start()
        self.connections: list[threading.Thread] = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def gap(self, message: str):
        try:
            self.writer.append({"message_type": "coverage", "message": message})
        except OSError:
            self.persistence_failed = True
            self.errors += 1

    def serve(self):
        while not self.stopping.is_set():
            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self.receive, args=(conn,), daemon=True)
            self.connections.append(t)
            t.start()

    def receive(self, conn):
        with conn:
            try:
                conn.settimeout(5)
                data, _, flags, _ = conn.recvmsg(MAX_PACKET)
                hello = Handshake()
                hello.ParseFromString(data)
                if flags & socket.MSG_TRUNC or hello.version != 1:
                    raise ValueError("unsupported handshake")
                conn.sendall(Handshake(version=1).SerializeToString())
                self.handshakes += 1
                conn.settimeout(0.2)
                while not self.stopping.is_set():
                    try:
                        data, _, flags, _ = conn.recvmsg(MAX_PACKET)
                    except socket.timeout:
                        continue
                    if not data:
                        self.disconnected_at = time.monotonic()
                        return
                    if flags & socket.MSG_TRUNC:
                        self.errors += 1
                        self.gap("SecCheck record rejected (truncated packet)")
                        continue
                    # Drain the socket independently of protobuf conversion and
                    # disk writes. Bound both queued bytes and packet count.
                    with self.pending_lock:
                        if self.pending_bytes + len(data) > 16 * 1024 * 1024 or self.pending.full():
                            self.queue_losses += 1
                            continue
                        self.pending_bytes += len(data)
                        self.pending.put_nowait(data)
            except Exception as exc:
                self.errors += 1
                self.gap(f"SecCheck connection failed ({type(exc).__name__})")

    def persist(self):
        try:
            self._persist()
        except OSError:
            self.persistence_failed = True
            self.errors += 1

    def _persist(self):
        last_dropped = 0
        # One writer preserves receive order and amortizes filesystem opens.
        with self.writer.path.open("a", encoding="utf-8") as stream:
            last_flush = time.monotonic()
            while True:
                data = self.pending.get()
                if data is None:
                    stream.flush()
                    return
                with self.pending_lock:
                    self.pending_bytes -= len(data)
                try:
                    record, dropped = decode_packet(data, self.sandbox)
                    delta = max(0, dropped - last_dropped)
                    if last_dropped > 0xf0000000 and dropped < 0x10000000:
                        delta = (dropped - last_dropped) & 0xffffffff
                        last_dropped = dropped
                    else:
                        last_dropped = max(last_dropped, dropped)
                    self.dropped += delta
                    if delta and self.dropped == delta:
                        stream.write(json.dumps({"message_type": "coverage", "message":
                            "gVisor reported dropped source messages; see runtime status for the count"}) + "\n")
                    record["dropped_count"] = dropped
                    stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                    self.messages += 1
                    if self.pending.empty() or time.monotonic() - last_flush > 0.1:
                        stream.flush()
                        last_flush = time.monotonic()
                except (ValueError, TypeError, KeyError, OverflowError, DecodeError) as exc:
                    self.errors += 1
                    stream.write(json.dumps({"message_type": "coverage", "message":
                        f"SecCheck record rejected ({type(exc).__name__})"}) + "\n")

    def close(self):
        # Guest shutdown closes the peer: drain queued packets, then finalize.
        for thread in self.connections:
            thread.join(2)
        self.stopping.set()
        self.server.close()
        self.thread.join(1)
        for thread in self.connections:
            thread.join(1)
        if self.worker.is_alive():
            try:
                self.pending.put(None, timeout=2)
            except queue.Full:
                self.persistence_failed = True
                self.errors += 1
            self.worker.join(30)
        if self.worker.is_alive():
            self.errors += 1
            self.gap("SecCheck persistence worker did not drain before shutdown")
        if self.queue_losses:
            self.gap(f"collector queue overflow discarded {self.queue_losses} source messages")
        self.path.unlink(missing_ok=True)


def supervise(request_path: Path, *, services_factory=None) -> int:
    request = json.loads(request_path.read_text())
    request_path.unlink()  # includes transient agent arguments/env, not evidence
    output = request_path.parent
    sandbox = "tw-" + request["run_id"]
    abi = "arm64" if platform.machine() in {"aarch64", "arm64"} else "amd64"
    if request.get("rootfs") == "/custom-rootfs":
        Path("/custom-rootfs").mkdir(mode=0o700, exist_ok=True)
        # This is a Docker export of an explicitly selected, trusted image.
        subprocess.run(["tar", "-xf", "/custom-rootfs.tar", "-C", "/custom-rootfs"], check=True)
    metadata = subprocess.run(['runsc', 'trace', 'metadata'], capture_output=True, text=True, check=True, timeout=10).stdout
    if 'sentry/file_delete' not in metadata:
        raise RuntimeError('incompatible runtime: required sentry/file_delete capability missing; rebuild the TraceWard runner')
    rootfs = Path(request.get("rootfs", "/opt/traceward/rootfs"))
    if not (rootfs / "usr/local/bin/python3").exists():
        raise RuntimeError("guest image requires /usr/local/bin/python3 for trusted hooks")
    fixture_server = None
    services = services_factory(request, output) if services_factory else []
    if request.get('fixture_receiver') and not services_factory:
        from http.server import BaseHTTPRequestHandler, HTTPServer
        class Discard(BaseHTTPRequestHandler):
            def do_POST(self):
                length = min(max(int(self.headers.get('Content-Length','0')),0),65536)
                self.rfile.read(length)
                self.send_response(204); self.end_headers()
            def log_message(self, *_): pass
        fixture_server = HTTPServer(('127.0.0.1',8800),Discard)
        threading.Thread(target=fixture_server.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix="tw-", ignore_cleanup_errors=True) as directory:
        tmp = Path(directory)
        receiver = Receiver(tmp / "events.sock", output / "raw.gvisor.jsonl", sandbox)
        config = tmp / "session.json"
        config.write_text(json.dumps(trace_config(str(receiver.path), abi)))
        bundle = tmp / "bundle"
        bundle.mkdir()
        subprocess.run(["runsc", "spec", "--bundle", str(bundle)], check=True,
                       stdout=subprocess.DEVNULL)
        spec_path = bundle / "config.json"
        spec = json.loads(spec_path.read_text())
        spec["root"] = {"path": request.get("rootfs", "/opt/traceward/rootfs"), "readonly": True}
        # Per-sandbox temporary files and explicitly mounted workspace/home are
        # writable, while the shared development image stays immutable.
        spec["mounts"] += [{"destination": path, "type": "tmpfs", "source": "tmpfs",
                            "options": ["rw", "nosuid", "nodev", "mode=1777"]} for path in ("/tmp", "/run")]
        # --network=host refers to the outer Docker namespace. A fresh OCI
        # network namespace would have only loopback and silently lose egress.
        spec["linux"]["namespaces"] = [n for n in spec["linux"]["namespaces"] if n["type"] != "network"]
        proc = spec["process"]
        launch = tmp / "launch"
        launch.mkdir(mode=0o755)
        (launch / "command.json").write_text(json.dumps(request["command"]))
        (launch / "command.json").chmod(0o644)
        home_mount = next(source for source, target, _ in request["guest_mounts"]
                          if target == request.get('home_target', '/codex-home'))
        proc.update({"args": ["/usr/local/bin/python3", "/opt/traceward-hooks/traceward/guest_start.py"], "cwd": request["cwd"],
                     "env": [f"{k}={v}" for k, v in request["env"].items()],
                     "user": {"uid": os.stat(home_mount).st_uid,
                              "gid": os.stat(home_mount).st_gid},
                     "terminal": False})
        # These are emulated guest capabilities. They let Codex establish
        # its nested user namespace; they grant no host kernel capabilities.
        for values in proc["capabilities"].values():
            values.extend(["CAP_SETUID", "CAP_SETGID", "CAP_SETFCAP"])
        proc["rlimits"] = [{"type": "RLIMIT_NOFILE", "hard": 65536, "soft": 65536}]
        spec["mounts"] += [{"destination": target, "type": "bind", "source": source,
                            "options": ["rbind", "rw" if writable else "ro"]}
                           for source, target, writable in request["guest_mounts"]]
        spec["mounts"] += [{"destination": path, "source": path, "type": "bind", "options": ["bind", "ro"]}
                           for path in ("/etc/resolv.conf", "/etc/hosts")]
        spec["mounts"].append({"destination": "/traceward-launch", "source": str(launch),
                               "type": "bind", "options": ["bind", "ro"]})
        spec_path.write_text(json.dumps(spec))
        base = ["runsc", "--root=" + str(tmp / "state"), "--platform=systrap", "--network=host",
                "--ignore-cgroups", "--pod-init-config=" + str(config)]
        # OCI terminal attachment requires a console socket. Proxy its PTY to
        # inherited Docker stdio, retaining window size and operator signals.
        console = None
        if sys.stdin.isatty() and sys.stdout.isatty():
            console = socket.socket(socket.AF_UNIX)
            console.bind(str(tmp / "console.sock"))
            console.listen(1)
            console.settimeout(30)
            proc["terminal"] = True
            spec_path.write_text(json.dumps(spec))
        command = [*base, "run", "--bundle=" + str(bundle)]
        if console:
            command += ["--console-socket=" + str(tmp / "console.sock")]
        command += [sandbox]
        # gVisor can log an init-session error and still start the sandbox.
        # Only the trusted bootstrap runs until the session is verified.
        child = subprocess.Popen(command)
        cleanup_started, signal_forwarded = False, False
        established = False
        def forward(signum, _frame):
            nonlocal signal_forwarded
            if cleanup_started or signal_forwarded: return
            signal_forwarded = True
            subprocess.run([*base, "kill", "--all", sandbox, str(signum)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        previous = {s: signal.signal(s, forward) for s in (signal.SIGTERM, signal.SIGINT)}
        status_failure_reported = False
        def persist_status(*, established, finalized):
            nonlocal status_failure_reported
            try:
                write_status(output, receiver, abi=abi, established=established, finalized=finalized)
            except OSError:
                # Losing observer status must not change the guest's outcome.
                if not status_failure_reported:
                    receiver.gap("collector status persistence failed; final counters unavailable")
                    status_failure_reported = True
        proxy = None
        try:
            persist_status(established=False, finalized=False)
            if console:
                from .terminal import ConsoleProxy
                proxy = ConsoleProxy(console)
                proxy.start()
            deadline = time.monotonic() + 15
            established = False
            while child.poll() is None and time.monotonic() < deadline:
                sessions = subprocess.run([*base, "trace", "list", sandbox],
                                          capture_output=True, text=True)
                if (sessions.returncode == 0 and '"Default"' in sessions.stdout and "remote" in sessions.stdout
                        and receiver.handshakes and receiver.worker.is_alive() and not receiver.persistence_failed):
                    established = True
                    persist_status(established=True, finalized=False)
                    (launch / "ready").touch()
                    break
                time.sleep(0.05)
            if not established:
                receiver.gap("required trace session missing; agent task was not started")
                subprocess.run([*base, "kill", "--all", sandbox, "KILL"], capture_output=True)
                child.wait()
                raise RuntimeError("gVisor required tracing session did not initialize")
            loss_reported = False
            last_status = time.monotonic()
            while child.poll() is None:
                for service in services:
                    if hasattr(service, 'check_health'): service.check_health()
                if receiver.disconnected_at and time.monotonic() - receiver.disconnected_at > 0.5 and not loss_reported:
                    receiver.gap("collector connection closed while the guest was running; coverage incomplete")
                    loss_reported = True
                if (receiver.persistence_failed or not receiver.worker.is_alive()) and not loss_reported:
                    receiver.gap("collector persistence failed while the guest was running; coverage incomplete")
                    loss_reported = True
                if time.monotonic() - last_status >= 1:
                    persist_status(established=established, finalized=False)
                    last_status = time.monotonic()
                time.sleep(0.05)
            code = child.wait()
        finally:
            cleanup_started = True
            try:
                if proxy:
                    proxy.close()
                if console:
                    console.close()
                subprocess.run([*base, "delete", "--force", sandbox],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for mount in [tmp / "state" / "null-netns"]:
                    subprocess.run(["umount", "-l", str(mount)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                receiver.close()
                if fixture_server:
                    fixture_server.shutdown()
                    fixture_server.server_close()
                for service in services:
                    service.shutdown()
                    service.server_close()
                if not receiver.handshakes or not receiver.messages:
                    receiver.gap("required gVisor telemetry was not established")
            finally:
                try:
                    persist_status(established=established, finalized=not receiver.worker.is_alive())
                finally:
                    for sig, handler in previous.items(): signal.signal(sig, handler)
        return code if code >= 0 else 128 - code


if __name__ == "__main__":
    raise SystemExit(supervise(Path(sys.argv[1])))
