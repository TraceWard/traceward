"""Collector finalization is independent of agent exit and model availability."""
import json
import os
import time
from pathlib import Path


def read_status(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def describe_status(status: dict, observed_records: int = 0) -> dict:
    observed = bool(observed_records or status.get('source_messages'))
    established = True if observed else status.get('trace_established',
        bool(status['handshakes']) if 'handshakes' in status else None)
    finalized = bool(status.get('finalized', bool(status.get('handshakes') and status.get('source_messages'))))
    losses = any(status.get(k) for k in ('collector_failed', 'decode_errors', 'collector_dropped_messages', 'dropped_messages'))
    if not established:
        state = 'not_established' if established is False else 'unknown'
        message = 'gVisor telemetry was not established; run coverage is incomplete' if state == 'not_established' else 'Collector status unavailable; telemetry establishment could not be confirmed'
    elif not finalized:
        state = 'incomplete'
        message = 'Telemetry observed; final collector status/counters unavailable; trailing coverage is unknown'
    else:
        state = 'incomplete' if losses else 'complete'
        message = 'Collection finalized with reported loss or collector errors' if losses else 'Collection finalized; loss after the last source header remains unknown'
    return dict(status=state, trace_established=established, finalized=finalized, message=message)


def write_status(output: Path, receiver, *, abi: str, established: bool, finalized: bool) -> dict:
    from .gvisor import RELEASE
    versions = read_status(Path('/opt/traceward/versions.json'))
    provenance = read_status(Path('/opt/traceward/gvisor-provenance.json'))
    resources = {}
    if finalized:
        for name in ('cpu.stat', 'memory.peak'):
            try: resources[name] = (Path('/sys/fs/cgroup') / name).read_text().strip()
            except OSError: pass
    value = dict(runtime='gvisor', gvisor_release=RELEASE, abi=abi, versions=versions,
        gvisor_patch=provenance, trace_established=established, finalized=finalized,
        status_updated_at=time.time(), handshakes=receiver.handshakes, source_messages=receiver.messages,
        dropped_messages=receiver.dropped, decode_errors=receiver.errors,
        collector_dropped_messages=receiver.queue_losses, collector_failed=receiver.persistence_failed,
        outer_container_resources=resources,
        final_loss_counter='last received header; trailing loss after final message is unknown' if finalized else 'partial snapshot; final counters unavailable')
    target = output / 'runtime-status.json'
    temporary = output / 'runtime-status.json.tmp'
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        owner = output.stat()
        os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream)
        stream.flush()
    temporary.replace(target)
    return value
