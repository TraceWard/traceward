"""Small Codex hook handler. It never returns a decision to Codex."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from .privacy import redact
from .state import content_redact
from .context import text_content


def compact_hook(payload: dict) -> dict:
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    response = payload.get("tool_response")
    response_json = json.dumps(response, sort_keys=True, default=str) if response is not None else ""
    response_meta = response if isinstance(response, dict) else {}
    patch = tool_input.get("patch", "")
    file_targets = (re.findall(r"^\*\*\* (?:Add|Update|Delete|Move to) File: (.+)$", patch, re.MULTILINE)
                    if isinstance(patch, str) else [])
    item = {
        "source": "codex_hook",
        "time": time.time(),
        "event": payload.get("hook_event_name"),
        "session_id": payload.get("session_id"),
        "turn_id": payload.get("turn_id"),
        "tool_use_id": payload.get("tool_use_id"),
        "tool_name": payload.get("tool_name"),
        "command": redact(str(tool_input.get("command", ""))),
        "file_targets": [redact(path, 256) for path in file_targets[:20]],
        "cwd": redact(str(payload.get("cwd", ""))),
        "response_sha256": hashlib.sha256(response_json.encode()).hexdigest() if response_json else None,
        "response_bytes": len(response_json),
        "result_status": redact(response_meta["status"], 32) if isinstance(response_meta.get("status"), str) else None,
        "result_exit_code": response_meta.get("exit_code") if isinstance(response_meta.get("exit_code"), int) else None,
    }
    # Explicit metadata allowlist: lifecycle hooks can carry prompts, transcripts
    # and other content which must not become implicit payload capture.
    metadata = {}
    for key in ("source", "reason", "trigger", "agent_id", "agent_type", "permission_mode"):
        if isinstance(payload.get(key), str):
            metadata[key] = redact(payload[key], 256)
    if isinstance(payload.get("stop_hook_active"), bool):
        metadata["stop_hook_active"] = payload["stop_hook_active"]
    item["hook_metadata"] = metadata
    if os.environ.get('TRACEWARD_CONTEXT_MODE') == 'redacted' and response is not None:
        item['response_excerpt'] = content_redact(text_content(response))
    return item


def main() -> int:
    target = os.environ.get("TRACEWARD_HOOK_FILE")
    if not target:
        return 0
    payload = {}
    try:
        payload = json.load(sys.stdin)
        item = compact_hook(payload)
        item["run_id"] = os.environ.get("TRACEWARD_RUN_ID")
        encoded = (json.dumps(item, separators=(",", ":")) + "\n").encode()
        fd = os.open(Path(target), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, encoded)
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError):
        # Observability must not change Codex's permission or execution outcome.
        pass
    if isinstance(payload, dict) and payload.get("hook_event_name") in {"Stop", "SubagentStop"}:
        # These events expect JSON output. An empty object makes no continuation
        # request and provides no instruction or permission decision.
        print("{}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
