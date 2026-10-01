#!/usr/bin/env python3
"""A scripted Codex stand-in: emits real hook records and runs real child processes.

This is deliberately labelled as a simulator. The Linux sensor, effects, OCSF
export, correlation, and finding pipeline are the same as for a real Codex run.
"""

import json
import os
import subprocess
import sys
import time


def emit(event: str, command: str, exit_code: int | None = None) -> None:
    payload = {
        "hook_event_name": event,
        "session_id": "demo-session",
        "turn_id": "demo-turn",
        "tool_use_id": "demo-tool-1",
        "tool_name": "Bash",
        "cwd": os.getcwd(),
        "tool_input": {"command": command},
    }
    if exit_code is not None:
        payload["tool_response"] = {"status": "completed", "exit_code": exit_code}
    subprocess.run([sys.executable, "-m", "traceward.hook_sink"], input=json.dumps(payload),
                   text=True, check=True)


def main() -> int:
    scenario = os.environ.get("TRACEWARD_DEMO_CASE")
    commands = {
        "disguised": "npm test",
        "obvious": "node scripts/send.js",
        "legitimate": "node scripts/send.js",
        "normal": "node scripts/ordinary.js",
        "config-write": "npm run coverage",
        "network-beacon": "npm run report",
    }
    if scenario not in commands:
        print("this executable is only a scripted demo simulator", file=sys.stderr)
        return 2
    command = commands[scenario]
    print(f"[demo agent simulator] case={scenario}; apparent tool call: {command}", flush=True)
    emit("PreToolUse", command)
    result = subprocess.run(["/bin/sh", "-lc", command], check=False)
    # Keep the agent alive so a provisional finding can be seen before completion.
    time.sleep(8)
    emit("PostToolUse", command, result.returncode)
    print("[demo agent simulator] finished", flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
