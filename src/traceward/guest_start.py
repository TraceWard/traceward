"""Trusted startup rendezvous; never makes a decision about agent activity.

The supervisor exposes only this read-only, transient launch directory, then
releases the gate after verifying SecCheck. No collector control/evidence is
mounted. The directory contains the agent's own argv, not observer secrets.
"""
import json
import os
import time
from pathlib import Path


def main():
    control = Path("/traceward-launch")
    while not (control / "ready").exists():
        time.sleep(0.01)
    command = json.loads((control / "command.json").read_text())
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
