"""Observer-only local settings. Never execute or source an agent's .env."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

OBSERVER_KEYS = {"UNSLOTH_TOKEN", "TRACEWARD_LAYA_URL", "TRACEWARD_LAYA_MODEL",
                 "TRACEWARD_JUDGE_PROVIDER", "TRACEWARD_JUDGE_URL", "TRACEWARD_JUDGE_MODEL", "TRACEWARD_JUDGE_TOKEN"}


def load_observer_env(path: Path | None = None, *, extra_keys=()) -> None:
    """Environment wins; otherwise load TraceWard's checkout .env, not the cwd.

    Installed users can select an exact file via TRACEWARD_ENV_FILE. Never
    evaluate shell interpolation or commands, or load arbitrary environment keys.
    """
    if path is None:
        selected = os.environ.get("TRACEWARD_ENV_FILE")
        root = Path(__file__).resolve().parents[2]
        path = Path(selected).expanduser() if selected else root / ".env"
        if not selected and not (root / "pyproject.toml").is_file():
            return
    if not path.is_file():
        if os.environ.get("TRACEWARD_ENV_FILE"):
            raise ValueError("TRACEWARD_ENV_FILE does not name a readable file")
        return
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or key not in OBSERVER_KEYS | set(extra_keys) or key in os.environ:
            continue
        try:
            parts = shlex.split(value, comments=True)
        except ValueError as exc:
            raise ValueError(f"invalid observer setting on .env line {number}") from exc
        if len(parts) > 1:
            raise ValueError(f"quote whitespace in observer setting on .env line {number}")
        os.environ[key] = parts[0] if parts else ""
