"""Metadata-only redaction at all persisted/model-facing boundaries."""

from __future__ import annotations

import re

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:[A-Z_]*)(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Z_]*\s*[=:]\s*)([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+")
_SK = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")


def redact(value: str, limit: int = 512) -> str:
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    text = _BEARER.sub(r"\1[REDACTED]", text)
    text = _SK.sub("[REDACTED]", text)
    return text[:limit] + ("…" if len(text) > limit else "")
