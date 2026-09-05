"""Safe evidence containers (SCANNER.md §20).

Evidence is what a report reader sees. It must never contain secrets:
- cookie values are dropped at construction time (only name + flags survive),
- keys that look secret-shaped are redacted,
- long response excerpts are truncated,
- the redaction runs again at serialization time as a backstop.
"""

from __future__ import annotations

import re
from typing import Any

SECRET_KEY_PATTERN = re.compile(r"password|passwd|secret|token|authorization|auth|session|credential|api[-_]?key|jwt|cookie", re.I)

# Raw token-ish blobs inside text: long base64url / hex / JWT fragments.
BLOB_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]{16,}\.){2}[A-Za-z0-9_-]{8,}|(?<![A-Fa-f0-9])[A-Fa-f0-9]{40,}(?![A-Fa-f0-9])|(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{48,}(?![A-Za-z0-9_-])")

MAX_EXCERPT = 400


def redact_string(text: str, limit: int = MAX_EXCERPT) -> str:
    text = BLOB_PATTERN.sub("[redacted]", text)
    return text[:limit]


def sanitize(obj: Any, limit: int = MAX_EXCERPT) -> Any:
    """Recursively redact secret-shaped keys and truncate string values."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if SECRET_KEY_PATTERN.search(str(k)):
                out[str(k)] = "[redacted]"
            else:
                out[str(k)] = sanitize(v, limit)
        return out
    if isinstance(obj, (list, tuple)):
        return [sanitize(v, limit) for v in obj]
    if isinstance(obj, str):
        return redact_string(obj, limit)
    return obj


def response_evidence(url: str, method: str, status: int, headers: dict[str, str], excerpt: str, reason: str, **extra: Any) -> dict[str, Any]:
    """Build a standard evidence dict for an HTTP observation."""
    keep = {}
    for name, value in (headers or {}).items():
        if SECRET_KEY_PATTERN.search(name):
            keep[name] = "[redacted]"
        else:
            keep[name] = redact_string(value, 200)
    ev = {
        "url": url,
        "method": method,
        "status": status,
        "headers": keep,
        "excerpt": redact_string(excerpt),
        "detection_reason": reason,
    }
    ev.update(sanitize(extra))
    return ev


def cookie_evidence(name: str, flags: dict[str, Any], source_url: str, reason: str) -> dict[str, Any]:
    """Cookie evidence carries ONLY the name and flag values — never the value."""
    return {
        "cookie_name": name,
        "flags": flags,
        "url": source_url,
        "cookie_value": "[redacted]",  # explicit: values are never stored
        "detection_reason": reason,
    }
