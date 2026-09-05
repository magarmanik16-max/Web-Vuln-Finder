"""Scanner configuration with conservative defaults and strict bounds.

A scan loads defaults from here; a JSON config file (via --config) may only
tighten or moderately adjust them — values are clamped to safe ceilings so no
configuration can turn the scanner into a flood tool (MASTER.md §3: never
flood endpoints / perform DoS).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from typing import Any

DEFAULT_USER_AGENT = "WebVulnApp-Scanner/0.2 (authorized security assessment; contact: site owner)"

# Hard ceilings — no user config may exceed these.
LIMITS = {
    "max_depth": 5,
    "max_pages": 200,
    "max_requests": 500,
    "request_timeout": 30,
    "max_response_bytes": 1_000_000,
    "concurrency": 8,
    "max_redirects": 5,
    "max_params_tested": 25,
    "min_request_interval": 0.1,  # seconds; never faster than 10 rps
}

ALL_CHECKS = [
    "headers",
    "tls",
    "cookies",
    "cors",
    "methods",
    "disclosure",
    "xss",
    "sqli",
    "csrf",
]


@dataclass
class ScanConfig:
    max_depth: int = 3
    max_pages: int = 50
    max_requests: int = 200
    request_timeout: float = 15.0
    max_response_bytes: int = 512_000
    concurrency: int = 4
    max_redirects: int = 5
    max_params_tested: int = 12
    min_request_interval: float = 0.25
    timing_probes: bool = False  # SQLi timing analysis; off by default
    user_agent: str = DEFAULT_USER_AGENT
    enabled_checks: list[str] = field(default_factory=lambda: list(ALL_CHECKS))

    def __post_init__(self) -> None:
        defaults = {f.name: f.default for f in fields(ScanConfig)}
        for name, ceiling in LIMITS.items():
            if name == "min_request_interval":
                continue  # a floor, handled below — not a ceiling
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                object.__setattr__(self, name, defaults[name])
            elif value > ceiling:
                object.__setattr__(self, name, ceiling)
        if self.min_request_interval < LIMITS["min_request_interval"]:
            object.__setattr__(self, "min_request_interval", LIMITS["min_request_interval"])
        unknown = [c for c in self.enabled_checks if c not in ALL_CHECKS]
        if unknown:
            raise ValueError(f"Unknown checks: {unknown}")


def load_config(path: str | None) -> ScanConfig:
    """Load a JSON config; unknown keys are ignored, values are clamped."""
    if not path:
        return ScanConfig()
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    valid = {f.name for f in fields(ScanConfig)}
    filtered = {k: v for k, v in raw.items() if k in valid}
    return ScanConfig(**filtered)


def config_to_dict(cfg: ScanConfig) -> dict[str, Any]:
    return {f.name: getattr(cfg, f.name) for f in fields(ScanConfig)}
