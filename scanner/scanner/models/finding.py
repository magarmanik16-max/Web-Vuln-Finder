"""Finding model (SCANNER.md §16–§19).

DETECTION + EVIDENCE + RISK + REMEDIATION. Severity and confidence are
independent enums. Every finding carries a fingerprint used for deduplication
so one root cause cannot produce hundreds of near-identical findings.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.lower())
        except ValueError:
            return cls.INFORMATIONAL


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def parse(cls, value: str) -> "Confidence":
        try:
            return cls(value.lower())
        except ValueError:
            return cls.LOW


@dataclass
class Finding:
    target_id: str
    target_url: str
    url: str
    method: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: dict[str, Any]
    impact: str
    remediation: str
    module: str
    parameter: str = ""
    cwe: str = ""
    owasp: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def fingerprint(self) -> str:
        """Dedup key: same root cause at the same location must collapse."""
        root = f"{self.category}|{self.title}|{self.url.split('?')[0].lower()}|{self.method.upper()}|{self.parameter.lower()}"
        return hashlib.sha256(root.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "target_url": self.target_url,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "scanner_module": self.module,
            "timestamp": self.timestamp,
        }


def make_finding(**kwargs: Any) -> Finding:
    """Convenience constructor: accepts raw strings for severity/confidence."""
    kwargs["severity"] = Severity.parse(kwargs.get("severity", "informational"))
    kwargs["confidence"] = Confidence.parse(kwargs.get("confidence", "low"))
    return Finding(**kwargs)
