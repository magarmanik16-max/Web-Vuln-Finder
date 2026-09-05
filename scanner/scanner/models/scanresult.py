"""Scan result container with finding deduplication (SCANNER.md §21)."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from .finding import Finding, Severity


@dataclass
class ScanResult:
    scan_id: str
    target_id: str
    target_url: str
    status: str = "running"  # running | completed | cancelled | failed
    started_at: str = ""
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    _fingerprints: set[str] = field(default_factory=set, repr=False)
    _duplicates: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_finding(self, finding: Finding) -> bool:
        """Add a finding unless its fingerprint was already recorded."""
        with self._lock:
            fp = finding.fingerprint()
            if fp in self._fingerprints:
                self._duplicates += 1
                return False
            self._fingerprints.add(fp)
            self.findings.append(finding)
            return True

    def add_error(self, source: str, message: str) -> None:
        with self._lock:
            self.errors.append({"source": source, "message": str(message)[:300]})

    @property
    def duplicates_suppressed(self) -> int:
        return self._duplicates

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": {"id": self.target_id, "url": self.target_url},
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "statistics": {
                **self.statistics,
                "findings_total": len(self.findings),
                "findings_by_severity": self.severity_counts(),
                "duplicates_suppressed": self._duplicates,
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
