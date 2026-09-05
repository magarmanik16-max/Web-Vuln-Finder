"""JSON report assembly (SCANNER.md §21). Evidence is re-redacted at
serialization time as a final backstop (§20)."""

from __future__ import annotations

import json
from typing import Any

from ..models.evidence import sanitize


def build_report(result) -> dict[str, Any]:
    report = result.to_dict()
    report["findings"] = [sanitize(f) for f in report["findings"]]
    return report


def write_report(report: dict[str, Any], path: str | None) -> None:
    text = json.dumps(report, indent=2, ensure_ascii=False)
    print(text)
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
