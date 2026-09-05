"""Stub scanner used by Jest integration tests — mimics scanner.main's CLI
contract (same arguments, PROGRESS stderr lines, JSON output file, exit codes)
without touching the network. Behavior is selected via STUB_MODE env:

  ok        -> 2 findings, exit 0 (fast)
  cancelled -> sleeps until SIGTERM, then writes partial findings, exit 4
  fail      -> exit 3, no output
  garbage   -> writes invalid JSON, exit 0
"""

import json
import os
import signal
import sys
import time


def write_report(path, report):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh)


def finding(sev, title):
    from datetime import datetime, timezone

    return {
        "target_id": "stub.example.test",
        "target_url": "https://stub.example.test/",
        "url": "https://manikmagar.com.np/",
        "method": "GET",
        "parameter": "",
        "title": title,
        "category": "headers",
        "severity": sev,
        "confidence": "high",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "description": f"Stub finding: {title}",
        "evidence": {"url": "https://manikmagar.com.np/", "method": "GET", "status": 200, "detection_reason": "stub"},
        "impact": "stub impact",
        "remediation": "stub remediation",
        "scanner_module": "checks.headers",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    args = {}
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a.startswith("--"):
            args[a[2:]] = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("--") else ""

    mode = os.environ.get("STUB_MODE", "ok")
    output = args.get("output", "")
    scan_id = args.get("scan-id", "unknown")
    target_url = args.get("target-url", "https://stub.example.test/")

    # mirror the real scanner's independent enforcement for unsafe targets
    from urllib.parse import urlparse

    parts = urlparse(target_url)
    if parts.scheme != "https" or parts.hostname in ("127.0.0.1", "localhost", "169.254.169.254") or parts.port:
        print("UNAUTHORIZED", file=sys.stderr)
        return 1

    if mode == "fail":
        return 3

    if mode == "garbage":
        with open(output, "w") as fh:
            fh.write("{definitely not json")
        return 0

    if mode == "cancelled":
        done = {"flag": False}

        def handle(signum, frame):
            done["flag"] = True

        signal.signal(signal.SIGTERM, handle)
        signal.signal(signal.SIGINT, handle)
        print("PROGRESS " + json.dumps({"stage": "check_started", "name": "xss", "requests": 4}), file=sys.stderr, flush=True)
        while not done["flag"]:
            time.sleep(0.1)
        write_report(
            output,
            {
                "scan_id": scan_id,
                "target": {"id": "stub.example.test", "url": target_url},
                "status": "cancelled",
                "statistics": {"pages_crawled": 1, "requests_made": 5, "forms_found": 0, "endpoints": 0, "findings_by_severity": {"high": 1}},
                "findings": [finding("high", "Partial finding preserved on cancellation")],
                "errors": [],
            },
        )
        return 4

    # mode == ok
    print("PROGRESS " + json.dumps({"stage": "check_started", "name": "authorization"}), file=sys.stderr, flush=True)
    print("PROGRESS " + json.dumps({"stage": "check_done", "name": "crawl", "pages": 2, "endpoints": 3, "requests": 6, "modules_done": ["authorization", "connectivity", "crawl"]}), file=sys.stderr, flush=True)
    print("PROGRESS " + json.dumps({"stage": "check_started", "name": "headers"}), file=sys.stderr, flush=True)
    write_report(
        output,
        {
            "scan_id": scan_id,
            "target": {"id": "stub.example.test", "url": target_url},
            "status": "completed",
            "statistics": {"pages_crawled": 2, "requests_made": 8, "forms_found": 1, "endpoints": 3, "findings_by_severity": {"high": 1, "informational": 1}},
            "findings": [finding("high", "Stub high finding"), finding("informational", "Stub informational finding")],
            "errors": [],
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
