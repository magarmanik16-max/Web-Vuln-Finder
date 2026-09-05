"""Scanner CLI — the Node integration contract (SCANNER.md §24).

Usage:
  python3 -m scanner.main --target-id STATIC_TARGET [--scan-id <id>] [--config cfg.json] [--output out.json]

Contract:
- target:      ONLY an allowlisted target ID (never a URL) — resolved through
               scanner.authorization, then re-validated origin+DNS.
- scan id:     caller-supplied, echoed in the JSON report.
- config:      optional JSON file; values are clamped to safe ceilings.
- cancellation: SIGINT/SIGTERM -> graceful stop, status "cancelled".
- structured output: the JSON report is printed to stdout; human logs go to stderr.
- exit codes:  0 completed · 1 unauthorized target · 2 usage error ·
               3 runtime failure · 4 cancelled.
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import uuid
from datetime import datetime, timezone

from .authorization import UnauthorizedTargetError, load_allowlist, resolve_target_id, validate_target_url
from .config import load_config
from .context import ScanContext
from .crawler.crawler import Crawler
from .checks import CHECKS
from .httpengine import SafeHTTPClient, ScannerCancelled, ScannerHTTPError
from .models.scanresult import ScanResult
from .reporting.json_report import build_report, write_report


def _on_error(result):
    def handler(source: str, message: str) -> None:
        result.add_error(source, message)

    return handler


def run_scan(target_id: str, scan_id: str, config_path: str | None = None, stop_event: threading.Event | None = None) -> tuple:
    """Programmatic entry point (used by the CLI and unit tests)."""
    stop_event = stop_event or threading.Event()
    config = load_config(config_path)
    allowlist = load_allowlist()
    target = resolve_target_id(target_id, allowlist)  # IDs only — never URLs
    validate_target_url(target.url, allowlist=allowlist)  # origin + DNS re-check

    result = ScanResult(
        scan_id=scan_id,
        target_id=target.target_id,
        target_url=target.url,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    client = SafeHTTPClient(config, stop_event=stop_event, allowlist=allowlist)
    crawler = Crawler(client, target, config, on_error=_on_error(result))

    crawl = crawler.crawl()
    ctx = ScanContext(target=target, config=config, client=client, crawl=crawl, result=result)

    for name in config.enabled_checks:
        if stop_event.is_set():
            break
        module = CHECKS.get(name)
        if module is None:
            continue
        try:
            for finding in module.run(ctx):
                result.add_finding(finding)
        except ScannerCancelled:
            raise
        except Exception as e:  # one broken check must not kill the scan
            result.add_error(f"check.{name}", f"{type(e).__name__}: {e}")

    result.statistics = {"pages_crawled": len(crawl.pages), "requests_made": client.requests_made, "forms_found": len(crawl.forms)}
    return result, config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner", description="Authorized vulnerability scanner (Phase 2)")
    parser.add_argument("--target-id", required=True, help="STATIC_TARGET or DYNAMIC_TARGET (never a URL)")
    parser.add_argument("--scan-id", default=None, help="caller-supplied scan id (default: generated)")
    parser.add_argument("--config", default=None, help="path to JSON config")
    parser.add_argument("--output", default=None, help="also write the JSON report to this path")
    args = parser.parse_args(argv)
    if not args.scan_id:
        args.scan_id = str(uuid.uuid4())

    stop_event = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda _s, _f: stop_event.set())
        except (ValueError, OSError):
            pass

    try:
        result, _cfg = run_scan(args.target_id, args.scan_id, args.config, stop_event)
        result.status = "cancelled" if stop_event.is_set() else "completed"
        write_report(build_report(result), args.output)
        return 4 if result.status == "cancelled" else 0
    except UnauthorizedTargetError as e:
        print(f"UNAUTHORIZED: {e}", file=sys.stderr)
        return 1
    except ScannerCancelled:
        print("SCAN CANCELLED", file=sys.stderr)
        return 4
    except ScannerHTTPError as e:
        print(f"HTTP FAILURE: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"RUNTIME FAILURE: {type(e).__name__}: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
