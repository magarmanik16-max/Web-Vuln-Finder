"""Scanner CLI — the Node integration contract.

Usage:
  python3 -m scanner.main --target-url https://example.com [--scan-id <id>] [--config cfg.json] [--output out.json]

Contract:
- target:      a PUBLIC HTTPS URL. The engine independently re-enforces the
               full safety policy (scheme, no port/userinfo, global-unicast
               DNS, origin-scoped redirects) — it never trusts the caller.
- scan id:     caller-supplied, echoed in the JSON report.
- config:      optional JSON file; values are clamped to safe ceilings.
- cancellation: SIGINT/SIGTERM -> graceful stop, status "cancelled".
- structured output: the JSON report is printed to stdout; human logs go to stderr.
- exit codes:  0 completed · 1 unsafe target · 2 usage error ·
               3 runtime failure · 4 cancelled.
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import uuid
from datetime import datetime, timezone

from .authorization import UnauthorizedTargetError, validate_target_url
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


def _emit_progress(stage: str, **kwargs) -> None:
    """Live progress for the Node Scan Manager: `PROGRESS {json}` on stderr."""
    import json as _json
    import time as _time

    payload = {"stage": stage, "ts": _time.time(), **kwargs}
    print(f"PROGRESS {_json.dumps(payload)}", file=sys.stderr, flush=True)


def run_scan(target_url: str, scan_id: str, config_path: str | None = None, stop_event: threading.Event | None = None) -> tuple:
    """Programmatic entry point (used by the CLI and unit tests)."""
    stop_event = stop_event or threading.Event()
    config = load_config(config_path)
    target = validate_target_url(target_url)  # independent policy + DNS check
    _emit_progress("check_started", name="authorization")

    result = ScanResult(
        scan_id=scan_id,
        target_id=target.host,
        target_url=target.target_url,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    client = SafeHTTPClient(config, origin_host=target.host, stop_event=stop_event)
    crawler = Crawler(client, target, config, on_error=_on_error(result))

    crawl = crawler.crawl()
    if crawl.pages:
        _emit_progress("check_done", name="connectivity")
    _emit_progress(
        "check_done",
        name="crawl",
        pages=len(crawl.pages),
        endpoints=len(crawl.parameter_urls) + len(crawl.api_endpoints),
        requests=client.requests_made,
        modules_done=["authorization", "connectivity", "crawl"],
    )
    ctx = ScanContext(target=target, config=config, client=client, crawl=crawl, result=result)

    done = ["authorization", "connectivity", "crawl"]
    for name in config.enabled_checks:
        if stop_event.is_set():
            break
        module = CHECKS.get(name)
        if module is None:
            continue
        _emit_progress("check_started", name=name, requests=client.requests_made, findings=len(result.findings), modules_done=list(done), modules_running=[name])
        try:
            for finding in module.run(ctx):
                result.add_finding(finding)
        except ScannerCancelled:
            raise
        except Exception as e:  # one broken check must not kill the scan
            result.add_error(f"check.{name}", f"{type(e).__name__}: {e}")
        done.append(name)
        _emit_progress("check_done", name=name, requests=client.requests_made, findings=len(result.findings), modules_done=list(done))

    result.statistics = {
        "pages_crawled": len(crawl.pages),
        "requests_made": client.requests_made,
        "forms_found": len(crawl.forms),
        "endpoints": len(crawl.parameter_urls) + len(crawl.api_endpoints),
    }
    return result, config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner", description="Authorized vulnerability scanner")
    parser.add_argument("--target-url", required=True, help="public HTTPS origin to assess (validated again independently)")
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
        result, _cfg = run_scan(args.target_url, args.scan_id, args.config, stop_event)
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
