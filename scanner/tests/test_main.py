"""Integration contract (SCANNER.md §24): target ID, scan ID, config,
cancellation, structured JSON output, exit codes — orchestrated end-to-end
with fakes (no network)."""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fakes import FakeClient, make_page  # noqa: E402

from scanner.crawler.crawler import CrawlOutput  # noqa: E402
from scanner.httpengine import HTTPResponse, ScannerCancelled  # noqa: E402
from scanner.config import ScanConfig  # noqa: E402
from scanner.main import main, run_scan  # noqa: E402
from scanner.models.finding import make_finding  # noqa: E402
from scanner.models.scanresult import ScanResult  # noqa: E402

BASE = "https://manikmagar.com.np"

ROOT_HTML = """<html><head><title>Site</title></head><body>
<a href="/about">about</a>
<form action="/contact" method="POST"><input name="email"/><input name="password" type="password"/></form>
</body></html>"""

# TLS is excluded in orchestrated tests: it would open real sockets even
# against fake IPs. All other checks run through the FakeClient.
OFFLINE_CHECKS = ["headers", "cookies", "cors", "methods", "disclosure", "xss", "sqli", "csrf"]


def fake_client_factory(responses):
    def factory(config, stop_event=None, allowlist=None):
        client = FakeClient(responses, config=config)
        client.stop_event = stop_event or threading.Event()
        return client

    return factory


class ExitCodeTests(unittest.TestCase):
    def test_missing_target_id_is_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            main([])
        self.assertEqual(cm.exception.code, 2)

    def test_unknown_target_id_rejected_exit_1(self):
        code = main(["--target-id", "EVIL_TARGET", "--scan-id", "s1"])
        self.assertEqual(code, 1)

    def test_url_as_target_rejected_exit_1(self):
        # the scanner contract accepts IDs only; a URL is not an authorized ID
        code = main(["--target-id", "https://example.com", "--scan-id", "s1"])
        self.assertEqual(code, 1)


class OrchestrationTests(unittest.TestCase):
    def _run(self, responses, scan_id="scan-123", extra_args=None, crawler_patch=None, config=None):
        client = FakeClient(responses)
        config = config or ScanConfig(enabled_checks=OFFLINE_CHECKS)

        class FakeCrawler:
            def __init__(self, c, target, cfg, on_error=None):
                self.client = c

            def crawl(self):
                return CrawlOutput(pages=[make_page(f"{BASE}/", ROOT_HTML, headers={"server": "nginx/1.2.3"})])

        with mock.patch("scanner.main.load_config", lambda p=None: config), \
             mock.patch("scanner.main.validate_target_url", lambda *a, **k: None), \
             mock.patch("scanner.main.SafeHTTPClient", fake_client_factory(responses)), \
             mock.patch("scanner.main.Crawler", crawler_patch or FakeCrawler):
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--target-id", "STATIC_TARGET", "--scan-id", scan_id] + (extra_args or []))
        return code, out.getvalue(), client

    def test_completed_scan_outputs_json_and_exit_0(self):
        responses = {"/": HTTPResponse(url=f"{BASE}/", status=200, headers={"server": "nginx/1.2.3"}, body=ROOT_HTML)}
        code, output, _client = self._run(responses)

        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report["scan_id"], "scan-123")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["target"]["id"], "STATIC_TARGET")
        self.assertEqual(report["target"]["url"], BASE)
        self.assertIn("statistics", report)
        self.assertIn("findings", report)
        self.assertIn("errors", report)
        self.assertEqual(report["statistics"]["pages_crawled"], 1)
        self.assertTrue(any(f["category"] == "headers" for f in report["findings"]))
        required = {"id", "target_id", "url", "method", "parameter", "title", "category",
                    "severity", "confidence", "cwe", "owasp", "description", "evidence",
                    "impact", "remediation", "scanner_module", "timestamp"}
        for f in report["findings"]:
            self.assertTrue(required.issubset(f.keys()), f)

    def test_config_file_is_honoured(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"max_pages": 1, "enabled_checks": ["headers"]}, fh)
            path = fh.name
        try:
            responses = {"/": HTTPResponse(url=f"{BASE}/", status=200, headers={}, body=ROOT_HTML)}
            code, output, _client = self._run(responses, extra_args=["--config", path],
                                              config=ScanConfig(enabled_checks=["headers"], max_pages=1))
        finally:
            os.unlink(path)
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report["statistics"]["pages_crawled"], 1)
        self.assertTrue(all(f["category"] == "headers" for f in report["findings"]))

    def test_cancellation_reports_cancelled_exit_4(self):
        class CancellingCrawler:
            def __init__(self, client, target, config, on_error=None):
                self.client = client

            def crawl(self):
                self.client.stop_event.set()
                return CrawlOutput()

        code, output, _client = self._run({}, crawler_patch=CancellingCrawler)
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(output)["status"], "cancelled")


class ReportRedactionTests(unittest.TestCase):
    def test_report_serialization_redacts_secret_shaped_evidence(self):
        r = ScanResult(scan_id="s", target_id="STATIC_TARGET", target_url=BASE)
        r.add_finding(
            make_finding(
                target_id="STATIC_TARGET",
                target_url=BASE,
                url=BASE + "/login",
                method="POST",
                title="t",
                category="csrf",
                severity="medium",
                confidence="low",
                description="d",
                evidence={"password": "hunter2", "excerpt": "safe text"},
                impact="i",
                remediation="r",
                module="m",
            )
        )
        from scanner.reporting.json_report import build_report

        report = build_report(r)
        blob = json.dumps(report)
        self.assertNotIn("hunter2", blob)
        self.assertIn("[redacted]", blob)
        self.assertEqual(report["status"], "running")


class StopEventUnitTests(unittest.TestCase):
    def test_run_scan_propagates_cancellation(self):
        stop = threading.Event()
        stop.set()

        class StoppedClient(FakeClient):
            def request(self, *a, **k):
                raise ScannerCancelled()

        with mock.patch("scanner.main.validate_target_url", lambda *a, **k: None), \
             mock.patch("scanner.main.SafeHTTPClient", lambda config, stop_event=None, allowlist=None: StoppedClient(config=config)):
            with self.assertRaises(ScannerCancelled):
                run_scan("STATIC_TARGET", "s1", stop_event=stop)


if __name__ == "__main__":
    unittest.main()
