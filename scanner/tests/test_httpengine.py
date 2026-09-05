"""HTTP engine: redirect authorization, size caps, budget, rate limit,
cancellation — all with fake connections (no network)."""

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fakes import PUBLIC_IP, FakeConn, FakeResponse, conn_factory_from  # noqa: E402

from scanner.config import ScanConfig  # noqa: E402
from scanner.httpengine import (  # noqa: E402
    ScannerCancelled,
    ScannerHTTPError,
    SafeHTTPClient,
    _default_connection_factory,
)
from scanner.authorization import UnauthorizedTargetError  # noqa: E402

BASE = "https://manikmagar.com.np"


def make_client(conns_responses, **cfg):
    config = ScanConfig(**{"min_request_interval": 0, **cfg})
    return SafeHTTPClient(
        config,
        stop_event=threading.Event(),
        resolver=lambda h: [PUBLIC_IP],
        connection_factory=conn_factory_from(conns_responses),
    )


class RedirectAuthorizationTests(unittest.TestCase):
    def test_redirect_to_authorized_host_path_is_followed(self):
        client = make_client(
            [
                FakeResponse(302, [("Location", f"{BASE}/moved")], b""),
                FakeResponse(200, [("Content-Type", "text/html")], b"moved page"),
            ]
        )
        resp = client.get(f"{BASE}/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.url, f"{BASE}/moved")
        self.assertEqual(resp.redirect_chain, [f"{BASE}/moved"])

    def test_redirect_to_unauthorized_host_is_NEVER_followed(self):
        client = make_client([FakeResponse(302, [("Location", "https://evil.com/steal")], b"")])
        with self.assertRaises(UnauthorizedTargetError):
            client.get(f"{BASE}/")
        self.assertEqual(len(client._conn_factory.conns), 0)  # one connection used, no second

    def test_redirect_to_private_ip_is_NEVER_followed(self):
        client = make_client([FakeResponse(302, [("Location", "http://169.254.169.254/latest/meta-data/")], b"")])
        with self.assertRaises(UnauthorizedTargetError):
            client.get(f"{BASE}/")

    def test_redirect_downgrade_to_http_is_NEVER_followed(self):
        client = make_client([FakeResponse(302, [("Location", "http://manikmagar.com.np/")], b"")])
        with self.assertRaises(UnauthorizedTargetError):
            client.get(f"{BASE}/")

    def test_redirect_to_port_is_NEVER_followed(self):
        client = make_client([FakeResponse(302, [("Location", "https://manikmagar.com.np:8080/")], b"")])
        with self.assertRaises(UnauthorizedTargetError):
            client.get(f"{BASE}/")

    def test_too_many_redirects(self):
        loop = FakeResponse(302, [("Location", f"{BASE}/next")], b"")
        client = make_client([loop] * 8, max_redirects=3)
        with self.assertRaises(ScannerHTTPError):
            client.get(f"{BASE}/")

    def test_relative_redirect_resolved_and_authorized(self):
        client = make_client(
            [
                FakeResponse(301, [("Location", "/relative-target")], b""),
                FakeResponse(200, [], b"ok"),
            ]
        )
        resp = client.get(f"{BASE}/deep/path")
        self.assertEqual(resp.url, f"{BASE}/relative-target")

    def test_relative_redirect_escaping_origin_rejected(self):
        client = make_client([FakeResponse(301, [("Location", "//evil.com/x")], b"")])
        with self.assertRaises(UnauthorizedTargetError):
            client.get(f"{BASE}/")


class LimitTests(unittest.TestCase):
    def test_response_size_cap(self):
        big = b"A" * 5000
        client = make_client([FakeResponse(200, [], big)], max_response_bytes=1000)
        resp = client.get(f"{BASE}/")
        self.assertTrue(resp.truncated)
        self.assertEqual(len(resp.body), 1000)

    def test_request_budget_exhausted(self):
        responses = [FakeResponse(200, [], b"x") for _ in range(5)]
        client = make_client(responses, max_requests=2)
        client.get(f"{BASE}/1")
        client.get(f"{BASE}/2")
        with self.assertRaises(ScannerHTTPError):
            client.get(f"{BASE}/3")
        self.assertEqual(client.requests_made, 2)

    def test_rate_limit_min_interval(self):
        client = make_client([FakeResponse(200, [], b"x")] * 3, min_request_interval=0.2)
        start = time.monotonic()
        client.get(f"{BASE}/1")
        client.get(f"{BASE}/2")
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.19)

    def test_transport_error_wrapped(self):
        client = make_client([])  # factory raises ConnectionError immediately
        with self.assertRaises(ScannerHTTPError):
            client.get(f"{BASE}/")

    def test_retry_for_safe_methods_then_success(self):
        class FlakyFactory:
            def __init__(self):
                self.calls = 0

            def __call__(self, host, ip, timeout):
                self.calls += 1
                if self.calls == 1:
                    raise ConnectionError("reset")
                return FakeConn(FakeResponse(200, [], b"ok"))

        flaky = FlakyFactory()
        client = SafeHTTPClient(
            ScanConfig(min_request_interval=0),
            resolver=lambda h: [PUBLIC_IP],
            connection_factory=flaky,
        )
        resp = client.get(f"{BASE}/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(flaky.calls, 2)

    def test_unsafe_methods_not_retried(self):
        class FlakyFactory:
            def __init__(self):
                self.calls = 0

            def __call__(self, host, ip, timeout):
                self.calls += 1
                raise ConnectionError("no")

        flaky = FlakyFactory()
        client = SafeHTTPClient(
            ScanConfig(min_request_interval=0),
            resolver=lambda h: [PUBLIC_IP],
            connection_factory=flaky,
        )
        with self.assertRaises(ScannerHTTPError):
            client.request("PUT", f"{BASE}/probe")
        self.assertEqual(flaky.calls, 1)


class CancellationAndUrlRulesTests(unittest.TestCase):
    def test_cancelled_before_request(self):
        client = make_client([FakeResponse(200, [], b"x")])
        client.stop_event.set()
        with self.assertRaises(ScannerCancelled):
            client.get(f"{BASE}/")

    def test_non_https_rejected_at_engine_level(self):
        client = make_client([FakeResponse(200, [], b"x")])
        with self.assertRaises(UnauthorizedTargetError):
            client.get("http://manikmagar.com.np/")

    def test_port_rejected_at_engine_level(self):
        client = make_client([FakeResponse(200, [], b"x")])
        with self.assertRaises(UnauthorizedTargetError):
            client.get("https://manikmagar.com.np:9000/")

    def test_deep_path_allowed(self):
        client = make_client([FakeResponse(200, [], b"ok")])
        self.assertEqual(client.get(f"{BASE}/a/b/c?q=1").status, 200)

    def test_default_connection_factory_rejects_invalid_connections(self):
        # The real factory demands a validated certificate; a dead endpoint
        # must raise rather than return an anonymous connection.
        with self.assertRaises(Exception):
            _default_connection_factory("manikmagar.com.np", "127.0.0.1", 0.3)

    def test_probe_requires_allowlisted_host(self):
        from scanner.authorization import Target

        client = make_client([FakeResponse(200, [], b"x")])
        evil = Target(target_id="EVIL", host="evil.com", url="https://evil.com", type="static")
        with self.assertRaises(UnauthorizedTargetError):
            client.probe_http_redirect(evil)


if __name__ == "__main__":
    unittest.main()
