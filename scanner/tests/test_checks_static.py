"""Header/cookie/CORS/methods/disclosure checks against fixture pages."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fakes import FakeClient, make_ctx, make_page  # noqa: E402
from scanner.httpengine import HTTPResponse  # noqa: E402

from scanner.checks import cookies, cors, disclosure, headers, methods  # noqa: E402

BASE = "https://manikmagar.com.np"
GOOD_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


class HeaderTests(unittest.TestCase):
    def test_all_missing_six_findings(self):
        ctx = make_ctx(FakeClient(), [make_page(f"{BASE}/", "<html></html>")])
        findings = headers.run(ctx)
        self.assertEqual(len(findings), 6)

    def test_all_present_no_findings(self):
        ctx = make_ctx(FakeClient(), [make_page(f"{BASE}/", "<html></html>", headers=GOOD_HEADERS)])
        self.assertEqual(headers.run(ctx), [])

    def test_missing_hsts_is_low_not_critical(self):
        h = dict(GOOD_HEADERS)
        del h["strict-transport-security"]
        ctx = make_ctx(FakeClient(), [make_page(f"{BASE}/", "<html></html>", headers=h)])
        findings = headers.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "low")

    def test_frame_ancestors_supersedes_xfo(self):
        h = dict(GOOD_HEADERS)
        del h["x-frame-options"]
        h["content-security-policy"] = "default-src 'self'; frame-ancestors 'self'"
        ctx = make_ctx(FakeClient(), [make_page(f"{BASE}/", "<html></html>", headers=h)])
        self.assertEqual(headers.run(ctx), [])

    def test_weak_csp_reported_informational(self):
        h = dict(GOOD_HEADERS)
        h["content-security-policy"] = "default-src * 'unsafe-inline'"
        ctx = make_ctx(FakeClient(), [make_page(f"{BASE}/", "<html></html>", headers=h)])
        findings = headers.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "informational")
        self.assertIn("unsafe-inline", findings[0].evidence["headers"]["content-security-policy"])

    def test_findings_carry_evidence_and_remediation(self):
        ctx = make_ctx(FakeClient(), [make_page(f"{BASE}/", "<html></html>")])
        for finding in headers.run(ctx):
            self.assertIn("detection_reason", finding.evidence)
            self.assertTrue(finding.remediation)
            self.assertEqual(finding.module, "checks.headers")


class CookieTests(unittest.TestCase):
    def test_unprotected_session_cookie_three_findings(self):
        page = make_page(f"{BASE}/", "", headers={"set-cookie": "sessionid=TOPSECRET; Path=/"})
        ctx = make_ctx(FakeClient(), [page])
        findings = cookies.run(ctx)
        titles = [f.title for f in findings]
        self.assertEqual(len(findings), 3)
        self.assertTrue(any("Secure" in t for t in titles))
        self.assertTrue(any("HttpOnly" in t for t in titles))
        self.assertTrue(any("SameSite" in t for t in titles))

    def test_value_never_in_evidence(self):
        page = make_page(f"{BASE}/", "", headers={"set-cookie": "sessionid=TOPSECRETVALUE123; Path=/"})
        ctx = make_ctx(FakeClient(), [page])
        blob = str([f.to_dict() for f in cookies.run(ctx)])
        self.assertNotIn("TOPSECRETVALUE123", blob)

    def test_hardened_cookie_no_findings(self):
        page = make_page(f"{BASE}/", "", headers={"set-cookie": "sessionid=x; Path=/; Secure; HttpOnly; SameSite=Lax"})
        ctx = make_ctx(FakeClient(), [page])
        self.assertEqual(cookies.run(ctx), [])

    def test_flags_parsed_correctly(self):
        name, flags = cookies.parse_set_cookie("sid=v; Path=/admin; Domain=.example.com; Secure; HttpOnly; SameSite=Strict")
        self.assertEqual(name, "sid")
        self.assertTrue(flags["secure"])
        self.assertTrue(flags["httponly"])
        self.assertEqual(flags["samesite"], "strict")
        self.assertEqual(flags["path"], "/admin")

    def test_dedup_across_pages(self):
        h = {"set-cookie": "sid=v; Path=/"}
        ctx = make_ctx(FakeClient(), [make_page(f"{BASE}/", "", headers=h), make_page(f"{BASE}/2", "", headers=h)])
        findings = cookies.run(ctx)
        # three findings from the FIRST page; the second page's identical
        # Set-Cookie must be deduplicated at check level
        self.assertEqual(len(findings), 3)


class CORSTests(unittest.TestCase):
    def _page(self, **resp_headers):
        return make_page(f"{BASE}/", "", headers=resp_headers)

    def test_reflected_origin_with_credentials_high(self):
        client = FakeClient({"/": self._page()})
        client.request = lambda method, url, headers=None, body=None, follow_redirects=True: HTTPResponse(
            url=url, status=200, headers={"access-control-allow-origin": headers["Origin"], "access-control-allow-credentials": "true"}, body=""
        )
        ctx = make_ctx(client, [self._page()])
        findings = cors.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "high")
        self.assertIn("webvulnapp-attacker.example", str(findings[0].evidence["headers"]))

    def test_wildcard_informational(self):
        client = FakeClient()
        client.request = lambda method, url, headers=None, body=None, follow_redirects=True: HTTPResponse(
            url=url, status=200, headers={"access-control-allow-origin": "*"}, body=""
        )
        ctx = make_ctx(client, [self._page()])
        findings = cors.run(ctx)
        self.assertEqual(findings[0].severity.value, "informational")

    def test_reflected_without_credentials_medium(self):
        client = FakeClient()
        client.request = lambda method, url, headers=None, body=None, follow_redirects=True: HTTPResponse(
            url=url, status=200, headers={"access-control-allow-origin": headers["Origin"]}, body=""
        )
        ctx = make_ctx(client, [self._page()])
        self.assertEqual(cors.run(ctx)[0].severity.value, "medium")

    def test_no_acao_no_finding(self):
        ctx = make_ctx(FakeClient(), [self._page()])
        self.assertEqual(cors.run(ctx), [])


class MethodTests(unittest.TestCase):
    @staticmethod
    def _client(handler):
        """FakeClient whose request() logs every call, like the real engine."""
        client = FakeClient()

        def request(method, url, headers=None, body=None, follow_redirects=True):
            client.requests.append((method.upper(), url))
            return handler(method, url, headers or {})

        client.request = request
        return client

    def test_allow_header_dangerous_methods_reported(self):
        def handler(method, url, headers):
            if method == "OPTIONS":
                return HTTPResponse(url=url, status=200, headers={"allow": "GET, POST, PUT, DELETE"}, body="")
            return HTTPResponse(url=url, status=405, headers={}, body="")

        ctx = make_ctx(self._client(handler), [])
        findings = methods.run(ctx)
        self.assertTrue(any("PUT" in f.title and "DELETE" in f.title for f in findings))

    def test_trace_echo_reported_with_marker(self):
        def handler(method, url, headers):
            if method == "TRACE":
                return HTTPResponse(
                    url=url, status=200, headers={}, body=f"X-WebVulnApp-Marker: {headers.get('X-WebVulnApp-Marker', '')}"
                )
            if method == "OPTIONS":
                return HTTPResponse(url=url, status=200, headers={"allow": "GET, HEAD, POST"}, body="")
            return HTTPResponse(url=url, status=405, headers={}, body="")

        ctx = make_ctx(self._client(handler), [])
        findings = methods.run(ctx)
        self.assertTrue(any(f.method == "TRACE" for f in findings))

    def test_put_delete_sent_only_to_random_probe_path(self):
        def handler(method, url, headers):
            return HTTPResponse(url=url, status=200, headers={}, body="")

        client = self._client(handler)
        ctx = make_ctx(client, [])
        findings = methods.run(ctx)
        put_requests = [(m, u) for m, u in client.requests if m == "PUT"]
        self.assertEqual(len(put_requests), 1)
        path = put_requests[0][1]
        self.assertIn("/webvulnapp-probe-", path)  # random probe path — no real resource
        self.assertTrue(any("non-existent resource" in f.title for f in findings))

    def test_method_not_allowed_no_finding(self):
        def handler(method, url, headers):
            return HTTPResponse(url=url, status=405, headers={"allow": "GET, POST"}, body="")

        ctx = make_ctx(self._client(handler), [])
        self.assertEqual(methods.run(ctx), [])


class DisclosureTests(unittest.TestCase):
    def test_version_header_disclosure(self):
        page = make_page(f"{BASE}/", "<html></html>", headers={"server": "nginx/1.18.0", "x-powered-by": "Express"})
        ctx = make_ctx(FakeClient(), [page])
        findings = disclosure.run(ctx)
        self.assertEqual(len(findings), 2)

    def test_stack_trace_and_directory_listing(self):
        page = make_page(f"{BASE}/", "Traceback (most recent call last):\n  File 'app.py'\n<html><title>Index of /</title>")
        ctx = make_ctx(FakeClient(), [page])
        findings = disclosure.run(ctx)
        titles = [f.title for f in findings]
        self.assertTrue(any("Python stack trace" in t for t in titles))
        self.assertTrue(any("Directory listing" in t for t in titles))

    def test_env_probe_detected_with_excerpt_withheld(self):
        client = FakeClient({"/.env": make_page(f"{BASE}/.env", "DB_PASSWORD=supersecret\nAPP_KEY=abc", headers={"content-type": "text/plain"}).response})
        ctx = make_ctx(client, [])
        findings = [f for f in disclosure.run(ctx) if ".env" in f.url]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "high")
        self.assertIn("withheld", findings[0].evidence["excerpt"])
        self.assertNotIn("supersecret", str(findings[0].to_dict()))

    def test_clean_site_clean_probes(self):
        client = FakeClient({"/.env": make_page(f"{BASE}/.env", "404 not found", status=404).response})
        page = make_page(f"{BASE}/", "<html><body>clean</body></html>", headers={"server": "nginx/1.2.3"})
        ctx = make_ctx(client, [page])
        findings = disclosure.run(ctx)
        self.assertEqual(len(findings), 1)  # only the generic server version header
        self.assertEqual(findings[0].category, "disclosure")


if __name__ == "__main__":
    unittest.main()
