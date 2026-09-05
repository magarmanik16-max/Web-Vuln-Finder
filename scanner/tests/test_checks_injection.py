"""XSS, SQLi and CSRF checks — safe markers, minimal probes, no submissions."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fakes import FakeClient, make_ctx, make_page  # noqa: E402

from scanner.checks import csrf, sqli, xss  # noqa: E402
from scanner.config import ScanConfig  # noqa: E402
from scanner.httpengine import HTTPResponse  # noqa: E402

BASE = "https://manikmagar.com.np"
PARAM_URL = f"{BASE}/search?q=hello&page=2"


class XssTests(unittest.TestCase):
    def _probe_client(self, page_body: str):
        """Client that echoes the marker wherever the page body has @MARKER."""
        client = FakeClient()

        from urllib.parse import unquote

        def request(method, url, headers=None, body=None, follow_redirects=True):
            marker = unquote([p.split("=", 1)[1] for p in url.split("?", 1)[1].split("&") if p.startswith("q=")][0])
            echoed = page_body.replace("@MARKER", marker)
            return HTTPResponse(url=url, status=200, headers={}, body=echoed)

        client.request = request
        return client

    def test_raw_reflection_in_html_body_reported(self):
        client = self._probe_client("<p>Hello @MARKER, welcome</p>")
        ctx = make_ctx(client, param_urls=[PARAM_URL], param_names=["q"])
        findings = xss.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "xss")
        self.assertEqual(findings[0].parameter, "q")
        self.assertIn("html body", findings[0].title.lower() + findings[0].description)
        self.assertNotIn("confirmed", findings[0].title.lower())

    def test_raw_reflection_in_script_context_is_high(self):
        client = self._probe_client("<script>var x = '@MARKER';</script>")
        ctx = make_ctx(client, param_urls=[PARAM_URL])
        findings = xss.run(ctx)
        self.assertEqual(findings[0].severity.value, "high")

    def test_attribute_and_url_context(self):
        client = self._probe_client('<a title="@MARKER">x</a><img alt="@MARKER">')
        ctx = make_ctx(client, param_urls=[PARAM_URL])
        findings = xss.run(ctx)
        self.assertTrue(any("attribute" in f.title.lower() for f in findings))
        self.assertFalse(any(f.severity.value == "critical" for f in findings))

    def test_encoded_only_reflection_not_reported(self):
        # site HTML-encodes the marker's trailing quote -> no raw reflection
        client = FakeClient()

        from urllib.parse import unquote

        def get(url, headers=None):
            marker = unquote([p.split("=", 1)[1] for p in url.split("?", 1)[1].split("&") if p.startswith("q=")][0])
            token = marker[:-1]  # drop the trailing quote
            return HTTPResponse(url=url, status=200, headers={}, body=f"<p>{token}&quot;</p>")

        client.get = get
        ctx = make_ctx(client, param_urls=[PARAM_URL])
        self.assertEqual(xss.run(ctx), [])

    def test_no_reflection_no_finding(self):
        client = FakeClient({"/search": HTTPResponse(url=PARAM_URL, status=200, headers={}, body="<p>no marker here</p>")})
        ctx = make_ctx(client, param_urls=[PARAM_URL])
        self.assertEqual(xss.run(ctx), [])

    def test_markers_are_unique_per_request(self):
        markers = []
        client = FakeClient()

        from urllib.parse import unquote

        def get(url, headers=None):
            marker = unquote([p.split("=", 1)[1] for p in url.split("?", 1)[1].split("&") if p.startswith("q=")][0])
            markers.append(marker)
            return HTTPResponse(url=url, status=200, headers={}, body=f"<p>{marker}</p>")

        client.get = get
        urls = [f"{BASE}/p{i}?q=x" for i in range(3)]
        ctx = make_ctx(client, param_urls=urls)
        xss.run(ctx)
        self.assertEqual(len(markers), len(set(markers)))

    def test_param_budget_respected(self):
        client = FakeClient()
        count = {"n": 0}

        def get(url, headers=None):
            count["n"] += 1
            return HTTPResponse(url=url, status=200, headers={}, body="nothing reflected")

        client.get = get
        urls = [f"{BASE}/p{i}?q=x" for i in range(30)]
        ctx = make_ctx(client, param_urls=urls, param_names=[f"p{i}" for i in range(30)])
        xss.run(ctx)
        self.assertLessEqual(count["n"], ScanConfig().max_params_tested)

    def test_evidence_contains_marker_excerpt(self):
        client = self._probe_client("<p>Hello @MARKER, welcome</p>")
        ctx = make_ctx(client, param_urls=[PARAM_URL])
        f = xss.run(ctx)[0]
        self.assertIn("reflection", f.evidence["detection_reason"])


class SqliTests(unittest.TestCase):
    def test_db_error_signature_reported_high(self):
        client = FakeClient()

        def get(url, headers=None):
            # urlencode encodes the appended quote as %27; only the q probe triggers
            if "%27" in url and "q=hello%27" in url:
                return HTTPResponse(url=url, status=500, headers={}, body="<b>Warning</b>: You have an error in your SQL syntax near \"'\"")
            return HTTPResponse(url=url, status=200, headers={}, body="results")

        client.get = get
        ctx = make_ctx(client, param_urls=[PARAM_URL])
        findings = sqli.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "high")
        self.assertEqual(findings[0].confidence.value, "medium")
        self.assertIn("MySQL", findings[0].title)

    def test_boolean_differential_reported_low_confidence(self):
        client = FakeClient()

        def get(url, headers=None):
            if "AND+1%3D2" in url or "AND 1=2" in url:
                return HTTPResponse(url=url, status=200, headers={}, body="X" * 10)
            return HTTPResponse(url=url, status=200, headers={}, body="Y" * 300)

        client.get = get
        ctx = make_ctx(client, param_urls=[f"{BASE}/items?id=5"])
        findings = sqli.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence.value, "low")
        self.assertIn("boolean", findings[0].title.lower())

    def test_identical_responses_no_finding(self):
        client = FakeClient()

        def get(url, headers=None):
            return HTTPResponse(url=url, status=200, headers={}, body="same body")

        client.get = get
        ctx = make_ctx(client, param_urls=[f"{BASE}/items?id=5"])
        self.assertEqual(sqli.run(ctx), [])

    def test_no_enumeration_requests(self):
        client = FakeClient()

        def get(url, headers=None):
            if "%27" in url and "q=hello%27" in url:
                return HTTPResponse(url=url, status=500, headers={}, body="SQL syntax error")
            return HTTPResponse(url=url, status=200, headers={}, body="ok")

        client.get = get
        ctx = make_ctx(client, param_urls=[PARAM_URL])
        sqli.run(ctx)
        for _m, u in client.requests:
            lowered = u.lower()
            for banned in ("union+select", "information_schema", "or+1%3d1--", "select+*", "drop+table", "sleep%28", "benchmark%28"):
                self.assertNotIn(banned, lowered, u)

    def test_timing_probes_disabled_by_default(self):
        timings = []

        def get(url, headers=None):
            if "SLEEP" in url.upper() or "pg_sleep" in url.lower():
                timings.append(url)
            return HTTPResponse(url=url, status=200, headers={}, body="ok")

        client = FakeClient()
        client.get = get
        ctx = make_ctx(client, param_urls=[f"{BASE}/items?id=5"])
        self.assertFalse(ctx.config.timing_probes)
        sqli.run(ctx)
        self.assertEqual(timings, [])


class CsrfTests(unittest.TestCase):
    def test_post_form_without_token_reported(self):
        form = type("F", (), {"action_url": f"{BASE}/login", "method": "POST",
                              "inputs": [{"name": "email"}, {"name": "password", "type": "password"}], "source_url": BASE + "/"})()
        ctx = make_ctx(FakeClient(), forms=[form])
        findings = csrf.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("NOT submitted", findings[0].description)

    def test_post_form_with_token_not_reported(self):
        form = type("F", (), {"action_url": f"{BASE}/login", "method": "POST",
                              "inputs": [{"name": "email"}, {"name": "csrf_token"}, {"name": "password", "type": "password"}], "source_url": BASE + "/"})()
        ctx = make_ctx(FakeClient(), forms=[form])
        self.assertEqual(csrf.run(ctx), [])

    def test_get_search_form_not_reported(self):
        form = type("F", (), {"action_url": f"{BASE}/search", "method": "GET",
                              "inputs": [{"name": "q"}], "source_url": BASE + "/"})()
        ctx = make_ctx(FakeClient(), forms=[form])
        self.assertEqual(csrf.run(ctx), [])

    def test_forms_never_submitted(self):
        form = type("F", (), {"action_url": f"{BASE}/login", "method": "POST",
                              "inputs": [{"name": "password", "type": "password"}], "source_url": BASE + "/"})()
        client = FakeClient()
        ctx = make_ctx(client, forms=[form])
        csrf.run(ctx)
        posts = [(m, u) for m, u in client.requests if m == "POST"]
        self.assertEqual(posts, [])


if __name__ == "__main__":
    unittest.main()
