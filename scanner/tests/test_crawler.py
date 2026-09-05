"""Same-origin crawler: discovery, normalization, boundaries, limits."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fakes import FakeClient  # noqa: E402

from scanner.config import ScanConfig  # noqa: E402
from scanner.crawler.crawler import Crawler, normalize_url  # noqa: E402
from scanner.httpengine import HTTPResponse, ScannerCancelled  # noqa: E402

BASE = "https://manikmagar.com.np"


def resp(url, body, status=200):
    return HTTPResponse(url=url, status=status, headers={}, body=body)


def crawl(pages: dict, **cfg):
    client = FakeClient({url: resp(url, body) for url, body in pages.items()})
    crawler = Crawler(client, type("T", (), {"host": "manikmagar.com.np", "url": BASE + "/"})(), ScanConfig(**cfg))
    return crawler.crawl(), client


class NormalizeTests(unittest.TestCase):
    def test_relative_and_absolute(self):
        self.assertEqual(normalize_url(f"{BASE}/a/", "/b", "manikmagar.com.np"), f"{BASE}/b")
        self.assertEqual(normalize_url(f"{BASE}/a/", f"{BASE}/b", "manikmagar.com.np"), f"{BASE}/b")

    def test_fragment_and_query_order_normalized(self):
        self.assertEqual(normalize_url(f"{BASE}/", f"{BASE}/p?b=2&a=1#frag", "manikmagar.com.np"), f"{BASE}/p?a=1&b=2")
        # same URL with different param order dedupes to one canonical form
        self.assertEqual(normalize_url(f"{BASE}/", f"{BASE}/p?a=1&b=2", "manikmagar.com.np"), f"{BASE}/p?a=1&b=2")

    def test_out_of_origin_dropped(self):
        for candidate in (
            "https://evil.com/x",
            "https://sub.manikmagar.com.np/x",
            "http://manikmagar.com.np/x",  # downgrade
            "https://manikmagar.com.np:8443/x",
            "javascript:void(0)",
            "mailto:a@b.c",
            "tel:+123",
            "data:text/html,x",
            "#anchor",
            "",
            None,
        ):
            self.assertIsNone(normalize_url(f"{BASE}/", candidate, "manikmagar.com.np"), candidate)


class CrawlerBoundaryTests(unittest.TestCase):
    def test_discovers_links_params_forms_api_endpoints(self):
        root = f"""<html><body>
            <a href="/about">About</a>
            <a href="/api/users">API</a>
            <a href="/search?q=hello">Search</a>
            <a href="https://evil.com/nope">Evil</a>
            <a href="http://manikmagar.com.np/nope">Downgrade</a>
            <form action="/contact" method="POST"><input name="email" type="email"/><input name="message"/></form>
            <form action="/search" method="GET"><input name="q"/></form>
        </body></html>"""
        out, client = crawl({"/": root})
        urls = [p.url for p in out.pages]
        self.assertIn(f"{BASE}/about", urls)
        self.assertIn(f"{BASE}/api/users", urls)
        self.assertIn(f"{BASE}/search?q=hello", urls)
        self.assertNotIn("https://evil.com/nope", urls)
        self.assertNotIn("http://manikmagar.com.np/nope", urls)
        self.assertIn(f"{BASE}/api/users", out.api_endpoints)
        self.assertIn("q", out.parameter_names)
        self.assertEqual({f.action_url for f in out.forms}, {f"{BASE}/contact", f"{BASE}/search"})

    def test_depth_limit(self):
        pages = {"/": '<a href="/1">1</a>', "/1": '<a href="/2">2</a>', "/2": '<a href="/3">3</a>', "/3": "leaf"}
        out, _ = crawl(pages, max_depth=2)
        depths = {p.url: p.depth for p in out.pages}
        self.assertIn(f"{BASE}/2", depths)
        self.assertNotIn(f"{BASE}/3", depths)  # depth 3 > max_depth 2

    def test_page_limit(self):
        root = "".join(f'<a href="/p{i}">i</a>' for i in range(20))
        pages = {"/": root, **{f"/p{i}": f"page {i}" for i in range(20)}}
        out, _ = crawl(pages, max_pages=5)
        self.assertEqual(len(out.pages), 5)

    def test_dedup_does_not_refetch(self):
        pages = {
            "/": '<a href="/a">a</a><a href="/a">a again</a><a href="/a?x=1">a with query</a>',
            "/a": '<a href="/">back</a>',
            "/a?x=1": "variant",
        }
        out, client = crawl(pages)
        fetched = [u for (_m, u) in client.requests]
        self.assertEqual(fetched.count(f"{BASE}/"), 1)
        self.assertEqual(fetched.count(f"{BASE}/a"), 1)
        # /a?x=1 is a distinct normalized URL from /a and IS fetched
        self.assertEqual(fetched.count(f"{BASE}/a?x=1"), 1)
        self.assertEqual(len(out.pages), 3)

    def test_cancellation_stops_crawl(self):
        client = FakeClient({"/": resp("/", '<a href="/1">x</a>')})
        client.stop_event.set()
        crawler = Crawler(client, type("T", (), {"host": "manikmagar.com.np", "url": BASE + "/"})(), ScanConfig())
        with self.assertRaises(ScannerCancelled):
            crawler.crawl()

    def test_fetch_errors_are_recorded_not_fatal(self):
        errors = []
        client = FakeClient({"/": resp("/", '<a href="/broken">b</a><a href="/ok">o</a>'), "/ok": resp("/ok", "fine")})
        # /broken has no canned response -> 404 from FakeClient; that still counts as a page.
        # To simulate an exception we monkeypatch get for that URL.
        original_get = client.get

        def get(url, headers=None):
            if url.endswith("/broken"):
                from scanner.httpengine import ScannerHTTPError

                raise ScannerHTTPError("boom")
            return original_get(url, headers)

        client.get = get
        crawler = Crawler(client, type("T", (), {"host": "manikmagar.com.np", "url": BASE + "/"})(), ScanConfig(), on_error=lambda s, m: errors.append((s, m)))
        out = crawler.crawl()
        self.assertTrue(errors)
        self.assertIn(f"{BASE}/ok", [p.url for p in out.pages])


if __name__ == "__main__":
    unittest.main()
