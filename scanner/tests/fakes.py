"""Shared offline fakes for scanner tests — no real network is ever touched."""

from __future__ import annotations

import threading
import uuid
from urllib.parse import urlsplit

from scanner.config import ScanConfig
from scanner.context import ScanContext
from scanner.crawler.crawler import CrawlOutput, Form, Page
from scanner.httpengine import HTTPResponse
from scanner.models.scanresult import ScanResult
from scanner.authorization import Target

PUBLIC_IP = "93.184.216.34"  # fictional public IP used by fake resolvers


def make_target(target_id: str = "STATIC_TARGET") -> Target:
    url = "https://manikmagar.com.np" if target_id == "STATIC_TARGET" else "https://mnk.manikmagar.com.np"
    return Target(target_id=target_id, host=urlsplit(url).hostname, url=url, type="static")


class FakeResponse:
    """http.client-shaped response."""

    def __init__(self, status: int, headers: list[tuple[str, str]] | None = None, body: bytes = b""):
        self.status = status
        self._headers = headers or []
        self._body = body

    def getheaders(self):
        return self._headers

    def read(self, n=-1):
        data, self._body = self._body, b""
        if n is None or n < 0:
            return data
        return data[:n]


class FakeConn:
    def __init__(self, response: FakeResponse):
        self._response = response
        self.requests: list[tuple[str, str, dict]] = []
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, headers or {}))

    def getresponse(self):
        return self._response

    def close(self):
        self.closed = True


def conn_factory_from(responses: list[FakeResponse]):
    """Connection factory serving canned responses in order."""
    conns: list[FakeConn] = [FakeConn(r) for r in responses]

    def factory(host, ip, timeout):
        if not conns:
            raise ConnectionError("no more canned connections")
        return conns.pop(0)

    factory.conns = conns
    return factory


class FakeClient:
    """SafeHTTPClient-shaped fake: canned responses keyed by URL path."""

    def __init__(self, responses: dict[str, HTTPResponse | list[HTTPResponse]] | None = None, config: ScanConfig | None = None):
        self.responses = responses or {}
        self.config = config or ScanConfig()
        self.stop_event = threading.Event()
        self.requests: list[tuple[str, str]] = []
        self.requests_made = 0
        self.probe_result = {"http_status": 301, "location": "https://x/", "upgrades_to_https": True}

    def request(self, method, url, headers=None, body=None, follow_redirects=True):
        self.requests.append((method.upper(), url))
        self.requests_made += 1
        if self.stop_event.is_set():
            raise RuntimeError("cancelled")
        path = urlsplit(url).path or "/"
        seq = self.responses.get(path) or self.responses.get(url)
        if seq is None:
            seq = HTTPResponse(url=url, status=404, headers={}, body="not found")
        resp = seq.pop(0) if isinstance(seq, list) else seq
        # return a copy with the requested URL (responses are reusable)
        return HTTPResponse(
            url=url,
            status=resp.status,
            headers=dict(resp.headers),
            body=resp.body,
            elapsed_ms=1,
            truncated=resp.truncated,
        )

    def get(self, url, headers=None):
        return self.request("GET", url, headers)

    def head(self, url, headers=None):
        return self.request("HEAD", url, headers)

    def options(self, url, headers=None):
        return self.request("OPTIONS", url, headers)

    def _validated_ip(self, host):
        return PUBLIC_IP

    def probe_http_redirect(self, target):
        self.requests.append(("HEAD", f"http://{target.host}/"))
        return self.probe_result


def make_page(url: str, body: str, status: int = 200, headers: dict | None = None, depth: int = 0) -> Page:
    return Page(
        url=url,
        depth=depth,
        response=HTTPResponse(url=url, status=status, headers=headers or {}, body=body),
    )


def make_ctx(client: FakeClient, pages: list[Page] | None = None, forms: list[Form] | None = None, param_urls: list[str] | None = None, param_names: list[str] | None = None) -> ScanContext:
    crawl = CrawlOutput(
        pages=pages or [],
        forms=forms or [],
        parameter_urls=param_urls or [],
        parameter_names=param_names or [],
    )
    target = make_target()
    return ScanContext(
        target=target,
        config=client.config,
        client=client,
        crawl=crawl,
        result=ScanResult(scan_id=str(uuid.uuid4()), target_id=target.target_id, target_url=target.url),
    )
