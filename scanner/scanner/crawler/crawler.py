"""Same-origin crawler (SCANNER.md §6).

Discovers links, forms, query parameters and API-like endpoints. Hard limits:
max depth, max pages, max requests (enforced by the HTTP engine's global
budget), response size, timeout and concurrency — all from ScanConfig.

Boundary rules (defense-in-depth, independent of the HTTP engine):
- A candidate URL is enqueued only if authorize_request_url() accepts it
  (exact authorized host, https, no port/userinfo). Everything else — other
  hosts, subdomains, IP forms, http links, javascript:/mailto:/tel:/data:
  — is dropped before it can ever be fetched.
- URLs are normalized (fragment stripped, query params sorted) and
  deduplicated so the same page is never fetched twice.
"""

from __future__ import annotations

import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

from ..authorization import UnauthorizedTargetError, authorize_request_url
from ..httpengine import HTTPResponse, SafeHTTPClient, ScannerCancelled, ScannerHTTPError


@dataclass
class Form:
    action_url: str
    method: str
    inputs: list[dict[str, str]]
    source_url: str


@dataclass
class Page:
    url: str
    depth: int
    response: HTTPResponse
    forms: list[Form] = field(default_factory=list)


@dataclass
class CrawlOutput:
    pages: list[Page] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    # every discovered query-parameter name on the authorized origin
    parameter_names: list[str] = field(default_factory=list)
    # URLs carrying query parameters (candidates for param reflection testing)
    parameter_urls: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)


API_HINTS = ("/api/", "/wp-json/", ".json", "/graphql", "/rest/")


class _HTMLLinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "GET").upper(), "inputs": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name") or ""
            if name:
                self._form["inputs"].append({"name": name, "type": a.get("type", "text") if tag == "input" else tag})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def normalize_url(base: str, candidate: str, origin_host: str) -> str | None:
    """Resolve and normalize; return None for anything outside the origin rules."""
    if not candidate:
        return None
    candidate = candidate.strip()
    if candidate.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "ftp:", "sms:")):
        return None
    absolute = urljoin(base, candidate)
    try:
        canonical = authorize_request_url(absolute, origin_host)
    except UnauthorizedTargetError:
        return None
    # normalize: drop fragment (already), sort query params for stable dedupe
    parts = urlparse(canonical)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    normalized = urlunsplit(("https", parts.hostname, parts.path or "/", query, ""))
    return normalized


class Crawler:
    def __init__(self, client: SafeHTTPClient, target, config, on_error=None):
        self.client = client
        self.target = target
        self.config = config
        self.on_error = on_error or (lambda src, msg: None)
        self._lock = threading.Lock()

    def crawl(self) -> CrawlOutput:
        out = CrawlOutput()
        start = urlunsplit(("https", self.target.host, "/", "", ""))
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        seen: set[str] = {start}

        while queue and len(out.pages) < self.config.max_pages:
            if self.client.stop_event.is_set():
                raise ScannerCancelled()
            level_size = min(len(queue), self.config.max_pages - len(out.pages))
            batch = [queue.popleft() for _ in range(level_size)]
            with ThreadPoolExecutor(max_workers=max(1, self.config.concurrency)) as pool:
                for page in pool.map(lambda item: self._fetch(item[0], item[1]), batch):
                    if page is None:
                        continue
                    out.pages.append(page)
                    links = self._links_of(page)  # also populates page.forms
                    out.forms.extend(page.forms)
                    with self._lock:
                        for link in links:
                            normalized = normalize_url(page.url, link, self.target.host)
                            if not normalized or normalized in seen:
                                continue
                            seen.add(normalized)
                            if any(h in normalized for h in API_HINTS):
                                out.api_endpoints.append(normalized)
                            if urlsplit(normalized).query:
                                out.parameter_urls.append(normalized)
                                for name, _ in parse_qsl(urlsplit(normalized).query, keep_blank_values=True):
                                    if name not in out.parameter_names:
                                        out.parameter_names.append(name)
                            if page.depth + 1 <= self.config.max_depth:
                                queue.append((normalized, page.depth + 1))
        return out

    def _links_of(self, page: Page) -> list[str]:
        links = []
        collector = _HTMLLinkCollector()
        try:
            collector.feed(page.response.body)
            links = collector.links
            for f in collector.forms:
                action = urljoin(page.url, f["action"] or page.url)
                forms_action = normalize_url(page.url, action, self.target.host)
                if forms_action:
                    page.forms.append(Form(action_url=forms_action, method=f["method"], inputs=f["inputs"], source_url=page.url))
        except Exception as e:  # malformed HTML must never stop the scan
            self.on_error("crawler.parse", f"{page.url}: {e}")
        return links

    def _fetch(self, url: str, depth: int) -> Page | None:
        try:
            resp = self.client.get(url)
        except ScannerCancelled:
            raise
        except (ScannerHTTPError, UnauthorizedTargetError) as e:
            self.on_error("crawler.fetch", f"{url}: {e}")
            return None
        return Page(url=url, depth=depth, response=resp)
