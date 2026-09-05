"""Scanner HTTP engine (SCANNER.md §4, §5).

Safety properties (all enforced per request):
- URL authorization via authorization.authorize_request_url (exact allowlist
  host, https only, no port, no userinfo — any path on the authorized origin).
- DNS answers validated as global unicast, then the connection is PINNED to a
  validated IP with SNI/cert validation against the authorized hostname
  (validate-then-connect; closes the rebinding gap between check and connect).
- Redirects are followed manually: each hop re-authorized via
  authorize_request_url (exact same host), up to max_redirects.
- Timeout, response size cap, global rate limit, cooperative cancellation,
  small retry budget for idempotent methods.

The transport (connection_factory) is injectable so unit tests run with mock
connections and never touch the network.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlunparse

from .authorization import (
    UnauthorizedTargetError,
    authorize_request_url,
    resolve_and_validate_ips,
)


class ScannerCancelled(Exception):
    pass


class ScannerHTTPError(Exception):
    """Non-authorization transport failure (timeout, reset, bad status...)."""


class UnauthorizedRedirectError(UnauthorizedTargetError):
    pass


@dataclass
class HTTPResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int = 0
    truncated: bool = False
    redirect_chain: list[str] = field(default_factory=list)

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def header_all(self, name: str) -> list[str]:
        v = self.headers.get(name.lower())
        return [v] if v is not None else []


class _RateLimiter:
    """Global minimum interval between request starts."""

    def __init__(self, min_interval: float, stop_event: threading.Event | None = None):
        self.min_interval = min_interval
        self._stop = stop_event
        self._next_slot = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        while True:
            if self._stop is not None and self._stop.is_set():
                raise ScannerCancelled()
            with self._lock:
                delay = self._next_slot - time.monotonic()
                if delay <= 0:
                    # claim the slot exactly once, then release
                    self._next_slot = time.monotonic() + self.min_interval
                    return
            if self._stop is not None:
                # sleep in small slices so cancellation stays responsive
                if self._stop.wait(min(delay, 0.25)):
                    raise ScannerCancelled()
            else:
                time.sleep(min(delay, 0.25))


def _default_connection_factory(host: str, ip: str, timeout: float) -> http.client.HTTPConnection:
    """Connect to the validated IP but present/validate TLS for the hostname."""
    context = ssl.create_default_context()
    raw = socket.create_connection((ip, 443), timeout=timeout)
    try:
        tls = context.wrap_socket(raw, server_hostname=host)
        if tls.getpeercert() is None:
            raise ScannerHTTPError("no peer certificate presented")
    except Exception:
        raw.close()
        raise
    conn = http.client.HTTPConnection(host, 443, timeout=timeout)
    conn.sock = tls  # pre-connected: HTTPConnection will not re-resolve DNS
    return conn


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class SafeHTTPClient:
    def __init__(
        self,
        config,
        origin_host: str,
        stop_event: threading.Event | None = None,
        resolver: Callable[[str], list[str]] | None = None,
        connection_factory: Callable[[str, str, float], http.client.HTTPConnection] | None = None,
    ):
        self.config = config
        # The scanned origin: every request URL and redirect hop must stay on it.
        self.origin_host = str(origin_host).lower()
        self.resolver = resolver
        self.stop_event = stop_event or threading.Event()
        self._rate = _RateLimiter(config.min_request_interval, self.stop_event)
        self._conn_factory = connection_factory or _default_connection_factory
        self._local = threading.local()
        self._req_count = 0
        self._req_lock = threading.Lock()
        self.requests_made = 0

    @property
    def budget_exhausted(self) -> bool:
        return self.requests_made >= self.config.max_requests

    # -- public API ---------------------------------------------------------

    def request(self, method: str, url: str, headers: dict[str, str] | None = None, body: bytes | None = None, follow_redirects: bool = True) -> HTTPResponse:
        return self._request(method, url, headers or {}, body, follow_redirects, chain=[])

    def get(self, url: str, headers: dict[str, str] | None = None) -> HTTPResponse:
        return self.request("GET", url, headers)

    def head(self, url: str, headers: dict[str, str] | None = None) -> HTTPResponse:
        return self.request("HEAD", url, headers)

    def options(self, url: str, headers: dict[str, str] | None = None) -> HTTPResponse:
        return self.request("OPTIONS", url, headers)

    # -- internals ----------------------------------------------------------

    def _check_cancel(self) -> None:
        if self.stop_event.is_set():
            raise ScannerCancelled()

    def _validated_ip(self, host: str) -> str:
        ips = resolve_and_validate_ips(host, resolver=self.resolver)
        return ips[0]

    def _request(self, method: str, url: str, headers: dict[str, str], body: bytes | None, follow_redirects: bool, chain: list[str]) -> HTTPResponse:
        self._check_cancel()
        with self._req_lock:
            if self.requests_made >= self.config.max_requests:
                raise ScannerHTTPError("request budget exhausted (max_requests)")
            self.requests_made += 1
        method = method.upper()
        canonical = authorize_request_url(url, self.origin_host)
        self._rate.wait()
        self._check_cancel()

        attempts = 1 if method in SAFE_METHODS else 0
        last_error: Exception | None = None
        for attempt in range(attempts + 1):
            try:
                resp = self._send_once(method, canonical, headers, body)
                break
            except (TimeoutError, socket.timeout, ConnectionError, OSError, http.client.HTTPException) as e:
                last_error = e
                if attempt < attempts and method in SAFE_METHODS and not self.stop_event.is_set():
                    time.sleep(0.2)
                    continue
                raise ScannerHTTPError(f"{method} {canonical}: {type(e).__name__}: {e}") from e

        assert resp is not None
        resp.redirect_chain = list(chain)

        if follow_redirects and 300 <= resp.status < 400:
            location = resp.header("location")
            if location:
                if len(chain) >= self.config.max_redirects:
                    raise ScannerHTTPError(f"too many redirects for {canonical}")
                # Resolve relative Location against the current URL, then
                # re-authorize the hop: unauthorized destinations are never followed.
                from urllib.parse import urljoin

                nxt = urljoin(canonical, location)
                try:
                    authorize_request_url(nxt, self.origin_host)
                except UnauthorizedTargetError as e:
                    raise UnauthorizedRedirectError(e.code, f"redirect to {nxt} rejected: {e}") from e
                if nxt in chain or nxt == canonical:
                    raise ScannerHTTPError(f"redirect loop at {nxt}")
                hop_headers = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length", "origin", "cookie")}
                return self._request(method, nxt, hop_headers, None, follow_redirects, chain + [nxt])

        return resp

    def _send_once(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> HTTPResponse:
        from urllib.parse import urlsplit

        sp = urlsplit(url)
        ip = self._validated_ip(self.origin_host)
        started = time.monotonic()
        conn = self._conn_factory(self.origin_host, ip, self.config.request_timeout)
        try:
            send_headers = {
                "Host": self.origin_host,
                "User-Agent": self.config.user_agent,
                "Accept-Encoding": "identity",
                "Connection": "close",
            }
            send_headers.update({k: v for k, v in headers.items() if k.lower() not in ("host", "user-agent", "accept-encoding", "connection", "content-length")})
            path = sp.path or "/"
            if sp.query:
                path += "?" + sp.query
            conn.request(method, path, body=body, headers=send_headers)
            r = conn.getresponse()
            data = r.read(self.config.max_response_bytes + 1)
            truncated = len(data) > self.config.max_response_bytes
            data = data[: self.config.max_response_bytes]
            resp_headers = {}
            for name, value in r.getheaders():
                key = name.lower()
                if key in resp_headers:
                    resp_headers[key] += ", " + value
                else:
                    resp_headers[key] = value
            return HTTPResponse(
                url=url,
                status=r.status,
                headers=resp_headers,
                body=data.decode("utf-8", errors="replace"),
                elapsed_ms=int((time.monotonic() - started) * 1000),
                truncated=truncated,
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def probe_http_redirect(self, target_host: str) -> dict[str, Any]:
        """TLS check helper: observe HTTP->HTTPS behavior on the scanned host.

        This is the ONLY place the engine touches port 80, and it is scoped
        hard: the host must be this scan's origin, DNS answers global unicast,
        only a single HEAD / with no redirect following, and only
        status/headers are examined — never the body, never the redirect
        destination followed.
        """
        self._check_cancel()
        if str(target_host).lower() != self.origin_host:
            raise UnauthorizedTargetError("out_of_scope")
        self._rate.wait()
        ip = self._validated_ip(self.origin_host)
        raw = socket.create_connection((ip, 80), timeout=self.config.request_timeout)
        try:
            conn = http.client.HTTPConnection(self.origin_host, 80, timeout=self.config.request_timeout)
            conn.sock = raw  # plain HTTP on port 80, pinned to the validated IP
            conn.request("HEAD", "/", headers={"Host": self.origin_host, "User-Agent": self.config.user_agent, "Connection": "close"})
            r = conn.getresponse()
            r.read(1)  # drain status; headers only
            return {
                "http_status": r.status,
                "location": r.getheader("Location") or "",
                "upgrades_to_https": 300 <= r.status < 400 and (r.getheader("Location") or "").startswith("https://"),
            }
        finally:
            try:
                conn.close()
            except Exception:
                raw.close()
