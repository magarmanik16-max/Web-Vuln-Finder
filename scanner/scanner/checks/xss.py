"""Reflected XSS check (SCANNER.md §13) — safe marker reflection analysis.

For a bounded number of discovered GET parameters, inject a unique harmless
marker (no HTML/JS syntax) and classify the reflection CONTEXT via HTML
parsing (body text, attribute value, script block, URL attribute).

We report reflection context, never "confirmed XSS": no breakout payloads are
sent, nothing persistent is created, and severity stays conservative per §3/§13.
"""

from __future__ import annotations

import re
import uuid
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models.evidence import response_evidence
from ..models.finding import Confidence, Severity, make_finding

CONTEXTS = {
    "html_body": {"title": "Reflected input rendered in HTML body context", "severity": Severity.MEDIUM, "impact": "Raw reflection in HTML body is one escape from text context away from script execution if any markup is permitted."},
    "attribute": {"title": "Reflected input rendered inside an HTML attribute", "severity": Severity.MEDIUM, "impact": "If attribute quoting can be broken, an event handler can be injected."},
    "script": {"title": "Reflected input rendered inside a script block", "severity": Severity.HIGH, "impact": "JavaScript-context reflection frequently allows direct script execution via quote/delimiter handling."},
    "url_attribute": {"title": "Reflected input rendered in a URL attribute (href/src)", "severity": Severity.MEDIUM, "impact": "Unless scheme-restricted, crafted URLs (javascript:) can execute when clicked."},
}


class _ReflectionContextFinder(HTMLParser):
    """Locate marker occurrences and classify their HTML context."""

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.contexts: list[str] = []
        self._in_script = 0
        self._current_attr = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._in_script += 1
        if tag == "title":
            self._in_title = True
        for _k, v in attrs:
            if v and self.marker in v:
                url_attr = tag in ("a", "img", "iframe", "link", "source", "form") and _k in ("href", "src", "action", "formaction", "data")
                self.contexts.append("url_attribute" if url_attr else "attribute")

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self.marker in data:
            self.contexts.append("script" if self._in_script else ("attribute" if self._in_title else "html_body"))


def _raw_reflection(body: str, marker: str) -> bool:
    """Marker (incl. its trailing double-quote) present WITHOUT HTML-encoding.

    The marker carries one quote character: a site that HTML-encodes output
    will transform it, so only truly unencoded reflection matches.
    """
    return marker in body


def _encoded_only(body: str, marker: str) -> bool:
    if marker in body:
        return False
    for enc in ("&quot;", "&#34;", "&#x22;"):
        if marker.replace('"', enc) in body:
            return True
    return False


def build_probe_url(url: str, param: str, marker: str) -> str:
    sp = urlsplit(url)
    from urllib.parse import parse_qsl

    pairs = [(k, marker if k == param else v) for k, v in parse_qsl(sp.query, keep_blank_values=True)]
    if not any(k == param for k, _ in pairs):
        pairs.append((param, marker))
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(pairs), ""))


def run(ctx) -> list:
    findings: list = []
    param_urls = ctx.crawl.parameter_urls[: max(1, ctx.config.max_params_tested)]
    tested = 0

    for url in param_urls:
        for param in [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]:
            if tested >= ctx.config.max_params_tested:
                return findings
            marker = f'wvaxss{uuid.uuid4().hex[:16]}x"'
            token = marker[:-1]  # alnum-only prefix, safe for HTML parsing
            probe = build_probe_url(url, param, marker)
            try:
                resp = ctx.client.get(probe)
            except Exception:
                continue
            tested += 1
            if marker not in resp.body:
                continue  # not reflected raw — encoded/absent reflections are not reported

            finder = _ReflectionContextFinder(token)
            try:
                finder.feed(resp.body)
            except Exception:
                pass
            contexts = list(dict.fromkeys(finder.contexts)) or ["html_body"]
            for context in contexts:
                spec = CONTEXTS[context]
                findings.append(
                    make_finding(
                        target_id=ctx.target.target_id,
                        target_url=ctx.target.url,
                        url=probe,
                        method="GET",
                        parameter=param,
                        title=f"{spec['title']} (parameter '{param}')",
                        category="xss",
                        severity=spec["severity"],
                        confidence=Confidence.MEDIUM,
                        cwe="CWE-79",
                        owasp="A03:2021",
                        description=(
                            f"A unique harmless marker injected into parameter '{param}' was reflected UNENCODED in the "
                            f"{context} context of the response. This is reflection evidence, not a confirmed exploit: "
                            "no breakout payload was sent."
                        ),
                        evidence=response_evidence(
                            probe,
                            "GET",
                            resp.status,
                            {"content-type": resp.header("content-type")},
                            excerpt=_excerpt_around(resp.body, marker),
                            reason=f"raw reflection of unique marker in {context} context",
                        ),
                        impact=spec["impact"],
                        remediation="HTML-encode all reflected input per output context; add a CSP; prefer templating with auto-escaping.",
                        module="checks.xss",
                    )
                )
    return findings


def _excerpt_around(body: str, marker: str, pad: int = 120) -> str:
    idx = body.find(marker)
    if idx < 0:
        return ""
    start, end = max(0, idx - pad), min(len(body), idx + len(marker) + pad)
    return ("..." if start else "") + body[start:end] + ("..." if end < len(body) else "")
