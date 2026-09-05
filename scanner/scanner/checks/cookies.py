"""Cookie security check (SCANNER.md §9).

Analyzes Set-Cookie flags on every crawled response. Evidence contains ONLY
cookie names and flags — values (session tokens) are never stored (§20).
"""

from __future__ import annotations

import re
from http.cookies import SimpleCookie

from ..models.evidence import cookie_evidence
from ..models.finding import Confidence, Severity, make_finding

SENSITIVE_NAME = re.compile(r"sess|auth|login|token|sid|jwt|remember", re.I)


def parse_set_cookie(raw: str) -> tuple[str | None, dict]:
    """Return (name, flags) for one Set-Cookie header value. The cookie VALUE
    is discarded immediately — it must never reach evidence (§20)."""
    try:
        jar = SimpleCookie()
        jar.load(raw)
        if not jar:
            return None, {}
        morsel = next(iter(jar.values()))
    except Exception:
        return None, {}
    attrs = [part.strip().lower() for part in raw.split(";")[1:]]
    flags: dict = {"secure": False, "httponly": False, "samesite": "", "domain": "", "path": ""}
    for attr in attrs:
        key, _, value = attr.partition("=")
        if key == "secure":
            flags["secure"] = True
        elif key == "httponly":
            flags["httponly"] = True
        elif key == "samesite":
            flags["samesite"] = value.strip()
        elif key == "domain":
            flags["domain"] = value.strip()
        elif key == "path":
            flags["path"] = value.strip()
    return morsel.key, flags


def check_cookie(ctx, page, name: str, flags: dict, findings: list) -> None:
    sensitive = bool(SENSITIVE_NAME.search(name))

    if not flags.get("secure"):
        findings.append(
            make_finding(
                target_id=ctx.target.host,
                target_url=ctx.target.target_url,
                url=page.url,
                method="GET",
                parameter=name,
                title=f"Cookie '{name}' lacks the Secure flag",
                category="cookies",
                severity=Severity.MEDIUM if sensitive else Severity.LOW,
                confidence=Confidence.HIGH,
                cwe="CWE-614",
                owasp="A05:2021",
                description=f"Set-Cookie for '{name}' has no Secure attribute, so the browser also transmits it over plain HTTP.",
                evidence=cookie_evidence(name, flags, page.url, "Set-Cookie without Secure flag"),
                impact="Cookie value can be captured on the network during any downgrade or mixed-content request.",
                remediation="Add the Secure attribute to every cookie.",
                module="checks.cookies",
            )
        )
    if sensitive and not flags.get("httponly"):
        findings.append(
            make_finding(
                target_id=ctx.target.host,
                target_url=ctx.target.target_url,
                url=page.url,
                method="GET",
                parameter=name,
                title=f"Session cookie '{name}' lacks HttpOnly",
                category="cookies",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-1004",
                owasp="A05:2021",
                description=f"Sensitive cookie '{name}' is readable by JavaScript (no HttpOnly attribute).",
                evidence=cookie_evidence(name, flags, page.url, "sensitive cookie without HttpOnly"),
                impact="Any XSS in the application can exfiltrate the session cookie.",
                remediation="Add HttpOnly to session/authentication cookies.",
                module="checks.cookies",
            )
        )
    if flags.get("samesite", "") not in ("strict", "lax"):
        findings.append(
            make_finding(
                target_id=ctx.target.host,
                target_url=ctx.target.target_url,
                url=page.url,
                method="GET",
                parameter=name,
                title=f"Cookie '{name}' has no SameSite protection",
                category="cookies",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                cwe="CWE-1275",
                owasp="A07:2021",
                description=f"Set-Cookie for '{name}' does not set SameSite (or uses None), so it is sent on cross-site requests.",
                evidence=cookie_evidence(name, flags, page.url, "SameSite missing or None"),
                impact="Increases exposure to CSRF and cross-site information leakage.",
                remediation="Set SameSite=Lax (or Strict) unless third-party embedding is required.",
                module="checks.cookies",
            )
        )


def run(ctx) -> list:
    findings: list = []
    seen: set[str] = set()  # dedupe per cookie name at scanner level too
    for page in ctx.crawl.pages:
        for raw_value in page.response.header_all("set-cookie"):
            name, flags = parse_set_cookie(raw_value)
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            check_cookie(ctx, page, name, flags, findings)
    return findings
