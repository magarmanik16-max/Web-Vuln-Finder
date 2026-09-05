"""Security header check (SCANNER.md §7).

Missing headers are classified sensibly — absence of CSP/HSTS on an
information site is a hardening gap, not a Critical. Severity is evidence-based
and reflects real exploitability, never alarmism.
"""

from __future__ import annotations

from ..models.evidence import response_evidence
from ..models.finding import Confidence, Severity, make_finding

# header -> (title, severity, cwe, impact, remediation)
HEADER_MATRIX = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "impact": "Without CSP, injected inline script (e.g. from any future XSS) faces no additional browser-side restriction.",
        "remediation": "Add a Content-Security-Policy header, starting with default-src 'self' and avoiding 'unsafe-inline'.",
    },
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "severity": Severity.LOW,
        "cwe": "CWE-319",
        "owasp": "A02:2021",
        "impact": "Visitors who type the http:// URL (or click an http link) can be downgraded or intercepted before the first HTTPS redirect.",
        "remediation": "Send Strict-Transport-Security: max-age=31536000; includeSubDomains from the HTTPS site.",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": Severity.LOW,
        "cwe": "CWE-430",
        "owasp": "A05:2021",
        "impact": "Browsers may MIME-sniff user-uploaded or mislabelled content into executable scripts.",
        "remediation": "Send X-Content-Type-Options: nosniff on all responses.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options header (and no frame-ancestors CSP)",
        "severity": Severity.LOW,
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "impact": "The page can be framed by third parties, enabling clickjacking against authenticated users.",
        "remediation": "Send X-Frame-Options: DENY (or SAMEORIGIN), or a CSP frame-ancestors directive.",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "severity": Severity.INFORMATIONAL,
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "impact": "Full URLs (including any query strings) may leak to third-party sites via the Referer header.",
        "remediation": "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy header",
        "severity": Severity.INFORMATIONAL,
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "impact": "Powerful browser features (camera, geolocation, ...) are not explicitly restricted for embedded third parties.",
        "remediation": "Send a Permissions-Policy header restricting features the site does not use.",
    },
}

# Weak CSP directives that materially reduce protection (informational notes).
WEAK_CSP_HINTS = ("'unsafe-inline'", "'unsafe-eval'", "*")


def _csp_weakness(csp: str) -> list[str]:
    return [hint for hint in WEAK_CSP_HINTS if hint in csp]


def check_page(ctx, page, findings: list) -> None:
    resp = page.response
    for header_name, spec in HEADER_MATRIX.items():
        if resp.header(header_name):
            continue
        if header_name == "x-frame-options" and "frame-ancestors" in resp.header("content-security-policy"):
            continue  # CSP frame-ancestors supersedes XFO
        findings.append(
            make_finding(
                target_id=ctx.target.target_id,
                target_url=ctx.target.url,
                url=page.url,
                method="GET",
                title=spec["title"],
                category="headers",
                severity=spec["severity"],
                confidence=Confidence.HIGH,
                cwe=spec["cwe"],
                owasp=spec["owasp"],
                description=f"The response for {page.url} does not send the {header_name} header.",
                evidence=response_evidence(
                    page.url,
                    "GET",
                    resp.status,
                    {"content-type": resp.header("content-type")},
                    excerpt="",
                    reason=f"required header '{header_name}' absent from response",
                ),
                impact=spec["impact"],
                remediation=spec["remediation"],
                module="checks.headers",
            )
        )
    csp = resp.header("content-security-policy")
    if csp:
        weak = _csp_weakness(csp)
        if weak:
            findings.append(
                make_finding(
                    target_id=ctx.target.target_id,
                    target_url=ctx.target.url,
                    url=page.url,
                    method="GET",
                    title="Content-Security-Policy contains permissive directives",
                    category="headers",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    cwe="CWE-693",
                    owasp="A05:2021",
                    description=f"CSP includes {', '.join(weak)}, which weakens or voids its script/frame restrictions.",
                    evidence=response_evidence(
                        page.url, "GET", resp.status, {"content-security-policy": csp}, "", reason="permissive CSP directives present"
                    ),
                    impact="The policy does not meaningfully restrict inline script execution or embedding.",
                    remediation="Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces or hashes.",
                    module="checks.headers",
                )
            )


def run(ctx) -> list:
    findings: list = []
    for page in ctx.crawl.pages:
        check_page(ctx, page, findings)
    return findings
