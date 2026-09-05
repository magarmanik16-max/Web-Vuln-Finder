"""Information disclosure check (SCANNER.md §12).

Passive analysis of crawled responses plus a tiny set of conservative probes
(/.env, /.git/HEAD, /phpinfo.php, /server-status). Presence is reported with a
short excerpt — contents that could contain secrets are redacted (§20) and
never retrieved beyond the detection excerpt.
"""

from __future__ import annotations

import re

from ..models.evidence import response_evidence
from ..models.finding import Confidence, Severity, make_finding

HEADER_RULES = [
    ("server", r"\d+\.\d+(\.\d+)?", "Server header discloses a version", Severity.INFORMATIONAL),
    ("x-powered-by", r"", "Framework/technology disclosed via X-Powered-By", Severity.INFORMATIONAL),
    ("x-aspnet-version", r"", "ASP.NET version disclosed", Severity.LOW),
]

BODY_PATTERNS = [
    (r"Fatal error.*?on line \d+", "PHP fatal error/debug output in response", Severity.LOW),
    (r"Warning:\s*.+?\s+in\s+/.+?\.php on line \d+", "PHP warning with filesystem path in response", Severity.LOW),
    (r"Traceback \(most recent call last\):", "Python stack trace exposed in response", Severity.MEDIUM),
    (r"at [\w$.]+\([\w-]+\.java:\d+\)", "Java stack trace exposed in response", Severity.MEDIUM),
    (r"<title>Index of /", "Directory listing enabled", Severity.MEDIUM),
    (r"django\.debug|DEBUG = True", "Django debug mode indicator", Severity.MEDIUM),
    (r"laravel.*whoops|Whoops, looks like something went wrong", "Laravel error page exposing framework", Severity.INFORMATIONAL),
]

PROBES = [
    ("/.env", re.compile(r"^[A-Z_]+=", re.M), "Public .env configuration file", Severity.HIGH, "CWE-538"),
    ("/.git/HEAD", re.compile(r"ref: refs/", re.I), "Exposed .git repository", Severity.MEDIUM, "CWE-538"),
    ("/phpinfo.php", re.compile(r"phpinfo\(\)", re.I), "Public phpinfo page", Severity.MEDIUM, "CWE-200"),
    ("/server-status", re.compile(r"Apache Server Status", re.I), "Apache server-status publicly readable", Severity.LOW, "CWE-200"),
]


def _unique(items, key):
    seen, out = set(), []
    for item in items:
        k = key(item)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


def run(ctx) -> list:
    findings: list = []
    for page in ctx.crawl.pages:
        resp = page.response
        for header_name, pattern, title, sev in HEADER_RULES:
            value = resp.header(header_name)
            if value and (not pattern or re.search(pattern, value)):
                findings.append(
                    make_finding(
                        target_id=ctx.target.host,
                        target_url=ctx.target.target_url,
                        url=page.url,
                        method="GET",
                        title=f"{title}: '{value[:80]}'",
                        category="disclosure",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        cwe="CWE-200",
                        owasp="A05:2021",
                        description=f"Response header '{header_name}: {value[:120]}' reveals software and/or version information useful to attackers.",
                        evidence=response_evidence(page.url, "GET", resp.status, {header_name: value}, "", reason=f"version/technology disclosure in '{header_name}' header"),
                        impact="Helps an attacker select known exploits for the exact software version.",
                        remediation=f"Suppress or generalize the {header_name} header.",
                        module="checks.disclosure",
                    )
                )
        for pattern, title, sev in BODY_PATTERNS:
            m = re.search(pattern, resp.body[:50000])
            if m:
                findings.append(
                    make_finding(
                        target_id=ctx.target.host,
                        target_url=ctx.target.target_url,
                        url=page.url,
                        method="GET",
                        title=title,
                        category="disclosure",
                        severity=sev,
                        confidence=Confidence.MEDIUM,
                        cwe="CWE-209",
                        owasp="A05:2021",
                        description=f"Response body matches a debug/error indicator pattern ({title.lower()}).",
                        evidence=response_evidence(page.url, "GET", resp.status, {"content-type": resp.header("content-type")}, excerpt=resp.body[max(0, m.start() - 100): m.start() + 200], reason=f"body matched {pattern!r}"),
                        impact="Stack traces and error output leak paths, versions and code structure.",
                        remediation="Disable verbose errors in production; log server-side instead.",
                        module="checks.disclosure",
                    )
                )

    for path, indicator, title, sev, cwe in PROBES:
        url = ctx.target.target_url.rstrip("/") + path
        try:
            resp = ctx.client.request("GET", url, follow_redirects=False)
        except Exception:
            continue
        if resp.status == 200 and indicator.search(resp.body[:4096]):
            findings.append(
                make_finding(
                    target_id=ctx.target.host,
                    target_url=ctx.target.target_url,
                    url=url,
                    method="GET",
                    title=title,
                    category="disclosure",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    cwe=cwe,
                    owasp="A05:2021",
                    description=f"{url} is publicly readable and looks like {title.lower()}. Contents are NOT stored by this scanner.",
                    evidence=response_evidence(url, "GET", resp.status, {"content-type": resp.header("content-type")}, excerpt="(excerpt withheld)", reason=f"200 response matched {title.lower()}"),
                    impact="Configuration or source metadata exposure can reveal secrets and aid further attacks.",
                    remediation=f"Block public access to {path} (web server rules, repository hygiene).",
                    module="checks.disclosure",
                )
            )
    return findings
