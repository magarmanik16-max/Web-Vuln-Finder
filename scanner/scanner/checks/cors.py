"""CORS check (SCANNER.md §10).

Sends one harmless GET with a bogus attacker origin and inspects the
Access-Control-Allow-Origin response. Findings require meaningful evidence:
the exact reflected origin or wildcard plus the credentials header state.
"""

from __future__ import annotations

from ..models.evidence import response_evidence
from ..models.finding import Confidence, Severity, make_finding

PROBE_ORIGIN = "https://webvulnapp-attacker.example"


def run(ctx) -> list:
    findings: list = []
    seen_roots: set[str] = set()
    pages = ctx.crawl.pages or []

    for page in pages:
        root = page.url.split("?")[0]
        if root in seen_roots:
            continue
        seen_roots.add(root)
        try:
            resp = ctx.client.get(root, headers={"Origin": PROBE_ORIGIN})
        except Exception:
            continue  # transport errors are already recorded by the engine caller

        acao = resp.header("access-control-allow-origin")
        if not acao:
            continue
        acac = resp.header("access-control-allow-credentials", "").lower()

        if acao == "*" and acac == "true":
            sev, title, desc = (
                Severity.MEDIUM,
                "CORS: wildcard origin combined with credentials",
                "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is an invalid/ignored combination in browsers but signals misconfiguration; when the wildcard is served dynamically it becomes exploitable.",
            )
        elif acao.strip() == PROBE_ORIGIN and acac == "true":
            sev, title, desc = (
                Severity.HIGH,
                "CORS: arbitrary origin reflected with credentials allowed",
                f"The server reflected attacker origin '{PROBE_ORIGIN}' in Access-Control-Allow-Origin and allows credentials — any website can read authenticated responses.",
            )
        elif acao.strip() == PROBE_ORIGIN:
            sev, title, desc = (
                Severity.MEDIUM,
                "CORS: arbitrary origin reflected (no credentials)",
                f"The server reflects arbitrary origins ('{PROBE_ORIGIN}') in Access-Control-Allow-Origin. Without credentials the impact is limited, but it exposes any public resource to any site.",
            )
        elif acao == "*":
            sev, title, desc = (
                Severity.INFORMATIONAL,
                "CORS: wildcard origin (public resources only)",
                "Access-Control-Allow-Origin: * is acceptable for purely public, non-credentialed resources.",
            )
        else:
            continue

        findings.append(
            make_finding(
                target_id=ctx.target.target_id,
                target_url=ctx.target.url,
                url=root,
                method="GET",
                parameter="Origin",
                title=title,
                category="cors",
                severity=sev,
                confidence=Confidence.HIGH,
                cwe="CWE-942",
                owasp="A05:2021",
                description=desc,
                evidence=response_evidence(
                    root,
                    "GET",
                    resp.status,
                    {
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac or "(absent)",
                        "vary": resp.header("vary") or "(absent)",
                    },
                    excerpt="",
                    reason=f"request sent with Origin: {PROBE_ORIGIN}",
                ),
                impact="Cross-origin data exposure depends on the credentials combination; see description.",
                remediation="Return only an explicit allowlist of trusted origins; never reflect Origin; set credentials only when required.",
                module="checks.cors",
            )
        )
    return findings
