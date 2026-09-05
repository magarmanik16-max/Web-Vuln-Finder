"""CSRF check (SCANNER.md §15) — static form analysis.

Identifies state-changing forms (POST, or password/file fields, or action
keywords) and checks for anti-CSRF tokens and SameSite cookie protection.
Forms are NEVER submitted (§3: no destructive actions).
"""

from __future__ import annotations

import re

from ..models.evidence import sanitize
from ..models.finding import Confidence, Severity, make_finding

TOKEN_NAME = re.compile(r"csrf|_token|authenticity_token|csrfmiddlewaretoken|xsrf|nonce", re.I)
STATE_CHANGING = re.compile(r"delete|update|create|add|remove|edit|submit|save|register|login|signup|contact|send|upload|order|checkout|subscribe|password", re.I)


def _is_state_changing(form) -> bool:
    if form.method.upper() == "POST":
        return True
    text = form.action_url.lower() + " " + " ".join(i.get("name", "") for i in form.inputs)
    return bool(STATE_CHANGING.search(text)) or any(i.get("type") in ("password", "file") for i in form.inputs)


def run(ctx) -> list:
    findings: list = []
    seen_actions: set[str] = set()
    samesite_ok = _cookies_samesite_protected(ctx)

    for form in ctx.crawl.forms:
        if not _is_state_changing(form):
            continue
        key = f"{form.method}:{form.action_url}"
        if key in seen_actions:
            continue
        seen_actions.add(key)

        has_token = any(TOKEN_NAME.search(i.get("name", "")) for i in form.inputs)
        if has_token:
            continue

        findings.append(
            make_finding(
                target_id=ctx.target.host,
                target_url=ctx.target.target_url,
                url=form.action_url,
                method=form.method,
                parameter=", ".join(i.get("name", "") for i in form.inputs[:8]),
                title="State-changing form without a visible anti-CSRF token",
                category="csrf",
                severity=Severity.MEDIUM if form.method.upper() == "POST" else Severity.LOW,
                confidence=Confidence.LOW,
                cwe="CWE-352",
                owasp="A01:2021",
                description=f"Form posting to {form.action_url} contains no field matching common anti-CSRF token names. Static analysis only — the form was NOT submitted.",
                evidence=sanitize(
                    {
                        "url": form.action_url,
                        "method": form.method,
                        "form_fields": [i.get("name", "") for i in form.inputs],
                        "source_page": form.source_url,
                        "detection_reason": "no anti-CSRF token field found; SameSite-protected cookies observed: %s" % ("yes" if samesite_ok else "no/unknown"),
                    }
                ),
                impact="If no other mitigation (SameSite cookies, origin checks) exists, an attacker page could submit this action as a victim.",
                remediation="Add a per-session anti-CSRF token to state-changing forms and verify it server-side; keep SameSite=Lax/Strict cookies.",
                module="checks.csrf",
            )
        )
    return findings


def _cookies_samesite_protected(ctx) -> bool:
    from ..checks.cookies import parse_set_cookie

    for page in ctx.crawl.pages:
        for raw in page.response.header_all("set-cookie"):
            _name, flags = parse_set_cookie(raw)
            if flags.get("samesite") in ("strict", "lax"):
                return True
    return False
