"""SQL injection check (SCANNER.md §14) — controlled, minimal probes.

For a bounded number of discovered GET parameters:
1. baseline GET,
2. one minimal error probe (single quote appended) checked against a curated
   list of DATABASE ERROR INDICATORS,
3. boolean differential (AND 1=1 vs AND 1=2) only for numeric-looking values,
4. timing probes ONLY if config.timing_probes is enabled AND the error probe
   already suggested a specific database — at most one 2-second probe.

We report POTENTIAL injection with confidence. Never: enumeration, dumping,
credential extraction, record retrieval (§3/§14).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models.evidence import response_evidence
from ..models.finding import Confidence, Severity, make_finding

DB_ERROR_PATTERNS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysql_", "MySQL"),
    (r"unclosed quotation mark after the character string", "SQL Server"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"pg_query\(\)|postgresql.*error|psql:", "PostgreSQL"),
    (r"sqlite3?::query|sqlite_error|unrecognized token", "SQLite"),
    (r"odbc.*driver.*error|microsoft ole db provider", "ODBC"),
]

_NUMERIC_VALUE = re.compile(r"^\d+$")


def _set_param(url: str, param: str, value: str) -> str:
    sp = urlsplit(url)
    pairs = [(k, value if k == param else v) for k, v in parse_qsl(sp.query, keep_blank_values=True)]
    if not any(k == param for k, _ in pairs):
        pairs.append((param, value))
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(pairs), ""))


def _match_db_error(body: str) -> str | None:
    for pattern, db in DB_ERROR_PATTERNS:
        if re.search(pattern, body, re.I):
            return db
    return None


def run(ctx) -> list:
    findings: list = []
    tested = 0

    for url in ctx.crawl.parameter_urls[: max(1, ctx.config.max_params_tested)]:
        params = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        if not params:
            continue
        try:
            baseline = ctx.client.get(url)
        except Exception:
            continue
        base_len, base_status = len(baseline.body), baseline.status

        for param, value in params:
            if tested >= ctx.config.max_params_tested:
                return findings
            tested += 1

            # 1) minimal error probe: single quote appended
            probe_url = _set_param(url, param, f"{value}'")
            try:
                probe = ctx.client.get(probe_url)
            except Exception:
                continue
            db = _match_db_error(probe.body)
            if db:
                findings.append(
                    make_finding(
                        target_id=ctx.target.target_id,
                        target_url=ctx.target.url,
                        url=probe_url,
                        method="GET",
                        parameter=param,
                        title=f"Possible SQL injection (database error triggered) — {db}",
                        category="sqli",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe="CWE-89",
                        owasp="A03:2021",
                        description=f"Appending a single quote to parameter '{param}' produced a {db} error message. This indicates unsanitized input reaching the database layer. NO enumeration or extraction was performed.",
                        evidence=response_evidence(
                            probe_url, "GET", probe.status, {"content-type": probe.header("content-type")}, excerpt=_excerpt(probe.body), reason=f"{db} error signature in response after minimal quote probe"
                        ),
                        impact="Attackers may read or modify database content depending on the injection type.",
                        remediation="Use parameterized queries/prepared statements; validate types; least-privilege DB accounts.",
                        module="checks.sqli",
                    )
                )
                continue

            # 2) boolean differential for numeric values
            if _NUMERIC_VALUE.match(value):
                try:
                    true_resp = ctx.client.get(_set_param(url, param, f"{value} AND 1=1"))
                    false_resp = ctx.client.get(_set_param(url, param, f"{value} AND 1=2"))
                except Exception:
                    continue
                same_status = true_resp.status == false_resp.status
                delta = abs(len(true_resp.body) - len(false_resp.body))
                true_like = true_resp.status == base_status and abs(len(true_resp.body) - base_len) < 50
                false_differs = (false_resp.status != base_status) or (abs(len(false_resp.body) - base_len) >= 50)
                if true_like and false_differs and (not same_status or delta >= 50):
                    findings.append(
                        make_finding(
                            target_id=ctx.target.target_id,
                            target_url=ctx.target.url,
                            url=url,
                            method="GET",
                            parameter=param,
                            title="Possible SQL injection (boolean-based differential)",
                            category="sqli",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            cwe="CWE-89",
                            owasp="A03:2021",
                            description=f"Parameter '{param}' returns the baseline for '{value} AND 1=1' but a different response for '{value} AND 1=2' (status {true_resp.status} vs {false_resp.status}, length delta {delta}). Conditional SQL evaluation is suspected; NO data was extracted.",
                            evidence=response_evidence(
                                url, "GET", base_status,
                                {},
                                excerpt="",
                                reason=f"boolean differential: baseline={base_len}B/{base_status}, true={len(true_resp.body)}B/{true_resp.status}, false={len(false_resp.body)}B/{false_resp.status}",
                            ),
                            impact="If confirmed, the parameter evaluates attacker-controlled conditions in SQL, enabling data extraction.",
                            remediation="Use parameterized queries; treat the value as an integer; investigate at the code level.",
                            module="checks.sqli",
                        )
                    )
                    continue

            # 3) timing probe — only when enabled AND a DB was already suggested
            if ctx.config.timing_probes and db:
                pass  # reserved: probes are limited to confirmed error signatures
    return findings


def _excerpt(body: str) -> str:
    for pattern, _db in DB_ERROR_PATTERNS:
        m = re.search(pattern, body, re.I)
        if m:
            start = max(0, m.start() - 100)
            return body[start: m.start() + 150]
    return ""
