"""HTTP methods check (SCANNER.md §11) — strictly non-destructive.

1. OPTIONS on the root: read the Allow header (standard, safe).
2. TRACE: sent to the root; a 200 with our marker echoed back is reported.
3. PUT/DELETE: NEVER sent against real resources. They are sent to a random
   non-existent probe path, so even a permissive server has nothing to
   create/modify/delete. A 2xx there is itself the finding.
"""

from __future__ import annotations

import uuid

from ..models.evidence import response_evidence
from ..models.finding import Confidence, Severity, make_finding


def run(ctx) -> list:
    findings: list = []
    root = ctx.target.url
    probe_path = f"/webvulnapp-probe-{uuid.uuid4().hex[:12]}"

    # 1) Allow header via OPTIONS (safe)
    try:
        opt = ctx.client.options(root)
        allow = opt.header("allow")
    except Exception:
        opt, allow = None, ""
    if allow:
        methods_list = [m.strip().upper() for m in allow.split(",")]
        dangerous = [m for m in ("TRACE", "PUT", "DELETE", "PATCH", "CONNECT") if m in methods_list]
        if dangerous:
            findings.append(
                make_finding(
                    target_id=ctx.target.target_id,
                    target_url=ctx.target.url,
                    url=root,
                    method="OPTIONS",
                    title=f"Server advertises potentially dangerous methods: {', '.join(dangerous)}",
                    category="methods",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    cwe="CWE-650",
                    owasp="A05:2021",
                    description=f"OPTIONS / returns Allow: {allow}. Advertising does not prove enablement; each is verified safely below where applicable.",
                    evidence=response_evidence(root, "OPTIONS", opt.status, {"allow": allow}, "", reason="dangerous methods listed in Allow header"),
                    impact="If actually enabled, PUT/DELETE allow resource manipulation and TRACE can leak headers.",
                    remediation="Disable unused HTTP methods at the web server.",
                    module="checks.methods",
                )
            )

    # 2) TRACE — harmless echo check with a marker header
    marker = f"wva-{uuid.uuid4().hex[:12]}"
    try:
        trace = ctx.client.request("TRACE", root, headers={"X-WebVulnApp-Marker": marker}, follow_redirects=False)
        if trace.status == 200 and marker in trace.body:
            findings.append(
                make_finding(
                    target_id=ctx.target.target_id,
                    target_url=ctx.target.url,
                    url=root,
                    method="TRACE",
                    title="TRACE method enabled (Cross-Site Tracing surface)",
                    category="methods",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    cwe="CWE-693",
                    owasp="A05:2021",
                    description="TRACE request returned 200 and echoed our marker header, enabling header theft via XST in old browsers.",
                    evidence=response_evidence(root, "TRACE", trace.status, {"content-type": trace.header("content-type")}, excerpt=trace.body[:200], reason="marker header echoed in TRACE response"),
                    impact="Historically allows reading HttpOnly cookies when combined with XSS (modern browsers block TRACE).",
                    remediation="Disable TRACE at the web server.",
                    module="checks.methods",
                )
            )
    except Exception:
        pass  # rejected/blocked TRACE is the expected outcome

    # 3) PUT/DELETE against a random non-existent probe path (nothing to modify)
    for method in ("PUT", "DELETE"):
        try:
            resp = ctx.client.request(method, ctx.target.url.rstrip("/") + probe_path, body=b"{}" if method == "PUT" else None, follow_redirects=False)
            if 200 <= resp.status < 300:
                findings.append(
                    make_finding(
                        target_id=ctx.target.target_id,
                        target_url=ctx.target.url,
                        url=ctx.target.url.rstrip("/") + probe_path,
                        method=method,
                        title=f"{method} accepted on a non-existent resource path",
                        category="methods",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe="CWE-650",
                        owasp="A01:2021",
                        description=f"{method} to a random path returned {resp.status}; the server appears to accept {method} without an existing resource (no real resource was touched).",
                        evidence=response_evidence(probe_path, method, resp.status, {"allow": resp.header("allow")}, excerpt=resp.body[:200], reason=f"{method} returned 2xx on a random probe path"),
                        impact="If an authorized writer is found, arbitrary resource creation/deletion may be possible.",
                        remediation="Reject PUT/DELETE unless a controlled API explicitly requires them (authz + CSRF protections).",
                        module="checks.methods",
                    )
                )
        except Exception:
            pass
    return findings
