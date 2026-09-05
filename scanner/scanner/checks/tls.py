"""TLS check (SCANNER.md §8).

Observational only: certificate validity/expiration from the pinned TLS
session, and HTTP→HTTPS upgrade behavior via the engine's scoped port-80 probe.
No destructive TLS attacks.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timezone

from ..models.evidence import sanitize
from ..models.finding import Confidence, Severity, make_finding


def _cert_info(ctx) -> dict | None:
    """Peek at the peer certificate through a real pinned connection."""
    from ..httpengine import _default_connection_factory

    try:
        ip = ctx.client._validated_ip(ctx.target.host)
        conn = _default_connection_factory(ctx.target.host, ip, ctx.config.request_timeout)
        sock = conn.sock
        return sock.getpeercert() if sock is not None else None
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run(ctx) -> list:
    findings: list = []
    cert = _cert_info(ctx)

    if cert is None:
        findings.append(
            make_finding(
                target_id=ctx.target.target_id,
                target_url=ctx.target.url,
                url=ctx.target.url,
                method="GET",
                title="TLS certificate could not be validated",
                category="tls",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                cwe="CWE-295",
                owasp="A02:2021",
                description="A certificate-validating TLS connection to the authorized origin failed (expired, self-signed, mismatched, or untrusted chain).",
                evidence={"url": ctx.target.url, "method": "GET", "detection_reason": "ssl handshake/certificate validation failed"},
                impact="Clients cannot authenticate the server; MITM becomes feasible.",
                remediation="Renew/fix the TLS certificate and chain.",
                module="checks.tls",
            )
        )
        return findings

    # Expiration
    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
        except ValueError:
            days_left = None

    if days_left is not None:
        if days_left < 0:
            sev = Severity.CRITICAL
            title = "TLS certificate has expired"
            impact = "Browsers block the site or users learn to click through warnings; traffic integrity is compromised."
        elif days_left <= 14:
            sev = Severity.HIGH
            title = f"TLS certificate expires in {days_left} days"
            impact = "Imminent expiry will cause browser warnings and outages if not renewed."
        elif days_left <= 30:
            sev = Severity.MEDIUM
            title = f"TLS certificate expires in {days_left} days"
            impact = "Certificate renewal is due; expiry causes user-facing errors."
        else:
            sev = Severity.INFORMATIONAL
            title = f"TLS certificate valid ({days_left} days remaining)"
            impact = "No action required; recorded for the report."
        findings.append(
            make_finding(
                target_id=ctx.target.target_id,
                target_url=ctx.target.url,
                url=ctx.target.url,
                method="GET",
                title=title,
                category="tls",
                severity=sev,
                confidence=Confidence.HIGH,
                cwe="CWE-298" if days_left < 0 else "CWE-324",
                owasp="A02:2021",
                description=f"Certificate notAfter={not_after} ({days_left} days from scan).",
                evidence=sanitize({"url": ctx.target.url, "method": "GET", "certificate": {"not_after": not_after, "issuer": dict(x[0] for x in cert.get("issuer", ())).get("organizationName", ""), "subject_cn": dict(x[0] for x in cert.get("subject", ())).get("commonName", "")}}),
                impact=impact,
                remediation="Ensure automated certificate renewal (e.g. ACME/Let's Encrypt).",
                module="checks.tls",
            )
        )

    # HTTP -> HTTPS upgrade behavior (scoped port-80 HEAD probe, no follow)
    try:
        probe = ctx.client.probe_http_redirect(ctx.target)
    except Exception:
        probe = None
    if probe is not None:
        if not probe["upgrades_to_https"]:
            findings.append(
                make_finding(
                    target_id=ctx.target.target_id,
                    target_url=ctx.target.url,
                    url=f"http://{ctx.target.host}/",
                    method="HEAD",
                    title="HTTP does not redirect to HTTPS",
                    category="tls",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    cwe="CWE-319",
                    owasp="A02:2021",
                    description=f"Port 80 answered HTTP {probe['http_status']} without redirecting to https://.",
                    evidence={"url": f"http://{ctx.target.host}/", "method": "HEAD", "status": probe["http_status"], "headers": {"location": probe["location"] or "(none)"}, "detection_reason": "no https upgrade redirect"},
                    impact="Cleartext HTTP remains usable, exposing visitors to downgrade and interception (esp. without HSTS).",
                    remediation="Redirect all HTTP requests to HTTPS (301) and enable HSTS.",
                    module="checks.tls",
                )
            )
        else:
            findings.append(
                make_finding(
                    target_id=ctx.target.target_id,
                    target_url=ctx.target.url,
                    url=f"http://{ctx.target.host}/",
                    method="HEAD",
                    title="HTTP redirects to HTTPS",
                    category="tls",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    cwe="",
                    owasp="",
                    description=f"Port 80 answers HTTP {probe['http_status']} with a Location header starting with https:// (good practice).",
                    evidence={"url": f"http://{ctx.target.host}/", "method": "HEAD", "status": probe["http_status"], "detection_reason": "https upgrade observed"},
                    impact="Positive finding.",
                    remediation="",
                    module="checks.tls",
                )
            )
    return findings
