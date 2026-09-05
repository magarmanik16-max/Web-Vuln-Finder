"""Independent target safety policy for the Python scanner.

The platform accepts user-supplied PUBLIC HTTPS targets. The Python engine
re-enforces the complete safety policy on its own — a malicious or buggy
Node.js layer must not be able to point it at an unsafe destination.

Rules (mirrors server/src/security/urlGuard.js; stdlib only):

  1. Parse with urllib.parse; malformed input is rejected, never repaired.
  2. HTTPS only — http, ftp, file, javascript:, data:, ws: … are rejected.
  3. No credentials/userinfo, no explicit port (443 only).
  4. The submitted target is normalized to its ORIGIN (https://host/).
  5. Hostnames that ARE IP literals must be globally routable at the
     structural stage (rejects 127.0.0.1, 10.0.0.0/8, 172.16/12, 192.168/16,
     169.254/16 incl. cloud metadata, ::1, fe80::/10, fc00::/7, multicast,
     unspecified, IPv4-mapped IPv6 — via the ipaddress module, not regexes).
  6. DNS resolution happens after the structural gate; every resolved
     address must be a global unicast IP (rejects rebinding answers).
  7. Deep request URLs and every redirect hop must stay on the scanned
     origin and re-pass the structural rules.

The DNS resolver is injectable so tests run without network.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class UnauthorizedTargetError(ValueError):
    """Raised for any target that is not a safe, public HTTPS destination."""

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or f"Target rejected: {code}")
        self.code = code


@dataclass(frozen=True)
class Target:
    target_url: str  # normalized origin, e.g. https://example.com/
    host: str


def _reject(code: str):
    raise UnauthorizedTargetError(code)


def _assert_global_ip(ip_string: str) -> None:
    try:
        addr = ipaddress.ip_address(ip_string)
    except ValueError:
        raise UnauthorizedTargetError("bad_dns_answer")
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # ::ffff:x.x.x.x is judged by the embedded IPv4
    if not (
        addr.is_global
        and not addr.is_multicast
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_private
        and not addr.is_unspecified
    ):
        raise UnauthorizedTargetError("non_public_ip", f"Resolved address {ip_string} is not a global unicast address")


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


def _parse_https(raw_url) -> urlparse:
    """Structural parse shared by target, request and redirect authorization."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        _reject("malformed")
    cleaned = raw_url.strip()
    try:
        parts = urlparse(cleaned)
    except ValueError:
        _reject("malformed")
    if parts.scheme != "https":
        _reject("scheme")
    if parts.username or parts.password:
        _reject("userinfo")
    if parts.hostname is None or parts.hostname == "":
        _reject("malformed")
    netloc = parts.netloc.lower()
    if netloc not in (parts.hostname, f"[{parts.hostname}]"):
        _reject("port")  # netloc carries a port (or IPv6 literal) — none allowed
    if parts.hostname.endswith("."):
        _reject("malformed")  # trailing-dot host forms are unexpected
    if "%" in parts.hostname:
        _reject("malformed")  # percent/zone-id forms are unexpected
    # RFC 6761 loopback names can never be legitimate scan targets.
    host = parts.hostname.lower()
    if host == "localhost" or host.endswith(".localhost"):
        _reject("non_public_ip")
    return parts


def _assert_host_ip_is_global(hostname: str) -> None:
    """A hostname that IS an IP literal must already be globally routable."""
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return  # regular hostname — DNS checks apply later
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not (
        addr.is_global
        and not addr.is_multicast
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_private
        and not addr.is_unspecified
    ):
        _reject("non_public_ip")


def authorize_target_url(raw_url) -> Target:
    """Structural validation of a user-supplied target; normalized to origin.

    Returns Target(target_url='https://host/', host='host'). No DNS here.
    """
    parts = _parse_https(raw_url)
    host = parts.hostname.lower()
    _assert_host_ip_is_global(host)
    return Target(target_url=f"https://{host}/", host=host)


def validate_target_url(raw_url, resolver=None) -> Target:
    """Full validation: structural gate first, then DNS (all answers global).

    The structural gate runs BEFORE any DNS — unsafe names never resolve.
    """
    target = authorize_target_url(raw_url)
    lookup = resolver if resolver is not None else _default_resolver
    try:
        answers = lookup(target.host)
    except UnauthorizedTargetError:
        raise
    except OSError:
        _reject("dns_failure")
    if not answers:
        _reject("dns_failure")
    for ip in answers:
        _assert_global_ip(ip)
    return target


def authorize_request_url(raw_url, origin_host: str) -> str:
    """Authorize a deep request URL that must stay on the scanned origin.

    Returns the canonical URL (fragment stripped). Every structural rule
    applies; the host must equal the authorized origin host.
    """
    parts = _parse_https(raw_url)
    if parts.hostname.lower() != str(origin_host).lower():
        _reject("out_of_scope")
    from urllib.parse import urlunparse

    return urlunparse(parts._replace(fragment=""))


def assert_authorized_redirect(origin_host: str, location_url) -> str:
    """Every redirect hop must be re-validated and stay on the scanned origin."""
    return authorize_request_url(location_url, origin_host)


def resolve_and_validate_ips(hostname: str, resolver=None) -> list[str]:
    """Resolve hostname and require every answer to be a global unicast IP."""
    lookup = resolver if resolver is not None else _default_resolver
    try:
        answers = lookup(hostname)
    except UnauthorizedTargetError:
        raise
    except OSError:
        _reject("dns_failure")
    if not answers:
        _reject("dns_failure")
    for ip in answers:
        _assert_global_ip(ip)
    return list(answers)
