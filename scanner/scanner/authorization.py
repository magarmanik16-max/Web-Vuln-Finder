"""Independent target authorization for the Python scanner.

Mirrors server/src/security/urlGuard.js with the same rules (stdlib only):

  1. Parse with urllib.parse; malformed input is rejected, never repaired.
  2. Exact host equality against the allowlist (no suffix/substring matching).
  3. https only, no port, no userinfo, origin-level path.
  4. DNS resolution only AFTER the allowlist gate; every resolved address must
     be a global unicast IP (rejects loopback, private, link-local incl. cloud
     metadata 169.254.169.254, multicast, ULA, IPv4-mapped, unspecified).
  5. Redirects must re-validate to the same authorized target.

The resolver is injectable so tests run without network.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ALLOWLIST_PATH = os.path.join(_HERE, "..", "authorized_targets.json")


class UnauthorizedTargetError(ValueError):
    """Raised for any target that is not explicitly authorized."""

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or f"Target rejected: {code}")
        self.code = code


@dataclass(frozen=True)
class Target:
    target_id: str
    host: str
    url: str
    type: str


def load_allowlist(path: str = DEFAULT_ALLOWLIST_PATH) -> dict[str, Target]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    targets = {}
    for t in raw["targets"]:
        targets[t["id"]] = Target(target_id=t["id"], host=t["host"].lower(), url=t["url"], type=t["type"])
    return targets


def resolve_target_id(target_id: str, allowlist: dict[str, Target] | None = None) -> Target:
    """The ONLY way the scanner learns a destination: ID -> configured target."""
    allowlist = allowlist or load_allowlist()
    if not isinstance(target_id, str) or target_id not in allowlist:
        raise UnauthorizedTargetError("not_authorized", f"Unknown targetId. Authorized: {sorted(allowlist)}")
    return allowlist[target_id]


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


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


def validate_target_url(raw_url, allowlist: dict[str, Target] | None = None, resolver=None) -> Target:
    """Stage 1: exact allowlist check. Stage 2: DNS -> all answers must be global."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise UnauthorizedTargetError("malformed")
    try:
        parts = urlparse(raw_url.strip())
    except ValueError:
        raise UnauthorizedTargetError("malformed")

    if parts.scheme != "https":
        raise UnauthorizedTargetError("scheme")
    if parts.username or parts.password:
        raise UnauthorizedTargetError("userinfo")
    if parts.hostname is None or parts.hostname == "":
        raise UnauthorizedTargetError("malformed")
    if parts.netloc != parts.hostname:
        raise UnauthorizedTargetError("port")  # netloc carries a port (or IPv6 literal) — none allowed
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise UnauthorizedTargetError("path")

    # Exact host equality; urlparse hostname is lowercased for us.
    match = [t for t in (allowlist or load_allowlist()).values() if t.host == parts.hostname]
    if not match:
        raise UnauthorizedTargetError("not_authorized")
    target = match[0]

    if resolver is None:  # explicit opt-out reserved for tests only
        resolver = _default_resolver
    try:
        answers = resolver(target.host)
    except UnauthorizedTargetError:
        raise
    except OSError:
        raise UnauthorizedTargetError("dns_failure")
    if not answers:
        raise UnauthorizedTargetError("dns_failure")
    for ip in answers:
        _assert_global_ip(ip)
    return target


def assert_authorized_redirect(current: Target, location_url) -> Target:
    """Every redirect hop must land on the exact same authorized origin."""
    nxt = validate_target_url(location_url)
    if nxt.target_id != current.target_id:
        raise UnauthorizedTargetError("unauthorized_redirect")
    return nxt


# --------------------------------------------------------------------------
# Scanner-grade primitives (Phase 2). The crawler and HTTP engine must request
# deep paths (e.g. /blog/post-1) on the authorized ORIGIN, so beyond the
# origin-level checks above they use the following two functions:
#   - authorize_request_url(): exact-host allowlist + https + no port/userinfo,
#     but any path/query — the path is always on the authorized origin.
#   - resolve_and_validate_ips(): DNS answers for an authorized host, all of
#     which must be global unicast. The HTTP engine PINS the connection to one
#     of these validated IPs (validate-then-connect, see docs/SECURITY-DESIGN.md).
# --------------------------------------------------------------------------


def authorize_request_url(raw_url, allowlist: dict[str, Target] | None = None) -> tuple[Target, "urlparse"]:
    """Authorize an arbitrary-depth request URL on an authorized origin only."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise UnauthorizedTargetError("malformed")
    cleaned = raw_url.strip()
    try:
        parts = urlparse(cleaned)
    except ValueError:
        raise UnauthorizedTargetError("malformed")
    if parts.scheme != "https":
        raise UnauthorizedTargetError("scheme")
    if parts.username or parts.password:
        raise UnauthorizedTargetError("userinfo")
    if parts.hostname is None or parts.hostname == "":
        raise UnauthorizedTargetError("malformed")
    if parts.netloc != parts.hostname:
        raise UnauthorizedTargetError("port")  # netloc carries a port (or IPv6 literal) — none allowed

    match = [t for t in (allowlist or load_allowlist()).values() if t.host == parts.hostname]
    if not match:
        raise UnauthorizedTargetError("not_authorized")
    # Strip the fragment — clients never send it and it must not affect dedupe.
    parts = parts._replace(fragment="")
    return match[0], parts


def resolve_and_validate_ips(hostname: str, resolver=None) -> list[str]:
    """Resolve hostname and require every answer to be a global unicast IP."""
    lookup = resolver or _default_resolver
    try:
        answers = lookup(hostname)
    except UnauthorizedTargetError:
        raise
    except OSError:
        raise UnauthorizedTargetError("dns_failure")
    if not answers:
        raise UnauthorizedTargetError("dns_failure")
    for ip in answers:
        _assert_global_ip(ip)
    return list(answers)
