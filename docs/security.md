# Security Design — Target Authorization & SSRF Prevention

The platform's core security property: **no request path exists from browser
input to a network destination.** This document defines the design that Phase 2
(scanner engine) must preserve.

## 1. Three independent authorization walls

| Wall | Location | Mechanism |
|---|---|---|
| W1: API boundary | `server` routes/controllers | `targetId` must be a member of the closed enum in `config/targets.js`. Unknown → `400` + audit `scan.target.rejected (denied)`. **URLs are not an accepted input format anywhere.** |
| W2: Scan-service guard | `server/src/security/urlGuard.js` | Full URL validation used by the scan service before any dispatch (defense-in-depth; also the reference implementation of the rules). |
| W3: Scanner self-check | `scanner/scanner/authorization.py` | The Python engine independently re-validates every destination. It runs with its own allowlist copy; W2/W3 are deliberately redundant. |

A target is assessable only if it passes **all three** walls.

## 2. URL validation rules (W2/W3 — identical semantics)

1. **Parse with a real URL parser** (WHATWG `URL` in Node, `urlparse` in
   Python). Malformed input is rejected — never repaired, never "best-effort".
2. **Scheme allowlist**: `https:` only. `http`, `ftp`, `file`, `javascript`,
   `data`… are rejected (also blocks TLS-downgrade redirects).
3. **Exact host equality** against the allowlist — no suffix matching, no
   substring matching, no regex. This single rule defeats: arbitrary domains,
   arbitrary/lookalike subdomains (`evil.manikmagar.com.np`,
   `manikmagar.com.np.evil.com`), raw IP literals in any notation (decimal
   `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, IPv6), `localhost`, and
   internal hostnames — none can byte-equal `manikmagar.com.np`.
   URL-parser normalization (lowercasing, default-port stripping) is embraced:
   normalized forms are compared, so canonical equivalents pass and all
   non-canonical spellings fail.
4. **No port, no userinfo, origin-level path/query/fragment** — the assessment
   scope is the origin; deeper paths are chosen by the crawl engine (Phase 2)
   within the same origin.
5. **DNS validation AFTER the allowlist gate**: every A/AAAA answer for an
   authorized host must be a **global unicast** address. Rejects: loopback
   (`127/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`), link-local
   (`169.254/16` incl. cloud metadata `169.254.169.254`, `fe80::/10`),
   unique-local (`fc00::/7`), multicast, unspecified, CGNAT (`100.64/10`),
   benchmarking (`198.18/15`), and IPv4-mapped IPv6 (judged by the embedded
   IPv4). Address classification uses `ipaddr.js` range semantics (Node) /
   the `ipaddress` module predicates (Python) — **never string matching**.
6. **No DNS for unauthorized names** — the allowlist gate runs first, so
   attacker-controlled names are never resolved (no DNS-exfil side channel).

## 3. Redirect policy

Every redirect hop must re-validate to the **same** authorized target
(`assertAuthorizedRedirect`): HTTPS→HTTPS, same exact host. Any downgrade,
cross-target hop, subdomain hop, or IP hop is rejected. The Phase 2 HTTP client
MUST use manual redirect handling and call this check per hop — it must never
use "follow redirects" primitives. This also mitigates DNS rebinding between
hops.

## 4. Residual risks & Phase 2 obligations

- **TOCTOU / rebinding between validation and connection**: Phase 2's HTTP
  client must connect to a DNS answer that was validated in the same request
  (validate-then-connect on the returned addresses, or re-validate per hop).
  Optional hardening: DNS answer pinning + reverse-confirmation.
- **End-to-end request enforcement**: the Python engine must never open sockets
  to raw IPs or user-passed hosts; only `Target.url` (or same-origin subpaths of
  it) may be requested.
- **In-memory JWT denylist** is per-process (fine for the single-node Phase 1
  deployment; persist in Phase 4 when scaling).
- **Token storage in the browser** uses `localStorage` (XSS-exposed). CSP from
  Helmet, no third-party scripts, and Phase 4's hardening pass (httpOnly-cookie
  option) address this.

## 5. Audit trail

`AuditLog` records actor, action, targetId, scanId, result
(`success/failure/denied`), IP, user-agent, timestamp, and sanitized details.
Secret-shaped keys (`password`, `token`, `secret`, `authorization`, `credential`,
`jwt`) are redacted before persistence. Failed logins and rejected target
attempts are always recorded; audit-write failures never break request flow.
