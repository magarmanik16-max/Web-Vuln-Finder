# Security Design — Target Authorization & SSRF Prevention

The platform's core security property: **no request path exists from browser
input to a network destination.** This document defines the design that Phase 2
(scanner engine) must preserve.

## 1. Three independent authorization walls

| Wall | Location | Mechanism |
|---|---|---|
| W1: API boundary | `server` routes/controllers | The submitted `url` is normalized and validated (structure + DNS) **before** a scan row is created or the scanner is launched. Unsafe → `400` + audit `scan.target.rejected (denied)` with a deliberately terse client-facing message. |
| W2: Scan-service guard | `server/src/security/urlGuard.js` | The Scan Manager re-validates the target immediately before spawning the scanner, and `authorizeRequestUrl` scopes every redirect hop to the scanned origin. |
| W3: Scanner self-check | `scanner/scanner/authorization.py` | The Python engine independently re-implements the full policy and re-validates the target (structure + DNS) before its first request. |

A destination is assessable only if it passes **all three** walls. A malicious
or buggy Node layer cannot make Python scan an unsafe target, and vice versa.

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

## 3. Redirect & crawler scope policy

Every redirect hop must re-validate and stay on the **scanned origin**
(`assertAuthorizedRedirect`): HTTPS→HTTPS, same exact host. Any downgrade,
cross-site hop, subdomain hop, or IP hop is rejected — a redirect away from
the origin leaves the authorized scope. The HTTP client uses manual redirect
handling and calls this check per hop; it never uses "follow redirects"
primitives. This also mitigates DNS rebinding between hops.

The crawler is likewise same-origin only: candidate links are authorized with
`authorizeRequestUrl(url, originHost)` before being queued, so a page on the
target cannot redirect or link the crawler onto third-party or internal
systems. Crawl depth/page/request/rate limits are unchanged.

## 4. Residual risks & Phase 2 obligations

- **TOCTOU / rebinding between validation and connection**: the HTTP engine
  resolves the host per request, validates every answer as globally routable,
  and PINS the TLS connection to a validated IP (validate-then-connect).
  Each redirect hop re-resolves and re-validates. Residual risk: a DNS server
  with multiple answers that rotate between checks is bounded by per-request
  re-validation; a same-IP answer set is pinned.
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
