# Scanner Methodology

What the Python engine actually does during an assessment — and what it
deliberately does not do.

## Guiding principle

DETECTION + EVIDENCE + RISK + REMEDIATION — never destructive exploitation.
The scanner never dumps databases, extracts credentials, brute-forces, deletes
or modifies resources, uploads anything, floods endpoints, or exfiltrates data.

## Assessment pipeline

1. **Authorization** — the user-supplied target URL is independently
   re-validated by the engine: HTTPS only, no port/userinfo/fragments,
   IP-literal hosts must be globally routable, and DNS answers must all be
   global unicast. The target is normalized to its origin. Unsafe input never
   triggers a DNS lookup.
2. **Connectivity + crawling** — a same-origin BFS crawler fetches the
   authorized origin and follows links/forms it discovers. Limits: depth 3,
   50 pages, ≤500 requests (global budget), 512 KB responses, 15 s timeouts,
   4 concurrent workers, ≥0.25 s between requests. URLs are normalized
   (fragment stripped, params sorted) and deduplicated; anything that is not
   the exact authorized host over https is dropped before fetching.
3. **Checks** (each bounded, evidence-producing):

| Module | What it detects | Safety controls | Typical severity |
|---|---|---|---|
| headers | missing CSP/HSTS/XCTO/XFO/Referrer-Policy/Permissions-Policy; weak CSP | passive | Info–Medium |
| tls | certificate validity/expiry, HTTP→HTTPS upgrade | observation only (scoped port-80 HEAD, no redirect follow) | Info–Critical (expiry bands) |
| cookies | missing Secure/HttpOnly/SameSite on Set-Cookie | values never stored | Low–Medium |
| cors | wildcard / reflected Origin / credentials combos | one probe GET per page with a bogus Origin | Info–High |
| methods | advertised dangerous methods, TRACE echo, PUT/DELETE acceptance | PUT/DELETE only to random non-existent probe paths | Low–High |
| disclosure | version headers, stack traces, directory listings, public .env/.git/phpinfo/server-status | 4 fixed probes; contents withheld from evidence | Info–High |
| xss | raw reflection of a unique marker in HTML/attribute/script/URL contexts | harmless alphanumeric+quote marker, no breakout payloads, encoded reflection ignored | Medium (High for script context) |
| sqli | DB error signatures after a single-quote probe; boolean differentials on numeric params | ≤1 request per param per technique; timing probes disabled by default; never enumerates | Medium–High |
| csrf | state-changing forms without anti-CSRF tokens | static analysis; forms never submitted | Low–Medium |

4. **Reporting** — findings are deduplicated by fingerprint
   (category+title+origin-path+method+parameter), evidence is sanitized
   (secret-shaped keys redacted, token blobs scrubbed, excerpts ≤400 chars,
   cookie values never stored), and the result is emitted as structured JSON.

## Severity & confidence

Severity (informational/low/medium/high/critical) is evidence-based and
conservative: missing hardening headers are Low/Medium; reflection evidence is
never reported as "confirmed XSS"; SQLi heuristics carry Medium/Low confidence.
Confidence (low/medium/high) is independent of severity.

## Every-request safety net

- origin-scoped authorization: every request URL and redirect hop must stay
  on the scanned origin (exact host equality), https only, no port/userinfo;
- DNS answers validated as global unicast and the TLS connection **pinned** to
  a validated IP with SNI + certificate verification (validate-then-connect);
- manual redirects: each hop re-authorized against the exact same origin;
- global request budget + rate limiter + response cap + cancellation — a scan
  cannot flood a target even if misconfigured.
