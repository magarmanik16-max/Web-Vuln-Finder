# Phase 2 Report — Python Vulnerability Scanner

Status: **COMPLETE** (all Definition-of-Done items satisfied). Phase 3 has NOT
been started. Phase 1 code, tests and security controls were not modified
except for two additive scanner-facing functions in `scanner/authorization.py`
(see "Preserved security controls" below).

## Pre-flight verification (before any change)

- Git working tree clean on `main` (commit `c2d8b48`).
- Phase 1 structure, `.env`, userspace mongod present; all three services up.
- Phase 1 suites green: server Jest **97/97**, scanner unittests **14/14**, E2E smoke **9/9**.
- Phase 2 prompt (`ai-prompts/02-SCANNER.md`) read in full before implementation.

## What was implemented (Python only; Node/React untouched)

- **Config** (`scanner/config.py`): `ScanConfig` with conservative defaults and
  hard clamps — no configuration can exceed safe ceilings (pages, requests,
  concurrency, rate, timeouts) or enable flooding.
- **HTTP engine** (`scanner/httpengine.py`): `SafeHTTPClient` with per-request
  authorization, DNS-validated then **connection-pinned** TLS (validate-then-
  connect, SNI + cert verification for the authorized host), manual redirects
  with per-hop re-authorization, timeout, response size cap, global rate
  limiter, cooperative cancellation, retry budget for idempotent methods,
  global request budget, and the scoped port-80 `probe_http_redirect` for the
  TLS check.
- **Crawler** (`scanner/crawler/crawler.py`): same-origin BFS crawler
  discovering links, forms (with inputs), query parameters and API-like
  endpoints; URL normalization (fragment strip, sorted params) + dedup; hard
  limits for depth/pages/requests/size/timeout/concurrency; out-of-origin,
  subdomain, downgrade, port and `javascript:/mailto:/tel:/data:` candidates
  dropped before fetch.
- **Checks** (`scanner/checks/`): headers (6 headers + weak-CSP notes),
  tls (certificate validity/expiry bands + HTTP→HTTPS probe), cookies
  (Secure/HttpOnly/SameSite/Domain/Path, values never stored), cors (reflected
  origin / wildcard / credentials combos with evidence), methods (OPTIONS
  Allow, TRACE echo marker, PUT/DELETE only to random non-existent probe
  paths), disclosure (version headers, stack traces, directory listing, and
  four conservative probes: /.env, /.git/HEAD, /phpinfo.php, /server-status —
  contents withheld), xss (unique harmless markers with a trailing quote;
  reflection context classification: HTML body / attribute / script / URL
  attribute; encoded reflections never reported), sqli (single-quote error
  indicators, boolean differential for numeric params, timing probes off by
  default, never enumeration/dumping), csrf (state-changing forms without
  anti-CSRF tokens, SameSite correlation; forms never submitted).
- **Models** (`scanner/models/`): `Finding` (full §16 contract: id, target,
  URL, method, parameter, title, category, severity, confidence, CWE, OWASP,
  description, evidence, impact, remediation, module, timestamp),
  `ScanResult` (fingerprint dedup, severity stats, errors), `evidence.py`
  (secret-key redaction, token-blob scrubbing, excerpt caps, cookie values
  never stored; re-redacted at report serialization as a backstop).
- **Reporting** (`scanner/reporting/json_report.py`): JSON on stdout —
  `{scan_id, target, status, statistics, findings, errors}`.
- **CLI / Node contract** (`scanner/main.py`): `--target-id` (IDs only),
  `--scan-id`, `--config`, `--output`; SIGINT/SIGTERM → `cancelled`; exit codes
  0/1/2/3/4 (completed/unauthorized/usage/runtime-failure/cancelled).

## Tests

**120/120 offline scanner tests pass** (mock transports; live websites are
never hit in unit tests). Coverage includes every area §22 requires:
authorization, redirect authorization, URL normalization, crawler boundaries,
header/cookie/CORS detection, XSS reflection contexts, SQLi probes and
non-enumeration assertion, CSRF form analysis, deduplication, severity,
evidence redaction, config clamping, CLI exit codes, JSON shape, cancellation.

## Controlled live scans (both authorized targets only)

| Run | Result |
|---|---|
| `--target-id STATIC_TARGET` | exit 0, status `completed` — 10 requests, 9 findings (1 Medium: missing CSP; 3 Low: HSTS/XCTO/XFO; 5 Informational incl. valid TLS cert 64 days, HTTP→HTTPS redirect, wildcard CORS), 0 errors |
| `--target-id DYNAMIC_TARGET` | exit 0, status `completed` — 10 requests, 3 Informational findings (permissive CSP directives, TLS cert 32 days, HTTP→HTTPS redirect), 0 errors |
| `--target-id EVIL_TARGET` (CLI) | rejected, exit 1 |
| usage error / bad config | exit 2 / exit 3 (verified) |

Crawler page-count note: the static site's homepage links are external
(GitHub/LinkedIn/mailto) and are correctly dropped by the same-origin filter —
boundary behavior, not a crawler defect.

Artifacts: `.data/scan-static.json`, `.data/scan-dynamic.json` (gitignored).

## Security controls preserved/added

- Preserved: Phase 1 allowlist, SSRF guard, auth, audit logging, middleware —
  untouched; **97/97 Phase 1 tests still pass after Phase 2**.
- Additive (scanner-facing only): `authorize_request_url()` (any-depth paths on
  the authorized origin) and `resolve_and_validate_ips()` (DNS→global-unicast
  validation for connection pinning) in `scanner/authorization.py`; plus the
  existing origin-level functions are unchanged and still tested by the
  Phase 1 suite (14 tests) and the new Phase 2 suite.

## Bugs found and fixed during this phase (all caught by tests)

1. **Rate limiter infinite loop** — the slot reservation advanced on every
   wait iteration so `delay` never reached ≤0 (test hang). Fixed to claim the
   slot exactly once.
2. **Config floor/ceiling conflict** — `min_request_interval` (a floor) was
   clamped by the ceiling loop, silently capping it at 0.1 s. Excluded from
   the ceiling loop.
3. **Crawler forms parsed after being collected** — `out.forms.extend()` ran
   before HTML parsing populated `page.forms`. Reordered.
4. **Crawler depth off-by-one** — pages at exactly `max_depth` were never
   fetched (`<` instead of `<=`).
5. **CORS `header()` lacked a default-argument** — TypeError on optional
   headers. Added `header(name, default="")`.
6. XSS marker hardening: alphanumeric-only markers cannot distinguish encoded
   from raw reflection; the marker now carries one quote character so
   HTML-encoding output suppresses the finding (test-driven change).

## Definition of done

- [x] Python scanner exists — [x] authorization works — [x] SSRF protections exist
- [x] crawler works — [x] headers check — [x] TLS check — [x] cookie check
- [x] CORS check — [x] methods check — [x] disclosure check — [x] XSS check
- [x] SQLi check — [x] CSRF check — [x] finding model — [x] evidence redaction
- [x] deduplication — [x] JSON output — [x] unit tests pass (120/120)
- [x] controlled live scan works (both targets, exit 0)
- [x] unauthorized targets rejected (exit 1, unit + CLI verified)

## Remaining environmental/manual tasks

- None blocking. Optional: wire Node → scanner spawn (that is Phase 3's
  integration work per §24 "can **later** be called by Node"); pip/git still
  absent from the OS base image (not needed for Phase 2 — scanner is stdlib-only).

## Git status

Working tree has uncommitted Phase 2 changes (new scanner modules + tests +
docs; no modifications to `client/`, `server/` beyond none, `tests/smoke.mjs`
unchanged). Commit left to the operator per workflow.

**Phase 2 complete. Phase 3 not started.**
