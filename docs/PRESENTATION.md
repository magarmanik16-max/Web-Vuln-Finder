# Final-Year Presentation Material

Concise, evaluation-ready material. Everything below reflects what the system
actually does and actual recorded results.

## 1. Problem Statement

Security teams need to regularly assess their web assets, but general-purpose
scanners can point at arbitrary URLs — making them dangerous when untrained
users run them, and unusable when a strict, consented scope is required. This
project delivers a self-hosted vulnerability assessment platform that is
**architecturally incapable** of scanning anything outside a single,
hard-coded, consented allowlist, while producing evidence-based findings and
professional reports.

## 2. Objectives

1. Build a three-layer platform (React dashboard, Express API, Python engine).
2. Make the authorized target allowlist an architectural property, not a setting.
3. Detect common web vulnerability classes with safe, evidence-producing checks.
4. Persist everything (scans, findings, audit trail) in MongoDB.
5. Generate professional reports with complete data integrity.
6. Test the security boundary adversarially, in both Node and Python.

## 3. Scope

Authorized targets ONLY (immutable, in code, mirrored independently):

- `STATIC_TARGET` — https://manikmagar.com.np (static)
- `DYNAMIC_TARGET` — https://mnk.manikmagar.com.np (dynamic)

No arbitrary URL scanning exists anywhere: the browser cannot submit a URL, the
API accepts only target IDs, and the Python scanner re-validates independently.

## 4. System Architecture

```
React (Vite, Tailwind)  →  Express API  →  Scan Manager  →  Python Scanner  →  Authorized Target
        ↑ results: Python JSON → Express → MongoDB → React dashboard / findings / report (+PDF)
```

- Express never blocks on scans: the Python engine runs as a managed child
  process with progress streamed to the UI (2 s polling of module checklist).
- The dashboard shows live scan progress, findings with evidence, and generates
  PDF reports from stored data.

## 5. Technology Selection

| Layer | Choice | Why |
|---|---|---|
| Frontend | React 18, Vite, Tailwind 4 | fast dev loop, small SPA, no framework lock-in |
| API | Node.js + Express | single-language orchestration, easy process supervision |
| Data | MongoDB + Mongoose | flexible finding shapes, schema validation where it matters |
| Engine | Python 3.12 (stdlib only) | best-in-class parsing/ipaddress modules; zero pip dependencies |
| PDF | pdfkit | pure-JS, no headless browser required |

## 6. Scanner Architecture

Pipeline: authorization → connectivity → same-origin crawler → 9 bounded
checks (headers, TLS, cookies, CORS, methods, disclosure, XSS, SQLi, CSRF) →
deduplication → evidence sanitization → JSON report.
Details: `docs/scanner-methodology.md`.

## 7. Database Design

- **User** — email, bcrypt(12) hash, role (admin/analyst), active flag.
- **Scan** — targetId (enum), requestedBy, status (queued/running/completed/
  failed/cancelled), severity summary, progress (module checklist, requests,
  pages, endpoints), timing.
- **Finding** — scan ref, targetId, severity, confidence, category, title,
  description, url/method/parameter, CWE, OWASP, impact, remediation, evidence,
  status. Indexes on scan, severity, confidence, category, target.
- **Report** — scan ref, format, status, fileKey, full sections JSON.
- **AuditLog** — actor, action, targetId, scanId, result, ip, user-agent,
  sanitized details (secret-shaped keys redacted before write).
- Targets are deliberately NOT a collection — they are immutable configuration.

## 8. Security Model

Why arbitrary URLs are forbidden: an assessment tool that accepts any URL is a
weaponizable SSRF/credential-theft primitive; this project's whole premise is
consented, scoped testing of the owner's own two domains.

Three independent walls enforce it:

1. **API**: only target IDs (closed enum) are accepted; URLs are rejected 400
   and audited as `denied`.
2. **Node guard** (`urlGuard.js`): WHATWG parsing, https-only, exact host
   equality, no port/userinfo, DNS answers must all be global unicast
   (ipaddr.js range semantics), per-hop redirect re-authorization.
3. **Python engine** (`authorization.py`): same rules implemented independently
   with `urlparse`/`ipaddress`; connections are **pinned** to a validated IP
   with SNI + certificate verification (validate-then-connect), closing the
   DNS-rebinding window between check and connect.

Destructive testing is avoided because the tool runs against live production
sites: probes are limited to unique harmless markers, single-quote error
indicators, boolean differentials, random non-existent probe paths for
PUT/DELETE, and static form analysis. Details: `docs/security.md`.

## 9. Threat Model

| Threat | Mitigation |
|---|---|
| Attacker uses platform to scan third parties | triple allowlist, IDs-only API, independent Python enforcement |
| SSRF via DNS rebinding / pinning | per-request DNS validation + IP pinning + per-hop redirect authorization |
| Scans point at internal services (localhost, metadata, private ranges) | IP classification rejects non-unicast answers before any connection |
| Abuse of the scan API (floods) | auth, rate limits (20/15min auth, 300/15min global), concurrency cap + FIFO, 429 hard cap |
| Credential/secret leakage | bcrypt hashing, JWT denylist logout, evidence redaction, audit secret-key redaction, no secrets in code |
| Malicious request bodies | JSON size limit, id-format validation, enum validation, generic error messages |
| Scanner harming the target | request budget, rate limiter, response caps, timeouts, cancellation, non-destructive probes only |

## 10. Vulnerability Detection Methodology

See `docs/scanner-methodology.md` — the one-line version: every check pairs a
bounded probe with concrete evidence (URL, method, status, headers, short
excerpt, detection reason) and a remediation; severity is conservative and
confidence is stated separately.

## 11. Testing Methodology

Five suites, 271+ checks total (130 server, 128 scanner, 7 frontend, 6 E2E),
plus a 9-check smoke. Security tests are adversarial by design: encoded
addresses, parser differentials, IDN homoglyphs, userinfo tricks, rebinding
answers, redirect escapes — verified against BOTH Node and Python
implementations. Integration tests spawn a real child process through the
production code path. Unit tests never touch live websites. Details:
`docs/testing.md`.

## 12. Results (actual, final conservative assessments)

| Target | Duration | Requests | Findings |
|---|---|---|---|
| manikmagar.com.np (STATIC) | ~3 s | 10 | 9 — 1 Medium (missing CSP), 3 Low (missing HSTS/XCTO/XFO), 5 Informational (referrer/permissions policy, valid TLS 64 days, HTTP→HTTPS redirect, wildcard CORS on public resources) |
| mnk.manikmagar.com.np (DYNAMIC) | ~3 s | 10 | 3 — Informational (permissive CSP directives, valid TLS 32 days, HTTP→HTTPS redirect) |

Zero errors, zero duplicate findings, evidence redaction verified, report
sections matched stored findings exactly. Unauthorized targets (example.com,
localhost, IP literals, lookalike subdomains) were rejected at every layer.

## 13. Limitations

See `docs/limitations.md`. Headline: automated scanning is a component of
assurance, not assurance itself; authentication-protected and JS-rendered
areas are out of scope; XSS/SQLi results require human verification.

## 14. Future Work

- Persist the JWT denylist (Redis) and support multi-node deployments.
- Authenticated scanning with scoped, consented credentials.
- DOM-based XSS detection via headless rendering.
- CVSS scoring and trend dashboards across scan history.
- Resume interrupted scans instead of marking them failed.

## 15. Conclusion

The project demonstrates that a vulnerability scanner can be made *incapable*
of violating its scope by construction — three independent enforcement layers,
a hardened orchestration pipeline, evidence-based detection, and an audited,
tested security boundary — while remaining a practical, usable assessment tool
for its two authorized targets.
