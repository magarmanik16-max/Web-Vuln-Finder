# Scanner (Python) — Phase 2

The vulnerability assessment engine. It only ever assesses the two targets on
`authorized_targets.json` and enforces that restriction independently of Node
(see `scanner/authorization.py` and `docs/SECURITY-DESIGN.md`).

## Layout

```
scanner/
├── authorized_targets.json     immutable allowlist (mirrors server config)
├── scanner/
│   ├── authorization.py        allowlist + SSRF guard (origin + request URLs, IP validation)
│   ├── config.py               ScanConfig: conservative defaults, hard clamps
│   ├── httpengine.py           SafeHTTPClient: pinned TLS, rate limit, redirects, budget
│   ├── crawler/crawler.py      same-origin crawler (links, forms, params, API endpoints)
│   ├── context.py              per-scan context
│   ├── main.py                 CLI + orchestration + exit codes (Node contract)
│   ├── models/                 Finding, ScanResult (dedup), Evidence (redaction)
│   ├── checks/                 headers, tls, cookies, cors, methods,
│   │                           disclosure, xss, sqli, csrf
│   └── reporting/json_report.py  structured JSON output (stdout + optional file)
└── tests/                      120 offline unit tests (mock transport, no live hits)
```

Standard library only — no pip packages required.

## Usage

```bash
cd scanner
python3 -m unittest discover -s tests -v          # 128 tests, fully offline

python3 -m scanner.main --target-url https://example.com \
    [--scan-id <id>] [--config cfg.json] [--output report.json]
```

The JSON report is always printed to **stdout** (Node parses stdout, never
terminal text); human logs go to stderr.

### Integration contract (for Node, §24)

| Aspect | Contract |
|---|---|
| target | `--target-url <public HTTPS origin>` — the engine independently re-enforces the full safety policy (it never trusts the caller) |
| scan id | `--scan-id`, echoed in the report |
| config | `--config cfg.json`; every value clamped to safe ceilings |
| cancellation | `SIGINT`/`SIGTERM` → graceful stop, `"status": "cancelled"` |
| output | JSON on stdout: `{scan_id, target, status, statistics, findings, errors}` |
| exit codes | `0` completed · `1` unauthorized target · `2` usage error · `3` runtime failure · `4` cancelled |

### Engine safety properties

- **Authorization per request**: exact allowlist host, https, no port, no
  userinfo; any path is allowed but always on the authorized origin.
- **Pinned connections**: DNS answers are validated as global unicast and the
  TLS connection is opened to a validated IP with SNI + certificate validation
  for the authorized hostname (validate-then-connect, closing the rebinding gap).
- **Manual redirects**: each hop re-authorized; unauthorized/downgrade/loop
  hops are rejected, up to `max_redirects`.
- **Global request budget** (`max_requests`) + rate limit (`min_request_interval`)
  + response size cap + timeout — a scan cannot flood a target.
- **Destructive action prohibition**: XSS uses unique harmless markers, SQLi
  uses minimal single-quote/boolean probes (timing probes off by default),
  PUT/DELETE are only sent to random non-existent probe paths, forms are never
  submitted, no enumeration/dumping/extraction anywhere.

### Severity / confidence

Severity (`informational…critical`) is evidence-based and deliberately
conservative: missing hardening headers are Low/Medium, reflected-input
findings are reported as reflection evidence (never "confirmed XSS"), SQLi
findings carry Medium/Low confidence. Confidence (`low/medium/high`) is
independent of severity. Findings deduplicate by fingerprint
(category+title+origin path+method+parameter).

## Live verification (controlled, conservative defaults)

| Target | Result |
|---|---|
| manikmagar.com.np | completed, exit 0 — 10 requests, 1 page (homepage links are external only), 9 findings (1 Medium: missing CSP; 3 Low; 5 Informational), 0 errors |
| mnk.manikmagar.com.np | completed, exit 0 — 10 requests, 1 page, 3 Informational findings, 0 errors |
| http://localhost / https://192.168.1.1 via CLI | rejected, exit 1 |

Scan artifacts: `.data/scan-static.json`, `.data/scan-dynamic.json` (gitignored).
