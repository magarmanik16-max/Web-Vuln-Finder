# Phase 3 Report — Full Platform Integration

Status: **COMPLETE** — the full pipeline works end-to-end with live scans:
React → Express → Scan Manager → Python scanner → authorized target → scanner
JSON → MongoDB → React dashboard/findings/reports (+PDF). Phase 4 NOT started.

## Architecture / integration implemented

- **Scan Manager** (`server/src/services/scanManager.js`) — Node ↔ Python
  orchestration: spawns the scanner with an argument array and `shell: false`
  (target ID from the validated enum, server-generated scan id and output path
  only — no user-controlled string reaches the command line), tracks the child
  process, consumes its structured output, stores findings in MongoDB, updates
  scan status/timing/progress, handles failures, supports cancellation.
  - Concurrency: `SCAN_CONCURRENCY` (default 2) with a FIFO queue — request
    bursts cannot start uncontrolled scans; a hard 429 cap at 20 pending.
  - Orphan recovery on boot: scans from a previous process are marked failed.
  - Cancellation: SIGTERM (10 s grace, then SIGKILL); the scanner flushes a
    `cancelled` report whose partial findings are preserved in MongoDB.
  - Progress: the scanner emits `PROGRESS {json}` lines on stderr (additive in
    `scanner/main.py`); the manager maps them to a per-module checklist and
    live request/page/endpoint counters.
- **Real-time progress** — polling (2 s) while scans are active; simplest
  reliable mechanism, no WebSockets/SSE over-engineering.
- **Reports** (`server/src/services/reportService.js`, `report.controller.js`):
  `POST /api/reports {scanId}` builds every section strictly from stored Scan +
  Finding documents (Executive Summary, Assessment Scope, Methodology, Risk
  Summary, Findings, Remediation, Limitations, assessment timestamp); renders a
  clean professional **PDF via pdfkit** stored under `.data/reports/`; download
  streams with basename + directory-confinement path guarding. Data integrity
  (§11) is asserted by tests: report findings/severity counts must equal the
  stored findings exactly.
- **Models** — `Scan`: progress (currentModule, module checklist, requests,
  pages, endpoints), durationMs, status index. `Finding`: full Phase 2 contract
  (url, method, parameter, confidence, cwe, owasp, impact, remediation,
  scannerModule, evidence, detectedAt) + normalized severity + useful indexes.
  `Report`: sections, fileKey, status. No over-indexing.
- **API** — findings filters now include `category` and `confidence` (plus
  existing severity/target/scan); scan create/cancel wired to the manager;
  reports: generate/list/detail/PDF download; 409 for reporting non-terminal
  scans; id-format validation on all `:id` routes (IDOR/input hygiene).
- **Frontend** — Scans page shows live module checklist (✓/→/○ per §5), status,
  duration, requests, endpoints, findings, cancel button; Findings page got
  severity/target/category/confidence filters and a full detail dialog;
  Reports page generates, views (all 8 sections) and downloads PDFs;
  Dashboard shows totals, active/completed split, severity distribution,
  recent scans and findings. Targets page unchanged (read-only, no input).

## Tests run — exact counts

| Suite | Result |
|---|---|
| Server Jest (Phase 1 security + Phase 3 integration) | **112/112 pass** |
| Scanner unittests (Phase 1 auth + Phase 2 checks) | **120/120 pass** |
| Frontend vitest (Targets, Login, Findings, Dashboard) | **7/7 pass** |
| Phase 1 smoke (`tests/smoke.mjs`) | **9/9 pass** |
| Production builds (`vite build`) | clean |

New integration tests spawn a **real child process** (`tests/fixtures/stub_scanner.py`,
same CLI contract as the scanner, zero network) through the production code
path: launch → progress → findings storage → status transitions → cancellation
with partial findings → failure/garbage output handling → reports → PDF bytes.

## End-to-end scan results (live, §17 — via the Vite proxy like the real frontend)

| Check | Result |
|---|---|
| STATIC_TARGET full flow | ✓ completed — 10 requests, 9 findings stored in MongoDB, report ready, valid PDF (`%PDF-`), duration 3 s |
| DYNAMIC_TARGET full flow | ✓ completed — 10 requests, 3 findings, report ready, valid PDF |
| Unauthorized targets (`https://example.com`, `http://localhost`, `EVIL_TARGET`) | ✓ **rejected (400)** at the API boundary |
| Dashboard data | ✓ totals, active/completed split, severity distribution, recent activity |
| Unauthenticated access to scans/reports | ✓ 401 |
| Summary/finding consistency | ✓ scan.summary totals equal stored findings count; report findings equal stored findings |

## Security controls verified

- Target allowlist (IDs only, enum-validated; URLs rejected) + audit `denied` entries.
- SSRF protections intact (scanner-side validation unchanged; 120/120 scanner tests).
- Safe subprocess execution: argument array, `shell: false`, no user input in argv.
- Authentication on every new route (reports incl. PDF download) — 401 verified.
- Rate limiting (global + auth), CORS allowlist, helmet, JSON limit — unchanged.
- Concurrency cap + queue prevents scan floods; 429 beyond hard cap.
- Report path traversal guarded (invalid ids → 400; basename confinement).
- Audit log entries: scan.create/completed/failed/cancelled, report.generate.

## Bugs discovered and fixed (all test-caught)

1. Scan data directory not created before launch → child exit 1 (tests).
2. `REPO_ROOT` resolved one level short → default `SCANNER_CWD`/data dirs pointed
   into `server/` → live scans failed with `spawn python3 ENOENT` (caught by E2E).
3. Jest sandbox does not propagate test-time `process.env` mutations to spawned
   children → explicit `env: process.env` on spawn.
4. Unparseable scanner output with exit 0 was stored as `completed` → now `failed`
   (results cannot be trusted).
5. vitest 5 requires Vite ≥ 6 → pinned vitest 2 (Vite-5 compatible) instead of
   upgrading the working build stack.
6. Test-side: invalid Mongo id format in a cancel test (400 vs 404); finding
   dedup collision in fixture data.

## Definition of done

- [x] Node launches Python — [x] scanner results reach Node — [x] findings reach MongoDB
- [x] scan status works (queued/running/completed/failed/cancelled + timing/progress)
- [x] cancellation works (SIGTERM, partial findings preserved — tested)
- [x] dashboard works — [x] target page works (no arbitrary target field)
- [x] findings page works (filters + detail) — [x] report generation works
- [x] PDF works — [x] authentication works — [x] authorization works
- [x] audit logs work — [x] API tests pass (112/112) — [x] frontend tests pass (7/7)
- [x] end-to-end scan works (both targets, live) — [x] unauthorized target rejected

## Remaining tasks / notes

- Browser-based UI click-through was not possible in this session (no browser
  backend); UI behavior is covered by component tests, the production build,
  and the live API-level E2E through the same proxy the frontend uses.
- Reports of `cancelled` scans include partial findings and say so via the scan
  status in the report header — intentional per §6.
- Git: changes are uncommitted (2 modified + 16 new files), left to the operator.

**Phase 3 complete. Phase 4 not started.**
