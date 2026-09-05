# Phase 1 Report — Project Foundation

Status: **COMPLETE** (all Definition-of-Done items satisfied — see checklist at
the end). Phase 2 (Python scanner engine) has NOT been started.

## Environment (as inspected)

- Ubuntu 24.04, Node v22.23.2, npm 10.9.8, Python 3.12.3.
- MongoDB, pip, and git were NOT installed. No sudo access available.
  - **MongoDB**: solved by running the official 8.0.29 community binary
    (tarball) in userspace — `~/.local/opt/mongodb/bin/mongod`, dbpath
    `.data/db`, bound to 127.0.0.1:27017. Start command documented in README.
  - **pip**: not needed in Phase 1 (scanner is stdlib-only); install before Phase 2 (`apt install python3-pip` with sudo, or `python3 -m ensurepip --user`).
  - **git**: not installed and not required for Phase 1; install before committing.

## What was implemented

- **Structure**: `client/ server/ scanner/ docs/ tests/` (file inventory in README).
- **Target authorization**: `server/src/config/targets.js` (single authoritative
  allowlist, frozen), mirrored by `scanner/authorized_targets.json` with a
  cross-layer consistency test. Frontend sends target IDs only; the Targets page
  is a read-only view with **no input controls**.
- **SSRF-safe URL guard** (`server/src/security/urlGuard.js`): WHATWG parsing,
  https-only, exact-host allowlist, no port/userinfo/origin-beyond, DNS-stage
  with injectable resolver, global-unicast-only IP classification via
  `ipaddr.js`, same-origin-only redirect policy. Mirrored in Python stdlib.
- **Models**: User, Scan, Finding, Report, AuditLog (no Target collection —
  targets are immutable config, documented).
- **Auth**: bcrypt(12) hashing, JWT access tokens with `jti`, logout denylist,
  roles (`admin`/`analyst`), first-user-bootstrap registration then admin-only.
- **API**: auth (login/logout/me/register), targets, scans (create/list/detail/
  cancel), findings (list/detail + filters), reports (list), health.
- **Middleware**: helmet, CORS allowlist, JSON limit, global + auth rate
  limiting, JWT authN, role authZ, centralized error handler, 404.
- **Audit logging**: `logAudit()` with secret redaction; failed logins,
  registrations, scan creations, cancellations, and **rejected target attempts
  (result: denied)** are recorded.
- **Frontend**: React 18 + Vite 5 + Tailwind 4; 6 pages; auth context; API
  client with 401 handling; dev proxy `/api → :5000`. Production build passes.
- **Python scanner authorization interface**: allowlist loader, ID resolver,
  URL validator, redirect policy, CLI (`python3 -m scanner check-id|check-url|self-test`).
  No scanning logic — per Phase 1 scope.

## Verification results

| Check | Result |
|---|---|
| `server` Jest suite (urlguard + api security) | **97/97 pass** |
| `scanner` unittest suite (offline, injected DNS) | **14/14 pass** |
| E2E smoke through the Vite proxy (`tests/smoke.mjs`) | **9/9 pass** |
| MongoDB connectivity (userspace mongod 8.0.29) | connected (`/api/health` reports `connected`) |
| Authentication (seeded admin login → JWT → /me → logout revokes) | verified live |
| Target authorization live: `STATIC_TARGET`/`DYNAMIC_TARGET` → 201; `https://example.com`, `http://127.0.0.1`, `EVIL_TARGET` → 400 + audit `denied`; unauthenticated → 401 | verified live |
| Frontend | serves on :5173, proxy reaches API; `vite build` clean. **Browser-UI walk-through not performed** — no browser backend available in this session; HTTP-level behavior verified via smoke tests instead. |

### Notable decisions

- Mongo via userspace binary tarball (no sudo available); db files under
  `.data/` (gitignored).
- JWT Bearer (not cookies) for Phase 1; `localStorage` tradeoff documented in
  SECURITY-DESIGN.md §4.
- Registration kept but self-locking (first user = admin bootstrap), so the
  platform cannot be joined by strangers after setup.
- Scan cancel returns 409 for terminal states; rejected targetIds are audited
  as `denied` with the attempted value truncated to 120 chars.

### Bugs found and fixed during verification

1. `config/env.js` validated `JWT_SECRET` but never exported it → login 500. (Fixed; caught by API tests.)
2. Register route never parsed the Bearer token → admin gate dead. (Added `softAuth`; caught by API tests.)
3. `.env` path resolved one directory too high. (Fixed; caught at seed time.)
4. Test-expectation fixes for URL-parser normalizations (uppercase host, explicit `:443` = same origin) — guard unchanged, semantics documented.

## Definition of done

- [x] environment inspected
- [x] architecture established
- [x] project structure created
- [x] frontend runs (:5173)
- [x] backend runs (:5000)
- [x] MongoDB connects
- [x] authentication foundation works
- [x] API structure exists
- [x] target IDs exist
- [x] arbitrary URL input does not exist (frontend has no input; API rejects URLs)
- [x] server-side target validation works (97 tests + live checks)
- [x] security middleware exists
- [x] audit infrastructure exists
- [x] security tests exist
- [x] tests pass
- [x] README has setup instructions
- [x] Phase 1 is documented (this file)

## Prerequisites / recommendations before Phase 2

1. Install `pip` (and `git` if committing) — both absent on this machine.
2. Decide the Node↔Python transport (Phase 2's SCANNER.md defines it): child
   process spawn vs HTTP job service; the scan service in Express must call
   `urlGuard.validateTargetUrl()` before spawning anything.
3. Phase 2 scanner code MUST import `scanner.authorization` for every outbound
   request and use manual redirect handling (see SECURITY-DESIGN.md §4).
4. Consider making the userspace mongod a systemd user unit or adding the start
   command to a Makefile for convenience.
