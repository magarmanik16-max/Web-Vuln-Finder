# Testing Guide

How the project is tested, what each suite covers, and how to run everything.

## Suites

| Suite | Location | Count | Runs against |
|---|---|---|---|
| Server (Jest + supertest) | `server/tests/` | 130 | real Express app + local MongoDB; scanner replaced by an offline stub via the production spawn path |
| Scanner (unittest) | `scanner/tests/` | 128 | pure logic; DNS resolver injected — **never** hits live websites |
| Frontend (vitest + testing-library) | `client/src/test/` | 7 | jsdom; API mocked |
| Smoke (API-level, live stack) | `tests/smoke.mjs` | 9 | running stack via the Vite proxy |
| E2E (full pipeline, live stack) | `tests/e2e-phase3.mjs` | 6 | running stack + **real scanner + real targets** |

## Commands

```bash
cd server     && npx jest --runInBand      # 130 tests
cd scanner    && python3 -m unittest discover -s tests   # 128 tests
cd client     && npm test                  # 7 tests
node tests/smoke.mjs                        # needs mongod + API + client up
node tests/e2e-phase3.mjs                   # full E2E; authorized targets only
```

## Coverage highlights

- **Authorization boundary** (the critical suite): exact-host allowlist, scheme/
  port/userinfo/path rules, IP literals in every notation, localhost, cloud
  metadata, IPv4-mapped IPv6, DNS rebinding answers, unauthorized redirects —
  tested independently in Node (`urlguard.test.js`) and Python
  (`test_authorization*.py`, `test_bypass_attempts.py`).
- **API security**: authentication, roles, target-ID enforcement, audit trail,
  CORS headers, JWT expiry/forgery, rate limiting, ID format validation.
- **Integration**: Node→Python spawn with a stub scanner sharing the real CLI
  contract; findings reach MongoDB; status transitions; cancellation preserves
  partial findings; failure and garbage-output handling; report generation and
  PDF bytes; concurrency queue; orphan recovery.
- **Frontend**: Targets page has exactly two targets and **no input elements**;
  login flow and error display; findings detail contract; dashboard stats.

## Conventions

- Tests never hit live websites: unit/integration tests use injected resolvers,
  canned connections, and a stub scanner process.
- Live assessments run only against the two authorized targets and only through
  the conservative defaults.
- A bug fix must come with a regression test in the suite that caught it (or a
  new one) — this was enforced throughout the project.
