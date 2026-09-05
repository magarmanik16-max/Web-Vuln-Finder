# API Reference

Base URL: `http://127.0.0.1:5000/api` (or `http://localhost:5173/api` through
the Vite dev proxy, which is what the dashboard uses). All responses are JSON.
Errors: `{ "error": "…" }` with a meaningful status code.

## Authentication

JWT Bearer tokens: `Authorization: Bearer <token>`. Tokens are HS256, 8 h
expiry, single-use logout via `jti` denylist.

| Method & path | Auth | Body | Notes |
|---|---|---|---|
| `POST /auth/register` | conditional | `{email, password (≥12), name?, role?}` | first user bootstraps as admin; afterwards admin-only |
| `POST /auth/login` | – | `{email, password}` | rate-limited 20 / 15 min; returns `{token, user}` |
| `POST /auth/logout` | ✓ | – | revokes the presented token |
| `GET /auth/me` | ✓ | – | current user (no password hash) |

## Targets

| Method & path | Auth | Notes |
|---|---|---|
| `GET /targets` | ✓ | exactly `STATIC_TARGET` (manikmagar.com.np, static) and `DYNAMIC_TARGET` (mnk.manikmagar.com.np, dynamic); read-only — no create/update/delete exists |

## Scans

| Method & path | Auth | Body / query | Notes |
|---|---|---|---|
| `POST /scans` | ✓ | `{targetId}` — **IDs only; URLs are rejected (400)** | spawns the Python scanner; bounded concurrency (default 2) with FIFO queue; 429 if ≥20 pending |
| `GET /scans` | ✓ | `?targetId=&status=&limit=` | history |
| `GET /scans/:id` | ✓ | – | detail incl. `progress` (currentModule, module checklist, requests, pages, endpoints), `durationMs`, timing |
| `POST /scans/:id/cancel` | ✓ | – | SIGTERM → graceful stop; partial findings preserved; 409 for terminal scans |

Scan states: `queued → running → completed | failed | cancelled`.

## Findings

| Method & path | Auth | Query | Notes |
|---|---|---|---|
| `GET /findings` | ✓ | `?scanId=&targetId=&severity=&category=&confidence=&status=&limit=` | filters combine |
| `GET /findings/:id` | ✓ | – | full contract: title, severity, confidence, url, method, parameter, description, evidence, impact, remediation, CWE, OWASP, module, detectedAt |

## Reports

| Method & path | Auth | Body / notes |
|---|---|---|
| `POST /reports` | ✓ | `{scanId}` → builds all sections from stored scan results; 409 unless scan is `completed`/`cancelled` |
| `GET /reports` | ✓ | list |
| `GET /reports/:id` | ✓ | full structured report |
| `GET /reports/:id/pdf` | ✓ | PDF download (`application/pdf`) |

## Health

| Method & path | Auth | Notes |
|---|---|---|
| `GET /health` | – | `{ok, service, mongo, time}` — no sensitive data |

## Error codes

`400` validation / unknown target · `401` unauthenticated or bad token · `403`
insufficient role · `404` unknown id · `409` conflicting state · `429` rate
limit / too many pending scans · `500` unexpected (details logged, never
returned). Invalid `:id` formats are rejected with `400` before any lookup.
