# Architecture

## Layers

```
┌──────────────────────────────────────────────────────────┐
│ React (client/, Vite, Tailwind)                          │
│  /login /dashboard /targets /scans /findings /reports    │
│  Sends a user-supplied public HTTPS target URL.          │
└────────────────────────┬─────────────────────────────────┘
                         │ JSON over HTTP, Bearer JWT
┌────────────────────────▼─────────────────────────────────┐
│ Express API (server/)  — application/orchestration layer │
│  authn/authz · validation · rate limiting · audit log    │
│  security headers · CORS · centralized errors            │
└────────────────────────┬─────────────────────────────────┘
                         │ Scan Service (Phase 2 spawns/queues)
┌────────────────────────▼─────────────────────────────────┐
│ Python Scanner (scanner/) — security scanning engine     │
│  Independently re-enforces the target allowlist          │
│  (authorized_targets.json + scanner/authorization.py).   │
└────────────────────────┬─────────────────────────────────┘
                         │ HTTPS, redirect-validated
┌────────────────────────▼─────────────────────────────────┐
│ User-supplied PUBLIC HTTPS origins ONLY:                 │
│   private/loopback/link-local/reserved ranges rejected   │
│   at every layer (Node guard + Python engine)            │
└──────────────────────────────────────────────────────────┘

Results: Python Scanner → Express → MongoDB → React Dashboard
```

## Key decisions

**The target boundary is the safety policy, not a name list.** A scan accepts
a user-supplied URL; `server/src/config/targets.js` (policy + legacy mapping)
and `server/src/security/urlGuard.js` normalize and validate it structurally
(HTTPS only, no ports/credentials, IP literals must be globally routable) and
then validate DNS (every answer must be a global unicast address). The
normalized origin is stored on the scan (`targetUrl`/`targetHost`); legacy
scans keep their `targetId` and remain displayable.

**Python independence.** `scanner/scanner/authorization.py` re-implements the
entire policy and re-validates the target URL (structure + DNS) before a
single request is made, scopes every request/redirect to the scanned origin,
and pins connections to validated IPs. Even a buggy Node layer cannot point
Python at an unsafe destination.

**Data model** (Mongoose):

- `User` — email, passwordHash (bcrypt), role (`admin`/`analyst`), active.
- `Scan` — targetId (enum), requestedBy, status (`queued/running/completed/failed/cancelled`), severity summary, timestamps.
- `Finding` — scan ref, targetId, severity, category, title, description, location, evidence, status.
- `Report` — scan ref, format, status, fileKey (generation = later phase).
- `AuditLog` — actor, action, targetId, scanId, result (`success/failure/denied`), ip, userAgent, sanitized details.
- `Target` is deliberately NOT a collection: targets are immutable configuration.

**Authentication.** JWT access tokens (8 h, random `jti`), Bearer header.
Logout revokes the token's `jti` via an in-memory denylist (single-process
Phase 1; persist it in Phase 4 if scaling out). Passwords: bcrypt cost 12.
Registration: the first account bootstraps as admin; afterwards only admins
create accounts (via `POST /api/auth/register`).

**Dev topology.** Vite (:5173) proxies `/api` to Express (:5000); Express talks
to MongoDB (:27017, localhost only). CORS allows only the configured client
origin. `trust proxy` is enabled so rate limiting keys on the real client IP.
