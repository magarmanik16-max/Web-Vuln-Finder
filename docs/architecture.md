# Architecture

## Layers

```
┌──────────────────────────────────────────────────────────┐
│ React (client/, Vite, Tailwind)                          │
│  /login /dashboard /targets /scans /findings /reports    │
│  Sends ONLY target IDs. No URL input exists anywhere.    │
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
│ Authorized targets ONLY:                                 │
│   https://manikmagar.com.np        (STATIC_TARGET)       │
│   https://mnk.manikmagar.com.np    (DYNAMIC_TARGET)      │
└──────────────────────────────────────────────────────────┘

Results: Python Scanner → Express → MongoDB → React Dashboard
```

## Key decisions

**Targets are configuration, not data.** The allowlist lives in exactly two
code artifacts — `server/src/config/targets.js` and
`scanner/authorized_targets.json` (mirrored; a consistency test fails the build
if they drift). No user input, database record, or environment variable can add
a target. The API's only "write" surface for scans accepts a `targetId` from a
closed enum; URLs are rejected with `400` and audited as `denied`.

**Backend resolves ID → URL.** `resolveTarget(id)` is the single resolution
point. The frontend fetches `GET /api/targets` for display but selects by ID
only, so the browser never controls the destination.

**Python independence.** The scanner re-validates with its own implementation
and its own copy of the allowlist. Even if the Node layer were bypassed or
misconfigured, the scanner refuses any destination not on the list.

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
