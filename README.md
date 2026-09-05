# WebVulnApp — Authorized Web Vulnerability Assessment & Reporting Platform

Final-year cybersecurity project. The platform assesses **exactly two targets**
(the project owner's own assets) and nothing else:

| ID | Host | Type |
|---|---|---|
| `STATIC_TARGET` | manikmagar.com.np | Static |
| `DYNAMIC_TARGET` | mnk.manikmagar.com.np | Dynamic |

The allowlist is **architectural**: the browser can never submit a URL — only a
target ID — and both the Node layer and the Python scanner independently
re-enforce the same restriction. See [docs/security.md](docs/security.md).

## Architecture

```
React (client, :5173)
  ↓  HTTP + JWT (Vite dev proxy /api → :5000)
Express API (server, :5000)
  ↓  Scan Service (Phase 2)
Python Scanner (scanner/)      ← independently re-validates authorization
  ↓
Authorized Targets (allowlist)

Results:  Python Scanner → Express → MongoDB → React Dashboard
```

## Project layout

```
client/    React + Vite + Tailwind dashboard (no target-URL input exists)
server/    Express API, Scan Manager (Python orchestration), Mongoose models, tests/
scanner/   Python vulnerability scanner (auth engine, crawler, 9 checks, JSON reports)
docs/      ARCHITECTURE.md · SECURITY-DESIGN.md · PHASE1.md · PHASE2.md · PHASE3.md
tests/     tests/smoke.mjs + tests/e2e-phase3.mjs — E2E against the running stack
```

## Setup

Requirements: Node ≥ 20, npm, Python 3.12+, MongoDB (local).

### 1. MongoDB

No sudo required — run MongoDB in userspace from the official binary tarball:

```bash
mkdir -p ~/.local/opt ~/webvulnapp/.data/db
curl -L -o ~/.local/opt/mongodb.tgz \
  https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2404-8.0.29.tgz
tar -xzf ~/.local/opt/mongodb.tgz -C ~/.local/opt \
  && mv ~/.local/opt/mongodb-linux-x86_64-ubuntu2404-* ~/.local/opt/mongodb
~/.local/opt/mongodb/bin/mongod \
  --dbpath ~/webvulnapp/.data/db --bind_ip 127.0.0.1 --port 27017 \
  --logpath ~/webvulnapp/.data/mongod.log --fork
```

(Any MongoDB reachable via `MONGODB_URI` works equally — a system service is
fine if you have root.)

### 2. Server

```bash
cd server
cp .env.example .env          # then set JWT_SECRET (see below) and admin creds
npm install
npm run seed                  # creates the bootstrap admin from .env
npm run dev                   # API on http://localhost:5000
```

Generate a strong JWT secret:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

### 3. Client

```bash
cd client
npm install
npm run dev                   # dashboard on http://localhost:5173
```

The dev server proxies `/api/*` to the Express backend. Log in with the
credentials you put in `server/.env` (`ADMIN_EMAIL` / `ADMIN_PASSWORD`).

### 4. Tests

```bash
npm run test:server           # 112 server tests (needs mongod running)
npm run test:scanner          # 120 offline Python tests (no network)
npm run test:client           # 7 frontend component tests (vitest)
npm run smoke                 # E2E smoke against the running stack
node tests/e2e-phase3.mjs     # full E2E: both targets, live scans, reports, PDF
```

## API surface (Phase 3)

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /api/health` | – | Liveness + MongoDB status |
| `POST /api/auth/register` | conditional | First user bootstraps as admin; afterwards admin-only |
| `POST /api/auth/login` | – | JWT access token |
| `POST /api/auth/logout` | ✓ | Revokes the presented token |
| `GET /api/auth/me` | ✓ | Current user |
| `GET /api/targets` | ✓ | The immutable allowlist (read-only, no mutations exist) |
| `POST /api/scans` | ✓ | Body: `{ "targetId": "STATIC_TARGET" \| "DYNAMIC_TARGET" }` — **URLs are rejected**; spawns the Python scanner (bounded concurrency + FIFO queue) |
| `GET /api/scans` · `GET /api/scans/:id` | ✓ | History / detail incl. live progress (module checklist, requests, pages, endpoints) |
| `POST /api/scans/:id/cancel` | ✓ | SIGTERM → graceful stop, partial findings preserved |
| `GET /api/findings` · `GET /api/findings/:id` | ✓ | Filters: severity, target, category, confidence, scan |
| `POST /api/reports` | ✓ | `{ "scanId": "…" }` — builds the report strictly from stored scan results |
| `GET /api/reports` · `GET /api/reports/:id` | ✓ | List / full structured report |
| `GET /api/reports/:id/pdf` | ✓ | PDF download (pdfkit) |

## Security summary

- Bcrypt(12) password hashing; plaintext never stored or logged.
- JWT Bearer auth with per-token `jti` + in-memory logout denylist.
- Roles: `admin`, `analyst`. Registration self-locks after the first user.
- Helmet secure headers, strict CORS allowlist, JSON body limit, rate limiting
  (global 300/15 min, auth 20/15 min), centralized error handling without stack leaks.
- Target authorization: exact allowlist match + full SSRF guard (see
  [docs/security.md](docs/security.md)) — mirrored in Python.
- Audit logging (`AuditLog` collection) with automatic secret redaction.

Full Phase 1 status: [docs/PHASE1.md](docs/PHASE1.md).

## Documentation

- [docs/architecture.md](docs/architecture.md) — system architecture & data model
- [docs/security.md](docs/security.md) — security model: target allowlist, SSRF prevention, audit design
- [docs/scanner-methodology.md](docs/scanner-methodology.md) — what the scanner checks and how it stays safe
- [docs/api.md](docs/api.md) — full API reference
- [docs/testing.md](docs/testing.md) — test suites and how to run them
- [docs/limitations.md](docs/limitations.md) — honest limitations
- [docs/PRESENTATION.md](docs/PRESENTATION.md) — academic/presentation material
- [docs/PHASE1.md](docs/PHASE1.md) · [docs/PHASE2.md](docs/PHASE2.md) · [docs/PHASE3.md](docs/PHASE3.md) — phase reports
