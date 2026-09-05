# PHASE 1 — PROJECT FOUNDATION

You are working on a final-year cybersecurity project:

**Authorized Web Vulnerability Assessment & Reporting Platform**

Your task in this phase is to establish the project's complete foundation.

You are an autonomous coding agent.

You must inspect the environment, inspect the repository, make the architectural decisions, create the project structure, implement the foundational security boundaries, and verify that the foundation works.

Do NOT start implementing the full vulnerability scanner yet.

Do NOT build unnecessary features.

Do NOT move into Phase 2.

---

# 1. IMMUTABLE PROJECT SCOPE

The system is authorized to assess ONLY:

STATIC TARGET:

https://manikmagar.com.np

DYNAMIC TARGET:

https://mnk.manikmagar.com.np

These are the ONLY permitted targets.

This restriction is part of the architecture.

Never implement arbitrary URL scanning.

Never allow the user to enter an arbitrary target URL.

Never weaken this restriction for development convenience.

---

# 2. TECHNOLOGY

Frontend:

- React
- Vite
- Tailwind CSS

Backend:

- Node.js
- Express
- MongoDB
- Mongoose

Scanner:

- Python

Python will be implemented in Phase 2.

---

# 3. FIRST ACTION — ENVIRONMENT INSPECTION

Before installing anything, inspect:

- operating system
- Node version
- npm version
- Python version
- pip
- MongoDB
- Git
- project directory
- existing source files
- package.json
- environment files
- existing documentation
- existing tests
- available ports

Do NOT reinstall software that already works.

Do NOT destroy existing project files.

If a project already exists, understand it before modifying it.

---

# 4. ARCHITECTURE

Establish this architecture:

React
↓
Express API
↓
Scan Service
↓
Python Scanner
↓
Authorized Target

Results:

Python Scanner
↓
Express
↓
MongoDB
↓
React Dashboard

Python is the security scanning engine.

Node.js is the application/orchestration layer.

---

# 5. PROJECT STRUCTURE

Create a clean maintainable structure.

Suggested:

client/
server/
scanner/
docs/
tests/

Do not create hundreds of unnecessary files.

Keep modules logically separated.

---

# 6. TARGET AUTHORIZATION

Create a single authoritative target configuration.

Conceptually:

STATIC_TARGET
    https://manikmagar.com.np

DYNAMIC_TARGET
    https://mnk.manikmagar.com.np

The frontend should use target IDs.

Example:

STATIC_TARGET

DYNAMIC_TARGET

The browser must NOT control the actual destination URL.

The backend resolves target ID → authorized URL.

---

# 7. SERVER-SIDE VALIDATION

Implement strict target authorization in Express.

Reject:

- arbitrary domains
- arbitrary subdomains
- IP addresses
- localhost
- private addresses
- alternate ports
- alternate schemes
- malformed URLs
- unauthorized redirects

Do not rely on frontend validation.

---

# 8. PYTHON AUTHORIZATION PREPARATION

Create the Python scanner authorization interface now, but do not implement the scanner itself.

Python must eventually independently enforce the same target restrictions.

The architecture should make bypassing Node impossible.

---

# 9. SSRF DESIGN

Document and establish the security design for SSRF prevention.

The final scanner must reject:

- localhost
- loopback
- private IPv4
- private IPv6
- link-local
- multicast
- metadata endpoints
- arbitrary IP destinations
- unauthorized redirects

Do not solve SSRF using simple string matching.

---

# 10. DATABASE

Create the initial MongoDB models.

At minimum:

User
Scan
Finding
Report
AuditLog

A Target collection is optional because targets are immutable configuration.

---

# 11. USER AUTHENTICATION

Implement the foundation for:

- registration if appropriate
- login
- logout
- password hashing
- protected API routes
- role support

Never store plaintext passwords.

Never hard-code secrets.

Use environment variables.

---

# 12. BACKEND API

Create the basic API architecture.

Suggested endpoints:

POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me

GET  /api/targets

POST /api/scans
GET  /api/scans
GET  /api/scans/:id
POST /api/scans/:id/cancel

GET  /api/findings
GET  /api/findings/:id

GET  /api/reports

Do not implement scanner functionality yet.

---

# 13. FRONTEND FOUNDATION

Create the basic application shell.

Pages:

/login
/dashboard
/targets
/scans
/findings
/reports

The Targets page must show ONLY:

manikmagar.com.np
Static

mnk.manikmagar.com.np
Dynamic

No arbitrary URL input.

---

# 14. SECURITY MIDDLEWARE

Establish:

- secure headers
- CORS policy
- request validation
- authentication middleware
- authorization middleware
- rate limiting
- centralized error handling

Use sensible defaults.

Do not over-engineer.

---

# 15. AUDIT LOGGING

Create the audit-log infrastructure.

Record:

- authenticated user
- action
- target ID
- scan ID where applicable
- timestamp
- result

Do not log:

- passwords
- tokens
- secrets

---

# 16. CONFIGURATION

Create a safe environment configuration system.

Use .env for secrets.

Provide .env.example.

Never commit actual credentials.

---

# 17. TESTING

Create tests for the most important security boundary.

At minimum test:

AUTHORIZED:

https://manikmagar.com.np

https://mnk.manikmagar.com.np

REJECT:

https://example.com

https://google.com

http://localhost

http://127.0.0.1

http://192.168.1.1

arbitrary IP addresses

unauthorized subdomains

alternate ports

malformed URLs

redirect scenarios

The target allowlist is the most important test in this phase.

---

# 18. QUALITY RULE

Do not merely create files.

Run the application.

Run tests.

Fix actual errors.

Verify MongoDB connectivity.

Verify authentication.

Verify target authorization.

Verify frontend → backend communication.

---

# 19. TOKEN DISCIPLINE

You have a limited AI token budget.

Therefore:

- inspect efficiently
- don't repeatedly read unchanged files
- don't rewrite working code
- don't explain obvious decisions
- don't dump entire files unnecessarily
- don't regenerate architecture repeatedly
- don't create unnecessary abstractions

Spend tokens on implementation and verification.

---

# 20. PHASE 1 DEFINITION OF DONE

Do not declare this phase complete until:

[ ] environment inspected
[ ] architecture established
[ ] project structure created
[ ] frontend runs
[ ] backend runs
[ ] MongoDB connects
[ ] authentication foundation works
[ ] API structure exists
[ ] target IDs exist
[ ] arbitrary URL input does not exist
[ ] server-side target validation works
[ ] security middleware exists
[ ] audit infrastructure exists
[ ] security tests exist
[ ] tests pass
[ ] README has setup instructions
[ ] Phase 1 is documented

---

# 21. STOP CONDITION

When ALL Phase 1 requirements pass:

STOP.

Do NOT implement the Python vulnerability scanner.

Do NOT implement XSS detection.

Do NOT implement SQL injection detection.

Do NOT implement crawling.

Do NOT start Phase 3.

Do NOT start Phase 4.

At the end, provide only a concise completion summary containing:

- what was implemented
- tests performed
- tests passed/failed
- important decisions
- anything that must be fixed before Phase 2

Then WAIT.

The next phase will be explicitly authorized later.