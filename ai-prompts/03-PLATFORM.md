# PHASE 3 — FULL PLATFORM INTEGRATION

Phase 1 established the application foundation.

Phase 2 established the Python vulnerability scanner.

Now integrate everything into one working platform.

Do NOT replace working components without a real reason.

---

# 1. FINAL ARCHITECTURE

Implement:

React
↓
Express
↓
Scan Manager
↓
Python Scanner
↓
Authorized Target
↓
Scanner JSON
↓
Express
↓
MongoDB
↓
React
↓
Report

---

# 2. NODE ↔ PYTHON

Implement a robust scanner orchestration service.

Node must:

1. validate target ID
2. create scan
3. launch Python scanner
4. track process
5. receive structured output
6. store findings
7. update scan status
8. handle failure
9. support cancellation

Never pass arbitrary shell commands.

Never construct unsafe shell strings from user input.

---

# 3. SCAN STATES

Support:

queued
running
completed
failed
cancelled

Store:

- start time
- end time
- duration
- target
- progress
- request count
- endpoint count
- finding count
- error

---

# 4. REAL-TIME PROGRESS

Implement a reasonable mechanism.

Possible:

- polling
- Server-Sent Events
- WebSocket

Choose the simplest reliable solution.

Do not over-engineer.

---

# 5. SCAN PAGE

Display:

Target
Status
Duration
Current module
Requests
Endpoints
Findings

Example:

Authorization       ✓
Connectivity        ✓
Crawler             ✓
Headers             ✓
TLS                 ✓
Cookies             ✓
CORS                ✓
XSS                 →
SQL Injection       →
CSRF                ○
Report              ○

---

# 6. CANCELLATION

Implement:

POST /api/scans/:id/cancel

The scanner process must terminate safely.

Partial findings should be preserved.

---

# 7. DASHBOARD

Create a professional security dashboard.

Show:

- total scans
- active scans
- completed scans
- total findings
- severity distribution
- recent scans
- recent findings

Keep the interface professional and understandable.

Avoid useless animations.

---

# 8. TARGET PAGE

Show exactly:

manikmagar.com.np
Static

mnk.manikmagar.com.np
Dynamic

No arbitrary target field.

---

# 9. FINDINGS

Implement:

GET /api/findings

Filtering:

- severity
- target
- category
- confidence
- scan

Finding detail should display:

- title
- severity
- confidence
- affected URL
- parameter
- description
- evidence
- impact
- remediation
- CWE
- OWASP

---

# 10. REPORTING

Generate professional reports.

Report must contain:

Executive Summary

Assessment Scope

Methodology

Risk Summary

Findings

Remediation

Limitations

Assessment timestamp

---

# 11. REPORT DATA INTEGRITY

Reports must use actual stored scan results.

Never fabricate findings.

Never generate fake evidence.

Never invent severity.

Never invent scan statistics.

---

# 12. PDF

Implement PDF export if practical.

Use a clean professional structure.

Do not spend excessive time on visual decoration.

Correct data is more important than design.

---

# 13. DATABASE

Ensure MongoDB correctly stores:

Users
Scans
Findings
Reports
AuditLogs

Use indexes where useful.

Do not over-index.

---

# 14. SECURITY

Verify:

authentication
authorization
IDOR protection
rate limiting
CORS
input validation
secure headers
safe subprocess execution
target authorization
SSRF protections

---

# 15. API TESTING

Test:

- login
- unauthorized API access
- scan creation
- unauthorized target
- scan retrieval
- scan cancellation
- findings
- reports

---

# 16. FRONTEND TESTING

Test:

- login
- dashboard
- target selection
- scan creation
- scan progress
- scan cancellation
- findings
- reports
- error handling

---

# 17. END-TO-END TEST

Run:

Target selection
↓
Start scan
↓
Node
↓
Python
↓
Target
↓
Findings
↓
MongoDB
↓
Report
↓
Dashboard

Do this for both authorized targets.

Then attempt an unauthorized target.

It MUST be rejected.

---

# 18. PERFORMANCE

Do not prematurely optimize.

Ensure:

- scanner doesn't block Express
- frontend remains responsive
- multiple requests cannot accidentally start uncontrolled scans
- rate limits work

---

# 19. TOKEN DISCIPLINE

Do not rewrite Phase 1 or Phase 2 unnecessarily.

Reuse existing code.

Inspect only relevant files.

Fix actual integration problems.

---

# 20. PHASE 3 DEFINITION OF DONE

[ ] Node launches Python
[ ] scanner results reach Node
[ ] findings reach MongoDB
[ ] scan status works
[ ] cancellation works
[ ] dashboard works
[ ] target page works
[ ] findings page works
[ ] report generation works
[ ] PDF works if implemented
[ ] authentication works
[ ] authorization works
[ ] audit logs work
[ ] API tests pass
[ ] frontend tests pass
[ ] end-to-end scan works
[ ] unauthorized target rejected

---

# 21. STOP CONDITION

When the complete platform works end-to-end:

STOP.

Do not start major new scanner features.

Do not add random functionality.

Do not redesign the architecture.

Wait for Phase 4.