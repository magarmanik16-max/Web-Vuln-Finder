# PHASE 2 — PYTHON VULNERABILITY SCANNER

Phase 1 has already established the application foundation.

Now implement the **Python vulnerability assessment engine**.

Do NOT redesign the entire MERN application.

Do NOT replace working Phase 1 architecture.

Do NOT start building advanced frontend features.

Focus almost entirely on the Python scanner.

---

# 1. AUTHORIZED TARGETS

The scanner may ONLY assess:

https://manikmagar.com.np

https://mnk.manikmagar.com.np

No exceptions.

The Python scanner must independently enforce this restriction.

Never trust Node.js to enforce it.

---

# 2. SCANNER ARCHITECTURE

Create a modular Python scanner.

Suggested:

scanner/
├── main.py
├── config.py
├── authorization.py
├── crawler/
├── checks/
│   ├── headers.py
│   ├── tls.py
│   ├── cookies.py
│   ├── cors.py
│   ├── methods.py
│   ├── disclosure.py
│   ├── xss.py
│   ├── sqli.py
│   └── csrf.py
├── evidence/
├── models/
├── reporting/
└── tests/

Improve this structure if necessary.

Do not create unnecessary complexity.

---

# 3. SCANNER PRINCIPLES

The scanner is:

DETECTION
+
EVIDENCE
+
RISK
+
REMEDIATION

It is NOT:

DESTRUCTIVE EXPLOITATION.

Never:

- dump databases
- extract credentials
- brute force
- delete resources
- modify accounts
- upload malware
- perform DoS
- flood endpoints
- exfiltrate data

---

# 4. HTTP ENGINE

Implement a reliable HTTP client.

Requirements:

- timeout
- redirect control
- response size limit
- rate limiting
- controlled concurrency
- useful user-agent
- error handling

Every redirect destination must pass authorization.

---

# 5. SSRF PROTECTION

Implement robust authorization.

Validate:

1. URL syntax
2. scheme
3. hostname
4. port
5. DNS resolution
6. resulting IP
7. redirect destination

Reject:

- localhost
- loopback
- private networks
- link-local
- multicast
- metadata endpoints
- arbitrary IPs
- unauthorized hosts

---

# 6. CRAWLER

Implement a same-origin crawler.

Discover:

- links
- forms
- query parameters
- basic API-like endpoints

Limits:

- maximum depth
- maximum pages
- maximum requests
- response size
- timeout
- concurrency

Normalize URLs.

Deduplicate URLs.

Never leave the authorized host.

---

# 7. SECURITY HEADER CHECK

Implement detection for:

- CSP
- HSTS
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

Classify findings sensibly.

Missing HSTS on HTTP-only sites should not automatically become Critical.

---

# 8. TLS CHECK

Assess:

- HTTPS
- HTTP → HTTPS behavior
- certificate validity
- expiration
- basic observable TLS information

Avoid destructive TLS attacks.

---

# 9. COOKIE CHECK

Analyze:

- Secure
- HttpOnly
- SameSite
- Domain
- Path

Redact sensitive cookie values.

Never store session tokens as evidence.

---

# 10. CORS CHECK

Detect:

- wildcard origin
- reflected Origin
- credentials + permissive origins

Require meaningful evidence before reporting a vulnerability.

---

# 11. HTTP METHODS

Safely detect potentially dangerous methods.

Examples:

TRACE
PUT
DELETE

Do not modify or delete resources.

---

# 12. INFORMATION DISCLOSURE

Detect obvious:

- server version disclosure
- framework disclosure
- debug information
- directory listing
- public metadata
- accidental configuration exposure

Do not retrieve secrets.

---

# 13. REFLECTED XSS

Implement safe detection.

Use unique harmless markers.

Determine whether input appears in:

- HTML
- attributes
- JavaScript
- URL contexts

Do not create persistent payloads.

Do not claim confirmed XSS from weak evidence.

---

# 14. SQL INJECTION

Implement controlled detection.

Use minimal probes.

Analyze:

- response differences
- status changes
- database error indicators
- safe timing anomalies

Do NOT:

- enumerate tables
- dump databases
- extract credentials
- retrieve records

Report potential injection with confidence.

---

# 15. CSRF

Identify:

- forms
- state-changing actions
- anti-CSRF tokens
- SameSite protection

Do not automatically perform destructive actions.

---

# 16. FINDING MODEL

Every finding:

- id
- target
- URL
- method
- parameter
- title
- category
- severity
- confidence
- CWE
- OWASP
- description
- evidence
- impact
- remediation
- scanner module
- timestamp

---

# 17. SEVERITY

Use:

Informational
Low
Medium
High
Critical

Severity must be evidence-based.

Do not inflate results.

---

# 18. CONFIDENCE

Use:

Low
Medium
High

Severity and confidence are independent.

---

# 19. DEDUPLICATION

Implement finding fingerprints.

Do not generate hundreds of identical findings for the same root cause.

---

# 20. SAFE EVIDENCE

Store only necessary evidence.

Include:

- URL
- method
- parameter
- relevant status
- relevant headers
- short response excerpt
- detection reason

Redact:

- passwords
- tokens
- session cookies
- secrets

---

# 21. JSON OUTPUT

Python must produce structured JSON.

Do not make Node parse terminal text.

Example:

{
  "scan_id": "...",
  "target": "...",
  "status": "completed",
  "statistics": {},
  "findings": [],
  "errors": []
}

---

# 22. SCANNER TESTING

Create extensive unit tests.

Especially test:

- target authorization
- redirect authorization
- URL normalization
- crawler boundaries
- header detection
- cookie detection
- CORS detection
- XSS detection
- SQLi detection
- finding deduplication
- severity
- evidence redaction

Use mocks/fixtures whenever possible.

Do NOT repeatedly hit live websites during unit tests.

---

# 23. LIVE TEST

After unit tests pass, perform a controlled assessment against ONLY:

https://manikmagar.com.np

and

https://mnk.manikmagar.com.np

Use conservative scanner settings.

Do not perform destructive testing.

---

# 24. INTEGRATION CONTRACT

Ensure the Python scanner can later be called by Node.

It must support:

- target
- scan ID
- configuration
- cancellation
- structured output
- exit codes

Do not tightly couple Python to React.

---

# 25. TOKEN DISCIPLINE

Do not waste tokens rewriting Phase 1.

Inspect only files necessary to integrate.

Do not redesign working components.

Focus on scanner implementation.

---

# 26. PHASE 2 DEFINITION OF DONE

[ ] Python scanner exists
[ ] authorization works
[ ] SSRF protections exist
[ ] crawler works
[ ] headers check works
[ ] TLS check works
[ ] cookie check works
[ ] CORS check works
[ ] methods check works
[ ] disclosure check works
[ ] XSS check works
[ ] SQLi check works
[ ] CSRF check works
[ ] finding model works
[ ] evidence redaction works
[ ] deduplication works
[ ] JSON output works
[ ] unit tests pass
[ ] controlled live scan works
[ ] unauthorized targets are rejected

---

# 27. STOP CONDITION

When Phase 2 is complete:

STOP.

Do NOT redesign the dashboard.

Do NOT add unrelated vulnerabilities.

Do NOT start major reporting UI.

Do NOT start Phase 4.

Provide a concise completion summary and WAIT for explicit authorization to begin Phase 3.