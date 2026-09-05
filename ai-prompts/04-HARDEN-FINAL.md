# PHASE 4 — HARDENING, AUDIT, TESTING & FINAL DELIVERY

The complete platform has now been implemented.

Your job is NOT to add random features.

Your job is to find what is wrong, fix it, verify it, and prepare the project for final-year evaluation.

Be skeptical.

Assume the existing implementation contains bugs.

Do not declare success merely because the application starts.

---

# 1. DO NOT EXPAND SCOPE

Do not turn this into:

- Burp Suite
- OWASP ZAP
- commercial SaaS
- enterprise SIEM
- massive vulnerability framework

The project is already feature-complete.

Focus on:

SECURITY
CORRECTNESS
RELIABILITY
TESTING
DOCUMENTATION
PRESENTATION

---

# 2. APPLICATION SECURITY AUDIT

Review the entire project.

Check for:

- SSRF
- command injection
- path traversal
- IDOR
- authentication flaws
- authorization flaws
- insecure JWT/session handling
- unsafe CORS
- missing rate limits
- injection
- unsafe subprocess execution
- secrets in source code
- unsafe environment handling
- sensitive data leakage
- insecure error messages
- improper validation
- race conditions
- scan process abuse

Fix every genuine issue you find.

---

# 3. TARGET RESTRICTION AUDIT

This is critical.

Try to bypass the scanner target restriction using:

- unauthorized domains
- unauthorized subdomains
- IP addresses
- localhost
- private IPs
- encoded addresses
- unusual URL syntax
- alternate ports
- redirects
- DNS tricks
- userinfo syntax
- HTTP instead of HTTPS

The system must remain restricted to:

https://manikmagar.com.np

https://mnk.manikmagar.com.np

Verify BOTH Node and Python independently enforce this.

---

# 4. SCANNER SAFETY AUDIT

Verify the scanner cannot:

- DoS the target
- brute force
- delete resources
- dump databases
- extract credentials
- spam endpoints
- create uncontrolled concurrency
- run arbitrary shell commands

Verify:

- request limits
- concurrency limits
- crawl depth
- response size
- timeout
- cancellation

---

# 5. FINDING QUALITY AUDIT

Inspect scanner results.

Look for:

- false positives
- duplicate findings
- incorrect severity
- incorrect confidence
- weak evidence
- misleading descriptions

Do not optimize for "more vulnerabilities."

Optimize for:

accurate findings.

---

# 6. LIVE ASSESSMENT

Run conservative final assessments against ONLY:

https://manikmagar.com.np

https://mnk.manikmagar.com.np

Record actual:

- scan duration
- endpoints
- findings
- severity
- errors
- limitations

Do not fabricate results.

---

# 7. COMPLETE TEST SUITE

Run:

Frontend tests
Backend tests
Python tests
Integration tests
Authorization tests
Security tests

Fix failures.

Run them again.

Do not stop at "mostly passing."

---

# 8. BUILD TEST

Verify production builds.

Frontend:

npm run build

Backend:

production startup

Python:

clean environment execution where practical

Verify there are no missing dependencies.

---

# 9. CLEANUP

Remove:

- unused files
- dead code
- debugging output
- accidental credentials
- temporary test data
- unnecessary dependencies
- meaningless comments

Do not remove useful documentation.

---

# 10. ERROR HANDLING

Test:

- MongoDB unavailable
- Python unavailable
- target unreachable
- timeout
- scan cancellation
- malformed scanner output
- scanner crash
- expired authentication
- invalid scan ID

The application should fail gracefully.

---

# 11. DOCUMENTATION

Finish:

README.md

docs/architecture.md
docs/security.md
docs/scanner-methodology.md
docs/testing.md
docs/api.md
docs/limitations.md

Documentation must describe what the application ACTUALLY does.

Do not document features that don't exist.

---

# 12. ACADEMIC MATERIAL

Prepare concise material for final-year presentation.

Include:

Problem Statement

Objectives

Scope

System Architecture

Technology Selection

Scanner Architecture

Database Design

Security Model

Threat Model

Vulnerability Detection Methodology

Testing Methodology

Results

Limitations

Future Work

Conclusion

---

# 13. SECURITY MODEL

Clearly document:

Why arbitrary URLs are forbidden.

Why the target allowlist exists.

How Node validates targets.

How Python independently validates targets.

How redirects are controlled.

How SSRF is prevented.

Why destructive testing is avoided.

---

# 14. LIMITATIONS

Be honest.

Examples:

- automated scanning cannot find every vulnerability
- authentication testing is limited
- business logic vulnerabilities may require manual testing
- false positives are possible
- some vulnerabilities require human verification
- scanner coverage is intentionally limited

Do not claim the application provides complete security assurance.

---

# 15. FINAL USER EXPERIENCE

A final demonstration should be:

Login
↓
Dashboard
↓
Select authorized target
↓
Start assessment
↓
Watch progress
↓
View findings
↓
View evidence
↓
View remediation
↓
Generate report

The workflow should be obvious.

---

# 16. FINAL SECURITY DEMONSTRATION

Demonstrate:

Authorized target:

✓ scan allowed

Unauthorized target:

✗ scan rejected

This is an important part of the project's security story.

---

# 17. FINAL CODE REVIEW

Review:

- naming
- structure
- error handling
- duplicated logic
- security boundaries
- comments
- environment configuration
- dependency usage

Make only changes that improve the actual project.

---

# 18. FINAL DEFINITION OF DONE

The project is complete only when:

[ ] application starts cleanly
[ ] frontend builds
[ ] backend starts
[ ] MongoDB works
[ ] authentication works
[ ] target restriction works
[ ] SSRF protection works
[ ] Python scanner works
[ ] crawler works
[ ] vulnerability checks work
[ ] findings are accurate
[ ] evidence is safe
[ ] reports work
[ ] scan cancellation works
[ ] audit logging works
[ ] tests pass
[ ] security audit completed
[ ] documentation completed
[ ] no secrets committed
[ ] no unauthorized scanning capability exists
[ ] end-to-end demonstration succeeds

---

# 19. FINAL REPORT TO ME

At the end, provide a concise final engineering report containing:

1. Project status
2. Architecture
3. Implemented scanner modules
4. Security controls
5. Tests executed
6. Test results
7. Actual findings from authorized targets
8. Known limitations
9. Remaining issues, if any
10. Exact commands required to run the project

Do not fabricate anything.

If something is broken, say it is broken.

If something was not tested, say it was not tested.

If a vulnerability is only potential, say potential.

---

# 20. FINAL RULE

Do not stop merely because the checklist looks complete.

Actually run the relevant tests.

Actually inspect the implementation.

Actually verify the security boundary.

Fix what you find.

Then stop.

This is the final phase.