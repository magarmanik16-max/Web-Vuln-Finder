# Limitations

Honest boundaries of this platform. Nothing here is a claim of complete
security assurance.

## Assessment coverage

- Automated scanning cannot find every vulnerability. Logic flaws, broken
  access control in application code, and business-logic issues generally
  require manual testing that this platform does not perform.
- Authentication-protected areas are not assessed: the scanner carries no
  credentials and no session state.
- Crawling is bounded (depth 3, 50 pages, ≤500 requests by default), so
  unlinked, deeply nested, or JavaScript-rendered endpoints may never be
  assessed.
- XSS results are reflection evidence in a context — not confirmed exploits.
  Breakout payloads are never sent, so exploitability must be verified manually.
- SQL injection results are heuristics (error signatures, boolean differentials)
  with deliberately low/medium confidence; false negatives and false positives
  are both possible. Timing-based checks are disabled by default.
- The platform detects a fixed set of issue classes (headers, TLS, cookies,
  CORS, methods, disclosure, reflected XSS, SQLi heuristics, CSRF form
  hygiene). It is not a general-purpose vulnerability framework.
- Responses are truncated (512 KB default) and executed JS is not analyzed —
  DOM-based issues are out of scope.

## Operational

- Single Node process: the JWT logout denylist is in-memory (restarts forget
  revocations) and the scan queue is per-process with orphan recovery marking
  interrupted scans failed rather than resuming them.
- The dashboard is a management UI, not a SIEM: no alerting, no trending.
- Reports are generated from stored findings only — they are accurate but no
  substitute for a human-written assessment narrative.

## Security posture

- The target allowlist is enforced in three independent places, but the
  platform is intended to run on a trusted network: the API is loopback-bound
  by default and any exposure (HOST env) should sit behind a reverse proxy,
  TLS, and network access control.
- The scanner is safe by construction (rate limits, budgets, non-destructive
  probes) but still sends requests to the target — run assessments with the
  owner's consent and at conservative settings.
