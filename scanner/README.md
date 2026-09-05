# Scanner (Python) — Phase 1 status

This package contains ONLY the authorization interface. The vulnerability
scanning engine is implemented in Phase 2 and is out of scope until then.

Everything runs on the Python standard library — no third-party packages and
therefore no pip installation is required for Phase 1.

## Layout

- `authorized_targets.json` — the immutable allowlist (mirrors `server/src/config/targets.js`; enforced independently so bypassing Node does not unlock arbitrary targets)
- `scanner/authorization.py` — allowlist loading, ID→target resolution, URL validation, IP classification, redirect policy
- `scanner/__main__.py` — CLI: `check-id`, `check-url`, `self-test`
- `tests/test_authorization.py` — offline security tests (DNS resolver injected)

## Usage

```bash
cd scanner
python3 -m unittest discover -s tests -v      # run the security tests
python3 -m scanner check-id STATIC_TARGET     # AUTHORIZED
python3 -m scanner check-id EVIL_TARGET       # REJECTED (exit 1)
python3 -m scanner check-url https://example.com   # REJECTED (exit 1)
```

## Phase 2 contract (binding for the scanner engine)

Before ANY network-bound operation, the engine must call
`authorization.validate_target_url()` (or operate on a `Target` obtained via
`resolve_target_id()`), follow redirects only through
`assert_authorized_redirect()`, and never open sockets to raw IPs or
user-supplied hosts. Results are reported back to Express (Phase 2 defines the
transport), which persists them to MongoDB.
