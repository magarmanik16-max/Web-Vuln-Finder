"""Check registry. Each check module exposes run(ctx) -> list[Finding]."""

from . import cookies, cors, csrf, disclosure, headers, methods, sqli, tls, xss

CHECKS = {
    "headers": headers,
    "tls": tls,
    "cookies": cookies,
    "cors": cors,
    "methods": methods,
    "disclosure": disclosure,
    "xss": xss,
    "sqli": sqli,
    "csrf": csrf,
}
