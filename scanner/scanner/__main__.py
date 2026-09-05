"""CLI for the scanner safety policy (no scanning here).

Usage:
  python3 -m scanner check-url https://example.com     -> AUTHORIZED / REJECTED
"""

import sys

from .authorization import UnauthorizedTargetError, validate_target_url


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "check-url":
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        t = validate_target_url(argv[1])
        print(f"AUTHORIZED {t.target_url}")
        return 0
    except UnauthorizedTargetError as e:
        print(f"REJECTED ({e.code}): {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
