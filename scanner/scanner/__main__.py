"""CLI for the scanner authorization interface (no scanning in Phase 1).

Usage:
  python3 -m scanner check-id STATIC_TARGET
  python3 -m scanner check-url https://manikmagar.com.np
  python3 -m scanner self-test
"""

import sys

from .authorization import (
    UnauthorizedTargetError,
    load_allowlist,
    resolve_target_id,
    validate_target_url,
)


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("check-id", "check-url", "self-test"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd = argv[0]
    try:
        if cmd == "check-id":
            t = resolve_target_id(argv[1])
            print(f"AUTHORIZED {t.target_id} -> {t.url}")
            return 0
        if cmd == "check-url":
            t = validate_target_url(argv[1])
            print(f"AUTHORIZED {t.target_id} -> {t.url}")
            return 0
        if cmd == "self-test":
            for tid in load_allowlist():
                resolve_target_id(tid)
            print(f"OK allowlist={sorted(load_allowlist())}")
            return 0
    except UnauthorizedTargetError as e:
        print(f"REJECTED ({e.code}): {e}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
