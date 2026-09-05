"""Authorized Web Vulnerability Assessment platform — Python scanner package.

Phase 1: authorization interface only. The actual scanning engine is
implemented in Phase 2 and MUST use scanner.authorization for every
network-bound operation; no request may leave this process without passing
validate_target_url() first.
"""

__version__ = "0.1.0"
