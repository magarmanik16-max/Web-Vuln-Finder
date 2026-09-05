"""Evidence redaction (SCANNER.md §20) — secrets must never reach a report."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.models.evidence import (  # noqa: E402
    cookie_evidence,
    redact_string,
    response_evidence,
    sanitize,
)


class RedactionTests(unittest.TestCase):
    def test_secret_shaped_keys_are_redacted(self):
        out = sanitize({"password": "hunter2", "api_key": "xyz", "auth": "Bearer x", "note": "fine"})
        self.assertEqual(out["password"], "[redacted]")
        self.assertEqual(out["api_key"], "[redacted]")
        self.assertEqual(out["auth"], "[redacted]")
        self.assertEqual(out["note"], "fine")

    def test_nested_structures(self):
        out = sanitize({"headers": {"set-cookie": "a=b", "server": "nginx"}, "deep": [{"session": "abc"}]})
        self.assertEqual(out["headers"]["set-cookie"], "[redacted]")
        self.assertEqual(out["headers"]["server"], "nginx")
        self.assertEqual(out["deep"][0]["session"], "[redacted]")

    def test_token_blobs_scrubbed_from_strings(self):
        text = "user token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c end"
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redact_string(text))
        self.assertIn("[redacted]", redact_string(text))

    def test_long_strings_truncated(self):
        self.assertLessEqual(len(redact_string("A" * 10000)), 400)

    def test_response_evidence_redacts_secret_headers(self):
        ev = response_evidence("u", "GET", 200, {"set-cookie": "sess=SECRETVAL", "server": "nginx/1.2"}, "body", "reason")
        self.assertEqual(ev["headers"]["set-cookie"], "[redacted]")
        self.assertEqual(ev["headers"]["server"], "nginx/1.2")
        self.assertEqual(ev["detection_reason"], "reason")

    def test_cookie_evidence_never_carries_value(self):
        ev = cookie_evidence("sessionid", {"secure": False, "httponly": False}, "https://x/", "reason")
        self.assertEqual(ev["cookie_value"], "[redacted]")
        self.assertNotIn("SECRET", str(ev))
        self.assertEqual(ev["cookie_name"], "sessionid")
        self.assertEqual(ev["flags"]["secure"], False)


if __name__ == "__main__":
    unittest.main()
