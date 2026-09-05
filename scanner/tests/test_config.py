"""ScanConfig clamping — no configuration can exceed safe ceilings."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.config import LIMITS, ScanConfig, load_config  # noqa: E402


class ConfigTests(unittest.TestCase):
    def test_conservative_defaults(self):
        c = ScanConfig()
        self.assertLessEqual(c.max_requests, LIMITS["max_requests"])
        self.assertLessEqual(c.max_pages, LIMITS["max_pages"])
        self.assertGreaterEqual(c.min_request_interval, LIMITS["min_request_interval"])
        self.assertFalse(c.timing_probes)

    def test_values_clamped_to_ceilings(self):
        c = ScanConfig(max_requests=100000, max_pages=9999, concurrency=500, request_timeout=999)
        self.assertEqual(c.max_requests, LIMITS["max_requests"])
        self.assertEqual(c.max_pages, LIMITS["max_pages"])
        self.assertEqual(c.concurrency, LIMITS["concurrency"])
        self.assertEqual(c.request_timeout, LIMITS["request_timeout"])

    def test_negative_and_non_numeric_reset_to_defaults(self):
        c = ScanConfig(max_requests=-5, max_pages="lots", concurrency=None)
        self.assertEqual(c.max_requests, ScanConfig().max_requests)
        self.assertEqual(c.max_pages, ScanConfig().max_pages)
        self.assertEqual(c.concurrency, ScanConfig().concurrency)

    def test_unknown_check_names_rejected(self):
        with self.assertRaises(ValueError):
            ScanConfig(enabled_checks=["headers", "metasploit"])

    def test_load_from_json_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"max_pages": 3, "enabled_checks": ["headers"]}, fh)
            path = fh.name
        try:
            c = load_config(path)
            self.assertEqual(c.max_pages, 3)
            self.assertEqual(c.enabled_checks, ["headers"])
            self.assertEqual(c.max_depth, ScanConfig().max_depth)  # defaults preserved
        finally:
            os.unlink(path)

    def test_load_unknown_keys_ignored(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"max_pages": 2, "nukes": True}, fh)
            path = fh.name
        try:
            c = load_config(path)
            self.assertEqual(c.max_pages, 2)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
