"""Security tests for the Python authorization interface (mirror of the Node
suite — no network: the DNS resolver is injected)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.authorization import (  # noqa: E402
    Target,
    UnauthorizedTargetError,
    assert_authorized_redirect,
    load_allowlist,
    resolve_target_id,
    validate_target_url,
)

STATIC = "https://manikmagar.com.np"
DYNAMIC = "https://mnk.manikmagar.com.np"


def resolver(answers):
    return lambda host: list(answers)


class AllowlistTests(unittest.TestCase):
    def test_load_allowlist_contains_exactly_two_targets(self):
        al = load_allowlist()
        self.assertEqual(sorted(al), ["DYNAMIC_TARGET", "STATIC_TARGET"])
        self.assertEqual(al["STATIC_TARGET"].host, "manikmagar.com.np")
        self.assertEqual(al["DYNAMIC_TARGET"].host, "mnk.manikmagar.com.np")

    def test_resolve_valid_ids(self):
        self.assertEqual(resolve_target_id("STATIC_TARGET").host, "manikmagar.com.np")
        self.assertEqual(resolve_target_id("DYNAMIC_TARGET").host, "mnk.manikmagar.com.np")

    def test_resolve_rejects_unknown_ids_and_non_strings(self):
        for bad in ("EVIL_TARGET", "https://example.com", "", None, 42):
            with self.assertRaises(UnauthorizedTargetError):
                resolve_target_id(bad)


class UrlValidationTests(unittest.TestCase):
    def test_authorized_urls_pass_without_dns(self):
        al = load_allowlist()
        self.assertEqual(validate_target_url(STATIC, al, resolver=resolver(["1.2.3.4"])).target_id, "STATIC_TARGET")

    def test_authorized_urls_pass_with_public_dns_answers(self):
        al = load_allowlist()
        t = validate_target_url(STATIC, al, resolver=resolver(["104.21.0.5", "172.67.0.5"]))
        self.assertEqual(t.target_id, "STATIC_TARGET")

    def test_malformed_rejected(self):
        al = load_allowlist()
        for bad in ("", "   ", "not a url", "https://", None, 123):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url(bad, al, resolver=resolver([]))

    def test_scheme_port_userinfo_path_rejected(self):
        al = load_allowlist()
        for bad in (
            "http://manikmagar.com.np",
            "ftp://manikmagar.com.np",
            "https://manikmagar.com.np:8443",
            "https://user@manikmagar.com.np",
            "https://user:pass@manikmagar.com.np",
            "https://manikmagar.com.np/admin",
            "https://manikmagar.com.np?x=1",
            "https://manikmagar.com.np#f",
        ):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url(bad, al, resolver=resolver([]))

    def test_arbitrary_domains_and_subdomains_rejected(self):
        al = load_allowlist()
        for bad in (
            "https://example.com",
            "https://google.com",
            "https://evil.manikmagar.com.np",
            "https://manikmagar.com.np.evil.com",
            "https://evilmanikmagar.com.np",
            "https://www.manikmagar.com.np",
            "https://manikmagar.com.np.",
        ):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url(bad, al, resolver=[])

    def test_ips_and_localhost_rejected(self):
        al = load_allowlist()
        for bad in (
            "http://localhost",
            "http://127.0.0.1",
            "https://192.168.1.1",
            "https://10.0.0.1",
            "https://172.16.0.9",
            "https://169.254.169.254",
            "https://[::1]",
            "https://[fe80::1]",
            "https://93.184.216.34",
        ):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url(bad, al, resolver=[])

    def test_non_public_dns_answers_rejected(self):
        al = load_allowlist()
        for answers in (
            ["127.0.0.1"],
            ["10.0.0.5"],
            ["192.168.1.1"],
            ["169.254.169.254"],
            ["::1"],
            ["fe80::1"],
            ["fd00::1"],
            ["::ffff:10.0.0.1"],
            ["1.2.3.4", "10.9.9.9"],  # one bad record poisons the set
            ["224.0.0.1"],
            ["0.0.0.0"],
        ):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url(STATIC, al, resolver=resolver(answers))

    def test_dns_failure_rejected(self):
        def boom(host):
            raise OSError("NXDOMAIN")

        with self.assertRaises(UnauthorizedTargetError):
            validate_target_url(STATIC, load_allowlist(), resolver=boom)

    def test_unauthorized_host_never_triggers_dns(self):
        al = load_allowlist()
        called = []

        def spy(host):
            called.append(host)
            return []

        with self.assertRaises(UnauthorizedTargetError):
            validate_target_url("https://example.com", al, resolver=spy)
        self.assertEqual(called, [])

    def test_redirect_policy(self):
        t = resolve_target_id("STATIC_TARGET")
        self.assertEqual(assert_authorized_redirect(t, "https://manikmagar.com.np").target_id, "STATIC_TARGET")
        for bad in ("http://manikmagar.com.np", "https://mnk.manikmagar.com.np", "https://evil.com", "https://192.168.1.1"):
            with self.assertRaises(UnauthorizedTargetError):
                assert_authorized_redirect(t, bad)


class CrossLayerConsistencyTests(unittest.TestCase):
    """scanner/authorized_targets.json must mirror the Node allowlist."""

    def test_hosts_match_node_registry(self):
        node = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server", "src", "config", "targets.js")
        with open(node, encoding="utf-8") as fh:
            src = fh.read()
        for t in load_allowlist().values():
            self.assertIn(f"host: '{t.host}'", src, f"{t.host} missing from Node registry")
            self.assertIn(f"authorizedUrl: '{t.url}'", src)


if __name__ == "__main__":
    unittest.main()
