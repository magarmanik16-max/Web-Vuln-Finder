"""Target safety policy tests (general-purpose model).

Any PUBLIC https:// origin is authorized; private/loopback/link-local/
reserved/unsafe destinations and unsafe URL forms are rejected. The DNS
stage is tested with an INJECTED resolver (no network).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.authorization import (  # noqa: E402
    Target,
    UnauthorizedTargetError,
    assert_authorized_redirect,
    authorize_request_url,
    authorize_target_url,
    validate_target_url,
)

PUBLIC = "93.184.216.34"


def res(answers):
    return lambda host: list(answers)


class StructuralPolicyTests(unittest.TestCase):
    def test_public_https_origins_are_authorized_and_normalized(self):
        for url in (
            "https://example.com",
            "https://example.org",
            "https://public-test-domain.example",
            "https://manikmagar.com.np",  # the original two domains remain valid
            "https://mnk.manikmagar.com.np",
            "https://Example.COM/",  # case-normalized
        ):
            t = authorize_target_url(url)
            self.assertIsInstance(t, Target)
            self.assertTrue(t.target_url.startswith("https://"))
            self.assertEqual(t.target_url, f"https://{t.host}/")

    def test_submitted_paths_are_normalized_to_the_origin(self):
        t = authorize_target_url("https://example.com/some/page?x=1")
        self.assertEqual(t.target_url, "https://example.com/")

    def test_non_https_schemes_rejected(self):
        for url in (
            "http://example.com",
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,x",
            "ws://example.com",
            "wss://example.com",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_target_url(url)

    def test_userinfo_and_ports_rejected(self):
        for url in (
            "https://user@example.com",
            "https://user:password@example.com",
            "https://example.com:8443",
            "https://example.com:80",
            "https://example.com:443",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_target_url(url)

    def test_malformed_and_unexpected_forms_rejected(self):
        for url in ("", "   ", "not a url", "https://", None, 42, "https://example.com.", "https://ex%20ample.com"):
            with self.assertRaises(UnauthorizedTargetError, msg=str(url)):
                authorize_target_url(url)

    def test_ip_literals_must_be_global(self):
        # public literals allowed
        for url in ("https://93.184.216.34", "https://[2606:4700::1111]"):
            t = authorize_target_url(url)
            self.assertTrue(t.target_url.startswith("https://"))
        # non-global literals rejected — every special-use range
        for url in (
            "https://127.0.0.1",
            "https://10.0.0.1",
            "https://172.16.0.1",
            "https://192.168.1.1",
            "https://169.254.169.254",  # cloud metadata
            "https://0.0.0.0",
            "https://100.64.0.1",  # CGNAT
            "https://198.18.0.1",  # benchmarking
            "https://224.0.0.1",  # multicast
            "https://[::1]",
            "https://[fe80::1]",  # IPv6 link-local
            "https://[fc00::1]",  # IPv6 unique-local
            "https://[ff02::1]",  # IPv6 multicast
            "https://[::]",  # unspecified
            "https://[::ffff:127.0.0.1]",  # IPv4-mapped loopback
            "https://[::ffff:10.0.0.1]",  # IPv4-mapped private
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_target_url(url)

    def test_localhost_hostname_rejected_at_dns_stage(self):
        # 'localhost' is a regular hostname structurally; the DNS/global-IP
        # stage is what rejects it (in production it resolves to loopback).
        with self.assertRaises(UnauthorizedTargetError):
            validate_target_url("https://localhost", resolver=res(["127.0.0.1"]))


class DnsStageTests(unittest.TestCase):
    def test_public_answers_pass(self):
        t = validate_target_url("https://example.com", resolver=res([PUBLIC, "2606:4700::1111"]))
        self.assertEqual(t.host, "example.com")

    def test_private_answer_rejected(self):
        for answers in (["10.0.0.5"], ["192.168.1.1"], ["127.0.0.1"], ["169.254.169.254"], ["::1"], ["fe80::1"], ["fc00::1"], ["::ffff:10.0.0.1"]):
            with self.assertRaises(UnauthorizedTargetError, msg=str(answers)):
                validate_target_url("https://example.com", resolver=res(answers))

    def test_mixed_answers_rejected_if_any_unsafe(self):
        with self.assertRaises(UnauthorizedTargetError):
            validate_target_url("https://example.com", resolver=res([PUBLIC, "10.9.9.9"]))

    def test_dns_failure_rejected(self):
        def boom(host):
            raise OSError("NXDOMAIN")

        with self.assertRaises(UnauthorizedTargetError) as cm:
            validate_target_url("https://example.com", resolver=boom)
        self.assertEqual(cm.exception.code, "dns_failure")
        with self.assertRaises(UnauthorizedTargetError):
            validate_target_url("https://example.com", resolver=res([]))

    def test_unsafe_structural_form_never_triggers_dns(self):
        called = []

        def spy(host):
            called.append(host)
            return []

        with self.assertRaises(UnauthorizedTargetError):
            validate_target_url("http://example.com", resolver=spy)
        self.assertEqual(called, [])


class RequestAndRedirectScopeTests(unittest.TestCase):
    ORIGIN = "example.com"

    def test_same_origin_deep_paths_allowed(self):
        self.assertEqual(
            authorize_request_url("https://example.com/blog/post?id=5", self.ORIGIN),
            "https://example.com/blog/post?id=5",
        )

    def test_off_origin_requests_rejected(self):
        for url in (
            "https://another-site.com/",
            "https://evil.example/",
            "https://sub.example.com/",
            "http://example.com/x",
            "https://example.com:8443/x",
            "https://user@example.com/x",
            "https://127.0.0.1/x",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_request_url(url, self.ORIGIN)

    def test_redirect_hops_must_stay_on_origin(self):
        self.assertEqual(assert_authorized_redirect(self.ORIGIN, "https://example.com/other"), "https://example.com/other")
        for loc in (
            "https://another-site.com/",
            "http://example.com/",
            "http://127.0.0.1",
            "https://example.com:8443",
            "https://169.254.169.254/latest/meta-data/",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=loc):
                assert_authorized_redirect(self.ORIGIN, loc)


if __name__ == "__main__":
    unittest.main()
