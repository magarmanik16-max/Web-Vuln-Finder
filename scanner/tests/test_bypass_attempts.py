"""Phase 4/5 adversarial bypass attempts against the Python safety policy.

Every case here tries to make the engine reach something other than the
public HTTPS origin the user submitted — encoded addresses, parser
differentials, ports, userinfo tricks, redirect escapes, rebinding answers.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.authorization import (
    UnauthorizedTargetError,
    assert_authorized_redirect,
    authorize_request_url,
    authorize_target_url,
    validate_target_url,
)

ORIGIN = "example.com"
PUBLIC = "93.184.216.34"


def res(answers):
    return lambda host: list(answers)


class StructuralBypassAttempts(unittest.TestCase):
    def test_every_private_or_special_ip_literal_rejected(self):
        for url in (
            "https://127.0.0.1",
            "https://10.0.0.1",
            "https://172.16.0.1",
            "https://192.168.1.1",
            "https://169.254.169.254",
            "https://[::1]",
            "https://[fe80::1]",
            "https://[fc00::1]",
            "https://[ff02::1]",
            "https://[::]",
            "https://[::ffff:127.0.0.1]",
            "https://[::ffff:10.0.0.1]",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_target_url(url)

    def test_encoded_and_unusual_hosts_rejected(self):
        for url in (
            "https://2130706433",  # decimal 127.0.0.1 (WHATWG would map; urllib sees a name — either way not global-checked as name... must not silently pass)
            "https://0x7f.0x0.0x0.0x1",
            "https://0177.0.0.1",
            "https://manikmagar.com.np%2f@evil.com",
            "https://manikmagar.com.np@evil.com",
            "https://evil.com\\@manikmagar.com.np",
            "https://example.com.",
            "https://ex%20ample.com",
            "https://ＭＡＮＩＫＭＡＧＡＲ.com.np",
            "https://xn--80ak6aa92e.com",
        ):
            # Either structurally rejected, or accepted as an opaque public
            # NAME whose DNS answers must then all be global — never resolved
            # to a private range without rejection.
            try:
                t = authorize_target_url(url)
                # if accepted structurally, the DNS stage must still guard it
                with self.assertRaises(UnauthorizedTargetError):
                    validate_target_url(url, resolver=res(["10.0.0.5"]))
            except UnauthorizedTargetError:
                pass

    def test_numeric_host_forms_resolve_through_dns_gate(self):
        # 2130706433 / 0x7f000001 resolve to 127.0.0.1 in real DNS terms;
        # our injected resolver answers 127.0.0.1 -> must be rejected.
        for url in ("https://2130706433", "https://0x7f.0.0.1"):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url(url, resolver=res(["127.0.0.1"]))

    def test_parser_differential_hosts_fail_dns_gate_when_private(self):
        for url in (
            "https://example.com\t.evil.com",
            "https://example.com\n.evil.com",
        ):
            try:
                validate_target_url(url, resolver=res(["10.0.0.5"]))
                self.fail("mangled host with private answer passed")
            except UnauthorizedTargetError:
                pass


class RequestScopeBypassAttempts(unittest.TestCase):
    def test_redirect_chain_cannot_escape(self):
        for loc in (
            "https://evil.example/",
            "http://example.com/",
            "http://127.0.0.1",
            "https://example.com:8443",
            "https://169.254.169.254/latest/meta-data/",
            "https://user@example.com/",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=loc):
                assert_authorized_redirect(ORIGIN, loc)

    def test_deep_request_cannot_escape(self):
        for url in (
            "https://another-site.com/x",
            "https://example.com:8080/x",
            "https://user@example.com/x",
            "https://192.168.1.1/x",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_request_url(url, ORIGIN)


class DnsRebindingAttempts(unittest.TestCase):
    def test_public_name_resolving_private_rejected_every_time(self):
        for _ in range(3):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url("https://example.com", resolver=res(["10.0.0.5"]))

    def test_tocotou_rebinding_second_answer_rejected(self):
        # first request public (passes); second request private (must fail) —
        # the engine resolves per request, so every request is guarded.
        answers = iter([["93.184.216.34"], ["10.0.0.5"]])
        resolver = lambda h: next(answers)  # noqa: E731
        t = validate_target_url("https://example.com", resolver=resolver)
        self.assertEqual(t.host, "example.com")
        with self.assertRaises(UnauthorizedTargetError):
            validate_target_url("https://example.com", resolver=resolver)


if __name__ == "__main__":
    unittest.main()
