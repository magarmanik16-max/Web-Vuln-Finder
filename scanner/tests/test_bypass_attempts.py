"""Phase 4 adversarial bypass attempts against the Python authorization layer.

Every case here is an attempt to make the scanner reach anything other than
https://manikmagar.com.np or https://mnk.manikmagar.com.np — encoded addresses,
parser differentials, ports, userinfo tricks, redirects. All must be rejected.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.authorization import (  # noqa: E402
    UnauthorizedTargetError,
    assert_authorized_redirect,
    authorize_request_url,
    load_allowlist,
    resolve_target_id,
    validate_target_url,
)

AL = load_allowlist()
STATIC = "https://manikmagar.com.np"


def res(answers):
    return lambda host: list(answers)


class BypassAttempts(unittest.TestCase):
    def assert_rejected(self, url, resolver=None):
        with self.assertRaises(UnauthorizedTargetError, msg=url):
            validate_target_url(url, AL, resolver=resolver)

    def test_alternate_ports_rejected(self):
        # regression: the port check was missing from the origin validator
        for url in (
            "https://manikmagar.com.np:8443",
            "https://manikmagar.com.np:80",
            "https://manikmagar.com.np:443",
            "https://manikmagar.com.np:0",
            "https://manikmagar.com.np:99999999",
        ):
            self.assert_rejected(url, res([]))

    def test_encoded_and_unusual_addresses_rejected(self):
        for url in (
            "https://2130706433",            # decimal IPv4 (127.0.0.1)
            "https://0x7f.0x0.0x0.0x1",      # hex octets
            "https://0177.0.0.1",            # octal
            "https://[::ffff:7f00:1]",       # hex-mapped loopback
            "https://manikmagar.com.np%2f@evil.com",  # encoded-at userinfo trick
            "https://manikmagar.com.np@evil.com",     # userinfo left-hand host
            "https://evil.com\\@manikmagar.com.np",   # backslash authority trick
            "https://manikmagar.com.np\\t.evil.com",
            "https://ＭＡＮＩＫＭＡＧＡＲ.com.np",    # fullwidth lookalike
        ):
            self.assert_rejected(url, res([]))

    def test_parser_differential_hosts_never_match(self):
        # Python's urlparse does NOT strip tabs/newlines (unlike WHATWG) — the
        # mangled hostname must fail the exact match, never be "cleaned up".
        for url in (
            "https://manikmagar.com.np\t.evil.com",
            "https://manikmagar.com.np\n.evil.com",
            "https://manikmagar.com.np\r.evil.com",
        ):
            self.assert_rejected(url, res([]))

    def test_punycode_idn_must_match_exactly(self):
        # homoglyph IDN encodes to a different punycode label -> not authorized
        self.assert_rejected("https://xn--mnikmagar-n1a.com.np", res([]))

    def test_authorized_url_with_public_dns_still_passes(self):
        t = validate_target_url(STATIC, AL, resolver=res(["93.184.216.34"]))
        self.assertEqual(t.target_id, "STATIC_TARGET")

    def test_redirect_chain_cannot_escape_via_port_or_scheme(self):
        t = resolve_target_id("STATIC_TARGET", AL)
        for loc in (
            "https://manikmagar.com.np:8443/",
            "http://manikmagar.com.np/",
            "https://mnk.manikmagar.com.np:443/",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=loc):
                assert_authorized_redirect(t, loc)

    def test_request_urls_cannot_carry_ports_or_credentials(self):
        for url in (
            "https://manikmagar.com.np:8443/blog",
            "https://user@manikmagar.com.np/blog",
            "https://manikmagar.com.np:443/a",
        ):
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_request_url(url, AL)

    def test_dns_rebinding_answer_rejected_every_time(self):
        # the engine resolves per request; a public name resolving private must
        # fail resolution on EVERY request, not just the first
        for _ in range(3):
            with self.assertRaises(UnauthorizedTargetError):
                validate_target_url(STATIC, AL, resolver=res(["10.0.0.5"]))


if __name__ == "__main__":
    unittest.main()
