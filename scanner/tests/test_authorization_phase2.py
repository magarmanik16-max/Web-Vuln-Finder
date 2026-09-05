"""Phase 2 authorization primitives: request-URL authorization and IP resolution."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.authorization import (  # noqa: E402
    UnauthorizedTargetError,
    authorize_request_url,
    load_allowlist,
    resolve_and_validate_ips,
)

AL = load_allowlist()


class RequestUrlAuthorizationTests(unittest.TestCase):
    def test_deep_paths_on_authorized_origin_are_allowed(self):
        target, parts = authorize_request_url("https://manikmagar.com.np/blog/post?id=5&x=1")
        self.assertEqual(target.target_id, "STATIC_TARGET")
        self.assertEqual(parts.path, "/blog/post")

    def test_fragment_is_stripped(self):
        _t, parts = authorize_request_url("https://manikmagar.com.np/page#section")
        self.assertEqual(parts.fragment, "")

    def test_every_non_authorized_destination_rejected(self):
        bad = [
            "https://example.com/x",
            "https://evil.manikmagar.com.np/x",
            "http://manikmagar.com.np/x",          # scheme downgrade
            "https://manikmagar.com.np:8443/x",    # port
            "https://user@manikmagar.com.np/x",    # userinfo
            "https://169.254.169.254/latest/meta-data",
            "https://192.168.1.1/x",
            "not a url",
            "",
            None,
        ]
        for url in bad:
            with self.assertRaises(UnauthorizedTargetError, msg=url):
                authorize_request_url(url, AL)

    def test_redirect_to_unauthorized_host_rejected(self):
        from scanner.authorization import assert_authorized_redirect

        target, _ = authorize_request_url("https://manikmagar.com.np/a", AL)
        with self.assertRaises(UnauthorizedTargetError):
            assert_authorized_redirect(target, "https://mnk.manikmagar.com.np/")


class IPResolutionTests(unittest.TestCase):
    def test_all_answers_validated(self):
        ips = resolve_and_validate_ips("manikmagar.com.np", resolver=lambda h: ["93.184.216.34"])
        self.assertEqual(ips, ["93.184.216.34"])

    def test_private_answer_rejected(self):
        with self.assertRaises(UnauthorizedTargetError) as cm:
            resolve_and_validate_ips("manikmagar.com.np", resolver=lambda h: ["10.0.0.9"])
        self.assertEqual(cm.exception.code, "non_public_ip")

    def test_metadata_answer_rejected(self):
        with self.assertRaises(UnauthorizedTargetError):
            resolve_and_validate_ips("manikmagar.com.np", resolver=lambda h: ["169.254.169.254"])

    def test_dns_failure(self):
        def boom(h):
            raise OSError("NXDOMAIN")

        with self.assertRaises(UnauthorizedTargetError) as cm:
            resolve_and_validate_ips("manikmagar.com.np", resolver=boom)
        self.assertEqual(cm.exception.code, "dns_failure")

    def test_empty_answers_rejected(self):
        with self.assertRaises(UnauthorizedTargetError):
            resolve_and_validate_ips("manikmagar.com.np", resolver=lambda h: [])


if __name__ == "__main__":
    unittest.main()
