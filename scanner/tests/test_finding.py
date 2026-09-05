"""Finding model, severity/confidence independence, deduplication."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scanner.models.finding import Confidence, Severity, make_finding  # noqa: E402
from scanner.models.scanresult import ScanResult  # noqa: E402


def f(**kw):
    base = dict(
        target_id="STATIC_TARGET",
        target_url="https://manikmagar.com.np",
        url="https://manikmagar.com.np/page",
        method="GET",
        title="Test finding",
        category="test",
        severity="medium",
        confidence="low",
        description="d",
        evidence={},
        impact="i",
        remediation="r",
        module="tests",
    )
    base.update(kw)
    return make_finding(**base)


class SeverityTests(unittest.TestCase):
    def test_all_five_levels_exist(self):
        self.assertEqual([s.value for s in Severity], ["informational", "low", "medium", "high", "critical"])

    def test_parse_and_fallback(self):
        self.assertEqual(Severity.parse("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.parse("bogus"), Severity.INFORMATIONAL)

    def test_confidence_independent_of_severity(self):
        a = f(severity="critical", confidence="low")
        b = f(severity="informational", confidence="high")
        self.assertEqual(a.severity, Severity.CRITICAL)
        self.assertEqual(a.confidence, Confidence.LOW)
        self.assertEqual(b.severity, Severity.INFORMATIONAL)
        self.assertEqual(b.confidence, Confidence.HIGH)

    def test_finding_has_all_contract_fields(self):
        finding = f()
        d = finding.to_dict()
        for field in ("id", "target_id", "target_url", "url", "method", "parameter", "title", "category",
                      "severity", "confidence", "cwe", "owasp", "description", "evidence", "impact",
                      "remediation", "scanner_module", "timestamp"):
            self.assertIn(field, d)
        self.assertTrue(finding.id)
        self.assertIn("T", finding.timestamp)


class DedupTests(unittest.TestCase):
    def test_identical_root_cause_deduplicates(self):
        r = ScanResult(scan_id="1", target_id="STATIC_TARGET", target_url="https://manikmagar.com.np")
        self.assertTrue(r.add_finding(f(url="https://manikmagar.com.np/p?q=1")))
        self.assertFalse(r.add_finding(f(url="https://manikmagar.com.np/p?q=2")))  # same path+param+cause
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.duplicates_suppressed, 1)

    def test_different_parameters_or_paths_are_kept(self):
        r = ScanResult(scan_id="1", target_id="STATIC_TARGET", target_url="https://manikmagar.com.np")
        r.add_finding(f(parameter="q"))
        r.add_finding(f(parameter="page"))
        r.add_finding(f(url="https://manikmagar.com.np/other"))
        self.assertEqual(len(r.findings), 3)

    def test_fingerprint_is_stable(self):
        self.assertEqual(f().fingerprint(), f().fingerprint())
        self.assertNotEqual(f(title="A").fingerprint(), f(title="B").fingerprint())

    def test_severity_counts_and_to_dict_shape(self):
        r = ScanResult(scan_id="s", target_id="STATIC_TARGET", target_url="https://manikmagar.com.np")
        r.add_finding(f(severity="high", title="H"))
        r.add_finding(f(severity="low", title="L1"))
        r.add_finding(f(severity="low", title="L2"))
        r.add_error("check.x", "boom")
        d = r.to_dict()
        self.assertEqual(d["statistics"]["findings_by_severity"]["high"], 1)
        self.assertEqual(d["statistics"]["findings_by_severity"]["low"], 2)
        self.assertEqual(d["status"], "running")
        self.assertEqual(d["errors"], [{"source": "check.x", "message": "boom"}])
        self.assertEqual(d["scan_id"], "s")
        self.assertEqual(d["target"]["url"], "https://manikmagar.com.np")


if __name__ == "__main__":
    unittest.main()
