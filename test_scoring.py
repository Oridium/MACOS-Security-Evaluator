import unittest

from secureops_audit.models import Finding
from secureops_audit.report import rating, score_findings


class ScoringTests(unittest.TestCase):
    def test_score_ignores_informational_findings(self):
        findings = [
            Finding("A", "A", "Test", "PASS", "high", 20, 20, "", ""),
            Finding("B", "B", "Test", "FAIL", "high", 10, 0, "", ""),
            Finding("C", "C", "Test", "INFO", "info", 0, 0, "", ""),
        ]
        self.assertEqual(score_findings(findings), (20, 30, 30))

    def test_unknown_reduces_coverage_not_score(self):
        findings = [
            Finding("A", "A", "Test", "PASS", "high", 20, 20, "", ""),
            Finding("B", "B", "Test", "UNKNOWN", "high", 10, 0, "", ""),
        ]
        self.assertEqual(score_findings(findings), (20, 20, 30))

    def test_rating(self):
        self.assertEqual(rating(90, 100), "Strong")
        self.assertEqual(rating(80, 100), "Good")
        self.assertEqual(rating(65, 100), "Needs Improvement")
        self.assertEqual(rating(40, 100), "High Risk")


if __name__ == "__main__":
    unittest.main()
