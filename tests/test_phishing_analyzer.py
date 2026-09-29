import unittest
from pathlib import Path

from phishing_email_analyzer import analyze_email


class TestPhishingAnalyzer(unittest.TestCase):
    def test_analyze_suspicious_email(self):
        sample_path = Path(__file__).resolve().parent.parent / "sample_email.eml"
        result = analyze_email(sample_path)

        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertTrue(result["is_suspicious"])
        self.assertIn("sender", result)
        self.assertIn("urls", result)
        self.assertIn("headers", result)


if __name__ == "__main__":
    unittest.main()
