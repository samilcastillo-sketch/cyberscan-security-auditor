"""
Automated Test Suite for CyberScan Security Engine
"""
import unittest
from src.scanner import evaluate_headers

class TestSecurityScanner(unittest.TestCase):
    def test_all_headers_present_gives_a_plus(self):
        full_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()"
        }
        res = evaluate_headers(full_headers)
        self.assertEqual(res["grade"], "A+")
        self.assertEqual(res["headers_passed"], 6)

    def test_missing_headers_downgrades_grade(self):
        poor_headers = {
            "Content-Type": "text/html"
        }
        res = evaluate_headers(poor_headers)
        self.assertEqual(res["grade"], "F")
        self.assertEqual(res["headers_passed"], 0)

if __name__ == "__main__":
    unittest.main()
