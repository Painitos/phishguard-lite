import unittest

from phishguard.analyzer import analyze_many, analyze_url


class AnalyzeUrlTests(unittest.TestCase):
    def test_low_risk_for_plain_https_domain(self):
        result = analyze_url("https://www.example.com/about")

        self.assertEqual(result.risk_level, "low")
        self.assertLess(result.score, 35)

    def test_high_risk_for_brand_in_subdomain_and_keywords(self):
        result = analyze_url("http://paypal-login.example.com/verify")

        self.assertEqual(result.risk_level, "high")
        self.assertGreaterEqual(result.score, 65)
        self.assertTrue(any("Brand word" in item.message for item in result.findings))

    def test_detects_ip_host(self):
        result = analyze_url("http://192.168.1.10/login")

        self.assertTrue(any("IP address" in item.message for item in result.findings))

    def test_detects_punycode(self):
        result = analyze_url("https://xn--paypa1-l2c.example/security-update")

        self.assertTrue(any("punycode" in item.message for item in result.findings))

    def test_normalizes_missing_scheme(self):
        result = analyze_url("example.com/login")

        self.assertEqual(result.normalized_url, "https://example.com/login")

    def test_batch_ignores_empty_lines_and_comments(self):
        results = analyze_many(["https://example.com", "", "# comment", "http://test.example"])

        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
