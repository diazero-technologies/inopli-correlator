import unittest
from unittest.mock import patch, Mock
from cti.hybrid_analysis import HybridAnalysisIntegration

class TestHybridAnalysisIntegration(unittest.TestCase):
    def setUp(self):
        self.config = {"api_key": "YOUR_HYBRID_ANALYSIS_API_KEY"}
        self.ha = HybridAnalysisIntegration(self.config)

    @patch("cti.hybrid_analysis.requests.get")
    def test_file_hash_malicious(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: [
            {
                "verdict": "malicious",
                "threat_level_human": "High",
                "environment_description": "Windows 10 64 bit",
                "state": "SUCCESS",
                "id": "123456",
                "sha256": "abcdef123456"
            }
        ])
        result = self.ha.query("file_hash", "abcdef123456")
        self.assertIsNotNone(result)
        if result:
            self.assertTrue(result["threat"])
            self.assertEqual(result["field_type"], "file_hash")
            self.assertEqual(result["verdict"], "malicious")

    @patch("cti.hybrid_analysis.requests.get")
    def test_file_hash_benign(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: [])
        result = self.ha.query("file_hash", "benignhash")
        self.assertIsNone(result)

    @patch("cti.hybrid_analysis.requests.get")
    def test_url_malicious(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: [
            {
                "verdict": "malicious",
                "threat_level_human": "High",
                "environment_description": "Windows 10 64 bit",
                "state": "SUCCESS",
                "id": "654321",
                "sha256": "fedcba654321"
            }
        ])
        result = self.ha.query("url", "http://malicious.com")
        self.assertIsNotNone(result)
        if result:
            self.assertTrue(result["threat"])
            self.assertEqual(result["field_type"], "url")
            self.assertEqual(result["verdict"], "malicious")

    @patch("cti.hybrid_analysis.requests.get")
    def test_url_benign(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: [])
        result = self.ha.query("url", "http://benign.com")
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main() 