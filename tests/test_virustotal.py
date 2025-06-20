import unittest
from unittest.mock import patch, Mock
from cti.virustotal import VirusTotalIntegration

class TestVirusTotalIntegration(unittest.TestCase):
    def setUp(self):
        self.config = {"api_key": "YOUR_VIRUSTOTAL_API_KEY"}
        self.vt = VirusTotalIntegration(self.config)

    @patch("cti.virustotal.requests.get")
    def test_ip_malicious(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 0}, "reputation": -10, "country": "RU", "tags": ["botnet"]}}
        })
        result = self.vt.query("ip", "110.34.2.94")
        self.assertIsNotNone(result)
        if result:
            self.assertTrue(result["threat"])
            self.assertEqual(result["field_type"], "ip")

    @patch("cti.virustotal.requests.get")
    def test_domain_harmless(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}, "categories": {"category": "benign"}, "reputation": 0, "tags": []}}
        })
        result = self.vt.query("domain", "http://malicious.com")
        self.assertIsNone(result)

    @patch("cti.virustotal.requests.get")
    def test_file_hash_suspicious(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 1}, "type_description": "exe", "names": ["evil.exe"], "reputation": -5}}
        })
        result = self.vt.query("file_hash", "f5c11f20320dfc1be95d715260880695bc3e0fc76cc19664b3d6129c57fc80f7/675e3958df98892876065991")
        self.assertIsNotNone(result)
        if result:
            self.assertTrue(result["threat"])
            self.assertEqual(result["field_type"], "file_hash")

    @patch("cti.virustotal.requests.get")
    def test_url_malicious(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=lambda: {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}, "categories": {"phishing": True}, "reputation": -20, "tags": ["phishing"]}}
        })
        result = self.vt.query("url", "http://malicious.com")
        self.assertIsNotNone(result)
        if result:
            self.assertTrue(result["threat"])
            self.assertEqual(result["field_type"], "url")

if __name__ == "__main__":
    unittest.main() 