import unittest
from unittest.mock import patch, Mock, mock_open
from cti.virustotal import VirusTotalIntegration
from integrations.integration_manager import IntegrationManager
from config.debug import DEBUG_MODE

# Replace with your VirusTotal API key for local testing
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

class DummyRule:
    def __init__(self, integration_manager):
        self.integration_manager = integration_manager
        self.source_name = "test_source"
        self.ID = 1000
        self.allowed_event_types = [1000]
        self.hostname = "testhost"
        self.resolve_tenant = lambda payload, source, rule_id: ("tenant1", "dummy_token")

    def send_alert(self, alert):
        print(f"[ALERT] Would send alert: {alert}")

    def test_workflow(self, payload):
        alert_mode = self.integration_manager.alert_mode
        tenant_id, token = self.resolve_tenant(payload, self.source_name, self.ID)
        if alert_mode == "all":
            self.send_alert(payload)
        if self.integration_manager.has_active_integrations():
            alerts_to_send = self.integration_manager.process_alert(payload)
            enriched_alerts = [a for a in alerts_to_send if "cti" in a]
            for alert in alerts_to_send:
                tenant_id, token = self.resolve_tenant(alert, self.source_name, self.ID)
                self.send_alert(alert)
            # Assert only one enriched alert and cti is a list
            if enriched_alerts:
                assert len(enriched_alerts) == 1
                cti = enriched_alerts[0]["cti"]
                assert isinstance(cti, list)
                assert all(isinstance(e, dict) and "integration" in e and "field_type" in e for e in cti)

class TestVirusTotalWorkflowHash(unittest.TestCase):
    @patch("utils.webhook_sender.send_to_inopli")
    @patch("integrations.integration_manager.os.path.exists", return_value=True)
    @patch("integrations.integration_manager.yaml.safe_load")
    @patch("integrations.integration_manager.open", new_callable=mock_open, create=True)
    def test_full_file_hash_workflow(self, mock_file, mock_yaml, mock_exists, mock_send):
        TEST_HASH = "a322b230a3451fd11dcfe72af4da1df07183d6aaf1ab9e062f0e6b14cf6d23cd"  # Example malicious hash
        config = {
            "virustotal": {
                "enabled": True,
                "api_key": API_KEY,
                "fields": ["file_hash"]
            }
        }
        mock_yaml.return_value = {"integrations": config}
        manager = IntegrationManager()
        rule = DummyRule(manager)
        payload = {
            "detection_rule_id": 1000,
            "source": "test_source",
            "rule": "DummyRule",
            "event_type": "test_event",
            "severity": "high",
            "timestamp": "2024-01-01T00:00:00Z",
            "file_hash": TEST_HASH,
            "raw_event": "test raw event",
            "message": "Test file hash alert"
        }
        rule.test_workflow(payload)
        calls = mock_send.call_args_list
        for call in calls:
            print(f"[MOCK SEND] {call}")

class TestVirusTotalWorkflowDomain(unittest.TestCase):
    @patch("utils.webhook_sender.send_to_inopli")
    @patch("integrations.integration_manager.os.path.exists", return_value=True)
    @patch("integrations.integration_manager.yaml.safe_load")
    @patch("integrations.integration_manager.open", new_callable=mock_open, create=True)
    def test_full_domain_workflow(self, mock_file, mock_yaml, mock_exists, mock_send):
        TEST_DOMAIN = "inopli.com"  # Example domain
        config = {
            "virustotal": {
                "enabled": True,
                "api_key": API_KEY,
                "fields": ["domain"]
            }
        }
        mock_yaml.return_value = {"integrations": config}
        manager = IntegrationManager()
        rule = DummyRule(manager)
        payload = {
            "detection_rule_id": 1000,
            "source": "test_source",
            "rule": "DummyRule",
            "event_type": "test_event",
            "severity": "high",
            "timestamp": "2024-01-01T00:00:00Z",
            "domain": TEST_DOMAIN,
            "raw_event": "test raw event",
            "message": "Test domain alert"
        }
        rule.test_workflow(payload)
        calls = mock_send.call_args_list
        for call in calls:
            print(f"[MOCK SEND] {call}")

class TestVirusTotalWorkflowIP(unittest.TestCase):
    @patch("utils.webhook_sender.send_to_inopli")
    @patch("integrations.integration_manager.os.path.exists", return_value=True)
    @patch("integrations.integration_manager.yaml.safe_load")
    @patch("integrations.integration_manager.open", new_callable=mock_open, create=True)
    def test_full_ip_workflow(self, mock_file, mock_yaml, mock_exists, mock_send):
        TEST_IP = "110.34.2.94"  # Example IP
        config = {
            "virustotal": {
                "enabled": True,
                "api_key": API_KEY,
                "fields": ["ip"]
            }
        }
        mock_yaml.return_value = {"integrations": config}
        manager = IntegrationManager()
        rule = DummyRule(manager)
        payload = {
            "detection_rule_id": 1000,
            "source": "test_source",
            "rule": "DummyRule",
            "event_type": "test_event",
            "severity": "high",
            "timestamp": "2024-01-01T00:00:00Z",
            "ip": TEST_IP,
            "raw_event": "test raw event",
            "message": "Test IP alert"
        }
        rule.test_workflow(payload)
        calls = mock_send.call_args_list
        for call in calls:
            print(f"[MOCK SEND] {call}")

class TestVirusTotalWorkflowURL(unittest.TestCase):
    @patch("utils.webhook_sender.send_to_inopli")
    @patch("integrations.integration_manager.os.path.exists", return_value=True)
    @patch("integrations.integration_manager.yaml.safe_load")
    @patch("integrations.integration_manager.open", new_callable=mock_open, create=True)
    def test_full_url_workflow(self, mock_file, mock_yaml, mock_exists, mock_send):
        TEST_URL = "http://malicious.example.com"  # Example URL
        config = {
            "virustotal": {
                "enabled": True,
                "api_key": API_KEY,
                "fields": ["url"]
            }
        }
        mock_yaml.return_value = {"integrations": config}
        manager = IntegrationManager()
        rule = DummyRule(manager)
        payload = {
            "detection_rule_id": 1000,
            "source": "test_source",
            "rule": "DummyRule",
            "event_type": "test_event",
            "severity": "high",
            "timestamp": "2024-01-01T00:00:00Z",
            "url": TEST_URL,
            "raw_event": "test raw event",
            "message": "Test URL alert"
        }
        rule.test_workflow(payload)
        calls = mock_send.call_args_list
        for call in calls:
            print(f"[MOCK SEND] {call}")

if __name__ == "__main__":
    unittest.main() 