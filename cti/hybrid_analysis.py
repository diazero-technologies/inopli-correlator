import requests
from .base import ThreatIntelligenceIntegration
from utils.ip_utils import is_public_ip

class HybridAnalysisIntegration(ThreatIntelligenceIntegration):
    SUPPORTED_FIELDS = ["file_hash", "url"]
    API_URL = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, config):
        super().__init__(config)
        self.api_key = config.get("api_key")
        self.fields = config.get("fields", self.SUPPORTED_FIELDS)

    def query(self, field_type: str, value: str):
        if field_type not in self.fields:
            return None
        headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon"
        }
        try:
            if field_type == "file_hash":
                url = f"{self.API_URL}/search/hash?hash={value}"
                resp = requests.get(url, headers=headers, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                if data and isinstance(data, list) and len(data) > 0:
                    # Take the first report (most recent)
                    report = data[0]
                    return {
                        "integration": "hybrid_analysis",
                        "field_type": field_type,
                        "value": value,
                        "threat": report.get("verdict", "") == "malicious",
                        "verdict": report.get("verdict"),
                        "threat_level": report.get("threat_level_human"),
                        "environment": report.get("environment_description"),
                        "state": report.get("state"),
                        "report_id": report.get("id"),
                        "details": f"https://www.hybrid-analysis.com/sample/{value}"
                    }
            elif field_type == "url":
                url = f"{self.API_URL}/search/url?url={value}"
                resp = requests.get(url, headers=headers, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                if data and isinstance(data, list) and len(data) > 0:
                    report = data[0]
                    return {
                        "integration": "hybrid_analysis",
                        "field_type": field_type,
                        "value": value,
                        "threat": report.get("verdict", "") == "malicious",
                        "verdict": report.get("verdict"),
                        "threat_level": report.get("threat_level_human"),
                        "environment": report.get("environment_description"),
                        "state": report.get("state"),
                        "report_id": report.get("id"),
                        "details": f"https://www.hybrid-analysis.com/sample/{report.get('sha256', '')}"
                    }
        except Exception as e:
            # Log or handle error as needed
            return None
        return None 