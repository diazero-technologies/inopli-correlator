import requests
from .base import ThreatIntelligenceIntegration
from config.debug import DEBUG_MODE

class AbuseIPDBIntegration(ThreatIntelligenceIntegration):
    SUPPORTED_FIELDS = ["ip"]
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"
    DEFAULT_THRESHOLD = 50  # You can make this configurable

    def __init__(self, config):
        super().__init__(config)
        self.api_key = config.get("api_key")
        self.threshold = config.get("threshold", self.DEFAULT_THRESHOLD)
        if not self.api_key:
            raise ValueError("AbuseIPDB API key is required in config.")

    def query(self, field_type: str, value: str):
        if field_type != "ip":
            return None
        try:
            return self._query_ip(value)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] AbuseIPDBIntegration error for ip={value}: {e}")
        return None

    def _headers(self):
        return {"Key": self.api_key, "Accept": "application/json"}

    def _query_ip(self, ip):
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,  # You can make this configurable
            "verbose": ""
        }
        resp = requests.get(self.BASE_URL, headers=self._headers(), params=params, timeout=10)
        if resp.status_code != 200:
            if DEBUG_MODE:
                print(f"[DEBUG] AbuseIPDB IP query failed: {resp.status_code} {resp.text}")
            return None
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        if score >= self.threshold:
            return {
                "integration": "abuseipdb",
                "field_type": "ip",
                "value": ip,
                "threat": True,
                "details": {
                    "abuseConfidenceScore": score,
                    "totalReports": data.get("totalReports"),
                    "countryCode": data.get("countryCode"),
                    "countryName": data.get("countryName"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usageType": data.get("usageType"),
                    "reports": data.get("reports", []),
                }
            }
        if DEBUG_MODE:
            print(f"[DEBUG] AbuseIPDB score below threshold: {score} < {self.threshold}")
        return None 