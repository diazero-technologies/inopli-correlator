import requests
import base64
from .base import ThreatIntelligenceIntegration
from config.debug import DEBUG_MODE

class VirusTotalIntegration(ThreatIntelligenceIntegration):
    SUPPORTED_FIELDS = ["ip", "domain", "file_hash", "url"]
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, config):
        super().__init__(config)
        self.api_key = config.get("api_key")
        if not self.api_key:
            raise ValueError("VirusTotal API key is required in config.")

    def query(self, field_type: str, value: str):
        if field_type not in self.SUPPORTED_FIELDS:
            return None
        try:
            if field_type == "ip":
                return self._query_ip(value)
            elif field_type == "domain":
                return self._query_domain(value)
            elif field_type == "file_hash":
                return self._query_file(value)
            elif field_type == "url":
                return self._query_url(value)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] VirusTotalIntegration error for {field_type}={value}: {e}")
        return None

    def _headers(self):
        return {"x-apikey": self.api_key}

    def _query_ip(self, ip):
        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        resp = requests.get(url, headers=self._headers(), timeout=10)
        if resp.status_code != 200:
            if DEBUG_MODE:
                print(f"[DEBUG] VT IP query failed: {resp.status_code} {resp.text}")
            return None
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            return {
                "integration": "virustotal",
                "field_type": "ip",
                "value": ip,
                "threat": True,
                "details": {
                    "stats": stats,
                    "reputation": attrs.get("reputation"),
                    "country": attrs.get("country"),
                    "tags": attrs.get("tags"),
                }
            }
        return None

    def _query_domain(self, domain):
        url = f"{self.BASE_URL}/domains/{domain}"
        resp = requests.get(url, headers=self._headers(), timeout=10)
        if resp.status_code != 200:
            if DEBUG_MODE:
                print(f"[DEBUG] VT domain query failed: {resp.status_code} {resp.text}")
            return None
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            return {
                "integration": "virustotal",
                "field_type": "domain",
                "value": domain,
                "threat": True,
                "details": {
                    "stats": stats,
                    "categories": attrs.get("categories"),
                    "reputation": attrs.get("reputation"),
                    "tags": attrs.get("tags"),
                }
            }
        return None

    def _query_file(self, file_hash):
        url = f"{self.BASE_URL}/files/{file_hash}"
        resp = requests.get(url, headers=self._headers(), timeout=10)
        if resp.status_code != 200:
            if DEBUG_MODE:
                print(f"[DEBUG] VT file query failed: {resp.status_code} {resp.text}")
            return None
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            return {
                "integration": "virustotal",
                "field_type": "file_hash",
                "value": file_hash,
                "threat": True,
                "details": {
                    "stats": stats,
                    "type_description": attrs.get("type_description"),
                    "names": attrs.get("names"),
                    "reputation": attrs.get("reputation"),
                }
            }
        return None

    def _query_url(self, url_value):
        # VT requires url_id to be url-safe base64 encoded (no padding)
        url_id = base64.urlsafe_b64encode(url_value.encode()).decode().rstrip("=")
        url = f"{self.BASE_URL}/urls/{url_id}"
        resp = requests.get(url, headers=self._headers(), timeout=10)
        if resp.status_code != 200:
            if DEBUG_MODE:
                print(f"[DEBUG] VT url query failed: {resp.status_code} {resp.text}")
            return None
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            return {
                "integration": "virustotal",
                "field_type": "url",
                "value": url_value,
                "threat": True,
                "details": {
                    "stats": stats,
                    "categories": attrs.get("categories"),
                    "reputation": attrs.get("reputation"),
                    "tags": attrs.get("tags"),
                }
            }
        return None 