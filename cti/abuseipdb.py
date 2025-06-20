from .base import ThreatIntelligenceIntegration

class AbuseIPDBIntegration(ThreatIntelligenceIntegration):
    SUPPORTED_FIELDS = ["ip"]

    def query(self, field_type: str, value: str):
        if field_type not in self.SUPPORTED_FIELDS:
            return None
        # Mocked API call: treat any IP starting with '1.2.3' as a threat
        if value.startswith("1.2.3"):
            return {
                "integration": "abuseipdb",
                "field_type": field_type,
                "value": value,
                "threat": True,
                "details": "Mocked: found as malicious in AbuseIPDB"
            }
        return None 