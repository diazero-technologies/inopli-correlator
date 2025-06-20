from .base import ThreatIntelligenceIntegration

class HybridAnalysisIntegration(ThreatIntelligenceIntegration):
    SUPPORTED_FIELDS = ["file_hash", "ip", "url"]

    def query(self, field_type: str, value: str):
        if field_type not in self.SUPPORTED_FIELDS:
            return None
        # Mocked API call: treat any value ending with 'bad' as a threat
        if value.endswith("bad"):
            return {
                "integration": "hybrid_analysis",
                "field_type": field_type,
                "value": value,
                "threat": True,
                "details": "Mocked: found as malicious in Hybrid Analysis"
            }
        return None 