from abc import ABC, abstractmethod

class ThreatIntelligenceIntegration(ABC):
    def __init__(self, config):
        self.config = config

    @abstractmethod
    def query(self, field_type: str, value: str):
        """
        Query the threat intelligence service with the given field type and value.
        Returns a dict with enrichment results or None if not found/threat not detected.
        """
        pass 