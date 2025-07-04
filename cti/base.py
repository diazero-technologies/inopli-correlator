from abc import ABC, abstractmethod

class ThreatIntelligenceIntegration(ABC):
    def __init__(self, config):
        self.config = config

    @abstractmethod
    def query(self, field_type: str, value: str):
        pass 