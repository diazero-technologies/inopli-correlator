import yaml
import os
from cti.virustotal import VirusTotalIntegration
from cti.abuseipdb import AbuseIPDBIntegration
from cti.base import ThreatIntelligenceIntegration
from integrations.field_mapping import FIELD_MAPPING, get_field_value
from config.debug import DEBUG_MODE

INTEGRATION_CLASSES = {
    "virustotal": VirusTotalIntegration,
    "abuseipdb": AbuseIPDBIntegration,
    # Add more integrations here
}

class IntegrationManager:
    def __init__(self, config_path="config/integrations_config.yaml", business_rules_path="config/business_rules.yaml"):
        self.config_path = config_path
        self.business_rules_path = business_rules_path
        self.integrations = {}
        self.alert_mode = "all"  # default
        self._load_config()
        self._load_business_rules()
        if DEBUG_MODE:
            print(f"[DEBUG] IntegrationManager initialized with alert_mode={self.alert_mode}")

    def _load_config(self):
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Integration config not found: {self.config_path}")
        with open(self.config_path, "r") as f:
            config = yaml.safe_load(f)
        self.integrations = {}
        for name, settings in config.get("integrations", {}).items():
            if settings.get("enabled") and name in INTEGRATION_CLASSES:
                self.integrations[name] = INTEGRATION_CLASSES[name](settings)
                if DEBUG_MODE:
                    print(f"[DEBUG] Loaded integration: {name}")

    def _load_business_rules(self):
        if not os.path.exists(self.business_rules_path):
            self.alert_mode = "all"
            return
        with open(self.business_rules_path, "r") as f:
            config = yaml.safe_load(f)
        self.alert_mode = config.get("alert_mode", "all")
        if DEBUG_MODE:
            print(f"[DEBUG] Business rules loaded: alert_mode={self.alert_mode}")

    def has_active_integrations(self):
        return bool(self.integrations)

    def enrich_event(self, event: dict):
        results = []
        for field_type, possible_names in FIELD_MAPPING.items():
            value = get_field_value(event, field_type)
            if not value:
                continue
            for integration_name, integration in self.integrations.items():
                result = integration.query(field_type, value)
                if result:
                    results.append(result)
                    if DEBUG_MODE:
                        print(f"[DEBUG] Enrichment hit: integration={integration_name}, field_type={field_type}, value={value}, result={result}")
        if DEBUG_MODE and not results:
            print(f"[DEBUG] No enrichment results for event: {event}")
        return results

    def process_alert(self, alert: dict):
        """
        Applies the business rule for alert generation.
        Returns a list of enriched alerts/results for the rule to decide on sending.
        """
        self._load_business_rules()  # Reload in case config changed at runtime
        enrichment_results = self.enrich_event(alert) if self.has_active_integrations() else []
        alerts_to_return = []

        if self.alert_mode == "all":
            alerts_to_return.append(alert)
            for enrichment in enrichment_results:
                enriched_alert = alert.copy()
                enriched_alert["cti"] = enrichment
                alerts_to_return.append(enriched_alert)
            if DEBUG_MODE:
                print(f"[DEBUG] process_alert (all): returning {len(alerts_to_return)} alerts (original + CTI)")
        elif self.alert_mode == "cti_only":
            for enrichment in enrichment_results:
                enriched_alert = alert.copy()
                enriched_alert["cti"] = enrichment
                alerts_to_return.append(enriched_alert)
            if DEBUG_MODE:
                print(f"[DEBUG] process_alert (cti_only): returning {len(alerts_to_return)} CTI alerts")
        elif self.alert_mode == "none":
            if DEBUG_MODE:
                print(f"[DEBUG] process_alert (none): returning 0 alerts (test mode)")
                if enrichment_results:
                    print(f"[DEBUG] Enriched alerts (test mode, not sent):")
                    for enrichment in enrichment_results:
                        enriched_alert = alert.copy()
                        enriched_alert["cti"] = enrichment
                        print(enriched_alert)
            # Do not return any alerts
        else:
            # Fallback to default
            alerts_to_return.append(alert)
            for enrichment in enrichment_results:
                enriched_alert = alert.copy()
                enriched_alert["cti"] = enrichment
                alerts_to_return.append(enriched_alert)
            if DEBUG_MODE:
                print(f"[DEBUG] process_alert (fallback): returning {len(alerts_to_return)} alerts")

        return alerts_to_return 