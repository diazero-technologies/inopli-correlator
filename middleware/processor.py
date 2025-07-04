from typing import Dict, List, Any, Optional
import threading
from utils.event_logger import log_event
from utils.tenant_router import resolve_tenant
from utils.webhook_sender import send_to_inopli
from integrations.integration_manager import IntegrationManager
from config.debug import DEBUG_MODE


class AlertProcessor:
    """
    Singleton class for processing alerts through the middleware.
    Handles enrichment, filtering, and routing to tenants.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(AlertProcessor, cls).__new__(cls)
                    cls._instance._init()
        return cls._instance
    
    def _init(self):
        """Initialize the processor instance."""
        self.integration_manager = IntegrationManager()
        if DEBUG_MODE:
            print("[DEBUG] AlertProcessor initialized")
    
    @classmethod
    def get_instance(cls):
        """Get the singleton instance."""
        return cls()
    
    def process_alert(self, alert: Dict[str, Any], source_name: str):
        """
        Process an alert through the middleware pipeline:
        1. Apply filters and validation
        2. Extract rule ID and check if it should be processed
        3. Route to appropriate tenants
        4. Apply CTI enrichment and business rules
        5. Send to Inopli based on business rules
        """
        try:
            # Step 1: Validate and prepare alert
            if not self._validate_alert(alert, source_name):
                if DEBUG_MODE:
                    print(f"[DEBUG] Alert validation failed for {source_name}")
                return
            
            # Step 2: Extract rule ID for routing
            rule_id = self._extract_rule_id(alert, source_name)
            if not rule_id:
                if DEBUG_MODE:
                    print(f"[DEBUG] No rule ID found in alert from {source_name}")
                return
            
            # Step 3: Route to tenants
            tenant_matches = self._route_to_tenants(alert, source_name, rule_id)
            if not tenant_matches:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matches for alert from {source_name}")
                return
            
            # Step 4: Apply CTI enrichment and business rules
            for tenant_id, token, alert_mode in tenant_matches:
                self._process_and_send_alert(alert, tenant_id, token, source_name, rule_id, alert_mode)
                
        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_middleware",
                data_source=source_name,
                class_name="AlertProcessor",
                method="process_alert",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] AlertProcessor.process_alert(): {e}")
    
    def _validate_alert(self, alert: Dict[str, Any], source_name: str) -> bool:
        """Validate that the alert has required fields."""
        if not alert or not isinstance(alert, dict):
            return False
        
        # Basic validation - alert should have some content
        if not alert:
            return False
        
        return True
    
    def _extract_rule_id(self, alert: Dict[str, Any], source_name: str) -> Optional[int]:
        """Extract rule ID from alert based on source type."""
        try:
            if source_name == "wazuh_file" or source_name == "wazuh_o365":
                rule_obj = alert.get("rule", {})
                rule_id_str = rule_obj.get("id")
                if rule_id_str:
                    return int(rule_id_str)
            elif source_name == "qradar":
                # QRadar specific rule ID extraction
                rules = alert.get("rules", [])
                if rules:
                    # Return the first rule ID (QRadar offenses can have multiple rules)
                    return rules[0].get("id")
            elif source_name == "crowdstrike":
                # CrowdStrike specific rule ID extraction
                return alert.get("detection_rule_id")
            elif source_name.startswith("linux"):
                # Linux specific rule ID extraction
                return alert.get("detection_rule_id")
            
            # Fallback to generic field
            return alert.get("detection_rule_id")
            
        except (ValueError, TypeError):
            return None
    
    def _route_to_tenants(self, alert: Dict[str, Any], source_name: str, rule_id: int) -> List[tuple]:
        """Route alert to appropriate tenants based on middleware configuration."""
        tenant_matches = []
        
        # Get tenant configurations from middleware manager
        from middleware.manager import MiddlewareManager
        middleware_manager = MiddlewareManager.get_instance()
        
        # Extract alert information based on source type
        if source_name == "wazuh":
            agent = alert.get("agent", {}) or {}
            agent_id = agent.get("id")
        elif source_name == "qradar":
            # QRadar uses source_address_ids instead of agent_id
            agent_id = alert.get("offense_source", "")
        else:
            agent_id = None
        
        # Check each tenant configuration
        for tenant_id, tenant_data in middleware_manager.tenants_config.items():
            # Check Wazuh configuration
            wazuh_config = tenant_data.get("siem_sources", {}).get("wazuh", {})
            if wazuh_config.get("enabled", False) and source_name == "wazuh":
                # Check rule filters
                rule_filters = wazuh_config.get("rule_filters", {})
                allowed_rule_ids = rule_filters.get("rule_ids", [])
                
                if "*" not in allowed_rule_ids and rule_id not in allowed_rule_ids:
                    continue
                
                # Check agent filters
                agent_filters = wazuh_config.get("agent_filters", {})
                allowed_agent_ids = agent_filters.get("agent_ids", [])
                
                if "*" not in allowed_agent_ids and agent_id not in allowed_agent_ids:
                    continue
                
                # Get tenant token and alert mode
                token = tenant_data.get("token")
                alert_mode = wazuh_config.get("alert_mode", "all")
                
                if token:
                    tenant_matches.append((tenant_id, token, alert_mode))
            
            # Check QRadar configuration
            qradar_config = tenant_data.get("siem_sources", {}).get("qradar", {})
            if qradar_config.get("enabled", False) and source_name == "qradar":
                # Check rule filters
                rule_filters = qradar_config.get("rule_filters", {})
                allowed_rule_ids = rule_filters.get("rule_ids", [])
                
                if "*" not in allowed_rule_ids and rule_id not in allowed_rule_ids:
                    continue
                
                # Check source filters (QRadar uses source networks instead of agents)
                source_filters = qradar_config.get("source_filters", {})
                allowed_source_networks = source_filters.get("source_networks", [])
                offense_source_network = alert.get("source_network", "")
                
                if "*" not in allowed_source_networks and offense_source_network not in allowed_source_networks:
                    continue
                
                # Get tenant token and alert mode
                token = tenant_data.get("token")
                alert_mode = qradar_config.get("alert_mode", "all")
                
                if token:
                    tenant_matches.append((tenant_id, token, alert_mode))
        
        return tenant_matches
    
    def _process_and_send_alert(self, alert: Dict[str, Any], tenant_id: str, token: str, source_name: str, rule_id: int, alert_mode: str):
        """
        Process alert with CTI enrichment and business rules, then send to tenant.
        This method implements the business logic for alert processing.
        """
        try:
            # Add source information to alert
            alert["source"] = source_name
            
            # Use tenant-specific alert mode instead of global business rules
            # alert_mode is passed from tenant configuration
            
            if DEBUG_MODE:
                print(f"[DEBUG] Processing alert for tenant {tenant_id} with alert_mode={alert_mode}")
            
            # Apply CTI enrichment if integrations are available
            enrichment_results = []
            if self.integration_manager.has_active_integrations():
                enrichment_results = self.integration_manager.enrich_event(alert)
                if DEBUG_MODE and enrichment_results:
                    print(f"[DEBUG] CTI enrichment found {len(enrichment_results)} results")
            
            # Apply business rules to decide what to send
            alerts_to_send = []
            
            if alert_mode == "all":
                # Send original alert
                alerts_to_send.append(alert)
                
                # Send enriched alert if CTI results exist
                if enrichment_results:
                    enriched_alert = alert.copy()
                    enriched_alert["cti"] = enrichment_results
                    alerts_to_send.append(enriched_alert)
                    
                if DEBUG_MODE:
                    print(f"[DEBUG] alert_mode=all: sending {len(alerts_to_send)} alerts")
                    
            elif alert_mode == "cti_only":
                # Only send if CTI enrichment indicates a threat
                if enrichment_results:
                    enriched_alert = alert.copy()
                    enriched_alert["cti"] = enrichment_results
                    alerts_to_send.append(enriched_alert)
                    
                if DEBUG_MODE:
                    print(f"[DEBUG] alert_mode=cti_only: sending {len(alerts_to_send)} alerts")
                    
            elif alert_mode == "none":
                # Test mode - don't send anything
                if DEBUG_MODE:
                    print(f"[DEBUG] alert_mode=none: not sending alerts (test mode)")
                    if enrichment_results:
                        print(f"[DEBUG] Enriched alert (test mode, not sent):")
                        enriched_alert = alert.copy()
                        enriched_alert["cti"] = enrichment_results
                        print(enriched_alert)
                return
                
            else:
                # Fallback to default (same as "all")
                alerts_to_send.append(alert)
                if enrichment_results:
                    enriched_alert = alert.copy()
                    enriched_alert["cti"] = enrichment_results
                    alerts_to_send.append(enriched_alert)
                    
                if DEBUG_MODE:
                    print(f"[DEBUG] alert_mode=fallback: sending {len(alerts_to_send)} alerts")
            
            # Send alerts to tenant
            for alert_to_send in alerts_to_send:
                self._send_single_alert(alert_to_send, tenant_id, token, source_name, rule_id)
                
        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_middleware",
                data_source=source_name,
                class_name="AlertProcessor",
                method="_process_and_send_alert",
                event_type="error",
                description=f"Failed to process alert for tenant {tenant_id}: {e}"
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to process alert for tenant {tenant_id}: {e}")
    
    def _send_single_alert(self, alert: Dict[str, Any], tenant_id: str, token: str, source_name: str, rule_id: int):
        """Send a single alert to a specific tenant."""
        try:
            # Ensure alert has required fields
            if "detection_rule_id" not in alert:
                alert["detection_rule_id"] = rule_id
            
            if "timestamp" not in alert:
                # Add current timestamp if missing
                from datetime import datetime
                alert["timestamp"] = datetime.utcnow().isoformat()
            
            if DEBUG_MODE:
                print(f"[DEBUG] Sending alert to tenant {tenant_id} from {source_name}")
            
            send_to_inopli(alert, token_override=token)
            
        except Exception as e:
            log_event(
                event_id=998,
                solution_name="inopli_middleware",
                data_source=source_name,
                class_name="AlertProcessor",
                method="_send_single_alert",
                event_type="error",
                description=f"Failed to send to tenant {tenant_id}: {e}"
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to send alert to tenant {tenant_id}: {e}") 