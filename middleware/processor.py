from typing import Dict, List, Any, Optional
import threading
from utils.event_logger import log_event
from utils.webhook_sender import send_to_inopli
from integrations.integration_manager import IntegrationManager
from config.debug import DEBUG_MODE


class AlertProcessor:
    
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
        self.integration_manager = IntegrationManager()
        if DEBUG_MODE:
            print("[DEBUG] AlertProcessor initialized")
    
    @classmethod
    def get_instance(cls):
        return cls()
    
    def process_alert(self, alert: Dict[str, Any], source_name: str):
        try:
            if DEBUG_MODE:
                print(f"[DEBUG] AlertProcessor.process_alert called for source: {source_name}")
                import traceback
                print(f"[DEBUG] Call stack:")
                traceback.print_stack(limit=5)
            
            # Step 1: Validate and prepare alert
            if not self._validate_alert(alert, source_name):
                if DEBUG_MODE:
                    print(f"[DEBUG] Alert validation failed for {source_name}")
                return
            
            # Step 2: Get source configuration for rule ID extraction
            source_config = self._get_source_config(source_name)
            if not source_config:
                if DEBUG_MODE:
                    print(f"[DEBUG] No source configuration found for {source_name}")
                return
            
            # Step 3: Extract rule ID for routing
            rule_id = self._extract_rule_id(alert, source_name, source_config)
            if not rule_id:
                if DEBUG_MODE:
                    print(f"[DEBUG] No rule ID found in alert from {source_name}")
                return
            
            # Step 4: Route to tenants
            tenant_matches = self._route_to_tenants(alert, source_name, rule_id)
            if not tenant_matches:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matches for alert from {source_name}")
                return
            
            # Step 5: Apply CTI enrichment and business rules
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
                import traceback
                traceback.print_exc()
    
    def _validate_alert(self, alert: Dict[str, Any], source_name: str) -> bool:
        if not alert or not isinstance(alert, dict):
            return False
        
        # Basic validation - alert should have some content
        if not alert:
            return False
        
        return True
    
    def _get_source_config(self, source_name: str) -> Optional[Dict[str, Any]]:
        """Get the configuration for a specific source from any tenant"""
        try:
            if DEBUG_MODE:
                print(f"[DEBUG] _get_source_config called for source: {source_name}")
            
            from middleware.manager import MiddlewareManager
            middleware_manager = MiddlewareManager.get_instance()
            
            if DEBUG_MODE:
                print(f"[DEBUG] MiddlewareManager has {len(middleware_manager.connectors)} connectors")
                print(f"[DEBUG] Available connectors: {list(middleware_manager.connectors.keys())}")
            
            # Always try to load configuration if no connectors or tenants config
            if not middleware_manager.connectors or not middleware_manager.tenants_config:
                if DEBUG_MODE:
                    print(f"[DEBUG] No connectors or tenants config found, attempting to load configuration...")
                if middleware_manager.load_config():
                    if DEBUG_MODE:
                        print(f"[DEBUG] Configuration loaded successfully")
                    # Try to create connectors if they don't exist
                    if not middleware_manager.connectors:
                        if DEBUG_MODE:
                            print(f"[DEBUG] No connectors found, attempting to create them...")
                        middleware_manager.create_connectors()
                        if DEBUG_MODE:
                            print(f"[DEBUG] Created {len(middleware_manager.connectors)} connectors")
                else:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Failed to load configuration")
            
            # First, check if there's a connector with this name that already has config
            if source_name in middleware_manager.connectors:
                if DEBUG_MODE:
                    print(f"[DEBUG] Found connector for {source_name} in MiddlewareManager")
                connector = middleware_manager.connectors[source_name]
                # Return a minimal config with module info
                config = {
                    "module": connector.config.get("module", source_name.split("_")[0]),
                    "enabled": connector.config.get("enabled", True)
                }
                if DEBUG_MODE:
                    print(f"[DEBUG] Returning connector config: {config}")
                return config
            
            if DEBUG_MODE:
                print(f"[DEBUG] No connector found for {source_name}, searching in tenant configs")
            
            # Fallback: search in tenant configurations
            for tenant_id, tenant_data in middleware_manager.tenants_config.items():
                siem_sources = tenant_data.get("siem_sources", {})
                if DEBUG_MODE:
                    print(f"[DEBUG] Checking tenant {tenant_id}, has sources: {list(siem_sources.keys())}")
                if source_name in siem_sources:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Found {source_name} in tenant {tenant_id}")
                    return siem_sources[source_name]
            
            if DEBUG_MODE:
                print(f"[DEBUG] No source configuration found for {source_name} in any tenant")
            return None
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Failed to get source config for {source_name}: {e}")
                import traceback
                traceback.print_exc()
            return None
    
    def _extract_rule_id(self, alert: Dict[str, Any], source_name: str, source_config: dict) -> Optional[str]:
        try:
            module = source_config.get("module", source_name)
            if module == "wazuh_file" or module == "wazuh_o365":
                rule_obj = alert.get("rule", {})
                rule_id_str = rule_obj.get("id")
                if rule_id_str:
                    return str(rule_id_str)
            elif module == "qradar":
                # QRadar specific rule ID extraction - use description as rule_id
                description = alert.get("description", "")
                if description and description.strip():
                    return description
                else:
                    # Fallback to rules array if description is empty
                    rules = alert.get("rules", [])
                    if rules:
                        return rules[0].get("name", "Unknown Rule")
                    else:
                        return "Unknown Rule"
            elif module == "crowdstrike":
                # CrowdStrike specific rule ID extraction
                return alert.get("detection_rule_id")
            elif module.startswith("linux"):
                # Linux specific rule ID extraction
                return alert.get("detection_rule_id")
            # Fallback to generic field
            return alert.get("detection_rule_id")
        except (ValueError, TypeError):
            return None

    def _route_to_tenants(self, alert: Dict[str, Any], source_name: str, rule_id: str) -> list:
        tenant_matches = []
        from middleware.manager import MiddlewareManager
        middleware_manager = MiddlewareManager.get_instance()
        for tenant_id, tenant_data in middleware_manager.tenants_config.items():
            siem_sources = tenant_data.get("siem_sources", {})
            for src_name, src_config in siem_sources.items():
                if not src_config.get("enabled", False):
                    continue
                module = src_config.get("module", src_name)
                # Match by source_name for agent/source_id, but by module for logic
                if src_name == source_name:
                    # Wazuh
                    if module == "wazuh":
                        rule_filters = src_config.get("rule_filters", {})
                        allowed_rule_ids = rule_filters.get("rule_ids", [])
                        if "*" not in allowed_rule_ids and rule_id not in allowed_rule_ids:
                            continue
                        agent_filters = src_config.get("agent_filters", {})
                        allowed_agent_ids = agent_filters.get("agent_ids", [])
                        agent = alert.get("agent", {}) or {}
                        agent_id = agent.get("id")
                        if "*" not in allowed_agent_ids and agent_id not in allowed_agent_ids:
                            continue
                        token = tenant_data.get("token")
                        alert_mode = src_config.get("alert_mode", "all")
                        if token:
                            tenant_matches.append((tenant_id, token, alert_mode))
                    # QRadar
                    elif module == "qradar":
                        rule_filters = src_config.get("rule_filters", {})
                        allowed_rule_ids = rule_filters.get("rule_ids", [])
                        if "*" not in allowed_rule_ids:
                            if not any(allowed_rule in rule_id for allowed_rule in allowed_rule_ids):
                                continue
                        source_filters = src_config.get("source_filters", {})
                        allowed_source_networks = source_filters.get("source_networks", [])
                        offense_source_network = alert.get("source_network", "")
                        if "*" not in allowed_source_networks and offense_source_network not in allowed_source_networks:
                            continue
                        token = tenant_data.get("token")
                        alert_mode = src_config.get("alert_mode", "all")
                        if token:
                            tenant_matches.append((tenant_id, token, alert_mode))
                    # Outros módulos podem ser adicionados aqui
        return tenant_matches
    
    def _process_and_send_alert(self, alert: Dict[str, Any], tenant_id: str, token: str, source_name: str, rule_id: str, alert_mode: str):
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
    
    def _send_single_alert(self, alert: Dict[str, Any], tenant_id: str, token: str, source_name: str, rule_id: str):
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