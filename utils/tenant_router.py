import time
import yaml
import os
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class TenantRouter:
    _instance = None
    _config_path = "config/sources_config.yaml"
    _config_reload_interval = 300

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TenantRouter, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self._tenants_config = {}
        self._last_reload = 0
        self._load_config()

    def _load_config(self):
        try:
            if not os.path.exists(self._config_path):
                if DEBUG_MODE:
                    print(f"[DEBUG] Sources config not found: {self._config_path}")
                return
                
            with open(self._config_path, "r") as f:
                config = yaml.safe_load(f)
            
            # Extract tenants configuration
            self._tenants_config = config.get("tenants", {})
            self._last_reload = time.time()
            
            if DEBUG_MODE:
                print(f"[DEBUG] Loaded tenant config with {len(self._tenants_config)} tenants")
                
        except Exception as e:
            log_event(
                event_id=997,
                solution_name="inopli_monitor",
                data_source="tenant_router",
                class_name="TenantRouter",
                method="_load_config",
                event_type="error",
                description=str(e)
            )

    def _check_reload(self):
        if time.time() - self._last_reload > self._config_reload_interval:
            if DEBUG_MODE:
                print("[DEBUG] Reloading tenant configuration")
            self._load_config()

    def resolve_tenant(self, event_payload, source_name, rule_id):
        self._check_reload()
        
        for tenant_id, tenant_data in self._tenants_config.items():
            # Check legacy data_sources first
            ds_list = tenant_data.get("data_sources", []) or []
            ds_conf = next(
                (d for d in ds_list if d.get("name") == source_name and d.get("enabled", False)),
                None
            )
            
            if ds_conf:
                # Legacy data_sources logic
                allowed_rules = ds_conf.get("event_types", []) or []
                if "*" not in allowed_rules and rule_id not in allowed_rules:
                    continue
                filters = ds_conf.get("filters") or {}
                if not self._filters_match(event_payload, source_name, filters):
                    continue
                token = tenant_data.get("token")
                return tenant_id, token
            
            # Check new siem_sources
            siem_sources = tenant_data.get("siem_sources", {})
            if source_name in siem_sources:
                siem_conf = siem_sources[source_name]
                if not siem_conf.get("enabled", False):
                    continue
                
                # Check rule filters
                rule_filters = siem_conf.get("rule_filters", {})
                allowed_rule_ids = rule_filters.get("rule_ids", [])
                
                if "*" not in allowed_rule_ids:
                    # For QRadar, use string matching with description
                    module = siem_conf.get("module", source_name)
                    if module == "qradar":
                        if not any(allowed_rule in rule_id for allowed_rule in allowed_rule_ids):
                            continue
                    else:
                        # For other modules, use exact matching
                        if rule_id not in allowed_rule_ids:
                            continue
                
                # Check source filters
                source_filters = siem_conf.get("source_filters", {})
                if source_filters:
                    if not self._siem_filters_match(event_payload, source_name, source_filters):
                        continue
                
                # Check agent filters (for Wazuh)
                agent_filters = siem_conf.get("agent_filters", {})
                if agent_filters:
                    if not self._agent_filters_match(event_payload, source_name, agent_filters):
                        continue
                
                token = tenant_data.get("token")
                return tenant_id, token
        
        return None, None

    def _filters_match(self, event_payload, source_name, filters):
        """Legacy filter matching for data_sources"""
        for key, values in filters.items():
            if source_name == "wazuh_alerts" and key == "agent_ids":
                if "*" in values:
                    continue
                agent = event_payload.get("agent", {})
                agent_id = agent.get("id") if isinstance(agent, dict) else None
                if agent_id not in values:
                    return False
            elif source_name.startswith("linux") and key == "hostname":
                if "*" in values:
                    continue
                hostname = event_payload.get("hostname")
                if hostname not in values:
                    return False
            elif source_name == "crowdstrike" and key == "sensor_ids":
                if "*" in values:
                    continue
                sensor_id = event_payload.get("sensor_id")
                if sensor_id not in values:
                    return False
            elif key == "organization_ids":
                if "*" in values:
                    continue
                org_id = (
                    event_payload.get("data", {})
                    .get("office365", {})
                    .get("OrganizationId")
                )
                if not org_id or org_id not in values:
                    return False
        return True

    def _siem_filters_match(self, event_payload, source_name, source_filters):
        """New filter matching for siem_sources"""
        allowed_source_networks = source_filters.get("source_networks", [])
        if "*" in allowed_source_networks:
            return True
        
        # For QRadar, check source_network field
        if source_name.startswith("qradar"):
            offense_source_network = event_payload.get("source_network", "")
            return offense_source_network in allowed_source_networks
        
        return True

    def _agent_filters_match(self, event_payload, source_name, agent_filters):
        """Agent filter matching for siem_sources"""
        allowed_agent_ids = agent_filters.get("agent_ids", [])
        if "*" in allowed_agent_ids:
            return True
        
        # For Wazuh, check agent.id
        if source_name == "wazuh":
            agent = event_payload.get("agent", {}) or {}
            agent_id = agent.get("id")
            return agent_id in allowed_agent_ids
        
        return True

_router = TenantRouter()
def resolve_tenant(event_payload, source_name, rule_id):
    return _router.resolve_tenant(event_payload, source_name, rule_id)
