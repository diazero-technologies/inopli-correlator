import time
from utils.config_loader import load_multi_tenant_config
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class TenantRouter:
    """
    Singleton class to handle tenant routing with config reloading support.
    """
    _instance = None
    _config_path = "config/sources_config.yaml"
    _config_reload_interval = 300  # 5 minutes

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TenantRouter, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        """Initialize the router instance"""
        self._tenants_config = {}
        self._last_reload = 0
        self._load_config()

    def _load_config(self):
        """Load or reload the configuration"""
        try:
            new_config = load_multi_tenant_config(path=self._config_path)
            self._tenants_config = new_config
            self._last_reload = time.time()
            
            if DEBUG_MODE:
                print(f"[DEBUG] Loaded tenant config with {len(new_config)} tenants")
                
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
        """Check if config needs reloading"""
        if time.time() - self._last_reload > self._config_reload_interval:
            if DEBUG_MODE:
                print("[DEBUG] Reloading tenant configuration")
            self._load_config()

    def resolve_tenant(self, event_payload, source_name, rule_id):
        """
        Determine which tenant (if any) should receive this event based on:
        - source_name: name of the data source
        - rule_id: the detection rule ID
        - event_payload: the alert payload, including any filter fields

        Returns a tuple (tenant_id, token) if matched, else (None, None).
        """
        # Check if config needs reloading
        self._check_reload()

        for tenant_id, tenant_data in self._tenants_config.items():
            ds_list = tenant_data.get("data_sources", []) or []

            # Find matching data source config for this tenant
            ds_conf = next(
                (d for d in ds_list if d.get("name") == source_name and d.get("enabled", False)),
                None
            )
            if not ds_conf:
                continue

            # Check if this rule is allowed
            allowed_rules = ds_conf.get("event_types", []) or []
            if rule_id not in allowed_rules:
                continue

            # Apply filters
            filters = ds_conf.get("filters") or {}
            if not self._filters_match(event_payload, source_name, filters):
                continue

            # Return tenant match
            token = tenant_data.get("token")
            return tenant_id, token

        return None, None

    def _filters_match(self, event_payload, source_name, filters):
        """
        Evaluate filter conditions for a given data source against the payload.
        Returns True if all filters match, False otherwise.
        """
        for key, values in filters.items():
            if source_name == "wazuh_alerts" and key == "agent_ids":
                agent = event_payload.get("agent", {})
                agent_id = agent.get("id") if isinstance(agent, dict) else None
                if agent_id not in values:
                    return False

            elif source_name.startswith("linux") and key == "hostname":
                hostname = event_payload.get("hostname")
                if hostname not in values:
                    return False

            elif source_name == "crowdstrike" and key == "sensor_ids":
                sensor_id = event_payload.get("sensor_id")
                if sensor_id not in values:
                    return False

            elif key == "organization_ids":
                org_id = (
                    event_payload.get("data", {})
                    .get("office365", {})
                    .get("OrganizationId")
                )
                if org_id not in values:
                    return False

            # Unknown filter key: skip
        return True


# Create singleton instance
_router = TenantRouter()

# Export resolve_tenant function that uses the singleton
def resolve_tenant(event_payload, source_name, rule_id):
    return _router.resolve_tenant(event_payload, source_name, rule_id)
