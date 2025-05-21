from utils.config_loader import load_multi_tenant_config

# Load tenants config from unified sources_config.yaml
TENANTS_CONFIG = load_multi_tenant_config(path="config/sources_config.yaml")


def resolve_tenant(event_payload, source_name, rule_id):
    """
    Determine which tenant (if any) should receive this event based on:
    - source_name: name of the data source
    - rule_id: the detection rule ID
    - event_payload: the alert payload, including any filter fields

    Returns a tuple (tenant_id, token) if matched, else (None, None).
    """
    for tenant_id, tenant_data in TENANTS_CONFIG.items():
        # Now data_sources is a list
        ds_list = tenant_data.get("data_sources", []) or []
        # Find the matching data_source entry by its 'name'
        ds_conf = next((d for d in ds_list if d.get("name") == source_name and d.get("enabled", False)), None)
        if not ds_conf:
            continue

        # Check if this rule is allowed for the tenant
        allowed_rules = ds_conf.get("event_types", []) or []
        if rule_id not in allowed_rules:
            continue

        # Apply filters (fallback to empty dict if None)
        filters = ds_conf.get("filters") or {}
        if not _filters_match(event_payload, source_name, filters):
            continue

        # Matched tenant
        token = tenant_data.get("token")
        return tenant_id, token

    return None, None


def _filters_match(event_payload, source_name, filters):
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
            # For linux sources, name may vary (linux_auth, linux_syslog), but hostname filter applies
            hostname = event_payload.get("hostname")
            if hostname not in values:
                return False

        elif source_name == "crowdstrike" and key == "sensor_ids":
            sensor_id = event_payload.get("sensor_id")
            if sensor_id not in values:
                return False

        # Unknown filter key: skip
    return True
