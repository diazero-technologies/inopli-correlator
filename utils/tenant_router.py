# utils/tenant_router.py

from utils.config_loader import load_multi_tenant_config

# Load tenants configuration once
TENANTS_CONFIG = load_multi_tenant_config()


def resolve_tenant(event_payload, source_name, rule_id):
    """
    Given an event payload, data source name, and rule_id,
    determine the tenant that should receive this event.

    Returns a tuple (tenant_id, token) if a matching tenant is found,
    otherwise (None, None).
    """
    for tenant_id, tenant_data in TENANTS_CONFIG.items():
        ds_conf = tenant_data.get("data_sources", {}).get(source_name)
        if not ds_conf or not ds_conf.get("enabled", False):
            continue

        # Check if this rule is allowed for the tenant
        allowed_rules = ds_conf.get("event_types", [])
        if rule_id not in allowed_rules:
            continue

        # Apply filters specific to data source
        filters = ds_conf.get("filters", {})
        if not _filters_match(event_payload, source_name, filters):
            continue

        # Matched tenant
        token = tenant_data.get("token")
        return tenant_id, token

    return None, None


def _filters_match(event_payload, source_name, filters):
    """
    Evaluate all filter conditions for the given data source against the payload.
    Returns True if all filters pass, False otherwise.
    """
    for key, values in filters.items():
        # Wazuh: filter by agent.id
        if source_name == "wazuh_alerts" and key == "agent_ids":
            agent = event_payload.get("agent", {})
            agent_id = agent.get("id") if isinstance(agent, dict) else None
            if agent_id not in values:
                return False

        # Linux: filter by hostname
        elif source_name == "linux" and key == "hostname":
            hostname = event_payload.get("hostname")
            if hostname not in values:
                return False

        # Crowdstrike: filter by sensor_id
        elif source_name == "crowdstrike" and key == "sensor_ids":
            sensor_id = event_payload.get("sensor_id")
            if sensor_id not in values:
                return False

        # Unknown filter: skip
        else:
            continue

    return True
