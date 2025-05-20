# utils/config_loader.py

import yaml
from utils.event_logger import log_event


def load_multi_tenant_config(path="config/multi_tenant_config.yaml"):
    """
    Loads the YAML configuration file containing multi-tenant settings.
    Returns a dict of tenants, each with their own data_sources, token and filters.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            tenants = config.get("tenants")
            if tenants is None:
                raise ValueError("Configuration file must include a 'tenants' key.")
            return tenants
    except Exception as e:
        log_event(
            event_id=997,
            solution_name="inopli_monitor",
            data_source="config_loader",
            class_name="ConfigLoader",
            method="load_multi_tenant_config",
            event_type="error",
            description=str(e)
        )
        return {}


def load_legacy_sources_config(path="config/sources_config.yaml"):
    """
    (Optional) Legacy loader for per-data-source configuration.
    Returns a dict with key 'data_sources', compatible with older code paths.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            if not isinstance(config, dict) or "data_sources" not in config:
                raise ValueError("Configuration file must include a 'data_sources' key.")
            return config
    except Exception as e:
        log_event(
            event_id=997,
            solution_name="inopli_monitor",
            data_source="config_loader",
            class_name="ConfigLoader",
            method="load_legacy_sources_config",
            event_type="error",
            description=str(e)
        )
        return {"data_sources": []}
