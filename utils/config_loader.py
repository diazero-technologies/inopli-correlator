import yaml
from utils.event_logger import log_event


def load_multi_tenant_config(path="config/sources_config.yaml"):
    """
    Loads the YAML configuration containing multi-tenant settings,
    where each tenant defines a list of data_sources with name, path, module, event_types, and filters.
    Returns a dict mapping tenant_id to its configuration.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            tenants = config.get("tenants")
            if not isinstance(tenants, dict):
                raise ValueError("Configuration file must include a 'tenants' mapping.")
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
    (Optional) Legacy loader for single-tenant per-data-source configuration.
    Returns a dict with key 'data_sources', compatible with older code paths.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
            if not isinstance(cfg, dict) or "data_sources" not in cfg:
                raise ValueError("Configuration file must include a 'data_sources' key.")
            return cfg
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
