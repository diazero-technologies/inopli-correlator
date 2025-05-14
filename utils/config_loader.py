# utils/config_loader.py

import yaml
from utils.event_logger import log_event

def load_config(path):
    """
    Loads the YAML configuration file containing monitored data sources.
    If an error occurs, logs the failure and returns an empty structure.
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
            method="load_config",
            event_type="error",
            description=str(e)
        )
        return {"data_sources": []}
