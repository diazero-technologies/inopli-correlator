# inopli_correlator.py

import time
import importlib
from utils.config_loader import load_config
from utils.event_logger import log_event

CONFIG_PATH = "config/sources_config.yaml"

def load_monitor(source):
    try:
        # Support `module` override to allow shared implementation with different logical names
        module_key = source.get("module", source["name"])
        module_name = f"datasources.{module_key}"
        module = importlib.import_module(module_name)

        class_name = ''.join([part.capitalize() for part in module_key.split('_')]) + "Monitor"
        monitor_class = getattr(module, class_name)

        return monitor_class(
            source_name=source["name"],
            file_path=source["path"],
            allowed_event_types=source["event_types"]
        )

    except Exception as e:
        log_event(
            event_id=994,
            solution_name="inopli_monitor",
            data_source=source.get("name", "unknown"),
            class_name="DynamicLoader",
            method="load_monitor",
            event_type="error",
            description=str(e)
        )
        return None

def main():
    config = load_config(CONFIG_PATH)
    monitors = []

    for source in config.get("data_sources", []):
        if not source.get("enabled", False):
            continue

        monitor = load_monitor(source)
        if monitor:
            monitors.append(monitor)

    while True:
        for monitor in monitors:
            monitor.run()
        time.sleep(1)

if __name__ == "__main__":
    main()

