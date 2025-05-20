import time
import threading
import importlib
from utils.config_loader import load_multi_tenant_config

# Load tenants configuration globally
TENANTS_CONFIG = load_multi_tenant_config(path="config/multi_tenant_config.yaml")


def load_monitor(source):
    """
    Dynamically load and instantiate a monitor for the given source config.
    """
    try:
        module_key = source.get("module", source["name"])
        module_name = f"datasources.{module_key}"
        module = importlib.import_module(module_name)
        class_name = ''.join([part.capitalize() for part in module_key.split('_')]) + "Monitor"
        monitor_class = getattr(module, class_name)

        # Instantiate monitor with allowed rules
        return monitor_class(
            source_name=source["name"],
            file_path=source["path"],
            allowed_event_types=source.get("event_types", [])
        )
    except Exception as e:
        from utils.event_logger import log_event
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
    # Aggregate unique sources across all tenants
    aggregated = {}
    for tenant_id, tenant_data in TENANTS_CONFIG.items():
        for src_name, src_conf in tenant_data.get("data_sources", {}).items():
            if not src_conf.get("enabled", False):
                continue
            if src_name not in aggregated:
                aggregated[src_name] = {
                    "name": src_name,
                    "path": src_conf.get("path"),
                    "module": src_conf.get("module", src_name),
                    "event_types": src_conf.get("event_types", [])
                }

    # Instantiate monitors
    monitors = []
    for src in aggregated.values():
        monitor = load_monitor(src)
        if monitor:
            monitors.append(monitor)

    # Start each monitor in its own thread
    threads = []
    for monitor in monitors:
        t = threading.Thread(target=monitor.run, daemon=True)
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
