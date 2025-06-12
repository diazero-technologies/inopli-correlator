import os
import time
import threading
import importlib

from utils.config_loader import load_multi_tenant_config

# Path para o arquivo unificado de configuração multi-tenant
CONFIG_PATH = "config/sources_config.yaml"

# Carrega configuração de tenants
tenants = load_multi_tenant_config(path=CONFIG_PATH)
print(f"[INFO] Loaded tenants: {list(tenants.keys())} from {CONFIG_PATH}")


def load_monitor(source):
    """
    Carrega dinamicamente e instancia o monitor
    para a fonte passada em `source`.
    """
    try:
        module_key = source.get("module", source["name"])
        mod = importlib.import_module(f"datasources.{module_key}")
        cls_name = ''.join(p.capitalize() for p in module_key.split('_')) + "Monitor"
        monitor_cls = getattr(mod, cls_name)

        # Prepara argumentos de inicialização, incluindo filtros (agent_ids, org_ids, etc.)
        init_kwargs = {
            "source_name": source["name"],
            "file_path": source["path"],
            "allowed_event_types": source.get("event_types", [])
        }
        # Aplica filtros genéricos definidos em 'filters'
        for filter_key, filter_val in source.get("filters", {}).items():
            init_kwargs[filter_key] = filter_val

        inst = monitor_cls(**init_kwargs)
        print(f"[DEBUG] Instantiated monitor for '{source['name']}'")
        return inst

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
        print(f"[ERROR] Could not load monitor for '{source.get('name')}': {e}")
        return None


def main():
    if not tenants:
        print(f"[ERROR] No tenants configured in {CONFIG_PATH}. Exiting.")
        return

    # 1) Agrega todas as fontes habilitadas e une event_types e filtros
    aggregated = {}
    for tenant_id, td in tenants.items():
        for ds_conf in td.get("data_sources", []) or []:
            if not ds_conf.get("enabled", False):
                continue

            src_name = ds_conf.get("name")
            if not src_name:
                continue

            if src_name not in aggregated:
                # inicia com event_types e filtros (como sets)
                aggregated[src_name] = {
                    "name": src_name,
                    "path": ds_conf.get("path"),
                    "module": ds_conf.get("module", src_name),
                    "event_types": set(ds_conf.get("event_types", [])),
                    "filters": {k: set(v) for k, v in ds_conf.get("filters", {}).items()}
                }
            else:
                aggregated[src_name]["event_types"].update(ds_conf.get("event_types", []))
                # mescla filtros de forma genérica
                for k, v in ds_conf.get("filters", {}).items():
                    if k not in aggregated[src_name]["filters"]:
                        aggregated[src_name]["filters"][k] = set(v)
                    else:
                        aggregated[src_name]["filters"][k].update(v)

    if not aggregated:
        print("[ERROR] No enabled data sources found across tenants. Exiting.")
        return

    # 2) Converte sets de volta para listas
    for src in aggregated.values():
        src["event_types"] = list(src["event_types"])
        for k, v in src.get("filters", {}).items():
            src["filters"][k] = list(v)

    print(f"[INFO] Aggregated data sources: {list(aggregated.keys())}")

    # 3) Instancia um monitor por fonte
    monitors = []
    for src in aggregated.values():
        m = load_monitor(src)
        if m:
            monitors.append(m)

    if not monitors:
        print("[ERROR] No monitors instantiated. Check configuration.")
        return

    # 4) Roda cada monitor em sua própria thread
    print(f"[INFO] Starting {len(monitors)} monitor thread(s)...")
    for m in monitors:
        t = threading.Thread(target=m.run, daemon=True)
        print(f"[INFO] Starting thread for: {m.source_name}")
        t.start()

    # 5) Mantém o processo vivo
    print("[INFO] Inopli correlator running indefinitely. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("[INFO] Shutdown requested. Exiting.")


if __name__ == "__main__":
    main()
