"""
Smoke / manual test for DatadogConnector.

Reads the Datadog source configuration from config/sources_config.yaml
(first 'datadog' siem_source found), connects to the Datadog API,
fetches triggered monitors, and prints the first 50 to the console.

Credentials can be overridden via environment variables:
  DD_API_KEY   – Datadog API key
  DD_APP_KEY   – Datadog application key
  DD_BASE_URL  – Datadog API base URL (default: https://api.datadoghq.com)

Usage (from repo root):
  python tests/test_datadog_fetch.py

Optional flags:
  --all-states   Fetch monitors regardless of overall_state (not just Alert/Warn)
  --source NAME  Use a specific siem_source name from the YAML config
  --limit N      Override the maximum number of alerts to print (default: 50)
"""

import sys
import os
import json
import yaml
import argparse
from datetime import datetime

# Allow imports from the project root when run directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from middleware.connectors.datadog_connector import DatadogConnector


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "sources_config.yaml")


def load_datadog_source(source_name: str = None):
    """
    Returns (source_key, source_config, tenant_id) for the first datadog
    siem_source found in sources_config.yaml, or the one matching source_name.
    """
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    tenants = config.get("tenants", {})
    for tenant_id, tenant_data in tenants.items():
        siem_sources = tenant_data.get("siem_sources", {})
        for src_key, src_config in siem_sources.items():
            connector_type = src_config.get("connector_type", src_key.split("_")[0])
            if connector_type != "datadog":
                continue
            if source_name and src_key != source_name:
                continue
            return src_key, src_config, tenant_id

    raise ValueError(
        "No datadog siem_source found in config. "
        "Add a datadog_prod entry under tenants.<id>.siem_sources and set connector_type: datadog."
    )


def build_connector_config(src_key, src_config, tenant_id, all_states: bool) -> dict:
    """Build the connector_config dict that MiddlewareManager would normally pass."""
    api_cfg = dict(src_config.get("api_config", {}))

    # Allow credential overrides via environment variables
    if os.environ.get("DD_API_KEY"):
        api_cfg["api_key"] = os.environ["DD_API_KEY"]
    if os.environ.get("DD_APP_KEY"):
        api_cfg["app_key"] = os.environ["DD_APP_KEY"]
    if os.environ.get("DD_BASE_URL"):
        api_cfg["base_url"] = os.environ["DD_BASE_URL"]

    alert_states = (
        ["Alert", "Warn", "No Data", "OK", "Skipped", "Unknown", "Ignored"]
        if all_states
        else src_config.get("alert_states", ["Alert", "Warn"])
    )

    return {
        "enabled": True,
        "polling_interval": src_config.get("polling_interval", 5),
        "api_config": api_cfg,
        # Disable state persistence – this is a read-only smoke test
        "collection_control": {
            "save_state": False,
            "state_file_path": src_config.get("collection_control", {}).get(
                "state_file_path", f"config/datadog_{src_key}_state.json"
            ),
        },
        "alert_states": alert_states,
        "batch_size": src_config.get("batch_size", 100),
        "rule_filters": src_config.get("rule_filters", {}),
        "tenant_id": tenant_id,
        "tenant_config": {},
    }


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

SEVERITY_LABELS = {1: "LOW", 2: "LOW-MEDIUM", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}


def format_alert(idx: int, alert: dict) -> str:
    sep = "-" * 72
    lines = [
        sep,
        f"  Alert #{idx + 1}",
        sep,
        f"  Monitor ID   : {alert.get('id', 'N/A')}",
        f"  Name         : {alert.get('name', 'N/A')}",
        f"  State        : {alert.get('overall_state', 'N/A')}",
        f"  Severity     : {alert.get('severity', 'N/A')} "
        f"({SEVERITY_LABELS.get(alert.get('severity'), '?')})",
        f"  Type         : {alert.get('type', 'N/A')}",
        f"  Tags         : {', '.join(alert.get('tags', [])) or 'none'}",
        f"  Timestamp    : {alert.get('timestamp', 'N/A')}",
        f"  Rule ID      : {alert.get('detection_rule_id', 'N/A')}",
    ]

    # Triggered groups
    groups = alert.get("triggered_groups", [])
    if groups:
        lines.append(f"  Groups ({len(groups)})  :")
        for g in groups:
            ts = g.get("last_triggered_ts")
            ts_str = (
                datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
                if ts
                else "N/A"
            )
            lines.append(
                f"    • {g.get('group', '?')}  [{g.get('status', '?')}]  triggered: {ts_str}"
            )

    # Message (truncated)
    msg = (alert.get("message") or "").strip()
    if msg:
        preview = msg[:120].replace("\n", " ")
        lines.append(f"  Message      : {preview}{'…' if len(msg) > 120 else ''}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Datadog connector smoke test")
    parser.add_argument(
        "--all-states",
        action="store_true",
        help="Fetch monitors regardless of overall_state (not just Alert/Warn)",
    )
    parser.add_argument(
        "--source",
        metavar="NAME",
        default=None,
        help="Specific siem_source key in the YAML (e.g. datadog_prod)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of alerts to print (default: 50)",
    )
    args = parser.parse_args()

    print("=" * 72)
    print("  Datadog Connector – Smoke Test")
    print("=" * 72)

    # 1. Load config
    try:
        src_key, src_config, tenant_id = load_datadog_source(args.source)
    except (FileNotFoundError, ValueError) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    print(f"\n  Source   : {src_key}")
    print(f"  Tenant   : {tenant_id}")

    connector_config = build_connector_config(
        src_key, src_config, tenant_id, args.all_states
    )

    api_cfg = connector_config["api_config"]
    base_url = api_cfg.get("base_url", "https://api.datadoghq.com")
    api_key_preview = (api_cfg.get("api_key", "") or "")[:6] or "(not set)"
    app_key_preview = (api_cfg.get("app_key", "") or "")[:6] or "(not set)"

    print(f"  Base URL : {base_url}")
    print(f"  API Key  : {api_key_preview}… (first 6 chars)")
    print(f"  App Key  : {app_key_preview}… (first 6 chars)")
    print(f"  States   : {connector_config['alert_states']}")
    print(f"  Limit    : {args.limit}")
    print()

    # 2. Instantiate connector
    connector = DatadogConnector(src_key, connector_config)

    # Force empty state so deduplication does not hide currently-alerting monitors
    connector.monitor_state = {}

    # 3. Connect (credential validation)
    print("  [1/2] Validating credentials …")
    if not connector.connect():
        print("\n[ERROR] Connection failed. Check api_key / app_key / base_url.")
        print(
            "        You can override them with env vars DD_API_KEY, DD_APP_KEY, DD_BASE_URL."
        )
        sys.exit(1)
    print("  [1/2] Credentials OK.\n")

    # 4. Collect alerts
    print("  [2/2] Fetching triggered monitors …")
    alerts = connector.collect_alerts()
    total = len(alerts)
    print(f"  [2/2] Fetched {total} triggered monitor(s).\n")

    if not alerts:
        print("  No triggered monitors found.")
        if not args.all_states:
            print(
                "  Tip: run with --all-states to see monitors in any state."
            )
        sys.exit(0)

    # 5. Print first N
    to_print = alerts[: args.limit]
    print(f"  Showing {len(to_print)} of {total} alert(s):\n")

    for idx, alert in enumerate(to_print):
        print(format_alert(idx, alert))
    print("-" * 72)

    if total > args.limit:
        print(f"\n  … and {total - args.limit} more (use --limit N to see more).")

    print(f"\n  Done. {len(to_print)} alert(s) printed.")


if __name__ == "__main__":
    main()
