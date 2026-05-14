"""
Smoke / manual test for the Datadog integration.

Reads credentials from config/sources_config.yaml (first 'datadog'
siem_source found) and calls GET /api/v1/monitor directly, printing
the first N monitors with no state filtering — any monitor that exists
in the account is shown.

Credentials can be overridden via environment variables:
  DD_API_KEY   – Datadog API key
  DD_APP_KEY   – Datadog application key
  DD_BASE_URL  – Datadog API base URL (default: https://api.datadoghq.com)

Usage (from repo root):
  python tests/test_datadog_fetch.py

Optional flags:
  --source NAME  Use a specific siem_source name from the YAML config
  --limit N      Number of monitors to fetch and print (default: 50)
"""

import sys
import os
import json
import yaml
import argparse
import requests
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "sources_config.yaml")


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_api_config(source_name: str = None) -> dict:
    """
    Returns the api_config dict for the first datadog siem_source found
    in sources_config.yaml (or the one matching source_name).
    """
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    for tenant_id, tenant_data in config.get("tenants", {}).items():
        for src_key, src_config in tenant_data.get("siem_sources", {}).items():
            connector_type = src_config.get("connector_type", src_key.split("_")[0])
            if connector_type != "datadog":
                continue
            if source_name and src_key != source_name:
                continue
            api_cfg = dict(src_config.get("api_config", {}))
            return src_key, api_cfg

    raise ValueError(
        "No datadog siem_source found in config/sources_config.yaml.\n"
        "Add a siem_source with connector_type: datadog under any tenant."
    )


def resolve_credentials(api_cfg: dict) -> dict:
    """Apply environment variable overrides on top of YAML values."""
    cfg = dict(api_cfg)
    if os.environ.get("DD_API_KEY"):
        cfg["api_key"] = os.environ["DD_API_KEY"]
    if os.environ.get("DD_APP_KEY"):
        cfg["app_key"] = os.environ["DD_APP_KEY"]
    if os.environ.get("DD_BASE_URL"):
        cfg["base_url"] = os.environ["DD_BASE_URL"]
    cfg.setdefault("base_url", "https://api.datadoghq.com")
    return cfg


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def validate_credentials(base_url: str, headers: dict) -> bool:
    try:
        r = requests.get(f"{base_url}/api/v1/validate", headers=headers, timeout=10)
        return r.status_code == 200
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def fetch_monitors(base_url: str, headers: dict, limit: int) -> list:
    """
    Fetches up to `limit` monitors from GET /api/v1/monitor with no
    state filter — returns raw Datadog monitor dicts.
    """
    monitors = []
    page = 0
    page_size = min(limit, 100)   # Datadog max page_size is 100

    while len(monitors) < limit:
        remaining = limit - len(monitors)
        params = {
            "page": page,
            "page_size": min(page_size, remaining),
            "with_downtimes": False,
        }
        try:
            r = requests.get(
                f"{base_url}/api/v1/monitor",
                headers=headers,
                params=params,
                timeout=30,
            )
        except Exception as e:
            print(f"[ERROR] Request failed on page {page}: {e}")
            break

        if r.status_code == 429:
            retry = int(r.headers.get("X-RateLimit-Reset", 60))
            print(f"[WARN] Rate limited. Waiting {retry}s …")
            import time
            time.sleep(retry)
            continue

        if r.status_code != 200:
            print(f"[ERROR] HTTP {r.status_code}: {r.text[:300]}")
            break

        batch = r.json()
        if not batch:
            break

        monitors.extend(batch)
        if len(batch) < params["page_size"]:
            break   # Last page

        page += 1

    return monitors[:limit]


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------

def format_monitor(idx: int, m: dict) -> str:
    sep = "-" * 72
    header = [
        sep,
        f"  Monitor #{idx + 1}  —  ID: {m.get('id', 'N/A')}  |  State: {m.get('overall_state', 'N/A')}  |  {m.get('name', 'N/A')}",
        sep,
    ]
    body = json.dumps(m, indent=2, default=str)
    return "\n".join(header) + "\n" + body


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Datadog smoke test – fetch any monitors")
    parser.add_argument("--source", metavar="NAME", default=None,
                        help="Specific siem_source key in the YAML (e.g. datadog_prod)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Number of monitors to fetch (default: 50)")
    args = parser.parse_args()

    print("=" * 72)
    print("  Datadog – Monitor Fetch Test (no state filter)")
    print("=" * 72)

    # 1. Load config
    try:
        src_key, api_cfg = load_api_config(args.source)
    except (FileNotFoundError, ValueError) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    api_cfg = resolve_credentials(api_cfg)
    base_url = api_cfg["base_url"]

    api_key_preview = (api_cfg.get("api_key") or "")[:6] or "(not set)"
    app_key_preview = (api_cfg.get("app_key") or "")[:6] or "(not set)"

    print(f"\n  Source   : {src_key}")
    print(f"  Base URL : {base_url}")
    print(f"  API Key  : {api_key_preview}… (first 6 chars)")
    print(f"  App Key  : {app_key_preview}… (first 6 chars)")
    print(f"  Limit    : {args.limit}\n")

    headers = {
        "Accept": "application/json",
        "DD-API-KEY": api_cfg.get("api_key", ""),
        "DD-APPLICATION-KEY": api_cfg.get("app_key", ""),
    }

    # 2. Validate credentials
    print("  [1/2] Validating credentials …")
    if not validate_credentials(base_url, headers):
        print("[ERROR] Credential validation failed. Check api_key / app_key / base_url.")
        print("        Override with env vars: DD_API_KEY, DD_APP_KEY, DD_BASE_URL")
        sys.exit(1)
    print("  [1/2] OK.\n")

    # 3. Fetch monitors (no state filter)
    print(f"  [2/2] Fetching first {args.limit} monitor(s) …")
    monitors = fetch_monitors(base_url, headers, args.limit)
    print(f"  [2/2] Received {len(monitors)} monitor(s).\n")

    if not monitors:
        print("  No monitors found in this Datadog account.")
        sys.exit(0)

    # 4. Print
    print(f"  Showing {len(monitors)} monitor(s):\n")
    for idx, m in enumerate(monitors):
        print(format_monitor(idx, m))
    print("-" * 72)
    print(f"\n  Done. {len(monitors)} monitor(s) printed.")


if __name__ == "__main__":
    main()
