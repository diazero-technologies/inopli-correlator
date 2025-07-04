# utils/webhook_sender.py

import os
import requests
from config.debug import DEBUG_MODE

def send_to_inopli(payload, token_override=None):
    url = os.environ.get("INOPLI_WEBHOOK_URL", "https://api.inopli.com/alerts")
    token = token_override or os.environ.get("INOPLI_TOKEN")
    if not token:
        raise ValueError("No Inopli token provided.")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        import json
        data = json.dumps(payload)
        verify_ssl = not DEBUG_MODE
        resp = requests.post(url, headers=headers, data=data, timeout=15, verify=verify_ssl)
        resp.raise_for_status()
        if DEBUG_MODE:
            print(f"[INFO] Sent alert to Inopli: {resp.status_code}")
        return resp.json() if resp.content else None
    except Exception as e:
        if DEBUG_MODE:
            print(f"[ERROR] Failed to send alert to Inopli: {e}")
        raise