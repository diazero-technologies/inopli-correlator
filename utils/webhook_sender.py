# utils/webhook_sender.py

import os
import json
import requests
from config.debug import DEBUG_MODE


def send_to_inopli(payload, token_override=None):
    base_url = os.environ.get("INOPLI_WEBHOOK_URL", "https://api.inopli.com/send")
    token = token_override or os.environ.get("INOPLI_TOKEN")
    if not token:
        raise ValueError("No Inopli token provided.")

    # Token is sent as query parameter, as required by the Inopli API
    url = f"{base_url}?token={token}"
    headers = {"Content-Type": "application/json"}

    try:
        data = json.dumps(payload)
        resp = requests.post(url, headers=headers, data=data, timeout=15, verify=True)
        resp.raise_for_status()
        if DEBUG_MODE:
            print(f"[INFO] Sent alert to Inopli: {resp.status_code}")
        return resp.json() if resp.content else None
    except Exception as e:
        if DEBUG_MODE:
            print(f"[ERROR] Failed to send alert to Inopli: {e}")
        raise