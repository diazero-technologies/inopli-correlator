# utils/webhook_sender.py

import os
import requests
import json
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

WEBHOOK_URL = "https://api.inopli.com/send"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0 inopli-monitor"
TOKEN_ENV_VAR = "MS_TOKEN"
REQUEST_TIMEOUT = 15  # seconds


def send_to_inopli(payload, token_override=None):
    """
    Sends a JSON payload to the Inopli webhook using the requests library.
    Allows overriding the default token via `token_override` for multi-tenant support.
    """
    try:
        # Determine token: override > env
        token = token_override or os.environ.get(TOKEN_ENV_VAR)
        if not token:
            raise EnvironmentError(f"Missing environment variable: '{TOKEN_ENV_VAR}' and no override token provided")

        # Validate payload
        if "detection_rule_id" not in payload:
            raise ValueError("Payload must include 'detection_rule_id' key.")
        if "timestamp" not in payload:
            raise ValueError("Payload must include 'timestamp' key in ISO format.")

        headers = {
            "MS-TOKEN": token,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json"
        }

        # In debug mode, we don't verify SSL certs (for local/dev servers with self-signed certs)
        should_verify_ssl = not DEBUG_MODE

        if DEBUG_MODE:
            print(f"[DEBUG] Sending webhook to {WEBHOOK_URL} (SSL Verify: {should_verify_ssl})")
            print(f"[DEBUG] Payload: {json.dumps(payload)}")

        response = requests.post(
            WEBHOOK_URL,
            json=payload,
            headers=headers,
            verify=should_verify_ssl,
            timeout=REQUEST_TIMEOUT
        )

        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status()

        if DEBUG_MODE:
            print(f"[DEBUG] Webhook response status: {response.status_code}")
            print(f"[DEBUG] Webhook response body: {response.text}")

        # Log success
        log_event(
            event_id=1001,
            solution_name="inopli_monitor",
            data_source=payload.get("source", "unknown"),
            class_name="WebhookSender",
            method="send_to_inopli",
            event_type="info",
            description=f"Alert sent successfully for rule {payload.get('detection_rule_id')}"
        )

    except requests.exceptions.RequestException as e:
        # This catches connection errors, timeouts, HTTP errors, etc.
        log_event(
            event_id=998,
            solution_name="inopli_monitor",
            data_source=payload.get("source", "unknown"),
            class_name="WebhookSender",
            method="send_to_inopli",
            event_type="error",
            description=f"Request failed: {e}"
        )
        if DEBUG_MODE:
            print(f"[ERROR] WebhookSender request failed: {e}")

    except Exception as e:
        # Log other failures (e.g., validation)
        log_event(
            event_id=998,
            solution_name="inopli_monitor",
            data_source=payload.get("source", "unknown"),
            class_name="WebhookSender",
            method="send_to_inopli",
            event_type="error",
            description=str(e)
        )
        if DEBUG_MODE:
            print(f"[ERROR] WebhookSender failed: {e}")