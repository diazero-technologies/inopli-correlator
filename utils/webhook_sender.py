# utils/webhook_sender.py

import os
import subprocess
import json
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

WEBHOOK_URL = "https://gateway.inopli.com/webhook/send"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0 inopli-monitor"
TOKEN_ENV_VAR = "MS_TOKEN"

def send_to_inopli(payload):
    """
    Sends a JSON payload to the Inopli webhook using curl with required headers.
    Logs success or failure, including curl output.
    """

    try:
        token = os.environ.get(TOKEN_ENV_VAR)
        if not token:
            raise EnvironmentError(f"Missing environment variable: '{TOKEN_ENV_VAR}'")

        if "detection_rule_id" not in payload:
            raise ValueError("Payload must include 'detection_rule_id' key.")
        if "timestamp" not in payload:
            raise ValueError("Payload must include 'timestamp' key in ISO format.")

        command = [
            "curl", "--location", WEBHOOK_URL,
            "--header", f"MS-TOKEN: {token}",
            "--header", f"User-Agent: {USER_AGENT}",
            "--header", "Content-Type: application/json",
            "--data", json.dumps(payload)
        ]

        result = subprocess.run(command, capture_output=True, text=True)

        if DEBUG_MODE:
            print(f"[DEBUG] curl return code: {result.returncode}")
            print(f"[DEBUG] curl stdout: {result.stdout.strip()}")
            print(f"[DEBUG] curl stderr: {result.stderr.strip()}")

        if result.returncode != 0:
            raise RuntimeError(f"curl failed: {result.stderr.strip()}")

        log_event(
            event_id=1001,
            solution_name="inopli_monitor",
            data_source=payload.get("source", "unknown"),
            class_name="WebhookSender",
            method="send_to_inopli",
            event_type="info",
            description=f"Alert sent successfully for rule {payload.get('detection_rule_id')}"
        )

    except Exception as e:
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
