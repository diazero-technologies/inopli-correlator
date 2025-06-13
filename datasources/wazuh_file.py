# datasources/wazuh_file.py

import os
import time
import json
from datetime import datetime

from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from utils.tenant_router import resolve_tenant


class WazuhFileMonitor:
    """
    Monitors the Wazuh alerts.json file using tail -f logic.
    Supports wildcard filtering on agent_ids.
    """

    def __init__(self, source_name, file_path, allowed_event_types, agent_ids=None):
        self.source_name         = source_name
        self.file_path           = file_path
        self.allowed_event_types = allowed_event_types
        self.agent_ids           = agent_ids or []
        self.collect_all         = "*" in self.agent_ids

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing {self.__class__.__name__} "
                  f"for source '{source_name}' at path '{file_path}' "
                  f"with agent_ids={self.agent_ids!r}")

    def run(self):
        """
        Tails the alerts.json file, assembles possibly multi-line JSON records
        and processes each complete JSON object as one event.
        """
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"File not found: {self.file_path}")

            with open(self.file_path, "r") as f:
                f.seek(0, os.SEEK_END)
                buffer = ""
                while True:
                    chunk = f.readline()
                    if not chunk:
                        time.sleep(0.5)
                        continue

                    buffer += chunk
                    try:
                        # Try to parse a full JSON object from the buffer
                        event = json.loads(buffer)
                    except json.JSONDecodeError:
                        # Incomplete JSON: read another line
                        continue

                    # Successfully parsed one event
                    buffer = ""
                    self._handle_event(event)

        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="run",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}.run(): {e}")

    def _handle_event(self, event):
        """
        Applies filtering and, if matched, sends the event to Inopli.
        """
        try:
            # --- agent_id filter with wildcard support ---
            agent = event.get("agent", {}) or {}
            agent_id = agent.get("id")
            if not self.collect_all and agent_id not in self.agent_ids:
                return

            # Extract and validate rule ID
            rule_obj    = event.get("rule", {})
            rule_id_str = rule_obj.get("id")
            if not rule_id_str:
                return
            try:
                rule_id = int(rule_id_str)
            except ValueError:
                return

            # Filter by allowed_event_types
            if rule_id not in self.allowed_event_types:
                return

            # Prepare payload
            payload = event
            payload["detection_rule_id"] = rule_id
            payload["source"]            = self.source_name

            if DEBUG_MODE:
                print(f"[DEBUG] WazuhFileMonitor payload: {payload}")

            # Resolve tenant and send
            tenant_id, token = resolve_tenant(payload, self.source_name, rule_id)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for rule_id={rule_id}")
                return

            if DEBUG_MODE:
                print(f"[ALERT] Sending alert to tenant {tenant_id}")
            send_to_inopli(payload, token_override=token)

        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="_handle_event",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}._handle_event(): {e}")
