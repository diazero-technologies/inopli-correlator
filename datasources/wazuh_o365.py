# datasources/wazuh_o365.py

import os
import time
import json
from datetime import datetime

from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from utils.tenant_router import resolve_tenant


class WazuhO365Monitor:
    """
    Monitors Wazuh alerts.json for Office 365-related alerts.
    Filters by rule.id and OrganizationId, and sends matched alerts to Inopli
    with detection_rule_id included.
    """

    def __init__(self, source_name, file_path, allowed_event_types):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing {self.__class__.__name__} "
                  f"for source '{source_name}' at path '{file_path}'")

    def run(self):
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"File not found: {self.file_path}")

            with open(self.file_path, "r") as file:
                file.seek(0, os.SEEK_END)

                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    self._analyze_line(line)

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

    def _analyze_line(self, line):
        try:
            line = line.strip()
            if not line:
                return

            data = json.loads(line)

            # Must be an Office 365 integration alert
            if data.get("data", {}).get("integration") != "office365":
                return

            # Extract rule.id and convert to int
            rule_obj = data.get("rule", {})
            rule_id_str = rule_obj.get("id")
            if not rule_id_str:
                return

            try:
                rule_id = int(rule_id_str)
            except ValueError:
                return

            # Check if this rule is allowed
            if rule_id not in self.allowed_event_types:
                return

            # Get OrganizationId
            org_id = data.get("data", {}).get("office365", {}).get("OrganizationId")
            if not org_id:
                return

            # Add detection_rule_id and source
            payload = data
            payload["detection_rule_id"] = rule_id
            payload["source"] = self.source_name

            if DEBUG_MODE:
                print(f"[DEBUG] WazuhO365Monitor payload: {payload}")

            tenant_id, token = resolve_tenant(payload, self.source_name, rule_id)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for OrganizationId={org_id}")
                return

            if DEBUG_MODE:
                print(f"[ALERT] Sending Office 365 alert to tenant {tenant_id}")
            send_to_inopli(payload, token_override=token)

        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="_analyze_line",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}._analyze_line(): {e}")
