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
    Filters events by configured rule.id values (and optionally by agent_ids),
    then sends matching alerts to Inopli, appending detection_rule_id to the payload.
    """

    def __init__(self, source_name, file_path, allowed_event_types, agent_ids=None):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types
        # se "*" estiver na lista, coleta todos os agentes sem filtro
        self.agent_ids = agent_ids or []
        self.collect_all = "*" in self.agent_ids

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing {self.__class__.__name__} "
                  f"for source '{source_name}' at path '{file_path}' "
                  f"with agent_ids={self.agent_ids!r}")

    def run(self):
        """
        Executes a continuous tail -f loop on the alerts.json file.
        """
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"File not found: {self.file_path}")

            with open(self.file_path, "r") as file:
                file.seek(0, os.SEEK_END)  # Move to EOF to simulate tail -f

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
        """
        Processes a single JSON line from alerts.json:
        - Optionally filters by agent_id (unless collect_all is True)
        - Extracts rule.id and converts it to int
        - Checks if it is in the list of allowed_event_types
        - Adds detection_rule_id to the payload
        - Resolves the tenant and sends the alert to Inopli
        """
        try:
            data = json.loads(line)

            # --- FILTRO DE AGENT_ID (wildcard support) ---
            agent_id = data.get("agent", {}).get("id")
            if not self.collect_all and agent_id not in self.agent_ids:
                return
            # ----------------------------------------------

            rule_obj = data.get("rule", {})
            rule_id_str = rule_obj.get("id")
            if not rule_id_str:
                return

            try:
                rule_id = int(rule_id_str)
            except ValueError:
                return

            if rule_id not in self.allowed_event_types:
                return

            payload = data
            payload["detection_rule_id"] = rule_id
            payload["source"] = self.source_name  # Ensure correct source is set

            if DEBUG_MODE:
                print(f"[DEBUG] WazuhFileMonitor payload: {payload}")

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
                method="_analyze_line",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}._analyze_line(): {e}")
