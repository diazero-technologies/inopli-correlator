# datasources/crowdstrike.py

import os
import time
import json
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from utils.tenant_router import resolve_tenant

class CrowdstrikeMonitor:
    DETECTION_MAP = {
        "NGAV": (111171, "low", "Anomalies Detected by NGAV - Crowdstrike"),
        "Known Malware": (111172, "medium", "Known Malware Detected - CrowdStrike"),
        "Privilege Escalation": (111175, "high", "Privilege Escalation Attempt Detected - CrowdStrike"),
        "Suspicious Activity": (111176, "medium", "Suspicious Activity Detected - Crowdstrike"),
        "Ransomware": (111177, "critical", "Ransomware Detected - Crowdstrike"),
        "Evade Detection": (111178, "medium", "Defense Evasion Detected - CrowdStrike"),
        "Blocked Hash": (111179, "medium", "Activity Blocked by Hash - CrowdStrike"),
        "Blocked Exploit": (111180, "critical", "Exploit Detected and Blocked - CrowdStrike"),
        "Establish Persistence": (111181, "medium", "Persistence Mechanism Detected - CrowdStrike"),
        "Social Engineering": (111182, "medium", "Social Engineering Detected - CrowdStrike"),
    }

    def __init__(self, source_name, file_path, allowed_event_types):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing CrowdstrikeMonitor for {source_name} at {file_path}")

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
                print(f"[ERROR] Exception in CrowdstrikeMonitor.run(): {e}")

    def _analyze_line(self, line):
        try:
            data = json.loads(line)
            event = data.get("event", {})
            detect_name = event.get("DetectName")

            if not detect_name or detect_name not in self.DETECTION_MAP:
                return

            rule_id, severity, message = self.DETECTION_MAP[detect_name]

            # Skip if rule not allowed
            if rule_id not in self.allowed_event_types:
                return

            timestamp = datetime.utcnow().isoformat()
            # Build payload
            payload = {
                "detection_rule_id": rule_id,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": detect_name.lower().replace(" ", "_"),
                "severity": severity,
                "timestamp": timestamp,
                "hostname": event.get("ComputerName"),
                "ip": event.get("LocalIP"),
                "user": event.get("UserName"),
                "command": event.get("CommandLine"),
                "file": event.get("FileName"),
                "sensor_id": event.get("SensorId"),
                "raw_event": line.strip(),
                "message": message
            }

            if DEBUG_MODE:
                print(f"[DEBUG] Generated Crowdstrike payload: {payload}")

            # Resolve tenant and token
            tenant_id, token = resolve_tenant(payload, self.source_name, rule_id)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for payload: {payload}")
                return

            if DEBUG_MODE:
                print(f"[ALERT] Sending Crowdstrike alert to tenant {tenant_id}")
            # Send with tenant-specific token
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
                print(f"[ERROR] Failed to process line: {e}")
