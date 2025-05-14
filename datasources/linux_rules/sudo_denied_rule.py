# datasources/linux_rules/sudo_denied_rule.py

import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class SudoDeniedRule:
    """
    Detects attempts to run sudo by users not listed in the sudoers file.
    """

    detection_rule_id = 1003
    TYPE = "sudo_denied"
    SEVERITY = "medium"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types

    def analyze_line(self, line):
        try:
            if not re.search(r'user .*not in sudoers', line, re.IGNORECASE):
                return

            if self.detection_rule_id not in self.allowed_event_types:
                if DEBUG_MODE:
                    print(f"[DEBUG] Rule {self.__class__.__name__} skipped due to event type config.")
                return

            timestamp_str = datetime.utcnow().isoformat()
            user = self._extract_user(line)
            ip = self._extract_ip(line)
            log_line = line.strip()

            payload = {
                "detection_rule_id": self.detection_rule_id,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp_str,
                "ip": ip,
                "username": user,
                "raw_event": log_line,
                "message": f"Sudo denied attempt by user '{user}'"
            }

            if DEBUG_MODE:
                print(f"[ALERT] Sending payload: {payload}")
            send_to_inopli(payload)

        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="analyze_line",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {e}")

    def _extract_user(self, line):
        match = re.search(r'sudo: (\w+)', line)
        if match:
            if DEBUG_MODE:
                print(f"[DEBUG] Extracted username: {match.group(1)}")
            return match.group(1)
        if DEBUG_MODE:
            print("[DEBUG] Failed to extract username.")
        return "unknown"

    def _extract_ip(self, line):
        match = re.search(r'from ([\d\.]+)', line)
        if match:
            if DEBUG_MODE:
                print(f"[DEBUG] Extracted IP: {match.group(1)}")
            return match.group(1)
        return "unknown"
