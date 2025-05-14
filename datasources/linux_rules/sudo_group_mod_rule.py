# datasources/linux_rules/sudo_group_mod_rule.py

import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class SudoGroupModificationRule:
    """
    Detects when a user is added to the 'sudo' group.
    """

    detection_rule_id = 1004
    TYPE = "sudo_group_modification"
    SEVERITY = "high"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types

    def analyze_line(self, line):
        try:
            if not self._matches_sudo_addition(line):
                return

            if self.detection_rule_id not in self.allowed_event_types:
                return

            timestamp = datetime.utcnow().isoformat()
            user = self._extract_user(line)
            log_line = line.strip()

            payload = {
                "detection_rule_id": self.detection_rule_id,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "username": user,
                "raw_event": log_line,
                "message": f"User '{user}' was added to the 'sudo' group"
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

    def _matches_sudo_addition(self, line):
        sudo_patterns = [
            r"added user (\w+) to group sudo",
            r"user '(\w+)' added to group 'sudo'",
            r"add '(\w+)' to group 'sudo'"
        ]
        return any(re.search(pattern, line) for pattern in sudo_patterns)

    def _extract_user(self, line):
        match = re.search(r"user '?(\w+)'? added to group 'sudo'", line) or \
                re.search(r"add '(\w+)' to group 'sudo'", line) or \
                re.search(r"added user (\w+) to group sudo", line)
        if match:
            return match.group(1)
        if DEBUG_MODE:
            print("[DEBUG] Failed to extract username")
        return "unknown"
