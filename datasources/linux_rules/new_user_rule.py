# datasources/linux_rules/new_user_rule.py

import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class NewUserCreationRule:
    """
    Detects creation of new users on the system via adduser/useradd logs.
    """

    detection_rule_id = 1006
    TYPE = "new_user_creation"
    SEVERITY = "high"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types

    def analyze_line(self, line):
        try:
            if not self._matches_user_creation(line):
                return

            if self.detection_rule_id not in self.allowed_event_types:
                if DEBUG_MODE:
                    print(f"[DEBUG] Rule {self.__class__.__name__} skipped due to event type config.")
                return

            timestamp = datetime.utcnow().isoformat()
            username = self._extract_username(line)
            log_line = line.strip()

            payload = {
                "detection_rule_id": self.detection_rule_id,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "username": username,
                "raw_event": log_line,
                "message": f"New system user created: '{username}'"
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

    def _matches_user_creation(self, line):
        patterns = [
            r'useradd\[\d+\]: new user: name=',
            r'adduser\[\d+\]: added user ',
            r'new user added'
        ]
        for pattern in patterns:
            if re.search(pattern, line):
                if DEBUG_MODE:
                    print(f"[DEBUG] Matched user creation pattern: {pattern}")
                return True
        return False

    def _extract_username(self, line):
        match = re.search(r'name=([\w\-]+)', line)
        if match:
            if DEBUG_MODE:
                print(f"[DEBUG] Extracted username from useradd: {match.group(1)}")
            return match.group(1)

        match = re.search(r"added user '([\w\-]+)'", line)
        if match:
            if DEBUG_MODE:
                print(f"[DEBUG] Extracted username from adduser: {match.group(1)}")
            return match.group(1)

        if DEBUG_MODE:
            print("[DEBUG] Could not extract username from line.")
        return "unknown"
