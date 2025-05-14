# datasources/linux_rules/ssh_key_injection_rule.py

import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class SshKeyInjectionRule:
    """
    Detects potential SSH key injection attempts into authorized_keys files.
    """

    detection_rule_id = 1007
    TYPE = "ssh_key_injection"
    SEVERITY = "high"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types

    def analyze_line(self, line):
        try:
            if not self._matches_ssh_key_injection(line):
                return

            if self.detection_rule_id not in self.allowed_event_types:
                if DEBUG_MODE:
                    print(f"[DEBUG] Rule {self.__class__.__name__} skipped due to config.")
                return

            timestamp = datetime.utcnow().isoformat()
            log_line = line.strip()
            user = self._extract_user(line)

            payload = {
                "detection_rule_id": self.detection_rule_id,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "username": user,
                "raw_event": log_line,
                "message": f"Potential SSH key injection by user '{user}'"
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

    def _matches_ssh_key_injection(self, line):
        patterns = [
            r'COMMAND=.*>>.*authorized_keys',
            r'COMMAND=.*tee\s+-a\s+.*/authorized_keys',
            r'COMMAND=.*cat.*>>.*authorized_keys',
            r'COMMAND=.*scp.*authorized_keys',
            r'COMMAND=.*rsync.*authorized_keys'
        ]
        for pattern in patterns:
            if re.search(pattern, line):
                if DEBUG_MODE:
                    print(f"[DEBUG] Matched SSH key injection pattern: {pattern}")
                return True
        return False

    def _extract_user(self, line):
        match = re.search(r'sudo: +(\w+)', line)
        if match:
            return match.group(1)
        return "unknown"
