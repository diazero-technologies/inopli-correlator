# datasources/linux_rules/root_shell_rule.py

import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class RootShellExecutionRule:
    """
    Detects attempts to open a root shell using 'su', 'sudo su', 'sudo -i', or 'sudo bash'.
    """

    detection_rule_id = 1005
    TYPE = "root_shell_execution"
    SEVERITY = "critical"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types

    def analyze_line(self, line):
        try:
            if not self._matches_root_shell_pattern(line):
                return

            if self.detection_rule_id not in self.allowed_event_types:
                return

            timestamp = datetime.utcnow().isoformat()
            user = self._extract_user(line)
            command = self._extract_command(line)
            log_line = line.strip()

            payload = {
                "detection_rule_id": self.detection_rule_id,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "username": user,
                "command": command,
                "raw_event": log_line,
                "message": f"Root shell execution detected: user '{user}' ran '{command}'"
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

    def _matches_root_shell_pattern(self, line):
        patterns = [
            r'sudo: .* : .*USER=root.*COMMAND=(/bin/bash|/bin/sh|/bin/zsh)',
            r'sudo: .* : .*COMMAND=/bin/su',
            r'su\[\d+\]: Successful su for root by \w+'
        ]
        for pattern in patterns:
            if re.search(pattern, line):
                if DEBUG_MODE:
                    print(f"[DEBUG] Matched root shell pattern: {pattern}")
                return True
        return False

    def _extract_user(self, line):
        match = re.search(r'sudo: (\w+)', line)
        if match:
            return match.group(1)
        match = re.search(r'for root by (\w+)', line)
        if match:
            return match.group(1)
        if DEBUG_MODE:
            print("[DEBUG] Could not extract username from line")
        return "unknown"

    def _extract_command(self, line):
        match = re.search(r'COMMAND=(.*)', line)
        if match:
            return match.group(1)
        return "su"

