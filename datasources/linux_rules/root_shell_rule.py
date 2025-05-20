import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class RootShellExecutionRule:
    """
    Detects attempts to open a root shell using patterns like 'su', 'sudo su', 'sudo -i', or 'sudo bash'.
    Integrates multi-tenant routing.
    """
    ID = 1005
    TYPE = "root_shell_execution"
    SEVERITY = "critical"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types
        # hostname and resolve_tenant will be injected by the monitor

    def analyze_line(self, line):
        try:
            if not self._matches_root_shell_pattern(line):
                return

            # Ensure rule is enabled for this monitor
            if self.ID not in self.allowed_event_types:
                return

            timestamp = datetime.utcnow().isoformat()
            user = self._extract_user(line)
            command = self._extract_command(line)
            log_line = line.strip()

            payload = {
                "detection_rule_id": self.ID,
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

            # Attach hostname for filtering
            if hasattr(self, 'hostname'):
                payload['hostname'] = self.hostname

            # Resolve tenant and token based on payload
            tenant_id, token = self.resolve_tenant(payload, self.source_name, self.ID)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for payload: {payload}")
                return

            if DEBUG_MODE:
                print(f"[ALERT] Sending root shell payload to tenant {tenant_id}")
            send_to_inopli(payload, token_override=token)

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
        return "unknown"
