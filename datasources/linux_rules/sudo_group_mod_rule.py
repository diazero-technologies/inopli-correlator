import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class SudoGroupModificationRule:
    """
    Detects modification of the sudo group.
    Integrates multi-tenant routing.
    """
    ID = 1004
    TYPE = "sudo_group_modification"
    SEVERITY = "high"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types
        # hostname and resolve_tenant will be injected by the monitor

    def analyze_line(self, line):
        try:
            # Pattern for appending to sudo group
            if not re.search(r'usermod .* -a ?-G sudo', line):
                return

            # Check if this rule is allowed
            if self.ID not in self.allowed_event_types:
                return

            # Extract username from parts
            parts = line.strip().split()
            username = None
            if 'usermod' in parts:
                idx = parts.index('usermod') + 1
                if idx < len(parts):
                    username = parts[idx]

            timestamp_str = datetime.utcnow().isoformat()

            payload = {
                "detection_rule_id": self.ID,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp_str,
                "username": username,
                "raw_event": line.strip(),
                "message": f"User {username} added to sudo group"
            }

            # Include hostname if provided
            if hasattr(self, 'hostname'):
                payload['hostname'] = self.hostname

            # Determine tenant and token
            tenant_id, token = self.resolve_tenant(payload, self.source_name, self.ID)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for payload: {payload}")
                return

            if DEBUG_MODE:
                print(f"[ALERT] Sending sudo group modification alert to tenant {tenant_id}")
            send_to_inopli(payload, token_override=token)

        except Exception as e:
            log_event(
                999,
                "inopli_monitor",
                self.source_name,
                self.__class__.__name__,
                "analyze_line",
                "error",
                str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {e}")
