import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class SudoGroupModificationRule:
    """
    Detects users added to the sudo group via sudo usermod commands.
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
            # Debug log for incoming line
            if DEBUG_MODE:
                print(f"[DEBUG] SudoGroupModificationRule analyzing line: {line.strip()}")

            # Regex match for COMMAND containing usermod -aG sudo <user>
            match = re.search(r'COMMAND=.*usermod\s+-aG\s+sudo\s+(\w+)', line)
            if not match:
                if DEBUG_MODE:
                    print("[DEBUG] SudoGroupModificationRule: pattern not found")
                return

            # Ensure rule is enabled at monitor level
            if self.ID not in self.allowed_event_types:
                if DEBUG_MODE:
                    print(f"[DEBUG] SudoGroupModificationRule: rule {self.ID} not in allowed_event_types {self.allowed_event_types}")
                return

            # Extract executor (the user who ran sudo)
            exec_match = re.search(r'sudo:\s*(\w+)\s*:', line)
            executor = exec_match.group(1) if exec_match else "unknown"

            # Extract target_user (the one added to the group)
            target_user = match.group(1)

            # Build timestamp
            timestamp = datetime.utcnow().isoformat()

            payload = {
                "detection_rule_id": self.ID,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "executor": executor,
                "target_user": target_user,
                "raw_event": line.strip(),
                "message": f"User '{target_user}' added to sudo group by '{executor}'"
            }

            # Include hostname for tenant filtering if available
            if hasattr(self, 'hostname'):
                payload['hostname'] = self.hostname

            # Resolve tenant and get token
            tenant_id, token = self.resolve_tenant(payload, self.source_name, self.ID)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for payload in SudoGroupModificationRule: {payload}")
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
