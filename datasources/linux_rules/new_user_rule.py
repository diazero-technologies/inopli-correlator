import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from integrations.integration_manager import IntegrationManager

class NewUserCreationRule:
    """
    Detects creation of new users on the system via adduser/useradd logs.
    Integrates multi-tenant routing.
    """
    ID = 1006
    TYPE = "new_user_creation"
    SEVERITY = "high"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types
        self.integration_manager = IntegrationManager()
        # hostname and resolve_tenant will be injected by the monitor

    def analyze_line(self, line):
        try:
            if not self._matches_user_creation(line):
                return
            if self.ID not in self.allowed_event_types:
                if DEBUG_MODE:
                    print(f"[DEBUG] Rule {self.__class__.__name__} skipped due to config.")
                return
            timestamp = datetime.utcnow().isoformat()
            username = self._extract_username(line)
            log_line = line.strip()
            payload = {
                "detection_rule_id": self.ID,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "username": username,
                "raw_event": log_line,
                "message": f"New system user created: '{username}'"
            }
            if hasattr(self, 'hostname'):
                payload['hostname'] = self.hostname
            tenant_id, token = self.resolve_tenant(payload, self.source_name, self.ID)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for payload: {payload}")
                return
            alert_mode = self.integration_manager.alert_mode
            if alert_mode == "all":
                if DEBUG_MODE:
                    print(f"[ALERT] Sending NewUserCreation alert to tenant {tenant_id} (pre-enrichment, alert_mode=all)")
                send_to_inopli(payload, token_override=token)
            if self.integration_manager.has_active_integrations():
                alerts_to_send = self.integration_manager.process_alert(payload)
                for alert in alerts_to_send:
                    tenant_id, token = self.resolve_tenant(alert, self.source_name, self.ID)
                    if not token:
                        if DEBUG_MODE:
                            print(f"[DEBUG] No tenant matched for payload: {alert}")
                        continue
                    if DEBUG_MODE:
                        print(f"[ALERT] Sending enriched NewUserCreation alert to tenant {tenant_id}")
                    send_to_inopli(alert, token_override=token)
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
