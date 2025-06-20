import re
import time
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from integrations.integration_manager import IntegrationManager

class SudoDeniedRule:
    """
    Detects denied sudo attempts.
    Integrates multi-tenant routing.
    """
    ID = 1003
    TYPE = "sudo_denied"
    SEVERITY = "medium"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types
        # hostname and resolve_tenant injected by monitor
        self.integration_manager = IntegrationManager()

    def analyze_line(self, line):
        try:
            if not re.search(r'sudo: .*: 3 incorrect password attempts', line):
                return
            user = self._extract_user(line)
            timestamp_str = datetime.utcnow().isoformat()
            payload = {
                "detection_rule_id": self.ID,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp_str,
                "username": user,
                "raw_event": line.strip(),
                "message": f"Sudo denied for user {user}"
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
                    print(f"[ALERT] Sending sudo denied alert to tenant {tenant_id} (pre-enrichment, alert_mode=all)")
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
                        print(f"[ALERT] Sending enriched sudo denied alert to tenant {tenant_id}")
                    send_to_inopli(alert, token_override=token)
        except Exception as e:
            log_event(999, "inopli_monitor", self.source_name, self.__class__.__name__, "analyze_line", "error", str(e))
            if DEBUG_MODE:
                print(f"[ERROR] {e}")

    def _extract_user(self, line):
        match = re.search(r'sudo: *([^:]+): 3 incorrect password attempts', line)
        return match.group(1) if match else None
