import re
from datetime import datetime
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from integrations.integration_manager import IntegrationManager

class CrontabModificationRule:
    """
    Detects crontab changes or scheduling of persistence mechanisms via cron jobs.
    Integrates multi-tenant routing.
    """
    ID = 1008
    TYPE = "cron_modification"
    SEVERITY = "high"

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types
        self.integration_manager = IntegrationManager()
        # hostname and resolve_tenant will be injected by the monitor

    def analyze_line(self, line):
        try:
            if not self._matches_crontab_change(line):
                return
            if self.ID not in self.allowed_event_types:
                if DEBUG_MODE:
                    print(f"[DEBUG] Rule {self.__class__.__name__} skipped due to config.")
                return
            timestamp = datetime.utcnow().isoformat()
            user = self._extract_user(line)
            log_line = line.strip()
            payload = {
                "detection_rule_id": self.ID,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "username": user,
                "raw_event": log_line,
                "message": f"Crontab modified or suspicious cron job activity by user '{user}'"
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
                    print(f"[ALERT] Sending crontab modification alert to tenant {tenant_id} (pre-enrichment, alert_mode=all)")
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
                        print(f"[ALERT] Sending enriched crontab modification alert to tenant {tenant_id}")
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

    def _matches_crontab_change(self, line):
        patterns = [
            r'crontab\[\d+\]: (new|replace|remove|edit)',
            r'CRON.*\(.*\) CMD .*',
            r'pam_unix\(cron:session\): session (opened|closed) for user .*'
        ]
        for pattern in patterns:
            if re.search(pattern, line):
                if DEBUG_MODE:
                    print(f"[DEBUG] Matched crontab pattern: {pattern}")
                return True
        return False

    def _extract_user(self, line):
        match = re.search(r'for user (\w+)', line)
        if match:
            if DEBUG_MODE:
                print(f"[DEBUG] Extracted user: {match.group(1)}")
            return match.group(1)
        match = re.search(r'\((\w+)\)', line)
        if match:
            return match.group(1)
        return "unknown"