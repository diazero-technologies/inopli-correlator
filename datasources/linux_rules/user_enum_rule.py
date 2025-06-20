import re
import time
from datetime import datetime
from collections import defaultdict, deque
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from integrations.integration_manager import IntegrationManager

class UserEnumerationRule:
    """
    Detects multiple invalid user login attempts (user enumeration) within a time window.
    Integrates multi-tenant routing.
    """
    ID = 1002
    TYPE = "user_enumeration"
    SEVERITY = "medium"
    THRESHOLD = 10
    WINDOW_SECONDS = 60

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types
        self.attempts_by_ip = defaultdict(deque)
        self.raw_lines_by_ip = defaultdict(deque)
        # hostname and resolve_tenant will be injected by LinuxMonitor
        self.integration_manager = IntegrationManager()

    def analyze_line(self, line):
        try:
            # Case-insensitive match for invalid user
            if not re.search(r'invalid user', line, re.IGNORECASE):
                return

            ip = self._extract_ip(line)
            if not ip:
                return

            now = time.time()
            timestamp_str = datetime.utcnow().isoformat()
            times = self.attempts_by_ip[ip]
            lines = self.raw_lines_by_ip[ip]

            times.append(now)
            lines.append(line.strip())
            self._prune(times, lines, now)

            if DEBUG_MODE:
                print(f"[DEBUG] IP {ip} has {len(times)} invalid user attempts")

            if len(times) >= self.THRESHOLD:
                related_events = list(lines)
                times.clear()
                lines.clear()
                self._send_alert(ip, timestamp_str, related_events)

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

    def _send_alert(self, ip, timestamp, related_events):
        if self.ID not in self.allowed_event_types:
            return
        payload = {
            "detection_rule_id": self.ID,
            "source": self.source_name,
            "rule": self.__class__.__name__,
            "event_type": self.TYPE,
            "severity": self.SEVERITY,
            "timestamp": timestamp,
            "ip": ip,
            "raw_event": related_events[-1] if related_events else "",
            "related_events": related_events,
            "message": f"User enumeration detected from IP {ip}"
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
                print(f"[ALERT] Sending payload to tenant {tenant_id} (pre-enrichment, alert_mode=all)")
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
                    print(f"[ALERT] Sending enriched payload to tenant {tenant_id}")
                send_to_inopli(alert, token_override=token)

    def _prune(self, times, lines, now):
        while times and (now - times[0]) > self.WINDOW_SECONDS:
            times.popleft()
            lines.popleft()

    def _extract_ip(self, line):
        match = re.search(r'from ([\d\.]+)', line)
        if match:
            return match.group(1)
        if DEBUG_MODE:
            print("[DEBUG] Failed to extract IP")
        return None
