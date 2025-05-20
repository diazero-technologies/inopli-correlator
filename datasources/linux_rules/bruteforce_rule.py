import time
import re
from datetime import datetime
from collections import defaultdict, deque
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class BruteforceRule:
    ID = 1001
    TYPE = "bruteforce"
    SEVERITY = "high"
    THRESHOLD = 15
    WINDOW_SECONDS = 60

    def __init__(self, source_name, allowed_event_types):
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types
        self.failed_by_ip = defaultdict(deque)
        self.failed_by_user = defaultdict(deque)
        self.raw_lines_by_ip = defaultdict(deque)
        self.raw_lines_by_user = defaultdict(deque)
        # hostname and resolve_tenant will be injected by LinuxMonitor

    def analyze_line(self, line):
        try:
            if "Failed password" not in line:
                return

            ip = self._extract_ip(line)
            user = self._extract_user(line)
            now = time.time()
            timestamp_str = datetime.utcnow().isoformat()

            # Handle IP-based tracking
            if ip:
                self.failed_by_ip[ip].append(now)
                self.raw_lines_by_ip[ip].append(line.strip())
                self._prune(self.failed_by_ip[ip], self.raw_lines_by_ip[ip], now)

                if DEBUG_MODE:
                    print(f"[DEBUG] IP {ip} has {len(self.failed_by_ip[ip])} failed attempts")

                if len(self.failed_by_ip[ip]) >= self.THRESHOLD:
                    related_events = list(self.raw_lines_by_ip[ip])
                    self.failed_by_ip[ip].clear()
                    self.raw_lines_by_ip[ip].clear()
                    self._send_alert(ip, user, line.strip(), timestamp_str, related_events)

            # Handle user-based tracking
            if user:
                self.failed_by_user[user].append(now)
                self.raw_lines_by_user[user].append(line.strip())
                self._prune(self.failed_by_user[user], self.raw_lines_by_user[user], now)

                if DEBUG_MODE:
                    print(f"[DEBUG] User {user} has {len(self.failed_by_user[user])} failed attempts")

                if len(self.failed_by_user[user]) >= self.THRESHOLD:
                    related_events = list(self.raw_lines_by_user[user])
                    self.failed_by_user[user].clear()
                    self.raw_lines_by_user[user].clear()
                    self._send_alert(ip, user, line.strip(), timestamp_str, related_events)

        except Exception as e:
            log_event(999, "inopli_monitor", self.source_name, self.__class__.__name__, "analyze_line", "error", str(e))
            if DEBUG_MODE:
                print(f"[ERROR] {e}")

    def _send_alert(self, ip, username, log_line, timestamp, related_events):
        # Check if rule is allowed globally for this monitor
        if self.ID not in self.allowed_event_types:
            return
        # Build payload
        payload = {
            "detection_rule_id": self.ID,
            "source": self.source_name,
            "rule": self.__class__.__name__,
            "event_type": self.TYPE,
            "severity": self.SEVERITY,
            "timestamp": timestamp,
            "ip": ip,
            "username": username,
            "raw_event": log_line,
            "related_events": related_events,
            "message": f"Bruteforce detected from IP {ip} targeting user {username}"
        }
        # Include hostname for tenant filtering if available
        if hasattr(self, 'hostname'):
            payload['hostname'] = self.hostname

        # Resolve tenant and token
        tenant_id, token = self.resolve_tenant(payload, self.source_name, self.ID)
        if not token:
            if DEBUG_MODE:
                print(f"[DEBUG] No tenant matched for payload: {payload}")
            return

        if DEBUG_MODE:
            print(f"[ALERT] Sending payload to tenant {tenant_id} with token override")
        send_to_inopli(payload, token_override=token)

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

    def _extract_user(self, line):
        match = re.search(r'for (invalid user )?(\w+)', line)
        if match:
            return match.group(2)
        if DEBUG_MODE:
            print("[DEBUG] Failed to extract user")
        return None
