import time
import re
from datetime import datetime
from collections import defaultdict, deque
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class UserEnumerationRule:
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

    def analyze_line(self, line):
        try:
            if "Invalid user" not in line:
                return

            ip = self._extract_ip(line)
            if not ip:
                return

            now = time.time()
            timestamp_str = datetime.utcnow().isoformat()
            self.attempts_by_ip[ip].append(now)
            self.raw_lines_by_ip[ip].append(line.strip())
            self._prune(self.attempts_by_ip[ip], self.raw_lines_by_ip[ip], now)

            if DEBUG_MODE:
                print(f"[DEBUG] IP {ip} has {len(self.attempts_by_ip[ip])} invalid user attempts")

            if len(self.attempts_by_ip[ip]) >= self.THRESHOLD:
                related_events = list(self.raw_lines_by_ip[ip])
                self.attempts_by_ip[ip].clear()
                self.raw_lines_by_ip[ip].clear()
                self._send_alert(ip, line.strip(), timestamp_str, related_events)

        except Exception as e:
            log_event(999, "inopli_monitor", self.source_name, self.__class__.__name__, "analyze_line", "error", str(e))
            if DEBUG_MODE:
                print(f"[ERROR] {e}")

    def _send_alert(self, ip, log_line, timestamp, related_events):
        if self.ID in self.allowed_event_types:
            payload = {
                "detection_rule_id": self.ID,
                "source": self.source_name,
                "rule": self.__class__.__name__,
                "event_type": self.TYPE,
                "severity": self.SEVERITY,
                "timestamp": timestamp,
                "ip": ip,
                "raw_event": log_line,
                "related_events": related_events,
                "message": f"User enumeration detected from IP {ip}"
            }
            if DEBUG_MODE:
                print(f"[ALERT] Sending payload: {payload}")
            send_to_inopli(payload)

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
