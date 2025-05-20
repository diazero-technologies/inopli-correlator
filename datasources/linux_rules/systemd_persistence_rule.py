import os
import re
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class SystemdPersistenceRule(FileSystemEventHandler):
    """
    Detects creation, modification, or deletion of .service files
    in systemd directories using inotify via watchdog.
    Integrates multi-tenant routing.
    """
    ID = 1009
    TYPE = "systemd_persistence"
    SEVERITY = "critical"
    is_filesystem_watcher = True

    def __init__(self, source_name, allowed_event_types):
        super().__init__()
        self.source_name = source_name
        self.allowed_event_types = allowed_event_types

        self.watch_paths = [
            "/etc/systemd/system/",
            "/usr/lib/systemd/system/",
            "/lib/systemd/system/"
        ]
        self.observer = Observer()

    def start_observer(self):
        for path in self.watch_paths:
            if os.path.isdir(path):
                if DEBUG_MODE:
                    print(f"[DEBUG] Watching path: {path}")
                self.observer.schedule(self, path=path, recursive=False)
        self.observer.start()

    def _trigger_alert(self, path, operation):
        # Check if rule is allowed for this monitor
        if self.ID not in self.allowed_event_types:
            return

        timestamp = datetime.utcnow().isoformat()
        log_line = f"{operation.upper()} event on {path}"

        payload = {
            "detection_rule_id": self.ID,
            "source": self.source_name,
            "rule": self.__class__.__name__,
            "event_type": self.TYPE,
            "severity": self.SEVERITY,
            "timestamp": timestamp,
            "target_file": path,
            "raw_event": log_line,
            "message": f"Systemd persistence file {operation}: {os.path.basename(path)}"
        }

        # Attach hostname for tenant filtering if available
        if hasattr(self, 'hostname'):
            payload['hostname'] = self.hostname

        # Resolve tenant and token
        tenant_id, token = self.resolve_tenant(payload, self.source_name, self.ID)
        if not token:
            if DEBUG_MODE:
                print(f"[DEBUG] No tenant matched for payload: {payload}")
            return

        if DEBUG_MODE:
            print(f"[ALERT] Sending systemd persistence alert to tenant {tenant_id}: {payload}")
        send_to_inopli(payload, token_override=token)

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".service"):
            if DEBUG_MODE:
                print(f"[DEBUG] .service file created: {event.src_path}")
            self._trigger_alert(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(".service"):
            if DEBUG_MODE:
                print(f"[DEBUG] .service file modified: {event.src_path}")
            self._trigger_alert(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory and event.src_path.endswith(".service"):
            if DEBUG_MODE:
                print(f"[DEBUG] .service file deleted: {event.src_path}")
            self._trigger_alert(event.src_path, "deleted")
