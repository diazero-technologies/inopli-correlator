import os
import re
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from integrations.integration_manager import IntegrationManager

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
        self.observer = None
        self.active_observers = set()  # Track which paths are being watched
        self.integration_manager = IntegrationManager()

        self.watch_paths = [
            "/etc/systemd/system/",
            "/usr/lib/systemd/system/",
            "/lib/systemd/system/"
        ]

    def start_observer(self):
        """Start the file system observer with error handling and recovery"""
        try:
            if self.observer:
                self.stop_observer()

            self.observer = Observer()
            self._schedule_watches()
            self.observer.start()

            if DEBUG_MODE:
                print(f"[DEBUG] Started systemd persistence watcher for paths: {', '.join(self.active_observers)}")

        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="start_observer",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to start systemd persistence watcher: {e}")

    def stop_observer(self):
        """Safely stop the observer"""
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.observer = None
                self.active_observers.clear()
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error stopping observer: {e}")

    def _schedule_watches(self):
        """Schedule watches for all available paths"""
        self.active_observers.clear()
        
        for path in self.watch_paths:
            try:
                if os.path.isdir(path):
                    self.observer.schedule(self, path=path, recursive=False)
                    self.active_observers.add(path)
                    if DEBUG_MODE:
                        print(f"[DEBUG] Successfully watching path: {path}")
            except Exception as e:
                log_event(
                    event_id=996,
                    solution_name="inopli_monitor",
                    data_source=self.source_name,
                    class_name=self.__class__.__name__,
                    method="_schedule_watches",
                    event_type="error",
                    description=f"Failed to watch {path}: {str(e)}"
                )
                if DEBUG_MODE:
                    print(f"[ERROR] Failed to watch path {path}: {e}")

        if not self.active_observers:
            log_event(
                event_id=997,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="_schedule_watches",
                event_type="warning",
                description="No systemd paths available for watching"
            )

    def _trigger_alert(self, path, operation):
        try:
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
                    print(f"[ALERT] Sending systemd persistence alert to tenant {tenant_id} (pre-enrichment, alert_mode=all)")
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
                        print(f"[ALERT] Sending enriched systemd persistence alert to tenant {tenant_id}: {alert}")
                    send_to_inopli(alert, token_override=token)
        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="_trigger_alert",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to trigger alert: {e}")

    def on_created(self, event):
        """Handle file creation with error handling"""
        try:
            if not event.is_directory and event.src_path.endswith(".service"):
                if DEBUG_MODE:
                    print(f"[DEBUG] .service file created: {event.src_path}")
                self._trigger_alert(event.src_path, "created")
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error handling file creation: {e}")

    def on_modified(self, event):
        """Handle file modification with error handling"""
        try:
            if not event.is_directory and event.src_path.endswith(".service"):
                if DEBUG_MODE:
                    print(f"[DEBUG] .service file modified: {event.src_path}")
                self._trigger_alert(event.src_path, "modified")
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error handling file modification: {e}")

    def on_deleted(self, event):
        """Handle file deletion with error handling"""
        try:
            if not event.is_directory and event.src_path.endswith(".service"):
                if DEBUG_MODE:
                    print(f"[DEBUG] .service file deleted: {event.src_path}")
                self._trigger_alert(event.src_path, "deleted")
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error handling file deletion: {e}")
