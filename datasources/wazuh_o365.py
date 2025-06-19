# datasources/wazuh_o365.py

import os
import time
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from utils.tenant_router import resolve_tenant


class WazuhO365Handler(FileSystemEventHandler):
    """
    Watchdog handler for monitoring Wazuh O365 alerts file.
    """

    def __init__(self, monitor):
        self.monitor = monitor
        self.file = None
        self.position = 0
        self._open_file()

    def _open_file(self):
        """Safely open the file and seek to the end"""
        try:
            if self.file:
                self.file.close()
            self.file = open(self.monitor.file_path, "r")
            self.file.seek(0, os.SEEK_END)
            self.position = self.file.tell()
        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.monitor.source_name,
                class_name="WazuhO365Handler",
                method="_open_file",
                event_type="error",
                description=str(e)
            )

    def on_modified(self, event):
        """Handle file modification events"""
        if event.src_path != self.monitor.file_path:
            return

        try:
            if not self.file or self.file.closed:
                self._open_file()
                return

            self.file.seek(self.position)

            while True:
                line = self.file.readline()
                if not line:
                    break

                self.monitor._analyze_line(line)

            self.position = self.file.tell()

        except Exception as e:
            self._open_file()  # Reopen file on any error
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.monitor.source_name,
                class_name="WazuhO365Handler",
                method="on_modified",
                event_type="error",
                description=str(e)
            )

    def on_deleted(self, event):
        """Handle file deletion events"""
        if event.src_path == self.monitor.file_path:
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0

    def on_created(self, event):
        """Handle file creation events"""
        if event.src_path == self.monitor.file_path:
            self._open_file()


class WazuhO365Monitor:
    """
    Monitors Wazuh alerts.json for Office 365-related alerts using watchdog.
    Filters by rule.id and OrganizationId, and sends matched alerts to Inopli
    with detection_rule_id included.
    """

    def __init__(self, source_name, file_path, allowed_event_types):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types
        self.observer = None

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing {self.__class__.__name__} "
                  f"for source '{source_name}' at path '{file_path}'")

    def run(self):
        try:
            if not os.path.exists(os.path.dirname(self.file_path)):
                raise FileNotFoundError(f"Directory not found: {os.path.dirname(self.file_path)}")

            event_handler = WazuhO365Handler(self)
            self.observer = Observer()
            self.observer.schedule(event_handler, os.path.dirname(self.file_path), recursive=False)
            self.observer.start()

            if DEBUG_MODE:
                print(f"[INFO] Started watchdog observer for {self.file_path}")

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.observer.stop()

            self.observer.join()

        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="run",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}.run(): {e}")

    def _analyze_line(self, line):
        try:
            line = line.strip()
            if not line:
                return

            data = json.loads(line)

            # Must be an Office 365 integration alert
            if data.get("data", {}).get("integration") != "office365":
                return

            # Extract rule.id and convert to int
            rule_obj = data.get("rule", {})
            rule_id_str = rule_obj.get("id")
            if not rule_id_str:
                return

            try:
                rule_id = int(rule_id_str)
            except ValueError:
                return

            # Check if this rule is allowed
            if rule_id not in self.allowed_event_types:
                return

            # Get OrganizationId
            org_id = data.get("data", {}).get("office365", {}).get("OrganizationId")
            if not org_id:
                return

            # Add detection_rule_id and source
            payload = data
            payload["detection_rule_id"] = rule_id
            payload["source"] = self.source_name

            if DEBUG_MODE:
                print(f"[DEBUG] WazuhO365Monitor payload: {payload}")

            tenant_id, token = resolve_tenant(payload, self.source_name, rule_id)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for OrganizationId={org_id}")
                return

            if DEBUG_MODE:
                print(f"[ALERT] Sending Office 365 alert to tenant {tenant_id}")
            send_to_inopli(payload, token_override=token)

        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="_analyze_line",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}._analyze_line(): {e}")
