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


class WazuhFileHandler(FileSystemEventHandler):
    """
    Watchdog handler for monitoring Wazuh alerts file.
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
                class_name="WazuhFileHandler",
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
            buffer = ""

            while True:
                chunk = self.file.readline()
                if not chunk:
                    break

                buffer += chunk
                try:
                    event_data = json.loads(buffer)
                    buffer = ""
                    self.monitor._handle_event(event_data)
                except json.JSONDecodeError:
                    continue

            self.position = self.file.tell()

        except Exception as e:
            self._open_file()  # Reopen file on any error
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.monitor.source_name,
                class_name="WazuhFileHandler",
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


class WazuhFileMonitor:
    """
    Monitors the Wazuh alerts.json file using watchdog for reliable monitoring.
    Supports wildcard filtering on agent_ids.
    """

    def __init__(self, source_name, file_path, allowed_event_types, agent_ids=None):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types
        self.agent_ids = agent_ids or []
        self.collect_all = "*" in self.agent_ids
        self.observer = None

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing {self.__class__.__name__} "
                  f"for source '{source_name}' at path '{file_path}' "
                  f"with agent_ids={self.agent_ids!r}")

    def run(self):
        """
        Start monitoring the alerts.json file using watchdog observer.
        """
        try:
            if not os.path.exists(os.path.dirname(self.file_path)):
                raise FileNotFoundError(f"Directory not found: {os.path.dirname(self.file_path)}")

            event_handler = WazuhFileHandler(self)
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

    # ... existing _handle_event method stays the same ...