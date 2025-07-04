# datasources/wazuh_o365.py

import os
import time
import json
from datetime import datetime
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler

from utils.webhook_sender import send_to_inopli
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from utils.tenant_router import resolve_tenant
from integrations.integration_manager import IntegrationManager


class WazuhO365Handler(FileSystemEventHandler):

    def __init__(self, monitor):
        self.monitor = monitor
        self.file = None
        self.position = 0
        self._open_file()

    def _open_file(self):
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
        if event.src_path != self.monitor.file_path:
            return
        
        if DEBUG_MODE:
            print(f"[DEBUG] O365 file modified: {event.src_path}. Reading new data.")

        try:
            if not self.file or self.file.closed:
                if DEBUG_MODE:
                    print("[DEBUG] File was closed. Reopening.")
                self._open_file()
                if not self.file:
                    return

            self.file.seek(self.position)
            new_content = self.file.read()
            self.position = self.file.tell()

            if not hasattr(self, 'buffer'):
                self.buffer = ""
            
            self.buffer += new_content

            if not self.buffer.strip():
                return

            decoder = json.JSONDecoder()
            events_processed = 0
            while self.buffer:
                try:
                    event_data, end_index = decoder.raw_decode(self.buffer)
                    
                    self.monitor._handle_event(event_data)
                    events_processed += 1
                    
                    self.buffer = self.buffer[end_index:].lstrip()

                except json.JSONDecodeError:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Incomplete JSON in O365 buffer, waiting for more data. Buffer starts with: {self.buffer[:100]}...")
                    break
            
            if events_processed > 0 and DEBUG_MODE:
                print(f"[DEBUG] Processed {events_processed} new O365 event(s).")

        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error in O365 on_modified: {e}. Reopening file.")
            self._open_file()
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
        if event.src_path == self.monitor.file_path:
            if DEBUG_MODE:
                print(f"[DEBUG] O365 watched file deleted: {event.src_path}")
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0

    def on_created(self, event):
        if event.src_path == self.monitor.file_path:
            if DEBUG_MODE:
                print(f"[DEBUG] O365 watched file created: {event.src_path}")
            self._open_file()

    def on_moved(self, event):
        if event.src_path == self.monitor.file_path:
            if DEBUG_MODE:
                print(f"[DEBUG] O365 watched file moved from {event.src_path} to {event.dest_path}")
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0
        
        elif event.dest_path == self.monitor.file_path:
            if DEBUG_MODE:
                print(f"[DEBUG] New O365 file moved into place at {event.dest_path}")
            self._open_file()

    def _handle_event(self, data):
        try:
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

            # Get OrganizationId
            org_id = data.get("data", {}).get("office365", {}).get("OrganizationId")
            if not org_id:
                return

            # Add detection_rule_id and source
            payload = data
            payload["detection_rule_id"] = rule_id
            payload["source"] = self.monitor.source_name

            if DEBUG_MODE:
                print(f"[DEBUG] WazuhO365Monitor payload: {payload}")

            tenant_id, token = resolve_tenant(payload, self.monitor.source_name, rule_id)
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
                data_source=self.monitor.source_name,
                class_name=self.__class__.__name__,
                method="_handle_event",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}._handle_event(): {e}")


class WazuhO365Monitor:
    """
    Monitors Wazuh alerts.json for Office 365-related alerts using watchdog.
    Filters by rule.id (with wildcard support) and OrganizationId, and
    sends matched alerts to Inopli with detection_rule_id included.
    """

    def __init__(self, source_name, file_path, allowed_event_types):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types
        self.collect_all_events = "*" in self.allowed_event_types
        self.observer = None
        self.integration_manager = IntegrationManager()
        if DEBUG_MODE:
            print(f"[DEBUG] Initializing {self.__class__.__name__} "
                  f"for source '{source_name}' at path '{file_path}' "
                  f"with event_types={self.allowed_event_types!r}")

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

    def _handle_event(self, data):
        try:
            if data.get("data", {}).get("integration") != "office365":
                return
            rule_obj = data.get("rule", {})
            rule_id_str = rule_obj.get("id")
            if not rule_id_str:
                return
            try:
                rule_id = int(rule_id_str)
            except ValueError:
                return
            if not self.collect_all_events and rule_id not in self.allowed_event_types:
                return
            org_id = data.get("data", {}).get("office365", {}).get("OrganizationId")
            if not org_id:
                return
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
            alert_mode = self.integration_manager.alert_mode
            if alert_mode == "all":
                if DEBUG_MODE:
                    print(f"[ALERT] Sending Office 365 alert to tenant {tenant_id} (pre-enrichment, alert_mode=all)")
                send_to_inopli(payload, token_override=token)
            if self.integration_manager.has_active_integrations():
                alerts_to_send = self.integration_manager.process_alert(payload)
                for alert in alerts_to_send:
                    tenant_id, token = resolve_tenant(alert, self.source_name, rule_id)
                    if not token:
                        if DEBUG_MODE:
                            print(f"[DEBUG] No tenant matched for payload: {alert}")
                        continue
                    if DEBUG_MODE:
                        print(f"[ALERT] Sending enriched Office 365 alert to tenant {tenant_id}")
                    send_to_inopli(alert, token_override=token)
        except Exception as e:
            log_event(
                event_id=999,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="_handle_event",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}._handle_event(): {e}")
