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
        """Handle file modification events by reading and buffering all new content."""
        if event.src_path != self.monitor.file_path:
            return

        if DEBUG_MODE:
            print(f"[DEBUG] File modified: {event.src_path}. Reading new data.")

        try:
            if not self.file or self.file.closed:
                if DEBUG_MODE:
                    print("[DEBUG] File was closed. Reopening.")
                self._open_file()
                if not self.file:
                    return

            self.file.seek(self.position)
            # Read all new content since our last check
            new_content = self.file.read()
            # Immediately update our position to the new end of the file
            self.position = self.file.tell()

            if not hasattr(self, 'buffer'):
                self.buffer = ""
            
            self.buffer += new_content
            
            # Nothing to process
            if not self.buffer.strip():
                return

            decoder = json.JSONDecoder()
            events_processed = 0
            # Process the buffer until it's empty or we have an incomplete JSON object
            while self.buffer:
                try:
                    # Find one valid JSON object from the start of the buffer
                    event_data, end_index = decoder.raw_decode(self.buffer)
                    
                    self.monitor._handle_event(event_data)
                    events_processed += 1
                    
                    # Remove the processed object from the buffer and any leading whitespace
                    self.buffer = self.buffer[end_index:].lstrip()

                except json.JSONDecodeError:
                    # This is expected if the file ends with a partial JSON object.
                    # We break the loop and wait for the next file modification to get the rest.
                    if DEBUG_MODE:
                        print(f"[DEBUG] Incomplete JSON in buffer, waiting for more data. Buffer starts with: {self.buffer[:100]}...")
                    break
            
            if events_processed > 0 and DEBUG_MODE:
                print(f"[DEBUG] Processed {events_processed} new event(s).")

        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error in on_modified: {e}. Reopening file.")
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
            if DEBUG_MODE:
                print(f"[DEBUG] Watched file deleted: {event.src_path}")
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0

    def on_created(self, event):
        """Handle file creation events"""
        if event.src_path == self.monitor.file_path:
            if DEBUG_MODE:
                print(f"[DEBUG] Watched file created: {event.src_path}")
            self._open_file()

    def on_moved(self, event):
        """Handle file move events (log rotation)"""
        # If the file we were watching was moved away
        if event.src_path == self.monitor.file_path:
            if DEBUG_MODE:
                print(f"[DEBUG] Watched file moved from {event.src_path} to {event.dest_path}")
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0
        
        # If a new file was moved into the place we are watching
        elif event.dest_path == self.monitor.file_path:
            if DEBUG_MODE:
                print(f"[DEBUG] New file moved into place at {event.dest_path}")
            self._open_file()


class WazuhFileMonitor:
    """
    Monitors the Wazuh alerts.json file using watchdog for reliable monitoring.
    Supports wildcard filtering on agent_ids and event_types.
    """

    def __init__(self, source_name, file_path, allowed_event_types, agent_ids=None):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types
        self.agent_ids = agent_ids or []
        self.collect_all_agents = "*" in self.agent_ids
        self.collect_all_events = "*" in self.allowed_event_types
        self.observer = None

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing {self.__class__.__name__} "
                  f"for source '{source_name}' at path '{file_path}' "
                  f"with agent_ids={self.agent_ids!r} and event_types={self.allowed_event_types!r}")

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

    def _handle_event(self, event):
        """
        Applies filtering and, if matched, sends the event to Inopli.
        """
        try:
            # --- agent_id filter with wildcard support ---
            agent = event.get("agent", {}) or {}
            agent_id = agent.get("id")
            if not self.collect_all_agents and agent_id not in self.agent_ids:
                return

            # Extract and validate rule ID
            rule_obj = event.get("rule", {})
            rule_id_str = rule_obj.get("id")
            if not rule_id_str:
                return
            try:
                rule_id = int(rule_id_str)
            except ValueError:
                return

            # Filter by allowed_event_types (with wildcard support)
            if not self.collect_all_events and rule_id not in self.allowed_event_types:
                return

            # Prepare payload
            payload = event
            payload["detection_rule_id"] = rule_id
            payload["source"] = self.source_name

            if DEBUG_MODE:
                print(f"[DEBUG] WazuhFileMonitor payload: {payload}")

            # Resolve tenant and send
            tenant_id, token = resolve_tenant(payload, self.source_name, rule_id)
            if not token:
                if DEBUG_MODE:
                    print(f"[DEBUG] No tenant matched for rule_id={rule_id}")
                return

            if DEBUG_MODE:
                print(f"[ALERT] Sending alert to tenant {tenant_id}")
            send_to_inopli(payload, token_override=token)

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