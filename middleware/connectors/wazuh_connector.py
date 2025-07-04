import os
import json
import time
import threading
from typing import Dict, List, Any
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler

from middleware.base import SIEMConnector
from utils.event_logger import log_event
from config.debug import DEBUG_MODE


class WazuhFileHandler(FileSystemEventHandler):
    """
    Watchdog handler for monitoring Wazuh alerts file.
    Adapted from the original datasource implementation.
    """

    def __init__(self, connector):
        self.connector = connector
        self.file = None
        self.position = 0
        self.buffer = ""
        self._open_file()

    def _open_file(self):
        """Safely open the file and seek to the end"""
        try:
            if self.file:
                self.file.close()
            self.file = open(self.connector.config["file_path"], "r")
            self.file.seek(0, os.SEEK_END)
            self.position = self.file.tell()
        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_middleware",
                data_source=self.connector.name,
                class_name="WazuhFileHandler",
                method="_open_file",
                event_type="error",
                description=str(e)
            )

    def on_modified(self, event):
        """Handle file modification events by reading and buffering all new content."""
        if event.src_path != self.connector.config["file_path"]:
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
                    
                    # Validate and process the event
                    if self.connector.validate_alert(event_data):
                        # Add to connector's alert queue
                        self.connector._add_alert(event_data)
                    
                    events_processed += 1
                    
                    # Remove the processed object from the buffer and any leading whitespace
                    self.buffer = self.buffer[end_index:].lstrip()

                except json.JSONDecodeError:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Incomplete JSON in buffer, waiting for more data. Buffer starts with: {self.buffer[:100]}...")
                    # Realign buffer if it does not start with '{'
                    first_brace = self.buffer.find('{')
                    if first_brace > 0:
                        if DEBUG_MODE:
                            print(f"[DEBUG] Realigning buffer. Discarding {first_brace} bytes before next '{{'.")
                        self.buffer = self.buffer[first_brace:]
                    elif first_brace == -1:
                        if DEBUG_MODE:
                            print(f"[DEBUG] No '{{' found in buffer. Clearing buffer.")
                        self.buffer = ""
                    break
            
            if events_processed > 0 and DEBUG_MODE:
                print(f"[DEBUG] Processed {events_processed} new event(s).")

        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error in on_modified: {e}. Reopening file.")
            self._open_file()  # Reopen file on any error
            log_event(
                event_id=995,
                solution_name="inopli_middleware",
                data_source=self.connector.name,
                class_name="WazuhFileHandler",
                method="on_modified",
                event_type="error",
                description=str(e)
            )

    def on_deleted(self, event):
        """Handle file deletion events"""
        if event.src_path == self.connector.config["file_path"]:
            if DEBUG_MODE:
                print(f"[DEBUG] Watched file deleted: {event.src_path}")
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0
            self.buffer = ""

    def on_created(self, event):
        """Handle file creation events"""
        if event.src_path == self.connector.config["file_path"]:
            if DEBUG_MODE:
                print(f"[DEBUG] Watched file created: {event.src_path}")
            self._open_file()
            self.buffer = ""

    def on_moved(self, event):
        """Handle file move events (log rotation)"""
        # If the file we were watching was moved away
        if event.src_path == self.connector.config["file_path"]:
            if DEBUG_MODE:
                print(f"[DEBUG] Watched file moved from {event.src_path} to {event.dest_path}")
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0
            self.buffer = ""
        
        # If a new file was moved into the place we are watching
        elif event.dest_path == self.connector.config["file_path"]:
            if DEBUG_MODE:
                print(f"[DEBUG] New file moved into place at {event.dest_path}")
            self._open_file()
            self.buffer = ""


class WazuhConnector(SIEMConnector):
    """
    Connector for Wazuh SIEM alerts.
    Monitors the Wazuh alerts.json file using watchdog for reliable monitoring.
    Supports multi-tenant configuration with individual filtering per tenant.
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.file_monitoring = config.get("file_monitoring", True)
        self.buffer_size = config.get("buffer_size", 8192)
        self.tenants_config = config.get("tenants_config", {})
        self.observer = None
        self.alert_queue = []
        self.queue_lock = threading.Lock()
        
        # Get file path from first enabled tenant
        self.file_path = self._get_file_path_from_tenants()
        
        if DEBUG_MODE:
            print(f"[DEBUG] Initializing WazuhConnector "
                  f"for '{name}' with {len(self.tenants_config)} tenants "
                  f"at path '{self.file_path}'")
    
    def _get_file_path_from_tenants(self) -> str:
        """Get file path from the first enabled tenant configuration."""
        for tenant_id, tenant_data in self.tenants_config.items():
            wazuh_config = tenant_data.get("siem_sources", {}).get("wazuh", {})
            if wazuh_config.get("enabled", False):
                return wazuh_config.get("file_path", "")
        return ""

    def connect(self) -> bool:
        """Establish connection to Wazuh by checking file accessibility."""
        try:
            if not self.file_path:
                if DEBUG_MODE:
                    print("[ERROR] No file path configured for Wazuh connector")
                return False
                
            if not self.file_path:
                if DEBUG_MODE:
                    print("[ERROR] No file path configured for Wazuh connector")
                return False
                
            file_path_str = str(self.file_path)
            if not os.path.exists(os.path.dirname(file_path_str)):
                if DEBUG_MODE:
                    print(f"[ERROR] Directory not found: {os.path.dirname(file_path_str)}")
                return False
                
            # Try to open the file to verify access
            if os.path.exists(file_path_str):
                with open(file_path_str, "r") as f:
                    pass  # Just test if we can open it
                    
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Failed to connect to Wazuh: {e}")
            return False

    def collect_alerts(self) -> List[Dict[str, Any]]:
        """Collect alerts from the internal queue."""
        with self.queue_lock:
            alerts = self.alert_queue.copy()
            self.alert_queue.clear()
        return alerts

    def validate_alert(self, alert: Dict[str, Any]) -> bool:
        """Validate if an alert should be processed based on tenant configurations."""
        try:
            # Extract alert information
            agent = alert.get("agent", {}) or {}
            agent_id = agent.get("id")
            rule_obj = alert.get("rule", {})
            rule_id_str = rule_obj.get("id")
            
            if not rule_id_str:
                return False
                
            try:
                rule_id = int(rule_id_str)
            except ValueError:
                return False
            
            # Check if any tenant should receive this alert
            for tenant_id, tenant_data in self.tenants_config.items():
                wazuh_config = tenant_data.get("siem_sources", {}).get("wazuh", {})
                
                if not wazuh_config.get("enabled", False):
                    continue
                
                # Check rule filters
                rule_filters = wazuh_config.get("rule_filters", {})
                allowed_rule_ids = rule_filters.get("rule_ids", [])
                
                if "*" not in allowed_rule_ids and rule_id not in allowed_rule_ids:
                    continue
                
                # Check agent filters
                agent_filters = wazuh_config.get("agent_filters", {})
                allowed_agent_ids = agent_filters.get("agent_ids", [])
                
                if "*" not in allowed_agent_ids and agent_id not in allowed_agent_ids:
                    continue
                
                # If we reach here, at least one tenant should receive this alert
                return True
            
            return False
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error validating Wazuh alert: {e}")
            return False

    def start(self):
        """Start the Wazuh connector with file monitoring."""
        if not super().start():
            return
            
        try:
            event_handler = WazuhFileHandler(self)
            self.observer = Observer()
            self.observer.schedule(event_handler, os.path.dirname(str(self.file_path)), recursive=False)
            self.observer.start()

            if DEBUG_MODE:
                print(f"[INFO] Started watchdog observer for {self.file_path}")

        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name=self.__class__.__name__,
                method="start",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] {self.__class__.__name__}.start(): {e}")

    def stop(self):
        """Stop the Wazuh connector."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
        super().stop()

    def _add_alert(self, alert: Dict[str, Any]):
        """Add an alert to the internal queue."""
        with self.queue_lock:
            self.alert_queue.append(alert) 