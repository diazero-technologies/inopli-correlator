from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import threading
import time
from utils.event_logger import log_event
from config.debug import DEBUG_MODE


class SIEMConnector(ABC):
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled = config.get("enabled", False)
        self.running = False
        self.thread = None
        
    @abstractmethod
    def connect(self) -> bool:
        pass
    
    @abstractmethod
    def collect_alerts(self) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def validate_alert(self, alert: Dict[str, Any]) -> bool:
        pass
    
    def start(self):
        if not self.enabled:
            if DEBUG_MODE:
                print(f"[DEBUG] Connector {self.name} is disabled, skipping start.")
            return
            
        if self.running:
            if DEBUG_MODE:
                print(f"[DEBUG] Connector {self.name} is already running.")
            return
            
        try:
            if self.connect():
                self.running = True
                self.thread = threading.Thread(target=self._run_loop, daemon=True)
                self.thread.start()
                if DEBUG_MODE:
                    print(f"[INFO] Started SIEM connector: {self.name}")
            else:
                log_event(
                    event_id=996,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name=self.__class__.__name__,
                    method="start",
                    event_type="error",
                    description=f"Failed to connect to SIEM: {self.name}"
                )
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name=self.__class__.__name__,
                method="start",
                event_type="error",
                description=str(e)
            )
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        if DEBUG_MODE:
            print(f"[INFO] Stopped SIEM connector: {self.name}")
    
    def _run_loop(self):
        while self.running:
            try:
                alerts = self.collect_alerts()
                for alert in alerts:
                    if self.validate_alert(alert):
                        # Send to middleware processor
                        from middleware.processor import AlertProcessor
                        processor = AlertProcessor.get_instance()
                        processor.process_alert(alert, self.name)
                        
            except Exception as e:
                log_event(
                    event_id=996,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name=self.__class__.__name__,
                    method="_run_loop",
                    event_type="error",
                    description=str(e)
                )
                if DEBUG_MODE:
                    print(f"[ERROR] Error in {self.name} connector: {e}")
            
            # Sleep before next collection
            time.sleep(self.config.get("polling_interval", 30)) 