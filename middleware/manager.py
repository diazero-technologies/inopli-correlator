import yaml
import os
import threading
import time
from typing import Dict, List, Any
from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from middleware.base import SIEMConnector
from middleware.connectors.wazuh_connector import WazuhConnector
from middleware.connectors.qradar_connector import QRadarConnector


class MiddlewareManager:
    """
    Main manager for the SIEM middleware.
    Handles loading configuration, managing connectors, and coordinating alert processing.
    """
    
    def __init__(self, config_path: str = "config/middleware_config.yaml"):
        self.config_path = config_path
        self.connectors: Dict[str, SIEMConnector] = {}
        self.running = False
        self.thread = None
        self.tenants_config = {}
        
        if DEBUG_MODE:
            print("[DEBUG] MiddlewareManager initialized")
    
    @classmethod
    def get_instance(cls):
        """Get the singleton instance."""
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance
    
    def _merge_with_wildcard(self, existing_values, new_values):
        """
        Merge two lists of values, handling wildcards.
        If either list contains '*', returns ['*'].
        Otherwise, returns the union of both lists.
        """
        if not isinstance(existing_values, (list, set)):
            existing_values = list(existing_values) if existing_values else []
        if not isinstance(new_values, (list, set)):
            new_values = list(new_values) if new_values else []
        
        # If either has wildcard, result is wildcard
        if '*' in existing_values or '*' in new_values:
            return ['*']
        
        # Otherwise, merge unique values
        return list(set(existing_values) | set(new_values))
    
    def load_config(self) -> bool:
        """Load middleware configuration from YAML file."""
        try:
            if not os.path.exists(self.config_path):
                if DEBUG_MODE:
                    print(f"[DEBUG] Middleware config not found: {self.config_path}")
                return False
                
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
            
            # Extract tenants configuration
            self.tenants_config = config.get("tenants", {})
            
            if DEBUG_MODE:
                print(f"[DEBUG] Loaded middleware config with {len(self.tenants_config)} tenants")
            
            return True
            
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source="middleware_manager",
                class_name="MiddlewareManager",
                method="load_config",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to load middleware config: {e}")
            return False
    
    def create_connectors(self) -> bool:
        """
        Create SIEM connectors based on middleware configuration.
        Creates one connector per SIEM type with aggregated tenant configurations.
        """
        try:
            # Stop existing connectors
            self.stop_connectors()
            
            # Get connector configurations from middleware config
            connector_configs = self._get_connector_configs()
            
            # Create connectors for each SIEM type
            for siem_type, config in connector_configs.items():
                if config.get("enabled", False):
                    connector = self._create_connector(siem_type, config)
                    if connector:
                        self.connectors[siem_type] = connector
                        if DEBUG_MODE:
                            print(f"[DEBUG] Created connector: {siem_type}")
            
            if DEBUG_MODE:
                print(f"[DEBUG] Created {len(self.connectors)} connectors")
            
            return True
            
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source="middleware_manager",
                class_name="MiddlewareManager",
                method="create_connectors",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to create connectors: {e}")
            return False
    
    def _get_connector_configs(self) -> Dict[str, Any]:
        """Get connector configurations from middleware config file."""
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
            
            return config.get("connectors", {})
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Failed to load connector configs: {e}")
            return {}
    
    def _create_connector(self, siem_type: str, config: Dict[str, Any]) -> SIEMConnector | None:
        """Create a specific connector based on the SIEM type."""
        try:
            if siem_type == "wazuh":
                # Create Wazuh connector with tenant configurations
                connector_config = {
                    "enabled": config.get("enabled", False),
                    "file_monitoring": config.get("file_monitoring", True),
                    "buffer_size": config.get("buffer_size", 8192),
                    "tenants_config": self.tenants_config  # Pass tenant configurations
                }
                return WazuhConnector(siem_type, connector_config)
            
            elif siem_type == "qradar":
                # Create QRadar connector with tenant configurations
                connector_config = {
                    "enabled": config.get("enabled", False),
                    "polling_interval": config.get("polling_interval", 5),
                    "api_config": config.get("api_config", {}),
                    "collection_control": config.get("collection_control", {}),
                    "tenants_config": self.tenants_config  # Pass tenant configurations
                }
                return QRadarConnector(siem_type, connector_config)
            
            # Add more connector types here as needed
            # elif siem_type == "crowdstrike":
            #     return CrowdStrikeConnector(siem_type, config)
            # elif siem_type == "linux":
            #     return LinuxConnector(siem_type, config)
            
            if DEBUG_MODE:
                print(f"[DEBUG] No connector available for SIEM type: {siem_type}")
            return None
            
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source=siem_type,
                class_name="MiddlewareManager",
                method="_create_connector",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to create connector for {siem_type}: {e}")
            return None
    
    def start_connectors(self):
        """Start all enabled connectors."""
        try:
            for name, connector in self.connectors.items():
                connector.start()
                
            if DEBUG_MODE:
                print(f"[INFO] Started {len(self.connectors)} connectors")
                
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source="middleware_manager",
                class_name="MiddlewareManager",
                method="start_connectors",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to start connectors: {e}")
    
    def stop_connectors(self):
        """Stop all connectors."""
        try:
            for name, connector in self.connectors.items():
                connector.stop()
                
            if DEBUG_MODE:
                print(f"[INFO] Stopped {len(self.connectors)} connectors")
                
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source="middleware_manager",
                class_name="MiddlewareManager",
                method="stop_connectors",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to stop connectors: {e}")
    
    def start(self):
        """Start the middleware manager."""
        if self.running:
            if DEBUG_MODE:
                print("[DEBUG] Middleware manager is already running")
            return
        
        try:
            self.running = True
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
            
            if DEBUG_MODE:
                print("[INFO] Started middleware manager")
                
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source="middleware_manager",
                class_name="MiddlewareManager",
                method="start",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to start middleware manager: {e}")
    
    def stop(self):
        """Stop the middleware manager."""
        self.running = False
        self.stop_connectors()
        
        if self.thread:
            self.thread.join(timeout=5)
            
        if DEBUG_MODE:
            print("[INFO] Stopped middleware manager")
    
    def _run_loop(self):
        """Main loop for the middleware manager."""
        while self.running:
            try:
                # Check if any connectors need restarting
                for name, connector in self.connectors.items():
                    if connector.enabled and not connector.running:
                        if DEBUG_MODE:
                            print(f"[DEBUG] Restarting connector: {name}")
                        connector.start()
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                log_event(
                    event_id=996,
                    solution_name="inopli_middleware",
                    data_source="middleware_manager",
                    class_name="MiddlewareManager",
                    method="_run_loop",
                    event_type="error",
                    description=str(e)
                )
                if DEBUG_MODE:
                    print(f"[ERROR] Error in middleware manager loop: {e}")
                time.sleep(30)  # Wait before retrying 