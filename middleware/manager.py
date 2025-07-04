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
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance
    
    def _merge_with_wildcard(self, existing_values, new_values):
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
        try:
            # Stop existing connectors
            self.stop_connectors()
            
            # Get global connector configurations
            connector_configs = self._get_connector_configs()
            
            # Create connectors for each SIEM source instance in each tenant
            for tenant_id, tenant_config in self.tenants_config.items():
                siem_sources = tenant_config.get("siem_sources", {})
                
                for source_name, source_config in siem_sources.items():
                    if not source_config.get("enabled", False):
                        continue
                    
                    connector_type = source_config.get("connector_type", source_name.split("_")[0])
                    
                    # Check if this connector type is globally enabled
                    if not connector_configs.get(connector_type, {}).get("enabled", True):
                        if DEBUG_MODE:
                            print(f"[DEBUG] Skipping {source_name} - {connector_type} globally disabled")
                        continue
                    
                    # Create connector for this specific source instance
                    connector = self._create_connector(source_name, source_config, tenant_id)
                    if connector:
                        self.connectors[source_name] = connector
                        if DEBUG_MODE:
                            print(f"[DEBUG] Created connector: {source_name} for tenant {tenant_id}")
            
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
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
            
            return config.get("connectors", {})
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Failed to load connector configs: {e}")
            return {}
    
    def _create_connector(self, source_name: str, source_config: Dict[str, Any], tenant_id: str) -> SIEMConnector | None:
        try:
            connector_type = source_config.get("connector_type", source_name.split("_")[0])
            
            if connector_type == "wazuh":
                # Create Wazuh connector with source-specific configuration
                connector_config = {
                    "enabled": source_config.get("enabled", False),
                    "file_monitoring": source_config.get("file_monitoring", True),
                    "buffer_size": source_config.get("buffer_size", 8192),
                    "file_path": source_config.get("file_path", ""),
                    "tenant_id": tenant_id,
                    "tenant_config": self.tenants_config.get(tenant_id, {})
                }
                return WazuhConnector(source_name, connector_config)
            
            elif connector_type == "qradar":
                # Create QRadar connector with source-specific configuration
                connector_config = {
                    "enabled": source_config.get("enabled", False),
                    "polling_interval": source_config.get("polling_interval", 5),
                    "api_config": source_config.get("api_config", {}),
                    "collection_control": source_config.get("collection_control", {}),
                    "tenant_id": tenant_id,
                    "tenant_config": self.tenants_config.get(tenant_id, {})
                }
                return QRadarConnector(source_name, connector_config)
            
            # Add more connector types here as needed
            # elif connector_type == "crowdstrike":
            #     return CrowdStrikeConnector(source_name, connector_config)
            # elif connector_type == "linux":
            #     return LinuxConnector(source_name, connector_config)
            
            if DEBUG_MODE:
                print(f"[DEBUG] No connector available for connector type: {connector_type}")
            return None
            
        except Exception as e:
            log_event(
                event_id=996,
                solution_name="inopli_middleware",
                data_source=source_name,
                class_name="MiddlewareManager",
                method="_create_connector",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to create connector for {source_name}: {e}")
            return None
    
    def start_connectors(self):
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
        self.running = False
        self.stop_connectors()
        
        if self.thread:
            self.thread.join(timeout=5)
            
        if DEBUG_MODE:
            print("[INFO] Stopped middleware manager")
    
    def _run_loop(self):
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