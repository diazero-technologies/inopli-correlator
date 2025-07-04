import json
import time
import threading
import requests
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from middleware.base import SIEMConnector
from utils.event_logger import log_event
from config.debug import DEBUG_MODE


class QRadarConnector(SIEMConnector):
    """
    Connector for QRadar SIEM offenses.
    Collects offenses from QRadar API using REST endpoints.
    Supports multi-tenant configuration with individual filtering per tenant.
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.api_config = config.get("api_config", {})
        self.tenant_id = config.get("tenant_id", "")
        self.tenant_config = config.get("tenant_config", {})
        self.collection_control = config.get("collection_control", {})
        self.alert_queue = []
        self.queue_lock = threading.Lock()
        self.last_collection_time = None
        self.session = requests.Session()
        
        # Initialize last offense ID control
        self.last_offense_id = self._load_last_offense_id()
        
        # Configure session with SSL verification settings
        self.session.verify = self.api_config.get("verify_ssl", False)
        if not self.session.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        if DEBUG_MODE:
            print(f"[DEBUG] Initializing QRadarConnector "
                  f"for '{name}' with tenant {self.tenant_id}")
            print(f"[DEBUG] Last offense ID: {self.last_offense_id}")

    def connect(self) -> bool:
        """Establish connection to QRadar by testing API connectivity."""
        try:
            # Test connection by making a simple API call
            test_url = f"{self.api_config['base_url']}/api/siem/offenses"
            headers = self._get_auth_headers()
            
            response = self.session.get(
                test_url,
                headers=headers,
                params={"limit": 1},
                timeout=10
            )
            
            if response.status_code == 200:
                if DEBUG_MODE:
                    print(f"[DEBUG] Successfully connected to QRadar API")
                return True
            else:
                if DEBUG_MODE:
                    print(f"[ERROR] Failed to connect to QRadar API. Status: {response.status_code}")
                return False
                
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Connection error: {e}")
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="QRadarConnector",
                method="connect",
                event_type="error",
                description=str(e)
            )
            return False

    def collect_alerts(self) -> List[Dict[str, Any]]:
        """Collect offenses from QRadar API for this specific tenant."""
        alerts = []
        
        try:
            # Get offenses for this specific tenant
            tenant_alerts = self._collect_tenant_offenses()
            alerts.extend(tenant_alerts)
                
        except Exception as e:
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="QRadarConnector",
                method="collect_alerts",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Error collecting alerts: {e}")
        
        return alerts

    def _load_last_offense_id(self) -> int:
        """Load the last collected offense ID from file or config."""
        try:
            # First try to load from file
            id_file_path = self.collection_control.get("id_file_path", "config/qradar_last_id.json")
            
            if os.path.exists(id_file_path):
                with open(id_file_path, 'r') as f:
                    data = json.load(f)
                    last_id = data.get("last_offense_id", 0)
                    if DEBUG_MODE:
                        print(f"[DEBUG] Loaded last offense ID from file: {last_id}")
                    return last_id
            
            # Fallback to config value
            last_id = self.collection_control.get("last_offense_id", 0)
            if DEBUG_MODE:
                print(f"[DEBUG] Using last offense ID from config: {last_id}")
            return last_id
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error loading last offense ID: {e}")
            return 0

    def _save_last_offense_id(self, offense_id: int):
        """Save the last collected offense ID to file."""
        try:
            if not self.collection_control.get("save_last_id", True):
                return
                
            id_file_path = self.collection_control.get("id_file_path", "config/qradar_last_id.json")
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(id_file_path), exist_ok=True)
            
            data = {
                "last_offense_id": offense_id,
                "last_updated": datetime.now().isoformat()
            }
            
            with open(id_file_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            if DEBUG_MODE:
                print(f"[DEBUG] Saved last offense ID: {offense_id}")
                
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error saving last offense ID: {e}")
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="QRadarConnector",
                method="_save_last_offense_id",
                event_type="error",
                description=str(e)
            )

    def _collect_tenant_offenses(self) -> List[Dict[str, Any]]:
        """Collect offenses for this specific tenant."""
        alerts = []
        max_offense_id = self.last_offense_id
        
        try:
            # Build query parameters
            params = {
                "sort": "-id",  # Sort by ID descending to get newest first
                "limit": self.config.get("batch_size", 100)
            }
            
            # Add ID filter to get only offenses newer than last collected
            if self.last_offense_id > 0:
                params["filter"] = f"id>{self.last_offense_id}"
            
            # Add status filter
            status_filter = self.config.get("status_filter", "OPEN")
            if status_filter != "ALL":
                if "filter" in params:
                    params["filter"] += f" and status='{status_filter}'"
                else:
                    params["filter"] = f"status='{status_filter}'"
            
            # Make API request
            url = f"{self.api_config['base_url']}/api/siem/offenses"
            headers = self._get_auth_headers()
            
            if DEBUG_MODE:
                print(f"[DEBUG] Collecting offenses for tenant {self.tenant_id} with filter: {params.get('filter', 'None')}")
            
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                offenses = response.json()
                
                for offense in offenses:
                    # Track the highest offense ID
                    offense_id = offense.get("id", 0)
                    if offense_id > max_offense_id:
                        max_offense_id = offense_id
                    
                    # Add tenant information to the offense
                    offense["_tenant_id"] = self.tenant_id
                    offense["_siem_source"] = "qradar"
                    
                    # Validate and add to alerts
                    if self.validate_alert(offense):
                        alerts.append(offense)
                
                # Update last offense ID if we found newer offenses
                if max_offense_id > self.last_offense_id:
                    self.last_offense_id = max_offense_id
                    self._save_last_offense_id(max_offense_id)
                
                if DEBUG_MODE:
                    print(f"[DEBUG] Collected {len(alerts)} offenses for tenant {self.tenant_id}")
                    if max_offense_id > self.last_offense_id:
                        print(f"[DEBUG] Updated last offense ID to: {max_offense_id}")
                    
            else:
                if DEBUG_MODE:
                    print(f"[ERROR] Failed to get offenses for tenant {self.tenant_id}. Status: {response.status_code}")
                    
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error collecting offenses for tenant {self.tenant_id}: {e}")
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="QRadarConnector",
                method="_collect_tenant_offenses",
                event_type="error",
                description=f"Tenant {self.tenant_id}: {str(e)}"
            )
        
        return alerts

    def validate_alert(self, alert: Dict[str, Any]) -> bool:
        """Validate if an offense should be processed based on tenant filters."""
        tenant_id = alert.get("_tenant_id")
        if not tenant_id or tenant_id != self.tenant_id:
            return False
        
        # Apply rule filters
        rule_filters = self.config.get("rule_filters", {})
        if rule_filters:
            # Check rule IDs
            rule_ids_filter = rule_filters.get("rule_ids", ["*"])
            if rule_ids_filter != ["*"]:
                offense_rules = alert.get("rules", [])
                offense_rule_ids = [rule.get("id") for rule in offense_rules]
                
                # Check if any offense rule matches the filter
                if not any(rule_id in rule_ids_filter for rule_id in offense_rule_ids):
                    return False
            
            # Check severity filter
            severity_filter = rule_filters.get("min_severity", 0)
            if alert.get("severity", 0) < severity_filter:
                return False
        
        # Apply source filters
        source_filters = self.config.get("source_filters", {})
        if source_filters:
            # Check source networks
            source_networks_filter = source_filters.get("source_networks", ["*"])
            if source_networks_filter != ["*"]:
                offense_source_network = alert.get("source_network", "")
                if offense_source_network not in source_networks_filter:
                    return False
        
        return True

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for QRadar API."""
        headers = {
            "Accept": "application/json",
            "Version": self.api_config.get("api_version", "17"),
            "SEC": self.api_config.get("auth_token", "")
        }
        return headers

    def start(self):
        """Start the connector and initialize collection time."""
        super().start()
        if self.running:
            self.last_collection_time = datetime.now() - timedelta(minutes=5)  # Start from 5 minutes ago

    def stop(self):
        """Stop the connector and close session."""
        super().stop()
        if self.session:
            self.session.close()

    def _add_alert(self, alert: Dict[str, Any]):
        """Add alert to the queue (thread-safe)."""
        with self.queue_lock:
            self.alert_queue.append(alert)
            # Keep only the last 1000 alerts to prevent memory issues
            if len(self.alert_queue) > 1000:
                self.alert_queue = self.alert_queue[-1000:]

    def _run_loop(self):
        """Override the base run loop to update collection time."""
        while self.running:
            try:
                alerts = self.collect_alerts()
                for alert in alerts:
                    if self.validate_alert(alert):
                        # Send to middleware processor
                        from middleware.processor import AlertProcessor
                        processor = AlertProcessor.get_instance()
                        processor.process_alert(alert, self.name)
                
                # Update last collection time
                self.last_collection_time = datetime.now()
                        
            except Exception as e:
                log_event(
                    event_id=997,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name="QRadarConnector",
                    method="_run_loop",
                    event_type="error",
                    description=str(e)
                )
                if DEBUG_MODE:
                    print(f"[ERROR] Error in {self.name} connector: {e}")
            
            # Sleep before next collection (convert minutes to seconds)
            polling_interval_minutes = self.config.get("polling_interval", 5)
            sleep_seconds = polling_interval_minutes * 60
            if DEBUG_MODE:
                print(f"[DEBUG] Sleeping for {polling_interval_minutes} minutes ({sleep_seconds} seconds)")
            time.sleep(sleep_seconds) 