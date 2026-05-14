import json
import time
import threading
import requests
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from middleware.base import SIEMConnector
from utils.event_logger import log_event
from config.debug import DEBUG_MODE


class DatadogConnector(SIEMConnector):
    """
    Polls the Datadog Monitors API and forwards triggered monitors
    (state Alert or Warn) to the Inopli AlertProcessor.

    Deduplication is done via a per-monitor state file that stores the
    maximum last_triggered_ts seen for each monitor ID.  A monitor is
    only forwarded again when its last_triggered_ts increases.

    Authentication uses two Datadog credentials:
      DD-API-KEY   → api_config.api_key
      DD-APPLICATION-KEY → api_config.app_key

    Polling interval is expressed in minutes (same convention as
    QRadarConnector).
    """

    # States that are considered actionable alerts
    ALERT_STATES = {"Alert", "Warn"}

    # Datadog priority → internal severity (1 = critical → 5, 5 = low → 1)
    def _map_severity(self, priority: Optional[int]) -> int:
        if priority is None:
            return 3
        clamped = max(1, min(5, int(priority)))
        return 6 - clamped

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.api_config = config.get("api_config", {})
        self.tenant_id = config.get("tenant_id", "")
        self.tenant_config = config.get("tenant_config", {})
        self.collection_control = config.get("collection_control", {})
        self.alert_states = set(config.get("alert_states", list(self.ALERT_STATES)))
        self.last_collection_time = None
        self.session = requests.Session()

        # State: {str(monitor_id): int(max_last_triggered_ts)}
        self.monitor_state: Dict[str, int] = self._load_state()
        self._state_lock = threading.Lock()

        if DEBUG_MODE:
            print(
                f"[DEBUG] Initializing DatadogConnector for '{name}' "
                f"with tenant {self.tenant_id}"
            )
            print(f"[DEBUG] Loaded state for {len(self.monitor_state)} monitors")

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Validate credentials via GET /api/v1/validate."""
        try:
            url = f"{self.api_config['base_url']}/api/v1/validate"
            response = self.session.get(
                url,
                headers=self._get_auth_headers(),
                timeout=10,
            )
            if response.status_code == 200:
                if DEBUG_MODE:
                    print(f"[DEBUG] DatadogConnector: credentials validated for {self.name}")
                return True
            else:
                if DEBUG_MODE:
                    print(
                        f"[ERROR] DatadogConnector: validation failed for {self.name}. "
                        f"Status: {response.status_code} – {response.text[:200]}"
                    )
                log_event(
                    event_id=997,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name="DatadogConnector",
                    method="connect",
                    event_type="error",
                    description=f"HTTP {response.status_code}: {response.text[:200]}",
                )
                return False
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] DatadogConnector.connect: {e}")
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="DatadogConnector",
                method="connect",
                event_type="error",
                description=str(e),
            )
            return False

    def collect_alerts(self) -> List[Dict[str, Any]]:
        """
        Fetches all monitors from the Datadog API (paginated), keeps only
        those whose overall_state is in self.alert_states, and deduplicates
        by last_triggered_ts.
        """
        if DEBUG_MODE:
            print(f"[DEBUG] DatadogConnector.collect_alerts: starting for {self.name}")

        alerts: List[Dict[str, Any]] = []
        try:
            alerts = self._collect_triggered_monitors()
        except Exception as e:
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="DatadogConnector",
                method="collect_alerts",
                event_type="error",
                description=str(e),
            )
            if DEBUG_MODE:
                print(f"[ERROR] DatadogConnector.collect_alerts: {e}")
                import traceback
                traceback.print_exc()

        if DEBUG_MODE:
            print(
                f"[DEBUG] DatadogConnector.collect_alerts: returning {len(alerts)} alerts"
            )
        return alerts

    def validate_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Validates that the alert belongs to this connector's tenant and
        passes all configured rule/tag/severity filters.
        """
        if alert.get("_tenant_id") != self.tenant_id:
            return False

        rule_filters = self.config.get("rule_filters", {})
        if rule_filters:
            # Monitor name substring filter (equivalent to QRadar rule_ids)
            rule_ids_filter = rule_filters.get("rule_ids", ["*"])
            if rule_ids_filter and rule_ids_filter != ["*"]:
                monitor_name = alert.get("name", "")
                if not any(r in monitor_name for r in rule_ids_filter):
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector: rule filter rejected "
                            f"'{monitor_name[:60]}'"
                        )
                    return False

            # Monitor tags filter
            allowed_tags = rule_filters.get("monitor_tags", [])
            if allowed_tags:
                alert_tags = alert.get("tags", [])
                if not any(t in alert_tags for t in allowed_tags):
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector: tag filter rejected "
                            f"tags {alert_tags}"
                        )
                    return False

            # Minimum severity filter
            min_severity = rule_filters.get("min_severity", 0)
            if min_severity > 0 and alert.get("severity", 0) < min_severity:
                if DEBUG_MODE:
                    print(
                        f"[DEBUG] DatadogConnector: severity filter rejected "
                        f"severity={alert.get('severity', 0)} < min={min_severity}"
                    )
                return False

        return True

    def stop(self):
        super().stop()
        if self.session:
            self.session.close()

    # ------------------------------------------------------------------
    # Internal collection helpers
    # ------------------------------------------------------------------

    def _collect_triggered_monitors(self) -> List[Dict[str, Any]]:
        """
        Pages through GET /api/v1/monitor, collects monitors whose
        overall_state is in alert_states, and deduplicates using the
        per-monitor last_triggered_ts state file.
        """
        alerts: List[Dict[str, Any]] = []
        new_state: Dict[str, int] = {}
        batch_size = self.config.get("batch_size", 100)
        page = 0

        # Optional tag filter forwarded to the API to reduce payload size
        api_tag_filter = self.api_config.get("monitor_tags_filter", "")

        while True:
            params: Dict[str, Any] = {
                "page": page,
                "page_size": batch_size,
                "with_downtimes": False,
            }
            if api_tag_filter:
                params["monitor_tags"] = api_tag_filter

            if DEBUG_MODE:
                print(
                    f"[DEBUG] DatadogConnector: fetching monitors page={page} "
                    f"page_size={batch_size}"
                )

            try:
                response = self.session.get(
                    f"{self.api_config['base_url']}/api/v1/monitor",
                    headers=self._get_auth_headers(),
                    params=params,
                    timeout=30,
                )
            except Exception as e:
                log_event(
                    event_id=997,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name="DatadogConnector",
                    method="_collect_triggered_monitors",
                    event_type="error",
                    description=f"HTTP request failed on page {page}: {e}",
                )
                if DEBUG_MODE:
                    print(f"[ERROR] DatadogConnector: HTTP error on page {page}: {e}")
                break

            if response.status_code == 429:
                retry_after = int(response.headers.get("X-RateLimit-Reset", 60))
                if DEBUG_MODE:
                    print(
                        f"[WARN] DatadogConnector: rate-limited, "
                        f"sleeping {retry_after}s"
                    )
                time.sleep(retry_after)
                continue

            if response.status_code != 200:
                if DEBUG_MODE:
                    print(
                        f"[ERROR] DatadogConnector: monitors API returned "
                        f"{response.status_code}: {response.text[:200]}"
                    )
                log_event(
                    event_id=997,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name="DatadogConnector",
                    method="_collect_triggered_monitors",
                    event_type="error",
                    description=f"HTTP {response.status_code} on page {page}",
                )
                break

            monitors = response.json()
            if not monitors:
                # No more pages
                break

            for monitor in monitors:
                monitor_id = monitor.get("id")
                overall_state = monitor.get("overall_state", "")

                if overall_state not in self.alert_states:
                    continue

                # Determine the maximum last_triggered_ts across all groups
                max_ts = self._get_max_triggered_ts(monitor)
                monitor_id_key = str(monitor_id)
                saved_ts = self.monitor_state.get(monitor_id_key, 0)

                if max_ts <= saved_ts:
                    # Already forwarded this trigger cycle
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector: skipping monitor {monitor_id} "
                            f"(last_triggered_ts unchanged: {max_ts})"
                        )
                    continue

                # Track new state regardless of validation outcome
                new_state[monitor_id_key] = max_ts

                # Enrich monitor dict with Inopli required fields
                monitor["_tenant_id"] = self.tenant_id
                monitor["_siem_source"] = "datadog"
                monitor["timestamp"] = datetime.now(timezone.utc).isoformat()
                monitor["detection_rule_id"] = monitor.get("name", "Unknown Monitor")
                monitor["severity"] = self._map_severity(monitor.get("priority"))
                monitor["triggered_groups"] = self._get_triggered_groups(monitor)

                if self.validate_alert(monitor):
                    alerts.append(monitor)
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector: queued monitor {monitor_id} "
                            f"'{monitor.get('name', '')}' state={overall_state}"
                        )

            # Datadog returns fewer items than page_size on the last page
            if len(monitors) < batch_size:
                break

            page += 1

        # Persist updated state only for monitors that were forwarded
        if new_state:
            with self._state_lock:
                self.monitor_state.update(new_state)
            self._save_state()

        return alerts

    def _get_max_triggered_ts(self, monitor: Dict[str, Any]) -> int:
        """Return the maximum last_triggered_ts across all monitor groups."""
        state = monitor.get("state", {}) or {}
        groups = state.get("groups", {}) or {}
        max_ts = 0
        for group_data in groups.values():
            ts = group_data.get("last_triggered_ts") or 0
            if ts and ts > max_ts:
                max_ts = ts
        return max_ts

    def _get_triggered_groups(self, monitor: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Returns the subset of monitor groups whose status is in alert_states,
        to be included in the Inopli payload for context.
        """
        state = monitor.get("state", {}) or {}
        groups = state.get("groups", {}) or {}
        triggered = []
        for group_name, group_data in groups.items():
            if group_data.get("status") in self.alert_states:
                triggered.append(
                    {
                        "group": group_name,
                        "status": group_data.get("status"),
                        "last_triggered_ts": group_data.get("last_triggered_ts"),
                        "last_notified_ts": group_data.get("last_notified_ts"),
                    }
                )
        return triggered

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _state_file_path(self) -> str:
        return self.collection_control.get(
            "state_file_path",
            f"config/datadog_{self.name}_state.json",
        )

    def _load_state(self) -> Dict[str, int]:
        try:
            path = self._state_file_path()
            if os.path.exists(path):
                with open(path, "r") as f:
                    data = json.load(f)
                    state = data.get("monitor_state", {})
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector: loaded state from {path} "
                            f"({len(state)} entries)"
                        )
                    return state
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] DatadogConnector._load_state: {e}")
        return {}

    def _save_state(self):
        if not self.collection_control.get("save_state", True):
            return
        try:
            path = self._state_file_path()
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
            with self._state_lock:
                data = {
                    "monitor_state": self.monitor_state,
                    "last_updated": datetime.now().isoformat(),
                    "source": self.name,
                }
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            if DEBUG_MODE:
                print(
                    f"[DEBUG] DatadogConnector: saved state to {path} "
                    f"({len(self.monitor_state)} entries)"
                )
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] DatadogConnector._save_state: {e}")
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="DatadogConnector",
                method="_save_state",
                event_type="error",
                description=str(e),
            )

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _get_auth_headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "DD-API-KEY": self.api_config.get("api_key", ""),
            "DD-APPLICATION-KEY": self.api_config.get("app_key", ""),
        }

    # ------------------------------------------------------------------
    # Run loop (minutes-based, same convention as QRadarConnector)
    # ------------------------------------------------------------------

    def _run_loop(self):
        while self.running:
            try:
                if DEBUG_MODE:
                    print(
                        f"[DEBUG] DatadogConnector._run_loop: collection cycle for {self.name}"
                    )

                alerts = self.collect_alerts()

                if DEBUG_MODE:
                    print(
                        f"[DEBUG] DatadogConnector._run_loop: collected {len(alerts)} alerts"
                    )

                if alerts:
                    from middleware.processor import AlertProcessor
                    processor = AlertProcessor.get_instance()
                    for alert in alerts:
                        if self.validate_alert(alert):
                            if DEBUG_MODE:
                                print(
                                    f"[DEBUG] DatadogConnector._run_loop: processing "
                                    f"monitor {alert.get('id', 'unknown')} "
                                    f"'{alert.get('name', '')}'"
                                )
                            processor.process_alert(alert, self.name)
                        else:
                            if DEBUG_MODE:
                                print(
                                    f"[DEBUG] DatadogConnector._run_loop: monitor "
                                    f"{alert.get('id', 'unknown')} failed post-collect "
                                    f"validation"
                                )
                else:
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector._run_loop: no new alerts, "
                            f"skipping AlertProcessor"
                        )

                self.last_collection_time = datetime.now()

            except Exception as e:
                log_event(
                    event_id=997,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name="DatadogConnector",
                    method="_run_loop",
                    event_type="error",
                    description=str(e),
                )
                if DEBUG_MODE:
                    print(f"[ERROR] DatadogConnector._run_loop: {e}")
                    import traceback
                    traceback.print_exc()

            polling_interval_minutes = self.config.get("polling_interval", 5)
            sleep_seconds = polling_interval_minutes * 60
            if DEBUG_MODE:
                print(
                    f"[DEBUG] DatadogConnector._run_loop: sleeping "
                    f"{polling_interval_minutes} min ({sleep_seconds}s)"
                )
            time.sleep(sleep_seconds)
