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

# State file schema version.  Bump when the on-disk format changes.
_STATE_VERSION = 2


class DatadogConnector(SIEMConnector):
    """
    Polls the Datadog Monitors API and forwards triggered monitors
    (state Alert or Warn by default) to the Inopli AlertProcessor.

    --- Deduplication strategy ---
    The Datadog monitor list endpoint always returns 'overall_state_modified'
    (an ISO-8601 timestamp that changes every time the monitor transitions to
    a new state).  This field is used as the deduplication key:

      • A monitor is forwarded when its overall_state_modified timestamp is
        NEWER than what was last saved for that monitor ID.
      • ALL seen monitors are written to the state file — including those
        currently in a non-alert state — so that a future OK→Alert transition
        is correctly detected as a new trigger.
      • The state file (JSON, v2) stores per-monitor:
          name, overall_state, state_modified_ts, state_modified_raw,
          last_sent_at, send_count
        providing a full audit trail and making debugging trivial.

    --- Authentication ---
      DD-API-KEY          → api_config.api_key
      DD-APPLICATION-KEY  → api_config.app_key

    --- Polling interval ---
    Expressed in minutes, same convention as QRadarConnector.
    """

    ALERT_STATES = {"Alert", "Warn"}

    def _map_severity(self, priority: Optional[int]) -> int:
        """Datadog priority 1 (critical) → severity 5; priority 5 (low) → severity 1."""
        if priority is None:
            return 3
        return 6 - max(1, min(5, int(priority)))

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.api_config = config.get("api_config", {})
        self.tenant_id = config.get("tenant_id", "")
        self.tenant_config = config.get("tenant_config", {})
        self.collection_control = config.get("collection_control", {})
        self.alert_states = set(config.get("alert_states", list(self.ALERT_STATES)))
        self.last_collection_time = None
        self.session = requests.Session()
        self._state_lock = threading.Lock()

        # {str(monitor_id): MonitorStateEntry dict}
        self.monitor_state: Dict[str, Dict] = self._load_state()

        if DEBUG_MODE:
            print(
                f"[DEBUG] DatadogConnector '{name}' initialised "
                f"(tenant={self.tenant_id}, "
                f"tracked_monitors={len(self.monitor_state)})"
            )

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Validate credentials via GET /api/v1/validate."""
        try:
            r = self.session.get(
                f"{self.api_config['base_url']}/api/v1/validate",
                headers=self._get_auth_headers(),
                timeout=10,
            )
            if r.status_code == 200:
                if DEBUG_MODE:
                    print(f"[DEBUG] DatadogConnector: credentials OK for '{self.name}'")
                return True
            if DEBUG_MODE:
                print(
                    f"[ERROR] DatadogConnector: validation failed "
                    f"(HTTP {r.status_code}) for '{self.name}'"
                )
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="DatadogConnector",
                method="connect",
                event_type="error",
                description=f"HTTP {r.status_code}: {r.text[:200]}",
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
        Fetches monitors from the Datadog API (paginated), keeps only those
        whose overall_state is in self.alert_states, and deduplicates via
        overall_state_modified.
        """
        if DEBUG_MODE:
            print(f"[DEBUG] DatadogConnector.collect_alerts: starting for '{self.name}'")
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
                f"[DEBUG] DatadogConnector.collect_alerts: "
                f"returning {len(alerts)} alert(s)"
            )
        return alerts

    def validate_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Checks tenant ownership and applies optional rule/tag/severity
        filters defined in the YAML config.
        """
        if alert.get("_tenant_id") != self.tenant_id:
            return False

        rule_filters = self.config.get("rule_filters", {})
        if not rule_filters:
            return True

        # Monitor name substring filter  (rule_ids: ["*"] = accept all)
        allowed_ids = rule_filters.get("rule_ids", ["*"])
        if allowed_ids and allowed_ids != ["*"]:
            name = alert.get("name", "")
            if not any(r in name for r in allowed_ids):
                if DEBUG_MODE:
                    print(
                        f"[DEBUG] DatadogConnector.validate_alert: "
                        f"rule_ids filter rejected '{name[:60]}'"
                    )
                return False

        # Monitor tags filter  (empty list = accept all)
        allowed_tags = rule_filters.get("monitor_tags", [])
        if allowed_tags:
            alert_tags = alert.get("tags") or []
            if not any(t in alert_tags for t in allowed_tags):
                if DEBUG_MODE:
                    print(
                        f"[DEBUG] DatadogConnector.validate_alert: "
                        f"monitor_tags filter rejected tags={alert_tags}"
                    )
                return False

        # Minimum severity filter  (0 = accept all)
        min_sev = rule_filters.get("min_severity", 0)
        if min_sev > 0 and alert.get("severity", 0) < min_sev:
            if DEBUG_MODE:
                print(
                    f"[DEBUG] DatadogConnector.validate_alert: "
                    f"min_severity filter rejected severity={alert.get('severity', 0)}"
                )
            return False

        return True

    def stop(self):
        super().stop()
        if self.session:
            self.session.close()

    # ------------------------------------------------------------------
    # Internal collection
    # ------------------------------------------------------------------

    def _collect_triggered_monitors(self) -> List[Dict[str, Any]]:
        """
        Pages through GET /api/v1/monitor.

        For every monitor seen this cycle:
          • Updates the state entry (state + state_modified_ts) regardless
            of whether the monitor is currently alerting.  This ensures that
            a future transition back into an alert state is always caught.
          • Forwards the monitor to AlertProcessor only when:
              1. overall_state is in self.alert_states, AND
              2. state_modified_ts is strictly greater than the last saved ts.
        """
        alerts: List[Dict[str, Any]] = []
        # Accumulate state updates for the whole cycle; write once at the end.
        state_updates: Dict[str, Dict] = {}
        batch_size = self.config.get("batch_size", 100)
        api_tag_filter = self.api_config.get("monitor_tags_filter", "")
        page = 0

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
                    f"[DEBUG] DatadogConnector: GET /api/v1/monitor "
                    f"page={page} page_size={batch_size}"
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
                    description=f"Request failed on page {page}: {e}",
                )
                if DEBUG_MODE:
                    print(f"[ERROR] DatadogConnector: request error page {page}: {e}")
                break

            if response.status_code == 429:
                retry_after = int(response.headers.get("X-RateLimit-Reset", 60))
                if DEBUG_MODE:
                    print(f"[WARN] DatadogConnector: rate-limited, waiting {retry_after}s")
                time.sleep(retry_after)
                continue

            if response.status_code != 200:
                log_event(
                    event_id=997,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name="DatadogConnector",
                    method="_collect_triggered_monitors",
                    event_type="error",
                    description=f"HTTP {response.status_code} on page {page}",
                )
                if DEBUG_MODE:
                    print(
                        f"[ERROR] DatadogConnector: HTTP {response.status_code} "
                        f"on page {page}: {response.text[:200]}"
                    )
                break

            monitors = response.json()
            if not monitors:
                break

            for monitor in monitors:
                monitor_id_key = str(monitor.get("id"))
                overall_state = monitor.get("overall_state", "")
                state_modified_raw = monitor.get("overall_state_modified", "")
                current_ts = self._parse_iso_ts(state_modified_raw)

                # Always update the state entry for this monitor so that
                # transitions from non-alert → alert are correctly detected
                # in subsequent polling cycles.
                saved_entry = self.monitor_state.get(monitor_id_key, {})
                state_updates[monitor_id_key] = {
                    "name": monitor.get("name", ""),
                    "overall_state": overall_state,
                    "state_modified_ts": current_ts,
                    "state_modified_raw": state_modified_raw,
                    # Preserve sent metadata; will be updated below if we send.
                    "last_sent_at": saved_entry.get("last_sent_at"),
                    "send_count": saved_entry.get("send_count", 0),
                }

                # Only forward if state is actionable AND has changed since
                # the last time we saw this monitor.
                if overall_state not in self.alert_states:
                    continue

                saved_ts = saved_entry.get("state_modified_ts", 0)
                if current_ts <= saved_ts:
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector: skip {monitor_id_key} "
                            f"'{monitor.get('name', '')[:50]}' — "
                            f"state unchanged (ts={current_ts})"
                        )
                    continue

                # Enrich with Inopli-required fields
                now_iso = datetime.now(timezone.utc).isoformat()
                monitor["_tenant_id"] = self.tenant_id
                monitor["_siem_source"] = "datadog"
                monitor["timestamp"] = now_iso
                monitor["detection_rule_id"] = monitor.get("name", "Unknown Monitor")
                monitor["severity"] = self._map_severity(monitor.get("priority"))
                monitor["triggered_groups"] = self._get_triggered_groups(monitor)

                if self.validate_alert(monitor):
                    alerts.append(monitor)
                    # Record send metadata in the pending state update
                    state_updates[monitor_id_key]["last_sent_at"] = now_iso
                    state_updates[monitor_id_key]["send_count"] = (
                        saved_entry.get("send_count", 0) + 1
                    )
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector: queued monitor {monitor_id_key} "
                            f"'{monitor.get('name', '')[:60]}' "
                            f"state={overall_state} ts={current_ts}"
                        )

            if len(monitors) < batch_size:
                break
            page += 1

        # Merge all state updates and persist once per cycle
        if state_updates:
            with self._state_lock:
                self.monitor_state.update(state_updates)
            self._save_state()

        return alerts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_iso_ts(self, raw: str) -> int:
        """Parse an ISO-8601 string to a Unix timestamp (int). Returns 0 on failure."""
        if not raw:
            return 0
        try:
            return int(datetime.fromisoformat(raw).timestamp())
        except Exception:
            return 0

    def _get_triggered_groups(self, monitor: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Returns groups (from monitor.state.groups) whose status is in
        alert_states.  Usually empty for the list endpoint — included for
        completeness when the field is present.
        """
        groups = (monitor.get("state") or {}).get("groups") or {}
        return [
            {
                "group": name,
                "status": gd.get("status"),
                "last_triggered_ts": gd.get("last_triggered_ts"),
                "last_notified_ts": gd.get("last_notified_ts"),
            }
            for name, gd in groups.items()
            if gd.get("status") in self.alert_states
        ]

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _state_file_path(self) -> str:
        return self.collection_control.get(
            "state_file_path",
            f"config/datadog_{self.name}_state.json",
        )

    def _load_state(self) -> Dict[str, Dict]:
        """
        Loads the state file and returns a dict of {monitor_id_str: entry}.

        Handles two on-disk formats:
          v1 (legacy) — {"monitor_state": {"id": int_ts}, ...}
          v2 (current) — {"version": 2, "monitors": {"id": {...}}, ...}
        """
        path = self._state_file_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r") as f:
                data = json.load(f)

            version = data.get("version", 1)

            if version >= 2:
                monitors = data.get("monitors", {})
                if DEBUG_MODE:
                    print(
                        f"[DEBUG] DatadogConnector: loaded v2 state from '{path}' "
                        f"({len(monitors)} monitors)"
                    )
                return monitors

            # Migrate v1 → v2 in-memory (file will be rewritten on next save)
            legacy = data.get("monitor_state", {})
            migrated = {
                mid: {
                    "name": "",
                    "overall_state": "",
                    "state_modified_ts": int(ts),
                    "state_modified_raw": "",
                    "last_sent_at": None,
                    "send_count": 0,
                }
                for mid, ts in legacy.items()
                if isinstance(ts, (int, float))
            }
            if DEBUG_MODE:
                print(
                    f"[DEBUG] DatadogConnector: migrated v1→v2 state from '{path}' "
                    f"({len(migrated)} monitors)"
                )
            return migrated

        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] DatadogConnector._load_state: {e}")
            return {}

    def _save_state(self):
        """Writes the current monitor state to disk in v2 format."""
        if not self.collection_control.get("save_state", True):
            return
        path = self._state_file_path()
        try:
            dir_part = os.path.dirname(path)
            if dir_part:
                os.makedirs(dir_part, exist_ok=True)

            with self._state_lock:
                payload = {
                    "version": _STATE_VERSION,
                    "source": self.name,
                    "saved_at": datetime.now().isoformat(),
                    "monitors": self.monitor_state,
                }

            with open(path, "w") as f:
                json.dump(payload, f, indent=2)

            if DEBUG_MODE:
                print(
                    f"[DEBUG] DatadogConnector: saved state to '{path}' "
                    f"({len(self.monitor_state)} monitors)"
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
                        f"[DEBUG] DatadogConnector._run_loop: "
                        f"collection cycle for '{self.name}'"
                    )

                alerts = self.collect_alerts()

                if DEBUG_MODE:
                    print(
                        f"[DEBUG] DatadogConnector._run_loop: "
                        f"collected {len(alerts)} alert(s)"
                    )

                if alerts:
                    from middleware.processor import AlertProcessor
                    processor = AlertProcessor.get_instance()
                    for alert in alerts:
                        if self.validate_alert(alert):
                            if DEBUG_MODE:
                                print(
                                    f"[DEBUG] DatadogConnector._run_loop: "
                                    f"processing monitor {alert.get('id')} "
                                    f"'{alert.get('name', '')[:60]}'"
                                )
                            processor.process_alert(alert, self.name)
                        else:
                            if DEBUG_MODE:
                                print(
                                    f"[DEBUG] DatadogConnector._run_loop: "
                                    f"monitor {alert.get('id')} failed post-collect validation"
                                )
                else:
                    if DEBUG_MODE:
                        print(
                            f"[DEBUG] DatadogConnector._run_loop: "
                            f"no new alerts — skipping AlertProcessor"
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
