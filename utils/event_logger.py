import os
from datetime import datetime

LOG_FILE_PATH = "/var/log/inopli_monitor.log"
DEFAULT_SOLUTION_NAME = "inopli_monitor"


def log_event(event_id, solution_name=None, data_source=None, class_name=None,
              method=None, event_type=None, description=None, tenant_id=None):
    """
    Writes an event to the log file with fields:
    Timestamp | TenantID | EventID | SolutionName | DataSource | ClassName | Method | EventType | Description

    tenant_id is optional; if not provided, the field is left empty.
    """
    try:
        timestamp = datetime.utcnow().isoformat()
        sol = solution_name or DEFAULT_SOLUTION_NAME
        tid = tenant_id or ""
        ds = data_source or ""
        cn = class_name or ""
        mth = method or ""
        etype = event_type or ""
        desc = description or ""

        log_line = (
            f"{timestamp}|{tid}|{event_id}|{sol}|{ds}|{cn}|{mth}|{etype}|{desc}\n"
        )

        # Ensure directory exists
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        # Fallback to console if logging fails
        print(f"[LOGGING ERROR] {e} — Attempted log: {timestamp}|{tenant_id}|{event_id}|{solution_name}|{data_source}|{class_name}|{method}|{event_type}|{description}")
