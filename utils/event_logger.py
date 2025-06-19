import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
import logging

# Default values
DEFAULT_LOG_PATH = "/var/log/inopli_monitor.log"
DEFAULT_SOLUTION_NAME = "inopli_monitor"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5

# Initialize logger
logger = logging.getLogger('inopli_monitor')
logger.setLevel(logging.INFO)

def setup_logging(log_path=None):
    """
    Setup logging with rotation support.
    Can be called multiple times to update the log path.
    """
    global logger
    
    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Use provided path or default
    log_file = log_path or os.environ.get('INOPLI_LOG_PATH', DEFAULT_LOG_PATH)
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Setup rotating file handler
        handler = RotatingFileHandler(
            log_file,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
            encoding='utf-8'
        )
        
        # Don't use logging's formatting - we'll format our own messages
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        
    except Exception as e:
        # Fallback to console logging if file logging fails
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter('[LOGGING ERROR] %(message)s'))
        logger.addHandler(console)
        logger.error(f"Failed to setup file logging: {e}")

# Initialize with default path
setup_logging()

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
            f"{timestamp}|{tid}|{event_id}|{sol}|{ds}|{cn}|{mth}|{etype}|{desc}"
        )
        
        logger.info(log_line)
        
    except Exception as e:
        # Fallback to console if logging fails
        print(f"[LOGGING ERROR] {e} — Attempted log: {timestamp}|{tenant_id}|{event_id}|{solution_name}|{data_source}|{class_name}|{method}|{event_type}|{description}")
