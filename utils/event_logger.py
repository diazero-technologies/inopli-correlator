# utils/event_logger.py

import os
from datetime import datetime

LOG_FILE_PATH = "/var/log/inopli_monitor.log"
SOLUTION_NAME = "inopli_monitor"

def log_event(event_id, solution_name, data_source, class_name, method, event_type, description):
    """
    Escreve um evento no formato:
    Timestamp|id do evento|Nome da solução|Nome do data source|Classe|Método|Tipo|Descrição
    """
    timestamp = datetime.utcnow().isoformat()
    log_line = f"{timestamp}|{event_id}|{solution_name}|{data_source}|{class_name}|{method}|{event_type}|{description}\n"

    try:
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        # Se falhar em logar, imprime no console (fallback)
        print(f"[LOGGING ERROR] {e} — Original log: {log_line}")
