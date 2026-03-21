import csv
import os
from datetime import datetime

LOG_DIR = "../logs"
LOG_FILE = os.path.join(LOG_DIR, "events.csv")

HEADERS = [
    "timestamp",
    "user_id",
    "action",
    "process_name",
    "app_name",
    "duration_sec",
    "risk",
    "severity"
]

os.makedirs(LOG_DIR, exist_ok=True)

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)


def log_event(event: dict):
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            event.get("timestamp"),
            event.get("user_id"),
            event.get("action"),
            event.get("process_name"),
            event.get("app_name"),
            event.get("duration_sec"),
            event.get("risk"),
            event.get("severity"),
        ])
