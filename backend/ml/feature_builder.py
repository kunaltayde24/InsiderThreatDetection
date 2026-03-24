from datetime import datetime

SENSITIVE_APPS = ["powershell.exe", "cmd.exe", "python.exe"]

def build_features(event, event_count):
    hour = datetime.fromisoformat(event["timestamp"]).hour

    duration = event.get("duration_sec", 0)
    sensitive = 1 if event.get("process_name", "").lower() in SENSITIVE_APPS else 0

    return [[
        hour,
        duration,
        event_count,
        sensitive
    ]]
