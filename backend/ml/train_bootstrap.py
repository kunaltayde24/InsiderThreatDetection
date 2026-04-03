from backend.ml.anomaly_model import train_model

# 🔥 Initial realistic dataset
events = []

# Normal behavior
for i in range(100):
    events.append({
        "file_sensitive": False,
        "malicious_process": False,
        "duration_sec": 60,
        "action": "app_usage"
    })

# Suspicious behavior
for i in range(20):
    events.append({
        "file_sensitive": True,
        "malicious_process": True,
        "duration_sec": 2,
        "action": "process_start"
    })

# 🔥 Train model once
train_model(events)

print("✅ Initial model trained")