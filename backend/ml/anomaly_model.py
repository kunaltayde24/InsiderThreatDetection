import threading
import time
import numpy as np
from sklearn.ensemble import IsolationForest

model = None
lock = threading.Lock()

# 🔥 Shared buffer (used by FastAPI)
events_buffer = []


# ---------------- FEATURE EXTRACTION ---------------- #
def extract_features(events):
    features = []
    for e in events:
        hour = datetime.fromisoformat(e.get("timestamp", datetime.now().isoformat())).hour
        features.append([
            int(e.get("file_sensitive", False)),
            int(e.get("malicious_process", False)),
            float(e.get("duration_sec", 0)),
            int(e.get("action") == "usb_insert"),     # USB activity
            int(hour < 6 or hour > 22),               # after-hours
            int(e.get("action") == "file_access"),    # file access frequency
        ])
    return np.array(features)


# ---------------- TRAIN MODEL ---------------- #
def train_model(events):
    global model

    if len(events) < 50:
        return

    X = extract_features(events)

    if len(X) == 0:
        return

    try:
        new_model = IsolationForest(contamination=0.1)
        new_model.fit(X)

        with lock:
            model = new_model

        print(f"✅ Model updated with {len(events)} events")

    except Exception as e:
        print(f"❌ Training error: {e}")


# ---------------- REAL-TIME TRAINER ---------------- #
def realtime_trainer():
    global events_buffer

    while True:
        time.sleep(10)

        if len(events_buffer) > 50:
            train_model(events_buffer.copy())

            # 🔥 Prevent memory overflow
            if len(events_buffer) > 1000:
                events_buffer = events_buffer[-500:]


# ---------------- PREDICT ---------------- #
def predict(event):
    global model

    if model is None:
        return 0  # model not ready

    try:
        X = extract_features([event])

        if len(X) == 0:
            return 0

        with lock:
            score = model.decision_function(X)[0]

        return float(score)

    except Exception as e:
        print(f"❌ Prediction error: {e}")
        return 0