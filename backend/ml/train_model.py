import joblib
import os
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

FEATURES = [
    "process_count",
    "unique_apps",
    "avg_app_time",
    "night_activity"
]

def train():
    X = []

    # Simulated NORMAL user behavior
    for _ in range(300):
        X.append([
            np.random.randint(5, 18),      # process_count
            np.random.randint(2, 6),       # unique apps
            np.random.uniform(60, 600),    # avg app time
            0                              # night activity
        ])

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )

    model.fit(X)
    joblib.dump(model, MODEL_PATH)

    print("✅ ML anomaly model trained successfully")

def load_model():
    if not os.path.exists(MODEL_PATH):
        train()
    return joblib.load(MODEL_PATH)

MODEL = load_model()

def anomaly_score(features: list) -> float:
    score = MODEL.decision_function([features])[0]
    return round(-score * 100, 2)   # higher = risk

if __name__ == "__main__":
    train()
