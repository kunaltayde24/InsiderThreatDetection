import joblib
import os
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

def train():
    X = []
    for _ in range(200):
        X.append([
            np.random.randint(5, 25),      # process_count
            np.random.randint(2, 7),       # unique apps
            np.random.uniform(60, 900),    # avg app time
            np.random.randint(0, 2)        # night activity
        ])

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print("✅ ML model trained")

def load_model():
    if not os.path.exists(MODEL_PATH):
        train()
    return joblib.load(MODEL_PATH)

MODEL = load_model()

def anomaly_score(features: list) -> float:
    score = MODEL.decision_function([features])[0]
    normalized = min(max(-score * 50, 0), 100)
    return normalized
