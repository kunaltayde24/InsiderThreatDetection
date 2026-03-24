import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

def train(X):
    model.fit(X)
    joblib.dump(model, "ml/isolation_model.pkl")

def load_model():
    return joblib.load("ml/isolation_model.pkl")

def predict(model, X):
    score = model.decision_function(X)[0]  # higher = normal
    anomaly_score = max(0, (-score) * 100)
    return min(int(anomaly_score), 100)
