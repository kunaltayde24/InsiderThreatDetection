# backend/pipeline.py

from backend.risk_engine import compute_risk
from backend.alert_engine import generate_alerts

def process_event(event: dict):
    """
    Full real-time processing pipeline
    """
    risk = compute_risk(event)
    alert = generate_alerts(risk)

    return {
        "event": event,
        "risk": risk,
        "alert": alert
    }
