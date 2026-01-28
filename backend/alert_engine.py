from datetime import datetime

ALERTS = []

def create_alert(user_id: str, risk_score: float):
    severity = "LOW"

    if risk_score >= 90:
        severity = "CRITICAL"
    elif risk_score >= 70:
        severity = "HIGH"
    elif risk_score >= 50:
        severity = "MEDIUM"

    alert = {
        "user_id": user_id,
        "risk_score": risk_score,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat()
    }

    ALERTS.append(alert)
    return alert


def get_alerts():
    return ALERTS[-100:]  # last 100 alerts
