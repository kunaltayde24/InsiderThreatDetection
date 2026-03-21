from database import incidents_collection
from datetime import datetime

def log_incident(user, ip, risk_score, action):
    incident = {
        "user": user,
        "ip": ip,
        "risk_score": risk_score,
        "action_taken": action,
        "timestamp": datetime.utcnow()
    }

    incidents_collection.insert_one(incident)