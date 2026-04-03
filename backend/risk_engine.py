# risk_engine.py
import time

USER_STATE = {}

def compute_risk(event):
    user = event.get("user_id", "unknown")
    now = time.time()

    if user not in USER_STATE:
        USER_STATE[user] = {"risk": 0, "last_seen": now}

    # Decay: reduce risk by 10% every 5 minutes of inactivity
    elapsed = now - USER_STATE[user]["last_seen"]
    decay = (elapsed / 300) * 10
    USER_STATE[user]["risk"] = max(0, USER_STATE[user]["risk"] - decay)
    USER_STATE[user]["last_seen"] = now

    risk = 0
    if event.get("file_sensitive"): risk += 30
    if event.get("malicious_process"): risk += 40
    if event.get("duration_sec", 0) < 3: risk += 10

    USER_STATE[user]["risk"] += risk
    return risk

# ✅ ADD THIS FUNCTION
def get_severity(risk):
    if risk < 20:
        return "Low"
    elif risk < 50:
        return "Medium"
    else:
        return "High"
