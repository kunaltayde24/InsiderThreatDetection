# ---------------- RISK ENGINE ---------------- #

USER_STATE = {}

def compute_risk(event):
    risk = 0

    # 🔥 Sensitive file access
    if event.get("file_sensitive"):
        risk += 30

    # 🔥 Malicious process
    if event.get("malicious_process"):
        risk += 40

    # 🔥 Suspicious short duration
    if event.get("duration_sec", 0) < 3:
        risk += 10

    # 🔥 Track user risk
    user = event.get("user_id", "unknown")

    if user not in USER_STATE:
        USER_STATE[user] = {"risk": 0}

    USER_STATE[user]["risk"] += risk

    return risk


def get_severity(risk):
    if risk >= 80:
        return "CRITICAL"
    elif risk >= 50:
        return "HIGH"
    elif risk >= 20:
        return "MEDIUM"
    return "LOW"