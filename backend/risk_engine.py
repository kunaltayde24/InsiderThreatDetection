from datetime import datetime, timezone
from .ml.anomaly_model import anomaly_score

# ---------------- STATE ---------------- #

USER_STATE = {}

HIGH_RISK = 50
CRITICAL_RISK = 80


def now():
    return datetime.now(timezone.utc).isoformat()


def get_user(user_id):
    if user_id not in USER_STATE:
        USER_STATE[user_id] = {
            "risk": 0,
            "last_event": None,
            "apps_used": {},
            "process_count": 0,
            "suspicious_events": [],
            "night_events": 0
        }
    return USER_STATE[user_id]


# ---------------- CORE RISK ENGINE ---------------- #

def compute_risk(event: dict) -> int:
    user_id = event.get("user_id", "unknown")
    action = event.get("action", "")
    state = get_user(user_id)

    rule_risk = 0

    # -------- RULE BASED DETECTION -------- #

    risky_processes = {
        "powershell.exe",
        "cmd.exe",
        "regedit.exe",
        "mimikatz.exe",
        "procdump.exe"
    }

    if action == "process_start":
        pname = (event.get("process_name") or "").lower()
        state["process_count"] += 1

        if pname in risky_processes:
            rule_risk += 30
            state["suspicious_events"].append(
                f"Suspicious process detected: {pname}"
            )

    if state["process_count"] > 40:
        rule_risk += 10

    if action == "app_usage":
        app = event.get("app_name")
        duration = float(event.get("duration_sec", 0))

        if app:
            state["apps_used"].setdefault(app, 0)
            state["apps_used"][app] += duration

            if duration > 1800:  # 30+ minutes
                rule_risk += 15

    # Night activity
    try:
        ts = datetime.fromisoformat(event.get("timestamp"))
        if ts.hour < 6 or ts.hour > 22:
            rule_risk += 10
            state["night_events"] += 1
    except:
        pass

    # -------- ML BASED ANOMALY DETECTION -------- #

    app_times = list(state["apps_used"].values())
    avg_app_time = sum(app_times) / len(app_times) if app_times else 0

    features = [
        state["process_count"],
        len(state["apps_used"]),
        avg_app_time,
        state["night_events"]
    ]

    ml_score = anomaly_score(features)  # Expected 0–1

    # Convert ML score to risk scale
    ml_risk = int(abs(ml_score) * 100)

    if ml_score > 0.15:
        state["suspicious_events"].append(
            f"ML anomaly detected (score={ml_score:.2f})"
        )

    # -------- FINAL RISK CALCULATION -------- #

    # Blend ML + Rules
    combined_risk = max(rule_risk, ml_risk)

    # Apply soft decay to avoid infinite growth
    previous_risk = state["risk"] * 0.7

    new_risk = previous_risk + combined_risk

    # Bound risk between 0 and 100
    state["risk"] = min(100, int(new_risk))

    state["last_event"] = event.get("timestamp", now())

    return state["risk"]


# ---------------- SEVERITY ---------------- #

def get_severity(risk: int) -> str:
    if risk >= CRITICAL_RISK:
        return "CRITICAL"
    if risk >= HIGH_RISK:
        return "HIGH"
    if risk >= 30:
        return "MEDIUM"
    return "LOW"
