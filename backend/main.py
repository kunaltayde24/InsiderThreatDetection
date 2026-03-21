from fastapi import FastAPI
from datetime import datetime, timezone
from collections import defaultdict

from backend.incident_response import escalate_if_needed
from backend.risk_engine import compute_risk, get_severity
from backend.auto_response import (
    trigger_auto_response,
    incidents,
    disabled_users,
    blocked_ips
)

app = FastAPI()

# ---------------- STORAGE ---------------- #

process_events = []
alerts = []

active_processes = {}
app_usage = defaultdict(float)

blocked_users = set()   # local block list

# ---------------- HEALTH ---------------- #

@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------- EVENT INGEST ---------------- #

@app.post("/event")
def ingest_event(event: dict):

    # 🚫 BLOCK CHECK
    if event.get("user_id") in blocked_users:
        return {"message": "User is blocked"}

    # Add timestamp
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    action = event.get("action")

    # ---------- ACTIVE APPS ---------- #
    if action == "app_open":
        active_processes[event["app_name"]] = {
            "pid": event.get("pid"),
            "start_time": event["timestamp"],
            "user_id": event.get("user_id")
        }

    elif action == "app_usage":
        app_name = event.get("app_name")
        app_usage[app_name] += event.get("duration_sec", 0)
        active_processes.pop(app_name, None)

    # ---------- STORE ALL EVENTS (FOR TIMELINE) ---------- #
    process_events.append(event)

    # ---------- RISK ENGINE ---------- #
    risk = compute_risk(event)
    severity = get_severity(risk)

    # ---------- ESCALATION ---------- #
    user_data = {
        "user": event.get("user_id"),
        "risk_score": risk,
        "location": event.get("location", "Unknown"),
        "malicious_process_detected": event.get("malicious_process", False),
        "session_duration": event.get("duration_sec", 0)
    }

    escalate_if_needed(user_data)

    # ---------- ALERT SYSTEM ---------- #
    if risk >= 50:
        alert = {
            "timestamp": event["timestamp"],
            "user_id": event.get("user_id"),
            "risk": risk,
            "severity": severity,
            "message": "Suspicious behavior detected"
        }
        alerts.append(alert)

    # ---------- AUTO RESPONSE ---------- #
    trigger_auto_response(event, risk)

    return {
        "status": "received",
        "risk": risk,
        "severity": severity
    }


# ---------------- DASHBOARD APIs ---------------- #

@app.get("/active-processes")
def get_active_processes():
    return [
        {
            "process_name": name,
            "pid": data["pid"],
            "user_id": data["user_id"],
            "start_time": data["start_time"]
        }
        for name, data in active_processes.items()
    ]


@app.get("/process-summary")
def get_process_summary():
    return [
        {
            "process_name": app,
            "time_spent_sec": round(sec, 2)
        }
        for app, sec in app_usage.items()
    ]


@app.get("/process-events")
def get_process_events():
    return process_events[-200:]


@app.get("/alerts")
def get_alerts():
    return alerts


@app.get("/users")
def get_users():
    from backend.risk_engine import USER_STATE
    return [
        {"user_id": uid, "risk": data["risk"]}
        for uid, data in USER_STATE.items()
    ]


# ---------- AUTO RESPONSE DATA ---------- #

@app.get("/incidents")
def get_incidents():
    return incidents


@app.get("/blocked-ips")
def get_blocked_ips():
    return list(blocked_ips)


@app.get("/disabled-users")
def get_disabled_users():
    return list(disabled_users)


# ---------------- MANUAL USER BLOCK ---------------- #

@app.post("/block_user/{username}")
def block_user(username: str):
    blocked_users.add(username)
    return {"status": f"{username} blocked successfully"}


@app.post("/unblock_user/{username}")
def unblock_user(username: str):
    blocked_users.discard(username)
    return {"status": f"{username} unblocked successfully"}