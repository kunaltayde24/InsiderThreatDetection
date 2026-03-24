from fastapi import FastAPI
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Union
import logging
import threading
import time

# ---------------- IMPORTS ---------------- #
from backend.alert_service import send_alert_email
from backend.incident_response import escalate_if_needed
from backend.risk_engine import compute_risk, get_severity
from backend.auto_response import (
    trigger_auto_response,
    incidents,
    disabled_users,
    blocked_ips
)

# 🔥 ML
from backend.ml.anomaly_model import (
    events_buffer,
    realtime_trainer,
    predict
)

# 🔥 EXPLAINABILITY
from backend.ml.explain import explain_event

app = FastAPI()

# ---------------- LOGGING ---------------- #
logging.basicConfig(level=logging.INFO)

# ---------------- STORAGE ---------------- #
process_events = []
alerts = []
active_processes = {}
app_usage = defaultdict(float)

# ---------------- EMAIL CONTROL ---------------- #
user_last_risk = {}
last_email_time = {}
EMAIL_COOLDOWN = 60  # seconds

# ---------------- START ML TRAINER ---------------- #
@app.on_event("startup")
def start_ml():
    thread = threading.Thread(target=realtime_trainer, daemon=True)
    thread.start()
    logging.info("🔥 Real-time ML trainer started")

# ---------------- HEALTH ---------------- #
@app.get("/health")
def health():
    return {"status": "ok"}

# ---------------- EVENT INGEST ---------------- #
@app.post("/event")
def ingest_event(data: Union[dict, List[dict]]):

    events = data if isinstance(data, list) else [data]
    responses = []

    for event in events:
        try:
            user_id = event.get("user_id")

            # 🚫 BLOCK CHECK
            if user_id in disabled_users:
                continue

            event["timestamp"] = datetime.now(timezone.utc).isoformat()
            action = event.get("action")

            # ---------- ACTIVE APPS ---------- #
            if action == "app_open":
                active_processes[event.get("app_name", "unknown")] = {
                    "pid": event.get("pid"),
                    "start_time": event["timestamp"],
                    "user_id": user_id
                }

            elif action == "app_usage":
                app_name = event.get("app_name", "unknown")
                app_usage[app_name] += event.get("duration_sec", 0)
                active_processes.pop(app_name, None)

            # ---------- PROCESS EVENTS ---------- #
            if action in ["process_start", "process_stop", "file_access"]:
                process_events.append(event)

            # 🔥 ADD EVENT TO ML BUFFER
            events_buffer.append(event)

            # ---------- ML PREDICTION ---------- #
            ml_score = predict(event)

            # ---------- RULE-BASED RISK ---------- #
            rule_risk = compute_risk(event)

            # ---------- ML → RISK MAPPING ---------- #
            if ml_score > 0:
                ml_risk = 0
            elif ml_score > -0.2:
                ml_risk = 10
            elif ml_score > -0.5:
                ml_risk = 30
            else:
                ml_risk = 60

            # ---------- FINAL RISK ---------- #
            risk = rule_risk + ml_risk
            severity = get_severity(risk)

            # ---------- EXPLAINABILITY ---------- #
            reasons = explain_event(event, risk, ml_score)

            # ---------- ESCALATION ---------- #
            user_data = {
                "user": user_id,
                "risk_score": risk,
                "location": event.get("location", "Unknown"),
                "malicious_process_detected": event.get("malicious_process", False),
                "session_duration": event.get("duration_sec", 0)
            }

            escalate_if_needed(user_data)

            # ---------- ALERT STORAGE ---------- #
            if risk >= 20:
                alerts.append({
                    "timestamp": event["timestamp"],
                    "user_id": user_id,
                    "risk": round(risk, 2),
                    "severity": severity,
                    "ml_score": round(ml_score, 3),
                    "ml_risk": ml_risk,
                    "message": "⚠ Suspicious behavior detected",
                    "reasons": reasons
                })

            # ---------- EMAIL ALERT LOGIC 🔥 ---------- #
            prev_risk = user_last_risk.get(user_id, 0)

            trigger_email = (
                risk >= 80 or
                event.get("file_sensitive") or
                (risk - prev_risk > 40) or
                ml_score < -0.3
            )

            now = time.time()

            if trigger_email:
                last_sent = last_email_time.get(user_id, 0)

                # ⛔ Prevent spam emails
                if now - last_sent > EMAIL_COOLDOWN:
                    send_alert_email(
                        user_id=user_id,
                        risk=round(risk, 2),
                        severity=severity,
                        reasons=reasons,
                        events=process_events[-50:]
                    )

                    last_email_time[user_id] = now
                    logging.info(f"📧 Email alert sent for {user_id}")

            # update last risk
            user_last_risk[user_id] = risk

            # ---------- AUTO RESPONSE ---------- #
            trigger_auto_response(event, risk)

            # ---------- RESPONSE ---------- #
            responses.append({
                "user_id": user_id,
                "risk": round(risk, 2),
                "severity": severity,
                "ml_score": round(ml_score, 3),
                "ml_risk": ml_risk,
                "reasons": reasons
            })

        except Exception as e:
            logging.error(f"❌ Error processing event: {e}")

    return {
        "status": "processed",
        "events_received": len(events),
        "results": responses
    }

# ---------------- DASHBOARD APIS ---------------- #

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

@app.get("/incidents")
def get_incidents():
    return incidents

@app.get("/file-events")
def get_file_events():
    return [
        e for e in process_events
        if e.get("action") == "file_access"
    ][-100:]

# ---------------- OPTIONAL FIXES ---------------- #

@app.get("/blocked-ips")
def get_blocked_ips():
    return blocked_ips

@app.get("/disabled-users")
def get_disabled_users():
    return disabled_users