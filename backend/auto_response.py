from datetime import datetime, timezone

# Temporary in-memory storage (later we move to DB)
blocked_ips = set()
disabled_users = set()
incidents = []

RISK_THRESHOLD = 70
CRITICAL_THRESHOLD = 85


def block_ip(ip):
    blocked_ips.add(ip)


def disable_user(user_id):
    disabled_users.add(user_id)


def log_incident(user_id, ip, risk, action):
    incidents.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "ip": ip,
        "risk": risk,
        "action": action
    })


def trigger_auto_response(event, risk):
    user_id = event.get("user_id")
    ip = event.get("ip", "unknown")

    if risk >= CRITICAL_THRESHOLD:
        block_ip(ip)
        disable_user(user_id)
        action = "CRITICAL: User disabled + IP blocked"

    elif risk >= RISK_THRESHOLD:
        disable_user(user_id)
        action = "HIGH: User disabled"

    else:
        return

    log_incident(user_id, ip, risk, action)