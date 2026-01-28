from fastapi import FastAPI, WebSocket
from alert_engine import create_alert, get_alerts   # <-- changed
from risk_engine import compute_risk               # <-- changed
import asyncio

app = FastAPI()
clients = []

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep connection alive
    except:
        clients.remove(ws)

def broadcast_alert(alert):
    for ws in clients:
        asyncio.create_task(ws.send_json(alert))

@app.post("/event")
def ingest_event(event: dict):
    risk = compute_risk(event)
    alert = None
    if risk >= 50:
        alert = create_alert(event.get("user_id", "unknown"), risk)
        broadcast_alert(alert)
    return {"risk_score": risk, "alert": alert}

@app.get("/alerts")
def alerts():
    return get_alerts()
