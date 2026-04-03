import streamlit as st
import asyncio
import json
import websockets

st.set_page_config(page_title="Insider Threat Live Dashboard", layout="wide")
st.title("🚨 AI-Powered Insider Threat Detection – Live Alerts")

st.info("System is monitoring user activity in real time...")

# Placeholder for alerts table
alerts_placeholder = st.empty()

# List to store alerts
alerts_data = []

async def listen_alerts():
    uri = "ws://localhost:8000/ws"  # FastAPI WebSocket
    async with websockets.connect(uri) as websocket:
        while True:
            message = await websocket.recv()
            alert = json.loads(message)
            alerts_data.append(alert)
            alerts_placeholder.table(alerts_data)

# Run WebSocket listener
asyncio.run(listen_alerts())
