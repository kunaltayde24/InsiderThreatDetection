import streamlit as st
import requests
import pandas as pd
from streamlit_autorefresh import st_autorefresh

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(layout="wide")
st.title("🚨 AI-Powered Insider Threat Detection – Real-Time Dashboard")

# 🔁 Auto refresh every 2 seconds
st_autorefresh(interval=2000, key="realtime")

def fetch_alerts():
    try:
        r = requests.get(f"{API_BASE}/alerts", timeout=2)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                return pd.DataFrame(data)
    except Exception as e:
        st.error(f"Backend not reachable: {e}")
    return pd.DataFrame()

alerts_df = fetch_alerts()

# ---------------- METRICS ----------------
st.subheader("Live Metrics")

c1, c2, c3 = st.columns(3)

total = len(alerts_df)
high = len(alerts_df[alerts_df["severity"] == "HIGH"]) if not alerts_df.empty else 0
critical = len(alerts_df[alerts_df["severity"] == "CRITICAL"]) if not alerts_df.empty else 0

c1.metric("Total Alerts", total)
c2.metric("High Risk", high)
c3.metric("Critical", critical)

# ---------------- ALERT TABLE ----------------
st.subheader("🚨 Live Alerts")

if alerts_df.empty:
    st.info("No alerts yet. System is monitoring...")
else:
    st.dataframe(
        alerts_df.sort_values("timestamp", ascending=False),
        use_container_width=True
    )

# ---------------- CHART ----------------
st.subheader("⚠️ Severity Distribution")

if not alerts_df.empty:
    st.bar_chart(alerts_df["severity"].value_counts())

st.caption("Real-time alerts pulled from FastAPI backend")
