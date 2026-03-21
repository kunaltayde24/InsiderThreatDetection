import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

API_BASE = "http://127.0.0.1:8000"

# ---------------- PAGE CONFIG ---------------- #

st.set_page_config(
    page_title="AI Insider Threat SOC",
    layout="wide",
)

# ---------------- BACKGROUND IMAGE ---------------- #

# page_bg = """
# <style>
# .stApp {
#     background-image: url("https://images.unsplash.com/photo-1550751827-4bd374c3f58b");
#     background-size: cover;
#     background-attachment: fixed;
# }
# .block-container {
#     padding-top: 2rem;
#     padding-bottom: 2rem;
# }
# </style>
# """
# st.markdown(page_bg, unsafe_allow_html=True)

st.title("🚨 AI-Powered Insider Threat Detection – SOC Dashboard")

# 🔁 Auto refresh every 3 seconds
st_autorefresh(interval=3000, key="realtime")

# ---------------- FETCH FUNCTION ---------------- #

def fetch_data(endpoint):
    try:
        r = requests.get(f"{API_BASE}/{endpoint}", timeout=2)
        if r.status_code == 200:
            return pd.DataFrame(r.json())
    except:
        pass
    return pd.DataFrame()


alerts_df = fetch_data("alerts")
process_df = fetch_data("process-events")
summary_df = fetch_data("process-summary")
active_df = fetch_data("active-processes")
users_df = fetch_data("users")

# ---------------- METRIC CARDS ---------------- #

st.markdown("### 📊 Live SOC Metrics")

m1, m2, m3, m4 = st.columns(4)

m1.metric("Total Alerts", len(alerts_df))
m2.metric("High Risk", len(alerts_df[alerts_df["severity"] == "HIGH"]) if not alerts_df.empty else 0)
m3.metric("Critical", len(alerts_df[alerts_df["severity"] == "CRITICAL"]) if not alerts_df.empty else 0)
m4.metric("Running Apps", len(active_df))

st.divider()

# ---------------- ROW 1 (BAR + PIE) ---------------- #

col1, col2 = st.columns(2)

# 📊 USER RISK GRAPH
with col1:
    st.subheader("📊 User Risk Levels")

    if not users_df.empty:
        fig = px.bar(
            users_df,
            x="user_id",
            y="risk",
            color="risk",
            color_continuous_scale="RdYlGn_r",
            height=300
        )

        fig.update_layout(
            margin=dict(l=10, r=10, t=30, b=10),
            transition_duration=800
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No user risk data")

# ⚠️ SEVERITY PIE
with col2:
    st.subheader("⚠️ Alert Severity Distribution")

    if not alerts_df.empty:
        severity_counts = alerts_df["severity"].value_counts().reset_index()
        severity_counts.columns = ["severity", "count"]

        fig2 = px.pie(
            severity_counts,
            names="severity",
            values="count",
            color="severity",
            color_discrete_map={
                "LOW": "#2ECC71",
                "MEDIUM": "#F1C40F",
                "HIGH": "#E67E22",
                "CRITICAL": "#E74C3C"
            },
            height=300
        )

        fig2.update_layout(
            margin=dict(l=10, r=10, t=30, b=10),
            transition_duration=800
        )

        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.success("No alerts detected")

st.divider()

# ---------------- ROW 2 (APP USAGE + ACTIVE) ---------------- #

col3, col4 = st.columns(2)

with col3:
    st.subheader("⏱️ Application Usage (Minutes)")

    if not summary_df.empty:
        summary_df["time_spent_min"] = summary_df["time_spent_sec"] / 60

        fig3 = px.bar(
            summary_df,
            x="process_name",
            y="time_spent_min",
            color="time_spent_min",
            color_continuous_scale="Blues",
            height=300
        )

        fig3.update_layout(
            margin=dict(l=10, r=10, t=30, b=10),
            transition_duration=800
        )

        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No usage data")

with col4:
    st.subheader("🟢 Active Processes")

    if not active_df.empty:
        st.dataframe(active_df, use_container_width=True, height=300)
    else:
        st.info("No active processes")

st.divider()

# ---------------- TIMELINE ---------------- #

st.subheader("🧠 User Activity Timeline")

if not process_df.empty:
    st.dataframe(
        process_df.sort_values("timestamp", ascending=False),
        use_container_width=True,
        height=300
    )
else:
    st.info("Waiting for activity...")

st.divider()

# ---------------- ALERT TABLE ---------------- #

st.subheader("🚨 Security Alerts")

if alerts_df.empty:
    st.success("System operating normally – No suspicious activity detected.")
else:
    st.dataframe(
        alerts_df.sort_values("timestamp", ascending=False),
        use_container_width=True,
        height=300
    )

# Fetch incidents
incidents = requests.get("http://127.0.0.1:8000/incidents").json()
st.subheader("🚨 Incidents")
st.write(incidents)

# Fetch blocked IPs
blocked_ips = requests.get("http://127.0.0.1:8000/blocked-ips").json()
st.subheader("🔐 Blocked IPs")
st.write(blocked_ips)

# Fetch disabled users
disabled_users = requests.get("http://127.0.0.1:8000/disabled-users").json()
st.subheader("👤 Disabled Users")
st.write(disabled_users)
st.caption("🔐 Real-time endpoint monitoring | AI-powered insider threat detection")


st.subheader("🚫 Block Suspicious User")

username_to_block = st.text_input("Enter Username")

if st.button("Block User"):
    response = requests.post(f"http://127.0.0.1:8000/block_user/{username_to_block}")
    st.success(response.json()["status"])