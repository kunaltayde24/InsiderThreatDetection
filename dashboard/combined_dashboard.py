import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

API_BASE = "http://127.0.0.1:8000"

# ---------------- PAGE CONFIG ---------------- #
st.set_page_config(page_title="AI Insider Threat SOC", layout="wide")

st.title("🚨 AI-Powered Insider Threat Detection – SOC Dashboard")

# 🔁 Auto refresh
st_autorefresh(interval=3000, key="refresh")

# ---------------- FETCH FUNCTION ---------------- #
def fetch_data(endpoint):
    try:
        r = requests.get(f"{API_BASE}/{endpoint}", timeout=2)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                return pd.DataFrame(data)
            return pd.DataFrame([data])
    except:
        pass
    return pd.DataFrame()

# ---------------- LOAD DATA ---------------- #
alerts_df = fetch_data("alerts")
process_df = fetch_data("process-events")
file_df = fetch_data("file-events")
summary_df = fetch_data("process-summary")
active_df = fetch_data("active-processes")
users_df = fetch_data("users")

# ---------------- METRICS ---------------- #
st.markdown("### 📊 Live SOC Metrics")

m1, m2, m3, m4 = st.columns(4)

total_alerts = len(alerts_df)
high = len(alerts_df[alerts_df["severity"] == "HIGH"]) if not alerts_df.empty else 0
critical = len(alerts_df[alerts_df["severity"] == "CRITICAL"]) if not alerts_df.empty else 0
running = len(active_df)

m1.metric("Total Alerts", total_alerts)
m2.metric("High Risk", high)
m3.metric("Critical", critical)
m4.metric("Running Apps", running)

# 🚨 ALERT BANNER
if critical > 0:
    st.error("🚨 CRITICAL ALERT DETECTED!")
elif high > 0:
    st.warning("⚠️ High-risk activity detected")

st.divider()

# ---------------- USER RISK GRAPH ---------------- #
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 User Risk Levels")
    if not users_df.empty:
        fig = px.bar(users_df, x="user_id", y="risk", color="risk")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No user data")

# ---------------- SEVERITY PIE ---------------- #
with col2:
    st.subheader("⚠️ Alert Severity")
    if not alerts_df.empty:
        severity_counts = alerts_df["severity"].value_counts().reset_index()
        severity_counts.columns = ["severity", "count"]

        fig2 = px.pie(severity_counts, names="severity", values="count")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.success("No alerts")

st.divider()

# ---------------- FILE ACCESS ---------------- #
st.subheader("📂 File Access Monitoring")

def highlight_sensitive(row):
    styles = [""] * len(row)

    # 🔴 Sensitive file → RED
    if row.get("file_sensitive"):
        styles = ["background-color: #ff4d4d; color: white"] * len(row)

    # 🟢 Latest file → GREEN (LIVE)
    if row.name == 0:
        styles = ["background-color: #00cc66; color: black"] * len(row)

    return styles


if not file_df.empty:

    # 🔥 Sort latest first
    file_df_sorted = file_df.sort_values("timestamp", ascending=False)

    # 🚨 LIVE FILE ALERT
    latest = file_df_sorted.iloc[0]

    st.warning(f"""
📂 **LIVE FILE ACCESS DETECTED**

User: {latest.get('user_id')}
File: {latest.get('file_path')}
Time: {latest.get('timestamp')}
""")

    # 🔔 Optional popup
    st.toast(f"📂 {latest.get('file_path')} opened!", icon="🚨")

    # Columns to show
    cols = ["timestamp", "user_id", "file_path", "file_sensitive"]
    cols = [c for c in cols if c in file_df.columns]

    # 📊 Table
    st.dataframe(
        file_df_sorted[cols]
        .reset_index(drop=True)
        .style.apply(highlight_sensitive, axis=1),
        use_container_width=True,
        height=300
    )

else:
    st.info("No file activity detected")

# ---------------- APP USAGE ---------------- #
col3, col4 = st.columns(2)

with col3:
    st.subheader("⏱️ Application Usage")
    if not summary_df.empty:
        summary_df["minutes"] = summary_df["time_spent_sec"] / 60
        fig3 = px.bar(summary_df, x="process_name", y="minutes", color="minutes")
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

# ---------------- RISK TREND ---------------- #
st.subheader("📈 Risk Trend")

if not process_df.empty and "timestamp" in process_df.columns:
    try:
        process_df["timestamp"] = pd.to_datetime(process_df["timestamp"])
        process_df["risk_score"] = process_df.get("risk_score", 0)

        trend = process_df.groupby(
            process_df["timestamp"].dt.floor("10S")
        )["risk_score"].mean().reset_index()

        fig4 = px.line(trend, x="timestamp", y="risk_score")
        st.plotly_chart(fig4, use_container_width=True)

    except:
        st.info("Not enough data")
else:
    st.info("Waiting for data")

st.divider()

# ---------------- 🚨 ALERTS (🔥 UPGRADED) ---------------- #
st.subheader("🚨 Alerts (Explainable AI)")

if alerts_df.empty:
    st.success("System safe")
else:
    alerts_df = alerts_df.sort_values("timestamp", ascending=False)

    for _, row in alerts_df.head(20).iterrows():

        severity = row.get("severity", "INFO")

        if severity == "CRITICAL":
            box = st.error
        elif severity == "HIGH":
            box = st.warning
        else:
            box = st.info

        reasons = row.get("reasons", [])
        if isinstance(reasons, list):
            reasons_text = "\n- ".join(reasons)
        else:
            reasons_text = "No details"

        box(f"""
🚨 **User:** {row.get('user_id')}
**Risk:** {row.get('risk')} ({severity})

🤖 **ML Score:** {row.get('ml_score', 0)}
⚠️ **ML Risk:** {row.get('ml_risk', 0)}

📌 **Reasons:**
- {reasons_text}
""")

st.divider()

# ---------------- INCIDENTS ---------------- #
st.subheader("🚨 Incidents")
try:
    st.write(requests.get(f"{API_BASE}/incidents").json())
except:
    st.warning("Error loading incidents")

# ---------------- BLOCKED IPS ---------------- #
st.subheader("🔐 Blocked IPs")
try:
    st.write(requests.get(f"{API_BASE}/blocked-ips").json())
except:
    st.warning("Error loading IPs")

# ---------------- DISABLED USERS ---------------- #
st.subheader("👤 Disabled Users")
try:
    st.write(requests.get(f"{API_BASE}/disabled-users").json())
except:
    st.warning("Error loading users")

# ---------------- BLOCK USER ---------------- #
st.subheader("🚫 Block User")

user = st.text_input("Enter Username")

if st.button("Block"):
    try:
        res = requests.post(f"{API_BASE}/block_user/{user}")
        st.success(res.json().get("status", "Done"))
    except:
        st.error("Failed")

st.caption("🔐 AI-powered real-time insider threat detection system")