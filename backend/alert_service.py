import smtplib
from email.message import EmailMessage
import pandas as pd
import os

# 🔐 CONFIG (CHANGE THESE)
SENDER_EMAIL = "kunalthepro007@gmail.com"
APP_PASSWORD = "hijhvttwailypwut"   # Gmail App Password
RECEIVER_EMAIL = "darkseidd7@gmail.com"


def send_alert_email(user_id, risk, severity, reasons, events):

    msg = EmailMessage()
    msg["Subject"] = f"🚨 {severity} Insider Threat Alert - {user_id}"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    # ---------------- EMAIL BODY ---------------- #
    reason_text = "\n- ".join(reasons)

    msg.set_content(f"""
🚨 SECURITY ALERT DETECTED

User: {user_id}
Severity: {severity}
Risk Score: {risk}

⚠️ Reasons:
- {reason_text}

🧠 AI Insight:
User behavior is anomalous and deviates from normal patterns.

🔐 Action Taken:
System has logged the activity and triggered monitoring.

📎 Detailed report attached (CSV)
""")

    # ---------------- CSV ATTACHMENT ---------------- #
    df = pd.DataFrame(events)
    file_path = "alert_report.csv"
    df.to_csv(file_path, index=False)

    with open(file_path, "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="octet-stream",
            filename="alert_report.csv"
        )

    # ---------------- SEND EMAIL ---------------- #
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)

        print("📧 Alert email sent successfully!")

    except Exception as e:
        print("❌ Email error:", e)

    # cleanup
    if os.path.exists(file_path):
        os.remove(file_path)