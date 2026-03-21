import requests
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

HIGHER_AUTHORITY_EMAIL = "admin@example.com"
RISK_THRESHOLD = 80


def send_email_alert(user_data):
    try:
        subject = f"🚨 Insider Threat Alert - {user_data['user']}"
        
        body = f"""
        ALERT GENERATED: {datetime.now()}

        User: {user_data['user']}
        Risk Score: {user_data['risk_score']}
        Location: {user_data['location']}
        Malicious Process: {user_data['malicious_process_detected']}
        Session Duration: {user_data['session_duration']}

        ACTION REQUIRED: Review & Block if necessary.
        """

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = "soc-system@example.com"
        msg["To"] = HIGHER_AUTHORITY_EMAIL

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login("taydekunal24@gmail.com", "abcdefghijklmnop")
        server.send_message(msg)
        server.quit()

        print("✅ Email alert sent")

    except Exception as e:
        print("❌ Email failed:", e)


def escalate_if_needed(user_data):
    if user_data["risk_score"] >= RISK_THRESHOLD:
        print("🚨 High risk detected. Escalating...")
        send_email_alert(user_data)
        return True
    return False