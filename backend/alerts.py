import requests
from config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

def send_telegram_alert(user, risk_score):
    message = f"""
🚨 INSIDER THREAT DETECTED
User: {user}
Risk Score: {risk_score}
Action: Auto Response Triggered
"""

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    
    requests.post(url, data={
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    })