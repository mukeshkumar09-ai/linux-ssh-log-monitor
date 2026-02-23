import requests
import json
from datetime import datetime

API_URL = "https://linux-ssh-log-monitor.onrender.com/api/store"

def send_to_dashboard(ip, user, attempts, severity):
    payload = {
        "ip": ip,
        "user": user,
        "attempts": attempts,
        "severity": severity,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        requests.post(API_URL, json=payload)
    except:
        pass
