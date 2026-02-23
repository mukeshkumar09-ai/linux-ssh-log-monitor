import time
import re
import requests
from datetime import datetime
from collections import defaultdict

LOG_FILE = "sample_auth.log"   # change to /var/log/auth.log on real server
API_URL = "https://linux-ssh-log-monitor.onrender.com/api/store"

attempt_tracker = defaultdict(int)

print("🚀 Advanced Cloud SSH Monitor Started...")
print("Monitoring for failed SSH login attempts...\n")

def send_to_dashboard(ip, user, attempts, severity):
    payload = {
        "ip": ip,
        "user": user,
        "attempts": attempts,
        "severity": severity,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=5)
        print("Sent to cloud:", response.status_code)
    except Exception as e:
        print("Failed to send:", e)

def monitor_logs():
    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            if "Failed password" in line:
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                user_match = re.search(r"for (invalid user )?(\w+)", line)

                if ip_match and user_match:
                    ip = ip_match.group(1)
                    user = user_match.group(2)

                    attempt_tracker[ip] += 1
                    attempts = attempt_tracker[ip]

                    if attempts >= 5:
                        severity = "HIGH"
                    else:
                        severity = "MEDIUM"

                    print(f"[ALERT] {ip} - {user} - Attempts: {attempts} - {severity}")

                    send_to_dashboard(ip, user, attempts, severity)

monitor_logs()
