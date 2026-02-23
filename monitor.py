import time
import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "sample_auth.log"
ALERT_FILE = "alerts.json"
BRUTE_FORCE_THRESHOLD = 5

failed_attempts = defaultdict(int)
blocked_ips = set()

pattern = re.compile(
    r"Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[0-9.]+)"
)

def block_ip(ip):
    if ip not in blocked_ips:
        print(f"🔒 Blocking IP: {ip}")
        blocked_ips.add(ip)

def log_event(event_data):
    with open(ALERT_FILE, "a") as f:
        json.dump(event_data, f)
        f.write("\n")

def monitor_logs():
    print("🚀 Advanced Cloud SSH Monitor Started...")
    print("Monitoring for failed SSH login attempts...\n")

    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            match = pattern.search(line)

            if match:
                user = match.group("user")
                ip = match.group("ip")
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                failed_attempts[ip] += 1

                severity = "medium"

                if failed_attempts[ip] >= BRUTE_FORCE_THRESHOLD:
                    severity = "high"
                    block_ip(ip)

                event = {
                    "event": "ssh_failed_login",
                    "user": user,
                    "ip": ip,
                    "attempts": failed_attempts[ip],
                    "timestamp": timestamp,
                    "severity": severity
                }

                print(f"⚠️ {severity.upper()} ALERT → {ip} ({failed_attempts[ip]} attempts)")
                log_event(event)

if __name__ == "__main__":
    try:
        monitor_logs()
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")
