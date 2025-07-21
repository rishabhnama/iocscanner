import json
import re
from utils.reputation_api import check_ip_reputation

# Load bad IPs list (or use online feed)
with open("utils/known_bad_ips.txt") as f:
    bad_ips = set(ip.strip() for ip in f.readlines())

def is_suspicious(log):
    flags = []

    if "EventID" in log and log["EventID"] == 4625:
        flags.append("Failed Login (Windows)")

    if "command" in log and "sudo" in log["command"]:
        flags.append("Privilege Escalation (Linux)")

    if "object" in log and any(path in log["object"] for path in ["/etc/shadow", "/var/log/auth.log"]):
        flags.append("Sensitive File Access")

    if "sourceIPAddress" in log:
        ip = log["sourceIPAddress"]
        if ip in bad_ips or check_ip_reputation(ip):
            flags.append(f"Known Bad IP: {ip}")

    return flags

def scan_logs(input_path, output_path):
    with open(input_path) as f:
        logs = [json.loads(line) for line in f]

    alerts = []
    for log in logs:
        flags = is_suspicious(log)
        if flags:
            alerts.append({
                "timestamp": log.get("timestamp"),
                "log": log,
                "flags": flags,
                "reputation_score": len(flags) * 10  # Simple scoring logic
            })

    with open(output_path, "w") as f:
        json.dump(alerts, f, indent=2)

if __name__ == "__main__":
    scan_logs("logs/sample_logs.json", "outputs/alerts.json")
