import json

def simulate_firewall_block(alerts_file):
    with open(alerts_file) as f:
        alerts = json.load(f)

    blocked_ips = set()

    for alert in alerts:
        flags = alert["flags"]
        if any("Known Bad IP" in f for f in flags):
            ip = alert["log"].get("sourceIPAddress", None)
            if ip:
                blocked_ips.add(ip)

    for ip in blocked_ips:
        print(f"[SOAR] 🛑 Simulating firewall block for IP: {ip}")

if __name__ == "__main__":
    simulate_firewall_block("outputs/alerts.json")
