import json

def simulate_user_lockout(alerts_file):
    with open(alerts_file) as f:
        alerts = json.load(f)

    users_locked = set()

    for alert in alerts:
        log = alert["log"]
        flags = alert["flags"]

        user = log.get("user", "unknown")
        if any("Failed Login" in f or "Privilege Escalation" in f for f in flags):
            users_locked.add(user)

    for user in users_locked:
        print(f"[SOAR] 🔒 Simulating lockout for suspicious user: {user}")

if __name__ == "__main__":
    simulate_user_lockout("outputs/alerts.json")
