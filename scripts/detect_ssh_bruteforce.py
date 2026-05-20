import json
import re
from collections import Counter
from pathlib import Path

LOG_PATH = Path("sample-logs/auth.log")
THRESHOLD = 5

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+) port"
)

def detect_ssh_bruteforce(log_path: Path, threshold: int):
    failed_counts = Counter()

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                source_ip = match.group("ip")
                failed_counts[source_ip] += 1

    alerts = []

    for source_ip, failed_count in failed_counts.items():
        if failed_count >= threshold:
            alerts.append({
                "type": "SSH_BRUTE_FORCE",
                "source_ip": source_ip,
                "failed_count": failed_count,
                "severity": "HIGH",
                "recommendation": "Investigate the source IP and restrict SSH access"
            })

    return alerts

def main():
    alerts = detect_ssh_bruteforce(LOG_PATH, THRESHOLD)
    print(json.dumps(alerts, indent=2))

if __name__ == "__main__":
    main()