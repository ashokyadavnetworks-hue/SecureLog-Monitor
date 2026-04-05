import re
import json
import csv
import time
import logging
from collections import defaultdict
from pathlib import Path

LOG_FILE = "network_logs.txt"
JSON_OUTPUT = "parsed_logs.json"
CSV_OUTPUT = "parsed_logs.csv"
ALERT_LOG = "security_alerts.log"

FAILED_LOGIN_THRESHOLD = 5
DENIED_TRAFFIC_THRESHOLD = 5

LOG_PATTERN = re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+%\S+-(\d+)-\S+:\s+(.*)")

logging.basicConfig(
    filename=ALERT_LOG,
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

parsed_logs = []
failed_logins = defaultdict(int)
denied_traffic = defaultdict(int)
alerted_failed_ips = set()
alerted_denied_ips = set()
recent_failed_ips = set()


def parse_line(line: str):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    timestamp, device, security_level, message = match.groups()
    return {
        "timestamp": timestamp,
        "device": device,
        "security_level": security_level,
        "message": message
    }


def write_outputs():
    with open(JSON_OUTPUT, "w", encoding="utf-8") as jf:
        json.dump(parsed_logs, jf, indent=4)

    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=["timestamp", "device", "security_level", "message"])
        writer.writeheader()
        writer.writerows(parsed_logs)


def process_entry(entry: dict):
    msg = entry["message"]

    login_fail = re.search(r"Login failed.*from (\d+\.\d+\.\d+\.\d+)", msg, re.IGNORECASE)
    login_success = re.search(r"Login succeeded.*from (\d+\.\d+\.\d+\.\d+)", msg, re.IGNORECASE)
    denied_conn = re.search(r"(Denied|Deny|Blocked|ACL deny).*?(\d+\.\d+\.\d+\.\d+)", msg, re.IGNORECASE)

    if login_fail:
        ip = login_fail.group(1)
        failed_logins[ip] += 1
        recent_failed_ips.add(ip)

        if failed_logins[ip] >= FAILED_LOGIN_THRESHOLD and ip not in alerted_failed_ips:
            alert_msg = f"Possible brute-force attack detected from {ip} ({failed_logins[ip]} failed logins)"
            print(f"[ALERT] {alert_msg}")
            logging.warning(alert_msg)
            alerted_failed_ips.add(ip)

    if login_success:
        ip = login_success.group(1)
        if ip in recent_failed_ips and failed_logins[ip] >= 3:
            alert_msg = f"Suspicious login success after multiple failures from {ip}"
            print(f"[ALERT] {alert_msg}")
            logging.warning(alert_msg)
        recent_failed_ips.discard(ip)

    if denied_conn:
        ip = denied_conn.group(2)
        denied_traffic[ip] += 1

        if denied_traffic[ip] >= DENIED_TRAFFIC_THRESHOLD and ip not in alerted_denied_ips:
            alert_msg = f"Possible port scan or suspicious denied traffic from {ip} ({denied_traffic[ip]} denied attempts)"
            print(f"[ALERT] {alert_msg}")
            logging.warning(alert_msg)
            alerted_denied_ips.add(ip)


def process_existing_lines():
    log_path = Path(LOG_FILE)
    if not log_path.exists():
        print(f"Log file not found: {LOG_FILE}")
        return 0

    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines:
        entry = parse_line(line)
        if entry:
            parsed_logs.append(entry)
            process_entry(entry)

    write_outputs()
    return len(lines)


def monitor_logs():
    log_path = Path(LOG_FILE)
    if not log_path.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    print(f"Monitoring {LOG_FILE} in real time...")
    print("Press Ctrl + C to stop.\n")

    processed_lines = process_existing_lines()
    print(f"Loaded existing lines: {processed_lines}")

    with open(log_path, "r", encoding="utf-8") as f:
        for _ in range(processed_lines):
            f.readline()

        while True:
            line = f.readline()

            if not line:
                time.sleep(1)
                continue

            entry = parse_line(line)
            if entry:
                parsed_logs.append(entry)
                print(f"[LOG] {entry['timestamp']} | {entry['device']} | {entry['message']}")
                process_entry(entry)
                write_outputs()


if __name__ == "__main__":
    try:
        monitor_logs()
    except KeyboardInterrupt:
        print("\nStopped real-time monitoring.")
