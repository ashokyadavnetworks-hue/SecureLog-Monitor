import re
import json
import csv
import logging
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "network_logs.txt"
ALERT_FILE = BASE_DIR / "security_alerts.log"
JSON_FILE = BASE_DIR / "parsed_logs.json"
CSV_FILE = BASE_DIR / "parsed_logs.csv"


def parse_logs(log_lines):
    """
    Parse Cisco-style syslog lines into structured dictionaries.

    Expected format:
    <Month> <Day> <HH:MM:SS> <Device> %<FACILITY>-<SEVERITY>-<MNEMONIC>: <message>
    """
    parsed = []
    pattern = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+%\S+-(\d+)-\S+:\s+(.*)"
    )

    for line in log_lines:
        match = pattern.match(line.strip())
        if match:
            timestamp, device, security_level, message = match.groups()
            parsed.append(
                {
                    "timestamp": timestamp,
                    "device": device,
                    "security_level": int(security_level),
                    "message": message,
                }
            )
    return parsed


def detect_threats(parsed_logs):
    """
    Detect:
    1. Brute-force login attempts (5+ failures from same IP)
    2. Successful login after multiple failures
    3. Repeated denied traffic / possible scanning (4+ denies from same IP)
    """
    failed_logins = defaultdict(int)
    denied_traffic = defaultdict(int)
    alerts = []

    for entry in parsed_logs:
        msg = entry["message"]

        login_fail = re.search(r"Login failed.*from (\d+\.\d+\.\d+\.\d+)", msg, re.IGNORECASE)
        if login_fail:
            ip = login_fail.group(1)
            failed_logins[ip] += 1

            if failed_logins[ip] == 5:
                alerts.append(
                    f"ALERT: Possible brute-force login attempt from {ip} "
                    f"({failed_logins[ip]} failures)"
                )

        login_success = re.search(r"Login successful.*from (\d+\.\d+\.\d+\.\d+)", msg, re.IGNORECASE)
        if login_success:
            ip = login_success.group(1)
            if failed_logins[ip] >= 3:
                alerts.append(
                    f"ALERT: Suspicious login success from {ip} after "
                    f"{failed_logins[ip]} failed attempts"
                )

        denied_match = re.search(
            r"Denied (?:tcp|udp|icmp).*from (\d+\.\d+\.\d+\.\d+)",
            msg,
            re.IGNORECASE,
        )
        if denied_match:
            ip = denied_match.group(1)
            denied_traffic[ip] += 1

            if denied_traffic[ip] == 4:
                alerts.append(
                    f"ALERT: Possible port scan or repeated denied traffic from {ip} "
                    f"({denied_traffic[ip]} denies)"
                )

    return alerts


def export_json(parsed_logs):
    with open(JSON_FILE, "w", encoding="utf-8") as jf:
        json.dump(parsed_logs, jf, indent=4)


def export_csv(parsed_logs):
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=["timestamp", "device", "security_level", "message"])
        writer.writeheader()
        writer.writerows(parsed_logs)


def write_alerts(alerts):
    logging.basicConfig(
        filename=ALERT_FILE,
        level=logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True,
    )

    if not alerts:
        logging.warning("No suspicious activity detected in current log set.")
        return

    for alert in alerts:
        logging.warning(alert)


def main():
    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    parsed_logs = parse_logs(log_lines)
    alerts = detect_threats(parsed_logs)

    export_json(parsed_logs)
    export_csv(parsed_logs)
    write_alerts(alerts)

    print(f"Parsed {len(parsed_logs)} log entries.")
    print(f"Generated {len(alerts)} alert(s).")
    print(f"JSON output: {JSON_FILE}")
    print(f"CSV output: {CSV_FILE}")
    print(f"Alerts log: {ALERT_FILE}")


if __name__ == "__main__":
    main()
