"""Simple defensive log analyzer for identifying suspicious login activity."""
import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_LOG = Path(__file__).parent / "sample_logs" / "auth.log"

PATTERNS = {
    "failed_login": re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"),
    "accepted_login": re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"),
    "invalid_user": re.compile(r"Invalid user (\S+) from ([\d.]+)"),
}


def analyze_lines(lines, threshold=3):
    failed_by_ip = Counter()
    failed_by_user = Counter()
    successful_by_ip = Counter()
    events = []
    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        match = PATTERNS["failed_login"].search(line)
        if match:
            user, ip = match.groups()
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1
            events.append({"line": line_number, "event": "FAILED_LOGIN", "user": user, "ip": ip, "details": "Failed password attempt"})
            continue
        match = PATTERNS["invalid_user"].search(line)
        if match:
            user, ip = match.groups()
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1
            events.append({"line": line_number, "event": "INVALID_USER", "user": user, "ip": ip, "details": "Login attempted for unknown account"})
            continue
        match = PATTERNS["accepted_login"].search(line)
        if match:
            user, ip = match.groups()
            successful_by_ip[ip] += 1
            events.append({"line": line_number, "event": "SUCCESSFUL_LOGIN", "user": user, "ip": ip, "details": "Successful authentication"})

    alerts = []
    for ip, count in failed_by_ip.most_common():
        if count >= threshold:
            alerts.append({"severity": "HIGH" if count >= threshold * 2 else "MEDIUM", "type": "POSSIBLE_BRUTE_FORCE", "ip": ip, "count": count, "message": f"{count} failed/invalid login attempts from {ip}"})
    for ip in failed_by_ip.keys() & successful_by_ip.keys():
        alerts.append({"severity": "MEDIUM", "type": "FAILURES_AND_SUCCESS", "ip": ip, "count": failed_by_ip[ip], "message": f"Both failed and successful logins seen from {ip}; review context"})
    return events, alerts, failed_by_ip, failed_by_user, successful_by_ip


def write_csv(path, rows, columns):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Analyze SSH authentication logs for suspicious login activity.")
    parser.add_argument("logfile", nargs="?", default=str(DEFAULT_LOG), help="Path to a text auth log file")
    parser.add_argument("--threshold", type=int, default=3, help="Failed attempts from one IP before alerting (default: 3)")
    parser.add_argument("--out", default="reports", help="Directory for CSV reports (default: reports)")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    log_path = Path(args.logfile)
    if not log_path.is_file():
        parser.error(f"Log file not found: {log_path}")
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    events, alerts, failed_by_ip, failed_by_user, successful_by_ip = analyze_lines(lines, args.threshold)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "events.csv", events, ["line", "event", "user", "ip", "details"])
    write_csv(out_dir / "alerts.csv", alerts, ["severity", "type", "ip", "count", "message"])
    print("\n=== Cyber Log Threat Detector ===")
    print(f"Log file: {log_path}\nLines analyzed: {len(lines)}\nRecognized events: {len(events)}\nAlerts: {len(alerts)}")
    print("\nFailed attempts by IP:")
    for ip, count in failed_by_ip.most_common(): print(f"  {ip}: {count}")
    print("\nAlerts:")
    if not alerts: print("  No alert matched the configured rules.")
    for alert in alerts: print(f"  [{alert['severity']}] {alert['type']} - {alert['message']}")
    print(f"\nCSV reports saved in: {out_dir.resolve()}")
    print("Note: Rule-based alerts are indicators for review, not proof of an attack.")

if __name__ == "__main__":
    main()
