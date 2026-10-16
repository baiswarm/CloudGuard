"""CloudGuard - analyzes SIMULATED cloud audit logs for suspicious patterns.

Alerts are suspicious patterns, not proof of an attack.
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# Detection settings (README and tests use the same values)
FAIL_THRESHOLD = 5          # failed logins needed to raise an alert
WINDOW_MINUTES = 10         # failures must happen within this many minutes
APPROVED_ADMINS = {"admin", "secops"}   # users allowed to change privileges
PRIVILEGE_EVENTS = {"privilege_change"}

REQUIRED_COLUMNS = ["timestamp", "username", "source_ip", "event_type", "status"]


class LogError(Exception):
    """Raised when the log file cannot be used at all."""


def parse_timestamp(text):
    """Parse an ISO 8601 timestamp. Naive times are treated as UTC."""
    value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def parse_row(row, line_number, warnings):
    """Turn one CSV row into an event dict, or return None if it is bad."""
    if None in row or any(not (row.get(c) or "").strip() for c in REQUIRED_COLUMNS):
        warnings.append(f"Line {line_number}: skipped (missing or extra fields)")
        return None
    try:
        when = parse_timestamp(row["timestamp"])
    except ValueError:
        warnings.append(f"Line {line_number}: skipped (invalid timestamp)")
        return None
    return {
        "timestamp": when,
        "username": row["username"].strip(),
        "source_ip": row["source_ip"].strip(),
        "event_type": row["event_type"].strip().lower(),
        "status": row["status"].strip().lower(),
    }


def read_events(path):
    """Read the CSV. Returns (events, warnings). Raises LogError if unusable."""
    events, warnings = [], []
    try:
        with open(path, newline="", encoding="utf-8") as log_file:
            reader = csv.DictReader(log_file)
            if not reader.fieldnames:
                raise LogError("Log file is empty.")
            missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
            if missing:
                raise LogError("Missing required columns: " + ", ".join(missing))
            for line_number, row in enumerate(reader, start=2):
                event = parse_row(row, line_number, warnings)
                if event:
                    events.append(event)
    except FileNotFoundError:
        raise LogError(f"File not found: {path}")
    except (OSError, UnicodeDecodeError, csv.Error) as error:
        raise LogError(f"Could not read file: {error}")
    return events, warnings


def make_alert(rule, severity, reason, event):
    return {
        "rule": rule,
        "severity": severity,
        "reason": reason,
        "timestamp": event["timestamp"].isoformat(),
        "username": event["username"],
        "source_ip": event["source_ip"],
    }


def failed_logins_by_ip(events):
    """Group failed login events by source IP (events must be time-sorted)."""
    groups = defaultdict(list)
    for event in events:
        if event["event_type"] == "login" and event["status"] == "failure":
            groups[event["source_ip"]].append(event)
    return groups


def find_burst(failures, threshold, window):
    """Return the first `threshold` failures that fit inside `window`, or None."""
    for start in range(len(failures) - threshold + 1):
        group = failures[start:start + threshold]
        if group[-1]["timestamp"] - group[0]["timestamp"] <= window:
            return group
    return None


def detect_brute_force(events, threshold=FAIL_THRESHOLD, window_minutes=WINDOW_MINUTES):
    """Rule 1: many failed logins from one IP inside the time window (one alert per IP)."""
    window = timedelta(minutes=window_minutes)
    alerts = []
    for ip, failures in failed_logins_by_ip(events).items():
        burst = find_burst(failures, threshold, window)
        if burst:
            names = ", ".join(sorted({e["username"] for e in burst}))
            alert = make_alert(
                "repeated_failed_logins", "high",
                f"{len(burst)} failed logins from {ip} within {window_minutes} minutes",
                burst[-1])
            alert["username"] = names
            alerts.append(alert)
    return alerts


def detect_success_after_failures(events, threshold=FAIL_THRESHOLD,
                                  window_minutes=WINDOW_MINUTES):
    """Rule 2: a successful login right after enough recent failures from the same IP."""
    window = timedelta(minutes=window_minutes)
    failures_by_ip = failed_logins_by_ip(events)
    alerts = []
    for event in events:
        if event["event_type"] != "login" or event["status"] != "success":
            continue
        recent = [f for f in failures_by_ip.get(event["source_ip"], [])
                  if event["timestamp"] - window <= f["timestamp"] <= event["timestamp"]]
        if len(recent) >= threshold:
            alerts.append(make_alert(
                "success_after_failures", "critical",
                f"Successful login after {len(recent)} failed logins from the same IP "
                f"within {window_minutes} minutes", event))
    return alerts


def detect_privilege_changes(events):
    """Rule 3: a successful privilege change by a user NOT in APPROVED_ADMINS."""
    alerts = []
    for event in events:
        if (event["event_type"] in PRIVILEGE_EVENTS and event["status"] == "success"
                and event["username"] not in APPROVED_ADMINS):
            alerts.append(make_alert(
                "unexpected_privilege_change", "high",
                f"Privilege change by '{event['username']}', who is not an approved admin",
                event))
    return alerts


def analyze(events, threshold=FAIL_THRESHOLD, window_minutes=WINDOW_MINUTES):
    """Run all detections and return alerts sorted by time."""
    events = sorted(events, key=lambda e: e["timestamp"])
    alerts = (detect_brute_force(events, threshold, window_minutes)
              + detect_success_after_failures(events, threshold, window_minutes)
              + detect_privilege_changes(events))
    return sorted(alerts, key=lambda a: a["timestamp"])


def write_report(alerts, warnings, settings, path):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "Alerts show suspicious patterns in simulated logs, not proof of an attack.",
        "settings": settings,
        "alert_count": len(alerts),
        "alerts": alerts,
        "warnings": warnings,
    }
    try:
        with open(path, "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2)
    except OSError as error:
        raise LogError(f"Could not write report: {error}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="CloudGuard - simulated cloud log analyzer")
    parser.add_argument("--input", default="sample_logs.csv", help="CSV log file")
    parser.add_argument("--output", default="report.json", help="JSON report path")
    parser.add_argument("--threshold", type=int, default=FAIL_THRESHOLD,
                        help="failed logins that trigger an alert")
    parser.add_argument("--window-minutes", type=int, default=WINDOW_MINUTES,
                        help="time window in minutes")
    args = parser.parse_args(argv)

    if args.threshold < 1 or args.window_minutes < 1:
        print("Error: --threshold and --window-minutes must be 1 or more.")
        return 1
    try:
        events, warnings = read_events(args.input)
        alerts = analyze(events, args.threshold, args.window_minutes)
        settings = {"fail_threshold": args.threshold, "window_minutes": args.window_minutes,
                    "approved_admins": sorted(APPROVED_ADMINS)}
        write_report(alerts, warnings, settings, args.output)
    except LogError as error:
        print(f"Error: {error}")
        return 1

    for warning in warnings:
        print("Warning:", warning)
    print(f"Read {len(events)} events, raised {len(alerts)} alerts -> {args.output}")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['timestamp']} "
              f"{alert['username']} {alert['source_ip']}: {alert['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())