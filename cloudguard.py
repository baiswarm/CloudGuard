"""CloudGuard - analyzes SIMULATED cloud audit logs for suspicious patterns.

Alerts are suspicious patterns, not proof of an attack.

Exact behaviour (also documented in the README):

* Time: every timestamp is converted to an exact UTC instant. Timestamps with no
  offset are ASSUMED to be UTC (one summary warning is raised). Windows are
  INCLUSIVE: an event exactly ``window_minutes`` old still counts. Ordering and
  windows use the instant, never the text of the timestamp.
* Event order: events are sorted by (instant, CSV line, username, ip, type, status),
  so shuffled input gives identical alerts. Events at the same instant are treated
  as simultaneous: a failure at the same instant as a success counts as BEFORE it.
* Rule 1 (brute force): per source IP, a *burst* starts when ``threshold`` failures
  fit inside ``window_minutes``. It continues while every new failure still has at
  least ``threshold`` unclaimed failures inside its own trailing window. A failure
  belongs to at most one burst. Later separate bursts raise separate alerts.
* Rule 2 (success after failures): a successful login from an IP with at least
  ``threshold`` failures in the preceding window is critical. All qualifying
  successes that follow the same burst give ONE alert; a later, separate burst
  followed by a success gives another.
* Rule 3 (privilege change): every successful privilege change by a user not in
  APPROVED_ADMINS is its own alert (no de-duplication). Usernames are compared
  exactly (case-sensitive). The log has no target/role fields, so none are reported.
* Only ``success`` and ``failure`` statuses are accepted. Anything else is skipped
  with a warning; there is deliberately NO alias policy ("failed" is not "failure").
"""
import argparse
import csv
import io
import json
import sys
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# Detection settings (README and tests use the same values)
FAIL_THRESHOLD = 5          # failed logins needed to raise an alert
WINDOW_MINUTES = 10         # failures must happen within this many minutes
MAX_WINDOW_MINUTES = 525_600    # one year; stops absurd values overflowing timedelta
APPROVED_ADMINS = {"admin", "secops"}   # users allowed to change privileges
PRIVILEGE_EVENTS = {"privilege_change"}

REQUIRED_COLUMNS = ["timestamp", "username", "source_ip", "event_type", "status"]
KNOWN_STATUSES = ("success", "failure")
KNOWN_EVENT_TYPES = ("login", "privilege_change")
MAX_WARNINGS = 200          # per file; extra warnings are counted, not stored

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_MICROSECOND = timedelta(microseconds=1)
_MICROS_PER_MINUTE = 60 * 1_000_000


class LogError(Exception):
    """Raised when the log file cannot be used at all."""


# ----------------------------------------------------------------------------
# Settings validation and small helpers
# ----------------------------------------------------------------------------

def validate_settings(threshold, window_minutes):
    """Raise ValueError with a clear message for unusable detection settings."""
    for name, value in (("threshold", threshold), ("window_minutes", window_minutes)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be a whole number, got {value!r}")
        if value < 1:
            raise ValueError(f"{name} must be 1 or more, got {value}")
    if window_minutes > MAX_WINDOW_MINUTES:
        raise ValueError(f"window_minutes must be at most {MAX_WINDOW_MINUTES}, "
                         f"got {window_minutes}")


def _clip(value, limit=40):
    """Quote an untrusted value for a message: truncated, control characters escaped."""
    text = str(value)
    return repr(text[:limit] + ("..." if len(text) > limit else ""))


def _instant(moment):
    """Exact integer microseconds since the Unix epoch (naive input is taken as UTC)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment - _EPOCH) // _ONE_MICROSECOND


def _utc(moment):
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _event_key(event):
    line = event.get("line")
    return (_instant(event["timestamp"]), 0 if line is None else line, event["username"],
            event["source_ip"], event["event_type"], event["status"])


def sort_events(events):
    """Deterministic chronological order (see module docstring). Returns a new list."""
    return sorted(events, key=_event_key)


def _is_failed_login(event):
    return event["event_type"] == "login" and event["status"] == "failure"


def _is_successful_login(event):
    return event["event_type"] == "login" and event["status"] == "success"


# ----------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------

def parse_timestamp_ex(text):
    """Parse ISO 8601. Returns (UTC datetime, assumed_utc). Raises ValueError."""
    text = text.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    value = datetime.fromisoformat(text)
    assumed = value.tzinfo is None
    if assumed:
        value = value.replace(tzinfo=timezone.utc)
    try:
        return value.astimezone(timezone.utc), assumed
    except OverflowError:
        raise ValueError("timestamp out of range") from None


def parse_timestamp(text):
    """Parse an ISO 8601 timestamp into an aware UTC datetime. Naive times mean UTC."""
    return parse_timestamp_ex(text)[0]


class _Warnings(list):
    """A list of warning strings that stops storing after MAX_WARNINGS."""

    def __init__(self):
        super().__init__()
        self.suppressed = 0

    def append(self, message):
        if len(self) < MAX_WARNINGS:
            super().append(message)
        else:
            self.suppressed += 1


def parse_row(row, line_number, warnings):
    """Turn one CSV row into an event dict, or return None if it is bad."""
    if None in row or any(not (row.get(c) or "").strip() for c in REQUIRED_COLUMNS):
        warnings.append(f"Line {line_number}: skipped (missing or extra fields)")
        return None
    try:
        when, assumed = parse_timestamp_ex(row["timestamp"])
    except ValueError:
        warnings.append(f"Line {line_number}: skipped (invalid timestamp "
                        f"{_clip(row['timestamp'])})")
        return None
    status = row["status"].strip().lower()
    if status not in KNOWN_STATUSES:
        warnings.append(f"Line {line_number}: skipped (unknown status {_clip(status)}; "
                        f"expected 'success' or 'failure')")
        return None
    return {
        "timestamp": when,
        "username": row["username"].strip(),
        "source_ip": row["source_ip"].strip(),
        "event_type": row["event_type"].strip().lower(),
        "status": status,
        "line": line_number,
        "tz_assumed": assumed,
    }


@dataclass
class LogData:
    """Result of reading a log: parsed events plus what happened to every row."""
    events: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    rows_read: int = 0          # non-blank data rows seen
    rows_skipped: int = 0       # rows that produced no event


def parse_log_stream(stream):
    """Parse CSV text from a file-like object. Raises LogError if unusable."""
    reader = csv.DictReader(stream)
    if not reader.fieldnames:
        raise LogError("Log file is empty.")
    names = [(name or "").strip().lower() for name in reader.fieldnames]
    repeated = sorted({n for n in names if n and names.count(n) > 1})
    if repeated:
        raise LogError("Duplicate column names (after trimming and ignoring case): "
                       + ", ".join(repeated))
    missing = [c for c in REQUIRED_COLUMNS if c not in names]
    if missing:
        raise LogError("Missing required columns: " + ", ".join(missing))
    reader.fieldnames = names

    log = LogData()
    warnings = _Warnings()
    other_types = {}                    # event_type -> [row count, first line]
    for row in reader:
        log.rows_read += 1
        event = parse_row(row, reader.line_num, warnings)
        if event is None:
            log.rows_skipped += 1
            continue
        log.events.append(event)
        if event["event_type"] not in KNOWN_EVENT_TYPES:
            entry = other_types.setdefault(event["event_type"], [0, event["line"]])
            entry[0] += 1

    for name, (count, first_line) in sorted(other_types.items()):
        warnings.append(f"{count} rows have event_type {_clip(name)} (first at line "
                        f"{first_line}); kept as events but no detection rule uses them")
    assumed = sum(1 for e in log.events if e["tz_assumed"])
    if assumed:
        warnings.append(f"{assumed} timestamp(s) had no timezone offset and were treated as UTC")
    log.warnings = list(warnings)
    if warnings.suppressed:
        log.warnings.append(f"... {warnings.suppressed} more warning(s) suppressed")
    return log


def read_log(path):
    """Read a CSV file (UTF-8, BOM allowed). Returns LogData. Raises LogError."""
    try:
        with open(path, newline="", encoding="utf-8-sig") as log_file:
            return parse_log_stream(log_file)
    except FileNotFoundError:
        raise LogError(f"File not found: {path}")
    except (OSError, UnicodeDecodeError, csv.Error) as error:
        raise LogError(f"Could not read file: {error}")


def parse_log_bytes(data):
    """Parse uploaded bytes directly in memory (no temporary file). Raises LogError."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise LogError("File is not valid UTF-8 text.")
    try:
        return parse_log_stream(io.StringIO(text, newline=""))
    except csv.Error as error:
        raise LogError(f"Could not read file: {error}")


def read_events(path):
    """Read the CSV. Returns (events, warnings). Raises LogError if unusable."""
    log = read_log(path)
    return log.events, log.warnings


# ----------------------------------------------------------------------------
# Alerts
# ----------------------------------------------------------------------------

def make_alert(rule, severity, reason, event, evidence=None):
    """Build an alert. `evidence` are the events behind it, in chronological order."""
    evidence = [event] if evidence is None else evidence
    return {
        "rule": rule,
        "severity": severity,
        "reason": reason,
        "timestamp": _utc(event["timestamp"]).isoformat(),
        "username": event["username"],
        "source_ip": event["source_ip"],
        "first_seen": _utc(evidence[0]["timestamp"]).isoformat(),
        "last_seen": _utc(evidence[-1]["timestamp"]).isoformat(),
        "event_count": len(evidence),
        "usernames": sorted({e["username"] for e in evidence}),
        "source_lines": [e["line"] for e in evidence if e.get("line") is not None],
    }


def _duration_text(delta):
    seconds = int(delta.total_seconds())
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    parts = ([f"{hours}h"] if hours else []) + ([f"{minutes}m"] if minutes else []) \
        + ([f"{seconds}s"] if seconds or not (hours or minutes) else [])
    return " ".join(parts)


def _failures_by_ip(events):
    """{ip: (failure events, their instants)} - events must already be sorted."""
    grouped = defaultdict(list)
    for event in events:
        if _is_failed_login(event):
            grouped[event["source_ip"]].append(event)
    return {ip: (items, [_instant(e["timestamp"]) for e in items])
            for ip, items in grouped.items()}


def _find_bursts(times, threshold, window_us):
    """Find bursts in one IP's sorted failure instants. O(n).

    Returns [(start, trigger, end)] index triples (inclusive): `start` is the first
    failure of the burst, `trigger` the failure at which `threshold` was first
    reached, `end` the last failure that still met the threshold.
    """
    bursts, current = [], None
    low = floor = 0
    for i, moment in enumerate(times):
        if current is not None and moment - times[i - 1] > window_us:
            bursts.append(tuple(current))
            floor, current = current[2] + 1, None
        low = max(low, floor)
        while moment - times[low] > window_us:
            low += 1
        if i - low + 1 >= threshold:
            if current is None:
                current = [low, i, i]
            else:
                current[2] = i
        elif current is not None:
            bursts.append(tuple(current))
            floor, current = current[2] + 1, None
    if current is not None:
        bursts.append(tuple(current))
    return bursts


def detect_brute_force(events, threshold=FAIL_THRESHOLD, window_minutes=WINDOW_MINUTES):
    """Rule 1: many failed logins from one IP inside the window (one alert per burst)."""
    validate_settings(threshold, window_minutes)
    window_us = window_minutes * _MICROS_PER_MINUTE
    alerts = []
    for ip, (failures, times) in _failures_by_ip(sort_events(events)).items():
        for start, trigger, end in _find_bursts(times, threshold, window_us):
            burst = failures[start:end + 1]
            span = _duration_text(burst[-1]["timestamp"] - burst[0]["timestamp"])
            alerts.append(make_alert(
                "repeated_failed_logins", "high",
                f"{len(burst)} failed logins from {ip} over {span} "
                f"(threshold: {threshold} within {window_minutes} minutes)",
                failures[trigger], burst))
            alerts[-1]["username"] = ", ".join(alerts[-1]["usernames"])
    return alerts


def find_qualifying_successes(events, threshold=FAIL_THRESHOLD, window_minutes=WINDOW_MINUTES):
    """Every successful login with >= threshold same-IP failures in the preceding window.

    Returns [(success_event, failure_count)] in chronological order. Uses two binary
    searches per success instead of rescanning every failure (O(n log n) overall).
    """
    validate_settings(threshold, window_minutes)
    return [(success, count) for success, _support, count
            in _qualifying(sort_events(events), threshold, window_minutes)]


def _qualifying(events, threshold, window_minutes):
    window_us = window_minutes * _MICROS_PER_MINUTE
    failures = _failures_by_ip(events)
    for event in events:
        if not _is_successful_login(event) or event["source_ip"] not in failures:
            continue
        items, times = failures[event["source_ip"]]
        moment = _instant(event["timestamp"])
        high = bisect_right(times, moment)
        low = bisect_left(times, moment - window_us)
        if high - low >= threshold:
            yield event, items[low:high], high - low


def detect_success_after_failures(events, threshold=FAIL_THRESHOLD,
                                  window_minutes=WINDOW_MINUTES):
    """Rule 2: a successful login right after enough recent failures from the same IP.

    Successes that follow the same burst (the latest burst of that IP whose threshold
    was reached at or before the success) are merged into ONE alert.
    """
    validate_settings(threshold, window_minutes)
    ordered = sort_events(events)
    window_us = window_minutes * _MICROS_PER_MINUTE
    failures = _failures_by_ip(ordered)
    triggers = {}                       # ip -> instants at which each burst was triggered
    incidents = {}                      # (ip, burst number) -> incident
    for success, support, count in _qualifying(ordered, threshold, window_minutes):
        ip = success["source_ip"]
        if ip not in triggers:
            times = failures[ip][1]
            triggers[ip] = [times[t] for _s, t, _e in _find_bursts(times, threshold, window_us)]
        number = bisect_right(triggers[ip], _instant(success["timestamp"])) - 1
        key = (ip, number) if number >= 0 else (ip, "unmatched", len(incidents))
        if key in incidents:
            incidents[key]["successes"].append(success)
        else:
            incidents[key] = {"successes": [success], "support": support, "count": count}

    alerts = []
    for (ip, _number), incident in incidents.items():
        first, successes = incident["successes"][0], incident["successes"]
        extra = len(successes) - 1
        reason = (f"Successful login after {incident['count']} failed logins from the same IP "
                  f"within {window_minutes} minutes")
        if extra:
            reason += f" ({extra} further successful login(s) followed the same burst)"
        evidence = sort_events(incident["support"] + successes)
        alerts.append(make_alert("success_after_failures", "critical", reason, first, evidence))
    return alerts


def detect_privilege_changes(events):
    """Rule 3: a successful privilege change by a user NOT in APPROVED_ADMINS."""
    alerts = []
    for event in sort_events(events):
        if (event["event_type"] in PRIVILEGE_EVENTS and event["status"] == "success"
                and event["username"] not in APPROVED_ADMINS):
            alerts.append(make_alert(
                "unexpected_privilege_change", "high",
                f"Privilege change by '{event['username']}', who is not an approved admin",
                event))
    return alerts


def _alert_key(alert):
    return (_instant(parse_timestamp(alert["timestamp"])), alert["rule"], alert["source_ip"],
            alert["username"], tuple(alert["source_lines"]))


def analyze(events, threshold=FAIL_THRESHOLD, window_minutes=WINDOW_MINUTES):
    """Run all detections and return alerts sorted by actual time instant."""
    validate_settings(threshold, window_minutes)
    events = sort_events(events)
    alerts = (detect_brute_force(events, threshold, window_minutes)
              + detect_success_after_failures(events, threshold, window_minutes)
              + detect_privilege_changes(events))
    return sorted(alerts, key=_alert_key)


# ----------------------------------------------------------------------------
# Reports and command line
# ----------------------------------------------------------------------------

def build_report(alerts, warnings, settings, log_summary=None, extra=None):
    """Report dict shared by the command line and the dashboard exports."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "Alerts show suspicious patterns in simulated logs, not proof of an attack.",
        "timezone": "All timestamps are UTC (ISO 8601); times without an offset were assumed UTC.",
        "settings": settings,
        "log_summary": log_summary or {},
        "alert_count": len(alerts),
        "alerts": alerts,
        "warnings": warnings,
    }
    if extra:
        report.update(extra)
    return report


def write_report(alerts, warnings, settings, path, log_summary=None):
    report = build_report(alerts, warnings, settings, log_summary)
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

    try:
        validate_settings(args.threshold, args.window_minutes)
    except ValueError as error:
        print(f"Error: {error}")
        return 1
    try:
        log = read_log(args.input)
        alerts = analyze(log.events, args.threshold, args.window_minutes)
        settings = {"fail_threshold": args.threshold, "window_minutes": args.window_minutes,
                    "approved_admins": sorted(APPROVED_ADMINS)}
        summary = {"rows_read": log.rows_read, "events_parsed": len(log.events),
                   "rows_skipped": log.rows_skipped}
        write_report(alerts, log.warnings, settings, args.output, summary)
    except LogError as error:
        print(f"Error: {error}")
        return 1

    for warning in log.warnings:
        print("Warning:", warning)
    print(f"Read {len(log.events)} events, raised {len(alerts)} alerts -> {args.output}")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['timestamp']} "
              f"{alert['username']} {alert['source_ip']}: {alert['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
