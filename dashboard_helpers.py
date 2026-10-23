"""Pure helper functions for the CloudGuard dashboard (standard library only).

Kept separate from dashboard.py so they can be unit-tested without Streamlit.
Everything that reaches the screen or an export from an UNTRUSTED log (usernames,
file names, reasons) is treated as plain text.
"""
import csv
import io
import json
import os
import unicodedata
from datetime import timedelta

import cloudguard as cg

MAX_UPLOAD_MB = 5
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_TIMELINE_ROWS = 500

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
SORT_OPTIONS = {
    "Time (oldest first)": lambda a: (_when(a), a["alert_id"]),
    "Time (newest first)": None,                       # reverse of the above
    "Severity (critical first)": lambda a: (SEVERITY_ORDER.get(a["severity"], 9), _when(a),
                                            a["alert_id"]),
    "Event count (most first)": lambda a: (-a["event_count"], _when(a), a["alert_id"]),
}
EXPORT_FIELDS = ["alert_id", "timestamp", "severity", "rule", "username", "usernames",
                 "source_ip", "first_seen", "last_seen", "event_count", "source_lines",
                 "reason"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _when(alert):
    return cg.parse_timestamp(alert["timestamp"])


# ---------------- uploads and display names ----------------

def check_upload_size(size_bytes):
    """Raise cg.LogError if an upload exceeds the 5 MB limit."""
    if size_bytes > MAX_UPLOAD_BYTES:
        raise cg.LogError(f"File is larger than {MAX_UPLOAD_MB} MB.")


def load_log_from_bytes(data):
    """Parse an uploaded CSV entirely in memory (no temporary file is ever created)."""
    check_upload_size(len(data))
    return cg.parse_log_bytes(data)


def safe_display_name(name, limit=80):
    """Make an uploaded file name safe to show: no path, no control/bidi characters."""
    base = os.path.basename(str(name or "").replace("\\", "/"))
    cleaned = "".join(ch for ch in base if unicodedata.category(ch) not in ("Cc", "Cf", "Cs"))
    cleaned = cleaned.strip()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit - 3] + "..."
    return cleaned or "uploaded.csv"


# ---------------- alerts: ids, sorting, filtering ----------------

def assign_alert_ids(alerts):
    """Copies of the alerts with a run-scoped id (A001, A002...) in chronological order."""
    return [dict(alert, alert_id=f"A{number:03d}") for number, alert in enumerate(alerts, 1)]


def sort_alerts(alerts, option="Time (oldest first)"):
    if option == "Time (newest first)":
        return sorted(alerts, key=SORT_OPTIONS["Time (oldest first)"], reverse=True)
    return sorted(alerts, key=SORT_OPTIONS.get(option) or SORT_OPTIONS["Time (oldest first)"])


def filter_alerts(alerts, severities=None, rules=None, ips=None, username_query=""):
    """None means 'no restriction'; an empty list means 'nothing selected'."""
    query = (username_query or "").strip().lower()
    result = []
    for alert in alerts:
        if severities is not None and alert["severity"] not in severities:
            continue
        if rules is not None and alert["rule"] not in rules:
            continue
        if ips is not None and alert["source_ip"] not in ips:
            continue
        if query and not any(query in name.lower() for name in alert["usernames"]):
            continue
        result.append(alert)
    return result


def kpi_summary(log, all_alerts, shown_alerts):
    """KPI numbers, explicitly split into 'all alerts' and 'after filters'."""
    count = lambda items, level: sum(1 for a in items if a["severity"] == level)
    return {"events_parsed": len(log.events), "rows_skipped": log.rows_skipped,
            "alerts_all": len(all_alerts), "critical_all": count(all_alerts, "critical"),
            "high_all": count(all_alerts, "high"), "alerts_shown": len(shown_alerts)}


# ---------------- exports ----------------

def sanitize_cell(value):
    """Neutralise spreadsheet formulas in a CSV cell (export only; data is untouched)."""
    if isinstance(value, str) and value.lstrip(" ")[:1] in _FORMULA_PREFIXES:
        return "'" + value
    return value


def _csv_row(alert):
    row = {name: alert.get(name, "") for name in EXPORT_FIELDS}
    row["usernames"] = "; ".join(alert["usernames"])
    row["source_lines"] = " ".join(str(n) for n in alert["source_lines"])
    return {name: sanitize_cell(value) for name, value in row.items()}


def alerts_to_csv(alerts):
    """CSV text for the given alerts with formula-injection protection."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for alert in alerts:
        writer.writerow(_csv_row(alert))
    return buffer.getvalue()


def alerts_to_json(alerts, warnings, settings, log, total_alerts, filters):
    """Same alerts and order as the CSV, in the CLI report shape plus export scope."""
    summary = {"rows_read": log.rows_read, "events_parsed": len(log.events),
               "rows_skipped": log.rows_skipped}
    extra = {"export_scope": {"alerts_exported": len(alerts),
                              "alerts_before_filters": total_alerts, "filters": filters}}
    return json.dumps(cg.build_report(alerts, warnings, settings, summary, extra), indent=2)


# ---------------- investigation views ----------------

def display_time(iso_text):
    return cg.parse_timestamp(iso_text).strftime("%Y-%m-%d %H:%M:%S UTC")


def explain_alert(alert, settings):
    """Plain-text explanation of exactly why this alert fired (data from the alert only)."""
    n, w = settings["fail_threshold"], settings["window_minutes"]
    ip, user = alert["source_ip"], alert["username"]
    if alert["rule"] == "repeated_failed_logins":
        return (f"{alert['event_count']} failed login events from {ip} between "
                f"{display_time(alert['first_seen'])} and {display_time(alert['last_seen'])}. "
                f"The threshold ({n} failures within {w} minutes, edges inclusive) was first "
                f"reached at {display_time(alert['timestamp'])}. The burst kept going while "
                f"every new failure still had {n} failures in its own trailing {w}-minute window.")
    if alert["rule"] == "success_after_failures":
        return (f"A successful login by '{user}' from {ip} at {display_time(alert['timestamp'])} "
                f"came after at least {n} failed logins from the same IP in the preceding "
                f"{w} minutes. Further successful logins after the same burst are merged into "
                f"this alert ({alert['event_count']} evidence events in total).")
    if alert["rule"] == "unexpected_privilege_change":
        admins = ", ".join(sorted(settings["approved_admins"]))
        return (f"'{user}' recorded a successful privilege_change event from {ip} and is not in "
                f"the approved admin list ({admins}). The log has no target-account or role "
                f"fields, so what was changed, and for whom, cannot be known from this data.")
    return alert["reason"]


def build_incident_summary(alert, settings):
    """One short evidence-based paragraph (plain text, template-generated, not AI)."""
    names = ", ".join(alert["usernames"])
    lines = alert["source_lines"]
    where = (f" CSV lines {min(lines)}-{max(lines)} ({len(lines)} events)." if lines else "")
    return (f"{alert['severity'].upper()} | {alert['rule']} | {alert['source_ip']} | "
            f"{display_time(alert['first_seen'])} -> {display_time(alert['last_seen'])}. "
            f"{alert['reason']}. Accounts involved: {names}.{where} "
            f"Needs analyst review; a pattern in simulated logs is not proof of an attack. "
            f"(Thresholds: {settings['fail_threshold']} within {settings['window_minutes']} min.)")


def timeline_for_alert(events, alert, context_minutes=10, whole_ip=False,
                       limit=MAX_TIMELINE_ROWS):
    """Events around an alert. Returns (rows, total_matching).

    Related = same source IP (privilege-change alerts also include that user's other
    events). Without `whole_ip`, only events within `context_minutes` of the alert's
    first/last evidence are shown. `in_alert` is True for the alert's own evidence lines.
    """
    first, last = cg.parse_timestamp(alert["first_seen"]), cg.parse_timestamp(alert["last_seen"])
    context = timedelta(minutes=context_minutes)
    evidence = set(alert["source_lines"])
    users = set(alert["usernames"]) if alert["rule"] == "unexpected_privilege_change" else set()
    rows = []
    for event in cg.sort_events(events):
        if event["source_ip"] != alert["source_ip"] and event["username"] not in users:
            continue
        if not whole_ip:
            moment = event["timestamp"]
            if first - moment > context or moment - last > context:
                continue
        rows.append({"line": event.get("line"), "time_utc": display_time(event["timestamp"].isoformat()),
                     "username": event["username"], "source_ip": event["source_ip"],
                     "event_type": event["event_type"], "status": event["status"],
                     "in_alert": event.get("line") in evidence})
    return rows[:limit], len(rows)
