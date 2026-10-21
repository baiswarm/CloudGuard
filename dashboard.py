"""CloudGuard SOC dashboard (Streamlit) for SIMULATED cloud audit logs.

All detection logic lives in cloudguard.py. This file only loads data, calls
read_events() and analyze(), and displays the results.

Alerts indicate suspicious patterns, not confirmed attacks.
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

import cloudguard as cg

SAMPLE_PATH = Path(__file__).with_name("sample_logs.csv")
MAX_UPLOAD_MB = 5
TABLE_COLUMNS = ["timestamp", "severity", "rule", "username", "source_ip", "reason"]
DISCLAIMER = ("Alerts indicate suspicious patterns in SIMULATED logs, not confirmed "
              "attacks. A human analyst must review every alert.")


# ---------- helpers (no Streamlit calls, easy to test) ----------

def load_events_from_bytes(data):
    """Read uploaded CSV bytes with cg.read_events() via a temporary file."""
    handle = tempfile.NamedTemporaryFile("wb", suffix=".csv", delete=False)
    try:
        handle.write(data)
        handle.close()
        return cg.read_events(handle.name)
    finally:
        handle.close()
        os.remove(handle.name)


def alerts_to_frame(alerts):
    """Turn the alert dicts from cg.analyze() into a table (empty-safe)."""
    frame = pd.DataFrame(alerts, columns=TABLE_COLUMNS)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    return frame


def filter_frame(frame, severities, rules):
    return frame[frame["severity"].isin(severities) & frame["rule"].isin(rules)]


def frame_to_alerts(frame):
    """Convert a (filtered) table back to alert dicts with ISO timestamps."""
    records = frame.assign(timestamp=frame["timestamp"].map(lambda t: t.isoformat()))
    return records[TABLE_COLUMNS].to_dict("records")


def build_json_report(alerts, warnings, settings):
    """Same shape as the report written by cloudguard.py's command line."""
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "Alerts show suspicious patterns in simulated logs, not proof of an attack.",
        "settings": settings,
        "alert_count": len(alerts),
        "alerts": alerts,
        "warnings": warnings,
    }, indent=2)


# ---------- page sections ----------

def choose_source():
    """Sidebar input choice. Returns (events, warnings, source_name) or stops."""
    st.sidebar.header("Log source")
    choice = st.sidebar.radio("Input", ["Bundled sample_logs.csv", "Upload CSV"],
                              label_visibility="collapsed")
    try:
        if choice == "Upload CSV":
            uploaded = st.sidebar.file_uploader("CSV file", type=["csv"])
            if uploaded is None:
                st.info("Upload a CSV with columns: " + ", ".join(cg.REQUIRED_COLUMNS))
                st.stop()
            if uploaded.size > MAX_UPLOAD_MB * 1024 * 1024:
                st.error(f"File is larger than {MAX_UPLOAD_MB} MB.")
                st.stop()
            events, warnings = load_events_from_bytes(uploaded.getvalue())
            return events, warnings, uploaded.name
        events, warnings = cg.read_events(str(SAMPLE_PATH))
        return events, warnings, SAMPLE_PATH.name
    except cg.LogError as error:
        st.error(f"Could not use this file: {error}")
        st.stop()


def choose_settings():
    st.sidebar.header("Detection settings")
    threshold = st.sidebar.number_input("Failed-login threshold", min_value=1, max_value=100,
                                        value=cg.FAIL_THRESHOLD, step=1)
    window = st.sidebar.number_input("Time window (minutes)", min_value=1, max_value=1440,
                                     value=cg.WINDOW_MINUTES, step=1)
    st.sidebar.caption("Privilege-change rule uses APPROVED_ADMINS: "
                       + ", ".join(sorted(cg.APPROVED_ADMINS)))
    return int(threshold), int(window)


def show_kpis(total_events, alerts, skipped_rows):
    severities = [a["severity"] for a in alerts]
    cards = [("Total events", total_events), ("Total alerts", len(alerts)),
             ("Critical", severities.count("critical")), ("High", severities.count("high")),
             ("Skipped rows", skipped_rows)]
    for column, (label, value) in zip(st.columns(len(cards)), cards):
        with column.container(border=True):
            st.metric(label, value)


def show_charts(frame):
    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by severity")
        st.bar_chart(frame["severity"].value_counts(), color="#ff4b4b")
    with right:
        st.subheader("Alerts by detection rule")
        st.bar_chart(frame["rule"].value_counts(), color="#ffa421")


def show_table_and_exports(frame, warnings, settings):
    st.subheader("Alerts")
    st.dataframe(
        frame, hide_index=True,
        column_config={"timestamp": st.column_config.DatetimeColumn(
            "timestamp", format="YYYY-MM-DD HH:mm:ss")})
    alerts = frame_to_alerts(frame)
    csv_col, json_col = st.columns(2)
    csv_col.download_button("Download alerts (CSV)", frame.to_csv(index=False),
                            file_name="cloudguard_alerts.csv", mime="text/csv")
    json_col.download_button("Download report (JSON)",
                             build_json_report(alerts, warnings, settings),
                             file_name="cloudguard_report.json", mime="application/json")


def main():
    st.set_page_config(page_title="CloudGuard SOC", page_icon=":shield:", layout="wide")
    st.title("CloudGuard — SOC Dashboard")
    st.warning(DISCLAIMER)

    events, warnings, source_name = choose_source()
    threshold, window = choose_settings()
    alerts = cg.analyze(events, threshold, window)
    frame = alerts_to_frame(alerts)

    st.caption(f"Source: {source_name} · threshold {threshold} failures "
               f"within {window} minutes")
    show_kpis(len(events), alerts, len(warnings))
    if warnings:
        with st.expander(f"Parser warnings ({len(warnings)})"):
            for warning in warnings:
                st.write(warning)
    if not events:
        st.info("No valid events were found in this file.")
        return

    st.sidebar.header("Filters")
    severities = st.sidebar.multiselect("Severity", sorted(frame["severity"].unique()),
                                        default=sorted(frame["severity"].unique()))
    rules = st.sidebar.multiselect("Detection rule", sorted(frame["rule"].unique()),
                                   default=sorted(frame["rule"].unique()))
    shown = filter_frame(frame, severities, rules)
    if shown.empty:
        st.success("No alerts match the current settings and filters.")
        return
    show_charts(shown)
    settings = {"fail_threshold": threshold, "window_minutes": window,
                "approved_admins": sorted(cg.APPROVED_ADMINS)}
    show_table_and_exports(shown, warnings, settings)


if __name__ == "__main__":
    main()
