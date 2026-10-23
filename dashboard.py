"""CloudGuard SOC dashboard (Streamlit) for SIMULATED cloud audit logs.

All detection logic lives in cloudguard.py and all testable helpers in
dashboard_helpers.py. This file only wires them to Streamlit widgets.
Text that comes from a log (usernames, file names, reasons) is always shown with
st.text / st.dataframe, never as markdown, so a hostile log cannot inject links.

Alerts indicate suspicious patterns, not confirmed attacks.
"""
from pathlib import Path

import pandas as pd
import streamlit as st

import cloudguard as cg
import dashboard_helpers as dh

BASE_DIR = Path(__file__).parent
SAMPLES = {"Bundled sample_logs.csv": BASE_DIR / "sample_logs.csv",
           "Bundled malformed sample (parser warnings demo)": BASE_DIR / "sample_logs_malformed.csv"}
UPLOAD_CHOICE = "Upload CSV"
DISCLAIMER = ("Alerts indicate suspicious patterns in SIMULATED logs, not confirmed "
              "attacks. A human analyst must review every alert.")


@st.cache_data(max_entries=3, show_spinner="Analyzing log...")
def load_and_analyze(data, threshold, window_minutes):
    """Parse + analyze. Cached on the file CONTENT and settings (never on the file name),
    so a changed upload or setting always recomputes. Errors are not cached."""
    log = dh.load_log_from_bytes(data)
    return log, dh.assign_alert_ids(cg.analyze(log.events, threshold, window_minutes))


def choose_source():
    """Sidebar input choice. Returns (CSV bytes, display name) or stops the app."""
    st.sidebar.header("Log source")
    choice = st.sidebar.radio("Input", list(SAMPLES) + [UPLOAD_CHOICE],
                              label_visibility="collapsed")
    try:
        if choice == UPLOAD_CHOICE:
            uploaded = st.sidebar.file_uploader(f"CSV file (max {dh.MAX_UPLOAD_MB} MB)",
                                                type=["csv"])
            if uploaded is None:
                st.info("Upload a CSV with columns: " + ", ".join(cg.REQUIRED_COLUMNS))
                st.stop()
            dh.check_upload_size(uploaded.size)
            data = uploaded.getvalue()
            dh.check_upload_size(len(data))
            return data, dh.safe_display_name(uploaded.name)
        path = SAMPLES[choice]
        return path.read_bytes(), path.name
    except (cg.LogError, OSError) as error:
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
    return {"fail_threshold": int(threshold), "window_minutes": int(window),
            "approved_admins": sorted(cg.APPROVED_ADMINS)}


def show_kpis(kpis):
    st.subheader("Overview: all alerts (before filters)")
    cards = [("Events parsed", kpis["events_parsed"]), ("Rows skipped", kpis["rows_skipped"]),
             ("Alerts (all)", kpis["alerts_all"]), ("Critical (all)", kpis["critical_all"]),
             ("High (all)", kpis["high_all"])]
    for column, (label, value) in zip(st.columns(len(cards)), cards):
        with column.container(border=True):
            st.metric(label, value)


def choose_filters(alerts):
    st.sidebar.header("Filters and sorting")
    severities = sorted({a["severity"] for a in alerts}, key=lambda s: dh.SEVERITY_ORDER.get(s, 9))
    rules = sorted({a["rule"] for a in alerts})
    ips = sorted({a["source_ip"] for a in alerts})
    chosen = {
        "severities": st.sidebar.multiselect("Severity", severities, default=severities),
        "rules": st.sidebar.multiselect("Detection rule", rules, default=rules),
        "ips": st.sidebar.multiselect("Source IP", ips, default=ips),
        "username_query": st.sidebar.text_input("Username contains"),
    }
    return chosen, st.sidebar.selectbox("Sort by", list(dh.SORT_OPTIONS))


def alerts_frame(alerts):
    return pd.DataFrame([{
        "ID": a["alert_id"],
        "Time (UTC)": pd.to_datetime(a["timestamp"], utc=True),
        "Severity": f"{dh.SEVERITY_ICON.get(a['severity'], '')} {a['severity']}",
        "Rule": a["rule"], "Source IP": a["source_ip"], "Usernames": ", ".join(a["usernames"]),
        "Events": a["event_count"],
        "First seen (UTC)": pd.to_datetime(a["first_seen"], utc=True),
        "Last seen (UTC)": pd.to_datetime(a["last_seen"], utc=True),
        "Reason": a["reason"]} for a in alerts])


def show_charts(alerts):
    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by severity (filtered)")
        st.bar_chart(pd.Series([a["severity"] for a in alerts]).value_counts(), color="#ff4b4b")
    with right:
        st.subheader("Alerts by detection rule (filtered)")
        st.bar_chart(pd.Series([a["rule"] for a in alerts]).value_counts(), color="#ffa421")


def show_table_and_exports(alerts, log, settings, total, filters):
    st.subheader(f"Alerts: showing {len(alerts)} of {total} (times are UTC)")
    stamp = st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss")
    st.dataframe(alerts_frame(alerts), hide_index=True,
                 column_config={"Time (UTC)": stamp, "First seen (UTC)": stamp,
                                "Last seen (UTC)": stamp})
    export_filters = {"severities": filters["severities"], "rules": filters["rules"],
                      "source_ips": filters["ips"], "username_contains": filters["username_query"]}
    csv_col, json_col = st.columns(2)
    csv_col.download_button("Download shown alerts (CSV)", dh.alerts_to_csv(alerts),
                            file_name="cloudguard_alerts.csv", mime="text/csv")
    json_col.download_button("Download shown alerts (JSON report)",
                             dh.alerts_to_json(alerts, log.warnings, settings, log, total,
                                               export_filters),
                             file_name="cloudguard_report.json", mime="application/json")
    st.caption("CSV and JSON contain the same alerts in the same order. CSV cells that start "
               "with = + - @ are prefixed with ' so spreadsheets do not run them as formulas.")


def show_investigation(alerts, log, settings):
    st.subheader("Investigate an alert")
    by_id = {a["alert_id"]: a for a in alerts}
    labels = {a["alert_id"]: f"{a['alert_id']} | {dh.display_time(a['timestamp'])} | "
                             f"{a['severity']} | {a['rule']} | {a['source_ip']}" for a in alerts}
    picked = st.selectbox("Alert", list(by_id), format_func=labels.get)
    alert = by_id[picked]

    st.markdown("**Why it triggered**")
    st.text(dh.explain_alert(alert, settings))
    st.markdown("**Incident summary**")
    st.text(dh.build_incident_summary(alert, settings))
    st.markdown("**Evidence**")
    st.text(f"Events: {alert['event_count']}\n"
            f"First seen: {dh.display_time(alert['first_seen'])}\n"
            f"Last seen: {dh.display_time(alert['last_seen'])}\n"
            f"Usernames: {', '.join(alert['usernames'])}\n"
            f"CSV lines (chronological): {' '.join(map(str, alert['source_lines'])) or 'not available'}")

    st.markdown("**Event timeline for this source IP**")
    left, right = st.columns(2)
    minutes = left.slider("Context before/after (minutes)", 0, 120, 10)
    whole_ip = right.checkbox("Show every event from this IP")
    rows, total = dh.timeline_for_alert(log.events, alert, minutes, whole_ip)
    if total > len(rows):
        st.caption(f"Showing the first {len(rows)} of {total} events.")
    st.dataframe(pd.DataFrame(rows).rename(columns={"in_alert": "part of this alert"}),
                 hide_index=True)


def main():
    st.set_page_config(page_title="CloudGuard SOC", page_icon=":shield:", layout="wide")
    st.title("CloudGuard — SOC Dashboard")
    st.warning(DISCLAIMER)

    data, source_name = choose_source()
    settings = choose_settings()
    try:
        log, alerts = load_and_analyze(data, settings["fail_threshold"],
                                       settings["window_minutes"])
    except (cg.LogError, ValueError) as error:
        st.error(f"Could not use this file: {error}")
        st.stop()

    st.text(f"Source: {source_name} | threshold {settings['fail_threshold']} failures within "
            f"{settings['window_minutes']} minutes")
    st.caption("All times are UTC. Timestamps without an offset in the CSV are assumed to be UTC.")
    filters, sort_option = choose_filters(alerts)
    shown = dh.sort_alerts(dh.filter_alerts(alerts, **filters), sort_option)
    show_kpis(dh.kpi_summary(log, alerts, shown))

    if log.warnings:
        with st.expander(f"Parser warnings ({len(log.warnings)}), {log.rows_skipped} rows skipped"):
            for warning in log.warnings[:100]:
                st.text(warning)
            if len(log.warnings) > 100:
                st.caption(f"{len(log.warnings) - 100} more warnings are in the JSON export.")
    if not log.events:
        st.info("No valid events were found in this file.")
        return
    if not alerts:
        st.success("No alerts were raised for this log with the current detection settings.")
        return
    if not shown:
        st.info(f"No alerts match the current filters ({len(alerts)} alerts are hidden). "
                "Widen the filters in the sidebar to see them.")
        return

    st.divider()
    show_charts(shown)
    show_table_and_exports(shown, log, settings, len(alerts), filters)
    st.divider()
    show_investigation(shown, log, settings)


if __name__ == "__main__":
    main()
