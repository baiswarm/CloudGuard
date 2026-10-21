# CloudGuard — Cloud Security Log Analyzer

A small, defensive Python project that analyzes **simulated** cloud audit logs (CSV) and flags suspicious patterns. It has a command-line tool and a Streamlit SOC dashboard. It is a local learning prototype: no cloud access, no credentials, no network, no database.

> Alerts indicate **suspicious patterns, not confirmed attacks**. A human analyst must review them.

## Features

- Three detection rules with documented thresholds (below).
- Alerts include rule, severity, reason, timestamp, username and source IP.
- JSON report from the command line; CSV and JSON exports from the dashboard.
- Handles missing files, empty files, malformed rows and invalid timestamps without crashing.
- Dashboard: KPI cards, severity and rule charts, severity/rule filters, alert table, CSV upload (max 5 MB) or the bundled sample, adjustable threshold and time window.
- 9 automated tests for the detection engine and input handling.

## Detection rules (defaults, set in `cloudguard.py`)

| Rule | Severity | Logic |
|---|---|---|
| `repeated_failed_logins` | high | 5 or more failed logins from the same IP within 10 minutes (one alert per IP) |
| `success_after_failures` | critical | A successful login from an IP that had 5 or more failed logins in the 10 minutes before it |
| `unexpected_privilege_change` | high | A **successful** `privilege_change` event by a username not in `APPROVED_ADMINS` (`admin`, `secops`) |

Only failures inside the time window count; older failures are ignored. Threshold and window can be changed with `--threshold` and `--window-minutes` on the command line, or in the dashboard sidebar.

## Architecture

```
sample_logs.csv / uploaded CSV
        |
   cloudguard.py   read_events() -> analyze() -> alert dicts   (standard library only)
        |                |
   command line     dashboard.py (Streamlit + pandas, display only, no detection logic)
   report.json      KPIs, charts, filters, table, CSV/JSON export
```

`dashboard.py` imports `read_events()` and `analyze()` from `cloudguard.py`, so the command line and the dashboard always use the same rules.

## CSV format

`timestamp,username,source_ip,event_type,status` — timestamps are ISO 8601 (e.g. `2026-03-01T10:00:00Z`); `event_type` uses `login` or `privilege_change`; `status` uses `success` or `failure`. Bad rows and invalid timestamps are skipped with a warning; missing or empty files give a clear error.

## Setup

Python 3 is required. The command-line tool and tests need nothing else. The dashboard needs Streamlit (which includes pandas).

Windows:
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Linux:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Command line (Windows: use `python`; Linux: use `python3`):
```
python cloudguard.py --input sample_logs.csv --output report.json
```

Dashboard (run from the project folder):
```
streamlit run dashboard.py
```

## Test

Run from the project folder (the sample-data test reads `sample_logs.csv` by relative path):

Windows:
```
python -m unittest test_cloudguard -v
```

Linux:
```
python3 -m unittest test_cloudguard -v
```

The tests cover the detection engine and input handling. The dashboard has no automated tests.

## Limitations

- Works only on simulated CSV data; not tested against real cloud log formats.
- The privilege rule uses a fixed allowlist and treats `username` as the account making the change.
- Source IPs can be shared or spoofed; no geolocation, no user-agent or device checks.
- One alert per IP for repeated failures; its `username` field lists every user tried and its timestamp is the last failure in the burst.
- The dashboard holds the uploaded file in memory and in a temporary file during analysis only; it keeps no history and has no login.
- Not a production security tool.
