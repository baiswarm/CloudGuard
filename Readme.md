# CloudGuard — Cloud Security Log Analyzer

A small, defensive Python project that analyzes **simulated** cloud audit logs (CSV) and flags suspicious patterns. It has a command-line tool and a Streamlit SOC dashboard.

> **Local educational prototype.** It reads synthetic CSV files on your own machine. It is **not** a SIEM, does no live monitoring, has no cloud integration, no credentials, no network access and no database. Alerts indicate **suspicious patterns, not confirmed attacks**; a human analyst must review them.

## Purpose and use cases

- Learn how simple detection rules (brute force, success-after-failures, unexpected privilege change) work and where they go wrong.
- Practise alert triage on synthetic data: why did a rule fire, which log lines back it up, what happened around it.
- A small, testable codebase for experimenting with detection logic.

## Architecture and data flow

```
sample_logs.csv / uploaded CSV (UTF-8, BOM allowed)
        |
   cloudguard.py          parse (validate rows) -> sort -> 3 detectors -> alerts   (standard library only)
        |                         |
   command line            dashboard_helpers.py   filters, sorting, exports, timeline, summaries (standard library only)
   report.json                    |
                           dashboard.py           Streamlit + pandas: display only, no detection logic
```

- Uploads are parsed **in memory**; no temporary files are created.
- The dashboard caches parse+analysis keyed on the file **content** and the settings (never the file name), so changed uploads or settings always recompute.

## Detection rules (defaults in `cloudguard.py`)

| Rule | Severity | Exact logic |
|---|---|---|
| `repeated_failed_logins` | high | A *burst* of failed logins from one source IP: 5 or more failures within 10 minutes |
| `success_after_failures` | critical | A successful login from an IP with 5 or more failures in the 10 minutes before it |
| `unexpected_privilege_change` | high | A **successful** `privilege_change` by a username not in `APPROVED_ADMINS` (`admin`, `secops`) |

Threshold and window are adjustable (`--threshold`, `--window-minutes`, or the dashboard sidebar). Values below 1 raise `ValueError` (the CLI prints an error and exits 1).

### Precise semantics

- **Time.** Every timestamp becomes an exact UTC instant; alerts and ordering use the instant, never the text. Timestamps **without an offset are assumed to be UTC** (one summary warning is shown). All alert timestamps are output in UTC (`+00:00`). Mixed offsets in one file are handled correctly.
- **Windows are inclusive.** A failure exactly 10:00 minutes before an event still counts; 10:01 does not.
- **Ordering.** Events are sorted by instant, then CSV line. Shuffled input gives identical alerts. Events at the same instant are treated as simultaneous, so a failure at the same instant as a success counts as *before* it.
- **Bursts (rule 1).** A burst starts when 5 failures fit in the window. It continues while each new failure still has 5 unclaimed failures in its own trailing window, so a sustained attack is **one** alert with the true count. A failure belongs to at most one burst. After a quiet gap, a new burst raises a **new** alert. The alert `timestamp` is the moment the threshold was first reached; `first_seen`/`last_seen` span the whole burst.
- **De-duplication (rule 2).** Successes that follow the same burst give **one** critical alert (`username` is the first success; `usernames` lists everyone involved; the reason notes how many further successes were merged). A later, separate burst followed by a success gives another alert.
- **Rule 3.** Every matching privilege change is its own alert (identical duplicate rows give separate alerts). Usernames are compared exactly, case-sensitive. The log has no target-account or role fields, so none are reported.
- **Validation.** Only `success` and `failure` statuses are accepted (case/space-insensitive). Anything else (`failed`, `denied`, `invalid`...) is **skipped with a warning**; there is deliberately no alias policy. Unknown event types are kept (and warned about once per type) but no rule uses them.
- **Identity.** Source IPs and usernames are compared as exact trimmed text (no IPv6 normalisation).

## CSV format

`timestamp,username,source_ip,event_type,status`: ISO 8601 timestamps; `event_type` `login` or `privilege_change`; `status` `success` or `failure`. Headers are trimmed and case-insensitive; a UTF-8 BOM is accepted; extra columns are ignored; duplicate headers (after normalising) are rejected. Bad rows are skipped with a warning that names the CSV line. At most 200 warnings are stored per file, with a count of the rest.

`sample_logs.csv` is clean. `sample_logs_malformed.csv` (synthetic) demonstrates every parser warning plus mixed UTC offsets, a naive timestamp and a BOM.

## Alert fields and sample output

`rule, severity, reason, timestamp, username, source_ip` plus evidence: `first_seen, last_seen, event_count, usernames` (list) and `source_lines` (CSV line numbers, chronological). Real output for `sample_logs.csv`:

```
Read 20 events, raised 3 alerts -> report.json
[HIGH] 2026-03-01T10:02:00+00:00 admin, root, test 203.0.113.50: 6 failed logins from 203.0.113.50 over 2m 30s (threshold: 5 within 10 minutes)
[CRITICAL] 2026-03-01T10:04:00+00:00 admin 203.0.113.50: Successful login after 6 failed logins from the same IP within 10 minutes
[HIGH] 2026-03-01T10:06:00+00:00 bob 192.0.2.11: Privilege change by 'bob', who is not an approved admin
```

```json
{
  "rule": "success_after_failures",
  "severity": "critical",
  "reason": "Successful login after 6 failed logins from the same IP within 10 minutes",
  "timestamp": "2026-03-01T10:04:00+00:00",
  "username": "admin",
  "source_ip": "203.0.113.50",
  "first_seen": "2026-03-01T10:00:00+00:00",
  "last_seen": "2026-03-01T10:04:00+00:00",
  "event_count": 7,
  "usernames": ["admin", "root", "test"],
  "source_lines": [9, 10, 11, 12, 13, 14, 15]
}
```

The JSON report also has `generated_at`, `note`, `timezone`, `settings`, `log_summary` (rows read / events parsed / rows skipped), `alert_count`, `alerts` and `warnings`.

## Dashboard

- **Overview KPIs describe ALL alerts (before filters)**; the table heading and the charts say how many alerts the filters leave ("showing 1 of 3"). All times are labelled UTC.
- Filters: severity, rule, source IP, username search. Sorting: time (either way), severity, event count. Severity icons in the table.
- Different empty states: "no alerts raised", "no alerts match your filters (N hidden)", "no valid events".
- **Investigate an alert:** why it triggered, an evidence-based incident summary (template text, not AI), evidence list with CSV line numbers, and an event timeline for the source IP (adjustable context, evidence rows flagged).
- Exports (CSV and JSON) contain the **shown** alerts in the same order. CSV cells that begin with `=`, `+`, `-`, `@`, tab or CR are prefixed with `'` to block spreadsheet formula injection; the JSON and the underlying data are untouched.
- Text from logs (usernames, file names, reasons) is shown as plain text, not markdown. Uploaded file names are shown without path or control characters.
- Analyst notes / case status are **not** implemented (nothing is stored between sessions by design).

## Setup

Tested with Python 3.12.3 and Streamlit 1.66.1 (pandas 3.0.2). The command-line tool and the core tests need only the Python standard library (Python 3.11+ recommended; older versions parse fewer ISO 8601 variants). The dashboard needs Streamlit (`requirements.txt` says `streamlit>=1.30`; versions other than 1.66.1 were not tested).

Windows (PowerShell or cmd):
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Linux/macOS:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```
python cloudguard.py --input sample_logs.csv --output report.json
streamlit run dashboard.py
```

The dashboard binds to **127.0.0.1** (see `.streamlit/config.toml`) and rejects uploads over **5 MB** (config `maxUploadSize = 5`, re-checked in code). Run commands from the project folder.

## Test

```
python -m unittest discover -p "test_*.py" -v
```

Result of the last run (Python 3.12.3, Streamlit 1.66.1): **124 tests, all passing**.

| File | Tests | Covers |
|---|---|---|
| `test_cloudguard.py` | 9 | Original tests, unchanged |
| `test_engine_semantics.py` | 70 | Counts, boundaries, bursts, de-duplication, IPs/users, ordering, time zones, thresholds, statuses, parsing, evidence, report structure |
| `test_differential.py` | 4 | New engine vs the original algorithms over seeded data (60 seeds x 6 settings), burst invariants, scaling |
| `test_dashboard_helpers.py` | 28 | CSV formula injection, export consistency, upload limits, no temp files, file names, filters/sorting, timeline |
| `test_dashboard_app.py` | 13 | Real `dashboard.py` run headlessly with Streamlit's `AppTest` (skipped if Streamlit is missing) |

`AppTest` checks the rendered element tree; it is not a browser.

**Performance.** The successful-login check used to rescan every failure for each success (quadratic). It now uses binary search. One IP, equal numbers of failures and successes: 16,000 events took 8.8 s before and 0.1 s now; 200,000 events take about 1.5 s. A file near the 5 MB limit (~95,000 rows) parsed in 0.4 s and analyzed in 1.5 s on the test machine.

## Security precautions and limitations

- Synthetic data only; never tested against real cloud log formats. Do not upload real logs containing secrets.
- Naive timestamps are assumed UTC, which can be wrong for your data. IPs can be shared or spoofed; there is no geolocation or device checking.
- The privilege rule is a fixed allowlist and assumes `username` is the account making the change.
- A very long attack that keeps its pace is one alert; successes at any point of that same ongoing burst merge into one critical alert.
- No login, no history, no persistence. The local server is not hardened for network exposure; keep it on localhost.
- Alerts are patterns, not proof.

## Future ideas

Configurable approved-admin list, more event types, per-user failure rules, optional analyst notes exported with the report, real browser end-to-end tests.
