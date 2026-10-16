# CloudGuard — Cloud Security Log Analyzer

A small, defensive Python tool that analyzes **simulated** cloud audit logs (CSV) and flags suspicious patterns. It is a local learning prototype: no cloud access, no credentials, no network, standard library only.

> Alerts indicate **suspicious patterns, not proof of an attack**. A human must review them.

## Detection rules (defaults, set in `cloudguard.py`)

| Rule | Severity | Logic |
|---|---|---|
| `repeated_failed_logins` | high | 5 or more failed logins from the same IP within 10 minutes (one alert per IP) |
| `success_after_failures` | critical | A successful login from an IP that had 5 or more failed logins in the 10 minutes before it |
| `unexpected_privilege_change` | high | A **successful** `privilege_change` event by a username not in `APPROVED_ADMINS` (`admin`, `secops`) |

Only failures inside the time window count; older failures are ignored. Threshold and window can be changed with `--threshold` and `--window-minutes`.

## CSV format

`timestamp,username,source_ip,event_type,status` — timestamps are ISO 8601 (e.g. `2026-03-01T10:00:00Z`); `event_type` uses `login` or `privilege_change`; `status` uses `success` or `failure`. Bad rows and invalid timestamps are skipped with a warning; missing or empty files give a clear error.

## Run

Windows:
```
python cloudguard.py --input sample_logs.csv --output report.json
python -m unittest test_cloudguard -v
```

Linux:
```
python3 cloudguard.py --input sample_logs.csv --output report.json
python3 -m unittest test_cloudguard -v
```

## Limitations

- Works only on simulated CSV data; not tested against real cloud log formats.
- The privilege rule uses a fixed allowlist and treats `username` as the account making the change.
- Source IPs can be shared or spoofed; no geolocation, no user-agent or device checks.
- One alert per IP for repeated failures; no alert deduplication across runs.
- Not a production security tool.