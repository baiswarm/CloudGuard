import json
import os
import tempfile
import unittest

import cloudguard as cg


def make_event(time_text, user, ip, event_type, status):
    return {"timestamp": cg.parse_timestamp(time_text), "username": user,
            "source_ip": ip, "event_type": event_type, "status": status}


def failures(ip, minutes_apart, count):
    """Build `count` failed logins from one IP, spaced `minutes_apart` minutes."""
    events = []
    for i in range(count):
        minute = i * minutes_apart
        events.append(make_event(f"2026-03-01T{minute // 60:02d}:{minute % 60:02d}:00Z",
                                 "eve", ip, "login", "failure"))
    return events


def write_temp_csv(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8")
    handle.write(text)
    handle.close()
    return handle.name


class TestDetections(unittest.TestCase):
    def test_normal_activity_has_no_alerts(self):
        events = [make_event("2026-03-01T09:00:00Z", "alice", "192.0.2.10", "login", "success"),
                  make_event("2026-03-01T09:10:00Z", "bob", "192.0.2.11", "login", "failure"),
                  make_event("2026-03-01T09:11:00Z", "bob", "192.0.2.11", "login", "success")]
        self.assertEqual(cg.analyze(events), [])

    def test_repeated_failures_in_window_raise_alert(self):
        events = failures("203.0.113.9", 1, cg.FAIL_THRESHOLD)
        alerts = cg.analyze(events)
        self.assertEqual([a["rule"] for a in alerts], ["repeated_failed_logins"])
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(alerts[0]["source_ip"], "203.0.113.9")

    def test_old_failures_outside_window_are_not_counted(self):
        events = failures("203.0.113.9", cg.WINDOW_MINUTES * 3, cg.FAIL_THRESHOLD)
        self.assertEqual(cg.analyze(events), [])

    def test_success_after_failures_is_critical(self):
        events = failures("203.0.113.9", 1, cg.FAIL_THRESHOLD)
        events.append(make_event("2026-03-01T00:30:00Z", "admin", "203.0.113.9",
                                 "login", "success"))
        # Success is 25 minutes after the last failure -> too late, no alert
        self.assertNotIn("success_after_failures", [a["rule"] for a in cg.analyze(events)])
        events[-1] = make_event("2026-03-01T00:06:00Z", "admin", "203.0.113.9",
                                "login", "success")
        alerts = cg.analyze(events)
        self.assertIn("success_after_failures", [a["rule"] for a in alerts])
        critical = [a for a in alerts if a["rule"] == "success_after_failures"][0]
        self.assertEqual(critical["severity"], "critical")
        self.assertEqual(critical["username"], "admin")

    def test_privilege_change_rule(self):
        bad = make_event("2026-03-01T10:00:00Z", "bob", "192.0.2.11", "privilege_change", "success")
        good = make_event("2026-03-01T10:01:00Z", "admin", "10.0.0.5", "privilege_change", "success")
        failed = make_event("2026-03-01T10:02:00Z", "carol", "192.0.2.12", "privilege_change", "failure")
        alerts = cg.analyze([bad, good, failed])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "bob")


class TestInputHandling(unittest.TestCase):
    def test_malformed_rows_and_bad_timestamps_are_skipped(self):
        path = write_temp_csv(
            "timestamp,username,source_ip,event_type,status\n"
            "2026-03-01T09:00:00Z,alice,192.0.2.10,login,success\n"
            "not-a-date,bob,192.0.2.11,login,failure\n"
            "2026-03-01T09:05:00Z,,192.0.2.12,login,failure\n"
            "2026-03-01T09:06:00Z,carol\n")
        try:
            events, warnings = cg.read_events(path)
        finally:
            os.remove(path)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(warnings), 3)

    def test_missing_file_raises_clear_error(self):
        with self.assertRaises(cg.LogError):
            cg.read_events("does_not_exist.csv")

    def test_empty_file_raises_clear_error(self):
        path = write_temp_csv("")
        try:
            with self.assertRaises(cg.LogError):
                cg.read_events(path)
        finally:
            os.remove(path)


class TestSampleAndReport(unittest.TestCase):
    def test_sample_logs_trigger_expected_rules_and_json_report(self):
        out_path = write_temp_csv("")
        try:
            code = cg.main(["--input", "sample_logs.csv", "--output", out_path])
            with open(out_path, encoding="utf-8") as report_file:
                report = json.load(report_file)
        finally:
            os.remove(out_path)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(a["rule"] for a in report["alerts"]),
                         ["repeated_failed_logins", "success_after_failures",
                          "unexpected_privilege_change"])


if __name__ == "__main__":
    unittest.main()