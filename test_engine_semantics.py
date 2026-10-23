"""Tests for the hardened detection engine (cloudguard.py).

These pin down the exact documented behaviour: burst handling, window
boundaries, de-duplication, status validation, thresholds, time zones,
BOM/header handling, evidence fields and the JSON report structure.
Standard library only.
"""
import io
import json
import os
import random
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

import cloudguard as cg

BASE = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
HEADER = "timestamp,username,source_ip,event_type,status\n"


def ev(offset_seconds, user, ip, event_type="login", status="failure", line=None):
    """Build an event `offset_seconds` after BASE."""
    return {"timestamp": BASE + timedelta(seconds=offset_seconds), "username": user,
            "source_ip": ip, "event_type": event_type, "status": status, "line": line}


def fail(sec, ip="203.0.113.9", user="eve", line=None):
    return ev(sec, user, ip, "login", "failure", line)


def ok(sec, ip="203.0.113.9", user="admin", line=None):
    return ev(sec, user, ip, "login", "success", line)


def rules(alerts):
    return [a["rule"] for a in alerts]


def write_temp(data, mode="wb"):
    handle = tempfile.NamedTemporaryFile(mode, suffix=".csv", delete=False)
    handle.write(data)
    handle.close()
    return handle.name


def parse(text):
    return cg.parse_log_bytes(text.encode("utf-8"))


class TestBruteForceCounting(unittest.TestCase):
    def test_exact_threshold_reports_five(self):
        alerts = cg.detect_brute_force([fail(i * 60) for i in range(5)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 5)
        self.assertIn("5 failed logins", alerts[0]["reason"])

    def test_true_count_is_reported_not_the_threshold(self):
        alerts = cg.detect_brute_force([fail(i * 30) for i in range(8)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 8)
        self.assertIn("8 failed logins", alerts[0]["reason"])

    def test_sustained_attack_is_one_alert_with_full_count(self):
        alerts = cg.detect_brute_force([fail(i * 60) for i in range(31)])  # 30 minutes
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 31)

    def test_threshold_minus_one_is_quiet(self):
        self.assertEqual(cg.detect_brute_force([fail(i * 60) for i in range(4)]), [])

    def test_custom_threshold_and_window(self):
        events = [fail(0), fail(60), fail(120)]
        self.assertEqual(len(cg.detect_brute_force(events, threshold=3, window_minutes=2)), 1)
        self.assertEqual(cg.detect_brute_force(events, threshold=3, window_minutes=1), [])


class TestWindowBoundaries(unittest.TestCase):
    def test_exactly_on_window_edge_alerts(self):
        # first and fifth failure are exactly 10 minutes apart (inclusive window)
        alerts = cg.detect_brute_force([fail(s) for s in (0, 150, 300, 450, 600)])
        self.assertEqual(len(alerts), 1)

    def test_one_second_outside_window_does_not_alert(self):
        self.assertEqual(cg.detect_brute_force([fail(s) for s in (0, 150, 300, 450, 601)]), [])

    def test_success_exactly_window_after_failures_counts(self):
        events = [fail(s) for s in (0, 1, 2, 3, 4)] + [ok(600)]
        self.assertEqual(rules(cg.detect_success_after_failures(events)),
                         ["success_after_failures"])

    def test_success_just_outside_window_does_not_count(self):
        events = [fail(s) for s in (0, 1, 2, 3, 4)] + [ok(605)]  # oldest failure is 605s old
        self.assertEqual(cg.detect_success_after_failures(events), [])

    def test_success_window_needs_threshold_inside_window_only(self):
        # 5 failures exist, but only 4 are inside the window before the success
        events = [fail(s) for s in (0, 100, 200, 300, 400)] + [ok(650)]
        self.assertEqual(cg.detect_success_after_failures(events), [])

    def test_same_instant_failure_counts_as_before_success(self):
        events = [fail(s) for s in (0, 10, 20, 30)] + [fail(100), ok(100)]
        self.assertEqual(len(cg.detect_success_after_failures(events)), 1)

    def test_success_before_failures_is_not_an_alert(self):
        events = [ok(0)] + [fail(s) for s in (10, 20, 30, 40, 50)]
        self.assertEqual(cg.detect_success_after_failures(events), [])


class TestMultipleBursts(unittest.TestCase):
    def test_two_separate_bursts_two_alerts(self):
        first = [fail(i * 60, line=i + 1) for i in range(5)]
        second = [fail(7200 + i * 60, line=i + 11) for i in range(6)]
        alerts = cg.detect_brute_force(first + second)
        self.assertEqual(len(alerts), 2)
        self.assertEqual([a["event_count"] for a in alerts], [5, 6])
        self.assertEqual(alerts[0]["source_lines"], [1, 2, 3, 4, 5])
        self.assertEqual(alerts[1]["source_lines"], [11, 12, 13, 14, 15, 16])

    def test_bursts_never_share_events(self):
        # threshold 3: 0,60,120 | 690,720,780.  The failure at 120 is within 10 min of 690
        # but already belongs to burst one, so it must not be reused.
        events = [fail(s, line=n) for n, s in enumerate((0, 60, 120, 690, 720, 780), 1)]
        alerts = cg.detect_brute_force(events, threshold=3, window_minutes=10)
        self.assertEqual([a["source_lines"] for a in alerts], [[1, 2, 3], [4, 5, 6]])

    def test_leftover_failures_do_not_form_a_burst_alone(self):
        events = [fail(s) for s in (0, 60, 120, 690, 720)]
        alerts = cg.detect_brute_force(events, threshold=3, window_minutes=10)
        self.assertEqual(len(alerts), 1)

    def test_threshold_one_splits_on_gaps_longer_than_window(self):
        events = [fail(0), fail(60), fail(3600)]
        alerts = cg.detect_brute_force(events, threshold=1, window_minutes=10)
        self.assertEqual([a["event_count"] for a in alerts], [2, 1])

    def test_alert_timestamp_is_when_threshold_was_first_reached(self):
        alerts = cg.detect_brute_force([fail(i * 60) for i in range(8)])
        self.assertEqual(alerts[0]["timestamp"], (BASE + timedelta(minutes=4)).isoformat())
        self.assertEqual(alerts[0]["first_seen"], BASE.isoformat())
        self.assertEqual(alerts[0]["last_seen"], (BASE + timedelta(minutes=7)).isoformat())


class TestIpsAndUsers(unittest.TestCase):
    def test_interleaved_ips_are_tracked_independently(self):
        events = []
        for i in range(5):
            events.append(fail(i * 60, ip="198.51.100.1"))
            events.append(fail(i * 60 + 30, ip="198.51.100.2"))
        for i in range(4):
            events.append(fail(i * 60 + 45, ip="198.51.100.3"))
        alerts = cg.analyze(events)
        self.assertEqual(sorted((a["source_ip"], a["event_count"]) for a in alerts),
                         [("198.51.100.1", 5), ("198.51.100.2", 5)])

    def test_failures_from_two_ips_are_not_combined(self):
        events = [fail(i * 60, ip="198.51.100.1") for i in range(3)] + \
                 [fail(i * 60 + 30, ip="198.51.100.2") for i in range(3)]
        self.assertEqual(cg.analyze(events), [])

    def test_multiple_usernames_behind_one_ip(self):
        users = ["root", "admin", "test", "admin", "guest"]
        events = [fail(i * 20, user=u) for i, u in enumerate(users)]
        alert = cg.detect_brute_force(events)[0]
        self.assertEqual(alert["usernames"], ["admin", "guest", "root", "test"])
        self.assertEqual(alert["username"], "admin, guest, root, test")

    def test_success_by_other_ip_is_not_an_alert(self):
        events = [fail(s) for s in (0, 1, 2, 3, 4)] + [ok(60, ip="198.51.100.77")]
        self.assertEqual(cg.detect_success_after_failures(events), [])

    def test_ip_text_is_compared_exactly(self):
        # documented limitation: no IP normalisation (IPv6 case etc.)
        events = [fail(i, ip="2001:db8::1") for i in range(3)] + \
                 [fail(i + 3, ip="2001:DB8::1") for i in range(2)]
        self.assertEqual(cg.analyze(events), [])


class TestSuccessAfterFailures(unittest.TestCase):
    def test_reports_true_failure_count(self):
        events = [fail(i * 10) for i in range(7)] + [ok(100)]
        alert = cg.detect_success_after_failures(events)[0]
        self.assertIn("after 7 failed logins", alert["reason"])
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["username"], "admin")
        self.assertEqual(alert["event_count"], 8)          # 7 failures + 1 success
        self.assertEqual(alert["timestamp"], (BASE + timedelta(seconds=100)).isoformat())

    def test_many_successes_after_one_burst_give_one_alert(self):
        events = [fail(i * 10) for i in range(6)] + \
                 [ok(100, user="admin"), ok(130, user="root"), ok(160, user="admin")]
        alerts = cg.detect_success_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "admin")           # first success
        self.assertEqual(alerts[0]["usernames"], ["admin", "eve", "root"])
        self.assertEqual(alerts[0]["event_count"], 6 + 3)
        self.assertEqual(alerts[0]["last_seen"], (BASE + timedelta(seconds=160)).isoformat())
        self.assertIn("2 further successful login", alerts[0]["reason"])

    def test_two_distinct_incidents_from_one_ip_both_alert(self):
        events = [fail(i * 10) for i in range(5)] + [ok(100)] + \
                 [fail(7200 + i * 10) for i in range(5)] + [ok(7300)]
        alerts = cg.detect_success_after_failures(events)
        self.assertEqual(len(alerts), 2)

    def test_two_ips_each_get_their_own_alert(self):
        events = []
        for ip in ("198.51.100.1", "198.51.100.2"):
            events += [fail(i * 10, ip=ip) for i in range(5)] + [ok(100, ip=ip)]
        self.assertEqual(len(cg.detect_success_after_failures(events)), 2)

    def test_success_while_attack_continues_is_one_incident(self):
        events = [fail(i * 20) for i in range(5)] + [ok(100)] + \
                 [fail(120 + i * 20) for i in range(5)] + [ok(300)]
        self.assertEqual(len(cg.detect_success_after_failures(events)), 1)

    def test_default_setting_scope_in_reason(self):
        events = [fail(i) for i in range(5)] + [ok(30)]
        reason = cg.detect_success_after_failures(events)[0]["reason"]
        self.assertIn("within 10 minutes", reason)


class TestPrivilegeChange(unittest.TestCase):
    def test_alert_has_evidence_and_nothing_invented(self):
        events = [ev(5, "bob", "192.0.2.11", "privilege_change", "success", line=7)]
        alert = cg.detect_privilege_changes(events)[0]
        self.assertEqual(set(alert), {"rule", "severity", "reason", "timestamp", "username",
                                      "source_ip", "first_seen", "last_seen", "event_count",
                                      "usernames", "source_lines"})
        self.assertEqual(alert["usernames"], ["bob"])
        self.assertEqual(alert["event_count"], 1)
        self.assertEqual(alert["source_lines"], [7])
        self.assertEqual(alert["first_seen"], alert["last_seen"])

    def test_each_privilege_change_is_its_own_alert(self):
        events = [ev(5, "bob", "192.0.2.11", "privilege_change", "success"),
                  ev(5, "bob", "192.0.2.11", "privilege_change", "success")]
        self.assertEqual(len(cg.detect_privilege_changes(events)), 2)

    def test_username_match_is_case_sensitive(self):
        events = [ev(5, "Admin", "10.0.0.5", "privilege_change", "success")]
        self.assertEqual(len(cg.detect_privilege_changes(events)), 1)


class TestOrderingAndTime(unittest.TestCase):
    def test_same_second_events_form_a_burst(self):
        alerts = cg.analyze([fail(0, user=f"u{i}") for i in range(5)])
        self.assertEqual(alerts[0]["event_count"], 5)

    def test_shuffled_input_gives_identical_alerts(self):
        events = [fail(i * 20, line=i + 2) for i in range(7)] + [ok(200, line=9)] + \
                 [ev(50, "bob", "10.0.0.9", "privilege_change", "success", line=10)] + \
                 [fail(0, ip="198.51.100.5", user=f"u{i}", line=20 + i) for i in range(5)]
        expected = cg.analyze(events)
        rng = random.Random(7)
        for _ in range(25):
            shuffled = events[:]
            rng.shuffle(shuffled)
            self.assertEqual(cg.analyze(shuffled), expected)

    def test_analyze_does_not_mutate_input(self):
        events = [fail(i * 20) for i in range(6)]
        snapshot = [dict(e) for e in events]
        cg.analyze(events)
        self.assertEqual(events, snapshot)

    def test_alerts_sorted_by_instant_not_string(self):
        # 09:30+05:30 is 04:00Z, which is EARLIER than 05:00Z although its text sorts later.
        a = ev(0, "bob", "10.0.0.1", "privilege_change", "success")
        a["timestamp"] = cg.parse_timestamp("2026-03-01T09:30:00+05:30")
        b = ev(0, "carol", "10.0.0.2", "privilege_change", "success")
        b["timestamp"] = cg.parse_timestamp("2026-03-01T05:00:00Z")
        alerts = cg.analyze([b, a])
        self.assertEqual([x["username"] for x in alerts], ["bob", "carol"])
        self.assertEqual(alerts[0]["timestamp"], "2026-03-01T04:00:00+00:00")

    def test_mixed_offsets_count_in_one_window(self):
        # all five failures are 08:00Z..08:04Z when converted, though written differently
        texts = ["2026-03-01T08:00:00Z", "2026-03-01T10:01:00+02:00", "2026-03-01T03:02:00-05:00",
                 "2026-03-01T13:33:00+05:30", "2026-03-01T08:04:00+00:00"]
        events = [{"timestamp": cg.parse_timestamp(t), "username": "eve", "source_ip": "1.1.1.1",
                   "event_type": "login", "status": "failure", "line": None} for t in texts]
        self.assertEqual(len(cg.analyze(events)), 1)

    def test_naive_timestamps_are_treated_as_utc(self):
        self.assertEqual(cg.parse_timestamp("2026-03-01T10:00:00"),
                         cg.parse_timestamp("2026-03-01T10:00:00Z"))
        self.assertEqual(cg.parse_timestamp("2026-03-01T10:00:00z").tzinfo, timezone.utc)

    def test_naive_event_objects_do_not_crash(self):
        events = [{"timestamp": datetime(2026, 3, 1, 0, i), "username": "eve",
                   "source_ip": "1.1.1.1", "event_type": "login", "status": "failure"}
                  for i in range(5)]
        self.assertEqual(len(cg.analyze(events)), 1)

    def test_extreme_dates_do_not_overflow(self):
        events = [{"timestamp": cg.parse_timestamp("0001-01-01T00:00:0%dZ" % i), "username": "e",
                   "source_ip": "1.1.1.1", "event_type": "login", "status": "failure"}
                  for i in range(5)]
        events.append({"timestamp": cg.parse_timestamp("0001-01-01T00:00:30Z"), "username": "a",
                       "source_ip": "1.1.1.1", "event_type": "login", "status": "success"})
        self.assertEqual(sorted(rules(cg.analyze(events))),
                         ["repeated_failed_logins", "success_after_failures"])

    def test_out_of_range_offset_timestamp_is_rejected_cleanly(self):
        for text in ("0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00", "", "garbage"):
            with self.assertRaises(ValueError):
                cg.parse_timestamp(text)


class TestThresholds(unittest.TestCase):
    def test_invalid_values_raise_value_error(self):
        events = [fail(0)]
        for bad in (0, -1, 1.5, "5", None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                cg.analyze(events, threshold=bad)
            with self.assertRaises(ValueError, msg=repr(bad)):
                cg.analyze(events, window_minutes=bad)

    def test_each_detector_validates_even_without_events(self):
        for func in (cg.detect_brute_force, cg.detect_success_after_failures):
            with self.assertRaises(ValueError):
                func([], threshold=0)
            with self.assertRaises(ValueError):
                func([], window_minutes=0)

    def test_message_names_the_bad_setting(self):
        with self.assertRaisesRegex(ValueError, "threshold"):
            cg.analyze([], threshold=0)
        with self.assertRaisesRegex(ValueError, "window_minutes"):
            cg.analyze([], window_minutes=-5)

    def test_absurd_window_is_rejected_not_crashed(self):
        with self.assertRaises(ValueError):
            cg.analyze([], window_minutes=10 ** 12)

    def test_cli_rejects_bad_thresholds_with_exit_1(self):
        for args in (["--threshold", "0"], ["--window-minutes", "0"], ["--threshold", "-3"]):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cg.main(["--input", "sample_logs.csv", "--output", os.devnull] + args)
            self.assertEqual(code, 1)
            self.assertIn("Error", buffer.getvalue())


class TestStatusValidation(unittest.TestCase):
    def test_unknown_statuses_are_warned_and_not_counted(self):
        rows = "".join(f"2026-03-01T00:0{i}:00Z,eve,1.1.1.1,login,{s}\n"
                       for i, s in enumerate(["failed", "denied", "invalid", "FAILED", "error"]))
        log = parse(HEADER + rows)
        self.assertEqual(log.events, [])
        self.assertEqual(len(log.warnings), 5)
        self.assertEqual(log.rows_skipped, 5)
        self.assertIn("Line 2", log.warnings[0])
        self.assertIn("unknown status", log.warnings[0])
        self.assertIn("'failed'", log.warnings[0])
        self.assertEqual(cg.analyze(log.events), [])    # NOT silently treated as failures

    def test_known_statuses_are_case_and_space_insensitive(self):
        log = parse(HEADER + "2026-03-01T00:00:00Z, eve ,1.1.1.1,LOGIN, FAILURE \n")
        self.assertEqual(log.warnings, [])
        self.assertEqual((log.events[0]["status"], log.events[0]["event_type"],
                          log.events[0]["username"]), ("failure", "login", "eve"))

    def test_no_alias_policy_exists(self):
        self.assertEqual(set(cg.KNOWN_STATUSES), {"success", "failure"})

    def test_unknown_event_type_is_kept_but_warned_once_per_type(self):
        rows = "".join(f"2026-03-01T00:0{i}:00Z,eve,1.1.1.1,logout,success\n" for i in range(3))
        log = parse(HEADER + rows)
        self.assertEqual(len(log.events), 3)
        self.assertEqual(len(log.warnings), 1)
        self.assertIn("logout", log.warnings[0])
        self.assertIn("3 rows", log.warnings[0])
        self.assertEqual(cg.analyze(log.events), [])

    def test_naive_timestamps_trigger_one_summary_warning(self):
        log = parse(HEADER + "2026-03-01T00:00:00,eve,1.1.1.1,login,success\n"
                             "2026-03-01T00:01:00,eve,1.1.1.1,login,success\n"
                             "2026-03-01T00:02:00Z,eve,1.1.1.1,login,success\n")
        self.assertEqual(len(log.events), 3)
        self.assertEqual(len(log.warnings), 1)
        self.assertIn("2 timestamp", log.warnings[0])
        self.assertIn("UTC", log.warnings[0])

    def test_echoed_values_are_clipped_and_escaped(self):
        nasty = "[x](http://e.example)\x1b[31m" + "A" * 200
        log = parse(HEADER + f"2026-03-01T00:00:00Z,eve,1.1.1.1,login,\"{nasty}\"\n")
        self.assertEqual(len(log.warnings), 1)
        self.assertLess(len(log.warnings[0]), 200)
        self.assertNotIn("\x1b", log.warnings[0])


class TestParserRobustness(unittest.TestCase):
    def test_utf8_bom_and_messy_headers(self):
        text = " Timestamp , USERNAME ,Source_IP,EVENT_TYPE,Status \n" \
               "2026-03-01T00:00:00Z,eve,1.1.1.1,login,failure\n"
        log = cg.parse_log_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
        self.assertEqual(len(log.events), 1)
        self.assertEqual(log.warnings, [])

    def test_bom_file_on_disk(self):
        path = write_temp(b"\xef\xbb\xbf" + (HEADER + "2026-03-01T00:00:00Z,a,1.1.1.1,login,success\n").encode())
        try:
            events, warnings = cg.read_events(path)
        finally:
            os.remove(path)
        self.assertEqual((len(events), warnings), (1, []))

    def test_extra_columns_are_ignored(self):
        log = parse("timestamp,username,source_ip,event_type,status,note\n"
                    "2026-03-01T00:00:00Z,a,1.1.1.1,login,success,hello\n")
        self.assertEqual(len(log.events), 1)

    def test_duplicate_headers_after_normalising_are_rejected(self):
        with self.assertRaisesRegex(cg.LogError, "Duplicate"):
            parse("timestamp,Timestamp ,username,source_ip,event_type,status\n")

    def test_missing_columns_named_in_error(self):
        with self.assertRaisesRegex(cg.LogError, "status"):
            parse("timestamp,username,source_ip,event_type\n")

    def test_invalid_utf8_is_a_clean_error(self):
        with self.assertRaises(cg.LogError):
            cg.parse_log_bytes(b"timestamp,username\n\xff\xfe\xfa\n")

    def test_header_only_file_is_valid_but_empty(self):
        log = parse(HEADER)
        self.assertEqual((log.events, log.rows_read), ([], 0))

    def test_line_numbers_survive_blank_lines(self):
        log = parse(HEADER + "2026-03-01T00:00:00Z,a,1.1.1.1,login,success\n\n\n"
                             "2026-03-01T00:01:00Z,b,1.1.1.1,login,success\n"
                             "bad-time,c,1.1.1.1,login,success\n")
        self.assertEqual([e["line"] for e in log.events], [2, 5])
        self.assertIn("Line 6", log.warnings[0])

    def test_extra_fields_row_is_skipped(self):
        log = parse(HEADER + "2026-03-01T00:00:00Z,a,1.1.1.1,login,success,surprise\n")
        self.assertEqual((log.events, log.rows_skipped), ([], 1))

    def test_counts_rows_read_and_skipped(self):
        log = parse(HEADER + "2026-03-01T00:00:00Z,a,1.1.1.1,login,success\n"
                             "oops\n2026-03-01T00:00:00Z,a,1.1.1.1,login,wat\n")
        self.assertEqual((log.rows_read, len(log.events), log.rows_skipped), (3, 1, 2))

    def test_warning_flood_is_capped(self):
        log = parse(HEADER + "oops\n" * 1000)
        self.assertEqual(log.rows_skipped, 1000)
        self.assertLessEqual(len(log.warnings), cg.MAX_WARNINGS + 1)
        self.assertIn("suppressed", log.warnings[-1])

    def test_events_carry_line_numbers(self):
        log = parse(HEADER + "2026-03-01T00:00:00Z,a,1.1.1.1,login,success\n")
        self.assertEqual(log.events[0]["line"], 2)

    def test_directory_as_input_is_a_clean_error(self):
        with self.assertRaises(cg.LogError):
            cg.read_events(tempfile.gettempdir())


class TestEvidenceFromCsv(unittest.TestCase):
    def test_source_lines_point_at_the_real_csv_lines(self):
        rows = "2026-03-01T09:00:00Z,alice,192.0.2.10,login,success\n"
        for i in range(5):
            rows += f"2026-03-01T10:0{i}:00Z,eve,203.0.113.9,login,failure\n"
        rows += "2026-03-01T10:06:00Z,eve,203.0.113.9,login,success\n"
        alerts = cg.analyze(parse(HEADER + rows).events)
        by_rule = {a["rule"]: a for a in alerts}
        self.assertEqual(by_rule["repeated_failed_logins"]["source_lines"], [3, 4, 5, 6, 7])
        self.assertEqual(by_rule["success_after_failures"]["source_lines"], [3, 4, 5, 6, 7, 8])

    def test_sample_logs_alerts(self):
        events, warnings = cg.read_events("sample_logs.csv")
        self.assertEqual(warnings, [])
        alerts = cg.analyze(events)
        self.assertEqual([(a["rule"], a["event_count"]) for a in alerts],
                         [("repeated_failed_logins", 6),
                          ("success_after_failures", 7),      # 6 failures + 1 success
                          ("unexpected_privilege_change", 1)])  # admin's own change is approved
        self.assertIn("6 failed logins", alerts[0]["reason"])   # old code said 5

    def test_malformed_sample_warns_but_still_analyses(self):
        events, warnings = cg.read_events("sample_logs_malformed.csv")
        self.assertGreaterEqual(len(warnings), 6)
        text = "\n".join(warnings)
        for needle in ("unknown status", "invalid timestamp", "missing or extra", "UTC"):
            self.assertIn(needle, text)
        self.assertTrue(cg.analyze(events))


class TestReportStructure(unittest.TestCase):
    def run_cli(self, *extra):
        out = write_temp(b"")
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cg.main(["--input", "sample_logs.csv", "--output", out, *extra])
            with open(out, encoding="utf-8") as handle:
                return code, json.load(handle), buffer.getvalue()
        finally:
            os.remove(out)

    def test_report_keys_and_alert_fields(self):
        code, report, console = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(set(report), {"generated_at", "note", "timezone", "settings",
                                       "log_summary", "alert_count", "alerts", "warnings"})
        self.assertEqual(report["alert_count"], len(report["alerts"]))
        self.assertEqual(report["settings"], {"fail_threshold": 5, "window_minutes": 10,
                                              "approved_admins": ["admin", "secops"]})
        self.assertEqual(report["log_summary"], {"rows_read": 20, "events_parsed": 20,
                                                 "rows_skipped": 0})
        datetime.fromisoformat(report["generated_at"])
        for alert in report["alerts"]:
            self.assertEqual(set(alert), {"rule", "severity", "reason", "timestamp", "username",
                                          "source_ip", "first_seen", "last_seen", "event_count",
                                          "usernames", "source_lines"})
            self.assertIsInstance(alert["usernames"], list)
            self.assertIsInstance(alert["event_count"], int)
            self.assertTrue(all(isinstance(n, int) for n in alert["source_lines"]))
            self.assertTrue(alert["timestamp"].endswith("+00:00"))
        self.assertEqual(report["alerts"], sorted(report["alerts"], key=lambda a: a["timestamp"]))
        self.assertIn("raised 3 alerts", console)

    def test_cli_options_flow_into_report(self):
        _, report, _ = self.run_cli("--threshold", "3", "--window-minutes", "5")
        self.assertEqual(report["settings"]["fail_threshold"], 3)
        self.assertEqual(report["settings"]["window_minutes"], 5)

    def test_build_report_is_pure_and_json_safe(self):
        report = cg.build_report([], ["w"], {"fail_threshold": 5})
        json.dumps(report)
        self.assertEqual((report["alert_count"], report["warnings"]), (0, ["w"]))


if __name__ == "__main__":
    unittest.main()
