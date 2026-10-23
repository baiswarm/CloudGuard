"""Tests for dashboard_helpers.py (standard library only; no Streamlit needed)."""
import copy
import csv
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import cloudguard as cg
import dashboard_helpers as dh

HEADER = "timestamp,username,source_ip,event_type,status\n"


def sample_alerts():
    events, _ = cg.read_events("sample_logs.csv")
    return dh.assign_alert_ids(cg.analyze(events))


def alert_with(**changes):
    base = dict(sample_alerts()[0])
    base.update(changes)
    return base


class TestFormulaInjection(unittest.TestCase):
    def test_every_dangerous_prefix_is_neutralised(self):
        for prefix in ("=", "+", "-", "@", "\t", "\r"):
            value = prefix + "cmd|' /C calc'!A0"
            self.assertEqual(dh.sanitize_cell(value), "'" + value, repr(prefix))

    def test_leading_spaces_do_not_bypass(self):
        self.assertEqual(dh.sanitize_cell("  =1+1"), "'  =1+1")

    def test_safe_values_pass_through(self):
        for value in ("alice", "10.0.0.1", "2026-03-01T10:00:00+00:00", "", "  ", 5, None):
            self.assertEqual(dh.sanitize_cell(value), value)

    def test_csv_export_neutralises_every_text_column(self):
        evil = "=HYPERLINK(\"http://evil.example\",\"x\")"
        alert = alert_with(username=evil, usernames=["+bad", "@bad", "-bad"], reason="=1+1",
                           source_ip="\t10.0.0.1", rule="@rule")
        rows = list(csv.DictReader(io.StringIO(dh.alerts_to_csv([alert]))))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["username"], "'" + evil)
        self.assertEqual(row["usernames"], "'+bad; @bad; -bad")   # whole cell starts with '+'
        self.assertEqual(row["reason"], "'=1+1")
        self.assertEqual(row["source_ip"], "'\t10.0.0.1")
        self.assertEqual(row["rule"], "'@rule")
        for cell in row.values():
            self.assertNotIn(cell[:1], ("=", "+", "-", "@", "\t", "\r"))

    def test_export_does_not_modify_underlying_alerts(self):
        alert = alert_with(username="=evil", usernames=["=evil"])
        before = copy.deepcopy(alert)
        dh.alerts_to_csv([alert])
        self.assertEqual(alert, before)

    def test_json_export_keeps_original_values(self):
        alert = alert_with(username="=evil", usernames=["=evil"])
        log = cg.LogData()
        report = json.loads(dh.alerts_to_json([alert], [], {}, log, 1, {}))
        self.assertEqual(report["alerts"][0]["username"], "=evil")


class TestExportConsistency(unittest.TestCase):
    def test_csv_and_json_hold_the_same_alerts_in_the_same_order(self):
        alerts = dh.sort_alerts(sample_alerts(), "Severity (critical first)")
        log = cg.LogData(events=[1] * 20, rows_read=20)
        csv_rows = list(csv.DictReader(io.StringIO(dh.alerts_to_csv(alerts))))
        report = json.loads(dh.alerts_to_json(alerts, ["w"], {"fail_threshold": 5}, log, 3,
                                              {"severities": ["critical", "high"]}))
        self.assertEqual([r["alert_id"] for r in csv_rows], [a["alert_id"] for a in report["alerts"]])
        self.assertEqual([r["timestamp"] for r in csv_rows], [a["timestamp"] for a in report["alerts"]])
        self.assertEqual([int(r["event_count"]) for r in csv_rows],
                         [a["event_count"] for a in report["alerts"]])
        self.assertEqual(report["alert_count"], len(csv_rows))
        self.assertEqual(report["export_scope"]["alerts_before_filters"], 3)
        self.assertEqual(report["export_scope"]["filters"], {"severities": ["critical", "high"]})
        self.assertEqual(report["log_summary"]["events_parsed"], 20)

    def test_empty_export_is_header_only_and_valid_json(self):
        self.assertEqual(dh.alerts_to_csv([]).strip(), ",".join(dh.EXPORT_FIELDS))
        self.assertEqual(json.loads(dh.alerts_to_json([], [], {}, cg.LogData(), 0, {}))["alert_count"], 0)

    def test_csv_list_columns_are_flattened(self):
        row = next(csv.DictReader(io.StringIO(dh.alerts_to_csv(sample_alerts()[:1]))))
        self.assertIn("3", row["source_lines"] + " ")        # line numbers, space separated
        self.assertNotIn("[", row["source_lines"])


class TestUploads(unittest.TestCase):
    def test_exact_limit_is_accepted_and_one_byte_over_rejected(self):
        dh.check_upload_size(dh.MAX_UPLOAD_BYTES)
        with self.assertRaisesRegex(cg.LogError, "5 MB"):
            dh.check_upload_size(dh.MAX_UPLOAD_BYTES + 1)

    def test_loader_rechecks_size_itself(self):
        with self.assertRaises(cg.LogError):
            dh.load_log_from_bytes(b"x" * (dh.MAX_UPLOAD_BYTES + 1))

    def test_streamlit_config_matches_code_limit_and_binds_localhost(self):
        text = open(os.path.join(os.path.dirname(__file__) or ".", ".streamlit", "config.toml"),
                    encoding="utf-8").read()
        self.assertIn(f"maxUploadSize = {dh.MAX_UPLOAD_MB}", text)
        self.assertIn('address = "127.0.0.1"', text)
        self.assertIn('base = "dark"', text)                  # theme preserved
        self.assertIn('primaryColor = "#ff4b4b"', text)
        self.assertIn("gatherUsageStats = false", text)

    def test_no_temporary_files_on_success_or_failure(self):
        with tempfile.TemporaryDirectory() as scratch, \
                mock.patch.object(tempfile, "tempdir", scratch), \
                mock.patch("tempfile.NamedTemporaryFile", side_effect=AssertionError("temp file")), \
                mock.patch("tempfile.mkstemp", side_effect=AssertionError("temp file")):
            good = dh.load_log_from_bytes((HEADER + "2026-03-01T00:00:00Z,a,1.1.1.1,login,success\n").encode())
            self.assertEqual(len(good.events), 1)
            for bad in (b"", b"\xff\xfe\xfa", b"a,b\n1,2\n", b"x" * (dh.MAX_UPLOAD_BYTES + 1)):
                with self.assertRaises(cg.LogError):
                    dh.load_log_from_bytes(bad)
            self.assertEqual(os.listdir(scratch), [])

    def test_bom_upload(self):
        data = b"\xef\xbb\xbf" + (HEADER + "2026-03-01T00:00:00Z,a,1.1.1.1,login,success\n").encode()
        self.assertEqual(len(dh.load_log_from_bytes(data).events), 1)


class TestDisplayNames(unittest.TestCase):
    def test_paths_are_stripped(self):
        self.assertEqual(dh.safe_display_name("../../etc/passwd"), "passwd")
        self.assertEqual(dh.safe_display_name("C:\\Users\\bob\\logs.csv"), "logs.csv")

    def test_control_and_bidi_characters_removed(self):
        self.assertEqual(dh.safe_display_name("a\x1b[31mb\n.csv\u202etxt"), "a[31mb.csvtxt")

    def test_markdown_is_not_interpreted_text_is_just_returned(self):
        self.assertEqual(dh.safe_display_name("[x](e).csv"), "[x](e).csv")

    def test_long_and_empty_names(self):
        self.assertLessEqual(len(dh.safe_display_name("a" * 500 + ".csv")), 80)
        for empty in ("", None, "\x00\x01", "///"):
            self.assertEqual(dh.safe_display_name(empty), "uploaded.csv")


class TestFilteringAndSorting(unittest.TestCase):
    def setUp(self):
        self.alerts = sample_alerts()     # brute (high), critical, privilege (high)

    def test_none_means_unrestricted_empty_means_nothing(self):
        self.assertEqual(len(dh.filter_alerts(self.alerts)), 3)
        self.assertEqual(dh.filter_alerts(self.alerts, severities=[]), [])

    def test_filters_combine(self):
        self.assertEqual([a["rule"] for a in dh.filter_alerts(self.alerts, severities=["critical"])],
                         ["success_after_failures"])
        self.assertEqual(len(dh.filter_alerts(self.alerts, rules=["repeated_failed_logins"],
                                              ips=["203.0.113.50"])), 1)
        self.assertEqual(dh.filter_alerts(self.alerts, ips=["9.9.9.9"]), [])

    def test_username_search_is_case_insensitive_substring(self):
        hits = dh.filter_alerts(self.alerts, username_query=" ROO ")
        # 'root' appears in the burst's failures and in the critical alert's evidence
        self.assertEqual({a["rule"] for a in hits},
                         {"repeated_failed_logins", "success_after_failures"})

    def test_sorting_options(self):
        by_sev = dh.sort_alerts(self.alerts, "Severity (critical first)")
        self.assertEqual(by_sev[0]["severity"], "critical")
        newest = dh.sort_alerts(self.alerts, "Time (newest first)")
        self.assertEqual([a["alert_id"] for a in newest], ["A003", "A002", "A001"])
        by_count = dh.sort_alerts(self.alerts, "Event count (most first)")
        self.assertEqual(by_count[0]["event_count"], 7)
        self.assertEqual([a["alert_id"] for a in dh.sort_alerts(self.alerts)], ["A001", "A002", "A003"])

    def test_kpis_split_all_vs_shown(self):
        log = cg.LogData(events=[0] * 20, rows_skipped=2)
        shown = dh.filter_alerts(self.alerts, severities=["critical"])
        kpis = dh.kpi_summary(log, self.alerts, shown)
        self.assertEqual(kpis, {"events_parsed": 20, "rows_skipped": 2, "alerts_all": 3,
                                "critical_all": 1, "high_all": 2, "alerts_shown": 1})


class TestInvestigation(unittest.TestCase):
    SETTINGS = {"fail_threshold": 5, "window_minutes": 10, "approved_admins": ["admin", "secops"]}

    def setUp(self):
        self.events, _ = cg.read_events("sample_logs.csv")
        self.alerts = sample_alerts()
        self.by_rule = {a["rule"]: a for a in self.alerts}

    def test_explanations_mention_real_numbers(self):
        brute = dh.explain_alert(self.by_rule["repeated_failed_logins"], self.SETTINGS)
        self.assertIn("6 failed login events", brute)
        self.assertIn("203.0.113.50", brute)
        self.assertIn("UTC", brute)
        priv = dh.explain_alert(self.by_rule["unexpected_privilege_change"], self.SETTINGS)
        self.assertIn("cannot be known", priv)       # no invented privilege details
        self.assertNotIn("role was", priv)

    def test_incident_summary_contains_evidence(self):
        text = dh.build_incident_summary(self.by_rule["success_after_failures"], self.SETTINGS)
        for needle in ("CRITICAL", "203.0.113.50", "admin", "CSV lines", "not proof"):
            self.assertIn(needle, text)

    def test_timeline_marks_evidence_and_respects_context(self):
        alert = self.by_rule["repeated_failed_logins"]
        rows, total = dh.timeline_for_alert(self.events, alert, context_minutes=0)
        self.assertEqual(total, 6)                 # only the burst itself; success is 90s later
        self.assertTrue(all(r["in_alert"] for r in rows))
        self.assertTrue(all(r["source_ip"] == "203.0.113.50" for r in rows))
        wide, wide_total = dh.timeline_for_alert(self.events, alert, context_minutes=10)
        self.assertEqual(wide_total, 7)            # now includes the later success
        self.assertEqual(sum(r["in_alert"] for r in dh.timeline_for_alert(self.events, alert, 10)[0]), 6)
        whole, whole_total = dh.timeline_for_alert(self.events, alert, whole_ip=True)
        self.assertEqual(whole_total, 7)
        self.assertEqual([r["line"] for r in rows], sorted(r["line"] for r in rows))

    def test_privilege_timeline_includes_that_users_other_ips(self):
        alert = self.by_rule["unexpected_privilege_change"]          # bob @ 192.0.2.11
        rows, total = dh.timeline_for_alert(self.events, alert, whole_ip=True)
        self.assertEqual({r["username"] for r in rows} | {"bob"}, {"bob"})
        self.assertGreaterEqual(total, 3)           # bob's failure, success and the change

    def test_timeline_row_limit(self):
        alert = self.by_rule["repeated_failed_logins"]
        rows, total = dh.timeline_for_alert(self.events, alert, whole_ip=True, limit=2)
        self.assertEqual((len(rows), total), (2, 7))


if __name__ == "__main__":
    unittest.main()
