"""Streamlit app behaviour tests using Streamlit's AppTest runner.

AppTest executes the real dashboard.py script headlessly (no browser). It checks the
rendered element tree, not pixels. Skipped automatically if Streamlit is not installed.
"""
import unittest

try:
    from streamlit.testing.v1 import AppTest
except ImportError:                                    # pragma: no cover
    AppTest = None

HEADER = "timestamp,username,source_ip,event_type,status\n"
MALFORMED = "Bundled malformed sample (parser warnings demo)"


def new_app():
    return AppTest.from_file("dashboard.py", default_timeout=60).run()


def metrics(app):
    return {m.label: m.value for m in app.metric}


@unittest.skipIf(AppTest is None, "streamlit is not installed")
class TestDashboardApp(unittest.TestCase):
    def test_default_sample_renders_without_errors(self):
        app = new_app()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(metrics(app), {"Events parsed": "20", "Rows skipped": "0",
                                        "Alerts (all)": "3", "Critical (all)": "1",
                                        "High (all)": "2"})
        headers = [s.value for s in app.subheader]
        self.assertIn("Overview: all alerts (before filters)", headers)
        self.assertIn("Alerts: showing 3 of 3 (times are UTC)", headers)
        self.assertIn("Investigate an alert", headers)
        self.assertEqual(len(app.warning), 1)                      # the disclaimer

    def test_kpis_stay_on_all_alerts_when_filters_hide_some(self):
        app = new_app()
        severity = [m for m in app.sidebar.multiselect if m.label == "Severity"][0]
        severity.set_value(["critical"]).run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(metrics(app)["Alerts (all)"], "3")        # KPIs = all alerts
        self.assertIn("Alerts: showing 1 of 3 (times are UTC)", [s.value for s in app.subheader])

    def test_filtered_to_nothing_shows_distinct_message(self):
        app = new_app()
        [m for m in app.sidebar.multiselect if m.label == "Severity"][0].set_value([]).run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("No alerts match the current filters (3 alerts are hidden)" in i.value
                            for i in app.info))
        self.assertEqual(len(app.dataframe), 0)

    def test_no_alerts_raised_message_differs_from_filtered_empty(self):
        app = new_app()
        app.sidebar.radio[0].set_value("Upload CSV").run()
        quiet = HEADER + "2026-03-01T00:00:00Z,alice,1.1.1.1,login,success\n"
        app.sidebar.file_uploader[0].upload("quiet.csv", quiet.encode(), "text/csv").run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("No alerts were raised" in s.value for s in app.success))

    def test_sort_and_username_filter_are_applied(self):
        app = new_app()
        [s for s in app.sidebar.selectbox if s.label == "Sort by"][0].set_value("Time (newest first)").run()
        self.assertTrue(app.selectbox[0].options[0].startswith("A003"))
        [t for t in app.sidebar.text_input if t.label == "Username contains"][0].set_value("bob").run()
        self.assertIn("showing 1 of 3", " ".join(s.value for s in app.subheader))

    def test_malformed_sample_shows_warnings_and_skipped_rows(self):
        app = new_app()
        app.sidebar.radio[0].set_value(MALFORMED).run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(metrics(app)["Rows skipped"], "7")
        self.assertEqual(len(app.expander), 1)
        self.assertIn("Parser warnings (9)", app.expander[0].label)
        texts = " ".join(t.value for t in app.text)
        self.assertIn("unknown status 'failed'", texts)

    def test_upload_valid_file(self):
        app = new_app()
        app.sidebar.radio[0].set_value("Upload CSV").run()
        rows = "".join(f"2026-03-01T00:0{i}:00Z,eve,1.1.1.1,login,failure\n" for i in range(5))
        app.sidebar.file_uploader[0].upload("../../my logs.csv", (HEADER + rows).encode(), "text/csv").run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(metrics(app)["Alerts (all)"], "1")
        self.assertTrue(any("Source: my logs.csv" in t.value for t in app.text))   # path stripped

    def test_upload_with_bom_and_messy_headers(self):
        app = new_app()
        app.sidebar.radio[0].set_value("Upload CSV").run()
        data = b"\xef\xbb\xbf" + b" TIMESTAMP ,Username,SOURCE_IP,Event_Type,STATUS\n" \
            + b"2026-03-01T00:00:00Z,bob,1.1.1.1,privilege_change,success\n"
        app.sidebar.file_uploader[0].upload("x.csv", data, "text/csv").run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(metrics(app)["Alerts (all)"], "1")

    def test_upload_oversize_is_rejected_with_message(self):
        app = new_app()
        app.sidebar.radio[0].set_value("Upload CSV").run()
        app.sidebar.file_uploader[0].upload("big.csv", b"x" * (5 * 1024 * 1024 + 1), "text/csv").run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("larger than 5 MB" in e.value for e in app.error))
        self.assertEqual(len(app.metric), 0)

    def test_upload_bad_files_give_errors_not_crashes(self):
        for name, data in (("empty.csv", b""), ("bin.csv", b"\xff\xfe\x00\x01"),
                           ("cols.csv", b"a,b\n1,2\n")):
            app = new_app()
            app.sidebar.radio[0].set_value("Upload CSV").run()
            app.sidebar.file_uploader[0].upload(name, data, "text/csv").run()
            self.assertEqual(len(app.exception), 0, name)
            self.assertEqual(len(app.error), 1, name)

    def test_hostile_values_are_not_rendered_as_markdown(self):
        app = new_app()
        app.sidebar.radio[0].set_value("Upload CSV").run()
        row = "2026-03-01T00:00:00Z,[click](http://evil.example),1.1.1.1,privilege_change,success\n"
        app.sidebar.file_uploader[0].upload("hostile.csv", (HEADER + row).encode(), "text/csv").run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("[click](http://evil.example)" in t.value for t in app.text))
        for md in app.markdown:                       # only fixed headings may use markdown
            self.assertNotIn("evil.example", md.value)

    def test_cache_never_serves_stale_results(self):
        """Same file name, different content / different settings => fresh results.
        st.cache_data is shared across sessions in one process, so two sessions that upload
        different bytes under the SAME name prove the cache key is the content."""
        row = "2026-03-01T00:0{}:00Z,eve,1.1.1.1,login,failure\n"
        five = "".join(row.format(i) for i in range(5))
        four = "".join(row.format(i) for i in range(4))

        def upload(text):
            app = new_app()
            app.sidebar.radio[0].set_value("Upload CSV").run()
            app.sidebar.file_uploader[0].upload("same.csv", (HEADER + text).encode(), "text/csv").run()
            self.assertEqual(len(app.exception), 0)
            return app

        self.assertEqual(metrics(upload(five))["Alerts (all)"], "1")
        self.assertEqual(metrics(upload(four))["Alerts (all)"], "0")      # not the cached '1'
        app = upload(five)                                                 # back to the first bytes
        self.assertEqual(metrics(app)["Alerts (all)"], "1")
        # same bytes, new setting -> recomputed. (Kept to one run from a page that has
        # alerts: AppTest cannot re-run a page whose multiselects have no options.)
        threshold = [n for n in app.sidebar.number_input if n.label.startswith("Failed-login")][0]
        threshold.set_value(6).run()
        self.assertEqual(metrics(app)["Alerts (all)"], "0")

    def test_header_only_upload_says_no_events(self):
        app = new_app()
        app.sidebar.radio[0].set_value("Upload CSV").run()
        app.sidebar.file_uploader[0].upload("h.csv", HEADER.encode(), "text/csv").run()
        self.assertTrue(any("No valid events" in i.value for i in app.info))


if __name__ == "__main__":
    unittest.main()
