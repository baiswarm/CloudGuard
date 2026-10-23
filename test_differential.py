"""Differential tests: optimised engine vs the ORIGINAL (pre-audit) algorithms.

The reference functions below are the original CloudGuard implementations,
kept verbatim in behaviour (O(n*m) list scans). The new engine must agree with
them on the intended semantics over seeded synthetic data, and must keep its own
burst/de-duplication invariants. Datasets use a coarse time grid so window
edges and same-second ties occur constantly.
"""
import random
import time
import unittest
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import cloudguard as cg

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


# ---------------- reference implementation (original semantics) ----------------

def ref_failures_by_ip(events):
    groups = defaultdict(list)
    for e in events:
        if e["event_type"] == "login" and e["status"] == "failure":
            groups[e["source_ip"]].append(e)
    return groups


def ref_find_burst(failures, threshold, window):
    for start in range(len(failures) - threshold + 1):
        group = failures[start:start + threshold]
        if group[-1]["timestamp"] - group[0]["timestamp"] <= window:
            return group
    return None


def ref_first_bursts(events, threshold, window_minutes):
    """{ip: timestamp of the Nth failure of the FIRST burst} (the original alert)."""
    ordered = sorted(events, key=lambda e: e["timestamp"])
    window = timedelta(minutes=window_minutes)
    result = {}
    for ip, failures in ref_failures_by_ip(ordered).items():
        burst = ref_find_burst(failures, threshold, window)
        if burst:
            result[ip] = burst[-1]["timestamp"]
    return result


def ref_qualifying_successes(events, threshold, window_minutes):
    """[(line, failures_in_window)] exactly as the original quadratic scan computed it."""
    ordered = sorted(events, key=lambda e: e["timestamp"])
    window = timedelta(minutes=window_minutes)
    failures = ref_failures_by_ip(ordered)
    out = []
    for e in ordered:
        if e["event_type"] != "login" or e["status"] != "success":
            continue
        recent = [f for f in failures.get(e["source_ip"], [])
                  if e["timestamp"] - window <= f["timestamp"] <= e["timestamp"]]
        if len(recent) >= threshold:
            out.append((e["line"], len(recent)))
    return out


# ---------------- synthetic data ----------------

def make_dataset(seed, size):
    rng = random.Random(seed)
    ips = [f"198.51.100.{i}" for i in range(1, rng.randint(2, 5))]
    tz_choices = [timezone.utc, timezone(timedelta(hours=5, minutes=30)),
                  timezone(timedelta(hours=-8))]
    events = []
    for line in range(2, size + 2):
        # 30-second grid over ~3 hours: lots of exact-boundary and same-second events
        when = (BASE + timedelta(seconds=30 * rng.randint(0, 360))).astimezone(rng.choice(tz_choices))
        kind = rng.random()
        if kind < 0.62:
            etype, status = "login", "failure"
        elif kind < 0.90:
            etype, status = "login", "success"
        else:
            etype, status = "privilege_change", rng.choice(["success", "failure"])
        events.append({"timestamp": when, "username": rng.choice(["a", "b", "admin", "c"]),
                       "source_ip": rng.choice(ips), "event_type": etype, "status": status,
                       "line": line})
    rng.shuffle(events)
    return events


SETTINGS = [(5, 10), (3, 5), (1, 10), (2, 1), (4, 30), (6, 3)]
SEEDS = range(60)


class TestDifferentialAgainstOriginal(unittest.TestCase):
    def test_qualifying_successes_match_original_scan(self):
        compared = 0
        for seed in SEEDS:
            events = make_dataset(seed, 50 + seed * 4)
            for threshold, window in SETTINGS:
                expected = ref_qualifying_successes(events, threshold, window)
                actual = [(e["line"], n) for e, n in
                          cg.find_qualifying_successes(events, threshold, window)]
                self.assertEqual(sorted(actual), sorted(expected),
                                 f"seed={seed} threshold={threshold} window={window}")
                compared += len(expected)
        self.assertGreater(compared, 500, "datasets should actually exercise the rule")

    def test_first_burst_matches_original_find_burst(self):
        hits = 0
        for seed in SEEDS:
            events = make_dataset(seed, 50 + seed * 4)
            for threshold, window in SETTINGS:
                expected = ref_first_bursts(events, threshold, window)
                alerts = cg.detect_brute_force(events, threshold, window)
                first = {}
                for a in alerts:            # alerts are chronological per call; take earliest per IP
                    first.setdefault(a["source_ip"], a["timestamp"])
                self.assertEqual(set(first), set(expected),
                                 f"seed={seed} threshold={threshold} window={window}")
                for ip, stamp in expected.items():
                    self.assertEqual(first[ip], stamp.astimezone(timezone.utc).isoformat())
                hits += len(expected)
        self.assertGreater(hits, 100)


class TestBurstInvariants(unittest.TestCase):
    def test_invariants_over_seeded_data(self):
        for seed in SEEDS:
            events = make_dataset(seed, 40 + seed * 5)
            by_line = {e["line"]: e for e in events}
            for threshold, window in SETTINGS:
                alerts = cg.analyze(events, threshold, window)
                self.assertEqual(alerts, cg.analyze(list(reversed(events)), threshold, window))
                brute = [a for a in alerts if a["rule"] == "repeated_failed_logins"]
                succ = [a for a in alerts if a["rule"] == "success_after_failures"]

                # bursts: every event used at most once, only failures from that IP, >= threshold
                seen = set()
                for a in brute:
                    self.assertGreaterEqual(a["event_count"], threshold)
                    self.assertEqual(a["event_count"], len(a["source_lines"]))
                    for line in a["source_lines"]:
                        self.assertNotIn(line, seen, "failure reused by two bursts")
                        seen.add(line)
                        e = by_line[line]
                        self.assertEqual((e["source_ip"], e["event_type"], e["status"]),
                                         (a["source_ip"], "login", "failure"))
                    self.assertLessEqual(a["first_seen"], a["timestamp"])
                    self.assertLessEqual(a["timestamp"], a["last_seen"])

                # every qualifying success is covered by exactly one critical alert
                qualifying = [e["line"] for e, _ in
                              cg.find_qualifying_successes(events, threshold, window)]
                covered = []
                for a in succ:
                    covered += [l for l in a["source_lines"]
                                if by_line[l]["status"] == "success"]
                self.assertEqual(sorted(covered), sorted(qualifying))
                self.assertLessEqual(len(succ), len(qualifying))

                # alerts are chronological by instant
                stamps = [datetime.fromisoformat(a["timestamp"]) for a in alerts]
                self.assertEqual(stamps, sorted(stamps))


class TestScaling(unittest.TestCase):
    def test_large_single_ip_dataset_finishes_quickly(self):
        # 30k failures + 30k successes from ONE ip: the original scan did ~9e8 comparisons.
        events = []
        for i in range(30000):
            events.append({"timestamp": BASE + timedelta(seconds=i * 7), "username": "u",
                           "source_ip": "203.0.113.1", "event_type": "login",
                           "status": "failure", "line": i})
            events.append({"timestamp": BASE + timedelta(seconds=i * 7 + 3), "username": "u",
                           "source_ip": "203.0.113.1", "event_type": "login",
                           "status": "success", "line": 100000 + i})
        started = time.perf_counter()
        alerts = cg.analyze(events)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(alerts), 2)          # one sustained burst, one deduplicated incident
        self.assertLess(elapsed, 15, f"took {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
