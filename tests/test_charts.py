import json
import unittest
from datetime import datetime, timedelta

from log_sleuth import charts
from log_sleuth.detectors import detect
from log_sleuth.models import Event, Report
from log_sleuth.report import render_html, render_json

T0 = datetime(2026, 10, 10, 22, 0, 0)


def ssh(kind, seconds, ip="203.0.113.9", user="deploy"):
    return Event(timestamp=T0 + timedelta(seconds=seconds), source="auth", kind=kind, ip=ip, user=user, raw=kind)


class HelpersTest(unittest.TestCase):
    def test_nice_ticks(self):
        self.assertEqual(charts.nice_ticks(320), [0, 100, 200, 300, 400])
        self.assertEqual(charts.nice_ticks(7), [0, 2, 4, 6, 8])
        self.assertEqual(charts.nice_ticks(1), [0, 1])
        self.assertEqual(charts.nice_ticks(0), [0, 1])

    def test_pick_bucket(self):
        self.assertEqual(charts.pick_bucket(timedelta(hours=23)), timedelta(minutes=30))
        self.assertEqual(charts.pick_bucket(timedelta(hours=24)), timedelta(hours=1))  # 48 bars is the limit
        self.assertEqual(charts.pick_bucket(timedelta(minutes=20)), timedelta(minutes=1))
        self.assertEqual(charts.pick_bucket(timedelta(days=90)), timedelta(days=1))

    def test_floor_time(self):
        self.assertEqual(charts.floor_time(datetime(2026, 1, 1, 14, 47, 12), timedelta(minutes=15)),
                         datetime(2026, 1, 1, 14, 45))

    def test_fmt_duration(self):
        self.assertEqual(charts.fmt_duration(timedelta(seconds=42)), "42 s")
        self.assertEqual(charts.fmt_duration(timedelta(seconds=130)), "2 min 10 s")
        self.assertEqual(charts.fmt_duration(timedelta(hours=1, minutes=5)), "1 h 05 min")


class ChartsTest(unittest.TestCase):
    def setUp(self):
        self.events = [ssh("ssh_failed", i * 10) for i in range(8)] + [ssh("ssh_accepted", 90)]
        self.events.append(ssh("ssh_accepted", 300, ip="198.51.100.10", user="alice"))
        self.findings = detect(self.events)

    def test_incident_tells_the_story(self):
        critical = next(f for f in self.findings if f.rule == "SSH_COMPROMISE")
        html = charts.incident(critical)
        self.assertIn("8 failed logins in 1 min 30 s", html)
        self.assertEqual(html.count('class="try"'), 8)
        self.assertEqual(html.count('class="hit"'), 1)

    def test_timeline_colours_by_worst_finding(self):
        html = charts.timeline(self.events, self.findings)
        self.assertIn("var(--sev-critical)", html)  # the attacker's events
        self.assertIn("var(--sev-other)", html)  # alice, no finding
        self.assertIn("<table>", html)  # accessible data table

    def test_offenders_order(self):
        html = charts.offenders(self.findings)
        self.assertIn("203.0.113.9", html)
        self.assertNotIn("198.51.100.10", html)

    def test_empty_inputs(self):
        self.assertEqual(charts.timeline([], []), "")
        self.assertEqual(charts.offenders([]), "")

    def test_attacker_controlled_username_is_escaped(self):
        evil = '"><img src=x onerror=alert(1)>'
        events = [ssh("ssh_failed", i, user=evil) for i in range(6)] + [ssh("ssh_accepted", 10, user=evil)]
        findings = detect(events)
        page = render_html(Report(files=[], findings=findings, generated_at=T0, events=events))
        self.assertNotIn(evil, page)
        self.assertNotIn("<img", page)

    def test_json_excludes_raw_events(self):
        data = json.loads(render_json(Report(files=[], findings=self.findings, generated_at=T0, events=self.events)))
        self.assertTrue(data["findings"])
        self.assertNotIn("events", data["findings"][0])


if __name__ == "__main__":
    unittest.main()
