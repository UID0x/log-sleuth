import unittest
from datetime import datetime, timedelta

from log_sleuth.detectors import Thresholds, detect, max_in_window
from log_sleuth.models import Event, Severity

T0 = datetime(2026, 10, 10, 12, 0, 0)


def ssh(kind, ip, seconds, user="root"):
    return Event(timestamp=T0 + timedelta(seconds=seconds), source="auth", kind=kind, ip=ip, user=user, raw=kind)


def http(ip, path, status=404, seconds=0, ua="Mozilla/5.0"):
    return Event(timestamp=T0 + timedelta(seconds=seconds), source="web", kind="http_request",
                 ip=ip, method="GET", path=path, status=status, user_agent=ua, raw=path)


def rules(findings):
    return sorted((f.rule, f.ip) for f in findings)


class SlidingWindowTest(unittest.TestCase):
    def test_max_in_window(self):
        times = [T0 + timedelta(seconds=s) for s in (0, 10, 20, 400, 401, 402, 403)]
        self.assertEqual(max_in_window(times, timedelta(minutes=5)), 4)
        self.assertEqual(max_in_window([], timedelta(minutes=5)), 0)


class SshRulesTest(unittest.TestCase):
    def test_brute_force_and_severity(self):
        medium = detect([ssh("ssh_failed", "192.0.2.1", i * 10) for i in range(6)])
        high = detect([ssh("ssh_failed", "192.0.2.2", i) for i in range(25)])
        self.assertEqual([(f.rule, f.severity) for f in medium], [("SSH_BRUTE_FORCE", Severity.MEDIUM)])
        self.assertEqual([(f.rule, f.severity) for f in high], [("SSH_BRUTE_FORCE", Severity.HIGH)])

    def test_slow_attempts_stay_under_threshold(self):
        events = [ssh("ssh_failed", "192.0.2.1", i * 120) for i in range(10)]  # one every 2 minutes
        self.assertEqual(detect(events), [])

    def test_user_enumeration(self):
        events = [ssh("ssh_invalid_user", "192.0.2.7", i * 90, user=u) for i, u in enumerate("abcde")]
        self.assertEqual(rules(detect(events)), [("SSH_USER_ENUM", "192.0.2.7")])

    def test_success_after_brute_force_is_critical(self):
        events = [ssh("ssh_failed", "203.0.113.9", i * 5) for i in range(8)]
        events.append(ssh("ssh_accepted", "203.0.113.9", 60, user="deploy"))
        findings = detect(events)
        self.assertEqual(findings[0].rule, "SSH_COMPROMISE")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("deploy", findings[0].description)

    def test_single_typo_then_success_is_fine(self):
        events = [ssh("ssh_failed", "198.51.100.10", 0, "alice"), ssh("ssh_accepted", "198.51.100.10", 5, "alice")]
        self.assertEqual(detect(events), [])

    def test_failures_from_another_ip_do_not_count(self):
        events = [ssh("ssh_failed", "192.0.2.1", i) for i in range(10)]
        events.append(ssh("ssh_accepted", "198.51.100.10", 30, "alice"))
        self.assertNotIn("SSH_COMPROMISE", [f.rule for f in detect(events)])


class WebRulesTest(unittest.TestCase):
    def test_exposed_sensitive_file(self):
        findings = detect([http("192.0.2.5", "/.env"), http("192.0.2.5", "/.git/config", status=200)])
        self.assertEqual([(f.rule, f.severity) for f in findings], [("WEB_SENSITIVE_EXPOSED", Severity.HIGH)])

    def test_refused_probe_is_low(self):
        findings = detect([http("192.0.2.5", "/wp-login.php")])
        self.assertEqual([(f.rule, f.severity) for f in findings], [("WEB_SENSITIVE_PROBE", Severity.LOW)])

    def test_injection_payloads(self):
        cases = {
            "/p?id=1%20UNION%20SELECT%20password%20FROM%20users": "SQL injection",
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E": "Cross-site scripting",
            "/dl?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd": "Path traversal",  # double-encoded
            "/ping?h=1;cat%20/etc/passwd": "Command injection",
        }
        for path, label in cases.items():
            findings = [f for f in detect([http("203.0.113.1", path, status=200)]) if f.rule == "WEB_INJECTION"]
            self.assertEqual(len(findings), 1, path)
            self.assertIn(label, findings[0].description)

    def test_log4shell_in_user_agent(self):
        findings = detect([http("192.0.2.9", "/", status=200, ua="${jndi:ldap://x/a}")])
        self.assertIn("Log4Shell", findings[0].description)

    def test_benign_requests(self):
        events = [http("198.51.100.1", p, status=200, seconds=i)
                  for i, p in enumerate(["/", "/blog?page=2", "/search?q=union+station", "/products?sort=id"])]
        self.assertEqual(detect(events), [])

    def test_scanner_by_404_burst_and_user_agent(self):
        burst = [http("192.0.2.20", f"/dir{i}", seconds=i) for i in range(20)]
        tool = [http("192.0.2.21", "/", status=200, ua="Nikto/2.5.0")]
        self.assertEqual(rules(detect(burst + tool)), [("WEB_SCANNER", "192.0.2.20"), ("WEB_SCANNER", "192.0.2.21")])

    def test_custom_thresholds(self):
        events = [http("192.0.2.20", f"/dir{i}", seconds=i) for i in range(5)]
        self.assertEqual(detect(events), [])
        self.assertEqual(len(detect(events, Thresholds(scan_404s=5))), 1)


if __name__ == "__main__":
    unittest.main()
