import unittest
from datetime import datetime

from log_sleuth.parsers import detect_format, iter_auth_events, parse_auth_line, parse_nginx_line


class AuthParserTest(unittest.TestCase):
    def test_failed_password(self):
        e = parse_auth_line("Oct 10 03:14:15 web01 sshd[4242]: Failed password for root from 203.0.113.42 port 52211 ssh2", 2026)
        self.assertEqual(e.kind, "ssh_failed")
        self.assertEqual((e.ip, e.user), ("203.0.113.42", "root"))
        self.assertEqual(e.timestamp, datetime(2026, 10, 10, 3, 14, 15))

    def test_invalid_user(self):
        e = parse_auth_line("Oct  9 11:01:30 web01 sshd[1]: Failed password for invalid user oracle from 192.0.2.77 port 4000 ssh2", 2026)
        self.assertEqual((e.kind, e.user, e.timestamp.day), ("ssh_invalid_user", "oracle", 9))

    def test_empty_invalid_user(self):
        e = parse_auth_line("Oct 10 11:01:30 web01 sshd[1]: Failed password for invalid user  from 192.0.2.77 port 4000 ssh2", 2026)
        self.assertEqual((e.kind, e.user), ("ssh_invalid_user", ""))

    def test_accepted_publickey(self):
        e = parse_auth_line("Oct 10 09:00:00 web01 sshd[1]: Accepted publickey for alice from 198.51.100.10 port 5 ssh2: ED25519 SHA256:x", 2026)
        self.assertEqual((e.kind, e.user), ("ssh_accepted", "alice"))

    def test_iso_timestamp_and_ipv6(self):
        e = parse_auth_line("2026-10-10T03:14:15.123456+02:00 web01 sshd[9]: Failed password for root from 2001:db8::1 port 22 ssh2", 2000)
        self.assertEqual((e.ip, e.timestamp), ("2001:db8::1", datetime(2026, 10, 10, 3, 14, 15)))

    def test_irrelevant_lines_are_ignored(self):
        for line in [
            "Oct 10 03:14:15 web01 sshd[1]: Connection closed by 203.0.113.42 port 1 [preauth]",
            "Oct 10 03:15:01 web01 CRON[2]: pam_unix(cron:session): session opened for user root",
            "garbage",
            "",
        ]:
            self.assertIsNone(parse_auth_line(line, 2026), line)

    def test_year_rollover(self):
        lines = [
            "Dec 31 23:59:58 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
            "Jan  1 00:00:03 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        ]
        first, second = iter_auth_events(lines, 2025)
        self.assertEqual((first.timestamp.year, second.timestamp.year), (2025, 2026))


class NginxParserTest(unittest.TestCase):
    LINE = ('203.0.113.200 - - [10/Oct/2026:16:30:06 +0200] "GET /products?id=1%27 HTTP/1.1" 500 312 '
            '"-" "sqlmap/1.8.9#stable (https://sqlmap.org)"')

    def test_combined_format(self):
        e = parse_nginx_line(self.LINE, line_no=7, file="access.log")
        self.assertEqual((e.ip, e.method, e.path, e.status), ("203.0.113.200", "GET", "/products?id=1%27", 500))
        self.assertTrue(e.user_agent.startswith("sqlmap"))
        self.assertEqual(e.location, "access.log:7")

    def test_common_format_without_user_agent(self):
        e = parse_nginx_line('192.0.2.1 - bob [10/Oct/2026:16:30:06 +0000] "POST /login HTTP/1.0" 302 0', 1)
        self.assertEqual((e.method, e.status, e.user_agent), ("POST", 302, None))

    def test_malformed_request_is_ignored(self):
        self.assertIsNone(parse_nginx_line('192.0.2.1 - - [10/Oct/2026:16:30:06 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"'))


class DetectFormatTest(unittest.TestCase):
    def test_detects_each_format(self):
        self.assertEqual(detect_format([NginxParserTest.LINE]), "nginx")
        self.assertEqual(detect_format(["Oct 10 03:15:01 web01 CRON[2]: session opened"]), "auth")
        self.assertIsNone(detect_format(["hello world", ""]))


if __name__ == "__main__":
    unittest.main()
