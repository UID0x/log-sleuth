import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from log_sleuth.cli import main
from log_sleuth.models import Finding, Report, Severity
from log_sleuth.report import render_html

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def run(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main([*map(str, args), "--no-color"])
    return code, stdout.getvalue(), stderr.getvalue()


class CliTest(unittest.TestCase):
    def test_samples_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            code, stdout, _ = run(SAMPLES / "auth.log", SAMPLES / "access.log", "--year", "2026", "--json", out)
            self.assertEqual(code, 0)
            self.assertIn("SSH_COMPROMISE", stdout)
            data = json.loads(out.read_text(encoding="utf-8"))
        found = {(f["rule"], f["ip"]) for f in data["findings"]}
        expected = {
            ("SSH_COMPROMISE", "203.0.113.99"),
            ("SSH_BRUTE_FORCE", "203.0.113.42"),
            ("SSH_USER_ENUM", "192.0.2.77"),
            ("WEB_SENSITIVE_EXPOSED", "192.0.2.150"),
            ("WEB_SCANNER", "192.0.2.150"),
            ("WEB_INJECTION", "203.0.113.200"),
            ("WEB_INJECTION", "192.0.2.201"),
        }
        self.assertTrue(expected <= found, expected - found)
        # Legitimate admins must never show up.
        admins = {"198.51.100.10", "198.51.100.11", "198.51.100.20"}
        self.assertFalse(admins & {ip for _, ip in found})

    def test_fail_on_exit_code(self):
        code, _, _ = run(SAMPLES / "auth.log", "--fail-on", "critical")
        self.assertEqual(code, 2)

    def test_min_severity_filter(self):
        _, stdout, _ = run(SAMPLES / "access.log", "--min-severity", "high")
        self.assertNotIn("WEB_SENSITIVE_PROBE", stdout)
        self.assertNotIn("WEB_SCANNER", stdout)

    def test_missing_file(self):
        code, _, stderr = run("does-not-exist.log")
        self.assertEqual(code, 1)
        self.assertIn("file not found", stderr)


class HtmlEscapingTest(unittest.TestCase):
    def test_payloads_from_logs_are_escaped(self):
        """A log line is attacker-controlled: it must not become XSS in our own report."""
        from datetime import datetime

        now = datetime(2026, 10, 10)
        evil = '<script>alert("pwned")</script>'
        finding = Finding("WEB_INJECTION", Severity.HIGH, "192.0.2.1", evil, evil, now, now, 1, [evil])
        page = render_html(Report(files=[], findings=[finding], generated_at=now))
        self.assertNotIn(evil, page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
