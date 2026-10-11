"""Command-line entry point: ``log-sleuth FILE [FILE ...]``."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .models import Severity
from .parsers import FORMATS
from .report import render_html, render_json, render_terminal, supports_color

SEVERITIES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-sleuth",
        description="Find brute-force, scanning and injection attempts in SSH and web server logs.",
    )
    parser.add_argument("files", nargs="+", type=Path, help="log files to analyse (.gz supported)")
    parser.add_argument("-f", "--format", choices=["auto", *FORMATS], default="auto",
                        help="log format (default: auto-detect per file)")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year for syslog timestamps, which don't include one (default: current year)")
    parser.add_argument("--json", type=Path, metavar="FILE", help="also write findings as JSON")
    parser.add_argument("--html", type=Path, metavar="FILE", help="also write a standalone HTML report")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="low",
                        help="hide findings below this severity")
    parser.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                        help="exit with status 2 if a finding reaches this severity (useful in CI/cron)")
    parser.add_argument("-v", "--verbose", action="store_true", help="print evidence lines")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    missing = [str(p) for p in args.files if not p.is_file()]
    if missing:
        print(f"log-sleuth: file not found: {', '.join(missing)}", file=sys.stderr)
        return 1

    report = analyze(args.files, fmt=args.format, year=args.year)
    for stats in report.files:
        if stats.format is None:
            print(f"log-sleuth: warning: could not detect the format of {stats.path}, skipped "
                  f"(use --format)", file=sys.stderr)

    floor = Severity(args.min_severity).rank
    report.findings = [f for f in report.findings if f.severity.rank >= floor]

    color = not args.no_color and supports_color()
    sys.stdout.write(render_terminal(report, color=color, verbose=args.verbose))

    if args.json:
        args.json.write_text(render_json(report), encoding="utf-8")
        print(f"JSON report written to {args.json}")
    if args.html:
        args.html.write_text(render_html(report), encoding="utf-8")
        print(f"HTML report written to {args.html}")

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(f.severity.rank >= threshold for f in report.findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
