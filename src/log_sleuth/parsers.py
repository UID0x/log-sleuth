"""Turn raw log lines into normalized :class:`Event` objects.

Supported formats:

* ``auth``  - OpenSSH messages from ``/var/log/auth.log`` (classic syslog
  timestamps or ISO 8601 timestamps as written by journald/rsyslog).
* ``nginx`` - the "combined" access log format, shared by nginx and Apache.
"""
from __future__ import annotations

import gzip
import re
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from .models import Event

FORMATS = ("auth", "nginx")

MONTHS = {
    name: number
    for number, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

_IP = r"[0-9a-fA-F:.]+"

# --- auth.log -------------------------------------------------------------

_SYSLOG_ANY = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ [^\s:]+:")
_ISO_ANY = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S* \S+ [^\s:]+:")

_SYSLOG_SSHD = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"\S+ sshd\[\d+\]: (?P<msg>.*)$"
)
_ISO_SSHD = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})? "
    r"\S+ sshd\[\d+\]: (?P<msg>.*)$"
)
_FAILED = re.compile(
    rf"^Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S*) "
    rf"from (?P<ip>{_IP}) port \d+"
)
_ACCEPTED = re.compile(rf"^Accepted \S+ for (?P<user>\S+) from (?P<ip>{_IP}) port \d+")


def parse_auth_line(line: str, year: int, line_no: int = 0, file: str = "") -> Event | None:
    """Parse one auth.log line. Returns ``None`` for lines we don't care about."""
    if m := _SYSLOG_SSHD.match(line):
        month = MONTHS.get(m["month"])
        if month is None:
            return None
        hour, minute, second = map(int, m["time"].split(":"))
        try:
            timestamp = datetime(year, month, int(m["day"]), hour, minute, second)
        except ValueError:
            return None
    elif m := _ISO_SSHD.match(line):
        timestamp = datetime.fromisoformat(m["iso"])
    else:
        return None

    msg = m["msg"]
    common = {"timestamp": timestamp, "source": "auth", "file": file, "line_no": line_no, "raw": line}
    if f := _FAILED.match(msg):
        kind = "ssh_invalid_user" if f["invalid"] else "ssh_failed"
        return Event(kind=kind, ip=f["ip"], user=f["user"], **common)
    if a := _ACCEPTED.match(msg):
        return Event(kind="ssh_accepted", ip=a["ip"], user=a["user"], **common)
    return None


def iter_auth_events(lines: Iterable[str], year: int, file: str = "") -> Iterator[Event]:
    """Parse auth.log lines, handling the December -> January rollover.

    Classic syslog timestamps have no year, so we start from ``year`` and bump
    it whenever time jumps backwards by more than ~6 months.
    """
    current_year = year
    last: datetime | None = None
    for line_no, line in enumerate(lines, start=1):
        event = parse_auth_line(line, current_year, line_no, file)
        if event is None:
            continue
        if last is not None and (last - event.timestamp).days > 180:
            current_year += 1
            event = replace(event, timestamp=event.timestamp.replace(year=current_year))
        last = event.timestamp
        yield event


# --- nginx / apache combined ---------------------------------------------

_COMBINED = re.compile(
    rf"^(?P<ip>{_IP}) \S+ \S+ "
    r"\[(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2}) [+-]\d{4}\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) \S+'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_nginx_line(line: str, line_no: int = 0, file: str = "") -> Event | None:
    m = _COMBINED.match(line)
    if not m:
        return None
    month = MONTHS.get(m["month"])
    if month is None:
        return None
    hour, minute, second = map(int, m["time"].split(":"))
    try:
        timestamp = datetime(int(m["year"]), month, int(m["day"]), hour, minute, second)
    except ValueError:
        return None
    return Event(
        timestamp=timestamp,
        source="web",
        kind="http_request",
        ip=m["ip"],
        method=m["method"],
        path=m["path"],
        status=int(m["status"]),
        user_agent=m["ua"],
        file=file,
        line_no=line_no,
        raw=line,
    )


def iter_nginx_events(lines: Iterable[str], file: str = "") -> Iterator[Event]:
    for line_no, line in enumerate(lines, start=1):
        if event := parse_nginx_line(line, line_no, file):
            yield event


# --- helpers --------------------------------------------------------------


def detect_format(lines: Iterable[str], sample_size: int = 50) -> str | None:
    """Guess the format from the first non-empty lines (majority vote)."""
    scores = dict.fromkeys(FORMATS, 0)
    seen = 0
    for line in lines:
        if not line.strip():
            continue
        if _COMBINED.match(line):
            scores["nginx"] += 1
        elif _SYSLOG_ANY.match(line) or _ISO_ANY.match(line):
            scores["auth"] += 1
        seen += 1
        if seen >= sample_size:
            break
    best = max(scores, key=scores.get)
    return best if scores[best] else None


def read_lines(path: Path) -> list[str]:
    """Read a (possibly gzip-compressed) log file. Invalid bytes are replaced."""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\r\n") for line in handle]


def parse_lines(lines: list[str], fmt: str, year: int, file: str = "") -> list[Event]:
    if fmt == "auth":
        return list(iter_auth_events(lines, year, file))
    if fmt == "nginx":
        return list(iter_nginx_events(lines, file))
    raise ValueError(f"unknown format: {fmt!r}")
