"""Detection rules. Each rule takes time-sorted events and yields findings."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable, Iterator
from urllib.parse import unquote_plus

from .models import Event, Finding, Severity

FAILURE_KINDS = {"ssh_failed", "ssh_invalid_user"}
MAX_EVIDENCE = 5


@dataclass(frozen=True)
class Thresholds:
    brute_force_attempts: int = 5
    brute_force_window: timedelta = timedelta(minutes=5)
    user_enum_distinct: int = 4
    compromise_lookback: timedelta = timedelta(hours=1)
    scan_404s: int = 15
    scan_window: timedelta = timedelta(minutes=2)


SENSITIVE_PATH = re.compile(
    r"(/\.env\b|/\.git/|/\.svn/|/\.aws/|/\.ssh/|/wp-login\.php|/wp-admin|/xmlrpc\.php"
    r"|/phpmyadmin|/server-status|/actuator|/cgi-bin/|/etc/passwd|/config\.php"
    r"|\.(?:sql|bak|old)$)",
    re.IGNORECASE,
)

# (label, pattern, also scan the User-Agent header?)
INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    ("SQL injection", re.compile(
        r"(union(?:\s|/\*.*?\*/)+(?:all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\)|information_schema)",
        re.IGNORECASE), False),
    ("Cross-site scripting", re.compile(
        r"(<script|javascript:|onerror\s*=|<svg[^>]*onload)", re.IGNORECASE), False),
    ("Log4Shell (CVE-2021-44228)", re.compile(r"\$\{jndi:", re.IGNORECASE), True),
    ("Path traversal", re.compile(r"\.\./"), False),
    ("Command injection", re.compile(
        r"(?:;|\||`|\$\()\s*(?:wget|curl|nc|bash|sh|id|whoami|cat)\b", re.IGNORECASE), False),
]

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|nuclei|wpscan|feroxbuster|ffuf)",
    re.IGNORECASE,
)


# --- helpers --------------------------------------------------------------


def _by_ip(events: Iterable[Event]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        groups[event.ip].append(event)
    return groups


def max_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of timestamps falling inside any sliding ``window``.

    ``times`` must be sorted. Runs in O(n) with a two-pointer sweep.
    """
    best = start = 0
    for end, current in enumerate(times):
        while current - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def _decode(path: str) -> str:
    # Decode twice to catch double-encoded payloads such as %252e%252e%252f.
    return unquote_plus(unquote_plus(path))


def _preview(items: list[str], limit: int) -> str:
    extra = len(items) - limit
    return ", ".join(items[:limit]) + (f" (+{extra} more)" if extra > 0 else "")


def _fmt_window(window: timedelta) -> str:
    minutes = int(window.total_seconds() // 60)
    return f"{minutes} min" if minutes else f"{int(window.total_seconds())} s"


def _finding(rule: str, severity: Severity, ip: str, title: str, description: str,
             events: list[Event], evidence: list[Event] | None = None) -> Finding:
    shown = evidence if evidence is not None else events[:MAX_EVIDENCE]
    return Finding(
        rule=rule,
        severity=severity,
        ip=ip,
        title=title,
        description=description,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        count=len(events),
        evidence=[f"{e.location}: {e.raw}" for e in shown],
        events=events,
    )


# --- SSH rules ------------------------------------------------------------


def ssh_brute_force(events: list[Event], t: Thresholds) -> Iterator[Finding]:
    for ip, failures in _by_ip(e for e in events if e.kind in FAILURE_KINDS).items():
        peak = max_in_window([e.timestamp for e in failures], t.brute_force_window)
        if peak < t.brute_force_attempts:
            continue
        severity = Severity.HIGH if peak >= 4 * t.brute_force_attempts else Severity.MEDIUM
        targets = ", ".join(user or "<empty>" for user, _ in Counter(e.user for e in failures).most_common(3))
        yield _finding(
            "SSH_BRUTE_FORCE", severity, ip, "SSH brute-force",
            f"{len(failures)} failed logins, peak of {peak} within "
            f"{_fmt_window(t.brute_force_window)}. Most targeted: {targets}.",
            failures,
        )


def ssh_user_enumeration(events: list[Event], t: Thresholds) -> Iterator[Finding]:
    for ip, attempts in _by_ip(e for e in events if e.kind == "ssh_invalid_user").items():
        users = sorted({e.user or "<empty>" for e in attempts})
        if len(users) < t.user_enum_distinct:
            continue
        yield _finding(
            "SSH_USER_ENUM", Severity.MEDIUM, ip, "SSH username enumeration",
            f"{len(users)} non-existent usernames tried: {_preview(users, 8)}.",
            attempts,
        )


def ssh_success_after_failures(events: list[Event], t: Thresholds) -> Iterator[Finding]:
    ssh = [e for e in events if e.kind in FAILURE_KINDS or e.kind == "ssh_accepted"]
    for ip, ip_events in _by_ip(ssh).items():
        suspicious: list[Event] = []
        users: set[str] = set()
        for i, event in enumerate(ip_events):
            if event.kind != "ssh_accepted":
                continue
            window_start = event.timestamp - t.compromise_lookback
            prior = [e for e in ip_events[:i] if e.kind in FAILURE_KINDS and e.timestamp >= window_start]
            if len(prior) >= t.brute_force_attempts:
                suspicious.extend(e for e in prior + [event] if e not in suspicious)
                users.add(event.user or "?")
        if suspicious:
            # Show the failures closest to the successful login: that's the story.
            yield _finding(
                "SSH_COMPROMISE", Severity.CRITICAL, ip, "Successful login after brute-force",
                f"Login accepted for {', '.join(sorted(users))} after repeated failures "
                f"from the same address. Treat the account as compromised.",
                suspicious,
                evidence=suspicious[-MAX_EVIDENCE:],
            )


# --- Web rules ------------------------------------------------------------


def web_sensitive_paths(events: list[Event], t: Thresholds) -> Iterator[Finding]:
    # Only the path part: payloads in the query string are the injection rule's job.
    web = (e for e in events
           if e.kind == "http_request" and SENSITIVE_PATH.search(_decode(e.path or "").split("?", 1)[0]))
    for ip, hits in _by_ip(web).items():
        exposed = [e for e in hits if e.status is not None and 200 <= e.status < 300]
        preview = _preview(sorted({e.path or "" for e in hits}), 6)
        if exposed:
            leaked = _preview(sorted({e.path or "" for e in exposed}), 4)
            yield _finding(
                "WEB_SENSITIVE_EXPOSED", Severity.HIGH, ip, "Sensitive file served",
                f"The server answered 2xx for: {leaked}. Probed: {preview}.",
                exposed + [e for e in hits if e not in exposed],
            )
        else:
            yield _finding(
                "WEB_SENSITIVE_PROBE", Severity.LOW, ip, "Probing for sensitive files",
                f"{len(hits)} requests for well-known sensitive paths, all refused: {preview}.",
                hits,
            )


def web_injection(events: list[Event], t: Thresholds) -> Iterator[Finding]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    labels: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.kind != "http_request":
            continue
        path = _decode(event.path or "")
        for label, pattern, scan_ua in INJECTION_PATTERNS:
            if pattern.search(path) or (scan_ua and pattern.search(event.user_agent or "")):
                if not by_ip[event.ip] or by_ip[event.ip][-1] is not event:
                    by_ip[event.ip].append(event)
                labels[event.ip].add(label)
    for ip, hits in by_ip.items():
        yield _finding(
            "WEB_INJECTION", Severity.HIGH, ip, "Injection attempts",
            f"{len(hits)} requests carrying attack payloads: {', '.join(sorted(labels[ip]))}.",
            hits,
        )


def web_scanner(events: list[Event], t: Thresholds) -> Iterator[Finding]:
    for ip, requests in _by_ip(e for e in events if e.kind == "http_request").items():
        not_found = [e for e in requests if e.status == 404]
        peak = max_in_window([e.timestamp for e in not_found], t.scan_window) if not_found else 0
        tools = sorted({m.group(1).lower() for e in requests if (m := SCANNER_UA.search(e.user_agent or ""))})
        if peak < t.scan_404s and not tools:
            continue
        reasons = []
        if peak >= t.scan_404s:
            reasons.append(f"{peak} not-found responses within {_fmt_window(t.scan_window)}")
        if tools:
            reasons.append(f"scanner User-Agent ({', '.join(tools)})")
        yield _finding(
            "WEB_SCANNER", Severity.MEDIUM, ip, "Automated scanner",
            f"{len(requests)} requests; " + " and ".join(reasons) + ".",
            not_found or requests,
        )


Rule = Callable[[list[Event], Thresholds], Iterable[Finding]]

RULES: list[Rule] = [
    ssh_brute_force,
    ssh_user_enumeration,
    ssh_success_after_failures,
    web_sensitive_paths,
    web_injection,
    web_scanner,
]


def detect(events: Iterable[Event], thresholds: Thresholds | None = None) -> list[Finding]:
    """Run every rule and return findings, most severe first."""
    thresholds = thresholds or Thresholds()
    ordered = sorted(events, key=lambda e: e.timestamp)
    findings = [finding for rule in RULES for finding in rule(ordered, thresholds)]
    return sorted(findings, key=lambda f: (-f.severity.rank, -f.count, f.ip))
