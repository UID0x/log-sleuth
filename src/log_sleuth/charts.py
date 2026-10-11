"""Dependency-free charts for the HTML report, built from plain HTML and CSS.

HTML/CSS (rather than SVG) keeps text at a readable size on any screen width.
Every string that comes from a log goes through ``escape()``; tooltips are read
back with ``textContent`` on the client, never ``innerHTML``.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from html import escape
from math import ceil, floor, log10

from .models import Event, Finding, Severity

OTHER = "other"  # events from IPs without any finding
STACK = [OTHER, *(s.value for s in Severity)]  # bottom to top
LABELS = {OTHER: "Other traffic", **{s.value: s.value.capitalize() for s in Severity}}

BUCKETS = [timedelta(minutes=m) for m in (1, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440)]


# --- small helpers ----------------------------------------------------------


def pick_bucket(span: timedelta, target: int = 48) -> timedelta:
    """Smallest standard bucket that keeps the timeline under ``target`` bars."""
    for bucket in BUCKETS:
        if span / bucket < target:
            return bucket
    return BUCKETS[-1]


def floor_time(ts: datetime, bucket: timedelta) -> datetime:
    midnight = ts.replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight + ((ts - midnight) // bucket) * bucket


def nice_ticks(vmax: int, count: int = 4) -> list[int]:
    """Round axis ticks (steps of 1, 2 or 5 x 10^n) covering ``0..vmax``."""
    if vmax <= 0:
        return [0, 1]
    raw = vmax / count
    magnitude = 10 ** floor(log10(raw))
    step = max(1, int(next(m * magnitude for m in (1, 2, 5, 10) if m * magnitude >= raw)))
    return list(range(0, ceil(vmax / step) * step + 1, step))


def fmt_duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min {seconds % 60:02d} s"
    return f"{seconds // 3600} h {seconds % 3600 // 60:02d} min"


def worst_severity_by_ip(findings: list[Finding]) -> dict[str, Severity]:
    worst: dict[str, Severity] = {}
    for f in findings:
        if f.ip not in worst or f.severity.rank > worst[f.ip].rank:
            worst[f.ip] = f.severity
    return worst


def legend(keys: list[str]) -> str:
    items = "".join(f'<span><i style="background:var(--sev-{k})"></i>{LABELS[k]}</span>' for k in keys)
    return f'<div class="legend">{items}</div>'


# --- 1. activity timeline -----------------------------------------------------


def timeline(events: list[Event], findings: list[Finding]) -> str:
    """Stacked bars of events over time, coloured by the worst finding of their source IP."""
    if not events:
        return ""
    worst = worst_severity_by_ip(findings)
    first = min(e.timestamp for e in events)
    last = max(e.timestamp for e in events)
    bucket = pick_bucket(last - first)
    start = floor_time(first, bucket)
    columns = [Counter() for _ in range(int((last - start) // bucket) + 1)]
    for e in events:
        key = worst[e.ip].value if e.ip in worst else OTHER
        columns[int((e.timestamp - start) // bucket)][key] += 1

    ticks = nice_ticks(max(sum(c.values()) for c in columns))
    top = ticks[-1]
    multi_day = last.date() != first.date()
    time_fmt = "%d %b %H:%M" if multi_day else "%H:%M"

    bars, rows = [], []
    for i, counts in enumerate(columns):
        t0 = start + i * bucket
        total = sum(counts.values())
        tip = [f"{t0:{time_fmt}} - {t0 + bucket:%H:%M}", f"{total} events"]
        tip += [f"{LABELS[k]}: {counts[k]}" for k in reversed(STACK) if counts[k]]
        segments = "".join(
            f'<b style="height:{counts[k] / top * 100:.2f}%;background:var(--sev-{k})"></b>'
            for k in STACK if counts[k]
        )
        bars.append(f'<div class="col" data-tip="{escape(chr(10).join(tip))}">{segments}</div>')
        if total:
            cells = "".join(f"<td>{counts[k]}</td>" for k in reversed(STACK))
            rows.append(f"<tr><td>{t0:{time_fmt}}</td><td>{total}</td>{cells}</tr>")

    grid = "".join(f'<i style="bottom:{v / top * 100:.2f}%"></i>' for v in ticks)
    y_axis = "".join(f'<span style="bottom:{v / top * 100:.2f}%">{v:,}</span>' for v in ticks)
    step = max(1, ceil(len(columns) / 6))
    x_axis = "".join(
        f'<span style="left:{i / len(columns) * 100:.2f}%">{start + i * bucket:{time_fmt}}</span>'
        for i in range(0, len(columns), step)
    )
    head = "".join(f"<th>{LABELS[k]}</th>" for k in reversed(STACK))
    minutes = int(bucket.total_seconds() // 60)
    bucket_label = f"{minutes} min" if minutes < 60 else f"{minutes // 60} h"
    return f"""<figure class="chart">
<figcaption>Events per {bucket_label}, coloured by the most severe finding of their source IP</figcaption>
{legend(list(reversed(STACK)))}
<div class="tl"><div class="tl-y">{y_axis}</div><div class="tl-plot"><div class="grid">{grid}</div>{''.join(bars)}</div></div>
<div class="tl-x">{x_axis}</div>
<details><summary>Data table</summary><table><thead><tr><th>Time</th><th>Total</th>{head}</tr></thead>
<tbody>{''.join(rows)}</tbody></table></details>
</figure>"""


# --- 2. incident reconstruction -------------------------------------------------


def incident(finding: Finding) -> str:
    """A time strip showing how a critical incident unfolded, event by event."""
    events = sorted(finding.events, key=lambda e: e.timestamp)
    if len(events) < 2:
        return ""
    first, last = events[0].timestamp, events[-1].timestamp
    span = (last - first) or timedelta(seconds=1)
    failures = [e for e in events if e.kind != "ssh_accepted"]
    granted = [e for e in events if e.kind == "ssh_accepted"]

    marks = []
    for e in events:
        left = (e.timestamp - first) / span * 100
        ok = e.kind == "ssh_accepted"
        label = f"Login ACCEPTED for {e.user}" if ok else f"Failed login for {e.user or '<empty>'}"
        tip = f"{e.timestamp:%H:%M:%S}\n{label}\n{e.location}"
        marks.append(f'<i class="{"hit" if ok else "try"}" style="left:{left:.2f}%" data-tip="{escape(tip)}"></i>')

    users = ", ".join(sorted({e.user or "?" for e in granted}))
    story = (f"{len(failures)} failed logins in {fmt_duration(span)}, then "
             f"<strong>access granted</strong> as <code>{escape(users)}</code>") if granted else \
            f"{len(events)} events in {fmt_duration(span)}"
    return f"""<figure class="incident">
<figcaption><span class="ip">{escape(finding.ip)}</span> &middot; {story}</figcaption>
<div class="strip">{''.join(marks)}</div>
<div class="strip-x"><span>{first:%H:%M:%S}</span><span>{last:%H:%M:%S}</span></div>
<div class="legend"><span><i class="try-key"></i>Failed attempt</span><span><i class="hit-key"></i>Successful login</span></div>
</figure>"""


# --- 3. top offenders -----------------------------------------------------------


def offenders(findings: list[Finding], limit: int = 8) -> str:
    """Horizontal bars: threat score per IP, segmented by finding severity."""
    per_ip: dict[str, list[Finding]] = {}
    for f in findings:
        per_ip.setdefault(f.ip, []).append(f)
    scored = sorted(per_ip.items(), key=lambda kv: (-sum(2 ** f.severity.rank for f in kv[1]), kv[0]))[:limit]
    if not scored:
        return ""
    top = sum(2 ** f.severity.rank for f in scored[0][1])
    rows = []
    for ip, ip_findings in scored:
        score = sum(2 ** f.severity.rank for f in ip_findings)
        segments = "".join(
            f'<b style="width:{2 ** f.severity.rank / top * 100:.2f}%;background:var(--sev-{f.severity.value})"></b>'
            for f in sorted(ip_findings, key=lambda f: -f.severity.rank)
        )
        tip = "\n".join([ip, f"Score {score}"] + [f"{f.severity.value.upper()}  {f.rule}" for f in ip_findings])
        rows.append(f'<div class="off" data-tip="{escape(tip)}"><span class="ip">{escape(ip)}</span>'
                    f'<div class="off-bar">{segments}</div><span class="num">{score}</span></div>')
    present = [s.value for s in reversed(Severity) if any(f.severity is s for _, fs in scored for f in fs)]
    return f"""<figure class="chart">
<figcaption>Threat score per IP (critical = 8, high = 4, medium = 2, low = 1)</figcaption>
{legend(present)}{''.join(rows)}
</figure>"""
