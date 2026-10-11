"""Render a :class:`Report` as terminal text, JSON or a self-contained HTML page."""
from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from html import escape

from . import __version__
from .models import Finding, Report, Severity

# --- terminal -------------------------------------------------------------

BANNER = r"""
  _                   ____  _            _   _
 | |    ___   __ _   / ___|| | ___ _   _| |_| |__
 | |   / _ \ / _` |  \___ \| |/ _ \ | | | __| '_ \
 | |__| (_) | (_| |   ___) | |  __/ |_| | |_| | | |
 |_____\___/ \__, |  |____/|_|\___|\__,_|\__|_| |_|
             |___/
"""

_ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;91m",
    Severity.MEDIUM: "\033[1;93m",
    Severity.LOW: "\033[96m",
}
_DIM, _BOLD, _RESET = "\033[2m", "\033[1m", "\033[0m"


def supports_color(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR") or not stream.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return True


def _enable_windows_vt() -> bool:
    """Turn on ANSI escape processing in the legacy Windows console."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except (AttributeError, OSError):
        return False


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(width - 3, 0)] + "..."


def render_terminal(report: Report, color: bool = False, verbose: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    width = shutil.get_terminal_size((120, 24)).columns
    out: list[str] = [paint(BANNER.rstrip("\n"), _BOLD), paint(f"  v{__version__}  -  log triage for blue teams\n", _DIM)]

    out.append(paint("Files", _BOLD))
    for f in report.files:
        fmt = f.format or "unknown"
        out.append(f"  {_truncate(f.path, 40):<40}  {fmt:<7} {f.lines:>8} lines {f.events:>8} events")
    out.append("")

    counts = report.count_by_severity()
    summary = "  ".join(paint(f"{counts[s]} {s.value}", _ANSI[s]) for s in reversed(Severity))
    out.append(f"{paint('Findings', _BOLD)}  {summary}")
    if not report.findings:
        out.append(paint("  Nothing suspicious found. Either you're lucky or the logs are quiet.", _DIM))
        return "\n".join(out) + "\n"
    out.append("")

    out.append(paint(f"  {'SEVERITY':<9} {'RULE':<22} {'IP':<16} {'COUNT':>6}  FIRST SEEN", _DIM))
    for finding in report.findings:
        sev = paint(f"{finding.severity.value.upper():<9}", _ANSI[finding.severity])
        out.append(
            f"  {sev} {finding.rule:<22} {finding.ip:<16} {finding.count:>6}  "
            f"{finding.first_seen:%Y-%m-%d %H:%M:%S}"
        )
        for line in textwrap.wrap(finding.description, width=max(width - 13, 40)):
            out.append(f"            {line}")
        if verbose:
            for line in finding.evidence:
                out.append(paint(f"      > {_truncate(line, width - 9)}", _DIM))

    out.append("")
    out.append(paint("Top offenders", _BOLD))
    for ip, score in top_offenders(report.findings):
        bar = "#" * min(score, 40)
        out.append(f"  {ip:<16} {paint(bar, _ANSI[Severity.HIGH])} {score}")
    return "\n".join(out) + "\n"


def top_offenders(findings: list[Finding], limit: int = 5) -> list[tuple[str, int]]:
    """Rank IPs by a weighted score: critical=8, high=4, medium=2, low=1."""
    scores: Counter[str] = Counter()
    for f in findings:
        scores[f.ip] += 2 ** f.severity.rank
    return scores.most_common(limit)


# --- JSON -----------------------------------------------------------------


def render_json(report: Report) -> str:
    def default(value):
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Severity):
            return value.value
        raise TypeError(f"cannot serialise {type(value).__name__}")

    payload = {"tool": "log-sleuth", "version": __version__, **asdict(report)}
    return json.dumps(payload, indent=2, default=default)


# --- HTML -----------------------------------------------------------------
# Every value coming from a log file is attacker-controlled (paths, user
# agents, usernames...). It all goes through html.escape() so that a
# "<script>" payload in a log can't execute inside the report itself.

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5f6b7a;--border:#dde2e8;
--critical:#c62828;--high:#e4572e;--medium:#d99a00;--low:#2c7be5;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--text:#e6e9ee;--muted:#93a0b0;--border:#2a323d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px}
h1{margin:0;font-size:26px}h2{font-size:17px;margin:32px 0 12px}.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:26px}.card.critical b{color:var(--critical)}.card.high b{color:var(--high)}
.card.medium b{color:var(--medium)}.card.low b{color:var(--low)}
.finding{background:var(--card);border:1px solid var(--border);border-left:5px solid var(--sev);border-radius:10px;padding:14px 16px;margin-bottom:10px}
.finding header{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:baseline}
.badge{background:var(--sev);color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:700;text-transform:uppercase}
.rule,.ip,code,pre{font-family:var(--mono);font-size:13px}.ip{font-weight:600}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted)}
pre{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;overflow-x:auto;white-space:pre}
.bar{display:flex;align-items:center;gap:10px;margin:6px 0}.bar span{font-family:var(--mono);width:140px;flex:none}
.bar i{display:block;height:12px;border-radius:3px;background:var(--high)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
td,th{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border)}th{color:var(--muted);font-weight:600}
"""


def _finding_html(f: Finding) -> str:
    evidence = escape("\n".join(f.evidence))
    return (
        f'<article class="finding" style="--sev:var(--{f.severity.value})"><header>'
        f'<span class="badge">{f.severity.value}</span><strong>{escape(f.title)}</strong>'
        f'<span class="ip">{escape(f.ip)}</span><span class="rule muted">{escape(f.rule)}</span>'
        f'<span class="muted">{f.count} events &middot; {f.first_seen:%Y-%m-%d %H:%M:%S} '
        f'&rarr; {f.last_seen:%H:%M:%S}</span></header>'
        f"<p>{escape(f.description)}</p>"
        f"<details><summary>Evidence</summary><pre>{evidence}</pre></details></article>"
    )


def render_html(report: Report) -> str:
    counts = report.count_by_severity()
    cards = "".join(
        f'<div class="card {s.value}"><b>{counts[s]}</b>{s.value}</div>' for s in reversed(Severity)
    )
    files = "".join(
        f"<tr><td><code>{escape(f.path)}</code></td><td>{escape(f.format or 'unknown')}</td>"
        f"<td>{f.lines:,}</td><td>{f.events:,}</td></tr>"
        for f in report.files
    )
    offenders = top_offenders(report.findings, limit=8)
    top = max((score for _, score in offenders), default=1)
    bars = "".join(
        f'<div class="bar"><span>{escape(ip)}</span><i style="width:{score / top * 60:.1f}%"></i>{score}</div>'
        for ip, score in offenders
    )
    findings = "".join(_finding_html(f) for f in report.findings) or '<p class="muted">No findings.</p>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Sleuth report</title><style>{_CSS}</style></head>
<body><main>
<h1>Log Sleuth report</h1>
<p class="muted">Generated {report.generated_at:%Y-%m-%d %H:%M} &middot; {report.total_lines:,} lines &middot;
{report.total_events:,} security events &middot; log-sleuth v{__version__}</p>
<div class="cards">{cards}</div>
<h2>Top offenders</h2>{bars or '<p class="muted">None.</p>'}
<h2>Findings</h2>{findings}
<h2>Files analysed</h2>
<table><thead><tr><th>File</th><th>Format</th><th>Lines</th><th>Events</th></tr></thead><tbody>{files}</tbody></table>
</main></body></html>
"""
