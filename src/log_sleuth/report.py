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

from . import __version__, charts
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


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Severity):
        return value.value
    raise TypeError(f"cannot serialise {type(value).__name__}")


def render_json(report: Report) -> str:
    findings = []
    for f in report.findings:
        data = asdict(f)
        data.pop("events")  # raw events stay out of the JSON; evidence lines are enough
        findings.append(data)
    payload = {
        "tool": "log-sleuth",
        "version": __version__,
        "generated_at": report.generated_at,
        "files": [asdict(f) for f in report.files],
        "findings": findings,
    }
    return json.dumps(payload, indent=2, default=_jsonable)


# --- HTML -----------------------------------------------------------------
# Every value coming from a log file is attacker-controlled (paths, user
# agents, usernames...). It all goes through html.escape() so that a
# "<script>" payload in a log can't execute inside the report itself.

_CSS = """
.report{color-scheme:light;
--page:#f9f9f7;--card:#fcfcfb;--text:#0b0b0b;--muted:#52514e;--faint:#898781;--border:rgba(11,11,11,.10);
--grid:#e1e0d9;--axis:#c3c2b7;--hover:rgba(11,11,11,.05);--tip-bg:#0b0b0b;--tip-text:#fff;
--sev-critical:#d03b3b;--sev-high:#ec835a;--sev-medium:#fab219;--sev-low:#2a78d6;--sev-other:#d6d5ce;
--ink-critical:#fff;--ink-high:#0b0b0b;--ink-medium:#0b0b0b;--ink-low:#fff;
--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .report{color-scheme:dark;
--page:#0d0d0d;--card:#1a1a19;--text:#fff;--muted:#c3c2b7;--faint:#898781;--border:rgba(255,255,255,.10);
--grid:#2c2c2a;--axis:#383835;--hover:rgba(255,255,255,.06);--tip-bg:#fff;--tip-text:#0b0b0b;
--sev-low:#3987e5;--sev-other:#3a3a37}}
:root[data-theme="dark"] .report{color-scheme:dark;
--page:#0d0d0d;--card:#1a1a19;--text:#fff;--muted:#c3c2b7;--faint:#898781;--border:rgba(255,255,255,.10);
--grid:#2c2c2a;--axis:#383835;--hover:rgba(255,255,255,.06);--tip-bg:#fff;--tip-text:#0b0b0b;
--sev-low:#3987e5;--sev-other:#3a3a37}
*{box-sizing:border-box}html,body{margin:0}
body.report{background:var(--page);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
h1{margin:0;font-size:26px}h2{font-size:17px;margin:36px 0 12px}.muted{color:var(--muted)}
code,pre,.ip,.rule{font-family:var(--mono);font-size:13px}.ip{font-weight:600}
.num,td{font-variant-numeric:tabular-nums}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px;color:var(--muted)}
.card b{display:flex;align-items:center;gap:8px;font-size:28px;color:var(--text)}
.card b::before{content:"";width:10px;height:10px;border-radius:50%;background:var(--sev)}
.chart,.incident{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;margin:0 0 12px}
figcaption{color:var(--muted);font-size:13px;margin-bottom:10px}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px;color:var(--muted);margin-bottom:12px}
.legend span{display:inline-flex;align-items:center;gap:6px}.legend i{width:10px;height:10px;border-radius:2px;display:inline-block}
.tl{display:flex;height:220px}
.tl-y{position:relative;width:44px;flex:none;font-size:11px;color:var(--faint)}
.tl-y span{position:absolute;right:8px;transform:translateY(50%)}
.tl-plot{position:relative;flex:1;display:flex;align-items:stretch;border-bottom:1px solid var(--axis)}
.grid i{position:absolute;left:0;right:0;border-top:1px solid var(--grid)}
.col{position:relative;flex:1;display:flex;flex-direction:column-reverse;padding:0 1px;cursor:default}
.col:hover{background:var(--hover)}
.col b{display:block;min-height:1px}.col b+b{border-bottom:2px solid var(--card)}
.col b:last-child{border-radius:3px 3px 0 0}
.tl-x{position:relative;height:20px;margin-left:44px;font-size:11px;color:var(--faint)}
.tl-x span{position:absolute;top:4px;white-space:nowrap}
details{margin-top:10px}summary{cursor:pointer;color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
td,th{text-align:left;padding:6px 10px;border-bottom:1px solid var(--grid)}th{color:var(--muted);font-weight:600}
.strip{position:relative;height:44px;margin:4px 8px;border-bottom:1px solid var(--axis)}
.strip i{position:absolute;bottom:0;transform:translateX(-50%)}
.strip .try{width:3px;height:22px;border-radius:2px 2px 0 0;background:var(--sev-high)}
.strip .hit{bottom:-7px;width:16px;height:16px;border-radius:50%;background:var(--sev-critical);box-shadow:0 0 0 2px var(--card)}
.strip i:hover{filter:brightness(1.2)}
.strip-x{display:flex;justify-content:space-between;font-size:11px;color:var(--faint);margin:10px 0 8px}
.try-key,.hit-key{display:inline-block;width:10px;height:10px}.try-key{background:var(--sev-high);border-radius:2px}
.hit-key{background:var(--sev-critical);border-radius:50%}
.off{display:grid;grid-template-columns:130px 1fr 32px;align-items:center;gap:10px;padding:5px 0}
.off:hover{background:var(--hover)}
.off-bar{display:flex;gap:2px;height:14px}.off-bar b{display:block}.off-bar b:last-child{border-radius:0 4px 4px 0}
.off .num{text-align:right;color:var(--muted)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.filters label{display:inline-flex;align-items:center;gap:6px;background:var(--card);border:1px solid var(--border);
border-radius:999px;padding:4px 12px;font-size:13px;cursor:pointer}
.finding{background:var(--card);border:1px solid var(--border);border-left:5px solid var(--sev);border-radius:10px;padding:14px 16px;margin-bottom:10px}
.finding[hidden]{display:none}
.finding header{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:baseline}
.badge{background:var(--sev);color:var(--ink);border-radius:4px;padding:1px 8px;font-size:12px;font-weight:700;text-transform:uppercase}
pre{background:var(--page);border:1px solid var(--border);border-radius:6px;padding:10px;overflow-x:auto;white-space:pre}
#tip{position:fixed;z-index:10;pointer-events:none;background:var(--tip-bg);color:var(--tip-text);font-size:12px;
line-height:1.45;padding:6px 9px;border-radius:6px;white-space:pre-line;max-width:320px}
@media (max-width:600px){.off{grid-template-columns:110px 1fr 28px}.tl{height:180px}}
"""

# Tooltips use textContent, so even an unescaped payload would render as text.
_JS = """
const tip=document.getElementById('tip');
document.addEventListener('pointerover',e=>{const t=e.target.closest('[data-tip]');
  if(!t){tip.hidden=true;return}tip.textContent=t.dataset.tip;tip.hidden=false});
document.addEventListener('pointermove',e=>{if(tip.hidden)return;
  tip.style.left=Math.min(e.clientX+14,innerWidth-tip.offsetWidth-8)+'px';
  tip.style.top=Math.min(e.clientY+14,innerHeight-tip.offsetHeight-8)+'px'});
addEventListener('scroll',()=>{tip.hidden=true},{passive:true});
document.querySelectorAll('.filters input').forEach(box=>box.addEventListener('change',()=>{
  document.querySelectorAll('.finding[data-sev="'+box.value+'"]').forEach(f=>f.hidden=!box.checked)}));
"""


def _sev_style(severity: Severity) -> str:
    return f"--sev:var(--sev-{severity.value});--ink:var(--ink-{severity.value})"


def _finding_html(f: Finding) -> str:
    evidence = escape("\n".join(f.evidence))
    return (
        f'<article class="finding" data-sev="{f.severity.value}" style="{_sev_style(f.severity)}"><header>'
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
        f'<div class="card" style="{_sev_style(s)}"><b>{counts[s]}</b>{s.value}</div>' for s in reversed(Severity)
    )
    files = "".join(
        f"<tr><td><code>{escape(f.path)}</code></td><td>{escape(f.format or 'unknown')}</td>"
        f"<td>{f.lines:,}</td><td>{f.events:,}</td></tr>"
        for f in report.files
    )
    critical = [f for f in report.findings if f.severity is Severity.CRITICAL]
    incidents = "".join(charts.incident(f) for f in critical)
    filters = "".join(
        f'<label><input type="checkbox" value="{s.value}" checked> {s.value} ({counts[s]})</label>'
        for s in reversed(Severity) if counts[s]
    )
    findings = "".join(_finding_html(f) for f in report.findings) or '<p class="muted">No findings.</p>'
    activity = charts.timeline(report.events, report.findings)
    top = charts.offenders(report.findings)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Sleuth report</title><style>{_CSS}</style></head>
<body class="report"><main>
<h1>Log Sleuth report</h1>
<p class="muted">Generated {report.generated_at:%Y-%m-%d %H:%M} &middot; {report.total_lines:,} lines &middot;
{report.total_events:,} security events &middot; log-sleuth v{__version__}</p>
<div class="cards">{cards}</div>
{f'<h2>Incident reconstruction</h2>{incidents}' if incidents else ''}
{f'<h2>Activity over time</h2>{activity}' if activity else ''}
{f'<h2>Top offenders</h2>{top}' if top else ''}
<h2>Findings</h2>{f'<div class="filters">{filters}</div>' if filters else ''}{findings}
<h2>Files analysed</h2>
<div class="chart"><table><thead><tr><th>File</th><th>Format</th><th>Lines</th><th>Events</th></tr></thead>
<tbody>{files}</tbody></table></div>
</main><div id="tip" hidden></div><script>{_JS}</script></body></html>
"""


