# log-sleuth

[![CI](https://github.com/UID0x/log-sleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/UID0x/log-sleuth/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**Find the attacks hiding in your SSH and web server logs, in one command.**

`log-sleuth` reads `auth.log` and nginx/Apache access logs, correlates events per
source IP and flags brute-force attacks, username enumeration, vulnerability
scanners, injection payloads, and the worst-case scenario: **a successful login
right after a brute-force**.

Pure Python standard library: no dependencies, nothing to configure.

```text
Findings  1 critical  4 high  4 medium  1 low

  SEVERITY  RULE                   IP                COUNT  FIRST SEEN
  CRITICAL  SSH_COMPROMISE         203.0.113.99          5  2026-10-10 22:42:41
            Login accepted for deploy after repeated failures from the same address.
  HIGH      SSH_BRUTE_FORCE        203.0.113.42        300  2026-10-10 03:14:01
            300 failed logins, peak of 186 within 5 min. Most targeted: root, admin.
  HIGH      WEB_SENSITIVE_EXPOSED  192.0.2.150          40  2026-10-10 14:05:05
            The server answered 2xx for: /.git/config.
  HIGH      WEB_INJECTION          192.0.2.201           2  2026-10-10 19:12:00
            2 requests carrying attack payloads: Log4Shell (CVE-2021-44228).
  ...
```

It also writes a standalone **HTML report** (light/dark, no external assets) and
**JSON** for SIEM ingestion or scripting. See [`docs/example-report.html`](docs/example-report.html).

## Quick start

```bash
pip install git+https://github.com/UID0x/log-sleuth
log-sleuth /var/log/auth.log /var/log/nginx/access.log --html report.html
```

Try it on the bundled synthetic logs:

```bash
log-sleuth samples/auth.log samples/access.log --year 2026 -v
```

## Detection rules

| Rule | Severity | Logic |
|---|---|---|
| `SSH_COMPROMISE` | critical | Login **accepted** from an IP that failed ≥ 5 times in the previous hour |
| `SSH_BRUTE_FORCE` | medium / high | ≥ 5 failures in a sliding 5-minute window (high at ≥ 20) |
| `SSH_USER_ENUM` | medium | ≥ 4 distinct non-existent usernames tried from one IP |
| `WEB_SENSITIVE_EXPOSED` | high | `.env`, `.git/`, backups… requested **and served with 2xx** |
| `WEB_SENSITIVE_PROBE` | low | Same paths requested but refused (background noise of the Internet) |
| `WEB_INJECTION` | high | SQLi, XSS, path traversal, command injection, Log4Shell (path and User-Agent), double URL decoding |
| `WEB_SCANNER` | medium | Burst of ≥ 15 404s within 2 minutes, or a known tool User-Agent (sqlmap, nikto, gobuster, nuclei…) |

## Options

```text
log-sleuth FILE [FILE ...]
  -f, --format {auto,auth,nginx}   default: auto-detect per file
  --year YEAR                      syslog timestamps have no year (default: current)
  --json FILE / --html FILE        extra outputs
  --min-severity LEVEL             hide noise
  --fail-on LEVEL                  exit 2 if a finding reaches LEVEL (cron, CI)
  -v, --verbose                    print the evidence lines (file:line)
```

`.gz` rotated logs are read transparently. Exit codes: `0` OK, `1` usage error, `2` threshold reached.

Example cron job that emails you only when something serious happens:

```bash
0 7 * * * log-sleuth /var/log/auth.log --fail-on high --no-color > /tmp/ls.txt || mail -s "log-sleuth alert" me@example.com < /tmp/ls.txt
```

## Design notes

- **Two-pointer sliding window** (`max_in_window`) finds the peak attack rate in O(n), instead of comparing every pair of events.
- **Parsers and rules are decoupled.** Parsers normalize every format into one `Event` dataclass; rules are plain functions `(events, thresholds) -> findings`. Adding a format or a rule touches one file.
- **The report is not an attack vector.** Log content is attacker-controlled (paths, User-Agents, usernames). Everything is HTML-escaped and a test asserts that a `<script>` payload from a log stays inert.
- **Low false-positive bias.** A human typo followed by a successful login is ignored; refused probes for `wp-login.php` stay `low` because every public server receives them.
- **Year rollover.** Syslog lines have no year: a backwards jump of more than 6 months (December → January) bumps the year.
- **Synthetic sample data only uses RFC 5737 documentation addresses**, so no real host is accused.

## Development

```bash
python -m unittest discover -s tests -v   # 30 tests, ~0.1 s
python scripts/generate_samples.py        # regenerate samples/ (deterministic seed)
```

CI runs the suite on Linux and Windows against Python 3.10 to 3.13, then publishes a demo HTML report as a build artifact.

## Roadmap

- [ ] Windows Security event log (4625 / 4624) via exported CSV/EVTX
- [ ] `--follow` mode (tail -f) with live alerts
- [ ] GeoIP / ASN enrichment (optional dependency)
- [ ] Configurable thresholds through a TOML file

## License

MIT
