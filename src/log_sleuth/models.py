"""Core data structures shared by parsers, detectors and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass(frozen=True)
class Event:
    """A single security-relevant log line, normalized across formats.

    Timestamps are naive and expressed in the log's own wall-clock time.
    """

    timestamp: datetime
    source: str  # "auth" or "web"
    kind: str  # ssh_failed, ssh_invalid_user, ssh_accepted, http_request
    ip: str
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    file: str = ""
    line_no: int = 0
    raw: str = ""

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line_no}"


@dataclass
class Finding:
    rule: str
    severity: Severity
    ip: str
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    count: int
    evidence: list[str] = field(default_factory=list)


@dataclass
class FileStats:
    path: str
    format: str | None
    lines: int
    events: int


@dataclass
class Report:
    files: list[FileStats]
    findings: list[Finding]
    generated_at: datetime

    @property
    def total_lines(self) -> int:
        return sum(f.lines for f in self.files)

    @property
    def total_events(self) -> int:
        return sum(f.events for f in self.files)

    def count_by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
