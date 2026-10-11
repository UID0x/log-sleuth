"""Glue between files on disk, parsers and detectors."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .detectors import Thresholds, detect
from .models import Event, FileStats, Report
from .parsers import detect_format, parse_lines, read_lines


def analyze(paths: list[Path], fmt: str = "auto", year: int | None = None,
            thresholds: Thresholds | None = None) -> Report:
    year = year or datetime.now().year
    stats: list[FileStats] = []
    events: list[Event] = []
    for path in paths:
        lines = read_lines(path)
        file_fmt = detect_format(lines) if fmt == "auto" else fmt
        file_events = parse_lines(lines, file_fmt, year, path.name) if file_fmt else []
        stats.append(FileStats(str(path), file_fmt, len(lines), len(file_events)))
        events.extend(file_events)
    return Report(files=stats, findings=detect(events, thresholds), generated_at=datetime.now())
