import csv
import io
import re
from datetime import datetime

from models.log_entry import LogEntry, LogFormat
from parsers.base import LogParser

# Known column names from Event Viewer and PowerShell Get-WinEvent exports
_HEADER_SIGNALS = {
    "TimeCreated", "Date and Time", "EventId", "Event ID", "Id",
    "LevelDisplayName", "Level", "Source", "Task", "Message",
    "Task Category", "Computer", "UserName",
}

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Map column name variants to a canonical name
_TS_COLS      = ("TimeCreated", "Date and Time", "Date", "Time")
_LEVEL_COLS   = ("LevelDisplayName", "Level")
_SOURCE_COLS  = ("Source", "ProviderName", "EventSource")
_ID_COLS      = ("EventId", "Event ID", "Id")
_TASK_COLS    = ("Task", "Task Category", "TaskDisplayName")
_MSG_COLS     = ("Message", "Description")
_USER_COLS    = ("UserName", "AccountName", "SubjectUserName")
_HOST_COLS    = ("Computer", "MachineName", "ComputerName")

_TS_FORMATS = (
    "%m/%d/%Y %I:%M:%S %p",   # Event Viewer: 1/5/2024 12:34:56 PM
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
)


def _col(row: dict, candidates: tuple) -> str | None:
    for key in candidates:
        if key in row and row[key]:
            return row[key].strip()
    return None


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass
    return None


def _normalize_level(level: str | None) -> str | None:
    if level is None:
        return None
    mapping = {
        "critical": "CRITICAL",
        "error": "ERROR",
        "warning": "WARNING",
        "information": "INFO",
        "verbose": "DEBUG",
        "audit failure": "WARNING",
        "audit success": "INFO",
    }
    return mapping.get(level.lower(), level.upper())


class WindowsCsvParser(LogParser):
    """
    Parses Windows Event Log CSV exports from Event Viewer or PowerShell.
    Expects a header row on the first call; subsequent calls are data rows.
    """

    def __init__(self):
        self._headers: list[str] | None = None

    @classmethod
    def format_type(cls) -> LogFormat:
        return LogFormat.WINDOWS_CSV

    @classmethod
    def detect(cls, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        # Check the first line for known Windows Event Log column names
        try:
            reader = csv.reader(io.StringIO(sample_lines[0]))
            header_cols = {col.strip() for col in next(reader)}
        except (StopIteration, csv.Error):
            return 0.0
        overlap = header_cols & _HEADER_SIGNALS
        # High confidence if 3+ known columns present
        return min(1.0, len(overlap) / 3)

    def parse_line(self, raw: str) -> LogEntry:
        try:
            reader = csv.reader(io.StringIO(raw))
            values = next(reader)
        except (StopIteration, csv.Error):
            return LogEntry(raw=raw, format=LogFormat.UNKNOWN, message=raw)

        # First non-empty line sets headers
        if self._headers is None:
            self._headers = [v.strip() for v in values]
            # Return a sentinel entry so the header row is not silently eaten
            return LogEntry(raw=raw, format=LogFormat.WINDOWS_CSV, message="[CSV header]")

        if len(values) != len(self._headers):
            return LogEntry(raw=raw, format=LogFormat.UNKNOWN, message=raw)

        row = dict(zip(self._headers, (v.strip() for v in values)))

        message  = _col(row, _MSG_COLS) or raw
        ts       = _parse_ts(_col(row, _TS_COLS))
        level    = _normalize_level(_col(row, _LEVEL_COLS))
        source   = _col(row, _SOURCE_COLS)
        event_id = _col(row, _ID_COLS)
        task     = _col(row, _TASK_COLS)
        user     = _col(row, _USER_COLS)
        host     = _col(row, _HOST_COLS)

        ip_match = _IP_RE.search(message)

        extra: dict = {}
        if event_id:
            extra["event_id"] = event_id
        if task:
            extra["task_category"] = task
        if user:
            extra["account_name"] = user
        # Pass through any unrecognised columns
        known = set(_TS_COLS + _LEVEL_COLS + _SOURCE_COLS + _ID_COLS +
                    _TASK_COLS + _MSG_COLS + _USER_COLS + _HOST_COLS)
        for k, v in row.items():
            if k not in known and v:
                extra[k] = v

        return LogEntry(
            raw=raw,
            format=LogFormat.WINDOWS_CSV,
            message=message,
            timestamp=ts,
            source_ip=ip_match.group(1) if ip_match else None,
            host=host,
            facility=source,
            severity=level,
            extra=extra,
        )
