import json
import re
from datetime import datetime

from models.log_entry import LogEntry, LogFormat
from parsers.base import LogParser

# Common key names across different JSON log schemas
_TS_KEYS    = ("timestamp", "time", "@timestamp", "ts", "date", "datetime", "created_at")
_MSG_KEYS   = ("message", "msg", "log", "text", "body", "event", "description")
_LEVEL_KEYS = ("level", "severity", "loglevel", "log_level", "lvl", "priority", "status")
_IP_KEYS    = ("src_ip", "source_ip", "remote_addr", "client_ip", "ip", "remote_ip", "sourceIPAddress")
_HOST_KEYS  = ("host", "hostname", "server", "node", "machine", "source")

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _find(d: dict, keys: tuple) -> str | None:
    for k in keys:
        if k in d:
            v = d[k]
            return str(v) if v is not None else None
    return None


def _parse_timestamp(ts: str) -> datetime | None:
    if not ts:
        return None
    # Try ISO 8601 variants
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass
    # Fallback: strip sub-second precision and timezone suffix, try again
    ts_clean = re.sub(r"\.\d+", "", ts)
    ts_clean = re.sub(r"[+-]\d{2}:\d{2}$", "", ts_clean).replace("Z", "")
    try:
        return datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def _normalize_level(level: str | None) -> str | None:
    if level is None:
        return None
    mapping = {
        "fatal": "CRITICAL", "panic": "CRITICAL",
        "error": "ERROR", "err": "ERROR",
        "warn": "WARNING", "warning": "WARNING",
        "info": "INFO", "information": "INFO",
        "debug": "DEBUG", "trace": "DEBUG",
    }
    return mapping.get(level.lower(), level.upper())


class JsonLogParser(LogParser):

    @classmethod
    def format_type(cls) -> LogFormat:
        return LogFormat.JSON

    @classmethod
    def detect(cls, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        parsed = 0
        for line in sample_lines:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    parsed += 1
            except (json.JSONDecodeError, ValueError):
                pass
        return parsed / len(sample_lines)

    def parse_line(self, raw: str) -> LogEntry:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return LogEntry(raw=raw, format=LogFormat.UNKNOWN, message=raw)

        if not isinstance(data, dict):
            return LogEntry(raw=raw, format=LogFormat.UNKNOWN, message=raw)

        message = _find(data, _MSG_KEYS) or raw
        ts_str  = _find(data, _TS_KEYS)
        level   = _normalize_level(_find(data, _LEVEL_KEYS))
        src_ip  = _find(data, _IP_KEYS)
        host    = _find(data, _HOST_KEYS)

        # If no IP field, scan message for an IP address
        if not src_ip:
            ip_match = _IP_RE.search(message)
            src_ip = ip_match.group(1) if ip_match else None

        # Pass through all keys not consumed above as extras
        consumed = set(_TS_KEYS + _MSG_KEYS + _LEVEL_KEYS + _IP_KEYS + _HOST_KEYS)
        extra = {k: v for k, v in data.items() if k not in consumed}

        return LogEntry(
            raw=raw,
            format=LogFormat.JSON,
            message=message,
            timestamp=_parse_timestamp(ts_str) if ts_str else None,
            source_ip=src_ip,
            host=host,
            severity=level,
            extra=extra,
        )
