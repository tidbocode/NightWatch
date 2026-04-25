import re
from datetime import datetime

from models.log_entry import LogEntry, LogFormat
from parsers.base import LogParser

# Traditional BSD syslog: Jan  5 12:34:56 hostname process[pid]: message
_BSD_RE = re.compile(
    r"^(?:<\d+>)?"                                    # optional <PRI>
    r"(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})"    # timestamp
    r"\s+(\S+)"                                        # hostname
    r"\s+([\w\-\.\/]+)"                               # process
    r"(?:\[(\d+)\])?"                                 # optional [pid]
    r":\s*(.*)"                                        # message
)

# RFC 5424: <PRI>1 2024-01-05T12:34:56Z hostname app pid msgid - message
_RFC5424_RE = re.compile(
    r"^<\d+>1\s+"
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r"\s+(\S+)"   # hostname
    r"\s+(\S+)"   # appname
    r"\s+\S+"     # procid
    r"\s+\S+"     # msgid
    r"\s+\S+"     # structured data
    r"\s*(.*)"    # message
)

# Systemd/journald: 2024-01-05 12:34:56 hostname process[pid]: message
_SYSTEMD_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(\S+)"
    r"\s+([\w\-\.\/]+)"
    r"(?:\[(\d+)\])?"
    r":\s*(.*)"
)

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Syslog severity codes (PRI % 8)
_SEVERITY_NAMES = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"]

# Syslog facility codes (PRI // 8)
_FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog",
    "lpr", "news", "uucp", "cron", "authpriv", "ftp",
]


def _parse_pri(raw: str) -> tuple[str | None, str | None]:
    """Extract facility and severity names from a <PRI> prefix."""
    m = re.match(r"^<(\d+)>", raw)
    if not m:
        return None, None
    pri = int(m.group(1))
    facility_idx = pri >> 3
    severity_idx = pri & 0x7
    facility = _FACILITY_NAMES[facility_idx] if facility_idx < len(_FACILITY_NAMES) else str(facility_idx)
    severity = _SEVERITY_NAMES[severity_idx]
    return facility, severity


def _parse_bsd_timestamp(ts: str) -> datetime | None:
    try:
        # Add a placeholder year since BSD syslog omits it
        return datetime.strptime(f"2000 {ts.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


class SyslogParser(LogParser):

    @classmethod
    def format_type(cls) -> LogFormat:
        return LogFormat.SYSLOG

    @classmethod
    def detect(cls, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        matches = sum(
            1 for line in sample_lines
            if _BSD_RE.match(line) or _RFC5424_RE.match(line) or _SYSTEMD_RE.match(line)
        )
        return matches / len(sample_lines)

    def parse_line(self, raw: str) -> LogEntry:
        facility, severity = _parse_pri(raw)

        m = _RFC5424_RE.match(raw)
        if m:
            ts_str, host, process, message = m.group(1), m.group(2), m.group(3), m.group(4)
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                ts = None
            return LogEntry(
                raw=raw, format=LogFormat.SYSLOG, message=message,
                timestamp=ts, host=host, facility=facility or process, severity=severity,
                extra={"process": process},
            )

        m = _BSD_RE.match(raw)
        if m:
            ts_str, host, process, pid, message = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            ip_match = _IP_RE.search(message)
            return LogEntry(
                raw=raw, format=LogFormat.SYSLOG, message=message,
                timestamp=_parse_bsd_timestamp(ts_str),
                source_ip=ip_match.group(1) if ip_match else None,
                host=host, facility=facility, severity=severity,
                extra={"process": process, "pid": pid},
            )

        m = _SYSTEMD_RE.match(raw)
        if m:
            ts_str, host, process, pid, message = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                ts = None
            ip_match = _IP_RE.search(message)
            return LogEntry(
                raw=raw, format=LogFormat.SYSLOG, message=message,
                timestamp=ts,
                source_ip=ip_match.group(1) if ip_match else None,
                host=host, facility=facility, severity=severity,
                extra={"process": process, "pid": pid},
            )

        # Unparseable — return a minimal entry so nothing is silently dropped
        ip_match = _IP_RE.search(raw)
        return LogEntry(
            raw=raw, format=LogFormat.UNKNOWN, message=raw,
            source_ip=ip_match.group(1) if ip_match else None,
        )
