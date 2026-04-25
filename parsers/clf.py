import re
from datetime import datetime

from models.log_entry import LogEntry, LogFormat
from parsers.base import LogParser

# nginx / Apache Combined Log Format
# 192.168.1.1 - user [05/Jan/2024:12:34:56 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "ua"
_CLF_RE = re.compile(
    r"^(\S+)"                   # source IP or hostname
    r"\s+\S+"                   # ident (usually -)
    r"\s+(\S+)"                 # auth user (- if none)
    r'\s+\[([^\]]+)\]'          # [timestamp]
    r'\s+"([^"]*)"'             # "request line"
    r"\s+(\d{3})"               # status code
    r"\s+(\S+)"                 # bytes sent
    r'(?:\s+"([^"]*)"'          # optional "referer"
    r'\s+"([^"]*)")?'           # optional "user-agent"
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

_REQUEST_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)$")


def _parse_clf_timestamp(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, _TS_FORMAT)
    except ValueError:
        return None


def _status_severity(code: int) -> str:
    if code >= 500:
        return "ERROR"
    if code >= 400:
        return "WARNING"
    return "INFO"


class ClfParser(LogParser):

    @classmethod
    def format_type(cls) -> LogFormat:
        return LogFormat.CLF

    @classmethod
    def detect(cls, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        matches = sum(1 for line in sample_lines if _CLF_RE.match(line))
        return matches / len(sample_lines)

    def parse_line(self, raw: str) -> LogEntry:
        m = _CLF_RE.match(raw)
        if not m:
            return LogEntry(raw=raw, format=LogFormat.UNKNOWN, message=raw)

        src_ip, auth_user, ts_str, request, status_str, bytes_sent, referer, user_agent = (
            m.group(1), m.group(2), m.group(3), m.group(4),
            m.group(5), m.group(6), m.group(7), m.group(8),
        )

        status_code = int(status_str)
        req_m = _REQUEST_RE.match(request)
        method = req_m.group(1) if req_m else None
        path   = req_m.group(2) if req_m else request

        user = auth_user if auth_user != "-" else None

        extra: dict = {
            "method": method,
            "path": path,
            "status_code": status_code,
            "bytes_sent": bytes_sent,
        }
        if referer and referer != "-":
            extra["referer"] = referer
        if user_agent and user_agent != "-":
            extra["user_agent"] = user_agent
        if user:
            extra["auth_user"] = user

        return LogEntry(
            raw=raw,
            format=LogFormat.CLF,
            message=f'{method or "?"} {path} → {status_code}',
            timestamp=_parse_clf_timestamp(ts_str),
            source_ip=src_ip if src_ip != "-" else None,
            severity=_status_severity(status_code),
            extra=extra,
        )
