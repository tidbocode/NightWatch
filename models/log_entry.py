from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class LogFormat(str, Enum):
    SYSLOG      = "syslog"
    CLF         = "clf"          # nginx / apache Combined Log Format
    JSON        = "json"
    WINDOWS_CSV = "windows_csv"
    UNKNOWN     = "unknown"


@dataclass
class LogEntry:
    raw: str                        # original unmodified line
    format: LogFormat
    message: str                    # cleaned message body
    timestamp: datetime | None = None
    source_ip: str | None = None
    host: str | None = None
    facility: str | None = None     # syslog facility or Windows event source
    severity: str | None = None     # log-level string (ERROR, WARNING, INFO, etc.)
    extra: dict = field(default_factory=dict)
    # CLF extras:      method, path, status_code, bytes_sent, referer, user_agent
    # Windows extras:  event_id, task_category, account_name, level
    # JSON:            passthrough of any additional keys
