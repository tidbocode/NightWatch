import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# Lower index = higher severity; used for filtering comparisons
SEVERITY_RANK: dict[str, int] = {s.value: i for i, s in enumerate(Severity)}


@dataclass
class Remediation:
    action: str
    command: str
    reversible: bool = True
    undo_command: str = ""


@dataclass
class Alert:
    severity: Severity
    title: str
    description: str
    recommendation: str
    iocs: list[str]
    affected_lines: list[str]
    log_format: str
    chunk_index: int
    timestamp_first: datetime | None = None
    timestamp_last: datetime | None = None
    source_file: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = field(default_factory=datetime.utcnow)
    remediation: Remediation | None = None

    def meets_minimum(self, min_severity: str) -> bool:
        """Return True if this alert's severity is >= min_severity."""
        return SEVERITY_RANK.get(self.severity.value, 99) <= SEVERITY_RANK.get(min_severity, 99)
