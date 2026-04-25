from abc import ABC, abstractmethod
from typing import Iterable, Iterator

from models.log_entry import LogEntry, LogFormat


class LogParser(ABC):

    @classmethod
    @abstractmethod
    def detect(cls, sample_lines: list[str]) -> float:
        """Return confidence 0.0–1.0 that this parser can handle these lines."""

    @abstractmethod
    def parse_line(self, raw: str) -> LogEntry:
        """
        Parse a single raw line into a LogEntry.
        Must never raise — return LogEntry with format=UNKNOWN on failure.
        """

    def parse_lines(self, source: Iterable[str]) -> Iterator[LogEntry]:
        for raw in source:
            line = raw.rstrip("\n")
            if line.strip():
                yield self.parse_line(line)


class FormatDetector:
    """
    Auto-detect the format of a log file by sampling its first lines.
    Each parser votes with a confidence score; highest wins.
    """

    # Import here to avoid circular imports at module load time
    @staticmethod
    def _parsers() -> list[type[LogParser]]:
        from parsers.syslog import SyslogParser
        from parsers.clf import ClfParser
        from parsers.json_log import JsonLogParser
        from parsers.windows_csv import WindowsCsvParser
        return [SyslogParser, ClfParser, JsonLogParser, WindowsCsvParser]

    @classmethod
    def detect_format(cls, file_path: str, sample_size: int = 20) -> LogFormat:
        """Read the first sample_size non-empty lines and return the best-fit LogFormat."""
        try:
            sample = cls._read_sample(file_path, sample_size)
        except OSError:
            return LogFormat.UNKNOWN

        if not sample:
            return LogFormat.UNKNOWN

        scores: dict[LogFormat, float] = {}
        for parser_cls in cls._parsers():
            confidence = parser_cls.detect(sample)
            # Boost CSV parser when extension matches
            if parser_cls.__name__ == "WindowsCsvParser" and file_path.lower().endswith(".csv"):
                confidence = min(1.0, confidence + 0.2)
            scores[parser_cls.format_type()] = confidence  # type: ignore[attr-defined]

        best_format, best_score = max(scores.items(), key=lambda x: x[1])
        return best_format if best_score >= 0.3 else LogFormat.UNKNOWN

    @classmethod
    def detect_from_lines(cls, lines: list[str]) -> LogFormat:
        """Detect format from an already-loaded list of lines (e.g. from stdin)."""
        sample = [l for l in lines if l.strip()][:20]
        if not sample:
            return LogFormat.UNKNOWN

        scores: dict[LogFormat, float] = {}
        for parser_cls in cls._parsers():
            scores[parser_cls.format_type()] = parser_cls.detect(sample)  # type: ignore[attr-defined]

        best_format, best_score = max(scores.items(), key=lambda x: x[1])
        return best_format if best_score >= 0.3 else LogFormat.UNKNOWN

    @staticmethod
    def _read_sample(file_path: str, n: int) -> list[str]:
        lines: list[str] = []
        with open(file_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
                if len(lines) >= n:
                    break
        return lines

    @classmethod
    def get_parser(cls, fmt: LogFormat) -> LogParser:
        """Return a parser instance for the given format."""
        from parsers.syslog import SyslogParser
        from parsers.clf import ClfParser
        from parsers.json_log import JsonLogParser
        from parsers.windows_csv import WindowsCsvParser

        mapping: dict[LogFormat, type[LogParser]] = {
            LogFormat.SYSLOG:      SyslogParser,
            LogFormat.CLF:         ClfParser,
            LogFormat.JSON:        JsonLogParser,
            LogFormat.WINDOWS_CSV: WindowsCsvParser,
        }
        parser_cls = mapping.get(fmt)
        if parser_cls is None:
            # Fall back to syslog for UNKNOWN — it's the most permissive
            return SyslogParser()
        return parser_cls()
