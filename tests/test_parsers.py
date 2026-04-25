"""
Parser tests — all sample data is inline; no external files required.
"""
import pytest
from datetime import datetime

from models.log_entry import LogFormat
from parsers.syslog import SyslogParser
from parsers.clf import ClfParser
from parsers.json_log import JsonLogParser
from parsers.windows_csv import WindowsCsvParser
from parsers.base import FormatDetector


# ---------------------------------------------------------------------------
# Sample log lines
# ---------------------------------------------------------------------------

SYSLOG_BSD = "Jan  5 12:34:56 myserver sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2"
SYSLOG_BSD_NO_PID = "Jan 15 08:23:11 webserver nginx: connection refused"
SYSLOG_RFC5424 = '<34>1 2024-01-05T12:34:56Z myserver sshd 1234 - - Failed password for invalid user admin'
SYSLOG_SYSTEMD = "2024-01-05 12:34:56 myserver sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
SYSLOG_WITH_PRI = "<34>Jan  5 12:34:56 myserver sshd[1234]: Failed password for root from 192.168.1.1 port 22"

CLF_FULL = '192.168.1.1 - - [05/Jan/2024:12:34:56 +0000] "GET /admin HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
CLF_AUTH = '10.0.0.5 - admin [15/Jan/2024:08:23:11 +0000] "POST /login HTTP/1.1" 401 89 "-" "curl/7.68.0"'
CLF_NO_AGENT = '172.16.0.1 - - [05/Jan/2024:12:34:56 +0000] "GET /etc/passwd HTTP/1.1" 404 0'
CLF_SERVER_ERROR = '203.0.113.42 - - [05/Jan/2024:12:34:56 +0000] "GET / HTTP/1.1" 500 512 "-" "-"'

JSON_STANDARD = '{"timestamp":"2024-01-05T12:34:56Z","level":"error","message":"Failed login","src_ip":"192.168.1.1"}'
JSON_ALT_KEYS = '{"time":"2024-01-15T08:23:11","severity":"WARNING","msg":"Port scan detected","remote_addr":"10.0.0.1","host":"sensor1"}'
JSON_NO_IP = '{"@timestamp":"2024-01-05T12:34:56Z","level":"INFO","message":"Service started"}'
JSON_EXTRA_KEYS = '{"timestamp":"2024-01-05T12:34:56Z","level":"debug","message":"ok","request_id":"abc123","duration_ms":42}'

WIN_HEADER = "Level,Date and Time,Source,Event ID,Task Category,Computer,Message"
WIN_ROW_ERROR = '4625,1/5/2024 12:34:56 PM,Microsoft-Windows-Security-Auditing,4625,Logon,WORKSTATION1,An account failed to log on. Source: 192.168.1.100'
WIN_ROW_WARNING = 'Warning,1/15/2024 8:23:11 AM,Microsoft-Windows-WinRM,91,None,SERVER1,Creating a HTTP listener on any IP failed'
WIN_ROW_POWERSHELL_HEADER = "TimeCreated,Id,LevelDisplayName,Task,Message,Computer,UserName"
WIN_ROW_POWERSHELL = "1/5/2024 12:34:56 PM,4625,Error,Logon,An account failed to log on.,WORKSTATION1,DOMAIN\\jdoe"


# ---------------------------------------------------------------------------
# SyslogParser
# ---------------------------------------------------------------------------

class TestSyslogParser:

    def setup_method(self):
        self.parser = SyslogParser()

    def test_detects_bsd_lines(self):
        score = SyslogParser.detect([SYSLOG_BSD, SYSLOG_BSD_NO_PID, SYSLOG_BSD])
        assert score >= 0.6

    def test_detects_rfc5424_lines(self):
        score = SyslogParser.detect([SYSLOG_RFC5424])
        assert score == 1.0

    def test_does_not_detect_clf(self):
        score = SyslogParser.detect([CLF_FULL, CLF_AUTH])
        assert score == 0.0

    def test_bsd_format(self):
        entry = self.parser.parse_line(SYSLOG_BSD)
        assert entry.format == LogFormat.SYSLOG
        assert entry.source_ip == "192.168.1.1"
        assert entry.host == "myserver"
        assert "Failed password" in entry.message
        assert entry.extra["process"] == "sshd"

    def test_bsd_timestamp_parsed(self):
        entry = self.parser.parse_line(SYSLOG_BSD)
        assert entry.timestamp is not None
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 5

    def test_bsd_no_pid(self):
        entry = self.parser.parse_line(SYSLOG_BSD_NO_PID)
        assert entry.format == LogFormat.SYSLOG
        assert entry.host == "webserver"

    def test_rfc5424_format(self):
        entry = self.parser.parse_line(SYSLOG_RFC5424)
        assert entry.format == LogFormat.SYSLOG
        assert entry.host == "myserver"
        assert entry.timestamp is not None

    def test_systemd_format(self):
        entry = self.parser.parse_line(SYSLOG_SYSTEMD)
        assert entry.format == LogFormat.SYSLOG
        assert entry.source_ip == "10.0.0.1"
        assert entry.timestamp is not None
        assert entry.timestamp.year == 2024

    def test_pri_severity_decoded(self):
        # <34> = facility 4 (auth), severity 2 (CRITICAL)
        entry = self.parser.parse_line(SYSLOG_WITH_PRI)
        assert entry.severity == "CRITICAL"
        assert entry.facility == "auth"

    def test_unparseable_returns_unknown(self):
        entry = self.parser.parse_line("this is not a syslog line at all")
        assert entry.format == LogFormat.UNKNOWN
        assert entry.raw == "this is not a syslog line at all"

    def test_never_raises(self):
        for line in ["", "   ", "!!!", "null", "<>", "Jan"]:
            entry = self.parser.parse_line(line)
            assert entry is not None


# ---------------------------------------------------------------------------
# ClfParser
# ---------------------------------------------------------------------------

class TestClfParser:

    def setup_method(self):
        self.parser = ClfParser()

    def test_detects_clf_lines(self):
        score = ClfParser.detect([CLF_FULL, CLF_AUTH, CLF_NO_AGENT])
        assert score >= 0.6

    def test_does_not_detect_syslog(self):
        score = ClfParser.detect([SYSLOG_BSD, SYSLOG_BSD_NO_PID])
        assert score == 0.0

    def test_full_line(self):
        entry = self.parser.parse_line(CLF_FULL)
        assert entry.format == LogFormat.CLF
        assert entry.source_ip == "192.168.1.1"
        assert entry.extra["method"] == "GET"
        assert entry.extra["path"] == "/admin"
        assert entry.extra["status_code"] == 200
        assert entry.extra["referer"] == "http://example.com"
        assert "Mozilla" in entry.extra["user_agent"]

    def test_timestamp_parsed(self):
        entry = self.parser.parse_line(CLF_FULL)
        assert entry.timestamp is not None
        assert entry.timestamp.day == 5
        assert entry.timestamp.month == 1

    def test_401_is_warning(self):
        entry = self.parser.parse_line(CLF_AUTH)
        assert entry.severity == "WARNING"

    def test_500_is_error(self):
        entry = self.parser.parse_line(CLF_SERVER_ERROR)
        assert entry.severity == "ERROR"

    def test_auth_user_extracted(self):
        entry = self.parser.parse_line(CLF_AUTH)
        assert entry.extra.get("auth_user") == "admin"

    def test_no_agent_line(self):
        entry = self.parser.parse_line(CLF_NO_AGENT)
        assert entry.format == LogFormat.CLF
        assert entry.extra["path"] == "/etc/passwd"

    def test_message_summary(self):
        entry = self.parser.parse_line(CLF_FULL)
        assert "GET" in entry.message
        assert "200" in entry.message

    def test_never_raises(self):
        for line in ["", "not clf", "192.168.1.1 only"]:
            assert self.parser.parse_line(line) is not None


# ---------------------------------------------------------------------------
# JsonLogParser
# ---------------------------------------------------------------------------

class TestJsonLogParser:

    def setup_method(self):
        self.parser = JsonLogParser()

    def test_detects_json_lines(self):
        score = JsonLogParser.detect([JSON_STANDARD, JSON_ALT_KEYS, JSON_NO_IP])
        assert score == 1.0

    def test_does_not_detect_syslog(self):
        score = JsonLogParser.detect([SYSLOG_BSD, SYSLOG_BSD_NO_PID])
        assert score == 0.0

    def test_standard_keys(self):
        entry = self.parser.parse_line(JSON_STANDARD)
        assert entry.format == LogFormat.JSON
        assert entry.source_ip == "192.168.1.1"
        assert entry.severity == "ERROR"
        assert "Failed login" in entry.message

    def test_timestamp_parsed(self):
        entry = self.parser.parse_line(JSON_STANDARD)
        assert entry.timestamp is not None
        assert entry.timestamp.year == 2024

    def test_alt_key_names(self):
        entry = self.parser.parse_line(JSON_ALT_KEYS)
        assert entry.source_ip == "10.0.0.1"
        assert entry.host == "sensor1"
        assert entry.severity == "WARNING"
        assert "Port scan" in entry.message

    def test_no_ip_field(self):
        entry = self.parser.parse_line(JSON_NO_IP)
        assert entry.format == LogFormat.JSON
        assert entry.source_ip is None

    def test_extra_keys_passed_through(self):
        entry = self.parser.parse_line(JSON_EXTRA_KEYS)
        assert "request_id" in entry.extra
        assert "duration_ms" in entry.extra

    def test_level_normalisation(self):
        import json
        line = json.dumps({"message": "x", "level": "fatal"})
        entry = self.parser.parse_line(line)
        assert entry.severity == "CRITICAL"

    def test_invalid_json_returns_unknown(self):
        entry = self.parser.parse_line("not json {{{")
        assert entry.format == LogFormat.UNKNOWN

    def test_never_raises(self):
        for line in ["", "{}", "[]", "null", "42"]:
            assert self.parser.parse_line(line) is not None


# ---------------------------------------------------------------------------
# WindowsCsvParser
# ---------------------------------------------------------------------------

class TestWindowsCsvParser:

    def setup_method(self):
        self.parser = WindowsCsvParser()

    def test_detects_windows_csv(self):
        score = WindowsCsvParser.detect([WIN_HEADER])
        assert score >= 0.6

    def test_does_not_detect_syslog(self):
        score = WindowsCsvParser.detect([SYSLOG_BSD])
        assert score == 0.0

    def test_header_sets_state(self):
        entry = self.parser.parse_line(WIN_HEADER)
        assert entry.message == "[CSV header]"
        assert self.parser._headers is not None

    def test_data_row_parsed(self):
        self.parser.parse_line(WIN_ROW_POWERSHELL_HEADER)
        entry = self.parser.parse_line(WIN_ROW_POWERSHELL)
        assert entry.format == LogFormat.WINDOWS_CSV
        assert "failed to log on" in entry.message.lower()
        assert entry.host == "WORKSTATION1"
        assert entry.severity == "ERROR"

    def test_event_id_in_extra(self):
        self.parser.parse_line(WIN_ROW_POWERSHELL_HEADER)
        entry = self.parser.parse_line(WIN_ROW_POWERSHELL)
        assert entry.extra.get("event_id") == "4625"

    def test_ip_extracted_from_message(self):
        self.parser.parse_line(WIN_HEADER)
        entry = self.parser.parse_line(WIN_ROW_ERROR)
        assert entry.source_ip == "192.168.1.100"

    def test_never_raises(self):
        p = WindowsCsvParser()
        for line in ["", "not,csv,really", WIN_HEADER]:
            assert p.parse_line(line) is not None


# ---------------------------------------------------------------------------
# FormatDetector
# ---------------------------------------------------------------------------

class TestFormatDetector:

    def test_detects_syslog(self):
        lines = [SYSLOG_BSD, SYSLOG_BSD_NO_PID, SYSLOG_SYSTEMD]
        fmt = FormatDetector.detect_from_lines(lines)
        assert fmt == LogFormat.SYSLOG

    def test_detects_clf(self):
        lines = [CLF_FULL, CLF_AUTH, CLF_NO_AGENT]
        fmt = FormatDetector.detect_from_lines(lines)
        assert fmt == LogFormat.CLF

    def test_detects_json(self):
        lines = [JSON_STANDARD, JSON_ALT_KEYS, JSON_NO_IP]
        fmt = FormatDetector.detect_from_lines(lines)
        assert fmt == LogFormat.JSON

    def test_empty_input_returns_unknown(self):
        fmt = FormatDetector.detect_from_lines([])
        assert fmt == LogFormat.UNKNOWN

    def test_get_parser_returns_correct_type(self):
        assert isinstance(FormatDetector.get_parser(LogFormat.SYSLOG), SyslogParser)
        assert isinstance(FormatDetector.get_parser(LogFormat.CLF), ClfParser)
        assert isinstance(FormatDetector.get_parser(LogFormat.JSON), JsonLogParser)
        assert isinstance(FormatDetector.get_parser(LogFormat.WINDOWS_CSV), WindowsCsvParser)


# ---------------------------------------------------------------------------
# parse_lines() integration — stream behaviour
# ---------------------------------------------------------------------------

class TestParseLines:

    def test_skips_blank_lines(self):
        parser = SyslogParser()
        lines = [SYSLOG_BSD, "", "   ", SYSLOG_BSD_NO_PID]
        entries = list(parser.parse_lines(lines))
        assert len(entries) == 2

    def test_strips_trailing_newline(self):
        parser = ClfParser()
        entries = list(parser.parse_lines([CLF_FULL + "\n"]))
        assert entries[0].format == LogFormat.CLF

    def test_json_stream(self):
        parser = JsonLogParser()
        lines = [JSON_STANDARD, JSON_ALT_KEYS, JSON_NO_IP]
        entries = list(parser.parse_lines(lines))
        assert len(entries) == 3
        assert all(e.format == LogFormat.JSON for e in entries)
