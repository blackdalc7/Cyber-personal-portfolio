"""Tests for RFC 5424, RFC 3164 and BSD syslog parsing."""

from datetime import datetime, timezone

import pytest

from realtime_siem.syslog_parser import parse_structured_data, parse_syslog

RECEIVED = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)


def test_rfc5424_full_header_and_structured_data():
    raw = (b'<165>1 2026-10-26T08:01:30.123+11:00 web01.example.org sshd 2055 ID47 '
           b'[exampleSDID@32473 iut="3" eventSource="App\\"lication"][meta seq="1"] '
           b'\xef\xbb\xbfAccepted publickey for alice from 192.0.2.10 port 4 ssh2')
    msg = parse_syslog(raw, received_at=RECEIVED)
    assert msg.format == "rfc5424"
    assert msg.priority == 165 and msg.facility == 20 and msg.severity == 5
    assert msg.facility_name == "local4" and msg.severity_name == "notice"
    assert msg.version == 1
    assert msg.hostname == "web01.example.org"
    assert msg.app_name == "sshd" and msg.procid == "2055" and msg.msgid == "ID47"
    assert msg.structured_data == {"exampleSDID@32473": {"iut": "3", "eventSource": 'App"lication'},
                                   "meta": {"seq": "1"}}
    assert msg.message.startswith("Accepted publickey")  # BOM stripped
    assert msg.timestamp == datetime(2026, 10, 25, 21, 1, 30, 123000, tzinfo=timezone.utc)


def test_rfc5424_nil_values():
    msg = parse_syslog(b"<14>1 - - - - - - hello", received_at=RECEIVED)
    assert msg.format == "rfc5424"
    assert msg.timestamp is None and msg.hostname is None and msg.app_name is None
    assert msg.structured_data == {} and msg.message == "hello"


def test_rfc3164_with_pid():
    msg = parse_syslog(b"<38>Oct 26 08:01:30 web01 sshd[2055]: Failed password for root from 1.2.3.4",
                       received_at=RECEIVED)
    assert msg.format == "rfc3164"
    assert msg.priority == 38 and msg.facility_name == "auth" and msg.severity_name == "informational"
    assert msg.hostname == "web01" and msg.app_name == "sshd" and msg.procid == "2055"
    assert msg.timestamp == datetime(2026, 10, 26, 8, 1, 30, tzinfo=timezone.utc)
    assert msg.message == "Failed password for root from 1.2.3.4"


def test_rfc3164_single_digit_day_and_timezone():
    msg = parse_syslog(b"<38>Oct  6 08:01:30 web01 cron: job", received_at=RECEIVED,
                       default_tz="Australia/Melbourne")
    # 08:01:30 AEDT (UTC+11) == 21:01:30 UTC the previous day
    assert msg.timestamp == datetime(2026, 10, 5, 21, 1, 30, tzinfo=timezone.utc)
    assert msg.procid is None


def test_rfc3164_year_rollover():
    received = datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc)
    msg = parse_syslog(b"<38>Dec 31 23:59:59 web01 sshd[1]: x", received_at=received)
    assert msg.timestamp.year == 2026


def test_bsd_without_pri():
    msg = parse_syslog("Oct 26 08:01:30 web01 sshd[2055]: hello", received_at=RECEIVED)
    assert msg.format == "bsd" and msg.priority is None and msg.facility is None
    assert msg.hostname == "web01"


@pytest.mark.parametrize("raw", [b"", b"garbage", b"<999>1 x", b"\xff\xfe\x00\x01", b"<34>", b"<12>1 "])
def test_malformed_never_raises(raw):
    msg = parse_syslog(raw, received_at=RECEIVED)
    assert msg.format in {"unknown", "rfc5424", "rfc3164", "bsd"}
    assert msg.received_at == RECEIVED


def test_out_of_range_pri_is_not_trusted():
    msg = parse_syslog(b"<999>Oct 26 08:01:30 web01 sshd: x", received_at=RECEIVED)
    assert msg.priority is None


def test_structured_data_malformed_returns_text():
    _elements, rest = parse_structured_data('[id k=noquote] msg')
    assert rest == '[id k=noquote] msg'


def test_structured_data_escaped_bracket():
    elements, rest = parse_structured_data('[a x="1\\]2"] tail')
    assert elements == {"a": {"x": "1]2"}} and rest == "tail"
