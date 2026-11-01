"""Tests for the UDP log replay tool."""

from helpers import FIXTURES

from realtime_siem.replay import iter_datagrams, main, to_datagram
from realtime_siem.syslog_parser import parse_syslog


def test_to_datagram_rfc5424_roundtrip():
    dgram = to_datagram("Oct 26 08:01:30 web01 sshd[2055]: Accepted publickey for x from 1.2.3.4", "rfc5424", 2026)
    msg = parse_syslog(dgram)
    assert msg.format == "rfc5424" and msg.procid == "2055" and msg.app_name == "sshd"
    assert msg.message.startswith("Accepted")


def test_to_datagram_rfc3164_and_blank():
    assert parse_syslog(to_datagram("Oct 26 08:01:30 web01 sshd: hi", "rfc3164", 2026)).format == "rfc3164"
    assert to_datagram("   \n", "rfc5424", 2026) is None


def test_iter_fixture_count():
    assert sum(1 for _ in iter_datagrams(FIXTURES / "auth.log", "rfc5424", 2026)) == 138


def test_main_missing_file(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == 2
