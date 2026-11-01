"""Tests for loading Windows XML and ECS NDJSON log exports."""

import json
from datetime import timezone

import pytest
from conftest import EXAMPLES
from defusedxml import EntitiesForbidden

from attack_coverage.logs import LogFormatError, ecs_to_sigma, load_events, read_ecs_ndjson, read_windows_xml
from attack_coverage.logs.base import parse_time

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def test_windows_export_normalises_sysmon_and_4688():
    events = read_windows_xml(EXAMPLES / "logs" / "ws01_windows_events.xml")
    assert len(events) == 9  # the Sysmon EID 3 network event is skipped
    whoami = next(e for e in events if e["Image"].endswith("whoami.exe"))
    assert whoami["EventID"] == 1 and whoami["ProcessId"] == 5120 and whoami["_host"] == "ws01"
    assert whoami["_logsource"] == {"category": "process_creation", "product": "windows"}
    sec = next(e for e in events if e["EventID"] == 4688)
    assert sec["Image"].endswith("systeminfo.exe") and sec["ProcessId"] == 5200 and sec["ParentProcessId"] == 4800
    assert sec["User"] == "LAB\\analyst" and sec["_time"].microsecond == 200000


def test_bare_event_siblings_and_single_event(tmp_path):
    one = (
        f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
        f'<TimeCreated SystemTime="2026-10-26T09:00:00.1234567Z"/><Computer>H1</Computer></System>'
        f'<EventData><Data Name="Image">C:\\a.exe</Data><Data Name="ProcessId">0x10</Data></EventData></Event>'
    )
    (tmp_path / "two.xml").write_text(one + one)
    (tmp_path / "one.xml").write_text(one)
    assert len(read_windows_xml(tmp_path / "two.xml")) == 2
    ev = read_windows_xml(tmp_path / "one.xml")[0]
    assert ev["ProcessId"] == 16 and ev["_host"] == "h1"


def test_windows_export_rejects_xxe_and_missing_time(tmp_path):
    evil = tmp_path / "evil.xml"
    evil.write_text('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><Events>&x;</Events>')
    with pytest.raises(EntitiesForbidden):
        read_windows_xml(evil)
    bad = tmp_path / "bad.xml"
    bad.write_text(
        f'<Events><Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>1</EventID></System></Event></Events>"
    )
    with pytest.raises(LogFormatError, match="TimeCreated"):
        read_windows_xml(bad)


def test_ecs_ndjson_maps_process_starts_only():
    events = read_ecs_ndjson(EXAMPLES / "logs" / "srv01_auditbeat.ndjson")
    assert len(events) == 6
    uname = next(e for e in events if e["Image"] == "/usr/bin/uname")
    assert uname["CommandLine"] == "uname -a" and uname["_logsource"]["product"] == "linux"
    assert uname["ParentImage"] == "/usr/bin/bash" and uname["_host"] == "srv01"


def test_ecs_variants(tmp_path):
    flat = {
        "@timestamp": "2026-10-26T09:00:00Z",
        "event.category": "process",
        "event.type": "start",
        "host.hostname": "WS9",
        "host.os.type": "windows",
        "process.args": ["cmd.exe", "/c", "x"],
        "user.name": "bob",
        "user.domain": "LAB",
    }
    ev = ecs_to_sigma(flat)
    assert ev["CommandLine"] == "cmd.exe /c x" and ev["User"] == "LAB\\bob" and ev["_logsource"]["product"] == "windows"
    hit = {"_index": "logs", "_source": {**flat, "process.command_line": "cmd.exe /c y"}}
    f = tmp_path / "hits.ndjson"
    f.write_text(json.dumps(hit) + "\n\n" + json.dumps({"event": {"category": "file"}}) + "\n")
    assert [e["CommandLine"] for e in read_ecs_ndjson(f)] == ["cmd.exe /c y"]
    with pytest.raises(LogFormatError, match="@timestamp"):
        ecs_to_sigma({"event": {"category": ["process"], "type": ["start"]}})


@pytest.mark.parametrize(("content", "msg"), [("{not json\n", "invalid JSON"), ("[1,2]\n", "JSON object")])
def test_ecs_errors(tmp_path, content, msg):
    f = tmp_path / "x.ndjson"
    f.write_text(content)
    with pytest.raises(LogFormatError, match=msg):
        read_ecs_ndjson(f)


def test_format_detection_and_time_parsing(tmp_path):
    assert load_events(EXAMPLES / "logs" / "srv01_auditbeat.ndjson")[0]["_source"].startswith("ecs:")
    assert load_events(EXAMPLES / "logs" / "ws01_windows_events.xml", "windows-xml")[0]["_source"].startswith("winxml:")
    with pytest.raises(LogFormatError, match="unknown log format"):
        load_events(EXAMPLES / "logs" / "srv01_auditbeat.ndjson", "evtx")
    assert parse_time("2026-10-26T09:00:00").tzinfo == timezone.utc
    assert parse_time("2026-10-26T09:00:00.1234567Z").microsecond == 123456
    assert parse_time(parse_time("2026-10-26T09:00:00Z")).year == 2026
    with pytest.raises(LogFormatError):
        parse_time("yesterday")
