"""Tests for alert normalisation and file loading."""

import json

import pytest

from alert_triage.alerts import AlertFormatError, load_alerts, normalise


def test_generic_record():
    a = normalise(
        {
            "id": "1",
            "timestamp": "2026-10-26T10:00:00Z",
            "rule": "R",
            "severity": "crit",
            "src_ip": "198.51.100.1",
            "dst_ip": "10.0.0.1",
            "dst_port": "443",
            "protocol": "TCP",
            "label": "benign",
        }
    )
    assert a.severity == "critical" and a.dst_port == 443 and a.protocol == "tcp" and a.timestamp.tzinfo
    assert a.signature == "R" and a.label == "benign" and a.category == "uncategorised"


def test_ecs_nested_and_dotted():
    nested = {
        "@timestamp": "2026-10-26T10:00:00+00:00",
        "rule": {"name": "SIEM-AUTH-001"},
        "event": {"severity": 73, "id": "e1"},
        "source": {"ip": "203.0.113.5"},
        "destination": {"ip": "10.0.0.2", "port": 22},
        "network": {"transport": "tcp"},
        "message": "brute force",
    }
    a = normalise(nested)
    assert (a.id, a.rule, a.severity, a.src_ip, a.dst_port, a.signature) == (
        "e1",
        "SIEM-AUTH-001",
        "high",
        "203.0.113.5",
        22,
        "brute force",
    )
    dotted = normalise({"@timestamp": 1_790_000_000, "rule.name": "X", "event.severity": 99})
    assert dotted.severity == "critical" and dotted.src_ip == "" and len(dotted.id) == 16


@pytest.mark.parametrize(
    ("value", "expected"),
    [(21, "low"), (47, "medium"), (2, "medium"), ("nonsense", "medium"), (None, "medium"), ("info", "informational")],
)
def test_severity_mapping(value, expected):
    assert normalise({"timestamp": "2026-10-26T10:00:00", "rule": "R", "severity": value}).severity == expected


def test_bad_fields_are_dropped_not_fatal():
    a = normalise({"timestamp": "2026-10-26T10:00:00", "rule": "R", "src_ip": "not-an-ip", "dst_port": 70000})
    assert a.src_ip == "" and a.dst_port is None
    assert normalise({"timestamp": "2026-10-26T10:00:00", "rule": "R", "dst_port": "x"}).dst_port is None


@pytest.mark.parametrize("doc", [{"rule": "R"}, {"timestamp": "yesterday", "rule": "R"}, {"timestamp": 1}, "str"])
def test_invalid_records(doc):
    with pytest.raises(AlertFormatError):
        normalise(doc)


def test_load_formats(tmp_path):
    recs = [{"timestamp": f"2026-10-26T10:00:0{i}Z", "rule": "R", "id": str(i)} for i in (2, 1)]
    for name, text in (
        ("a.json", json.dumps(recs)),
        ("b.json", json.dumps({"alerts": recs})),
        ("c.ndjson", "\n".join(json.dumps(r) for r in recs) + "\n"),
    ):
        (tmp_path / name).write_text(text)
        assert [a.id for a in load_alerts(tmp_path / name)] == ["1", "2"]  # sorted by time
    (tmp_path / "d.json").write_text(json.dumps(recs[0]))
    assert len(load_alerts(tmp_path / "d.json")) == 1
    (tmp_path / "e.json").write_text("   ")
    assert load_alerts(tmp_path / "e.json") == []


@pytest.mark.parametrize(
    ("text", "match"),
    [("hello", "expected JSON"), ('{"a":1}\n{bad', ":2: invalid JSON"), ('[{"rule": "R"}]', "record 0")],
)
def test_load_errors(tmp_path, text, match):
    (tmp_path / "x.json").write_text(text)
    with pytest.raises(AlertFormatError, match=match):
        load_alerts(tmp_path / "x.json")
