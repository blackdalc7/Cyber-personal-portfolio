"""Tests for the rotating NDJSON sinks."""

import json

from realtime_siem.sinks import NdjsonSink


def test_ndjson_roundtrip(tmp_path):
    sink = NdjsonSink("events", tmp_path, max_bytes=1_000_000, backup_count=2)
    sink.write({"a": 1, "b": "ü"})
    sink.write({"a": 2})
    sink.close()
    lines = (tmp_path / "events.ndjson").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["a"] for line in lines] == [1, 2]
    assert "ü" in lines[0]


def test_rotation_caps_disk_usage(tmp_path):
    sink = NdjsonSink("events", tmp_path, max_bytes=2048, backup_count=3)
    for i in range(500):
        sink.write({"i": i, "pad": "x" * 100})
    sink.close()
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == ["events.ndjson", "events.ndjson.1", "events.ndjson.2", "events.ndjson.3"]
    assert all(p.stat().st_size <= 2048 + 200 for p in tmp_path.iterdir())
    newest = json.loads((tmp_path / "events.ndjson").read_text().splitlines()[-1])
    assert newest["i"] == 499


def test_sinks_are_isolated(tmp_path):
    a = NdjsonSink("alerts", tmp_path, 10_000, 1)
    b = NdjsonSink("events", tmp_path, 10_000, 1)
    a.write({"k": "alert"})
    b.write({"k": "event"})
    a.close()
    b.close()
    assert "event" not in (tmp_path / "alerts.ndjson").read_text()
    assert "alert" not in (tmp_path / "events.ndjson").read_text()
