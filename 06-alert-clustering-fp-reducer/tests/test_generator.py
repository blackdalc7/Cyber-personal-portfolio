"""Tests for the simulated alert generator."""

import json

import pytest

from alert_triage import generator
from alert_triage.alerts import load_alerts


def test_deterministic_and_labelled():
    a, b = generator.generate(1000, seed=3), generator.generate(1000, seed=3)
    assert a == b and a != generator.generate(1000, seed=4)
    assert abs(len(a) - 1000) <= len(generator.SCENARIOS)
    assert {x["label"] for x in a} == {"benign", "false_positive", "true_positive"}
    assert {x["scenario"] for x in a} == {s.name for s in generator.SCENARIOS}
    assert [x["id"] for x in a[:2]] == ["SIM-000001", "SIM-000002"]


def test_write_round_trips(tmp_path):
    out = tmp_path / "x" / "alerts.json"
    n = generator.write(out, 200, seed=1)
    doc = json.loads(out.read_text())
    assert doc["simulated"] is True and len(doc["alerts"]) == n
    assert len(load_alerts(out)) == n


def test_count_floor():
    with pytest.raises(ValueError):
        generator.generate(3)
