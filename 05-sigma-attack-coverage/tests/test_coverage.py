"""Tests for exercise scoring and the coverage outputs."""

import json
from datetime import timedelta

import pytest
from conftest import ROOT

from attack_coverage.catalog import CatalogError, load_catalog, load_exercise
from attack_coverage.coverage import (
    DETECTED,
    DETECTION_GAP,
    NO_CONTENT,
    TELEMETRY_GAP,
    evaluate,
    navigator_layer,
    to_json,
    to_markdown,
)
from attack_coverage.ruletests import run_rule_tests


@pytest.fixture(scope="module")
def report(exercise, catalog, rules, events):
    return evaluate(exercise, catalog, rules, events)


def outcomes(report):
    return {t.technique.id: t.outcome for t in report.techniques}


def test_example_exercise_outcomes(report):
    assert outcomes(report) == {
        "T1033": DETECTED,
        "T1059.001": DETECTED,
        "T1059.003": DETECTED,
        "T1059.004": DETECTED,
        "T1016": DETECTION_GAP,
        "T1083": DETECTION_GAP,
        "T1057": NO_CONTENT,
        "T1082": TELEMETRY_GAP,
    }
    assert report.detection_coverage == 50.0
    assert report.telemetry_coverage == 87.5
    assert report.by_tactic() == {"discovery": (1, 5), "execution": (3, 3)}


def test_worst_step_decides_and_steps_keep_detail(report):
    t1082 = next(t for t in report.techniques if t.technique.id == "T1082")
    assert [s.outcome for s in t1082.steps] == [DETECTED, DETECTED, TELEMETRY_GAP]
    t1083 = next(t for t in report.techniques if t.technique.id == "T1083")
    ws01 = next(s for s in t1083.steps if s.step.host == "ws01")
    # 'cmd /c dir' is not recursive, so the T1083 rule stays quiet, but the cmd rule still fires
    assert ws01.matched_rules == [] and ws01.other_rules == ["7190ed3f-8657-4c1b-96fd-353776fb15d2"]


def test_window_and_skew(exercise, catalog, rules, events):
    # Pretend the log source's clock runs 12 s fast: events land just outside each 10 s step window.
    shifted = [{**e, "_time": e["_time"] + timedelta(seconds=12)} for e in events]
    strict = evaluate(exercise, catalog, rules, shifted, skew_s=0)
    loose = evaluate(exercise, catalog, rules, shifted, skew_s=30)
    assert strict.detection_coverage < loose.detection_coverage == 50.0


def test_unknown_rule_in_catalogue_is_an_error(exercise, catalog, events):
    with pytest.raises(ValueError, match="unknown Sigma rule"):
        evaluate(exercise, catalog, [], events)


def test_outputs(report, rules):
    by_id = {r.id: r for r in rules}
    doc = to_json(report, by_id)
    assert doc["detection_coverage"] == 50.0
    t1033 = next(t for t in doc["techniques"] if t["id"] == "T1033")
    assert {r["title"] for s in t1033["steps"] for r in s["matched_rules"]} == {
        "Local User Discovery via Whoami",
        "Linux Current User Discovery",
    }
    json.dumps(doc)
    layer = navigator_layer(report)
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1033"] == 100 and scores["T1082"] == 0 and scores["T1016"] == 50
    md = to_markdown(report, by_id)
    assert "**Detection coverage: 50.0%**" in md and "| discovery | 1 / 5 |" in md
    assert "## Hosts with no process telemetry" in md and "**ws02** (windows)" in md
    assert "ss -tunap" in md and "Detection engineering" in md


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


@pytest.mark.parametrize(
    ("text", "msg"),
    [
        ("techniques:\n - {id: X1, tactic: discovery}\n", "id must look like"),
        ("techniques:\n - {id: T1000, tactic: sleeping}\n", "unknown tactic"),
        ("techniques:\n - {id: T1000, tactic: discovery}\n - {id: T1000, tactic: discovery}\n", "duplicate"),
        ("- a list\n", "mapping"),
    ],
)
def test_catalog_validation(tmp_path, text, msg):
    with pytest.raises(CatalogError, match=msg):
        load_catalog(write(tmp_path, "c.yml", text))


@pytest.mark.parametrize(
    ("text", "msg"),
    [
        ("steps:\n - {technique: T9999, host: a, start: 2026-01-01T00:00:00Z, end: 2026-01-01T00:01:00Z}\n", "not in"),
        ("steps:\n - {technique: T1033, start: 2026-01-01T00:00:00Z, end: 2026-01-01T00:01:00Z}\n", "'host'"),
        (
            "steps:\n - {technique: T1033, host: a, start: '2026-01-01T00:02:00Z', end: '2026-01-01T00:01:00Z'}\n",
            "before",
        ),
        ("steps:\n - {technique: T1033, host: a, start: soon, end: later}\n", "unparseable"),
        ("name: empty\n", "no steps"),
    ],
)
def test_exercise_validation(tmp_path, catalog, text, msg):
    with pytest.raises(CatalogError, match=msg):
        load_exercise(write(tmp_path, "e.yml", text), catalog)


def test_bundled_rule_cases_all_pass(rules):
    total, failures, untested = run_rule_tests(ROOT / "rule-tests", {r.id: r for r in rules})
    assert total >= 40 and failures == [] and untested == []


def test_rule_case_runner_reports_failures(tmp_path, rules):
    write(tmp_path, "c.yml", "rule: ce753259-9469-4fd9-9727-fd242d084d4f\nmatch:\n - {Image: 'C:\\x\\notepad.exe'}\n")
    total, failures, untested = run_rule_tests(tmp_path, {r.id: r for r in rules})
    assert total == 1 and len(failures) == 1 and "should match" in str(failures[0]) and len(untested) == 10
    write(tmp_path, "d.yml", "rule: 00000000-0000-4000-8000-00000000dead\n")
    with pytest.raises(ValueError, match="unknown rule id"):
        run_rule_tests(tmp_path, {r.id: r for r in rules})
