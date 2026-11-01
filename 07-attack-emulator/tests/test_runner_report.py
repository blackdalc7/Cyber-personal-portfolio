from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone

from attack_emulator.executors import ExecResult
from attack_emulator.poller import Observation
from attack_emulator.report import markdown, navigator_layer, run_doc, summarise, write_outputs
from attack_emulator.runner import new_run_id, run_campaign


class ScriptedExecutor:
    def __init__(self, results):
        self.results, self.cleaned, self.ran = results, [], []

    def run(self, test, target):
        self.ran.append(test.technique)
        return self.results[test.technique]

    def cleanup(self, test, target):
        self.cleaned.append(test.technique)
        return ExecResult(0, 0, 0)

    def close(self):
        pass


def test_new_run_id():
    rid = new_run_id(datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc))
    assert rid.startswith("run-20261001T093000Z-") and len(rid) == 27


def test_run_campaign_outcomes(campaign, settings, monkeypatch):
    calls = []

    def fake_wait(hub, **kw):
        calls.append(kw)
        return Observation("detected", ttd_ms=1200, findings=[{"title": "t", "product": "p"}], telemetry_events=4,
                           polls=2)

    monkeypatch.setattr("attack_emulator.runner.wait_for_detection", fake_wait)
    ex = ScriptedExecutor({"T1003.008": ExecResult(1000, 2000, 0, "ok"),
                           "T1059.001": ExecResult(1000, 2000, 1, "", "blocked", prevented=True)})
    sleeps = []
    c = replace(campaign, settle_s=5)
    res = run_campaign(c, settings, {"kubectl": ex, "winrm": ex}, hub=object(), run_id="run-x", sleep=sleeps.append)
    a, b = res.cells
    assert (a.outcome, a.ttd_ms, a.telemetry_events, a.hostname) == ("detected", 1200, 4, "lab-k8s")
    assert b.outcome == "prevented" and b.ttd_ms is None
    assert calls[0]["match"] == "shadow" and calls[0]["technique"] == "T1003.008"
    assert ex.cleaned == ["T1003.008", "T1059.001"] and sleeps == [5]
    assert not res.dry_run


def test_run_campaign_errors_skips_and_only(campaign, settings):
    ex = ScriptedExecutor({"T1003.008": ExecResult(1, 2, 127, executed=False, error="kubectl not found"),
                           "T1059.001": ExecResult(1, 2, 255, error="ConnectionError")})
    res = run_campaign(campaign, settings, {"kubectl": ex, "winrm": ex}, hub=object(), run_id="r", sleep=lambda s: None)
    assert [c.outcome for c in res.cells] == ["error", "error"]
    assert ex.cleaned == ["T1059.001"]  # never clean up what did not run
    ex2 = ScriptedExecutor({"T1003.008": ExecResult(1, 2, 0, executed=False),
                            "T1059.001": ExecResult(1, 2, 0)})
    res = run_campaign(campaign, settings, {"kubectl": ex2, "winrm": ex2}, hub=None, run_id="r", only={"T1059"},
                       sleep=lambda s: None)
    assert ex2.ran == ["T1059.001"] and [c.outcome for c in res.cells] == ["skipped"] and res.dry_run


def cells():
    base = {"technique": "T1", "name": "n", "target": "k8s", "test": "T1#1", "ttd_ms": None, "findings": []}
    return [
        {**base, "technique": "T1003.008", "outcome": "detected", "ttd_ms": 2000,
         "findings": [{"title": "Shadow read", "product": "detection-rules"}]},
        {**base, "technique": "T1003.008", "outcome": "telemetry_only"},
        {**base, "technique": "T1059.001", "outcome": "detected", "ttd_ms": 4000},
        {**base, "technique": "T1003.001", "outcome": "prevented"},
        {**base, "technique": "T1070.003", "outcome": "telemetry_only"},
        {**base, "technique": "T1562.001", "outcome": "missed"},
        {**base, "technique": "T1046", "outcome": "error"},
        {**base, "technique": "T1087", "outcome": "skipped"},
    ]


def test_summarise():
    s = summarise(cells())
    assert s["total"] == 8 and s["scored"] == 6 and s["error"] == 1 and s["skipped"] == 1
    assert s["detection_coverage"] == 50.0 and s["telemetry_coverage"] == 83.3 and s["mean_ttd_ms"] == 3000
    assert summarise([])["detection_coverage"] == 0.0


def doc():
    return {"kind": "emulation-run", "run_id": "run-1", "campaign": "unit", "summary": summarise(cells()),
            "results": cells()}


def test_navigator_worst_outcome_wins():
    layer = navigator_layer(doc())
    by = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by["T1003.008"]["score"] == 1  # telemetry_only beats detected when it ran twice
    assert by["T1059.001"]["comment"] == "detected, TTD 4.0s"
    assert "T1046" not in by and "T1087" not in by
    assert layer["versions"]["layer"] == "4.5"


def test_markdown_and_outputs(tmp_path, campaign, settings):
    md = markdown(doc())
    assert "Detection coverage **50.0%**" in md and "Shadow read (detection-rules)" in md
    assert "write or tune a rule" in md and "fix the sensor" in md
    from attack_emulator.runner import RunResult
    rr = RunResult("run-2", "unit", 1, 2, [])
    d = run_doc(rr)
    assert d["kind"] == "emulation-run" and d["summary"]["total"] == 0
    paths = write_outputs(d, tmp_path / "o")
    assert json.loads(paths["run"].read_text())["run_id"] == "run-2"
    assert json.loads(paths["navigator"].read_text())["techniques"] == []
    assert "## Gaps" not in paths["markdown"].read_text()
