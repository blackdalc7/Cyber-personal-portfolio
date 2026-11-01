from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import MALDOC, ROOT, SEED

from ai_analyst import cli
from ai_analyst.engine import ProviderError
from ai_analyst.evals import load_cases, markdown, run_suite
from ai_analyst.offline import OfflineProvider
from ai_analyst.watch import Watcher


class Flaky(OfflineProvider):
    def __init__(self, fail: set[str]):
        self.fail = fail

    def run(self, session, system, task, incident_id):
        if incident_id in self.fail:
            raise ProviderError("boom")
        super().run(session, system, task, incident_id)


def test_watcher(box, server, tmp_path: Path) -> None:
    clock = [1000.0]
    w = Watcher(box, server, Flaky({MALDOC}), tmp_path, clock=lambda: clock[0], backoff_s=10)
    first = w.once()
    assert len(first) == 4 and MALDOC in w.failures and not (tmp_path / f"{MALDOC}.json").exists()
    assert w.once() == []  # done ones skipped, failed one still backing off
    clock[0] += 11
    w.provider = OfflineProvider()
    assert [p.name for p in w.once()] == [f"{MALDOC}.json"] and not w.failures
    doc = json.loads((tmp_path / f"{MALDOC}.json").read_text())
    assert doc["incident_status"] == "remediated"
    doc["incident_status"] = "awaiting_approval"  # state changed in 02 since: investigate again
    (tmp_path / f"{MALDOC}.json").write_text(json.dumps(doc))
    (tmp_path / "INC-20261028-5CA11E5C.json").write_text("{broken")
    assert {p.name for p in w.once()} == {f"{MALDOC}.json", "INC-20261028-5CA11E5C.json"}


def test_watch_run_survives_errors(box, server, tmp_path: Path) -> None:
    w = Watcher(box, server, OfflineProvider(), tmp_path)
    calls, sleeps = [], []

    def once():
        calls.append(1)
        raise RuntimeError("lake mid-write")

    w.once = once
    w.run(5, sleep=sleeps.append, cycles=3)
    assert len(calls) == 3 and sleeps == [5, 5]


def test_offline_eval_suite_passes() -> None:
    cases = load_cases(ROOT / "evals")
    assert {c["kind"] for c in cases} == {"triage", "injection"} and len(cases) >= 8
    report = run_suite(ROOT / "evals", OfflineProvider, SEED)
    assert report["pass_rate"] == 1.0, markdown(report, "offline")
    text = markdown(report, "offline")
    assert "| maldoc-ransomware | triage | true_positive |" in text


def test_eval_reports_failures() -> None:
    report = run_suite(ROOT / "evals", lambda: Flaky({MALDOC}), SEED, only="maldoc")
    assert report["passed"] == 0 and report["results"][0]["error"] == "boom"
    assert "FAIL: boom" in markdown(report, "x")


@pytest.fixture
def env(monkeypatch, data_dir: Path, tmp_path: Path) -> Path:
    monkeypatch.setenv("ANALYST_LAKE_DIR", str(data_dir / "lake"))
    monkeypatch.setenv("ANALYST_CMDB_PATH", str(data_dir / "cmdb.sqlite"))
    monkeypatch.setenv("ANALYST_OUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("ANALYST_PROVIDER", "offline")
    return tmp_path


def test_cli_investigate_watch_eval(env: Path, capsys) -> None:
    assert cli.main(["investigate", "--incident", MALDOC, "--write"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "true_positive"
    assert (env / "out" / f"{MALDOC}.json").exists()
    assert cli.main(["watch", "--once"]) == 0
    assert len(list((env / "out").glob("*.json"))) == 5
    assert cli.main(["eval", "--only", "scanner", "--out", str(env / "ev")]) == 0
    assert json.loads((env / "ev" / "eval-offline.json").read_text())["passed"] == 1
    assert cli.main(["build-cmdb", "--out", str(env / "c.sqlite")]) == 0
    assert '"assets": 15' in capsys.readouterr().out


def test_cli_errors(env: Path, monkeypatch, capsys) -> None:
    assert cli.main(["investigate", "--incident", "INC-NOPE"]) == 2
    assert "no incident" in capsys.readouterr().err
    monkeypatch.setenv("ANALYST_PROVIDER", "gpt")
    assert cli.main(["watch", "--once"]) == 2
    monkeypatch.setenv("ANALYST_PROVIDER", "offline")
    assert cli.main(["--provider", "offline", "eval", "--only", "nothing-matches", "--min-pass-rate", "0.5"]) == 1


def test_committed_examples_match_console_contract() -> None:
    files = sorted((ROOT / "examples" / "output").glob("*.json"))
    assert files
    for f in files:
        doc = json.loads(f.read_text())
        assert {"incident_id", "provider", "model", "verdict", "confidence", "summary", "evidence",
                "recommended_actions", "tool_calls", "citations_valid", "created"} <= set(doc)
        assert doc["citations_valid"] is True and doc["provider"] == "offline"
        ids = {c["id"] for c in doc["tool_calls"]}
        assert all(e["tool_call"] in ids for e in doc["evidence"])
        assert all({"id", "tool", "arguments", "result_preview"} <= set(c) for c in doc["tool_calls"])
