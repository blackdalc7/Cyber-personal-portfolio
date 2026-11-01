"""Tests for the CLI subcommands and quality gates."""

import json

import pytest
from conftest import REQUIREMENTS, SEED

from alert_triage.cli import main


@pytest.fixture
def env(tmp_path, monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "TRIAGE_LLM_PROVIDER", "TRIAGE_ALGORITHM", "TRIAGE_DBSCAN_EPS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TRIAGE_DB_PATH", str(tmp_path / "cmdb.sqlite"))
    assert main(["--env-file", str(tmp_path / "none.env"), "init-cmdb", "--seed", str(SEED)]) == 0
    assert main(["generate", "--count", "2000", "--seed", "7", "--out", str(tmp_path / "alerts.json")]) == 0
    return tmp_path


def test_triage_end_to_end(env, capsys):
    md, js = env / "out" / "queue.md", env / "out" / "queue.json"
    rc = main(
        [
            "triage",
            "--alerts",
            str(env / "alerts.json"),
            "--requirements",
            str(REQUIREMENTS),
            "--report",
            str(md),
            "--json",
            str(js),
        ]
    )
    assert rc == 0 and "meta-alerts -> queue of" in capsys.readouterr().out
    doc = json.loads(js.read_text())
    m = doc["metrics"]
    # Sparser data means longer gaps, so some behaviours split into more than one session.
    assert m["raw_alerts"] > 1900 and m["meta_alerts"] < 40 and m["analyst_queue"] <= 20
    assert doc["evaluation"]["true_threat_recall"] == 1.0 and doc["evaluation"]["suppression_precision"] == 1.0
    assert {"STRUCTURAL_FP", "AUTHORIZED_SCANNER", "MAINTENANCE_WINDOW"} <= set(m["suppression_reasons"])
    text = md.read_text()
    for heading in ("## Summary", "## Queue", "## Suppressed", "## Evaluation against ground truth", "Simulated data"):
        assert heading in text
    assert "<" not in text.split("## Queue")[1].replace("&lt;", "")


def test_evaluate_gates(env, capsys):
    assert main(["evaluate", "--alerts", str(env / "alerts.json")]) == 0
    assert json.loads(capsys.readouterr().out)["evaluation"]["cluster_purity"] == 1.0
    assert main(["evaluate", "--alerts", str(env / "alerts.json"), "--min-precision", "1.01"]) == 2


def test_evaluate_requires_labels(env):
    (env / "plain.json").write_text(json.dumps([{"timestamp": "2026-10-26T10:00:00Z", "rule": "R"}]))
    assert main(["evaluate", "--alerts", str(env / "plain.json")]) == 1


def test_kmeans_offline_and_fail_on_escalate(env):
    rc = main(
        ["triage", "--alerts", str(env / "alerts.json"), "--algorithm", "kmeans", "--offline", "--fail-on-escalate"]
    )
    assert rc == 3


def test_errors(env, tmp_path):
    assert main(["--db", str(tmp_path / "missing.sqlite"), "triage", "--alerts", str(env / "alerts.json")]) == 1
    assert main(["triage", "--alerts", str(env / "alerts.json"), "--eps", "2"]) == 1
    assert main(["triage", "--alerts", str(tmp_path / "nope.json")]) == 1


def test_no_queue_and_no_suppression_tables(env, capsys):
    (env / "one.json").write_text(
        json.dumps([{"timestamp": "2026-10-26T02:00:00Z", "rule": "PostgreSQL stopped", "dst_ip": "10.20.3.30"}])
    )
    md = env / "one.md"
    assert main(["triage", "--alerts", str(env / "one.json"), "--report", str(md)]) == 0
    assert "Nothing left to review" in md.read_text()
    (env / "two.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-10-26T12:00:00Z",
                    "rule": "Odd | <b>thing</b>",
                    "dst_ip": "10.20.9.9",
                    "src_ip": "198.51.100.1",
                }
            ]
        )
    )
    assert main(["triage", "--alerts", str(env / "two.json"), "--report", str(md)]) == 0
    text = md.read_text()
    assert "Nothing suppressed" in text and "Odd \\| &lt;b&gt;thing&lt;/b&gt;" in text
