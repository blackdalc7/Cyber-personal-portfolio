from __future__ import annotations

import json

from conftest import RULES

from detection_rules import cli


def env(monkeypatch, tmp_path, **extra):
    monkeypatch.setenv("RULES_BUILD_DIR", str(tmp_path / "build"))
    monkeypatch.setenv("RULES_LAKE_DIR", str(tmp_path / "lake"))
    monkeypatch.setenv("RULES_STATE_FILE", str(tmp_path / "state.json"))
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_test_and_build(monkeypatch, tmp_path, capsys):
    env(monkeypatch, tmp_path)
    assert cli.main(["test", "-q"]) == 0
    assert "26/26 rule tests passed" in capsys.readouterr().out
    assert cli.main(["build"]) == 0
    idx = json.loads((tmp_path / "build" / "rules_index.json").read_text())
    assert len(idx["rules"]) == 7 and all(t["passed"] for r in idx["rules"] for t in r["tests"])


def test_failing_samples_fail_the_build(monkeypatch, tmp_path, capsys):
    env(monkeypatch, tmp_path, RULES_SAMPLES_DIR=str(tmp_path / "nosamples"))
    assert cli.main(["test"]) == 1
    assert "FAIL" in capsys.readouterr().out
    assert cli.main(["build"]) == 1


def test_convert(capsys):
    assert cli.main(["convert", str(RULES / "linux" / "proc_creation_lnx_local_account_created.yml")]) == 0
    assert "SELECT uid" in capsys.readouterr().out


def test_run_dry(monkeypatch, tmp_path, capsys):
    env(monkeypatch, tmp_path)
    assert cli.main(["run", "--dry-run"]) == 0
    assert json.loads((tmp_path / "state.json").read_text())["watermark"]


def test_run_needs_hub(monkeypatch, tmp_path, capsys):
    env(monkeypatch, tmp_path, RULES_HUB_URL="", RULES_INGEST_TOKEN="")
    assert cli.main(["run"]) == 2
    assert "RULES_HUB_URL" in capsys.readouterr().err


def test_bad_env(monkeypatch, tmp_path, capsys):
    env(monkeypatch, tmp_path, RULES_OVERLAP_S="soon")
    assert cli.main(["test"]) == 2
    env(monkeypatch, tmp_path, RULES_OVERLAP_S="-1")
    assert cli.main(["test"]) == 2
