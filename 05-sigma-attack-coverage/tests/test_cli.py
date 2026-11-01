"""Tests for the CLI subcommands and exit codes."""

import json
import subprocess
import sys

from conftest import EXAMPLES, ROOT

from attack_coverage.cli import main

LOGS = [str(EXAMPLES / "logs" / "ws01_windows_events.xml"), str(EXAMPLES / "logs" / "srv01_auditbeat.ndjson")]


def env(tmp_path):
    return ["--env-file", str(tmp_path / "none.env")]


def test_lint(tmp_path, capsys):
    assert main([*env(tmp_path), "lint", "--exercise", str(EXAMPLES / "exercise.yml")]) == 0
    assert "11 Sigma rules, 8 techniques" in capsys.readouterr().out


def test_lint_catches_tag_mismatch_and_unknown_rules(tmp_path):
    cat = tmp_path / "c.yml"
    cat.write_text(
        "techniques:\n - {id: T1057, tactic: discovery, expected_rules: [ce753259-9469-4fd9-9727-fd242d084d4f]}\n"
    )
    assert main([*env(tmp_path), "--catalog", str(cat), "lint"]) == 1
    cat.write_text(
        "techniques:\n - {id: T1057, tactic: discovery, expected_rules: [00000000-0000-4000-8000-000000000000]}\n"
    )
    assert main([*env(tmp_path), "--catalog", str(cat), "lint"]) == 1


def test_test_rules(tmp_path, capsys):
    assert main([*env(tmp_path), "test-rules", "--require-all"]) == 0
    assert "43/43 rule cases passed" in capsys.readouterr().out
    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "x.yml").write_text(
        "rule: ce753259-9469-4fd9-9727-fd242d084d4f\nno_match:\n - {Image: 'C:\\\\w\\\\whoami.exe'}\n"
    )
    assert main([*env(tmp_path), "test-rules", "--cases", str(cases)]) == 1
    (cases / "x.yml").write_text("rule: ce753259-9469-4fd9-9727-fd242d084d4f\n")
    assert main([*env(tmp_path), "test-rules", "--cases", str(cases)]) == 0
    assert main([*env(tmp_path), "test-rules", "--cases", str(cases), "--require-all"]) == 1


def test_score_writes_outputs_and_gates(tmp_path, capsys):
    out = tmp_path / "out"
    rc = main(
        [
            *env(tmp_path),
            "score",
            "--exercise",
            str(EXAMPLES / "exercise.yml"),
            "--logs",
            *LOGS,
            "--json",
            str(out / "c.json"),
            "--report",
            str(out / "c.md"),
            "--navigator",
            str(out / "layer.json"),
        ]
    )
    assert rc == 0
    assert json.loads((out / "c.json").read_text())["detection_coverage"] == 50.0
    assert json.loads((out / "layer.json").read_text())["domain"] == "enterprise-attack"
    assert (out / "c.md").read_text().startswith("# Detection coverage")
    assert "Detection coverage 50.0%" in capsys.readouterr().out
    assert (
        main(
            [
                *env(tmp_path),
                "score",
                "--exercise",
                str(EXAMPLES / "exercise.yml"),
                "--logs",
                *LOGS,
                "--min-coverage",
                "80",
            ]
        )
        == 2
    )
    assert (
        main(
            [
                *env(tmp_path),
                "score",
                "--exercise",
                str(EXAMPLES / "exercise.yml"),
                "--logs",
                *LOGS,
                "--min-coverage",
                "50",
                "--skew",
                "1",
            ]
        )
        == 0
    )


def test_errors_exit_1(tmp_path, monkeypatch):
    assert main([*env(tmp_path), "score", "--exercise", str(tmp_path / "missing.yml"), "--logs", *LOGS]) == 1
    bad = tmp_path / "bad.ndjson"
    bad.write_text("{nope\n")
    assert main([*env(tmp_path), "score", "--exercise", str(EXAMPLES / "exercise.yml"), "--logs", str(bad)]) == 1
    monkeypatch.setenv("COVERAGE_RULES_DIR", str(tmp_path / "no-rules"))
    (tmp_path / "no-rules").mkdir()
    (tmp_path / "no-rules" / "r.yml").write_text("title: x\n")
    assert main([*env(tmp_path), "lint"]) == 1


def test_module_entry_point():
    proc = subprocess.run(
        [sys.executable, "-m", "attack_coverage", "lint"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
