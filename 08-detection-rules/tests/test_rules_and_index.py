from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from conftest import RULES, SAMPLES, rule_yaml

from detection_rules.index import build_index, write_build
from detection_rules.rules import CompiledRule, RuleError, compile_file, load_rules
from detection_rules.testing import load_samples, run_rule_tests


def test_shipped_rules_compile_and_carry_metadata(rules):
    assert len(rules) == 7
    by = {r.stem: r for r in rules}
    shadow = by["file_access_lnx_shadow_read"]
    assert shadow.techniques == ("T1003.008",) and shadow.tactics == ("credential-access",)
    assert shadow.logsource == "linux:file_access" and shadow.severity_id == 4 and shadow.tuned_from
    assert shadow.path == "rules/linux/file_access_lnx_shadow_read.yml"
    assert by["proc_creation_win_system_binary_masquerade"].techniques == ("T1036.003", "T1036.005")
    assert all(r.sql.startswith("SELECT ") and "time >= ? AND time < ?" in r.sql for r in rules)


@pytest.mark.parametrize("stem", [p.stem for p in sorted(RULES.rglob("*.yml"))])
def test_every_rule_passes_its_samples(rules, stem):
    rule = next(r for r in rules if r.stem == stem)
    results = run_rule_tests(rule, SAMPLES)
    assert results and all(t.passed for t in results), [t for t in results if not t.passed]
    kinds = {t.name.split(":")[0] for t in results}
    assert kinds == {"match", "nomatch"}


def test_rule_without_samples_fails(tmp_path, rules):
    results = run_rule_tests(rules[0], tmp_path)
    assert [t.passed for t in results] == [False, False]
    assert load_samples(tmp_path, rules[0]) == {}


def write(tmp_path, name, text):
    d = tmp_path / "rules"
    d.mkdir(exist_ok=True)
    (d / name).write_text(text)
    return d


def test_rule_errors(tmp_path):
    d = write(tmp_path, "a.yml", rule_yaml("  sel:\n    Image: x\n  condition: sel"))
    with pytest.raises(RuleError, match="no rules"):
        load_rules(tmp_path / "empty")
    write(tmp_path, "b.yml", rule_yaml("  sel:\n    Image: y\n  condition: sel"))
    with pytest.raises(RuleError, match="duplicate rule ids"):
        load_rules(d)
    (d / "b.yml").write_text(rule_yaml("  sel:\n    Image: y\n  condition: sel").replace("id: 1111", "id: 2111"))
    assert len(load_rules(d)) == 2
    (d / "c.yml").write_text("title: no id\nlogsource: {category: process_creation}\n"
                             "detection: {sel: {Image: x}, condition: sel}\n")
    with pytest.raises(RuleError, match="needs an id"):
        compile_file(d / "c.yml", d)
    (d / "c.yml").write_text(rule_yaml("  sel:\n    Image: x\n  condition: sel", "registry_set"))
    with pytest.raises(RuleError, match="no OCSF class mapping"):
        compile_file(d / "c.yml", d)
    (d / "c.yml").write_text(rule_yaml("  sel:\n    Image: x\n  condition: sel") + "---\n" +
                             rule_yaml("  sel:\n    Image: z\n  condition: sel").replace("id: 1111", "id: 3111"))
    with pytest.raises(RuleError, match="one rule per file"):
        compile_file(d / "c.yml", d)


def test_compiled_rule_defaults():
    r = CompiledRule(id="x", title="t", status="test", level="weird", description="", techniques=(), tactics=(),
                     logsource="", path="rules/x.yml", sql="SELECT 1")
    assert r.severity_id == 3 and r.stem == "x"


def test_index_and_build(rules, tmp_path):
    tests = {r.id: run_rule_tests(r, SAMPLES) for r in rules}
    idx = build_index(rules, tests, generated=datetime(2026, 10, 1, 9, 0, 0, 123, tzinfo=timezone.utc))
    assert idx["generated"] == "2026-10-01T09:00:00Z" and len(idx["rules"]) == 7
    info = idx["rules"][0]
    assert set(info) >= {"id", "title", "status", "level", "techniques", "logsource", "tests", "path", "queries",
                         "tuned_from", "description"}
    assert info["queries"]["duckdb"].startswith("SELECT")
    out = write_build(idx, rules, tmp_path / "build")
    assert json.loads(out.read_text())["rules"][0]["id"] == info["id"]
    assert len(list((tmp_path / "build" / "queries").glob("*.sql"))) == 7
