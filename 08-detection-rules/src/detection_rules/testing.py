"""Rule tests: every rule ships samples that must match and samples that must not, run on an in-memory lake."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .lake import memory_lake
from .rules import CompiledRule

OCSF_VERSION = "1.4.0"
CATEGORY = {1001: 1, 1007: 1, 3002: 3, 4001: 4}
WINDOW = (0, 2**62)  # tests ignore time


@dataclass(frozen=True)
class RuleTestResult:
    rule_id: str
    name: str
    expected: int
    got: int

    @property
    def passed(self) -> bool:
        return self.expected == self.got

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "expected": self.expected, "got": self.got, "passed": self.passed}


def envelope(event: dict[str, Any], *, uid: str, time: int = 1_790_845_200_000) -> dict[str, Any]:
    """Fill in the parts of an OCSF event that samples leave out."""
    doc = copy.deepcopy(event)
    cls, act = int(doc["class_uid"]), int(doc["activity_id"])
    doc.setdefault("category_uid", CATEGORY.get(cls, cls // 1000))
    doc.setdefault("type_uid", cls * 100 + act)
    doc.setdefault("severity_id", 1)
    doc.setdefault("time", time)
    doc.setdefault("device", {"hostname": "sample-host"})
    meta = doc.setdefault("metadata", {})
    meta.setdefault("version", OCSF_VERSION)
    meta.setdefault("uid", uid)
    meta.setdefault("product", {"name": "rule-samples", "vendor_name": "Watchfloor portfolio"})
    return doc


def load_samples(samples_dir: Path, rule: CompiledRule) -> dict[str, list[dict[str, Any]]]:
    path = Path(samples_dir) / f"{rule.stem}.yml"
    if not path.is_file():
        return {}
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, list[dict[str, Any]]] = {}
    for kind in ("match", "nomatch"):
        out[kind] = [{"name": s["name"], "event": envelope(s["event"], uid=f"{rule.stem}:{kind}:{i}")}
                     for i, s in enumerate(doc.get(kind) or [])]
    return out


def run_rule_tests(rule: CompiledRule, samples_dir: Path) -> list[RuleTestResult]:
    """One result per sample, plus a failing result if the rule has no match/nomatch samples at all."""
    samples = load_samples(samples_dir, rule)
    results = []
    for kind, expected in (("match", 1), ("nomatch", 0)):
        items = samples.get(kind) or []
        if not items:
            results.append(RuleTestResult(rule.id, f"{kind}: missing samples", 1, 0))
        for s in items:
            con = memory_lake([s["event"]])
            got = len(con.execute(rule.sql, list(WINDOW)).fetchall())
            con.close()
            results.append(RuleTestResult(rule.id, f"{kind}: {s['name']}", expected, got))
    return results
