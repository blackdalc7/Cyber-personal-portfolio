"""Detection-as-code unit tests: each rule ships with events it must and must not match.

rule-tests/<anything>.yml::

    rule: ce753259-9469-4fd9-9727-fd242d084d4f
    match:
      - {Image: 'C:\\Windows\\System32\\whoami.exe', CommandLine: whoami /all}
    no_match:
      - {Image: 'C:\\Tools\\whoami-helper.exe'}

Events take the rule's logsource automatically, so cases only list the fields that matter.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .sigma import SigmaRule


@dataclass(frozen=True)
class CaseFailure:
    """One failed detection-as-code test case: the event a rule should or should not have matched."""
    file: str
    rule: str
    kind: str      # "match" or "no_match"
    index: int
    event: dict

    def __str__(self) -> str:
        want = "should match" if self.kind == "match" else "should NOT match"
        return f"{self.file}: rule {self.rule} {want} {self.kind}[{self.index}] {self.event}"


def run_rule_tests(directory: str | Path, rules: dict[str, SigmaRule]) -> tuple[int, list[CaseFailure], list[str]]:
    """Returns (cases run, failures, ids of rules without any test file)."""
    total, failures, tested = 0, [], set()
    for f in sorted(Path(directory).glob("*.y*ml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        rid = str(doc.get("rule", ""))
        if rid not in rules:
            raise ValueError(f"{f}: unknown rule id {rid!r}")
        tested.add(rid)
        rule = rules[rid]
        for kind, expect in (("match", True), ("no_match", False)):
            for i, ev in enumerate(doc.get(kind) or []):
                total += 1
                event = {**ev, "_logsource": dict(rule.logsource)}
                if rule.matches(event) is not expect:
                    failures.append(CaseFailure(f.name, rid, kind, i, dict(ev)))
    return total, failures, sorted(set(rules) - tested)
