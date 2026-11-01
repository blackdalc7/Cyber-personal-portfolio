"""Evaluate a rule set against normalised events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .rule import SigmaRule


@dataclass(frozen=True)
class RuleMatch:
    """One rule matching one event."""
    rule_id: str
    rule_title: str
    level: str
    event: Mapping[str, Any]


class SigmaMatcher:
    """Match events against a set of loaded Sigma rules."""
    def __init__(self, rules: Iterable[SigmaRule]) -> None:
        self.rules = {r.id: r for r in rules}

    def match(self, events: Iterable[Mapping[str, Any]], rule_ids: Iterable[str] | None = None) -> list[RuleMatch]:
        """Return every ``(rule, event)`` match, optionally limited to ``rule_ids``.

        A rule is only tested against events whose ``_logsource`` fits the rule's logsource.
        """
        wanted = self.rules.keys() if rule_ids is None else rule_ids
        rules = [self.rules[i] for i in wanted if i in self.rules]
        out = []
        for ev in events:
            src = ev.get("_logsource", {})
            for r in rules:
                if r.applies_to(src) and r.matches(ev):
                    out.append(RuleMatch(r.id, r.title, r.level, ev))
        return out
