"""Enrich meta-alerts with CMDB context, decide a disposition, and rank the queue.

Decision order (first match wins):

1. ``AUTHORIZED_SCANNER``: every source is inside a registered scanner range. Suppress.
2. ``MAINTENANCE_WINDOW``: every target is in a maintenance window for the whole cluster. Suppress.
3. ``STRUCTURAL_FP``: every target is a known asset that lacks the OS, port or product the
   signature needs (``applicability.py``). Suppress. This is the deterministic version of
   "RDP exploit against a Linux web server cannot succeed".
4. Otherwise ask the triager (Claude, or the offline rules) and apply the guardrail:
   a model-only suppression needs ``confidence >= min_confidence``, no target with
   criticality >= 4, and severity below critical. Anything else stays in the queue.

The deterministic checks run first because they are free, explainable, and cannot be
talked out of their answer by text inside an alert.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .applicability import Applicability
from .cluster import MetaAlert
from .cmdb import Asset, Cmdb
from .llm import OfflineTriager, Triager, Verdict

ESCALATE, INVESTIGATE, SUPPRESS = "escalate", "investigate", "suppress"
DISPOSITION_ORDER = {ESCALATE: 0, INVESTIGATE: 1, SUPPRESS: 2}
VERDICT_WEIGHT = {"true_positive": 1.0, "needs_investigation": 0.8, "benign_true_positive": 0.45,
                  "false_positive": 0.3}
CRITICALITY_CEILING = 4          # a model alone may not suppress alerts on assets this critical
MAX_CONTEXT_ASSETS = 10


@dataclass
class Triage:
    """Final decision for one meta-alert: disposition, reason, priority and the context behind it."""
    meta: MetaAlert
    disposition: str
    reason: str
    explanation: str
    priority: float
    target_assets: list[Asset] = field(default_factory=list)
    unknown_targets: list[str] = field(default_factory=list)
    source_assets: list[Asset] = field(default_factory=list)
    verdict: Verdict | None = None
    flags: list[str] = field(default_factory=list)

    @property
    def max_criticality(self) -> int:
        """Highest CMDB criticality among the meta-alert's source and target assets."""
        return max((a.criticality for a in self.target_assets + self.source_assets), default=0)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the decision and its context for the JSON queue."""
        return {
            **self.meta.summary(), "disposition": self.disposition, "reason": self.reason,
            "explanation": self.explanation, "priority": self.priority, "flags": self.flags,
            "max_criticality": self.max_criticality,
            "target_assets": [a.context() for a in self.target_assets[:MAX_CONTEXT_ASSETS]],
            "unknown_targets": self.unknown_targets[:MAX_CONTEXT_ASSETS],
            "source_assets": [a.context() for a in self.source_assets[:MAX_CONTEXT_ASSETS]],
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "labels": dict(self.meta.labels),
        }


def priority_score(meta: MetaAlert, targets: list[Asset], sources: list[Asset], unknown: list[str],
                   verdict_weight: float) -> float:
    """0-100. Severity, asset criticality, exposure, volume and spread, scaled by the verdict."""
    severity = max(a.severity_rank for a in meta.alerts) / 4
    crits = [a.criticality for a in targets + sources]
    criticality = max(max(crits, default=0) / 5, 0.6 if unknown else 0.0)
    exposure = 1.0 if any(a.internet_facing for a in targets) else 0.5
    volume = min(1.0, math.log10(meta.count + 1) / 3)
    spread = min(1.0, math.log10(len(meta.targets) + len(meta.sources) + 1) / 2)
    base = 0.4 * severity + 0.3 * criticality + 0.1 * exposure + 0.1 * volume + 0.1 * spread
    return round(100 * verdict_weight * base, 1)


class TriageEngine:
    """Decide what happens to each meta-alert: escalate, investigate or suppress.

    Order of checks:

    1. Deterministic rules (authorised scanner, maintenance window, structurally
       impossible attack) suppress with a fixed reason and no LLM call.
    2. Everything else goes to the triager (Claude or the offline rules).
    3. Guardrails stop the model from suppressing alerts that are low-confidence,
       critical severity, aimed at critical assets or at hosts missing from the CMDB.
    """
    def __init__(self, cmdb: Cmdb, applicability: Applicability, triager: Triager | None = None,
                 min_confidence: float = 0.8, workers: int = 4) -> None:
        self.cmdb = cmdb
        self.applicability = applicability
        self.triager = triager or OfflineTriager()
        self.min_confidence = min_confidence
        self.workers = workers

    # -- enrichment ---------------------------------------------------------------
    def _enrich(self, meta: MetaAlert) -> tuple[list[Asset], list[str], list[Asset]]:
        targets, unknown = [], []
        for ip in meta.targets:
            asset = self.cmdb.asset(ip)
            (targets.append(asset) if asset else unknown.append(ip))
        sources = [a for a in (self.cmdb.asset(ip) for ip in meta.sources) if a]
        return targets, unknown, sources

    # -- deterministic checks -------------------------------------------------------
    def _authorized(self, meta: MetaAlert) -> str | None:
        if not meta.sources:
            return None
        owners = set()
        for ip in meta.sources:
            hit = self.cmdb.authorized_scanner(ip)
            if hit is None:
                return None
            owners.add(f"{hit[0]} ({hit[1]})" if hit[1] else hit[0])
        return f"all {len(meta.sources)} source(s) are registered scanners: {', '.join(sorted(owners))}"

    def _maintenance(self, meta: MetaAlert) -> str | None:
        if not meta.targets:
            return None
        reasons = set()
        for ip in meta.targets:
            start, end = self.cmdb.maintenance(ip, meta.first_seen), self.cmdb.maintenance(ip, meta.last_seen)
            if not (start and end):
                return None
            reasons.add(start)
        return f"every target was in a maintenance window: {'; '.join(sorted(reasons))}"

    def _structural(self, meta: MetaAlert, targets: list[Asset], unknown: list[str]) -> str | None:
        if unknown or not targets:
            return None                                 # never dismiss what the CMDB does not know
        signatures = {}
        for a in meta.alerts:
            signatures.setdefault(a.rule, a.signature)
        per_rule = {rule: self.applicability.for_alert(rule, sig) for rule, sig in signatures.items()}
        if not all(per_rule.values()):
            return None
        examples = []
        for asset in targets:
            for reqs in per_rule.values():
                reasons = [r for req in reqs for r in req.immunity(asset)]
                if not reasons:
                    return None
                if len(examples) < 3:
                    examples.append(reasons[0])
        ids = sorted({r.id for reqs in per_rule.values() for r in reqs})
        return (f"attack cannot succeed on any of the {len(targets)} target(s) "
                f"[{', '.join(ids)}]: {'; '.join(dict.fromkeys(examples))}")

    def _deterministic(self, meta: MetaAlert, targets: list[Asset], unknown: list[str]) -> tuple[str, str] | None:
        """(reason, explanation) of the first deterministic check that suppresses, else None."""
        explanation = self._authorized(meta)
        if explanation:
            return "AUTHORIZED_SCANNER", explanation
        explanation = self._maintenance(meta)
        if explanation:
            return "MAINTENANCE_WINDOW", explanation
        explanation = self._structural(meta, targets, unknown)
        return ("STRUCTURAL_FP", explanation) if explanation else None

    # -- LLM payload ----------------------------------------------------------------
    def payload(self, meta: MetaAlert, targets: list[Asset], unknown: list[str], sources: list[Asset]) -> dict:
        """Build the bounded, structured context sent to the triager for one meta-alert."""
        summary = meta.summary()
        summary.pop("cohesion")
        notes = sorted({r.reason for rule in meta.rules[:5]
                        for r in self.applicability.for_alert(rule, meta.representative.signature) if r.reason})
        return {
            "meta_alert": summary,
            "target_assets": [a.context() for a in targets[:MAX_CONTEXT_ASSETS]],
            "unknown_targets": unknown[:MAX_CONTEXT_ASSETS],
            "source_assets": [a.context() for a in sources[:MAX_CONTEXT_ASSETS]],
            "applicability_notes": notes,
        }

    def _decide(self, meta: MetaAlert, targets, unknown, sources, verdict: Verdict) -> Triage:
        flags = []
        if verdict.fallback_reason:
            flags.append(f"llm_fallback:{verdict.fallback_reason}")
        weight = VERDICT_WEIGHT[verdict.verdict]
        explanation = verdict.rationale
        if verdict.verdict == "true_positive":
            disposition = ESCALATE
            reason = "RULES_TRUE_POSITIVE" if verdict.provider == "offline" else "LLM_TRUE_POSITIVE"
        elif verdict.verdict == "needs_investigation":
            disposition, reason = INVESTIGATE, "NEEDS_REVIEW"
        else:
            reason = "LLM_FALSE_POSITIVE" if verdict.verdict == "false_positive" else "LLM_BENIGN"
            blockers = []
            if verdict.confidence < self.min_confidence:
                blockers.append(f"confidence {verdict.confidence:.2f} < {self.min_confidence:.2f}")
            crit = max((a.criticality for a in targets + sources), default=0)
            if crit >= CRITICALITY_CEILING:
                blockers.append(f"asset criticality {crit} >= {CRITICALITY_CEILING}")
            if meta.severity == "critical":
                blockers.append("critical severity")
            if unknown:
                blockers.append(f"{len(unknown)} target(s) missing from the CMDB")
            if blockers:
                disposition = INVESTIGATE
                flags.append("guardrail:" + ", ".join(blockers))
                reason = f"{reason}_UNCONFIRMED"
            else:
                disposition = SUPPRESS
        priority = 0.0 if disposition == SUPPRESS else priority_score(meta, targets, sources, unknown, weight)
        return Triage(meta, disposition, reason, explanation, priority, targets, unknown, sources, verdict, flags)

    # -- pipeline ---------------------------------------------------------------------
    def run(self, metas: Iterable[MetaAlert]) -> list[Triage]:
        """Triage every meta-alert and return them sorted by disposition, then priority.

        Triager calls run in parallel across ``workers`` threads.
        """
        decided: list[Triage] = []
        pending: list[tuple[MetaAlert, list[Asset], list[str], list[Asset]]] = []
        for meta in metas:
            targets, unknown, sources = self._enrich(meta)
            hit = self._deterministic(meta, targets, unknown)
            if hit:
                decided.append(Triage(meta, SUPPRESS, hit[0], hit[1], 0.0, targets, unknown, sources))
            else:
                pending.append((meta, targets, unknown, sources))

        def analyse(item):
            """Ask the triager about one pending meta-alert and apply the guardrails."""
            meta, targets, unknown, sources = item
            return self._decide(meta, targets, unknown, sources,
                                self.triager.triage(self.payload(meta, targets, unknown, sources)))

        if pending:
            with ThreadPoolExecutor(max_workers=max(1, self.workers)) as pool:
                decided.extend(pool.map(analyse, pending))
        decided.sort(key=lambda t: (DISPOSITION_ORDER[t.disposition], -t.priority, t.meta.id))
        return decided
