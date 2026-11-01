"""Score an exercise: for every step, did the logs see it, and did the expected Sigma rule fire?

Step outcomes
-------------
DETECTED        an expected rule matched an event from that host inside the step window
DETECTION_GAP   the host logged process activity in the window, but no expected rule matched
                (the telemetry is there; the detection content is missing or too narrow)
TELEMETRY_GAP   no process events from that host in the window (logging is off, not
                forwarded, or the host is not onboarded), so no rule could ever fire
NO_CONTENT      the catalogue lists no Sigma rule for this technique on this platform

A technique takes the WORST outcome across its steps: it counts as covered only if it was
detected on every host it was exercised on, because attackers pick the host you are
blind on. Splitting the two gaps matters:
they go to different teams (detection engineering vs. logging/platform), and a coverage
number that hides the difference sends work to the wrong one.

Detection coverage = DETECTED techniques / techniques exercised.
Telemetry coverage = techniques with any telemetry / techniques exercised.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .catalog import Exercise, ExerciseStep, Technique
from .sigma import SigmaMatcher, SigmaRule

DETECTED, DETECTION_GAP, TELEMETRY_GAP, NO_CONTENT = "DETECTED", "DETECTION_GAP", "TELEMETRY_GAP", "NO_CONTENT"
RANK = {DETECTED: 3, DETECTION_GAP: 2, NO_CONTENT: 1, TELEMETRY_GAP: 0}
COLOURS = {DETECTED: "#31a354", DETECTION_GAP: "#fd8d3c", NO_CONTENT: "#fdd0a2", TELEMETRY_GAP: "#de2d26"}
SCORES = {DETECTED: 100, DETECTION_GAP: 50, NO_CONTENT: 25, TELEMETRY_GAP: 0}


@dataclass
class StepResult:
    """Outcome of one exercise step, with the rules that fired and evidence lines."""
    step: ExerciseStep
    outcome: str
    events_in_window: int
    matched_rules: list[str] = field(default_factory=list)
    other_rules: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass
class TechniqueResult:
    """Outcome of one technique: the worst outcome across all its steps."""
    technique: Technique
    outcome: str
    steps: list[StepResult]


@dataclass
class CoverageReport:
    """Coverage results for a whole exercise, with headline percentages."""
    exercise: str
    techniques: list[TechniqueResult]

    def _share(self, outcomes: set[str]) -> float:
        """Percentage of techniques whose outcome is in ``outcomes`` (0.0 when empty)."""
        if not self.techniques:
            return 0.0
        return round(100 * sum(1 for t in self.techniques if t.outcome in outcomes) / len(self.techniques), 1)

    @property
    def detection_coverage(self) -> float:
        """Percentage of exercised techniques that were detected on every host."""
        return self._share({DETECTED})

    @property
    def telemetry_coverage(self) -> float:
        """Percentage of exercised techniques that were not a telemetry gap."""
        return self._share({DETECTED, DETECTION_GAP, NO_CONTENT})

    def by_tactic(self) -> dict[str, tuple[int, int]]:
        """Per tactic: ``(detected, exercised)`` technique counts, sorted by tactic."""
        out: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for t in self.techniques:
            out[t.technique.tactic][1] += 1
            out[t.technique.tactic][0] += t.outcome == DETECTED
        return {k: (v[0], v[1]) for k, v in sorted(out.items())}


def _summary(ev: Mapping[str, Any]) -> str:
    return (f"{ev['_time'].isoformat(timespec='seconds')} {ev.get('_host', '?')} "
            f"{ev.get('Image', '?')} | {str(ev.get('CommandLine', ''))[:160]}")


def evaluate(exercise: Exercise, catalog: Mapping[str, Technique], rules: Iterable[SigmaRule],
             events: list[dict[str, Any]], skew_s: float = 5.0) -> CoverageReport:
    """Score ``exercise`` against the log ``events`` using the Sigma ``rules``.

    Each step window is widened by ``skew_s`` seconds on both sides to absorb
    clock differences between the exercise log and the hosts.

    Raises:
        ValueError: if the catalogue references a rule id that was not loaded.
    """
    rules = list(rules)
    by_id = {r.id: r for r in rules}
    matcher = SigmaMatcher(rules)
    missing = sorted({rid for t in catalog.values() for rid in t.expected_rules if rid not in by_id})
    if missing:
        raise ValueError(f"catalogue references unknown Sigma rule id(s): {', '.join(missing)}")
    skew = timedelta(seconds=skew_s)

    per_technique: dict[str, list[StepResult]] = defaultdict(list)
    for step in exercise.steps:
        window = [e for e in events if e.get("_host") == step.host
                  and step.start - skew <= e["_time"] <= step.end + skew]
        expected = [rid for rid in catalog[step.technique].expected_rules
                    if by_id[rid].logsource.get("product", step.platform) == step.platform]
        hits = matcher.match(window)
        matched = sorted({h.rule_id for h in hits if h.rule_id in expected})
        other = sorted({h.rule_id for h in hits if h.rule_id not in expected})
        if not window:
            outcome = TELEMETRY_GAP
        elif not expected:
            outcome = NO_CONTENT
        elif matched:
            outcome = DETECTED
        else:
            outcome = DETECTION_GAP
        evidence = [_summary(h.event) for h in hits if h.rule_id in matched][:3] or [_summary(e) for e in window[:3]]
        per_technique[step.technique].append(StepResult(step, outcome, len(window), matched, other, evidence))

    results = [TechniqueResult(catalog[tid], min((s.outcome for s in steps), key=RANK.__getitem__), steps)
               for tid, steps in per_technique.items()]
    results.sort(key=lambda r: (RANK[r.outcome], r.technique.tactic, r.technique.id))
    return CoverageReport(exercise.name, results)


def navigator_layer(report: CoverageReport) -> dict[str, Any]:
    """ATT&CK Navigator layer (format 4.5): load it at https://mitre-attack.github.io/attack-navigator/."""
    return {
        "name": f"Detection coverage: {report.exercise}",
        "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": "16"},
        "domain": "enterprise-attack",
        "description": (f"Sigma-validated detection coverage {report.detection_coverage}% "
                        f"(telemetry {report.telemetry_coverage}%)."),
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [{
            "techniqueID": t.technique.id, "tactic": t.technique.tactic, "score": SCORES[t.outcome],
            "color": COLOURS[t.outcome], "comment": t.outcome, "enabled": True,
            "metadata": [{"name": "procedure", "value": s.step.procedure or s.step.host} for s in t.steps],
        } for t in report.techniques],
        "gradient": {"colors": ["#de2d26", "#fd8d3c", "#31a354"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": k.replace("_", " ").title(), "color": v} for k, v in COLOURS.items()],
    }


def to_json(report: CoverageReport, rules: Mapping[str, SigmaRule]) -> dict[str, Any]:
    """Serialise a coverage report to a JSON-ready dict, including per-step evidence."""
    return {
        "exercise": report.exercise,
        "detection_coverage": report.detection_coverage,
        "telemetry_coverage": report.telemetry_coverage,
        "by_tactic": {k: {"detected": d, "exercised": n} for k, (d, n) in report.by_tactic().items()},
        "techniques": [{
            "id": t.technique.id, "name": t.technique.name, "tactic": t.technique.tactic, "outcome": t.outcome,
            "steps": [{"host": s.step.host, "platform": s.step.platform, "procedure": s.step.procedure,
                       "start": s.step.start.isoformat(), "end": s.step.end.isoformat(), "outcome": s.outcome,
                       "events_in_window": s.events_in_window,
                       "matched_rules": [{"id": r, "title": rules[r].title} for r in s.matched_rules],
                       "other_rules": [{"id": r, "title": rules[r].title} for r in s.other_rules],
                       "evidence": s.evidence} for s in t.steps],
        } for t in report.techniques],
    }


FIX = {
    DETECTION_GAP: "Detection engineering: the events are there. Extend or add a Sigma rule using the evidence lines.",
    TELEMETRY_GAP: ("Logging/platform: enable process-creation logging (Sysmon EID 1 or 4688 with command line; "
                    "auditd execve on Linux) and confirm the host forwards to the SIEM."),
    NO_CONTENT: "Detection engineering: no Sigma rule is mapped to this technique for this platform yet.",
}


def to_markdown(report: CoverageReport, rules: Mapping[str, SigmaRule]) -> str:
    """Render a coverage report as Markdown: headline numbers, per-tactic table and technique table."""
    icon = {DETECTED: "✅", DETECTION_GAP: "🟧", TELEMETRY_GAP: "🟥", NO_CONTENT: "⬜"}
    lines = [f"# Detection coverage: {report.exercise}", "",
             f"**Detection coverage: {report.detection_coverage}%**, telemetry coverage {report.telemetry_coverage}% "
             f"across {len(report.techniques)} exercised techniques.", "",
             "| Tactic | Detected / exercised |", "|---|---|"]
    lines += [f"| {k} | {d} / {n} |" for k, (d, n) in report.by_tactic().items()]
    lines += ["", "| | Technique | Outcome | Rule(s) that fired | Hosts |", "|---|---|---|---|---|"]
    for t in sorted(report.techniques, key=lambda r: (-RANK[r.outcome], r.technique.id)):
        fired = sorted({rules[r].title for s in t.steps for r in s.matched_rules}) or ["-"]
        hosts = sorted({s.step.host for s in t.steps})
        lines.append(f"| {icon[t.outcome]} | {t.technique.id} {t.technique.name} | {t.outcome} | "
                     f"{'; '.join(fired)} | {', '.join(hosts)} |")
    blind = sorted({(s.step.host, s.step.platform) for t in report.techniques for s in t.steps
                    if s.outcome == TELEMETRY_GAP})
    if blind:
        lines += ["", "## Hosts with no process telemetry", "",
                  "Nothing from these hosts reached the log export during their exercise steps:", ""]
        lines += [f"- **{h}** ({p})" for h, p in blind]
    gaps = [t for t in report.techniques if t.outcome != DETECTED]
    if gaps:
        lines += ["", "## Gaps and who fixes them", ""]
        for t in gaps:
            lines.append(f"### {icon[t.outcome]} {t.technique.id} {t.technique.name}: {t.outcome}")
            lines.append("")
            lines.append(FIX[t.outcome])
            for s in t.steps:
                lines.append(f"- {icon[s.outcome]} {s.step.host} ({s.step.platform}) `{s.step.procedure or 'n/a'}`: "
                             f"{s.outcome}, {s.events_in_window} event(s) in window")
                if s.outcome != DETECTED:
                    lines += [f"    - `{e}`" for e in s.evidence if s.events_in_window]
            lines.append("")
    return "\n".join(lines) + "\n"
