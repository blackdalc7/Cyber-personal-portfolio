"""Metrics, evaluation against ground-truth labels, and the Markdown / JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .assess import ESCALATE, INVESTIGATE, SUPPRESS, Triage
from .cluster import ClusterResult

TRUE_POSITIVE = "true_positive"


@dataclass
class RunInfo:
    """Parameters of one run, recorded in the report so results are reproducible."""
    input: str
    algorithm: str
    eps: float
    time_window_s: int
    llm_provider: str
    llm_model: str
    minutes_per_raw_alert: float
    minutes_per_meta_alert: float
    simulated: bool = False
    llm_stats: dict[str, int] | None = None


def metrics(raw_count: int, clusters: ClusterResult, triaged: list[Triage], run: RunInfo) -> dict[str, Any]:
    """Compute volume and workload metrics: raw alerts, meta-alerts, queue size and analyst hours saved."""
    by_disp = Counter(t.disposition for t in triaged)
    queue = by_disp[ESCALATE] + by_disp[INVESTIGATE]
    suppressed_alerts = sum(t.meta.count for t in triaged if t.disposition == SUPPRESS)
    before_h = raw_count * run.minutes_per_raw_alert / 60
    after_h = queue * run.minutes_per_meta_alert / 60
    return {
        "raw_alerts": raw_count,
        "unique_documents": clusters.unique_documents,
        "meta_alerts": len(triaged),
        "silhouette": clusters.silhouette,
        "escalate": by_disp[ESCALATE],
        "investigate": by_disp[INVESTIGATE],
        "suppressed_meta_alerts": by_disp[SUPPRESS],
        "suppressed_alerts": suppressed_alerts,
        "analyst_queue": queue,
        "queue_reduction_pct": round(100 * (1 - queue / raw_count), 2) if raw_count else 0.0,
        "suppression_reasons": dict(Counter(t.reason for t in triaged if t.disposition == SUPPRESS)),
        "analyst_hours_before": round(before_h, 1),
        "analyst_hours_after": round(after_h, 1),
        "analyst_time_saved_pct": round(100 * (1 - after_h / before_h), 1) if before_h else 0.0,
    }


def evaluate(triaged: list[Triage]) -> dict[str, Any] | None:
    """Alert-level scores against simulated ground truth; None when the input has no labels."""
    labelled = sum(sum(t.meta.labels.values()) for t in triaged)
    if not labelled:
        return None
    tp_total = sum(t.meta.labels[TRUE_POSITIVE] for t in triaged)
    noise_total = labelled - tp_total
    suppressed = [t for t in triaged if t.disposition == SUPPRESS]
    sup_tp = sum(t.meta.labels[TRUE_POSITIVE] for t in suppressed)
    sup_all = sum(sum(t.meta.labels.values()) for t in suppressed)
    escalated_noise = [t.meta.id for t in triaged if t.disposition == ESCALATE
                       and t.meta.labels.most_common(1)[0][0] != TRUE_POSITIVE]
    missed = [t.meta.id for t in suppressed if t.meta.labels[TRUE_POSITIVE]]
    purity = sum(t.meta.labels.most_common(1)[0][1] for t in triaged if t.meta.labels) / labelled
    return {
        "labelled_alerts": labelled,
        "true_positive_alerts": tp_total,
        "true_threat_recall": round(1 - sup_tp / tp_total, 4) if tp_total else 1.0,
        "suppression_precision": round(1 - sup_tp / sup_all, 4) if sup_all else 1.0,
        "noise_removed_pct": round(100 * (sup_all - sup_tp) / noise_total, 2) if noise_total else 0.0,
        "cluster_purity": round(purity, 4),
        "suppressed_true_positive_meta_alerts": missed,
        "escalated_noise_meta_alerts": escalated_noise,
    }


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _cell(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return text.replace("<", "&lt;").replace(">", "&gt;")   # alert text is untrusted; never render HTML


def _span(t: Triage) -> str:
    f, last = t.meta.first_seen, t.meta.last_seen
    return f"{f:%m-%d %H:%M}–{last:%H:%M}" if f.date() == last.date() else f"{f:%m-%d %H:%M}–{last:%m-%d %H:%M}"


def _targets(t: Triage, limit: int = 3) -> str:
    names = [a.hostname for a in t.target_assets[:limit]] + t.unknown_targets[: max(0, limit - len(t.target_assets))]
    more = len(t.meta.targets) - len(names)
    return ", ".join(names) + (f" +{more}" if more > 0 else "")


def _internal(t: Triage) -> str:
    return f" (internal: {', '.join(a.hostname for a in t.source_assets[:3])})" if t.source_assets else ""


def render_markdown(run: RunInfo, m: dict[str, Any], triaged: list[Triage], evaluation: dict[str, Any] | None,
                    detail_limit: int = 15) -> str:
    """Render the prioritised queue, the suppressed items and the metrics as Markdown."""
    queue = [t for t in triaged if t.disposition != SUPPRESS]
    suppressed = [t for t in triaged if t.disposition == SUPPRESS]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Prioritised Alert Queue", "",
        f"Generated {now} from `{_cell(run.input)}`. Clustering: {run.algorithm} (eps {run.eps}, "
        f"session gap {run.time_window_s}s). Triage model: {run.llm_provider} / {run.llm_model}.",
    ]
    if run.simulated:
        lines += ["", "> **Simulated data.** Every alert in this run was produced by the built-in generator. "
                      "Figures describe this lab dataset, not a production SOC."]
    lines += [
        "", "## Summary", "",
        "| Metric | Value |", "|---|---|",
        f"| Raw alerts ingested | {m['raw_alerts']:,} |",
        f"| Distinct alert documents | {m['unique_documents']:,} |",
        f"| Meta-alerts generated | {m['meta_alerts']:,} |",
        f"| Suppressed (with reason) | {m['suppressed_meta_alerts']} meta-alerts / {m['suppressed_alerts']:,} alerts |",
        f"| Analyst queue | **{m['analyst_queue']}** ({m['escalate']} escalate, {m['investigate']} investigate) |",
        f"| Queue reduction | {m['queue_reduction_pct']}% |",
        f"| Analyst time, before → after | {m['analyst_hours_before']} h → {m['analyst_hours_after']} h "
        f"(**{m['analyst_time_saved_pct']}% saved**) |",
        "", f"Time model: {run.minutes_per_raw_alert} min per raw alert vs {run.minutes_per_meta_alert} min per "
            "enriched meta-alert (set with `TRIAGE_MINUTES_PER_*`).",
        "", "## Queue", "",
        "| # | ID | Priority | Action | Alerts | Rule | Severity | Targets | Window (UTC) | Why |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for n, t in enumerate(queue, start=1):
        lines.append(f"| {n} | {t.meta.id} | {t.priority} | **{t.disposition}** | {t.meta.count} | "
                     f"{_cell(t.meta.rules[0])} | {t.meta.severity} | {_cell(_targets(t))} | {_span(t)} | "
                     f"{_cell(t.reason)} |")
    if not queue:
        lines.append("| – | – | – | – | – | Nothing left to review | – | – | – | – |")

    if queue:
        lines += ["", "## Meta-alert detail", ""]
    for t in queue[:detail_limit]:
        lines += [f"### {t.meta.id}: {_cell(t.meta.rules[0])}", "",
                  f"- **Action:** {t.disposition} (priority {t.priority}, reason `{t.reason}`)",
                  f"- **Volume:** {t.meta.count} alert(s) from {len(t.meta.sources)} source(s) to "
                  f"{len(t.meta.targets)} target(s), ports {', '.join(map(str, t.meta.ports[:10])) or 'n/a'}",
                  f"- **Sources:** {_cell(', '.join(t.meta.sources[:5]))}{_internal(t)}"]
        for a in t.target_assets[:3]:
            svcs = ", ".join(f"{s.port}/{s.protocol}" for s in a.services) or "no service inventory"
            lines.append(f"- **Target {a.hostname}** ({a.ip}): {a.os_family} {a.os_version}, {a.role}, "
                         f"criticality {a.criticality}{', internet-facing' if a.internet_facing else ''}; {svcs}")
        if t.unknown_targets:
            lines.append(f"- **Not in CMDB:** {_cell(', '.join(t.unknown_targets[:5]))}")
        if t.verdict:
            v = t.verdict
            lines += [f"- **Assessment ({v.provider}{', cached' if v.cached else ''}):** {v.verdict}, "
                      f"confidence {v.confidence:.2f}. {_cell(v.rationale)}",
                      f"- **Next step:** {_cell(v.recommended_action)}"]
        if t.flags:
            lines.append(f"- **Flags:** {_cell('; '.join(t.flags))}")
        lines.append("")

    lines += ["## Suppressed", "",
              "Every suppression is listed with its evidence so it can be audited or reversed.", "",
              "| ID | Alerts | Rule | Reason | Evidence |", "|---|---|---|---|---|"]
    for t in sorted(suppressed, key=lambda x: -x.meta.count):
        lines.append(f"| {t.meta.id} | {t.meta.count} | {_cell(t.meta.rules[0])} | `{t.reason}` | "
                     f"{_cell(t.explanation)} |")
    if not suppressed:
        lines.append("| – | – | Nothing suppressed | – | – |")

    learned = [t for t in triaged if t.verdict and t.verdict.structural_mismatch and t.verdict.provider != "offline"]
    if learned:
        lines += ["", "## Suggested applicability rules", "",
                  "The model found structural mismatches the requirements file does not cover. Review and add "
                  "them to `config/signature_requirements.yml` so they are caught deterministically next time.", ""]
        lines += [f"- `{_cell(t.meta.rules[0])}`: {_cell(t.verdict.rationale)}" for t in learned]

    if evaluation:
        e = evaluation
        lines += ["", "## Evaluation against ground truth", "",
                  "| Measure | Value |", "|---|---|",
                  f"| True-threat recall (alerts) | {e['true_threat_recall']:.2%} |",
                  f"| Suppression precision | {e['suppression_precision']:.2%} |",
                  f"| Noise removed | {e['noise_removed_pct']}% |",
                  f"| Cluster purity | {e['cluster_purity']:.2%} |",
                  f"| Suppressed meta-alerts containing a true positive | "
                  f"{', '.join(e['suppressed_true_positive_meta_alerts']) or 'none'} |",
                  f"| Escalated meta-alerts that are noise | {', '.join(e['escalated_noise_meta_alerts']) or 'none'} |"]
    if run.llm_stats:
        s = run.llm_stats
        lines += ["", f"LLM usage: {s.get('calls', 0)} calls, {s.get('cache_hits', 0)} cache hits, "
                      f"{s.get('fallbacks', 0)} offline fallbacks."]
    return "\n".join(lines) + "\n"


def render_json(run: RunInfo, m: dict[str, Any], triaged: list[Triage], evaluation: dict[str, Any] | None) -> str:
    """Render the run, metrics, queue and suppressed items as JSON."""
    doc = {
        "run": run.__dict__, "metrics": m, "evaluation": evaluation,
        "queue": [t.to_dict() for t in triaged if t.disposition != SUPPRESS],
        "suppressed": [t.to_dict() for t in triaged if t.disposition == SUPPRESS],
    }
    return json.dumps(doc, indent=2, default=str) + "\n"


def write(path: str | Path, text: str) -> None:
    """Write ``text`` to ``path``, creating parent directories."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
