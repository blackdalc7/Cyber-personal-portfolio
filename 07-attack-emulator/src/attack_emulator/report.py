"""Outputs: the emulation-run JSON the Watchfloor hub reads, an ATT&CK Navigator layer, and Markdown."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .runner import RunResult

COLORS = {"detected": "#39ff88", "prevented": "#a78bfa", "telemetry_only": "#ffb224", "missed": "#ff3b5c",
          "error": "#f472b6", "skipped": "#71717a"}
SCORES = {"missed": 0, "telemetry_only": 1, "detected": 2, "prevented": 3}


def _ttd(cell: dict[str, Any], prefix: str = "") -> str:
    return f"{prefix}{cell['ttd_ms'] / 1000:.1f}s" if cell.get("ttd_ms") is not None else ""


def summarise(cells: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {k: sum(1 for c in cells if c["outcome"] == k) for k in COLORS}
    scored = sum(counts[k] for k in ("detected", "prevented", "telemetry_only", "missed"))
    ttds = [c["ttd_ms"] for c in cells if c["outcome"] == "detected" and c.get("ttd_ms") is not None]

    def pct(n: int) -> float:
        return round(100.0 * n / scored, 1) if scored else 0.0

    return {
        "total": len(cells), "scored": scored, **counts,
        # Prevented counts as covered: the technique did not succeed.
        "detection_coverage": pct(counts["detected"] + counts["prevented"]),
        "telemetry_coverage": pct(counts["detected"] + counts["prevented"] + counts["telemetry_only"]),
        "mean_ttd_ms": round(sum(ttds) / len(ttds)) if ttds else None,
    }


def run_doc(run: RunResult) -> dict[str, Any]:
    cells = [asdict(c) for c in run.cells]
    return {"kind": "emulation-run", "version": 1, "run_id": run.run_id, "campaign": run.campaign,
            "started": run.started, "finished": run.finished, "dry_run": run.dry_run,
            "summary": summarise(cells), "results": cells}


def navigator_layer(doc: dict[str, Any]) -> dict[str, Any]:
    """ATT&CK Navigator 4.5 layer: one entry per technique, worst outcome wins when a technique ran twice."""
    best: dict[str, dict[str, Any]] = {}
    for c in doc["results"]:
        if c["outcome"] not in SCORES:
            continue
        cur = best.get(c["technique"])
        if cur is None or SCORES[c["outcome"]] < SCORES[cur["outcome"]]:
            best[c["technique"]] = c
    return {
        "name": f"Watchfloor emulation: {doc['campaign']}",
        "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{doc['run_id']}: detection coverage {doc['summary']['detection_coverage']}%",
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [{"techniqueID": t, "score": SCORES[c["outcome"]], "color": COLORS[c["outcome"]],
                        "comment": c["outcome"] + _ttd(c, ", TTD "), "enabled": True} for t, c in sorted(best.items())],
        "legendItems": [{"label": k.replace("_", " "), "color": v} for k, v in COLORS.items() if k in SCORES],
        "gradient": {"colors": ["#ff3b5c", "#39ff88"], "minValue": 0, "maxValue": 3},
    }


def markdown(doc: dict[str, Any]) -> str:
    s = doc["summary"]
    lines = [f"# Emulation run {doc['run_id']}", "", f"Campaign: **{doc['campaign']}**", "",
             f"Detection coverage **{s['detection_coverage']}%**, telemetry coverage {s['telemetry_coverage']}% "
             f"({s['detected']} detected, {s['prevented']} prevented, {s['telemetry_only']} telemetry only, "
             f"{s['missed']} missed, {s['error']} errors, {s['skipped']} skipped).", "",
             "| Technique | Test | Target | Outcome | Time to detect | Findings |", "|---|---|---|---|---|---|"]
    for c in doc["results"]:
        found = "; ".join(f"{f.get('title')} ({f.get('product')})" for f in c.get("findings", [])[:2])
        lines.append(f"| {c['technique']} {c['name']} | {c['test']} | {c['target']} | {c['outcome']} | {_ttd(c)} "
                     f"| {found} |")
    gaps = [c for c in doc["results"] if c["outcome"] in ("telemetry_only", "missed")]
    if gaps:
        lines += ["", "## Gaps", ""]
        for c in gaps:
            fix = ("events arrived but no rule fired: write or tune a rule in 08-detection-rules"
                   if c["outcome"] == "telemetry_only" else "no telemetry arrived: fix the sensor or log source first")
            lines.append(f"- **{c['technique']} {c['name']}** on {c['target']}: {fix}.")
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"run": out_dir / f"{doc['run_id']}.json", "navigator": out_dir / f"{doc['run_id']}.layer.json",
             "markdown": out_dir / f"{doc['run_id']}.md"}
    paths["run"].write_text(json.dumps(doc, indent=2), encoding="utf-8")
    paths["navigator"].write_text(json.dumps(navigator_layer(doc), indent=2), encoding="utf-8")
    paths["markdown"].write_text(markdown(doc), encoding="utf-8")
    return paths
