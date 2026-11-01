"""Export the static JSON that powers the GitHub Pages replay demo.

The exporter loads every recorded scenario into a temporary lake and calls the same
query functions the live hub uses, so the demo shows exactly what the platform would
show for that data. File outputs (04 exposure, 05/07 coverage, 06 triage, 08 rules,
09 evidence, 10 analyst transcripts) are copied through the same readers.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import ocsf
from .hub import artifacts, queries
from .lake import LakeReader, LakeWriter
from .scenarios import list_scenarios, score_stages

SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str), encoding="utf-8")


def export_demo(out: Path, scenarios_dir: Path, *, exposure_file: Path | None = None,
                coverage_dir: Path | None = None, triage_queue: Path | None = None, rules_index: Path | None = None,
                evidence_dir: Path | None = None, analyst_dir: Path | None = None) -> dict[str, Any]:
    """Write the demo files under ``out`` and return the manifest."""
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    tmp = Path(tempfile.mkdtemp(prefix="wf-demo-"))
    try:
        writer = LakeWriter(tmp)
        scenarios = list_scenarios(scenarios_dir)
        for sc in scenarios:
            writer.add_many(sc.events())
        writer.flush()
        lake = LakeReader(tmp)

        _dump(out / "summary.json", queries.summary(lake))
        _dump(out / "findings.json", queries.findings(lake, limit=1000))
        incs = queries.incidents(lake)
        _dump(out / "incidents.json", incs)
        for inc in incs:
            detail = queries.incident_detail(lake, inc["id"])
            detail["evidence"] = [e for e in artifacts.json_dir(evidence_dir, "*/manifest.json")
                                  if e.get("incident_id") == inc["id"] or e.get("scenario") == inc["scenario"]][:5]
            detail["analyses"] = [a for a in artifacts.json_dir(analyst_dir)
                                  if a.get("incident_id") == inc["id"] or a.get("scenario") == inc["scenario"]][:5]
            _dump(out / "incident" / f"{SAFE.sub('_', inc['id'])}.json", detail)

        index = []
        for sc in scenarios:
            events = sc.events()
            _dump(out / "scenario" / f"{sc.id}.json", {**sc.to_dict(), "events": [_compact(e) for e in events]})
            _dump(out / "score" / f"{sc.id}.json",
                  {"scenario": sc.id, "source": "dataset", "stages": score_stages(sc.stages, events)})
            _dump(out / "summary" / f"{sc.id}.json", queries.summary(lake, scenario=sc.id))
            index.append(sc.to_dict())
        _dump(out / "scenarios.json", index)

        runs = artifacts.coverage_runs(coverage_dir)
        _dump(out / "coverage.json", runs)
        for run in runs:
            _dump(out / "coverage" / f"{SAFE.sub('_', run['id'])}.json",
                  artifacts.coverage_run(coverage_dir, run["id"]))
        expo = artifacts.exposure(exposure_file)
        if expo:
            _dump(out / "exposure.json", expo)
        if triage_queue and Path(triage_queue).is_file():
            q = json.loads(Path(triage_queue).read_text(encoding="utf-8"))
            _dump(out / "triage.json", {k: q.get(k) for k in ("run", "metrics", "evaluation", "queue")}
                  | {"suppressed": q.get("suppressed", [])[:50]})
        _dump(out / "rules.json", artifacts.rules(rules_index) or {"rules": [], "generated": None})
        _dump(out / "evidence.json", artifacts.json_dir(evidence_dir, "*/manifest.json"))
        _dump(out / "analyst.json", artifacts.json_dir(analyst_dir))
        manifest = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "ocsf_version": ocsf.OCSF_VERSION, "scenarios": [s.id for s in scenarios],
                    "incidents": [i["id"] for i in incs], "has_exposure": bool(expo),
                    "has_triage": (out / "triage.json").exists()}
        _dump(out / "manifest.json", manifest)
        lake.close()
        return manifest
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _compact(doc: dict[str, Any]) -> dict[str, Any]:
    row = ocsf.flatten(doc)
    row.pop("raw", None)
    if doc.get("finding_info"):
        row["desc"] = doc["finding_info"].get("desc")
    if doc.get("unmapped"):
        row["unmapped"] = doc["unmapped"]
    return row
