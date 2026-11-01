"""Readers for the file outputs the hub serves as-is (the "existing outputs" principle).

* coverage: 07 emulation runs (``run-*.json``) and 05 exercise scores (``coverage.json``), searched recursively
* exposure: 04's ``findings.json`` with a what-if helper
* rules: 08's generated ``rules_index.json``
* evidence: 09's incident packages (``*/manifest.json``)
* analyst: 10's investigation transcripts (``*.json``)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def coverage_runs(directory: Path | None) -> list[dict[str, Any]]:
    """Summaries of every coverage result in ``directory``, newest first."""
    if not directory or not Path(directory).is_dir():
        return []
    out = []
    for p in sorted(Path(directory).rglob("*.json")):
        try:
            doc = _load(p)
        except (OSError, ValueError):
            continue
        if "techniques" in doc and "detection_coverage" in doc:  # 05's format
            out.append({"id": p.stem, "kind": "exercise", "title": doc.get("exercise", p.stem),
                        "started": None, "detection_coverage": doc["detection_coverage"],
                        "telemetry_coverage": doc.get("telemetry_coverage"), "file": p.name})
        elif doc.get("kind") == "emulation-run":  # 07's format
            out.append({"id": doc["run_id"], "kind": "emulation", "title": doc.get("campaign", p.stem),
                        "started": doc.get("started"), "detection_coverage": doc["summary"]["detection_coverage"],
                        "telemetry_coverage": doc["summary"].get("telemetry_coverage"), "file": p.name})
    return sorted(out, key=lambda r: (r["started"] or 0), reverse=True)


def coverage_run(directory: Path | None, run_id: str) -> dict[str, Any] | None:
    """One coverage result, normalised to the ATT&CK matrix shape the UI renders."""
    if not directory:
        return None
    for p in sorted(Path(directory).rglob("*.json")):
        try:
            doc = _load(p)
        except (OSError, ValueError):
            continue
        if doc.get("run_id") == run_id or (p.stem == run_id and "techniques" in doc):
            return to_matrix(doc)
    return None


def to_matrix(doc: dict[str, Any]) -> dict[str, Any]:
    """Normalise a 05 or 07 result to ``{title, cells: [{technique, tactic, outcome, ...}]}``."""
    if doc.get("kind") == "emulation-run":
        return {"id": doc["run_id"], "title": doc.get("campaign"), "kind": "emulation",
                "summary": doc["summary"], "cells": doc["results"]}
    mapping = {"DETECTED": "detected", "DETECTION_GAP": "telemetry_only", "TELEMETRY_GAP": "missed",
               "NO_CONTENT": "missed", "PARTIAL": "telemetry_only"}
    cells = []
    for t in doc.get("techniques", []):
        cells.append({"technique": t["id"], "name": t.get("name"), "tactic": t.get("tactic"),
                      "outcome": mapping.get(t.get("outcome"), "missed"), "source_outcome": t.get("outcome"),
                      "steps": t.get("steps", [])})
    return {"id": doc.get("exercise"), "title": doc.get("exercise"), "kind": "exercise",
            "summary": {"detection_coverage": doc.get("detection_coverage"),
                        "telemetry_coverage": doc.get("telemetry_coverage")}, "cells": cells}


def exposure(path: Path | None) -> dict[str, Any] | None:
    """04's findings, entry points and attack paths, plus a graph for Cytoscape."""
    if not path or not Path(path).is_file():
        return None
    doc = _load(path)
    nodes: dict[str, dict[str, Any]] = {"internet": {"id": "internet", "label": "internet", "kind": "internet"}}
    for f in doc.get("findings", []):
        nodes.setdefault(f["host"], {"id": f["host"], "label": f.get("asset") or f["host"], "kind": "host",
                                     "criticality": f.get("criticality"), "exposure": f.get("exposure"),
                                     "cves": []})
        nodes[f["host"]]["cves"].append({k: f.get(k) for k in ("cve", "cvss", "epss", "kev", "port", "priority",
                                                                "blast_radius_score", "chokepoint")})
    edges = {}
    for path_ in doc.get("attack_paths", []):
        for step in path_["steps"]:
            for end in (step["from"], step["to"]):
                nodes.setdefault(end, {"id": end, "label": end, "kind": "host", "cves": []})
            key = f"{step['from']}>{step['to']}"
            edges[key] = {"id": key, "source": step["from"], "target": step["to"], "port": step.get("port"),
                          "cve": step.get("cve")}
    return {"generated": doc.get("generated"), "entry_points": doc.get("entry_points", []),
            "attack_paths": doc.get("attack_paths", []), "findings": doc.get("findings", []),
            "graph": {"nodes": list(nodes.values()), "edges": list(edges.values())}}


def what_if(exposure_doc: dict[str, Any], patched: list[str]) -> dict[str, Any]:
    """Attack paths that survive if the CVEs in ``patched`` are fixed (a path dies if any step needs one)."""
    patched_set = {c.upper() for c in patched}
    alive = [p for p in exposure_doc.get("attack_paths", [])
             if not any((s.get("cve") or "").upper() in patched_set for s in p["steps"])]
    return {"patched": sorted(patched_set), "paths_before": len(exposure_doc.get("attack_paths", [])),
            "paths_after": len(alive), "surviving_paths": alive,
            "crown_jewels_reachable": sorted({p["target"] for p in alive})}


def rules(path: Path | None) -> dict[str, Any] | None:
    """08's rules index (rule metadata, test status, techniques, last conversion)."""
    if not path or not Path(path).is_file():
        return None
    return _load(path)


def json_dir(directory: Path | None, pattern: str = "*.json", limit: int = 200) -> list[dict[str, Any]]:
    """Load up to ``limit`` JSON documents matching ``pattern`` under ``directory``, newest first."""
    if not directory or not Path(directory).is_dir():
        return []
    files = sorted(Path(directory).glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    out = []
    for p in files:
        try:
            out.append(_load(p))
        except (OSError, ValueError):
            continue
    return out
