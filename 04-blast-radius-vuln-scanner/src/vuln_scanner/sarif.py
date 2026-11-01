"""SARIF 2.1.0 output, so findings land in GitHub code scanning, Azure DevOps or any SARIF viewer.

Each CVE is a rule; each (host, port, CVE) is a result whose physical location is the
exact line of the Nmap XML that proves the service was listening. ``rank`` carries the
blast-radius priority (SARIF defines rank as 0-100, higher = more important) and
``security-severity`` carries CVSS, which GitHub uses for its severity badges.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from . import __version__
from .analysis import AnalysisResult, Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def level_for(priority: float) -> str:
    """Map a priority score to a SARIF level: error (>= 40), warning (>= 15) or note."""
    if priority >= 40:
        return "error"
    if priority >= 15:
        return "warning"
    return "note"


def _uri(path: str, base: Path | None) -> str:
    p = Path(path)
    if base is not None:
        try:
            return Path(os.path.relpath(p.resolve(), base.resolve())).as_posix()
        except ValueError:
            pass
    return p.as_posix()


def _rule(f: Finding) -> dict[str, Any]:
    c = f.cve
    tags = ["security", "vulnerability", *c.cwes]
    if f.kev:
        tags.append("cisa-kev")
    return {
        "id": c.cve_id,
        "name": c.cve_id.replace("-", ""),
        "shortDescription": {"text": f"{c.cve_id} in {f.service.banner}"},
        "fullDescription": {"text": c.description or c.cve_id},
        "helpUri": f"https://nvd.nist.gov/vuln/detail/{c.cve_id}",
        "help": {"text": f"See {c.cve_id} on NVD. Patch or mitigate {f.service.banner}.",
                 "markdown": f"[{c.cve_id}](https://nvd.nist.gov/vuln/detail/{c.cve_id}). "
                             f"CVSS {c.cvss if c.cvss is not None else 'n/a'} ({c.cvss_version or 'unscored'})."},
        "properties": {"security-severity": f"{c.cvss:.1f}" if c.cvss is not None else "5.0", "tags": tags,
                       "precision": "high" if c.match == "cpe" else "low"},
    }


def _result(f: Finding, rule_index: int, base: Path | None) -> dict[str, Any]:
    s = f.service
    blast = f.blast
    targets = [f"{t.name} ({t.ip}) hop {t.hops} via {t.via_port}/{t.via_cve}" for t in (blast.targets if blast else ())]
    msg = (f"{f.cve.cve_id} on {f.asset_name} ({s.key}, {s.banner}). Priority {f.priority:.1f}: "
           f"EPSS {f.epss:.3f}{', CISA KEV' if f.kev else ''}, CVSS {f.cve.cvss if f.cve.cvss is not None else 'n/a'}, "
           f"exposure {f.exposure}, blast radius {len(targets)} secondary target(s).")
    fp = hashlib.sha256(f.fingerprint.encode()).hexdigest()
    return {
        "ruleId": f.cve.cve_id,
        "ruleIndex": rule_index,
        "level": level_for(f.priority),
        "rank": f.priority,
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": _uri(s.source_file, base)},
                                 "region": {"startLine": s.line}},
            "logicalLocations": [{"name": s.key, "fullyQualifiedName": f"{f.asset_name}/{s.key}", "kind": "resource"}],
        }],
        "partialFingerprints": {"hostPortCve/v1": fp},
        "properties": {
            "host": s.host, "port": s.port, "protocol": s.protocol, "asset": f.asset_name,
            "criticality": f.criticality, "epss": f.epss, "epssPercentile": f.epss_percentile,
            "kev": f.kev, "kevRansomware": f.kev_ransomware, "likelihood": round(f.likelihood, 4),
            "exposure": f.exposure, "blastRadiusScore": blast.score if blast else 0.0, "chokepoint": f.chokepoint,
            "secondaryTargets": targets, "cpeMatch": f.cve.match,
        },
    }


def to_sarif(result: AnalysisResult, base: Path | None = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log, one rule per CVE and one result per finding.

    Artifact URIs are made relative to ``base`` so GitHub code scanning can link
    them to the scan files in the repository.
    """
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results = []
    for f in result.findings:
        if f.cve.cve_id not in index:
            index[f.cve.cve_id] = len(rules)
            rules.append(_rule(f))
        results.append(_result(f, index[f.cve.cve_id], base))
    paths = [{"target": p.target, "probability": p.probability, "path": list(p.nodes)} for p in result.paths]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "blast-radius-vuln-scanner", "version": __version__,
                                "semanticVersion": __version__,
                                "informationUri": "https://www.first.org/epss/", "rules": rules}},
            "invocations": [{"executionSuccessful": not result.errors,
                             "toolExecutionNotifications": [{"level": "warning", "message": {"text": e}}
                                                            for e in result.errors]}],
            "results": results,
            "properties": {"entryPoints": result.entry_points, "attackPaths": paths,
                           "hostsScanned": len({s.host for s in result.services}),
                           "servicesScanned": len(result.services)},
        }],
    }


def validate_sarif(doc: dict[str, Any]) -> list[str]:
    """Structural checks for the parts of SARIF 2.1.0 consumers rely on. Returns problems found."""
    problems = []
    if doc.get("version") != "2.1.0":
        problems.append("version must be 2.1.0")
    for r_i, run in enumerate(doc.get("runs", [])):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        ids = [r.get("id") for r in rules]
        if len(ids) != len(set(ids)):
            problems.append(f"runs[{r_i}]: duplicate rule ids")
        for i, res in enumerate(run.get("results", [])):
            where = f"runs[{r_i}].results[{i}]"
            if res.get("level") not in ("none", "note", "warning", "error"):
                problems.append(f"{where}: bad level")
            if not res.get("message", {}).get("text"):
                problems.append(f"{where}: message.text required")
            ri = res.get("ruleIndex")
            if ri is not None and (ri >= len(rules) or rules[ri]["id"] != res.get("ruleId")):
                problems.append(f"{where}: ruleIndex does not match ruleId")
            rank = res.get("rank", 0)
            if not 0 <= rank <= 100:
                problems.append(f"{where}: rank must be 0-100")
            for loc in res.get("locations", []):
                region = loc.get("physicalLocation", {}).get("region", {})
                if region and region.get("startLine", 1) < 1:
                    problems.append(f"{where}: startLine must be >= 1")
    return problems
