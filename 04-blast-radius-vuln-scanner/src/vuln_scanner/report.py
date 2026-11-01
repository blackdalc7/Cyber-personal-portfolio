"""Human-readable Markdown report and machine-readable JSON findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analysis import AnalysisResult, Finding


def finding_dict(f: Finding) -> dict[str, Any]:
    """Flatten a finding into the JSON shape used in ``findings.json``."""
    s = f.service
    return {
        "host": s.host, "port": s.port, "protocol": s.protocol, "asset": f.asset_name, "banner": s.banner,
        "cpe": s.cpe, "cve": f.cve.cve_id, "cvss": f.cve.cvss, "cvss_vector": f.cve.cvss_vector,
        "epss": f.epss, "epss_percentile": f.epss_percentile, "kev": f.kev, "kev_ransomware": f.kev_ransomware,
        "likelihood": round(f.likelihood, 4), "criticality": f.criticality, "exposure": f.exposure,
        "blast_radius_score": f.blast.score if f.blast else 0.0, "chokepoint": f.chokepoint,
        "secondary_targets": [{"ip": t.ip, "name": t.name, "hops": t.hops, "via_port": t.via_port, "via_cve": t.via_cve}
                              for t in (f.blast.targets if f.blast else ())],
        "priority": f.priority, "match": f.cve.match,
    }


def to_json(result: AnalysisResult) -> dict[str, Any]:
    """Build the complete JSON report: entry points, attack paths, errors and findings."""
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entry_points": result.entry_points,
        "attack_paths": [{"target": p.target, "probability": p.probability, "path": list(p.nodes),
                          "steps": [{"from": a, "to": b, "port": port, "cve": cve} for a, b, port, cve in p.steps]}
                         for p in result.paths],
        "errors": result.errors,
        "findings": [finding_dict(f) for f in result.findings],
    }


def _name(result: AnalysisResult, ip: str) -> str:
    return result.reach.nodes[ip].get("name", ip) if ip in result.reach else ip


def to_markdown(result: AnalysisResult, top: int = 15, graph_path: str | None = None) -> str:
    """Render a Markdown report with a summary, the top findings and attack paths."""
    out: list[str] = ["# Blast-radius vulnerability report", ""]
    hosts = len({s.host for s in result.services})
    kev = sum(1 for f in result.findings if f.kev)
    out += [f"Scanned **{hosts} hosts / {len(result.services)} services**, found **{len(result.findings)} CVE "
            f"findings** ({kev} in CISA KEV). **{len(result.entry_points)} entry point(s)** are exploitable from "
            f"the internet.", ""]
    if result.errors:
        out += ["> **Incomplete data:** " + "; ".join(result.errors), ""]
    if graph_path:
        out += [f"![Blast radius]({graph_path})", ""]

    out += ["## Fix first", "",
            "| # | Priority | Asset | Service | CVE | CVSS | EPSS | KEV | Exposure | Blast radius |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(result.findings[:top], start=1):
        n = len(f.blast.targets) if f.blast else 0
        out.append(f"| {i} | **{f.priority:.1f}** | {f.asset_name} ({f.service.host}) | {f.service.port}/"
                   f"{f.service.protocol} {f.service.banner} | [{f.cve.cve_id}](https://nvd.nist.gov/vuln/detail/"
                   f"{f.cve.cve_id}) | {f.cve.cvss if f.cve.cvss is not None else 'n/a'} | {f.epss:.3f} | "
                   f"{'yes' if f.kev else ''} | {f.exposure} | {n} host(s) |")
    out.append("")

    by_cvss = sorted(result.findings, key=lambda f: -(f.cve.cvss or 0))
    if by_cvss and result.findings and by_cvss[0].fingerprint != result.findings[0].fingerprint:
        a, b = by_cvss[0], result.findings[0]
        out += ["## Why not just sort by CVSS?", "",
                f"CVSS alone would put **{a.cve.cve_id}** on {a.asset_name} first (CVSS {a.cve.cvss}, EPSS "
                f"{a.epss:.3f}, {a.exposure}, blast radius {len(a.blast.targets) if a.blast else 0}). "
                f"This report puts **{b.cve.cve_id}** on {b.asset_name} first (CVSS {b.cve.cvss}, EPSS {b.epss:.3f}"
                f"{', in CISA KEV' if b.kev else ''}, {b.exposure}, blast radius "
                f"{len(b.blast.targets) if b.blast else 0}).", ""]

    if result.paths:
        out += ["## Attack paths to crown jewels", ""]
        for p in result.paths:
            hops = " → ".join(_name(result, n) if n != "internet" else "Internet" for n in p.nodes)
            out.append(f"- **{_name(result, p.target)}** (path likelihood {p.probability:.2f}): {hops}")
            for a, b, port, cve in p.steps:
                out.append(f"    - {_name(result, a) if a != 'internet' else 'Internet'} → {_name(result, b)} "
                           f"on {port} via {cve}")
        out.append("")

    out += ["## Blast radius by entry point", ""]
    if not result.entry_points:
        out += ["No host is exploitable directly from the internet.", ""]
    for ip in result.entry_points:
        b = result.blast[ip]
        out.append(f"### {_name(result, ip)} ({ip}): score {b.score:.2f}, {len(b.targets)} secondary target(s)")
        out.append("")
        for t in b.targets:
            out.append(f"- hop {t.hops}: {t.name} ({t.ip}), criticality {t.criticality}, "
                       f"via {t.via_port} / {t.via_cve}")
        out.append("")
    out += ["## Method", "",
            "Priority = 100 × √likelihood × CVSS/10 × (0.3·criticality/5 + 0.25·exposure + 0.25·blast radius + "
            "0.2·chokepoint). Likelihood is the FIRST EPSS probability, floored for CISA KEV entries. Exposure is 1.0 "
            "for internet-facing, 0.5 when reachable from a host an internet attacker can take, 0.25 otherwise. Blast "
            "radius is the criticality reachable by chaining exploitable services from the host (halved per hop), "
            "relative to the worst host in this scan. Chokepoint is the share of attack paths that pass through "
            "the host.",
            ""]
    return "\n".join(out)


def write_outputs(result: AnalysisResult, *, json_path: Path | None = None, md_path: Path | None = None,
                  top: int = 15, graph_rel: str | None = None) -> None:
    """Write the JSON and/or Markdown report, creating parent directories as needed."""
    if json_path:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(to_json(result), indent=2), encoding="utf-8")
    if md_path:
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(to_markdown(result, top=top, graph_path=graph_rel), encoding="utf-8")
