"""Turns services into ranked findings: CVE lookup → EPSS + KEV likelihood → graph context → priority.

Priority (0-100)
----------------
    likelihood = max(EPSS, KEV floor if the CVE is in CISA KEV)
    impact     = CVSS base score / 10           (5.0 when NVD has no score yet)
    context    = 0.3 * criticality/5 + 0.25 * exposure + 0.25 * blast_radius + 0.2 * chokepoint
    priority   = 100 * sqrt(likelihood) * impact * context

* EPSS is the probability of exploitation in the next 30 days; KEV means it is already
  happening, so KEV sets a floor instead of a bonus that could exceed 1.
* sqrt() compresses EPSS's long tail (most CVEs sit below 0.01) without changing order,
  so a 0.02 is not treated as worthless next to a 0.9.
* exposure is 1.0 (internet), 0.5 (reachable through a host an internet attacker can take)
  or 0.25 (internal only).
* blast_radius is this host's blast-radius score relative to the largest one in the scan
  (see graph.py), so the same CVE ranks higher on the host that opens the most doors.
* chokepoint is the share of the most likely internet-to-crown-jewel attack paths that pass
  through this host, so fixing it breaks the most chains.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from dataclasses import dataclass, field

import networkx as nx

from .config import Settings
from .feeds import CveRecord, EpssClient, FeedError, KevCatalog, NvdClient
from .graph import AttackPath, BlastRadius, attack_paths, blast_radius, build_graphs, chokepoint, exposure
from .inventory import INTERNET, Inventory
from .nmap_parser import Service

logger = logging.getLogger("vuln_scanner.analysis")
EXPOSURE_WEIGHT = {"internet": 1.0, "chained": 0.5, "internal": 0.25}


@dataclass
class Finding:
    """One CVE on one exposed service, with every score that feeds its priority.

    ``likelihood`` combines EPSS and KEV; ``criticality`` and ``exposure`` come from
    the inventory; ``blast`` is the blast radius of the host the service runs on.
    """
    service: Service
    cve: CveRecord
    epss: float
    epss_percentile: float
    kev: bool
    kev_ransomware: bool
    likelihood: float
    criticality: int
    asset_name: str
    exposure: str = "internal"
    blast: BlastRadius | None = None
    chokepoint: float = 0.0
    priority: float = 0.0

    @property
    def impact(self) -> float:
        """CVSS base score scaled to 0-1 (5.0 is assumed when NVD has no score)."""
        return (self.cve.cvss if self.cve.cvss is not None else 5.0) / 10.0

    @property
    def fingerprint(self) -> str:
        """Stable identity ``host:port/proto:CVE`` used to deduplicate and track findings."""
        return f"{self.service.host}:{self.service.port}/{self.service.protocol}:{self.cve.cve_id}"


@dataclass
class AnalysisResult:
    """Everything one analysis run produced: services, ranked findings, graphs and attack paths.

    ``errors`` lists feed lookups that failed, so a report can flag incomplete data.
    """
    services: list[Service]
    findings: list[Finding]
    reach: nx.DiGraph
    exploit: nx.DiGraph
    blast: dict[str, BlastRadius]
    paths: list[AttackPath]
    errors: list[str] = field(default_factory=list)

    @property
    def entry_points(self) -> list[str]:
        """Hosts with an exploitable service reachable directly from the internet."""
        return sorted(self.exploit.successors(INTERNET)) if INTERNET in self.exploit else []


def _clamp(x: float) -> float:
    return min(max(x, 0.0), 1.0)


def compute_priority(likelihood: float, impact: float, criticality: int, exposure_kind: str, blast_rel: float,
                     chokepoint: float = 0.0) -> float:
    """Combine likelihood, impact and business context into a 0-100 priority score.

    Context weights: asset criticality 30%, exposure 25%, relative blast radius
    25%, chokepoint centrality 20%. ``sqrt(likelihood)`` keeps low-EPSS but
    high-impact findings from collapsing to zero.
    """
    context = (0.3 * criticality / 5 + 0.25 * EXPOSURE_WEIGHT[exposure_kind] + 0.25 * _clamp(blast_rel)
               + 0.2 * _clamp(chokepoint))
    return round(100 * math.sqrt(min(max(likelihood, 0.0), 1.0)) * impact * context, 2)


class Analyzer:
    """Run the full pipeline: CVE lookup, EPSS and KEV scoring, graph building and ranking."""
    def __init__(self, settings: Settings, nvd: NvdClient, epss: EpssClient, kev: KevCatalog) -> None:
        self.settings = settings
        self.nvd = nvd
        self.epss = epss
        self.kev = kev

    def run(self, services: Iterable[Service], inventory: Inventory) -> AnalysisResult:
        """Analyse ``services`` against ``inventory`` and return ranked findings.

        Feed failures for individual services are recorded in ``errors`` rather than
        aborting the whole run.
        """
        services = list(services)
        errors: list[str] = []
        per_service: list[tuple[Service, list[CveRecord]]] = []
        for svc in services:
            try:
                per_service.append((svc, self.nvd.cves_for(svc)))
            except FeedError as exc:
                errors.append(f"NVD lookup failed for {svc.key} ({svc.banner}): {exc}")
                per_service.append((svc, []))

        all_ids = {c.cve_id for _, cves in per_service for c in cves}
        try:
            epss = self.epss.scores(all_ids)
        except FeedError as exc:
            errors.append(f"EPSS unavailable, likelihood falls back to KEV only: {exc}")
            epss = {}

        findings: list[Finding] = []
        for svc, cves in per_service:
            asset = inventory.asset(svc.host)
            for c in cves:
                e = epss.get(c.cve_id)
                kev = self.kev.get(c.cve_id)
                p = e.epss if e else 0.0
                likelihood = max(p, self.settings.kev_likelihood_floor) if kev else p
                findings.append(Finding(service=svc, cve=c, epss=p, epss_percentile=e.percentile if e else 0.0,
                                        kev=kev is not None, kev_ransomware=bool(kev and kev.ransomware),
                                        likelihood=likelihood, criticality=asset.criticality, asset_name=asset.name))

        best: dict[tuple[str, int], tuple[float, str]] = {}
        for f in findings:
            k = (f.service.host, f.service.port)
            if f.likelihood > best.get(k, (-1.0, ""))[0]:
                best[k] = (f.likelihood, f.cve.cve_id)
        reach, exploit = build_graphs(services, inventory, best, self.settings.exploitable_threshold)

        blasts = {ip: blast_radius(exploit, ip, self.settings.max_hops, self.settings.hop_decay)
                  for ip in {s.host for s in services}}
        paths = attack_paths(exploit)
        worst = max((b.score for b in blasts.values()), default=0.0)
        for f in findings:
            f.exposure = exposure(reach, exploit, f.service.host, f.service.port)
            f.blast = blasts[f.service.host]
            f.chokepoint = chokepoint(paths, f.service.host)
            relative = f.blast.score / worst if worst else 0.0
            f.priority = compute_priority(f.likelihood, f.impact, f.criticality, f.exposure, relative, f.chokepoint)
        findings.sort(key=lambda f: (-f.priority, -f.likelihood, -(f.cve.cvss or 0), f.fingerprint))
        return AnalysisResult(services, findings, reach, exploit, blasts, paths, errors)
