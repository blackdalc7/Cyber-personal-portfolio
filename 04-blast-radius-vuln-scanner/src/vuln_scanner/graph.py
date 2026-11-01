"""Reachability and attack graphs with NetworkX.

Two directed graphs over the same nodes (every scanned host plus a synthetic ``internet``):

* **Reachability graph**: edge A → B when policy lets A reach an open port on B.
* **Exploit graph**: the subset of reachability edges where at least one reachable port on
  B runs a service whose exploitation likelihood is at or above the threshold. An attacker
  holding A can plausibly take B, so B is a pivot.

Blast radius of a host H = everything reachable from H in the exploit graph within
``max_hops``. Those are the "secondary internal targets" an attacker gets if H falls,
weighted by asset criticality and discounted per hop.

The most likely attack path from the internet to a crown jewel uses edge weight
``-log(likelihood)``, so Dijkstra's shortest path is the path with the highest product of
per-hop likelihoods.
"""

from __future__ import annotations

import itertools
import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

import networkx as nx

from .inventory import INTERNET, Inventory
from .nmap_parser import Service


@dataclass(frozen=True)
class SecondaryTarget:
    """A host an attacker could reach and exploit after compromising the blast-radius source."""
    ip: str
    name: str
    hops: int
    criticality: int
    via_port: int
    via_cve: str


@dataclass(frozen=True)
class BlastRadius:
    """How much an attacker could reach from one compromised host, weighted by criticality and distance."""
    source: str
    score: float
    normalised: float          # score / worst-case score (every other host one hop away)
    targets: tuple[SecondaryTarget, ...]


@dataclass(frozen=True)
class AttackPath:
    """The most likely exploit chain from the internet to one high-value host."""
    target: str
    nodes: tuple[str, ...]
    probability: float
    steps: tuple[tuple[str, str, int, str], ...]   # (from, to, port, cve)


def build_graphs(services: Iterable[Service], inventory: Inventory,
                 likelihood: dict[tuple[str, int], tuple[float, str]],
                 threshold: float) -> tuple[nx.DiGraph, nx.DiGraph]:
    """``likelihood`` maps (host, port) to (best likelihood, CVE id) for that service."""
    open_ports: dict[str, set[int]] = defaultdict(set)
    for s in services:
        open_ports[s.host].add(s.port)

    reach = nx.DiGraph()
    reach.add_node(INTERNET, name="Internet", zone=INTERNET, criticality=0, kind="internet")
    for ip in open_ports:
        a = inventory.asset(ip)
        vulnerable = any(likelihood.get((ip, p), (0.0, ""))[0] >= threshold for p in open_ports[ip])
        reach.add_node(ip, name=a.name, zone=a.zone, criticality=a.criticality, kind="host",
                       ports=sorted(open_ports[ip]), exploitable=vulnerable)

    sources = [(INTERNET, INTERNET)] + [(ip, inventory.asset(ip).zone) for ip in open_ports]
    for src_ip, src_zone in sources:
        for dst_ip, ports in open_ports.items():
            allowed = inventory.allowed_ports(src_ip, src_zone, inventory.asset(dst_ip), ports)
            if allowed:
                reach.add_edge(src_ip, dst_ip, ports=sorted(allowed))

    exploit = nx.DiGraph()
    exploit.add_nodes_from(reach.nodes(data=True))
    for u, v, data in reach.edges(data=True):
        best = max(((likelihood.get((v, p), (0.0, ""))[0], p, likelihood.get((v, p), (0.0, ""))[1])
                    for p in data["ports"]), default=(0.0, 0, ""))
        if best[0] >= threshold:
            exploit.add_edge(u, v, likelihood=best[0], port=best[1], cve=best[2],
                             weight=-math.log(max(best[0], 1e-9)))
    return reach, exploit


def blast_radius(exploit: nx.DiGraph, source: str, max_hops: int, decay: float) -> BlastRadius:
    """Compute the blast radius of ``source`` in the exploit graph.

    Every host within ``max_hops`` contributes its criticality times
    ``decay ** (hops - 1)``.
    """
    if source not in exploit:
        return BlastRadius(source, 0.0, 0.0, ())
    paths = nx.single_source_shortest_path(exploit, source, cutoff=max_hops)
    targets = []
    for node, path in paths.items():
        if node in (source, INTERNET):
            continue
        last = exploit.edges[path[-2], path[-1]]
        attrs = exploit.nodes[node]
        targets.append(SecondaryTarget(node, attrs.get("name", node), len(path) - 1, int(attrs.get("criticality", 0)),
                                       int(last["port"]), str(last["cve"])))
    targets.sort(key=lambda t: (t.hops, -t.criticality, t.ip))
    score = sum(t.criticality * decay ** (t.hops - 1) for t in targets)
    estate = sum(int(d.get("criticality", 0)) for n, d in exploit.nodes(data=True) if n not in (source, INTERNET))
    return BlastRadius(source, round(score, 3), round(score / estate, 4) if estate else 0.0, tuple(targets))


def exposure(reach: nx.DiGraph, exploit: nx.DiGraph, host: str, port: int) -> str:
    """internet: directly reachable from the internet on this port.
    chained: reachable on this port from a host an internet attacker can already take.
    internal: only reachable from inside."""
    if reach.has_edge(INTERNET, host) and port in reach.edges[INTERNET, host]["ports"]:
        return "internet"
    owned = nx.descendants(exploit, INTERNET) if INTERNET in exploit else set()
    for pred in reach.predecessors(host):
        if pred in owned and port in reach.edges[pred, host]["ports"]:
            return "chained"
    return "internal"


def attack_paths(exploit: nx.DiGraph, min_criticality: int = 4) -> list[AttackPath]:
    """Find the most likely path from the internet to each host with criticality >= ``min_criticality``.

    Edge weights are ``-log(likelihood)``, so the shortest path is the most probable.
    """
    out = []
    for node, data in exploit.nodes(data=True):
        if node == INTERNET or int(data.get("criticality", 0)) < min_criticality:
            continue
        try:
            path = nx.dijkstra_path(exploit, INTERNET, node, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        steps = tuple((u, v, int(exploit.edges[u, v]["port"]), str(exploit.edges[u, v]["cve"]))
                      for u, v in itertools.pairwise(path))
        prob = math.prod(exploit.edges[u, v]["likelihood"] for u, v in itertools.pairwise(path))
        out.append(AttackPath(node, tuple(path), round(prob, 4), steps))
    out.sort(key=lambda p: (-p.probability, len(p.nodes), p.target))
    return out


def chokepoint(paths: list[AttackPath], host: str) -> float:
    """Share of attack paths that enter ``host`` (as a stepping stone or as the target)."""
    if not paths:
        return 0.0
    return round(sum(1 for p in paths if host in p.nodes[1:]) / len(paths), 4)
