"""Blast-radius picture: who an attacker reaches, and through what, once an entry point falls.

Columns are network distance from the internet. Colour answers "what is this host in the
attack story": red = entry point (exploitable from the internet), orange = secondary
target (reachable by chaining exploits), gold = vulnerable but not on any chain from the
internet, blue-grey = clean. Thick red edges are exploitable hops; thin grey edges are
plain reachability. Node size follows asset criticality.
"""

from __future__ import annotations

import json
from itertools import pairwise
from pathlib import Path

import matplotlib

matplotlib.use("Agg")   # headless: CI runners and containers have no display

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.lines import Line2D

from .analysis import AnalysisResult
from .inventory import INTERNET

ROLE_COLOURS = {"internet": "#1f2937", "entry": "#dc2626", "secondary": "#f97316", "vulnerable": "#eab308",
                "clean": "#94a3b8", "focus": "#7c3aed"}


def classify(result: AnalysisResult, focus: str | None = None) -> dict[str, str]:
    """Assign each node a drawing role: internet, entry point, focus, secondary target or other."""
    roles: dict[str, str] = {}
    entries = set(result.entry_points)
    sources = [focus] if focus else sorted(entries)
    secondary = {t.ip for s in sources for t in result.blast.get(s, ()).targets} if sources else set()
    if not focus:
        secondary -= entries
    for node, data in result.reach.nodes(data=True):
        if node == INTERNET:
            roles[node] = "internet"
        elif focus and node == focus:
            roles[node] = "focus"
        elif not focus and node in entries:
            roles[node] = "entry"
        elif node in secondary:
            roles[node] = "secondary"
        elif data.get("exploitable"):
            roles[node] = "vulnerable"
        else:
            roles[node] = "clean"
    return roles


def _layers(g: nx.DiGraph) -> dict[str, int]:
    dist = nx.single_source_shortest_path_length(g, INTERNET) if INTERNET in g else {}
    far = max(dist.values(), default=0) + 1
    return {n: dist.get(n, far) for n in g.nodes}


def render_blast_radius(result: AnalysisResult, out_path: str | Path, focus: str | None = None,
                        title: str | None = None) -> Path:
    """Draw the reachability graph with the blast radius highlighted, as PNG or SVG.

    With ``focus`` set, the picture shows what one specific host could reach.

    Raises:
        ValueError: if ``focus`` is not a scanned host.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    g = result.reach.copy()
    if focus is not None and focus not in g:
        raise ValueError(f"focus host {focus} is not in the scan")
    roles = classify(result, focus)
    for n, layer in _layers(g).items():
        g.nodes[n]["layer"] = layer
    pos = nx.multipartite_layout(g, subset_key="layer", align="vertical", scale=1.0)

    width = max(10.0, 3.2 * (max(nx.get_node_attributes(g, "layer").values(), default=1) + 1))
    fig, ax = plt.subplots(figsize=(width, 7.5), dpi=130)
    exploit_edges = set(result.exploit.edges)
    highlighted: set[tuple[str, str]] = set()
    if focus:
        # Shortest exploit chain from the compromised host to each target in its blast radius.
        highlighted = set(nx.bfs_tree(result.exploit, focus).edges)
    else:
        for p in result.paths:
            highlighted |= set(pairwise(p.nodes))

    plain = [e for e in g.edges if e not in exploit_edges]
    nx.draw_networkx_edges(g, pos, edgelist=plain, ax=ax, edge_color="#cbd5e1", width=0.8, arrowsize=8,
                           connectionstyle="arc3,rad=0.06", min_source_margin=12, min_target_margin=14)
    weak = [e for e in exploit_edges if e not in highlighted and e in g.edges]
    nx.draw_networkx_edges(g, pos, edgelist=weak, ax=ax, edge_color="#fca5a5", width=1.6, arrowsize=12,
                           connectionstyle="arc3,rad=0.06", min_source_margin=12, min_target_margin=14)
    strong = [e for e in highlighted if e in g.edges]
    nx.draw_networkx_edges(g, pos, edgelist=strong, ax=ax, edge_color="#b91c1c", width=3.0, arrowsize=16,
                           connectionstyle="arc3,rad=0.06", min_source_margin=12, min_target_margin=14)
    edge_labels = {(u, v): f"{result.exploit.edges[u, v]['port']}\n{result.exploit.edges[u, v]['cve']}"
                   for u, v in strong}
    nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels, ax=ax, font_size=6.5, font_color="#7f1d1d",
                                 bbox={"boxstyle": "round,pad=0.15", "fc": "white", "ec": "none", "alpha": 0.85},
                                 connectionstyle="arc3,rad=0.06")

    nodes = list(g.nodes)
    sizes = [900 if n == INTERNET else 380 + 260 * int(g.nodes[n].get("criticality", 1)) for n in nodes]
    colours = [ROLE_COLOURS[roles[n]] for n in nodes]
    nx.draw_networkx_nodes(g, pos, nodelist=nodes, node_size=sizes, node_color=colours, edgecolors="white",
                           linewidths=1.5, ax=ax)
    labels = {n: "Internet" if n == INTERNET
              else f"{g.nodes[n].get('name', n)}\n{n}\nC{g.nodes[n].get('criticality')}" for n in nodes}
    label_pos = {n: (x, y - 0.075) for n, (x, y) in pos.items()}
    nx.draw_networkx_labels(g, label_pos, labels=labels, font_size=7, ax=ax, verticalalignment="top")

    legend = [Line2D([0], [0], marker="o", color="w", markerfacecolor=ROLE_COLOURS[k], markersize=10, label=v)
              for k, v in (("entry", "Entry point (exploitable from internet)"),
                           ("secondary", "Secondary target (reachable by chaining)"),
                           ("vulnerable", "Vulnerable, not on a chain"), ("clean", "No exploitable service"))]
    if focus:
        legend.insert(0, Line2D([0], [0], marker="o", color="w", markerfacecolor=ROLE_COLOURS["focus"],
                                markersize=10, label=f"Assumed compromised: {focus}"))
    legend += [Line2D([0], [0], color="#b91c1c", lw=3, label="Attack path hop (port / CVE)"),
               Line2D([0], [0], color="#fca5a5", lw=1.6, label="Other exploitable hop"),
               Line2D([0], [0], color="#cbd5e1", lw=1, label="Network reachability")]
    ax.legend(handles=legend, loc="lower left", fontsize=7.5, frameon=True, framealpha=0.95)
    n_secondary = sum(1 for r in roles.values() if r == "secondary")
    ax.set_title(title or (f"Blast radius from {focus}" if focus else
                           f"Blast radius: {len(result.entry_points)} entry point(s), "
                           f"{n_secondary} secondary target(s)"),
                 fontsize=12, loc="left")
    ax.axis("off")
    ax.margins(0.12)
    fig.tight_layout()
    fig.savefig(out_path, format=out_path.suffix.lstrip(".") or "png")
    plt.close(fig)
    return out_path


def export_graph_json(result: AnalysisResult, out_path: str | Path) -> Path:
    """Node-link JSON (reachability graph annotated with exploit edges) for D3, Gephi or Neo4j import."""
    out_path = Path(out_path)
    g = result.reach.copy()
    for u, v in g.edges:
        g.edges[u, v]["exploitable"] = result.exploit.has_edge(u, v)
        if result.exploit.has_edge(u, v):
            e = result.exploit.edges[u, v]
            g.edges[u, v].update(likelihood=e["likelihood"], via_port=e["port"], via_cve=e["cve"])
    for n in g.nodes:
        b = result.blast.get(n)
        g.nodes[n]["blast_radius_score"] = b.score if b else 0.0
        g.nodes[n]["secondary_targets"] = [t.ip for t in b.targets] if b else []
    data = nx.node_link_data(g, edges="links")
    out_path.write_text(json.dumps(data, indent=2, default=list), encoding="utf-8")
    return out_path
