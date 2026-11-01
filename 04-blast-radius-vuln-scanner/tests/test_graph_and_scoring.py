"""Tests for reachability, exploit graphs, blast radius and attack paths."""

import networkx as nx
import pytest

from vuln_scanner.analysis import compute_priority
from vuln_scanner.graph import attack_paths, blast_radius, build_graphs, chokepoint, exposure
from vuln_scanner.inventory import INTERNET, load_inventory
from vuln_scanner.nmap_parser import Service


def test_reachability_follows_policy(lab_result):
    r = lab_result.reach
    assert r.edges[INTERNET, "10.10.1.10"]["ports"] == [80]
    assert r.edges["10.10.1.10", "10.10.2.20"]["ports"] == [8009, 8080]
    assert not r.has_edge(INTERNET, "10.10.3.30")
    assert not r.has_edge("10.10.1.10", "10.10.3.30")  # dmz cannot reach data
    assert r.has_edge("10.10.2.20", "10.10.2.21")  # flat app VLAN


def test_exploit_graph_only_keeps_likely_hops(lab_result):
    e = lab_result.exploit
    assert e.has_edge(INTERNET, "10.10.1.10")
    assert not e.has_edge(INTERNET, "10.10.1.11")  # vpn01 has nothing exploitable
    assert not e.has_edge("10.10.4.40", "10.10.5.50")  # jump01 is clean
    assert e.edges["10.10.2.20", "10.10.3.31"]["cve"] == "CVE-2017-7494"


def test_blast_radius_of_entry_point(lab_result):
    b = lab_result.blast["10.10.1.10"]
    assert [(t.name, t.hops) for t in b.targets] == [("app01", 1), ("db01", 2), ("fs01", 2), ("cache01", 2)]
    assert b.score == pytest.approx(4 + 0.5 * (5 + 5 + 3))
    assert lab_result.blast["10.10.4.41"].targets == ()


def test_attack_paths_pick_most_likely_route_to_crown_jewels(lab_result):
    paths = {p.target: p for p in lab_result.paths}
    assert set(paths) == {"10.10.2.20", "10.10.3.30", "10.10.3.31"}
    assert paths["10.10.3.31"].nodes == (INTERNET, "10.10.1.10", "10.10.2.20", "10.10.3.31")
    assert paths["10.10.3.31"].probability == pytest.approx(0.944 * 0.944 * 0.941, abs=1e-3)
    assert chokepoint(lab_result.paths, "10.10.1.10") == 1.0
    assert chokepoint(lab_result.paths, "10.10.3.30") == pytest.approx(1 / 3, abs=1e-3)
    assert chokepoint([], "x") == 0.0


def test_exposure_classes(lab_result):
    assert exposure(lab_result.reach, lab_result.exploit, "10.10.1.10", 80) == "internet"
    assert exposure(lab_result.reach, lab_result.exploit, "10.10.2.20", 8009) == "chained"
    assert exposure(lab_result.reach, lab_result.exploit, "10.10.1.10", 22) == "internal"
    assert exposure(lab_result.reach, lab_result.exploit, "10.10.4.41", 21) == "internal"


def test_cycles_and_depth_limit(tmp_path):
    inv_file = tmp_path / "i.yml"
    inv_file.write_text(
        "assets:\n"
        + "".join(f" - {{ip: 10.0.0.{i}, zone: z{i}, criticality: 4}}\n" for i in range(1, 6))
        + "flows:\n"
        + "".join(f" - {{from: z{i}, to: z{i % 5 + 1}, ports: [22]}}\n" for i in range(1, 6))
    )
    inv = load_inventory(inv_file)
    svcs = [Service(f"10.0.0.{i}", 22, "tcp", "ssh") for i in range(1, 6)]
    likely = {(f"10.0.0.{i}", 22): (0.9, "CVE-X") for i in range(1, 6)}
    _, exploit = build_graphs(svcs, inv, likely, 0.1)
    assert nx.is_directed_acyclic_graph(exploit) is False
    b = blast_radius(exploit, "10.0.0.1", max_hops=2, decay=0.5)
    assert [t.ip for t in b.targets] == ["10.0.0.2", "10.0.0.3"]
    assert blast_radius(exploit, "10.0.0.1", 16, 0.5).targets[-1].hops == 4
    assert blast_radius(exploit, "missing", 4, 0.5).score == 0
    assert attack_paths(exploit) == []  # nothing reachable from the internet


def test_priority_formula_bounds_and_monotonicity():
    top = compute_priority(1.0, 1.0, 5, "internet", 1.0, 1.0)
    assert top == 100.0
    assert compute_priority(0.0, 1.0, 5, "internet", 1.0, 1.0) == 0.0
    base = compute_priority(0.3, 0.8, 3, "chained", 0.5, 0.5)
    assert compute_priority(0.6, 0.8, 3, "chained", 0.5, 0.5) > base
    assert compute_priority(0.3, 0.8, 3, "internet", 0.5, 0.5) > base
    assert compute_priority(0.3, 0.8, 3, "chained", 0.9, 0.5) > base
    assert compute_priority(0.3, 0.8, 5, "chained", 0.5, 0.5) > base
    assert compute_priority(5.0, 1.0, 5, "internet", 9.0, 9.0) == 100.0  # inputs are clamped
