"""Tests for the SARIF, Markdown and JSON outputs and graph rendering."""

import json

import pytest
from conftest import EXAMPLES

from vuln_scanner.render import classify, export_graph_json, render_blast_radius
from vuln_scanner.report import to_json, to_markdown
from vuln_scanner.sarif import level_for, to_sarif, validate_sarif


def test_sarif_structure(lab_result, tmp_path):
    doc = to_sarif(lab_result, base=tmp_path)
    assert validate_sarif(doc) == []
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == len({r["id"] for r in rules}) == 10  # CVE-2020-1938 appears on two ports
    first = run["results"][0]
    assert first["ruleId"] == "CVE-2021-42013" and first["level"] == "error"
    assert first["rank"] == lab_result.findings[0].priority
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith("examples/lab_scan.xml")
    assert not loc["artifactLocation"]["uri"].startswith("/")
    line = (EXAMPLES / "lab_scan.xml").read_text().splitlines()[loc["region"]["startLine"] - 1]
    assert 'portid="80"' in line
    assert first["properties"]["kev"] is True and len(first["properties"]["secondaryTargets"]) == 4
    assert rules[first["ruleIndex"]]["properties"]["security-severity"] == "9.8"
    assert "cisa-kev" in rules[first["ruleIndex"]]["properties"]["tags"]
    assert run["properties"]["entryPoints"] == ["10.10.1.10"]
    fps = [r["partialFingerprints"]["hostPortCve/v1"] for r in run["results"]]
    assert len(fps) == len(set(fps))
    json.dumps(doc)


def test_sarif_validator_catches_problems():
    bad = {
        "version": "2.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "A"}, {"id": "A"}]}},
                "results": [
                    {
                        "ruleId": "B",
                        "ruleIndex": 0,
                        "level": "fatal",
                        "rank": 101,
                        "message": {},
                        "locations": [{"physicalLocation": {"region": {"startLine": 0}}}],
                    }
                ],
            }
        ],
    }
    problems = " | ".join(validate_sarif(bad))
    for needle in ("2.1.0", "duplicate", "bad level", "message.text", "ruleIndex", "rank", "startLine"):
        assert needle in problems


@pytest.mark.parametrize(("priority", "level"), [(80, "error"), (40, "error"), (20, "warning"), (5, "note")])
def test_levels(priority, level):
    assert level_for(priority) == level


def test_markdown_report(lab_result):
    md = to_markdown(lab_result, top=5, graph_path="blast.png")
    assert "![Blast radius](blast.png)" in md
    assert md.count("| **") == 5
    assert "Why not just sort by CVSS?" in md and "CVE-2022-0543" in md
    assert "Internet → web01 → app01 → fs01" in md
    assert "### web01 (10.10.1.10)" in md


def test_json_report(lab_result):
    doc = to_json(lab_result)
    assert doc["findings"][0]["cve"] == "CVE-2021-42013"
    assert doc["findings"][0]["secondary_targets"][0]["name"] == "app01"
    assert doc["attack_paths"][0]["steps"][0]["from"] == "internet"


def test_roles(lab_result):
    roles = classify(lab_result)
    assert roles["10.10.1.10"] == "entry"
    assert {roles[ip] for ip in ("10.10.2.20", "10.10.2.21", "10.10.3.30", "10.10.3.31")} == {"secondary"}
    assert roles["10.10.4.41"] == "vulnerable" and roles["10.10.5.50"] == "clean"
    focus = classify(lab_result, focus="10.10.2.21")
    assert focus["10.10.2.21"] == "focus" and focus["10.10.1.10"] == "vulnerable"


def test_render_png_and_svg(lab_result, tmp_path):
    png = render_blast_radius(lab_result, tmp_path / "g" / "blast.png")
    assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" and png.stat().st_size > 20_000
    svg = render_blast_radius(lab_result, tmp_path / "focus.svg", focus="10.10.2.20")
    assert "<svg" in svg.read_text()[:500]
    with pytest.raises(ValueError, match="not in the scan"):
        render_blast_radius(lab_result, tmp_path / "x.png", focus="192.0.2.1")


def test_graph_json_export(lab_result, tmp_path):
    data = json.loads(export_graph_json(lab_result, tmp_path / "g.json").read_text())
    links = {(link["source"], link["target"]): link for link in data["links"]}
    assert links[("internet", "10.10.1.10")]["exploitable"] is True
    assert links[("internet", "10.10.1.11")]["exploitable"] is False
    node = next(n for n in data["nodes"] if n["id"] == "10.10.1.10")
    assert node["secondary_targets"][0] == "10.10.2.20"
