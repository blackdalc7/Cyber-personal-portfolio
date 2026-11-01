from __future__ import annotations

import copy

import pytest
from conftest import CAMPAIGNS, campaign_doc

from attack_emulator.campaign import CampaignError, load_campaign, parse_campaign


def test_parse_ok(campaign):
    assert campaign.live
    assert set(campaign.targets) == {"k8s", "win"}
    t = campaign.tests[0]
    assert t.key == "T1003.008#1" and t.telemetry_match == "shadow" and t.cleanup
    assert campaign.tests[1].key == "T1059.001#Encoded it's"


def test_guid_key():
    doc = campaign_doc(tests=[{"technique": "t1059", "target": "k8s",
                               "test_guids": ["a6c49d78-1a3a-4c4d-a0d6-a4b0fcb8a5c1"]}])
    c = parse_campaign(doc)
    assert c.tests[0].technique == "T1059" and c.tests[0].key == "T1059#a6c49d78"


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d.update(name=""), "'name'"),
    (lambda d: d.update(targets=[]), "targets"),
    (lambda d: d.update(tests=[]), "tests"),
    (lambda d: d.update(settle_s=-1), "settle_s"),
    (lambda d: d["targets"].append(dict(d["targets"][0])), "duplicate"),
    (lambda d: d["targets"][0].update(executor="psexec"), "executor"),
    (lambda d: d["targets"][0].update(name="bad name"), "simple identifier"),
    (lambda d: d["targets"][0].update(hostname="-x"), "valid host"),
    (lambda d: d["targets"][0].pop("kube_context"), "kube_context"),
    (lambda d: d["targets"][1].pop("address"), "address"),
    (lambda d: d["targets"][0].update(namespace="Bad_NS!"), "Kubernetes name"),
    (lambda d: d["targets"][0].update(atomics_path="C:\\x'; rm"), "atomics_path"),
    (lambda d: d["targets"].__setitem__(0, "nope"), "mapping"),
    (lambda d: d["tests"].__setitem__(0, "nope"), "mapping"),
    (lambda d: d["tests"][0].update(technique="TA0001"), "T1059"),
    (lambda d: d["tests"][0].update(target="nowhere"), "unknown target"),
    (lambda d: d["tests"][0].update(test_numbers=[0]), "1-999"),
    (lambda d: d["tests"][0].update(test_numbers=[True]), "1-999"),
    (lambda d: d["tests"][0].update(test_guids=["not-a-guid"]), "GUIDs"),
    (lambda d: d["tests"][0].update(test_numbers=[]), "never 'all'"),
    (lambda d: d["tests"][1].update(test_names=["line\nbreak"]), "single-line"),
    (lambda d: d["tests"][0].update(input_args=["x"]), "input_args"),
    (lambda d: d["tests"][0].update(input_args={"bad-name": "x"}), "valid identifier"),
    (lambda d: d["tests"][0].update(input_args={"x": "a\nb"}), "single-line"),
    (lambda d: d["tests"][0].update(input_args={"x": 1.5}), "single-line"),
    (lambda d: d["tests"][0].update(timeout_s=1), "timeout_s"),
    (lambda d: d["tests"][0].update(telemetry_match=""), "telemetry_match"),
])
def test_invalid(mutate, message):
    doc = copy.deepcopy(campaign_doc())
    mutate(doc)
    with pytest.raises(CampaignError, match=message):
        parse_campaign(doc)


def test_not_a_mapping():
    with pytest.raises(CampaignError):
        parse_campaign([1])


@pytest.mark.parametrize("path", sorted(CAMPAIGNS.glob("*.yml")), ids=lambda p: p.name)
def test_shipped_campaigns_validate(path):
    c = load_campaign(path)
    assert c.tests and all(t.test_names for t in c.tests)


def test_load_errors(tmp_path):
    with pytest.raises(CampaignError, match="cannot read"):
        load_campaign(tmp_path / "missing.yml")
    bad = tmp_path / "bad.yml"
    bad.write_text("name: [unclosed", encoding="utf-8")
    with pytest.raises(CampaignError, match="cannot read"):
        load_campaign(bad)
