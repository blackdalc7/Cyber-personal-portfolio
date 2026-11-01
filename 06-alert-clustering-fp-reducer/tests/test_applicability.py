"""Tests for structural attack requirements."""

import pytest

from alert_triage.applicability import RequirementError, load_requirements


def test_matching_and_immunity(cmdb, requirements):
    reqs = requirements.for_alert("ET EXPLOIT Possible BlueKeep RDP exploitation attempt", "")
    assert [r.id for r in reqs] == ["rdp"]
    reasons = reqs[0].immunity(cmdb.asset("10.20.1.10"))
    assert len(reasons) == 2 and "runs linux" in reasons[0] and "3389" in reasons[1]
    assert reqs[0].immunity(cmdb.asset("10.20.4.40")) == []  # Windows DC with RDP open
    assert requirements.for_alert("Kerberoasting: excessive RC4", "") == []


def test_products_and_missing_inventory(cmdb, requirements):
    struts = requirements.for_alert("Apache Struts2 OGNL injection", "")[0]
    assert struts.immunity(cmdb.asset("10.20.2.20")) == []  # app01 runs a struts2 application
    assert "does not run it" in struts.immunity(cmdb.asset("10.20.4.42"))[0]
    rdp = requirements.for_alert("RDP brute force", "")[0]
    mac = cmdb.asset("10.30.10.22")  # no service inventory
    assert rdp.immunity(mac) == ["targets windows but mac-design-022 runs macos"]
    ssh = requirements.for_alert("SSH brute force", "")[0]
    assert ssh.immunity(mac) == []  # unknown ports are not immunity


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("{a: 1}", "expected a list"),
        ("- requires: {ports: [1]}", "match"),
        ("- {match: '(', requires: {ports: [1]}}", "match"),
        ("- {match: x, requires: {os_family: [beos]}}", "unknown os_family"),
        ("- {match: x}", "must name"),
    ],
)
def test_invalid_files(tmp_path, text, match):
    (tmp_path / "r.yml").write_text(text)
    with pytest.raises(RequirementError, match=match):
        load_requirements(tmp_path / "r.yml")


def test_empty_file(tmp_path):
    (tmp_path / "r.yml").write_text("")
    assert load_requirements(tmp_path / "r.yml").requirements == []
