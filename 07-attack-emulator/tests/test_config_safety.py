from __future__ import annotations

from pathlib import Path

import pytest
from conftest import campaign_doc

from attack_emulator.campaign import parse_campaign
from attack_emulator.config import ConfigError, Settings
from attack_emulator.safety import SafetyError, check_campaign, kube_server


def test_defaults_and_env(settings):
    assert settings.hub_url == "http://hub.test"
    assert str(settings.allowed_cidrs[0]) == "192.168.56.0/24"
    assert settings.poll_timeout_s == 10
    d = Settings.from_env({})
    assert d.kube_contexts == ("microk8s",) and not d.ssh_trust_lab_hostkeys and d.ssh_key is None
    s = Settings.from_env({"EMU_SSH_KEY": "/k", "EMU_SSH_TRUST_LAB_HOSTKEYS": "yes",
                           "LAB_KUBE_CONTEXTS": "a, b", "LAB_ALLOWED_CIDRS": "10.9.0.0/16, fd00::/64"})
    assert s.ssh_trust_lab_hostkeys and s.ssh_key == Path("/k") and s.kube_contexts == ("a", "b")


@pytest.mark.parametrize("env, msg", [
    ({"LAB_ALLOWED_CIDRS": "0.0.0.0/0"}, "wider"),
    ({"LAB_ALLOWED_CIDRS": "10.0.0.0/8"}, "wider"),
    ({"LAB_ALLOWED_CIDRS": "::/0"}, "wider"),
    ({"LAB_ALLOWED_CIDRS": " , "}, "at least one"),
    ({"LAB_ALLOWED_CIDRS": "lab"}, "LAB_ALLOWED_CIDRS"),
    ({"EMU_POLL_TIMEOUT_S": "soon"}, "number"),
    ({"EMU_POLL_TIMEOUT_S": "1"}, ">="),
])
def test_config_errors(env, msg):
    with pytest.raises(ConfigError, match=msg):
        Settings.from_env(env)


def lab_server(ctx):
    return "https://192.168.56.10:16443"


def test_live_needs_confirm(campaign, settings):
    with pytest.raises(SafetyError, match="--confirm-lab"):
        check_campaign(campaign, settings, confirm=False, server_of=lab_server)


def test_ok(campaign, settings):
    notes = check_campaign(campaign, settings, confirm=True, server_of=lab_server)
    assert any("192.168.56.20" in n for n in notes) and any("microk8s" in n for n in notes)


def test_replay_needs_no_confirm(settings):
    c = parse_campaign(campaign_doc(targets=[{"name": "r", "executor": "replay", "hostname": "h"}],
                                    tests=[{"technique": "T1059", "target": "r", "test_numbers": [1]}]))
    assert check_campaign(c, settings, confirm=False) == []


@pytest.mark.parametrize("address", ["10.0.0.5", "lab-win01", "192.168.57.20"])
def test_address_outside_lab(settings, address):
    doc = campaign_doc()
    doc["targets"][1]["address"] = address
    with pytest.raises(SafetyError, match="must be an IP inside"):
        check_campaign(parse_campaign(doc), settings, confirm=True, server_of=lab_server)


def test_kube_context_not_allowed(settings):
    doc = campaign_doc()
    doc["targets"][0]["kube_context"] = "prod-eks"
    with pytest.raises(SafetyError, match="LAB_KUBE_CONTEXTS"):
        check_campaign(parse_campaign(doc), settings, confirm=True, server_of=lab_server)


def test_kube_context_points_outside(campaign, settings):
    with pytest.raises(SafetyError, match="outside the lab"):
        check_campaign(campaign, settings, confirm=True, server_of=lambda c: "https://k8s.example.com:443")


def test_kube_server(monkeypatch):
    class R:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    calls = []
    monkeypatch.setattr("subprocess.run", lambda argv, **kw: calls.append(argv) or R(0, "https://192.168.56.10:16443\n"))
    assert kube_server("microk8s") == "https://192.168.56.10:16443"
    assert calls[0][:3] == ["kubectl", "config", "view"] and "microk8s" in calls[0]
    monkeypatch.setattr("subprocess.run", lambda argv, **kw: R(1, err="no context"))
    with pytest.raises(SafetyError, match="no context"):
        kube_server("x")
