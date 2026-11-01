from __future__ import annotations

import json

import httpx
from conftest import CAMPAIGNS, FIXTURES, campaign_doc

from attack_emulator import cli
from attack_emulator.campaign import load_campaign, parse_campaign
from attack_emulator.config import Settings
from attack_emulator.executors import DryRunExecutor, KubectlExecutor, ReplayExecutor, SshExecutor, WinRmExecutor


def test_validate(capsys):
    assert cli.main(["validate", *map(str, sorted(CAMPAIGNS.glob("*.yml")))]) == 0
    assert capsys.readouterr().out.count("ok  ") == 3


def test_validate_bad(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("name: x\ntargets: []\n")
    assert cli.main(["validate", str(bad)]) == 2
    assert "targets" in capsys.readouterr().err


def test_dry_run_touches_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli.HubClient, "__init__", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no hub")))
    rc = cli.main(["run", str(CAMPAIGNS / "lab-windows.yml"), "--dry-run", "--out", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0 and out.count("[win01/winrm] ") == 5 and "detection coverage 0.0%" in out
    run = json.loads(next(tmp_path.glob("run-*[0-9a-f].json")).read_text())
    assert run["dry_run"] and {c["outcome"] for c in run["results"]} == {"skipped"}


def test_live_run_refused_without_confirm(capsys, monkeypatch):
    monkeypatch.setenv("LAB_ALLOWED_CIDRS", "192.168.56.0/24")
    assert cli.main(["run", str(CAMPAIGNS / "lab-windows.yml")]) == 2
    assert "--confirm-lab" in capsys.readouterr().err


def test_build_executors(tmp_path):
    c = parse_campaign(campaign_doc(targets=[
        {"name": "a", "executor": "kubectl", "hostname": "a", "kube_context": "microk8s"},
        {"name": "b", "executor": "winrm", "hostname": "b", "address": "192.168.56.20"},
        {"name": "c", "executor": "ssh", "hostname": "c", "address": "192.168.56.30"},
        {"name": "d", "executor": "replay", "hostname": "d"},
        {"name": "e", "executor": "dry-run", "hostname": "e"}],
        tests=[{"technique": "T1059", "target": "a", "test_numbers": [1]}]))
    s = Settings.from_env({"EMU_WINRM_USER": "u", "EMU_WINRM_PASSWORD": "p", "EMU_INGEST_TOKEN": "x"})
    ex = cli.build_executors(c, s, dry_run=False, run_id="r", fixtures=FIXTURES)
    assert isinstance(ex["kubectl"], KubectlExecutor) and isinstance(ex["winrm"], WinRmExecutor)
    assert isinstance(ex["ssh"], SshExecutor) and isinstance(ex["replay"], ReplayExecutor)
    assert isinstance(ex["dry-run"], DryRunExecutor)
    dry = cli.build_executors(c, s, dry_run=True, run_id="r", fixtures=None)
    assert len({id(e) for e in dry.values()}) == 1
    try:
        cli.build_executors(c, s, dry_run=False, run_id="r", fixtures=None)
    except cli.ConfigError as exc:
        assert "--fixtures" in str(exc)
    else:
        raise AssertionError("replay without fixtures must fail")


class FakeHub:
    """Detects whatever the platform's rules would: here, every technique except the gaps."""

    def __init__(self, *a, **k):
        self.closed = False

    def health(self):
        return {"status": "ok"}

    def findings(self, since, technique, hostname):
        if technique in ("T1070.003", "T1087.001", "T1562.001"):
            return []
        return [{"time": since + 3000, "finding_title": f"rule for {technique}", "product": "detection-rules",
                 "uid": "x"}]

    def telemetry(self, since, until, hostname, match=None):
        return [] if match is None else [{"class_uid": 1007}]

    def close(self):
        self.closed = True


def test_replay_run_end_to_end(tmp_path, capsys, monkeypatch):
    posted = []
    real_client = httpx.Client

    def fake_client(*a, **k):
        def handler(req):
            posted.append(req.content.decode().count("\n") + bool(req.content))
            return httpx.Response(200, json={"accepted": 1})
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr("attack_emulator.executors.replay.httpx.Client", fake_client)
    monkeypatch.setattr(cli, "HubClient", FakeHub)
    monkeypatch.setattr("attack_emulator.poller.time.sleep", lambda s: None)
    monkeypatch.setattr("attack_emulator.runner.time.sleep", lambda s: None)
    monkeypatch.setenv("EMU_INGEST_TOKEN", "ingest-token-123")
    monkeypatch.setenv("EMU_POLL_TIMEOUT_S", "5")
    rc = cli.main(["run", str(CAMPAIGNS / "replay-demo.yml"), "--fixtures", str(FIXTURES), "--out", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0, out
    doc = json.loads(next(p for p in tmp_path.glob("run-*.json") if not p.name.endswith(".layer.json")).read_text())
    outcomes = {c["technique"]: c["outcome"] for c in doc["results"]}
    assert outcomes["T1003.008"] == "detected" and outcomes["T1070.003"] == "telemetry_only"
    assert len(posted) == len(load_campaign(CAMPAIGNS / "replay-demo.yml").tests)
    assert cli.main(["report", str(tmp_path / f"{doc['run_id']}.json")]) == 0
    assert "Emulation run" in capsys.readouterr().out


def test_report_rejects_other_docs(tmp_path, capsys):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"kind": "coverage"}))
    assert cli.main(["report", str(p)]) == 2


def test_hub_down(monkeypatch, capsys):
    class Down(FakeHub):
        def health(self):
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(cli, "HubClient", Down)
    monkeypatch.setenv("EMU_INGEST_TOKEN", "ingest-token-123")
    assert cli.main(["run", str(CAMPAIGNS / "replay-demo.yml"), "--fixtures", str(FIXTURES)]) == 2
    assert "hub unreachable" in capsys.readouterr().err
