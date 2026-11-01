from __future__ import annotations

import json

import httpx
import pytest
from conftest import ROOT

from evidence_timeline import hayabusa
from evidence_timeline.config import ConfigError, Settings, check_artifact
from evidence_timeline.package import verify_package, write_package
from evidence_timeline.signing import Verifier, sign
from evidence_timeline.timeline import highlights, hub_events, merge, to_csv, triage_rows


def test_settings_from_env():
    s = Settings.from_env({"EVIDENCE_MODE": "LOCAL", "TRIAGE_ARTIFACTS": "Windows.System.Pslist, Generic.Client.Info",
                           "EVIDENCE_WINDOW_BEFORE_S": "60"}, dotenv=False)
    assert s.mode == "local" and s.triage_artifacts == ("Windows.System.Pslist", "Generic.Client.Info")
    assert s.window_before_s == 60 and "shared_secret" not in repr(s)


@pytest.mark.parametrize("env, msg", [
    ({"EVIDENCE_MODE": "ssh"}, "EVIDENCE_MODE"),
    ({"TRIAGE_ARTIFACTS": "Windows.Remediation.Quarantine"}, "allowlist"),
    ({"TRIAGE_ARTIFACTS": "Windows.System.PowerShell"}, "allowlist"),
    ({"HAYABUSA_ARTIFACT": "Admin.Client.Upgrade"}, "allowlist"),
    ({"EVIDENCE_WINDOW_BEFORE_S": "x"}, "integer"),
    ({"EVIDENCE_COLLECT_TIMEOUT_S": "5"}, ">="),
])
def test_settings_errors(env, msg):
    with pytest.raises(ConfigError, match=msg):
        Settings.from_env(env, dotenv=False)


@pytest.mark.parametrize("name", ["Windows.EventLogs.Hayabusa", "Windows.Sysinternals.Autoruns",
                                  "Windows.Network.Netstat", "Linux.Sys.Pslist", "Generic.Client.Info"])
def test_allowlisted_artifacts(name):
    assert check_artifact(name) == name


def test_signatures_and_replay():
    clock = [1_000_000.0]
    v = Verifier("s" * 40, clock=lambda: clock[0])
    body = b'{"a":1}'
    ts, sig = sign("s" * 40, body, 1_000_000)
    assert v.verify(body, ts, sig)
    assert not v.verify(body, ts, sig)  # replay
    ts2, sig2 = sign("s" * 40, body, 1_000_001)
    assert not v.verify(b'{"a":2}', ts2, sig2)  # tampered body
    assert not v.verify(body, ts2, sig2.replace("sha256=", "md5="))
    assert not v.verify(body, "soon", sig2)
    assert not v.verify(body, None, sig2)
    old_ts, old_sig = sign("s" * 40, body, 1_000_000 - 301)
    assert not v.verify(body, old_ts, old_sig)
    assert not Verifier("").verify(body, ts2, sig2)
    clock[0] += 1000  # seen-cache is pruned; the old signature is now refused for being stale instead
    assert not v.verify(body, ts, sig)
    assert sign("k", b"")[0].isdigit()


def test_hayabusa_csv_and_velociraptor_rows():
    rows = hayabusa.read_csv(ROOT / "examples" / "hayabusa" / "ws01.csv", "ws01", 1000)
    assert len(rows) == 10 and rows[1]["title"] == "Suspicious Office Child Process" and rows[1]["level"] == "high"
    assert rows[6]["level"] == "critical" and rows[0]["ref"] == "Sysmon:1"
    assert len(hayabusa.read_csv(ROOT / "examples" / "hayabusa" / "ws01.csv", "ws01", 3)) == 3
    velo = hayabusa.to_rows([{"Timestamp": "2026-10-26T09:00:12Z", "RuleTitle": "x", "Level": "med"},
                             {"Timestamp": "", "RuleTitle": "no time"}, {"Timestamp": 1793005212, "RuleTitle": "y"},
                             {"Timestamp": "garbage", "RuleTitle": "z"},
                             {"Timestamp": "2026-10-26 09:00:12 +00:00", "RuleTitle": "w", "Computer": "WS01"}], "ws01")
    assert [(r["title"], r["time"], r["level"]) for r in velo] == [
        ("x", 1793005212000, "medium"), ("y", 1793005212000, "informational"), ("w", 1793005212000, "informational")]
    assert velo[2]["host"] == "WS01"
    assert hayabusa.parse_time(1793005212000) == 1793005212000
    assert hayabusa.parse_time("2026-10-26T09:00:12") == 1793005212000


def test_triage_and_merge_and_highlights():
    t = triage_rows("Windows.System.Pslist", [{"Pid": 4, "Name": "System", "Ppid": 0, "CommandLine": ""},
                                              {"Name": "svchost", "Laddr": "10.0.0.5:445", "Raddr": "10.0.0.9:5000",
                                               "Status": "ESTAB"},
                                              {"Entry": "Updater", "Entry Location": "HKLM\\Run",
                                               "Launch String": "=cmd /c calc"},
                                              {"Other": 1}], "ws01", 5)
    assert [r["title"] for r in t] == ["process System (pid 4, ppid 0)",
                                       "svchost 10.0.0.5:445 -> 10.0.0.9:5000 ESTAB", "autorun Updater @ HKLM\\Run",
                                       "Windows.System.Pslist"]
    rows = merge(t, [{"time": 1, "source": "hayabusa", "host": "ws01", "title": "a", "level": "critical",
                      "details": "", "ref": "", "tags": ""}])
    assert rows[0]["title"] == "a" and rows[0]["time_utc"] == "1970-01-01T00:00:00.001Z"
    assert highlights(rows) == [{"time": "1970-01-01T00:00:00.001Z", "source": "hayabusa", "title": "a",
                                 "level": "critical"}]
    csv_text = to_csv(rows)
    assert "'=cmd /c calc" in csv_text  # formula injection neutralised


def test_hub_events_mapping():
    seen = {}

    def handler(req):
        seen["params"], seen["auth"] = dict(req.url.params), req.headers.get("authorization")
        return httpx.Response(200, json=[
            {"time": 5, "class_uid": 2004, "severity_id": 5, "finding_title": "Bad", "product": "edr-canary",
             "message": "m", "uid": "f1", "techniques": ["T1059"]},
            {"time": 4, "class_uid": 1007, "process_name": "cmd.exe", "cmd_line": "cmd /c x", "product": "sysmon"},
            {"time": 3, "class_uid": 1007, "process_name": "a.exe"},
            {"time": 2, "class_uid": 1001, "file_path": "C:\\x"},
            {"time": 1, "class_uid": 4001}])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    rows = hub_events(client, "http://hub", "tok", "ws01", 0, 10)
    assert seen["params"]["hostname"] == "ws01" and seen["auth"] == "Bearer tok"
    assert [r["title"] for r in rows] == ["Bad", "cmd.exe: cmd /c x", "a.exe started", "C:\\x", "OCSF class 4001"]
    assert rows[0]["level"] == "critical" and rows[0]["tags"] == "T1059" and rows[1]["level"] == "informational"
    hub_events(client, "http://hub", "", "ws01", 0, 10)
    assert seen["auth"] is None


def test_package_write_verify_and_tamper(tmp_path):
    p = write_package(tmp_path, "INC-1", {"raw/../evil.jsonl": "x\n", "timeline.csv": "a,b\n"}, {"host": "h"})
    doc = json.loads((p / "manifest.json").read_text())
    assert {f["name"] for f in doc["files"]} == {"raw/evil.jsonl", "timeline.csv"}  # traversal stripped
    assert verify_package(p) == []
    (p / "timeline.csv").write_text("a,c\n")
    assert verify_package(p) == ["timeline.csv: hash mismatch"]
    (p / "timeline.csv").unlink()
    assert "timeline.csv: missing" in verify_package(p)
    (p / "manifest.json").write_text(json.dumps({**doc, "host": "other"}))
    assert verify_package(p)[0].startswith("manifest.json does not match")
    again = write_package(tmp_path, "INC-1", {"t.csv": "1"}, {})
    assert again == p and len(list(tmp_path.glob("INC-1.prev-*"))) == 1  # the earlier package is kept


def test_package_failure_cleans_up(tmp_path, monkeypatch):
    import evidence_timeline.package as pkg

    def boom(*a):
        raise OSError("disk full")

    monkeypatch.setattr(pkg.os, "replace", boom)
    with pytest.raises(OSError):
        write_package(tmp_path, "INC-2", {"a": "b"}, {})
    assert list(tmp_path.iterdir()) == []
