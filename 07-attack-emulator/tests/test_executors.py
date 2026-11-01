from __future__ import annotations

import base64
import json
import subprocess

import httpx
import pytest
from conftest import FIXTURES

from attack_emulator.campaign import Target
from attack_emulator.executors import (
    DryRunExecutor,
    KubectlExecutor,
    ReplayExecutor,
    SshExecutor,
    WinRmExecutor,
    build_invoke,
    encode_ps,
    is_prevented,
    ps_quote,
)
from attack_emulator.executors.replay import load_fixture, rebase


def decode(b64: str) -> str:
    return base64.b64decode(b64).decode("utf-16-le")


def test_ps_quote_neutralises_everything():
    assert ps_quote("a'b") == "'a''b'"
    assert ps_quote("$(Remove-Item C:\\ -Recurse); `n") == "'$(Remove-Item C:\\ -Recurse); `n'"


def test_build_invoke(campaign):
    shadow, encoded = campaign.tests
    s = build_invoke(shadow)
    assert "Invoke-AtomicTest 'T1003.008' -TestNumbers 1" in s and s.endswith("-Confirm:$false")
    assert "-TimeoutSeconds 120" in s and "-Cleanup" not in s
    e = build_invoke(encoded, cleanup=True, atomics_path="C:\\Atomic Red\\atomics")
    assert "-TestNames 'Encoded it''s'" in e
    assert "-InputArgs @{ 'command' = 'Write-Host ''x'''; 'count' = 2; 'flag' = $true }" in e
    assert "-PathToAtomicsFolder 'C:\\Atomic Red\\atomics'" in e and "-Cleanup" in e
    assert "-GetPrereqs" in build_invoke(encoded, prereqs=True)


def test_build_invoke_guids():
    from conftest import campaign_doc

    from attack_emulator.campaign import parse_campaign
    c = parse_campaign(campaign_doc(tests=[{"technique": "T1059", "target": "k8s", "input_args": {"f": False},
                                            "test_guids": ["a6c49d78-1a3a-4c4d-a0d6-a4b0fcb8a5c1"]}]))
    s = build_invoke(c.tests[0])
    assert "-TestGuids 'a6c49d78-1a3a-4c4d-a0d6-a4b0fcb8a5c1'" in s and "'f' = $false" in s


def test_encode_ps_roundtrip():
    assert decode(encode_ps("Write-Host 'hé'")) == "Write-Host 'hé'"


def test_is_prevented():
    assert is_prevented(1, "", "Operation did not complete successfully because the file contains a virus")
    assert is_prevented(0, "", "This script contains malicious content and has been blocked by your antivirus")
    assert not is_prevented(0, "Done", "")
    assert not is_prevented(1, "", "Access is denied.")


class Proc:
    def __init__(self, rc=0, out="ok", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


K8S = Target(name="k8s", executor="kubectl", hostname="lab-k8s", kube_context="microk8s")


def test_kubectl_argv_only(campaign):
    calls = []

    def runner(argv, **kw):
        calls.append((argv, kw))
        return Proc()

    ex = KubectlExecutor(runner)
    test = campaign.tests[0]
    res = ex.run(test, K8S)
    argv, kw = calls[0]
    assert argv[:7] == ["kubectl", "--context", "microk8s", "-n", "atomic", "exec", "deploy/atomic-runner"]
    assert argv[-3] == "-NonInteractive" or "-EncodedCommand" in argv
    assert "Invoke-AtomicTest 'T1003.008'" in decode(argv[-1])
    assert kw["timeout"] == test.timeout_s + 30 and "shell" not in kw
    assert res.rc == 0 and res.executed and not res.prevented
    assert ex.cleanup(test, K8S).rc == 0 and "-Cleanup" in decode(calls[-1][0][-1])
    ex.close()


def test_kubectl_prereqs_timeout_missing(campaign):
    from dataclasses import replace
    test = replace(campaign.tests[0], get_prereqs=True)
    seen = []
    KubectlExecutor(lambda argv, **kw: seen.append(decode(argv[-1])) or Proc()).run(test, K8S)
    assert "-GetPrereqs" in seen[0] and "-GetPrereqs" not in seen[1]

    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)

    assert KubectlExecutor(slow).run(test, K8S).rc == 124

    def missing(argv, **kw):
        raise FileNotFoundError

    r = KubectlExecutor(missing).run(test, K8S)
    assert r.rc == 127 and not r.executed


WIN = Target(name="win", executor="winrm", hostname="lab-win01", address="192.168.56.20")


class WinResp:
    def __init__(self, rc, out, err):
        self.status_code, self.std_out, self.std_err = rc, out, err


def test_winrm(campaign):
    made, scripts = [], []

    class Session:
        def __init__(self, url, auth, transport):
            made.append((url, auth, transport))

        def run_ps(self, script):
            scripts.append(script)
            return WinResp(1, b"", b"This script contains malicious content and has been blocked")

    from dataclasses import replace
    ex = WinRmExecutor("vagrant", "vagrant", session_factory=Session)
    test = replace(campaign.tests[1], get_prereqs=True)
    res = ex.run(test, WIN)
    assert made == [("http://192.168.56.20:5985/wsman", ("vagrant", "vagrant"), "ntlm")]
    assert res.prevented and res.rc == 1 and len(scripts) == 2
    ex.cleanup(test, WIN)
    assert len(made) == 1  # session reused
    ex.close()
    with pytest.raises(ValueError, match="EMU_WINRM_USER"):
        WinRmExecutor("", "")


def test_winrm_transport_error(campaign):
    class Broken:
        def __init__(self, *a, **k):
            pass

        def run_ps(self, script):
            raise ConnectionError("refused")

    r = WinRmExecutor("u", "p", session_factory=Broken).run(campaign.tests[1], WIN)
    assert r.rc == 255 and "refused" in r.error


LNX = Target(name="lnx", executor="ssh", hostname="lab-lnx", address="192.168.56.30")


def test_ssh(campaign):
    class Chan:
        def recv_exit_status(self):
            return 0

    class Stream:
        def __init__(self, data):
            self.data, self.channel = data, Chan()

        def read(self):
            return self.data

    class Client:
        def __init__(self):
            self.cmds, self.closed = [], False

        def connect(self, host, **kw):
            self.host, self.kw = host, kw

        def exec_command(self, cmd, timeout):
            self.cmds.append(cmd)
            return None, Stream(b"done"), Stream(b"")

        def close(self):
            self.closed = True

    client = Client()
    ex = SshExecutor("vagrant", None, client_factory=lambda: client)
    res = ex.run(campaign.tests[0], LNX)
    assert client.host == "192.168.56.30" and client.kw["username"] == "vagrant"
    assert client.cmds[0].startswith("sudo -n pwsh -NoProfile -NonInteractive -EncodedCommand ")
    assert "'" not in client.cmds[0] and res.stdout == "done"
    ex.cleanup(campaign.tests[0], LNX)
    ex.close()
    assert client.closed


def test_ssh_error(campaign):
    class Bad:
        def connect(self, *a, **k):
            raise OSError("no route")

    r = SshExecutor("u", None, client_factory=Bad).run(campaign.tests[0], LNX)
    assert r.rc == 255 and "no route" in r.error


def test_ssh_default_factory_policy(monkeypatch):
    import paramiko
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda self, *a, **k: None)
    for trust, policy in ((False, paramiko.RejectPolicy), (True, paramiko.AutoAddPolicy)):
        ex = SshExecutor("u", None, trust_lab_hostkeys=trust)
        client = ex._client(Target(name="x", executor="ssh", hostname="x", address="192.0.2.1"))
        assert isinstance(client._policy, policy)
        ex.close()


def test_dry_run(campaign):
    ex = DryRunExecutor()
    r = ex.run(campaign.tests[0], K8S)
    assert not r.executed and r.rc == 0 and "Invoke-AtomicTest" in ex.commands[0]
    assert ex.cleanup(campaign.tests[0], K8S) is None
    ex.close()


def test_fixtures_are_activity_only():
    for path in FIXTURES.glob("*.ndjson"):
        for line in path.read_text().splitlines():
            doc = json.loads(line)
            assert doc["class_uid"] in (1001, 1007, 3002, 4001) and doc["metadata"]["version"] == "1.4.0"


def test_load_fixture_drops_findings(tmp_path):
    rows = [{"class_uid": 1007, "time": 5}, {"class_uid": 2004, "time": 6}, {"class_uid": 2005, "time": 7}]
    (tmp_path / "T1.ndjson").write_text("\n".join(json.dumps(r) for r in rows) + "\n\n")
    assert load_fixture(tmp_path, "T1") == [rows[0]]
    with pytest.raises(FileNotFoundError):
        load_fixture(tmp_path, "T2")


def test_rebase():
    events = [{"time": 100, "metadata": {"uid": "a", "labels": ["x"]}, "device": {"hostname": "old"}},
              {"time": 350, "metadata": {"uid": "b"}}]
    out = rebase(events, start_ms=10_000, hostname="lab-k8s", run_label="emulation:r1")
    assert [e["time"] for e in out] == [10_000, 10_250]
    assert {e["device"]["hostname"] for e in out} == {"lab-k8s"}
    assert out[0]["metadata"]["labels"] == ["emulation:r1", "x"] and out[0]["metadata"]["uid"] != "a"
    assert events[0]["time"] == 100  # input untouched
    assert rebase([], start_ms=1, hostname="h", run_label="l") == []


def test_replay_posts_ndjson(campaign):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["auth"] = str(request.url), request.headers["Authorization"]
        seen["lines"] = [json.loads(x) for x in request.content.decode().splitlines()]
        return httpx.Response(200, json={"accepted": len(seen["lines"])})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ex = ReplayExecutor("http://hub.test/", "tok", FIXTURES, "run-1", client=client)
    r = ex.run(campaign.tests[0], K8S)
    assert r.rc == 0 and r.executed and "replay 5 recorded events" in r.command
    assert seen["url"] == "http://hub.test/api/ingest/ocsf" and seen["auth"] == "Bearer tok"
    assert all(e["device"]["hostname"] == "lab-k8s" and "emulation:run-1" in e["metadata"]["labels"]
               for e in seen["lines"])
    assert ex.cleanup(campaign.tests[0], K8S) is None
    ex.close()


def test_replay_failures(campaign, tmp_path):
    from dataclasses import replace
    missing = ReplayExecutor("http://hub.test", "tok", tmp_path, "r", client=httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200))))
    r = missing.run(campaign.tests[0], K8S)
    assert not r.executed and "no replay fixture" in r.error
    rejected = ReplayExecutor("http://hub.test", "tok", FIXTURES, "r", client=httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(401, text="nope"))))
    r = rejected.run(campaign.tests[0], K8S)
    assert r.rc == 401 and "401" in r.error

    def boom(request):
        raise httpx.ConnectError("down")

    client = httpx.Client(transport=httpx.MockTransport(boom))
    down = ReplayExecutor("http://hub.test", "tok", FIXTURES, "r", client=client)
    assert down.run(replace(campaign.tests[0]), K8S).error == "ConnectError"
    with pytest.raises(ValueError, match="EMU_INGEST_TOKEN"):
        ReplayExecutor("http://hub.test", "", FIXTURES, "r")
