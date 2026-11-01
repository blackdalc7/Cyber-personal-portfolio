from __future__ import annotations

import pytest

from evidence_timeline.velociraptor import COLLECT, FIND_CLIENT, FLOW_STATE, RESULTS, Velociraptor, VelociraptorError


class FakeServer:
    def __init__(self, states=("RUNNING", "FINISHED"), clients=None, flow=None):
        self.calls, self.states = [], list(states)
        self.clients = clients if clients is not None else [
            {"client_id": "C.old", "hostname": "WS01", "last_seen_at": 1},
            {"client_id": "C.new", "hostname": "ws01", "last_seen_at": 9},
            {"client_id": "C.other", "hostname": "ws011", "last_seen_at": 99}]
        self.flow = flow if flow is not None else {"flow_id": "F.123"}

    def __call__(self, vql, env, max_rows=10_000):
        self.calls.append((vql, dict(env), max_rows))
        if vql == FIND_CLIENT:
            return self.clients
        if vql == COLLECT:
            return [{"flow": self.flow}]
        if vql == FLOW_STATE:
            state = self.states.pop(0) if self.states else "RUNNING"
            return [{"state": state, "status": "boom" if state == "ERROR" else "",
                     "artifacts_with_results": ["Windows.EventLogs.Hayabusa", "Windows.System.Pslist"]}]
        if vql == RESULTS:
            return [{"RuleTitle": "x", "Timestamp": "2026-10-26T09:00:00Z", "art": env["Artifact"]}]
        raise AssertionError(vql)


def test_happy_path_uses_env_not_formatting():
    srv, sleeps = FakeServer(), []
    v = Velociraptor(srv, poll_s=5, sleep=sleeps.append, clock=lambda: 0)
    host = "ws01' OR 1=1 --"  # would break a formatted query; here it is only ever a variable
    srv.clients = [{"client_id": "C.new", "hostname": host}]
    out = list(v.collect_all(host, ["Windows.EventLogs.Hayabusa", "Windows.System.Pslist",
                                    "Windows.Network.Netstat"], 600, 50))
    assert [a for a, _, _ in out] == ["Windows.EventLogs.Hayabusa", "Windows.System.Pslist"]  # netstat had no rows
    assert out[0][2] == {"client_id": "C.new", "flow_id": "F.123"}
    assert all(host not in vql for vql, _, _ in srv.calls)
    assert srv.calls[0][1] == {"Host": host}
    assert srv.calls[1][1]["Artifacts"] == "Windows.EventLogs.Hayabusa,Windows.System.Pslist,Windows.Network.Netstat"
    assert srv.calls[-1][2] == 50 and sleeps == [5]


def test_picks_most_recent_exact_client():
    assert Velociraptor(FakeServer()).find_client("ws01") == "C.new"
    fqdn = FakeServer(clients=[{"client_id": "C.f", "hostname": "", "fqdn": "WS01.corp.local"}])
    assert Velociraptor(fqdn).find_client("ws01") == "C.f"
    with pytest.raises(VelociraptorError, match="no Velociraptor client"):
        Velociraptor(FakeServer(clients=[])).find_client("ws01")


def test_collect_failures():
    with pytest.raises(VelociraptorError, match="not scheduled"):
        Velociraptor(FakeServer(flow={})).collect("C.1", ["a"], 60)
    with pytest.raises(VelociraptorError, match="failed: boom"):
        Velociraptor(FakeServer(states=("ERROR",))).wait("C.1", "F.1", 60)
    t = iter([0, 0, 100, 200])
    with pytest.raises(VelociraptorError, match="still RUNNING"):
        Velociraptor(FakeServer(states=()), sleep=lambda s: None, clock=lambda: next(t)).wait("C.1", "F.1", 60)


def test_grpc_query_reads_api_config(tmp_path, monkeypatch):
    import sys
    import types

    from evidence_timeline import velociraptor as mod

    cfg = tmp_path / "api.config.yaml"
    cfg.write_text("ca_certificate: CA\nclient_private_key: KEY\nclient_cert: CERT\n"
                   "api_connection_string: velociraptor:8001\n")
    sent = {}

    class Resp:
        def __init__(self, response, log=""):
            self.Response, self.log = response, log

    class Stub:
        def __init__(self, channel):
            pass

        def Query(self, req):
            sent["req"] = req
            return [Resp("", "starting"), Resp('[{"a": 1}, {"a": 2}]'), Resp('[{"a": 3}]')]

    class Channel:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    fake_grpc = types.SimpleNamespace(ssl_channel_credentials=lambda **kw: sent.setdefault("creds", kw),
                                      secure_channel=lambda target, creds, options: sent.update(
                                          target=target, options=options) or Channel())
    import pyvelociraptor.api_pb2_grpc as real_stub_mod
    monkeypatch.setitem(sys.modules, "grpc", fake_grpc)
    monkeypatch.setattr(real_stub_mod, "APIStub", Stub)
    q = mod.grpc_query(cfg, timeout_s=30)
    assert q("SELECT 1", {"Host": "ws01"}, max_rows=2) == [{"a": 1}, {"a": 2}]
    assert sent["target"] == "velociraptor:8001" and sent["creds"]["root_certificates"] == b"CA"
    req = sent["req"]
    assert req.Query[0].VQL == "SELECT 1" and req.env[0].key == "Host" and req.env[0].value == "ws01"
    assert req.max_row == 2 and req.timeout == 30
