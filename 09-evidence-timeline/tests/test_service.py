from __future__ import annotations

import json
from dataclasses import replace

import httpx
import pytest
from conftest import SECRET
from fastapi.testclient import TestClient
from test_velociraptor import FakeServer

from evidence_timeline import cli
from evidence_timeline.app import create_app
from evidence_timeline.jobs import CollectRequest, JobStore, collect
from evidence_timeline.package import verify_package
from evidence_timeline.signing import sign
from evidence_timeline.velociraptor import Velociraptor, VelociraptorError


class Inline:
    def submit(self, fn, *a):
        fn(*a)

    def shutdown(self, wait=True):
        pass


def post(client, payload, secret=SECRET, path="/collect"):
    body = json.dumps(payload).encode()
    ts, sig = sign(secret, body)
    return client.post(path, content=body, headers={"X-SOAR-Timestamp": ts, "X-SOAR-Signature": sig})


def signed_get(client, path):
    ts, sig = sign(SECRET, b"")
    return client.get(path, headers={"X-SOAR-Timestamp": ts, "X-SOAR-Signature": sig})


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings, JobStore(settings, executor=Inline())))


def test_collect_local_end_to_end(client, settings):
    r = post(client, {"incident_id": "INC-20261026-F64AEE6E", "host": "ws01", "decided_by": "analyst.dana",
                      "requested_by": "n8n", "around_ms": 1793005226000})
    assert r.status_code == 202 and r.json()["created"] is True
    job = signed_get(client, "/jobs/INC-20261026-F64AEE6E").json()
    assert job["status"] == "done" and job["rows"] == 10
    pkg = settings.out_dir / "INC-20261026-F64AEE6E"
    assert verify_package(pkg) == []
    m = json.loads((pkg / "manifest.json").read_text())
    assert m["decided_by"] == "analyst.dana" and m["host"] == "ws01" and m["highlights"]
    again = post(client, {"incident_id": "INC-20261026-F64AEE6E", "host": "ws01"})
    assert again.status_code == 200 and again.json()["created"] is False  # idempotent
    forced = post(client, {"incident_id": "INC-20261026-F64AEE6E", "host": "ws01", "force": True})
    assert forced.status_code == 202


def test_failed_job_is_reported(client):
    assert post(client, {"incident_id": "INC-2", "host": "nohost"}).status_code == 202
    job = signed_get(client, "/jobs/INC-2").json()
    assert job["status"] == "failed" and "no Hayabusa timeline" in job["error"]


@pytest.mark.parametrize("payload", [
    {"incident_id": "../../etc", "host": "ws01"}, {"incident_id": "INC-1", "host": "ws01; rm -rf /"},
    {"incident_id": "INC-1"}, {"incident_id": "INC-1", "host": "ws01", "reason": "x" * 501}])
def test_bad_requests(client, payload):
    assert post(client, payload).status_code == 422


def test_auth(client):
    assert post(client, {"incident_id": "INC-1", "host": "ws01"}, secret="x" * 40).status_code == 401
    assert client.post("/collect", content=b"{}").status_code == 401
    assert client.get("/jobs/INC-1").status_code == 401
    assert signed_get(client, "/jobs/INC-404").status_code == 404
    assert client.post("/collect", content=b"x" * 20000).status_code == 413
    body = b"not json"
    ts, sig = sign(SECRET, body)
    assert client.post("/collect", content=body, headers={"X-SOAR-Timestamp": ts,
                                                          "X-SOAR-Signature": sig}).status_code == 422
    assert client.get("/healthz").json() == {"status": "ok", "mode": "local"}


def test_collect_request_validation():
    with pytest.raises(ValueError):
        CollectRequest(incident_id="a..b", host="h")
    with pytest.raises(ValueError):
        CollectRequest(incident_id="INC-1", host="-h")


def test_velociraptor_mode_with_hub(settings):
    s = replace(settings, mode="velociraptor", hub_url="http://hub", hub_token="t")
    hub = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[
        {"time": 1793005212000, "class_uid": 2004, "severity_id": 5, "finding_title": "EDR hit",
         "product": "edr-canary"}])))
    path, n = collect(CollectRequest(incident_id="INC-V", host="ws01", around_ms=1793005226000), s,
                      velociraptor=Velociraptor(FakeServer(states=("FINISHED",))), http=hub, now_ms=1793005300000)
    m = json.loads((path / "manifest.json").read_text())
    assert m["collection"]["flow_id"] == "F.123" and "velociraptor:Windows.EventLogs.Hayabusa" in m["sources"]
    assert {f["name"] for f in m["files"]} >= {"raw/Windows.EventLogs.Hayabusa.jsonl",
                                               "raw/Windows.System.Pslist.jsonl"}
    assert n == 3 and m["window"] == {"since": 1793005226000 - 3600_000, "until": 1793005226000 + 1800_000}


def test_hub_outage_is_a_warning_not_a_failure(settings):
    s = replace(settings, hub_url="http://hub")
    down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    path, n = collect(CollectRequest(incident_id="INC-H", host="ws01"), s, http=down)
    m = json.loads((path / "manifest.json").read_text())
    assert m["warnings"] == ["watchfloor telemetry unavailable: HTTPStatusError"] and n == 10


def test_job_store_errors_and_persistence(settings, tmp_path):
    def boom(req):
        raise VelociraptorError("server down")

    store = JobStore(settings, runner=boom, executor=Inline())
    job, created = store.submit(CollectRequest(incident_id="INC-E", host="ws01"))
    assert created and job.status == "failed" and "server down" in job.error
    assert json.loads((settings.out_dir / ".jobs" / "INC-E.json").read_text())["status"] == "failed"
    _, created2 = store.submit(CollectRequest(incident_id="INC-E", host="ws01"))
    assert created2  # a failed job may be retried without force
    blocked = JobStore(replace(settings, out_dir=tmp_path / "file"), runner=lambda r: (tmp_path, 0),
                       executor=Inline())
    (tmp_path / "file").write_text("not a dir")
    assert blocked.submit(CollectRequest(incident_id="INC-P", host="ws01"))[0].status == "done"
    store.shutdown()


def test_cli(settings, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("EVIDENCE_MODE", "local")
    monkeypatch.setenv("EVIDENCE_LOCAL_DIR", str(settings.local_dir))
    monkeypatch.setenv("EVIDENCE_OUT_DIR", str(tmp_path / "out"))
    assert cli.main(["collect", "--incident", "INC-C", "--host", "ws01"]) == 0
    assert "10 timeline rows" in capsys.readouterr().out
    assert cli.main(["verify", str(tmp_path / "out" / "INC-C")]) == 0
    (tmp_path / "out" / "INC-C" / "timeline.csv").write_text("x")
    assert cli.main(["verify", str(tmp_path / "out" / "INC-C")]) == 1
    assert cli.main(["collect", "--incident", "../x", "--host", "ws01"]) == 2
    monkeypatch.setenv("EVIDENCE_SHARED_SECRET", "short")
    assert cli.main(["serve"]) == 2
    monkeypatch.setenv("EVIDENCE_SHARED_SECRET", SECRET)
    ran = {}
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: ran.update(kw))
    assert cli.main(["serve"]) == 0 and ran["port"] == 8090 and ran["server_header"] is False
