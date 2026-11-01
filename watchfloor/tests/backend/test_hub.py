import json
from dataclasses import replace

import fakeredis
import pytest
from fastapi.testclient import TestClient

from helpers import PORTFOLIO, SCENARIOS, finding, proc
from watchfloor.bus import EventBus
from watchfloor.config import Settings
from watchfloor.hub.app import compact_event, create_app, parse_records
from watchfloor.lake import LakeReader, LakeWriter
from watchfloor.scenarios import list_scenarios

AUTH = {"Authorization": "Bearer read-token"}


@pytest.fixture
def lake_dir(tmp_path):
    w = LakeWriter(tmp_path / "lake")
    for sc in list_scenarios(SCENARIOS):
        w.add_many(sc.events())
    w.add_many([proc(1793005212000, 9001, None, "winword.exe"), proc(1793005213000, 9002, 9001, "cmd.exe"),
                finding(1793005213500, ["T1059.003"], host="ws01", pid=9002)])
    w.flush()
    return tmp_path / "lake"


@pytest.fixture
def settings(tmp_path, lake_dir):
    cov = tmp_path / "coverage"
    cov.mkdir()
    (cov / "coverage.json").write_text(
        (PORTFOLIO / "05-sigma-attack-coverage/examples/output/coverage.json").read_text())
    (cov / "run-1.json").write_text(json.dumps({
        "kind": "emulation-run", "run_id": "run-1", "campaign": "lab", "started": 5,
        "summary": {"detection_coverage": 50.0, "telemetry_coverage": 100.0},
        "results": [{"technique": "T1003.008", "outcome": "detected"}]}))
    (cov / "broken.json").write_text("{")
    ev = tmp_path / "evidence" / "INC-1"
    ev.mkdir(parents=True)
    (ev / "manifest.json").write_text(json.dumps({"incident_id": "INC-20261026-FB976B87", "files": []}))
    an = tmp_path / "analyst"
    an.mkdir()
    (an / "a.json").write_text(json.dumps({"incident_id": "INC-20261026-FB976B87", "verdict": "true_positive"}))
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{"id": "r1"}], "generated": "x"}))
    return replace(Settings(), lake_dir=lake_dir, scenarios_dir=SCENARIOS, hub_token="read-token",
                   ingest_token="ingest-token", coverage_dir=cov, rules_index=rules, evidence_dir=tmp_path / "evidence",
                   analyst_dir=an, cors_origins=("http://localhost:5173",),
                   exposure_file=PORTFOLIO / "04-blast-radius-vuln-scanner/examples/output/findings.json")


@pytest.fixture
def bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


@pytest.fixture
def client(settings, bus):
    return TestClient(create_app(settings, LakeReader(settings.lake_dir), bus))


def test_health_is_public_and_read_api_needs_token(client):
    assert client.get("/api/health").json()["live"] is True
    assert client.get("/api/summary").status_code == 401
    r = client.get("/api/summary", headers=AUTH)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"


def test_summary_and_funnel(client):
    s = client.get("/api/summary", headers=AUTH).json()
    assert s["kpis"]["incidents"] == 2 and s["kpis"]["open_incidents"] == 0
    assert s["kpis"]["mtta_s"] > 0
    assert s["funnel"][0]["stage"] == "Activity events"
    per = client.get("/api/summary", params={"scenario": "maldoc-to-ransomware"}, headers=AUTH).json()
    assert per["kpis"]["incidents"] == 1


def test_events_findings_filters(client):
    rows = client.get("/api/events", params={"hostname": "web01", "class_uid": 3002, "limit": 5}, headers=AUTH).json()
    assert len(rows) == 5 and all(r["class_uid"] == 3002 for r in rows)
    f = client.get("/api/findings", params={"technique": "T1110"}, headers=AUTH).json()
    assert f and all(any(t.startswith("T1110") for t in r["techniques"]) for r in f)
    q = client.get("/api/events", params={"q": "shadow"}, headers=AUTH).json()
    assert any("shadow" in (r["cmd_line"] or r["message"] or "") for r in q)
    raw = client.get(f"/api/events/{rows[0]['uid']}", headers=AUTH).json()
    assert raw["class_uid"] == 3002
    assert client.get("/api/events/nope", headers=AUTH).status_code == 404
    sev = client.get("/api/findings", params={"min_severity": 5, "since": 0}, headers=AUTH).json()
    assert all(r["severity_id"] == 5 for r in sev)


def test_incidents_and_detail(client):
    incs = client.get("/api/incidents", headers=AUTH).json()
    ssh = next(i for i in incs if i["host"] == "web01")
    assert ssh["status"] == "remediated" and ssh["decided_by"] == "analyst.dana"
    d = client.get(f"/api/incidents/{ssh['id']}", headers=AUTH).json()
    assert [h["status"] for h in d["history"]] == ["awaiting_approval", "remediated"]
    assert d["chain"]["verdict"] == "True Positive"
    assert d["evidence"] and d["analyses"]
    kinds = {t["kind"] for t in d["timeline"]}
    assert kinds == {"finding", "activity", "response"}
    assert client.get("/api/incidents/none", headers=AUTH).status_code == 404


def test_process_tree_flags_alerted_pids(client):
    tree = client.get("/api/process-tree", params={"hostname": "ws01"}, headers=AUTH).json()
    names = {n["name"] for n in tree["nodes"]}
    assert {"WINWORD.EXE", "cmd.exe", "powershell.exe", "svch0st.exe"} <= names
    flagged = [n for n in tree["nodes"] if n["alerts"]]
    assert any(n["pid"] == 9002 for n in flagged)
    assert {"source": "9001", "target": "9002"} in tree["edges"]


def test_scenarios_and_score(client):
    lst = client.get("/api/scenarios", headers=AUTH).json()
    assert len(lst) == 2
    one = client.get("/api/scenarios/maldoc-to-ransomware", headers=AUTH).json()
    assert one["events"]
    for source in ("dataset", "lake"):
        sc = client.get("/api/scenarios/maldoc-to-ransomware/score", params={"source": source}, headers=AUTH).json()
        assert {s["stage"]: s["outcome"] for s in sc["stages"]}["masquerading"] == "telemetry_only"
    assert client.get("/api/scenarios/..%2Fetc", headers=AUTH).status_code == 404
    assert client.get("/api/scenarios/nope", headers=AUTH).status_code == 404


def test_file_backed_endpoints(client):
    runs = client.get("/api/coverage", headers=AUTH).json()
    assert [r["kind"] for r in runs] == ["emulation", "exercise"]
    m = client.get("/api/coverage/coverage", headers=AUTH).json()
    assert m["kind"] == "exercise" and {c["outcome"] for c in m["cells"]} <= {"detected", "telemetry_only", "missed"}
    assert client.get("/api/coverage/run-1", headers=AUTH).json()["cells"][0]["technique"] == "T1003.008"
    assert client.get("/api/coverage/none", headers=AUTH).status_code == 404
    ex = client.get("/api/exposure", headers=AUTH).json()
    assert ex["graph"]["nodes"] and ex["attack_paths"]
    wi = client.post("/api/exposure/what-if", json={"patched": ["CVE-2021-41773", "CVE-2021-42013"]},
                     headers=AUTH).json()
    assert wi["paths_before"] == 3 and wi["paths_after"] == 0
    assert client.get("/api/rules", headers=AUTH).json()["rules"] == [{"id": "r1"}]
    assert len(client.get("/api/evidence", headers=AUTH).json()) == 1
    assert len(client.get("/api/analyst", headers=AUTH).json()) == 1


def test_file_endpoints_when_unconfigured(lake_dir):
    c = TestClient(create_app(replace(Settings(), lake_dir=lake_dir, scenarios_dir=SCENARIOS)))
    assert c.get("/api/exposure").status_code == 404
    assert c.post("/api/exposure/what-if", json={"patched": []}).status_code == 404
    assert c.get("/api/rules").json() == {"rules": [], "generated": None}
    assert c.get("/api/coverage").json() == []
    assert c.get("/api/stream").status_code == 503
    assert c.post("/api/ingest/ocsf").status_code == 403


def test_ingest_requires_token_and_maps(client, bus):
    tg = {"process_exec": {"process": {"pid": 5, "binary": "/usr/bin/id"}}, "node_name": "k8s",
          "time": "2026-10-26T12:00:00Z"}
    assert client.post("/api/ingest/tetragon", content=json.dumps([tg])).status_code == 401
    hdr = {"Authorization": "Bearer ingest-token"}
    assert client.post("/api/ingest/nope", content="[]", headers=hdr).status_code == 404
    body = json.dumps(tg) + "\n" + json.dumps({"process_unknown": {}}) + "\nnot json\n"
    r = client.post("/api/ingest/tetragon", content=body, headers=hdr).json()
    assert r == {"received": 2, "accepted": 1, "rejected": 0, "skipped": 1}
    broken = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3, "Computer": "ws01",
              "TimeCreated": "2026-10-26T09:00:00Z", "Message": "DestinationIp: 1.2.3.4\nDestinationPort: abc"}
    bad = client.post("/api/ingest/winlog", content=json.dumps(broken), headers=hdr).json()
    assert bad["rejected"] == 1
    assert client.post("/api/ingest/ocsf", content="x" * 6_000_000, headers=hdr).status_code == 413
    assert bus.r.xlen("wf:events") == 1


def test_stream_auth(client):
    assert client.get("/api/stream").status_code == 401


def test_parse_records_and_compact_event():
    assert parse_records(b"") == []
    assert parse_records(b'{"a":1}') == [{"a": 1}]
    assert parse_records(b'[{"a":1}, 2]') == [{"a": 1}]
    row = compact_event(finding(1, ["T1078"]))
    assert "raw" not in row and row["techniques"] == ["T1078"]


def test_serves_ui_with_spa_fallback(settings, tmp_path):
    ui = tmp_path / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text("<html>wf</html>")
    (ui / "assets" / "app.js").write_text("js")
    c = TestClient(create_app(replace(settings, ui_dir=ui, hub_token="")))
    assert c.get("/assets/app.js").text == "js"
    assert c.get("/incidents/x").text == "<html>wf</html>"
    assert c.get("/../../etc/passwd").text == "<html>wf</html>"


def test_dashboard_responses_carry_csp(tmp_path):
    from fastapi.testclient import TestClient

    from watchfloor.config import Settings
    from watchfloor.hub.app import create_app

    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<!doctype html><title>t</title>", encoding="utf-8")
    client = TestClient(create_app(Settings(lake_dir=tmp_path / "lake", ui_dir=ui)))
    resp = client.get("/")
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert "Content-Security-Policy" not in client.get("/api/health").headers


def test_isolation_request_is_signed_for_02_and_needs_token(tmp_path, monkeypatch):
    import hashlib
    import hmac as _hmac

    import httpx
    from fastapi.testclient import TestClient

    from watchfloor.config import Settings
    from watchfloor.hub.app import create_app

    sent = {}

    def fake_post(url, content, timeout, headers):
        sent.update(url=url, body=content, headers=headers)
        return httpx.Response(202, json={"incident_id": "INC-1", "status": "awaiting_approval"},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    base = {"lake_dir": tmp_path / "lake", "soar_url": "http://soar:8080", "soar_webhook_secret": "s3cret"}
    off = TestClient(create_app(Settings(**base, hub_token="tok")))
    denied = off.post("/api/actions/isolation-request", json={"host": "web01", "reason": "brute force"})
    assert denied.status_code == 403
    no_token = TestClient(create_app(Settings(**base, actions_enabled=True)))
    assert no_token.post("/api/actions/isolation-request", json={"host": "web01", "reason": "x" * 5}).status_code == 403

    client = TestClient(create_app(Settings(**base, actions_enabled=True, hub_token="tok")))
    body = {"host": "web01", "reason": "brute force then sudo", "incident_id": "INC-9"}
    assert client.post("/api/actions/isolation-request", json=body).status_code == 401
    bad = client.post("/api/actions/isolation-request", json={**body, "host": "web01; rm -rf /"},
                      headers={"Authorization": "Bearer tok"})
    assert bad.status_code == 422
    ok = client.post("/api/actions/isolation-request", json=body, headers={"Authorization": "Bearer tok"})
    assert ok.status_code == 200 and ok.json()["status"] == "approval_requested"
    assert sent["url"] == "http://soar:8080/alerts"
    ts = sent["headers"]["X-SOAR-Timestamp"]
    expected = _hmac.new(b"s3cret", f"{ts}.".encode() + sent["body"], hashlib.sha256).hexdigest()
    assert sent["headers"]["X-SOAR-Signature"] == f"sha256={expected}"
    assert b"Analyst-requested isolation of web01" in sent["body"]
