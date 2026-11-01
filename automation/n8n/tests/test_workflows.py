"""The n8n playbooks: Code-node JavaScript run under Node against 02's and 09's real Python verifiers, plus the
structure of the generated workflow exports.

Needs ``node`` on PATH (skipped otherwise) and the sibling projects' sources; run from the repository root:

    pytest automation/n8n/tests
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

N8N = Path(__file__).resolve().parents[1]
PORTFOLIO = N8N.parents[1]
for src in (PORTFOLIO / "02-hitl-soar-bot" / "src", PORTFOLIO / "09-evidence-timeline" / "src", N8N):
    sys.path.insert(0, str(src))

import build_workflows
from evidence_timeline.jobs import CollectRequest
from evidence_timeline.signing import Verifier
from soar_bot.decision_hook import event_body
from soar_bot.ingest import normalise, sign_body, verify_body

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

SOAR_SECRET = "s" * 40
DECISION_SECRET = "d" * 40
EVIDENCE_SECRET = "e" * 40
ENV = {"WF_HUB_URL": "http://hub:8000", "WF_HUB_TOKEN": "read-token", "SOAR_WEBHOOK_SECRET": SOAR_SECRET,
       "DECISION_WEBHOOK_SECRET": DECISION_SECRET, "EVIDENCE_SHARED_SECRET": EVIDENCE_SECRET,
       "NOTIFY_WEBHOOK_URL": "https://hooks.example.test/x"}


def run(script: str, items: list[dict[str, Any]], env: dict[str, str] | None = None,
        static: dict[str, Any] | None = None, http: list[Any] | None = None) -> dict[str, Any]:
    ctx = {"env": ENV if env is None else env, "items": items, "static": static or {}, "http": http or []}
    proc = subprocess.run([NODE, str(N8N / "tests" / "run_code.mjs"), str(N8N / "code" / script)],
                          input=json.dumps(ctx), capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip())
    return json.loads(proc.stdout)


def finding(uid: str = "evt-1", **over: Any) -> dict[str, Any]:
    f = {"time": 1_761_469_212_000, "class_uid": 2004, "severity_id": 5, "uid": uid, "product": "detection-rules",
         "hostname": "ws01", "src_ip": "10.0.0.5", "finding_title": "Encoded PowerShell",
         "techniques": ["T1059.001"], "message": "powershell -enc ..."}
    return {**f, **over}


# --- alert intake -----------------------------------------------------------------------------------------------

def test_new_findings_dedupes_and_filters() -> None:
    items = [{"json": finding("a")}, {"json": finding("a")}, {"json": finding("b", product="soar-bot")},
             {"json": finding("c", class_uid=1007)}, {"json": finding("d")}]
    first = run("new_findings.js", items)
    assert [i["json"]["uid"] for i in first["output"]] == ["a", "d"]
    again = run("new_findings.js", [{"json": finding("a")}, {"json": finding("e")}], static=first["static"])
    assert [i["json"]["uid"] for i in again["output"]] == ["e"]


def test_new_findings_forgets_after_six_hours() -> None:
    old = {"seen": {"a": int(time.time() * 1000) - 7 * 3600 * 1000}}
    out = run("new_findings.js", [{"json": finding("a")}], static=old)
    assert [i["json"]["uid"] for i in out["output"]] == ["a"]


def test_built_alert_verifies_and_normalises_in_02() -> None:
    related = [{"techniques": ["T1059.001"]}, {"techniques": ["T1036.003", "T1059.001"]}]
    out = run("build_alert.js", [{"json": finding()}], http=[related])
    item = out["output"][0]["json"]
    body = item["body"].encode()
    assert verify_body(SOAR_SECRET, body, item["ts"], item["sig"])
    assert not verify_body("x" * 40, body, item["ts"], item["sig"])
    alert = normalise(json.loads(body))
    assert (alert.external_id, alert.severity, alert.host, alert.indicator_ip) == ("wf-evt-1", "critical", "ws01",
                                                                                   "10.0.0.5")
    assert alert.source == "watchfloor:detection-rules"
    assert "2 findings on ws01, techniques T1036.003, T1059.001" in alert.description
    req = out["requests"][0]
    assert req["url"] == "http://hub:8000/api/findings"
    assert req["headers"] == {"Authorization": "Bearer read-token"}
    assert req["qs"]["hostname"] == "ws01"


def test_built_alert_survives_hub_outage() -> None:
    out = run("build_alert.js", [{"json": finding()}], http=["ECONNREFUSED"])
    assert "Host context unavailable" in json.loads(out["output"][0]["json"]["body"])["description"]


def test_built_alert_refuses_without_secret() -> None:
    with pytest.raises(RuntimeError, match="SOAR_WEBHOOK_SECRET"):
        run("build_alert.js", [{"json": finding()}], env={**ENV, "SOAR_WEBHOOK_SECRET": "short"})


# --- decision follow-up ---------------------------------------------------------------------------------------

def decision_item(status: str = "approved", secret: str = DECISION_SECRET, ts: int | None = None,
                  raw: bool = True) -> tuple[dict[str, Any], bytes]:
    inc = SimpleNamespace(id="INC-20261026-F64AEE6E", external_id="wf-evt-1", title="Encoded PowerShell",
                          severity="critical", source="watchfloor:detection-rules", host="ws01",
                          indicator_ip="10.0.0.5", status=status, risk_score=88, decided_by="alice",
                          detected_at=1_761_469_212.0, decided_at=1_761_469_300.0, remediation_started_at=None,
                          resolved_at=None)
    # Byte-for-byte what DecisionWebhook.deliver sends.
    body = json.dumps(event_body(inc, time.time()), separators=(",", ":"), sort_keys=True).encode()
    t, sig = sign_body(secret, body, ts)
    item: dict[str, Any] = {"json": {"headers": {"x-soar-timestamp": t, "x-soar-signature": sig},
                                     "body": json.loads(body)}}
    if raw:
        item["binary"] = {"data": {"data": base64.b64encode(body).decode(), "mimeType": "application/json"}}
    return item, body


def test_verify_accepts_02s_signature() -> None:
    item, _ = decision_item()
    out = run("verify_decision.js", [item])["output"][0]["json"]
    assert out["valid"] is True, out["reason"]
    assert out["event"]["event"] == "incident.approved"


def test_verify_needs_the_raw_body() -> None:
    # 02 signs Python's JSON ("detected_at": 1761469212.0); JSON.stringify of the parsed body would drop the ".0".
    item, _ = decision_item(raw=False)
    out = run("verify_decision.js", [item])["output"][0]["json"]
    assert (out["valid"], out["reason"]) == (False, "raw body missing (enable rawBody on the webhook node)")


@pytest.mark.parametrize(("kwargs", "reason"), [
    ({"secret": "x" * 40}, "bad signature"),
    ({"ts": int(time.time()) - 301}, "stale or missing timestamp"),
])
def test_verify_rejects(kwargs: dict[str, Any], reason: str) -> None:
    item, _ = decision_item(**kwargs)
    out = run("verify_decision.js", [item])["output"][0]["json"]
    assert (out["valid"], out["reason"], out["event"]) == (False, reason, None)


def test_verify_rejects_tampered_body_and_replay() -> None:
    item, body = decision_item()
    tampered = body.replace(b'"ws01"', b'"dc01"')
    bad = {**item, "binary": {"data": {"data": base64.b64encode(tampered).decode()}}}
    assert run("verify_decision.js", [bad])["output"][0]["json"]["reason"] == "bad signature"
    first = run("verify_decision.js", [item])
    assert first["output"][0]["json"]["valid"] is True
    replay = run("verify_decision.js", [item], static=first["static"])["output"][0]["json"]
    assert (replay["valid"], replay["reason"]) == (False, "replayed request")


def test_verify_refuses_without_secret() -> None:
    item, _ = decision_item()
    out = run("verify_decision.js", [item], env={**ENV, "DECISION_WEBHOOK_SECRET": ""})["output"][0]["json"]
    assert (out["valid"], out["reason"]) == (False, "DECISION_WEBHOOK_SECRET is not set")


def test_approval_signs_a_collection_09_accepts() -> None:
    _, body = decision_item()
    plan = run("plan_actions.js", [{"json": {"valid": True, "event": json.loads(body)}}])["output"][0]["json"]
    assert plan["collect"] is True and plan["notify"] is True
    assert plan["text"].startswith("alice approved isolating ws01")
    raw = plan["collect_body"].encode()
    assert Verifier(EVIDENCE_SECRET).verify(raw, plan["collect_ts"], plan["collect_sig"])
    req = CollectRequest(**json.loads(raw))
    assert (req.incident_id, req.host, req.around_ms, req.decided_by) == ("INC-20261026-F64AEE6E", "ws01",
                                                                          1_761_469_212_000, "alice")


@pytest.mark.parametrize("status", ["rejected", "remediated", "failed", "expired"])
def test_other_decisions_only_notify(status: str) -> None:
    _, body = decision_item(status)
    plan = run("plan_actions.js", [{"json": {"valid": True, "event": json.loads(body)}}])["output"][0]["json"]
    assert plan["collect"] is False and "collect_body" not in plan
    assert plan["event"] == f"incident.{status}"


def test_no_collection_without_evidence_secret() -> None:
    _, body = decision_item()
    env = {**ENV, "EVIDENCE_SHARED_SECRET": "", "NOTIFY_WEBHOOK_URL": ""}
    plan = run("plan_actions.js", [{"json": {"event": json.loads(body)}}], env=env)["output"][0]["json"]
    assert (plan["collect"], plan["notify"]) == (False, False)


def test_only_crypto_is_required() -> None:
    for script in (N8N / "code").glob("*.js"):
        text = script.read_text()
        assert "require(" not in text.replace("require('crypto')", ""), script.name


# --- generated exports ----------------------------------------------------------------------------------------

def test_exports_are_current() -> None:
    for name, text in build_workflows.render().items():
        assert (N8N / "workflows" / name).read_text() == text, f"{name} is stale: run build_workflows.py"


def _wf(name: str) -> dict[str, Any]:
    return json.loads((N8N / "workflows" / name).read_text())


@pytest.mark.parametrize("name", list(build_workflows.WORKFLOWS))
def test_connections_reference_real_nodes(name: str) -> None:
    wf = _wf(name)
    names = {n["name"] for n in wf["nodes"]}
    assert len(names) == len(wf["nodes"])
    assert len({n["id"] for n in wf["nodes"]}) == len(wf["nodes"])
    targets = set()
    for src, conn in wf["connections"].items():
        assert src in names
        for output in conn["main"]:
            for edge in output:
                assert edge["node"] in names
                targets.add(edge["node"])
    triggers = {n["name"] for n in wf["nodes"] if n["type"].endswith(("Trigger", ".webhook"))}
    assert names - targets == triggers  # every node but the trigger is reachable
    assert wf["active"] is False


def test_decision_workflow_answers_before_acting_and_refuses_unsigned() -> None:
    wf = _wf("watchfloor-decision.json")
    nodes = {n["name"]: n for n in wf["nodes"]}
    hook = nodes["02 decision webhook"]["parameters"]
    assert hook["path"] == "watchfloor-decision" and hook["options"]["rawBody"] is True
    assert hook["responseMode"] == "responseNode"
    gate = wf["connections"]["Signed by 02?"]["main"]
    assert [e["node"] for e in gate[0]] == ["Accept"] and [e["node"] for e in gate[1]] == ["Refuse"]
    assert nodes["Refuse"]["parameters"]["options"]["responseCode"] == 401
    assert "Refuse" not in wf["connections"]  # nothing runs after a refusal
    collect = nodes["Start collection in 09"]["parameters"]
    assert collect["url"] == "={{ $env.EVIDENCE_URL }}/collect" and collect["contentType"] == "raw"


def test_intake_posts_raw_signed_body_to_02() -> None:
    nodes = {n["name"]: n for n in _wf("watchfloor-alert-intake.json")["nodes"]}
    post = nodes["Open incident in 02"]["parameters"]
    assert post["url"] == "={{ $env.SOAR_URL }}/alerts"
    assert post["body"] == "={{ $json.body }}" and post["contentType"] == "raw"
    headers = {h["name"]: h["value"] for h in post["headerParameters"]["parameters"]}
    assert headers == {"X-SOAR-Timestamp": "={{ $json.ts }}", "X-SOAR-Signature": "={{ $json.sig }}"}
    assert nodes["New findings only"]["parameters"]["jsCode"] == (N8N / "code" / "new_findings.js").read_text()
