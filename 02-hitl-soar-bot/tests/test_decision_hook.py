"""The outbound decision webhook: signed, nonce-free, retried, audited, and never in the way of the decision."""

import json
from dataclasses import replace

import pytest
import requests
from helpers import WEBHOOK_SECRET, signed_alert, slack_click
from test_hitl_flow import _create

from soar_bot.chat.base import action_value
from soar_bot.config import ConfigError, Settings
from soar_bot.decision_hook import DecisionWebhook, event_body
from soar_bot.ingest import verify_body
from soar_bot.server import build_service

HOOK_SECRET = "d" * 40


class Resp:
    def __init__(self, status):
        self.status_code = status


class FakeSession:
    def __init__(self, statuses=(200,), exc=None):
        self.statuses, self.exc, self.calls = list(statuses), exc, []

    def post(self, url, data, timeout, headers):
        self.calls.append({"url": url, "body": data, "headers": headers})
        if self.exc:
            raise self.exc
        return Resp(self.statuses.pop(0) if self.statuses else 200)


@pytest.fixture
def hooked(service, clock):
    session, sleeps = FakeSession(), []
    service.decision_hook = DecisionWebhook("https://n8n.lab/webhook/soar-decision", HOOK_SECRET, session=session,
                                            sleep=sleeps.append, clock=clock)
    return service, session, sleeps


def test_approval_emits_signed_events(client, hooked, clock):
    service, session, _ = hooked
    incident_id = _create(client)
    slack_click(client, action_value(service.db.get(incident_id)))
    events = [c["headers"]["X-SOAR-Event"] for c in session.calls]
    assert events == ["incident.approved", "incident.remediated"]
    for call in session.calls:
        h = call["headers"]
        assert verify_body(HOOK_SECRET, call["body"], h["X-SOAR-Timestamp"], h["X-SOAR-Signature"], now=clock())
        assert not verify_body(WEBHOOK_SECRET, call["body"], h["X-SOAR-Timestamp"], h["X-SOAR-Signature"],
                               now=clock())
    body = json.loads(session.calls[0]["body"])
    assert body["event"] == "incident.approved" and body["incident"]["id"] == incident_id
    assert body["incident"]["host"] == "web01" and body["incident"]["decided_by"] == "analyst"
    assert "approval_nonce" not in session.calls[0]["body"].decode()
    audit = [a["event"] for a in service.db.audit_trail(incident_id)]
    assert audit.count("decision_webhook_sent") == 2


def test_reject_and_expiry_emit_events(client, hooked, clock):
    service, session, _ = hooked
    a = _create(client)
    slack_click(client, action_value(service.db.get(a)), action="reject_isolation")
    payload = json.loads((__import__("helpers").SAMPLES / "ssh_bruteforce.json").read_text())
    payload["id"] = "other-alert"
    b = signed_alert(client, payload).get_json()["incident_id"]
    clock.advance(10_000)
    assert service.expire_stale() == [b]
    assert [c["headers"]["X-SOAR-Event"] for c in session.calls] == ["incident.rejected", "incident.expired"]


def test_retries_then_gives_up_and_audits(client, service, clock):
    session, sleeps = FakeSession(statuses=(503, 502, 500)), []
    service.decision_hook = DecisionWebhook("https://n8n.lab/x", HOOK_SECRET, session=session, sleep=sleeps.append,
                                            clock=clock, retries=3, backoff_s=1)
    incident_id = _create(client)
    slack_click(client, action_value(service.db.get(incident_id)), action="reject_isolation")
    assert len(session.calls) == 3 and sleeps == [1, 2]
    assert service.db.get(incident_id).status == "rejected"  # the decision stands regardless
    assert "decision_webhook_failed" in [a["event"] for a in service.db.audit_trail(incident_id)]


def test_client_errors_are_not_retried(service, clock):
    hook = DecisionWebhook("https://n8n.lab/x", HOOK_SECRET, session=FakeSession(statuses=(401,)),
                           sleep=lambda s: None, clock=clock)
    inc = replace(_fake_incident(), status="approved")
    assert hook.deliver(inc) is False and len(hook._http.calls) == 1
    retry_429 = DecisionWebhook("https://n8n.lab/x", HOOK_SECRET, session=FakeSession(statuses=(429, 200)),
                                sleep=lambda s: None, clock=clock)
    assert retry_429.deliver(inc) is True


def test_network_errors_and_unknown_status(clock):
    hook = DecisionWebhook("https://n8n.lab/x", HOOK_SECRET, session=FakeSession(exc=requests.ConnectionError()),
                           sleep=lambda s: None, clock=clock, retries=2)
    assert hook.deliver(replace(_fake_incident(), status="remediated")) is False
    assert len(hook._http.calls) == 2
    assert hook.deliver(replace(_fake_incident(), status="awaiting_approval")) is False
    assert len(hook._http.calls) == 2  # nothing sent for non-decision states


def test_event_body_has_no_secrets():
    body = event_body(replace(_fake_incident(), status="approved"), 5.0)
    assert body["event"] == "incident.approved" and body["sent_at"] == 5.0
    assert "approval_nonce" not in body["incident"] and "enrichment" not in body["incident"]


def _fake_incident():
    from soar_bot.db import Incident
    return Incident(id="INC-1", external_id="e", title="t", severity="high", source="s", host="web01",
                    indicator_ip="203.0.113.5", description=None, enrichment={}, risk_score=80, status="new",
                    approval_nonce="n" * 32, chat_provider=None, chat_channel=None, chat_message_ref=None,
                    decided_by="analyst", remediation_output=None, detected_at=1.0, created_at=1.0,
                    approval_requested_at=None, decided_at=2.0, remediation_started_at=None, resolved_at=None,
                    updated_at=2.0)


BASE = {"WEBHOOK_SHARED_SECRET": WEBHOOK_SECRET}


@pytest.mark.parametrize("env, msg", [
    ({"DECISION_WEBHOOK_URL": "ftp://x"}, "http"),
    ({"DECISION_WEBHOOK_URL": "https://n8n/x"}, ">= 32"),
    ({"DECISION_WEBHOOK_URL": "https://n8n/x", "DECISION_WEBHOOK_SECRET": WEBHOOK_SECRET}, "must differ"),
])
def test_config_validation(env, msg):
    with pytest.raises(ConfigError, match=msg):
        Settings.from_env({**BASE, **env})


def test_server_wires_the_hook(tmp_path):
    s = Settings.from_env({**BASE, "SOAR_DATA_DIR": str(tmp_path), "DECISION_WEBHOOK_URL": "https://n8n/x",
                           "DECISION_WEBHOOK_SECRET": HOOK_SECRET})
    assert "decision_webhook_secret" not in repr(s)
    svc = build_service(s)
    assert svc.decision_hook is not None and svc.decision_hook.url == "https://n8n/x"
    svc.shutdown()
    plain = build_service(Settings.from_env({**BASE, "SOAR_DATA_DIR": str(tmp_path / "b")}))
    assert plain.decision_hook is None
    plain.shutdown()
