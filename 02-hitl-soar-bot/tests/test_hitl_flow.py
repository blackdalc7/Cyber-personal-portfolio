"""The core guarantee: remediation runs only after an authorised human approves, exactly once."""

import json
import threading

from helpers import APPROVER, SAMPLES, signed_alert, slack_click

from soar_bot.chat.base import action_value


def _create(client, payload=None):
    payload = payload or json.loads((SAMPLES / "ssh_bruteforce.json").read_text())
    resp = signed_alert(client, payload)
    assert resp.status_code == 201, resp.data
    return resp.get_json()["incident_id"]


def test_alert_waits_for_approval_and_does_not_remediate(client, service, chat, settings):
    incident_id = _create(client)
    incident = service.db.get(incident_id)
    assert incident.status == "awaiting_approval"
    assert incident.chat_message_ref == "ts-1" and incident.chat_channel == "C123"
    assert len(chat.sent) == 1
    assert not (settings.data_dir / "iso.json").exists()  # nothing executed without a human


def test_approve_click_executes_remediation_once(client, service, chat, settings):
    incident_id = _create(client)
    value = action_value(service.db.get(incident_id))
    resp = slack_click(client, value)
    assert resp.status_code == 200
    incident = service.db.get(incident_id)
    assert incident.status == "remediated"
    assert incident.decided_by == "analyst"
    assert json.loads(incident.remediation_output)["exit_code"] == 0
    state = json.loads((settings.data_dir / "iso.json").read_text())
    assert state["isolated_hosts"]["web01"]["attacker_ip"] == "185.220.101.1"
    assert chat.updates == ["approved", "remediating", "remediated"]

    # A double click / Slack retry must not run the script again.
    slack_click(client, value)
    events = [a["event"] for a in service.db.audit_trail(incident_id)]
    assert events.count("status:remediating->remediated") == 1


def test_unauthorised_user_cannot_approve(client, service, settings):
    incident_id = _create(client)
    value = action_value(service.db.get(incident_id))
    slack_click(client, value, user="U0INTRUDER")
    assert service.db.get(incident_id).status == "awaiting_approval"
    reasons = [json.loads(a["details"]).get("reason") for a in service.db.audit_trail(incident_id)]
    assert "not_an_approver" in reasons
    assert not (settings.data_dir / "iso.json").exists()


def test_forged_nonce_is_refused(client, service):
    incident_id = _create(client)
    slack_click(client, f"{incident_id}:{'0' * 32}")
    assert service.db.get(incident_id).status == "awaiting_approval"


def test_bad_or_stale_slack_signature_is_401(client, service):
    incident_id = _create(client)
    value = action_value(service.db.get(incident_id))
    assert slack_click(client, value, secret="wrong").status_code == 401
    assert slack_click(client, value, ts=1_000_000_000).status_code == 401  # replayed old request
    assert service.db.get(incident_id).status == "awaiting_approval"


def test_reject_closes_without_remediation(client, service, settings, chat):
    incident_id = _create(client)
    slack_click(client, action_value(service.db.get(incident_id)), action="reject_isolation")
    incident = service.db.get(incident_id)
    assert incident.status == "rejected" and incident.resolved_at is not None
    assert not (settings.data_dir / "iso.json").exists()
    assert chat.updates == ["rejected"]


def test_remediation_failure_is_recorded(client, service):
    service.remediator.extra_args = ["--simulate-failure"]
    incident_id = _create(client)
    slack_click(client, action_value(service.db.get(incident_id)))
    incident = service.db.get(incident_id)
    assert incident.status == "failed" and incident.resolved_at is None
    assert "503" in json.loads(incident.remediation_output)["error"]


def test_concurrent_approvals_have_exactly_one_winner(service, settings):
    from soar_bot.ingest import normalise
    incident, _ = service.handle_alert(normalise({"id": "race-1", "title": "t", "severity": "high",
                                                  "host": "web02", "source_ip": "203.0.113.9"}))
    results = []
    barrier = threading.Barrier(8)

    def click():
        barrier.wait()
        results.append(service.decide(incident.id, incident.approval_nonce, "approve", APPROVER, "a", "slack"))

    threads = [threading.Thread(target=click) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r.accepted for r in results) == 1
    assert service.db.get(incident.id).status == "remediated"


def test_expiry_marks_stale_approvals(client, service, clock, chat):
    incident_id = _create(client)
    assert service.expire_stale() == []
    clock.advance(601)
    assert service.expire_stale() == [incident_id]
    assert service.db.get(incident_id).status == "expired"
    assert chat.updates[-1] == "expired"
    # A late click after expiry does nothing.
    out = service.decide(incident_id, service.db.get(incident_id).approval_nonce, "approve", APPROVER, "a", "slack")
    assert not out.accepted and "expired" in out.message


def test_chat_outage_keeps_incident_pending(service):
    from helpers import RecordingChat

    from soar_bot.ingest import normalise
    service.chat = RecordingChat(fail=True)
    incident, _ = service.handle_alert(normalise({"title": "x", "severity": "high", "host": "h1"}))
    assert incident.status == "awaiting_approval"
    assert "chat_delivery_failed" in [a["event"] for a in service.db.audit_trail(incident.id)]


def test_incident_without_host_cannot_be_approved(service):
    from soar_bot.ingest import normalise
    incident, _ = service.handle_alert(normalise({"title": "phish", "severity": "high"}))
    out = service.decide(incident.id, incident.approval_nonce, "approve", APPROVER, "a", "slack")
    assert not out.accepted and "no host" in out.message
