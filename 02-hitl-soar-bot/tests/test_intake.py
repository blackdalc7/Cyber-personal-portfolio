"""Tests for signed alert intake: authentication, replay protection, deduplication and parsing."""

import json

from helpers import SAMPLES, signed_alert

from soar_bot.ingest import AlertError, normalise, sign_body, verify_body


def test_unsigned_alert_rejected(client):
    assert client.post("/alerts", json={"title": "x"}).status_code == 401


def test_wrong_secret_and_replay_rejected(client):
    assert signed_alert(client, {"title": "x"}, secret="x" * 40).status_code == 401
    assert signed_alert(client, {"title": "x"}, ts=1_000_000_000).status_code == 401


def test_duplicate_alert_is_idempotent(client, chat):
    payload = json.loads((SAMPLES / "ssh_bruteforce.json").read_text())
    first = signed_alert(client, payload).get_json()
    second = signed_alert(client, payload)
    assert second.status_code == 200 and second.get_json()["duplicate"] is True
    assert second.get_json()["incident_id"] == first["incident_id"]
    assert len(chat.sent) == 1


def test_low_severity_is_auto_closed(client, service, chat):
    resp = signed_alert(client, {"title": "port scan", "severity": "low", "host": "web01"})
    incident = service.db.get(resp.get_json()["incident_id"])
    assert incident.status == "closed" and chat.sent == []


def test_text_alert(client, service):
    body = (SAMPLES / "suspicious_download.txt").read_bytes()
    resp = signed_alert(client, body, content_type="text/plain")
    incident = service.db.get(resp.get_json()["incident_id"])
    assert incident.indicator_ip == "198.51.100.77" and incident.title.startswith("EDR:")


def test_invalid_json_and_empty(client):
    assert signed_alert(client, b"{not json").status_code == 400
    assert signed_alert(client, b"   ", content_type="text/plain").status_code == 400


def test_body_size_limit(client, settings):
    big = b"x" * (settings.max_body_bytes + 1)
    t, sig = sign_body(settings.webhook_secret, big)
    resp = client.post("/alerts", data=big, content_type="text/plain",
                       headers={"X-SOAR-Timestamp": t, "X-SOAR-Signature": sig})
    assert resp.status_code == 413


def test_normalise_ecs_chain_from_project_01():
    doc = {"@timestamp": "2026-10-26T11:08:59.000Z", "ecs": {"version": "8.11.0"},
           "message": "203.0.113.66 brute forced and then logged in to web01...",
           "event": {"kind": "alert", "severity": 99, "module": "realtime_siem",
                     "start": "2026-10-26T11:00:00.000Z", "id": "e1"},
           "rule": {"name": "Correlated alert chain"}, "source": {"ip": "203.0.113.66"},
           "related": {"hosts": ["web01"]},
           "siem": {"chain": {"id": "chain-1", "verdict": "True Positive", "attack_stage": "post_compromise"}}}
    a = normalise(doc)
    assert a.severity == "critical" and a.source == "realtime_siem" and a.external_id == "chain-1"
    assert a.host == "web01" and a.indicator_ip == "203.0.113.66"
    assert "True Positive" in a.title
    assert a.detected_at == 1793012400.0  # event.start, not arrival time: MTTR starts at detection


def test_normalise_rejects_bad_types_and_sanitises():
    import pytest
    with pytest.raises(AlertError):
        normalise(42)
    a = normalise({"title": "t", "severity": "P1", "host": "web01; rm -rf /", "source_ip": "999.1.1.1"})
    assert a.severity == "critical" and a.host is None and a.indicator_ip is None


def test_signature_helpers():
    t, s = sign_body("k" * 32, b"body", 1000)
    assert verify_body("k" * 32, b"body", t, s, now=1000)
    assert not verify_body("k" * 32, b"body2", t, s, now=1000)
    assert not verify_body("k" * 32, b"body", t, s, now=2000)
    assert not verify_body("k" * 32, b"body", "abc", s, now=1000)
    assert not verify_body("", b"body", t, s, now=1000)
