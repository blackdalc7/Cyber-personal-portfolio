"""Tests for the incident store, the hash-chained audit log and MTTA/MTTR metrics."""

import sqlite3

import pytest
from helpers import APPROVER

from soar_bot.db import TransitionError
from soar_bot.ingest import normalise
from soar_bot.report import main as report_main
from soar_bot.report import render


def _incident(service, clock, severity="high", detected_ago=0, ext=None):
    alert = normalise({"id": ext, "title": "t", "severity": severity, "host": "h1", "source_ip": "203.0.113.1"})
    alert.detected_at = clock() - detected_ago
    incident, _ = service.handle_alert(alert)
    return incident


def test_mttr_kpis(service, clock):
    a = _incident(service, clock, "critical", detected_ago=60, ext="a")
    clock.advance(120)  # analyst takes 2 minutes
    service.decide(a.id, a.approval_nonce, "approve", APPROVER, "x", "slack")
    b = _incident(service, clock, "high", detected_ago=30, ext="b")
    clock.advance(300)
    service.decide(b.id, b.approval_nonce, "reject", APPROVER, "x", "slack")
    _incident(service, clock, "high", ext="c")  # still pending: excluded from MTTR

    r = service.metrics()
    assert r["incidents"] == 3
    assert r["by_status"] == {"remediated": 1, "rejected": 1, "awaiting_approval": 1}
    o = r["overall"]
    assert o["time_to_acknowledge"]["count"] == 2
    assert o["time_to_acknowledge"]["mean_s"] == pytest.approx((180 + 330) / 2)
    assert o["approval_latency"]["median_s"] == pytest.approx((120 + 300) / 2)
    assert o["time_to_contain"]["count"] == 1  # only actually-isolated incidents
    assert o["mttr"]["count"] == 2
    assert r["by_severity"]["critical"]["mttr"]["mean_s"] == pytest.approx(180)
    assert "time_to_acknowledge" in render(r)


def test_p90_nearest_rank(db):
    from soar_bot.db import _stats
    s = _stats([float(x) for x in range(1, 11)])
    assert s["p90_s"] == 9.0 and s["median_s"] == 5.5
    assert _stats([])["mean_s"] is None


def test_invalid_transition_raises(service, clock):
    inc = _incident(service, clock)
    with pytest.raises(TransitionError):
        service.db.transition(inc.id, "awaiting_approval", "remediated", "x")
    with pytest.raises(ValueError):
        service.db.transition(inc.id, "awaiting_approval", "approved", "x", status="hacked")


def test_audit_chain_detects_tampering(service, clock, settings):
    _incident(service, clock)
    assert service.db.verify_audit_chain() == (True, None)
    conn = sqlite3.connect(settings.database_path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit_log SET actor='mallory' WHERE seq=1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM audit_log")
    # An attacker with file access who drops the trigger is still caught by the hash chain.
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit_log SET actor='mallory' WHERE seq=1")
    conn.commit()
    conn.close()
    assert service.db.verify_audit_chain() == (False, 1)


def test_api_requires_token(client, service, clock, settings):
    inc = _incident(service, clock)
    assert client.get("/incidents").status_code == 401
    auth = {"Authorization": f"Bearer {settings.api_token}"}
    listed = client.get("/incidents", headers=auth).get_json()
    assert listed[0]["id"] == inc.id and "approval_nonce" not in listed[0]
    detail = client.get(f"/incidents/{inc.id}", headers=auth).get_json()
    assert detail["audit"][0]["event"] == "incident_created"
    assert client.get("/incidents/nope", headers=auth).status_code == 404
    assert client.get("/metrics/mttr", headers=auth).get_json()["incidents"] == 1
    assert client.get("/audit/verify", headers=auth).get_json()["intact"] is True
    assert client.get("/healthz").get_json()["status"] == "ok"


def test_api_disabled_without_token(settings, service):
    from dataclasses import replace

    from soar_bot.app import create_app
    app = create_app(replace(settings, api_token=""), service)
    assert app.test_client().get("/metrics/mttr").status_code == 403


def test_report_cli(service, clock, settings, capsys):
    _incident(service, clock)
    assert report_main(["--db", str(settings.database_path), "--json"]) == 0
    assert '"incidents": 1' in capsys.readouterr().out
    assert report_main(["--db", str(settings.data_dir / "missing.db")]) == 2
