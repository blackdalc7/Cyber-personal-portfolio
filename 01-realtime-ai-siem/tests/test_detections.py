"""Tests for the streaming detection rules (brute force, spraying, compromise, privilege)."""

from dataclasses import replace

from helpers import accepted, failed, make_event

from realtime_siem.detections import BoundedDict, DetectionEngine
from realtime_siem.ecs import validate


def run(engine, events):
    alerts = []
    for ev in events:
        alerts.extend(engine.process(ev))
    return alerts


def rule_ids(alerts):
    return [a["rule"]["id"] for a in alerts]


def test_brute_force_threshold(settings):
    engine = DetectionEngine(settings)
    alerts = run(engine, [failed("root", "203.0.113.5", i) for i in range(9)])
    assert alerts == []
    alerts = run(engine, [failed("root", "203.0.113.5", 9)])
    assert rule_ids(alerts) == ["SIEM-AUTH-001"]
    a = alerts[0]
    validate(a)
    assert a["event"]["kind"] == "alert"
    assert a["threat"]["technique"]["id"] == ["T1110.001"]
    assert a["source"]["ip"] == "203.0.113.5"
    assert a["siem"]["alert"]["evidence_count"] == 10


def test_failures_outside_window_do_not_count(settings):
    engine = DetectionEngine(replace(settings, brute_force_window_s=60))
    alerts = run(engine, [failed("root", "203.0.113.5", i * 30) for i in range(10)])
    assert "SIEM-AUTH-001" not in rule_ids(alerts)


def test_cooldown_suppresses_alert_storm(settings):
    engine = DetectionEngine(settings)
    alerts = run(engine, [failed("root", "203.0.113.5", i) for i in range(40)])
    assert rule_ids(alerts).count("SIEM-AUTH-001") == 1
    later = run(engine, [failed("root", "203.0.113.5", 40 + settings.alert_cooldown_s + i) for i in range(10)])
    assert rule_ids(later).count("SIEM-AUTH-001") == 1


def test_success_after_brute_force_is_critical(settings):
    engine = DetectionEngine(settings)
    run(engine, [failed("admin", "203.0.113.66", i) for i in range(12)])
    alerts = run(engine, [accepted("admin", "203.0.113.66", 20)])
    assert rule_ids(alerts) == ["SIEM-AUTH-002"]
    assert alerts[0]["event"]["severity"] == 99
    assert alerts[0]["user"]["name"] == "admin"
    assert alerts[0]["threat"]["technique"]["id"] == ["T1110.001", "T1078"]


def test_success_without_brute_force_is_quiet(settings):
    engine = DetectionEngine(settings)
    run(engine, [failed("alice", "192.0.2.10", i) for i in range(3)])
    assert run(engine, [accepted("alice", "192.0.2.10", 5)]) == []


def test_success_from_other_source_is_quiet(settings):
    engine = DetectionEngine(settings)
    run(engine, [failed("admin", "203.0.113.66", i) for i in range(12)])
    assert run(engine, [accepted("admin", "192.0.2.10", 20)]) == []


def test_password_spray(settings):
    engine = DetectionEngine(settings)
    users = ["root", "admin", "oracle", "postgres", "test"]
    alerts = run(engine, [failed(u, "198.51.100.23", i) for i, u in enumerate(users)])
    assert rule_ids(alerts) == ["SIEM-AUTH-003"]
    assert alerts[0]["related"]["user"] == sorted(users)


def test_privileged_activity_after_compromise(settings):
    engine = DetectionEngine(settings)
    run(engine, [failed("admin", "203.0.113.66", i) for i in range(12)])
    run(engine, [accepted("admin", "203.0.113.66", 20)])
    sudo = make_event("admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
                      offset_s=140, app="sudo")
    useradd = make_event("new user: name=svc-backup, UID=1005", offset_s=260, app="useradd")
    alerts = run(engine, [sudo, sudo, useradd])
    assert rule_ids(alerts) == ["SIEM-PRIV-001", "SIEM-PRIV-001"]  # duplicate sudo suppressed
    assert alerts[0]["source"]["ip"] == "203.0.113.66"  # links back to the attacker for chaining
    assert "svc-backup" in alerts[1]["related"]["user"]


def test_privileged_activity_on_clean_host_is_quiet(settings):
    engine = DetectionEngine(settings)
    sudo = make_event("ops : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update", app="sudo")
    assert run(engine, [sudo]) == []


def test_privileged_activity_after_window_is_quiet(settings):
    engine = DetectionEngine(replace(settings, post_compromise_window_s=60))
    run(engine, [failed("admin", "203.0.113.66", i) for i in range(12)])
    run(engine, [accepted("admin", "203.0.113.66", 20)])
    sudo = make_event("admin : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", offset_s=500, app="sudo")
    assert run(engine, [sudo]) == []


def test_bounded_state_evicts_lru():
    d = BoundedDict(maxlen=3)
    for k in "abcd":
        d.touch(k, list)
    assert list(d) == ["b", "c", "d"]
    d.touch("b", list)
    d.touch("e", list)
    assert list(d) == ["d", "b", "e"]


def test_flood_of_spoofed_sources_is_bounded(settings):
    engine = DetectionEngine(replace(settings, max_tracked_keys=100))
    for i in range(1000):
        engine.process(failed("root", f"10.0.{i // 250}.{i % 250}", i * 0.01))
    assert len(engine._failures) <= 100
