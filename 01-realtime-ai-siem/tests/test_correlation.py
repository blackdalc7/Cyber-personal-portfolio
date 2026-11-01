"""Tests for alert-chain correlation: grouping, escalation, debounce and expiry."""

from helpers import accepted, failed, make_event

from realtime_siem.correlation import ChainCorrelator, severity_label
from realtime_siem.detections import DetectionEngine


def attack_alerts(settings):
    engine = DetectionEngine(settings)
    alerts = []
    for i in range(12):
        alerts += engine.process(failed("admin", "203.0.113.66", i))
    alerts += engine.process(accepted("admin", "203.0.113.66", 20))
    alerts += engine.process(make_event("admin : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
                                        offset_s=60, app="sudo"))
    return alerts


def test_chain_groups_by_source_and_escalates(settings):
    alerts = attack_alerts(settings)
    assert len(alerts) == 3
    corr = ChainCorrelator(window_s=3600, min_alerts=2, resummarize_s=600)
    assert corr.add(alerts[0]) is None  # one alert: not yet a chain
    chain = corr.add(alerts[1])
    assert chain is not None and len(chain.alerts) == 2
    corr.mark_summarized(chain, chain.last_seen)
    # PRIV-001 is critical but so was AUTH-002: no escalation and inside the debounce
    assert corr.add(alerts[2]) is None
    payload = chain.to_payload()
    assert payload["rule_ids"] == ["SIEM-AUTH-001", "SIEM-AUTH-002", "SIEM-PRIV-001"]
    assert payload["source_ip"] == "203.0.113.66"
    assert "T1548.003" in payload["techniques"]
    assert payload["hosts"] == ["web01"]


def test_escalation_bypasses_debounce(settings):
    alerts = attack_alerts(settings)
    corr = ChainCorrelator(window_s=3600, min_alerts=1, resummarize_s=10_000)
    chain = corr.add(alerts[0])
    corr.mark_summarized(chain, chain.last_seen)
    assert corr.add(alerts[1]) is chain  # high -> critical


def test_chain_expiry(settings):
    alerts = attack_alerts(settings)
    corr = ChainCorrelator(window_s=1, min_alerts=1, resummarize_s=0)
    corr.add(alerts[0])
    corr.add(alerts[2])  # 60s later: first chain expired, new chain started
    assert len(next(iter(corr.chains.values())).alerts) == 1


def test_payload_is_bounded(settings):
    alerts = attack_alerts(settings)
    corr = ChainCorrelator(window_s=3600, min_alerts=1, resummarize_s=0)
    chain = None
    for _ in range(20):
        for a in alerts:
            chain = corr.add(a) or chain
    assert len(chain.to_payload(max_alerts=10)["alerts"]) == 10
    assert chain.to_payload(max_alerts=10)["alert_count"] == 60


def test_severity_label():
    assert severity_label(99) == "critical"
    assert severity_label(73) == "high"
    assert severity_label(50) == "medium"
    assert severity_label(0) == "low"
