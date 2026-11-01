"""Tests for triage decisions, deterministic suppression and guardrails."""

from conftest import make_alert

from alert_triage.assess import ESCALATE, INVESTIGATE, SUPPRESS, TriageEngine
from alert_triage.cluster import cluster_alerts
from alert_triage.llm import Verdict


class FakeTriager:
    provider = "anthropic"
    model = "fake"

    def __init__(self, verdict="false_positive", confidence=0.95, fallback=None):
        self.verdict, self.confidence, self.fallback = verdict, confidence, fallback
        self.payloads = []

    def triage(self, payload):
        self.payloads.append(payload)
        return Verdict(
            self.verdict,
            self.confidence,
            True,
            "nginx host, not Citrix",
            "close",
            self.provider,
            self.model,
            fallback_reason=self.fallback,
        )


def run(cmdb, requirements, alerts, triager=None):
    return TriageEngine(cmdb, requirements, triager, workers=2).run(cluster_alerts(alerts).meta_alerts)


def test_structural_false_positive(cmdb, requirements):
    alerts = [
        make_alert(
            "ET EXPLOIT Possible BlueKeep RDP exploitation attempt", offset_s=i, port=3389, dst=f"10.20.1.1{i % 3}"
        )
        for i in range(30)
    ]
    [t] = run(cmdb, requirements, alerts)
    assert (t.disposition, t.reason, t.priority) == (SUPPRESS, "STRUCTURAL_FP", 0.0)
    assert "cannot succeed on any of the 3 target(s) [rdp]" in t.explanation and "runs linux" in t.explanation


def test_structural_needs_every_target_immune(cmdb, requirements):
    alerts = [
        make_alert("GPL RDP brute force", dst="10.20.1.10", port=3389),
        make_alert("GPL RDP brute force", dst="10.20.4.40", port=3389, offset_s=1),
    ]  # DC really has RDP
    [t] = run(cmdb, requirements, alerts)
    assert t.disposition != SUPPRESS and t.reason != "STRUCTURAL_FP"


def test_unknown_target_is_never_structural(cmdb, requirements):
    [t] = run(cmdb, requirements, [make_alert("GPL RDP brute force", dst="10.20.9.99", port=3389)])
    assert t.disposition == INVESTIGATE and t.unknown_targets == ["10.20.9.99"]


def test_rule_without_requirements_goes_to_triager(cmdb, requirements):
    fake = FakeTriager("true_positive", 0.9)
    [t] = run(cmdb, requirements, [make_alert("Kerberoasting RC4", src="10.30.10.15", dst="10.20.4.40", port=88)], fake)
    assert t.disposition == ESCALATE and t.reason == "LLM_TRUE_POSITIVE" and t.priority > 0
    payload = fake.payloads[0]
    assert payload["target_assets"][0]["hostname"] == "dc01" and payload["source_assets"][0]["hostname"] == "ws-fin-015"
    assert "cohesion" not in payload["meta_alert"]


def test_authorised_scanner_and_maintenance(cmdb, requirements):
    scan = [
        make_alert("ET SCAN Nmap SYN scan", category="reconnaissance", src="10.0.5.10", offset_s=i, port=i + 1)
        for i in range(50)
    ]
    maint = [
        make_alert("PostgreSQL service stopped", src="10.40.0.5", dst="10.20.3.30", port=5432, offset_s=-36000 + i)
        for i in range(5)
    ]  # 02:00 UTC, inside CHG-20431
    out = run(cmdb, requirements, scan + maint)
    reasons = {t.reason: t for t in out}
    assert (
        reasons["AUTHORIZED_SCANNER"].meta.count == 50
        and "secops-vuln-mgmt" in reasons["AUTHORIZED_SCANNER"].explanation
    )
    assert "CHG-20431" in reasons["MAINTENANCE_WINDOW"].explanation


def test_partial_scanner_or_window_does_not_suppress(cmdb, requirements):
    mixed = [
        make_alert("ET SCAN Nmap SYN scan", category="reconnaissance", src="10.0.5.10"),
        make_alert("ET SCAN Nmap SYN scan", category="reconnaissance", src="10.0.5.200", offset_s=1),
    ]
    late = [
        make_alert("PostgreSQL service stopped", dst="10.20.3.30", offset_s=-32400),  # 03:00, inside
        make_alert("PostgreSQL service stopped", dst="10.20.3.30", offset_s=-29700),
    ]  # 03:45, after 03:30
    for alerts in (mixed, late):
        [t] = run(cmdb, requirements, alerts)
        assert t.disposition != SUPPRESS


def test_llm_suppression_and_guardrails(cmdb, requirements):
    citrix = [make_alert("Citrix ADC path traversal", severity="high", dst="10.20.1.12", offset_s=i) for i in range(5)]
    [ok] = run(cmdb, requirements, citrix, FakeTriager())
    assert ok.disposition == SUPPRESS and ok.reason == "LLM_FALSE_POSITIVE"

    [low] = run(cmdb, requirements, citrix, FakeTriager(confidence=0.6))
    assert low.disposition == INVESTIGATE and low.reason == "LLM_FALSE_POSITIVE_UNCONFIRMED"
    assert "confidence 0.60 < 0.80" in low.flags[0]

    crit = [make_alert("Citrix ADC path traversal", dst="10.20.5.50", severity="critical")]
    [blocked] = run(cmdb, requirements, crit, FakeTriager("benign_true_positive"))
    assert blocked.disposition == INVESTIGATE and "criticality 5" in blocked.flags[0]
    assert "critical severity" in blocked.flags[0] and blocked.reason == "LLM_BENIGN_UNCONFIRMED"

    unknown = [make_alert("Citrix ADC path traversal", dst="10.20.9.9")]
    [u] = run(cmdb, requirements, unknown, FakeTriager())
    assert "missing from the CMDB" in u.flags[0]


def test_needs_review_fallback_flag_and_ordering(cmdb, requirements):
    alerts = [
        make_alert("Odd thing", dst="10.20.1.12", severity="low"),
        make_alert("Worse thing", dst="10.20.3.30", severity="critical", offset_s=5),
    ]
    out = run(cmdb, requirements, alerts, FakeTriager("needs_investigation", 0.5, fallback="rate_limited"))
    assert [t.meta.rules[0] for t in out] == ["Worse thing", "Odd thing"]
    assert out[0].priority > out[1].priority and out[0].flags == ["llm_fallback:rate_limited"]
    d = out[0].to_dict()
    assert (
        d["disposition"] == INVESTIGATE
        and d["max_criticality"] == 5
        and d["verdict"]["verdict"] == "needs_investigation"
    )


def test_offline_default_triager(cmdb, requirements):
    [t] = run(cmdb, requirements, [make_alert("SSH brute force", dst="10.20.5.50", port=22, severity="high")])
    assert t.disposition == ESCALATE and t.reason == "RULES_TRUE_POSITIVE" and t.verdict.provider == "offline"
