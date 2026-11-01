"""Tests for workload metrics and report rendering."""

from conftest import make_alert
from test_assess import FakeTriager

from alert_triage.assess import TriageEngine
from alert_triage.cluster import cluster_alerts
from alert_triage.report import RunInfo, evaluate, metrics, render_json, render_markdown


def _run(cmdb, requirements, alerts, triager):
    clusters = cluster_alerts(alerts)
    triaged = TriageEngine(cmdb, requirements, triager).run(clusters.meta_alerts)
    run = RunInfo("in.json", "dbscan", 0.3, 3600, "anthropic", "fake", 4.0, 12.0,
                  llm_stats={"calls": 1, "cache_hits": 2, "fallbacks": 0})
    return run, metrics(len(alerts), clusters, triaged, run), triaged


def test_learned_rules_and_llm_usage(cmdb, requirements):
    alerts = [make_alert("Citrix ADC path traversal", dst="10.20.1.12", severity="high", label="false_positive",
                         offset_s=i) for i in range(4)]
    alerts += [make_alert("SSH brute force", dst="10.20.5.50", port=22, severity="high", label="true_positive",
                          offset_s=i) for i in range(2)]
    run, m, triaged = _run(cmdb, requirements, alerts, FakeTriager())
    text = render_markdown(run, m, triaged, evaluate(triaged))
    assert "## Suggested applicability rules" in text and "nginx host, not Citrix" in text
    assert "LLM usage: 1 calls, 2 cache hits, 0 offline fallbacks." in text
    e = evaluate(triaged)
    # The fake model calls everything a false positive; the guardrail keeps the bastion (criticality 5) in queue.
    assert e["true_threat_recall"] == 1.0 and m["suppressed_alerts"] == 4 and m["analyst_queue"] == 1
    assert '"queue"' in render_json(run, m, triaged, e)


def test_evaluation_counts_missed_threats(cmdb, requirements):
    alerts = [make_alert("Citrix ADC path traversal", dst="10.20.1.12", severity="high", label="true_positive")]
    triaged = _run(cmdb, requirements, alerts, FakeTriager())[2]
    e = evaluate(triaged)
    assert e["true_threat_recall"] == 0.0 and e["suppressed_true_positive_meta_alerts"] == ["MA-0001"]
    assert evaluate(_run(cmdb, requirements, [make_alert("X")], FakeTriager())[2]) is None


def test_multi_day_span_and_empty_metrics(cmdb, requirements):
    alerts = [make_alert("Odd", dst="10.20.9.9", offset_s=s) for s in range(0, 86400 * 2, 3000)]
    run, m, triaged = _run(cmdb, requirements, alerts, FakeTriager("needs_investigation", 0.5))
    assert "10-26 12:00–10-28" in render_markdown(run, m, triaged, None)
    empty = metrics(0, cluster_alerts([]), [], run)
    assert empty["queue_reduction_pct"] == 0.0 and empty["analyst_time_saved_pct"] == 0.0
